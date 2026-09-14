"""Seeding and the container, tested where they can be.

The image itself cannot be built in this environment -- the base image's
registry is unreachable from here -- so what is checked is everything that does
not need the build: that the command the container runs actually serves, that
the storage warning fires exactly when data would be lost, that seeding does
what it claims about cost, and that the deployment files do not promise
anything the code does not do.

The last of those is the one worth having. A Dockerfile is documentation that
executes somewhere else; the failure mode is that it drifts from the app and
nobody notices until a deploy.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.runtime import ephemeral_storage_warning, in_container  # noqa: E402
from eagle_eyes.storage import (  # noqa: E402
    FailureRepo, Principal, open_database,
)
from eagle_eyes.web import spend  # noqa: E402
from eagle_eyes.web.seed import (  # noqa: E402
    DEMO_OWNER, already_seeded, seed, seed_if_asked, seed_wanted,
)

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check

ROOT = Path(__file__).resolve().parents[1]


def _engine_factory(backend):
    from eagle_eyes.analysis import Engine
    from eagle_eyes.model_gateway import models_for
    return lambda: Engine(backend, models_for("mock"))


# ------------------------------------------------------------------ seeding

def test_seeding_spends_its_budget_on_the_failures_that_repeat() -> None:
    """The point of the demo is dedup, so the budget goes to the top fingerprints.

    Analysing whichever failures come first spends every call on one-off
    problems and leaves the spike -- the case the product exists for -- showing
    as unanalysed. Same money, and the difference between a home page that
    proves the argument and one that undercuts it.
    """
    from eagle_eyes.model_gateway import MockBackend

    d = Path(tempfile.mkdtemp())
    try:
        db = open_database(d / "seed.db")
        backend = MockBackend()
        summary = seed(db, _engine_factory(backend), real_analyses=6)

        check("the whole estate is ingested", summary["failures"] > 200,
              str(summary["failures"]))
        check("into far fewer distinct problems", summary["fingerprints"] < 40,
              str(summary["fingerprints"]))
        check("exactly the budgeted number of model calls is made",
              len(backend.calls) == 6, str(len(backend.calls)))
        check("  and the summary agrees", summary["analysed"] == 6)

        stats = FailureRepo(db, Principal.local()).stats()
        check("most failures are answered without a model call",
              stats["dedup_rate"] > 0.8, f"{stats['dedup_rate']:.3f}")
        check("  which is the whole cost argument",
              summary["deduped"] > summary["analysed"] * 20)

        check("what was not analysed is marked pending, not given a diagnosis",
              summary["unanalysed"] >= 0)
        pending_with_analysis = db.conn.execute(
            "SELECT COUNT(*) n FROM failure WHERE status='pending'"
            " AND analysis_id IS NOT NULL").fetchone()["n"]
        check("  and nothing pending carries one", pending_with_analysis == 0,
              str(pending_with_analysis))
        db.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_seeding_happens_once_ever() -> None:
    """Reseeding on each deploy would re-spend on each deploy."""
    from eagle_eyes.model_gateway import MockBackend

    d = Path(tempfile.mkdtemp())
    try:
        db = open_database(d / "seed.db")
        check("an empty database has not been seeded", not already_seeded(db))

        backend = MockBackend()
        env = {"EAGLE_EYES_SEED": "1", "EAGLE_EYES_SEED_ANALYSES": "2"}
        first = seed_if_asked(db, _engine_factory(backend), env)
        check("the first call seeds", first is not None)
        check("and it is recorded", already_seeded(db))
        calls = len(backend.calls)

        second = seed_if_asked(db, _engine_factory(backend), env)
        check("the second call does nothing", second is None)
        check("  and spends nothing", len(backend.calls) == calls)

        check("seeding is off unless asked", not seed_wanted({}))
        check("  and 'false' is not 'on'", not seed_wanted({"EAGLE_EYES_SEED": "false"}))
        check("  while 1/true/yes all mean on",
              all(seed_wanted({"EAGLE_EYES_SEED": v}) for v in ("1", "true", "YES", "on")))
        db.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_seeded_data_is_owned_by_a_demo_identity() -> None:
    """Not by a real address, and not by nobody -- the scoping rules need an owner."""
    from eagle_eyes.model_gateway import MockBackend

    d = Path(tempfile.mkdtemp())
    try:
        db = open_database(d / "seed.db")
        seed(db, _engine_factory(MockBackend()), real_analyses=2)
        owners = {r["email"] for r in db.conn.execute(
            "SELECT DISTINCT d.email FROM bot b JOIN developer d ON d.id=b.owner_dev_id")}
        check("every seeded bot has one owner", owners == {DEMO_OWNER}, str(owners))
        check("  at a domain that can never resolve", DEMO_OWNER.endswith(".invalid"))

        seen = FailureRepo(db, Principal(DEMO_OWNER, "user")).recent(limit=5)
        check("that identity can see the demo data", len(seen) > 0)
        other = FailureRepo(db, Principal("someone@else", "user")).recent(limit=5)
        check("and nobody else can", other == [])
        db.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_seed_failure_does_not_stop_the_app_booting() -> None:
    """No demo data is a bad afternoon. A container that will not boot is worse."""
    d = Path(tempfile.mkdtemp())
    try:
        db = open_database(d / "seed.db")

        def broken():
            raise RuntimeError("no model configured")

        result = seed_if_asked(db, broken, {"EAGLE_EYES_SEED": "1"})
        check("a broken engine returns None rather than raising", result is None)
        check("and nothing is recorded, so a later boot can retry",
              not already_seeded(db))
        db.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------- container

def test_ephemeral_storage_is_warned_about_not_discovered_later() -> None:
    """Everything works in a container with no volume -- accounts, analyses,
    spend -- and all of it disappears at the next deploy with no error
    anywhere. That silence is the failure, so it is broken loudly."""
    saved = {k: os.environ.get(k) for k in
             ("EAGLE_EYES_IN_CONTAINER", "EAGLE_EYES_DATA_DIR")}
    try:
        for k in saved:
            os.environ.pop(k, None)
        outside = ephemeral_storage_warning()
        check("outside a container there is nothing to warn about",
              outside is None, str(outside))

        os.environ["EAGLE_EYES_IN_CONTAINER"] = "1"
        check("the container is detected", in_container())

        warning = ephemeral_storage_warning()
        check("a container with no data dir warns", warning is not None)
        check("  and says what will be lost",
              "silently lost" in warning, warning or "")
        check("  and what to do about it", "volume" in warning, warning or "")

        os.environ["EAGLE_EYES_DATA_DIR"] = "data"
        relative = ephemeral_storage_warning()
        check("a relative data dir warns too -- it resolves against the cwd",
              relative is not None and "relative path" in relative)

        os.environ["EAGLE_EYES_DATA_DIR"] = "/data"
        check("an absolute one is fine", ephemeral_storage_warning() is None)
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v


def test_the_dockerfile_matches_what_the_app_needs() -> None:
    path = ROOT / "Dockerfile"
    check("there is a Dockerfile", path.is_file())
    if not path.is_file():
        return
    text = path.read_text()

    check("it installs the web extra", "[web," in text or "[web]" in text)
    check("and the postgres extra", "postgres]" in text)
    check("it does not run as root", "USER eagle" in text)
    check("it honours the platform's PORT", "${PORT:-" in text)
    check("it runs the app factory the module actually exposes",
          "eagle_eyes.web.app:create_app" in text and "--factory" in text)
    check("it marks itself as a container so the storage check fires",
          "EAGLE_EYES_IN_CONTAINER=1" in text)
    check("it sets an absolute data dir", "EAGLE_EYES_DATA_DIR=/data" in text)
    check("it ships the fixture generator, which seeding loads by path",
          "tools/" in text)
    check("one worker, because the job queue is in-process",
          "--workers 1" in text)


def test_the_dockerignore_keeps_data_and_secrets_out_of_the_image() -> None:
    path = ROOT / ".dockerignore"
    check("there is a .dockerignore", path.is_file())
    if not path.is_file():
        return
    text = path.read_text()
    for pattern, why in ((".git", "repository history"),
                         ("sandbox/", "generated fixtures"),
                         ("*.db", "local databases"),
                         (".env", "environment files"),
                         ("*.pem", "keys"),
                         ("__pycache__", "bytecode")):
        check(f"{why} are excluded", pattern in text, pattern)


def test_railway_config_is_consistent_with_the_app() -> None:
    path = ROOT / "railway.toml"
    check("there is a railway.toml", path.is_file())
    if not path.is_file():
        return
    text = path.read_text()

    check("it builds from the Dockerfile", 'dockerfilePath = "Dockerfile"' in text)
    m = re.search(r'healthcheckPath = "([^"]+)"', text)
    check("the health check path exists in the app", m and m.group(1) == "/healthz",
          m.group(1) if m else "absent")
    check("it records that this instance is synthetic data only",
          "SYNTHETIC DATA ONLY" in text)
    check("  and points at what must change before it is not",
          "PRODUCTION_MIGRATION" in text)

    # Every variable the documentation names must be one the code reads.
    documented = set(re.findall(r"^#\s{4,}(EAGLE_EYES_\w+)", text, re.M))
    source = "\n".join(
        p.read_text() for p in (ROOT / "eagle_eyes").rglob("*.py"))
    unknown = {v for v in documented if v not in source}
    check("every documented variable is one the code actually reads",
          not unknown, str(unknown))

    for var in (spend.KILL_SWITCH_VAR, spend.DAILY_VAR, spend.TOTAL_VAR,
                spend.HOURLY_ANALYSES_VAR):
        check(f"{var} is documented", var in text)


# -------------------------------------------------------- the migration guide

def test_the_migration_guide_describes_this_codebase() -> None:
    """A migration document that has drifted is worse than none.

    Somebody deploys from it. The claims here are the ones that would send a
    deployment the wrong way if they were stale -- which modes exist, which
    profiles exist, what is deliberately absent -- so each is checked against
    the code rather than believed.
    """
    doc_path = ROOT / "docs" / "PRODUCTION_MIGRATION.md"
    check("the guide exists", doc_path.is_file())
    if not doc_path.is_file():
        return
    raw = doc_path.read_text()
    # Phrase checks run against a whitespace-collapsed copy. Markdown wraps at
    # 100 columns, so "discards the\nargument being paid for" does not contain
    # "discards the argument being paid for" -- and a cross-reference test that
    # fails on where a line happens to break teaches people to delete it.
    doc = " ".join(raw.split())

    for other in ("SECURITY.md", "ARCHITECTURE.md", "DATA_MODEL.md"):
        check(f"{other} is referenced and present",
              other in doc and (ROOT / "docs" / other).is_file())

    from eagle_eyes.analysis import SCREENSHOT_MODES
    check("it says only modes 0 and 3 exist",
          "`{0, 3}`" in doc and SCREENSHOT_MODES == {0, 3})
    check("  and says not to re-admit one before it is built",
          "Do not re-admit a mode until the code behind it is written" in doc)

    fingerprint_src = (ROOT / "eagle_eyes" / "fingerprint.py").read_text()
    check("it says only the dotnet profile exists",
          'only `dotnet` exists' in doc)
    profiles = set(re.findall(r'profile\s*==\s*"(\w+)"', fingerprint_src))
    profiles |= set(re.findall(r'profile:\s*str\s*=\s*"(\w+)"', fingerprint_src))
    check("  and the code agrees", profiles <= {"dotnet"}, str(profiles))

    auth_src = (ROOT / "eagle_eyes" / "web" / "auth.py").read_text()
    check("it says an admin cannot set another account's password",
          "cannot** set another account's password" in doc)
    check("  and the code refuses it",
          "a password can only be changed by its owner" in auth_src)

    jobs_src = (ROOT / "eagle_eyes" / "web" / "jobs.py").read_text()
    check("it says the job queue is in-process and loses work on restart",
          "in-process queue" in doc)
    check("  which is what the module says about itself",
          "pretend to be durable" in jobs_src)
    check("  and the module points back at the section that records it",
          "docs/PRODUCTION_MIGRATION.md" in jobs_src)

    from eagle_eyes.web.seed import SEED_VAR
    check("it says to unset the seed variable in production",
          f"`{SEED_VAR}` unset" in doc, SEED_VAR)

    check("it names the questions that block real data",
          all(q in doc for q in ("Q1", "Q2", "Q5", "Q8")))
    security = (ROOT / "docs" / "SECURITY.md").read_text()
    for q in ("Q1", "Q2", "Q5", "Q8", "Q9", "Q12", "Q13", "Q14", "Q17"):
        check(f"  {q} is a real question in SECURITY.md",
              re.search(rf"\b{q}\b", security) is not None)
    check("and adds the one hosting creates", "Q28" in doc)
    check("  in SECURITY.md too, where the security team reads them",
          "Q28" in security)
    check("  marked blocking", re.search(r"\*\*Q28 \[BLOCKING[^\]]*\]\*\*", security)
          is not None)
    check("  and scoped to a hosted deployment, not to the CLI",
          "Q28 gates a" in security or "hosted deployment only" in security)

    # The check that would have caught this: the guide first numbered its new
    # question Q24, which SECURITY.md already uses for "has the client agreed to
    # this specific third-party recipient, by name, in writing?". Two documents
    # disagreeing about what a question number means wastes a security review,
    # and it is the kind of error a reader trusts rather than catches.
    definitions = re.findall(r"^-\s+(?:\*\*)?(Q\d+)\b", security, re.M)
    duplicates = sorted({q for q in definitions if definitions.count(q) > 1})
    check("no question number is defined twice in SECURITY.md",
          not duplicates, str(duplicates))
    for cited in sorted(set(re.findall(r"\bQ\d+\b", raw))):
        check(f"  {cited}, cited by the guide, is defined there exactly once",
              definitions.count(cited) == 1,
              f"defined {definitions.count(cited)} times")

    check("it states plainly where this may not run",
          "synthetic data only" in doc.lower())
    check("  and that the tenancy argument is the reason",
          "discards the argument being paid for" in doc)


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
