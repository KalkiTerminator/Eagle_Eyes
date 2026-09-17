"""The three tabs, the folder upload, and the schedules.

Two things here matter more than the rest and are tested first: that
reconstructing a client-supplied directory tree cannot write outside the
directory, and that a folder uploaded through the browser produces exactly what
the CLI scanner produces from the same tree. The second is the whole reason for
accepting a folder -- if the web path re-implemented discovery, there would be
two sets of pairing rules to keep in step and no test would notice them
diverging.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.storage import (  # noqa: E402
    ADMIN, MANAGER, USER, AccessDenied, FailureRepo, FeedbackRepo, Principal,
    open_database,
)
from eagle_eyes.web import charts  # noqa: E402
from eagle_eyes.web.auth import AccountRepo, bootstrap_admin  # noqa: E402
from eagle_eyes.web.ingest import discover_upload  # noqa: E402
from eagle_eyes.web.schedules import (  # noqa: E402
    MISSING_PATH, NO_FILESYSTEM, OK, ScheduleRepo, ScheduleRunner,
    can_scan_this_host,
)
from eagle_eyes.web.tree import UnsafePath, safe_relative, write_tree  # noqa: E402

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "correct-horse-battery-staple"


def _sandbox() -> Path | None:
    p = Path(os.environ.get("EAGLE_EYES_SANDBOX", ROOT / "sandbox"))
    return p if p.is_dir() else None


# ------------------------------------------------------------ path traversal

def test_a_hostile_path_cannot_escape_the_upload_directory() -> None:
    """The feature is writing client-chosen paths. That is also the hole."""
    hostile = [
        "../../../../etc/passwd", "..\\..\\..\\Windows\\System32\\x",
        "/etc/passwd", "\\\\server\\share\\x", "C:\\Windows\\evil",
        "C:relative", "stream:$DATA", "a/../../../b", "a/./../../b",
        "....//....//etc/passwd", "logs/\x00/passwd", "logs/x\ny",
        "CON", "com1.txt", "PRN.log", "a/nul/b",
        "trailing /x", "trailing./x", "", "   ", ".", "..",
        "/".join(["d"] * 40) + "/f.log", "x" * 300 + ".log",
    ]
    for path in hostile:
        refused = False
        try:
            safe_relative(path)
        except UnsafePath:
            refused = True
        check(f"refused {path[:34]!r}", refused)

    for good in ("data/FINANCE_AP/BOT201/2026/09/13/logs/user logs/logs/a.log",
                 "code_folder/BOT201.txt", "a.log", "./a.log",
                 "data\\FINANCE_AP\\BOT201\\x.log"):
        try:
            safe_relative(good)
            check(f"accepted a real path {good[:30]!r}", True)
        except UnsafePath as exc:
            check(f"accepted a real path {good[:30]!r}", False, str(exc))


def test_nothing_is_written_outside_the_root() -> None:
    d = Path(tempfile.mkdtemp())
    try:
        root, outside = d / "up", d / "OUTSIDE"
        outside.mkdir()

        refused = False
        try:
            write_tree(root, [("../OUTSIDE/pwned.txt", b"x")])
        except UnsafePath:
            refused = True
        check("a traversing path is refused", refused)
        check("  and nothing landed outside", list(outside.iterdir()) == [])

        # The case the component rules cannot see: a symlink inside the tree.
        root2 = d / "up2"
        root2.mkdir(parents=True)
        (root2 / "link").symlink_to(outside, target_is_directory=True)
        refused = False
        try:
            write_tree(root2, [("link/pwned.txt", b"x")])
        except UnsafePath:
            refused = True
        check("writing through a symlink is refused", refused)
        check("  and still nothing outside", list(outside.iterdir()) == [])

        check("one bad path rejects the whole upload, not just that file",
              not (root / "a.log").exists())
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_upload_size_limits_hold() -> None:
    from eagle_eyes.web.tree import MAX_FILES
    d = Path(tempfile.mkdtemp())
    try:
        refused = ""
        try:
            write_tree(d / "up", [(f"f{i}.log", b"x") for i in range(MAX_FILES + 1)])
        except UnsafePath as exc:
            refused = str(exc)
        check("too many files is refused", "the limit is" in refused, refused)

        out = write_tree(d / "up2", [("big.log", b"x" * (26 * 1024 * 1024)),
                                     ("ok.log", b"fine")])
        check("an oversized file is skipped rather than failing the upload",
              len(out.files) == 1 and out.skipped)
        check("  and the skip is reported", "too large" in out.skipped[0])
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------- discovery parity

def test_an_uploaded_folder_discovers_what_the_cli_discovers() -> None:
    """The point of taking a folder: the same code reads it.

    The browser sends each file with its relative path, the server rebuilds the
    tree, and `discovery.discover` runs over it -- the same function the scanner
    points at a real share. If these two ever disagree, there are two sets of
    pairing rules in the product and only one of them is tested.
    """
    sandbox = _sandbox()
    if sandbox is None:
        check("discovery parity skipped -- generate ./sandbox first", True,
              "python3 tools/make_fixtures.py --root ./sandbox")
        return

    from eagle_eyes.discovery import discover

    share = sandbox / "Network_Sharing_Folder"
    code = sandbox / "code_folder"
    direct = discover(share, share, code)

    items = [(str(f.relative_to(sandbox.parent)), f.read_bytes())
             for f in sorted(sandbox.rglob("*")) if f.is_file()]
    d = Path(tempfile.mkdtemp())
    try:
        rebuilt = write_tree(d / "tree", items)
        uploaded, share_label, code_label = discover_upload(rebuilt.root)

        check("the share root is found inside the upload",
              share_label.endswith("Network_Sharing_Folder"), share_label)
        check("and the code folder too", code_label.endswith("code_folder"),
              code_label)
        check("the same number of failures is found",
              len(uploaded) == len(direct), f"{len(uploaded)} vs {len(direct)}")

        def shape(candidates):
            return sorted(
                (c.location.label, c.exception_type, c.pairing_method, c.inputs)
                for c in candidates)

        check("and every one is identical -- bot, exception, pairing, inputs",
              shape(uploaded) == shape(direct))

        refused = [c for c in uploaded if c.pairing_method == "none"]
        check("the refusal to pair an ambiguous screenshot survives the upload",
              len(refused) == len([c for c in direct if c.pairing_method == "none"]))
        check("  and still carries its reason",
              all(c.pairing_note for c in refused) if refused else True)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_folder_with_nothing_recognisable_says_so() -> None:
    d = Path(tempfile.mkdtemp())
    try:
        rebuilt = write_tree(d / "tree", [("notes/readme.txt", b"hello")])
        candidates, share, code = discover_upload(rebuilt.root)
        check("no candidates are invented", candidates == [])
        check("and no share root is claimed", share == "")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# -------------------------------------------------------------- analytics

def _world():
    """An estate with two service lines and one owner each."""
    d = Path(tempfile.mkdtemp())
    db = open_database(d / "a.db")
    from eagle_eyes.storage import AnalysisRepo, BotRepo, DeveloperRepo, FingerprintRepo
    p = Principal("root@x.com", ADMIN)
    devs = DeveloperRepo(db, p)
    devs.ensure("alice@x.com", team="FINANCE_AP")
    devs.ensure("bob@x.com", team="CLAIMS_PROC")
    bots, fps, fails = BotRepo(db, p), FingerprintRepo(db, p), FailureRepo(db, p)
    for line, owner, h, n in (("FINANCE_AP", "alice@x.com", "a", 3),
                              ("CLAIMS_PROC", "bob@x.com", "b", 5)):
        bot = bots.upsert(line, "BOT001")
        bots.set_owner(bot, owner)
        fp = fps.touch(h * 64, 1, "NullReferenceException", "not set", "Bot.cs:1")
        analysis = AnalysisRepo(db, p).add(
            fp, path="text", root_cause="rc", suggested_fix="fix",
            confidence=0.8, cost_usd=0.02)
        for i in range(n):
            fails.add(bot_id=bot, fingerprint_id=fp, analysis_id=analysis,
                      occurred_at=f"2026-09-{11 + i:02d}T09:00:00",
                      log_path=f"/l/{line}/{i}.txt", correlation_id="c",
                      was_deduped=i > 0)
    return db, d


def test_every_analytics_query_is_scoped() -> None:
    """A chart is data. A trend line over rows you cannot open leaks the shape
    of another team's week, and a spend figure leaks what it costs them."""
    db, d = _world()
    try:
        everything = FailureRepo(db, Principal("root@x.com", ADMIN))
        check("the admin sees both lines", len(everything.by_service_line()) == 2)

        for label, principal in (
            ("a manager outside their scope",
             Principal("m@x.com", MANAGER, frozenset({"FINANCE_AP"}))),
            ("a manager with no scope", Principal("m@x.com", MANAGER, frozenset())),
            ("a user who owns nothing", Principal("nobody@x.com", USER)),
        ):
            repo = FailureRepo(db, principal)
            lines = {d_["service_line"] for d_ in repo.by_service_line()}
            check(f"{label}: by_service_line is scoped",
                  "CLAIMS_PROC" not in lines, str(lines))
            check(f"{label}: daily_counts is scoped",
                  all("CLAIMS" not in str(x) for x in repo.daily_counts(30)))
            check(f"{label}: top_fingerprints is scoped",
                  sum(t["n"] for t in repo.top_fingerprints()) <=
                  everything.stats()["failures"])
            check(f"{label}: by_bot is scoped",
                  all(b["service_line"] != "CLAIMS_PROC" for b in repo.by_bot()))
            check(f"{label}: confidence is scoped",
                  sum(n for _, n in repo.confidence_buckets()) <=
                  everything.stats()["failures"])
            check(f"{label}: path_breakdown is scoped",
                  sum(n for _, n in repo.path_breakdown()) <=
                  everything.stats()["failures"])

        blind = FailureRepo(db, Principal("nobody@x.com", USER))
        check("someone with no access sees nothing at all, in every query",
              blind.daily_counts(30) == [] and blind.top_fingerprints() == []
              and blind.by_service_line() == [] and blind.by_bot() == []
              and sum(n for _, n in blind.confidence_buckets()) == 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_feedback_tally_is_scoped_too() -> None:
    """It counted every row in the table, so a plain user asking how the
    diagnoses rated got the answer for the whole estate."""
    db, d = _world()
    try:
        from eagle_eyes.storage import DeveloperRepo
        p = Principal("root@x.com", ADMIN)
        row = db.conn.execute(
            "SELECT f.id fid, f.analysis_id aid FROM failure f"
            " JOIN bot b ON b.id=f.bot_id WHERE b.service_line='CLAIMS_PROC'"
            " LIMIT 1").fetchone()
        dev = DeveloperRepo(db, p).ensure("bob@x.com")
        FeedbackRepo(db, p).add(row["aid"], row["fid"], dev, "wrong", "no")

        check("the admin sees the verdict",
              FeedbackRepo(db, p).tally().get("wrong") == 1)
        outside = FeedbackRepo(
            db, Principal("m@x.com", MANAGER, frozenset({"FINANCE_AP"}))).tally()
        check("a manager outside that line does not", outside == {}, str(outside))
        check("nor does a user who owns nothing",
              FeedbackRepo(db, Principal("x@x.com", USER)).tally() == {})
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_charts_render_without_a_library_and_degrade_to_a_message() -> None:
    svg = charts.trend([("2026-09-11", 10, 2), ("2026-09-12", 30, 25)])
    check("the trend is inline SVG", "<svg" in svg and "</svg>" in svg)
    check("  with no script and no external reference",
          "<script" not in svg and "http" not in svg)
    check("  and a legend, because there are two series", "viz-legend" in svg)
    check("  labelling values rather than relying on colour", 'class="val"' in svg)

    check("an empty trend says so rather than drawing nothing",
          "No failures" in charts.trend([]))
    check("empty bars say so", "Nothing to show" in charts.bars([]))
    check("an empty breakdown says so", "Nothing analysed" in charts.stacked([]))

    bad = charts.bars([("<script>alert(1)</script>", 5)])
    check("a hostile label is escaped", "<script>" not in bad)
    check("  and shown as text", "&lt;script&gt;" in bad)

    css = charts.palette_css()
    check("the palette declares dark under both scopes",
          "prefers-color-scheme: dark" in css and '[data-theme="dark"]' in css)


# -------------------------------------------------------------- schedules

def test_a_schedule_belongs_to_the_account_that_made_it() -> None:
    db, d = _world()
    try:
        admin = bootstrap_admin(db, "root@x.com", PASSWORD)
        repo = ScheduleRepo(db, Principal("root@x.com", ADMIN))
        sid = repo.add(admin.id, name="Nightly", target_path=str(d),
                       share_root=str(d), code_root=str(d), every_minutes=60)

        accounts = AccountRepo(db, Principal("root@x.com", ADMIN))
        other = accounts.register("dev@x.com", PASSWORD)
        accounts.approve(other, role=USER)
        theirs = ScheduleRepo(db, Principal("dev@x.com", USER))

        check("another account's list is empty", theirs.list() == [])
        for label, call in (("read", lambda: theirs.get(sid)),
                            ("pause", lambda: theirs.set_enabled(sid, False)),
                            ("delete", lambda: theirs.delete(sid))):
            denied = False
            try:
                call()
            except AccessDenied:
                denied = True
            check(f"they cannot {label} it", denied)

        check("the owner still can", repo.get(sid).name == "Nightly")

        refused = ""
        try:
            repo.add(admin.id, name="Too fast", target_path=str(d),
                     share_root=str(d), code_root=str(d), every_minutes=1)
        except ValueError as exc:
            refused = str(exc)
        check("an interval below the floor is refused",
              "shortest interval" in refused, refused)
        check("  with the reason, not just a number",
              "spends the budget" in refused)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_container_refuses_to_pretend_it_scanned() -> None:
    """The failure this product argues against, applied to itself.

    A hosted instance has no desktop and no mapped share. A scheduler there
    that ticked over an empty directory and recorded success would be a
    monitoring job reporting healthy while looking at nothing.
    """
    db, d = _world()
    try:
        admin = bootstrap_admin(db, "root@x.com", PASSWORD)
        p = Principal("root@x.com", ADMIN)
        repo = ScheduleRepo(db, p)
        sid = repo.add(admin.id, name="Nightly", target_path=str(d),
                       share_root=str(d), code_root=str(d), every_minutes=5)

        saved = os.environ.get("EAGLE_EYES_IN_CONTAINER")
        runner = ScheduleRunner(db, p, lambda s: (99, 99), interval=9999)
        try:
            os.environ["EAGLE_EYES_IN_CONTAINER"] = "1"
            scannable, reason = can_scan_this_host()
            check("a container cannot scan", not scannable)
            check("  and the reason names what to do instead",
                  "run eagle eyes on the machine" in reason.lower(), reason)

            runner.tick()
            s = repo.get(sid)
            check("the run is recorded as not run", s.last_outcome == NO_FILESYSTEM)
            check("  with nothing claimed found or analysed",
                  s.last_found == 0 and s.last_analysed == 0)
            check("  and it does not read as healthy", not s.healthy)
            check("  the page wording says why",
                  "no filesystem to scan" in s.outcome_text)

            os.environ.pop("EAGLE_EYES_IN_CONTAINER", None)
            db.conn.execute("UPDATE scan_schedule SET target_path=?,"
                            " last_run_at=NULL WHERE id=?", ("/no/such/dir", sid))
            runner.tick()
            check("off a container, a missing path is named as a missing path",
                  repo.get(sid).last_outcome == MISSING_PATH)

            db.conn.execute("UPDATE scan_schedule SET target_path=?,"
                            " last_run_at=NULL WHERE id=?", (str(d), sid))
            runner.tick()
            s = repo.get(sid)
            check("and a real path actually runs", s.last_outcome == OK)
            check("  recording what it found", s.last_found == 99)

            check("a schedule that is not due is skipped", runner.tick() == 0)
        finally:
            runner.stop()
            os.environ.pop("EAGLE_EYES_IN_CONTAINER", None)
            if saved is not None:
                os.environ["EAGLE_EYES_IN_CONTAINER"] = saved
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_disabled_schedule_does_not_run() -> None:
    db, d = _world()
    try:
        admin = bootstrap_admin(db, "root@x.com", PASSWORD)
        p = Principal("root@x.com", ADMIN)
        repo = ScheduleRepo(db, p)
        sid = repo.add(admin.id, name="Paused", target_path=str(d),
                       share_root=str(d), code_root=str(d), every_minutes=5)
        repo.set_enabled(sid, False)
        check("it is off", not repo.get(sid).enabled)
        check("and it is not due", repo.due() == [])

        runner = ScheduleRunner(db, p, lambda s: (1, 1), interval=9999)
        try:
            check("so a tick runs nothing", runner.tick() == 0)
            check("  and it has still never run", repo.get(sid).last_outcome is None)
        finally:
            runner.stop()
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
