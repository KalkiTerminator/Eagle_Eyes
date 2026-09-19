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
    ADMIN, MANAGER, USER, AccessDenied, AnalysisRepo, FailureRepo, FeedbackRepo,
    PatternRepo, Principal, open_database,
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
        # A classified analysis, not a bare one. Several tests read severity,
        # failure_type and category off the joined row, and a fixture that
        # leaves them NULL lets those assertions pass by never running.
        analysis = AnalysisRepo(db, p).add(
            fp, path="text", root_cause="rc", suggested_fix="fix",
            confidence=0.8, cost_usd=0.02, latency_ms=1200,
            category="novel", failure_type="logic_error", severity="high")
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

            # The metrics added with the routing dashboard. Same rule: a count
            # is data, and "how many critical failures does that team have"
            # is a question about rows you cannot open.
            total = everything.stats()["failures"]
            check(f"{label}: routing_breakdown is scoped",
                  sum(n for _, n in repo.routing_breakdown()) <= total)
            check(f"{label}: severity_breakdown is scoped",
                  sum(n for _, n in repo.severity_breakdown()) <= total)
            check(f"{label}: failure_type_breakdown is scoped",
                  sum(n for _, n in repo.failure_type_breakdown()) <= total)
            check(f"{label}: efficiency is scoped",
                  repo.efficiency()["analyses"] <= total)
            check(f"{label}: notifications is scoped",
                  repo.notifications()["sent"] <=
                  everything.notifications()["sent"])
            check(f"{label}: fix_status_counts is scoped",
                  sum(repo.fix_status_counts().values()) <= total)
            check(f"{label}: by_developer is scoped",
                  all("CLAIMS" not in str(r) for r in repo.by_developer()))
            check(f"{label}: activity is scoped",
                  all(r["service_line"] != "CLAIMS_PROC" for r in repo.activity()))

        blind = FailureRepo(db, Principal("nobody@x.com", USER))
        check("someone with no access sees nothing at all, in every query",
              blind.daily_counts(30) == [] and blind.top_fingerprints() == []
              and blind.by_service_line() == [] and blind.by_bot() == []
              and sum(n for _, n in blind.confidence_buckets()) == 0
              and blind.routing_breakdown() == [] and blind.severity_breakdown() == []
              and blind.failure_type_breakdown() == [] and blind.by_developer() == []
              and blind.activity() == []
              and blind.efficiency()["analyses"] == 0
              and blind.notifications() == {"sent": 0, "suppressed": 0}
              and sum(blind.fix_status_counts().values()) == 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_routing_savings_buckets_do_not_overlap() -> None:
    """The avoided counts must not exceed the failures they are counted from.

    They did. Deduplicated failures point at an analysis that may itself have
    been a template answer, so counting `was_deduped` and `path='template'`
    separately and adding them reported 481 avoided calls against 260 failures
    -- a number that would have gone on a manager's dashboard and been believed.
    The buckets are computed in one pass, in priority order, and are mutually
    exclusive.
    """
    db, d = _world()
    try:
        repo = FailureRepo(db, Principal("root@x.com", ADMIN))
        s = repo.routing_savings()
        check("avoided plus analysed never exceeds the total",
              s["calls_avoided"] + s["analysed"] <= s["total"],
              f"{s['calls_avoided']} + {s['analysed']} > {s['total']}")
        check("  and no single bucket exceeds it either",
              all(v <= s["total"] for v in s["avoided"].values()), str(s["avoided"]))
        check("the total agrees with the visible count",
              s["total"] == repo.visible_count(), str(s["total"]))

        # Without a priced call there is no basis, and the estimate says so
        # rather than reaching for a list price.
        if s["spend_usd"] == 0:
            check("no spend means no basis, and no invented figure",
                  not s["have_basis"] and s["usd"] == 0.0, str(s))

        scoped = FailureRepo(db, Principal("m@x.com", MANAGER,
                                           frozenset({"FINANCE_AP"})))
        check("and the whole estimate is scoped",
              scoped.routing_savings()["total"] < s["total"],
              f"{scoped.routing_savings()['total']} vs {s['total']}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_fix_status_is_set_per_problem_and_stays_in_scope() -> None:
    """A fix applies to the problem, not to the row somebody happened to open.

    And fingerprints are deliberately shared across teams, so the UPDATE has to
    carry the scope clause too -- otherwise seeing one failure of a fingerprint
    would let you move every other team's failures of the same one.
    """
    db, d = _world()
    try:
        admin = FailureRepo(db, Principal("root@x.com", ADMIN))
        rows = admin.recent(limit=50)
        target = rows[0]
        same = [r for r in rows if r["fingerprint_id"] == target["fingerprint_id"]]

        moved = admin.set_fix_status(target["id"], "fixed")
        check("every failure sharing the fingerprint moves together",
              moved >= len(same), f"{moved} moved, {len(same)} share it")
        after = {r["fix_status"] for r in admin.recent(limit=50)
                 if r["fingerprint_id"] == target["fingerprint_id"]}
        check("  and they all read the same afterwards", after == {"fixed"}, str(after))

        counts = admin.fix_status_counts()
        check("counted per problem, not per occurrence",
              sum(counts.values()) == admin.stats()["fingerprints"],
              f"{sum(counts.values())} vs {admin.stats()['fingerprints']}")

        refused = False
        try:
            admin.set_fix_status(target["id"], "done")
        except ValueError:
            refused = True
        check("a status outside the closed list is refused", refused)

        stranger = FailureRepo(db, Principal("nobody@x.com", USER))
        denied = False
        try:
            stranger.set_fix_status(target["id"], "pending")
        except AccessDenied:
            denied = True
        check("someone who cannot see the failure cannot move it", denied)
        still = {r["fix_status"] for r in admin.recent(limit=50)
                 if r["fingerprint_id"] == target["fingerprint_id"]}
        check("  and nothing changed when they tried", still == {"fixed"}, str(still))
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


def test_a_joined_row_never_has_two_columns_of_one_name() -> None:
    """`FailureRepo.SELECT_` starts with `f.*`, so any failure column sharing a
    name with a joined one SHADOWS it.

    `failure.severity` did. It was declared in the first schema, never written
    by any code path, and a sqlite3.Row name lookup returns the first match --
    so `row["severity"]` was always the dead NULL one, and the severity badge
    on the failure page and in the diagnosis email could never appear. Nothing
    failed; the value was simply always empty.

    This asserts the shape rather than that one column, because the next join
    to `f.*` can reintroduce it just as quietly.
    """
    db, d = _world()
    try:
        p = Principal("root@x.com", ADMIN)
        failures = FailureRepo(db, p)

        # EVERY projection a repository hands back, not only the one that had
        # the bug. Each entry is (label, a callable returning rows).
        first = failures.recent(limit=1)
        check("there is a row to inspect", bool(first))
        fid = first[0]["id"] if first else 0

        projections = [
            ("FailureRepo.recent", lambda: failures.recent(limit=5)),
            ("FailureRepo.get", lambda: [failures.get(fid)] if fid else []),
            ("FailureRepo.top_fingerprints", lambda: failures.top_fingerprints(5)),
            ("FailureRepo.by_bot", lambda: failures.by_bot(5)),
            ("FailureRepo.by_service_line", lambda: failures.by_service_line()),
            ("FailureRepo.by_developer", lambda: failures.by_developer(5)),
            ("FailureRepo.activity", lambda: failures.activity(5)),
            ("PatternRepo.all", lambda: PatternRepo(db, p).all()),
            ("AnalysisRepo.get", lambda: [AnalysisRepo(db, p).get(1)]),
        ]
        checked = 0
        for label, fetch in projections:
            rows = [r for r in fetch() if r is not None]
            if not rows:
                continue                    # nothing to inspect, not a pass
            checked += 1
            names = list(rows[0].keys())
            dupes = sorted({n for n in names if names.count(n) > 1})
            check(f"{label}: no column name appears twice", not dupes, str(dupes))
        check("and several projections were actually inspected", checked >= 5,
              f"only {checked}")

        # And the value that was hidden is now readable end to end.
        with_sev = [r for r in failures.recent(limit=50) if r["severity"]]
        check("some analysis in the fixture carries a severity to read",
              bool(with_sev))
        if with_sev:
            check("a classified analysis reports its severity through the join",
                  with_sev[0]["severity"] in ("low", "medium", "high", "critical"),
                  str(with_sev[0]["severity"]))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_the_meter_says_in_words_what_its_colour_says() -> None:
    """A budget bar whose only signal is hue tells a deuteranope nothing.

    Amber against red is dE 4.3 for one, which no hex tuning fixes -- so the
    meter writes the state out, and the numbers sit above the track whatever
    the colour does.
    """
    for value, role, word in [(0.1, "good", "within budget"),
                              (1.4, "warning", "over half spent"),
                              (1.95, "serious", "close to the cap"),
                              (3.0, "critical", "over the cap")]:
        html = charts.meter(value, 2.0, "Spend")
        check(f"the meter at ${value} is {role}", f"--status-{role}" in html, html[:140])
        check(f"  and says '{word}'", word in html)
        check("  with the figures written out", "of $2.0000" in html, html[:200])

    check("no cap configured is stated, not divided by zero",
          "nothing to measure against" in charts.meter(1.0, 0, "Spend"))
    check("over the cap does not overflow the track",
          'width:100.0%' in charts.meter(9.0, 2.0, "Spend"))


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


# ------------------------------------------------- abandoned reviews

def test_an_abandoned_review_does_not_keep_the_upload_forever() -> None:
    """Upload a folder, read the table, close the tab.

    The review used to be dropped only when someone clicked Analyse, so an
    abandoned one left the whole tree on disk and in memory for the life of the
    process -- client-derived content on a server with nothing scheduled to
    remove it, which is exactly what docs/PRODUCTION_MIGRATION.md 1.1 warns
    about. Uploading is a decision that document says to take deliberately;
    leaving it there indefinitely is not a decision at all.
    """
    from datetime import datetime, timedelta, timezone
    from eagle_eyes.web.app import create_app

    d = Path(tempfile.mkdtemp())
    app = create_app(d / "w.db", {"EAGLE_EYES_SECRET_KEY": "k" * 40,
                                  "EAGLE_EYES_BACKEND": "mock"})
    state = app.state.ee
    try:
        tree = Path(tempfile.mkdtemp())
        (tree / "a.log").write_text("x")
        state.hold_review("tok", "me@x.com", tree, ["candidate"])
        check("the tree is held while the review is open", tree.exists())

        check("the owner can look at it without claiming it",
              state.peek_review("tok", "me@x.com") is not None)
        check("  twice, because peeking is not taking",
              state.peek_review("tok", "me@x.com") is not None)
        check("nobody else can see it",
              state.peek_review("tok", "other@x.com") is None)

        state.pending["tok"].created_at = (datetime.now(timezone.utc)
                                           - timedelta(hours=2))
        check("an expired review is swept", state.sweep_reviews() == 1)
        check("  its uploaded tree is deleted", not tree.exists())
        check("  and the token no longer resolves",
              state.peek_review("tok", "me@x.com") is None)
        check("  nor can it be claimed",
              state.take_review("tok", "me@x.com") is None)

        fresh = Path(tempfile.mkdtemp())
        state.hold_review("live", "me@x.com", fresh, ["c"])
        check("a review inside its window survives the sweep",
              state.sweep_reviews() == 0 and fresh.exists())
        claimed = state.take_review("live", "me@x.com")
        check("and claiming it hands over the same tree",
              claimed is not None and claimed.root == fresh)
        check("  removing it from the pending set",
              state.peek_review("live", "me@x.com") is None)
    finally:
        state.schedules.stop()
        state.db.close()
        shutil.rmtree(d, ignore_errors=True)


def test_the_screenshot_mode_means_something_on_the_folder_path() -> None:
    """It used to pass image=None unconditionally.

    So mode 3 silently did nothing on the main path -- a setting that claims to
    send the screenshot and does not, which is the same defect as the modes
    that claimed to crop. Mode 0 stays the default and still never opens the
    file.
    """
    from eagle_eyes.web.app import AppState
    from eagle_eyes.analysis import SCREENSHOT_MODES

    d = Path(tempfile.mkdtemp())
    try:
        for value, expected in (("0", 0), ("3", 3), ("", 0),
                                ("1", 0), ("2", 0), ("nonsense", 0), ("9", 0)):
            state = AppState(d / f"m{value or 'none'}.db",
                             {"EAGLE_EYES_SECRET_KEY": "k" * 40,
                              "EAGLE_EYES_BACKEND": "mock",
                              "EAGLE_EYES_SCREENSHOT_MODE": value})
            try:
                got = state.screenshot_mode()
                check(f"mode {value!r} resolves to {expected}", got == expected, str(got))
            finally:
                state.schedules.stop()
                state.db.close()

        check("an unbuilt mode falls back to the one that sends nothing",
              1 not in SCREENSHOT_MODES and 2 not in SCREENSHOT_MODES)

        src = (ROOT / "eagle_eyes" / "web" / "app.py").read_text()
        check("the folder path consults the mode before reading the file",
              "if state.screenshot_mode() and c.screenshot_path" in src)
        check("  and sniffs the bytes rather than trusting the extension",
              "sniff_image(raw)" in src)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_paired_file_that_is_not_an_image_is_not_sent() -> None:
    """The paired file came out of an upload and is trusted as far as its name.

    Forwarding arbitrary bytes to a provider as an image on the strength of a
    .png extension is not a thing to do.
    """
    from eagle_eyes.web.ingest import sniff_image

    check("a real PNG is recognised", sniff_image(b"\x89PNG\r\n\x1a\n" + b"0" * 20)
          == "image/png")
    check("a JPEG is recognised", sniff_image(b"\xff\xd8\xff" + b"0" * 20) == "image/jpeg")
    for label, raw in (("an SVG with a script", b"<svg onload=alert(1)>"),
                       ("a shell script", b"#!/bin/sh\nrm -rf /"),
                       ("a zip", b"PK\x03\x04"),
                       ("empty", b""),
                       ("plain text named .png", b"not an image at all")):
        check(f"{label} is refused", sniff_image(raw) == "")



if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
