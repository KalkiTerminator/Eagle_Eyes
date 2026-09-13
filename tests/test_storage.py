"""Persistence: schema fidelity, repositories, the reuse gate, retention."""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.storage import (  # noqa: E402
    ADMIN, MANAGER, USER, AccessDenied, AnalysisRepo, BotRepo, Database,
    FailureRepo, FeedbackRepo, FingerprintRepo, Principal, Repository,
    SCHEMA_PATH, WatermarkRepo, now, run_retention,
)

ROOT = Path(__file__).resolve().parents[1]
from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check


def _db() -> tuple[Database, Path]:
    d = Path(tempfile.mkdtemp())
    return Database(d / "t.db"), d


P = Principal(actor="tester", role=ADMIN)


def _seed(db: Database, p: Principal = P) -> tuple[int, int]:
    bot = BotRepo(db, p).upsert("FINANCE_AP", "BOT201", "AP.cs.txt")
    fp = FingerprintRepo(db, p).touch("a" * 64, 1, "X.Y.Z", "msg", "AP.cs:Post")
    return bot, fp


# ------------------------------------------------------------------ schema

def test_schema_matches_the_doc() -> None:
    """The doc embeds schema.sql verbatim. Drift between them is a silent lie."""
    doc = (ROOT / "docs" / "DATA_MODEL.md").read_text()
    blocks = re.findall(r"```sql\n(.*?)```", doc, re.S)
    check("the doc has exactly one DDL block", len(blocks) == 1, str(len(blocks)))
    in_file = SCHEMA_PATH.read_text()
    ddl_start = in_file.index("PRAGMA journal_mode")
    check("docs/DATA_MODEL.md section 4 matches eagle_eyes/schema.sql",
          blocks[0].strip() == in_file[ddl_start:].strip())


def test_migrate_is_idempotent() -> None:
    db, d = _db()
    try:
        v = db.conn.execute("PRAGMA user_version").fetchone()[0]
        check("schema version is stamped", v == 1, str(v))
        db.migrate()
        db.migrate()
        check("re-running migrate is harmless", True)
        n = db.conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
            " AND name NOT LIKE 'sqlite_%'").fetchone()[0]
        check("all tables created", n == 12, str(n))
        db.conn.execute("PRAGMA user_version = 99")
        try:
            db.migrate()
            check("a newer database is refused", False)
        except RuntimeError as e:
            check("a newer database is refused", "newer version" in str(e))
    finally:
        db.close(); shutil.rmtree(d)


# ------------------------------------------------------------- principals

def test_a_repository_cannot_exist_without_a_principal() -> None:
    db, d = _db()
    try:
        for bad in (None, "admin", 1):
            try:
                Repository(db, bad)  # type: ignore[arg-type]
                check(f"rejects principal={bad!r}", False)
            except TypeError as e:
                check(f"rejects principal={bad!r}", "needs a Principal" in str(e))
        check("accepts a real principal", Repository(db, P) is not None)
    finally:
        db.close(); shutil.rmtree(d)


def test_principal_scoping() -> None:
    admin = Principal("a", ADMIN)
    mgr = Principal("m", MANAGER, frozenset({"FINANCE_AP"}))
    usr = Principal("u", USER)
    check("admin sees every team", admin.may_see_team("ANYTHING"))
    check("manager sees their own team", mgr.may_see_team("FINANCE_AP"))
    check("manager does not see another team", not mgr.may_see_team("CLAIMS_PROC"))
    check("a plain user has no team scope", not usr.may_see_team("FINANCE_AP"))
    check("local install resolves to admin", Principal.local().is_admin)


# ----------------------------------------------------------- repositories

def test_bots_and_fingerprints() -> None:
    db, d = _db()
    try:
        repo = BotRepo(db, P)
        a = repo.upsert("FINANCE_AP", "BOT201")
        b = repo.upsert("FINANCE_AP", "BOT201", "AP.cs.txt")
        check("upsert is stable for the same bot", a == b)
        c = repo.upsert("CLAIMS_PROC", "BOT201")
        check("the same bot number in another service line is a different bot", c != a)

        fr = FingerprintRepo(db, P)
        f1 = fr.touch("b" * 64, 1, "X", "m", "loc")
        f2 = fr.touch("b" * 64, 1, "X", "m", "loc")
        check("a repeat sighting reuses the row", f1 == f2)
        n = db.conn.execute("SELECT occurrence_count FROM fingerprint WHERE id=?",
                            (f1,)).fetchone()[0]
        check("and increments the count", n == 2, str(n))
        check("a different algorithm version is a different row",
              fr.touch("b" * 64, 2, "X", "m", "loc") != f1)
    finally:
        db.close(); shutil.rmtree(d)


def test_rescan_is_a_no_op() -> None:
    db, d = _db()
    try:
        bot, fp = _seed(db)
        fr = FailureRepo(db, P)
        first = fr.add(bot_id=bot, fingerprint_id=fp, occurred_at=now(),
                       log_path=r"\\vm\share\a.log")
        again = fr.add(bot_id=bot, fingerprint_id=fp, occurred_at=now(),
                       log_path=r"\\vm\share\a.log")
        check("the first ingest succeeds", first is not None)
        check("re-ingesting the same log is a no-op, not an error", again is None)
        n = db.conn.execute("SELECT COUNT(*) FROM failure").fetchone()[0]
        check("only one row exists", n == 1, str(n))
    finally:
        db.close(); shutil.rmtree(d)


def test_watermark_enables_catch_up() -> None:
    db, d = _db()
    try:
        w = WatermarkRepo(db, P)
        check("an unseen file is unseen", not w.seen("/x/a.log", "m1", 100))
        w.mark("/x/a.log", "m1", 100)
        check("a marked file is seen", w.seen("/x/a.log", "m1", 100))
        check("a changed mtime means re-read", not w.seen("/x/a.log", "m2", 100))
        check("a changed size means re-read", not w.seen("/x/a.log", "m1", 200))
        w.mark("/x/a.log", "m2", 100)
        check("marking again replaces rather than duplicates", w.count() == 1)
    finally:
        db.close(); shutil.rmtree(d)


# ------------------------------------------------------------- reuse gate

def test_reuse_gate() -> None:
    db, d = _db()
    try:
        bot, fp = _seed(db)
        ar, fr = AnalysisRepo(db, P), FingerprintRepo(db, P)
        aid = ar.add(fp, path="text", root_cause="rc", suggested_fix="fix",
                     confidence=0.8, code_mtime="2026-09-01T00:00:00")

        check("a fresh analysis is reusable",
              fr.recent_analysis(fp, code_mtime="2026-09-01T00:00:00") is not None)
        check("changed code blocks reuse",
              fr.recent_analysis(fp, code_mtime="2026-09-20T00:00:00") is None)

        ar.supersede(aid)
        check("a superseded analysis is not reused",
              fr.recent_analysis(fp, code_mtime="2026-09-01T00:00:00") is None)

        aid2 = ar.add(fp, path="text", root_cause="rc2", suggested_fix="f2",
                      confidence=0.9, code_mtime="2026-09-01T00:00:00")
        fid = FailureRepo(db, P).add(bot_id=bot, fingerprint_id=fp,
                                     occurred_at=now(), log_path="/p/1.log",
                                     analysis_id=aid2)
        db.conn.execute("INSERT INTO team(name) VALUES ('T')")
        db.conn.execute("INSERT INTO developer(email, display_name, team_id)"
                        " VALUES ('d@x','D',1)")
        FeedbackRepo(db, P).add(aid2, fid, 1, "wrong", "not the cause")
        check("an analysis marked wrong is never served again",
              fr.recent_analysis(fp, code_mtime="2026-09-01T00:00:00") is None)
        check("feedback is tallied", FeedbackRepo(db, P).tally() == {"wrong": 1})
    finally:
        db.close(); shutil.rmtree(d)


# ----------------------------------------------------------------- audit

def test_audit_is_written_and_append_only() -> None:
    db, d = _db()
    try:
        _, fp = _seed(db)
        AnalysisRepo(db, P).add(fp, path="text", root_cause="rc",
                                suggested_fix="f", confidence=0.5)
        rows = db.conn.execute("SELECT * FROM audit_event").fetchall()
        check("creating an analysis is audited", len(rows) == 1)
        check("the actor is recorded", rows[0]["actor"] == "tester")
        check("the role is recorded", rows[0]["actor_role"] == ADMIN)
        for sql in ("UPDATE audit_event SET actor='x'", "DELETE FROM audit_event"):
            try:
                db.conn.execute(sql)
                check(f"{sql.split()[0]} on audit_event is refused", False)
            except Exception as e:
                check(f"{sql.split()[0]} on audit_event is refused",
                      "append-only" in str(e))
    finally:
        db.close(); shutil.rmtree(d)


# ------------------------------------------------------------- retention

def test_retention() -> None:
    db, d = _db()
    try:
        bot, fp = _seed(db)
        past = (datetime.now(timezone.utc).replace(tzinfo=None)
                - timedelta(days=1)).isoformat(timespec="seconds")
        fid = FailureRepo(db, P).add(bot_id=bot, fingerprint_id=fp, occurred_at=now(),
                                     log_path="/p/old.log", log_sanitized="secret log",
                                     code_snapshot="code")
        db.conn.execute("UPDATE failure SET content_expires_at=? WHERE id=?", (past, fid))

        r = run_retention(db, P)
        check("expired content is nulled", r.content_nulled == 1, r.summary())
        row = db.conn.execute("SELECT log_sanitized, code_snapshot, fingerprint_id"
                              " FROM failure WHERE id=?", (fid,)).fetchone()
        check("the log text is gone", row["log_sanitized"] is None)
        check("the code snapshot is gone", row["code_snapshot"] is None)
        check("but the row survives for trend analysis", row["fingerprint_id"] == fp)

        r2 = run_retention(db, P)
        check("re-running is safe and finds nothing new", r2.content_nulled == 0)
        check("retention is audited",
              db.conn.execute("SELECT COUNT(*) FROM audit_event WHERE action='retention'"
                              ).fetchone()[0] == 2)

        try:
            run_retention(db, Principal("u", USER))
            check("a non-admin cannot run retention", False)
        except AccessDenied:
            check("a non-admin cannot run retention", True)
    finally:
        db.close(); shutil.rmtree(d)


def test_stats() -> None:
    db, d = _db()
    try:
        bot, fp = _seed(db)
        fr = FailureRepo(db, P)
        for i in range(5):
            fr.add(bot_id=bot, fingerprint_id=fp, occurred_at=now(),
                   log_path=f"/p/{i}.log", was_deduped=(i > 0))
        s = fr.stats()
        check("failures counted", s["failures"] == 5)
        check("dedup rate computed", abs(s["dedup_rate"] - 0.8) < 1e-9, str(s["dedup_rate"]))
        check("recent() returns them", len(fr.recent()) == 5)
    finally:
        db.close(); shutil.rmtree(d)


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
