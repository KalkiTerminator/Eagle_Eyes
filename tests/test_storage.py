"""Persistence: schema fidelity, repositories, the reuse gate, retention."""
from __future__ import annotations

import sqlite3
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
    SCHEMA_PATH, SCHEMA_VERSION, WatermarkRepo, now, run_retention,
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


def _v5_schema() -> str:
    """schema.sql as version 5 looked -- before the failure taxonomy.

    Derived by deleting the four taxonomy columns from the current file rather
    than pasting a copy, so that adding a fifth one without extending
    migration 6 makes this fail instead of quietly skipping it.
    """
    full = SCHEMA_PATH.read_text()
    start = full.index("    -- The failure taxonomy.")
    end = full.index("    recommendations   TEXT,\n") + len("    recommendations   TEXT,\n")
    return full[:start] + full[end:]


def _v1_schema() -> str:
    """schema.sql as version 1 actually looked.

    Derived from the current file rather than pasted, so a new table added to
    schema.sql without a migration makes the equivalence test fail loudly
    instead of the two quietly describing different databases.

    It starts from the v5 shape because v1 had no taxonomy columns either, and
    migration 4 rebuilds `analysis` with `INSERT ... SELECT *`. Deriving v1
    from the *current* file gave that SELECT four columns the v3 table it was
    written against never had, and it failed with a column count mismatch --
    the test complaining, correctly, that the derivation was a fiction.
    """
    full = _v5_schema()
    v1 = full.split("-- ---------- accounts ----------")[0]
    v1 = v1.replace("CHECK (processing_mode IN (0, 3))",
                    "CHECK (processing_mode BETWEEN 0 AND 3)")
    v1 = v1.replace(
        "pairing_method       TEXT CHECK (pairing_method IN\n"
        "                             ('log_path','timestamp','none','uploaded')),",
        "pairing_method       TEXT CHECK (pairing_method IN "
        "('log_path','timestamp','none')),")
    return v1


def test_migration_lands_where_a_fresh_schema_does() -> None:
    """A migrated database must be indistinguishable from a freshly created one.

    Two ways to build the same schema is two things to keep in step, and nobody
    notices when they drift -- the old install just behaves slightly differently
    forever. So this builds a v1 database the way v1 actually looked, migrates
    it, and compares every table, index and trigger against schema.sql.
    """
    d = Path(tempfile.mkdtemp())
    try:
        con = sqlite3.connect(str(d / "old.db"))
        con.executescript(_v1_schema())
        # A row recording a protection that was never applied -- mode 2 claimed
        # crop and OCR-redaction, and no such code ever existed.
        con.execute("INSERT INTO team(name) VALUES ('ops')")
        con.execute("INSERT INTO developer(email, display_name, team_id)"
                    " VALUES ('d@x','D',1)")
        con.execute("INSERT INTO bot(service_line, bot_number) VALUES ('SL','B1')")
        con.execute("INSERT INTO fingerprint(hash, version, exception_type,"
                    " normalized_message, code_location, expires_at)"
                    " VALUES (?,1,'E','m','l.cs:1','2030-01-01')", ("a" * 64,))
        con.execute("INSERT INTO failure(bot_id, fingerprint_id, occurred_at,"
                    " log_path, correlation_id, content_expires_at, expires_at)"
                    " VALUES (1,1,'2026-01-01','/l.txt','c','2030-01-01','2030-01-01')")
        con.execute("INSERT INTO screenshot(failure_id, unc_path, processing_mode,"
                    " was_cropped, was_redacted) VALUES (1,'/s.png',2,1,1)")
        con.execute("PRAGMA user_version = 1")
        con.commit()
        con.close()

        migrated = Database(d / "old.db")
        fresh = Database(d / "new.db")

        v = migrated.conn.execute("PRAGMA user_version").fetchone()[0]
        check("the migration stamps the new version", v == SCHEMA_VERSION, str(v))

        def shape(db):
            out = {}
            for r in db.conn.execute(
                    "SELECT type, name, sql FROM sqlite_master"
                    " WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"):
                sql = re.sub(r"--[^\n]*", "", r["sql"] or "")       # comments differ
                sql = re.sub(r'"(\w+)"', r"\1", sql)                 # RENAME quotes the name
                out[(r["type"], r["name"])] = re.sub(r"\s+", " ", sql).strip()
            return out

        a, b = shape(migrated), shape(fresh)
        check("the same set of objects exists", set(a) == set(b),
              str(set(a) ^ set(b)))
        differing = sorted(k for k in set(a) & set(b) if a[k] != b[k])
        check("and each is defined identically", not differing, str(differing))

        row = migrated.conn.execute(
            "SELECT processing_mode, was_cropped, was_redacted FROM screenshot"
        ).fetchone()
        check("a mode 2 row is rewritten to what actually happened to it",
              tuple(row) == (3, 0, 0), str(tuple(row)))
        kept = migrated.conn.execute(
            "SELECT pairing_method FROM failure").fetchone()["pairing_method"]
        check("and a row the scanner wrote is left alone", kept is None, str(kept))

        # Rebuilding `failure` drops it, and `screenshot` cascades off it. With
        # foreign keys enabled during a migration that silently deleted every
        # screenshot row -- a data loss nothing would have reported.
        n = migrated.conn.execute("SELECT COUNT(*) n FROM screenshot").fetchone()["n"]
        check("rebuilding a parent table does not cascade its children away",
              n == 1, str(n))
        check("and no foreign key is left dangling",
              migrated.conn.execute("PRAGMA foreign_key_check").fetchall() == [])
        check("  with enforcement switched back on afterwards",
              migrated.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1)
        refused = False
        try:
            migrated.conn.execute(
                "INSERT INTO screenshot(failure_id, unc_path, processing_mode)"
                " VALUES (99,'/x.png',1)")
        except sqlite3.IntegrityError:
            refused = True
        check("and the upgraded table refuses a new mode 1 row", refused)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_migration_6_lands_where_a_fresh_schema_does() -> None:
    """The taxonomy migration, checked the way 2-5 are: object by object.

    And the part that matters more than the shape -- a diagnosis stored before
    the taxonomy existed still has its root cause afterwards, with the four new
    fields NULL. NULL is the honest value: nobody classified that failure.
    """
    d = Path(tempfile.mkdtemp())
    try:
        v5 = _v5_schema()
        check("the derived v5 schema really lacks the taxonomy",
              "failure_type" not in v5 and "affected_function" not in v5)

        con = sqlite3.connect(str(d / "old.db"))
        con.executescript(v5)
        con.execute("INSERT INTO bot(service_line, bot_number) VALUES ('SL','B1')")
        con.execute("INSERT INTO fingerprint(hash, version, exception_type,"
                    " normalized_message, code_location, expires_at)"
                    " VALUES (?,1,'E','m','l.cs:1','2030-01-01')", ("b" * 64,))
        con.execute("INSERT INTO analysis(fingerprint_id, path, root_cause,"
                    " suggested_fix, confidence, expires_at)"
                    " VALUES (1,'text','old cause','old fix',0.7,'2030-01-01')")
        con.execute("PRAGMA user_version = 5")
        con.commit()
        con.close()

        migrated = Database(d / "old.db")
        fresh = Database(d / "new.db")

        v = migrated.conn.execute("PRAGMA user_version").fetchone()[0]
        check("migration 6 stamps the new version", v == SCHEMA_VERSION, str(v))

        def shape(db):
            out = {}
            for r in db.conn.execute(
                    "SELECT type, name, sql FROM sqlite_master"
                    " WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"):
                sql = re.sub(r"--[^\n]*", "", r["sql"] or "")
                sql = re.sub(r'"(\w+)"', r"\1", sql)
                out[(r["type"], r["name"])] = re.sub(r"\s+", " ", sql).strip()
            return out

        a, b = shape(migrated), shape(fresh)
        check("migration 6 leaves the same set of objects", set(a) == set(b),
              str(set(a) ^ set(b)))
        differing = sorted(k for k in set(a) & set(b) if a[k] != b[k])
        check("  and each is defined identically", not differing, str(differing))

        row = migrated.conn.execute("SELECT * FROM analysis").fetchone()
        check("the diagnosis survives the rebuild",
              (row["root_cause"], row["suggested_fix"]) == ("old cause", "old fix"),
              str(tuple(row)[:6]))
        check("  with the taxonomy NULL rather than invented",
              row["failure_type"] is None and row["severity"] is None
              and row["affected_function"] is None and row["recommendations"] is None)

        check("and no foreign key is left dangling",
              migrated.conn.execute("PRAGMA foreign_key_check").fetchall() == [])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_an_unclassified_analysis_is_storable_and_readable() -> None:
    """The degradation path: a model that returns no taxonomy, stored and read.

    `add()` takes "" for all four and must write NULL, because the column CHECK
    accepts NULL or a member of the closed list and would refuse "". Getting
    this wrong makes every template answer and every older model unstorable.
    """
    db, d = _db()
    try:
        _bot, fp = _seed(db)
        ar = AnalysisRepo(db, P)
        plain = ar.add(fp, path="text", root_cause="rc", suggested_fix="sf",
                       confidence=0.6)
        full = ar.add(fp, path="text", root_cause="rc2", suggested_fix="sf2",
                      confidence=0.9, failure_type="selector", severity="high",
                      affected_function="Post", recommendations="add a wait")

        a = ar.get(plain)
        check("an analysis with no taxonomy stores", a is not None)
        check("  and reads back as NULL, not as an empty string",
              a["failure_type"] is None and a["severity"] is None
              and a["affected_function"] is None and a["recommendations"] is None)

        b = ar.get(full)
        check("a classified analysis keeps every field",
              (b["failure_type"], b["severity"], b["affected_function"],
               b["recommendations"]) == ("selector", "high", "Post", "add a wait"),
              str((b["failure_type"], b["severity"])))

        refused = False
        try:
            db.conn.execute(
                "INSERT INTO analysis(fingerprint_id, path, confidence, expires_at)"
                " VALUES (?,'text',0.5,'2030-01-01')", (fp,))
            db.conn.execute("UPDATE analysis SET severity='catastrophic'"
                            " WHERE id=(SELECT MAX(id) FROM analysis)")
        except sqlite3.IntegrityError:
            refused = True
        check("a severity outside the closed list is refused by the database",
              refused)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_schema_gap_is_refused_not_guessed() -> None:
    """No migration for a version means stop, not carry on and hope."""
    db, d = _db()
    try:
        db.conn.execute("PRAGMA user_version = 1")
        import eagle_eyes.storage as st
        saved = st.MIGRATIONS
        st.MIGRATIONS = {}
        try:
            db.migrate()
            check("a missing migration is refused", False)
        except RuntimeError as e:
            check("a missing migration is refused", "no migration" in str(e))
            check("  and it names both versions", "1" in str(e) and "2" in str(e))
        finally:
            st.MIGRATIONS = saved
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_migrate_is_idempotent() -> None:
    db, d = _db()
    try:
        v = db.conn.execute("PRAGMA user_version").fetchone()[0]
        check("schema version is stamped", v == SCHEMA_VERSION, str(v))
        db.migrate()
        db.migrate()
        check("re-running migrate is harmless", True)
        n = db.conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
            " AND name NOT LIKE 'sqlite_%'").fetchone()[0]
        check("all tables created", n == 16, str(n))
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
