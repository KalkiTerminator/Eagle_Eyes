"""The PostgreSQL port, checked against a real server when one is available.

Two kinds of check here, and the split matters:

  * WITHOUT a server -- the schemas are compared to each other and to the code.
    A table in one dialect and not the other, or a CHECK constraint that has
    drifted from the enum it is supposed to mirror, is caught with nothing
    installed and nothing running. These run everywhere, always.

  * WITH a server (EAGLE_EYES_TEST_DSN) -- the behaviour. tests/test_rbac.py and
    tests/test_web.py already run their whole suites against PostgreSQL when
    that variable is set, which is where the real coverage is; what is left here
    is the dialect seam itself.

The reason for running the suites twice rather than trusting the port: `WHERE 1`
is valid SQLite and a type error in PostgreSQL, and the clause it appeared in
was the one that makes an empty manager scope mean no rows. A port that is only
exercised on the development dialect is a port nobody has tested.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.analysis import Path_  # noqa: E402
from eagle_eyes.storage import SCHEMA_PATH  # noqa: E402
from eagle_eyes.storage_pg import (  # noqa: E402
    NO_ID_TABLES, Row, _redact, adapt, normalise, translate,
)

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check

PG_SCHEMA = Path(__file__).resolve().parents[1] / "eagle_eyes" / "schema_pg.sql"
DSN = os.environ.get("EAGLE_EYES_TEST_DSN", "").strip()


def _ddl(sql: str) -> str:
    """The statements with the commentary removed.

    Needed because this file argues for its choices in comments -- "NUMERIC for
    money, REAL is binary floating point", "hash TEXT, NOT CHAR(64)" -- and a
    test that greps the whole file finds the prose and passes or fails on it.
    Asserting against the comment that says what should be true is worse than
    having no test, because it reads exactly like one that works.
    """
    return re.sub(r"--[^\n]*", "", sql)


def _tables(sql: str) -> set[str]:
    return set(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)", sql, re.I))


def _columns(sql: str, table: str) -> set[str]:
    m = re.search(r"CREATE TABLE (?:IF NOT EXISTS )?" + table + r"\s*\((.*?)\n\);",
                  sql, re.S | re.I)
    if not m:
        return set()
    cols = set()
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("--"):
            continue
        word = line.split()[0]
        if word.upper() in {"UNIQUE", "PRIMARY", "CHECK", "FOREIGN", "CONSTRAINT"}:
            continue
        cols.add(word.strip(","))
    return cols


# ------------------------------------------------- schemas, no server needed

def test_both_dialects_describe_the_same_model() -> None:
    lite, pg = SCHEMA_PATH.read_text(), PG_SCHEMA.read_text()
    a, b = _tables(lite), _tables(pg)
    check("the same tables exist in both", a == b, str(a ^ b))

    for table in sorted(a & b):
        ca, cb = _columns(lite, table), _columns(pg, table)
        check(f"{table} has the same columns in both", ca == cb, str(ca ^ cb))


def test_money_is_not_binary_floating_point_in_postgres() -> None:
    """REAL is acceptable in SQLite and wrong here.

    cost_usd is summed over every analysis to decide whether a budget cap has
    been reached. Binary floating point drifts, and the number it drifts in is
    the one that decides whether more money gets spent.
    """
    pg = _ddl(PG_SCHEMA.read_text())
    m = re.search(r"cost_usd\s+(\S+)", pg)
    check("cost_usd is NUMERIC", bool(m) and m.group(1).upper().startswith("NUMERIC"),
          m.group(1) if m else "absent")
    m = re.search(r"confidence\s+(\S+)", pg)
    check("confidence is NUMERIC too", bool(m) and m.group(1).upper().startswith("NUMERIC"),
          m.group(1) if m else "absent")
    check("and no column is declared REAL",
          not re.search(r"\bREAL\b", pg, re.I),
          str(re.findall(r"^.*\bREAL\b.*$", pg, re.I | re.M)))


def test_the_hash_column_is_text_not_char() -> None:
    """CHAR(64) takes a different operator class and the dedup lookup falls to a
    sequential scan. Verified and written up in DATA_MODEL section 7.2."""
    pg = _ddl(PG_SCHEMA.read_text())
    check("hash is TEXT", bool(re.search(r"hash\s+TEXT NOT NULL", pg)))
    check("with the length as a CHECK", "char_length(hash) = 64" in pg)
    check("and never CHAR(n) or VARCHAR(n)",
          not re.search(r"\b(VAR)?CHAR\s*\(", pg, re.I),
          str(re.findall(r"^.*\b(?:VAR)?CHAR\s*\(.*$", pg, re.I | re.M)))


def test_the_path_check_matches_the_enum() -> None:
    """It listed four of six, so a deduplicated or skipped analysis could not be
    stored at all -- the insert failed the CHECK. Derived from the enum now."""
    expected = {p.value for p in Path_}
    for label, sql in (("sqlite", SCHEMA_PATH.read_text()),
                       ("postgres", PG_SCHEMA.read_text())):
        m = re.search(r"path\s+TEXT NOT NULL CHECK \(path IN\s*\n?\s*\((.*?)\)\)",
                      sql, re.S)
        listed = set(re.findall(r"'(\w+)'", m.group(1))) if m else set()
        check(f"{label} allows every path the engine can produce",
              listed == expected, f"missing {expected - listed}, extra {listed - expected}")


def test_append_only_audit_is_enforced_in_both() -> None:
    lite, pg = SCHEMA_PATH.read_text(), PG_SCHEMA.read_text()
    check("sqlite refuses UPDATE with a trigger", "audit_no_update" in lite)
    check("sqlite refuses DELETE with a trigger", "audit_no_delete" in lite)
    check("postgres refuses UPDATE too", "audit_no_update" in pg)
    check("postgres refuses DELETE too", "audit_no_delete" in pg)
    check("  with a trigger rather than a REVOKE, which an owner can ignore",
          "cannot be revoked from itself" in pg)


# ------------------------------------------------------------ the seam itself

def test_statements_are_translated() -> None:
    check("placeholders become %s",
          translate("SELECT * FROM bot WHERE id=?") == "SELECT * FROM bot WHERE id=%s")
    check("an insert asks for the new id",
          translate("INSERT INTO bot(a) VALUES (?)").endswith("RETURNING id"))
    check("a table with no id column does not",
          "RETURNING" not in translate("INSERT INTO account_scope(a) VALUES (?)"))
    check("  and that list is not empty", NO_ID_TABLES)
    check("an existing RETURNING is left alone",
          translate("INSERT INTO bot(a) VALUES (?) RETURNING id").count("RETURNING") == 1)
    check("a select is not given one",
          "RETURNING" not in translate("SELECT 1"))

    refused = ""
    try:
        translate("INSERT OR REPLACE INTO feedback(a) VALUES (?)")
    except ValueError as e:
        refused = str(e)
    check("INSERT OR REPLACE is refused rather than guessed at",
          "has no Postgres equivalent" in refused, refused)
    check("  because the conflict target would have to be invented",
          "conflict target" in refused)


def test_rows_are_normalised_to_what_sqlite_returns() -> None:
    from datetime import datetime, timezone
    from decimal import Decimal

    check("a boolean becomes 0/1", normalise(True) == 1 and normalise(False) == 0)
    check("a Decimal becomes a float",
          normalise(Decimal("0.0123")) == 0.0123
          and isinstance(normalise(Decimal("1")), float))
    check("an aware timestamp becomes the string storage.now() writes",
          normalise(datetime(2026, 9, 11, 9, 0, tzinfo=timezone.utc))
          == "2026-09-11T09:00:00")
    check("a naive one is left in UTC",
          normalise(datetime(2026, 9, 11, 9, 0)) == "2026-09-11T09:00:00")
    check("a text array becomes the JSON the SQLite column holds",
          normalise(["log", "code"]) == '["log", "code"]')
    check("text is untouched", normalise("hello") == "hello")
    check("None is untouched", normalise(None) is None)

    row = Row({"id": 1, "name": "x"}, ("id", "name"))
    check("a row indexes by name", row["name"] == "x")
    check("  and by position, as sqlite3.Row does", row[0] == 1)
    check("  and lists its keys", row.keys() == ["id", "name"])


def test_a_dsn_is_never_printed_with_its_password() -> None:
    check("the password is masked",
          _redact("postgresql://user:hunter2@host:5432/db")
          == "postgresql://user:***@host:5432/db")
    check("and does not survive anywhere in the string",
          "hunter2" not in _redact("postgresql://user:hunter2@host/db"))
    check("a dsn without one is unchanged",
          _redact("postgresql://host/db") == "postgresql://host/db")


def test_the_url_scheme_platforms_emit_is_accepted() -> None:
    """Several platforms still hand out postgres://, which psycopg rejects with
    an error that says nothing useful about why."""
    import eagle_eyes.storage as st
    src = Path(st.__file__).read_text()
    check("open_database rewrites postgres:// to postgresql://",
          'dsn.startswith("postgres://")' in src)


# ----------------------------------------------------------- against a server

def test_against_a_real_server() -> None:
    if not DSN:
        check("live PostgreSQL checks skipped -- set EAGLE_EYES_TEST_DSN", True,
              "e.g. postgresql://user@host/db")
        return

    import psycopg
    from eagle_eyes.storage_pg import PostgresDatabase
    from eagle_eyes.storage import (
        AnalysisRepo, BotRepo, FingerprintRepo, Principal, ADMIN)

    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DROP SCHEMA public CASCADE")
        c.execute("CREATE SCHEMA public")

    db = PostgresDatabase(DSN, max_size=4)
    try:
        p = Principal("root@x.com", ADMIN)
        check("the schema applies to an empty database", True)
        db.migrate()
        check("and applying it twice is harmless", True)

        n = db.conn.execute(
            "SELECT COUNT(*) n FROM information_schema.tables"
            " WHERE table_schema='public'").fetchone()["n"]
        check("every table exists", n == 16, str(n))

        fp = FingerprintRepo(db, p).touch("a" * 64, 1, "E", "m", "l.cs:1")
        for path in sorted({x.value for x in Path_}):
            AnalysisRepo(db, p).add(fp, path=path, root_cause="r",
                                    suggested_fix="f", confidence=0.5,
                                    cost_usd=0.01, inputs_used=("log",))
        check("every analysis path the engine produces can be stored", True)

        refused = False
        try:
            db.conn.execute(
                "INSERT INTO analysis(fingerprint_id, path, expires_at)"
                " VALUES (?,?,?)", (fp, "nonsense", "2030-01-01"))
        except psycopg.errors.CheckViolation:
            refused = True
        check("and a path the engine cannot produce is refused", refused)

        refused = False
        try:
            db.conn.execute("UPDATE audit_event SET actor='x'")
        except psycopg.Error:
            refused = True
        check("the audit log refuses UPDATE even as the owner", refused)

        refused = False
        try:
            db.conn.execute("DELETE FROM audit_event")
        except psycopg.Error:
            refused = True
        check("and refuses DELETE", refused)

        # Money must not drift. 1000 charges of $0.001 is exactly $1.
        for _ in range(1000):
            AnalysisRepo(db, p).add(fp, path="text", root_cause="r",
                                    suggested_fix="f", confidence=0.5,
                                    cost_usd=0.001)
        total = db.conn.execute(
            "SELECT SUM(cost_usd) s FROM analysis WHERE cost_usd = 0.001"
        ).fetchone()["s"]
        check("a thousand small charges sum exactly", total == 1.0, repr(total))

        # The pool is bounded, and a rolled-back transaction leaves nothing.
        check("the pool has a ceiling", db.pool.max_size == 4)

        before = db.conn.execute("SELECT COUNT(*) n FROM team").fetchone()["n"]
        try:
            with db.tx() as tx:
                tx.execute("INSERT INTO team(name) VALUES (?)", ("doomed",))
                # A nested helper using db.conn must join this transaction, not
                # borrow a second connection and commit independently.
                db.conn.execute("INSERT INTO team(name) VALUES (?)", ("also-doomed",))
                raise RuntimeError("roll it back")
        except RuntimeError:
            pass
        after = db.conn.execute("SELECT COUNT(*) n FROM team").fetchone()["n"]
        check("a rolled-back transaction leaves nothing behind, including work"
              " done through db.conn inside it", after == before,
              f"{before} -> {after}")
    finally:
        db.close()

    with psycopg.connect(DSN, autocommit=True) as c:
        left = c.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
            " AND pid <> pg_backend_pid()").fetchone()[0]
    check("closing the database returns every connection", left == 0, str(left))


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
