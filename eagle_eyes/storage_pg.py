"""PostgreSQL behind the same interface storage.Database presents.

WHY: SQLite is one writer at a time on one file. That is correct for a CLI
scanning a share and wrong for a service with concurrent sessions and
multi-user access control -- which is the first thing anyone would probe.
docs/DATA_MODEL.md section 8 planned this port; eagle_eyes/schema_pg.sql is it.

WHAT THIS MODULE IS NOT: an ORM, or a general SQL abstraction. Every repository
in storage.py keeps its own SQL. What changes between dialects is small and
mechanical, so it is handled here and nowhere else:

  placeholders   `?` becomes `%s`.
  new ids        SQLite hands back cur.lastrowid; Postgres needs RETURNING id.
  upserts        `INSERT OR REPLACE` becomes `ON CONFLICT ... DO UPDATE`.
  row shape      Postgres returns datetime and Decimal where SQLite returns
                 TEXT and float. Repositories compare timestamps as strings
                 (correct, because they are written as UTC ISO-8601 and sort),
                 so rows are normalised on the way out. The alternative is
                 auditing every comparison in the codebase for dialect, which
                 is how a port introduces a bug nobody finds for a month.
  booleans       SQLite stores 0/1; Postgres has BOOLEAN and refuses a
                 smallint. Parameters are coerced here rather than at 40 call
                 sites.

Rows come back as `Row`, a dict that also indexes by position, because
sqlite3.Row does and the repositories use both.
"""

from __future__ import annotations

import json
import re
import threading
from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator

SCHEMA_PATH = Path(__file__).resolve().parent / "schema_pg.sql"

try:                                    # register with storage, see INTEGRITY_ERRORS
    from psycopg import errors as _pg_errors
    from .storage import register_integrity_error
    register_integrity_error(_pg_errors.IntegrityError)
except ImportError:                     # psycopg absent -- SQLite only, nothing to do
    pass

# Tables with no `id` column, so `RETURNING id` must not be appended.
NO_ID_TABLES = {"account_scope", "scan_watermark"}

_INSERT_INTO = re.compile(r"^\s*INSERT\s+(?:OR\s+\w+\s+)?INTO\s+(\w+)", re.I)
_OR_REPLACE = re.compile(r"^\s*INSERT\s+OR\s+REPLACE\s+INTO\s+", re.I)


class Row(dict):
    """A dict that also indexes by position, the way sqlite3.Row does."""

    def __init__(self, mapping: dict, order: tuple[str, ...]) -> None:
        super().__init__(mapping)
        self._order = order

    def __getitem__(self, key):
        if isinstance(key, int):
            return super().__getitem__(self._order[key])
        return super().__getitem__(key)

    def keys(self):                      # sqlite3.Row.keys() returns a list
        return list(self._order)


def normalise(value: Any) -> Any:
    """Make one Postgres value look like the SQLite value for the same column.

    Timestamps become the exact string storage.now() writes, so the string
    comparisons the repositories already do keep working. Decimal becomes float
    -- it is read for display and for budget arithmetic that was always float.
    Booleans become 0/1, so a caller testing `row["is_superseded"] == 0` sees
    what it saw before.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.isoformat(timespec="seconds")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, list):
        # inputs_used is TEXT[] here and a JSON string in SQLite.
        return json.dumps(value)
    return value


def adapt(param: Any) -> Any:
    """A parameter on its way in."""
    if isinstance(param, bool):
        return param
    if isinstance(param, int) and not isinstance(param, bool):
        return param
    return param


def translate(sql: str) -> str:
    """Rewrite one statement from the SQLite dialect to Postgres."""
    if _OR_REPLACE.match(sql):
        raise ValueError(
            "INSERT OR REPLACE has no Postgres equivalent that means the same "
            "thing. Write the statement as INSERT ... ON CONFLICT (...) DO "
            "UPDATE, which both dialects accept, rather than translating it "
            "here where the conflict target would have to be guessed.")
    out = sql.replace("?", "%s")
    match = _INSERT_INTO.match(out)
    if match and "RETURNING" not in out.upper():
        if match.group(1).lower() not in NO_ID_TABLES:
            out = out.rstrip().rstrip(";") + " RETURNING id"
    return out


class Cursor:
    """Rows already fetched, plus the id of anything inserted.

    Materialised rather than lazy, because the connection goes back to the pool
    the moment `execute` returns. Every query in this codebase is bounded (the
    largest is LIMIT 500), so reading them into memory costs nothing and removes
    the question of what happens if a caller holds a cursor across a request.
    """

    def __init__(self, rows: list, names: tuple[str, ...],
                 lastrowid: int | None, rowcount: int) -> None:
        self._rows = rows
        self._names = names
        self.lastrowid = lastrowid
        self.rowcount = rowcount
        self._i = 0

    def fetchone(self) -> Row | None:
        if self._i >= len(self._rows):
            return None
        record = self._rows[self._i]
        self._i += 1
        return Row({n: normalise(v) for n, v in zip(self._names, record)}, self._names)

    def fetchall(self) -> list[Row]:
        out, row = [], self.fetchone()
        while row is not None:
            out.append(row)
            row = self.fetchone()
        return out

    def __iter__(self):
        return iter(self.fetchall())


class Connection:
    """The `db.conn` every repository already talks to.

    Bound either to the pool (borrow per statement) or to one checked-out
    connection, which is what `tx()` needs so a block of statements shares a
    transaction.
    """

    def __init__(self, pool=None, raw=None) -> None:
        self._pool = pool
        self._raw = raw

    @contextmanager
    def _borrow(self):
        if self._raw is not None:
            yield self._raw
            return
        with self._pool.connection() as raw:
            yield raw

    def execute(self, sql: str, params: Any = ()) -> Cursor:
        statement = translate(sql)
        with self._borrow() as raw:
            with raw.cursor() as cur:
                cur.execute(statement, tuple(adapt(p) for p in (params or ())))
                names = tuple(d.name for d in cur.description) if cur.description else ()
                rows = cur.fetchall() if cur.description else []
                rowcount = cur.rowcount
        lastrowid = None
        if "RETURNING id" in statement and rows:
            lastrowid = rows[0][0]
        return Cursor(rows, names, lastrowid, rowcount)

    def executescript(self, script: str) -> None:
        with self._borrow() as raw:
            with raw.cursor() as cur:
                cur.execute(script)


class PostgresDatabase:
    """storage.Database's interface, over PostgreSQL.

    A POOL, not a connection per thread. The SQLite class opens one per thread
    because the driver refuses to share; doing the same here would open one per
    request thread and per job worker and never give any of them back --
    roughly forty against a managed Postgres whose limit is often twenty, and
    the failure is "sorry, too many clients already" at the moment traffic
    arrives rather than in development. The pool is bounded, so the ceiling is a
    number this file states rather than however many threads the server decides
    to run.
    """

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 10) -> None:
        self.dsn = dsn
        self._local = threading.local()
        from psycopg_pool import ConnectionPool
        self.pool = ConnectionPool(dsn, min_size=min_size, max_size=max_size,
                                   kwargs={"autocommit": True}, open=True,
                                   timeout=30.0)
        self.pool.wait(timeout=30.0)
        self.migrate()

    @property
    def path(self) -> str:
        return _redact(self.dsn)

    @property
    def conn(self) -> Connection:
        """Inside tx() this is the transaction's connection; otherwise the pool.

        Pinning matters: `AccountRepo.approve` opens a transaction and, inside
        it, calls a helper that creates a team through `db.conn`. On SQLite that
        helper joins the transaction because there is one connection per thread.
        Without pinning it would borrow a second connection from the pool and
        commit independently -- so a rolled-back approval would leave the team
        it created behind. Same code, different outcome by dialect, which is the
        kind of difference nobody finds by reading.
        """
        pinned = getattr(self._local, "tx", None)
        return pinned if pinned is not None else Connection(pool=self.pool)

    def migrate(self) -> None:
        """Apply the schema. Every statement is IF NOT EXISTS or OR REPLACE, so
        it is safe on every boot -- which is what a container needs, having no
        separate migration step to run."""
        Connection(pool=self.pool).executescript(
            SCHEMA_PATH.read_text(encoding="utf-8"))

    @contextmanager
    def tx(self) -> Iterator[Connection]:
        with self.pool.connection() as raw:
            raw.autocommit = False
            bound = Connection(raw=raw)
            self._local.tx = bound
            try:
                yield bound
            except BaseException:
                raw.rollback()
                raise
            else:
                raw.commit()
            finally:
                self._local.tx = None
                raw.autocommit = True

    @staticmethod
    def day_expr(column: str) -> str:
        """TIMESTAMPTZ has no substr. See storage.Database.day_expr."""
        return f"to_char({column}, 'YYYY-MM-DD')"

    @staticmethod
    def encode_list(values) -> list:
        """TEXT[] takes a list. See storage.Database.encode_list."""
        return list(values)

    @staticmethod
    def decode_list(value) -> tuple[str, ...]:
        """TEXT[] comes back as a list. See storage.Database.decode_list."""
        from .storage import Database
        return Database.decode_list(value)

    def close(self) -> None:
        self.pool.close()


def _redact(dsn: str) -> str:
    """A DSN safe to print. It carries a password."""
    return re.sub(r"//([^:/@]+):[^@]*@", r"//\1:***@", dsn)
