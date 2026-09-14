"""Persistence: schema, migrations, repositories, retention.

Everything else sits on this. Without it there is no failure history, no local
dedup, no feedback, no metrics and nothing to apply a retention policy to.

Two decisions worth knowing before reading:

1. Every repository is constructed WITH A PRINCIPAL. There is no constructor
   without one. Today a local install resolves to an implicit admin and the
   answer is always yes, so nothing is restricted -- but the parameter is
   threaded through every call site now, while it is cheap. When enforcement
   moves server-side (docs/ARCHITECTURE.md, RBAC staging) that becomes a change
   of who answers rather than a rewrite of every caller. Authorization that has
   to be retrofitted is authorization that gets forgotten in one place.

2. The schema lives in schema.sql, not in a string here, and
   docs/DATA_MODEL.md embeds that file verbatim. A test fails if they drift.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
SCHEMA_VERSION = 2


def now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _plus(days: int) -> str:
    return (datetime.now(timezone.utc).replace(tzinfo=None)
            + timedelta(days=days)).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

ADMIN, MANAGER, USER = "admin", "manager", "user"


@dataclass(frozen=True)
class Principal:
    """Who is asking. Required by every repository.

    `scope` is the set of team names a manager covers; empty means "own bots
    only" for a user, and is ignored for an admin.
    """
    actor: str
    role: str = USER
    scope: frozenset[str] = frozenset()

    @property
    def is_admin(self) -> bool:
        return self.role == ADMIN

    def may_see_team(self, team: str | None) -> bool:
        if self.is_admin:
            return True
        if self.role == MANAGER:
            return team in self.scope
        return False

    @staticmethod
    def local() -> "Principal":
        """The single operator of a local install.

        A local install cannot enforce roles against its own operator -- they
        own the machine. Pretending otherwise would be theatre, so local mode
        says plainly that the operator is the admin, and the audit log records
        what they did. Real enforcement arrives with the server.
        """
        import getpass
        try:
            who = getpass.getuser()
        except Exception:
            who = "unknown"
        return Principal(actor=who, role=ADMIN)


class AccessDenied(PermissionError):
    pass


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Migrations
#
# Each entry upgrades FROM the previous version TO its key. A database created
# fresh runs schema.sql instead and skips all of them, so every migration here
# must leave the database in the same shape schema.sql would have produced --
# tests/test_storage.py compares the two directly rather than trusting that.
# --------------------------------------------------------------------------

MIGRATION_2 = """
CREATE TABLE account (
    id             INTEGER PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    display_name   TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    salt           TEXT NOT NULL,
    params         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'requested'
                   CHECK (status IN ('requested','approved','suspended','revoked')),
    role           TEXT NOT NULL DEFAULT 'user'
                   CHECK (role IN ('admin','manager','user')),
    developer_id   INTEGER REFERENCES developer(id),
    approved_by    TEXT,
    approved_at    TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at  TEXT,
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT
);

CREATE INDEX idx_account_status ON account (status, role);

CREATE TABLE account_scope (
    account_id  INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    team_id     INTEGER NOT NULL REFERENCES team(id),
    granted_by  TEXT NOT NULL,
    granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (account_id, team_id)
);

CREATE TABLE session (
    id           TEXT PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    user_agent   TEXT,
    revoked_at   TEXT
);

CREATE INDEX idx_session_account ON session (account_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_session_expiry  ON session (expires_at);

-- Tighten screenshot.processing_mode from BETWEEN 0 AND 3 to IN (0, 3).
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt. Any existing
-- row claiming mode 1 or 2 is rewritten to 3, which is what actually happened to
-- it: the image was sent as captured, uncropped and unredacted. Leaving the row
-- saying "cropped" would preserve a false record of a protection that was never
-- applied, which is the whole point of removing the modes.
UPDATE screenshot SET processing_mode = 3, was_cropped = 0, was_redacted = 0
 WHERE processing_mode IN (1, 2);

CREATE TABLE screenshot_new (
    id              INTEGER PRIMARY KEY,
    failure_id      INTEGER NOT NULL UNIQUE REFERENCES failure(id) ON DELETE CASCADE,
    unc_path        TEXT NOT NULL,
    processing_mode INTEGER NOT NULL CHECK (processing_mode IN (0, 3)),
    derivative_path TEXT,
    was_cropped     INTEGER NOT NULL DEFAULT 0 CHECK (was_cropped IN (0,1)),
    was_redacted    INTEGER NOT NULL DEFAULT 0 CHECK (was_redacted IN (0,1)),
    sent_to_model   INTEGER NOT NULL DEFAULT 0 CHECK (sent_to_model IN (0,1)),
    width_px        INTEGER,
    height_px       INTEGER,
    bytes           INTEGER,
    captured_at     TEXT,
    expires_at      TEXT,
    deleted_at      TEXT
);

INSERT INTO screenshot_new SELECT * FROM screenshot;
DROP TABLE screenshot;
ALTER TABLE screenshot_new RENAME TO screenshot;

CREATE INDEX idx_screenshot_derivative_expiry ON screenshot (expires_at)
    WHERE derivative_path IS NOT NULL AND deleted_at IS NULL;
"""

MIGRATIONS: dict[int, str] = {2: MIGRATION_2}


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.migrate()

    def migrate(self) -> None:
        """Create or upgrade. Idempotent, so it is safe on every start."""
        current = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if current == 0:
            self.conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            return
        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.path} was written by a newer version (schema {current}, "
                f"this build understands {SCHEMA_VERSION}). Upgrade rather than "
                f"risk writing data an older build cannot read.")
        while current < SCHEMA_VERSION:
            step = MIGRATIONS.get(current + 1)
            if step is None:
                raise RuntimeError(
                    f"{self.path} is at schema {current} and this build wants "
                    f"{SCHEMA_VERSION}, but no migration to {current + 1} exists. "
                    "Refusing to run against a schema nobody described.")
            self.conn.executescript(step)
            current += 1
            self.conn.execute(f"PRAGMA user_version = {current}")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    def close(self) -> None:
        self.conn.close()


# --------------------------------------------------------------------------
# Repositories
# --------------------------------------------------------------------------

class Repository:
    """Base. A repository cannot be constructed without a principal."""

    def __init__(self, db: Database, principal: Principal) -> None:
        if not isinstance(principal, Principal):
            raise TypeError(
                "a repository needs a Principal. Use Principal.local() for a "
                "single-operator install; never default it to None.")
        self.db = db
        self.p = principal

    def _audit(self, action: str, resource_type: str, resource_id: str,
               outcome: str = "allow") -> None:
        self.db.conn.execute(
            "INSERT INTO audit_event(actor, actor_role, action, resource_type,"
            " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
            (self.p.actor, self.p.role, action, resource_type, str(resource_id),
             outcome, now()))


class BotRepo(Repository):
    def upsert(self, service_line: str, bot_number: str,
               code_path: str | None = None) -> int:
        cur = self.db.conn.execute(
            "SELECT id FROM bot WHERE service_line=? AND bot_number=?",
            (service_line, bot_number))
        row = cur.fetchone()
        if row:
            if code_path:
                self.db.conn.execute("UPDATE bot SET code_path=? WHERE id=?",
                                     (code_path, row["id"]))
            return row["id"]
        cur = self.db.conn.execute(
            "INSERT INTO bot(service_line, bot_number, code_path) VALUES (?,?,?)",
            (service_line, bot_number, code_path))
        return cur.lastrowid

    def set_owner(self, bot_id: int, developer_email: str) -> None:
        """Who owns this bot. What a plain user's visibility is computed from."""
        dev_id = DeveloperRepo(self.db, self.p).ensure(developer_email)
        self.db.conn.execute("UPDATE bot SET owner_dev_id=? WHERE id=?",
                             (dev_id, bot_id))
        self._audit("set_owner", "bot", bot_id)

    def set_team(self, bot_id: int, team: str) -> None:
        team_id = DeveloperRepo(self.db, self.p)._team_id(team)
        self.db.conn.execute("UPDATE bot SET team_id=? WHERE id=?", (team_id, bot_id))
        self._audit("set_team", "bot", bot_id)


class FingerprintRepo(Repository):
    def touch(self, fp_hash: str, version: int, exception_type: str,
              normalized_message: str, code_location: str,
              retain_days: int = 730) -> int:
        """Record a sighting. Returns the fingerprint id."""
        row = self.db.conn.execute(
            "SELECT id FROM fingerprint WHERE hash=? AND version=?",
            (fp_hash, version)).fetchone()
        if row:
            self.db.conn.execute(
                "UPDATE fingerprint SET last_seen_at=?, occurrence_count=occurrence_count+1"
                " WHERE id=?", (now(), row["id"]))
            return row["id"]
        cur = self.db.conn.execute(
            "INSERT INTO fingerprint(hash, version, exception_type, normalized_message,"
            " code_location, first_seen_at, last_seen_at, expires_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (fp_hash, version, exception_type, normalized_message[:500],
             code_location, now(), now(), _plus(retain_days)))
        return cur.lastrowid

    def recent_analysis(self, fp_id: int, *, within_days: int = 30,
                        code_mtime: str | None = None) -> sqlite3.Row | None:
        """The reuse gate from docs/DATA_MODEL.md 2.6, in SQL.

        Requires: not superseded, inside the TTL, same code version, and no
        developer has marked it wrong.
        """
        cutoff = (datetime.now(timezone.utc).replace(tzinfo=None)
                  - timedelta(days=within_days)).isoformat(timespec="seconds")
        sql = ("SELECT a.* FROM analysis a"
               " WHERE a.fingerprint_id=? AND a.is_superseded=0 AND a.created_at >= ?"
               "   AND NOT EXISTS (SELECT 1 FROM feedback f"
               "                   WHERE f.analysis_id=a.id AND f.verdict='wrong')")
        params: list[Any] = [fp_id, cutoff]
        if code_mtime is not None:
            sql += " AND a.code_mtime IS ?"
            params.append(code_mtime)
        sql += " ORDER BY a.created_at DESC LIMIT 1"
        return self.db.conn.execute(sql, params).fetchone()


class AnalysisRepo(Repository):
    def add(self, fingerprint_id: int, *, path: str, root_cause: str,
            suggested_fix: str, confidence: float, model_id: str = "",
            code_mtime: str | None = None, inputs_used: tuple[str, ...] = (),
            tokens_in: int = 0, tokens_out: int = 0, cost_usd: float = 0.0,
            latency_ms: int = 0, retain_days: int = 365) -> int:
        cur = self.db.conn.execute(
            "INSERT INTO analysis(fingerprint_id, path, model_id, code_mtime, root_cause,"
            " suggested_fix, confidence, inputs_used, tokens_in, tokens_out, cost_usd,"
            " latency_ms, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fingerprint_id, path, model_id, code_mtime, root_cause, suggested_fix,
             confidence, json.dumps(list(inputs_used)), tokens_in, tokens_out,
             cost_usd, latency_ms, now(), _plus(retain_days)))
        self._audit("create", "analysis", cur.lastrowid)
        return cur.lastrowid

    def get(self, analysis_id: int) -> sqlite3.Row | None:
        row = self.db.conn.execute("SELECT * FROM analysis WHERE id=?",
                                   (analysis_id,)).fetchone()
        self._audit("read", "analysis", analysis_id, "allow" if row else "deny")
        return row

    def supersede(self, analysis_id: int) -> None:
        self.db.conn.execute("UPDATE analysis SET is_superseded=1 WHERE id=?",
                             (analysis_id,))
        self._audit("supersede", "analysis", analysis_id)


class FailureRepo(Repository):
    def add(self, *, bot_id: int, fingerprint_id: int, occurred_at: str,
            log_path: str, analysis_id: int | None = None,
            screenshot_path: str | None = None, code_path: str | None = None,
            code_mtime: str | None = None, code_possibly_stale: bool = False,
            pairing_method: str = "none", log_sanitized: str = "",
            code_snapshot: str = "", status: str = "analyzed",
            was_deduped: bool = False, correlation_id: str = "",
            content_days: int = 90, retain_days: int = 730) -> int | None:
        """Insert, or None when this log has already been ingested.

        The unique index on log_path is what makes a re-scan a no-op, which is
        what lets the scanner be restarted without reprocessing the estate.
        """
        try:
            cur = self.db.conn.execute(
                "INSERT INTO failure(bot_id, fingerprint_id, analysis_id, occurred_at,"
                " ingested_at, status, was_deduped, log_path, screenshot_path, code_path,"
                " code_mtime, code_possibly_stale, pairing_method, log_sanitized,"
                " code_snapshot, correlation_id, content_expires_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (bot_id, fingerprint_id, analysis_id, occurred_at, now(), status,
                 int(was_deduped), log_path, screenshot_path, code_path, code_mtime,
                 int(code_possibly_stale), pairing_method, log_sanitized, code_snapshot,
                 correlation_id, _plus(content_days), _plus(retain_days)))
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None

    SELECT_ = ("SELECT f.*, b.service_line, b.bot_number, b.owner_dev_id,"
               " a.root_cause, a.confidence, a.suggested_fix, a.path, a.model_id"
               " FROM failure f JOIN bot b ON b.id=f.bot_id"
               " LEFT JOIN analysis a ON a.id=f.analysis_id")

    def _scope_sql(self) -> tuple[str, list[Any]]:
        """The WHERE clause that implements the role, in SQL.

        In SQL rather than in Python because a filter applied after LIMIT is not
        a filter -- it is a page that silently comes back short, and the first
        time anyone notices is when a manager reports missing failures and
        somebody "fixes" it by widening the query. Scoping has to happen where
        the rows are selected.

          admin    everything.
          manager  the service lines named in their scope, and nothing else.
                   An empty scope means no rows, never all rows.
          user     failures on bots they own. Ownership is `bot.owner_dev_id`
                   resolved to a developer email; an account with no developer
                   record owns nothing and sees nothing.
        """
        if self.p.is_admin:
            return "", []
        if self.p.role == MANAGER:
            if not self.p.scope:
                return " AND 0", []
            marks = ",".join("?" for _ in self.p.scope)
            return f" AND b.service_line IN ({marks})", sorted(self.p.scope)
        return (" AND b.owner_dev_id IN"
                " (SELECT id FROM developer WHERE email = ?)", [self.p.actor.lower()])

    def recent(self, limit: int = 50, offset: int = 0) -> list[sqlite3.Row]:
        where, args = self._scope_sql()
        sql = f"{self.SELECT_} WHERE 1{where} ORDER BY f.occurred_at DESC LIMIT ? OFFSET ?"
        return self.db.conn.execute(sql, [*args, max(1, min(limit, 500)),
                                          max(0, offset)]).fetchall()

    def get(self, failure_id: int) -> sqlite3.Row:
        """One failure, or AccessDenied.

        Deliberately the same answer for "does not exist" and "not yours": a
        distinguishable 404 lets anyone enumerate which ids are real and which
        teams are busy. The denial is audited, which is the point of having an
        audit log -- a run of them from one actor is the signal.
        """
        where, args = self._scope_sql()
        row = self.db.conn.execute(
            f"{self.SELECT_} WHERE f.id = ?{where}", [failure_id, *args]).fetchone()
        if row is None:
            self._audit("read", "failure", failure_id, outcome="deny")
            raise AccessDenied(f"no failure {failure_id} is visible to {self.p.actor}")
        return row

    def visible_count(self) -> int:
        where, args = self._scope_sql()
        return self.db.conn.execute(
            f"SELECT COUNT(*) n FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" WHERE 1{where}", args).fetchone()["n"]

    def _visible(self, row: sqlite3.Row) -> bool:
        """Whether one already-fetched row is in scope.

        Kept as the single readable statement of the rule; `_scope_sql` is the
        same rule expressed where it can be enforced. A test asserts the two
        agree row for row, because two copies of a rule is how a rule rots.
        """
        if self.p.is_admin:
            return True
        if self.p.role == MANAGER:
            return self.p.may_see_team(row["service_line"])
        if row["owner_dev_id"] is None:
            return False
        owner = self.db.conn.execute(
            "SELECT email FROM developer WHERE id=?", (row["owner_dev_id"],)).fetchone()
        return bool(owner) and owner["email"] == self.p.actor.lower()

    def stats(self) -> dict[str, Any]:
        """Counts over what this principal can see, never over the whole estate.

        A dedup rate or a spend figure computed over every row would leak the
        size and cost of teams the reader has no access to.
        """
        where, args = self._scope_sql()
        c = self.db.conn
        base = f"FROM failure f JOIN bot b ON b.id=f.bot_id WHERE 1{where}"
        total = c.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
        deduped = c.execute(
            f"SELECT COUNT(*) {base} AND f.was_deduped=1", args).fetchone()[0]
        spend = c.execute(
            f"SELECT COALESCE(SUM(a.cost_usd),0) FROM analysis a WHERE a.id IN"
            f" (SELECT f.analysis_id {base} AND f.analysis_id IS NOT NULL)",
            args).fetchone()[0]
        fps = c.execute(
            f"SELECT COUNT(DISTINCT f.fingerprint_id) {base}", args).fetchone()[0]
        return {"failures": total, "deduped": deduped, "fingerprints": fps,
                "dedup_rate": (deduped / total) if total else 0.0,
                "spend_usd": spend}


class FeedbackRepo(Repository):
    """Developer verdicts. The ground truth that makes improvement possible.

    It also invalidates reuse immediately: an analysis marked wrong is never
    served again (see FingerprintRepo.recent_analysis). Feedback is not only
    future training data -- it is the cheapest quality mechanism in the system.
    """

    def add(self, analysis_id: int, failure_id: int, developer_id: int,
            verdict: str, comment: str = "") -> None:
        if verdict not in ("correct", "partial", "wrong"):
            raise ValueError(f"verdict must be correct/partial/wrong, got {verdict!r}")
        self.db.conn.execute(
            "INSERT OR REPLACE INTO feedback(analysis_id, failure_id, developer_id,"
            " verdict, comment, created_at) VALUES (?,?,?,?,?,?)",
            (analysis_id, failure_id, developer_id, verdict, comment, now()))
        self._audit("feedback", "analysis", analysis_id)

    def tally(self) -> dict[str, int]:
        rows = self.db.conn.execute(
            "SELECT verdict, COUNT(*) n FROM feedback GROUP BY verdict").fetchall()
        return {r["verdict"]: r["n"] for r in rows}


class DeveloperRepo(Repository):
    """People. Notifications and feedback both need a stable id for one."""

    UNASSIGNED = "unassigned"

    def ensure(self, email: str, *, display_name: str = "",
               team: str | None = None) -> int:
        """Resolve an email to a developer id, creating the row if needed.

        Creating on demand is deliberate. The alternative -- refusing to record
        anything for an address not already in the table -- means notification
        suppression silently does not apply to exactly the recipients nobody has
        registered yet, which is the same failure A2 is about. New developers
        land in the `unassigned` team, visible as such, rather than being
        invented into somebody's real team.
        """
        email = email.strip().lower()
        if not email:
            raise ValueError("a developer needs an email")
        row = self.db.conn.execute(
            "SELECT id FROM developer WHERE email=?", (email,)).fetchone()
        if row:
            return row["id"]
        team_id = self._team_id(team or self.UNASSIGNED)
        cur = self.db.conn.execute(
            "INSERT INTO developer(email, display_name, team_id, created_at)"
            " VALUES (?,?,?,?)",
            (email, display_name or email.split("@")[0], team_id, now()))
        self._audit("create", "developer", cur.lastrowid)
        return cur.lastrowid

    def _team_id(self, name: str) -> int:
        row = self.db.conn.execute(
            "SELECT id FROM team WHERE name=?", (name,)).fetchone()
        if row:
            return row["id"]
        cur = self.db.conn.execute(
            "INSERT INTO team(name, created_at) VALUES (?,?)", (name, now()))
        return cur.lastrowid

    def team_of(self, email: str) -> str | None:
        row = self.db.conn.execute(
            "SELECT t.name FROM developer d JOIN team t ON t.id=d.team_id"
            " WHERE d.email=?", (email.strip().lower(),)).fetchone()
        return row["name"] if row else None


class NotificationStateRepo(Repository):
    """Durable notification suppression, over the `notification_state` table.

    The in-memory version was correct for exactly as long as the process lived.
    In a CLI run that is one scan, so the repeat window and the hourly cap did
    what they claimed. In a service a new Notifier is built per request, so both
    reset continuously: the cap that reads as "ten an hour" would send ten per
    request, and an incident producing hundreds of failures would deliver
    hundreds of mails -- the precise outcome the suppression rules exist to
    prevent, and the one that gets the sender filtered to junk permanently.

    This implements notify.SuppressionStore against the database, so the rules
    survive a restart, a redeploy, and a second worker.
    """

    def _ids(self, to: str, fingerprint: str) -> tuple[int, int] | None:
        fp = self.db.conn.execute(
            "SELECT id FROM fingerprint WHERE hash=? ORDER BY version DESC LIMIT 1",
            (fingerprint,)).fetchone()
        if not fp:
            return None
        dev = DeveloperRepo(self.db, self.p).ensure(to)
        return fp["id"], dev

    def last_sent(self, to: str, fingerprint: str) -> datetime | None:
        ids = self._ids(to, fingerprint)
        if not ids:
            return None
        row = self.db.conn.execute(
            "SELECT last_notified_at FROM notification_state"
            " WHERE fingerprint_id=? AND developer_id=?", ids).fetchone()
        if not row:
            return None
        return datetime.fromisoformat(row["last_notified_at"]).replace(tzinfo=timezone.utc)

    def seen_count(self, to: str, fingerprint: str) -> int:
        ids = self._ids(to, fingerprint)
        if not ids:
            return 0
        row = self.db.conn.execute(
            "SELECT suppressed_count FROM notification_state"
            " WHERE fingerprint_id=? AND developer_id=?", ids).fetchone()
        return (row["suppressed_count"] + 1) if row else 0

    def bump_suppressed(self, to: str, fingerprint: str) -> int:
        """Count one suppressed repeat. Returns total sightings including sends."""
        ids = self._ids(to, fingerprint)
        if not ids:
            return 1
        self.db.conn.execute(
            "UPDATE notification_state SET suppressed_count = suppressed_count + 1"
            " WHERE fingerprint_id=? AND developer_id=?", ids)
        return self.seen_count(to, fingerprint)

    def sent_in_last_hour(self, to: str, now: datetime | None = None) -> int:
        ref = now or datetime.now(timezone.utc)
        if ref.tzinfo:
            ref = ref.astimezone(timezone.utc).replace(tzinfo=None)
        cutoff = (ref - timedelta(hours=1)).isoformat(timespec="seconds")
        row = self.db.conn.execute(
            "SELECT COUNT(*) n FROM notification_state ns"
            " JOIN developer d ON d.id = ns.developer_id"
            " WHERE d.email=? AND ns.last_notified_at >= ?",
            (to.strip().lower(), cutoff)).fetchone()
        return row["n"] if row else 0

    def record_sent(self, to: str, fingerprint: str, when: datetime) -> None:
        ids = self._ids(to, fingerprint)
        if not ids:
            # No fingerprint row means nothing durable to hang the state on.
            # Say so rather than pretending the send was recorded.
            raise LookupError(
                f"fingerprint {fingerprint[:12]}... is not in the database; "
                "record the failure before notifying about it")
        stamp = when.astimezone(timezone.utc).replace(tzinfo=None).isoformat(
            timespec="seconds")
        self.db.conn.execute(
            "INSERT INTO notification_state(fingerprint_id, developer_id,"
            " first_notified_at, last_notified_at, suppressed_count)"
            " VALUES (?,?,?,?,0)"
            " ON CONFLICT(fingerprint_id, developer_id) DO UPDATE SET"
            "   last_notified_at = excluded.last_notified_at,"
            "   suppressed_count = 0",
            (ids[0], ids[1], stamp, stamp))
        self._audit("notify", "fingerprint", ids[0])


class WatermarkRepo(Repository):
    """What the scanner has already processed.

    This is what makes a re-run cheap and a restart safe: the catch-up scan
    (docs/ARCHITECTURE.md 4.3) processes everything since the last mark rather
    than starting from now, so failures that arrived while the host was off are
    not lost.
    """

    def seen(self, file_path: str, mtime: str, size: int) -> bool:
        row = self.db.conn.execute(
            "SELECT file_mtime, file_size FROM scan_watermark WHERE file_path=?",
            (file_path,)).fetchone()
        return bool(row and row["file_mtime"] == mtime and row["file_size"] == size)

    def mark(self, file_path: str, mtime: str, size: int, outcome: str = "ingested") -> None:
        self.db.conn.execute(
            "INSERT OR REPLACE INTO scan_watermark(file_path, file_mtime, file_size,"
            " processed_at, outcome) VALUES (?,?,?,?,?)",
            (file_path, mtime, size, now(), outcome))

    def count(self) -> int:
        return self.db.conn.execute("SELECT COUNT(*) FROM scan_watermark").fetchone()[0]


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------

@dataclass
class RetentionResult:
    content_nulled: int = 0
    failures_deleted: int = 0
    analyses_deleted: int = 0
    fingerprints_deleted: int = 0
    watermarks_deleted: int = 0

    def summary(self) -> str:
        return (f"{self.content_nulled} content nulled, "
                f"{self.failures_deleted} failures, {self.analyses_deleted} analyses, "
                f"{self.fingerprints_deleted} fingerprints, "
                f"{self.watermarks_deleted} watermarks deleted")


def run_retention(db: Database, principal: Principal, *,
                  watermark_days: int = 180, batch: int = 500) -> RetentionResult:
    """Apply the retention policy. Idempotent and safe to re-run.

    Content is nulled before rows are deleted, so a failure keeps its
    fingerprint and timestamps for trend analysis long after its log text is
    gone -- metrics survive, PII does not (docs/DATA_MODEL.md 3).
    """
    if not principal.is_admin:
        raise AccessDenied("only an admin may run retention")

    r = RetentionResult()
    ts = now()
    c = db.conn

    cur = c.execute(
        "UPDATE failure SET log_sanitized=NULL, code_snapshot=NULL"
        " WHERE content_expires_at <= ? AND (log_sanitized IS NOT NULL"
        "    OR code_snapshot IS NOT NULL)", (ts,))
    r.content_nulled = cur.rowcount

    # Children before parents; FKs are enforced.
    cur = c.execute("DELETE FROM failure WHERE expires_at <= ?"
                    " AND id IN (SELECT id FROM failure WHERE expires_at <= ? LIMIT ?)",
                    (ts, ts, batch))
    r.failures_deleted = cur.rowcount

    cur = c.execute(
        "DELETE FROM analysis WHERE expires_at <= ?"
        " AND id NOT IN (SELECT analysis_id FROM failure WHERE analysis_id IS NOT NULL)",
        (ts,))
    r.analyses_deleted = cur.rowcount

    cur = c.execute(
        "DELETE FROM fingerprint WHERE expires_at <= ?"
        " AND id NOT IN (SELECT fingerprint_id FROM failure)"
        " AND id NOT IN (SELECT fingerprint_id FROM analysis)", (ts,))
    r.fingerprints_deleted = cur.rowcount

    cutoff = (datetime.now(timezone.utc).replace(tzinfo=None)
              - timedelta(days=watermark_days)).isoformat(timespec="seconds")
    cur = c.execute("DELETE FROM scan_watermark WHERE processed_at < ?", (cutoff,))
    r.watermarks_deleted = cur.rowcount

    c.execute("INSERT INTO audit_event(actor, actor_role, action, resource_type,"
              " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
              (principal.actor, principal.role, "retention", "database",
               str(db.path), "allow", now()))
    return r
