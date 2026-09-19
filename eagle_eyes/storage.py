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
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
SCHEMA_VERSION = 8


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


# Which exception means "a constraint said no". sqlite3 and psycopg raise
# different types for the same event, and the places that catch it -- the
# idempotent failure insert, the registration that must not confirm an address
# is taken -- are exactly the places where catching the wrong one turns a
# handled case into a 500. storage_pg extends this on import; it is looked up at
# raise time, so the order of imports does not matter.
INTEGRITY_ERRORS: tuple[type[BaseException], ...] = (sqlite3.IntegrityError,)


def register_integrity_error(exc_type: type[BaseException]) -> None:
    global INTEGRITY_ERRORS
    if exc_type not in INTEGRITY_ERRORS:
        INTEGRITY_ERRORS = (*INTEGRITY_ERRORS, exc_type)


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

MIGRATION_3 = """
-- Allow pairing_method = 'uploaded'. SQLite cannot alter a CHECK constraint, so
-- the table is rebuilt. Nothing is rewritten: existing rows came from the
-- scanner and their method is still accurate.
CREATE TABLE failure_new (
    id                   INTEGER PRIMARY KEY,
    bot_id               INTEGER NOT NULL REFERENCES bot(id),
    fingerprint_id       INTEGER NOT NULL REFERENCES fingerprint(id),
    analysis_id          INTEGER REFERENCES analysis(id),
    occurred_at          TEXT NOT NULL,
    ingested_at          TEXT NOT NULL DEFAULT (datetime('now')),
    status               TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','deduped','analyzing','analyzed','failed','suppressed')),
    was_deduped          INTEGER NOT NULL DEFAULT 0 CHECK (was_deduped IN (0,1)),

    -- provenance: exactly where each input came from
    log_path             TEXT NOT NULL,     -- UNC path on the VM share
    screenshot_path      TEXT,              -- UNC path; NOT copied in Mode 0
    code_path            TEXT,
    code_mtime           TEXT,
    code_possibly_stale  INTEGER NOT NULL DEFAULT 0 CHECK (code_possibly_stale IN (0,1)),
    -- 'log_path' is the normal case: the log names the screenshot file (ARCHITECTURE 4.4).
    -- 'timestamp' is the fallback when no capture line exists; 'none' means we refused to guess.
    -- 'uploaded' means a person submitted the image alongside the log through the
    -- web UI. There is no sibling directory and no capture line to check it
    -- against, so it is whatever they attached -- recorded as its own method
    -- rather than borrowed from 'log_path', which would claim the log named it.
    pairing_method       TEXT CHECK (pairing_method IN
                             ('log_path','timestamp','none','uploaded')),

    log_sanitized        TEXT,              -- nulled at 90 days
    code_snapshot        TEXT,              -- nulled at 90 days
    severity             TEXT CHECK (severity IN ('low','medium','high','critical')),
    correlation_id       TEXT NOT NULL,
    content_expires_at   TEXT NOT NULL,
    expires_at           TEXT NOT NULL
);

INSERT INTO failure_new SELECT * FROM failure;
DROP TABLE failure;
ALTER TABLE failure_new RENAME TO failure;

-- The scanner is restartable and re-reads folders; this makes a re-scan a no-op.
CREATE UNIQUE INDEX idx_failure_idempotency ON failure (log_path);
CREATE INDEX idx_failure_bot_time     ON failure (bot_id, occurred_at DESC);
CREATE INDEX idx_failure_fingerprint  ON failure (fingerprint_id, occurred_at DESC);
CREATE INDEX idx_failure_pending      ON failure (status) WHERE status IN ('pending','analyzing');
CREATE INDEX idx_failure_feed         ON failure (occurred_at DESC);
CREATE INDEX idx_failure_content_expiry ON failure (content_expires_at)
    WHERE log_sanitized IS NOT NULL;
"""

MIGRATION_4 = """
-- Widen analysis.path to every value analysis.Path_ can produce. It listed four
-- of six, so a deduplicated or skipped analysis could not be stored -- the
-- insert failed the CHECK. SQLite cannot alter a CHECK, so the table is rebuilt.
CREATE TABLE analysis_new (
    id                INTEGER PRIMARY KEY,
    fingerprint_id    INTEGER NOT NULL REFERENCES fingerprint(id),
    source_failure_id INTEGER,             -- provenance only; never dereferenced cross-team (§5)
    -- Every value analysis.Path_ can produce. It used to list four of the six,
    -- so an analysis that came back from the dedup store or was skipped for
    -- want of an exception could not be written down at all -- the two
    -- outcomes the design is proudest of. A test now derives this list from
    -- the enum rather than trusting the two to stay in step.
    path              TEXT NOT NULL CHECK (path IN
                          ('dedup','template','text','vision','fallback','skipped')),
    model_id          TEXT,
    code_mtime        TEXT,                -- pseudo-version; no VCS exists (ARCHITECTURE.md §4.5)
    root_cause        TEXT,
    suggested_fix     TEXT,
    confidence        REAL CHECK (confidence BETWEEN 0 AND 1),
    inputs_used       TEXT NOT NULL DEFAULT '[]',   -- JSON array
    is_superseded     INTEGER NOT NULL DEFAULT 0 CHECK (is_superseded IN (0,1)),
    tokens_in         INTEGER,
    tokens_out        INTEGER,
    cache_read_tokens INTEGER,
    image_tokens      INTEGER,
    cost_usd          REAL,
    latency_ms        INTEGER,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at        TEXT NOT NULL
);

INSERT INTO analysis_new SELECT * FROM analysis;
DROP TABLE analysis;
ALTER TABLE analysis_new RENAME TO analysis;

CREATE INDEX idx_analysis_fingerprint ON analysis (fingerprint_id, created_at DESC)
    WHERE is_superseded = 0;
CREATE INDEX idx_analysis_expiry ON analysis (expires_at);
"""

MIGRATION_5 = """
CREATE TABLE scan_schedule (
    id            INTEGER PRIMARY KEY,
    account_id    INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    target_path   TEXT NOT NULL,
    share_root    TEXT NOT NULL,
    code_root     TEXT NOT NULL,
    every_minutes INTEGER NOT NULL CHECK (every_minutes >= 5),
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_run_at   TEXT,
    last_outcome  TEXT,
    last_found    INTEGER NOT NULL DEFAULT 0,
    last_analysed INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_id, name)
);

CREATE INDEX idx_schedule_due ON scan_schedule (enabled, last_run_at);
"""

MIGRATION_6 = """
-- Add the failure taxonomy. SQLite cannot add a column with a CHECK that
-- references it, so the table is rebuilt -- and every existing row keeps its
-- diagnosis with the four new fields NULL, which is what "we did not classify
-- this one" should look like.
CREATE TABLE analysis_new (
    id                INTEGER PRIMARY KEY,
    fingerprint_id    INTEGER NOT NULL REFERENCES fingerprint(id),
    source_failure_id INTEGER,             -- provenance only; never dereferenced cross-team (§5)
    -- Every value analysis.Path_ can produce. It used to list four of the six,
    -- so an analysis that came back from the dedup store or was skipped for
    -- want of an exception could not be written down at all -- the two
    -- outcomes the design is proudest of. A test now derives this list from
    -- the enum rather than trusting the two to stay in step.
    path              TEXT NOT NULL CHECK (path IN
                          ('dedup','template','text','vision','fallback','skipped')),
    model_id          TEXT,
    code_mtime        TEXT,                -- pseudo-version; no VCS exists (ARCHITECTURE.md §4.5)
    root_cause        TEXT,
    suggested_fix     TEXT,
    confidence        REAL CHECK (confidence BETWEEN 0 AND 1),
    inputs_used       TEXT NOT NULL DEFAULT '[]',   -- JSON array
    -- The failure taxonomy. A separate axis from `path` (how it was answered)
    -- and from the routing class: this is what KIND of failure it was, which
    -- is what a manager filters and colours by. Nullable throughout, because
    -- analyses stored before these existed have none of them and an older row
    -- must still render.
    failure_type      TEXT CHECK (failure_type IS NULL OR failure_type IN
                          ('timeout','auth','network','data_validation','rate_limit',
                           'ssl','file_io','selector','logic_error','other')),
    severity          TEXT CHECK (severity IS NULL OR severity IN
                          ('low','medium','high','critical')),
    affected_function TEXT,
    recommendations   TEXT,
    is_superseded     INTEGER NOT NULL DEFAULT 0 CHECK (is_superseded IN (0,1)),
    tokens_in         INTEGER,
    tokens_out        INTEGER,
    cache_read_tokens INTEGER,
    image_tokens      INTEGER,
    cost_usd          REAL,
    latency_ms        INTEGER,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at        TEXT NOT NULL
);

INSERT INTO analysis_new (id, fingerprint_id, source_failure_id, path, model_id,
    code_mtime, root_cause, suggested_fix, confidence, inputs_used, is_superseded,
    tokens_in, tokens_out, cache_read_tokens, image_tokens, cost_usd, latency_ms,
    created_at, expires_at)
SELECT id, fingerprint_id, source_failure_id, path, model_id,
    code_mtime, root_cause, suggested_fix, confidence, inputs_used, is_superseded,
    tokens_in, tokens_out, cache_read_tokens, image_tokens, cost_usd, latency_ms,
    created_at, expires_at FROM analysis;
DROP TABLE analysis;
ALTER TABLE analysis_new RENAME TO analysis;

CREATE INDEX idx_analysis_fingerprint ON analysis (fingerprint_id, created_at DESC)
    WHERE is_superseded = 0;
CREATE INDEX idx_analysis_expiry ON analysis (expires_at);
"""

MIGRATION_7 = """
-- Two columns on two tables, both tables rebuilt for the reason migration 6
-- rebuilt `analysis`: SQLite cannot add a column carrying a CHECK that
-- references it.
--
-- `analysis.category` is the ROUTING class -- noise, known_pattern, novel --
-- which the engine computes on every analysis and then threw away. Without it
-- "noise skipped" can only be approximated by path='skipped', and that also
-- means "no exception found in this log".
--
-- `failure.fix_status` is REMEDIATION state, a different question from
-- `failure.status`, which tracks the pipeline. The POC kit kept this in
-- localStorage, where it is per-browser, invisible to a manager and outside
-- every access rule. As a column it is scoped through `bot` like the rest.
--
-- Existing rows get category NULL (nobody recorded it) and fix_status
-- 'pending' (nobody has said otherwise). Both are the honest values.
--
-- `failure` is dropped before `analysis` because it references it, and the
-- runner turns foreign keys off and runs foreign_key_check afterwards --
-- without that, dropping a parent silently takes its children with it, which
-- is exactly what an earlier migration did to every screenshot row.

CREATE TABLE analysis_new (
    id                INTEGER PRIMARY KEY,
    fingerprint_id    INTEGER NOT NULL REFERENCES fingerprint(id),
    source_failure_id INTEGER,             -- provenance only; never dereferenced cross-team (§5)
    -- Every value analysis.Path_ can produce. It used to list four of the six,
    -- so an analysis that came back from the dedup store or was skipped for
    -- want of an exception could not be written down at all -- the two
    -- outcomes the design is proudest of. A test now derives this list from
    -- the enum rather than trusting the two to stay in step.
    path              TEXT NOT NULL CHECK (path IN
                          ('dedup','template','text','vision','fallback','skipped')),
    model_id          TEXT,
    code_mtime        TEXT,                -- pseudo-version; no VCS exists (ARCHITECTURE.md §4.5)
    root_cause        TEXT,
    suggested_fix     TEXT,
    confidence        REAL CHECK (confidence BETWEEN 0 AND 1),
    inputs_used       TEXT NOT NULL DEFAULT '[]',   -- JSON array
    -- The ROUTING class: what the router decided to DO about this failure. It
    -- was computed on every analysis and then thrown away, so "noise skipped"
    -- could only be approximated by path='skipped' -- which also means "no
    -- exception found in this log". One column makes the headline metric exact
    -- instead of nearly right.
    category          TEXT CHECK (category IS NULL OR category IN
                          ('noise','known_pattern','novel')),
    -- The failure taxonomy. A separate axis from `path` (how it was answered)
    -- and from `category` (what we did about it): this is what KIND of failure
    -- it was, which is what a manager filters and colours by. Nullable
    -- throughout, because analyses stored before these existed have none of
    -- them and an older row must still render.
    failure_type      TEXT CHECK (failure_type IS NULL OR failure_type IN
                          ('timeout','auth','network','data_validation','rate_limit',
                           'ssl','file_io','selector','logic_error','other')),
    severity          TEXT CHECK (severity IS NULL OR severity IN
                          ('low','medium','high','critical')),
    affected_function TEXT,
    recommendations   TEXT,
    is_superseded     INTEGER NOT NULL DEFAULT 0 CHECK (is_superseded IN (0,1)),
    tokens_in         INTEGER,
    tokens_out        INTEGER,
    cache_read_tokens INTEGER,
    image_tokens      INTEGER,
    cost_usd          REAL,
    latency_ms        INTEGER,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at        TEXT NOT NULL
);

INSERT INTO analysis_new (
    id, fingerprint_id, source_failure_id, path, model_id, code_mtime,
    root_cause, suggested_fix, confidence, inputs_used, failure_type,
    severity, affected_function, recommendations, is_superseded, tokens_in,
    tokens_out, cache_read_tokens, image_tokens, cost_usd, latency_ms,
    created_at, expires_at)
SELECT
    id, fingerprint_id, source_failure_id, path, model_id, code_mtime,
    root_cause, suggested_fix, confidence, inputs_used, failure_type,
    severity, affected_function, recommendations, is_superseded, tokens_in,
    tokens_out, cache_read_tokens, image_tokens, cost_usd, latency_ms,
    created_at, expires_at FROM analysis;

CREATE TABLE failure_new (
    id                   INTEGER PRIMARY KEY,
    bot_id               INTEGER NOT NULL REFERENCES bot(id),
    fingerprint_id       INTEGER NOT NULL REFERENCES fingerprint(id),
    analysis_id          INTEGER REFERENCES analysis(id),
    occurred_at          TEXT NOT NULL,
    ingested_at          TEXT NOT NULL DEFAULT (datetime('now')),
    status               TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','deduped','analyzing','analyzed','failed','suppressed')),
    was_deduped          INTEGER NOT NULL DEFAULT 0 CHECK (was_deduped IN (0,1)),

    -- provenance: exactly where each input came from
    log_path             TEXT NOT NULL,     -- UNC path on the VM share
    screenshot_path      TEXT,              -- UNC path; NOT copied in Mode 0
    code_path            TEXT,
    code_mtime           TEXT,
    code_possibly_stale  INTEGER NOT NULL DEFAULT 0 CHECK (code_possibly_stale IN (0,1)),
    -- 'log_path' is the normal case: the log names the screenshot file (ARCHITECTURE 4.4).
    -- 'timestamp' is the fallback when no capture line exists; 'none' means we refused to guess.
    -- 'uploaded' means a person submitted the image alongside the log through the
    -- web UI. There is no sibling directory and no capture line to check it
    -- against, so it is whatever they attached -- recorded as its own method
    -- rather than borrowed from 'log_path', which would claim the log named it.
    pairing_method       TEXT CHECK (pairing_method IN
                             ('log_path','timestamp','none','uploaded')),

    log_sanitized        TEXT,              -- nulled at 90 days
    code_snapshot        TEXT,              -- nulled at 90 days
    severity             TEXT CHECK (severity IN ('low','medium','high','critical')),
    -- Remediation state, which is a different question from `status` above --
    -- that one tracks the PIPELINE (did we analyse this yet), this one tracks
    -- the DEVELOPER (have they done anything about it). The POC kit kept this
    -- in localStorage: per-browser, invisible to a manager, and outside every
    -- access rule. Here it is a column, so it is scoped by `bot` like
    -- everything else and a manager can see it.
    --
    -- Counted per distinct FINGERPRINT rather than per row: a 203-failure
    -- spike is one problem, and "203 pending" is a number nobody can act on.
    fix_status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (fix_status IN ('pending','reviewed','fixed')),
    correlation_id       TEXT NOT NULL,
    content_expires_at   TEXT NOT NULL,
    expires_at           TEXT NOT NULL
);

INSERT INTO failure_new (
    id, bot_id, fingerprint_id, analysis_id, occurred_at, ingested_at,
    status, was_deduped, log_path, screenshot_path, code_path, code_mtime,
    code_possibly_stale, pairing_method, log_sanitized, code_snapshot,
    severity, correlation_id, content_expires_at, expires_at)
SELECT
    id, bot_id, fingerprint_id, analysis_id, occurred_at, ingested_at,
    status, was_deduped, log_path, screenshot_path, code_path, code_mtime,
    code_possibly_stale, pairing_method, log_sanitized, code_snapshot,
    severity, correlation_id, content_expires_at, expires_at FROM failure;

DROP TABLE failure;
DROP TABLE analysis;
ALTER TABLE analysis_new RENAME TO analysis;
ALTER TABLE failure_new RENAME TO failure;

CREATE INDEX idx_analysis_fingerprint ON analysis (fingerprint_id, created_at DESC)
    WHERE is_superseded = 0;
CREATE INDEX idx_analysis_expiry ON analysis (expires_at);
CREATE UNIQUE INDEX idx_failure_idempotency ON failure (log_path);
CREATE INDEX idx_failure_bot_time     ON failure (bot_id, occurred_at DESC);
CREATE INDEX idx_failure_fingerprint  ON failure (fingerprint_id, occurred_at DESC);
CREATE INDEX idx_failure_pending      ON failure (status) WHERE status IN ('pending','analyzing');
CREATE INDEX idx_failure_feed         ON failure (occurred_at DESC);
CREATE INDEX idx_failure_content_expiry ON failure (content_expires_at)
    WHERE log_sanitized IS NOT NULL;
"""

MIGRATION_8 = """
-- Drop `failure.severity`. It was declared in the very first schema and NEVER
-- WRITTEN by any code path -- and because FailureRepo.SELECT_ begins with
-- `f.*`, it shadowed the live `analysis.severity` in every joined row. A
-- sqlite3.Row name lookup returns the first column of that name, so
-- `row["severity"]` was the dead one: always NULL. The severity badge on the
-- failure page and in the diagnosis email could never appear, and nothing
-- failed to say so.
--
-- Dropping it is the fix. Aliasing the live column would have worked and left
-- the trap sitting there for whoever added the next join.

CREATE TABLE failure_new (
    id                   INTEGER PRIMARY KEY,
    bot_id               INTEGER NOT NULL REFERENCES bot(id),
    fingerprint_id       INTEGER NOT NULL REFERENCES fingerprint(id),
    analysis_id          INTEGER REFERENCES analysis(id),
    occurred_at          TEXT NOT NULL,
    ingested_at          TEXT NOT NULL DEFAULT (datetime('now')),
    status               TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','deduped','analyzing','analyzed','failed','suppressed')),
    was_deduped          INTEGER NOT NULL DEFAULT 0 CHECK (was_deduped IN (0,1)),

    -- provenance: exactly where each input came from
    log_path             TEXT NOT NULL,     -- UNC path on the VM share
    screenshot_path      TEXT,              -- UNC path; NOT copied in Mode 0
    code_path            TEXT,
    code_mtime           TEXT,
    code_possibly_stale  INTEGER NOT NULL DEFAULT 0 CHECK (code_possibly_stale IN (0,1)),
    -- 'log_path' is the normal case: the log names the screenshot file (ARCHITECTURE 4.4).
    -- 'timestamp' is the fallback when no capture line exists; 'none' means we refused to guess.
    -- 'uploaded' means a person submitted the image alongside the log through the
    -- web UI. There is no sibling directory and no capture line to check it
    -- against, so it is whatever they attached -- recorded as its own method
    -- rather than borrowed from 'log_path', which would claim the log named it.
    pairing_method       TEXT CHECK (pairing_method IN
                             ('log_path','timestamp','none','uploaded')),

    log_sanitized        TEXT,              -- nulled at 90 days
    code_snapshot        TEXT,              -- nulled at 90 days
    -- Remediation state, which is a different question from `status` above --
    -- that one tracks the PIPELINE (did we analyse this yet), this one tracks
    -- the DEVELOPER (have they done anything about it). The POC kit kept this
    -- in localStorage: per-browser, invisible to a manager, and outside every
    -- access rule. Here it is a column, so it is scoped by `bot` like
    -- everything else and a manager can see it.
    --
    -- Counted per distinct FINGERPRINT rather than per row: a 203-failure
    -- spike is one problem, and "203 pending" is a number nobody can act on.
    fix_status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (fix_status IN ('pending','reviewed','fixed')),
    correlation_id       TEXT NOT NULL,
    content_expires_at   TEXT NOT NULL,
    expires_at           TEXT NOT NULL
);

INSERT INTO failure_new (
    id, bot_id, fingerprint_id, analysis_id, occurred_at, ingested_at,
    status, was_deduped, log_path, screenshot_path, code_path, code_mtime,
    code_possibly_stale, pairing_method, log_sanitized, code_snapshot,
    fix_status, correlation_id, content_expires_at, expires_at)
SELECT
    id, bot_id, fingerprint_id, analysis_id, occurred_at, ingested_at,
    status, was_deduped, log_path, screenshot_path, code_path, code_mtime,
    code_possibly_stale, pairing_method, log_sanitized, code_snapshot,
    fix_status, correlation_id, content_expires_at, expires_at FROM failure;

DROP TABLE failure;
ALTER TABLE failure_new RENAME TO failure;

CREATE UNIQUE INDEX idx_failure_idempotency ON failure (log_path);
CREATE INDEX idx_failure_bot_time     ON failure (bot_id, occurred_at DESC);
CREATE INDEX idx_failure_fingerprint  ON failure (fingerprint_id, occurred_at DESC);
CREATE INDEX idx_failure_pending      ON failure (status) WHERE status IN ('pending','analyzing');
CREATE INDEX idx_failure_feed         ON failure (occurred_at DESC);
CREATE INDEX idx_failure_content_expiry ON failure (content_expires_at)
    WHERE log_sanitized IS NOT NULL;
"""

MIGRATIONS: dict[int, str] = {2: MIGRATION_2, 3: MIGRATION_3, 4: MIGRATION_4,
                              5: MIGRATION_5, 6: MIGRATION_6,
                              7: MIGRATION_7, 8: MIGRATION_8}


# How long a writer waits for another writer before giving up. SQLite allows
# one writer at a time; without a busy timeout the second one raises "database
# is locked" immediately, which under a web server means a request fails for no
# reason a user could understand.
BUSY_TIMEOUT_MS = 5000


class Database:
    """One SQLite file, one connection PER THREAD.

    A single shared connection is correct for a CLI and raises ProgrammingError
    the first time a web server handles two requests at once -- sqlite3 refuses
    to use a connection from a thread other than the one that created it, and
    that refusal is the good outcome. The bad one is `check_same_thread=False`,
    which makes the error go away and leaves several threads interleaving
    statements on one connection and one transaction.

    So each thread opens its own. WAL mode allows many readers alongside one
    writer, and BUSY_TIMEOUT_MS makes a second writer wait its turn instead of
    failing. The API is unchanged: `db.conn` is still the connection, it is just
    the right one for whoever is asking.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self.migrate()

    @property
    def conn(self) -> sqlite3.Connection:
        existing = getattr(self._local, "conn", None)
        if existing is not None:
            return existing
        conn = sqlite3.connect(str(self.path), isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        self._local.conn = conn
        with self._lock:
            self._all.append(conn)
        return conn

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
            self._run_migration(step, current + 1)
            current += 1
            self.conn.execute(f"PRAGMA user_version = {current}")

    def _run_migration(self, script: str, to_version: int) -> None:
        """Apply one migration with foreign keys off, then prove they still hold.

        SQLite cannot alter a CHECK constraint, so those migrations rebuild the
        table -- and a DROP TABLE with foreign keys ON cascades. Dropping
        `failure` to rebuild it silently deleted every `screenshot` row, because
        the child has ON DELETE CASCADE. This is SQLite's own documented
        procedure for the rebuild (its ALTER TABLE page, the twelve steps):
        disable enforcement, rebuild, re-enable, and then run foreign_key_check
        so a migration that really did orphan something fails loudly instead of
        leaving a quietly broken database behind.
        """
        self.conn.execute("PRAGMA foreign_keys = OFF")
        try:
            self.conn.executescript(script)
            broken = self.conn.execute("PRAGMA foreign_key_check").fetchall()
            if broken:
                raise RuntimeError(
                    f"migration to schema {to_version} left {len(broken)} broken "
                    f"foreign key reference(s): {broken[:3]}")
        finally:
            self.conn.execute("PRAGMA foreign_keys = ON")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    @staticmethod
    def day_expr(column: str) -> str:
        """SQL grouping `column` to a YYYY-MM-DD string, per dialect.

        Timestamps are TEXT here and TIMESTAMPTZ in PostgreSQL, so `substr`
        works on one and not the other. One method rather than a dialect check
        wherever a chart groups by day.
        """
        return f"substr({column}, 1, 10)"

    @staticmethod
    def encode_list(values) -> str:
        """A list of strings, as this dialect stores it.

        SQLite has no array type, so `inputs_used` is JSON in a TEXT column.
        PostgreSQL has TEXT[] and refuses the JSON string with "malformed array
        literal". One method rather than a dialect check at the call site.
        """
        return json.dumps(list(values))

    @staticmethod
    def decode_list(value) -> tuple[str, ...]:
        """The inverse of `encode_list`, for whichever dialect wrote it.

        Tolerant of both because a row can outlive a migration between them:
        SQLite hands back the JSON string, PostgreSQL hands back a list, and
        `json.loads` on the list raises. Anything unreadable becomes empty
        rather than raising -- `inputs_used` decorates a report, and a report
        that will not render because a list did not parse is a worse outcome
        than one that says "log only".
        """
        if not value:
            return ()
        if isinstance(value, (list, tuple)):
            return tuple(str(v) for v in value)
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return ()
        return tuple(str(v) for v in decoded) if isinstance(decoded, list) else ()

    def close(self) -> None:
        """Close every thread's connection, not just this thread's."""
        with self._lock:
            connections, self._all = self._all, []
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()


DATABASE_URL_VAR = "DATABASE_URL"


def open_database(target: "Path | str | None" = None,
                  env: dict[str, str] | None = None):
    """The database this process should use: PostgreSQL if a DSN is set, else SQLite.

    One function so nothing else has to know which it got. The CLI passes a path
    and gets SQLite; a container sets DATABASE_URL and gets PostgreSQL without a
    code change, which is what Railway and every other platform hands you.
    """
    import os
    env = env if env is not None else os.environ
    dsn = (env.get(DATABASE_URL_VAR) or "").strip()
    if dsn:
        if dsn.startswith("postgres://"):
            # Several platforms still emit the old scheme; psycopg wants the
            # current one, and the failure without this is an unhelpful
            # "missing connection parameter".
            dsn = "postgresql://" + dsn[len("postgres://"):]
        from .storage_pg import PostgresDatabase
        return PostgresDatabase(dsn)
    if target is None:
        raise ValueError(
            "no DATABASE_URL and no path given -- refusing to guess where the "
            "database should live.")
    return Database(target)


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


class PatternRepo(Repository):
    """The known-pattern library, in the database.

    The library ships as eagle_eyes/patterns.json, but the TABLE is what the
    product reads. That is the point of `sync()`: an estate can deactivate a
    pattern, or correct a fix that turned out to be wrong for its environment,
    without waiting for a release. A pattern answers real failures without a
    model call and without review, so being able to switch one off in seconds
    matters more than it would for anything else here.
    """

    def sync(self, patterns=None) -> int:
        """Load the shipped library into the table. Idempotent.

        An existing row's `is_active` is left alone -- it is the one field an
        operator sets, and a deploy that silently switched a disabled pattern
        back on would undo a decision somebody made deliberately.
        """
        from .patterns import PatternLibrary, to_row
        if patterns is None:
            patterns = PatternLibrary.from_file().patterns
        n = 0
        for pattern in patterns:
            row = to_row(pattern)
            cur = self.db.conn.execute("SELECT id FROM pattern WHERE name=?",
                                       (row["name"],))
            existing = cur.fetchone()
            if existing:
                self.db.conn.execute(
                    "UPDATE pattern SET match_rule=?, response_template=?,"
                    " severity=? WHERE id=?",
                    (row["match_rule"], row["response_template"], row["severity"],
                     existing["id"]))
            else:
                self.db.conn.execute(
                    "INSERT INTO pattern(name, match_rule, response_template, severity)"
                    " VALUES (?,?,?,?)",
                    (row["name"], row["match_rule"], row["response_template"],
                     row["severity"]))
                n += 1
        self._audit("sync", "pattern", "library")
        return n

    def active(self) -> list[sqlite3.Row]:
        """In insertion order, which is the order the library file declares.

        Order is load-bearing: the first match wins, so a narrow pattern has to
        be able to sit ahead of a broad one.
        """
        return list(self.db.conn.execute(
            "SELECT * FROM pattern WHERE is_active = TRUE ORDER BY id"))

    def all(self) -> list[sqlite3.Row]:
        return list(self.db.conn.execute("SELECT * FROM pattern ORDER BY id"))

    def set_active(self, name: str, active: bool) -> None:
        self.db.conn.execute("UPDATE pattern SET is_active=? WHERE name=?",
                             (bool(active), name))
        self._audit("activate" if active else "deactivate", "pattern", name)

    def library(self):
        """The active patterns, compiled into a matcher."""
        from .patterns import from_rows
        return from_rows(self.active())


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
               " WHERE a.fingerprint_id=? AND a.is_superseded = FALSE AND a.created_at >= ?"
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
            latency_ms: int = 0, cache_read_tokens: int = 0, image_tokens: int = 0,
            category: str = "", failure_type: str = "", severity: str = "",
            affected_function: str = "", recommendations: str = "",
            retain_days: int = 365) -> int:
        """Store a diagnosis.

        `category` and the taxonomy fields default to empty and are stored as
        NULL when empty rather than as "". The column CHECK accepts NULL or a
        member of the closed list, so "" would be refused -- and an
        unclassified analysis is a real outcome (a template answer, an older
        model, a model that omitted the field), not an error.

        `cache_read_tokens` and `image_tokens` have been in the schema since
        the first commit and were never written: the gateway computes them, the
        cost calculation consumes them, and nothing carried them this far. Any
        chart of cache hit rate read an all-NULL column until they were added
        to this insert.
        """
        cur = self.db.conn.execute(
            "INSERT INTO analysis(fingerprint_id, path, model_id, code_mtime, root_cause,"
            " suggested_fix, confidence, inputs_used, category, failure_type, severity,"
            " affected_function, recommendations, tokens_in, tokens_out,"
            " cache_read_tokens, image_tokens, cost_usd, latency_ms, created_at,"
            " expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fingerprint_id, path, model_id, code_mtime, root_cause, suggested_fix,
             confidence, self.db.encode_list(inputs_used),
             category or None, failure_type or None, severity or None,
             affected_function or None, recommendations or None,
             tokens_in, tokens_out, cache_read_tokens, image_tokens,
             cost_usd, latency_ms, now(), _plus(retain_days)))
        self._audit("create", "analysis", cur.lastrowid)
        return cur.lastrowid

    def get(self, analysis_id: int) -> sqlite3.Row | None:
        row = self.db.conn.execute("SELECT * FROM analysis WHERE id=?",
                                   (analysis_id,)).fetchone()
        self._audit("read", "analysis", analysis_id, "allow" if row else "deny")
        return row

    def supersede(self, analysis_id: int) -> None:
        self.db.conn.execute("UPDATE analysis SET is_superseded = TRUE WHERE id=?",
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
                 bool(was_deduped), log_path, screenshot_path, code_path, code_mtime,
                 bool(code_possibly_stale), pairing_method, log_sanitized, code_snapshot,
                 correlation_id, _plus(content_days), _plus(retain_days)))
            return cur.lastrowid
        except INTEGRITY_ERRORS:
            return None

    SELECT_ = ("SELECT f.*, b.service_line, b.bot_number, b.owner_dev_id,"
               " a.root_cause, a.confidence, a.suggested_fix, a.path, a.model_id,"
               " a.failure_type, a.severity, a.affected_function, a.recommendations,"
               " a.inputs_used, a.category, a.cost_usd, a.latency_ms,"
               " fp.exception_type, fp.normalized_message"
               " FROM failure f JOIN bot b ON b.id=f.bot_id"
               " JOIN fingerprint fp ON fp.id=f.fingerprint_id"
               " LEFT JOIN analysis a ON a.id=f.analysis_id")

    def _scope_sql(self) -> tuple[str, list[Any]]:
        """The WHERE clause that implements the role, in SQL.

        Written in the subset both dialects share: TRUE and FALSE rather than
        1 and 0. SQLite treats an integer as a condition and PostgreSQL refuses
        it ("argument of WHERE must be type boolean"), and the place that would
        have bitten is `AND FALSE` -- the clause that makes an empty manager
        scope mean no rows.

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
                return " AND FALSE", []
            marks = ",".join("?" for _ in self.p.scope)
            return f" AND b.service_line IN ({marks})", sorted(self.p.scope)
        return (" AND b.owner_dev_id IN"
                " (SELECT id FROM developer WHERE email = ?)", [self.p.actor.lower()])

    def recent(self, limit: int = 50, offset: int = 0) -> list[sqlite3.Row]:
        where, args = self._scope_sql()
        sql = f"{self.SELECT_} WHERE TRUE{where} ORDER BY f.occurred_at DESC LIMIT ? OFFSET ?"
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

    FIX_STATUSES = ("pending", "reviewed", "fixed")

    def set_fix_status(self, failure_id: int, status: str) -> int:
        """Mark this PROBLEM, not this row. Returns how many rows changed.

        Every in-scope failure sharing the fingerprint moves together, because
        that is what a developer means. A 203-failure incident is one problem
        with one fix; marking the one row somebody happened to open would leave
        202 saying "pending" and make the workload numbers useless.

        `_scope_sql` is applied to the UPDATE as well as to the initial read --
        without it, a user who can see one failure of a fingerprint could move
        every other team's failures of the same fingerprint, and fingerprints
        are deliberately shared across teams.
        """
        if status not in self.FIX_STATUSES:
            raise ValueError(f"fix status {status!r} is not one of {self.FIX_STATUSES}")
        row = self.get(failure_id)                  # raises AccessDenied if not theirs
        where, args = self._scope_sql()
        cur = self.db.conn.execute(
            "UPDATE failure SET fix_status = ? WHERE id IN ("
            f"  SELECT f.id FROM failure f JOIN bot b ON b.id=f.bot_id"
            f"  WHERE f.fingerprint_id = ?{where})",
            [status, row["fingerprint_id"], *args])
        self._audit(f"fix_{status}", "failure", failure_id)
        return cur.rowcount if cur.rowcount is not None else 0

    def visible_count(self) -> int:
        where, args = self._scope_sql()
        return self.db.conn.execute(
            f"SELECT COUNT(*) n FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" WHERE TRUE{where}", args).fetchone()["n"]

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
        base = f"FROM failure f JOIN bot b ON b.id=f.bot_id WHERE TRUE{where}"
        total = c.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
        deduped = c.execute(
            f"SELECT COUNT(*) {base} AND f.was_deduped = TRUE", args).fetchone()[0]
        spend = c.execute(
            f"SELECT COALESCE(SUM(a.cost_usd),0) FROM analysis a WHERE a.id IN"
            f" (SELECT f.analysis_id {base} AND f.analysis_id IS NOT NULL)",
            args).fetchone()[0]
        fps = c.execute(
            f"SELECT COUNT(DISTINCT f.fingerprint_id) {base}", args).fetchone()[0]
        return {"failures": total, "deduped": deduped, "fingerprints": fps,
                "dedup_rate": (deduped / total) if total else 0.0,
                "spend_usd": spend}


    # -- analytics -----------------------------------------------------
    #
    # Every one of these goes through _scope_sql. A chart is data: a trend line
    # drawn over rows the reader cannot open would leak exactly what the
    # scoping exists to prevent -- how busy another team is, and what it costs.

    def daily_counts(self, days: int = 30) -> list[tuple[str, int, int]]:
        """(day, failures, deduped) for the last `days`, oldest first."""
        where, args = self._scope_sql()
        day = self.db.day_expr("f.occurred_at")
        rows = self.db.conn.execute(
            f"SELECT {day} d, COUNT(*) n,"
            f" SUM(CASE WHEN f.was_deduped = TRUE THEN 1 ELSE 0 END) dedup"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id WHERE TRUE{where}"
            f" GROUP BY {day} ORDER BY {day} DESC LIMIT ?",
            [*args, max(1, min(days, 365))]).fetchall()
        return [(r["d"], r["n"], r["dedup"] or 0) for r in reversed(rows)]

    def top_fingerprints(self, limit: int = 8) -> list[dict]:
        """The failures that happen most, with what they cost to diagnose."""
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT fp.exception_type, fp.normalized_message, fp.code_location,"
            f" COUNT(*) n, MAX(f.occurred_at) last_seen,"
            f" COALESCE(MAX(a.confidence), 0) confidence,"
            f" COALESCE(SUM(a.cost_usd), 0) cost"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" JOIN fingerprint fp ON fp.id = f.fingerprint_id"
            f" LEFT JOIN analysis a ON a.id = f.analysis_id"
            f" WHERE TRUE{where} GROUP BY fp.id, fp.exception_type,"
            f" fp.normalized_message, fp.code_location"
            f" ORDER BY n DESC, last_seen DESC LIMIT ?",
            [*args, max(1, min(limit, 50))]).fetchall()
        return [dict(r) for r in rows]

    def confidence_buckets(self) -> list[tuple[str, int]]:
        """How sure the diagnoses were. A tall low bucket is a quality signal."""
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT a.confidence c FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" JOIN analysis a ON a.id=f.analysis_id WHERE TRUE{where}",
            args).fetchall()
        buckets = {"0.0-0.3": 0, "0.3-0.5": 0, "0.5-0.7": 0, "0.7-0.9": 0, "0.9-1.0": 0}
        for r in rows:
            c = float(r["c"] or 0)
            if c < 0.3:   buckets["0.0-0.3"] += 1
            elif c < 0.5: buckets["0.3-0.5"] += 1
            elif c < 0.7: buckets["0.5-0.7"] += 1
            elif c < 0.9: buckets["0.7-0.9"] += 1
            else:         buckets["0.9-1.0"] += 1
        return list(buckets.items())

    def path_breakdown(self) -> list[tuple[str, int]]:
        """Which route each analysis took -- the dedup story, in one chart."""
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT COALESCE(a.path, 'not analysed') p, COUNT(*) n"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" LEFT JOIN analysis a ON a.id=f.analysis_id"
            f" WHERE TRUE{where} GROUP BY COALESCE(a.path, 'not analysed')"
            f" ORDER BY n DESC", args).fetchall()
        return [(r["p"], r["n"]) for r in rows]

    def routing_breakdown(self) -> list[tuple[str, int]]:
        """What the router DECIDED, which is not the same as how it answered.

        `path_breakdown` says how each analysis was reached -- dedup, template,
        text. This says what the router concluded about the failure: noise not
        worth a developer's time, a known pattern, or something novel. The two
        together are the whole cost argument.
        """
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT COALESCE(a.category, 'unclassified') c, COUNT(*) n"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" LEFT JOIN analysis a ON a.id=f.analysis_id"
            f" WHERE TRUE{where} GROUP BY COALESCE(a.category, 'unclassified')"
            f" ORDER BY n DESC", args).fetchall()
        # Underscores are a column value, not a label. `known_pattern` in a
        # legend reads as a leaked identifier.
        return [(r["c"].replace("_", " "), r["n"]) for r in rows]

    def severity_breakdown(self) -> list[tuple[str, int]]:
        """Worst first, and only rows a model actually classified.

        Unclassified rows are excluded rather than bucketed as 'low': a
        template answer and an older analysis both have NULL here, and calling
        them low severity would invent a judgement nobody made.
        """
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT a.severity s, COUNT(*) n"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" JOIN analysis a ON a.id=f.analysis_id"
            f" WHERE TRUE{where} AND a.severity IS NOT NULL"
            f" GROUP BY a.severity", args).fetchall()
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(((r["s"], r["n"]) for r in rows),
                      key=lambda kv: order.get(kv[0], 9))

    def failure_type_breakdown(self, limit: int = 10) -> list[tuple[str, int]]:
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT a.failure_type t, COUNT(*) n"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" JOIN analysis a ON a.id=f.analysis_id"
            f" WHERE TRUE{where} AND a.failure_type IS NOT NULL"
            f" GROUP BY a.failure_type ORDER BY n DESC LIMIT ?",
            [*args, max(1, min(limit, 50))]).fetchall()
        return [(r["t"].replace("_", " "), r["n"]) for r in rows]

    def efficiency(self) -> dict[str, Any]:
        """The numbers that say what the routing is worth.

        `avg_latency_ms` counts only analyses that actually called a model.
        Dedup hits and template answers store 0, and averaging those in would
        report a system that answers in a few milliseconds -- true, and a lie
        about what a diagnosis costs in time.

        `cache_hit_rate` is cached input tokens over all input tokens. It read
        an all-NULL column until `cache_read_tokens` was threaded into the
        insert, which is why it is stated here rather than assumed elsewhere.
        """
        where, args = self._scope_sql()
        base = (f" FROM failure f JOIN bot b ON b.id=f.bot_id"
                f" JOIN analysis a ON a.id=f.analysis_id WHERE TRUE{where}")
        row = self.db.conn.execute(
            f"SELECT COUNT(*) n,"
            f" COALESCE(SUM(a.tokens_in), 0) tin,"
            f" COALESCE(SUM(a.cache_read_tokens), 0) tcache,"
            f" COALESCE(SUM(a.latency_ms), 0) lat_all,"
            f" COALESCE(SUM(CASE WHEN a.latency_ms > 0 THEN a.latency_ms ELSE 0 END), 0) lat,"
            f" COALESCE(SUM(CASE WHEN a.latency_ms > 0 THEN 1 ELSE 0 END), 0) timed"
            f"{base}", args).fetchone()
        tin = float(row["tin"] or 0)
        timed = int(row["timed"] or 0)
        return {
            "analyses": int(row["n"] or 0),
            "tokens_in": tin,
            "cache_read_tokens": float(row["tcache"] or 0),
            "cache_hit_rate": (float(row["tcache"] or 0) / tin) if tin else 0.0,
            "avg_latency_ms": (float(row["lat"] or 0) / timed) if timed else 0.0,
            "timed_analyses": timed,
        }

    def notifications(self) -> dict[str, int]:
        """How many diagnoses were mailed, and how many were held back.

        Scoped through fingerprint -> failure -> bot, because
        `notification_state` is keyed on a fingerprint and fingerprints are
        deliberately shared across teams. One row is one mail sent; the
        suppressed count is how many repeats it stood in for.
        """
        where, args = self._scope_sql()
        row = self.db.conn.execute(
            f"SELECT COUNT(*) sent, COALESCE(SUM(ns.suppressed_count), 0) held"
            f" FROM notification_state ns"
            f" WHERE ns.fingerprint_id IN ("
            f"   SELECT f.fingerprint_id FROM failure f"
            f"   JOIN bot b ON b.id=f.bot_id WHERE TRUE{where})", args).fetchone()
        return {"sent": int(row["sent"] or 0), "suppressed": int(row["held"] or 0)}

    def fix_status_counts(self) -> dict[str, int]:
        """Per distinct PROBLEM, not per failure.

        A 203-failure incident is one problem with one fix. Counting rows would
        report 203 pending and make the number unusable -- which is exactly why
        `set_fix_status` moves every failure sharing a fingerprint together.
        """
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT f.fix_status s, COUNT(DISTINCT f.fingerprint_id) n"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" WHERE TRUE{where} GROUP BY f.fix_status", args).fetchall()
        out = {k: 0 for k in self.FIX_STATUSES}
        out.update({r["s"]: r["n"] for r in rows})
        return out

    def routing_savings(self) -> dict[str, Any]:
        """What the routing layer avoided, against analysing every failure.

        The buckets are MUTUALLY EXCLUSIVE and computed in one pass, in
        priority order, because they overlap in the data: a deduplicated
        failure points at an analysis that may itself have been a template
        answer, so counting `was_deduped` and `path='template'` separately and
        adding them reports more avoided calls than there are failures. It did,
        on the seeded estate: 230 + 251 = 481 against 260 failures.

        `analysed` is the only bucket that cost anything -- the text and vision
        paths. Everything else is a failure that never reached a model, and the
        reason it did not is which bucket it lands in.
        """
        where, args = self._scope_sql()
        row = self.db.conn.execute(
            f"SELECT"
            f" COUNT(*) total,"
            f" COALESCE(SUM(CASE WHEN f.was_deduped = TRUE THEN 1 ELSE 0 END), 0) deduped,"
            f" COALESCE(SUM(CASE WHEN f.was_deduped = FALSE AND a.path = 'template'"
            f"      THEN 1 ELSE 0 END), 0) templated,"
            f" COALESCE(SUM(CASE WHEN f.was_deduped = FALSE AND a.path <> 'template'"
            f"      AND a.category = 'noise' THEN 1 ELSE 0 END), 0) noise,"
            f" COALESCE(SUM(CASE WHEN f.was_deduped = FALSE"
            f"      AND a.path IN ('text','vision') THEN 1 ELSE 0 END), 0) analysed,"
            f" COALESCE(SUM(CASE WHEN a.path IN ('text','vision')"
            f"      THEN a.cost_usd ELSE 0 END), 0) spend"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" LEFT JOIN analysis a ON a.id=f.analysis_id"
            f" WHERE TRUE{where}", args).fetchone()

        total = int(row["total"] or 0)
        analysed = int(row["analysed"] or 0)
        spend = float(row["spend"] or 0)
        avoided = {"deduplicated": int(row["deduped"] or 0),
                   "known pattern": int(row["templated"] or 0),
                   "classified as noise": int(row["noise"] or 0)}
        calls_avoided = sum(avoided.values())

        # The basis is the mean cost of the calls ACTUALLY MADE HERE. Without a
        # priced call there is nothing to multiply by, and reaching for a list
        # price or a figure from the cost model would describe somebody else's
        # deployment. Zero, and the page says why.
        mean = (spend / analysed) if (analysed and spend > 0) else 0.0
        return {"total": total, "analysed": analysed, "spend_usd": spend,
                "avoided": avoided, "calls_avoided": calls_avoided,
                "mean_usd": mean, "usd": calls_avoided * mean,
                "have_basis": mean > 0}

    def by_developer(self, limit: int = 12) -> list[dict]:
        """Workload per owner: problems, not occurrences.

        A bot with no owner is reported as unassigned rather than dropped --
        an unowned bot is the thing a manager most needs to see, and silently
        omitting it is how it stays unowned.
        """
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT COALESCE(d.email, 'unassigned') owner,"
            f" COUNT(*) failures,"
            f" COUNT(DISTINCT f.fingerprint_id) problems,"
            f" COUNT(DISTINCT CASE WHEN f.fix_status = 'pending'"
            f"      THEN f.fingerprint_id END) pending,"
            f" MAX(f.occurred_at) last_seen"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" LEFT JOIN developer d ON d.id = b.owner_dev_id"
            f" WHERE TRUE{where}"
            f" GROUP BY COALESCE(d.email, 'unassigned')"
            f" ORDER BY problems DESC, failures DESC LIMIT ?",
            [*args, max(1, min(limit, 100))]).fetchall()
        return [dict(r) for r in rows]

    def activity(self, limit: int = 20) -> list[dict]:
        """The most recent failures, with how each was answered and what it cost."""
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT f.id, f.occurred_at, f.fix_status, b.service_line, b.bot_number,"
            f" COALESCE(a.path, 'not analysed') path, a.category, a.severity,"
            f" COALESCE(a.cost_usd, 0) cost"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" LEFT JOIN analysis a ON a.id=f.analysis_id"
            f" WHERE TRUE{where} ORDER BY f.occurred_at DESC LIMIT ?",
            [*args, max(1, min(limit, 100))]).fetchall()
        return [dict(r) for r in rows]

    def by_service_line(self) -> list[dict]:
        """Per service line: volume, distinct problems, spend. The manager view."""
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT b.service_line, COUNT(*) n,"
            f" COUNT(DISTINCT f.fingerprint_id) fingerprints,"
            f" SUM(CASE WHEN f.was_deduped = TRUE THEN 1 ELSE 0 END) dedup,"
            f" COALESCE(SUM(a.cost_usd), 0) cost"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" LEFT JOIN analysis a ON a.id=f.analysis_id"
            f" WHERE TRUE{where} GROUP BY b.service_line ORDER BY n DESC",
            args).fetchall()
        return [dict(r) for r in rows]

    def by_bot(self, limit: int = 12) -> list[dict]:
        where, args = self._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT b.service_line, b.bot_number, COALESCE(d.email, '') owner,"
            f" COUNT(*) n, COUNT(DISTINCT f.fingerprint_id) fingerprints,"
            f" COALESCE(SUM(a.cost_usd), 0) cost, MAX(f.occurred_at) last_seen"
            f" FROM failure f JOIN bot b ON b.id=f.bot_id"
            f" LEFT JOIN developer d ON d.id = b.owner_dev_id"
            f" LEFT JOIN analysis a ON a.id=f.analysis_id"
            f" WHERE TRUE{where} GROUP BY b.id, b.service_line, b.bot_number,"
            f" COALESCE(d.email, '') ORDER BY n DESC LIMIT ?",
            [*args, max(1, min(limit, 100))]).fetchall()
        return [dict(r) for r in rows]


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
        # ON CONFLICT rather than INSERT OR REPLACE: both dialects accept this
        # form, and it also says WHICH conflict is being resolved. OR REPLACE
        # deletes the existing row and inserts a new one, which fires ON DELETE
        # CASCADE on anything referencing it -- a footgun that has nothing to do
        # with "change this person's verdict".
        self.db.conn.execute(
            "INSERT INTO feedback(analysis_id, failure_id, developer_id,"
            " verdict, comment, created_at) VALUES (?,?,?,?,?,?)"
            " ON CONFLICT(analysis_id, developer_id) DO UPDATE SET"
            "   verdict = excluded.verdict, comment = excluded.comment,"
            "   created_at = excluded.created_at",
            (analysis_id, failure_id, developer_id, verdict, comment, now()))
        self._audit("feedback", "analysis", analysis_id)

    def tally(self) -> dict[str, int]:
        """Verdict counts over the failures this principal can see.

        This used to count every row in the table. A plain user asking how the
        diagnoses were rated got the answer for the whole estate -- a small
        leak, but the same kind stats() is scoped to avoid, and inconsistent
        with it in a way nobody would notice from reading either one.
        """
        scoped = FailureRepo(self.db, self.p)
        where, args = scoped._scope_sql()
        rows = self.db.conn.execute(
            f"SELECT fb.verdict, COUNT(*) n FROM feedback fb"
            f" JOIN failure f ON f.id = fb.failure_id"
            f" JOIN bot b ON b.id = f.bot_id WHERE TRUE{where}"
            f" GROUP BY fb.verdict", args).fetchall()
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

    def email_of(self, developer_id: int | None) -> str:
        """The address for a developer id, or empty. Never invented.

        An empty answer is the correct one when a bot has no owner: the caller
        refuses to send rather than guessing a recipient, because a diagnosis
        mailed to the wrong person is both useless and a disclosure.
        """
        if developer_id is None:
            return ""
        row = self.db.conn.execute(
            "SELECT email FROM developer WHERE id=?", (developer_id,)).fetchone()
        return row["email"] if row else ""

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
            "INSERT INTO scan_watermark(file_path, file_mtime, file_size,"
            " processed_at, outcome) VALUES (?,?,?,?,?)"
            " ON CONFLICT(file_path) DO UPDATE SET"
            "   file_mtime = excluded.file_mtime, file_size = excluded.file_size,"
            "   processed_at = excluded.processed_at, outcome = excluded.outcome",
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
