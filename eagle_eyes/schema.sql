-- Eagle Eyes schema.
--
-- AUTHORITATIVE. docs/DATA_MODEL.md section 4 embeds this file verbatim, and
-- tests/test_storage.py fails if the two drift apart. Edit here, then paste
-- into the doc -- never the other way round.
--
-- Rationale for the non-obvious choices lives in the doc: why hash is TEXT and
-- not CHAR(64) (7.2), why there is no second index on (hash, version) (7.1),
-- and what changes when this ports to Postgres (8).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------- organisation ----------

CREATE TABLE team (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    sso_group   TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE developer (
    id           INTEGER PRIMARY KEY,
    email        TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    team_id      INTEGER NOT NULL REFERENCES team(id),
    is_active    INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- service_line and bot_number come from the share path, not from log content.
CREATE TABLE bot (
    id            INTEGER PRIMARY KEY,
    service_line  TEXT NOT NULL,
    bot_number    TEXT NOT NULL,
    name          TEXT,
    team_id       INTEGER REFERENCES team(id),
    owner_dev_id  INTEGER REFERENCES developer(id),
    code_path     TEXT,                    -- resolved file in the shared code folder
    is_active     INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (service_line, bot_number)
);

-- ---------- known patterns ----------

CREATE TABLE pattern (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    match_rule        TEXT NOT NULL,       -- JSON
    response_template TEXT NOT NULL,
    severity          TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    is_active         INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- dedup ----------

CREATE TABLE fingerprint (
    id                 INTEGER PRIMARY KEY,
    hash               TEXT NOT NULL CHECK (length(hash) = 64),
    version            INTEGER NOT NULL,
    exception_type     TEXT NOT NULL,
    normalized_message TEXT NOT NULL,
    code_location      TEXT NOT NULL,
    first_seen_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at       TEXT NOT NULL DEFAULT (datetime('now')),
    occurrence_count   INTEGER NOT NULL DEFAULT 1,
    pattern_id         INTEGER REFERENCES pattern(id),
    expires_at         TEXT NOT NULL,
    UNIQUE (hash, version)
);

-- NOTE: no separate index on (hash, version). The UNIQUE constraint above already
-- creates one, and SQLite uses it as a COVERING INDEX for the dedup lookup. A second
-- index on the same columns would be dead weight on every write. Verified — see §7.
CREATE INDEX idx_fingerprint_expiry ON fingerprint (expires_at);

-- ---------- analyses ----------

CREATE TABLE analysis (
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

CREATE INDEX idx_analysis_fingerprint ON analysis (fingerprint_id, created_at DESC)
    WHERE is_superseded = 0;
CREATE INDEX idx_analysis_expiry ON analysis (expires_at);

-- ---------- failures ----------

CREATE TABLE failure (
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

-- The scanner is restartable and re-reads folders; this makes a re-scan a no-op.
CREATE UNIQUE INDEX idx_failure_idempotency ON failure (log_path);
CREATE INDEX idx_failure_bot_time     ON failure (bot_id, occurred_at DESC);
CREATE INDEX idx_failure_fingerprint  ON failure (fingerprint_id, occurred_at DESC);
CREATE INDEX idx_failure_pending      ON failure (status) WHERE status IN ('pending','analyzing');
CREATE INDEX idx_failure_feed         ON failure (occurred_at DESC);
CREATE INDEX idx_failure_content_expiry ON failure (content_expires_at)
    WHERE log_sanitized IS NOT NULL;

-- ---------- screenshots (metadata only; no image bytes, no copy in Mode 0) ----------

CREATE TABLE screenshot (
    id              INTEGER PRIMARY KEY,
    failure_id      INTEGER NOT NULL UNIQUE REFERENCES failure(id) ON DELETE CASCADE,
    unc_path        TEXT NOT NULL,
    -- Only the modes that exist. 1 (crop) and 2 (crop + OCR-redact) are
    -- designed in SECURITY.md 3.3 and unimplemented; a row claiming one
    -- would assert a protection nothing applied. See analysis.SCREENSHOT_MODES.
    processing_mode INTEGER NOT NULL CHECK (processing_mode IN (0, 3)),
    derivative_path TEXT,                  -- Modes 1-2 only; always NULL today
    was_cropped     INTEGER NOT NULL DEFAULT 0 CHECK (was_cropped IN (0,1)),
    was_redacted    INTEGER NOT NULL DEFAULT 0 CHECK (was_redacted IN (0,1)),
    sent_to_model   INTEGER NOT NULL DEFAULT 0 CHECK (sent_to_model IN (0,1)),
    width_px        INTEGER,
    height_px       INTEGER,
    bytes           INTEGER,
    captured_at     TEXT,
    expires_at      TEXT,                  -- derivative only; NULL when nothing was copied
    deleted_at      TEXT
);

CREATE INDEX idx_screenshot_derivative_expiry ON screenshot (expires_at)
    WHERE derivative_path IS NOT NULL AND deleted_at IS NULL;

-- ---------- feedback ----------

CREATE TABLE feedback (
    id           INTEGER PRIMARY KEY,
    analysis_id  INTEGER NOT NULL REFERENCES analysis(id),
    failure_id   INTEGER NOT NULL REFERENCES failure(id),
    developer_id INTEGER NOT NULL REFERENCES developer(id),
    verdict      TEXT NOT NULL CHECK (verdict IN ('correct','partial','wrong')),
    comment      TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (analysis_id, developer_id)
);

CREATE INDEX idx_feedback_analysis ON feedback (analysis_id);
CREATE INDEX idx_feedback_wrong    ON feedback (analysis_id) WHERE verdict = 'wrong';

-- ---------- scanner watermark ----------

CREATE TABLE scan_watermark (
    file_path     TEXT PRIMARY KEY,        -- UNC path of a processed file
    file_mtime    TEXT NOT NULL,
    file_size     INTEGER NOT NULL,
    processed_at  TEXT NOT NULL DEFAULT (datetime('now')),
    outcome       TEXT NOT NULL CHECK (outcome IN ('ingested','skipped','error'))
);

CREATE INDEX idx_watermark_processed ON scan_watermark (processed_at DESC);

-- ---------- audit ----------

CREATE TABLE audit_event (
    id             INTEGER PRIMARY KEY,
    actor          TEXT NOT NULL,
    actor_role     TEXT NOT NULL,
    action         TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('allow','deny')),
    correlation_id TEXT,
    occurred_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_audit_actor    ON audit_event (actor, occurred_at DESC);
CREATE INDEX idx_audit_resource ON audit_event (resource_type, resource_id, occurred_at DESC);
CREATE INDEX idx_audit_denials  ON audit_event (occurred_at DESC) WHERE outcome = 'deny';

-- SQLite has no GRANT/REVOKE, so append-only is enforced by trigger instead.
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_event
BEGIN SELECT RAISE(ABORT, 'audit_event is append-only'); END;

CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_event
BEGIN SELECT RAISE(ABORT, 'audit_event is append-only'); END;

-- ---------- notification suppression ----------

CREATE TABLE notification_state (
    id                INTEGER PRIMARY KEY,
    fingerprint_id    INTEGER NOT NULL REFERENCES fingerprint(id),
    developer_id      INTEGER NOT NULL REFERENCES developer(id),
    first_notified_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_notified_at  TEXT NOT NULL DEFAULT (datetime('now')),
    suppressed_count  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (fingerprint_id, developer_id)
);

-- ---------- accounts ----------
--
-- `developer` is a person a bot belongs to. `account` is a person who can sign
-- in. They are deliberately separate: a manager who owns no bots still needs a
-- login, and a developer who never uses the web UI still needs to receive
-- notifications and own failures.
--
-- Nothing is granted at registration. An account starts `requested` and can
-- sign in immediately -- and see nothing -- until an admin approves it with a
-- role. Sign-in and authorisation are different questions, and conflating them
-- is how "pending" accounts end up with read access nobody granted.

CREATE TABLE account (
    id             INTEGER PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    display_name   TEXT NOT NULL,
    -- scrypt. `salt` and `password_hash` are hex; `params` records n/r/p so a
    -- future cost increase can re-hash on next sign-in instead of locking
    -- everyone out.
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

-- A manager's scope: the teams they may see failures for. A row here is
-- meaningless for an admin (who sees everything) and for a user (who sees only
-- their own), so the application never reads it for those roles.
CREATE TABLE account_scope (
    account_id  INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    team_id     INTEGER NOT NULL REFERENCES team(id),
    granted_by  TEXT NOT NULL,
    granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (account_id, team_id)
);

-- Server-side sessions. The cookie carries an id and a signature; everything
-- that decides access is read from here on each request, so revoking an account
-- takes effect on its next request rather than whenever its cookie expires.
CREATE TABLE session (
    id           TEXT PRIMARY KEY,          -- 256 bits of urandom, hex
    account_id   INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    user_agent   TEXT,
    revoked_at   TEXT
);

CREATE INDEX idx_session_account ON session (account_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_session_expiry  ON session (expires_at);
