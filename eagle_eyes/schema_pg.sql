-- Eagle Eyes schema, PostgreSQL.
--
-- The port docs/DATA_MODEL.md section 8 describes, applied. It is the same
-- model with the same constraints; what changes is the type system and where
-- rules are enforced.
--
-- Deliberate differences from schema.sql, each with a reason:
--
--   BIGSERIAL          SQLite's INTEGER PRIMARY KEY is a rowid alias. Postgres
--                      needs an explicit sequence.
--
--   TIMESTAMPTZ        SQLite stores datetimes as TEXT and the application
--                      writes UTC. Postgres has the type, so use it -- a
--                      string comparison working "because ISO-8601 sorts" is a
--                      property nobody should have to remember.
--
--   NUMERIC for money  REAL is binary floating point. Summing cost_usd over a
--                      month of analyses drifts, and the number it drifts in is
--                      the one the budget caps are checked against. This is
--                      called out in DATA_MODEL section 8 and is the single
--                      most important line in this file.
--
--   BOOLEAN            SQLite has no boolean; the INTEGER + CHECK pairs become
--                      the real type.
--
--   TEXT[]             inputs_used is a list. JSON-in-TEXT was a SQLite
--                      workaround, not a design choice.
--
--   REVOKE on audit    SQLite has no GRANT, so append-only is enforced with
--                      triggers. Postgres does, so the privilege is simply not
--                      granted -- a rule the database enforces rather than one
--                      a trigger re-implements.
--
--   hash TEXT          NOT CHAR(64). bpchar takes a different operator class
--                      and the dedup lookup falls to a sequential scan --
--                      verified, and written up in DATA_MODEL section 7.2.
--                      The length is a CHECK instead.

-- ---------- organisation ----------

CREATE TABLE IF NOT EXISTS team (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    sso_group   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS developer (
    id           BIGSERIAL PRIMARY KEY,
    email        TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    team_id      BIGINT NOT NULL REFERENCES team(id),
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bot (
    id            BIGSERIAL PRIMARY KEY,
    service_line  TEXT NOT NULL,
    bot_number    TEXT NOT NULL,
    name          TEXT,
    team_id       BIGINT REFERENCES team(id),
    owner_dev_id  BIGINT REFERENCES developer(id),
    code_path     TEXT,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (service_line, bot_number)
);

-- ---------- known patterns ----------

CREATE TABLE IF NOT EXISTS pattern (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    match_rule        JSONB NOT NULL,
    response_template TEXT NOT NULL,
    severity          TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- dedup ----------

CREATE TABLE IF NOT EXISTS fingerprint (
    id                 BIGSERIAL PRIMARY KEY,
    hash               TEXT NOT NULL CHECK (char_length(hash) = 64),
    version            INTEGER NOT NULL,
    exception_type     TEXT NOT NULL,
    normalized_message TEXT NOT NULL,
    code_location      TEXT NOT NULL,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    occurrence_count   INTEGER NOT NULL DEFAULT 1,
    pattern_id         BIGINT REFERENCES pattern(id),
    expires_at         TIMESTAMPTZ NOT NULL,
    UNIQUE (hash, version)
);

-- No separate index on (hash, version): the UNIQUE constraint already builds
-- one and the planner uses it for the dedup lookup. A second would be dead
-- weight on every insert. Verified -- DATA_MODEL section 7.1.
CREATE INDEX IF NOT EXISTS idx_fingerprint_expiry ON fingerprint (expires_at);

-- ---------- analyses ----------

CREATE TABLE IF NOT EXISTS analysis (
    id                BIGSERIAL PRIMARY KEY,
    fingerprint_id    BIGINT NOT NULL REFERENCES fingerprint(id),
    source_failure_id BIGINT,
    path              TEXT NOT NULL CHECK (path IN
                          ('dedup','template','text','vision','fallback','skipped')),
    model_id          TEXT,
    code_mtime        TIMESTAMPTZ,
    root_cause        TEXT,
    suggested_fix     TEXT,
    confidence        NUMERIC(3,2) CHECK (confidence BETWEEN 0 AND 1),
    inputs_used       TEXT[] NOT NULL DEFAULT '{}',
    is_superseded     BOOLEAN NOT NULL DEFAULT FALSE,
    tokens_in         INTEGER,
    tokens_out        INTEGER,
    cache_read_tokens INTEGER,
    image_tokens      INTEGER,
    cost_usd          NUMERIC(12,6),
    latency_ms        INTEGER,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analysis_fingerprint ON analysis (fingerprint_id, created_at DESC)
    WHERE is_superseded = FALSE;
CREATE INDEX IF NOT EXISTS idx_analysis_expiry ON analysis (expires_at);

-- ---------- failures ----------

CREATE TABLE IF NOT EXISTS failure (
    id                   BIGSERIAL PRIMARY KEY,
    bot_id               BIGINT NOT NULL REFERENCES bot(id),
    fingerprint_id       BIGINT NOT NULL REFERENCES fingerprint(id),
    analysis_id          BIGINT REFERENCES analysis(id),
    occurred_at          TIMESTAMPTZ NOT NULL,
    ingested_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    status               TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','deduped','analyzing','analyzed','failed','suppressed')),
    was_deduped          BOOLEAN NOT NULL DEFAULT FALSE,

    log_path             TEXT NOT NULL,
    screenshot_path      TEXT,
    code_path            TEXT,
    code_mtime           TIMESTAMPTZ,
    code_possibly_stale  BOOLEAN NOT NULL DEFAULT FALSE,
    pairing_method       TEXT CHECK (pairing_method IN
                             ('log_path','timestamp','none','uploaded')),

    log_sanitized        TEXT,
    code_snapshot        TEXT,
    severity             TEXT CHECK (severity IN ('low','medium','high','critical')),
    correlation_id       TEXT NOT NULL,
    content_expires_at   TIMESTAMPTZ NOT NULL,
    expires_at           TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_failure_idempotency ON failure (log_path);
CREATE INDEX IF NOT EXISTS idx_failure_bot_time     ON failure (bot_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_failure_fingerprint  ON failure (fingerprint_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_failure_pending      ON failure (status) WHERE status IN ('pending','analyzing');
CREATE INDEX IF NOT EXISTS idx_failure_feed         ON failure (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_failure_content_expiry ON failure (content_expires_at)
    WHERE log_sanitized IS NOT NULL;

-- ---------- screenshots (metadata only) ----------

CREATE TABLE IF NOT EXISTS screenshot (
    id              BIGSERIAL PRIMARY KEY,
    failure_id      BIGINT NOT NULL UNIQUE REFERENCES failure(id) ON DELETE CASCADE,
    unc_path        TEXT NOT NULL,
    -- Only the modes that exist; 1 and 2 are designed and unbuilt.
    processing_mode SMALLINT NOT NULL CHECK (processing_mode IN (0, 3)),
    derivative_path TEXT,
    was_cropped     BOOLEAN NOT NULL DEFAULT FALSE,
    was_redacted    BOOLEAN NOT NULL DEFAULT FALSE,
    sent_to_model   BOOLEAN NOT NULL DEFAULT FALSE,
    width_px        INTEGER,
    height_px       INTEGER,
    bytes           BIGINT,
    captured_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_screenshot_derivative_expiry ON screenshot (expires_at)
    WHERE derivative_path IS NOT NULL AND deleted_at IS NULL;

-- ---------- feedback ----------

CREATE TABLE IF NOT EXISTS feedback (
    id           BIGSERIAL PRIMARY KEY,
    analysis_id  BIGINT NOT NULL REFERENCES analysis(id) ON DELETE CASCADE,
    failure_id   BIGINT NOT NULL REFERENCES failure(id) ON DELETE CASCADE,
    developer_id BIGINT NOT NULL REFERENCES developer(id),
    verdict      TEXT NOT NULL CHECK (verdict IN ('correct','partial','wrong')),
    comment      TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (analysis_id, developer_id)
);

-- ---------- scanner watermarks ----------

CREATE TABLE IF NOT EXISTS scan_watermark (
    file_path     TEXT PRIMARY KEY,
    file_mtime    TIMESTAMPTZ NOT NULL,
    file_size     BIGINT NOT NULL,
    processed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    outcome       TEXT NOT NULL CHECK (outcome IN ('ingested','skipped','error'))
);

CREATE INDEX IF NOT EXISTS idx_watermark_processed ON scan_watermark (processed_at DESC);

-- ---------- audit ----------

CREATE TABLE IF NOT EXISTS audit_event (
    id             BIGSERIAL PRIMARY KEY,
    actor          TEXT NOT NULL,
    actor_role     TEXT NOT NULL,
    action         TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('allow','deny')),
    correlation_id TEXT,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_event (actor, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_event (resource_type, resource_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_denials  ON audit_event (occurred_at DESC) WHERE outcome = 'deny';

-- Append-only, the same rule schema.sql enforces with triggers.
--
-- REVOKE UPDATE, DELETE is the textbook answer and it does not hold here: the
-- application connects as the database owner on every managed platform, and an
-- owner's privileges cannot be revoked from itself. A trigger applies to the
-- owner too, so that is what enforces it. When a deployment does separate the
-- roles, add the REVOKE as well -- belt and braces, not either/or.
CREATE OR REPLACE FUNCTION audit_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_event is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON audit_event;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION audit_is_append_only();

DROP TRIGGER IF EXISTS audit_no_delete ON audit_event;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION audit_is_append_only();

-- ---------- notification suppression ----------

CREATE TABLE IF NOT EXISTS notification_state (
    id                BIGSERIAL PRIMARY KEY,
    fingerprint_id    BIGINT NOT NULL REFERENCES fingerprint(id),
    developer_id      BIGINT NOT NULL REFERENCES developer(id),
    first_notified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_notified_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    suppressed_count  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (fingerprint_id, developer_id)
);

-- ---------- accounts ----------

CREATE TABLE IF NOT EXISTS account (
    id             BIGSERIAL PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    display_name   TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    salt           TEXT NOT NULL,
    params         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'requested'
                   CHECK (status IN ('requested','approved','suspended','revoked')),
    role           TEXT NOT NULL DEFAULT 'user'
                   CHECK (role IN ('admin','manager','user')),
    developer_id   BIGINT REFERENCES developer(id),
    approved_by    TEXT,
    approved_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ,
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_account_status ON account (status, role);

CREATE TABLE IF NOT EXISTS account_scope (
    account_id  BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    team_id     BIGINT NOT NULL REFERENCES team(id),
    granted_by  TEXT NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, team_id)
);

CREATE TABLE IF NOT EXISTS session (
    id           TEXT PRIMARY KEY,
    account_id   BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent   TEXT,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_session_account ON session (account_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_session_expiry  ON session (expires_at);
