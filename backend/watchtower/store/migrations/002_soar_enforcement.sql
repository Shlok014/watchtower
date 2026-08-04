-- Schema 1 → 2: SOAR enforcement.
--
-- Only ever applied to a database created at version 1. A fresh database gets
-- the current schema.sql, which already contains both of these — running an
-- ALTER on it would fail with "duplicate column name" and take the process down
-- on a clean install.
ALTER TABLE events ADD COLUMN dropped INTEGER NOT NULL DEFAULT 0 CHECK (dropped IN (0,1));
CREATE INDEX IF NOT EXISTS idx_events_dropped ON events (dropped);

CREATE TABLE IF NOT EXISTS blocklist (
    id             INTEGER PRIMARY KEY,
    ip             TEXT    NOT NULL UNIQUE,
    reason         TEXT    NOT NULL,
    alert_id       INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    created_ts_ms  INTEGER NOT NULL,
    expires_ts_ms  INTEGER NOT NULL,
    hits           INTEGER NOT NULL DEFAULT 0,
    last_hit_ts_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_blocklist_expires ON blocklist (expires_ts_ms);

-- `required` decides whether a failed step makes the alert `action_failed`.
-- Stored, so the API can report not just that a step failed but whether the
-- playbook allowed it to.
ALTER TABLE soar_steps ADD COLUMN required INTEGER NOT NULL DEFAULT 0 CHECK (required IN (0,1));
