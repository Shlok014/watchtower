CREATE INDEX IF NOT EXISTS idx_alerts_cooldown ON alerts (ip, event, ruleset_version, event_id);
CREATE TABLE IF NOT EXISTS alert_cooldown_resets (
    ip       TEXT PRIMARY KEY,
    alert_id INTEGER NOT NULL
);
