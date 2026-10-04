ALTER TABLE alerts ADD COLUMN review_status TEXT NOT NULL DEFAULT 'new'
    CHECK (review_status IN ('new','investigating','closed'));

CREATE TABLE IF NOT EXISTS alert_review_events (
    id           INTEGER PRIMARY KEY,
    alert_id     INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    ts_ms        INTEGER NOT NULL,
    from_status  TEXT NOT NULL,
    to_status    TEXT NOT NULL,
    note         TEXT NOT NULL CHECK (length(trim(note)) > 0),
    actor        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_review_events_alert ON alert_review_events (alert_id, id);

CREATE TABLE IF NOT EXISTS event_shadow_verdicts (
    event_id       INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    status         TEXT NOT NULL CHECK (status IN ('scored','unavailable','skipped')),
    profile_digest TEXT,
    verdict_json   TEXT NOT NULL
);

INSERT INTO event_shadow_verdicts (event_id, status, profile_digest, verdict_json)
SELECT id, 'unavailable', NULL,
       '{"status":"unavailable","detector":"live_profile_shadow",'
       || '"reason":"predates_shadow_schema","profile_digest":null}'
FROM events;
