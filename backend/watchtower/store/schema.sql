-- Watchtower storage schema.
--
-- Replaces four module-level Python lists that were mutated by a background
-- thread while Flask handlers iterated them with no lock held.
--
-- Conventions:
--   * Times are INTEGER milliseconds since the Unix epoch, UTC. Not ISO-8601
--     text: the stats endpoint buckets by time on every poll, and a TEXT column
--     carrying a "+00:00" suffix cannot be range-scanned as a number. The API
--     still emits ISO-8601 strings — storage format and wire format are
--     separate decisions.
--   * Two distinct times per event, and the distinction is load-bearing:
--       ts_ms          when the event happened (may be years old on replay)
--       ingested_ts_ms when this pipeline saw it
--     Detection windows and dashboard buckets key on ingested_ts_ms. Keying
--     both on a single column means replaying a 2008 dataset yields zero
--     detections and a flat-zero timeline while the ingest counter climbs —
--     silent, and indistinguishable from "nothing suspicious happened".

PRAGMA foreign_keys = ON;

-- ── events ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY,
    ts_ms           INTEGER NOT NULL,
    ingested_ts_ms  INTEGER NOT NULL,
    source          TEXT    NOT NULL,
    event           TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    severity        TEXT    NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    ip              TEXT    NOT NULL,
    -- UDP socket peer; NULL for legacy events and other source types.
    transport_peer_ip TEXT,
    user            TEXT    NOT NULL,
    message         TEXT    NOT NULL,
    log_format      TEXT    NOT NULL,

    -- Provenance. GLOB, not LIKE: SQLite's LIKE is ASCII case-insensitive by
    -- default, so a LIKE 'replay:%' check accepts 'REPLAY:x' and 'Replay:x' as
    -- well, and two spellings of one origin makes every GROUP BY origin
    -- under-count. GLOB is case-sensitive and 'replay:?*' already requires a
    -- non-empty suffix.
    origin          TEXT    NOT NULL CHECK (
                        origin IN ('synthetic','syslog','file') OR origin GLOB 'replay:?*'
                    ),

    -- Reputation is stored flat and re-nested on the way out; the API contract
    -- is a nested `reputation` object and must not change shape.
    rep_verdict     TEXT    NOT NULL,
    rep_score       REAL    NOT NULL,
    rep_sources     TEXT    NOT NULL,   -- JSON array
    rep_checked     INTEGER NOT NULL CHECK (rep_checked IN (0,1)),
    rep_detail      TEXT    NOT NULL,

    -- Suppressed by the blocklist before detection ran. The row is still
    -- stored, and still chained into the ledger: an audit ledger that omits the
    -- events a response action silenced has a hole exactly where the
    -- interesting traffic is.
    dropped         INTEGER NOT NULL DEFAULT 0 CHECK (dropped IN (0,1))
);

-- Serves the stats time buckets and retention sweeps.
CREATE INDEX IF NOT EXISTS idx_events_ingested ON events (ingested_ts_ms);
-- Serves the per-IP detection windows, which run on every single event.
CREATE INDEX IF NOT EXISTS idx_events_ip_ingested ON events (ip, ingested_ts_ms);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_origin ON events (origin);
CREATE INDEX IF NOT EXISTS idx_events_dropped ON events (dropped);

-- One immutable, event-linked shadow verdict. It cannot create an alert and
-- disappears with its event when retention or reset removes that event.
CREATE TABLE IF NOT EXISTS event_shadow_verdicts (
    event_id       INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    status         TEXT NOT NULL CHECK (status IN ('scored','unavailable','skipped')),
    profile_digest TEXT,
    verdict_json   TEXT NOT NULL
);

-- ── alerts ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY,
    event_id        INTEGER REFERENCES events(id) ON DELETE SET NULL,
    ts_ms           INTEGER NOT NULL,
    event           TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    ip              TEXT    NOT NULL,
    user            TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    anomaly_score   REAL    NOT NULL,
    ruleset_version TEXT    NOT NULL,
    explanation     TEXT    NOT NULL,
    features_json   TEXT    NOT NULL,
    reasons_json    TEXT    NOT NULL,
    reputation_json TEXT    NOT NULL,
    -- Stays 'open'. A status is earned by an action that actually ran.
    status          TEXT    NOT NULL CHECK (status IN ('open','contained','mitigated','action_failed','closed')),
    review_status   TEXT    NOT NULL DEFAULT 'new'
                    CHECK (review_status IN ('new','investigating','closed'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts_ms);
CREATE INDEX IF NOT EXISTS idx_alerts_event ON alerts (event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_cooldown ON alerts (ip, event, ruleset_version, event_id);

-- An explicit unblock opens a fresh alert epoch for that address. The alert ID
-- boundary works even when unblock and the next event share a millisecond.
CREATE TABLE IF NOT EXISTS alert_cooldown_resets (
    ip       TEXT PRIMARY KEY,
    alert_id INTEGER NOT NULL
);

-- Analyst actions are distinct from the automated SOAR outcome above.
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

-- ── SOAR ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soar_executions (
    id                 INTEGER PRIMARY KEY,
    alert_id           INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    ts_ms              INTEGER NOT NULL,
    event              TEXT    NOT NULL,
    ip                 TEXT    NOT NULL,
    playbook           TEXT    NOT NULL,
    priority           TEXT    NOT NULL,
    execution_mode     TEXT    NOT NULL CHECK (execution_mode IN ('simulated','live')),
    selection_time_us  REAL    NOT NULL,
    status             TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_soar_ts ON soar_executions (ts_ms);

CREATE TABLE IF NOT EXISTS soar_steps (
    id            INTEGER PRIMARY KEY,
    execution_id  INTEGER NOT NULL REFERENCES soar_executions(id) ON DELETE CASCADE,
    position      INTEGER NOT NULL,
    action        TEXT    NOT NULL,
    status        TEXT    NOT NULL CHECK (status IN ('executed','failed','skipped','selected')),
    executed      INTEGER NOT NULL CHECK (executed IN (0,1)),
    -- Whether the playbook marked this step required. It decides the alert's
    -- status, so it has to be stored: without it the API can report that a step
    -- failed but not whether that failure was allowed to happen.
    required      INTEGER NOT NULL DEFAULT 0 CHECK (required IN (0,1)),
    duration_us   REAL    NOT NULL,
    detail        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_soar_steps_exec ON soar_steps (execution_id, position);

-- ── ledger ───────────────────────────────────────────────────────────────────
-- Append-only and exempt from retention: an audit ledger you silently truncate
-- is not an audit ledger. See README for the disk budget this implies.
--
-- payload_canon records HOW the preimage was serialised, so the digest can be
-- reproduced later. It names the exact call, because "utf8-json" would not be
-- enough to reproduce anything: json.dumps defaults to ensure_ascii=True and
-- ', '/': ' separators, which are not the obvious choices.
CREATE TABLE IF NOT EXISTS ledger (
    block_id      INTEGER PRIMARY KEY,
    ts_ms         INTEGER NOT NULL,
    event_id      INTEGER,
    payload_json  TEXT    NOT NULL,
    payload_canon TEXT    NOT NULL DEFAULT 'py-json-sortkeys-ensureascii-defaultsep-v1',
    log_hash      TEXT    NOT NULL,
    prev_hash     TEXT    NOT NULL,
    hash          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_event ON ledger (event_id);

-- ── counters ─────────────────────────────────────────────────────────────────
-- Lifetime totals live here rather than being derived from max(id) or COUNT(*).
-- Both of those fall when retention prunes old rows, and "total events ever
-- ingested" must never go down.
CREATE TABLE IF NOT EXISTS counters (
    name   TEXT    PRIMARY KEY,
    value  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS schema_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- ── blocklist ────────────────────────────────────────────────────────────────
-- The closed loop. A `block_ip` action writes here; the pipeline consumer
-- checks this table *before* detection and marks matching events dropped, so a
-- blocked address is really suppressed rather than merely recorded as blocked.
--
-- Enforcement is at this application's own ingestion layer. Nothing here
-- touches pf, iptables or any firewall, and nothing needs root — see the README
-- for why that scope was chosen deliberately rather than reached for.
--
-- UNIQUE on ip: re-blocking an address extends its expiry and keeps its hit
-- count, rather than creating a second row that splits the count in half and
-- makes every "N events dropped from X" figure an undercount.
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
