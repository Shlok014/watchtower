"""
Watchtower Backend — Security Operations Center
"""

import hashlib
import json
import os
import random
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, jsonify, request
from flask_cors import CORS

import ledger
import store
import telemetry
import threatintel
from threatintel import pool as ip_pool

app = Flask(__name__)
CORS(app)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

# ─── In-Memory Data Stores ─────────────────────────────────────────────────────
# State lives in SQLite. It used to be four module-level lists that the
# generator thread appended to and popped from while Flask handlers iterated
# them, with no lock held — and only the ledger was persisted, on every
# twentieth block, inside a bare `except Exception: pass`.
#
# Lifetime totals are a persisted counters table rather than max(id) or
# COUNT(*), both of which fall when retention prunes. "Total events ever
# ingested" must never go down.

LOG_GENERATION_ACTIVE = True
ALERT_THRESHOLD = 0.45

# ─── Source Addresses for the Synthetic Generator ──────────────────────────────
# What used to live here was a table of fourteen addresses with invented cities
# and ISPs ("ShadowNet VPN", "DarkRelay Proxy", "BulletProof Hosting"), and
# reputation was decided by substring-matching those invented strings. Both the
# geolocation and the verdict were fiction.
#
# Reputation is now a real lookup against cached public feeds (see the
# threatintel package). Geolocation is simply gone: an honest offline geo-IP
# answer needs a licensed database, and a fabricated one is worse than none.
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5", "10.0.0.15", "172.16.0.100",
]

# Populated at startup from the cached Tor exit list; see threatintel/pool.py
# for why external addresses are split into two pools.
EXTERNAL_IPS: tuple[str, ...] = ip_pool.OFFLINE_POOL
IP_POOL_NOTE = "threat feeds not yet loaded"


def refresh_ip_pools() -> None:
    global EXTERNAL_IPS, IP_POOL_NOTE
    EXTERNAL_IPS, IP_POOL_NOTE = ip_pool.build_provenance_pool(threatintel.get_index())

# ─── Source-Specific Configuration ──────────────────────────────────────────────
SOURCE_PROFILES = {
    "linux-server": {
        "events": [("login_success", 25), ("failed_login", 15), ("file_access", 20),
                   ("privilege_escalation", 3), ("normal_traffic", 30), ("malware_detected", 2),
                   ("brute_force", 3), ("suspicious_ip", 2)],
        "users": ["root", "admin", "jdoe", "ssmith", "backup_svc"],
        "log_format": "syslog",
    },
    "windows-dc": {
        "events": [("login_success", 30), ("failed_login", 20), ("privilege_escalation", 4),
                   ("normal_traffic", 20), ("file_access", 15), ("brute_force", 5),
                   ("malware_detected", 3), ("suspicious_ip", 3)],
        "users": ["admin", "sysadmin", "jdoe", "ssmith", "guest"],
        "log_format": "windows_event",
    },
    "firewall-01": {
        "events": [("normal_traffic", 35), ("suspicious_ip", 10), ("port_scan", 12),
                   ("data_exfiltration", 5), ("brute_force", 8), ("login_success", 15),
                   ("failed_login", 10), ("malware_detected", 5)],
        "users": ["system", "firewall_svc"],
        "log_format": "cef",
    },
    "web-proxy": {
        "events": [("normal_traffic", 40), ("suspicious_ip", 8), ("data_exfiltration", 6),
                   ("login_success", 20), ("failed_login", 10), ("malware_detected", 4),
                   ("port_scan", 7), ("file_access", 5)],
        "users": ["proxy_svc", "jdoe", "ssmith"],
        "log_format": "squid",
    },
    "mail-server": {
        "events": [("login_success", 30), ("failed_login", 15), ("normal_traffic", 30),
                   ("suspicious_ip", 5), ("malware_detected", 8), ("data_exfiltration", 4),
                   ("file_access", 5), ("brute_force", 3)],
        "users": ["postmaster", "jdoe", "ssmith", "admin"],
        "log_format": "syslog",
    },
    "iot-gateway": {
        "events": [("normal_traffic", 40), ("suspicious_ip", 10), ("port_scan", 15),
                   ("malware_detected", 10), ("data_exfiltration", 8), ("failed_login", 7),
                   ("login_success", 5), ("brute_force", 5)],
        "users": ["device_001", "device_042", "device_117", "iot_admin"],
        "log_format": "json",
    },
    "db-server": {
        "events": [("login_success", 25), ("failed_login", 10), ("file_access", 25),
                   ("privilege_escalation", 5), ("normal_traffic", 20), ("data_exfiltration", 5),
                   ("suspicious_ip", 5), ("brute_force", 5)],
        "users": ["dba", "app_svc", "admin", "backup_svc"],
        "log_format": "oracle_audit",
    },
}
SOURCES = list(SOURCE_PROFILES.keys())

EVENT_TYPES = {
    "login_success":        {"severity": "low",      "category": "authentication"},
    "failed_login":         {"severity": "medium",   "category": "authentication"},
    "brute_force":          {"severity": "critical",  "category": "attack"},
    "suspicious_ip":        {"severity": "high",     "category": "network"},
    "port_scan":            {"severity": "high",     "category": "reconnaissance"},
    "malware_detected":     {"severity": "critical",  "category": "malware"},
    "file_access":          {"severity": "low",      "category": "file_system"},
    "privilege_escalation": {"severity": "critical",  "category": "attack"},
    "data_exfiltration":    {"severity": "critical",  "category": "data_leak"},
    "normal_traffic":       {"severity": "low",      "category": "network"},
}

# ─── Tamper-Evident Audit Ledger ───────────────────────────────────────────────
# Implementation lives in ledger.py. See that module for why the digest covers
# the block header, why there is no proof-of-work nonce, and what each failure
# reason means.
def hash_log(conn, log_entry, event_id, event_ts_ms, ts_ms):
    block = ledger.append(conn, log_entry, event_id, event_ts_ms, ts_ms)
    store.repos.bump(conn, "blocks")
    return block


def validate_chain():
    """Full verification: every digest recomputed from the live event rows."""
    result = ledger.verify(store.db.connect()).as_dict()
    count, oldest, newest = store.repos.ledger_bounds()
    result.update({
        "chain_length": count,
        "latest_hash": newest,
        "genesis_hash": oldest,
        # Kept so the existing dashboard panel keeps rendering; it now means
        # "the whole chain verified", not "two stored strings matched".
        "links_ok": result["ok"],
    })
    return result


# ─── Log Processing / Normalization ─────────────────────────────────────────────
def normalize_log(raw_log):
    """Normalize a raw log into the common Watchtower format."""
    event = raw_log.get("event", "unknown")
    meta = EVENT_TYPES.get(event, {"severity": "low", "category": "other"})
    ip = raw_log.get("ip", "0.0.0.0")
    verdict = threatintel.classify(ip)
    return {
        "timestamp": raw_log["timestamp"],
        "source": raw_log["source"],
        "event": event,
        "event_type": meta["category"],
        "severity": meta["severity"],
        "ip": ip,
        "user": raw_log.get("user", "unknown"),
        "message": raw_log.get("message", ""),
        # Replaces the invented {country, city, isp, flag} block. Every field
        # here is either measured or explicitly says it was not checked.
        "reputation": {
            "verdict": verdict.reputation,
            "score": verdict.score,
            "sources": list(verdict.sources),
            "checked": verdict.checked,
            "detail": verdict.explanation,
        },
        "log_format": raw_log.get("log_format", "syslog"),
    }


# ─── Detection Engine (rule-based correlation) ─────────────────────────────────
# Weights live at module scope so the ruleset can be versioned by its *content*.
# The old `model_version` was an integer that /api/retrain incremented on
# demand, so the version advanced while the rules stayed identical — and it was
# stamped on every alert as though it identified the logic that produced it.
EVENT_WEIGHTS = {
    "brute_force": 0.45,
    "malware_detected": 0.50,
    "privilege_escalation": 0.50,
    "data_exfiltration": 0.45,
    "port_scan": 0.35,
    "suspicious_ip": 0.35,
}
FAILED_LOGIN_RULES = ((5, 0.40), (3, 0.20))
FREQUENCY_RULES = ((15, 0.20), (8, 0.10))

RULESET_VERSION = "rules-" + hashlib.sha256(
    json.dumps(
        {
            "events": EVENT_WEIGHTS,
            "failed_login": FAILED_LOGIN_RULES,
            "frequency": FREQUENCY_RULES,
            "threshold": ALERT_THRESHOLD,
        },
        sort_keys=True,
    ).encode()
).hexdigest()[:8]

FAILED_LOGIN_WINDOW_S = 60
FREQUENCY_WINDOW_S = 30


def rules_detect(conn, log_entry, ingested_ts_ms):
    """
    Rule-based detection: sliding-window feature extraction + weighted scoring.

    The windows are SQL counts over the events table rather than two
    module-level `defaultdict(list)` caches. Those caches were mutated from the
    generator thread and read from request handlers, never evicted a key when
    its list emptied (so every IP ever seen leaked forever), and were lost on
    restart — so a restart silently reset every brute-force window to zero.

    They count on `ingested_ts_ms`, deliberately. Replayed events carry their
    original timestamps, so a window over event time would match nothing and
    the detector would report "no rule matched" on every replayed event — a
    silent failure indistinguishable from benign traffic.
    """
    ip = log_entry["ip"]
    event = log_entry["event"]

    # ── Feature Extraction ──
    # 1. Failed logins from this IP in the last 60s, whatever the current event
    #    is. The current event is already inserted, so it counts itself —
    #    matching the old tracker, which appended before reading its length.
    failed_attempts = store.repos.failed_logins_in_window(
        conn, ip, ingested_ts_ms - FAILED_LOGIN_WINDOW_S * 1000
    )

    # 2. IP reputation — a real lookup against cached public threat feeds.
    #
    # The previous version scored 0.25 for any address it did not recognise,
    # which put every unfamiliar host most of the way to the alert threshold on
    # no evidence at all. Absence from a blocklist is not evidence of malice, so
    # an unlisted address now contributes exactly nothing.
    rep = log_entry.get("reputation") or {}
    ip_reputation = rep.get("verdict", "unavailable")
    ip_rep_score = float(rep.get("score", 0.0))
    ip_rep_detail = rep.get("detail", "")

    # 3. Request frequency (events from this IP in last 30s)
    request_frequency = store.repos.events_in_window(
        conn, ip, ingested_ts_ms - FREQUENCY_WINDOW_S * 1000
    )

    features = {
        "failed_attempts_count": failed_attempts,
        "ip_reputation": ip_reputation,
        "ip_reputation_score": round(ip_rep_score, 2),
        "ip_reputation_checked": bool(rep.get("checked")),
        "request_frequency": request_frequency,
        "event_severity": log_entry["severity"],
        "source": log_entry["source"],
    }

    # ── Weighted Scoring ──
    score = 0.0
    explanation_parts = []

    # IP reputation weight
    score += ip_rep_score
    if ip_rep_score > 0:
        explanation_parts.append(f"{ip} — {ip_rep_detail}")

    # Failed login weight
    for threshold, weight in FAILED_LOGIN_RULES:
        if failed_attempts >= threshold:
            score += weight
            explanation_parts.append(f"{failed_attempts} failed logins from {ip} in 60s")
            break

    # Event type weight
    ew = EVENT_WEIGHTS.get(event, 0.0)
    if ew > 0:
        score += ew
        explanation_parts.append(f"High-risk event: {event.replace('_', ' ')}")

    # Request frequency weight
    for threshold, weight in FREQUENCY_RULES:
        if request_frequency > threshold:
            score += weight
            explanation_parts.append(f"{request_frequency} events from {ip} in 30s")
            break

    # The score is now exactly the sum of the rules that fired. It used to have
    # random.uniform(-0.04, 0.04) added under the comment "Randomness for
    # realism", which made the detector nondeterministic: the same event could
    # alert on one run and not the next, and any base score of exactly 0.45
    # became a coin toss.
    score = round(min(1.0, max(0.0, score)), 2)
    is_anomaly = score >= ALERT_THRESHOLD

    if not explanation_parts:
        explanation_parts = ["No rule matched"]

    return {
        "anomaly_score": score,
        "is_anomaly": is_anomaly,
        "threshold": ALERT_THRESHOLD,
        "ruleset_version": RULESET_VERSION,
        "features": features,
        "explanation": " + ".join(explanation_parts),
        "reasons": explanation_parts,
        # There is no `confidence` field any more. It used to be
        # 0.80 + score*0.15 + noise, capped at 0.99 — an affine restatement of
        # the score that carried no extra information, could never fall below
        # 0.80, and was displayed beside the score as if it were an independent
        # measure of reliability. Nothing here is calibrated against ground
        # truth, so no calibrated number may be reported.
    }


# ─── SOAR Automation ────────────────────────────────────────────────────────────
# Written in the imperative — "Block IP", not "IP Blocked".
#
# The past tense mattered more than it looks. Combined with a ✓ in the UI and a
# "completed" status, "IP Blocked" reads as a record of a remediation that
# happened. Nothing here contacts a firewall, a mail server or a ticket system,
# so these are the steps a playbook *would* run.
SOAR_PLAYBOOKS = {
    "brute_force":          {"actions": ["Block IP", "Terminate session", "Send alert email", "Open incident ticket"], "priority": "P1"},
    "suspicious_ip":        {"actions": ["Block IP", "Update firewall rule", "Send alert email"], "priority": "P2"},
    "malware_detected":     {"actions": ["Isolate host", "Trigger AV scan", "Send alert email", "Open incident ticket"], "priority": "P1"},
    "port_scan":            {"actions": ["Block IP", "Update IDS rule", "Send alert email"], "priority": "P2"},
    "privilege_escalation": {"actions": ["Terminate session", "Lock account", "Send alert email", "Open incident ticket", "Start forensics"], "priority": "P1"},
    "data_exfiltration":    {"actions": ["Isolate network segment", "Terminate session", "Send alert email", "Start forensics"], "priority": "P1"},
    "failed_login":         {"actions": ["Send alert email", "Enable account monitoring"], "priority": "P3"},
}

def soar_respond(alert_entry):
    """Select a response playbook for an alert.

    No step here has a side effect: nothing contacts a firewall, sends mail, or
    opens a ticket. The previous version disguised that by inventing a per-step
    `duration_ms = random.randint(120, 850)` and stamping each step "completed"
    with a timestamp in the future, producing an execution trace detailed enough
    to be mistaken for a real one.

    Timings are now measured, which honestly yields microseconds, and every
    field says the step was selected rather than performed.
    """
    event = alert_entry["event"]
    playbook = SOAR_PLAYBOOKS.get(
        event, {"actions": ["Notify", "Log to SIEM"], "priority": "P3"}
    )
    actions = playbook["actions"]

    ts = datetime.now(timezone.utc)
    steps = []
    t_start = time.perf_counter()
    for action in actions:
        t0 = time.perf_counter()
        # This is where a real integration would run. There isn't one.
        selected = {"action": action, "executed": False}
        steps.append({
            "action": action,
            "status": "selected",
            "executed": False,
            "duration_us": round((time.perf_counter() - t0) * 1e6, 1),
            "detail": "no integration configured — step selected, not executed",
            **{k: v for k, v in selected.items() if k not in ("action", "executed")},
        })
    total_us = round((time.perf_counter() - t_start) * 1e6, 1)

    response = {
        "alert_id": alert_entry["id"],
        "timestamp": ts.isoformat(),
        "event": event,
        "ip": alert_entry["ip"],
        # Renamed from `actions_taken`: nothing was taken.
        "playbook_steps": actions,
        "execution_steps": steps,
        "execution_mode": "simulated",
        "selection_time_us": total_us,
        "status": "selected",
        "priority": playbook["priority"],
        "playbook": f"PB-{event.upper().replace('_', '-')}",
    }
    return response


# ─── Alert System ──────────────────────────────────────────────────────────────
def create_alert(conn, log_entry, detection_result, event_id):
    """Create an alert from an anomalous log."""
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": log_entry["event"],
        "source": log_entry["source"],
        "ip": log_entry["ip"],
        "user": log_entry["user"],
        "severity": log_entry["severity"],
        "anomaly_score": detection_result["anomaly_score"],
        "features": detection_result["features"],
        "explanation": detection_result["explanation"],
        "reasons": detection_result["reasons"],
        "ruleset_version": detection_result["ruleset_version"],
        "reputation": log_entry.get("reputation", {}),
        "status": "open",
        "soar_response": None,
    }
    alert["id"] = store.repos.insert_alert(conn, alert, event_id)

    # The status stays "open". It used to be set to "mitigated" on the line
    # after soar_respond() returned — but soar_respond only builds a dict, so
    # every alert in the system claimed to have been remediated the instant it
    # was raised. A status has to be earned by an action that actually ran.
    response = soar_respond(alert)
    response["id"] = store.repos.insert_soar(conn, response, alert["id"])
    alert["soar_response"] = response
    return alert


# ─── Log Generator (Background Thread) ──────────────────────────────────────────
# This is the one place randomness is legitimate: it synthesises *input data*.
# Simulating a log stream is honest simulation, clearly labelled as such in the
# API (`origin: "synthetic"`) and the UI. What was removed elsewhere was
# randomness that faked a *measurement* of the system's own behaviour.
def generate_random_log():
    """Generate a source-specific synthetic log entry."""
    source = random.choice(SOURCES)
    profile = SOURCE_PROFILES[source]

    events, weights = zip(*profile["events"])
    event = random.choices(events, weights=weights, k=1)[0]

    external = event in (
        "suspicious_ip", "brute_force", "port_scan", "data_exfiltration", "malware_detected"
    )
    if external:
        ip = random.choice(ip_pool.pool_for_event(event, EXTERNAL_IPS))
    else:
        ip = random.choice(INTERNAL_IPS)

    user = random.choice(profile["users"])
    fmt = profile["log_format"].upper()

    messages = {
        "login_success": f"[{fmt}] User {user} authenticated successfully from {ip}",
        "failed_login": f"[{fmt}] Authentication failed for {user} from {ip}",
        "brute_force": f"[{fmt}] Multiple rapid auth attempts from {ip}",
        "suspicious_ip": f"[{fmt}] Connection from flagged IP {ip}",
        "port_scan": f"[{fmt}] Sequential port scan from {ip} ports 1-1024",
        "malware_detected": f"[{fmt}] Malware signature [Trojan.Gen.{random.randint(1,99)}] detected from {ip}",
        "file_access": f"[{fmt}] {user} accessed /etc/shadow from {ip}",
        "privilege_escalation": f"[{fmt}] sudo escalation by {user} from {ip}",
        "data_exfiltration": f"[{fmt}] {random.randint(50,500)}MB transfer to external {ip}",
        "normal_traffic": f"[{fmt}] Standard {random.choice(['HTTP', 'HTTPS', 'DNS', 'NTP'])} traffic from {ip}",
    }

    return {
        # No id here: it is the events table's rowid, assigned on insert.
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "event": event,
        "ip": ip,
        "user": user,
        "message": messages.get(event, f"Event {event} from {ip}"),
        "log_format": profile["log_format"],
        "origin": "synthetic",
    }


def process_log(raw_log):
    """Full pipeline: normalize → detect → alert → ledger.

    Stages are bracketed with inline perf_counter reads rather than a context
    manager: a @contextmanager timer measures ~2.1us of overhead against stages
    that run in under 1us, so the instrument would have dominated the reading.
    """
    t_pipeline = time.perf_counter()

    t0 = time.perf_counter()
    normalized = normalize_log(raw_log)
    # Never default a missing origin. Labelling real traffic "synthetic" is
    # wrong in the dangerous direction and would quietly defeat the provenance
    # labelling the whole honesty story rests on.
    origin = raw_log.get("origin")
    if not origin:
        raise ValueError(f"raw log {raw_log.get('id')} has no origin")
    normalized["origin"] = origin
    telemetry.record("normalize", time.perf_counter() - t0)

    ingested_ts_ms = store.repos.now_ms()

    # One transaction for the whole event: the row, its alert, its SOAR record
    # and its ledger block commit together or not at all. A half-committed
    # event would leave a ledger block chained to a log entry that does not
    # exist.
    with store.write() as conn:
        t0 = time.perf_counter()
        event_id = store.repos.insert_event(conn, normalized, ingested_ts_ms)
        normalized["id"] = event_id
        event_ts_ms = store.repos.from_iso(normalized["timestamp"])
        telemetry.record("ingest", time.perf_counter() - t0)

        t0 = time.perf_counter()
        detection = rules_detect(conn, normalized, ingested_ts_ms)
        telemetry.record("detect", time.perf_counter() - t0)

        if detection["is_anomaly"]:
            t0 = time.perf_counter()
            create_alert(conn, normalized, detection, event_id)
            telemetry.record("alert", time.perf_counter() - t0)

        t0 = time.perf_counter()
        hash_log(conn, normalized, event_id, event_ts_ms, ingested_ts_ms)
        telemetry.record("ledger", time.perf_counter() - t0)

    telemetry.record("pipeline", time.perf_counter() - t_pipeline)
    telemetry.record_event()
    return normalized


_last_prune = 0.0
PRUNE_INTERVAL_S = 300


def _housekeeping() -> None:
    """Retention sweep and WAL truncation, every few minutes."""
    global _last_prune
    now = time.monotonic()
    if now - _last_prune < PRUNE_INTERVAL_S:
        return
    _last_prune = now
    try:
        with store.write() as conn:
            store.repos.prune(conn)
        store.db.checkpoint()
    except Exception as exc:
        # Surfaced, not swallowed: a store that stopped pruning is a store
        # that will fill the disk.
        print(f"⚠️  housekeeping failed: {type(exc).__name__}: {exc}")


def log_generator_loop():
    """Background thread that continuously generates synthetic logs."""
    while True:
        if LOG_GENERATION_ACTIVE:
            try:
                process_log(generate_random_log())
            except Exception as exc:
                # A persistence failure must be visible. The old code wrote the
                # ledger inside `except Exception: pass`, so a full disk meant
                # nothing was recorded and the dashboard looked perfectly fine.
                print(f"⚠️  pipeline error: {type(exc).__name__}: {exc}")
        _housekeeping()
        time.sleep(random.uniform(0.8, 2.0))


# ─── API Endpoints ──────────────────────────────────────────────────────────────
def _query_int(name: str, default: int, lo: int, hi: int) -> int:
    """Bounded integer query param. `?limit=abc` used to raise and return 500."""
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except (TypeError, ValueError):
        abort(400, description=f"{name} must be an integer")



@app.route("/api/logs", methods=["GET"])
def get_logs():
    return jsonify(
        store.repos.recent_events(
            limit=_query_int("limit", 100, 1, 1000),
            severity=request.args.get("severity") or None,
            source=request.args.get("source") or None,
            search=request.args.get("search") or None,
        )
    )


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    return jsonify(store.repos.recent_alerts(_query_int("limit", 50, 1, 500)))


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Dashboard aggregates, computed in SQL.

    This used to loop over every retained log and every alert once per time
    bucket, calling datetime.fromisoformat each time — roughly 75,000 parses per
    request at a full buffer, measured at 13.0 ms of which 9.2 ms was parsing,
    repeated every 2 seconds.
    """
    st = store.repos.stats()
    totals, retained = st["totals"], st["retained"]
    return jsonify({
        # Lifetime totals, from the persisted counters table. Returning a
        # row count here would make every "total" fall the moment retention
        # pruned an old event.
        "total_logs": totals["events"],
        "total_alerts": totals["alerts"],
        "total_blocks": totals["blocks"],
        "soar_actions_count": totals["soar"],
        # ...and what is currently on disk, under names that say so.
        "logs_retained": retained["events"],
        "alerts_retained": retained["alerts"],
        "blocks_retained": retained["blocks"],
        # Derived from the live policy, never a literal. Hardcoded, this string
        # would have gone on describing the in-memory ring buffers it was
        # written for — in the very field added to stop the app misdescribing
        # its own storage.
        "retention_note": store.retention_note(),
        "high_severity_alerts": st["high_severity_alerts"],
        "critical_alerts": st["critical_alerts"],
        "medium_severity_alerts": st["medium_severity_alerts"],
        "ruleset_version": RULESET_VERSION,
        "logs_over_time": st["timeline"],
        "alert_distribution": st["alert_distribution"],
        "event_distribution": st["event_distribution"],
        "source_distribution": st["source_distribution"],
        "origin_distribution": st["origin_distribution"],
        "uptime_seconds": telemetry.uptime_seconds(),
        "sources": SOURCES,
    })


@app.route("/api/blockchain", methods=["GET"])
def get_blockchain():
    return jsonify(store.repos.recent_blocks(_query_int("limit", 30, 1, 500)))


@app.route("/api/blockchain/validate", methods=["POST"])
def validate_blockchain():
    """Check link continuity across the ledger. NOT an integrity verification."""
    return jsonify(validate_chain())


@app.route("/api/soar-actions", methods=["GET"])
def get_soar_actions():
    return jsonify(store.repos.recent_soar(_query_int("limit", 30, 1, 500)))


@app.route("/api/simulate-attack", methods=["POST"])
def simulate_attack():
    """Trigger a simulated attack — supports multiple attack types."""
    attack_type = request.json.get("attack_type", "mixed") if request.is_json else "mixed"

    # `ips: None` means "pick per event from the appropriate pool" — external
    # events that are about connection provenance draw from the real Tor exit
    # list, while events that fabricate forensic detail draw from RFC 5737
    # documentation ranges. See threatintel/pool.py.
    attack_profiles = {
        "brute_force": {
            "events": ["failed_login"] * 8 + ["brute_force"] * 4,
            # One fixed address, so the 60s failed-login window actually trips.
            "ips": [random.choice(EXTERNAL_IPS)],
            "users": ["admin", "root"],
            "count": (10, 18),
            "label": "Brute Force Attack",
        },
        "ddos": {
            "events": ["port_scan"] * 5 + ["suspicious_ip"] * 5 + ["normal_traffic"] * 3,
            "ips": list(EXTERNAL_IPS[:4]),
            "users": ["system"],
            "count": (15, 25),
            "label": "DDoS Attack",
        },
        "insider_threat": {
            "events": ["privilege_escalation"] * 3 + ["data_exfiltration"] * 4 + ["file_access"] * 3,
            "ips": INTERNAL_IPS[:2],
            "users": ["jdoe", "guest"],
            "count": (8, 12),
            "label": "Insider Threat",
        },
        "malware_outbreak": {
            "events": ["malware_detected"] * 6 + ["suspicious_ip"] * 3 + ["data_exfiltration"] * 2,
            "ips": None,
            "users": ["admin", "sysadmin", "backup_svc"],
            "count": (10, 16),
            "label": "Malware Outbreak",
        },
        "mixed": {
            "events": ["brute_force", "port_scan", "suspicious_ip", "malware_detected",
                       "privilege_escalation", "data_exfiltration", "failed_login"],
            "ips": None,
            "users": ["root", "admin", "guest"],
            "count": (8, 15),
            "label": "Multi-Vector Attack",
        },
    }

    profile = attack_profiles.get(attack_type, attack_profiles["mixed"])
    generated = []

    for _ in range(random.randint(*profile["count"])):
        event = random.choice(profile["events"])
        pool = profile["ips"] or ip_pool.pool_for_event(event, EXTERNAL_IPS)
        ip = random.choice(pool)
        user = random.choice(profile["users"])
        source = random.choice(SOURCES)
        raw = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "event": event,
            "ip": ip,
            "user": user,
            "message": f"⚠ ATTACK [{profile['label'].upper()}]: {event.replace('_', ' ')} from {ip}",
            "log_format": SOURCE_PROFILES[source]["log_format"],
            "origin": "synthetic",
        }
        generated.append(process_log(raw))

    return jsonify({
        "status": "success",
        "attack_type": attack_type,
        "label": profile["label"],
        "message": f"{profile['label']} triggered — {len(generated)} malicious events",
        "events_generated": len(generated),
    })


@app.route("/api/retrain", methods=["POST"])
def retrain_model():
    """Not implemented — there is no model to retrain.

    This endpoint used to increment a counter and return `previous_accuracy`,
    `new_accuracy`, `improvement` and an `epochs` count, all synthesised from
    `random.uniform` so that accuracy climbed roughly 1% per button press and
    could never go down. Its own docstring read "Fake model retraining
    endpoint." The dashboard rendered the result as a toast reading
    "Model retrained on N samples — +1.31% improvement".

    Detection is currently a rule set, versioned by the hash of its own weights.
    A trained model and a real evaluation against a labelled benchmark are the
    next piece of work; until one exists, this returns 501 rather than a number.
    """
    return jsonify({
        "status": "not_implemented",
        "error": "No trainable model exists in this build.",
        "detail": (
            "Detection is a rule set versioned by content hash "
            f"({RULESET_VERSION}); changing it means editing the weights, not "
            "retraining. Accuracy figures will appear here once a model is "
            "trained and evaluated against a labelled dataset."
        ),
        "ruleset_version": RULESET_VERSION,
    }), 501


@app.route("/api/reset", methods=["POST"])
def reset_all():
    """Delete every stored row, and report what was actually deleted.

    Against the old in-memory lists this cleared four Python lists and unlinked
    a JSON file. Left unchanged against a database it would have deleted
    nothing while still returning "All data cleared" — an endpoint that says it
    removed everything and did not is exactly the class of statement this
    project exists to remove. The message is now built from real row counts.
    """
    with store.write() as conn:
        deleted = store.repos.reset_all(conn)
    store.db.checkpoint()
    telemetry.reset()
    total = sum(deleted.values())
    return jsonify({
        "status": "success",
        "deleted": deleted,
        "message": (
            f"Deleted {total} rows — "
            f"{deleted['events']} events, {deleted['alerts']} alerts, "
            f"{deleted['ledger']} ledger blocks, "
            f"{deleted['soar_executions']} SOAR records"
        ),
    })


def _generator_alive() -> bool:
    return bool(_generator_thread and _generator_thread.is_alive())


def _component_health():
    """Per-stage health derived from measured state.

    Every `status` below is computed. The previous version returned the string
    literal "running" for all six components and a `random.randint` latency for
    each, so the panel reported a healthy system even with the generator thread
    dead and nothing being processed.
    """
    alive = _generator_alive()
    gen_status = "running" if alive else "stopped"
    c = store.repos.counters()
    retained = store.db.connect().execute("SELECT count(*) FROM events").fetchone()[0]
    feeds = threatintel.get_index()
    feed_ok = feeds.usable
    stale = any(s.state == threatintel.STALE for s in feeds.states.values())

    def stage(name, icon, stage_key, detail, status="running"):
        st = telemetry.stage_stats(stage_key)
        return {
            "name": name,
            "icon": icon,
            "status": status,
            "detail": detail,
            "p50_ms": st["p50_ms"],
            "p95_ms": st["p95_ms"],
            "samples": st["samples"],
        }

    return [
        stage("Ingest Queue", "📡", "ingest", f"{c['events']} ingested", gen_status),
        stage("Normalization", "⚙️", "normalize", f"{retained} retained", gen_status),
        stage(
            "Detection Engine",
            "🧠",
            "detect",
            RULESET_VERSION if feed_ok else "no threat feed",
            "running" if feed_ok else "degraded",
        ),
        stage("Alert System", "🚨", "alert", f"{c['alerts']} raised"),
        stage("SOAR Engine", "🤖", "alert", f"{c['soar']} playbooks selected", "simulated"),
        stage("Audit Ledger", "🔗", "ledger", f"{c['blocks']} blocks"),
    ], feed_ok, stale, alive


@app.route("/api/system-health", methods=["GET"])
def system_health():
    """Measured process and pipeline health."""
    components, feed_ok, stale, alive = _component_health()

    if not alive:
        state, label = "down", "Log generator stopped"
    elif not feed_ok:
        state, label = "degraded", "No threat feed cached — reputation unavailable"
    elif stale:
        state, label = "degraded", "Threat feed is stale"
    else:
        state, label = "ok", "All systems operational"

    payload = {
        "components": components,
        "summary": {"state": state, "label": label},
        **telemetry.process_metrics(),
        "stages": telemetry.all_stage_stats(),
    }
    # Kept under its old name for the dashboard, but it is now a measured rate
    # over a rolling 60s window. It used to be len(logs)/uptime — a numerator
    # capped at 2000 over a denominator that grows forever, so it provably
    # decayed toward zero no matter how fast the pipeline was actually running.
    payload["logs_per_second"] = payload["events_per_second"]
    return jsonify(payload)


@app.route("/api/pipeline-status", methods=["GET"])
def pipeline_status():
    components, _, _, _ = _component_health()
    return jsonify({"stages": components, "ruleset_version": RULESET_VERSION})


@app.route("/api/threat-intel", methods=["GET"])
def threat_intel_status():
    """Provenance for the reputation data: which feed, how many entries, how old."""
    idx = threatintel.get_index()
    return jsonify({
        "usable": idx.usable,
        "feeds": [
            {
                "name": s.name,
                "state": s.state,
                "entries": s.entries,
                "fetched_at": s.fetched_at,
                "age_hours": round(s.age_hours, 2) if s.age_hours is not None else None,
                "citation": s.citation,
                "homepage": s.homepage,
                "error": s.error,
            }
            for s in idx.states.values()
        ],
        "demo_address_pool": {"addresses": list(EXTERNAL_IPS), "note": IP_POOL_NOTE},
    })


# ─── Start ─────────────────────────────────────────────────────────────────────
_generator_thread = None


def start_background() -> None:
    """Bring the app up.

    Called at import time, not from `if __name__ == "__main__"`. The startup
    work used to live in the __main__ block, so under `flask run`, gunicorn, a
    WSGI shim or a test client the generator never started and uptime read 0.
    """
    global _generator_thread
    if _generator_thread is not None:
        return
    store.db.connect()          # creates/validates the schema once
    refresh_ip_pools()
    _generator_thread = threading.Thread(
        target=log_generator_loop, name="log-generator", daemon=True
    )
    _generator_thread.start()


def _startup_banner() -> str:
    idx = threatintel.get_index()
    lines = [
        "\n🛡️  Watchtower backend starting...",
        f"📡 Synthetic log generator active ({len(SOURCES)} source profiles)",
        f"🧠 Detection engine loaded — rule-based, {RULESET_VERSION}",
    ]
    for st in idx.states.values():
        if st.state == threatintel.MISSING:
            lines.append(f"⚠️  Threat feed '{st.name}' unavailable — {st.error}")
        else:
            lines.append(f"🌐 {st.citation}: {st.entries} entries ({st.state})")
    if not idx.usable:
        lines.append("   IP reputation will report 'unavailable' rather than guessing.")
        lines.append("   Fetch feeds with: python -m threatintel.fetch")
    c = store.repos.counters()
    lines.append(f"💾 Store: {store.db.path()} ({c['events']} events, {c['blocks']} blocks so far)")
    lines.append(f"🔎 Demo addresses: {IP_POOL_NOTE}")
    lines.append("🔗 API: http://localhost:5001\n")
    return "\n".join(lines)


start_background()

if __name__ == "__main__":
    print(_startup_banner())
    app.run(debug=False, port=5001, host="0.0.0.0")
