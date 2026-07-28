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

from flask import Flask, jsonify, request
from flask_cors import CORS

import telemetry
import threatintel
from threatintel import pool as ip_pool

app = Flask(__name__)
CORS(app)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

# ─── In-Memory Data Stores ─────────────────────────────────────────────────────
# These are ring buffers, not archives. len() of any of them is the buffer's
# current occupancy, never a cumulative total — the monotonic counters below are
# what the UI must show as "total ingested". Conflating the two meant the
# dashboard's "Total Logs Ingested" froze at 2000 after about 47 minutes.
logs = []
alerts = []
soar_actions = []
blockchain_ledger = []

# Monotonic lifetime counters. Guarded by _counter_lock because the generator
# thread and /api/simulate-attack both increment them, and `x += 1` is a
# LOAD/ADD/STORE that can interleave at a bytecode boundary.
_counter_lock = threading.Lock()
_log_counter = 0
_alert_counter = 0
_block_counter = 0
_soar_counter = 0
_dropped_unparseable = 0

# Config
LOG_GENERATION_ACTIVE = True
MAX_LOGS = 2000
MAX_ALERTS = 500
ALERT_THRESHOLD = 0.45


def _next(name: str) -> int:
    """Atomically increment and return one of the lifetime counters."""
    global _log_counter, _alert_counter, _block_counter, _soar_counter
    with _counter_lock:
        if name == "log":
            _log_counter += 1
            return _log_counter
        if name == "alert":
            _alert_counter += 1
            return _alert_counter
        if name == "block":
            _block_counter += 1
            return _block_counter
        _soar_counter += 1
        return _soar_counter

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

# ─── Persistence Helpers ────────────────────────────────────────────────────────
_save_lock = threading.Lock()
_save_counter = 0

def _save_data():
    """Persist data to JSON files periodically."""
    global _save_counter
    _save_counter += 1
    if _save_counter % 20 != 0:  # Save every 20th log
        return
    with _save_lock:
        try:
            with open(os.path.join(DATA_DIR, "ledger.json"), "w") as f:
                json.dump(blockchain_ledger[-200:], f, default=str)
        except Exception:
            pass

def _load_data():
    """Load persisted data on startup."""
    try:
        path = os.path.join(DATA_DIR, "ledger.json")
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
                blockchain_ledger.extend(data)
            print(f"   📂 Loaded {len(data)} blockchain blocks from disk")
    except Exception:
        pass


# ─── Append-Only Hash Chain ─────────────────────────────────────────────────────
# A single-writer hash chain: the data structure inside a blockchain, without
# the consensus, because there is exactly one trusted writer. It is not a
# blockchain and it is emphatically not Hyperledger.
#
# The `nonce` that used to sit in each block is gone. It implied proof-of-work
# that never happened, and it was not even an input to the digest — block_hash
# is computed from prev_hash + payload only, so the nonce was decoration that
# no verification step could ever have checked.
#
# NOTE: verification is still only link-continuity (see validate_chain). Making
# it recompute content hashes is the next piece of work; until then nothing in
# this file may claim the ledger is tamper-evident.
def hash_log(log_entry):
    """Append one entry to the hash chain and return the new block."""
    log_str = json.dumps(log_entry, sort_keys=True, default=str)
    prev_hash = blockchain_ledger[-1]["hash"] if blockchain_ledger else "0" * 64
    block_hash = hashlib.sha256((prev_hash + log_str).encode()).hexdigest()
    block = {
        # A monotonic counter, not len(blockchain_ledger) + 1. The list is
        # capped at 500 and pops from the front, so the old expression pinned
        # every block past the cap at id 501 forever.
        "block_id": _next("block"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "log_id": log_entry.get("id"),
        "log_hash": hashlib.sha256(log_str.encode()).hexdigest(),
        "prev_hash": prev_hash,
        "hash": block_hash,
    }
    blockchain_ledger.append(block)
    if len(blockchain_ledger) > 500:
        blockchain_ledger.pop(0)
    _save_data()
    return block


def validate_chain():
    """Check that each block's prev_hash matches its predecessor's hash.

    This is *link continuity only*. It does not recompute any block's hash from
    the log it claims to protect, so editing a log entry — or a block's own
    log_hash — passes this check. Callers must describe the result in exactly
    those terms; the API field is named `check` rather than `valid` so that no
    consumer can accidentally read it as "integrity verified".
    """
    errors = []
    for i in range(1, len(blockchain_ledger)):
        if blockchain_ledger[i]["prev_hash"] != blockchain_ledger[i - 1]["hash"]:
            errors.append({
                "block_id": blockchain_ledger[i]["block_id"],
                "expected": blockchain_ledger[i - 1]["hash"][:16] + "…",
                "got": blockchain_ledger[i]["prev_hash"][:16] + "…",
            })
    return {
        "check": "link_continuity",
        "links_ok": len(errors) == 0,
        "blocks_checked": len(blockchain_ledger),
        "errors": errors,
        "chain_length": len(blockchain_ledger),
        "content_hashes_recomputed": False,
        "caveat": (
            "Only prev_hash pointers were compared. Block contents were not "
            "re-hashed, so this cannot detect a modified log entry."
        ),
        "latest_hash": blockchain_ledger[-1]["hash"] if blockchain_ledger else None,
        "genesis_hash": blockchain_ledger[0]["hash"] if blockchain_ledger else None,
    }


# ─── Log Processing / Normalization ─────────────────────────────────────────────
def normalize_log(raw_log):
    """Normalize a raw log into the common Watchtower format."""
    event = raw_log.get("event", "unknown")
    meta = EVENT_TYPES.get(event, {"severity": "low", "category": "other"})
    ip = raw_log.get("ip", "0.0.0.0")
    verdict = threatintel.classify(ip)
    return {
        "id": raw_log["id"],
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

_failed_login_tracker = defaultdict(list)
_request_freq_tracker = defaultdict(list)

def rules_detect(log_entry):
    """
    Rule-based detection: sliding-window feature extraction + weighted scoring.
    """
    now = time.time()
    ip = log_entry["ip"]
    event = log_entry["event"]

    # ── Feature Extraction ──
    # 1. Failed attempts count (last 60s)
    if event == "failed_login":
        _failed_login_tracker[ip].append(now)
    _failed_login_tracker[ip] = [t for t in _failed_login_tracker[ip] if now - t < 60]
    failed_attempts = len(_failed_login_tracker[ip])

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
    _request_freq_tracker[ip].append(now)
    _request_freq_tracker[ip] = [t for t in _request_freq_tracker[ip] if now - t < 30]
    request_frequency = len(_request_freq_tracker[ip])

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
        "id": _next("soar"),
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
    soar_actions.append(response)
    if len(soar_actions) > 300:
        soar_actions.pop(0)
    return response


# ─── Alert System ──────────────────────────────────────────────────────────────
def create_alert(log_entry, detection_result):
    """Create an alert from an anomalous log."""
    alert = {
        "id": _next("alert"),
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
    alerts.append(alert)
    if len(alerts) > MAX_ALERTS:
        alerts.pop(0)

    # The status stays "open". It used to be set to "mitigated" on the line
    # after soar_respond() returned — but soar_respond only builds a dict, so
    # every alert in the system claimed to have been remediated the instant it
    # was raised. A status has to be earned by an action that actually ran.
    alert["soar_response"] = soar_respond(alert)
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
        "id": _next("log"),
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
    normalized.setdefault("origin", raw_log.get("origin", "synthetic"))
    telemetry.record("normalize", time.perf_counter() - t0)

    t0 = time.perf_counter()
    logs.append(normalized)
    if len(logs) > MAX_LOGS:
        logs.pop(0)
    telemetry.record("ingest", time.perf_counter() - t0)

    t0 = time.perf_counter()
    detection = rules_detect(normalized)
    telemetry.record("detect", time.perf_counter() - t0)

    if detection["is_anomaly"]:
        t0 = time.perf_counter()
        create_alert(normalized, detection)
        telemetry.record("alert", time.perf_counter() - t0)

    t0 = time.perf_counter()
    hash_log(normalized)
    telemetry.record("ledger", time.perf_counter() - t0)

    telemetry.record("pipeline", time.perf_counter() - t_pipeline)
    telemetry.record_event()
    return normalized


def log_generator_loop():
    """Background thread that continuously generates synthetic logs."""
    while True:
        if LOG_GENERATION_ACTIVE:
            process_log(generate_random_log())
        time.sleep(random.uniform(0.8, 2.0))


# ─── API Endpoints ──────────────────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
def get_logs():
    severity = request.args.get("severity")
    source = request.args.get("source")
    search = request.args.get("search", "").lower()
    limit = int(request.args.get("limit", 100))

    result = list(logs)
    if severity:
        result = [l for l in result if l["severity"] == severity]
    if source:
        result = [l for l in result if l["source"] == source]
    if search:
        result = [l for l in result if search in json.dumps(l).lower()]

    result = result[-limit:]
    result.reverse()
    return jsonify(result)


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    limit = int(request.args.get("limit", 50))
    result = list(alerts[-limit:])
    result.reverse()
    return jsonify(result)


@app.route("/api/stats", methods=["GET"])
def get_stats():
    now = datetime.now(timezone.utc)
    high_alerts = sum(1 for a in alerts if a["severity"] in ("high", "critical"))
    critical_alerts = sum(1 for a in alerts if a["severity"] == "critical")
    medium_alerts = sum(1 for a in alerts if a["severity"] == "medium")

    # Logs over time — last 30 intervals (each ~10 seconds)
    time_buckets = []
    for i in range(29, -1, -1):
        bucket_start = now - timedelta(seconds=(i + 1) * 10)
        bucket_end = now - timedelta(seconds=i * 10)
        log_count = 0
        for l in logs:
            try:
                ts = datetime.fromisoformat(l["timestamp"])
                if bucket_start <= ts <= bucket_end:
                    log_count += 1
            except Exception:
                pass
        alert_count = 0
        for a in alerts:
            try:
                ts = datetime.fromisoformat(a["timestamp"])
                if bucket_start <= ts <= bucket_end:
                    alert_count += 1
            except Exception:
                pass
        time_buckets.append({
            "time": bucket_end.strftime("%H:%M:%S"),
            "logs": log_count,
            "alerts": alert_count,
        })

    alert_dist = {"critical": critical_alerts, "high": high_alerts - critical_alerts,
                  "medium": medium_alerts, "low": len(alerts) - high_alerts - medium_alerts}

    event_dist = defaultdict(int)
    for l in logs[-200:]:
        event_dist[l["event"]] += 1

    source_dist = defaultdict(int)
    for l in logs[-200:]:
        source_dist[l["source"]] += 1

    return jsonify({
        # Lifetime totals come from monotonic counters. Returning len() here
        # meant every "total" silently stopped counting once its ring buffer
        # filled: total_logs froze at 2000, blocks at 500, SOAR actions at 300.
        "total_logs": _log_counter,
        "total_alerts": _alert_counter,
        "total_blocks": _block_counter,
        "soar_actions_count": _soar_counter,
        # ...and the buffer occupancies are reported separately, under names
        # that say what they are.
        "logs_retained": len(logs),
        "alerts_retained": len(alerts),
        "blocks_retained": len(blockchain_ledger),
        "retention_note": (
            f"in-memory ring buffers: {MAX_LOGS} logs, {MAX_ALERTS} alerts, "
            "500 blocks, 300 SOAR records"
        ),
        "high_severity_alerts": high_alerts,
        "critical_alerts": critical_alerts,
        "medium_severity_alerts": medium_alerts,
        "ruleset_version": RULESET_VERSION,
        "logs_over_time": time_buckets,
        "alert_distribution": alert_dist,
        "event_distribution": dict(event_dist),
        "source_distribution": dict(source_dist),
        "uptime_seconds": telemetry.uptime_seconds(),
        "sources": SOURCES,
    })


@app.route("/api/blockchain", methods=["GET"])
def get_blockchain():
    limit = int(request.args.get("limit", 30))
    result = list(blockchain_ledger[-limit:])
    result.reverse()
    return jsonify(result)


@app.route("/api/blockchain/validate", methods=["POST"])
def validate_blockchain():
    """Validate the integrity of the blockchain ledger."""
    result = validate_chain()
    return jsonify(result)


@app.route("/api/soar-actions", methods=["GET"])
def get_soar_actions():
    limit = int(request.args.get("limit", 30))
    result = list(soar_actions[-limit:])
    result.reverse()
    return jsonify(result)


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
            "id": _next("log"),
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
    """Clear all logs, alerts, blockchain, and SOAR actions."""
    global _log_counter, _alert_counter, _block_counter, _soar_counter, _save_counter
    logs.clear()
    alerts.clear()
    soar_actions.clear()
    blockchain_ledger.clear()
    _failed_login_tracker.clear()
    _request_freq_tracker.clear()
    with _counter_lock:
        _log_counter = _alert_counter = _block_counter = _soar_counter = 0
    _save_counter = 0
    telemetry.reset()
    # Clear persistence file
    ledger_path = os.path.join(DATA_DIR, "ledger.json")
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
    return jsonify({
        "status": "success",
        "message": "All data cleared — logs, alerts, blockchain, and SOAR actions reset to zero",
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
        stage("Ingest Queue", "📡", "ingest", f"{_log_counter} ingested", gen_status),
        stage("Normalization", "⚙️", "normalize", f"{len(logs)} retained", gen_status),
        stage(
            "Detection Engine",
            "🧠",
            "detect",
            RULESET_VERSION if feed_ok else "no threat feed",
            "running" if feed_ok else "degraded",
        ),
        stage("Alert System", "🚨", "alert", f"{_alert_counter} raised"),
        stage("SOAR Engine", "🤖", "alert", f"{_soar_counter} playbooks selected", "simulated"),
        stage("Audit Ledger", "🔗", "ledger", f"{_block_counter} blocks"),
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


def start_background(load_persisted: bool = True) -> None:
    """Bring the app up.

    Called at import time, not from `if __name__ == "__main__"`. The startup
    work used to live in the __main__ block, so under `flask run`, gunicorn, a
    WSGI shim or a test client the generator never started and uptime read 0.
    """
    global _generator_thread
    if _generator_thread is not None:
        return
    refresh_ip_pools()
    if load_persisted:
        _load_data()
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
    lines.append(f"🔎 Demo addresses: {IP_POOL_NOTE}")
    lines.append("🔗 API: http://localhost:5001\n")
    return "\n".join(lines)


start_background()

if __name__ == "__main__":
    print(_startup_banner())
    app.run(debug=False, port=5001, host="0.0.0.0")
