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

app = Flask(__name__)
CORS(app)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

# ─── In-Memory Data Stores ─────────────────────────────────────────────────────
logs = []
alerts = []
soar_actions = []
blockchain_ledger = []
model_version = {"version": 1, "last_trained": None}
system_start_time = None

# Config
LOG_GENERATION_ACTIVE = True
MAX_LOGS = 2000
MAX_ALERTS = 500

# ─── IP Geolocation Lookup (Fake) ──────────────────────────────────────────────
IP_GEO = {
    "192.168.1.10":  {"country": "US", "city": "New York", "isp": "Internal Network", "flag": "🇺🇸"},
    "192.168.1.20":  {"country": "US", "city": "Chicago", "isp": "Internal Network", "flag": "🇺🇸"},
    "192.168.1.30":  {"country": "US", "city": "San Jose", "isp": "Internal Network", "flag": "🇺🇸"},
    "10.0.0.5":      {"country": "US", "city": "Dallas", "isp": "Corp LAN", "flag": "🇺🇸"},
    "10.0.0.15":     {"country": "US", "city": "Seattle", "isp": "Corp LAN", "flag": "🇺🇸"},
    "172.16.0.100":  {"country": "US", "city": "Denver", "isp": "Corp LAN", "flag": "🇺🇸"},
    "45.33.32.156":  {"country": "RU", "city": "Moscow", "isp": "ShadowNet VPN", "flag": "🇷🇺"},
    "185.220.101.34": {"country": "DE", "city": "Frankfurt", "isp": "Tor Exit Node", "flag": "🇩🇪"},
    "91.240.118.172": {"country": "UA", "city": "Kyiv", "isp": "DarkRelay Proxy", "flag": "🇺🇦"},
    "198.51.100.23":  {"country": "CN", "city": "Shanghai", "isp": "PRC Telecom", "flag": "🇨🇳"},
    "203.0.113.50":   {"country": "IR", "city": "Tehran", "isp": "AnonHost", "flag": "🇮🇷"},
    "162.247.74.27":  {"country": "NL", "city": "Amsterdam", "isp": "Tor Exit Node", "flag": "🇳🇱"},
    "77.247.181.163": {"country": "RO", "city": "Bucharest", "isp": "BulletProof Hosting", "flag": "🇷🇴"},
    "104.248.30.45":  {"country": "SG", "city": "Singapore", "isp": "DigitalOcean", "flag": "🇸🇬"},
}

KNOWN_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.5", "10.0.0.15", "172.16.0.100"]
UNKNOWN_IPS = ["45.33.32.156", "185.220.101.34", "91.240.118.172", "198.51.100.23",
               "203.0.113.50", "162.247.74.27", "77.247.181.163", "104.248.30.45"]
USERS = ["admin", "root", "jdoe", "ssmith", "guest", "sysadmin", "backup_svc"]

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


# ─── Blockchain Simulation ──────────────────────────────────────────────────────
def hash_log(log_entry):
    """SHA-256 hash of log entry — simulates blockchain ledger."""
    log_str = json.dumps(log_entry, sort_keys=True, default=str)
    prev_hash = blockchain_ledger[-1]["hash"] if blockchain_ledger else "0" * 64
    block_data = prev_hash + log_str
    block_hash = hashlib.sha256(block_data.encode()).hexdigest()
    block = {
        "block_id": len(blockchain_ledger) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "log_id": log_entry.get("id"),
        "log_hash": hashlib.sha256(log_str.encode()).hexdigest(),
        "prev_hash": prev_hash,
        "hash": block_hash,
        "nonce": random.randint(1000, 9999),
    }
    blockchain_ledger.append(block)
    if len(blockchain_ledger) > 500:
        blockchain_ledger.pop(0)
    _save_data()
    return block


def validate_chain():
    """Verify integrity of the entire blockchain."""
    if len(blockchain_ledger) < 2:
        return {"valid": True, "blocks_checked": len(blockchain_ledger), "errors": []}
    errors = []
    for i in range(1, len(blockchain_ledger)):
        if blockchain_ledger[i]["prev_hash"] != blockchain_ledger[i - 1]["hash"]:
            errors.append({
                "block_id": blockchain_ledger[i]["block_id"],
                "expected": blockchain_ledger[i - 1]["hash"][:16] + "…",
                "got": blockchain_ledger[i]["prev_hash"][:16] + "…",
            })
    return {
        "valid": len(errors) == 0,
        "blocks_checked": len(blockchain_ledger),
        "errors": errors,
        "chain_length": len(blockchain_ledger),
        "latest_hash": blockchain_ledger[-1]["hash"] if blockchain_ledger else None,
        "genesis_hash": blockchain_ledger[0]["hash"] if blockchain_ledger else None,
    }


# ─── Log Processing / Normalization ─────────────────────────────────────────────
def normalize_log(raw_log):
    """Normalize a raw log into the common Watchtower format."""
    event = raw_log.get("event", "unknown")
    meta = EVENT_TYPES.get(event, {"severity": "low", "category": "other"})
    ip = raw_log.get("ip", "0.0.0.0")
    geo = IP_GEO.get(ip, {"country": "??", "city": "Unknown", "isp": "Unknown", "flag": "🏴"})
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
        "geo": geo,
        "log_format": raw_log.get("log_format", "syslog"),
    }


# ─── Detection Engine (rule-based correlation) ──────────────────────────────────────────────────
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

    # 2. IP reputation
    if ip in KNOWN_IPS:
        ip_reputation = "trusted"
        ip_rep_score = 0.0
    else:
        geo = IP_GEO.get(ip, {})
        isp = geo.get("isp", "")
        if "Tor" in isp or "VPN" in isp or "Proxy" in isp or "BulletProof" in isp:
            ip_reputation = "malicious"
            ip_rep_score = 0.40
        else:
            ip_reputation = "unknown"
            ip_rep_score = 0.25

    # 3. Request frequency (events from this IP in last 30s)
    _request_freq_tracker[ip].append(now)
    _request_freq_tracker[ip] = [t for t in _request_freq_tracker[ip] if now - t < 30]
    request_frequency = len(_request_freq_tracker[ip])

    features = {
        "failed_attempts_count": failed_attempts,
        "ip_reputation": ip_reputation,
        "ip_reputation_score": round(ip_rep_score, 2),
        "request_frequency": request_frequency,
        "event_severity": log_entry["severity"],
        "source": log_entry["source"],
    }

    # ── Weighted Scoring ──
    score = 0.0
    explanation_parts = []

    # IP reputation weight
    score += ip_rep_score
    if ip_rep_score > 0.2:
        explanation_parts.append(f"{'Malicious' if ip_reputation == 'malicious' else 'Unknown'} IP ({ip})")

    # Failed login weight
    if failed_attempts >= 5:
        score += 0.40
        explanation_parts.append(f"Brute force pattern: {failed_attempts} failed logins in 60s")
    elif failed_attempts >= 3:
        score += 0.20
        explanation_parts.append(f"Elevated failed logins: {failed_attempts} in 60s")

    # Event type weight
    event_weights = {
        "brute_force": 0.45, "malware_detected": 0.50, "privilege_escalation": 0.50,
        "data_exfiltration": 0.45, "port_scan": 0.35, "suspicious_ip": 0.35,
    }
    ew = event_weights.get(event, 0.0)
    if ew > 0:
        score += ew
        explanation_parts.append(f"High-risk event: {event.replace('_', ' ')}")

    # Request frequency weight
    if request_frequency > 15:
        score += 0.20
        explanation_parts.append(f"High request frequency: {request_frequency} requests/30s")
    elif request_frequency > 8:
        score += 0.10
        explanation_parts.append(f"Elevated request frequency: {request_frequency}/30s")

    # Randomness for realism
    score = min(1.0, max(0.0, score + random.uniform(-0.04, 0.04)))
    score = round(score, 2)

    is_anomaly = score >= 0.45
    if not explanation_parts:
        explanation_parts = ["Normal activity — no anomalies detected"]

    explanation = " + ".join(explanation_parts)

    return {
        "anomaly_score": score,
        "is_anomaly": is_anomaly,
        "model_version": f"rules-v{model_version['version']}.0",
        "features": features,
        "explanation": explanation,
        "reasons": explanation_parts,
        "confidence": round(min(0.99, 0.80 + score * 0.15 + random.uniform(0, 0.05)), 2),
    }


# ─── SOAR Automation ────────────────────────────────────────────────────────────
SOAR_PLAYBOOKS = {
    "brute_force":          {"actions": ["IP Blocked", "Session Terminated", "Alert Email Sent", "Incident Ticket Created"], "priority": "P1"},
    "suspicious_ip":        {"actions": ["IP Blocked", "Firewall Rule Updated", "Alert Email Sent"], "priority": "P2"},
    "malware_detected":     {"actions": ["Host Isolated", "AV Scan Triggered", "Alert Email Sent", "Incident Ticket Created"], "priority": "P1"},
    "port_scan":            {"actions": ["IP Blocked", "IDS Rule Updated", "Alert Email Sent"], "priority": "P2"},
    "privilege_escalation": {"actions": ["Session Terminated", "Account Locked", "Alert Email Sent", "Incident Ticket Created", "Forensics Initiated"], "priority": "P1"},
    "data_exfiltration":    {"actions": ["Network Isolated", "Session Terminated", "Alert Email Sent", "Forensics Initiated"], "priority": "P1"},
    "failed_login":         {"actions": ["Alert Email Sent", "Account Monitoring Enabled"], "priority": "P3"},
}

def soar_respond(alert_entry):
    """Simulate SOAR automated response with execution timeline."""
    event = alert_entry["event"]
    playbook = SOAR_PLAYBOOKS.get(event, {"actions": ["Alert Email Sent", "Logged to SIEM"], "priority": "P3"})
    actions = playbook["actions"]

    # Build execution timeline with simulated delays
    ts = datetime.now(timezone.utc)
    execution_steps = []
    total_ms = 0
    for action in actions:
        delay_ms = random.randint(120, 850)
        total_ms += delay_ms
        execution_steps.append({
            "action": action,
            "timestamp": (ts + timedelta(milliseconds=total_ms)).isoformat(),
            "duration_ms": delay_ms,
            "status": "completed",
        })

    response = {
        "id": len(soar_actions) + 1,
        "alert_id": alert_entry["id"],
        "timestamp": ts.isoformat(),
        "event": event,
        "ip": alert_entry["ip"],
        "actions_taken": actions,
        "execution_steps": execution_steps,
        "execution_time_ms": total_ms,
        "status": "completed",
        "priority": playbook["priority"],
        "playbook": f"PB-{event.upper().replace('_', '-')}",
    }
    soar_actions.append(response)
    if len(soar_actions) > 300:
        soar_actions.pop(0)
    return response


# ─── Alert System ────────────────────────────────────────────────────────────────
_alert_counter = 0

def create_alert(log_entry, detection_result):
    """Create an alert from an anomalous log."""
    global _alert_counter
    _alert_counter += 1
    alert = {
        "id": _alert_counter,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": log_entry["event"],
        "source": log_entry["source"],
        "ip": log_entry["ip"],
        "user": log_entry["user"],
        "severity": log_entry["severity"],
        "anomaly_score": detection_result["anomaly_score"],
        "confidence": detection_result["confidence"],
        "features": detection_result["features"],
        "explanation": detection_result["explanation"],
        "reasons": detection_result["reasons"],
        "model_version": detection_result["model_version"],
        "geo": log_entry.get("geo", {}),
        "status": "open",
        "soar_response": None,
    }
    alerts.append(alert)
    if len(alerts) > MAX_ALERTS:
        alerts.pop(0)

    soar_result = soar_respond(alert)
    alert["soar_response"] = soar_result
    alert["status"] = "mitigated"
    return alert


# ─── Log Generator (Background Thread) ──────────────────────────────────────────
_log_counter = 0

def generate_random_log():
    """Generate a source-specific random log entry."""
    global _log_counter
    _log_counter += 1

    source = random.choice(SOURCES)
    profile = SOURCE_PROFILES[source]

    events, weights = zip(*profile["events"])
    event = random.choices(events, weights=weights, k=1)[0]

    if event in ("suspicious_ip", "brute_force", "port_scan", "data_exfiltration"):
        ip = random.choice(UNKNOWN_IPS)
    else:
        ip = random.choice(KNOWN_IPS + UNKNOWN_IPS[:2])

    user = random.choice(profile["users"])
    geo = IP_GEO.get(ip, {"country": "??", "flag": "🏴"})

    messages = {
        "login_success": f"[{profile['log_format'].upper()}] User {user} authenticated successfully from {ip} ({geo.get('country', '??')})",
        "failed_login": f"[{profile['log_format'].upper()}] Authentication failed for {user} from {ip} ({geo.get('country', '??')})",
        "brute_force": f"[{profile['log_format'].upper()}] Multiple rapid auth attempts from {ip} ({geo.get('country', '??')})",
        "suspicious_ip": f"[{profile['log_format'].upper()}] Connection from flagged IP {ip} ({geo.get('country', '??')})",
        "port_scan": f"[{profile['log_format'].upper()}] Sequential port scan from {ip} ports 1-1024",
        "malware_detected": f"[{profile['log_format'].upper()}] Malware signature [Trojan.Gen.{random.randint(1,99)}] detected from {ip}",
        "file_access": f"[{profile['log_format'].upper()}] {user} accessed /etc/shadow from {ip}",
        "privilege_escalation": f"[{profile['log_format'].upper()}] sudo escalation by {user} from {ip}",
        "data_exfiltration": f"[{profile['log_format'].upper()}] {random.randint(50,500)}MB transfer to external {ip}",
        "normal_traffic": f"[{profile['log_format'].upper()}] Standard {random.choice(['HTTP', 'HTTPS', 'DNS', 'NTP'])} traffic from {ip}",
    }

    return {
        "id": _log_counter,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "event": event,
        "ip": ip,
        "user": user,
        "message": messages.get(event, f"Event {event} from {ip}"),
        "log_format": profile["log_format"],
    }


def process_log(raw_log):
    """Full pipeline: normalize → detect → alert → blockchain."""
    normalized = normalize_log(raw_log)
    logs.append(normalized)
    if len(logs) > MAX_LOGS:
        logs.pop(0)

    detection = rules_detect(normalized)
    if detection["is_anomaly"]:
        create_alert(normalized, detection)

    hash_log(normalized)
    return normalized


def log_generator_loop():
    """Background thread that continuously generates logs."""
    while True:
        if LOG_GENERATION_ACTIVE:
            raw = generate_random_log()
            process_log(raw)
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

    # Uptime
    uptime_sec = int((datetime.now(timezone.utc) - system_start_time).total_seconds()) if system_start_time else 0

    return jsonify({
        "total_logs": len(logs),
        "total_alerts": len(alerts),
        "high_severity_alerts": high_alerts,
        "critical_alerts": critical_alerts,
        "medium_severity_alerts": medium_alerts,
        "soar_actions_count": len(soar_actions),
        "blockchain_blocks": len(blockchain_ledger),
        "model_version": f"rules-v{model_version['version']}.0",
        "logs_over_time": time_buckets,
        "alert_distribution": alert_dist,
        "event_distribution": dict(event_dist),
        "source_distribution": dict(source_dist),
        "uptime_seconds": uptime_sec,
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

    attack_profiles = {
        "brute_force": {
            "events": ["failed_login"] * 8 + ["brute_force"] * 4,
            "ips": [random.choice(UNKNOWN_IPS)],  # Single IP for brute force
            "users": ["admin", "root"],
            "count": (10, 18),
            "label": "Brute Force Attack",
        },
        "ddos": {
            "events": ["port_scan"] * 5 + ["suspicious_ip"] * 5 + ["normal_traffic"] * 3,
            "ips": UNKNOWN_IPS[:4],
            "users": ["system"],
            "count": (15, 25),
            "label": "DDoS Attack",
        },
        "insider_threat": {
            "events": ["privilege_escalation"] * 3 + ["data_exfiltration"] * 4 + ["file_access"] * 3,
            "ips": KNOWN_IPS[:2],
            "users": ["jdoe", "guest"],
            "count": (8, 12),
            "label": "Insider Threat",
        },
        "malware_outbreak": {
            "events": ["malware_detected"] * 6 + ["suspicious_ip"] * 3 + ["data_exfiltration"] * 2,
            "ips": UNKNOWN_IPS[:3],
            "users": ["admin", "sysadmin", "backup_svc"],
            "count": (10, 16),
            "label": "Malware Outbreak",
        },
        "mixed": {
            "events": ["brute_force", "port_scan", "suspicious_ip", "malware_detected",
                       "privilege_escalation", "data_exfiltration", "failed_login"],
            "ips": UNKNOWN_IPS,
            "users": ["root", "admin", "guest"],
            "count": (8, 15),
            "label": "Multi-Vector Attack",
        },
    }

    profile = attack_profiles.get(attack_type, attack_profiles["mixed"])
    count_range = profile["count"]
    generated = []

    for _ in range(random.randint(*count_range)):
        global _log_counter
        _log_counter += 1
        event = random.choice(profile["events"])
        ip = random.choice(profile["ips"])
        user = random.choice(profile["users"])
        source = random.choice(SOURCES)
        raw = {
            "id": _log_counter,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "event": event,
            "ip": ip,
            "user": user,
            "message": f"⚠ ATTACK [{profile['label'].upper()}]: {event.replace('_', ' ')} from {ip}",
            "log_format": SOURCE_PROFILES[source]["log_format"],
        }
        result = process_log(raw)
        generated.append(result)

    return jsonify({
        "status": "success",
        "attack_type": attack_type,
        "label": profile["label"],
        "message": f"{profile['label']} triggered — {len(generated)} malicious events",
        "events_generated": len(generated),
    })


@app.route("/api/retrain", methods=["POST"])
def retrain_model():
    """Fake model retraining endpoint."""
    model_version["version"] += 1
    model_version["last_trained"] = datetime.now(timezone.utc).isoformat()
    prev_acc = round(0.90 + (model_version["version"] - 2) * 0.01 + random.uniform(0, 0.02), 4)
    new_acc = round(prev_acc + random.uniform(0.005, 0.02), 4)
    new_acc = min(new_acc, 0.9987)
    return jsonify({
        "status": "success",
        "message": f"Model retrained on {len(logs)} samples",
        "new_version": f"rules-v{model_version['version']}.0",
        "training_samples": len(logs),
        "previous_accuracy": prev_acc,
        "new_accuracy": new_acc,
        "improvement": f"+{round((new_acc - prev_acc) * 100, 2)}%",
        "epochs": random.randint(10, 50),
        "last_trained": model_version["last_trained"],
    })


@app.route("/api/reset", methods=["POST"])
def reset_all():
    """Clear all logs, alerts, blockchain, and SOAR actions."""
    global _log_counter, _alert_counter, _save_counter
    logs.clear()
    alerts.clear()
    soar_actions.clear()
    blockchain_ledger.clear()
    _failed_login_tracker.clear()
    _request_freq_tracker.clear()
    _log_counter = 0
    _alert_counter = 0
    _save_counter = 0
    model_version["version"] = 1
    model_version["last_trained"] = None
    # Clear persistence file
    ledger_path = os.path.join(DATA_DIR, "ledger.json")
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
    return jsonify({
        "status": "success",
        "message": "All data cleared — logs, alerts, blockchain, and SOAR actions reset to zero",
    })


@app.route("/api/system-health", methods=["GET"])
def system_health():
    """Return detailed system health status."""
    uptime = int((datetime.now(timezone.utc) - system_start_time).total_seconds()) if system_start_time else 0
    return jsonify({
        "components": [
            {"name": "Ingest Queue", "status": "running", "icon": "📡", "detail": f"{len(logs)} ingested", "latency_ms": random.randint(2, 15)},
            {"name": "Normalization", "status": "running", "icon": "⚙️", "detail": f"{len(logs)} processed", "latency_ms": random.randint(1, 5)},
            {"name": "Detection Engine", "status": "running", "icon": "🧠", "detail": f"v{model_version['version']}.0", "latency_ms": random.randint(8, 45)},
            {"name": "Alert System", "status": "running", "icon": "🚨", "detail": f"{len(alerts)} alerts", "latency_ms": random.randint(1, 8)},
            {"name": "SOAR Engine", "status": "running", "icon": "🤖", "detail": f"{len(soar_actions)} actions", "latency_ms": random.randint(50, 200)},
            {"name": "Audit Ledger", "status": "running", "icon": "🔗", "detail": f"{len(blockchain_ledger)} blocks", "latency_ms": random.randint(5, 25)},
        ],
        "uptime_seconds": uptime,
        "logs_per_second": round(len(logs) / max(uptime, 1), 2),
        "memory_usage_mb": round(random.uniform(128, 256), 1),
        "cpu_percent": round(random.uniform(12, 35), 1),
    })


@app.route("/api/pipeline-status", methods=["GET"])
def pipeline_status():
    return jsonify({
        "ingestion": {"status": "active", "label": "In-process queue", "logs_ingested": len(logs)},
        "processing": {"status": "active", "label": "Normalization Engine", "processed": len(logs)},
        "detection": {"status": "active", "label": "Detection Engine (rules)", "version": f"v{model_version['version']}.0"},
        "alerting": {"status": "active", "label": "Alert System", "alerts": len(alerts)},
        "soar": {"status": "active", "label": "SOAR Automation", "actions": len(soar_actions)},
        "blockchain": {"status": "active", "label": "SHA-256 hash chain", "blocks": len(blockchain_ledger)},
        "dashboard": {"status": "active", "label": "Watchtower Dashboard"},
    })


# ─── Start ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    system_start_time = datetime.now(timezone.utc)
    _load_data()
    generator_thread = threading.Thread(target=log_generator_loop, daemon=True)
    generator_thread.start()
    print("\n🛡️  Watchtower backend starting...")
    print("📡 Log generator active (7 source profiles)")
    print("🧠 Detection engine loaded (rule-based)")
    print(f"🔗 API: http://localhost:5001\n")
    app.run(debug=False, port=5001, host="0.0.0.0")
