"""The synthetic log generator.

This is the one place randomness is legitimate: it synthesises *input data*.
Simulating a log stream is honest simulation, clearly labelled as such in the
API (``origin: "synthetic"``) and in the UI. What was removed elsewhere was
randomness that faked a *measurement* of the system's own behaviour.
"""

import random
import time
from datetime import UTC, datetime

from .. import threatintel
from ..threatintel import pool as ip_pool
from .base import ThreadedSource

# ─── Source Addresses ─────────────────────────────────────────────────────────
# What used to live here was a table of fourteen addresses with invented cities
# and ISPs ("ShadowNet VPN", "DarkRelay Proxy", "BulletProof Hosting"), and
# reputation was decided by substring-matching those invented strings. Both the
# geolocation and the verdict were fiction.
INTERNAL_IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
    "10.0.0.5",
    "10.0.0.15",
    "172.16.0.100",
]

# Populated at startup from the cached Tor exit list; see threatintel/pool.py
# for why external addresses are split into two pools.
EXTERNAL_IPS: tuple[str, ...] = ip_pool.OFFLINE_POOL
IP_POOL_NOTE = "threat feeds not yet loaded"


def refresh_ip_pools() -> None:
    global EXTERNAL_IPS, IP_POOL_NOTE
    EXTERNAL_IPS, IP_POOL_NOTE = ip_pool.build_provenance_pool(threatintel.get_index())


def external_ips() -> tuple[str, ...]:
    return EXTERNAL_IPS


def pool_note() -> str:
    return IP_POOL_NOTE


# ─── Source-Specific Configuration ────────────────────────────────────────────
SOURCE_PROFILES = {
    "linux-server": {
        "events": [
            ("login_success", 25),
            ("failed_login", 15),
            ("file_access", 20),
            ("privilege_escalation", 3),
            ("normal_traffic", 30),
            ("malware_detected", 2),
            ("brute_force", 3),
            ("suspicious_ip", 2),
        ],
        "users": ["root", "admin", "jdoe", "ssmith", "backup_svc"],
        "log_format": "syslog",
    },
    "windows-dc": {
        "events": [
            ("login_success", 30),
            ("failed_login", 20),
            ("privilege_escalation", 4),
            ("normal_traffic", 20),
            ("file_access", 15),
            ("brute_force", 5),
            ("malware_detected", 3),
            ("suspicious_ip", 3),
        ],
        "users": ["admin", "sysadmin", "jdoe", "ssmith", "guest"],
        "log_format": "windows_event",
    },
    "firewall-01": {
        "events": [
            ("normal_traffic", 35),
            ("suspicious_ip", 10),
            ("port_scan", 12),
            ("data_exfiltration", 5),
            ("brute_force", 8),
            ("login_success", 15),
            ("failed_login", 10),
            ("malware_detected", 5),
        ],
        "users": ["system", "firewall_svc"],
        "log_format": "cef",
    },
    "web-proxy": {
        "events": [
            ("normal_traffic", 40),
            ("suspicious_ip", 8),
            ("data_exfiltration", 6),
            ("login_success", 20),
            ("failed_login", 10),
            ("malware_detected", 4),
            ("port_scan", 7),
            ("file_access", 5),
        ],
        "users": ["proxy_svc", "jdoe", "ssmith"],
        "log_format": "squid",
    },
    "mail-server": {
        "events": [
            ("login_success", 30),
            ("failed_login", 15),
            ("normal_traffic", 30),
            ("suspicious_ip", 5),
            ("malware_detected", 8),
            ("data_exfiltration", 4),
            ("file_access", 5),
            ("brute_force", 3),
        ],
        "users": ["postmaster", "jdoe", "ssmith", "admin"],
        "log_format": "syslog",
    },
    "iot-gateway": {
        "events": [
            ("normal_traffic", 40),
            ("suspicious_ip", 10),
            ("port_scan", 15),
            ("malware_detected", 10),
            ("data_exfiltration", 8),
            ("failed_login", 7),
            ("login_success", 5),
            ("brute_force", 5),
        ],
        "users": ["device_001", "device_042", "device_117", "iot_admin"],
        "log_format": "json",
    },
    "db-server": {
        "events": [
            ("login_success", 25),
            ("failed_login", 10),
            ("file_access", 25),
            ("privilege_escalation", 5),
            ("normal_traffic", 20),
            ("data_exfiltration", 5),
            ("suspicious_ip", 5),
            ("brute_force", 5),
        ],
        "users": ["dba", "app_svc", "admin", "backup_svc"],
        "log_format": "oracle_audit",
    },
}
SOURCES = list(SOURCE_PROFILES.keys())

EXTERNAL_EVENTS = (
    "suspicious_ip",
    "brute_force",
    "port_scan",
    "data_exfiltration",
    "malware_detected",
)


def generate_random_log() -> dict:
    """Generate a source-specific synthetic log entry."""
    source = random.choice(SOURCES)
    profile = SOURCE_PROFILES[source]

    events, weights = zip(*profile["events"], strict=False)
    event = random.choices(events, weights=weights, k=1)[0]

    if event in EXTERNAL_EVENTS:
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
        "malware_detected": (
            f"[{fmt}] Malware signature [Trojan.Gen.{random.randint(1, 99)}] detected from {ip}"
        ),
        "file_access": f"[{fmt}] {user} accessed /etc/shadow from {ip}",
        "privilege_escalation": f"[{fmt}] sudo escalation by {user} from {ip}",
        "data_exfiltration": f"[{fmt}] {random.randint(50, 500)}MB transfer to external {ip}",
        "normal_traffic": (
            f"[{fmt}] Standard {random.choice(['HTTP', 'HTTPS', 'DNS', 'NTP'])} traffic from {ip}"
        ),
    }

    return {
        # No id here: it is the events table's rowid, assigned on insert.
        "timestamp": datetime.now(UTC).isoformat(),
        "source": source,
        "event": event,
        "ip": ip,
        "user": user,
        "message": messages.get(event, f"Event {event} from {ip}"),
        "log_format": profile["log_format"],
        "origin": "synthetic",
    }


# ─── Attack simulation ────────────────────────────────────────────────────────
# `ips: None` means "pick per event from the appropriate pool" — external events
# that are about connection provenance draw from the real Tor exit list, while
# events that fabricate forensic detail draw from RFC 5737 documentation ranges.
# See threatintel/pool.py.
def attack_profiles() -> dict:
    return {
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
            "events": ["privilege_escalation"] * 3
            + ["data_exfiltration"] * 4
            + ["file_access"] * 3,
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
            "events": [
                "brute_force",
                "port_scan",
                "suspicious_ip",
                "malware_detected",
                "privilege_escalation",
                "data_exfiltration",
                "failed_login",
            ],
            "ips": None,
            "users": ["root", "admin", "guest"],
            "count": (8, 15),
            "label": "Multi-Vector Attack",
        },
    }


def build_attack(attack_type: str) -> tuple[str, list[dict]]:
    """Return (label, raw logs) for a simulated attack burst."""
    profiles = attack_profiles()
    profile = profiles.get(attack_type, profiles["mixed"])
    raws = []
    for _ in range(random.randint(*profile["count"])):
        event = random.choice(profile["events"])
        pool = profile["ips"] or ip_pool.pool_for_event(event, EXTERNAL_IPS)
        ip = random.choice(pool)
        user = random.choice(profile["users"])
        source = random.choice(SOURCES)
        raws.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "source": source,
                "event": event,
                "ip": ip,
                "user": user,
                "message": (
                    f"⚠ ATTACK [{profile['label'].upper()}]: {event.replace('_', ' ')} from {ip}"
                ),
                "log_format": SOURCE_PROFILES[source]["log_format"],
                "origin": "synthetic",
            }
        )
    return profile["label"], raws


# ─── The source ───────────────────────────────────────────────────────────────
class SyntheticSource(ThreadedSource):
    """Emits one synthetic event every 0.8–2.0 seconds."""

    name = "synthetic"
    origin = "synthetic"

    def __init__(self, on_tick=None) -> None:
        super().__init__()
        # Housekeeping used to be wired into the generator loop directly. It is
        # injected so the source stays a source.
        self._on_tick = on_tick

    def run(self, emit) -> None:
        while not self.stopping:
            try:
                emit(generate_random_log())
            except Exception as exc:
                # A persistence failure must be visible. The old code wrote the
                # ledger inside `except Exception: pass`, so a full disk meant
                # nothing was recorded and the dashboard looked perfectly fine.
                print(f"⚠️  pipeline error: {type(exc).__name__}: {exc}")
            if self._on_tick is not None:
                self._on_tick()
            time.sleep(random.uniform(0.8, 2.0))
