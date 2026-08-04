"""Raw event → the common Watchtower record.

Every source hands the pipeline a dict with a raw ``event`` name, an address, a
message and — mandatory — an ``origin``. Normalization decides severity and
category from the event type, and attaches a reputation verdict for the address.

What is *not* here any more: a ``geo`` block of ``{country, city, isp, flag}``
looked up from a fourteen-row table of invented ISP names. An honest offline
geolocation answer needs a licensed database; a fabricated one is worse than
none, so the field is gone rather than softened.
"""

from .. import threatintel

EVENT_TYPES = {
    "login_success": {"severity": "low", "category": "authentication"},
    "failed_login": {"severity": "medium", "category": "authentication"},
    "brute_force": {"severity": "critical", "category": "attack"},
    "suspicious_ip": {"severity": "high", "category": "network"},
    "port_scan": {"severity": "high", "category": "reconnaissance"},
    "malware_detected": {"severity": "critical", "category": "malware"},
    "file_access": {"severity": "low", "category": "file_system"},
    "privilege_escalation": {"severity": "critical", "category": "attack"},
    "data_exfiltration": {"severity": "critical", "category": "data_leak"},
    "normal_traffic": {"severity": "low", "category": "network"},
}

DEFAULT_META = {"severity": "low", "category": "other"}


def normalize_log(raw_log: dict) -> dict:
    """Normalize a raw log into the common Watchtower format."""
    event = raw_log.get("event", "unknown")
    meta = EVENT_TYPES.get(event, DEFAULT_META)
    ip = raw_log.get("ip", "0.0.0.0")
    verdict = threatintel.classify(ip)

    # Never default a missing origin. Labelling real traffic "synthetic" is
    # wrong in the dangerous direction, and it would quietly defeat the
    # provenance labelling the whole honesty story rests on.
    origin = raw_log.get("origin")
    if not origin:
        raise ValueError(f"raw log {raw_log.get('id')} has no origin")

    return {
        "timestamp": raw_log["timestamp"],
        "source": raw_log["source"],
        "event": event,
        "event_type": meta["category"],
        "severity": meta["severity"],
        "ip": ip,
        "user": raw_log.get("user", "unknown"),
        "message": raw_log.get("message", ""),
        "origin": origin,
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
