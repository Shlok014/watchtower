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
    # ── real sources ──────────────────────────────────────────────────────────
    # Syslog, a tailed file and a dataset replay carry a *log level*, not a
    # security classification. Mapping "WARN" onto "suspicious_ip" would invent
    # a threat judgement the line never made, so these keep the level they came
    # with and the severity is simply that level restated. They deliberately
    # carry no entry in EVENT_WEIGHTS: a real event alerts here only when the
    # correlation windows or the reputation lookup say something, never because
    # a filesystem logged an error.
    #
    # The eight names are the RFC 5424 severities, so a syslog PRI maps onto
    # them exactly and HDFS's INFO/WARN/ERROR/FATAL land on the same scale.
    "log_debug": {"severity": "low", "category": "application"},
    "log_info": {"severity": "low", "category": "application"},
    "log_notice": {"severity": "low", "category": "application"},
    "log_warning": {"severity": "medium", "category": "application"},
    "log_error": {"severity": "high", "category": "application"},
    "log_critical": {"severity": "critical", "category": "application"},
    "log_alert": {"severity": "critical", "category": "application"},
    "log_emergency": {"severity": "critical", "category": "application"},
}

# RFC 5424 severity code → event name. Index is the numeric severity.
SYSLOG_SEVERITY = (
    "log_emergency",
    "log_alert",
    "log_critical",
    "log_error",
    "log_warning",
    "log_notice",
    "log_info",
    "log_debug",
)

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
