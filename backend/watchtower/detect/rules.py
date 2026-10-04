"""Rule-based correlation over sliding windows.

This is what the dashboard's live detection actually is, and the module is named
for it. It was called ``loglm_detect`` in a file that described itself as an AI
model; the three features it computes — failed logins per minute, request
frequency, address reputation — are ordinary SIEM correlation rules and were
never the problem. The "AI" label and the noise injected into the score were.

The trained model lives in ``eval/`` and scores the HDFS benchmark. The two are
separate on purpose, and the API says which one produced any given verdict.
"""

import hashlib
import json

from .. import config
from ..sources import file_tailer
from ..store import repos

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

FAILED_LOGIN_WINDOW_S = 60
FREQUENCY_WINDOW_S = 30
ALERT_COOLDOWN_S = 60


def threshold() -> float:
    return config.get().alert_threshold


def ruleset_version() -> str:
    """Version the ruleset by the hash of its own content.

    The old ``model_version`` was an integer that /api/retrain incremented on
    demand, so the version advanced while the rules stayed identical — and it
    was stamped on every alert as though it identified the logic that produced
    it. The fingerprint includes weights, windows, cooldown, threshold, and the
    file-tail service-account signal that can now produce a rule alert.
    """
    return (
        "rules-"
        + hashlib.sha256(
            json.dumps(
                {
                    "events": EVENT_WEIGHTS,
                    "failed_login": FAILED_LOGIN_RULES,
                    "frequency": FREQUENCY_RULES,
                    "alert_cooldown_s": ALERT_COOLDOWN_S,
                    "file_service_account_su": {
                        "accounts": sorted(file_tailer.SERVICE_ACCOUNTS),
                        "daemon_tag": file_tailer.SU_DAEMON_TAG,
                        "pattern": file_tailer.SUCCESSFUL_SU.pattern,
                        "requires_different_target": file_tailer.SU_REQUIRES_DIFFERENT_TARGET,
                        "event": "privilege_escalation",
                    },
                    "threshold": threshold(),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()[:8]
    )


def detect(conn, log_entry: dict, ingested_ts_ms: int) -> dict:
    """Sliding-window feature extraction + weighted scoring.

    The windows are SQL counts over the events table rather than two
    module-level ``defaultdict(list)`` caches. Those caches were mutated from
    the generator thread and read from request handlers, never evicted a key
    when its list emptied (so every IP ever seen leaked forever), and were lost
    on restart — so a restart silently reset every brute-force window to zero.

    They count on ``ingested_ts_ms``, deliberately. Replayed events carry their
    original timestamps, so a window over event time would match nothing and the
    detector would report "no rule matched" on every replayed event — a silent
    failure indistinguishable from benign traffic.
    """
    ip = log_entry["ip"]
    event = log_entry["event"]
    thr = threshold()

    # ── Feature Extraction ──
    # 1. Failed logins from this IP in the last 60s, whatever the current event
    #    is. The current event is already inserted, so it counts itself —
    #    matching the old tracker, which appended before reading its length.
    failed_attempts = repos.failed_logins_in_window(
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
    request_frequency = repos.events_in_window(conn, ip, ingested_ts_ms - FREQUENCY_WINDOW_S * 1000)

    features = {
        # The threshold that applied to THIS alert, stored with it. The
        # dashboard printed a hardcoded 0.45 beside every score because the API
        # never sent one — so it would have gone on saying 0.45 after anyone set
        # WATCHTOWER_ALERT_THRESHOLD, and historical alerts would be shown
        # against today's threshold rather than the one they were judged by.
        "threshold": thr,
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

    score += ip_rep_score
    if ip_rep_score > 0:
        explanation_parts.append(f"{ip} — {ip_rep_detail}")

    for limit, weight in FAILED_LOGIN_RULES:
        if failed_attempts >= limit:
            score += weight
            explanation_parts.append(f"{failed_attempts} failed logins from {ip} in 60s")
            break

    ew = EVENT_WEIGHTS.get(event, 0.0)
    if ew > 0:
        score += ew
        explanation_parts.append(f"High-risk event: {event.replace('_', ' ')}")

    for limit, weight in FREQUENCY_RULES:
        if request_frequency > limit:
            score += weight
            explanation_parts.append(f"{request_frequency} events from {ip} in 30s")
            break

    # The score is exactly the sum of the rules that fired. It used to have
    # random.uniform(-0.04, 0.04) added under the comment "Randomness for
    # realism", which made the detector nondeterministic: the same event could
    # alert on one run and not the next, and any base score of exactly 0.45
    # became a coin toss.
    score = round(min(1.0, max(0.0, score)), 2)

    if not explanation_parts:
        explanation_parts = ["No rule matched"]

    return {
        "anomaly_score": score,
        "is_anomaly": score >= thr,
        "threshold": thr,
        "ruleset_version": ruleset_version(),
        "detector": "rules",
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
