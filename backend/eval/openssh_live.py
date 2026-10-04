"""Replay the committed real OpenSSH sample through the live rule pipeline.

The source has real log text but no independent incident labels. This measures
parser coverage and alert burden, not detection precision or recall.
"""

import hashlib
import json
import tempfile
from collections import Counter
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from watchtower import config, threatintel
from watchtower.detect import live_shadow, rules
from watchtower.pipeline import consumer
from watchtower.sources import replay
from watchtower.store import db, repos


def evaluate(*, cooldown: bool = True) -> dict:
    """Use original log intervals and an isolated store; never run SOAR actions."""
    source = config.get().samples_dir / "OpenSSH_2k.log"
    data = source.read_bytes()
    lines = data.decode("utf-8", errors="replace").splitlines()
    saved_config = config.get()
    saved_db_path = db.path()
    saved_profile = live_shadow._profile
    saved_reason = live_shadow._unavailable_reason
    saved_models_dir = live_shadow._models_dir
    events = Counter()
    unparsed = 0
    try:
        with tempfile.TemporaryDirectory(prefix="watchtower-openssh-eval-") as directory:
            config.replace(
                data_dir=Path(directory),
                alert_threshold=0.45,
                retention_hours=24,
                trusted_syslog_peers=(),
            )
            db.configure(None)
            live_shadow.enable(config.get().models_dir)
            db.connect()
            unavailable = threatintel.Verdict(
                "unavailable", 0.0, (), "Threat feeds disabled for replay", False
            )
            with (
                patch.object(consumer, "run_response", return_value=None),
                patch.object(consumer, "housekeeping", return_value=None),
                patch.object(threatintel, "classify", return_value=unavailable),
                nullcontext()
                if cooldown
                else patch.object(repos, "alert_within_cooldown", return_value=False),
            ):
                for line in lines:
                    raw = replay.parse_openssh(line)
                    if raw is None:
                        unparsed += 1
                        continue
                    events[raw["event"]] += 1
                    at_ms = repos.from_iso(raw["timestamp"])
                    with patch.object(repos, "now_ms", return_value=at_ms):
                        consumer.process_log(raw)
            conn = db.connect()
            stored = conn.execute("SELECT count(*) FROM events").fetchone()[0]
            if stored != sum(events.values()):
                raise RuntimeError("replay event count differs from persisted count")
            alerts = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
            alerted_ips = conn.execute("SELECT count(DISTINCT ip) FROM alerts").fetchone()[0]
            alerted_ip_set = sorted(
                row[0] for row in conn.execute("SELECT DISTINCT ip FROM alerts")
            )
            auth_ips = conn.execute(
                """SELECT count(DISTINCT ip) FROM events
                   WHERE event IN ('failed_login','auth_invalid_user','login_success')"""
            ).fetchone()[0]
            result = {
                "protocol": "openssh_2k_live_rules_replay_v1",
                "source": {
                    "name": "Loghub OpenSSH_2k.log",
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "lines": len(lines),
                },
                "parsed_events": stored,
                "unparsed_lines": unparsed,
                "event_counts": dict(sorted(events.items())),
                "unique_auth_ips": auth_ips,
                "alerts": alerts,
                "alerted_ips": alerted_ips,
                "alerted_ip_set_sha256": hashlib.sha256(
                    json.dumps(alerted_ip_set, separators=(",", ":")).encode()
                ).hexdigest(),
                "ruleset_version": rules.ruleset_version(),
                "cooldown_policy": (
                    f"{rules.ALERT_COOLDOWN_S}s_per_ip_event_type"
                    if cooldown
                    else "disabled_counterfactual"
                ),
                "replay_clock": "original_log_intervals",
                "response_actions": "disabled_for_replay",
                "threat_feeds": "disabled_for_replay",
                "incident_ground_truth": False,
                "limits": [
                    "No independent incident labels; precision, recall, and false-alarm rate cannot be estimated.",
                    "The 2k sample is a fixed excerpt, not a live traffic distribution.",
                    "Compressed message-repeated lines remain generic and are not expanded into attempts.",
                    "SOAR and threat feeds are disabled to isolate live rule behavior.",
                ],
            }
    finally:
        db.close_all()
        config.set_config(saved_config)
        db.configure(saved_db_path)
        live_shadow._profile = saved_profile
        live_shadow._unavailable_reason = saved_reason
        live_shadow._models_dir = saved_models_dir
    return result


def compare() -> dict:
    """Replay the same real input with and without only the alert cooldown."""
    with_cooldown = evaluate(cooldown=True)
    without_cooldown = evaluate(cooldown=False)
    for key in ("source", "parsed_events", "unparsed_lines", "event_counts", "unique_auth_ips"):
        if with_cooldown[key] != without_cooldown[key]:
            raise RuntimeError(f"counterfactual replay changed {key}")
    if with_cooldown["alerted_ip_set_sha256"] != without_cooldown["alerted_ip_set_sha256"]:
        raise RuntimeError("counterfactual replay changed the set of alerted IPs")
    return {
        "protocol": "openssh_2k_alert_cooldown_comparison_v1",
        "source": with_cooldown["source"],
        "parsed_events": with_cooldown["parsed_events"],
        "unparsed_lines": with_cooldown["unparsed_lines"],
        "event_counts": with_cooldown["event_counts"],
        "unique_auth_ips": with_cooldown["unique_auth_ips"],
        "alerted_ip_set_sha256": with_cooldown["alerted_ip_set_sha256"],
        "ruleset_version": with_cooldown["ruleset_version"],
        "with_cooldown": {
            "alerts": with_cooldown["alerts"],
            "alerted_ips": with_cooldown["alerted_ips"],
            "policy": with_cooldown["cooldown_policy"],
        },
        "without_cooldown": {
            "alerts": without_cooldown["alerts"],
            "alerted_ips": without_cooldown["alerted_ips"],
            "policy": without_cooldown["cooldown_policy"],
        },
        "replay_clock": "original_log_intervals",
        "response_actions": "disabled_for_replay",
        "threat_feeds": "disabled_for_replay",
        "incident_ground_truth": False,
        "limits": with_cooldown["limits"],
    }


def main() -> None:
    print(json.dumps(compare(), indent=2))


if __name__ == "__main__":
    main()
