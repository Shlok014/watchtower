"""Synthetic raw-event replay through Watchtower's live ingest path.

Run ``python -m eval.live_pipeline`` from ``backend``. This uses a temporary
SQLite database and an offline normal-only profile. Scenario labels are assigned
by this generator, so the report cannot establish production detection quality.
"""

import hashlib
import json
import random
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from watchtower import config
from watchtower.detect import live_profile, live_shadow
from watchtower.pipeline import consumer
from watchtower.store import db, repos

from . import live

SEED = live.SEED
SCENARIOS = (
    "routine",
    "benign_burst",
    "low_and_slow",
    "obvious_attack",
    "fast_failed_logins",
)


def _profile(seed: int) -> tuple[live_profile.LiveProfile, dict]:
    splits = live.build_scenarios(seed)
    baseline = splits["train"]
    if any(row["label"] != 0 for row in baseline):
        raise ValueError("profile baseline contains attack labels")
    source_blob = json.dumps(
        [{"group": row["group"], "features": row["features"]} for row in baseline],
        sort_keys=True,
        separators=(",", ":"),
    )
    source_hash = hashlib.sha256(source_blob.encode()).hexdigest()
    return live_profile.fit_normal(
        [row["features"] for row in baseline], source_hash=source_hash
    ), splits


def _raw_events(seed: int, split: str, groups: int) -> list[dict]:
    """Declare independent source/IP groups and event-level synthetic labels."""
    rng = random.Random(f"{seed}:{split}")
    prefix = "198.51.100" if split == "validation" else "203.0.113"
    rows = []
    for group in range(groups):
        source = f"{split}-pipeline-source-{group:02d}"
        for scenario_index, scenario in enumerate(SCENARIOS):
            ip = f"{prefix}.{group * 16 + scenario_index + 1}"
            if scenario == "routine":
                events = ["log_info"] * 2
            elif scenario == "benign_burst":
                events = ["log_info"] * rng.randint(9, 11)
            elif scenario == "low_and_slow":
                events = ["failed_login"] * 2
            elif scenario == "fast_failed_logins":
                events = ["failed_login"] * 9
            else:
                events = ["brute_force"]
            for position, event in enumerate(events):
                rows.append(
                    {
                        "source_group": source,
                        "ip_group": ip,
                        "scenario": scenario,
                        "label": int(
                            scenario in {"low_and_slow", "obvious_attack", "fast_failed_logins"}
                        ),
                        "raw": {
                            "timestamp": datetime(2026, 1, 1, tzinfo=UTC).isoformat(),
                            "source": source,
                            "ip": ip,
                            "event": event,
                            "user": "synthetic-evaluation",
                            "message": f"synthetic {scenario} event {position + 1}",
                            "origin": "synthetic",
                            "log_format": "syslog",
                        },
                    }
                )
    return rows


def _counts(rows: list[dict], predicted_ids: set[int]) -> dict:
    confusion = {key: 0 for key in ("tp", "fp", "fn", "tn")}
    misses = []
    for row in rows:
        actual = bool(row["label"])
        predicted = row["event_id"] in predicted_ids
        cell = "tp" if predicted and actual else "fp" if predicted else "fn" if actual else "tn"
        confusion[cell] += 1
        if cell == "fn":
            misses.append(
                {
                    "event_id": row["event_id"],
                    "scenario": row["scenario"],
                    "source_group": row["source_group"],
                    "ip_group": row["ip_group"],
                }
            )
    tp, fp, fn, tn = (confusion[key] for key in ("tp", "fp", "fn", "tn"))
    return {
        "confusion": confusion,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "misses": misses,
    }


def _score_split(rows: list[dict], stored: dict[int, dict], alerts: set[int]) -> dict:
    shadow_ids = set()
    for row in rows:
        event = stored[row["event_id"]]
        verdict = event["shadow_verdict"]
        if event["dropped"] or verdict is None or verdict["status"] != "scored":
            raise RuntimeError(f"unscored synthetic event {row['event_id']}")
        if verdict["shadow_anomaly"]:
            shadow_ids.add(row["event_id"])
    scenarios = {}
    for scenario in SCENARIOS:
        selected = [row for row in rows if row["scenario"] == scenario]
        scenarios[scenario] = {
            "events": len(selected),
            "attack_events": sum(row["label"] for row in selected),
            "benign_events": sum(not row["label"] for row in selected),
            "rules": _counts(selected, alerts),
            "shadow": _counts(selected, shadow_ids),
        }
    return {
        "events": len(rows),
        "attack_events": sum(row["label"] for row in rows),
        "benign_events": sum(not row["label"] for row in rows),
        "rules": _counts(rows, alerts),
        "shadow": _counts(rows, shadow_ids),
        "scenarios": scenarios,
    }


def evaluate(seed: int = SEED) -> dict:
    """Replay generated events through normalize/process_log into temporary SQLite."""
    profile, baseline = _profile(seed)
    rows_by_split = {
        "validation": _raw_events(seed, "validation", 2),
        "test": _raw_events(seed, "test", 3),
    }
    metadata = {
        "train": {
            "source_groups": sorted({row["source_group"] for row in baseline["train"]}),
            "ip_groups": sorted({row["ip_group"] for row in baseline["train"]}),
        }
    }
    for split, rows in rows_by_split.items():
        metadata[split] = {
            "source_groups": sorted({row["source_group"] for row in rows}),
            "ip_groups": sorted({row["ip_group"] for row in rows}),
        }
    for identity in ("source_groups", "ip_groups"):
        groups = [set(metadata[split][identity]) for split in ("train", "validation", "test")]
        if any(groups[left] & groups[right] for left, right in ((0, 1), (0, 2), (1, 2))):
            raise ValueError(f"{identity} overlap across splits")

    saved_config = config.get()
    saved_db_path = db.path()
    saved_profile = live_shadow._profile
    saved_unavailable_reason = live_shadow._unavailable_reason
    saved_models_dir = live_shadow._models_dir
    saved_prune = consumer._last_prune
    try:
        with tempfile.TemporaryDirectory(prefix="watchtower-live-eval-") as directory:
            config.replace(data_dir=Path(directory))
            db.configure(None)
            config.get().models_dir.mkdir(parents=True, exist_ok=True)
            live_profile.save_profile(profile, config.get().models_dir / "live-profile.json")
            live_shadow.enable(config.get().models_dir)
            db.connect()
            # The detector and persisted alert are measured; response actions
            # are excluded to prevent webhooks and per-IP suppression.
            with patch.object(consumer, "run_response", return_value=None):
                for rows in rows_by_split.values():
                    for row in rows:
                        row["event_id"] = consumer.process_log(row["raw"])["id"]
            all_rows = [row for rows in rows_by_split.values() for row in rows]
            events = repos.recent_events(limit=len(all_rows))
            stored = {event["id"]: event for event in events}
            if set(stored) != {row["event_id"] for row in all_rows}:
                raise RuntimeError("persisted event count differs from replay")
            alerts = {
                row[0] for row in db.connect().execute("SELECT event_id FROM alerts").fetchall()
            }
            results = {
                split: _score_split(rows, stored, alerts) for split, rows in rows_by_split.items()
            }
    finally:
        db.close_all()
        config.set_config(saved_config)
        db.configure(saved_db_path)
        live_shadow._profile = saved_profile
        live_shadow._unavailable_reason = saved_unavailable_reason
        live_shadow._models_dir = saved_models_dir
        consumer._last_prune = saved_prune

    return {
        "protocol": "synthetic_raw_event_pipeline_replay_v1",
        "seed": seed,
        "profile": {
            "digest": profile.digest,
            "source_hash": profile.source_hash,
            "normal_windows": profile.normal_windows,
            "threshold": live_profile.THRESHOLD,
        },
        "split": {"train_windows": len(baseline["train"]), **metadata},
        "validation": results["validation"],
        "test": results["test"],
        "provenance": {
            "source": "generated_raw_events",
            "ground_truth": "scenario_assigned",
            "production_validity": False,
            "baseline": "normal-only synthetic rule-feature windows from eval.live",
            "replay": "normalize_log and process_log with temporary SQLite",
            "response_actions": "disabled_for_replay",
            "ip_reputation": "RFC5737 non-routable documentation IPs; no threat-feed evidence",
        },
        "limits": [
            "Scenario-assigned labels are not incident ground truth or production false-alarm measurements.",
            "The baseline is feature-shaped synthetic data, not raw training traffic.",
            "Validation and test replay use disjoint sources and IPs but share one generator.",
            "SOAR actions are disabled; this measures alert creation, not containment.",
            "Shadow verdicts never create alerts; rule and shadow confusion matrices are separate.",
        ],
    }


def main() -> None:
    print(json.dumps(evaluate(), indent=2))


if __name__ == "__main__":
    main()
