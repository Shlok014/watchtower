"""Reproducible, synthetic-only evaluation of the live shadow profile.

Run ``python -m eval.live`` from ``backend``. This never touches the runtime
database, alerts, or the published HDFS benchmark. The result cannot establish
field accuracy: all examples are generated from these declared scenarios.
"""

import argparse
import hashlib
import json
import random
import time

from watchtower import config
from watchtower.detect import live_profile

SEED = 41


def _window(failed: int, frequency: int, severity: str = "low", reputation: float = 0.0) -> dict:
    # This matches the keys in detect.rules.detect(...)["features"]. Deliberately
    # omit attack labels, scenario names, IPs, and source IDs from model input.
    return {
        "failed_attempts_count": failed,
        "request_frequency": frequency,
        "ip_reputation_score": reputation,
        "event_severity": severity,
        "source": "synthetic-evaluation",
        "threshold": 0.45,
    }


def build_scenarios(seed: int = SEED) -> dict[str, list[dict]]:
    """Generate disjoint source/IP groups with normal-only training windows."""
    rng = random.Random(seed)
    splits: dict[str, list[dict]] = {"train": [], "validation": [], "test": []}
    for split, groups in (("train", 12), ("validation", 4), ("test", 8)):
        for group_index in range(groups):
            source_group = f"{split}-source-{group_index:02d}"
            ip_index = {"train": 0, "validation": 12, "test": 16}[split] + group_index + 1
            ip_group = f"synthetic-ip-{ip_index:03d}"
            group = f"{source_group}-{ip_group}"
            start = len(splits[split])
            for _ in range(8):
                splits[split].append(
                    {
                        "group": group,
                        "label": 0,
                        "scenario": "routine_window",
                        "features": _window(rng.randint(0, 1), rng.randint(1, 5)),
                    }
                )
            if split != "train":
                splits[split].extend(
                    [
                        {
                            "group": group,
                            "label": 1,
                            "scenario": "login_burst",
                            "features": _window(rng.randint(8, 12), rng.randint(3, 5), "medium"),
                        },
                        {
                            "group": group,
                            "label": 1,
                            "scenario": "request_surge",
                            "features": _window(0, rng.randint(16, 22)),
                        },
                        {
                            "group": group,
                            "label": 1,
                            "scenario": "subtle_single_event",
                            "features": _window(0, rng.randint(1, 3), "critical"),
                        },
                        {
                            "group": group,
                            "label": 1,
                            "scenario": "hostile_reputation",
                            "features": _window(0, rng.randint(1, 3), reputation=0.8),
                        },
                    ]
                )
            for row in splits[split][start:]:
                row["source_group"] = source_group
                row["ip_group"] = ip_group
    return splits


def _metrics(rows: list[dict], profile: live_profile.LiveProfile) -> dict:
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    misses = []
    for row in rows:
        verdict = profile.score(row["features"])
        predicted = verdict["shadow_anomaly"]
        actual = bool(row["label"])
        cell = "tp" if predicted and actual else "fp" if predicted else "fn" if actual else "tn"
        counts[cell] += 1
        if cell == "fn":
            misses.append({"group": row["group"], "scenario": row["scenario"]})
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
    return {
        "windows": len(rows),
        "confusion": counts,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "misses": misses,
    }


def fit_demo_profile(seed: int = SEED) -> live_profile.LiveProfile:
    """Fit the declared synthetic normal-only baseline for a demo, not field use."""
    splits = build_scenarios(seed)
    baseline = [row["features"] for row in splits["train"]]
    source_blob = json.dumps(
        [{"group": row["group"], "features": row["features"]} for row in splits["train"]],
        sort_keys=True,
        separators=(",", ":"),
    )
    return live_profile.fit_normal(
        baseline, source_hash=hashlib.sha256(source_blob.encode()).hexdigest()
    )


def evaluate(seed: int = SEED) -> dict:
    """Fit on normal train rows, measure fixed threshold on held-out groups."""
    started = time.perf_counter()
    splits = build_scenarios(seed)
    groups = {name: sorted({row["group"] for row in rows}) for name, rows in splits.items()}
    for identity in ("group", "source_group", "ip_group"):
        ids = {name: {row[identity] for row in rows} for name, rows in splits.items()}
        if any(
            ids[left] & ids[right]
            for left, right in (("train", "validation"), ("train", "test"), ("validation", "test"))
        ):
            raise ValueError(f"evaluation {identity} groups overlap")
    if any(row["label"] != 0 for row in splits["train"]):
        raise ValueError("training contains attack labels")
    fit_started = time.perf_counter()
    profile = fit_demo_profile(seed)
    fit_seconds = time.perf_counter() - fit_started
    score_started = time.perf_counter()
    validation = _metrics(splits["validation"], profile)
    test = _metrics(splits["test"], profile)
    score_seconds = time.perf_counter() - score_started
    scored = len(splits["validation"]) + len(splits["test"])
    return {
        "protocol": "normal_only_disjoint_synthetic_groups_v1",
        "seed": seed,
        "profile": {
            "digest": profile.digest,
            "source_hash": profile.source_hash,
            "normal_windows": profile.normal_windows,
            "version": profile.version,
            "threshold": live_profile.THRESHOLD,
        },
        "split": {
            "train_windows": len(splits["train"]),
            "validation_windows": len(splits["validation"]),
            "test_windows": len(splits["test"]),
            "groups": groups,
        },
        "validation": validation,
        "test": test,
        "runtime": {
            "fit_seconds": fit_seconds,
            "score_seconds": score_seconds,
            "total_seconds": time.perf_counter() - started,
            "scored_windows": scored,
            "scored_windows_per_second": scored / score_seconds if score_seconds else None,
        },
        "limits": [
            "Synthetic rule-feature-shaped windows only; no real incident labels or measured production false alarms.",
            "The harness bypasses live normalization, ingestion, threat-feed lookup, and rule-window queries.",
            "Validation and test groups are disjoint from training but share one generator.",
            "The threshold is fixed before validation/test and is not calibrated probability.",
            "Single-event attacks without window deviation are expected misses.",
            "This profile is shadow-only; rule detection remains the only alert trigger.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--install-demo-profile",
        action="store_true",
        help="write a synthetic-only shadow profile into the configured models directory",
    )
    args = parser.parse_args()
    report = evaluate()
    if args.install_demo_profile:
        path = config.get().models_dir / "live-profile.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        live_profile.save_profile(fit_demo_profile(), path)
        report["installed_demo_profile"] = str(path)
        report["install_note"] = (
            "Synthetic baseline only; restart Watchtower to load it; shadow-only."
        )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
