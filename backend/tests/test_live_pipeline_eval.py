"""Synthetic replay checks for the real live ingest, rule, and shadow path."""

from eval import live_pipeline
from watchtower import config
from watchtower.detect import live_profile, live_shadow
from watchtower.store import db


def test_replay_counts_are_reproducible_and_cover_each_persisted_event():
    first = live_pipeline.evaluate(seed=41)
    second = live_pipeline.evaluate(seed=41)
    assert first == second
    assert first["protocol"] == "synthetic_raw_event_pipeline_replay_v1"
    assert first["profile"]["normal_windows"] == first["split"]["train_windows"]
    for split in ("validation", "test"):
        part = first[split]
        for detector in ("rules", "shadow"):
            counts = part[detector]["confusion"]
            assert sum(counts.values()) == part["events"]
            assert counts["tp"] + counts["fn"] == part["attack_events"]
            assert counts["fp"] + counts["tn"] == part["benign_events"]
        assert sum(row["events"] for row in part["scenarios"].values()) == part["events"]
    assert first["test"]["scenarios"]["low_and_slow"]["rules"]["confusion"]["fn"] > 0
    assert first["test"]["scenarios"]["benign_burst"]["shadow"]["confusion"]["fp"] > 0
    assert first["test"]["scenarios"]["fast_failed_logins"]["rules"]["confusion"]["tp"] > 0
    assert first["test"]["scenarios"]["fast_failed_logins"]["shadow"]["confusion"]["tp"] > 0


def test_replay_splits_are_disjoint_and_provenance_is_explicit():
    report = live_pipeline.evaluate(seed=41)
    split = report["split"]
    for identity in ("source_groups", "ip_groups"):
        groups = [set(split[name][identity]) for name in ("train", "validation", "test")]
        assert all(groups)
        assert groups[0].isdisjoint(groups[1])
        assert groups[0].isdisjoint(groups[2])
        assert groups[1].isdisjoint(groups[2])
    assert report["provenance"]["source"] == "generated_raw_events"
    assert report["provenance"]["ground_truth"] == "scenario_assigned"
    assert report["provenance"]["production_validity"] is False
    assert report["provenance"]["response_actions"] == "disabled_for_replay"


def test_replay_restores_process_state_and_keeps_database_isolated():
    before_config = config.get()
    before_path = db.path()
    before_shadow = live_shadow.status()
    report = live_pipeline.evaluate(seed=42)
    assert report["test"]["events"] > 0
    assert config.get() is before_config
    assert db.path() == before_path
    assert live_shadow.status() == before_shadow


def test_replay_preserves_an_existing_active_shadow_profile():
    profile = live_profile.fit_normal(
        [
            {"failed_attempts_count": 0, "request_frequency": n, "ip_reputation_score": 0}
            for n in (1, 1, 2, 2, 3, 3, 4, 4)
        ],
        source_hash="preexisting-profile",
    )
    config.get().models_dir.mkdir(parents=True, exist_ok=True)
    live_profile.save_profile(profile, config.get().models_dir / "live-profile.json")
    live_shadow.enable(config.get().models_dir)
    assert live_shadow.status()["status"] == "enabled"

    live_pipeline.evaluate(seed=42)

    assert live_shadow.status()["status"] == "enabled"
    assert live_shadow.status()["profile_digest"] == profile.digest
