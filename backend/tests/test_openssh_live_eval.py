"""Real-log replay through the live rule path, without invented incident labels."""

from eval import openssh_live
from watchtower import config
from watchtower.store import db


def test_real_openssh_sample_replay_is_reproducible_and_isolated():
    before_config = config.get()
    before_path = db.path()
    first = openssh_live.evaluate()
    second = openssh_live.evaluate()
    assert first == second
    assert first["source"]["lines"] == 2000
    assert len(first["source"]["sha256"]) == 64
    assert sum(first["event_counts"].values()) == first["source"]["lines"]
    assert first["event_counts"]["failed_login"] > 0
    assert first["alerts"] > 0
    assert first["response_actions"] == "disabled_for_replay"
    assert first["replay_clock"] == "original_log_intervals"
    assert first["incident_ground_truth"] is False
    assert "precision" not in first and "recall" not in first
    assert config.get() is before_config
    assert db.path() == before_path


def test_cooldown_counterfactual_is_same_input_with_fewer_alerts():
    comparison = openssh_live.compare()
    assert comparison["source"]["lines"] == 2000
    assert comparison["without_cooldown"]["alerts"] > comparison["with_cooldown"]["alerts"]
    assert (
        comparison["without_cooldown"]["alerted_ips"] == comparison["with_cooldown"]["alerted_ips"]
    )
    assert len(comparison["alerted_ip_set_sha256"]) == 64
    assert comparison["incident_ground_truth"] is False
