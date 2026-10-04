"""Contracts for the offline, shadow-only live profile."""

import json

import pytest

from watchtower.detect import live_profile


def _features(failed=0, frequency=2, reputation=0.0):
    return {
        "failed_attempts_count": failed,
        "request_frequency": frequency,
        "ip_reputation_score": reputation,
        "event_severity": "critical",  # Must not become a label shortcut.
        "source": "unseen-test-source",
        "threshold": 0.45,
    }


def test_normal_profile_scores_numeric_live_features_without_alert_action():
    baseline = [_features(frequency=n) for n in (1, 2, 2, 3, 3, 4, 5)]
    profile = live_profile.fit_normal(baseline, source_hash="normal-source-sha256")

    normal = profile.score(_features(frequency=3))
    surge = profile.score(_features(frequency=20))

    assert normal["status"] == "scored"
    assert normal["shadow_anomaly"] is False
    assert surge["shadow_anomaly"] is True
    assert surge["anomaly_score"] > normal["anomaly_score"]
    assert surge["detector"] == "live_profile_shadow"
    assert "is_anomaly" not in surge  # Rule detector owns the alert decision.
    assert surge["profile_digest"] == profile.digest
    assert profile.score({**_features(frequency=3), "event_severity": "low"}) == normal


def test_profile_rejects_bad_or_missing_numeric_features():
    with pytest.raises(ValueError, match="normal baseline"):
        live_profile.fit_normal([], source_hash="sha")
    with pytest.raises(ValueError, match="source_hash"):
        live_profile.fit_normal([_features()], source_hash="")
    profile = live_profile.fit_normal([_features()], source_hash="sha")
    with pytest.raises(ValueError, match="request_frequency"):
        profile.score({**_features(), "request_frequency": -1})
    with pytest.raises(ValueError, match="ip_reputation_score"):
        profile.score({**_features(), "ip_reputation_score": float("nan")})


def test_profile_digest_detects_corrupt_saved_profile(tmp_path):
    profile = live_profile.fit_normal([_features(frequency=n) for n in (1, 2, 3)], "sha")
    path = tmp_path / "profile.json"
    live_profile.save_profile(profile, path)
    assert live_profile.load_profile(path) == profile

    payload = json.loads(path.read_text())
    payload["centers"]["request_frequency"] = 99
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="digest"):
        live_profile.load_profile(path)


def test_missing_profile_is_explicitly_unavailable():
    verdict = live_profile.score(_features(), profile=None)
    assert verdict == {
        "status": "unavailable",
        "detector": "live_profile_shadow",
        "reason": "profile_missing",
        "profile_digest": None,
    }


def test_new_hostile_reputation_is_a_shadow_deviation():
    profile = live_profile.fit_normal([_features() for _ in range(8)], "sha")
    assert profile.score(_features(reputation=0.8))["shadow_anomaly"] is True
