"""The shadow signal is persisted on real ingested events without raising alerts."""

from datetime import UTC, datetime

from watchtower import config
from watchtower.app import API_PREFIX, create_app
from watchtower.detect import live_profile
from watchtower.pipeline import consumer
from watchtower.pipeline.consumer import process_log
from watchtower.store import db, repos


def _raw(ip="203.0.113.70", event="failed_login"):
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "synthetic-lab",
        "event": event,
        "ip": ip,
        "user": "analyst",
        "message": event,
        "origin": "synthetic",
        "log_format": "cef",
    }


def test_missing_profile_records_unavailable_without_alerting():
    app = create_app(start_sources=False)
    with app.test_client() as client:
        process_log(_raw(event="login_success"))
        event = client.get(f"{API_PREFIX}/logs").get_json()[0]
        assert event["shadow_verdict"]["status"] == "unavailable"
        assert event["shadow_verdict"]["reason"] == "profile_missing"
        assert (
            client.get(f"{API_PREFIX}/live-shadow/status").get_json()["reason"] == "profile_missing"
        )
        assert client.get(f"{API_PREFIX}/alerts").get_json() == []


def test_profile_scores_real_window_and_remains_shadow_only():
    profile = live_profile.fit_normal(
        [
            {"failed_attempts_count": 0, "request_frequency": n, "ip_reputation_score": 0}
            for n in (1, 1, 2, 2, 3, 3, 4, 4)
        ],
        source_hash="synthetic-lab-normal-v1",
    )
    config.get().models_dir.mkdir(parents=True, exist_ok=True)
    live_profile.save_profile(profile, config.get().models_dir / "live-profile.json")
    app = create_app(start_sources=False)
    with app.test_client() as client:
        for _ in range(7):
            process_log(_raw(event="login_success"))
        process_log(_raw(event="brute_force"))
        event = client.get(f"{API_PREFIX}/logs").get_json()[0]
        assert event["shadow_verdict"]["status"] == "scored"
        assert event["shadow_verdict"]["profile_digest"] == profile.digest
        assert event["shadow_verdict"]["shadow_anomaly"] is True
        assert event["shadow_verdict"]["detector"] == "live_profile_shadow"
        # The rule's threshold, not the shadow score, decides whether an alert exists.
        assert repos.counters()["alerts"] == 1
        assert client.get(f"{API_PREFIX}/alerts").get_json()[0]["shadow_verdict"]
        assert (
            client.get(f"{API_PREFIX}/live-shadow/status").get_json()["profile_digest"]
            == profile.digest
        )

        # The stored verdict remains bound to its event after a profile change.
        (config.get().models_dir / "live-profile.json").unlink()
        db.close_all()
        db.configure(None)
        create_app(start_sources=False)
        assert repos.recent_events()[0]["shadow_verdict"]["profile_digest"] == profile.digest
        assert db.connect().execute("SELECT count(*) FROM event_shadow_verdicts").fetchone()[0] == 8


def test_corrupt_profile_does_not_break_ingestion():
    path = config.get().models_dir / "live-profile.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("broken")
    create_app(start_sources=False)
    process_log(_raw(event="login_success"))
    verdict = repos.recent_events()[0]["shadow_verdict"]
    assert verdict["status"] == "unavailable"
    assert verdict["reason"] == "profile_invalid"
    assert db.connect().execute("SELECT count(*) FROM ledger").fetchone()[0] == 1


def test_malformed_profile_shape_does_not_break_ingestion():
    path = config.get().models_dir / "live-profile.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[]")
    create_app(start_sources=False)
    process_log(_raw(event="login_success"))
    assert repos.recent_events()[0]["shadow_verdict"]["reason"] == "profile_invalid"
    assert repos.counters()["events"] == 1


def test_blocked_event_has_explicit_skipped_verdict():
    create_app(start_sources=False)
    with db.write() as conn:
        repos.block_ip(conn, "203.0.113.70", "test", None, 300)
    process_log(_raw(event="brute_force"))
    row = repos.recent_events()[0]
    assert row["dropped"] is True
    assert row["shadow_verdict"]["status"] == "skipped"
    assert row["shadow_verdict"]["reason"] == "blocked_event"
    assert repos.recent_alerts() == []


def test_reset_deletes_shadow_verdicts_with_events():
    create_app(start_sources=False)
    process_log(_raw(event="login_success"))
    assert db.connect().execute("SELECT count(*) FROM event_shadow_verdicts").fetchone()[0] == 1
    with db.write() as conn:
        repos.reset_all(conn)
    assert db.connect().execute("SELECT count(*) FROM event_shadow_verdicts").fetchone()[0] == 0


def test_repeated_rule_alerts_are_cooled_down_across_restart(monkeypatch):
    create_app(start_sources=False)
    clock = [1_800_000_000_000]
    monkeypatch.setattr(repos, "now_ms", lambda: clock[0])
    monkeypatch.setattr(consumer, "run_response", lambda alert: None)
    for _ in range(4):
        process_log(_raw(event="brute_force"))
    assert repos.counters()["events"] == 4
    assert repos.counters()["alerts"] == 1
    assert db.connect().execute("SELECT count(*) FROM ledger").fetchone()[0] == 4

    db.close_all()
    db.configure(None)
    clock[0] += 30_000
    process_log(_raw(event="brute_force"))
    assert repos.counters()["alerts"] == 1

    clock[0] += 31_000
    process_log(_raw(event="brute_force"))
    assert repos.counters()["alerts"] == 2


def test_new_event_type_can_alert_during_another_types_cooldown(monkeypatch):
    create_app(start_sources=False)
    monkeypatch.setattr(consumer, "run_response", lambda alert: None)
    process_log(_raw(event="brute_force"))
    process_log(_raw(event="malware_detected"))
    assert [alert["event"] for alert in repos.recent_alerts()] == [
        "malware_detected",
        "brute_force",
    ]
