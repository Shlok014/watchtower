"""Analyst review is a separate, durable record from automated SOAR outcome."""

import sqlite3
from pathlib import Path

import pytest

from watchtower import config
from watchtower.app import API_PREFIX, create_app
from watchtower.store import db, repos


@pytest.fixture()
def client():
    app = create_app(start_sources=False)
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


def _alert(client):
    response = client.post(f"{API_PREFIX}/simulate-attack", json={"attack_type": "brute_force"})
    assert response.status_code == 200
    alerts = client.get(f"{API_PREFIX}/alerts").get_json()
    assert alerts
    return alerts[0]


def test_review_transition_is_durable_and_does_not_rewrite_soar(client):
    alert = _alert(client)
    before_blocks = client.get(f"{API_PREFIX}/blocklist").get_json()["totals"]
    target = f"{API_PREFIX}/alerts/{alert['id']}/review"

    response = client.post(target, json={"status": "investigating", "note": "Checking source logs"})
    assert response.status_code == 200
    assert response.get_json()["review_status"] == "investigating"
    closed = client.post(target, json={"status": "closed", "note": "Confirmed synthetic test"})
    assert closed.status_code == 200

    current = next(
        a for a in client.get(f"{API_PREFIX}/alerts").get_json() if a["id"] == alert["id"]
    )
    assert current["review_status"] == "closed"
    assert current["status"] == alert["status"]
    assert client.get(f"{API_PREFIX}/blocklist").get_json()["totals"] == before_blocks
    history = client.get(target).get_json()["history"]
    assert [(row["from_status"], row["to_status"]) for row in history] == [
        ("new", "investigating"),
        ("investigating", "closed"),
    ]
    assert history[1]["note"] == "Confirmed synthetic test"


def test_invalid_review_transition_is_atomic(client):
    alert = _alert(client)
    target = f"{API_PREFIX}/alerts/{alert['id']}/review"
    assert client.post(target, json={"status": "closed", "note": "skip"}).status_code == 409
    assert client.post(target, json={"status": "investigating", "note": ""}).status_code == 400
    assert (
        client.post(target, json={"status": ["investigating"], "note": "reason"}).status_code == 400
    )
    assert client.post(target, json={"status": {"x": 1}, "note": "reason"}).status_code == 400
    assert client.get(target).get_json()["history"] == []
    assert client.get(target).get_json()["review_status"] == "new"


def test_closed_alert_can_be_reopened_with_a_recorded_reason(client):
    alert = _alert(client)
    target = f"{API_PREFIX}/alerts/{alert['id']}/review"
    client.post(target, json={"status": "investigating", "note": "Reviewing"})
    client.post(target, json={"status": "closed", "note": "Resolved"})
    assert client.post(target, json={"status": "new", "note": "undo"}).status_code == 409
    response = client.post(target, json={"status": "investigating", "note": "New evidence"})
    assert response.status_code == 200
    assert response.get_json()["review_status"] == "investigating"
    assert len(client.get(target).get_json()["history"]) == 3


def test_review_post_captures_snapshot_before_releasing_write_lock(client, monkeypatch):
    alert = _alert(client)
    target = f"{API_PREFIX}/alerts/{alert['id']}/review"
    original_snapshot = repos.alert_review_snapshot

    def locked_snapshot(alert_id, *, conn=None, cursor=None):
        assert conn is db.connect()
        assert conn.in_transaction
        return original_snapshot(alert_id, conn=conn, cursor=cursor)

    monkeypatch.setattr(repos, "alert_review_snapshot", locked_snapshot)
    response = client.post(target, json={"status": "investigating", "note": "Checking"})
    assert response.status_code == 200
    assert response.get_json()["review_status"] == "investigating"
    assert response.get_json()["history"][-1]["note"] == "Checking"


def test_review_history_pages_reach_oldest_decision(client):
    alert = _alert(client)
    target = f"{API_PREFIX}/alerts/{alert['id']}/review"
    with db.write() as conn:
        conn.executemany(
            """INSERT INTO alert_review_events
               (alert_id, ts_ms, from_status, to_status, note, actor)
               VALUES (?, ?, 'closed', 'new', ?, 'owner')""",
            [(alert["id"], n, f"prior-{n}") for n in range(121)],
        )
    first = client.get(target).get_json()
    assert first["has_more"] is True
    assert first["next_cursor"] == first["history"][0]["id"]
    second = client.get(f"{target}?cursor={first['next_cursor']}").get_json()
    assert second["has_more"] is False
    assert second["next_cursor"] is None
    assert [row["note"] for row in second["history"]] == [f"prior-{n}" for n in range(21)]
    assert set(row["id"] for row in first["history"]).isdisjoint(
        row["id"] for row in second["history"]
    )
    assert client.get(f"{target}?cursor=bad").status_code == 400


def test_review_history_response_is_bounded_but_database_remains_append_only(client):
    alert = _alert(client)
    target = f"{API_PREFIX}/alerts/{alert['id']}/review"
    with db.write() as conn:
        conn.executemany(
            """INSERT INTO alert_review_events
               (alert_id, ts_ms, from_status, to_status, note, actor)
               VALUES (?, ?, 'closed', 'new', ?, 'owner')""",
            [(alert["id"], n, f"prior-{n}") for n in range(120)],
        )

    response = client.post(target, json={"status": "investigating", "note": "Latest"})
    assert response.status_code == 200
    history = response.get_json()["history"]
    assert len(history) == 100
    assert history[0]["note"] == "prior-21"
    assert history[-1]["note"] == "Latest"
    assert len(client.get(target).get_json()["history"]) == 100
    assert (
        db.connect()
        .execute("SELECT count(*) FROM alert_review_events WHERE alert_id = ?", (alert["id"],))
        .fetchone()[0]
        == 121
    )


def test_public_reader_cannot_change_review_state(isolated_config):
    config.replace(host="0.0.0.0", trusted_hosts=("watchtower.example",))
    app = create_app(start_sources=False)
    with app.test_client() as public:
        response = public.post(
            f"{API_PREFIX}/alerts/1/review",
            base_url="https://watchtower.example",
            json={"status": "investigating", "note": "attempt"},
        )
        assert response.status_code == 403


def test_v2_database_migrates_existing_alert_to_new_review_state(isolated_config):
    path = isolated_config.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as legacy:
        legacy.executescript((Path(__file__).parent / "fixtures" / "schema_v2.sql").read_text())
        legacy.execute("INSERT INTO schema_meta VALUES ('schema_version', '2')")
        legacy.execute(
            """INSERT INTO events
               (id, ts_ms, ingested_ts_ms, source, event, event_type, severity,
                ip, user, message, log_format, origin, rep_verdict, rep_score,
                rep_sources, rep_checked, rep_detail)
               VALUES (9, 1, 1, 'synthetic', 'brute_force', 'authentication', 'critical',
                       '192.0.2.1', 'owner', 'legacy event', 'cef', 'synthetic',
                       'unknown', 0, '[]', 0, '')"""
        )
        legacy.execute(
            """INSERT INTO alerts
               (id, event_id, ts_ms, event, source, ip, user, severity, anomaly_score,
                ruleset_version, explanation, features_json, reasons_json,
                reputation_json, status)
               VALUES (7, 9, 1, 'brute_force', 'synthetic', '192.0.2.1', 'owner',
                       'critical', 0.8, 'rules-old', 'fixture', '{}', '[]', '{}', 'contained')"""
        )
    db.configure(path)
    conn = db.connect()
    row = conn.execute("SELECT status, review_status FROM alerts WHERE id = 7").fetchone()
    assert (row["status"], row["review_status"]) == ("contained", "new")
    assert (
        conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]
        == "4"
    )
    assert repos.alert_review_history(7) == []
    verdict = repos.recent_events()[0]["shadow_verdict"]
    assert verdict["status"] == "unavailable"
    assert verdict["reason"] == "predates_shadow_schema"
    assert repos.recent_alerts()[0]["shadow_verdict"] == verdict
