"""The HTTP surface.

These exist because the response shape is a contract the dashboard depends on,
and every field the frontend reads is optional-chained — a renamed key does not
throw, it renders an empty cell. Nothing in the UI would report the failure.
"""

import pytest

from watchtower.app import API_PREFIX, create_app


@pytest.fixture()
def client():
    # start_sources=False: the generator thread would race every assertion
    # below, and a test whose expected counts depend on how fast the machine is
    # is not a test.
    app = create_app(start_sources=False)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def _url(path: str) -> str:
    return f"{API_PREFIX}{path}"


def test_stats_is_served_under_the_versioned_prefix(client):
    assert client.get(_url("/stats")).status_code == 200
    # The unversioned path is gone, deliberately. Leaving it as an alias means
    # two contracts to keep in step, and the older one silently wins whenever
    # someone forgets.
    assert client.get("/api/stats").status_code == 404


def test_unversioned_404_is_json_not_html(client):
    """A dashboard that parses HTML as JSON reports 'no data', not 'wrong URL'."""
    r = client.get("/api/stats")
    assert r.is_json
    assert r.get_json()["error"] == "not_found"


def test_limit_must_be_an_integer(client):
    """`?limit=abc` used to raise ValueError inside the handler and return 500."""
    r = client.get(_url("/logs?limit=abc"))
    assert r.status_code == 400
    assert r.is_json
    assert "limit" in r.get_json()["detail"]


def test_limit_is_clamped_not_rejected(client):
    """A caller asking for a million rows gets the cap, not an error."""
    assert client.get(_url("/logs?limit=999999")).status_code == 200
    assert client.get(_url("/logs?limit=-5")).status_code == 200


def test_stats_reports_lifetime_totals_and_retained_separately(client):
    body = client.get(_url("/stats")).get_json()
    for key in ("total_logs", "logs_retained", "retention_note", "ruleset_version"):
        assert key in body, f"/stats lost {key}, which the dashboard renders"
    assert "SQLite" in body["retention_note"]


def test_health_reports_no_source_when_none_is_running(client):
    """The badge used to be the string literal 'All Systems Operational'."""
    body = client.get(_url("/system-health")).get_json()
    assert body["summary"]["state"] == "down"
    assert body["sources"] == []


def test_retrain_refuses_rather_than_inventing_a_number(client):
    r = client.post(_url("/retrain"))
    assert r.status_code == 501
    body = r.get_json()
    assert body["status"] == "not_implemented"
    # The specific regression: it used to return a rising accuracy.
    assert "accuracy" not in body
    assert "improvement" not in body


def test_config_endpoint_reports_the_live_configuration(client):
    body = client.get(_url("/config")).get_json()
    assert body["retention_hours"] == 24
    assert body["configured_sources"] == ["synthetic"]
    assert body["running_sources"] == []


def test_cors_is_not_wide_open(client):
    """`CORS(app)` allowed any origin to POST /reset."""
    r = client.get(_url("/stats"), headers={"Origin": "https://evil.example"})
    assert r.headers.get("Access-Control-Allow-Origin") != "https://evil.example"
    ok = client.get(_url("/stats"), headers={"Origin": "http://localhost:5173"})
    assert ok.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"


def test_simulate_attack_then_reset_reports_real_counts(client):
    client.post(_url("/simulate-attack"), json={"attack_type": "brute_force"})
    after = client.get(_url("/stats")).get_json()
    assert after["total_logs"] > 0

    body = client.post(_url("/reset")).get_json()
    # /reset used to clear four Python lists and claim "All data cleared"
    # regardless of what was actually removed.
    assert body["deleted"]["events"] == after["logs_retained"]
    assert client.get(_url("/stats")).get_json()["logs_retained"] == 0
