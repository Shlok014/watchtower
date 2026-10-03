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


def test_retrain_returns_measured_numbers(client):
    """It used to return an accuracy that rose ~1% per press and could never fall.

    The detailed contract lives in test_model.py; this one guards the HTTP
    surface — that the endpoint exists, reports a version, and carries none of
    the fabricated fields it used to.
    """
    r = client.post(_url("/retrain"))
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["status"] == "trained"
    assert body["version"] >= 1
    assert 0.0 <= body["metrics"]["f1"] <= 1.0
    for gone in ("previous_accuracy", "new_accuracy", "improvement", "epochs"):
        assert gone not in body


def test_config_endpoint_reports_the_live_configuration(client):
    body = client.get(_url("/config")).get_json()
    assert body["retention_hours"] == 24
    assert body["configured_sources"] == ["synthetic"]
    assert body["running_sources"] == []


def test_cors_is_not_wide_open(client):
    """CORS controls response visibility; unsafe writes need a separate guard."""
    r = client.get(_url("/stats"), headers={"Origin": "https://evil.example"})
    assert r.headers.get("Access-Control-Allow-Origin") != "https://evil.example"
    ok = client.get(_url("/stats"), headers={"Origin": "http://localhost:5173"})
    assert ok.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"


def test_cross_site_form_post_cannot_reset_data(client):
    """A browser form needs no CORS read permission to submit a destructive POST."""
    client.post(_url("/simulate-attack"), json={"attack_type": "brute_force"})
    before = client.get(_url("/stats")).get_json()["total_logs"]
    response = client.post(
        _url("/reset"),
        data={},
        headers={"Origin": "https://attacker.example"},
    )
    assert response.status_code == 403
    assert client.get(_url("/stats")).get_json()["total_logs"] == before


def test_cross_site_fetch_metadata_is_rejected_even_without_origin(client):
    response = client.post(_url("/reset"), headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403


def test_dns_rebinding_host_is_rejected(client):
    assert client.get(_url("/stats"), base_url="http://attacker.example").status_code == 400


def test_approved_local_frontend_origin_can_write(client):
    response = client.post(
        _url("/simulate-attack"),
        json={"attack_type": "brute_force"},
        headers={"Origin": "http://localhost:5173", "Sec-Fetch-Site": "same-site"},
    )
    assert response.status_code == 200


def test_public_bind_without_token_is_read_only(isolated_config):
    from watchtower import config

    config.replace(host="0.0.0.0", trusted_hosts=("watchtower.example",))
    app = create_app(start_sources=False)
    with app.test_client() as public:
        base = "https://watchtower.example"
        assert public.get(_url("/stats"), base_url=base).status_code == 200
        assert public.get(_url("/access"), base_url=base).get_json()["can_write"] is False
        public_config = public.get(_url("/config"), base_url=base).get_json()
        assert "/" not in public_config["database"]
        public_playbooks = public.get(_url("/playbooks"), base_url=base).get_json()
        assert "/" not in public_playbooks["directory"]
        assert public.post(_url("/simulate-attack"), base_url=base).status_code == 403
        assert (
            public.post(
                _url("/simulate-attack"),
                base_url=base,
                headers={"Origin": base, "Sec-Fetch-Site": "same-origin"},
            ).status_code
            == 403
        )
        assert public.post(_url("/reset"), base_url=base).status_code == 403
        assert public.post(_url("/retrain"), base_url=base).status_code == 403
        assert public.delete(_url("/blocklist/192.0.2.1"), base_url=base).status_code == 403
        assert public.post(_url("/blockchain/validate"), base_url=base).status_code == 200
        assert public.get(_url("/stats"), base_url=base).get_json()["total_logs"] == 0


def test_public_write_requires_configured_bearer_token(isolated_config):
    from watchtower import config

    token = "owner-only-secret-token-with-at-least-32-characters"
    config.replace(host="0.0.0.0", trusted_hosts=("watchtower.example",), write_token=token)
    app = create_app(start_sources=False)
    with app.test_client() as public:
        base = "https://watchtower.example"
        assert public.post(_url("/simulate-attack"), base_url=base).status_code == 403
        assert (
            public.post(
                _url("/simulate-attack"),
                base_url=base,
                headers={"Authorization": "Bearer wrong"},
            ).status_code
            == 403
        )
        headers = {"Authorization": f"Bearer {token}"}
        assert public.get(_url("/access"), base_url=base, headers=headers).get_json()["can_write"]
        assert (
            public.post(
                _url("/simulate-attack"),
                base_url=base,
                headers=headers,
                json={"attack_type": "brute_force"},
            ).status_code
            == 200
        )
        assert (
            public.post(
                _url("/reset"),
                base_url=base,
                headers={**headers, "Origin": "https://attacker.example"},
            ).status_code
            == 403
        )
        config_body = public.get(_url("/config"), base_url=base).get_json()
        assert token not in str(config_body)
        owner_config = public.get(_url("/config"), base_url=base, headers=headers).get_json()
        assert "/" in owner_config["database"]


def test_local_opt_in_reports_write_access(client):
    assert client.get(_url("/access")).get_json()["can_write"] is True
    assert (
        client.post(_url("/reset"), environ_overrides={"REMOTE_ADDR": "203.0.113.10"}).status_code
        == 403
    )


def test_tokenless_default_is_read_only_even_on_loopback(isolated_config):
    from watchtower import config

    config.replace(allow_local_writes=False)
    app = create_app(start_sources=False)
    with app.test_client() as local:
        assert local.get(_url("/access")).get_json()["can_write"] is False
        assert local.post(_url("/reset")).status_code == 403


def test_short_owner_token_is_refused(isolated_config):
    from watchtower import config

    with pytest.raises(ValueError, match="at least 32"):
        config.replace(write_token="too-short")


def test_simulate_attack_then_reset_reports_real_counts(client):
    client.post(_url("/simulate-attack"), json={"attack_type": "brute_force"})
    after = client.get(_url("/stats")).get_json()
    assert after["total_logs"] > 0

    body = client.post(_url("/reset")).get_json()
    # /reset used to clear four Python lists and claim "All data cleared"
    # regardless of what was actually removed.
    assert body["deleted"]["events"] == after["logs_retained"]
    assert client.get(_url("/stats")).get_json()["logs_retained"] == 0


def test_stats_lists_the_sources_actually_seen(client):
    """The filter dropdown is built from this.

    It used to return the synthetic generator's seven hardcoded hostnames, so
    running any real source made every option in the dashboard's source filter
    match nothing, while the sources genuinely in the table were absent from it.
    """
    from datetime import UTC, datetime

    from watchtower.pipeline.consumer import process_log

    process_log(
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "dfs.DataNode",
            "event": "log_info",
            "ip": "10.0.0.1",
            "user": "unknown",
            "message": "replayed",
            "log_format": "hdfs",
            "origin": "replay:hdfs",
        }
    )
    body = client.get(_url("/stats")).get_json()
    assert body["sources"] == ["dfs.DataNode"]
    # The generator's profile list is still available, under a name that says
    # what it is.
    assert "linux-server" in body["synthetic_source_profiles"]


def test_alerts_carry_the_threshold_they_were_judged_against(client):
    """The dashboard printed a hardcoded 0.45 because the API never sent one."""
    client.post(_url("/simulate-attack"), json={"attack_type": "brute_force"})
    alerts = client.get(_url("/alerts")).get_json()
    assert alerts, "the attack raised no alert"
    assert alerts[0]["features"]["threshold"] == 0.45


def test_the_distribution_window_is_published_not_implied(client):
    """The chart is a recent window; the stat card beside it is a lifetime total."""
    body = client.get(_url("/stats")).get_json()
    assert body["distribution_window"] == 200


def test_health_is_degraded_when_a_configured_source_is_not_running(client):
    """`any(alive)` used to make one dead source among several read as healthy."""
    from watchtower import config, runtime

    config.replace(sources=("synthetic", "syslog:5514"))
    try:
        body = client.get(_url("/system-health")).get_json()
        assert body["summary"]["state"] != "ok"
        assert "syslog:5514" in body["sources_not_running"]
    finally:
        runtime.stop_all()
        config.replace(sources=("synthetic",))
