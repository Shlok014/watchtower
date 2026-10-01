"""The public host is disposable and does not expose operational controls."""

import pytest

from watchtower import app as app_module
from watchtower import config
from watchtower.app import create_app


@pytest.fixture()
def public_client(tmp_path):
    config.replace(
        data_dir=tmp_path,
        sources=("synthetic",),
        public_demo=True,
    )
    app = create_app(start_sources=False)
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_public_mode_refuses_non_synthetic_sources(tmp_path):
    config.replace(data_dir=tmp_path, sources=("syslog",), public_demo=True)
    with pytest.raises(ValueError, match="synthetic"):
        create_app(start_sources=False)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/v1/reset"),
        ("post", "/api/v1/retrain"),
        ("delete", "/api/v1/blocklist/198.51.100.1"),
    ],
)
def test_public_mode_blocks_operational_mutations(public_client, method, path):
    result = getattr(public_client, method)(path)
    assert result.status_code == 403
    assert result.get_json()["error"] == "public_demo_read_only"


def test_public_attack_is_bounded_and_ledger_still_verifies(public_client):
    first = public_client.post("/api/v1/simulate-attack", json={"attack_type": "brute_force"})
    assert first.status_code == 200
    assert 1 <= first.get_json()["events_generated"] <= 30
    second = public_client.post("/api/v1/simulate-attack", json={"attack_type": "brute_force"})
    assert second.status_code == 429
    assert public_client.post("/api/v1/blockchain/validate").get_json()["ok"] is True


def test_public_config_reports_disposable_storage(public_client):
    config_body = public_client.get("/api/v1/config").get_json()
    assert config_body["public_demo"] is True
    stats = public_client.get("/api/v1/stats").get_json()
    assert "disposable" in stats["retention_note"]


def test_public_service_serves_built_dashboard_and_api(monkeypatch, tmp_path, public_client):
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text("<html>Watchtower dashboard</html>")
    (dist / "favicon.svg").write_text("<svg></svg>")
    (assets / "app.js").write_text("console.log('demo')")
    monkeypatch.setattr(app_module, "FRONTEND_DIST", dist)
    assert b"Watchtower dashboard" in public_client.get("/").data
    assert b"console.log" in public_client.get("/assets/app.js").data
    assert public_client.get("/api/v1/stats").is_json
