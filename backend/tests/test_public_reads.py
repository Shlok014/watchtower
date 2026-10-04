"""A public demo may expose synthetic records, never real-origin log contents."""

from datetime import UTC, datetime

from watchtower import config
from watchtower.app import API_PREFIX, create_app
from watchtower.pipeline.consumer import process_log

BASE = "https://watchtower.example"
TOKEN = "owner-only-secret-token-with-at-least-32-characters"


def _app(*, sources=("synthetic",)):
    config.replace(
        host="0.0.0.0",
        trusted_hosts=("watchtower.example", "localhost", "127.0.0.1"),
        sources=sources,
        write_token=TOKEN,
    )
    return create_app(start_sources=False)


def test_public_synthetic_only_reads_remain_available():
    app = _app()
    process_log(
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "demo",
            "event": "normal_traffic",
            "ip": "192.0.2.17",
            "user": "demo",
            "message": "synthetic example",
            "origin": "synthetic",
        }
    )
    with app.test_client() as client:
        assert client.get(f"{API_PREFIX}/logs", base_url=BASE).status_code == 200
        assert client.get(f"{API_PREFIX}/access", base_url=BASE).get_json()["can_read"]


def test_public_real_source_requires_owner_token_for_reads():
    app = _app(sources=("synthetic", "syslog"))
    with app.test_client() as client:
        for path in (
            "/logs",
            "/alerts",
            "/stats",
            "/config",
            "/system-health",
            "/model",
            "/blocklist",
            "/blockchain",
            "/soar-actions",
        ):
            denied = client.get(f"{API_PREFIX}{path}", base_url=BASE)
            assert denied.status_code == 403
            assert denied.get_json()["error"] == "read_forbidden"
            assert (
                client.get(
                    f"{API_PREFIX}{path}",
                    base_url=BASE,
                    headers={"Authorization": "Bearer wrong"},
                ).status_code
                == 403
            )
            assert (
                client.get(
                    f"{API_PREFIX}{path}",
                    base_url=BASE,
                    headers={"Authorization": f"Bearer {TOKEN}"},
                ).status_code
                == 200
            )
        assert not client.get(f"{API_PREFIX}/access", base_url=BASE).get_json()["can_read"]
        # A public server may sit behind a local proxy that rewrites Host.
        assert client.get(f"{API_PREFIX}/logs", base_url="http://localhost").status_code == 403
        assert client.post(f"{API_PREFIX}/blockchain/validate", base_url=BASE).status_code == 403


def test_persisted_real_event_closes_public_reads_even_if_config_returns_to_synthetic():
    app = _app()
    process_log(
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "ssh-host",
            "event": "log_info",
            "ip": "203.0.113.72",
            "user": "someone",
            "message": "private log text",
            "origin": "replay:openssh",
        }
    )
    with app.test_client() as client:
        assert client.get(f"{API_PREFIX}/logs", base_url=BASE).status_code == 403
        assert (
            client.get(
                f"{API_PREFIX}/logs", base_url=BASE, headers={"Authorization": f"Bearer {TOKEN}"}
            ).status_code
            == 200
        )


def test_loopback_only_server_can_read_real_source_locally():
    config.replace(
        sources=("syslog",),
        host="127.0.0.1",
        trusted_hosts=("localhost", "127.0.0.1"),
        write_token=None,
    )
    app = create_app(start_sources=False)
    with app.test_client() as client:
        assert client.get(f"{API_PREFIX}/logs", base_url="http://localhost").status_code == 200
        assert (
            client.get(
                f"{API_PREFIX}/logs",
                base_url="http://localhost",
                environ_overrides={"REMOTE_ADDR": "203.0.113.8"},
            ).status_code
            == 403
        )
