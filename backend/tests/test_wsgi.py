"""The alwaysdata entrypoint must stay safe and use durable local storage."""

import json
import os
import subprocess
import sys
from pathlib import Path


def test_wsgi_entrypoint_is_public_on_demand_and_persists_between_processes(tmp_path):
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.update(
        WATCHTOWER_DATA_DIR=str(tmp_path / "persistent"),
        WATCHTOWER_PUBLIC_DEMO="0",
        WATCHTOWER_SOURCES="syslog",
    )
    env.pop("WATCHTOWER_DB", None)

    def run(code):
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(result.stdout.splitlines()[-1])

    first = run(
        "import json, wsgi; c=wsgi.application.test_client(); "
        "a=c.post('/api/v1/simulate-attack', json={'attack_type':'brute_force'}); "
        "print(json.dumps({'attack':a.status_code, "
        "'config':c.get('/api/v1/config').get_json(), "
        "'stats':c.get('/api/v1/stats').get_json()['total_logs'], "
        "'reset':c.post('/api/v1/reset').status_code}))"
    )
    assert first["attack"] == 200
    assert first["config"]["public_demo"] is True
    assert first["config"]["configured_sources"] == []
    assert first["reset"] == 403
    assert first["stats"] > 0

    second = run(
        "import json, wsgi; c=wsgi.application.test_client(); "
        "a=c.post('/api/v1/simulate-attack', json={'attack_type':'mixed'}, "
        "environ_overrides={'REMOTE_ADDR':'198.51.100.240'}); "
        "print(json.dumps({'stats':c.get('/api/v1/stats').get_json()['total_logs'], "
        "'attack':a.status_code}))"
    )
    assert second["stats"] == first["stats"]
    assert second["attack"] == 429
