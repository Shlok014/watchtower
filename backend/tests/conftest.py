"""Shared fixtures.

The one rule these enforce: **no test may touch the developer's real data
directory.** Every path the app uses is derived from ``config``, so redirecting
``data_dir`` at a tmp_path is enough to isolate the database, the feed cache,
the drain state and anything written by a playbook. Before config existed, each
module computed its own path from ``__file__`` and a test that forgot one would
happily write into ``backend/data`` and still pass.
"""

import pytest

from watchtower import config
from watchtower.store import db


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Point every configured path at a per-test tmp dir."""
    monkeypatch.delenv("WATCHTOWER_DB", raising=False)
    monkeypatch.delenv("WATCHTOWER_DATA_DIR", raising=False)
    monkeypatch.delenv("WATCHTOWER_WRITE_TOKEN", raising=False)
    monkeypatch.delenv("WATCHTOWER_ALLOW_LOCAL_WRITES", raising=False)
    cfg = config.from_env()
    config.set_config(cfg)
    # Existing write-path tests exercise the explicit local development mode.
    config.replace(data_dir=tmp_path / "data", allow_local_writes=True)
    db.configure(None)
    yield config.get()
    db.close_all()
    config.set_config(config.from_env())
