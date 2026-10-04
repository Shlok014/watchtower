"""Every tunable in one place, read from the environment exactly once.

Before this module the settings were scattered as module constants across
``app.py``, ``store/db.py``, ``store/repos.py``, ``threatintel/store.py`` and
``detection/parser.py``, each deriving its own paths from ``__file__``. Two
consequences, both real: moving a file changed where the database lived, and
there was no single place to look up what the process would do before starting
it.

Paths are anchored to ``BASE_DIR`` — the ``backend/`` directory — rather than to
each module's own location, so the package can be rearranged without moving the
data that a running install has already written.
"""

import dataclasses
import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

# backend/, the parent of this package. Everything on disk hangs off it.
BASE_DIR = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


def _env_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Config:
    """Resolved configuration. Frozen: nothing rebinds these at runtime."""

    data_dir: Path
    db_path: Path
    retention_hours: int
    cors_origins: tuple[str, ...]
    trusted_hosts: tuple[str, ...]
    host: str
    port: int
    alert_threshold: float
    sources: tuple[str, ...]
    trusted_syslog_peers: tuple[str, ...] = ()
    allow_local_writes: bool = False
    write_token: str | None = field(default=None, repr=False)

    # Derived directories. Declared here so no other module has to know the
    # layout of data/.
    feeds_dir: Path = field(init=False)
    datasets_dir: Path = field(init=False)
    drain_dir: Path = field(init=False)
    models_dir: Path = field(init=False)
    incidents_dir: Path = field(init=False)
    samples_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        if self.write_token is not None and len(self.write_token) < 32:
            raise ValueError("WATCHTOWER_WRITE_TOKEN must contain at least 32 characters")
        for peer in self.trusted_syslog_peers:
            try:
                address = ipaddress.ip_address(peer)
            except ValueError:
                raise ValueError("WATCHTOWER_TRUSTED_SYSLOG_PEERS requires literal IPs") from None
            if str(address) != peer or getattr(address, "ipv4_mapped", None):
                raise ValueError("WATCHTOWER_TRUSTED_SYSLOG_PEERS requires canonical IPs")
            if not address.is_loopback:
                raise ValueError("WATCHTOWER_TRUSTED_SYSLOG_PEERS accepts loopback peers only")
        object.__setattr__(self, "feeds_dir", self.data_dir / "feeds")
        object.__setattr__(self, "datasets_dir", self.data_dir / "datasets")
        object.__setattr__(self, "drain_dir", self.data_dir / "drain")
        object.__setattr__(self, "models_dir", self.data_dir / "models")
        object.__setattr__(self, "incidents_dir", self.data_dir / "incidents")
        # The committed loghub 2k samples. Pinned to BASE_DIR rather than
        # data_dir: a test that redirects data_dir at a tmpdir still needs to
        # read them, and they are source, not runtime state.
        object.__setattr__(self, "samples_dir", BASE_DIR / "data" / "samples")


def from_env() -> Config:
    data_dir = Path(os.environ.get("WATCHTOWER_DATA_DIR") or (BASE_DIR / "data"))
    db_path = Path(os.environ.get("WATCHTOWER_DB") or (data_dir / "watchtower.db"))
    return Config(
        data_dir=data_dir,
        db_path=db_path,
        retention_hours=_env_int("WATCHTOWER_RETENTION_HOURS", 24),
        # CORS restricts response access; the app factory separately rejects
        # cross-site writes, because a form POST can mutate without reading a
        # response. Keep both spellings used by the local Vite frontend.
        cors_origins=_env_list(
            "WATCHTOWER_CORS_ORIGINS",
            ("http://localhost:5173", "http://127.0.0.1:5173"),
        ),
        # Also guards DNS rebinding: a page on an attacker-controlled hostname
        # must not be able to treat the loopback API as its own origin.
        trusted_hosts=_env_list("WATCHTOWER_TRUSTED_HOSTS", ("localhost", "127.0.0.1")),
        # Loopback by default. The previous host was 0.0.0.0, which published an
        # unauthenticated API with a destructive endpoint to every machine on
        # the network the moment the demo was run on café wifi.
        host=os.environ.get("WATCHTOWER_HOST", "127.0.0.1"),
        port=_env_int("WATCHTOWER_PORT", 5001),
        alert_threshold=_env_float("WATCHTOWER_ALERT_THRESHOLD", 0.45),
        sources=_env_list("WATCHTOWER_SOURCES", ("synthetic",)),
        trusted_syslog_peers=_env_list("WATCHTOWER_TRUSTED_SYSLOG_PEERS", ()),
        allow_local_writes=os.environ.get("WATCHTOWER_ALLOW_LOCAL_WRITES") == "1",
        write_token=os.environ.get("WATCHTOWER_WRITE_TOKEN") or None,
    )


_config: Config | None = None


def get() -> Config:
    """The process-wide configuration, resolved on first use."""
    global _config
    if _config is None:
        _config = from_env()
    return _config


def set_config(cfg: Config) -> None:
    """Override the configuration. For tests and the CLI's --db flag."""
    global _config
    _config = cfg


def replace(**changes) -> Config:
    """Set a modified copy of the current config, and return it.

    ``data_dir`` drags ``db_path`` with it unless the caller pins both. Without
    that, a test that redirects data_dir at a tmpdir would still write its
    database into the developer's real ``backend/data`` — and pass, while
    corrupting the store it was supposed to leave alone.
    """
    cur = get()
    if "data_dir" in changes and "db_path" not in changes:
        changes["db_path"] = Path(changes["data_dir"]) / "watchtower.db"
    cfg = dataclasses.replace(cur, **changes)
    set_config(cfg)
    return cfg
