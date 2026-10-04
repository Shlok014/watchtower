"""HTTP access boundaries for public demos and owner operations.

Without a configured token, local development writes require explicit opt-in
and the server, Host header and connecting peer must all be loopback. A public
host is read-only by default. Anonymous public reads are allowed only for a
synthetic-only configuration with no real-origin records. A long owner token
enables private reads and writes over a public host; it belongs in the server
environment and in non-browser clients, not the UI.
"""

import hmac
import ipaddress
from urllib.parse import urlsplit

from flask import Request

from .config import Config

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def can_write(cfg: Config, request: Request) -> bool:
    if cfg.write_token:
        scheme, separator, supplied = request.headers.get("Authorization", "").partition(" ")
        return bool(
            separator
            and scheme.lower() == "bearer"
            and supplied
            and hmac.compare_digest(supplied.encode(), cfg.write_token.encode())
        )

    if not cfg.allow_local_writes:
        return False
    host = urlsplit(request.host_url).hostname
    if cfg.host not in _LOCAL_HOSTS or not host or host not in _LOCAL_HOSTS:
        return False
    if not cfg.trusted_hosts or any(name not in _LOCAL_HOSTS for name in cfg.trusted_hosts):
        return False
    try:
        return ipaddress.ip_address(request.remote_addr or "").is_loopback
    except ValueError:
        return False


def can_read(cfg: Config, request: Request, has_real_events: bool) -> bool:
    """Expose a public dashboard only when its source and stored data are synthetic."""
    if can_write(cfg, request):
        return True
    host = urlsplit(request.host_url).hostname
    if (
        cfg.host in _LOCAL_HOSTS
        and host in _LOCAL_HOSTS
        and cfg.trusted_hosts
        and all(name in _LOCAL_HOSTS for name in cfg.trusted_hosts)
    ):
        try:
            if ipaddress.ip_address(request.remote_addr or "").is_loopback:
                return True
        except ValueError:
            pass
    return not has_real_events and all(source == "synthetic" for source in cfg.sources)
