"""Owner-only write boundary for the HTTP API.

Without a configured token, local development writes require explicit opt-in
and the server, Host header and connecting peer must all be loopback. A public
host is read-only by default. A long owner token enables writes over a public host;
it belongs in the server environment and in non-browser clients, not the UI.
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
            separator and scheme.lower() == "bearer" and supplied
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
