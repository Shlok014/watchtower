"""A real syslog listener.

Stdlib ``socketserver`` over UDP. Two things here are worth knowing before you
demo it, and both are the kind of detail that separates a listener that works
from one that works on the presenter's laptop:

**Port 5514, not 514.** Ports below 1024 need root on macOS and Linux alike, and
a security tool that asks for root to accept a datagram has made a bad trade.

The one-line demo differs by platform, which is worth knowing before you type it
in front of someone. ``logger -n host -P port`` is util-linux and **is not
supported by the BSD ``logger`` macOS ships** — it exits with "illegal option
-- n". Portable version:

    printf '<34>Aug  4 21:00:10 fw sshd[99]: Failed password for root from 198.51.100.4\\n' \\
      | nc -u -w1 127.0.0.1 5514

The UDP peer is stored separately. Only an explicitly configured loopback peer
may forward a strictly parsed sshd actor into correlation. UDP alone cannot
authenticate remote senders.

Both RFC 3164 (BSD, the ``logger`` default) and RFC 5424 are parsed. A datagram
that matches neither is still ingested, with its whole body as the message and
a ``log_format`` that says ``raw`` — dropping it would mean a misconfigured
sender produces silence, which looks exactly like a working listener.
"""

import ipaddress
import re
import socketserver
import threading
from datetime import UTC, datetime

from .. import config
from ..pipeline.normalize import SYSLOG_SEVERITY
from . import sshd
from .base import ThreadedSource

DEFAULT_PORT = 5514
DEFAULT_HOST = "127.0.0.1"

# <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)

# <PRI>MMM DD HH:MM:SS HOSTNAME TAG: MSG
RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)

TAG = re.compile(r"^(?P<tag>[^\s:\[]{1,32})(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$", re.DOTALL)

MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}

FACILITIES = (
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
)  # fmt: skip


def decode_pri(pri: int) -> tuple[str, int]:
    """PRI → (facility name, severity 0-7). PRI = facility * 8 + severity."""
    facility, severity = divmod(pri, 8)
    name = FACILITIES[facility] if facility < len(FACILITIES) else f"facility{facility}"
    return name, severity


def _bsd_timestamp(month: str, day: str, hhmmss: str) -> str:
    """RFC 3164 carries no year. Assume the current one, and say so.

    A December message received on 1 January would be stamped a year late by
    this rule. That is a real limitation of the format, not of the parser — it
    is why RFC 5424 exists — and guessing a rollover would be worse.
    """
    now = datetime.now(UTC)
    hh, mm, ss = (int(x) for x in hhmmss.split(":"))
    try:
        return datetime(now.year, MONTHS[month], int(day), hh, mm, ss, tzinfo=UTC).isoformat()
    except (KeyError, ValueError):
        return now.isoformat()


def _attributed(
    raw: dict, peer_ip: str, tag: str, body: str, trusted_peers: tuple[str, ...]
) -> dict:
    raw["transport_peer_ip"] = peer_ip
    try:
        local_peer = ipaddress.ip_address(peer_ip).is_loopback
    except ValueError:
        local_peer = False
    if local_peer and peer_ip in trusted_peers:
        auth = sshd.parse(tag, body)
        if auth is not None:
            raw["event"], raw["ip"], raw["user"] = auth
    return raw


def parse_syslog(payload: str, peer_ip: str, *, trusted_peers: tuple[str, ...] = ()) -> dict:
    """One datagram → a raw event. Never returns None; see the module docstring."""
    payload = payload.strip()

    m = RFC5424.match(payload)
    if m:
        g = m.groupdict()
        facility, severity = decode_pri(int(g["pri"]))
        try:
            ts = datetime.fromisoformat(g["ts"].replace("Z", "+00:00")).isoformat()
        except ValueError:
            ts = datetime.now(UTC).isoformat()
        # STRUCTURED-DATA is either "-" or one or more [id k="v"] elements. It is
        # kept in the message rather than parsed into fields: nothing downstream
        # reads it, and a half-parsed SD element is worse than an unparsed one.
        rest = g["rest"]
        app = g["app"] if g["app"] != "-" else facility
        raw = {
            "timestamp": ts,
            "source": g["host"] if g["host"] != "-" else peer_ip,
            "event": SYSLOG_SEVERITY[severity],
            "ip": peer_ip,
            "user": "unknown",
            "message": f"{app}: {rest}" if rest else app,
            "log_format": "rfc5424",
            "origin": "syslog",
        }
        # Only the NILVALUE structured-data form permits exact message parsing.
        body = rest[2:] if rest.startswith("- ") else ""
        return _attributed(raw, peer_ip, app, body, trusted_peers)

    m = RFC3164.match(payload)
    if m:
        g = m.groupdict()
        facility, severity = decode_pri(int(g["pri"]))
        rest = g["rest"]
        tag_m = TAG.match(rest)
        message = rest
        tag = ""
        body = ""
        if tag_m:
            tag, pid, msg = tag_m.group("tag"), tag_m.group("pid"), tag_m.group("msg")
            message = f"{tag}[{pid}]: {msg}" if pid else f"{tag}: {msg}"
            body = msg
        raw = {
            "timestamp": _bsd_timestamp(g["month"], g["day"], g["time"]),
            "source": g["host"],
            "event": SYSLOG_SEVERITY[severity],
            "ip": peer_ip,
            "user": "unknown",
            "message": message,
            "log_format": "rfc3164",
            "origin": "syslog",
        }
        return _attributed(raw, peer_ip, tag, body, trusted_peers)

    # Neither RFC matched. Ingested anyway, honestly labelled.
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": peer_ip,
        "event": "log_info",
        "ip": peer_ip,
        "transport_peer_ip": peer_ip,
        "user": "unknown",
        "message": payload,
        "log_format": "raw",
        "origin": "syslog",
    }


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        try:
            payload = data.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - decode with errors= cannot raise
            return
        if not payload.strip():
            return
        raw = parse_syslog(
            payload,
            self.client_address[0],
            trusted_peers=config.get().trusted_syslog_peers,
        )
        self.server.watchtower_source.on_datagram(raw)


class _Server(socketserver.ThreadingUDPServer):
    # Without this, restarting the process inside the TIME_WAIT window fails
    # with "Address already in use" — which reads as "something else has the
    # port" and sends you hunting for a process that does not exist.
    allow_reuse_address = True
    daemon_threads = True


class SyslogSource(ThreadedSource):
    """UDP syslog listener. Binds loopback by default."""

    origin = "syslog"

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        super().__init__()
        self.name = f"syslog:{port}"
        self.host = host
        self.port = port
        self.received = 0
        self._server: _Server | None = None
        self._emit = None
        self._ready = threading.Event()

    def on_datagram(self, raw: dict) -> None:
        self.received += 1
        try:
            if self._emit is not None:
                self._emit(raw)
        except Exception as exc:
            print(f"⚠️  syslog pipeline error: {type(exc).__name__}: {exc}")

    def run(self, emit) -> None:
        self._emit = emit
        with _Server((self.host, self.port), _Handler) as server:
            server.watchtower_source = self
            self._server = server
            self._ready.set()
            print(f"📡 syslog listening on udp://{self.host}:{self.port}")
            # poll_interval, not serve_forever's default 0.5s block: stop() has
            # to be observed within a shutdown, and shutdown() from another
            # thread is what actually breaks the loop.
            server.serve_forever(poll_interval=0.25)
        self._server = None

    def wait_ready(self, timeout: float = 2.0) -> bool:
        return self._ready.wait(timeout)

    def bound_port(self) -> int | None:
        """The port actually bound — differs from ``port`` when 0 was requested."""
        return self._server.server_address[1] if self._server else None

    def stop(self) -> None:
        super().stop()
        server = self._server
        if server is not None:
            threading.Thread(target=server.shutdown, daemon=True).start()

    def stats(self) -> dict:
        return {
            "host": self.host,
            "port": self.bound_port() or self.port,
            "received": self.received,
        }
