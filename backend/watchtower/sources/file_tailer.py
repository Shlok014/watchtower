"""``tail -F`` over a real log file on this machine.

Real bytes, from a file that exists whether or not this program is running —
which is the point: it is the only source here whose input nobody in this
repository controls.

The two things that make a tailer correct rather than nearly correct:

**Rotation is detected by inode, not by size.** ``newsyslog`` and ``logrotate``
both rename the file and create a fresh one at the same path. A tailer watching
the path keeps its handle on the renamed file and reads nothing ever again,
while the file it is "tailing" fills up. Size alone is not enough either:
``cp /dev/null file`` truncates in place, keeping the inode, and a size that
went *down* is the only signal. Both are checked.

**Attribution is loopback, and that is a real statement.** A line in
``/var/log/system.log`` did not come from a network peer; it came from this
host. So an address is lifted out of the message when there is one, and
otherwise the event is attributed to ``127.0.0.1``. That has a consequence worth
saying out loud rather than hiding: the 30-second frequency rule counts per
address, so a busy system log will trip it on ``127.0.0.1``. That is the rule
doing exactly what it says, and it is why real deployments scope rate rules by
source type instead of by address alone.
"""

import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path

from .base import ThreadedSource

# Aug  4 21:09:20 hostname process[1234]: message
SYSLOG_FILE_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^\s:\[]{1,64})(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}

# Words a line has to contain before it is called anything but informational.
# Deliberately literal: these are strings the daemons themselves emit.
LEVEL_MARKERS = (
    ("log_error", ("error", "failed", "failure", "denied", "refused", "panic", "fatal")),
    ("log_warning", ("warn", "warning", "unable to", "timeout", "retry")),
)


def _first_ip(text: str) -> str | None:
    for candidate in IPV4.findall(text):
        parts = candidate.split(".")
        if all(p.isdigit() and int(p) <= 255 for p in parts):
            return candidate
    return None


def classify(message: str) -> str:
    lowered = message.lower()
    for event, markers in LEVEL_MARKERS:
        if any(marker in lowered for marker in markers):
            return event
    return "log_info"


def parse_line(line: str, path: str) -> dict | None:
    """One tailed line → a raw event, or None for a blank line."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    m = SYSLOG_FILE_LINE.match(line)
    now = datetime.now(UTC)
    if m:
        g = m.groupdict()
        hh, mm, ss = (int(x) for x in g["time"].split(":"))
        try:
            # No year in the format; the current one, same limitation as BSD
            # syslog over the wire.
            ts = datetime(now.year, MONTHS[g["month"]], int(g["day"]), hh, mm, ss, tzinfo=UTC)
        except (KeyError, ValueError):
            ts = now
        tag, pid, msg = g["tag"], g["pid"], g["msg"]
        message = f"{tag}[{pid}]: {msg}" if pid else f"{tag}: {msg}"
        source = g["host"]
    else:
        ts, message, source = now, line, Path(path).name

    return {
        "timestamp": ts.isoformat(),
        "source": source,
        "event": classify(message),
        # Loopback unless the line names an address. See the module docstring.
        "ip": _first_ip(message) or "127.0.0.1",
        "user": "unknown",
        "message": message,
        "log_format": "syslog",
        "origin": "file",
    }


class FileTailSource(ThreadedSource):
    """Follow a file, surviving truncation and rotation."""

    origin = "file"

    def __init__(
        self,
        path: str,
        from_start: bool = False,
        poll_interval: float = 0.5,
        pending_timeout: float = 2.0,
        max_pending_bytes: int = 1 << 20,
    ):
        super().__init__()
        self.path = str(path)
        self.name = f"file:{self.path}"
        self.from_start = from_start
        self.poll_interval = poll_interval
        # How long an unterminated line may wait for its newline. See run().
        self.pending_timeout = pending_timeout
        self.max_pending_bytes = max_pending_bytes
        self.lines_read = 0
        self.rotations = 0
        self.discarded_partials = 0

    def _open(self):
        # SIM115 (no context manager) is suppressed on purpose here and below.
        # The handle has to outlive the call — it is the tail position — and it
        # is deliberately swapped for a new one when the file rotates. `run`
        # closes it in a finally.
        fh = open(self.path, encoding="utf-8", errors="replace")  # noqa: SIM115
        st = os.fstat(fh.fileno())
        if not self.from_start:
            fh.seek(0, os.SEEK_END)
        return fh, (st.st_dev, st.st_ino)

    def _rotated(self, ident, fh) -> bool:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            # Rotated away and not yet recreated. Not an error; wait for it.
            return False
        if (st.st_dev, st.st_ino) != ident:
            return True
        # Same inode, smaller than where we are: truncated in place.
        return st.st_size < fh.tell()

    def run(self, emit) -> None:
        if not Path(self.path).exists():
            raise FileNotFoundError(f"cannot tail {self.path}: no such file")

        fh, ident = self._open()

        # An unterminated line waits here for its newline — `readline()` returns
        # whatever bytes exist at EOF, and emitting half a line as a finished
        # event splits one record into two, the first with whatever address was
        # in its first half.
        #
        # But holding it indefinitely is worse than the problem it solves.
        # `copytruncate` (and `cp /dev/null file`) truncates in place; if the
        # writer refills past the old offset before the next poll, the size
        # check cannot see it, and `pending += chunk` glues the head of the old
        # file's last line onto the tail of the new file's first line. The
        # result is a single well-formed record whose text never existed in any
        # file — attributed, severity-classified from words that came from the
        # other file, and chained into the ledger as fact. That is strictly
        # worse than two obviously-broken fragments.
        #
        # So a partial line is held for at most `pending_timeout`, and dropped
        # with a warning if it does not complete. Losing a fragment is a known,
        # counted loss. Fabricating a convincing record is not.
        pending = ""
        pending_since = 0.0
        try:
            while not self.stopping:
                # Checked every iteration, not only at EOF: the sooner a
                # truncation is seen, the smaller the window in which bytes
                # could be spliced onto a held fragment.
                if self._rotated(ident, fh):
                    self.rotations += 1
                    pending = self._drop_pending(pending, "the file rotated or was truncated")
                    fh.close()
                    for _ in range(20):
                        if Path(self.path).exists():
                            break
                        time.sleep(0.1)
                    fh = open(self.path, encoding="utf-8", errors="replace")  # noqa: SIM115
                    st = os.fstat(fh.fileno())
                    ident = (st.st_dev, st.st_ino)
                    print(f"🔄 {self.path} rotated — reopened")
                    continue

                chunk = fh.readline()
                if chunk:
                    if not pending:
                        pending_since = time.monotonic()
                    pending += chunk
                    if len(pending) > self.max_pending_bytes:
                        # A writer emitting megabytes without a newline is not
                        # producing log lines, and buffering it is a leak.
                        pending = self._drop_pending(
                            pending, f"it passed {self.max_pending_bytes} bytes with no newline"
                        )
                        continue
                    if not pending.endswith("\n"):
                        continue
                    line, pending = pending, ""
                    self.lines_read += 1
                    raw = parse_line(line, self.path)
                    if raw is not None:
                        try:
                            emit(raw)
                        except Exception as exc:
                            print(f"⚠️  file tail pipeline error: {type(exc).__name__}: {exc}")
                    continue

                if pending and (time.monotonic() - pending_since) > self.pending_timeout:
                    pending = self._drop_pending(
                        pending, f"no newline arrived within {self.pending_timeout}s"
                    )

                time.sleep(self.poll_interval)
        finally:
            fh.close()

    def _drop_pending(self, pending: str, why: str) -> str:
        """Discard a held fragment, loudly and countably."""
        if pending:
            self.discarded_partials += 1
            print(f"⚠️  {self.path}: discarding {len(pending)} bytes of an incomplete line — {why}")
        return ""

    def stats(self) -> dict:
        return {
            "path": self.path,
            "lines_read": self.lines_read,
            "rotations": self.rotations,
            "discarded_partials": self.discarded_partials,
        }
