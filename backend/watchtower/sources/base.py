"""What a log source is.

A source produces raw event dicts and hands each one to a callback. It does not
know about detection, storage or the ledger — everything a source emits goes
through the same ``pipeline.consumer.process_log``, which is what makes a
replayed 2008 HDFS line and a live syslog datagram behave identically
downstream.

The one hard requirement is ``origin``. It is not defaulted anywhere in the
pipeline: a source that forgets it raises rather than having its traffic
silently labelled synthetic.
"""

import threading
from typing import Protocol


class Source(Protocol):
    """A named producer of raw events."""

    name: str
    origin: str

    def run(self, emit) -> None:
        """Produce events, calling ``emit(raw_log)`` for each. Blocks."""

    def stop(self) -> None:
        """Ask the source to return from ``run`` at the next opportunity."""


class ThreadedSource:
    """Base class: a source that runs on its own daemon thread.

    Daemon threads, so a Ctrl-C on the API process is not held open by a tailer
    blocked on a file that will never grow.
    """

    name = "unnamed"
    origin = "synthetic"

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, emit) -> threading.Thread:
        if self._thread is not None:
            return self._thread
        self._thread = threading.Thread(
            target=self._guarded_run, args=(emit,), name=f"source-{self.name}", daemon=True
        )
        self._thread.start()
        return self._thread

    def _guarded_run(self, emit) -> None:
        try:
            self.run(emit)
        except Exception as exc:
            # A source that dies must say so. The old generator loop swallowed
            # everything, so a persistent failure looked exactly like a quiet
            # network.
            print(f"⚠️  source {self.name} stopped: {type(exc).__name__}: {exc}")

    def run(self, emit) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def stop(self) -> None:
        self._stop.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())
