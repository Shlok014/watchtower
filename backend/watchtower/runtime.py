"""Which sources are running, and how they were started.

Kept out of the Flask app so that the CLI, the tests and a WSGI server all get
the same answer to "is anything actually producing events?" — the question the
health endpoint exists to answer, and the one the old dashboard answered with a
hardcoded "All Systems Operational".
"""

import threading

from . import config
from .pipeline.consumer import housekeeping, process_log
from .sources import synthetic

_lock = threading.Lock()
_sources: dict[str, object] = {}


class UnknownSource(ValueError):
    pass


def build(spec: str):
    """Turn one ``--sources`` token into a source instance.

    Tokens are ``synthetic``, ``syslog``, ``file:<path>`` or ``replay:<name>``.
    Only ``synthetic`` exists so far; the rest raise by name rather than being
    silently ignored, because a source that was requested and quietly did not
    start is indistinguishable from a source that started and saw nothing.
    """
    if spec == "synthetic":
        return synthetic.SyntheticSource(on_tick=housekeeping)
    raise UnknownSource(
        f"unknown source {spec!r} — known sources: synthetic "
        "(syslog, file:<path> and replay:<name> are not implemented yet)"
    )


def start(specs: tuple[str, ...] | None = None) -> list[str]:
    """Start each configured source. Returns the names actually started."""
    specs = specs if specs is not None else config.get().sources
    started = []
    with _lock:
        for spec in specs:
            if spec in _sources:
                continue
            source = build(spec)
            source.start(process_log)
            _sources[spec] = source
            started.append(spec)
    return started


def stop_all() -> None:
    with _lock:
        for source in _sources.values():
            source.stop()
        _sources.clear()


def running() -> dict:
    with _lock:
        return dict(_sources)


def any_alive() -> bool:
    return any(s.alive() for s in running().values())


def status() -> list[dict]:
    return [
        {"name": spec, "origin": getattr(s, "origin", spec), "alive": s.alive()}
        for spec, s in running().items()
    ]
