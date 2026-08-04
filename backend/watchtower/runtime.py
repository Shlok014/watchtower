"""Which sources are running, and how they were started.

Kept out of the Flask app so that the CLI, the tests and a WSGI server all get
the same answer to "is anything actually producing events?" — the question the
health endpoint exists to answer, and the one the old dashboard answered with a
hardcoded "All Systems Operational".
"""

import threading

from . import config
from .pipeline.consumer import process_log
from .sources import file_tailer, replay, synthetic, syslog_server

_lock = threading.Lock()
_sources: dict[str, object] = {}

SPEC_HELP = (
    "synthetic | syslog | syslog:<port> | file:<path> | replay:<dataset> "
    "| replay:<dataset>@<events-per-second>"
)


class UnknownSource(ValueError):
    pass


def build(spec: str):
    """Turn one ``--sources`` token into a source instance.

    Unknown tokens raise by name rather than being skipped. A source that was
    requested and quietly did not start is indistinguishable, on the dashboard,
    from a source that started and saw nothing — and "nothing suspicious
    happened" is the most expensive wrong answer this system can give.
    """
    if spec == "synthetic":
        return synthetic.SyntheticSource()

    if spec == "syslog" or spec.startswith("syslog:"):
        port = syslog_server.DEFAULT_PORT
        if ":" in spec:
            _, _, raw = spec.partition(":")
            try:
                port = int(raw)
            except ValueError as exc:
                raise UnknownSource(f"syslog port must be a number, got {raw!r}") from exc
        return syslog_server.SyslogSource(port=port)

    if spec.startswith("file:"):
        path = spec[len("file:") :]
        if not path:
            raise UnknownSource("file: needs a path, e.g. file:/var/log/system.log")
        return file_tailer.FileTailSource(path)

    if spec.startswith("replay:"):
        rest = spec[len("replay:") :]
        dataset, _, speed_raw = rest.partition("@")
        if not dataset:
            raise UnknownSource(f"replay: needs a dataset — known: {', '.join(replay.DATASETS)}")
        speed = 20.0
        if speed_raw:
            try:
                speed = float(speed_raw)
            except ValueError as exc:
                raise UnknownSource(f"replay speed must be a number, got {speed_raw!r}") from exc
        return replay.ReplaySource(dataset=dataset, speed=speed)

    raise UnknownSource(f"unknown source {spec!r} — expected one of: {SPEC_HELP}")


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


def dead() -> list[str]:
    """Configured sources that are not running.

    ``any_alive()`` is an OR, and health used to decide "ok" versus "down" from
    it alone. Start ``--sources synthetic,syslog:5514`` with 5514 already bound
    and the listener thread dies at bind while synthetic keeps going: the badge
    read "All systems operational" over a port that was deaf. This module's own
    docstring calls a source that was requested and quietly did not start the
    most expensive wrong answer the system can give — and then the health
    endpoint gave it.
    """
    return [
        spec
        for spec, s in running().items()
        if not s.alive() and not getattr(s, "completed", False)
    ]


def finished() -> list[str]:
    """Sources that ran to completion. A replay reaching EOF is not a fault."""
    return [
        spec
        for spec, s in running().items()
        if not s.alive() and getattr(s, "completed", False)
    ]


def never_started(configured: tuple[str, ...] | None = None) -> list[str]:
    """Configured sources that were never even constructed."""
    configured = configured if configured is not None else config.get().sources
    live = running()
    return [spec for spec in configured if spec not in live]


def status() -> list[dict]:
    out = []
    for spec, s in running().items():
        entry = {
            "spec": spec,
            "name": getattr(s, "name", spec),
            "origin": getattr(s, "origin", spec),
            "alive": s.alive(),
            "completed": bool(getattr(s, "completed", False)),
        }
        # Sources report their own counters. A replay that has finished its file
        # is not alive and should say how much it processed, not vanish.
        if hasattr(s, "stats"):
            entry["stats"] = s.stats()
        out.append(entry)
    return out
