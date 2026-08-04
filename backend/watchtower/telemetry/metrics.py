"""Measured process and pipeline telemetry.

Everything here replaces a `random.uniform()` call that was being presented to
the operator as a measurement. Three traps shaped the implementation, each
verified on this machine rather than assumed:

1. **The instrument must cost less than the thing it measures.** A
   `@contextlib.contextmanager` timer benchmarked at ~2.1us of overhead, while
   the pipeline stage it would wrap (`normalize_log`) runs in ~0.7us — the
   reported latency would have been mostly the act of measuring. Callers
   therefore bracket stages with two inline `perf_counter()` reads and call
   `record()`, which is a plain append.

2. **`ru_maxrss` is not current memory, and its unit is platform-dependent.**
   It is a high-water mark that never decreases — after a reset frees thousands
   of records, real RSS drops and `ru_maxrss` does not move — and it is bytes on
   macOS but kilobytes on Linux. It is reported here as `peak_rss_mb`, honestly
   labelled, alongside a real current RSS obtained per-platform.

3. **Percentiles are reported by nearest rank, never interpolated.**
   Interpolation invents a latency that was never observed, which is precisely
   the class of number this project is removing.
"""

import collections
import os
import resource
import sys
import threading
import time

# ── stage latency ────────────────────────────────────────────────────────────
# Bounded per stage. At ~1 event/s this holds roughly 8 minutes of history; the
# window is by count, so `samples` is always reported alongside any percentile.
_MAXLEN = 512
_stage_samples: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque(maxlen=_MAXLEN)
)
_STAGES = ("ingest", "normalize", "detect", "alert", "ledger", "pipeline")


def record(stage: str, seconds: float) -> None:
    """Record one stage duration. Called on the pipeline hot path — keep it cheap.

    deque.append is atomic under the GIL, so no lock is taken: the background
    generator thread and Flask request handlers can both touch this safely.
    """
    _stage_samples[stage].append(seconds)


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Nearest-rank percentile. No interpolation — every value returned is a
    duration that was actually observed."""
    if not sorted_vals:
        return 0.0
    k = max(1, min(len(sorted_vals), int(-(-pct * len(sorted_vals) // 100))))
    return sorted_vals[k - 1]


def stage_stats(stage: str) -> dict:
    vals = sorted(_stage_samples.get(stage, ()))
    n = len(vals)
    if not n:
        return {"samples": 0, "p50_ms": None, "p95_ms": None}
    return {
        "samples": n,
        "p50_ms": round(_percentile(vals, 50) * 1000, 4),
        # p95 over a handful of samples is barely more than "the second largest
        # value". Suppress it rather than dress up a weak estimate.
        "p95_ms": round(_percentile(vals, 95) * 1000, 4) if n >= 20 else None,
    }


def all_stage_stats() -> dict:
    return {s: stage_stats(s) for s in _STAGES}


# ── throughput ───────────────────────────────────────────────────────────────
# Time-bounded, not count-bounded: a deque(maxlen=K) of arrival times silently
# caps a burst at K/window and under-reports it. /api/simulate-attack emits up
# to 25 events in a tight loop, which is exactly that case.
_events_lock = threading.Lock()
_event_times: collections.deque = collections.deque()
_RATE_WINDOW = 60.0


def record_event() -> None:
    now = time.monotonic()
    with _events_lock:
        _event_times.append(now)
        cutoff = now - _RATE_WINDOW
        while _event_times and _event_times[0] < cutoff:
            _event_times.popleft()


def events_per_second() -> float:
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW
    with _events_lock:
        while _event_times and _event_times[0] < cutoff:
            _event_times.popleft()
        n = len(_event_times)
        oldest = _event_times[0] if n else None
    if n < 2 or oldest is None:
        return 0.0
    # Divide by the span actually covered, not the nominal window — otherwise
    # the rate reads artificially low for the first minute after startup.
    span = max(now - oldest, 1e-6)
    return round(n / span, 3)


# ── process metrics ──────────────────────────────────────────────────────────
_start_monotonic = time.monotonic()
_last_cpu_sample = (time.monotonic(), time.process_time())
_cpu_lock = threading.Lock()


def uptime_seconds() -> float:
    """Real uptime under any launcher.

    Module import time, not `if __name__ == "__main__"` — the previous version
    assigned the start time only in the __main__ block, so uptime read 0 under
    flask run, gunicorn, any WSGI shim, and every test client.
    """
    return round(time.monotonic() - _start_monotonic, 1)


def _current_rss_bytes() -> int | None:
    """Current resident set size, per platform. None if it cannot be measured."""
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/statm") as fh:
                pages = int(fh.read().split()[1])
            return pages * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError, IndexError):
            return None
    if sys.platform == "darwin":
        try:
            import ctypes

            libc = ctypes.CDLL("/usr/lib/libSystem.dylib")

            # mach_task_self() + task_info(MACH_TASK_BASIC_INFO)
            class _TaskBasicInfo(ctypes.Structure):
                _fields_ = [
                    ("virtual_size", ctypes.c_uint64),
                    ("resident_size", ctypes.c_uint64),
                    ("resident_size_max", ctypes.c_uint64),
                    ("user_time", ctypes.c_uint64),
                    ("system_time", ctypes.c_uint64),
                    ("policy", ctypes.c_int),
                    ("suspend_count", ctypes.c_int),
                ]

            info = _TaskBasicInfo()
            count = ctypes.c_uint32(ctypes.sizeof(info) // ctypes.sizeof(ctypes.c_uint32))
            libc.mach_task_self.restype = ctypes.c_uint32
            rc = libc.task_info(libc.mach_task_self(), 20, ctypes.byref(info), ctypes.byref(count))
            if rc == 0 and info.resident_size:
                return int(info.resident_size)
        except Exception:
            return None
    return None


def _peak_rss_bytes() -> int:
    """ru_maxrss, normalised.

    getrusage(2) documents ru_maxrss in kilobytes on Linux and bytes on
    macOS/BSD. Branch on the platform, never on the magnitude — a magnitude
    sniff silently produces a 1024x error that still looks plausible.
    """
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw if sys.platform == "darwin" else raw * 1024


def cpu_percent() -> float:
    """CPU used by this process since the previous call to this function.

    Sampled against a single module-level checkpoint rather than per-request:
    two dashboard tabs polling on the same interval would otherwise each charge
    the other's elapsed time and both read roughly half the true value.
    """
    global _last_cpu_sample
    with _cpu_lock:
        prev_wall, prev_cpu = _last_cpu_sample
        now_wall, now_cpu = time.monotonic(), time.process_time()
        elapsed = now_wall - prev_wall
        if elapsed < 0.05:
            return 0.0
        _last_cpu_sample = (now_wall, now_cpu)
        return round(min(100.0 * os.cpu_count(), (now_cpu - prev_cpu) / elapsed * 100.0), 1)


def process_metrics() -> dict:
    rss = _current_rss_bytes()
    return {
        "memory_usage_mb": round(rss / 1024 / 1024, 1) if rss is not None else None,
        "peak_rss_mb": round(_peak_rss_bytes() / 1024 / 1024, 1),
        "cpu_percent": cpu_percent(),
        "threads": threading.active_count(),
        "uptime_seconds": uptime_seconds(),
        "events_per_second": events_per_second(),
    }


def reset() -> None:
    """Drop recorded samples (used by /api/reset so telemetry matches the data)."""
    for d in _stage_samples.values():
        d.clear()
    with _events_lock:
        _event_times.clear()
