"""The reputation lookup itself.

Design notes worth defending in review:

* CIDR membership is answered by binary search over a sorted array of disjoint
  ``(start, end)`` integer intervals, not by iterating ``ipaddress`` networks.
  ``bisect`` runs its loop in C; a prefix trie or a per-prefix-length dict costs
  19-32 interpreter round-trips per lookup and measured ~8x slower.
* The interval array is built with ``ipaddress.collapse_addresses``, which
  *establishes* the disjointness that binary search depends on rather than
  assuming a third party's file has it.
* Absence from a blocklist scores 0.00. The previous code gave every address it
  did not recognise 0.25 — a quarter of the way to the alert threshold for no
  evidence whatsoever. Not being on a list of known-bad hosts is not evidence
  of being bad.
"""

import bisect
import ipaddress
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

from . import parse, store
from .feeds import FEEDS
from .scope import INTERNAL, NON_ROUTABLE, scope_of_addr

FRESH, STALE, MISSING = "fresh", "stale", "missing"


@dataclass(frozen=True)
class Verdict:
    reputation: str  # internal | tor_exit | blocklisted | unlisted | unavailable | unsupported
    score: float
    sources: tuple[str, ...] = ()
    explanation: str = ""
    checked: bool = False  # was this address actually compared against a feed?


@dataclass
class FeedState:
    name: str
    state: str = MISSING
    entries: int = 0
    fetched_at: str | None = None
    age_hours: float | None = None
    citation: str = ""
    homepage: str = ""
    error: str | None = None


def _age_hours(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        ts = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(UTC) - ts).total_seconds() / 3600.0


class ReputationIndex:
    """Immutable-after-build lookup over the cached feeds."""

    def __init__(self):
        self._exact: dict[str, set[int]] = {}
        self._starts: dict[str, list[int]] = {}
        self._ends: dict[str, list[int]] = {}
        self.states: dict[str, FeedState] = {}

    # ── build ────────────────────────────────────────────────────────────────
    @classmethod
    def load(cls, cache_dir=store.CACHE_DIR) -> "ReputationIndex":
        idx = cls()
        manifest = store.load_manifest(cache_dir)
        for spec in FEEDS:
            st = FeedState(name=spec.name, citation=spec.citation, homepage=spec.homepage)
            entry = manifest.get("feeds", {}).get(spec.name, {})
            data = store.read_cached(spec, cache_dir, manifest)
            if data is None:
                st.error = "not fetched — run `python -m threatintel.fetch`"
                idx.states[spec.name] = st
                continue
            parsed = parse.parse(spec.parser, data)
            if len(parsed) < spec.min_entries:
                st.error = f"cache holds {len(parsed)} entries, below the {spec.min_entries} floor"
                idx.states[spec.name] = st
                continue

            if spec.kind == "exact":
                idx._exact[spec.name] = set(parsed)
            else:
                nets = []
                for start, end in parsed:
                    nets.extend(
                        ipaddress.summarize_address_range(
                            ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
                        )
                    )
                # collapse_addresses both merges adjacent/overlapping ranges and
                # returns them sorted — it is what establishes the disjointness
                # invariant that the bisect below relies on.
                merged = list(ipaddress.collapse_addresses(nets))
                idx._starts[spec.name] = [int(n.network_address) for n in merged]
                idx._ends[spec.name] = [int(n.broadcast_address) for n in merged]

            st.entries = len(parsed)
            st.fetched_at = entry.get("fetched_at")
            st.age_hours = _age_hours(st.fetched_at)
            st.state = (
                STALE if st.age_hours is not None and st.age_hours > spec.max_age_hours else FRESH
            )
            idx.states[spec.name] = st
        return idx

    # ── query ────────────────────────────────────────────────────────────────
    @property
    def usable(self) -> bool:
        return any(s.state in (FRESH, STALE) for s in self.states.values())

    def _hits(self, ip_int: int) -> list:
        hits = []
        for spec in FEEDS:
            st = self.states.get(spec.name)
            if not st or st.state == MISSING:
                continue
            if spec.kind == "exact":
                if ip_int in self._exact.get(spec.name, ()):
                    hits.append(spec)
            else:
                starts = self._starts.get(spec.name)
                if not starts:
                    continue
                i = bisect.bisect_right(starts, ip_int) - 1
                if i >= 0 and ip_int <= self._ends[spec.name][i]:
                    hits.append(spec)
        return hits

    def classify(self, ip: str) -> Verdict:
        # Parse exactly once: constructing an ipaddress object dominates the
        # cost of the lookup, so doing it in both scope_of and here doubled it.
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return Verdict(
                "unsupported", 0.0, (), "Reputation not checked: unparseable address", False
            )
        if addr.version != 4:
            return Verdict(
                "unsupported",
                0.0,
                (),
                "Reputation not checked: IPv6 — neither feed publishes IPv6 entries",
                False,
            )

        scope, detail = scope_of_addr(addr)
        if scope in (INTERNAL, NON_ROUTABLE):
            noun = "Internal address" if scope == INTERNAL else "Non-routable address"
            return Verdict(scope, 0.0, (), f"{noun} — {detail}", False)

        if not self.usable:
            return Verdict(
                "unavailable",
                0.0,
                (),
                "Reputation unavailable — no threat feed cached; run `make feeds`",
                False,
            )

        hits = self._hits(int(addr))
        if not hits:
            names = ", ".join(s.citation for s in FEEDS if self.states[s.name].state != MISSING)
            return Verdict("unlisted", 0.0, (), f"Not listed in {names}", True)

        # Both feeds can match the same address (39 Tor exits also sit inside a
        # firehol_level1 range). Score the strongest hit once; do not stack.
        best = max(hits, key=lambda s: s.score)
        cites = []
        for s in hits:
            st = self.states[s.name]
            when = (st.fetched_at or "unknown date").split("T")[0]
            suffix = ""
            if st.state == STALE and st.age_hours is not None:
                suffix = f", {st.age_hours / 24:.1f}d stale"
            cites.append(f"{s.citation} (fetched {when}{suffix})")
        return Verdict(
            best.reputation,
            best.score,
            tuple(s.name for s in hits),
            f"Listed in {' + '.join(cites)}",
            True,
        )


# ── process-wide singleton ───────────────────────────────────────────────────
_lock = threading.Lock()
_index: ReputationIndex | None = None


def get_index(reload: bool = False) -> ReputationIndex:
    global _index
    with _lock:
        if _index is None or reload:
            _index = ReputationIndex.load()
        return _index


def classify(ip: str) -> Verdict:
    return get_index().classify(ip)
