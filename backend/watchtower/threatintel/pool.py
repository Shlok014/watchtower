"""Source addresses for the synthetic log generator.

Two pools, and the split is deliberate.

The generator needs to emit some traffic that the reputation lookup actually
flags, otherwise the feed integration is invisible in the demo — only 1 of the
8 addresses the original hardcoded list used appears in today's real Tor exit
list, so the dashboard would simply go quiet.

But the generator also fabricates *forensic detail*: "Malware signature
[Trojan.Gen.42] detected from <ip>", "312MB transfer to external <ip>". Printing
that next to a real Tor exit relay's address invents an accusation about a real
operator who is running a legal service, and it would end up in README
screenshots. So:

* ``provenance_pool`` — real addresses from the cached Tor exit list, used only
  for events that are genuinely *about* where a connection came from
  (suspicious_ip, port_scan, brute_force, failed_login). Being a Tor exit is a
  true, published fact about these addresses; flagging one for connection
  provenance is what the feed is for.
* ``fabrication_pool`` — RFC 5737 documentation ranges, used for every event
  that invents specifics (malware signatures, exfiltration volumes, privilege
  escalation). These addresses are reserved for documentation precisely so they
  can appear in examples, and they belong to nobody.

The pool is sampled deterministically from a digest of the feed contents, so a
given cached feed always yields the same demo addresses.
"""

import hashlib
import ipaddress
import random

from .feeds import FEEDS_BY_NAME
from .index import MISSING, ReputationIndex

# RFC 5737 TEST-NET-2 and TEST-NET-3. Reserved for documentation; no operator.
FABRICATION_POOL: tuple[str, ...] = tuple(
    [f"198.51.100.{n}" for n in (17, 42, 73, 118, 201)]
    + [f"203.0.113.{n}" for n in (23, 66, 149, 208)]
)

# Used when no feed is cached (offline clone, failed download). Documentation
# ranges again — never invented "plausible-looking" public addresses, which
# would put someone's real host in a screenshot captioned as an attacker.
OFFLINE_POOL: tuple[str, ...] = tuple(f"192.0.2.{n}" for n in (12, 45, 88, 130, 177, 222))

PROVENANCE_EVENTS = frozenset(
    {"suspicious_ip", "port_scan", "brute_force", "failed_login", "normal_traffic"}
)


def build_provenance_pool(index: ReputationIndex, size: int = 8) -> tuple[tuple[str, ...], str]:
    """Sample real Tor exit addresses from the cached feed.

    Returns (addresses, provenance_note). Falls back to documentation ranges
    when the feed is unavailable, and says so in the note — the demo degrades
    honestly rather than pretending.
    """
    spec = FEEDS_BY_NAME["tor_exits"]
    state = index.states.get(spec.name)
    exits = sorted(index._exact.get(spec.name, ()))
    if not state or state.state == MISSING or len(exits) < size:
        return OFFLINE_POOL, (
            "no threat feed cached — attacker addresses are RFC 5737 documentation "
            "ranges and will not match any blocklist"
        )

    # Deterministic given the feed contents: same cache -> same demo addresses.
    seed = int.from_bytes(hashlib.sha256(str(exits[:64]).encode()).digest()[:8], "big")
    rng = random.Random(seed)
    picked = rng.sample(exits, size)
    addrs = tuple(str(ipaddress.IPv4Address(n)) for n in picked)
    when = (state.fetched_at or "unknown").split("T")[0]
    return addrs, (
        f"attacker addresses sampled from the {spec.citation} fetched {when}; "
        "used only for connection-provenance events"
    )


def pool_for_event(event: str, provenance: tuple[str, ...]) -> tuple[str, ...]:
    """Pick which pool an event's source address should come from."""
    return provenance if event in PROVENANCE_EVENTS else FABRICATION_POOL
