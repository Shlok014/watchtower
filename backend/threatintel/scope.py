"""Address-scope classification, applied *before* any feed lookup.

This module exists because of a specific, verified trap: FireHOL level1
aggregates `fullbogons`, so the published netset contains 10.0.0.0/8,
172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 and the RFC 5737
documentation ranges. A naive "address is in the netset -> malicious" lookup
therefore flags every internal corporate host as a level-1 threat — replacing a
fabricated verdict with a confidently wrong one.

Non-routable addresses are classified here and never reach the blocklists.
"""

import ipaddress

__all__ = ["scope_of", "scope_of_addr", "GLOBAL", "INTERNAL", "NON_ROUTABLE", "UNSUPPORTED"]

GLOBAL = "global"
INTERNAL = "internal"
NON_ROUTABLE = "non_routable"
UNSUPPORTED = "unsupported"


# Checked in order, and checked *before* any ipaddress.is_* property.
#
# Relying on `addr.is_private` here would be a portability bug: CPython 3.13
# reclassified 100.64.0.0/10 (RFC 6598 shared address space) so that is_private
# became False, which silently moved CGNAT addresses from "non-routable" into
# the feed lookup — where firehol_level1 lists them as bogons and they came back
# labelled "blocklisted". An explicit table means the verdict does not change
# under the interpreter.
_SPECIAL_RANGES: list[tuple[ipaddress.IPv4Network, tuple[str, str]]] = [
    (ipaddress.ip_network("0.0.0.0/8"), (NON_ROUTABLE, "unspecified")),
    (ipaddress.ip_network("10.0.0.0/8"), (INTERNAL, "private (RFC1918)")),
    (ipaddress.ip_network("127.0.0.0/8"), (INTERNAL, "loopback")),
    (ipaddress.ip_network("169.254.0.0/16"), (INTERNAL, "link-local (RFC3927)")),
    (ipaddress.ip_network("172.16.0.0/12"), (INTERNAL, "private (RFC1918)")),
    (ipaddress.ip_network("192.168.0.0/16"), (INTERNAL, "private (RFC1918)")),
    (ipaddress.ip_network("100.64.0.0/10"), (NON_ROUTABLE, "carrier-grade NAT (RFC6598)")),
    (ipaddress.ip_network("192.0.0.0/24"), (NON_ROUTABLE, "IETF protocol assignments")),
    (ipaddress.ip_network("192.0.2.0/24"), (NON_ROUTABLE, "documentation range (RFC5737)")),
    (ipaddress.ip_network("198.51.100.0/24"), (NON_ROUTABLE, "documentation range (RFC5737)")),
    (ipaddress.ip_network("203.0.113.0/24"), (NON_ROUTABLE, "documentation range (RFC5737)")),
    (ipaddress.ip_network("198.18.0.0/15"), (NON_ROUTABLE, "benchmarking range (RFC2544)")),
    (ipaddress.ip_network("224.0.0.0/4"), (NON_ROUTABLE, "multicast")),
    (ipaddress.ip_network("240.0.0.0/4"), (NON_ROUTABLE, "reserved")),
]

_SPECIAL_BOUNDS = [
    (int(net.network_address), int(net.broadcast_address), label)
    for net, label in _SPECIAL_RANGES
]


def scope_of_addr(addr: ipaddress.IPv4Address) -> tuple[str, str]:
    """Classify an already-parsed IPv4 address. Returns (scope, detail)."""
    packed = int(addr)
    for lo, hi, label in _SPECIAL_BOUNDS:
        if lo <= packed <= hi:
            return label
    return GLOBAL, "globally routable"


def scope_of(ip: str) -> tuple[str, str]:
    """Classify an address given as a string."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return UNSUPPORTED, "unparseable address"
    if addr.version != 4:
        # Neither feed carries a single IPv6 entry (verified: zero lines
        # containing ':'). Returning "unlisted" for an IPv6 address would read
        # as "checked and clean" when nothing was checked at all.
        return UNSUPPORTED, "IPv6 — neither feed publishes IPv6 entries"
    return scope_of_addr(addr)
