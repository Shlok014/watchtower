"""Registry of the threat-intelligence feeds Watchtower consumes.

Both feeds are public, free, and fetched at runtime — nothing is vendored into
the repository. That is deliberate: the data is dated, third-party, and carries
its own licensing, so the cache lives under a git-ignored directory and the
manifest records exactly where each byte came from and when.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class FeedSpec:
    name: str
    url: str
    filename: str
    parser: str  # "ipv4_lines" | "cidr_lines"
    kind: str  # "exact" | "cidr"
    max_age_hours: int
    min_entries: int  # a smaller parse than this is rejected as a bad download
    reputation: str  # verdict emitted on a hit
    score: float  # contribution to the anomaly score on a hit
    citation: str  # prose used verbatim in operator-facing explanations
    homepage: str


FEEDS: tuple[FeedSpec, ...] = (
    FeedSpec(
        name="tor_exits",
        url="https://check.torproject.org/torbulkexitlist",
        filename="tor_exits.txt",
        parser="ipv4_lines",
        kind="exact",
        # Tor regenerates this roughly every 30 minutes and exit relays churn
        # fast, so a two-day-old copy genuinely misrepresents the network.
        max_age_hours=24,
        min_entries=100,
        reputation="tor_exit",
        score=0.40,
        citation="Tor Project bulk exit list",
        homepage="https://check.torproject.org/",
    ),
    FeedSpec(
        name="firehol_level1",
        url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        filename="firehol_level1.netset",
        parser="cidr_lines",
        kind="cidr",
        max_age_hours=72,
        min_entries=500,
        reputation="blocklisted",
        score=0.40,
        citation="FireHOL level1",
        homepage="https://iplists.firehol.org/?ipset=firehol_level1",
    ),
)

FEEDS_BY_NAME = {f.name: f for f in FEEDS}
