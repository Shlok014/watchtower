"""Real IP reputation, backed by public threat-intelligence feeds.

Replaces a hardcoded table of invented ISP strings ("ShadowNet VPN",
"BulletProof Hosting") that was scored by substring matching. Every verdict this
package returns names the feed it came from and the date that feed was fetched,
and an address that could not be checked says so rather than scoring 0.25 for
being unfamiliar.
"""

from .feeds import FEEDS, FeedSpec
from .index import FRESH, MISSING, STALE, ReputationIndex, Verdict, classify, get_index

__all__ = [
    "FEEDS",
    "FeedSpec",
    "ReputationIndex",
    "Verdict",
    "classify",
    "get_index",
    "FRESH",
    "STALE",
    "MISSING",
]
