"""Feed parsers.

Both parsers are total: they skip anything they cannot interpret rather than
raising, and the caller compares the resulting count against the feed's
``min_entries`` floor. That floor is what catches an HTTP 200 carrying an HTML
error, rate-limit or captcha page — such a body parses to roughly zero entries
and must never be allowed to overwrite a good cache with an empty blocklist.
"""

import ipaddress

__all__ = ["parse_ipv4_lines", "parse_cidr_lines", "parse", "count"]


def _iter_lines(body: bytes | str):
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def parse_ipv4_lines(body: bytes | str) -> list[int]:
    """One bare IPv4 address per line -> sorted list of 32-bit ints."""
    out = []
    for line in _iter_lines(body):
        try:
            addr = ipaddress.ip_address(line)
        except ValueError:
            continue
        if addr.version == 4:
            out.append(int(addr))
    out.sort()
    return out


def parse_cidr_lines(body: bytes | str) -> list[tuple[int, int]]:
    """CIDR-per-line -> list of inclusive (start, end) integer ranges.

    firehol_level1 is mostly CIDR but contains at least one bare address with
    no mask, so both forms are accepted.
    """
    out = []
    for line in _iter_lines(body):
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            out.append((int(net.network_address), int(net.broadcast_address)))
    return out


_PARSERS = {"ipv4_lines": parse_ipv4_lines, "cidr_lines": parse_cidr_lines}


def parse(parser: str, body: bytes | str):
    return _PARSERS[parser](body)


def count(parser: str, body: bytes | str) -> int:
    """Entry count as *this* parser sees it.

    Never trust a feed's own header count — firehol_level1's header advertises
    3862 subnets while the file actually carries 4580.
    """
    return len(parse(parser, body))
