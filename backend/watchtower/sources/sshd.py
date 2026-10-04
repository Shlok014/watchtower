"""Parse only complete sshd authentication messages with literal actor IPs."""

import ipaddress
import re

_USER = r"(?P<user>\S+)"
_IP = r"(?P<ip>\S+)"
_FAILED = re.compile(
    rf"^Failed password for (?:invalid user )?{_USER} from {_IP} port (?P<port>\d{{1,5}})(?: ssh2)?$"
)
_INVALID = re.compile(rf"^Invalid user {_USER} from {_IP}$")
_ACCEPTED = re.compile(
    rf"^Accepted (?:password|publickey) for {_USER} from {_IP} port (?P<port>\d{{1,5}})(?: ssh2)?$"
)
_TAG = re.compile(r"^sshd(?:\[\d+\])?$", re.ASCII)


def parse(tag: str, message: str) -> tuple[str, str, str] | None:
    """Return (event, actor IP, user), or None without guessing an address."""
    if not _TAG.fullmatch(tag):
        return None
    for pattern, event in (
        (_FAILED, "failed_login"),
        (_INVALID, "auth_invalid_user"),
        (_ACCEPTED, "login_success"),
    ):
        match = pattern.fullmatch(message)
        if match is None:
            continue
        port = match.groupdict().get("port")
        if port is not None and not 1 <= int(port) <= 65535:
            return None
        try:
            address = ipaddress.ip_address(match.group("ip"))
        except ValueError:
            return None
        if getattr(address, "scope_id", None):
            return None
        address = getattr(address, "ipv4_mapped", None) or address
        return event, str(address), match.group("user")
    return None
