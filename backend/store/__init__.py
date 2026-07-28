"""Persistence.

Replaces four module-level Python lists that a background thread mutated while
Flask request handlers iterated them, and a JSON file written on every twentieth
block inside a bare ``except Exception: pass``.
"""

from . import db, repos
from .db import close_all, configure, connect, write
from .repos import RETENTION_HOURS, retention_note

__all__ = [
    "db",
    "repos",
    "configure",
    "connect",
    "write",
    "close_all",
    "retention_note",
    "RETENTION_HOURS",
]
