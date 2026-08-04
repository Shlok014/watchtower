"""SQLite connection management.

Raw ``sqlite3`` rather than an ORM. At this scale an ORM would hide exactly the
details that make the design defensible — WAL mode, busy_timeout, where the
transaction boundaries are — and add a dependency to do it.

Threading model: one connection per thread via ``threading.local()``. The
writers are a daemon generator thread and Werkzeug's per-request threads; a
shared connection with ``check_same_thread=False`` would need a global lock that
serialises reads behind writes, which is the thing WAL exists to avoid.
"""

import contextlib
import os
import sqlite3
import threading
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
SCHEMA_VERSION = 2

_local = threading.local()
# Resolved lazily from config rather than captured at import. Bound at import,
# it would freeze whatever WATCHTOWER_DB said the first time this module was
# touched — including inside a test that had not yet redirected it.
_db_path: Path | None = None
_initialised = False
_init_lock = threading.Lock()


def configure(path: str | os.PathLike | None = None) -> None:
    """Point the store at a database file. Must run before the first connect()."""
    global _db_path, _initialised
    with _init_lock:
        _db_path = Path(path) if path is not None else None
        _initialised = False
    _close_local()


def path() -> Path:
    global _db_path
    if _db_path is None:
        from .. import config

        _db_path = config.get().db_path
    return _db_path


def _close_local() -> None:
    conn = getattr(_local, "conn", None)
    if conn is not None:
        with contextlib.suppress(sqlite3.Error):
            conn.close()
    _local.conn = None
    _local.path = None


def _new_connection() -> sqlite3.Connection:
    db_path = path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(db_path),
        timeout=5.0,
        # Transactions are managed explicitly. Python's sqlite3 opens implicit
        # transactions before DML and commits on some DDL, which makes it very
        # hard to reason about what is atomic; isolation_level=None turns that
        # off so a BEGIN means what it says.
        isolation_level=None,
    )
    conn.row_factory = sqlite3.Row

    # auto_vacuum MUST be set before the first table is created. Setting it on a
    # database that already has tables is silently ignored — the pragma reports
    # success and the value stays 0 — and then the file only ever grows: freed
    # pages go to the freelist and are never returned to the filesystem.
    conn.execute("PRAGMA auto_vacuum = INCREMENTAL")

    # Persistent, stored in the file header — set once, but harmless to repeat.
    conn.execute("PRAGMA journal_mode = WAL")

    # Per-connection, and must be re-set on every connection:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def connect() -> sqlite3.Connection:
    """Return this thread's connection, initialising the schema once per process."""
    global _initialised
    conn = getattr(_local, "conn", None)
    current = path()
    if conn is not None and getattr(_local, "path", None) == current:
        return conn
    _close_local()
    conn = _new_connection()
    _local.conn = conn
    _local.path = current

    if not _initialised:
        with _init_lock:
            if not _initialised:
                _apply_schema(conn)
                _initialised = True
    return conn


def _recorded_version(conn: sqlite3.Connection) -> int | None:
    """The version stamped in the file, or None for a database with no stamp."""
    try:
        row = conn.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.OperationalError:
        return None  # schema_meta itself does not exist yet: brand new file
    if row is None:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        raise RuntimeError(
            f"database at {path()} has an unreadable schema_version {row[0]!r}"
        ) from None


def migrations() -> dict[int, Path]:
    """Numbered migration scripts, keyed by the version they produce."""
    found = {}
    if MIGRATIONS_DIR.is_dir():
        for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
            try:
                found[int(f.name.split("_", 1)[0])] = f
            except ValueError:
                continue
    return found


def _apply_schema(conn: sqlite3.Connection) -> None:
    """Create or migrate, and refuse to run against anything else.

    ``schema.sql`` is always the *current* schema, so a fresh database gets the
    finished article and skips every migration. Migrations exist only for files
    created at an older version — which is why they must never be run against a
    new one: ``002`` adds a column ``schema.sql`` already declares, and the ALTER
    would fail with "duplicate column name" on every clean install.
    """
    before = _recorded_version(conn)

    if before is None:
        # New file (or one predating the stamp). CREATE ... IF NOT EXISTS
        # throughout, so this is safe on a database that already has the tables.
        conn.executescript(SCHEMA_PATH.read_text())
        conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )
        return

    if before == SCHEMA_VERSION:
        conn.executescript(SCHEMA_PATH.read_text())
        return

    if before > SCHEMA_VERSION:
        raise RuntimeError(
            f"database at {path()} has schema version {before}, but this build only "
            f"understands {SCHEMA_VERSION}. It was written by a newer Watchtower; "
            "running against it would silently ignore columns this code cannot see."
        )

    available = migrations()
    missing = [v for v in range(before + 1, SCHEMA_VERSION + 1) if v not in available]
    if missing:
        raise RuntimeError(
            f"database at {path()} is at schema version {before} and this build expects "
            f"{SCHEMA_VERSION}, but migration(s) {missing} are missing. Refusing to run "
            "against a schema this code does not understand."
        )

    for version in range(before + 1, SCHEMA_VERSION + 1):
        script = available[version]
        print(f"⬆️  migrating {path().name}: schema {version - 1} → {version} ({script.name})")
        # The migration and its version stamp go in one transaction. SQLite's
        # DDL is transactional, and without this a migration that failed
        # halfway would leave the stamp unchanged — so the next start would
        # re-run it, and `ALTER TABLE ADD COLUMN` is not idempotent. The
        # database would then be permanently unopenable with "duplicate column
        # name", which is a worse outcome than the original failure.
        conn.executescript(
            "BEGIN;\n"
            + script.read_text()
            + "\nINSERT INTO schema_meta(key, value) VALUES('schema_version', "
            + f"'{version}') ON CONFLICT(key) DO UPDATE SET value = excluded.value;\n"
            + "COMMIT;\n"
        )


class Transaction:
    """Explicit write transaction.

    BEGIN IMMEDIATE takes the write lock up front rather than on first write, so
    a busy database fails at the start of the transaction instead of partway
    through, where the caller has already done work.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def __enter__(self) -> sqlite3.Connection:
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None:
            self._rollback()
            return False
        # COMMIT gets its own guard. Writing this as `else: conn.execute("COMMIT")`
        # on the try/except is a real trap: an exception raised in an else clause
        # is NOT caught by the preceding except, so a failed COMMIT (disk full,
        # busy) would leave the connection inside a transaction forever, and
        # every later BEGIN would raise "cannot start a transaction within a
        # transaction" for the life of the process.
        try:
            self.conn.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return False

    def _rollback(self) -> None:
        try:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass


def write() -> Transaction:
    return Transaction(connect())


def checkpoint() -> None:
    """Truncate the WAL. Unbounded WAL growth is a real problem on a small disk."""
    with contextlib.suppress(sqlite3.Error):
        connect().execute("PRAGMA wal_checkpoint(TRUNCATE)")


def close_all() -> None:
    _close_local()
