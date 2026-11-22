"""migrations.py: the numbered schema steps that carry a database to `LATEST`.

`Store` creates the v1 base tables — its `SCHEMA` IS the v1 schema — seeds
`schema_version` with 1 for a file that has no version yet, and then hands the
connection to `migrate`.  A brand-new file therefore reaches `migrate` already at
version 1 (and with no earlier database to copy), while a file written by an
older build arrives with its own rows and its own recorded version.

Each step runs inside one `BEGIN IMMEDIATE ... COMMIT` that also writes the new
version, so a step either lands whole or leaves the database exactly at the
version before it: any failure rolls the DDL and the version write back together
and is reported as `MigrationError`.  A database whose version is past `LATEST`
is refused instead of touched, with the same message shape `Store` has always
answered for a file a newer build wrote.

Before a step runs, a database that was already at version 1 or later is copied
beside itself with `VACUUM INTO`, as `engine.pre-v<N>.sqlite` — the version in the
name is the step's target, the version in the copy is the one it copies from.  A
copy already at that name is trusted only when it opens, answers `PRAGMA
quick_check` with "ok" and records a version below the target: it is then kept
exactly as it is and the new copy is written beside it under a timestamped name,
because the oldest pre-N copy is the one worth keeping.  Anything else found at
the name — a truncated file, a database that will not open, a copy from a newer
version — is not trusted: it is left where it is and the new copy goes to the
timestamped name as well.  The new copy is written to a temporary name, read back
(`quick_check`, and the version it was taken from), fsynced and renamed into its
final name, and the directory is fsynced after it.  A copy that cannot be written
or does not read back is no copy at all: the step is NOT run and `MigrationError`
is raised instead, so a database is never carried forward without one.  The copy
is made outside the step's transaction, so it is a picture of the database as it
stood BEFORE that step.

Two engines may open the same v1 file at once.  Each step's transaction is
started with `BEGIN IMMEDIATE` and the version is read once more while that write
lock is held, so the engine that arrives second finds the work done, commits the
empty transaction and runs nothing; the backup's own names are chosen so a
collision with the other process costs a name, never the copy.

Step 2 is the transition this module exists for.  It adds the live-book columns
to `bots`, `orders` and `fills`, rebuilds `events` so an event has an id, a kind,
an owner and a JSON payload, rebuilds `hwm` so a mark belongs to a book as well
as an owner, and creates `ai_previews` and `nonces`.  The rebuilds copy the old
rows in their old rowid order and do not use `IF NOT EXISTS`: a step interrupted
halfway is rolled back and retried, rather than hidden behind a table that is
already there.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import time
from pathlib import Path
from typing import Callable, Optional

# The schema version this build reads and writes.
LATEST = 2

# The copy taken before a step runs, beside the database it copies.  The version
# in the name is the step's target, not the version it copies from.
BACKUP_FORMAT = "engine.pre-v{version}.sqlite"

# The copy taken when something already sits at the plain name above: a valid
# older copy stays under the plain name and this one is the picture taken now.
TIMESTAMPED_FORMAT = "engine.pre-v{version}.{stamp}.sqlite"

# The one sqlite path that is not a file: there is no directory to copy beside.
MEMORY_PATH = ":memory:"

# A numbered step: the DDL and DML of one version, run inside the caller's
# transaction.  It never writes `schema_version` itself.
_Step = Callable[[sqlite3.Connection], None]


class MigrationError(RuntimeError):
    """One numbered step failed and was rolled back; the cause is chained."""


# ---------------------------------------------------------------- helpers


def _current_version(conn: sqlite3.Connection) -> int:
    """MAX(version) in `schema_version`, with 0 for a missing or empty table.

    The table's presence is asked of `sqlite_master` rather than caught from an
    error, so a genuine read failure is not mistaken for a fresh database.
    """
    found = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if found is None:
        return 0
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    if row is None or row[0] is None:
        return 0
    return int(row[0])


def _read_version(path: str) -> Optional[int]:
    """MAX(version) inside a database file, or None when it is not a usable copy.

    The file is opened READ-ONLY, so a missing, empty or damaged file is answered
    None instead of being created as a new empty database beside the real one.
    `PRAGMA quick_check` has to answer "ok" and a `schema_version` row has to be
    readable, so a file that sqlite opens but reports damage in is no better than
    a zero-byte one.
    """
    if not os.path.exists(path):
        return None
    try:
        uri = Path(os.path.abspath(path)).as_uri() + "?mode=ro"
        raw = sqlite3.connect(uri, uri=True)
    except (sqlite3.Error, ValueError):
        return None
    try:
        check = raw.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            return None
        row = raw.execute("SELECT MAX(version) FROM schema_version").fetchone()
        if row is None or row[0] is None:
            return None
        return int(row[0])
    except (sqlite3.Error, ValueError):
        return None
    finally:
        with contextlib.suppress(sqlite3.Error):
            raw.close()


def _fsync(path: str) -> None:
    """Flush one file, or one directory, to the disk by path."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _stamped_target(directory: str, version: int) -> str:
    """`engine.pre-v<N>.<UTC stamp>.sqlite` in *directory*."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return os.path.join(
        directory, TIMESTAMPED_FORMAT.format(version=version, stamp=stamp)
    )


def _free_name(base: str) -> str:
    """*base*, or the first numeric variant of it that is not taken yet.

    Another process may take the name between this check and the write.  Both
    files are copies of the same database, so losing that race costs a name and
    nothing worse: `os.replace` into a name that appeared meanwhile simply keeps
    the newer copy.
    """
    if not os.path.exists(base):
        return base
    stem, extension = os.path.splitext(base)
    index = 1
    while os.path.exists(f"{stem}.{index}{extension}"):
        index += 1
    return f"{stem}.{index}{extension}"


def _backup(
    conn: sqlite3.Connection, db_path: str | None, version: int
) -> None:
    """Copy the database beside itself before the step to *version* runs.

    Nothing is copied when there is no file to copy beside: no path at all (a
    brand-new database, whose earlier state is the empty schema it was just
    created with) or the in-memory database.  Nothing is copied either when the
    database already records *version* or a later one: another engine has been
    here, so there is no earlier state this step still needs.

    A file already at `engine.pre-v<version>.sqlite` is kept exactly as it is —
    whether it is a valid older copy (the oldest one is the one worth keeping) or
    something this module will neither trust nor overwrite — and this copy is
    written under a timestamped name beside it.

    The copy is written to a temporary name of this process's own, read back, and
    only then renamed into its final name; both it and the directory are fsynced.
    A copy that cannot be written, or does not read back, raises `MigrationError`
    so the caller never runs a step on a database whose earlier state was lost.

    `VACUUM INTO` writes a consistent copy of the whole file without needing a
    transaction of its own, and it must not run inside one, so the caller invokes
    this between transactions.
    """
    if db_path is None:
        return
    path = str(db_path)
    if not path or path == MEMORY_PATH:
        return
    copying = _current_version(conn)
    if copying >= version:
        return
    directory = os.path.dirname(os.path.abspath(path))
    plain = os.path.join(directory, BACKUP_FORMAT.format(version=version))
    if os.path.exists(plain):
        # The plain name is taken: either by the oldest copy, which is kept as it
        # is, or by something this module will neither trust nor overwrite.
        final = _free_name(_stamped_target(directory, version))
    else:
        final = plain
    tmp = f"{final}.{os.getpid()}-{os.urandom(4).hex()}.tmp"
    try:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        literal = tmp.replace("'", "''")
        conn.execute(f"VACUUM INTO '{literal}'")
        copied = _read_version(tmp)
        if copied is not None and copied >= version:
            # The database moved past this step while the copy was being taken,
            # so this is a picture of work already done, not of work to keep.
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            return
        if copied != copying:
            raise sqlite3.DatabaseError(
                f"the copy reads back at version {copied}, not {copying}"
            )
        _fsync(tmp)
        os.replace(tmp, final)
        _fsync(directory)
    except BaseException as error:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        if not isinstance(error, Exception):
            raise
        raise MigrationError(f"backup before v{version} failed") from error


def _run_step(conn: sqlite3.Connection, target: int, step: _Step) -> None:
    """Run one step and the version write in ONE transaction, or neither.

    The transaction is started with `BEGIN IMMEDIATE`, so the write lock is taken
    before any DDL runs instead of being upgraded mid-step.  The version is read
    again once that lock is held: another engine that opened the same file first
    has already carried it to *target* or past it, and then this call commits the
    empty transaction and runs nothing at all.  A failure of the step, of the
    version write or of the `COMMIT` itself rolls everything back and answers
    `MigrationError` naming the version; the original error is chained, so the
    reason is not lost.  A `BaseException` that is not an `Exception` (an
    interrupt, say) is rolled back and re-raised as it is.
    """
    started = False
    try:
        conn.execute("BEGIN IMMEDIATE")
        started = True
        if _current_version(conn) >= target:
            conn.execute("COMMIT")
            started = False
            return
        step(conn)
        conn.execute("DELETE FROM schema_version")
        conn.execute("INSERT INTO schema_version(version) VALUES(?)", (target,))
        conn.execute("COMMIT")
    except BaseException as error:
        # Only a transaction this function opened is rolled back, so a caller's
        # own transaction is never undone by a step that could not even start.
        if started:
            with contextlib.suppress(sqlite3.Error):
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
        if not isinstance(error, Exception):
            raise
        raise MigrationError(f"migration to v{target} failed") from error


# ---------------------------------------------------------------- v2


def _to_v2(conn: sqlite3.Connection) -> None:
    """The P2 shape: per-book rows, a richer event, and the AI preview tables.

    Three groups.  First the columns the live book adds to the existing tables,
    each with a default that describes a P1 row exactly (a bot is a `dry` bot, an
    order is a `SPOT` order on the `dry` book, a fill is on the `dry` book).
    Then the two rebuilds: `events` gains an id, a kind, an owner and a payload
    while every old row keeps its order and its `ts`/`level`/`message`, and `hwm`
    becomes one mark per (book, owner) with the v1 rows as the dry book's marks.
    Finally the two tables a preview-confirmed order needs (`ai_previews` and
    `nonces`).

    The rebuilds create a new table, copy into it, drop the old one and rename
    the new one into its place.  None of that uses `IF NOT EXISTS`: a step that
    ran halfway must fail loudly and be rolled back rather than be papered over.
    """
    # (a) bots: which book a bot trades, and the capital it may use on the live one.
    conn.execute(
        "ALTER TABLE bots ADD COLUMN mode TEXT NOT NULL DEFAULT 'dry' "
        "CHECK(mode IN ('dry','live'))"
    )
    conn.execute("ALTER TABLE bots ADD COLUMN live_capital_quote TEXT")
    conn.execute("ALTER TABLE bots ADD COLUMN live_capital_base TEXT")

    # (b) orders and fills: the product type and the book the row belongs to.
    #     A book is `dry` or `live` and a product type `SPOT` or `EQUITY`; the
    #     defaults describe a P1 row exactly, so every old row reads as what it was.
    conn.execute(
        "ALTER TABLE orders ADD COLUMN product_type TEXT NOT NULL DEFAULT 'SPOT' "
        "CHECK(product_type IN ('SPOT','EQUITY'))"
    )
    conn.execute(
        "ALTER TABLE orders ADD COLUMN book TEXT NOT NULL DEFAULT 'dry' "
        "CHECK(book IN ('dry','live'))"
    )
    conn.execute(
        "ALTER TABLE fills ADD COLUMN book TEXT NOT NULL DEFAULT 'dry' "
        "CHECK(book IN ('dry','live'))"
    )

    # (c) events: an id to read forward from, a kind, an owner and a payload.
    conn.execute(
        "CREATE TABLE events_new ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, level TEXT, "
        "kind TEXT NOT NULL DEFAULT 'info', owner TEXT, message TEXT, "
        "data_json TEXT NOT NULL DEFAULT '{}')"
    )
    # The old rowid becomes the new id, holes and all: an id is read forward from,
    # so it must not be handed out a second time for an event written in P1.
    conn.execute(
        "INSERT INTO events_new(id,ts,level,message) "
        "SELECT rowid, ts, level, message FROM events ORDER BY rowid"
    )
    conn.execute("DROP TABLE events")
    conn.execute("ALTER TABLE events_new RENAME TO events")

    # (d) hwm: one high-water mark per book and owner; the v1 rows are dry.
    conn.execute(
        "CREATE TABLE hwm_new ("
        "book TEXT NOT NULL DEFAULT 'dry' CHECK(book IN ('dry','live')), "
        "owner TEXT NOT NULL, value TEXT, "
        "PRIMARY KEY (book, owner))"
    )
    conn.execute(
        "INSERT INTO hwm_new(book,owner,value) SELECT 'dry', owner, value FROM hwm"
    )
    conn.execute("DROP TABLE hwm")
    conn.execute("ALTER TABLE hwm_new RENAME TO hwm")

    # (e) the tables a confirmed AI preview and its one-use nonce live in.  A
    #     preview's state is one of six, and the client order id it confirms into
    #     is used by one preview only; `consumed_at` is when it was spent.
    conn.execute(
        "CREATE TABLE ai_previews ("
        "id TEXT PRIMARY KEY, created_at REAL NOT NULL, expires_at REAL NOT NULL, "
        "state TEXT NOT NULL DEFAULT 'pending' "
        "CHECK(state IN ('pending','approved','placed','expired','rejected',"
        "'cancelled')), "
        "product TEXT NOT NULL, side TEXT NOT NULL, size TEXT NOT NULL, "
        "limit_price TEXT NOT NULL, "
        "book TEXT NOT NULL DEFAULT 'dry' CHECK(book IN ('dry','live')), "
        "hash TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}', "
        "refusal TEXT, approved_at REAL, consumed_at REAL, cid TEXT)"
    )
    # A client order id is used by one preview only; a preview without one (not a
    # confirmed preview yet) is not held to that.
    conn.execute(
        "CREATE UNIQUE INDEX ai_previews_cid ON ai_previews(cid) "
        "WHERE cid IS NOT NULL"
    )
    conn.execute(
        "CREATE TABLE nonces (nonce TEXT PRIMARY KEY, seen_at REAL NOT NULL, "
        "ts REAL NOT NULL DEFAULT 0)"
    )
    conn.execute("CREATE INDEX nonces_seen_at ON nonces(seen_at)")


# The numbered steps, by target version.  Looked up in `migrate` through this
# name, so a step can be replaced for one call without touching the store.
_STEPS: dict[int, _Step] = {2: _to_v2}


# ---------------------------------------------------------------- the entry point


def migrate(conn: sqlite3.Connection, db_path: str | None = None) -> int:
    """Carry *conn* to `LATEST` and answer the version it ends at.

    `conn` is an autocommit connection (`isolation_level=None`), the same kind
    `Store` hands out: this function opens its own transactions and commits them.
    `db_path` is the file behind the connection when there is one, and is what a
    step's backup is taken beside; it is None for a database that had no earlier
    version to copy.

    Every step from the current version + 1 to `LATEST` runs in order.  A
    database already at `LATEST` is answered straight away and left alone (no
    step, no copy, no error), so calling this on every open costs nothing.  A
    database past `LATEST` is refused with `RuntimeError` before anything is
    written.  A step that fails answers `MigrationError` and leaves the database
    at the version immediately before it; a copy of that earlier state that
    cannot be written answers `MigrationError` too, before the step that asked
    for it runs at all.
    """
    recorded = _current_version(conn)
    if recorded > LATEST:
        raise RuntimeError(
            f"database schema version {recorded} is newer than this "
            f"engine's schema version {LATEST}"
        )
    version = recorded
    for target in range(recorded + 1, LATEST + 1):
        # Only a database that already held a recorded version has an earlier
        # state worth copying; a brand-new file does not.
        if recorded >= 1:
            _backup(conn, db_path, target)
        _run_step(conn, target, _STEPS[target])
        version = target
    return version
