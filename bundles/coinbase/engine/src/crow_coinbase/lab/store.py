"""SQLite system of record for the research lab: bars, events, rules, runs, studies.

Isolation mode: AUTOCOMMIT (`isolation_level=None`) with EXPLICIT transactions.
Every connection opens in autocommit and `LabStore.tx()` is the only place that
starts a transaction.  `tx()` runs `BEGIN IMMEDIATE`, so a writer takes the write
lock up front instead of failing late while upgrading a read lock, and it falls
back to a `SAVEPOINT` when the caller already holds a transaction: the work then
joins the caller's transaction and their commit/rollback decides its fate.  Every
method that writes rows, or reads then writes (`register_rule`, `record_run`),
runs inside `tx()`.

The file runs in WAL mode (readers never block the writer).  Each thread gets its
own connection through `threading.local`; `close()` closes every connection the
store opened.  Money and prices are `Decimal` in Python and TEXT in SQLite, so a
value round-trips as the text it was written as.  Datetimes are timezone-aware
UTC, stored as ISO-8601 TEXT written to the microsecond: the fixed width keeps
`>=`/`<` range filtering and `ORDER BY` correct in SQL, and a naive datetime is
refused rather than guessed at.

`PRAGMA user_version` carries the schema version (1).  A file stamped with a
higher version belongs to a newer lab store and is refused.

`bars` and `events` are market data, not project data: they carry no
`project_id`.  `rules`, `runs` and `studies` are per project; a run is unique on
`(project_id, asset, interval, rule_id, params_json, data_hash)`, so repeating a
trial returns the row already recorded instead of growing the
multiple-comparisons count.

A registered rule's grid is its pre-registered design, and changing that design
is a new VERSION rather than an edit: v1 keeps the rule's own id, v2 is stored
as `<id>@v2`, v3 as `<id>@v3`, and the current version is the highest number.
Versions are extra `rules` rows, so no column carries a number and no schema
changes.  `runs` always keeps the base id, which means every trial run against
an older grid goes on counting in `trials()`.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable, Optional

D = Decimal

SCHEMA_VERSION = 1

BAR_INTERVALS = frozenset({"1h", "1d"})
EVENT_KINDS = frozenset({"earnings", "lockup", "listing", "custom"})
EVENT_SESSIONS = frozenset({"pre", "post", "none"})

# An asset whose symbol carries a "-" is a pair (crypto); anything else is a
# single-name instrument (stock).
CRYPTO_CLASS, STOCK_CLASS = "crypto", "stock"
ASSET_CLASSES = (CRYPTO_CLASS, STOCK_CLASS)

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS bars (
         symbol TEXT NOT NULL, interval TEXT NOT NULL, ts TEXT NOT NULL,
         open TEXT NOT NULL, high TEXT NOT NULL, low TEXT NOT NULL,
         close TEXT NOT NULL, volume TEXT NOT NULL, adj_factor TEXT NOT NULL,
         PRIMARY KEY (symbol, interval, ts))""",
    """CREATE TABLE IF NOT EXISTS events (
         id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL,
         kind TEXT NOT NULL, at TEXT NOT NULL, announced_at TEXT NOT NULL,
         session TEXT NOT NULL, note TEXT NOT NULL,
         UNIQUE (symbol, kind, at))""",
    """CREATE INDEX IF NOT EXISTS events_at ON events(symbol, at)""",
    """CREATE TABLE IF NOT EXISTS rules (
         project_id TEXT NOT NULL, rule_id TEXT NOT NULL,
         hypothesis TEXT NOT NULL, grid_json TEXT NOT NULL,
         registered_at TEXT NOT NULL,
         PRIMARY KEY (project_id, rule_id))""",
    """CREATE TABLE IF NOT EXISTS runs (
         id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL,
         asset TEXT NOT NULL, interval TEXT NOT NULL, rule_id TEXT NOT NULL,
         params_json TEXT NOT NULL, data_hash TEXT NOT NULL,
         excess_sharpe REAL, result_json TEXT NOT NULL, created_at TEXT NOT NULL,
         UNIQUE (project_id, asset, interval, rule_id, params_json, data_hash))""",
    """CREATE INDEX IF NOT EXISTS runs_trials
         ON runs(project_id, interval, id)""",
    """CREATE TABLE IF NOT EXISTS studies (
         id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL,
         name TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL)""",
)


class LabStoreError(Exception):
    """A lab store refusal: a newer schema file, or a conflicting re-register."""


class StoredDecimal(Decimal):
    """A Decimal read back from the store, printing the text it was stored as.

    SQLite keeps money and prices as TEXT, so a value is read back as the exact
    text that was written; bars are written in fixed-point form, and this class
    prints that same fixed-point form (a plain `0.1`, never `1E-1`) while the
    value itself compares and calculates as the Decimal it is.
    """

    def __str__(self) -> str:
        return Decimal.__format__(self, "f")


@dataclass(frozen=True)
class Bar:
    """One OHLCV bar of one symbol and interval, stamped at its open time."""

    symbol: str
    interval: str
    ts: datetime
    open: D
    high: D
    low: D
    close: D
    volume: D
    adj_factor: D = D("1")

    def __post_init__(self) -> None:
        if self.interval not in BAR_INTERVALS:
            raise ValueError(
                f"invalid bar interval {self.interval!r}; expected one of "
                f"{sorted(BAR_INTERVALS)}"
            )
        for name, value in (
            ("open", self.open),
            ("high", self.high),
            ("low", self.low),
            ("close", self.close),
            ("volume", self.volume),
            ("adj_factor", self.adj_factor),
        ):
            object.__setattr__(self, name, _money(value, name))


@dataclass(frozen=True)
class Event:
    """A scheduled event for one symbol, with the instant it became known."""

    symbol: str
    kind: str
    at: datetime
    announced_at: datetime
    session: str
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind not in EVENT_KINDS:
            raise ValueError(
                f"invalid event kind {self.kind!r}; expected one of "
                f"{sorted(EVENT_KINDS)}"
            )
        if self.session not in EVENT_SESSIONS:
            raise ValueError(
                f"invalid event session {self.session!r}; expected one of "
                f"{sorted(EVENT_SESSIONS)}"
            )
        if (
            _is_aware(self.at)
            and _is_aware(self.announced_at)
            and _instant(self.announced_at) > _instant(self.at)
        ):
            raise ValueError(
                f"event announced_at {self.announced_at!r} is after its at "
                f"{self.at!r}"
            )


@dataclass(frozen=True)
class TrialRow:
    """One recorded run, as the multiple-comparisons count reads it."""

    project_id: str
    asset: str
    interval: str
    rule_id: str
    params: dict
    data_hash: str
    excess_sharpe: Optional[float]


# ---------------------------------------------------------------- value helpers


def _money(value: Any, name: str = "amount") -> D:
    """A Decimal from a Decimal, str or int.  A float is refused."""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, float):
        raise ValueError(f"{name} must be a Decimal, not float: {value!r}")
    try:
        return D(str(value))
    except Exception as exc:  # noqa: BLE001 - re-raised with the field name
        raise ValueError(f"{name} is not a decimal value: {value!r}") from exc


def _dec_text(value: Any, name: str = "amount") -> str:
    """The plain fixed-point text a Decimal is stored as (no exponent form)."""
    return format(_money(value, name), "f")


def _is_aware(moment: Any) -> bool:
    """True when *moment* is a datetime carrying a real UTC offset."""
    if not isinstance(moment, datetime):
        return False
    return moment.tzinfo is not None and moment.tzinfo.utcoffset(moment) is not None


def _instant(moment: datetime) -> datetime:
    """*moment* refused unless timezone-aware, rendered as UTC."""
    if not isinstance(moment, datetime):
        raise ValueError(f"expected a datetime, got {type(moment).__name__}")
    if not _is_aware(moment):
        raise ValueError(f"datetime must be timezone-aware: {moment!r}")
    return moment.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    """UTC ISO-8601 text at a fixed width, for range filters and ordering."""
    return _instant(moment).isoformat(timespec="microseconds")


def _from_iso(text: str) -> datetime:
    """The datetime written by `_iso`, as timezone-aware UTC."""
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def _canonical(value: Any) -> str:
    """Canonical JSON: sorted keys, no incidental whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _project_id(project_id: Any) -> str:
    """A non-empty project id, else ValueError (nothing written)."""
    if not isinstance(project_id, str) or not project_id.strip():
        raise ValueError(f"project_id must be a non-empty string: {project_id!r}")
    return project_id


def _token(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string: {value!r}")
    return value


def _base_rule_id(value: Any) -> str:
    """A caller's rule id, which is a base id and never a version's id.

    The store spells a version `<id>@v<n>`, so a `"@"` in a caller's id would
    collide with its own version rows; the caller names the base id and asks
    for a new version instead.
    """
    rule_id = _token(value, "rule_id")
    if "@" in rule_id:
        raise ValueError(
            f"rule_id {rule_id!r} carries '@', which is reserved for the "
            f"version rows the store keeps: pass the base id and ask for a new "
            f"version"
        )
    return rule_id


# What separates a base rule id from the number of a version after the first.
VERSION_SEPARATOR = "@v"


def _version_row_id(base: str, version: int) -> str:
    """The `rules.rule_id` a version is stored under: the base id at v1."""
    return base if version <= 1 else f"{base}{VERSION_SEPARATOR}{version}"


def _version_number(base: str, stored: str) -> Optional[int]:
    """The version `stored` stands for under `base`, or None for another rule.

    v1 is the base id itself, so a stored id that is neither the base id nor
    `<base>@v<n>` with n at least 2 belongs to some other rule.
    """
    if stored == base:
        return 1
    prefix = f"{base}{VERSION_SEPARATOR}"
    if not stored.startswith(prefix):
        return None
    digits = stored[len(prefix) :]
    if not (digits.isascii() and digits.isdigit()):
        return None
    number = int(digits)
    return number if number >= 2 else None


def _same_grid(stored_json: str, grid_json: str) -> bool:
    """True when two canonical grid texts describe the same grid.

    Both texts are read back as JSON first, the way the grid was written, so a
    grid supplied afresh compares equal to the stored one whenever the two
    describe the same configs.
    """
    return json.loads(stored_json) == json.loads(grid_json)


class LabStore:
    """The lab's database file.  Thread-safe: one connection per thread."""

    def __init__(self, path: Path | str):
        self.path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._conns: list[sqlite3.Connection] = []
        self._savepoints = itertools.count(1)
        self._apply_schema()

    # ------------------------------------------------ connections
    def _connect(self) -> sqlite3.Connection:
        # check_same_thread=False: `close()` may run on another thread than the
        # one that opened a connection and closes every connection from there.
        # Each connection is otherwise only ever used by its own thread (looked
        # up through `threading.local`).  `timeout` is the one place the busy
        # timeout is set (30 s), so a `BEGIN IMMEDIATE` that finds another writer
        # waits instead of failing.
        db = sqlite3.connect(
            self.path,
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def conn(self) -> sqlite3.Connection:
        """This thread's connection, created on first use."""
        db = getattr(self._local, "db", None)
        if db is None:
            db = self._connect()
            self._local.db = db
            with self._lock:
                self._conns.append(db)
        return db

    def close(self) -> None:
        """Close every connection this store opened, from any thread."""
        with self._lock:
            conns, self._conns = self._conns, []
        for db in conns:
            db.close()
        self._local = threading.local()

    @contextlib.contextmanager
    def tx(self):
        """One write transaction: BEGIN IMMEDIATE, or a savepoint when in one.

        Cleanup never masks the caller's error: a failing ROLLBACK / RELEASE is
        suppressed so the original exception keeps propagating.
        """
        db = self.conn()
        if db.in_transaction:
            name = f"lab_sp_{next(self._savepoints)}"
            db.execute(f"SAVEPOINT {name}")
            try:
                yield db
            except BaseException:
                with contextlib.suppress(sqlite3.Error):
                    if db.in_transaction:
                        db.execute(f"ROLLBACK TO {name}")
                        db.execute(f"RELEASE {name}")
                raise
            db.execute(f"RELEASE {name}")
            return
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                if db.in_transaction:
                    db.execute("ROLLBACK")
            raise
        try:
            db.execute("COMMIT")
        except BaseException:
            # The transaction is still open: undo it, then report the COMMIT error.
            with contextlib.suppress(sqlite3.Error):
                if db.in_transaction:
                    db.execute("ROLLBACK")
            raise

    def _apply_schema(self) -> None:
        """Refuse a newer file, create the tables, stamp the schema version."""
        db = self.conn()
        row = db.execute("PRAGMA user_version").fetchone()
        version = int(row[0]) if row is not None else 0
        if version > SCHEMA_VERSION:
            self.close()
            raise LabStoreError(
                f"database schema version {version} is newer than this lab "
                f"store's schema version {SCHEMA_VERSION}"
            )
        with self.tx() as db:
            for statement in SCHEMA:
                db.execute(statement)
        if version < SCHEMA_VERSION:
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def schema_version(self) -> int:
        row = self.conn().execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row is not None else SCHEMA_VERSION

    # ------------------------------------------------ bars
    def upsert_bars(self, symbol: str, interval: str, rows: Iterable[Bar]) -> int:
        """Insert or replace bars by (symbol, interval, ts); returns rows written.

        Every row's own symbol and interval must equal the arguments, and each
        timestamp must be timezone-aware; otherwise nothing is written and the
        call raises ValueError.  Repeating a batch rewrites the same rows, so the
        call is idempotent.
        """
        _token(symbol, "symbol")
        if interval not in BAR_INTERVALS:
            raise ValueError(
                f"invalid bar interval {interval!r}; expected one of "
                f"{sorted(BAR_INTERVALS)}"
            )
        prepared: list[tuple] = []
        for row in rows:
            if not isinstance(row, Bar):
                raise ValueError(f"expected a Bar, got {type(row).__name__}")
            if row.symbol != symbol or row.interval != interval:
                raise ValueError(
                    f"bar ({row.symbol!r}, {row.interval!r}) does not belong to "
                    f"({symbol!r}, {interval!r})"
                )
            prepared.append(
                (
                    symbol,
                    interval,
                    _iso(row.ts),
                    _dec_text(row.open, "open"),
                    _dec_text(row.high, "high"),
                    _dec_text(row.low, "low"),
                    _dec_text(row.close, "close"),
                    _dec_text(row.volume, "volume"),
                    _dec_text(row.adj_factor, "adj_factor"),
                )
            )
        if not prepared:
            return 0
        with self.tx() as db:
            db.executemany(
                "INSERT INTO bars(symbol,interval,ts,open,high,low,close,volume,"
                "adj_factor) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(symbol,interval,ts) DO UPDATE SET "
                "open=excluded.open, high=excluded.high, low=excluded.low, "
                "close=excluded.close, volume=excluded.volume, "
                "adj_factor=excluded.adj_factor",
                prepared,
            )
        return len(prepared)

    def bars(
        self, symbol: str, interval: str, start: datetime, end: datetime
    ) -> list[Bar]:
        """Bars with start <= ts < end, oldest first.  Decimals round-trip."""
        _token(symbol, "symbol")
        lo, hi = _iso(start), _iso(end)
        rows = self.conn().execute(
            "SELECT symbol, interval, ts, open, high, low, close, volume, "
            "adj_factor FROM bars WHERE symbol=? AND interval=? "
            "AND ts >= ? AND ts < ? ORDER BY ts",
            (symbol, interval, lo, hi),
        )
        return [_bar(row) for row in rows]

    # ------------------------------------------------ events
    def add_event(
        self,
        symbol: str,
        kind: str,
        at: datetime,
        announced_at: datetime,
        session: str,
        note: str = "",
    ) -> None:
        """Record an event, replacing the row for (symbol, kind, at).

        `announced_at` may not be later than `at`, and both must be
        timezone-aware; otherwise nothing is written and the call raises
        ValueError.
        """
        _token(symbol, "symbol")
        if kind not in EVENT_KINDS:
            raise ValueError(
                f"invalid event kind {kind!r}; expected one of "
                f"{sorted(EVENT_KINDS)}"
            )
        if session not in EVENT_SESSIONS:
            raise ValueError(
                f"invalid event session {session!r}; expected one of "
                f"{sorted(EVENT_SESSIONS)}"
            )
        at_utc, announced_utc = _instant(at), _instant(announced_at)
        if announced_utc > at_utc:
            raise ValueError(
                f"event announced_at {announced_at!r} is after its at {at!r}"
            )
        with self.tx() as db:
            db.execute(
                "INSERT INTO events(symbol,kind,at,announced_at,session,note) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(symbol,kind,at) DO UPDATE SET "
                "announced_at=excluded.announced_at, session=excluded.session, "
                "note=excluded.note",
                (
                    symbol,
                    kind,
                    at_utc.isoformat(timespec="microseconds"),
                    announced_utc.isoformat(timespec="microseconds"),
                    session,
                    str(note or ""),
                ),
            )

    def events(
        self, symbol: str, start: datetime, end: datetime
    ) -> list[Event]:
        """Events with start <= at < end, oldest first."""
        _token(symbol, "symbol")
        lo, hi = _iso(start), _iso(end)
        rows = self.conn().execute(
            "SELECT symbol, kind, at, announced_at, session, note FROM events "
            "WHERE symbol=? AND at >= ? AND at < ? ORDER BY at, id",
            (symbol, lo, hi),
        )
        return [_event(row) for row in rows]

    # ------------------------------------------------ rules
    def _current_version(self, db, project_id: str, rule_id: str):
        """The highest-version row of a base id, as (version, row), or None.

        The rows of a project are read out and matched on their stored id in
        Python rather than with a `LIKE` pattern, because a base id's own
        characters are not pattern syntax.  A project holds a handful of rules,
        so reading them all costs nothing.
        """
        best: Optional[tuple[int, sqlite3.Row]] = None
        for row in db.execute(
            "SELECT rule_id, hypothesis, grid_json, registered_at FROM rules "
            "WHERE project_id=?",
            (project_id,),
        ):
            version = _version_number(rule_id, row["rule_id"])
            if version is None:
                continue
            if best is None or version > best[0]:
                best = (version, row)
        return best

    def register_rule(
        self,
        project_id: str,
        rule_id: str,
        hypothesis: str,
        grid: list[dict],
        *,
        new_version: bool = False,
    ) -> int:
        """Register a rule and its parameter grid, and report its version.

        The store stamps `registered_at` itself (UTC now), so there is no such
        argument.  A first registration is version 1 and returns 1.

        The grid is the pre-registered design.  Registering the same (project,
        rule) again with an equal grid is a no-op that leaves the stamp alone
        and returns the version already on file, `new_version` or not.  A grid
        that differs is refused with `LabStoreError` unless `new_version` is
        set, because the registered grid is what the trials were run against
        and a quiet redefinition would read as a single design.  With
        `new_version` the changed grid becomes the next version in a row of its
        own and its number is returned; `new_version` with no rule on file has
        nothing to supersede and raises `LabStoreError`.

        The runs already recorded keep the base id, so a trial run against an
        older grid goes on counting in `trials()` rather than being erased.
        """
        _project_id(project_id)
        base = _base_rule_id(rule_id)
        grid_json = _canonical(grid)
        with self.tx() as db:
            current = self._current_version(db, project_id, base)
            if current is None:
                if new_version:
                    raise LabStoreError(
                        f"rule {base!r} is not registered in project "
                        f"{project_id!r}: there is nothing to supersede"
                    )
                db.execute(
                    "INSERT INTO rules(project_id,rule_id,hypothesis,grid_json,"
                    "registered_at) VALUES(?,?,?,?,?)",
                    (
                        project_id,
                        _version_row_id(base, 1),
                        str(hypothesis),
                        grid_json,
                        _iso(datetime.now(timezone.utc)),
                    ),
                )
                return 1
            version, row = current
            if _same_grid(row["grid_json"], grid_json):
                return version
            if not new_version:
                raise LabStoreError(
                    f"rule {base!r} is already registered in project "
                    f"{project_id!r} with a different grid; register a new "
                    f"rule version to change it"
                )
            number = version + 1
            db.execute(
                "INSERT INTO rules(project_id,rule_id,hypothesis,grid_json,"
                "registered_at) VALUES(?,?,?,?,?)",
                (
                    project_id,
                    _version_row_id(base, number),
                    str(hypothesis),
                    grid_json,
                    _iso(datetime.now(timezone.utc)),
                ),
            )
            return number

    def get_rule(self, project_id: str, rule_id: str) -> Optional[dict]:
        """The CURRENT version of a rule, or None when nothing is registered.

        The row carries the base id in `rule_id` whatever version it is, plus a
        `version` key naming that version: 1 for the first registration, the
        number of the newest row once the grid has been changed under
        `new_version`.
        """
        _project_id(project_id)
        base = _base_rule_id(rule_id)
        current = self._current_version(self.conn(), project_id, base)
        if current is None:
            return None
        version, row = current
        return {
            "rule_id": base,
            "hypothesis": row["hypothesis"],
            "grid": json.loads(row["grid_json"]),
            "registered_at": _from_iso(row["registered_at"]),
            "version": version,
        }

    def grid_matches_registered(
        self, project_id: str, rule_id: str, grid: list[dict]
    ) -> bool:
        """True when `grid` is the CURRENT version's pre-registered grid.

        The comparison is the one `register_rule` makes, so a grid supplied as
        `Decimal` values compares the way it was stored.  A rule this project
        has not registered has no grid to match, so that is False.
        """
        _project_id(project_id)
        base = _base_rule_id(rule_id)
        current = self._current_version(self.conn(), project_id, base)
        if current is None:
            return False
        _version, row = current
        return _same_grid(row["grid_json"], _canonical(grid))

    # ------------------------------------------------ runs / trials
    def record_run(
        self,
        project_id: str,
        asset: str,
        interval: str,
        rule_id: str,
        params: dict,
        data_hash: str,
        excess_sharpe: Optional[float],
        result: dict,
    ) -> int:
        """Record one trial run and return its id.

        A run is unique on (project, asset, interval, rule, canonical-JSON
        params, data hash): a repeat returns the id already on file and writes
        nothing, so the same trial seen twice counts once, while the same rule
        over another asset or another interval is its own trial.
        """
        _project_id(project_id)
        _token(asset, "asset")
        _token(interval, "interval")
        _token(rule_id, "rule_id")
        _token(data_hash, "data_hash")
        params_json = _canonical(params if params is not None else {})
        key = (project_id, asset, interval, rule_id, params_json, data_hash)
        lookup = (
            "SELECT id FROM runs WHERE project_id=? AND asset=? AND interval=? "
            "AND rule_id=? AND params_json=? AND data_hash=?"
        )
        with self.tx() as db:
            row = db.execute(lookup, key).fetchone()
            if row is not None:
                return int(row["id"])
            try:
                cur = db.execute(
                    "INSERT INTO runs(project_id,asset,interval,rule_id,"
                    "params_json,data_hash,excess_sharpe,result_json,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        project_id,
                        asset,
                        interval,
                        rule_id,
                        params_json,
                        data_hash,
                        None if excess_sharpe is None else float(excess_sharpe),
                        _canonical(result if result is not None else {}),
                        _iso(datetime.now(timezone.utc)),
                    ),
                )
            except sqlite3.IntegrityError:
                # Another writer recorded the same trial between the lookup and
                # the insert: the row it wrote is the one to report.
                row = db.execute(lookup, key).fetchone()
                if row is None:
                    raise
                return int(row["id"])
            return int(cur.lastrowid)

    def trials(
        self, project_id: str, interval: str, asset_class: str
    ) -> list[TrialRow]:
        """Every run of this project and interval in the asset class, by id.

        The class split is by symbol: a symbol carrying a "-" is crypto, anything
        else is stock.  All assets of the class and all rules are included, and
        no other project's runs are ever returned.
        """
        _project_id(project_id)
        _token(interval, "interval")
        if asset_class not in ASSET_CLASSES:
            raise ValueError(
                f"invalid asset class {asset_class!r}; expected one of "
                f"{list(ASSET_CLASSES)}"
            )
        if asset_class == CRYPTO_CLASS:
            klass = "instr(asset, '-') > 0"
        else:
            klass = "instr(asset, '-') = 0"
        rows = self.conn().execute(
            "SELECT project_id, asset, interval, rule_id, params_json, data_hash, "
            "excess_sharpe FROM runs WHERE project_id=? AND interval=? AND "
            f"{klass} ORDER BY id",
            (project_id, interval),
        )
        return [
            TrialRow(
                project_id=row["project_id"],
                asset=row["asset"],
                interval=row["interval"],
                rule_id=row["rule_id"],
                params=json.loads(row["params_json"]),
                data_hash=row["data_hash"],
                excess_sharpe=(
                    None if row["excess_sharpe"] is None else float(row["excess_sharpe"])
                ),
            )
            for row in rows
        ]

    # ------------------------------------------------ studies
    def record_study(self, project_id: str, name: str, result: dict) -> int:
        """Record one study result and return its id."""
        _project_id(project_id)
        _token(name, "name")
        with self.tx() as db:
            cur = db.execute(
                "INSERT INTO studies(project_id,name,result_json,created_at) "
                "VALUES(?,?,?,?)",
                (
                    project_id,
                    name,
                    _canonical(result if result is not None else {}),
                    _iso(datetime.now(timezone.utc)),
                ),
            )
            return int(cur.lastrowid)

    def studies(self, project_id: str) -> list[dict]:
        """This project's studies, oldest first."""
        _project_id(project_id)
        rows = self.conn().execute(
            "SELECT id, name, result_json, created_at FROM studies "
            "WHERE project_id=? ORDER BY id",
            (project_id,),
        )
        return [
            {
                "id": int(row["id"]),
                "name": row["name"],
                "result": json.loads(row["result_json"]),
                "created_at": _from_iso(row["created_at"]),
            }
            for row in rows
        ]


# ---------------------------------------------------------------- row readers


def _bar(row: sqlite3.Row) -> Bar:
    return Bar(
        symbol=row["symbol"],
        interval=row["interval"],
        ts=_from_iso(row["ts"]),
        open=StoredDecimal(row["open"]),
        high=StoredDecimal(row["high"]),
        low=StoredDecimal(row["low"]),
        close=StoredDecimal(row["close"]),
        volume=StoredDecimal(row["volume"]),
        adj_factor=StoredDecimal(row["adj_factor"]),
    )


def _event(row: sqlite3.Row) -> Event:
    return Event(
        symbol=row["symbol"],
        kind=row["kind"],
        at=_from_iso(row["at"]),
        announced_at=_from_iso(row["announced_at"]),
        session=row["session"],
        note=row["note"],
    )