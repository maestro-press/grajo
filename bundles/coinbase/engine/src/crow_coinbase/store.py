"""SQLite system of record: bots, orders, fills, high-water marks, kv, events.

Isolation mode: AUTOCOMMIT (`isolation_level=None`) with EXPLICIT transactions.
Every connection opens in autocommit and `Store.tx()` is the only place that
starts a transaction.  `tx()` runs `BEGIN IMMEDIATE`, so a writer takes the
write lock up front instead of failing late while upgrading a read lock, and it
falls back to a `SAVEPOINT` when the caller already holds a transaction: the
work then joins the caller's transaction and their commit/rollback decides its
fate.  Every method that writes more than one row, or reads then writes
(`create_bot`, `record_fill`, `update_hwm`, ...), runs inside `tx()`.

`orders.filled_size`, `orders.filled_value` and `orders.fees` mirror the
exchange's own order snapshot: `update_order()` is their single writer and
always sets absolute values.  `record_fill()` only books the `fills` table, so a
fill seen once through the stream and once through the reconcile loop is
counted once.

Every order row and every fill row belongs to a book (`books.py`: `dry` or
`live`), and `insert_order()` / `record_fill()` take it as a required keyword:
an order or a fill that cannot name its book is never written.  An order row's
instrument kind (`product_type`: `SPOT` or `EQUITY`) is a required keyword too,
because only its caller knows which instrument it is placing or adopting.  A bot
row carries the book it trades (`mode`) and a capital budget per book, and
`book_epoch()` stamps when a book (re)started counting for an owner, so the rows
of a book the owner has left stop counting.

The database runs in WAL mode (readers never block the writer).  Each thread
gets its own connection through `threading.local`; `Store.conn` is also a valid
`conn_factory` for `DryRunExchange`, and `close()` closes every connection the
store opened.  Money is `Decimal` in Python and TEXT in SQLite (`str(Decimal)`
out, `Decimal(x or "0")` back).  The dry-run exchange keeps its `sim_*` tables
in the same file, created by exchange.py: the names do not clash.

The file's shape is `SCHEMA` — the v1 base tables, created with `IF NOT EXISTS`
so reopening a file is a no-op — followed by the numbered steps in
`migrations.py`, which `_apply_schema` runs once the base tables are there.  A
file with no version row is seeded at 1 and carried to `SCHEMA_VERSION` in that
same open; a file that already records a version is copied beside itself before
the step that moves it forward.
"""

from __future__ import annotations

import contextlib
import contextvars
import itertools
import json
import re
import sqlite3
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable, Optional

from .books import BOOKS
from .migrations import LATEST, migrate

D = Decimal

# local order statuses
PENDING_SUBMIT = (
    "PENDING_SUBMIT"  # written before the API call; resolved by client_order_id
)
OPEN = "OPEN"
FILLED = "FILLED"
CANCELLED = "CANCELLED"
REJECTED = "REJECTED"  # exchange refused it (never live)
FAILED = "FAILED"  # never reached the exchange
LIVE_STATUSES = (PENDING_SUBMIT, OPEN)

# bot statuses
ACTIVE, PAUSED, STOPPED = "ACTIVE", "PAUSED", "STOPPED"

# the product kinds an order row may carry: the crypto pair, and an equity
SPOT = "SPOT"
EQUITY = "EQUITY"
PRODUCT_TYPES = (SPOT, EQUITY)

# opposite-order bookkeeping on a filled order
OPP_TODO, OPP_PLACED, OPP_SKIPPED = 0, 1, 2

# owners that are not bots and never hold a capital budget
RESERVED_OWNERS = ("ai", "orphan")
BOT_ID_RE = re.compile(r"^[a-z0-9]{1,16}$")

SCHEMA_VERSION = LATEST

# Applied with CREATE TABLE IF NOT EXISTS, so reopening a file is a no-op.
SCHEMA = (
    """CREATE TABLE IF NOT EXISTS bots (
         id TEXT PRIMARY KEY, product TEXT, strategy TEXT, params_json TEXT,
         state_json TEXT, capital_quote TEXT, capital_base TEXT, status TEXT,
         init_done INTEGER DEFAULT 0, created_at REAL)""",
    """CREATE TABLE IF NOT EXISTS orders (
         client_order_id TEXT PRIMARY KEY, order_id TEXT, owner TEXT, source TEXT,
         product TEXT, side TEXT, level INTEGER, price TEXT, size TEXT, status TEXT,
         parent_cid TEXT, created_at REAL, updated_at REAL,
         filled_size TEXT DEFAULT '0', filled_value TEXT DEFAULT '0',
         fees TEXT DEFAULT '0', basis_per_base TEXT, consumes_fill TEXT,
         opposite INTEGER DEFAULT 0, fills_ok INTEGER DEFAULT 0, note TEXT)""",
    """CREATE INDEX IF NOT EXISTS orders_created_at ON orders(created_at)""",
    """CREATE TABLE IF NOT EXISTS fills (
         trade_id TEXT PRIMARY KEY, order_id TEXT, client_order_id TEXT, owner TEXT,
         side TEXT, size TEXT, price TEXT, commission TEXT, trade_time TEXT,
         recorded_at REAL, product TEXT, trade_type TEXT)""",
    """CREATE TABLE IF NOT EXISTS hwm (owner TEXT PRIMARY KEY, value TEXT)""",
    """CREATE TABLE IF NOT EXISTS events (ts REAL, level TEXT, message TEXT)""",
    """CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT)""",
    """CREATE TABLE IF NOT EXISTS schema_version (version INTEGER)""",
)

ORDER_DECIMALS = ("price", "size", "filled_size", "filled_value", "fees")

# The vocabulary an event's kind comes from: one name per thing that makes an
# event, so a reader can pick the events it cares about without matching on a
# message.  `alert` is what a reader has to act on (a book that went idle, an
# exchange short of its owners, follow-ups given up on, a sweep that failed, a
# cycle that never got through) and `bot_paused` is one bot stopped (its own
# drawdown, its strategy's pause, its own cycle failing, follow-ups offered
# again); a real trading halt — a book's drawdown stop and the kill switch — is
# `halt`.  `EVENT_KIND_INFO` is the catch-all beside them — the kind of an event
# a caller did not classify — and is deliberately not one of the thirteen.
EVENT_KINDS = (
    "fill",
    "refusal",
    "halt",
    "watchdog",
    "ai_preview",
    "ai_placed",
    "ai_expired",
    "trailing_hold",
    "credentials",
    "live_switch",
    "caps",
    "alert",
    "bot_paused",
)
EVENT_KIND_INFO = "info"

# The source tag an event carries when the request that wrote it came from an
# MCP client, and the key it is stored under in the event's payload.  The tag
# lives in a `ContextVar` rather than in a parameter, so the code that writes an
# event (a store setter, a gateway step) never has to know how it was reached:
# the one middleware that serves the surface sets it for the duration of a
# request and resets it afterwards, so no cycle thread and no watchdog thread
# ever sees it.  The caller's own `source` key is overwritten by it: the tag is
# the engine's, not the payload's.
EVENT_SOURCE: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "crow_event_source", default=None
)
EVENT_SOURCE_MCP = "mcp"
EVENT_SOURCE_FIELD = "source"

# Event retention: how long an event is kept by default, the kv key holding when
# the daily prune last ran, and the least time between two of them.
EVENT_RETENTION_DAYS = 90
EVENTS_PRUNED_KEY = "events_pruned_at"
EVENT_RETENTION_INTERVAL_S = 86400

# The kv key an owner's book epoch lives under: `book_epoch:<book>:<owner>`.
BOOK_EPOCH_PREFIX = "book_epoch:"

# The kv key the lease's cursor lives under.  Event retention reads it: a reader
# that has read up to that id has not read past it, so nothing above it may go.
LEASE_CURSOR_KEY = "lease_cursor"

# The range a stored lease cursor is clamped into before retention binds it.  The
# floor is "has read nothing", so a stored cursor that cannot be used deletes
# nothing rather than everything; the ceiling is the largest integer sqlite can
# bind, so even a hand-edited value past 64 bits binds instead of raising.
MIN_LEASE_CURSOR = 0
MAX_LEASE_CURSOR = 2**63 - 1

# How many times the WAL switch is tried while another engine holds the file, and
# the one path that is not a file (where sqlite's own answer is `memory`).
WAL_ATTEMPTS = 5
MEMORY_PATH = ":memory:"

# The two sqlite result codes the WAL switch is retried on, by their own numbers
# (sqlite3.h): BUSY and LOCKED are the other engine holding the file, and the
# stored code's low byte is what is compared, so an extended code counts too.
SQLITE_BUSY = 5
SQLITE_LOCKED = 6


class Store:
    """The engine's database file. Thread-safe: one connection per thread."""

    def __init__(self, path: Path | str):
        self.path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._conns: list[sqlite3.Connection] = []
        self._savepoints = itertools.count(1)
        self._order_columns: Optional[set[str]] = None
        self._apply_schema()

    # ------------------------------------------------ connections
    def _connect(self) -> sqlite3.Connection:
        # check_same_thread=False: `close()` may run on a different thread than the
        # one that opened a connection, and it closes every connection from that
        # closing thread.  Each connection is otherwise only ever used by its own
        # thread (looked up through `threading.local`).
        # `timeout` is the one and only place the busy timeout is set (30 s), so a
        # `BEGIN IMMEDIATE` that finds another writer waits instead of failing.
        db = sqlite3.connect(
            self.path,
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        db.row_factory = sqlite3.Row
        # Switching into WAL is the one statement on this path that needs the
        # whole file rather than a row lock, and the busy timeout does not cover
        # it: an engine opening the same file at the same moment can find the
        # switch already in progress and answer SQLITE_BUSY or SQLITE_LOCKED.
        # That is the other engine's success, so exactly those two codes are
        # retried (compared on the low byte, so an extended code counts too) and
        # nothing else is: any other failure is a database this store cannot use,
        # and it is closed and raised at once instead of being retried into a
        # mask.  Once the statement answers, its own result row says which mode
        # the file is in: anything but `wal` is refused, because a store that
        # silently runs in another journal mode is not the store this file's
        # readers were built for.  The in-memory database is the one exception,
        # where sqlite answers `memory` and there is no file to switch.
        attempt = 0
        while True:
            try:
                row = db.execute("PRAGMA journal_mode=WAL").fetchone()
            except sqlite3.OperationalError as error:
                if not _wal_retryable(error) or attempt >= WAL_ATTEMPTS - 1:
                    db.close()
                    raise
                attempt += 1
                time.sleep(0.02 * attempt)
                continue
            mode = "" if row is None else str(row[0])
            if _wal_expected(self.path, mode):
                return db
            db.close()
            raise sqlite3.OperationalError(
                "could not switch the database to WAL mode"
            )

    def conn(self) -> sqlite3.Connection:
        """This thread's connection, created on first use (usable as conn_factory)."""
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
        """One write transaction: BEGIN IMMEDIATE, or a savepoint when already in one.

        Cleanup never masks the caller's error: a failing ROLLBACK / RELEASE is
        suppressed so the original exception keeps propagating.
        """
        db = self.conn()
        if db.in_transaction:
            name = f"crow_sp_{next(self._savepoints)}"
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
        """Create the v1 base tables, seed a new file's version, then migrate.

        `SCHEMA` IS the v1 schema: every step after it lives in `migrations.py`,
        which also refuses a file a newer build wrote.  A file with no version
        row is brand new (or carries the base tables and no version at all), so
        it is seeded at 1 and migrated with no path: there is no earlier state to
        copy beside it.  Any other file keeps its own recorded version and gets
        the copy a step takes before it runs.
        """
        seeded = False
        with self.tx() as db:
            for statement in SCHEMA:
                db.execute(statement)
            row = db.execute(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
            ).fetchone()
            if row is None:
                db.execute("INSERT INTO schema_version(version) VALUES(?)", (1,))
                seeded = True
        migrate(self.conn(), None if seeded else self.path)

    def schema_version(self) -> int:
        row = self.conn().execute(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
        ).fetchone()
        return int(row[0]) if row else SCHEMA_VERSION

    def order_columns(self) -> set[str]:
        """The real `orders` column names, read with PRAGMA and cached once."""
        if self._order_columns is None:
            self._order_columns = {
                row[1] for row in self.conn().execute("PRAGMA table_info(orders)")
            }
        return self._order_columns

    # ------------------------------------------------ bots
    def create_bot(
        self,
        bot_id: str,
        product: str,
        strategy: str,
        params: dict,
        capital_quote: Decimal,
        capital_base: Decimal,
    ) -> dict:
        """Insert a bot and return it. Validates the id and the capital budget."""
        if not isinstance(bot_id, str) or not BOT_ID_RE.fullmatch(bot_id):
            raise ValueError(f"invalid bot id: {bot_id!r}")
        if bot_id in RESERVED_OWNERS:
            raise ValueError(f"reserved bot id: {bot_id!r}")
        quote, base = D(capital_quote), D(capital_base)
        if quote < 0 or base < 0:
            raise ValueError(f"capital must not be negative: {quote} / {base}")
        now = time.time()
        with self.tx() as db:
            if (
                db.execute("SELECT 1 FROM bots WHERE id=?", (bot_id,)).fetchone()
                is not None
            ):
                raise ValueError(f"bot already exists: {bot_id!r}")
            db.execute(
                "INSERT INTO bots(id,product,strategy,params_json,state_json,"
                "capital_quote,capital_base,status,init_done,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,0,?)",
                (
                    bot_id,
                    product,
                    strategy,
                    json.dumps(params or {}),
                    json.dumps({}),
                    str(quote),
                    str(base),
                    ACTIVE,
                    now,
                ),
            )
        return self.get_bot(bot_id)

    def get_bot(self, bot_id: str) -> Optional[dict]:
        row = self.conn().execute("SELECT * FROM bots WHERE id=?", (bot_id,)).fetchone()
        return _bot(row) if row else None

    def list_bots(self) -> list[dict]:
        rows = self.conn().execute("SELECT * FROM bots ORDER BY created_at, id")
        return [_bot(r) for r in rows]

    def set_bot_status(self, bot_id: str, status: str) -> None:
        self.conn().execute("UPDATE bots SET status=? WHERE id=?", (status, bot_id))

    def set_bot_params(self, bot_id: str, params: dict) -> None:
        """Replace a bot's params, encoded the way `create_bot` encodes them."""
        self.conn().execute(
            "UPDATE bots SET params_json=? WHERE id=?",
            (json.dumps(params or {}), bot_id),
        )

    def set_bot_state(self, bot_id: str, state: dict) -> None:
        self.conn().execute(
            "UPDATE bots SET state_json=? WHERE id=?",
            (json.dumps(state or {}), bot_id),
        )

    def set_init_done(self, bot_id: str, flag: bool = True) -> None:
        """Mark the first book done (the default), or unmark it with `flag=False`."""
        self.conn().execute(
            "UPDATE bots SET init_done=? WHERE id=?", (1 if flag else 0, bot_id)
        )

    def set_bot_book(
        self,
        bot_id: str,
        *,
        mode: str,
        capital_quote: Optional[Decimal],
        capital_base: Optional[Decimal],
        live_capital_quote: Optional[Decimal],
        live_capital_base: Optional[Decimal],
    ) -> None:
        """Write which book a bot trades and both of its capital budgets, once.

        `mode` is "dry" or "live"; anything else is refused before a write.  An
        amount of `None` is stored as NULL, which is how a book with no capital
        of its own is recorded (the live budget of a bot that never traded live,
        the base budget of a bot rebased to a quote-only mix).  This is an
        ordinary setter: inside a caller's transaction it joins it, so a switch
        writes these five columns and everything else it needs as one step.
        """
        if mode not in BOOKS:
            raise ValueError(f"unknown bot mode: {mode!r}")
        self.conn().execute(
            "UPDATE bots SET mode=?, capital_quote=?, capital_base=?, "
            "live_capital_quote=?, live_capital_base=? WHERE id=?",
            (
                mode,
                _money(capital_quote),
                _money(capital_base),
                _money(live_capital_quote),
                _money(live_capital_base),
                bot_id,
            ),
        )

    # ------------------------------------------------ orders
    def insert_order(
        self,
        cid: str,
        owner: str,
        source: str,
        product: str,
        side: str,
        level: int,
        price: Decimal,
        size: Decimal,
        status: str = PENDING_SUBMIT,
        order_id: Optional[str] = None,
        parent_cid: Optional[str] = None,
        consumes_fill: Optional[str] = None,
        basis_per_base: Optional[Decimal] = None,
        note: Optional[str] = None,
        *,
        book: str,
        product_type: str,
    ) -> None:
        """Record a local order row before it is (or is not) sent to the exchange.

        `book` is required and names the book the row belongs to ("dry" or
        "live"): an order row that names no book, or a book this engine does not
        know, is refused with `ValueError` before anything is written.  Nothing
        infers the book from the owner, so a row can never land on the book the
        caller did not mean.

        `product_type` is the row's instrument kind and is required, exactly
        `SPOT` or `EQUITY` (upper-case, no padding): the caller that places or
        adopts the order is the only place that knows which instrument it is, so
        there is no default to fall back on, and anything else is refused with
        `ValueError` before anything is written, rather than left to the column's
        own CHECK.

        EVERY order's client order id starts with `cb-`: the engine's own ids all
        carry that prefix, so an id without it is not recognisably ours.

        For every owner except `orphan` the id must also carry the owner, i.e.
        `cb-<owner>-...` — any other owner part would make the reconcile loop
        attribute the order to the wrong owner.  An `orphan` order (a fill/order
        the exchange reported whose bot row is gone) still needs a `cb-` id, e.g.
        one built from the vanished bot's id (`cb-b9-B-1-000000000001`), but it
        need not carry the literal string `orphan`.

        Raises `ValueError` (nothing written) for any other id.
        """
        if book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        if product_type not in PRODUCT_TYPES:
            raise ValueError(
                f"unknown product type: {product_type!r}; a row is written as "
                f"one of {', '.join(PRODUCT_TYPES)}"
            )
        cid = str(cid)
        prefix = f"cb-{owner}-"
        if not cid.startswith("cb-"):
            raise ValueError(f"client order id {cid!r} must start with 'cb-'")
        if owner != "orphan" and not cid.startswith(prefix):
            raise ValueError(f"client order id {cid!r} must start with {prefix!r}")
        now = time.time()
        self.conn().execute(
            "INSERT INTO orders(client_order_id,order_id,owner,source,product,side,"
            "level,price,size,status,parent_cid,created_at,updated_at,basis_per_base,"
            "consumes_fill,note,book,product_type) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                cid,
                order_id,
                owner,
                source,
                product,
                side,
                level,
                str(price),
                str(size),
                status,
                parent_cid,
                now,
                now,
                None if basis_per_base is None else str(basis_per_base),
                consumes_fill,
                note,
                book,
                product_type,
            ),
        )

    def update_order(self, cid: str, **fields: Any) -> None:
        """Patch an order row; Decimals are stored as TEXT and updated_at is bumped.

        This is the SINGLE writer of `filled_size`, `filled_value` and `fees`:
        those columns mirror the exchange's order snapshot, so they are set to
        absolute values here and are never incremented (`record_fill` writes only
        the `fills` table).  Field names are checked against the real `orders`
        columns, and `client_order_id` itself is not patchable; an unknown name
        raises `ValueError` and writes nothing.
        """
        if not fields:
            return
        allowed = self.order_columns()
        for name in fields:
            if name == "client_order_id" or name not in allowed:
                raise ValueError(f"cannot update order column: {name!r}")
        fields["updated_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        vals = [str(v) if isinstance(v, Decimal) else v for v in fields.values()]
        with self.tx() as db:
            db.execute(f"UPDATE orders SET {cols} WHERE client_order_id=?", (*vals, cid))

    def order(self, cid: str) -> Optional[dict]:
        row = self.conn().execute(
            "SELECT * FROM orders WHERE client_order_id=?", (cid,)
        ).fetchone()
        return _order(row) if row else None

    def orders(
        self,
        owner: Optional[str] = None,
        statuses: Optional[Iterable[str]] = None,
        product: Optional[str] = None,
        book: Optional[str] = None,
    ) -> list[dict]:
        """Order rows, oldest first, optionally one owner's, some statuses', one
        product's, and one book's: each argument given is a filter, and a book of
        `None` reads both books."""
        q, args = "SELECT * FROM orders WHERE 1=1", []
        if owner is not None:
            q += " AND owner=?"
            args.append(owner)
        if statuses:
            st = list(statuses)
            q += f" AND status IN ({','.join('?' * len(st))})"
            args += st
        if product is not None:
            q += " AND product=?"
            args.append(product)
        if book is not None:
            q += " AND book=?"
            args.append(book)
        q += " ORDER BY created_at, client_order_id"
        return [_order(r) for r in self.conn().execute(q, args)]

    def product_of_order(self, order_id: str) -> Optional[str]:
        """The product of the row whose exchange order id is *order_id*.

        An order id is what a routed read or cancel may be given without its
        product, so this is how a caller learns which account to ask.  An id no
        row carries — and no id at all — answers None: an unknown id is not a
        product, and nothing here guesses one.
        """
        row = self.conn().execute(
            "SELECT product FROM orders WHERE order_id=? LIMIT 1", (order_id,)
        ).fetchone()
        return row["product"] if row else None

    def has_equity_rows(self, product: str) -> bool:
        """True when ANY row of *product* is an EQUITY row.

        The question is history, not a decision about trading: a filled or
        cancelled EQUITY row — on either book, under any owner — still has
        fills, shares and an adoption record on the equity account, so a read or
        a cancel about the product has to reach that account.  A product whose
        rows are all SPOT, and one with no rows at all, answer False.
        """
        row = self.conn().execute(
            "SELECT 1 FROM orders WHERE product=? AND product_type=? LIMIT 1",
            (product, EQUITY),
        ).fetchone()
        return row is not None

    # ------------------------------------------------ fills
    def record_fill(self, fill: dict, cid: str, *, book: str) -> bool:
        """Book one exchange fill into `fills` exactly once.

        Returns True when a row was inserted and False when the trade_id was
        already booked (nothing written).  Raises `KeyError` for an unknown
        client order id (nothing written).  The owner is copied from the order
        row, so a fill keeps its owner even after that bot's row is gone.

        `book` is required and names the book the fill belongs to.  It has to be
        the book the order row is on: a fill for an order on one book booked on
        the other would put one book's trade in the other's records, so a
        mismatch is refused with `ValueError` (nothing written), as is a book
        this engine does not know.

        A fill carrying a `product` that differs from the order row's product is
        refused with `ValueError` (nothing written): a fill belongs to its order's
        product.  When the fill carries no product, the order's product is used.

        This never writes `orders`: `filled_size` / `filled_value` / `fees` are
        the exchange's snapshot and only `update_order` sets them, so a fill seen
        by both the stream and the reconcile loop is counted once.

        A fill that IS booked writes one `fill` event in the same transaction —
        its owner, its side, size and price, and the ids a reader follows — so a
        booked trade is announced exactly once and a trade id that was already
        booked announces nothing.
        """
        if book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        now = time.time()
        with self.tx() as db:
            row = db.execute(
                "SELECT owner, product, book FROM orders WHERE client_order_id=?",
                (cid,),
            ).fetchone()
            if row is None:
                raise KeyError(cid)
            if book != row["book"]:
                raise ValueError(
                    f"fill trade_id {fill['trade_id']!r} is for order {cid!r} on "
                    f"the {row['book']!r} book, not {book!r}"
                )
            product = fill.get("product") or row["product"]
            if product != row["product"]:
                raise ValueError(
                    f"fill trade_id {fill['trade_id']!r} product {product!r} does "
                    f"not match order {cid!r} product {row['product']!r}"
                )
            size_text = str(D(fill["size"]))
            price_text = str(D(fill["price"]))
            cur = db.execute(
                "INSERT OR IGNORE INTO fills(trade_id,order_id,client_order_id,owner,"
                "side,size,price,commission,trade_time,recorded_at,product,"
                "trade_type,book) VALUES(:trade_id,:order_id,:cid,:owner,:side,"
                ":size,:price,:commission,:trade_time,:recorded_at,:product,"
                ":trade_type,:book)",
                {
                    "trade_id": fill["trade_id"],
                    "order_id": fill["order_id"],
                    "cid": cid,
                    "owner": row["owner"],
                    "side": fill["side"],
                    "size": size_text,
                    "price": price_text,
                    "commission": str(D(fill["commission"])),
                    "trade_time": fill["trade_time"],
                    "recorded_at": now,
                    "product": product,
                    "trade_type": fill.get("trade_type"),
                    "book": book,
                },
            )
            if cur.rowcount != 1:
                return False
            # The fill and the record of it are one write: this event joins the
            # transaction above, so a fill that is booked is announced and a
            # trade id that was already booked announces nothing.
            self.event(
                "info",
                f"{row['owner']}: {fill['side']} {size_text} {product} "
                f"filled at {price_text}",
                kind="fill",
                owner=row["owner"],
                data={
                    "cid": cid,
                    "trade_id": str(fill["trade_id"]),
                    "product": product,
                    "side": fill["side"],
                    "size": size_text,
                    "price": price_text,
                    "book": book,
                },
            )
            return True

    def has_fill(self, trade_id: str) -> bool:
        return (
            self.conn()
            .execute("SELECT 1 FROM fills WHERE trade_id=?", (trade_id,))
            .fetchone()
            is not None
        )

    # ------------------------------------------------ high-water mark
    #
    # One mark per (book, owner): the dry book's marks are the ones a P1 file
    # already held, so every caller that names no book keeps reading and writing
    # exactly the row it did before.
    def hwm(self, owner: str, book: str = "dry") -> Optional[Decimal]:
        row = self.conn().execute(
            "SELECT value FROM hwm WHERE book=? AND owner=?", (book, owner)
        ).fetchone()
        return D(row["value"]) if row and row["value"] is not None else None

    def update_hwm(
        self, owner: str, equity: Decimal, book: str = "dry"
    ) -> Decimal:
        """Ratchet the owner's high-water mark up to *equity* and return it."""
        value = D(equity)
        with self.tx() as db:
            row = db.execute(
                "SELECT value FROM hwm WHERE book=? AND owner=?", (book, owner)
            ).fetchone()
            previous = D(row["value"]) if row and row["value"] is not None else None
            new = value if previous is None else max(previous, value)
            db.execute(
                "INSERT INTO hwm(book,owner,value) VALUES(?,?,?) "
                "ON CONFLICT(book,owner) DO UPDATE SET value=excluded.value",
                (book, owner, str(new)),
            )
        return new

    def reset_hwm(self, owner: str, book: str) -> None:
        """Delete one (book, owner) high-water mark; a mark that is absent is a no-op."""
        if book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        self.conn().execute(
            "DELETE FROM hwm WHERE book=? AND owner=?", (book, owner)
        )

    # ------------------------------------------------ kv / events
    def get(self, key: str, default=None):
        """JSON-decode a kv entry, or return *default* when the key is absent."""
        row = self.conn().execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def put(self, key: str, value) -> None:
        self.conn().execute(
            "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)",
            (key, json.dumps(value)),
        )

    def book_epoch(self, book: str, owner: str) -> float:
        """When *owner*'s *book* started counting, in epoch seconds (0.0 default).

        An order row older than its book's epoch is not part of that book: it
        belongs to a period the owner has already left, and a switch writes a
        fresh epoch so the rows of the book it left stop counting.  A key that
        is absent, or not a number (a hand-edited file), is 0.0: every row
        counts, which is what every file written before epochs existed means.
        """
        if book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        value = self.get(f"{BOOK_EPOCH_PREFIX}{book}:{owner}")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return 0.0
        return float(value)

    def set_book_epoch(self, book: str, owner: str, when: float) -> None:
        """Stamp when *owner*'s *book* (re)started counting, in epoch seconds."""
        if book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        self.put(f"{BOOK_EPOCH_PREFIX}{book}:{owner}", float(when))

    def event(
        self,
        level: str,
        message: str,
        *,
        kind: str = EVENT_KIND_INFO,
        owner: Optional[str] = None,
        data: Optional[dict] = None,
    ) -> None:
        """Record one event: a level, what sort of event it is, and what is known.

        `kind` says what sort of event it is — one of `EVENT_KINDS`, or the
        catch-all `EVENT_KIND_INFO` for an event nobody classified — `owner`
        whose it is when it belongs to one, and `data` is stored as JSON so a
        reader can carry structured detail beside the message.  The timestamp is
        the wall clock, the one every other row is stamped with.

        An event written while the request being served carried the MCP source
        header (`EVENT_SOURCE`) gets `"source": "mcp"` merged into its payload,
        whatever the caller put under that key: the tag says how this event was
        reached, so it is the engine's to write.  Nothing else sets that
        variable, so an event a cycle or the watchdog writes is never tagged.

        Written on this thread's connection, so inside a caller's transaction
        (`record_fill`) it joins it and commits or rolls back with it.
        """
        payload = dict(data) if data else {}
        if EVENT_SOURCE.get() == EVENT_SOURCE_MCP:
            payload[EVENT_SOURCE_FIELD] = EVENT_SOURCE_MCP
        self.conn().execute(
            "INSERT INTO events(ts,level,kind,owner,message,data_json) "
            "VALUES(?,?,?,?,?,?)",
            (time.time(), level, kind, owner, message, json.dumps(payload)),
        )

    # ------------------------------------------------ event retention
    def prune_events(
        self, now: Optional[float] = None, days: int = EVENT_RETENTION_DAYS
    ) -> int:
        """Delete events older than *days* and answer how many went.

        The single newest event (the highest id) is always kept, whatever its
        age: an engine whose clock jumped, or one that only ever wrote old
        timestamps, must not end up with an empty history.  A row with no
        timestamp is left alone rather than read as ancient.

        The other floor is the lease cursor: once the kv key `lease_cursor` holds
        an integer, no event with a greater id is deleted, however old it is,
        because a reader working forward from that cursor has not read past it
        yet.  With no cursor (the key absent) retention is the age rule alone,
        exactly as it was before the lease existed.

        A stored cursor this store cannot use never raises here, and never
        deletes more than a cursor of 0 would: a value that is not an integer, or
        one below 0, is read as 0 (so nothing at all goes), and one above the
        largest integer sqlite can bind is clamped to that bound before it is
        bound.  Failing safe is deleting nothing, not deleting everything.
        """
        stamp = time.time() if now is None else float(now)
        cutoff = stamp - days * 86400
        with self.tx() as db:
            newest = db.execute("SELECT MAX(id) FROM events").fetchone()[0]
            if newest is None:
                return 0
            cursor = _lease_cursor(db)
            if cursor is None:
                cur = db.execute(
                    "DELETE FROM events WHERE id<>? AND ts IS NOT NULL AND ts<?",
                    (int(newest), cutoff),
                )
            else:
                cur = db.execute(
                    "DELETE FROM events WHERE id<>? AND id<=? "
                    "AND ts IS NOT NULL AND ts<?",
                    (int(newest), int(cursor), cutoff),
                )
            return cur.rowcount

    def prune_events_daily(self, now: Optional[float] = None) -> int:
        """Run `prune_events` at most once per 24 h and answer what it deleted.

        The last run is remembered in the kv key `events_pruned_at` (a float
        timestamp), so the ordinary case in a cycle is one read and no delete.
        The stamp is written only after the prune, so a prune that failed is
        retried by the next cycle instead of being skipped for a day.  A stamp
        that lies AFTER the current time (a clock that moved backwards, or a
        stamp written from the future) counts as due rather than as a fresh run:
        its elapsed time is negative, and reading that as "just ran" would stop
        the prune until the clock caught up with it again.
        """
        stamp = time.time() if now is None else float(now)
        last = self.get(EVENTS_PRUNED_KEY)
        if isinstance(last, bool) or not isinstance(last, (int, float)):
            last_at = None
        else:
            last_at = float(last)
        elapsed = None if last_at is None else stamp - last_at
        if elapsed is not None and 0 <= elapsed < EVENT_RETENTION_INTERVAL_S:
            return 0
        deleted = self.prune_events(stamp)
        self.put(EVENTS_PRUNED_KEY, stamp)
        return deleted


def _bot(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "product": row["product"],
        "strategy": row["strategy"],
        "params": json.loads(row["params_json"] or "{}"),
        "state": json.loads(row["state_json"] or "{}"),
        "capital_quote": D(row["capital_quote"] or "0"),
        "capital_base": D(row["capital_base"] or "0"),
        "status": row["status"],
        "init_done": bool(row["init_done"]),
        "created_at": row["created_at"],
        "mode": row["mode"],
        "live_capital_quote": _optional_money(row["live_capital_quote"]),
        "live_capital_base": _optional_money(row["live_capital_base"]),
    }


def _money(value: Any) -> Optional[str]:
    """A money value as the TEXT a column holds, or None for a NULL column."""
    return None if value is None else str(D(value))


def _optional_money(value: Any) -> Optional[Decimal]:
    """A money column read back: a `Decimal`, or None when the column is NULL."""
    return None if value is None else D(value)


def _lease_cursor(db: sqlite3.Connection) -> Optional[int]:
    """The lease cursor stored in `kv`, clamped to what sqlite can bind.

    None is "no cursor at all": the key is absent, which is the retention this
    table had before the lease existed (the age rule alone).  A key that is there
    but unusable — not a JSON value, not an integer, a bool, a value below 0 — is
    read as 0, the cursor of a reader that has read nothing, so retention deletes
    nothing above it rather than everything.  A value above the largest integer
    sqlite can bind is clamped to that bound so the statement binds and nothing
    above it can be deleted.  A cursor of 0 is a real cursor either way.
    """
    row = db.execute(
        "SELECT value FROM kv WHERE key=?", (LEASE_CURSOR_KEY,)
    ).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(row["value"])
    except (TypeError, ValueError):
        return MIN_LEASE_CURSOR
    if isinstance(value, bool) or not isinstance(value, int):
        return MIN_LEASE_CURSOR
    if value < MIN_LEASE_CURSOR:
        return MIN_LEASE_CURSOR
    if value > MAX_LEASE_CURSOR:
        return MAX_LEASE_CURSOR
    return value


def _wal_retryable(error: sqlite3.OperationalError) -> bool:
    """True only for SQLITE_BUSY or SQLITE_LOCKED: another engine holds the file.

    The low byte of `sqlite_errorcode` is compared, so an extended code (a busy
    with its own detail) counts as the busy it is, and a code sqlite did not
    report is not retried at all.
    """
    code = getattr(error, "sqlite_errorcode", None)
    if isinstance(code, bool) or not isinstance(code, int):
        return False
    return (code & 0xFF) in (SQLITE_BUSY, SQLITE_LOCKED)


def _wal_expected(path: str, mode: str) -> bool:
    """Whether the journal mode a file reported is the one this store runs in."""
    found = mode.strip().lower()
    if found == "wal":
        return True
    return path == MEMORY_PATH and found == "memory"


def _order(row: sqlite3.Row) -> dict:
    o = dict(row)
    for k in ORDER_DECIMALS:
        o[k] = D(o[k] or "0")
    o["basis_per_base"] = D(o["basis_per_base"]) if o["basis_per_base"] else None
    return o