"""Reconcile: the exchange snapshot is the truth, the store catches up.

One cycle reads the exchange and writes the store's order rows to match it:
`list_open_orders(None)` for the book, then one `get_order` or
`find_by_client_id` per live row that list did not mention, because absence from
the list is not evidence that an order is gone.  A snapshot's `filled_size`,
`filled_value` and `total_fees` are written as ABSOLUTE values, and only through
`store.update_order` (their single writer): a `filled_size` that moved clears
`fills_ok`, so the fills behind it are booked again, and the flag is set only
once the recorded FILL sizes reach it.

A queued cancel is not a settled order: only FILLED, CANCELLED, EXPIRED and
FAILED settle a row, so a `CANCEL_QUEUED` order stays live and its filled
amounts keep being recorded while the cancel is in flight.

Every fill is booked once: a trade already in `fills` is skipped, a trade id
`trades.csv` already holds gets no second row there, and a `trade_type` that is
null or absent counts as a FILL.  `trades.csv` is a convenience file written as
each fill is booked; the authoritative tax export is `/export/fills.csv`, built
from the database with one row per booked fill, so a `trades.csv` row missing a
cycle is never a lost trade.  A fill that cannot be booked is left out and
recorded as a warning: one with no `trade_id` (warned about every cycle, since
there is no id to remember it by), one naming another order id, and one for
another product (the last two once per trade id).  Ids that do not start with
`cb-` are somebody else's orders and are never adopted or touched.

One cycle works on ONE book (`books.py`): the rows it reads, adopts, settles and
books are that book's rows alone, and the exchange it is given has to be that
book's exchange — a dry cycle against the simulator, a live cycle against the
real account, never one against the other.

The `now` passed in is epoch seconds on the same clock as `time.time()`, because
a row's `created_at` is stamped with `time.time()` and the two are subtracted.

Nothing here writes to the exchange.  A kill is the gateway's `cancel_all`, run
after the rows are settled so their state is recorded first, and only for a halt
of that book (its own, or the global kill that halts both) or for an owner whose
bot row says STOPPED; an orphan waits for a halt.  A failing list call propagates
(an empty book must not be assumed), while a failing per-order read is a warning
that skips that one row for the cycle and retries it on the next one.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Optional

from . import money, records
from .books import BOOKS, DRY
from .exchange import PermanentError, TransientError
from .store import (
    CANCELLED,
    EQUITY,
    FAILED,
    FILLED,
    LIVE_STATUSES,
    OPEN,
    PENDING_SUBMIT,
    SPOT,
    STOPPED,
    Store,
)

D = Decimal
log = logging.getLogger("crow_coinbase.reconcile")

# The local status a snapshot settles to, by the exchange's own status string.
# Everything not named here (OPEN, PENDING, QUEUED, CANCEL_QUEUED, a status
# nobody knows) is a resting order: the safe reading of a status this module
# cannot interpret.  A cancel that is only queued is not a cancel yet, so the
# row stays live and the fills landing before the cancel takes effect are still
# booked.
STATUS_BY_EXCHANGE = {
    "FILLED": FILLED,
    "CANCELLED": CANCELLED,
    "EXPIRED": CANCELLED,
    "FAILED": FAILED,
}

# Rows that can still carry fills to book, so every cycle sweeps them: a cycle
# that died between the absolute update and the fill write leaves `fills_ok` at 0
# on a row nobody will settle again.
FILLABLE_STATUSES = (OPEN, FILLED, CANCELLED)

# A `cb-` row written before a send, with no order at the exchange, is given up
# on only after this long (seconds, measured against the `now` the caller passes
# in, which is on the same clock as `time.time()` that stamped `created_at`): an
# answer that was lost may still land, so a short window would fail an order the
# exchange is about to hold.
PENDING_WINDOW_S = 300.0

# `cb-<owner>-<B|S><+level>-<hex>`: the owner part and the shape the engine builds.
OWNER_RE = re.compile(r"^cb-([a-z0-9]{1,16})-")
SHAPE_RE = re.compile(r"^cb-[a-z0-9]{1,16}-([BS])([+-]\d+)-[0-9a-f]+$")
SIDES = {"B": money.BUY, "S": money.SELL}


@dataclass(frozen=True)
class ReconcileReport:
    """What one cycle did, for the caller to log, ring or alert on.

    `updated` counts the order rows inserted (an adopted stranger) or changed
    (a settle, an expiry) this call, each row once however many writes it took.
    `orphans` lists every `cb-` order still live after the sync whose owner is
    `orphan`, so a bot that vanished cannot leave an order resting unnoticed.
    `new_fills` maps an owner to the rows that went from live to terminal
    carrying a fill this call, each re-read after its update, which is the shape
    a strategy needs to react to a fill it did not place itself.
    """

    updated: int
    orphans: list[str]
    new_fills: dict[str, list[dict]]


def reconcile(
    store: Store,
    exchange: Any,
    now: float,
    gateway: Any = None,
    *,
    trades_csv: Path | None = None,
    book: str = DRY,
) -> ReconcileReport:
    """Bring the store's order rows up to date with the exchange, once.

    `now` is the caller's clock: epoch seconds on the same clock as
    `time.time()`, which is what stamps a row's `created_at`, so the two can be
    subtracted.  It decides only whether a row which never reached the exchange
    may be given up on.  `gateway` is the kill path: with none, live orders are
    left resting.  `trades_csv` defaults to the file beside the database, and
    `book` names the book this cycle is about: only that book's rows are read,
    adopted or settled, only that book's fills are booked, and it is written as
    the mode column of every `trades.csv` row.

    *exchange* has to be that book's own exchange.  Reconcile never picks one:
    the caller passes the simulator for the dry book and the live account for the
    live one, so a dry row can never be settled from the real account's answer or
    the other way round.
    """
    if book not in BOOKS:
        raise ValueError(f"unknown book: {book!r}")
    csv_path = (
        Path(trades_csv)
        if trades_csv is not None
        else Path(store.path).parent / "trades.csv"
    )
    open_list = _open_cb_orders(exchange)
    new_fills: dict[str, list[dict]] = {}

    # Rows this cycle wrote, so a row adopted and then settled in the same cycle
    # is counted once rather than once per write.
    touched: set[str] = set()
    _settle_live(store, exchange, open_list, now, new_fills, touched, book)
    _adopt_unknown(store, exchange, open_list, new_fills, touched, book)
    _book_fills(store, exchange, csv_path, book)
    if gateway is not None:
        _kill_gap(store, gateway, open_list, book)

    orphans = [
        row["client_order_id"]
        for row in store.orders(
            owner="orphan", statuses=LIVE_STATUSES, book=book
        )
    ]
    return ReconcileReport(updated=len(touched), orphans=orphans, new_fills=new_fills)


# ---------------------------------------------------------------- the book


def _open_cb_orders(exchange: Any) -> dict[str, dict]:
    """The exchange's open orders that are ours, keyed by client order id.

    A failing list call propagates: a cycle that cannot read the book must not
    settle anything from an empty one.  An id without the `cb-` prefix was not
    placed by the engine (a hand-placed order in the exchange's own UI) and is
    dropped here, so no later step can adopt it or ask about it.
    """
    listed = exchange.list_open_orders(None) or []
    return {
        snap["client_order_id"]: snap
        for snap in listed
        if str(snap.get("client_order_id") or "").startswith("cb-")
    }


def _settle_live(
    store: Store,
    exchange: Any,
    open_list: dict[str, dict],
    now: float,
    new_fills: dict[str, list[dict]],
    touched: set[str],
    book: str,
) -> None:
    """Settle every live row of *book* from the exchange, adding each change to *touched*.

    Only that book's rows are read, so a dry cycle cannot settle a live row (or
    the reverse) from an answer about another account.

    A row in the open list takes that snapshot.  A row the list omits is read on
    its own: with an order id it is never given up on, however old (a lost answer
    is not an order that never landed), and without one it is looked up by client
    order id, where only a row past the window with no order anywhere becomes
    FAILED.  One row's read failing skips that row alone.  Each row adds at most
    one entry, so a row settled in several places is still one changed row.
    """
    for row in store.orders(statuses=LIVE_STATUSES, book=book):
        cid = row["client_order_id"]
        snap = open_list.get(cid)
        if snap is None:
            answered, snap = _absent_snapshot(store, exchange, row)
            if not answered:
                continue
            if snap is None:
                created = row["created_at"] or 0.0
                if _may_be_given_up(row) and now - created > PENDING_WINDOW_S:
                    store.update_order(
                        cid,
                        status=FAILED,
                        note="never reached the exchange",
                    )
                    touched.add(cid)
                continue
        fresh, changed, new_fill = _apply(store, row, snap)
        if changed:
            touched.add(cid)
        if new_fill:
            new_fills.setdefault(row["owner"], []).append(fresh)


def _absent_snapshot(
    store: Store, exchange: Any, row: dict
) -> tuple[bool, Optional[dict]]:
    """The snapshot for a live row the open list did not mention.

    Returns `(answered, snapshot)`; `answered` False means the read raised, so the
    row is left exactly as it is.  A row with an order id is read with
    `get_order`, the one read that answers for a terminal order.  A row without
    one is looked up by its own id, on its own product, from the timestamp it was
    written with.  Nothing found for a resting row is recorded as a warning: no
    exchange read says that order is gone.
    """
    cid = row["client_order_id"]
    order_id = row["order_id"]
    if order_id:
        return _read(
            store,
            f"order {order_id}",
            lambda: exchange.get_order(order_id, row["product"]),
        )
    answered, snap = _read(
        store,
        f"client order id {cid}",
        lambda: exchange.find_by_client_id(cid, row["created_at"], row["product"]),
    )
    if answered and snap is None and row["status"] == OPEN:
        message = f"open order {cid} has no order id and was not found by client id"
        log.warning(message)
        store.event("warn", message)
    return answered, snap


def _may_be_given_up(row: dict) -> bool:
    """True for a row that may become FAILED: pending, sent nowhere, no order id."""
    return row["status"] == PENDING_SUBMIT and not row["order_id"]


def _read(store: Store, what: str, call: Callable[[], Any]) -> tuple[bool, Any]:
    """One per-order exchange read; an exchange error answers nothing.

    Returns `(answered, value)`.  `answered` False means a transient or permanent
    error was raised: it is logged and recorded as a warning, and the caller
    leaves that row alone for this cycle.  A failed read is never allowed to
    expire a row, treat it as a cancellation, or count as an empty fill list,
    because it says nothing about the order.
    """
    try:
        return True, call()
    except (TransientError, PermanentError) as error:
        log.warning("%s: %s", what, error)
        store.event("warn", f"{what}: {error}")
        return False, None


def _apply(store: Store, row: dict, snap: dict) -> tuple[dict, bool, bool]:
    """Write the exchange's snapshot of *row* onto its order row.

    `filled_size`, `filled_value` and `fees` take the snapshot's absolute values
    and are never added to, so a fill the stream also saw cannot double count.  A
    `filled_size` that moved clears `fills_ok`, which is what makes the fills
    behind the new total get booked.  One `store.update_order` is made, and only
    when something differs from the row, so a second cycle over an unchanged book
    writes nothing.

    Returns `(fresh, changed, new_fill)`: the row re-read after the write, whether
    the row was written, and whether a live row settled to a terminal one that
    carries a fill.
    """
    cid = row["client_order_id"]
    status = _status_of(snap)
    order_id = snap.get("order_id") or row["order_id"]
    filled_size = _dec(snap.get("filled_size"))
    fields: dict[str, Any] = {
        "status": status,
        "order_id": order_id,
        "filled_size": filled_size,
        "filled_value": _dec(snap.get("filled_value")),
        "fees": _dec(snap.get("total_fees")),
    }
    changed = (
        status != row["status"]
        or order_id != row["order_id"]
        or filled_size != row["filled_size"]
        or fields["filled_value"] != row["filled_value"]
        or fields["fees"] != row["fees"]
    )
    if changed:
        if filled_size != row["filled_size"]:
            fields["fills_ok"] = 0
        store.update_order(cid, **fields)
    fresh = store.order(cid) or row
    terminal_with_fill = status == FILLED or (
        status == CANCELLED and filled_size > 0
    )
    return fresh, changed, row["status"] in LIVE_STATUSES and terminal_with_fill


def _status_of(snap: dict) -> str:
    """The local status a normalised snapshot settles to."""
    return STATUS_BY_EXCHANGE.get(str(snap.get("status") or ""), OPEN)


def _owner_of(cid: str) -> Optional[str]:
    """The owner part of a `cb-<owner>-...` id, or None when the id does not parse."""
    match = OWNER_RE.match(cid)
    return match.group(1) if match else None


def _dec(value: Any) -> Decimal:
    """A snapshot number as a `Decimal`; an absent one is zero."""
    return D(str(value if value is not None else "0"))


# ---------------------------------------------------------------- adoption


def _adopt_unknown(
    store: Store,
    exchange: Any,
    open_list: dict[str, dict],
    new_fills: dict,
    touched: set[str],
    book: str,
) -> None:
    """Give a row to every one of our open orders on *book* the store has never seen.

    The owner comes from the id when it is `ai` or a bot row exists; anything else
    is an orphan (the bot is gone), which the halt branch alone may sweep.  The
    row is written OPEN with the exchange's own order id and then settled from the
    same snapshot in one further step, so a stranger that is already partly
    filled keeps its filled part.  Its kind is decided by `_product_type_of`: a
    product the exchange's `is_crypto` names is a SPOT row whatever the snapshot
    says, and otherwise a snapshot from a router's merged book carries
    `"account"`, so an order adopted off the equity account is an EQUITY row and
    one off the crypto account a SPOT row; an untagged one asks the exchange.
    Each adopted id is added to *touched* once, however many writes its row took.
    """
    for cid, snap in open_list.items():
        if store.order(cid) is not None:
            continue
        owner = _owner_of(cid)
        if owner == "ai":
            source = "ai"
        else:
            if owner is None or store.get_bot(owner) is None:
                owner = "orphan"
            source = "bot"
        side, level = _shape_of(cid, snap)
        orphan = owner == "orphan"
        product = snap.get("product")
        store.insert_order(
            cid,
            owner,
            source,
            product,
            side,
            level,
            _dec(snap.get("price")),
            _dec(snap.get("size")),
            status=OPEN,
            order_id=snap.get("order_id"),
            note="adopted orphan" if orphan else "adopted",
            book=book,
            product_type=_product_type_of(exchange, product, snap),
        )
        touched.add(cid)
        row = store.order(cid)
        if row is None:
            continue
        fresh, changed, new_fill = _apply(store, row, snap)
        if changed:
            touched.add(cid)
        if new_fill:
            new_fills.setdefault(owner, []).append(fresh)


def _product_type_of(
    exchange: Any, product: Any, snap: Optional[dict] = None
) -> str:
    """The kind an adopted row is written with: the crypto list, then the account.

    A product the exchange's own `is_crypto` names is a crypto product, whatever
    anything else says about it, so that answer is checked FIRST: a router's
    merged book could hand back a stray `"account": "equity"` tag for a coin —
    from a store row, from a hand-written stand-in, from an account that should
    not have listed it — and an EQUITY row on a coin would draw it against the
    equity pool forever after.  The list wins over the tag, never the reverse.

    Otherwise a snapshot from a router's merged book says which account listed it
    (`"account"`), and that is the answer: an order the EQUITY account reported
    is an EQUITY row whatever the configured list says about its product, and an
    order the CRYPTO account reported is a SPOT row even when the store carries a
    stray EQUITY row for that symbol.  Account before list: the account that
    holds the order is the fact, the list is only a rule about new orders.

    An untagged snapshot — a raw adapter's, a simulator's, a hand-written
    stand-in's — falls back to the exchange's own answer about the product: the
    router's public `owns_equity` when it has one, because that is what routes a
    delisted symbol's orders to the equity account, and otherwise an `is_equity`
    predicate.  An exchange with neither says nothing about kinds, so the row is
    SPOT, which is what every row written before equities existed is.
    """
    is_crypto = getattr(exchange, "is_crypto", None)
    if callable(is_crypto) and is_crypto(product):
        return SPOT
    account = (snap or {}).get("account")
    if account == "equity":
        return EQUITY
    if account == "crypto":
        return SPOT
    owns_equity = getattr(exchange, "owns_equity", None)
    if callable(owns_equity):
        return EQUITY if owns_equity(product) else SPOT
    is_equity = getattr(exchange, "is_equity", None)
    if callable(is_equity) and is_equity(product):
        return EQUITY
    return SPOT


def _shape_of(cid: str, snap: dict) -> tuple[str, int]:
    """The side and level an adopted id carries, or the snapshot's own.

    The engine builds every id as `cb-<owner>-<B|S><+level>-<hex>`, so an id that
    does not parse falls back to the exchange's side at level 0 rather than
    guessing from a prefix that may have been hand-written.
    """
    match = SHAPE_RE.match(cid)
    if match is None:
        return str(snap.get("side") or money.BUY), 0
    return SIDES[match.group(1)], int(match.group(2))


# ---------------------------------------------------------------- fills


def _book_fills(store: Store, exchange: Any, trades_csv: Path, book: str) -> None:
    """Book the fills behind every filled row of *book*: `trades.csv`, then the database.

    A row is skipped once `fills_ok` says its booked FILL sizes match the
    `filled_size` the exchange reported, so a cycle over an unchanged book writes
    nothing and a partial fill sitting on a resting order is booked as soon as it
    appears.  A trade already in `fills` (booked by the stream, or by an earlier
    cycle) adds no CSV row of its own, and a trade id the CSV already holds is not
    written there a second time, so a cycle that died between the two writes
    leaves one CSV row and no duplicate.  The authoritative tax export is
    `/export/fills.csv`, built from the database with one row per booked fill:
    this file is a convenience copy that can in principle lag behind it.
    """
    for row in store.orders(statuses=FILLABLE_STATUSES, book=book):
        if row["filled_size"] <= 0 or row["fills_ok"]:
            continue
        order_id = row["order_id"]
        if not order_id:
            continue
        cid = row["client_order_id"]
        answered, fills = _read(
            store,
            f"fills for {order_id}",
            lambda: exchange.fills(order_id, row["product"]),
        )
        if not answered:
            continue
        for fill in fills or []:
            _book_fill(store, row, fill, trades_csv, book)
        if _recorded_fill_size(store, cid) >= row["filled_size"]:
            store.update_order(cid, fills_ok=1)


def _book_fill(store: Store, row: dict, fill: dict, trades_csv: Path, book: str) -> None:
    """Book one exchange fill, unless it is already booked or belongs elsewhere.

    A fill with no `trade_id` cannot be booked and cannot be remembered either,
    so it is warned about on every cycle.  A fill whose `order_id` names a
    different order than the row, and a fill that names a different product than
    the row, are left unbooked — attributing either here would put another
    order's trade in this owner's records — and each of those is warned about
    once per trade id, so a permanent mismatch does not fill the event log every
    cycle.  A trade already in `fills` is skipped in silence: it was booked
    already, by the stream or by an earlier cycle.  The CSV row is written before
    the database row and only when the CSV does not already hold that trade id,
    so a cycle that died between the two writes does not duplicate it.
    """
    trade_id = fill.get("trade_id")
    if not trade_id:
        message = (
            f"fill for order {row['client_order_id']} has no trade id; "
            "left unbooked"
        )
        log.warning(message)
        store.event("warn", message)
        return
    if store.has_fill(trade_id):
        return
    cid = row["client_order_id"]
    order_id = fill.get("order_id")
    if order_id and order_id != row["order_id"]:
        _warn_unbooked(
            store,
            trade_id,
            f"fill {trade_id} is order {order_id} but order {cid} is "
            f"{row['order_id']}; left unbooked",
        )
        return
    product = fill.get("product") or row["product"]
    if product != row["product"]:
        _warn_unbooked(
            store,
            trade_id,
            f"fill {trade_id} is product {product!r} but order {cid} is "
            f"{row['product']!r}; left unbooked",
        )
        return
    if not records.has_trade(trades_csv, trade_id):
        records.append_fill(trades_csv, product, fill, cid, book)
    store.record_fill(fill, cid, book=book)


def _warn_unbooked(store: Store, trade_id: str, message: str) -> None:
    """Record *message* once per trade id, then never again for that trade.

    A fill that cannot be booked is read again on every cycle, so the marker in
    the store's kv table is what keeps one permanent mismatch to one warning.
    """
    key = f"reconcile:unbooked:{trade_id}"
    if store.get(key):
        return
    log.warning(message)
    store.event("warn", message)
    store.put(key, True)


def _recorded_fill_size(store: Store, cid: str) -> Decimal:
    """The traded size booked for *cid*, counting FILL trades only.

    A null or absent `trade_type` is a FILL; a CORRECTION (or any other type) moved
    no base, so it must not count toward the size the order says was filled.
    """
    total = D(0)
    rows = store.conn().execute(
        "SELECT trade_type, size FROM fills WHERE client_order_id=?", (cid,)
    )
    for fill in rows:
        if fill["trade_type"] in (None, "FILL"):
            total += _dec(fill["size"])
    return total


# ---------------------------------------------------------------- kill path


def _kill_gap(store: Store, gateway: Any, open_list: dict[str, dict], book: str) -> None:
    """Sweep *book*'s live orders off the book, through the gateway and nothing else.

    A halt OF THAT BOOK — its own drawdown stop, or the global kill that halts
    both books — sweeps every `cb-` order of that book, orphans and the `ai` owner
    included, and the sweep names the book so the other book's resting orders are
    left where they are.  Otherwise only an owner whose bot row says STOPPED is
    swept.  This runs after the rows are settled, so each row already records the
    state the exchange had before the sweep, and the next cycle settles them from
    the exchange itself.  A failing sweep is recorded as an error and the cycle
    still returns.  The sweep names the book, so a dry cycle never asks the gateway
    to take anything off the live account.
    """
    if not open_list:
        return
    if gateway.is_halted(book):
        _sweep(store, gateway, "all", None, book)
        return
    for owner in _owners_of(store, open_list):
        bot = store.get_bot(owner)
        if bot is not None and bot["status"] == STOPPED:
            _sweep(store, gateway, "owner", owner, book)


def _sweep(
    store: Store, gateway: Any, scope: str, owner: Optional[str], book: str
) -> None:
    """One gateway sweep of *book*; its exception is recorded, never raised.

    The record is an `alert` and carries the error's text: an order the kill path
    could not take off the book is something a reader has to act on, and the
    exchange's own words are what says which call refused it.
    """
    try:
        gateway.cancel_all(scope=scope, owner=owner, book=book)
    except Exception as error:  # noqa: BLE001 - a kill path may not abort the cycle
        message = f"sweep {scope} {owner or '-'} failed: {error}"
        log.error(message)
        store.event("error", message, kind="alert")


def _owners_of(store: Store, open_list: dict[str, dict]) -> list[str]:
    """Each distinct owner of an order in the open list, in the list's own order."""
    owners: list[str] = []
    for cid in open_list:
        row = store.order(cid)
        if row is None or row["owner"] in owners:
            continue
        owners.append(row["owner"])
    return owners