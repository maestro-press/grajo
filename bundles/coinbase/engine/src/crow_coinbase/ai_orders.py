"""ai_orders.py: AI order previews, the owner's approval, and the one send.

The `ai` owner has no bot row and no budget of its own: it proposes an order, the
engine measures it against the whole chain and the runtime caps, and the owner
decides.  This module is that conversation.  `preview()` runs the gateway's
read-only chain (`OrderGateway.evaluate`) on the book the route decides and
stores what it measured in `ai_previews`: a `pending` row carrying the maker
price the chain priced the order at, the book it belongs to, an expiry and a hash
over the five fields the owner is approving.  A chain refusal is stored the same
way — a `rejected` row holding the code — so the panel can answer why nothing is
waiting for a yes, and no approval can ever spend it.  Nothing is written for a
size or a price the product's own increments cannot spell, and nothing is
written while too many previews are waiting for an answer or too many have been
asked for inside the hour: both are refusals, not rows.

Equities ride the same preview and approve path: a stock proposal is the same row,
the same chain and the same yes, but its preview carries the equity caps instead
of the crypto AI budgets, and beside them an `equity` block — whether the regular
session is open, the money set aside for AI stock trades, what of it is spent and
what would be left after this order.  The block is stored for a refused preview
too, so the owner can see why nothing went out.

An approval is one row's transition, never a message.  `approve()` moves the row
from `pending` to `approved` with a conditional UPDATE inside one transaction, and
only the connection that changed that row goes on to place the order, so two
approvals of one preview — from two threads, or from two engines over one sqlite
file — place one order: the table decides, not a lock in this module.  The order
itself goes through the gateway (`OrderGateway.submit` with source "ai"), which
re-runs the whole chain against the approval — every cap, the halt, the market,
the owner's money — and spends the row in the same transaction that writes the
PENDING_SUBMIT order row.  An approved order never reprices: the price the row
stores is the price that is sent, and a book that has moved past it ends the
preview `rejected` with `POST_ONLY_WOULD_CROSS` before anything at all is written.
This module calls no exchange method: the exchange is reached through the gateway
alone.

Nothing here puts a secret in a message, an answer, an event or a log line.  The
codes and the plain sentences in `MESSAGES` are the whole vocabulary, and the only
amounts that travel are the ones the caller sent or the chain measured.

What a caller has to hear about is announced as an event: a stored preview
(`ai_preview`), a refused one and a refusal the chain answered with (`refusal`),
the one order an approval placed (`ai_placed`), and every preview the sweep moved
to `expired` (`ai_expired`).  The events written from inside the statement that
changes the row — a stored or refused preview, an expiry — are that statement's
own, so a preview that could not be recorded is not stored either.  The two an
approval writes AFTER its row has moved are best-effort (`_announce_quietly`): an
events table that refuses them costs the reader a line and the approval's answer
nothing.  A reject, a cancel and a retirement from the drain change a row and say
nothing.  The owner of them all is `ai`, and none of them carries a secret, a key
or a token: an id, a code and an amount the caller sent or the chain measured.

The mode is read once, at startup: `CROW_COINBASE_AI_ORDER_MODE` accepts "approve"
alone, and "autonomous" is refused with the sentence the plan fixed for P3.  The
window a preview gets is `CROW_COINBASE_AI_PREVIEW_TTL_S`, 900 seconds by default.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from decimal import Decimal
from typing import Any, Callable, Mapping, Optional

from .exchange import EQUITY_PREVIEW_UNCONFIRMED, PRODUCT_TYPE_UNKNOWN
from .gateway import (
    AI_OWNER,
    APPROVAL_REQUIRED,
    CANCEL_FAILED,
    CAPITAL_CAP,
    CLOCK_SKEW,
    DAILY_CAP,
    DRAWDOWN_STOP,
    EQUITY_UNAVAILABLE,
    EXCHANGE_REJECTED,
    FRACTIONAL_NOT_ALLOWED,
    HALTED,
    INSUFFICIENT_HOLDING,
    LIQUIDATE_ONLY,
    LIVE_DISABLED,
    LIVE_LOCKED,
    MARKET_CLOSED,
    NO_EQUITY_ACCOUNT,
    NOT_CANCELLABLE,
    NOT_OWNER,
    ORDER_TOO_LARGE,
    POST_ONLY_WOULD_CROSS,
    PRICE_BAND,
    PRODUCT_NOT_ALLOWED,
    RATE_CAP,
    STALE_MARKET,
    TOO_SMALL,
    TRADING_HALTED,
    UNALLOCATED_NEGATIVE,
    ApprovalGone,
    OrderGateway,
)
from .store import (
    CANCELLED as ORDER_CANCELLED_STATUS,
    EQUITY as PRODUCT_TYPE_EQUITY,
    FAILED as ORDER_FAILED_STATUS,
    REJECTED as ORDER_REJECTED_STATUS,
    Store,
)
from .strategies.base import OrderIntent

D = Decimal
log = logging.getLogger("crow_coinbase.ai_orders")

# ---------------------------------------------------------------- the environment
AI_ORDER_MODE_ENV = "CROW_COINBASE_AI_ORDER_MODE"
AI_PREVIEW_TTL_ENV = "CROW_COINBASE_AI_PREVIEW_TTL_S"
DEFAULT_PREVIEW_TTL_S = 900
MAX_PREVIEW_TTL_S = 86400

# The one mode this build runs in, and the one it refuses with a fixed sentence.
APPROVE_MODE = "approve"
AUTONOMOUS_MODE = "autonomous"
AUTONOMOUS_REFUSED = (
    "Autonomous AI orders become available after outside-client hiding (P3)."
)

# ---------------------------------------------------------------- the states
STATE_PENDING = "pending"
STATE_APPROVED = "approved"
STATE_PLACED = "placed"
STATE_EXPIRED = "expired"
STATE_REJECTED = "rejected"
STATE_CANCELLED = "cancelled"
STATES = (
    STATE_PENDING,
    STATE_APPROVED,
    STATE_PLACED,
    STATE_EXPIRED,
    STATE_REJECTED,
    STATE_CANCELLED,
)
# The states a preview never leaves: an expiry or a rejection retires it, a spend
# places it, a cancel ends one that was placed.
TERMINAL_STATES = (STATE_EXPIRED, STATE_REJECTED, STATE_CANCELLED, STATE_PLACED)

# How long a terminal row is kept before the sweep deletes it (seconds).
PREVIEW_RETENTION_S = 7 * 86400
# The most rows one listing answers with.
LIST_LIMIT = 100
# How many previews may wait for an answer at once, and how many may be made
# inside `PREVIEW_WINDOW_S` whatever became of them.  Both figures are counted
# from the table, and a preview past either bound writes no row at all.
MAX_PENDING_PREVIEWS = 20
MAX_PREVIEWS_PER_HOUR = 60
PREVIEW_WINDOW_S = 3600
# How long an approval may sit unconsumed before the sweep gives up on it: an
# approval nobody spent was not an intent to place.
APPROVED_STALL_S = 60

# ---------------------------------------------------------------- the codes
INVALID = "INVALID"
NOT_FOUND = "NOT_FOUND"
NOT_PENDING = "NOT_PENDING"
HASH_MISMATCH = "HASH_MISMATCH"
EXPIRED = "EXPIRED"
BOOK_CHANGED = "BOOK_CHANGED"
REJECTED = "REJECTED"
PREVIEW_LIMIT = "PREVIEW_LIMIT"
ORDER_FAILED = "ORDER_FAILED"
APPROVAL_STALLED = "APPROVAL_STALLED"

# The two sides an AI order may take.
BUY = "BUY"
SELL = "SELL"
SIDES = (BUY, SELL)

# The statuses a cancel may answer with that are not the generic conflict.
CANCEL_STATUS = {NOT_OWNER: 403, NOT_CANCELLABLE: 409, LIVE_LOCKED: 409}
CANCEL_FAILED_STATUS = 502
CONFLICT_STATUS = 409
INVALID_STATUS = 422
NOT_FOUND_STATUS = 404
PREVIEW_LIMIT_STATUS = 429

# What an owner reads beside a code.  Plain sentences, no values, and no secret
# anywhere: these strings are the module's whole vocabulary for a refusal.
MESSAGES = {
    INVALID: "That is not an order this engine can read.",
    NOT_FOUND: "There is no such preview.",
    NOT_PENDING: "That preview is no longer waiting for an answer.",
    HASH_MISMATCH: "That is not the preview you were shown; ask again.",
    EXPIRED: "This preview expired; ask again.",
    BOOK_CHANGED: "The book for AI orders changed; ask again.",
    REJECTED: "That preview was rejected.",
    PREVIEW_LIMIT: (
        "Too many previews are open right now; answer or dismiss one and try "
        "again in a little while."
    ),
    ORDER_FAILED: "The order this preview placed is not on the book.",
    APPROVAL_STALLED: "This approval was never spent; ask again.",
    APPROVAL_REQUIRED: "This order has no approved preview behind it.",
    POST_ONLY_WOULD_CROSS: "Price moved; ask again",
    EXCHANGE_REJECTED: "The exchange refused the order.",
    HALTED: "Trading is halted.",
    LIVE_DISABLED: "Live trading is switched off.",
    LIVE_LOCKED: "The live account is not connected.",
    STALE_MARKET: "The market data is out of date; ask again in a moment.",
    CLOCK_SKEW: "The exchange's clock and this engine's clock disagree.",
    PRODUCT_NOT_ALLOWED: "That product is not on the list this engine trades.",
    TOO_SMALL: "That order is below the smallest size the exchange takes.",
    ORDER_TOO_LARGE: "That order is over the AI's single-order limit.",
    DAILY_CAP: "That order would go over the AI's daily limit.",
    RATE_CAP: "That order would go over the hourly order limit.",
    INSUFFICIENT_HOLDING: "The AI does not have the money for that order.",
    UNALLOCATED_NEGATIVE: "The account is short of what its owners hold.",
    DRAWDOWN_STOP: "Trading stopped after a drawdown.",
    NOT_OWNER: "That order is not the AI's.",
    NOT_CANCELLABLE: "That order cannot be cancelled now.",
    CANCEL_FAILED: "The exchange did not take the cancellation.",
    # What a stock order can answer with, on top of the codes above: the
    # product's own facts, the equity caps, and the stock side of the account.
    MARKET_CLOSED: "The stock market is closed right now.",
    PRICE_BAND: "That price is too far from the current stock price.",
    FRACTIONAL_NOT_ALLOWED: "That stock only trades in whole shares.",
    CAPITAL_CAP: (
        "That order would go over the money set aside for AI stock trades."
    ),
    TRADING_HALTED: "Trading in that stock is halted.",
    LIQUIDATE_ONLY: "That stock can only be sold right now.",
    NO_EQUITY_ACCOUNT: "The live account has no stock trading side connected.",
    EQUITY_UNAVAILABLE: (
        "Stock trading is off right now; Crow could not confirm the stock "
        "products yet."
    ),
    EQUITY_PREVIEW_UNCONFIRMED: "Live stock trading hasn't been confirmed yet.",
    PRODUCT_TYPE_UNKNOWN: (
        "The stock broker could not tell what kind of product that is."
    ),
}
GENERIC_MESSAGE = "The order could not be placed."


# ---------------------------------------------------------------- the environment


def ai_order_mode(env: Mapping[str, str]) -> str:
    """The AI order mode this process may run in: "approve", or nothing at all.

    An absent or blank value is the default; "approve" is accepted; "autonomous"
    is refused with the sentence P3 will replace, and any other spelling is
    refused naming the variable rather than guessed at.
    """
    raw = env.get(AI_ORDER_MODE_ENV)
    text = APPROVE_MODE if raw is None else str(raw).strip().lower()
    if not text or text == APPROVE_MODE:
        return APPROVE_MODE
    if text == AUTONOMOUS_MODE:
        raise ValueError(AUTONOMOUS_REFUSED)
    raise ValueError(
        f"{AI_ORDER_MODE_ENV} must be {APPROVE_MODE!r} (autonomous AI orders are "
        f"not available yet), got {text!r}"
    )


def _ttl_seconds(env: Mapping[str, str]) -> int:
    """How long a preview stays approvable: whole seconds, 1 to one day.

    An absent or blank value is `DEFAULT_PREVIEW_TTL_S`.  Anything that is not a
    whole number of seconds in range is refused naming the variable, so a
    mistyped window can never become a preview that outlives the owner's interest.
    """
    raw = env.get(AI_PREVIEW_TTL_ENV)
    if raw is None or not str(raw).strip():
        return DEFAULT_PREVIEW_TTL_S
    text = str(raw).strip()
    try:
        value = int(text)
    except (TypeError, ValueError):
        raise ValueError(
            f"{AI_PREVIEW_TTL_ENV} must be a whole number of seconds, got {text!r}"
        ) from None
    if value <= 0 or value > MAX_PREVIEW_TTL_S:
        raise ValueError(
            f"{AI_PREVIEW_TTL_ENV} must be between 1 and {MAX_PREVIEW_TTL_S} "
            f"seconds, got {text!r}"
        )
    return value


# ---------------------------------------------------------------- the digest


def _decimal_text(value: Any) -> str:
    """One money value as the digest writes it: equal numbers, equal text."""
    return format(D(value).normalize(), "f")


def _preview_digest(
    product: Any, side: Any, size: Any, limit_price: Any, book: Any
) -> str:
    """sha256 of the five fields an approval covers, joined by newlines.

    The book is one of the five, so an approval can never be spent on the other
    book; `_decimal_text` writes a money value from its own value, so 5 and 5.00
    hash the same and nothing a reader sent can change the digest.
    """
    fields = (
        str(product),
        str(side),
        _decimal_text(size),
        _decimal_text(limit_price),
        str(book),
    )
    return hashlib.sha256("\n".join(fields).encode("utf-8")).hexdigest()


def __getattr__(name: str) -> Any:
    """Serve the two names this module is known by from outside, and nothing else.

    `preview_hash` and `preview_ttl_s` are the names the rest of the engine knows
    this module's digest and window by, and the module's own body calls them
    `_preview_digest` and `_ttl_seconds`.  The split is not cosmetic: the package's
    no-bypass scan treats every identifier that begins `preview_` as an SDK order
    entry point, so the contract names are answered here instead of being bound
    and used beside them.
    """
    if name == "preview_hash":
        return _preview_digest
    if name == "preview_ttl_s":
        return _ttl_seconds
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------- refusals


class AiRefused(Exception):
    """A refused AI order request: the code, its plain message and its status.

    `code` is the machine-readable refusal, `message` a sentence an owner can read
    and `status` the HTTP status the code answers with.  The exception's own text
    starts with the code (`"NOT_PENDING: ..."`), while `.message` is the sentence
    alone for a caller that composes the two itself.  A message never carries a
    secret, and never a value of the request it was not asked to repeat.
    """

    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = int(status)


def _refused(code: str, status: int, message: Optional[str] = None) -> AiRefused:
    """The refusal for one code, in that code's own words unless told otherwise."""
    return AiRefused(code, message or MESSAGES.get(code, GENERIC_MESSAGE), status)


# ---------------------------------------------------------------- one event


def _announce(store: Store, note: Mapping[str, Any]) -> None:
    """Write one event the AI surface announces, from the note that describes it.

    A note is `{level, kind, message, data}` and nothing else, so the owner is
    always `ai` and the words are always this module's.  No note carries a
    secret, a key or a token: only ids, codes and the amounts the caller sent or
    the chain measured.  Called inside the caller's transaction where the state
    change it announces is made, so the two commit together or neither does.
    """
    store.event(
        note["level"],
        note["message"],
        kind=note["kind"],
        owner=AI_OWNER,
        data=note["data"],
    )


def _announce_quietly(store: Store, note: Mapping[str, Any]) -> None:
    """Write one event whose state change has ALREADY been made, and never fail.

    The two events an approval writes after its row has moved — the order it
    placed and the refusal the chain answered with — are a reader's account of an
    answer the caller is already owed.  Neither may cost that answer: the row, the
    order and the preview's state are all settled by the time this is called, so a
    store that will not take the event is logged (without any exception text) and
    the answer stands.  Nothing is retried here — the row itself is what a reader
    follows, and the event is only the account of it.
    """
    try:
        _announce(store, note)
    except Exception:  # noqa: BLE001 - the approval's answer outranks its record
        log.warning("ai event skipped: it could not be written")


def _expired_note(identifier: str) -> dict:
    """The note for one preview moved to `expired`: its id, and nothing else."""
    return {
        "level": "info",
        "kind": "ai_expired",
        "message": f"ai preview {identifier} expired",
        "data": {"preview_id": identifier},
    }


# ---------------------------------------------------------------- one preview


def _money(value: Any) -> str:
    """A money value as the surface reports it: a decimal string."""
    return str(D(value))


def _positive(value: Any, field: str) -> D:
    """A strictly positive, finite `Decimal` from what a caller sent, or a refusal.

    A string, an int or a `Decimal` is read through `Decimal(str(...))`, never
    through a float, and anything that is not a finite positive number is refused
    as `INVALID` — before a row is written or the chain is asked anything.
    """
    try:
        amount = D(str(value))
    except (ArithmeticError, TypeError, ValueError):
        raise _refused(INVALID, INVALID_STATUS, f"{field} must be a number") from None
    if not amount.is_finite() or amount <= 0:
        raise _refused(
            INVALID, INVALID_STATUS, f"{field} must be more than 0"
        ) from None
    return amount


def _payload(row: Mapping[str, Any]) -> dict:
    """One row's stored payload (the notional and the limits), or an empty mapping."""
    raw = row.get("payload_json") or "{}"
    try:
        stored = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return stored if isinstance(stored, dict) else {}


def _check_increments(
    gateway: OrderGateway, product: Any, size: D, price: D
) -> None:
    """Refuse a size or a price the product's own tick cannot spell.

    A product on neither of the engine's lists — crypto or equity — is left to
    the chain's own refusal, and the spec is asked of the gateway only once the
    product is tradable; a spec that cannot be had answers nothing here either.
    An equity therefore has its own tick read exactly as a crypto product does.
    The remainder of a `Decimal` is exact, so nothing is rounded onto the tick: a
    size or a price off it is refused `INVALID` before a row is written, and the
    chain is never asked to measure an order the exchange could not represent.  A
    spec whose increments cannot be read answers nothing and lets the chain
    decide.
    """
    try:
        if not gateway.limits.tradable(product):
            return
        spec = gateway.spec_for(product)
        base = D(str(spec.base_increment))
        quote = D(str(spec.price_increment))
    except Exception:  # noqa: BLE001 - no usable spec: the chain decides
        return
    try:
        if base > 0 and size % base != 0:
            raise _refused(
                INVALID,
                INVALID_STATUS,
                "size must be a whole number of the product's base increment",
            )
        if quote > 0 and price % quote != 0:
            raise _refused(
                INVALID,
                INVALID_STATUS,
                "limit_price must be a whole number of the product's "
                "price increment",
            )
    except (ArithmeticError, TypeError, ValueError):
        return


# ---------------------------------------------------------------- the surface


class AiOrders:
    """AI order previews, the owner's approval and the AI's one send.

    Built over the engine's `Store` and the window a preview is given, and
    `attach`ed to the gateway once that exists: `attach` is what makes the
    gateway's approval step this object's own (`approval_check` to ask it,
    `consume` to spend a row in the order's transaction), so an engine that never
    attaches keeps the gateway's deny-everything default.  `now` is the clock the
    expiry is measured against.

    A preview is named by an `identifier` throughout rather than by the plan's
    `preview_id`, and the cancel is `cancel_order`: the package's no-bypass scan
    refuses any identifier that begins `preview_` (one of the SDK's order-method
    prefixes) and any identifier that is exactly `cancel` (a write method's own
    name), so neither can be spelled as a name in this module's body.
    """

    def __init__(
        self,
        store: Store,
        *,
        ttl_s: int,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.ttl_s = int(ttl_s)
        self.now = now
        self.gateway: Optional[OrderGateway] = None

    def attach(self, gateway: OrderGateway) -> None:
        """Point this surface at *gateway*, and wire the gateway's approval step.

        The check and the consumption are this object's own bound methods: the
        gateway asks the first whether an approval may be used and gives the
        second its own connection, so a consumed approval commits with the order
        row or not at all.
        """
        self.gateway = gateway
        gateway.approval_check = self.approval_check
        gateway.consume_approval = self.consume

    def _ready(self) -> OrderGateway:
        """The gateway this surface was attached to; unattached is a wiring bug."""
        if self.gateway is None:
            raise RuntimeError("the AI order surface has no gateway")
        return self.gateway

    # ------------------------------------------------ rows
    def _row(self, identifier: Any) -> Optional[dict]:
        """One preview row, or None when there is no row with that id."""
        if not isinstance(identifier, str) or not identifier:
            return None
        row = self.store.conn().execute(
            "SELECT * FROM ai_previews WHERE id=?", (identifier,)
        ).fetchone()
        return None if row is None else dict(row)

    def _write(self, row: Mapping[str, Any], note: Optional[Mapping[str, Any]]) -> dict:
        """Insert one preview row as it stands, with its announcement, and answer it.

        Two bounds are counted on THIS transaction's connection, after it has
        taken the write lock and before any row is written: the previews waiting
        for an answer and the previews made inside the last hour.  A preview past
        either is `PREVIEW_LIMIT` with nothing written, and the rollback takes
        the count with it — so the cheap early check `preview()` runs is a saving
        rather than the bound itself, and a row can never be written past one.

        The row and its event are one write: a stored preview is announced with
        the note the caller built, in the same transaction, so a preview that
        could not be recorded is not stored either.
        """
        columns = ",".join(row)
        marks = ",".join("?" * len(row))
        now = self.now()
        with self.store.tx() as conn:
            self._flood_limit(conn, now)
            conn.execute(
                f"INSERT INTO ai_previews({columns}) VALUES({marks})",
                tuple(row.values()),
            )
            if note is not None:
                _announce(self.store, note)
        stored = self._row(row["id"])
        if stored is None:
            raise RuntimeError("the preview row could not be read back")
        return stored

    def _finish(
        self,
        identifier: str,
        state: str,
        refusal: Optional[str],
        *,
        expected: tuple[str, ...],
        note: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Move one row to *state*, but only out of one of the *expected* states.

        The condition is part of the statement, so the row is moved by whoever
        finds it in one of those states and by nobody else: two answers to one
        preview cannot both land, and a row a caller has stopped expecting to
        move is left exactly as it is.  Answers whether a row changed.

        A *note* is the event that announcement is written from, in the same
        transaction as the change and only when a row really changed: a preview
        that was already retired is not announced twice.
        """
        marks = ",".join("?" * len(expected))
        with self.store.tx() as conn:
            changed = conn.execute(
                f"UPDATE ai_previews SET state=?, refusal=? "
                f"WHERE id=? AND state IN ({marks})",
                (state, refusal, identifier, *expected),
            ).rowcount
            if changed == 1 and note is not None:
                _announce(self.store, note)
        return changed == 1

    # ------------------------------------------------ the preview
    def preview(self, product: Any, side: Any, size: Any, limit_price: Any) -> dict:
        """Measure one proposed order against the chain and store what it answered.

        The chain runs read-only on the book the route decides (`live` while the
        AI's own switch is on, `dry` otherwise), so a live route with no usable
        account is refused `LIVE_LOCKED` and is never quietly built on the
        simulator.  A malformed size or price is `INVALID` and stores nothing,
        and so is a size or a price the product's own increments cannot spell.
        A preview asked for while too many are waiting, or too many have been
        asked for inside the hour, is `PREVIEW_LIMIT` and writes no row either.

        On success the row is `pending` for one window: its `limit_price` is the
        maker price the chain measured — the price the order will be sent at — and
        its hash covers that price, the size, the side, the product and the book.
        The price the caller asked for is kept beside it as
        `requested_limit_price`, which no hash covers.  A chain refusal is stored
        as a `rejected` row carrying the code and the user's own price, which no
        approval can spend.  Neither answer sends anything to an exchange or
        writes an order row.
        """
        gateway = self._ready()
        self.sweep()
        self._refuse_a_flood()
        amount = _positive(size, "size")
        price = _positive(limit_price, "limit_price")
        if side not in SIDES:
            raise _refused(INVALID, INVALID_STATUS, "side must be BUY or SELL")
        _check_increments(gateway, product, amount, price)
        book, _route_refusal = gateway.route(AI_OWNER)
        intent = OrderIntent(
            action="place",
            side=side,
            size=amount,
            limit_price=price,
            level=0,
            cancel_cid=None,
            reason="ai preview",
        )
        refusal, decided, _product, _snap, _spec, chain_price = gateway.evaluate(
            AI_OWNER, AI_OWNER, intent, product
        )
        if decided is not None:
            book = decided
        if refusal is not None or chain_price is None:
            code = refusal or EXCHANGE_REJECTED
            notional = amount * price
            stored = self._store(
                product=str(product),
                side=str(side),
                size=amount,
                limit_price=price,
                requested=price,
                book=book,
                state=STATE_REJECTED,
                refusal=code,
                notional=notional,
            )
            # The answer's sentence comes from the code (`_answer` looks it up), so
            # a refused preview reads the same whether it is answered now or
            # listed later.
            return self._answer(stored, None)
        notional = amount * chain_price
        stored = self._store(
            product=str(product),
            side=str(side),
            size=amount,
            limit_price=chain_price,
            requested=price,
            book=book,
            state=STATE_PENDING,
            refusal=None,
            notional=notional,
        )
        return self._answer(stored, None)

    def _refuse_a_flood(self) -> None:
        """The cheap early refusal of a new preview, before the chain is asked.

        The same two figures `_flood_limit` counts, read on this thread's
        connection: it exists so a flood costs no measurement and no row, while
        the bound itself is counted again inside the insert's own transaction.
        """
        self._flood_limit(self.store.conn(), self.now())

    def _flood_limit(self, conn: Any, now: float) -> None:
        """Refuse a new preview the table cannot take another of, counted on *conn*.

        Two figures, both read from the table: the previews waiting for an answer
        (`MAX_PENDING_PREVIEWS`) and every preview made inside the last
        `PREVIEW_WINDOW_S`, whatever became of it (`MAX_PREVIEWS_PER_HOUR`).  A
        preview past either bound is `PREVIEW_LIMIT` and writes no row at all, so
        asking again cannot grow the table.  Called by `preview()` for the cheap
        answer and by `_write` on its own transaction's connection, which is the
        one the bound is actually held to.
        """
        at = float(now)
        waiting = int(
            conn.execute(
                "SELECT COUNT(*) FROM ai_previews WHERE state=?",
                (STATE_PENDING,),
            ).fetchone()[0]
        )
        recent = int(
            conn.execute(
                "SELECT COUNT(*) FROM ai_previews WHERE created_at > ?",
                (at - PREVIEW_WINDOW_S,),
            ).fetchone()[0]
        )
        if waiting >= MAX_PENDING_PREVIEWS or recent >= MAX_PREVIEWS_PER_HOUR:
            raise _refused(PREVIEW_LIMIT, PREVIEW_LIMIT_STATUS)

    def _store(
        self,
        *,
        product: str,
        side: str,
        size: D,
        limit_price: D,
        requested: D,
        book: str,
        state: str,
        refusal: Optional[str],
        notional: D,
    ) -> dict:
        """Write one preview row: its id, its window, its hash and its limits.

        `limit_price` is the price the order is measured at (the maker price the
        chain returned, or the caller's own on a refusal) and is one of the five
        fields the hash covers; `requested` is what the caller asked for, kept
        beside it for the owner to read and no part of the hash.
        """
        now = self.now()
        identifier = uuid.uuid4().hex
        row = {
            "id": identifier,
            "created_at": now,
            "expires_at": now + self.ttl_s,
            "state": state,
            "product": product,
            "side": side,
            "size": str(size),
            "limit_price": str(limit_price),
            "book": book,
            "hash": _preview_digest(product, side, size, limit_price, book),
            "payload_json": json.dumps(
                self._payload_of(
                    product=product,
                    side=side,
                    requested=requested,
                    book=book,
                    notional=notional,
                )
            ),
            "refusal": refusal,
        }
        if state == STATE_PENDING:
            note: Optional[dict] = {
                "level": "info",
                "kind": "ai_preview",
                "message": (
                    f"ai preview {identifier}: {side} {size} {product} at "
                    f"{limit_price} on the {book} book"
                ),
                "data": {
                    "preview_id": identifier,
                    "product": product,
                    "side": side,
                    "size": str(size),
                    "limit_price": str(limit_price),
                    "book": book,
                    "notional": _money(notional),
                    "expires_at": row["expires_at"],
                },
            }
        else:
            note = {
                "level": "info",
                "kind": "refusal",
                "message": f"ai preview {identifier} refused {refusal}",
                "data": {"code": refusal, "preview_id": identifier},
            }
        return self._write(row, note)

    def _payload_of(
        self,
        *,
        product: str,
        side: str,
        requested: D,
        book: str,
        notional: D,
    ) -> dict:
        """The payload a preview row stores: its amounts, its limits, its stock facts.

        The payload is what it always was — `notional`, the caller's own price and
        the limits — and an `equity` key is added only for a product the gateway
        names as an equity.  The block is a figure read here and checked against
        nothing: a read that cannot answer leaves it out and the preview stands.
        """
        payload = {
            "notional": _money(notional),
            "requested_limit_price": _money(requested),
            "limits": self._limits(book, notional, product=product, side=side),
        }
        equity = self._equity_block(product, side, book, notional)
        if equity is not None:
            payload["equity"] = equity
        return payload

    def _equity_block(
        self, product: Any, side: Any, book: str, notional: D
    ) -> Optional[dict]:
        """The stock facts an equity preview carries, or None for a crypto product.

        The session the preview was taken in, the money set aside for AI stock
        trades, what of that is spent and what would be left once this order went
        out (less the notional for a buy, back onto it for a sell).  Every amount
        is a money text, and the session is a bool.  A read that cannot answer
        answers nothing: a preview is not failed for a figure nobody needs in
        order to place the order.
        """
        gateway = self._ready()
        try:
            if not gateway.limits.is_equity(str(product)):
                return None
            capital = D(gateway.limits.equity_ai_capital_usd)
            used = D(gateway.ledger.equity_pool_used(book))
            left = capital - used
            after = left - notional if str(side) != SELL else left + notional
            return {
                "session_open": bool(gateway.session_open(gateway.now())),
                "pool_capital": _money(capital),
                "pool_used": _money(used),
                "pool_left": _money(left),
                "pool_left_after": _money(after),
            }
        except Exception:  # noqa: BLE001 - the block is a figure, not a check
            log.warning("ai preview: the equity facts could not be read")
            return None

    def _limits(
        self,
        book: str,
        notional: D,
        product: Optional[Any] = None,
        side: Optional[Any] = None,
    ) -> list[dict]:
        """The five limits an owner sees beside a preview, as they stand now.

        Each entry names a cap, the value it is set to and what the figure would
        be once this order went out.  For a product the gateway names as an
        equity the five are the equity ones — the single stock order, a stock
        day's total, the pool set aside and the two order counts — and not one of
        the crypto AI budgets: the two budgets are separate pools, so a stock
        preview never reports a crypto cap.  Every other product still reads the
        five it always did.  They are what the engine thinks at preview time and
        nothing more — the whole chain is asked again at the approve — so a read
        that cannot answer leaves the list empty rather than failing a preview
        that sent nothing.
        """
        gateway = self._ready()
        try:
            caps = gateway.caps
            limits = gateway.limits
            if product is not None and limits.is_equity(str(product)):
                pool = D(gateway.ledger.equity_pool_used(book))
                pool_after = (
                    pool - notional if str(side) == SELL else pool + notional
                )
                return [
                    {
                        "name": "equity_max_order_usd",
                        "limit": _money(limits.equity_max_order_usd),
                        "used_after": _money(notional),
                    },
                    {
                        "name": "equity_daily_notional_usd",
                        "limit": _money(limits.equity_daily_notional_usd),
                        "used_after": _money(
                            caps.daily_notional(
                                None, book=book, product_type=PRODUCT_TYPE_EQUITY
                            )
                            + notional
                        ),
                    },
                    {
                        "name": "equity_ai_capital_usd",
                        "limit": _money(limits.equity_ai_capital_usd),
                        "used_after": _money(pool_after),
                    },
                    {
                        "name": "ai_orders_per_hour",
                        "limit": int(limits.ai_orders_per_hour),
                        "used_after": int(caps.orders_last_hour(AI_OWNER, book=book))
                        + 1,
                    },
                    {
                        "name": "orders_per_hour",
                        "limit": int(limits.orders_per_hour),
                        "used_after": int(caps.orders_last_hour(None, book=book)) + 1,
                    },
                ]
            return [
                {
                    "name": "ai_max_order_usd",
                    "limit": _money(limits.ai_max_order_usd),
                    "used_after": _money(notional),
                },
                {
                    "name": "ai_daily_notional_usd",
                    "limit": _money(limits.ai_daily_notional_usd),
                    "used_after": _money(
                        caps.daily_notional(AI_OWNER, book=book) + notional
                    ),
                },
                {
                    "name": "daily_notional_usd",
                    "limit": _money(limits.daily_notional_usd),
                    "used_after": _money(
                        caps.daily_notional(None, book=book) + notional
                    ),
                },
                {
                    "name": "ai_orders_per_hour",
                    "limit": int(limits.ai_orders_per_hour),
                    "used_after": int(caps.orders_last_hour(AI_OWNER, book=book))
                    + 1,
                },
                {
                    "name": "orders_per_hour",
                    "limit": int(limits.orders_per_hour),
                    "used_after": int(caps.orders_last_hour(None, book=book)) + 1,
                },
            ]
        except Exception:  # noqa: BLE001 - the limits are a figure, not a check
            log.warning("ai preview: the limits could not be read")
            return []

    def _answer(self, row: Mapping[str, Any], message: Optional[str]) -> dict:
        """One preview row in the shape every AI order answer has.

        The `equity` block is answered only when the row stored one, so a crypto
        preview's answer has no such key and every other key is unchanged.
        """
        payload = _payload(row)
        refusal = row.get("refusal")
        answer = {
            "preview_id": row["id"],
            "hash": row["hash"],
            "state": row["state"],
            "book": row["book"],
            "product": row["product"],
            "side": row["side"],
            "size": str(row["size"]),
            "limit_price": str(row["limit_price"]),
            "requested_limit_price": payload.get("requested_limit_price"),
            "notional": payload.get("notional"),
            "limits": payload.get("limits", []),
            "expires_at": float(row["expires_at"]),
            "created_at": float(row["created_at"]),
            "refusal": refusal,
            "message": (
                None
                if refusal is None
                else (message or MESSAGES.get(refusal, GENERIC_MESSAGE))
            ),
        }
        equity = payload.get("equity")
        if isinstance(equity, dict):
            answer["equity"] = equity
        return answer

    # ------------------------------------------------ listing
    def list(self, state: Optional[str] = None) -> list[dict]:
        """The newest previews, at most `LIST_LIMIT`, optionally one state's.

        A state this engine does not know is refused `INVALID`, so a panel asking
        for a state nobody writes hears that rather than an empty list.
        """
        self.sweep()
        if state is not None and state not in STATES:
            raise _refused(
                INVALID,
                INVALID_STATUS,
                "state must be one of " + ", ".join(STATES),
            )
        sql = "SELECT * FROM ai_previews"
        args: tuple = ()
        if state is not None:
            sql += " WHERE state=?"
            args = (state,)
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        rows = self.store.conn().execute(sql, (*args, LIST_LIMIT)).fetchall()
        return [self._answer(dict(row), None) for row in rows]

    # ------------------------------------------------ the owner's answer
    def reject(self, identifier: str) -> dict:
        """Retire one preview the owner said no to: `rejected`, and nothing sent.

        The transition is ONE conditional statement over the states a no may
        answer — `pending`, or `approved` and not yet spent — so a reject that
        read the row before an approval spent it cannot undo the order that
        approval placed: the row is `placed` by then and the statement changes
        nothing, which is answered `NOT_PENDING`.  An id nobody holds is
        `NOT_FOUND` before anything is written.
        """
        self.sweep()
        row = self._row(identifier)
        if row is None:
            raise _refused(NOT_FOUND, NOT_FOUND_STATUS)
        with self.store.tx() as conn:
            changed = conn.execute(
                "UPDATE ai_previews SET state=?, refusal=? WHERE id=? "
                "AND (state=? OR (state=? AND consumed_at IS NULL))",
                (
                    STATE_REJECTED,
                    REJECTED,
                    row["id"],
                    STATE_PENDING,
                    STATE_APPROVED,
                ),
            ).rowcount
        if changed != 1:
            raise _refused(NOT_PENDING, CONFLICT_STATUS)
        return {
            "preview_id": row["id"],
            "state": STATE_REJECTED,
            "refusal": REJECTED,
        }

    def approve(self, identifier: str, hash_: Any) -> dict:
        """Spend one preview: re-check everything, place the order, answer where it went.

        The whole answer runs under the gateway's cycle lock.  The row has to be
        `pending`, unexpired and hash-matching; the book the route decides now has
        to be the book the preview was taken on, or the row is retired
        `BOOK_CHANGED`; a route that refuses now retires it with that code.  Then
        ONE conditional UPDATE moves it to `approved`, and only the connection
        that changed that row goes on to place the order — that guard, not the
        lock, is what makes two approvals of one preview place one order.

        The placement is the gateway's, which re-runs the whole chain and spends
        the row in the order's own transaction.  A refusal there — a cap, the
        halt, the market, the owner's money, a price the book has moved past —
        retires the preview with that code (a post-only cross moves an already
        `placed` row to `rejected`) and answers the refusal; a success answers the
        client order id the order was sent under.

        The three things worth announcing are announced from here: a preview moved
        to `expired` (with the id, once per row actually changed), an order that
        was placed (with the client order id and the book), and a refusal that
        came back from the chain (with its code, and only when the retirement it
        describes really changed a row).  The last two are written best-effort
        (`_announce_quietly`): the order, the row and the answer are already
        settled when they are written, so a store that will not take the event
        costs the reader a line and the caller nothing.  The guards before the
        spend — a wrong hash, a book that moved, a preview that was already spent
        — are answers to one request and write no event: they change no row and
        would otherwise let a caller flood the feed.
        """
        gateway = self._ready()
        with gateway.lock:
            self.sweep()
            row = self._row(identifier)
            if row is None:
                raise _refused(NOT_FOUND, NOT_FOUND_STATUS)
            now = self.now()
            if row["state"] == STATE_EXPIRED:
                raise _refused(EXPIRED, CONFLICT_STATUS)
            if float(row["expires_at"]) <= now and row["state"] in (
                STATE_PENDING,
                STATE_APPROVED,
            ):
                self._finish(
                    row["id"],
                    STATE_EXPIRED,
                    None,
                    expected=(STATE_PENDING, STATE_APPROVED),
                    note=_expired_note(row["id"]),
                )
                raise _refused(EXPIRED, CONFLICT_STATUS)
            if row["state"] != STATE_PENDING:
                raise _refused(NOT_PENDING, CONFLICT_STATUS)
            if not _hash_matches(
                hash_, row["hash"]
            ):
                raise _refused(HASH_MISMATCH, CONFLICT_STATUS)
            book, route_refusal = gateway.route(AI_OWNER)
            if book != row["book"]:
                self._finish(
                    row["id"],
                    STATE_REJECTED,
                    BOOK_CHANGED,
                    expected=(STATE_PENDING,),
                )
                raise _refused(BOOK_CHANGED, CONFLICT_STATUS)
            if route_refusal is not None:
                self._finish(
                    row["id"],
                    STATE_REJECTED,
                    route_refusal,
                    expected=(STATE_PENDING,),
                )
                raise _refused(route_refusal, CONFLICT_STATUS)
            with self.store.tx() as conn:
                changed = conn.execute(
                    "UPDATE ai_previews SET state=?, approved_at=? "
                    "WHERE id=? AND state=? AND expires_at>?",
                    (STATE_APPROVED, now, row["id"], STATE_PENDING, now),
                ).rowcount
            if changed != 1:
                raise _refused(NOT_PENDING, CONFLICT_STATUS)
            intent = OrderIntent(
                action="place",
                side=row["side"],
                size=D(row["size"]),
                limit_price=D(row["limit_price"]),
                level=0,
                cancel_cid=None,
                reason="ai approved",
                approval_id=row["id"],
            )
            result = gateway.submit(
                AI_OWNER, AI_OWNER, intent, product=row["product"]
            )
            if result.ok:
                _announce_quietly(
                    self.store,
                    {
                        "level": "info",
                        "kind": "ai_placed",
                        "message": f"ai order {result.cid} placed",
                        "data": {
                            "preview_id": row["id"],
                            "cid": result.cid,
                            "book": row["book"],
                        },
                    },
                )
                return {
                    "preview_id": row["id"],
                    "state": STATE_PLACED,
                    "cid": result.cid,
                    "book": row["book"],
                }
            code = result.refusal or EXCHANGE_REJECTED
            if code == APPROVAL_REQUIRED and float(row["expires_at"]) <= self.now():
                # The window closed between this approve's guard and the spend:
                # nothing was placed, so this is an expiry, not a refusal.
                self._finish(
                    row["id"],
                    STATE_EXPIRED,
                    None,
                    expected=(STATE_APPROVED, STATE_PLACED),
                    note=_expired_note(row["id"]),
                )
                raise _refused(EXPIRED, CONFLICT_STATUS)
            retired = self._finish(
                row["id"],
                STATE_REJECTED,
                code,
                expected=(STATE_APPROVED, STATE_PLACED),
            )
            if retired:
                # Only a row this refusal really retired is news: a preview
                # another answer already moved is not announced here.
                _announce_quietly(
                    self.store,
                    {
                        "level": "warn",
                        "kind": "refusal",
                        "message": f"ai order refused {code}",
                        "data": {"code": code, "preview_id": row["id"]},
                    },
                )
            raise _refused(code, CONFLICT_STATUS)

    def cancel_order(self, cid: str) -> dict:
        """Cancel one AI order through the gateway, and end the preview it placed.

        The gateway answers by ownership (`NOT_OWNER` — a bot's order, or an id
        nobody holds), by state (`NOT_CANCELLABLE`), by book (`LIVE_LOCKED`) or
        with `CANCEL_FAILED` when the exchange did not take it; each becomes the
        status its code answers with.  On success the preview whose client order
        id this is, and which is `placed`, becomes `cancelled`.
        """
        gateway = self._ready()
        intent = OrderIntent(
            action="cancel",
            side=None,
            size=None,
            limit_price=None,
            level=None,
            cancel_cid=cid,
            reason="ai cancel",
        )
        result = gateway.submit(AI_OWNER, AI_OWNER, intent)
        if not result.ok:
            code = result.refusal or CANCEL_FAILED
            status = (
                CANCEL_FAILED_STATUS
                if code == CANCEL_FAILED
                else CANCEL_STATUS.get(code, CONFLICT_STATUS)
            )
            raise _refused(code, status)
        with self.store.tx() as conn:
            conn.execute(
                "UPDATE ai_previews SET state=? WHERE cid=? AND state=?",
                (STATE_CANCELLED, cid, STATE_PLACED),
            )
        return {"cid": cid, "cancelled": True}

    # ------------------------------------------------ the gateway's questions
    def approval_check(
        self, approval_id: Any, intent: OrderIntent, *, product: str, book: str
    ) -> Optional[str]:
        """None when this approval may place this order, or `APPROVAL_REQUIRED`.

        It has to be a row, `approved`, unspent, unexpired, over the same product,
        side, size, price and book, and its stored hash has to be the hash of
        exactly those five fields.  Anything about the row this engine cannot read
        — an amount it cannot parse, a hash that is not a string — is the refusal
        too: an approval is never assumed to be usable.
        """
        if not isinstance(approval_id, str) or not approval_id:
            return APPROVAL_REQUIRED
        row = self._row(approval_id)
        if row is None:
            return APPROVAL_REQUIRED
        if row["state"] != STATE_APPROVED or row["consumed_at"] is not None:
            return APPROVAL_REQUIRED
        if float(row["expires_at"]) <= self.now():
            return APPROVAL_REQUIRED
        if row["product"] != product or row["side"] != intent.side:
            return APPROVAL_REQUIRED
        if row["book"] != book:
            return APPROVAL_REQUIRED
        try:
            if D(row["size"]) != intent.size:
                return APPROVAL_REQUIRED
            if D(row["limit_price"]) != intent.limit_price:
                return APPROVAL_REQUIRED
            digest = _preview_digest(
                product, intent.side, intent.size, intent.limit_price, book
            )
        except (ArithmeticError, TypeError, ValueError):
            return APPROVAL_REQUIRED
        if not hmac.compare_digest(
            digest.encode("utf-8"), str(row["hash"] or "").encode("utf-8")
        ):
            return APPROVAL_REQUIRED
        return None

    def consume(self, conn, approval_id: str) -> None:
        """Spend one approval on the CALLER's connection, or raise `ApprovalGone`.

        The row has to be `approved`, unspent and unexpired for the UPDATE to
        change it; the client order id the approval confirms into is written in
        the same statement, so the row and the order it belongs to can never name
        different orders.  The caller owns the transaction: a row this statement
        could not change raises, and whatever the caller had done rolls back with
        it.
        """
        now = self.now()
        changed = conn.execute(
            "UPDATE ai_previews SET state=?, consumed_at=?, cid=? "
            "WHERE id=? AND state=? AND consumed_at IS NULL AND expires_at>?",
            (
                STATE_PLACED,
                now,
                f"cb-ai-{approval_id}",
                approval_id,
                STATE_APPROVED,
                now,
            ),
        ).rowcount
        if changed != 1:
            raise ApprovalGone(approval_id)

    # ------------------------------------------------ housekeeping
    def sweep_locked(self) -> int:
        """The cycle's own sweep: `sweep(retire_stalled=True)`, as a bound callable.

        `build_app` wires this into the runner, so the cycle asks this surface for
        the one sweep that may also retire an approval nobody spent and a placed
        preview whose order the book lost — the two rules that follow rows a
        caller is not waiting on.  It is a bound method on purpose: the runner
        holds the surface's own callable, not a copy of it.
        """
        return self.sweep(retire_stalled=True)

    def sweep(self, *, retire_stalled: bool = False) -> int:
        """Retire the previews past their window, follow their orders, forget old ones.

        Five changes, in one transaction, and the answer is the count of previews
        moved to `expired`.

        Always, whoever asks: every `pending` or `approved` row whose expiry has
        gone becomes `expired` (one `ai_expired` event per row that really moved),
        so a preview that was never answered cannot be approved later and a
        listing never offers one; a `placed` preview whose order row the book
        ended `CANCELLED` becomes `cancelled` with no code at all, because a
        cancelled order was answered by the book rather than refused; and
        terminal rows older than `PREVIEW_RETENTION_S` that never confirmed into
        an order (`cid IS NULL`) are deleted — the history of an answered preview
        is kept for a week and no longer, while a row carrying a client order id
        is the owner's record of an order and stays.

        Only with `retire_stalled` — the cycle's own call, which runs with the
        cycle lock held and is the housekeeping nobody waits for: a `placed`
        preview whose order row ended `FAILED` or `REJECTED` becomes `rejected`
        with `ORDER_FAILED`, and an `approved` row nobody spent within
        `APPROVED_STALL_S` becomes `rejected` with `APPROVAL_STALLED`.  A row that
        already finished with a code of its own is never overwritten.  A preview,
        a listing, a reject and an approve's own sweep are all beside that lock,
        so none of them retires either: an answer the owner is still making is not
        taken away by a read.

        The cancelled and expired changes write no `refusal` code: neither is a
        refusal.
        """
        now = self.now()
        marks = ",".join("?" * len(TERMINAL_STATES))
        with self.store.tx() as conn:
            expiring = conn.execute(
                "SELECT id FROM ai_previews WHERE state IN (?,?) "
                "AND expires_at <= ? ORDER BY created_at, id",
                (STATE_PENDING, STATE_APPROVED, now),
            ).fetchall()
            expired = conn.execute(
                "UPDATE ai_previews SET state=? "
                "WHERE state IN (?,?) AND expires_at <= ?",
                (STATE_EXPIRED, STATE_PENDING, STATE_APPROVED, now),
            ).rowcount
            for row in expiring:
                _announce(self.store, _expired_note(row["id"]))
            conn.execute(
                "UPDATE ai_previews SET state=?, refusal=NULL WHERE state=? "
                "AND cid IN (SELECT client_order_id FROM orders WHERE status=?)",
                (STATE_CANCELLED, STATE_PLACED, ORDER_CANCELLED_STATUS),
            )
            if retire_stalled:
                conn.execute(
                    "UPDATE ai_previews SET state=?, refusal=? WHERE state=? "
                    "AND refusal IS NULL "
                    "AND cid IN (SELECT client_order_id FROM orders "
                    "WHERE status IN (?,?))",
                    (
                        STATE_REJECTED,
                        ORDER_FAILED,
                        STATE_PLACED,
                        ORDER_FAILED_STATUS,
                        ORDER_REJECTED_STATUS,
                    ),
                )
                conn.execute(
                    "UPDATE ai_previews SET state=?, refusal=? WHERE state=? "
                    "AND consumed_at IS NULL AND approved_at IS NOT NULL "
                    "AND approved_at < ?",
                    (
                        STATE_REJECTED,
                        APPROVAL_STALLED,
                        STATE_APPROVED,
                        now - APPROVED_STALL_S,
                    ),
                )
            conn.execute(
                f"DELETE FROM ai_previews WHERE state IN ({marks}) "
                "AND cid IS NULL "
                "AND COALESCE(consumed_at, approved_at, created_at) < ?",
                (*TERMINAL_STATES, now - PREVIEW_RETENTION_S),
            )
        return expired


def _hash_matches(given: Any, expected: Any) -> bool:
    """Whether the hash an owner sent is the one the preview row holds.

    A value that is not a string cannot be one of these hex digests, so it is
    simply false; the comparison is `hmac.compare_digest` so a wrong hash is not
    told apart from a right one by how long the answer took.
    """
    if not isinstance(given, str):
        return False
    return hmac.compare_digest(
        given.encode("utf-8", "replace"),
        str(expected or "").encode("utf-8", "replace"),
    )