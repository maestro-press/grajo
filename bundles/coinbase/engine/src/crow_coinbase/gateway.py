"""The order gateway: the read-only check chain, then the execution after it.

`OrderGateway.check()` answers one question — may this intent go out? — and stops
at the first refusal.  For a place intent the order is fixed:

    BAD_INTENT -> WRONG_OWNER -> HALTED -> LIVE_DISABLED -> LIVE_LOCKED
    -> PRODUCT_NOT_ALLOWED -> APPROVAL_REQUIRED -> OWNER_PAUSED -> STALE_MARKET
    -> CLOCK_SKEW -> TOO_SMALL -> ORDER_TOO_LARGE -> DAILY_CAP -> RATE_CAP
    -> INSUFFICIENT_HOLDING -> UNALLOCATED_NEGATIVE -> DRAWDOWN_STOP

An EQUITY product has a chain of its own, and it is the exact order of THIS one
up to the product: BAD_INTENT -> WRONG_OWNER -> HALTED -> the route's refusal ->
the equity status's refusal (`EQUITY_UNAVAILABLE` while the stock products' kinds
are unconfirmed) -> the two equity gates (`LIVE_DISABLED` when the route is live
and `equity_live` is off, `NO_EQUITY_ACCOUNT` when the live account has no equity
side) ->
PRODUCT_NOT_ALLOWED -> APPROVAL_REQUIRED -> then the instrument's own facts:
TRADING_HALTED -> LIQUIDATE_ONLY -> MARKET_CLOSED -> STALE_MARKET -> CLOCK_SKEW
-> PRICE_BAND -> TOO_SMALL -> FRACTIONAL_NOT_ALLOWED -> ORDER_TOO_LARGE
-> DAILY_CAP -> CAPITAL_CAP (buy) or INSUFFICIENT_HOLDING (sell) -> RATE_CAP
-> UNALLOCATED_NEGATIVE -> DRAWDOWN_STOP.  Only the `ai` owner trades an equity:
a `bot` source, or a product its own row names, is PRODUCT_NOT_ALLOWED.

The `APPROVAL_REQUIRED` step is the AI's alone: an order under the `ai` owner
has to name an approved, unspent, unexpired preview of exactly that order before
it may go out, and the owner's answer is a row (`ai_orders.py`) rather than
anything the caller says.  A bot never takes an approval.  `check()` runs that
step, because the question it answers is "may this go out", and the AI's answer
is part of it; `evaluate()` is the ONE approval-free path — the chain as a caller
can read it, without that step — and it is what a preview asks.

A cancel intent is answered by its shape (BAD_INTENT) and then by ownership
alone (NOT_OWNER): it skips every other check, so a halt or a spent budget never
blocks taking an order off the book.

Every route takes one of the two books (`books.py`).  A bot trades the book its own
row's `mode` names; the `ai` owner trades the live book only while its own switch
is on and the simulator otherwise; every other owner is dry.  A live route is
refused `LIVE_DISABLED` when the ceiling or the owner's switch forbids it and
`LIVE_LOCKED` when there is no live exchange to reach it, and it is never
rerouted onto the simulator: the book a route decides is the book every step
after it reads — the caps, the ledger, the high-water marks and the portfolio
mark — and the book its order row is written with.  A refused live route makes no
call on either exchange.

`check()` is read-only: it writes no order row and never moves a high-water mark,
and it never calls the exchange.  Money and size are `Decimal` throughout (the
rounding, the fee-inclusive buy cost, the maker pricing and the minimums all come
from `money.py`); the only floats are a snapshot's timestamp and the measured
clock skew.

Execution sits beside the chain and runs under the cycle lock.  `submit()` runs
the same chain first (`_evaluate_place`) and refuses without touching the
exchange; past that it writes the order row BEFORE the exchange call, so a lost
answer can never leave an order the engine has no name for, and the row and the
send both carry the price that very chain measured.  A post-only rejection is
repriced one tick further from the market and retried under a fresh client order
id, up to `max_post_only_retries` times; each retry re-runs the whole chain on
its own read of the book and sends the price that read produced.

An equity order is the exception at every step: it is written with
`product_type` EQUITY, sent through the exchange's own equity path
(`place_equity_limit`) rather than the crypto one, and never repriced — an
equity print has one side, so the price the owner approved is the price it goes
at, once.  The chain's equity half is `_evaluate_equity_place`; the crypto half
above it is untouched, and a crypto row is still written as SPOT.

An `ai` order is the exception to the retry: the owner approved ONE price, so it
is one attempt at exactly the price the approval stores.  A chain whose maker
price has moved away from that price answers `POST_ONLY_WOULD_CROSS` before a row
is written or the approval is spent, and an exchange that refuses the post-only
order ends the same way, with no reprice.  The approval is spent in the same
transaction that writes the order row, so a lost answer can never spend it twice.  A transient
failure is looked up by client order id and re-sent under the same id only when
it did not land; a lookup that cannot answer leaves the row PENDING_SUBMIT,
which is also where three lost answers leave it, for the reconcile loop.  `cancel_all()` is the kill path:
it sweeps the open `cb-` orders off the exchange without going through `check()`,
so it works while halted.

A halt is per book.  `halt(reason)` with no book is the GLOBAL halt — the kill
switch — and it refuses every order on both books; `halt(reason, book)` halts one
book alone, which is what that book's portfolio drawdown stop does, so a dry
book's drawdown never stops a live bot (or the other way round).  `halt()` sets
the in-memory flag before persisting it and never waits for the cycle lock;
`is_halted()` answers the global flag alone, `is_halted(book)` also answers that
book's own, and either reads the in-memory flag, the persisted marker (a
restarted gateway on the same store is still halted) and the injected callable.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from decimal import Decimal
from typing import Any, Literal, Optional

from . import market_hours, money
from .books import (
    BOOKS,
    DRY,
    LIVE,
    BookRouter,
    LiveLocked,
    Switches,
    route_decision,
)
from .exchange import (
    EQUITY_PREVIEW_UNCONFIRMED,
    PRODUCT_TYPE_UNKNOWN,
    PermanentError,
    TransientError,
    equity_max_age_for,
    new_client_order_id,
)
from .ledger import Ledger
from .limits import CapWindow, Limits
from .money import ProductSpec
from .snapshot import SnapshotCache
from .store import (
    ACTIVE,
    EQUITY,
    OPEN,
    PENDING_SUBMIT,
    REJECTED,
    RESERVED_OWNERS,
    SPOT,
    STOPPED,
    Store,
)
from .strategies.base import MarketSnapshot, OrderIntent

D = Decimal
log = logging.getLogger(__name__)

# ---------------------------------------------------------------- refusal codes
BAD_INTENT = "BAD_INTENT"  # malformed: wrong shape, missing or unusable numbers
WRONG_OWNER = "WRONG_OWNER"  # a source acting as an owner it cannot be
HALTED = "HALTED"  # the halt flag is set
LIVE_DISABLED = "LIVE_DISABLED"  # a live route the ceiling or the switch forbids
LIVE_LOCKED = "LIVE_LOCKED"  # live is allowed but no live exchange can be reached
PRODUCT_NOT_ALLOWED = "PRODUCT_NOT_ALLOWED"  # unresolved, or outside the allow-list
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"  # an ai order with no usable approval
OWNER_PAUSED = "OWNER_PAUSED"  # a bot source whose bot is not ACTIVE
STALE_MARKET = "STALE_MARKET"  # no snapshot, or an unusable or old one
CLOCK_SKEW = "CLOCK_SKEW"  # the skew is unknown or beyond the tolerance
TOO_SMALL = "TOO_SMALL"  # below the product's base or quote minimum
ORDER_TOO_LARGE = "ORDER_TOO_LARGE"  # over the per-source single-order cap
DAILY_CAP = "DAILY_CAP"  # over the global or the ai daily notional cap
RATE_CAP = "RATE_CAP"  # over the global or the ai rolling-hour order count
INSUFFICIENT_HOLDING = "INSUFFICIENT_HOLDING"  # the owner cannot fund the order
UNALLOCATED_NEGATIVE = "UNALLOCATED_NEGATIVE"  # the exchange is short of the owners
DRAWDOWN_STOP = "DRAWDOWN_STOP"  # the owner's or the portfolio's drawdown stop
NOT_OWNER = "NOT_OWNER"  # a cancel of an order this owner does not own

# ---------------------------------------------------------------- equity codes
# The refusals an EQUITY order can earn on top of the ones above: the product's
# own facts (a halt, liquidation only, a closed session, a price outside the
# band, a size the listing does not take) and the equity caps (the pool and the
# account).
TRADING_HALTED = "TRADING_HALTED"  # the product's own spec says trading is halted
LIQUIDATE_ONLY = "LIQUIDATE_ONLY"  # the product may only be sold right now
MARKET_CLOSED = "MARKET_CLOSED"  # outside the regular session
PRICE_BAND = "PRICE_BAND"  # the limit is outside the band around the quote
FRACTIONAL_NOT_ALLOWED = "FRACTIONAL_NOT_ALLOWED"  # a fractional size it refuses
CAPITAL_CAP = "CAPITAL_CAP"  # over the AI's equity capital pool
NO_EQUITY_ACCOUNT = "NO_EQUITY_ACCOUNT"  # the live route has no equity account
EQUITY_UNAVAILABLE = "EQUITY_UNAVAILABLE"  # the stock products are not confirmed

# The refusal codes an exchange's own answer is passed through as, on an equity
# order: the code the adapter named is the code the caller reads.  Everything else
# the exchange refuses stays `EXCHANGE_REJECTED`.
EQUITY_SURFACED_REFUSALS = frozenset(
    {EQUITY_PREVIEW_UNCONFIRMED, PRODUCT_TYPE_UNKNOWN, NO_EQUITY_ACCOUNT}
)

# The equity price band: a buy may rest up to this much above the ask and a sell
# down to this fraction of the bid, and a limit exactly on the band passes.
EQUITY_BUY_BAND = D("1.05")
EQUITY_SELL_BAND = D("0.95")

# ---------------------------------------------------------------- cancel/exec codes
NOT_CANCELLABLE = "NOT_CANCELLABLE"  # no live row to cancel yet, or one already done
CANCEL_FAILED = "CANCEL_FAILED"  # the exchange did not take the cancellation
EXCHANGE_REJECTED = "EXCHANGE_REJECTED"  # the exchange refused the order itself
POST_ONLY_EXHAUSTED = "POST_ONLY_EXHAUSTED"  # every post-only retry was refused
POST_ONLY_WOULD_CROSS = "POST_ONLY_WOULD_CROSS"  # an approved price the book left behind

# The high-water mark key the portfolio drawdown stop reads and the runner
# ratchets with `portfolio_equity()`.  The leading underscore puts it outside the
# bot id grammar (`[a-z0-9]{1,16}`), so it can never name a bot.
PORTFOLIO_OWNER = "_portfolio"

# ---------------------------------------------------------------- halt keys
# The kv key the GLOBAL halt lives under (the kill switch, and the marker an
# earlier run left), and the prefix of the per-book one (`halted:dry`,
# `halted:live`).  One key per halt, so one book's drawdown stop can never set or
# clear the other's, and the global key goes on meaning exactly what it did.
HALT_KEY = "halted"
HALT_BOOK_PREFIX = "halted:"

# Owners a "bot" source may never act as: the reserved non-bot owners and the
# portfolio's own mark key.
NOT_BOT_OWNERS = frozenset(RESERVED_OWNERS) | {PORTFOLIO_OWNER}

# The one owner with no bot row whose route is a switch of its own: it trades the
# live book while `ai_live_enabled` is on, and the simulator otherwise.
AI_OWNER = "ai"

# A snapshot is stale once it is older than this many poll windows.
STALE_WINDOWS = 2
# The most clock skew tolerated, in seconds (either direction).
MAX_CLOCK_SKEW_S = 5.0
# How far a snapshot's timestamp may run ahead of our clock, in seconds.
MAX_FUTURE_S = 5.0
# A bot's own drawdown stop when its params do not name a usable one (percent).
DEFAULT_DRAWDOWN_PCT = 20

# The one exchange status an adopted order may carry into the row: OPEN.
# Every other status (FILLED, CANCELLED, FAILED, anything unknown) records the
# order id alone and leaves the row PENDING_SUBMIT, so reconcile's pending path
# finds it and applies the fills; a terminal status written here would skip that.
ADOPTED_STATUSES = frozenset({OPEN})

# The note a cancellation leaves on the row, appended to whatever is there.
CANCEL_REQUESTED_NOTE = "cancel requested"

# ---------------------------------------------------------------- seed keys
# The kv key holding the equity capital the dry book has already been given, so
# a restart deposits only what it has not seen and never the same money twice.
DRY_EQUITY_SEEDED_KEY = "dry_equity_seeded"
# The currency an equity's cash side is held in, and the note the deposit that
# seeds it leaves in the simulator's own deposit log.
EQUITY_CAPITAL_CURRENCY = "USD"
EQUITY_SEED_NOTE = "seed equity capital"


@dataclass(frozen=True)
class GatewayResult:
    """The outcome of one submit: did it go out, as which cid, or why it did not."""

    ok: bool
    cid: Optional[str]
    refusal: Optional[str]


class ApprovalGone(Exception):
    """The approval an `ai` order needs could not be spent.

    Raised by a `consume_approval` callable when the preview it was given cannot
    be spent — it is no longer `approved`, already spent, or past its window —
    and raised by the gateway's own default, which has no approval to spend at
    all.  The gateway answers it `APPROVAL_REQUIRED` and writes nothing: the row
    that could not be spent and the order row are one transaction.
    """


class OrderGateway:
    """The single gate every intent passes before it may reach the exchange.

    Constructed with its collaborators rather than reaching for them, so the
    check chain can be exercised against any store, clock and snapshot cache.
    `totals()` is the caller's cached totals of the DRY book per currency.  The
    `CapWindow` is built by the caller on the same clock that stamps order rows;
    `now` here is only for snapshot staleness.  `books` is the router that says
    which exchange serves which book (defaulting to this gateway's own `exchange`
    as the simulator and no live account at all) and `switches` the owner's two
    live switches (defaulting to both off).  `self.lock` is the cycle lock:
    `submit`, `cancel_all`, `seed_dry` and `seed_dry_equity_capital` take it,
    while `halt`, `clear_halt` and every read-only method never do.
    `sleep` is the retry backoff, injectable so a caller need not wait.

    `approval_check` and `consume_approval` are the AI's approval rail, wired in
    by whoever owns the previews (`ai_orders.py`).  The check is called as
    `approval_check(approval_id, intent, product=<resolved>, book=<the route's
    book>)` and answers None for an approval that may place this order or the
    refusal code to answer with; the two keyword arguments carry what the
    approval's hash covers, which is a little more than the two positional
    arguments of the plan's signature.  The consumption is called as
    `consume_approval(conn, approval_id)` on the connection of the transaction
    that writes the order row, and raises `ApprovalGone` when the approval cannot
    be spent.  Both default to refusing: a gateway nobody wired an approval rail
    into places no `ai` order at all.

    `session_open` answers whether the regular session is open at a moment in
    epoch seconds; it defaults to `market_hours.is_regular_session` and is asked
    with `self.now()`, so the equity chain's own session step reads the same clock
    as snapshot staleness.  `totals` is a callable and only a callable, so every
    step sees the dry book's totals as they stand now: a mapping is refused with
    `TypeError` rather than wrapped into one stale reading.

    `equity_status` is the equity half's own report
    (`equity_wiring.EquityStatus`): while it refuses a book, an equity product is
    refused with its code before anything of the order is read, and with none
    nothing is gated by it.
    """

    def __init__(
        self,
        *,
        store: Store,
        ledger: Ledger,
        limits: Limits,
        caps: CapWindow,
        snapshots: SnapshotCache,
        spec_for: Callable[[str], ProductSpec],
        fee_rate: Decimal,
        totals: Callable[[], dict[str, Decimal]],
        exchange=None,
        is_halted: Optional[Callable[[], bool]] = None,
        route_for: Optional[Callable[[str], str]] = None,
        books: Optional[BookRouter] = None,
        switches: Optional[Switches] = None,
        now: Callable[[], float] = time.time,
        max_post_only_retries: int = 5,
        sleep: Callable[[float], None] = time.sleep,
        approval_check: Optional[Callable[..., Optional[str]]] = None,
        consume_approval: Optional[Callable[..., None]] = None,
        session_open: Callable[[float], bool] = market_hours.is_regular_session,
        equity_status: Optional[Any] = None,
    ) -> None:
        self.store = store
        self.ledger = ledger
        self.limits = limits
        self.caps = caps
        self.snapshots = snapshots
        self.spec_for = spec_for
        self.fee_rate = D(fee_rate)
        # The dry book's totals as the caller reads them: a callable so every
        # step sees the account as it stands.  A mapping is refused rather than
        # wrapped: one reading of it would be a figure nobody updates.
        if not callable(totals):
            raise TypeError(
                "totals must be a callable returning the dry book's totals"
            )
        self.totals = totals
        self.exchange = exchange  # seed_dry's account; check() never reads it
        self.books = books if books is not None else BookRouter(exchange, None)
        self.switches = switches if switches is not None else Switches(store, {})
        self.equity_status = equity_status
        self._injected_halt = is_halted if is_halted is not None else _never_halted
        self.route_for = route_for if route_for is not None else self._default_route
        self.now = now
        self.session_open = session_open
        self.max_post_only_retries = int(max_post_only_retries)
        self.sleep = sleep
        self.approval_check = (
            approval_check if approval_check is not None else _refuse_every_approval
        )
        self.consume_approval = (
            consume_approval if consume_approval is not None else _consume_nothing
        )
        self.lock = threading.RLock()
        self._halt_event = threading.Event()
        # The per-book flags, held here as well as in the store so one is set
        # before it is persisted, exactly like the global event above.
        self._book_halts: set[str] = set()

    # ------------------------------------------------ the books
    def _default_route(self, owner: str) -> str:
        """Which book an owner trades when the caller wires no route of its own.

        A bot trades the book its own row's `mode` names, so a switched bot is
        routed without anything being rebuilt.  The `ai` owner has no bot row: it
        trades the live book only while `ai_live_enabled` is on and the simulator
        otherwise.  Every other owner (a reserved owner, a vanished bot) is dry.
        """
        bot = self.store.get_bot(owner)
        if bot is not None:
            return bot["mode"]
        if owner == AI_OWNER:
            return LIVE if self.switches.ai_live_enabled() else DRY
        return DRY

    def _switch_for(self, owner: str) -> bool:
        """The owner's own live switch: the ai owner has one, every bot the other."""
        if owner == AI_OWNER:
            return self.switches.ai_live_enabled()
        return self.switches.live_enabled()

    def _route(self, owner: str) -> tuple[str, Optional[str]]:
        """The book *owner*'s orders take, and the refusal that stopped it.

        `LIVE_DISABLED` (the ceiling or the switch) is answered before
        `LIVE_LOCKED` (no live exchange), and a refused live route is never
        rerouted onto the simulator.  Only a live route asks the router whether a
        live exchange is there at all: a dry route never looks for one.
        """
        mode = self.route_for(owner)
        return route_decision(
            ceiling=self.switches.ceiling,
            switch=self._switch_for(owner),
            have_exchange=mode == LIVE and self.books.live_available(),
            mode=mode,
        )

    def _totals_for(self, book: str) -> dict[str, Decimal]:
        """The totals of one book: the injected dry ones, or the live account's own.

        The live book's totals come from the router (`crypto_totals`), never from
        the dry callable: the money it allocates from is the real account's.
        """
        if book == DRY:
            return self.totals()
        return self.books.totals(LIVE)

    def _equity_totals_for(self, book: str) -> dict[str, Decimal]:
        """The totals an equity order's money check reads: that book's own.

        The dry book is the injected totals.  The live book is the EQUITY account's
        own (`live.equity.totals()`), never the crypto account's: the shares and
        the cash an equity order draws on live there, and the crypto side of the
        live account is the crypto orders' money.  An account that cannot be
        reached answers nothing, which reads as short and refuses the order rather
        than passing it against no totals at all.
        """
        if book == DRY:
            return self.totals()
        live = self.books.live_exchange()
        account = None if live is None else getattr(live, "equity", None)
        if account is None:
            return {}
        return account.totals()

    def _product_type(self, product: str) -> str:
        """The kind an order row for *product* is written with: `SPOT` or `EQUITY`.

        It is the engine's own allow-list that decides, i.e. exactly the question
        the chain branches on, so the row a placement writes and the chain it
        passed can never disagree about which instrument it was.
        """
        return EQUITY if self.limits.is_equity(product) else SPOT

    # ------------------------------------------------ the chain
    def check(
        self,
        source: str,
        owner: str,
        intent: OrderIntent,
        product: Optional[str] = None,
    ) -> Optional[str]:
        """Return the first refusal for *intent*, or None when it may go out.

        A place intent is answered by `_evaluate_place` and only its refusal is
        kept: the chain runs in the module docstring's order.  A cancel intent
        runs the shape check and then the ownership check alone.  `source` is
        "bot" or "ai", and it has to match the owner: "ai" only ever acts as the
        `ai` owner, "bot" only as a real bot.  `product` defaults to the owner's
        bot row product and must be given when the owner has no bot row ("ai").

        This is the read-only question "would the chain allow this", so for an
        `ai` order it runs the AI's approval step too: without an approved,
        unspent, unexpired preview of exactly this order the answer is
        `APPROVAL_REQUIRED`, which is the same step `submit()` takes.  A bot never
        takes an approval.  The ONE approval-free path is `evaluate()`, which is
        the measurement a preview is built from.  Reads store, caps, ledger and
        snapshots; calls no exchange method and writes nothing.
        """
        if intent.action == "cancel":
            if self._is_bad_cancel(intent):
                return BAD_INTENT
            return self._check_cancel(owner, intent)
        return self._evaluate_place(
            source, owner, intent, product, require_approval=True
        )[0]

    def evaluate(
        self,
        source: str,
        owner: str,
        intent: OrderIntent,
        product: Optional[str] = None,
    ) -> tuple[
        Optional[str],
        Optional[str],
        Optional[str],
        Optional[MarketSnapshot],
        Optional[ProductSpec],
        Optional[Decimal],
    ]:
        """`_evaluate_place` as a caller may read it: no approval step, no writes.

        The whole place chain without the AI's approval — the one approval-free
        path there is, so a caller that wants "what would the chain say about this
        order" asks here and nowhere else, and an `ai` order measured this way is
        never an order that may go out: `check()` and `submit()` both ask the
        approval.  Answers
        `(refusal, book, product, snap, spec, price)`, where the price is the
        maker price the order would be sent at.  That is the measurement a
        preview is built from, so a preview and the check that later places the
        order read one chain.
        """
        return self._evaluate_place(
            source, owner, intent, product, require_approval=False
        )

    def route(self, owner: str) -> tuple[str, Optional[str]]:
        """The book *owner*'s orders take right now, and the refusal that stopped it.

        The same answer the chain's route step reads: the book a preview belongs
        to, and — for a live route the ceiling, the switch or a missing account
        forbids — the code the route refuses with.  Writes nothing and reaches no
        exchange: it only asks whether a live exchange exists at all.
        """
        return self._route(owner)

    def _evaluate_place(
        self,
        source: str,
        owner: str,
        intent: OrderIntent,
        product: Optional[str],
        *,
        require_approval: bool = False,
    ) -> tuple[
        Optional[str],
        Optional[str],
        Optional[str],
        Optional[MarketSnapshot],
        Optional[ProductSpec],
        Optional[Decimal],
    ]:
        """Run the whole place chain once and report what it measured.

        Returns `(refusal, book, product, snap, spec, price)`.  On a refusal only
        the first item is set and the rest are None.  On success `book` is the
        book the route decided — the book every step after it reads and the book
        the caller writes its order row with — `product` is the resolved product,
        `snap` the single snapshot the chain read, `spec` its spec and `price`
        the maker price every minimum, cap, funds and drawdown step was measured
        against: the caller sends that price rather than reading a fresher book
        of its own.  Read-only and exchange-free, exactly like `check()`.

        The halt is judged for the order's own book, so it is answered after the
        route: the global halt refuses both books, a book's own halt only that
        book, and either still outranks the route's refusal.  Both come before
        the product, so a live route the switches or the missing account forbid
        is refused `LIVE_DISABLED`/`LIVE_LOCKED` before anything of the order is
        looked at, and never rerouted onto the other book.

        `require_approval` adds the AI's own step, directly after the product: an
        `ai` order has to name a non-empty approval id whose preview the wired
        `approval_check` accepts for THIS resolved product, this order and this
        book, or it is refused `APPROVAL_REQUIRED`.  A bot source never takes an
        approval, and neither does a caller that left the flag off.

        An EQUITY product is one `limits.is_equity` names, and it is answered by
        the equity half below (`_evaluate_equity_place`) from the approval on: the
        equity status's own refusal and then the two equity gates right after the
        route, then the product, the approval and the instrument's own facts.
        They are judged on the `product` argument, because the route and the
        account are facts of the request rather than of the resolved allow-list —
        a live route with equity live off refuses before anything of the product
        is known, and a stock whose kind no key has confirmed is refused on both
        books.  The crypto steps below that point are the ones they always were.
        """
        if self._is_bad_place(intent):
            return BAD_INTENT, None, None, None, None, None
        bot = self.store.get_bot(owner)
        if not self._is_bound(source, owner, bot):
            return WRONG_OWNER, None, None, None, None, None
        book, refusal = self._route(owner)
        if self.is_halted(book):
            return HALTED, None, None, None, None, None
        if refusal is not None:
            return refusal, None, None, None, None, None
        if product is not None and self.limits.is_equity(product):
            status_refusal = self._equity_status_refusal(book)
            if status_refusal is not None:
                return status_refusal, None, None, None, None, None
        if product is not None and book == LIVE and self.limits.is_equity(product):
            if not self.limits.equity_live:
                return LIVE_DISABLED, None, None, None, None, None
            live = self.books.live_exchange()
            if getattr(live, "equity", None) is None:
                return NO_EQUITY_ACCOUNT, None, None, None, None, None

        resolved = self._resolve_product(bot, product, source)
        if resolved is None:
            return PRODUCT_NOT_ALLOWED, None, None, None, None, None
        if require_approval and source == "ai":
            refusal = self._check_approval(intent, resolved, book)
            if refusal is not None:
                return refusal, None, None, None, None, None
        if self.limits.is_equity(resolved):
            return self._evaluate_equity_place(source, owner, intent, resolved, book)
        if source == "bot" and bot["status"] != ACTIVE:
            return OWNER_PAUSED, None, None, None, None, None

        snap = self.snapshots.get(resolved)
        if snap is None or self._is_unusable(snap):
            return STALE_MARKET, None, None, None, None, None
        skew = self.snapshots.skew_s()
        if skew is None or abs(skew) > MAX_CLOCK_SKEW_S:
            return CLOCK_SKEW, None, None, None, None, None

        spec = self.spec_for(resolved)
        price = money.maker_price(
            intent.side, intent.limit_price, snap.bid, snap.ask, spec.price_increment
        )
        refusal = self._check_size_and_caps(source, intent, price, spec, book)
        if refusal is not None:
            return refusal, None, None, None, None, None
        try:
            refusal = self._check_funds(owner, resolved, intent, price, book)
        except LiveLocked:
            # The live account went away between the route and the check: the
            # book is unreachable, so the order is refused rather than measured
            # against the other book's money.
            return LIVE_LOCKED, None, None, None, None, None
        if refusal is not None:
            return refusal, None, None, None, None, None
        refusal = self._check_drawdown(source, owner, resolved, snap, bot, book)
        if refusal is not None:
            return refusal, None, None, None, None, None
        return None, book, resolved, snap, spec, price

    def _evaluate_equity_place(
        self,
        source: str,
        owner: str,
        intent: OrderIntent,
        product: str,
        book: str,
    ) -> tuple[
        Optional[str],
        Optional[str],
        Optional[str],
        Optional[MarketSnapshot],
        Optional[ProductSpec],
        Optional[Decimal],
    ]:
        """The equity half of the place chain, from the instrument's own facts on.

        Runs once the intent is bound, the route allowed, the product resolved and
        the approval taken — those steps are the crypto chain's own and are
        answered before this is reached.  Answers the same 6-tuple, and on success
        the price is `intent.limit_price`: an equity quote is one print, so no
        maker price is derived from a book and an equity order is never repriced.
        The notional every cap reads is `size * price` with no fee, because an
        equity pays none.

        The caps are the equity ones throughout: the daily budget is the EQUITY
        rows of this book alone, the buy's capital is the AI's equity pool
        (`ledger.equity_pool_used`, which is the spend and never a partial fill's
        remainder), and the money check reads the equity account's own totals on
        the live book.  The rolling-hour count and the portfolio drawdown stop are
        shared with crypto exactly as they were.

        The print's own age is the BOOK's question, and `_print_unusable` is
        where it is asked.  A snapshot carrying `print_ts` — an equity print,
        which is what the poll stores — is usable only while `now - print_ts` is
        inside `equity_max_age_for(book)`: the practice bound lets a
        five-minute-old print price a dry order, and the strict one refuses
        anything past two minutes on the live book, whatever the poll was
        willing to accept for practice.  A snapshot with no `print_ts` (one
        built before prints carried their own time) carries no age a live order
        could be judged by, so every book but the practice one refuses it
        `STALE_MARKET` outright; the practice book goes on judging it by its
        `ts` exactly as it always did, in `_is_unusable`.

        Only the `ai` owner ever gets here (`_resolve_product`), so there is no
        bot half to the drawdown stop and no `OWNER_PAUSED`.
        """
        spec = self.spec_for(product)
        if spec.trading_halted:
            return TRADING_HALTED, None, None, None, None, None
        if intent.side == money.BUY and spec.liquidate_only:
            return LIQUIDATE_ONLY, None, None, None, None, None
        if not self.session_open(self.now()):
            return MARKET_CLOSED, None, None, None, None, None
        snap = self.snapshots.get(product)
        if snap is None or self._is_unusable(snap, equity=True):
            return STALE_MARKET, None, None, None, None, None
        if self._print_unusable(snap, book):
            return STALE_MARKET, None, None, None, None, None
        skew = self.snapshots.skew_s()
        if skew is None or abs(skew) > MAX_CLOCK_SKEW_S:
            return CLOCK_SKEW, None, None, None, None, None

        price = intent.limit_price
        if intent.side == money.BUY:
            if price > snap.ask * EQUITY_BUY_BAND:
                return PRICE_BAND, None, None, None, None, None
        elif price < snap.bid * EQUITY_SELL_BAND:
            return PRICE_BAND, None, None, None, None, None
        if money.too_small(intent.size, price, spec) is not None:
            return TOO_SMALL, None, None, None, None, None
        if not _is_whole(intent.size):
            if not spec.fractionable:
                return FRACTIONAL_NOT_ALLOWED, None, None, None, None, None
            floor = spec.fractional_notional_min_size
            if floor is not None and intent.size * price < floor:
                return FRACTIONAL_NOT_ALLOWED, None, None, None, None, None

        notional = intent.size * price
        if notional > self.limits.equity_max_order_usd:
            return ORDER_TOO_LARGE, None, None, None, None, None
        if (
            self.caps.daily_notional(None, book=book, product_type=EQUITY) + notional
            > self.limits.equity_daily_notional_usd
        ):
            return DAILY_CAP, None, None, None, None, None
        if intent.side == money.BUY:
            if (
                self.ledger.equity_pool_used(book) + notional
                > self.limits.equity_ai_capital_usd
            ):
                return CAPITAL_CAP, None, None, None, None, None
        elif (
            intent.size
            > self.ledger.holding(owner, product, book=book).available_base
        ):
            return INSUFFICIENT_HOLDING, None, None, None, None, None
        if (
            self.caps.orders_last_hour(None, book=book) + 1
            > self.limits.orders_per_hour
        ):
            return RATE_CAP, None, None, None, None, None
        if source == AI_OWNER and (
            self.caps.orders_last_hour(AI_OWNER, book=book) + 1
            > self.limits.ai_orders_per_hour
        ):
            return RATE_CAP, None, None, None, None, None
        base, quote = product.split("-", 1)
        spent = quote if intent.side == money.BUY else base
        if (
            self.ledger.unallocated(self._equity_totals_for(book), book=book).get(
                spent, D(0)
            )
            < 0
        ):
            return UNALLOCATED_NEGATIVE, None, None, None, None, None
        refusal = self._check_drawdown(source, owner, product, snap, None, book)
        if refusal is not None:
            return refusal, None, None, None, None, None
        return None, book, product, snap, spec, price

    def _equity_status_refusal(self, book: str) -> Optional[str]:
        """The equity status's refusal for *book*, or None when it has none.

        Only an equity product asks this, and it asks before any of the order is
        read: while the stock products are unconfirmed, or a live route's own
        preview confirmation is missing, the status names the code and nothing of
        the order, the book or the account is looked at.  A gateway with no status
        wired in has nothing of the kind to say, which is the crypto-only install
        and every caller that brought its own report.
        """
        status = self.equity_status
        if status is None:
            return None
        return status.refusal(book)

    # ------------------------------------------------ cancel
    def _check_cancel(self, owner: str, intent: OrderIntent) -> Optional[str]:
        """NOT_OWNER unless the id is shaped for *owner* and the row says so."""
        cid = intent.cancel_cid
        if not cid.startswith(f"cb-{owner}-"):
            return NOT_OWNER
        row = self.store.order(cid)
        if row is None or row["owner"] != owner:
            return NOT_OWNER
        return None

    # ------------------------------------------------ step helpers
    @staticmethod
    def _is_bad_place(intent: OrderIntent) -> bool:
        """True when the intent is not a well-formed place.

        A place needs a known side and a strictly positive, finite `Decimal` size
        and limit price, and it carries no cancellation id: a float, an int or a
        string is refused rather than coerced, because a price that quietly lost
        precision would slip past every cap and minimum downstream.
        """
        if intent.action != "place":
            return True
        if intent.side not in (money.BUY, money.SELL):
            return True
        if intent.cancel_cid is not None:
            return True
        if not _is_positive_decimal(intent.size):
            return True
        return not _is_positive_decimal(intent.limit_price)

    @staticmethod
    def _is_bad_cancel(intent: OrderIntent) -> bool:
        """True when the intent is not a bare cancellation.

        A cancel names one order id and nothing else: a side, a size or a price on
        it means the caller built a place intent by mistake, and an empty id could
        never match a row.
        """
        if intent.side is not None or intent.size is not None:
            return True
        if intent.limit_price is not None:
            return True
        cid = intent.cancel_cid
        return not isinstance(cid, str) or not cid

    @staticmethod
    def _is_bound(source: str, owner: str, bot: Optional[dict]) -> bool:
        """True when *source* and *owner* belong together.

        "ai" acts only as the `ai` owner.  "bot" acts only as a real bot: not one
        of the reserved non-bot owners, not the portfolio's own mark key, and the
        bot row has to exist.  An unknown source binds to nothing.
        """
        if source == "ai":
            return owner == AI_OWNER
        if source == "bot":
            return bot is not None and owner not in NOT_BOT_OWNERS
        return False

    def _resolve_product(
        self, bot: Optional[dict], product: Optional[str], source: Optional[str] = None
    ) -> Optional[str]:
        """The product to trade, or None when it cannot be resolved or is unlisted.

        A given product has to match the owner's bot row when there is one; with
        no bot row it stands alone (the "ai" owner).  The product then has to be
        on one of the engine's lists — `limits.tradable`, crypto or equity.

        An equity product is the `ai` owner's alone: it resolves only for the
        "ai" source with no bot row, so a bot's own row naming an equity, or a
        "bot" source offering one, answers None (`PRODUCT_NOT_ALLOWED`).
        """
        if product is None:
            if bot is None:
                return None
            product = bot["product"]
        elif bot is not None and product != bot["product"]:
            return None
        if not self.limits.tradable(product):
            return None
        if self.limits.is_equity(product) and (source != AI_OWNER or bot is not None):
            return None
        return product

    def _check_approval(
        self, intent: OrderIntent, product: str, book: str
    ) -> Optional[str]:
        """The AI's approval step: `APPROVAL_REQUIRED`, or None when it may place.

        An `ai` order goes out only with the owner's answer behind it, so it has to
        name an approval id and the wired `approval_check` has to accept it for
        THIS order: the resolved product, the side, the size, the price and the
        book the route decided.  A missing, empty or non-string id is refused
        without asking anything, and a check that raises is a refusal rather than
        an approval — an approval is never inferred from a failure.
        """
        approval_id = intent.approval_id
        if not isinstance(approval_id, str) or not approval_id:
            return APPROVAL_REQUIRED
        try:
            refusal = self.approval_check(
                approval_id, intent, product=product, book=book
            )
        except Exception:  # noqa: BLE001 - a broken approval is no approval
            log.error("the AI approval check failed; the order is refused")
            return APPROVAL_REQUIRED
        return None if refusal is None else refusal

    def _print_unusable(self, snap: MarketSnapshot, book: Optional[str]) -> bool:
        """True when the snapshot's own PRINT is one *book* may not be priced from.

        An equity print carries its own time (`MarketSnapshot.print_ts`), and the
        age bound is the book's and nothing else's (`equity_max_age_for`): the
        practice book takes a five-minute print, and every other book — the live
        one, an unknown word, none at all — the strict two minutes, so a misread
        book is never the looser rule.

        A print with no time of its own is no live price at all: the age a live
        reader would judge it by is unknown, so a book that is not the practice
        one refuses it outright.  The practice book keeps the old reading and
        leaves such a snapshot to `_is_unusable`'s rule on its `ts`, exactly as
        it always did.
        """
        print_ts = getattr(snap, "print_ts", None)
        if print_ts is None:
            return book != DRY
        return self.now() - print_ts > equity_max_age_for(book)

    def _is_unusable(self, snap: MarketSnapshot, *, equity: bool = False) -> bool:
        """True when the snapshot cannot price an order.

        Unusable is: a bid at or below zero, an ask at or below the bid (an empty
        or crossed book, from which neither side of the spread can be trusted), a
        timestamp ahead of our clock by more than the tolerance, or one older than
        twice the poll interval.

        An equity print is ONE price, so its two sides are equal and that is
        usable: `equity=True` refuses only an ask BELOW the bid (a print that
        cannot be true), and reads every other rule exactly as the crypto one does.
        """
        now = self.now()
        if snap.bid <= 0:
            return True
        if equity:
            if snap.ask < snap.bid:
                return True
        elif snap.ask <= snap.bid:
            return True
        if snap.ts > now + MAX_FUTURE_S:
            return True
        return now - snap.ts > STALE_WINDOWS * self.limits.poll_seconds

    def _check_size_and_caps(
        self,
        source: str,
        intent: OrderIntent,
        price: Decimal,
        spec: ProductSpec,
        book: str,
    ) -> Optional[str]:
        """TOO_SMALL, ORDER_TOO_LARGE, DAILY_CAP, RATE_CAP — in that order.

        Both caps are read on the route's own book, so a dry-heavy day never
        spends the live book's budget (or the other way round), and the daily
        sums are the SPOT rows alone: an equity order's notional is the equity
        budget's, never the crypto one's.
        """
        if money.too_small(intent.size, price, spec) is not None:
            return TOO_SMALL
        notional = intent.size * price
        order_cap = (
            self.limits.ai_max_order_usd
            if source == "ai"
            else self.limits.bot_max_order_usd
        )
        if notional > order_cap:
            return ORDER_TOO_LARGE
        if (
            self.caps.daily_notional(None, book=book, product_type=SPOT) + notional
            > self.limits.daily_notional_usd
        ):
            return DAILY_CAP
        if source == "ai" and (
            self.caps.daily_notional("ai", book=book, product_type=SPOT) + notional
            > self.limits.ai_daily_notional_usd
        ):
            return DAILY_CAP
        if (
            self.caps.orders_last_hour(None, book=book) + 1
            > self.limits.orders_per_hour
        ):
            return RATE_CAP
        if source == "ai" and (
            self.caps.orders_last_hour("ai", book=book) + 1
            > self.limits.ai_orders_per_hour
        ):
            return RATE_CAP
        return None

    def _check_funds(
        self,
        owner: str,
        product: str,
        intent: OrderIntent,
        price: Decimal,
        book: str,
    ) -> Optional[str]:
        """INSUFFICIENT_HOLDING, then UNALLOCATED_NEGATIVE for the spent currency.

        A buy spends the product's quote currency and a sell spends its base, so
        the unallocated check looks at whichever of the two this order draws on: a
        short exchange is exactly the case where one owner's order would spend
        another owner's money.  Both reads are of the route's own book — that
        book's capital, that book's rows and that book's totals — so a dry
        holding can never fund a live order or the reverse.
        """
        base, quote = product.split("-", 1)
        holding = self.ledger.holding(owner, product, book=book)
        if intent.side == money.BUY:
            cost = money.buy_cost(intent.size, price, self.fee_rate)
            if cost > holding.available_quote:
                return INSUFFICIENT_HOLDING
            spent = quote
        else:
            if intent.size > holding.available_base:
                return INSUFFICIENT_HOLDING
            spent = base
        if self.ledger.unallocated(self._totals_for(book), book=book).get(spent, D(0)) < 0:
            return UNALLOCATED_NEGATIVE
        return None

    def _check_drawdown(
        self,
        source: str,
        owner: str,
        product: str,
        snap: MarketSnapshot,
        bot: Optional[dict],
        book: str,
    ) -> Optional[str]:
        """DRAWDOWN_STOP for the owner (bots only), then for the whole portfolio.

        The owner's high-water mark is read here, never ratcheted: the runner
        moves it.  The marks and the marks' own equity are read on the route's
        book, so a bot that switched books is measured against the mark of the
        book it trades now, and the portfolio half is the mark of the bots on
        that same book.  The portfolio half only runs when such a mark exists,
        and an unknown portfolio valuation there refuses: a stop that cannot be
        measured must never step out of the way.
        """
        mid = (snap.bid + snap.ask) / 2
        if source == "bot":
            hwm = self.store.hwm(owner, book)
            if hwm is not None and hwm > 0:
                pct = bot_drawdown_pct(bot)
                equity = self.ledger.equity(
                    owner, {product: mid}, product, book=book
                )
                if equity < hwm * (1 - pct / 100):
                    return DRAWDOWN_STOP
        hwm = self.store.hwm(PORTFOLIO_OWNER, book)
        if hwm is not None and hwm > 0:
            equity = self.portfolio_equity(book)
            floor = hwm * (1 - self.limits.portfolio_drawdown_pct / 100)
            if equity is None or equity < floor:
                return DRAWDOWN_STOP
        return None

    # ------------------------------------------------ halt
    def halt(self, reason: str, book: Optional[str] = None) -> None:
        """Stop trading, globally or on one book: the flag first, then the marker.

        With no *book* the halt is GLOBAL — the kill switch — and it refuses
        every order on both books.  With a book it halts that book alone, which
        is what that book's portfolio drawdown stop does: the other book's bots
        go on trading.  The flag is set before the write so a submit that is
        already queued is refused even if persisting fails.  `self.lock` is
        deliberately not taken: a kill must never queue behind a cycle that is
        holding it.
        """
        key = self._halt_key(book)
        if book is None:
            self._halt_event.set()
        else:
            self._book_halts.add(book)
        try:
            self.store.put(key, {"reason": reason, "ts": time.time()})
        except Exception as error:  # noqa: BLE001 - the flag is already set
            log.error("halt: could not persist the flag: %s", error, exc_info=True)
            raise

    def clear_halt(self, book: Optional[str] = None) -> None:
        """Lower the halt, in memory and in the store.  Takes no lock.

        With no *book* the global flag comes down and so does every book's.  With
        a book only that book's does: the global flag and the other book's halt
        are left exactly as they were, so clearing one book's drawdown can never
        lift a kill.
        """
        if book is None:
            self._halt_event.clear()
            self._book_halts.clear()
            for name in BOOKS:
                self.store.put(self._halt_key(name), None)
            self.store.put(HALT_KEY, None)
            return
        self._book_halts.discard(book)
        self.store.put(self._halt_key(book), None)

    def is_halted(self, book: Optional[str] = None) -> bool:
        """True when the halt in question is set here, persisted, or injected.

        With no *book* the answer is the GLOBAL halt alone: the event this
        gateway set, the marker an earlier run persisted, or the injected
        callable.  With a book it is also that book's own halt, because a global
        halt stops every book while a book's halt stops only that one.
        """
        if self._halt_event.is_set():
            return True
        if self.store.get(HALT_KEY):
            return True
        if bool(self._injected_halt()):
            return True
        return book is not None and self._book_halted(book)

    def halted_books(self) -> dict[str, bool]:
        """Each book's effective halt: its own flag, or the global one above it."""
        return {book: self.is_halted(book) for book in BOOKS}

    def halt_reason(self, book: Optional[str] = None) -> Optional[str]:
        """The reason recorded for the global halt, or for one book's own halt.

        A book's reason is that book's marker alone: the global halt's reason
        belongs to the global flag, so a reader can tell a kill from one book's
        drawdown.  An absent or malformed marker answers None.
        """
        stored = self.store.get(self._halt_key(book))
        return stored.get("reason") if isinstance(stored, dict) else None

    def _book_halted(self, book: str) -> bool:
        """One book's own flag: set here, or persisted by this or an earlier run."""
        return book in self._book_halts or bool(
            self.store.get(self._halt_key(book))
        )

    @staticmethod
    def _halt_key(book: Optional[str]) -> str:
        """The kv key a halt lives under: the global one, or a book's own.

        A book this engine does not know is a programming error rather than a
        third book, so it is refused before any key is read or written.
        """
        if book is None:
            return HALT_KEY
        if book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        return f"{HALT_BOOK_PREFIX}{book}"

    # ------------------------------------------------ execution
    def submit(
        self,
        source: str,
        owner: str,
        intent: OrderIntent,
        product: Optional[str] = None,
    ) -> GatewayResult:
        """Run one intent under the cycle lock: refuse it, or put it on the exchange."""
        with self.lock:
            if intent.action == "cancel":
                return self._submit_cancel(source, owner, intent, product)
            return self._submit_place(source, owner, intent, product)

    def _submit_place(
        self,
        source: str,
        owner: str,
        intent: OrderIntent,
        product: Optional[str],
    ) -> GatewayResult:
        """Place one post-only order, repricing and retrying a post-only refusal.

        Every attempt runs the whole chain through `_evaluate_place` and sends
        exactly the price that call returned, so one attempt reads the book once:
        the priced book is always the checked one.  The row is written on the
        book the chain decided, with that price, before every send, so the engine
        always has a name for an order whose answer was lost.  The send goes to
        that book's own exchange (`books.for_book`): a live book that has become
        unreachable is refused `LIVE_LOCKED` before the row is written, never
        sent to the simulator.  An unknown outcome (None from `_send`) leaves the
        row PENDING_SUBMIT and counts as accepted: the reconcile loop resolves it.
        An adopted order's row is settled by `_adopt` (OPEN only when the exchange
        says OPEN), so it is left as it is.  Each retry re-runs the chain at its own price, because
        a reprice moves a sell UP and can push the notional over a cap.  An `ai`
        order never reaches this loop: `_submit_ai_place` sends it once, at the
        price the owner approved.
        """
        level = intent.level if intent.level is not None else 0
        if source == "ai":
            return self._submit_ai_place(source, owner, intent, product, level)
        attempt_intent = intent
        cid: Optional[str] = None
        for _attempt in range(self.max_post_only_retries + 1):
            refusal, book, resolved, _snap, spec, price = self._evaluate_place(
                source, owner, attempt_intent, product
            )
            if refusal is not None:
                return GatewayResult(False, None, refusal)
            try:
                exchange = self.books.for_book(book)
            except LiveLocked:
                return GatewayResult(False, None, LIVE_LOCKED)
            cid = new_client_order_id(f"cb-{owner}-", intent.side, level)
            self.store.insert_order(
                cid,
                owner,
                source,
                resolved,
                intent.side,
                level,
                price,
                intent.size,
                consumes_fill=intent.consumes_fill,
                book=book,
                product_type=self._product_type(resolved),
            )
            res = self._send(exchange, cid, resolved, intent.side, intent.size, price)
            if res is None:
                return GatewayResult(True, cid, None)
            if res["ok"]:
                if not res.get("adopted"):
                    self.store.update_order(
                        cid, status=OPEN, order_id=res["order_id"]
                    )
                return GatewayResult(True, cid, None)
            reason = str(res.get("reason") or "")
            self.store.update_order(cid, status=REJECTED, note=reason)
            if "POST_ONLY" not in reason:
                return GatewayResult(False, cid, EXCHANGE_REJECTED)
            attempt_intent = replace(
                intent,
                limit_price=money.reprice_away(
                    intent.side, price, spec.price_increment
                ),
            )
        return GatewayResult(False, cid, POST_ONLY_EXHAUSTED)

    def _submit_ai_place(
        self,
        source: str,
        owner: str,
        intent: OrderIntent,
        product: Optional[str],
        level: int,
    ) -> GatewayResult:
        """Place one approved AI order: ONE attempt, at the approved price, never repriced.

        The owner approved one price, so this is a single attempt at exactly that
        price.  The chain runs first, with the approval step in it; a refusal
        answers with its code and touches nothing.  The chain's maker price has to
        be the approved price: if the book has moved so the order would cross, the
        answer is `POST_ONLY_WOULD_CROSS` before a row is written or the approval
        spent.  Only then is the approval consumed — on the same connection, in
        the same transaction, as the PENDING_SUBMIT order row, so the two commit
        together or neither does; an approval that cannot be spent answers
        `APPROVAL_REQUIRED` and writes nothing.

        One send follows, under the id the approval names (`cb-ai-<approval id>`).
        An unknown outcome leaves the row PENDING_SUBMIT for reconcile, exactly as
        a bot's does.  An exchange rejection is recorded on the row and is never
        retried: a post-only refusal answers `POST_ONLY_WOULD_CROSS` (the price
        moved; ask again) and everything else `EXCHANGE_REJECTED`.

        An EQUITY order is the same one attempt, written with `product_type`
        EQUITY and sent through the exchange's equity path; its chain price IS the
        approved price, so it is never the crossed case.  The three codes an
        exchange's equity path names about itself (`EQUITY_PREVIEW_UNCONFIRMED`,
        `NO_EQUITY_ACCOUNT`, `PRODUCT_TYPE_UNKNOWN`) are answered to the caller
        as they are — the row still records them as its note — because they say
        what the caller has to fix rather than that the order was bad.
        """
        refusal, book, resolved, _snap, _spec, price = self._evaluate_place(
            source, owner, intent, product, require_approval=True
        )
        if refusal is not None:
            return GatewayResult(False, None, refusal)
        equity = self.limits.is_equity(resolved)
        if price != intent.limit_price:
            # The approved price is the only price this order may be sent at, and
            # the book has moved through it: nothing is written, nothing is sent.
            return GatewayResult(False, None, POST_ONLY_WOULD_CROSS)
        try:
            exchange = self.books.for_book(book)
        except LiveLocked:
            return GatewayResult(False, None, LIVE_LOCKED)
        cid = f"cb-ai-{intent.approval_id}"
        try:
            with self.store.tx() as conn:
                self.consume_approval(conn, intent.approval_id)
                self.store.insert_order(
                    cid,
                    owner,
                    source,
                    resolved,
                    intent.side,
                    level,
                    price,
                    intent.size,
                    consumes_fill=intent.consumes_fill,
                    book=book,
                    product_type=EQUITY if equity else SPOT,
                )
        except ApprovalGone:
            return GatewayResult(False, None, APPROVAL_REQUIRED)
        res = self._send(
            exchange, cid, resolved, intent.side, intent.size, price, equity=equity
        )
        if res is None:
            return GatewayResult(True, cid, None)
        if res["ok"]:
            if not res.get("adopted"):
                self.store.update_order(cid, status=OPEN, order_id=res["order_id"])
            return GatewayResult(True, cid, None)
        reason = str(res.get("reason") or "")
        self.store.update_order(cid, status=REJECTED, note=reason)
        if "POST_ONLY" in reason:
            return GatewayResult(False, cid, POST_ONLY_WOULD_CROSS)
        if equity and reason in EQUITY_SURFACED_REFUSALS:
            return GatewayResult(False, cid, reason)
        return GatewayResult(False, cid, EXCHANGE_REJECTED)

    def _submit_cancel(
        self,
        source: str,
        owner: str,
        intent: OrderIntent,
        product: Optional[str],
    ) -> GatewayResult:
        """Cancel one order this owner holds; reconcile moves the row to CANCELLED.

        The cancel goes to the exchange of the book the ORDER ROW is on, not to
        whichever book a route would pick now: an order resting on one book is
        taken off that book.  A live exchange that cannot be reached is refused
        `LIVE_LOCKED`, and nothing is sent anywhere else.
        """
        cid = intent.cancel_cid
        refusal = self.check(source, owner, intent, product)
        if refusal is not None:
            return GatewayResult(False, None, refusal)
        row = self.store.order(cid)
        if (
            row is None
            or row["status"] not in (PENDING_SUBMIT, OPEN)
            or row["order_id"] is None
        ):
            return GatewayResult(False, cid, NOT_CANCELLABLE)
        try:
            exchange = self.books.for_book(row["book"])
        except LiveLocked:
            return GatewayResult(False, cid, LIVE_LOCKED)
        order_id = row["order_id"]
        try:
            res = exchange.cancel([order_id])
        except (TransientError, PermanentError) as error:
            log.warning("cancel %s: %s", cid, error)
            return GatewayResult(False, cid, CANCEL_FAILED)
        if not (res or {}).get(order_id):
            return GatewayResult(False, cid, CANCEL_FAILED)
        self._note_cancel_requested(cid)
        return GatewayResult(True, cid, None)

    def _note_cancel_requested(self, cid: str) -> None:
        """Append the cancel note to a row, keeping whatever note it already has.

        A row note carries the history of the order (a post-only bounce, an
        adopted orphan), so the cancellation is added to it rather than written
        over it.  A row already marked as cancelled is left alone, so cancelling
        twice does not repeat the note.
        """
        row = self.store.order(cid)
        if row is None:
            return
        old = str(row["note"] or "")
        if old.endswith(CANCEL_REQUESTED_NOTE):
            return
        if not old:
            note = CANCEL_REQUESTED_NOTE
        else:
            note = f"{old}; {CANCEL_REQUESTED_NOTE}"
        self.store.update_order(cid, note=note)

    def _send(
        self,
        exchange,
        cid: str,
        product: str,
        side: str,
        size: Decimal,
        price: Decimal,
        *,
        equity: bool = False,
    ) -> Optional[dict]:
        """Place ONE order on *exchange*, adopting it rather than re-placing it after a timeout.

        *exchange* is the book's own exchange, the one the chain's route decided:
        nothing here reaches for another.  *equity* picks the write path and
        nothing else: an equity order goes out through
        `place_equity_limit`, a crypto one through `place_limit`, because the two
        requests have different shapes and neither adapter may be handed the
        other's.  At most three place calls per cid.  A
        `PermanentError` from the write is the exchange refusing the order, so
        it is reported as a not-ok result (the caller records REJECTED).  After a
        transient failure the order is looked up by client order id: found means
        it landed (adopt its id and status, never send again); not found means the
        same cid is re-sent.  A lookup that fails transiently also counts as not
        found.  A lookup that fails permanently says nothing about the order —
        the answer was lost, so this returns None and the row stays
        PENDING_SUBMIT for reconcile.  Three lost answers return None too, an
        outcome nobody knows.
        """
        created = self.now()
        place = exchange.place_equity_limit if equity else exchange.place_limit
        for attempt in range(3):
            try:
                return place(cid, product, side, size, price)
            except PermanentError as error:
                log.warning("place %s refused: %s", cid, error)
                return {"ok": False, "order_id": None, "reason": str(error)}
            except TransientError as error:
                log.warning("place %s: %s; looking it up", cid, error)
                self.sleep(min(2**attempt, 10))
                try:
                    found = self._lookup(exchange, cid, created, product)
                except PermanentError as lookup_error:
                    log.warning(
                        "lookup %s failed (%s); the outcome is unknown",
                        cid,
                        lookup_error,
                    )
                    return None
                if found is not None:
                    return self._adopt(cid, found)
        return None

    def _lookup(self, exchange, cid: str, created: float, product: str) -> Optional[dict]:
        """The order *exchange* holds for *cid*; a transient lookup counts as none."""
        try:
            return exchange.find_by_client_id(cid, created, product)
        except TransientError as error:
            log.warning("lookup %s: %s", cid, error)
            return None

    def _adopt(self, cid: str, found: dict) -> dict:
        """Record a found order: always its id, and its status only when it is OPEN.

        An OPEN order is written as OPEN.  Any other status the exchange reports
        (FILLED, CANCELLED, FAILED, unknown) records the order id alone and leaves
        the row PENDING_SUBMIT, because reconcile's pending path looks the row up
        and applies the fills: a terminal status written here would skip that.
        The result carries `adopted`, so the caller does not write the row again.
        """
        fields = {"order_id": found["order_id"]}
        if found.get("status") in ADOPTED_STATUSES:
            fields["status"] = found["status"]
        self.store.update_order(cid, **fields)
        return {
            "ok": True,
            "order_id": found["order_id"],
            "reason": None,
            "adopted": True,
        }

    # ------------------------------------------------ kill path
    def cancel_all(
        self,
        scope: Literal["owner", "all"],
        owner: Optional[str] = None,
        *,
        book: Optional[str] = None,
    ) -> int:
        """Sweep our open orders off the book; returns how many the exchange took.

        No `check()`: this is the kill path, so it works while halted and skips
        every cap, and it never touches an order whose id is not ours.  For
        scope "owner" the prefix ends at the dash, so "b1" does not sweep "cb-b10-".

        `book` says which book to sweep.  With none BOTH books are swept, and a
        live account that cannot be reached right now is simply skipped rather
        than raised about, so the kill path always works.  A named book sweeps
        that one alone: a live sweep with no live exchange raises `LiveLocked`,
        because a caller that asked for one book must hear that it is unreachable.
        A failing list or cancel propagates; the caller decides what to do.
        """
        if scope not in ("owner", "all"):
            raise ValueError(f"unknown cancel scope: {scope!r}")
        if scope == "owner" and owner is None:
            raise ValueError("the owner scope needs an owner")
        if book is not None and book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        prefix = "cb-" if scope == "all" else f"cb-{owner}-"
        with self.lock:
            taken = 0
            if book in (None, DRY):
                taken += self._sweep(self.books.dry, prefix)
            if book in (None, LIVE):
                live = self.books.live_exchange()
                if live is None:
                    if book == LIVE:
                        raise LiveLocked("the live book has no exchange")
                else:
                    taken += self._sweep(live, prefix)
            return taken

    def _sweep(self, exchange, prefix: str) -> int:
        """Cancel this exchange's open orders whose id starts with *prefix*.

        One exchange at a time: the caller names which book's account a sweep is
        for, so a dry sweep never asks the live account anything.
        """
        open_orders = exchange.list_open_orders(None)
        selected = [
            order
            for order in open_orders
            if str(order.get("client_order_id") or "").startswith(prefix)
        ]
        if not selected:
            return 0
        order_ids = [order["order_id"] for order in selected]
        res = exchange.cancel(order_ids) or {}
        for order in selected:
            cid = order.get("client_order_id")
            if cid:
                self._note_cancel_requested(cid)
        return sum(1 for order_id in order_ids if res.get(order_id))

    # ------------------------------------------------ dry seeding
    def seed_dry(self, owner: str, quote: Decimal, base: Decimal) -> None:
        """Fund a dry-run owner: the package's only `deposit` caller.

        Both deposits share one BEGIN IMMEDIATE transaction, and neither is made
        for an owner whose route is not the dry book (or who has no bot row to
        name the product), so a live account can never be funded from here: the
        route is read on every call, so a bot that has just been switched to the
        dry book is seeded and a bot that has left it is not.  A zero amount is
        skipped: the deposit itself refuses anything at or below zero.
        """
        with self.lock:
            if self.exchange is None:
                raise ValueError("no exchange to seed")
            if self.route_for(owner) != DRY:
                raise ValueError(f"owner {owner!r} is not on a dry route")
            bot = self.store.get_bot(owner)
            if bot is None:
                raise ValueError(f"no bot row for owner {owner!r}")
            quote_amt, base_amt = D(quote), D(base)
            if quote_amt < 0 or base_amt < 0:
                raise ValueError(f"a seed amount must not be negative: {owner!r}")
            base_cur, quote_cur = bot["product"].split("-", 1)
            note = f"seed {owner}"
            with self.store.tx():
                if quote_amt > 0:
                    self.exchange.deposit(quote_cur, quote_amt, note)
                if base_amt > 0:
                    self.exchange.deposit(base_cur, base_amt, note)

    def seed_dry_equity_capital(self) -> Decimal:
        """Fund the dry book's equity pool once, from the AI's equity capital.

        The AI's equity orders draw on one quote pool per book (`ledger.py`), so
        the dry book's pool has to hold the same capital the live one would: the
        capital is deposited as USD into the simulator, less whatever an earlier
        run already seeded.  The amount already seeded is kept in the store
        (`dry_equity_seeded`) and the deposit and that record commit together, so
        a deposit whose record was lost can never be made a second time.

        Nothing is seeded with no equity products configured, with a capital of
        zero or less, or when this gateway has no simulator to seed.  Nothing is
        ever withdrawn: the capital is deposited once and only ever increases, so
        a lowered capital leaves the extra USD in the dry account unallocated.
        The live book is not touched at all — it is the owner's real account,
        funded by them.

        Answers the amount deposited, so a caller can tell a first start from a
        restart without reading the store itself.
        """
        with self.lock:
            if not self.limits.equity_products or self.exchange is None:
                return D(0)
            capital = D(self.limits.equity_ai_capital_usd)
            if capital <= 0:
                return D(0)
            seeded = D(str(self.store.get(DRY_EQUITY_SEEDED_KEY, "0")))
            if capital <= seeded:
                return D(0)
            deposit = capital - seeded
            with self.store.tx():
                self.exchange.deposit(
                    EQUITY_CAPITAL_CURRENCY, deposit, EQUITY_SEED_NOTE
                )
                self.store.put(DRY_EQUITY_SEEDED_KEY, str(capital))
            return deposit

    # ------------------------------------------------ portfolio mark
    def portfolio_equity(self, book: str = DRY) -> Optional[Decimal]:
        """Every bot ON *book* at the snapshot mid of its own product, or None.

        None means at least one bot's product has no snapshot, or only an unusable
        one (stale, crossed, empty or stamped ahead of our clock): part of the
        portfolio is then unpriced, and a partial sum would let the drawdown stop
        read low enough to pass.  The caller treats None as unknown, not as zero.
        A bot whose `mode` is the other book is not part of this portfolio at all:
        its capital and its history belong to that book's mark.

        A STOPPED bot that holds nothing on the book — no quote, no base and
        nothing reserved — is left out before its snapshot is read.  It adds zero
        to the sum, and its product may not be polled any more, so making the
        whole mark unknown for it would leave the book unpriceable for ever.
        """
        total = D(0)
        for bot in self.store.list_bots():
            if bot["mode"] != book:
                continue
            product = bot["product"]
            if bot["status"] == STOPPED and _holds_nothing(
                self.ledger.holding(bot["id"], product, book=book)
            ):
                continue
            snap = self.snapshots.get(product)
            if snap is None or self._is_unusable(snap):
                return None
            mid = (snap.bid + snap.ask) / 2
            total += self.ledger.equity(bot["id"], {product: mid}, product, book=book)
        return total

    # ------------------------------------------------ the equity mark
    def equity_value(self, book: Optional[str] = None) -> Optional[Decimal]:
        """The AI's equity book on one book: the shares at their mid, plus cash left.

        *book* is the book to mark; with none it is the book the AI routes to now
        (`self.route_for("ai")`).  The shares are the AI's base holding on every
        product of the SORTED UNION of `limits.equity_products` and
        `ledger.equity_products(resolved)` at that product's snapshot mid, so a
        symbol taken off the equity list whose EQUITY rows still hold shares is
        marked too, and the cash is the equity capital less what the pool has
        already spent (`ledger.equity_pool_used`) — so a filled buy is counted
        once, as the shares it bought, and an order still resting counts as the
        cash it holds.

        A product the AI holds shares in but cannot be priced from a usable
        snapshot makes the WHOLE figure None: part of the book would be unpriced
        and a partial sum would read low enough to pass a stop it should trip.  A
        product held at zero needs no snapshot at all, and neither does a product
        the AI has never traded.

        The print a held product is marked from is judged by the same per-book
        age bound an order is (`_print_unusable`): on a book that is not the
        practice one, a snapshot whose `print_ts` is missing or past
        `equity_max_age_for(book)` leaves the whole figure None, so a print no
        order on that book could be priced from can neither ring a drawdown
        alert, nor clear one, nor move the mark — the runner reads None as "skip
        this cycle".  The practice book marks from its own five-minute bound when
        the print carries a time, and judges one without a time by the read's
        stamp as before.
        """
        resolved = self.route_for("ai") if book is None else book
        total = D(self.limits.equity_ai_capital_usd) - self.ledger.equity_pool_used(
            resolved
        )
        products = sorted(
            set(self.limits.equity_products)
            | set(self.ledger.equity_products(resolved))
        )
        for product in products:
            held = self.ledger.holding(AI_OWNER, product, book=resolved)
            if held.base == 0:
                continue
            snap = self.snapshots.get(product)
            if snap is None or self._is_unusable(snap, equity=True):
                return None
            if self._print_unusable(snap, resolved):
                return None
            total += held.base * ((snap.bid + snap.ask) / 2)
        return total


# ---------------------------------------------------------------- defaults


def _never_halted() -> bool:
    """The halt flag when the caller wires none: never halted."""
    return False


def _refuse_every_approval(
    approval_id, intent, *, product: str, book: str
) -> Optional[str]:
    """The AI approval check when the caller wires none: nothing is ever approved."""
    return APPROVAL_REQUIRED


def _consume_nothing(conn, approval_id) -> None:
    """The approval consumption when the caller wires none: there is none to spend."""
    raise ApprovalGone(approval_id)


def _params(bot: Optional[dict]) -> dict:
    """A bot row's params, or an empty mapping when there is no row."""
    return (bot or {}).get("params") or {}


def _holds_nothing(holding) -> bool:
    """True when an owner has nothing of its own left on a book.

    Quote, base and both reservations at zero is an owner a book's mark can leave
    out: it adds nothing to the sum whether or not its product can be priced.
    """
    return (
        holding.quote == 0
        and holding.base == 0
        and holding.reserved_quote == 0
        and holding.reserved_base == 0
    )


def _is_positive_decimal(value) -> bool:
    """True for a strictly positive, finite `Decimal` (and nothing else).

    Floats, ints and strings are refused rather than converted: a money value
    that arrives as a float has already lost precision, and `NaN` compares false
    against every bound, so it has to be excluded before any comparison.
    """
    if not isinstance(value, Decimal) or not value.is_finite():
        return False
    return value > 0


def _is_whole(value: Decimal) -> bool:
    """True when a `Decimal` size is a whole number of units (shares, coins)."""
    return value == value.to_integral_value()


def bot_drawdown_pct(bot: Optional[dict]) -> Decimal:
    """A bot's own drawdown stop, or the default when its params are unusable.

    The stored value has to be a finite `Decimal` strictly between 0 and 100: a
    stop of 0 would refuse every order and a stop over 100 could never trip, so
    both fall back to the default instead of silently changing the bot's risk.
    """
    raw = _params(bot).get("drawdown_pct", DEFAULT_DRAWDOWN_PCT)
    try:
        pct = D(str(raw))
    except (ArithmeticError, ValueError, TypeError):
        pct = None
    if pct is None or not pct.is_finite() or pct <= 0 or pct > 100:
        log.warning(
            "bot %s: unusable drawdown_pct %r, using the default %s%%",
            (bot or {}).get("id"),
            raw,
            DEFAULT_DRAWDOWN_PCT,
        )
        return D(DEFAULT_DRAWDOWN_PCT)
    return pct