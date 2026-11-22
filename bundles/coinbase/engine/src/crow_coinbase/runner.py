"""The runner: one cycle of the engine, and the loop that repeats it.

`cycle()` runs the whole engine in the order the parked rules require, one
method per step, so the body reads as that order:

    0. drop the events past their retention, at most once a day, and let the AI
       order surface sweep its own previews
    1. poll every product any bot row names (under the gateway's cycle lock)
    2. step the dry-run exchange
    3. reconcile each book against its own exchange
    4. re-check each book's portfolio mark, halting that book alone, and the
       per-bot drawdown stops
    5. one decision per ACTIVE bot whose book is not halted, its orders through
       the gateway; then alert a grid whose book is empty and has no fill left
       to answer
    6. ratchet the high-water marks, per book
    6b. alert a bot that has trailed its own starting mix for long enough
    7. alert while an exchange is short of what its own book's owners hold
    8. write the heartbeat, and return it

The heartbeat's payload names the bots that raised in step 5 (`errors`), which is
empty when every bot got through and also when a halt skipped it, so a reader can
tell a bot's own failure from a cycle that never got that far.  A halt is per
book (`gateway.halt(reason, book)`): a book's portfolio drawdown stops that
book's bots alone, while the global halt — the kill switch — stops both.  A loop
that keeps failing is not silent either: `run_forever` logs and records one
failure at a time, and re-raises after `MAX_CONSECUTIVE_FAILURES` failures in a
row, which ends the thread so the container restarts it.

Reads the store, the snapshots and the strategy; writes only through the store
and the gateway.  It never calls an exchange write method: every order goes out
through `gateway.submit("bot", owner, intent)`, and the only kill paths it uses
are `gateway.cancel_all` and `gateway.halt`.  `snapshots.put` happens in step 1
alone, under `gateway.lock`, because the gateway's staleness and skew reads
assume no snapshot is written outside that lock.

Follow-ups are derived from the STORED rows and never from a reconcile report: a
terminal row that carries a fill and still says `opposite == OPP_TODO` is a fill
nobody answered, so a crash between the reconcile and the submit loses nothing.
`reconcile()` is always called outside a transaction of ours, with `now` on the
clock the rows were stamped with (epoch seconds), so a rollback can never reach
the trades file the reconcile wrote first.

A poll covers every product ANY bot row names, whatever that bot's status: the
gateway's `portfolio_equity()` marks all of them and answers None as soon as one
product cannot be priced, which would stop every order with DRAWDOWN_STOP.  While
that mark is unknown the portfolio neither halts nor ratchets.

Money and size are `Decimal`; the only floats are clocks and timestamps, and an
owner's money is only ever read or written on that owner's own book.

There are two books (`books.py`).  A bot's `mode` names the one it trades, and
every step that reads or writes an owner's money — its holding, its benchmark,
its high-water mark, its caps, its orders, the portfolio mark it is part of —
reads that bot's own book.  The simulator (`self.exchange`) is advanced and
reconciled for the dry book alone, and the live account for the live book alone,
and only while that account exists: with no live exchange there is no live call
at all, and the two books are never reconciled, marked or totalled as one.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional

from . import money
from .benchmark import Benchmark
from .books import (
    BOOKS,
    DRY,
    LIVE,
    LIVE_DISABLED,
    LIVE_LOCKED,
    LiveLocked,
    ModeRefused,
)
from .gateway import (
    CLOCK_SKEW,
    DAILY_CAP,
    DRAWDOWN_STOP,
    HALTED,
    PORTFOLIO_OWNER,
    RATE_CAP,
    STALE_MARKET,
    UNALLOCATED_NEGATIVE,
    bot_drawdown_pct,
)
from .limits import Limits
from .money import ProductSpec
from .reconcile import reconcile
from .snapshot import SnapshotCache
from .store import (
    ACTIVE,
    CANCELLED,
    FAILED,
    FILLED,
    LIVE_STATUSES,
    OPEN,
    OPP_PLACED,
    OPP_SKIPPED,
    OPP_TODO,
    PAUSED,
    PENDING_SUBMIT,
    REJECTED,
    STOPPED,
    Store,
)
from .strategies.base import (
    BotView,
    Decision,
    MarketSnapshot,
    OrderIntent,
    Strategy,
)

D = Decimal
log = logging.getLogger("crow_coinbase.runner")

# ---------------------------------------------------------------- configuration
# The environment variable that is the hard ceiling on live trading, and the two
# word lists it may spell.  A value on neither list is a startup problem: the
# engine does not start while it cannot read its own ceiling.  The variable
# itself is `books.ENV_LIVE`; the name is repeated here so the watchdog can read
# the same three constants.
ENV_LIVE = "CROW_COINBASE_LIVE"
LIVE_ON = ("true", "1", "yes", "on")
LIVE_OFF = ("false", "0", "no", "off", "")

# The environment variable that names how long a bot has to trail its own
# starting mix before that is news, and the number of days used when it names
# nothing usable.  Read once, when the runner is built.
TRAIL_ALERT_DAYS_ENV = "CROW_COINBASE_TRAIL_ALERT_DAYS"
DEFAULT_TRAIL_ALERT_DAYS = 7

# One alert per negative-unallocated episode: the key holds the currency list.
# Each book has its own key, so a short simulator never silences a short account.
UNALLOCATED_KEY = "runner:unallocated_alert"
UNALLOCATED_LIVE_KEY = f"{UNALLOCATED_KEY}:{LIVE}"
UNALLOCATED_PREFIX = "unallocated negative: "

# One alert per empty-book episode: the key holds True while the episode lasts.
IDLE_BOOK_PREFIX = "runner:idle_book:"
IDLE_BOOK_NOTE = (
    "grid has no live orders and no pending fills; recenter or re-init it"
)

# The kv key holding, per fill, the refusal code last warned about: a follow-up
# the exchange keeps refusing is news once per fill and code, not once a cycle.
REFUSED_PREFIX = "runner:refused:"

# A recenter settles the cancelled rows before it reinstates the grid.
RECENTER_SETTLE_TRIES = 10
RECENTER_SETTLE_WAIT_S = 1.0
RECENTER_NOTE = "recentered"
# The kv key holding the epoch (epoch seconds on the wall clock, `time.time()`,
# which is what `created_at` is stamped with) a bot's current grid started at,
# written by a recenter so the replaced grid's rows stop counting as today's.
INIT_SINCE_PREFIX = "runner:init_since:"

# The kv key holding WHY a bot is PAUSED (`bot:paused_reason:<id>`), and the
# values this module writes to it: the owner's own pause (`pause_bot`), a bot
# drawdown stop, and the strategy's own reason.  It is kv and not a column, so
# there is nothing to migrate, and a resume clears it.
PAUSED_REASON_PREFIX = "bot:paused_reason:"
PAUSE_REASON_OWNER = "owner"
PAUSE_REASON_DRAWDOWN = "drawdown"
PAUSE_REASON_STRATEGY = "strategy"

# Refusals that clear by themselves: the level they held back is placed again on
# a later cycle, so the first book is not settled by them.  A currency short on
# the exchange is one of these: it clears once its owner's funds move.
TRANSIENT_REFUSALS = frozenset(
    {
        HALTED,
        CLOCK_SKEW,
        STALE_MARKET,
        DRAWDOWN_STOP,
        DAILY_CAP,
        RATE_CAP,
        UNALLOCATED_NEGATIVE,
    }
)

# A fill whose follow-ups the exchange keeps refusing is given up on instead of
# being offered for ever: at this many settled refusals its mark becomes
# `OPP_SKIPPED` and one alert says why.  A post-only bounce is the exchange's own
# reprice attempt rather than a settled answer, so it does not count.
MAX_FOLLOW_UP_REJECTIONS = 3
FOLLOW_UP_REJECTED_NOTE = "follow-up rejected x3"

# Failures in a row after which the loop raises instead of retrying for ever.
MAX_CONSECUTIVE_FAILURES = 5


class StartupRefused(ValueError):
    """An engine configuration that may not be started at all.

    Raised for an API key that could move funds or is not scoped to the one
    portfolio the engine trades.
    """


class PauseChanged(RuntimeError):
    """The bot row changed while a pause was sweeping its book.

    Raised at the start of a pass when the row it reads is no longer the row the
    pause found: a stop or a kill marked the bot STOPPED meanwhile, or its book,
    its params or its grid epoch moved.  Nothing of the pause is written then —
    not the PAUSED row, not a new grid epoch, and not the "orders may still be
    resting" alert — so the caller is told the bot changed rather than that the
    sweep failed.
    """


# ---------------------------------------------------------------- refusals
# The refusal codes a mode switch raises, each with the status it answers.  The
# message carries the reason alone; `ModeRefused` prefixes the code.
STOPPED_BOT = "STOPPED_BOT"  # a stopped bot has no book to move
ALREADY_LIVE = "ALREADY_LIVE"  # the bot already trades the live book
ALREADY_DRY = "ALREADY_DRY"  # the bot already trades the dry book
LIVE_CAPITAL_SHORT = "LIVE_CAPITAL_SHORT"  # the live book has not that much free
CAPITAL_INVALID = "CAPITAL_INVALID"  # the amounts sent, or the value found
PRICE_UNKNOWN = "PRICE_UNKNOWN"  # no usable mid to value the live book with
# The old book never settled, so the switch wrote nothing beyond the pause and
# the bot is left paused on the book it was on: a state to retry, not a fault.
SETTLE_FAILED = "SETTLE_FAILED"
SETTLE_FAILED_MESSAGE = (
    "Couldn't finish switching; the bot is paused. Try again in a minute."
)

HEARTBEAT_TMP_SUFFIX = ".tmp"


# ---------------------------------------------------------------- start-up checks


def check_key(perms: dict, portfolio_id: Optional[str]) -> None:
    """Refuse a live API key that could transfer out, or is not portfolio-scoped.

    A key that may transfer can move funds off the account, so nothing else it
    is allowed to do matters.  The engine also needs the key to belong to exactly
    one portfolio: an unscoped key, a blank target, or a mismatch between the two
    is refused rather than traded on.  Returns None for an acceptable key.
    """
    if perms.get("can_transfer"):
        raise StartupRefused(
            "API key has can_transfer permission; the engine never moves funds"
        )
    scoped = perms.get("portfolio_uuid")
    if not scoped:
        raise StartupRefused(
            "key is not scoped to a portfolio; create a portfolio-scoped key"
        )
    if not portfolio_id or not str(portfolio_id).strip():
        raise StartupRefused(
            f"no portfolio configured for a key scoped to {scoped}"
        )
    if scoped != portfolio_id:
        raise StartupRefused(
            f"key is scoped to portfolio {scoped}, not to {portfolio_id}"
        )


def live_fee_rate(env_fee_rate: Decimal, exchange: Any) -> Decimal:
    """The maker fee to use: the account's own rate when it is higher than ours.

    An exchange that cannot report a rate (dry run, or no fee tier yet) leaves
    the configured rate in place.  Never below the configured rate: a step sized
    against a too-cheap fee would trade at a loss.
    """
    configured = D(env_fee_rate)
    reported = exchange.maker_fee_rate()
    if reported is None:
        return configured
    return max(configured, D(reported))


def build_snapshot_cache(limits: Limits) -> SnapshotCache:
    """A cache whose staleness window matches the poll interval we actually run.

    The default 60-second poll would expire the measured skew between polls
    whenever an install polls slower than that, so the interval is passed in.
    """
    return SnapshotCache(poll_seconds=limits.poll_seconds, now=time.time)


def realized_pnl(
    store: Store, owner: Optional[str] = None, *, book: Optional[str] = None
) -> dict[str, Decimal]:
    """Realized profit per owner, derived from the order rows already stored.

    A sell contributes once its fill is settled: a FILLED row, or a CANCELLED one
    that still carries a filled part.  Its basis is the cost of the base it sold,
    so a row without one (an adopted order, a sell placed on no known basis) is
    skipped rather than counted at zero cost.  Only owners with such a row
    appear in the result; no table is written.

    `book` keeps only that book's rows, so a caller reporting a bot's current
    book does not add the profit of the book it left; with none, both books'
    rows are counted.  On a named book, a row stamped before that book's epoch
    for *owner* is left out too: it belongs to a period the owner has already
    left (a switch, a re-init), which is what makes the figure the profit of the
    period this book has been running, not of every period it ever had.
    """
    totals: dict[str, Decimal] = {}
    epoch = (
        store.book_epoch(book, owner)
        if book is not None and owner is not None
        else 0.0
    )
    for row in store.orders(owner=owner, book=book):
        if _stamp(row["created_at"]) < epoch:
            continue
        if row["side"] != money.SELL:
            continue
        basis = row["basis_per_base"]
        if basis is None:
            continue
        filled = row["filled_size"]
        if filled <= 0:
            continue
        settled = row["status"] == FILLED or (
            row["status"] == CANCELLED and filled > 0
        )
        if not settled:
            continue
        gain = money.realized_on_sell(
            sell_size=filled,
            sell_net_quote=row["filled_value"] - row["fees"],
            basis_per_base=basis,
        )
        totals[row["owner"]] = totals.get(row["owner"], D(0)) + gain
    return totals


# ---------------------------------------------------------------- the runner


class Runner:
    """The cycle loop: poll, reconcile, decide, mark, and write the heartbeat.

    Every collaborator is injected — the store, the gateway, the exchange, the
    snapshot cache, the strategies and the clocks — so a cycle can be driven
    against a scripted book with nothing mocked inside the engine.  `now` is an
    epoch-seconds clock (the wall clock by default, the one `created_at` is
    stamped with), `market_for` gives a product's book and poll range, and
    `spec_for` its `ProductSpec`.  The one stamp not taken from `now` is the init
    epoch a recenter writes: it is compared with `created_at` directly, so it is
    always the wall clock even when a caller moves `now`.
    """

    def __init__(
        self,
        *,
        store: Store,
        gateway: Any,
        exchange: Any,
        snapshots: SnapshotCache,
        strategies: Mapping[str, Strategy],
        env: Mapping[str, str],
        market_for: Callable[[str], Any],
        spec_for: Callable[[str], ProductSpec],
        now: Callable[[], float] = time.time,
        heartbeat_path: Path | str = "/data/heartbeat",
        benchmark: Optional[Benchmark] = None,
        sleep: Callable[[float], None] = time.sleep,
        ai_sweep: Optional[Callable[[], Any]] = None,
        trail_alert_days: Any = None,
    ) -> None:
        self.store = store
        self.gateway = gateway
        self.exchange = exchange
        self.snapshots = snapshots
        self.strategies = strategies
        self.env = env
        self.market_for = market_for
        self.spec_for = spec_for
        self.now = now
        self.heartbeat_path = Path(heartbeat_path)
        self.sleep = sleep
        self.benchmark = benchmark if benchmark is not None else Benchmark(store)
        # The AI's own housekeeping, run once per cycle: its previews' windows,
        # the orders they placed and the approvals nobody spent.  It is injected
        # (the surface's own `sweep_locked` — the cycle is the one caller allowed
        # to retire an approval nobody spent or an order the book lost) rather
        # than reached for, so a cycle can be driven without one and a caller can
        # stand in for it.
        self.ai_sweep = ai_sweep
        # How long a bot has to trail its own starting mix before the runner says
        # so.  It is read once, here, and never again: a value that is not a
        # positive whole number of days is the default.
        self.trail_alert_days = _trail_alert_days(trail_alert_days)

        # This copy is for the values that are not caps — the poll interval and
        # the maker fee.  Every cap is read from `self.gateway.limits`, which is
        # the runtime set an owner may have lowered since the process started.
        self.limits = Limits.from_env(env)
        self.fee_rate = self.limits.maker_fee_pct / 100
        self.ledger = gateway.ledger

        self.cycle_count = 0
        # The bots a pause is sweeping RIGHT NOW.  A pause sets its id under the
        # first lock it takes and clears it in a `finally`, so a pause that failed
        # leaves nothing behind; the resume, recenter and mode routes read it and
        # refuse rather than move a bot that is being swept.
        self._pausing: set[str] = set()
        # The last successful poll per product: the start of the next range read.
        self._last_poll: dict[str, float] = {}

    # ------------------------------------------------ start-up
    def startup_checks(self) -> list[str]:
        """Every configuration problem that blocks a start; an empty list is fine.

        One check on the live ceiling, then one pass per bot over its strategy —
        its name, then `validate` against the product's real `ProductSpec`, then
        the fee guard.  Passing the spec to `validate` is what refuses a step that
        collapses on the product's price tick before a single order is built, and
        a STOPPED bot is left alone: it places nothing.
        """
        problems = self._live_problems()
        for bot in self.store.list_bots():
            if bot["status"] == STOPPED:
                continue
            problems.extend(self._bot_problems(bot))
        return problems

    def _live_problems(self) -> list[str]:
        """A problem for a live ceiling this build cannot read.

        Live trading is part of the engine now, so a live route is not a startup
        problem: the ceiling and the switches decide per order.  What is still a
        problem is a `CROW_COINBASE_LIVE` value neither word list names, because
        nobody can then say whether live is allowed — and that is refused rather
        than guessed, so an unreadable ceiling never starts an engine.
        """
        value = str(self.env.get(ENV_LIVE) or "").strip().lower()
        if value not in LIVE_ON and value not in LIVE_OFF:
            return [f"unrecognised {ENV_LIVE} value {value!r}"]
        return []

    def _bot_problems(self, bot: dict) -> list[str]:
        """Every problem with one bot's strategy, each prefixed with the bot id."""
        prefix = f"bot {bot['id']}: "
        strategy = self.strategies.get(bot["strategy"])
        if strategy is None:
            return [prefix + f"unknown strategy {bot['strategy']!r}"]
        try:
            spec = self.spec_for(bot["product"])
        except Exception as error:  # noqa: BLE001 - any failure means no spec
            return [prefix + f"no product spec: {error}"]
        try:
            strategy.validate(bot["params"], spec)
            why = strategy.fee_guard(bot["params"], self.limits.maker_fee_pct)
        except ValueError as error:
            return [prefix + str(error)]
        return [prefix + why] if why else []

    # ------------------------------------------------ one cycle
    def cycle(self) -> dict:
        """Run every step once, under the gateway's cycle lock, and heartbeat.

        Step 3 reconciles each book against its own exchange: the simulator for
        the dry book, and the live account for the live book only while that
        account exists — with none, no live call is made at all.  Step 2 advances
        the simulator alone: it is the only simulated account.
        """
        with self.gateway.lock:
            self.cycle_count += 1
            self._prune_events()  # 0
            self._sweep_ai_previews()  # 0b
            self._poll_markets()  # 1
            self.exchange.advance(self.now())  # 2
            reconcile(  # 3
                self.store,
                self.exchange,
                now=self.now(),
                gateway=self.gateway,
                book=DRY,
            )
            live = self.gateway.books.live_exchange()
            if live is not None:
                reconcile(
                    self.store,
                    live,
                    now=self.now(),
                    gateway=self.gateway,
                    book=LIVE,
                )
            self._check_drawdowns()  # 4
            errors: list[str] = []
            if not self.gateway.is_halted():  # 5
                # A global halt skips the whole step; a book's own halt skips
                # its bots inside `_run_bots`, so the other book still runs.
                errors = self._run_bots()
                self._check_idle_books()
            self._ratchet_marks()  # 6
            self._check_trailing_hold()  # 6b
            self._check_unallocated()  # 7
            return self._heartbeat(errors)  # 8

    # ------------------------------------------------ step 0: event retention
    def _prune_events(self) -> None:
        """Let the store drop the events past retention; a failure is only logged.

        Housekeeping must never cost a cycle: whatever the prune raises is
        swallowed here, with one warning and no exception text, and the next
        cycle offers it again (the store only stamps its own daily mark once the
        prune has gone through).
        """
        try:
            self.store.prune_events_daily()
        except Exception:  # noqa: BLE001 - retention is housekeeping, not a cycle
            log.warning("event retention skipped: the prune failed")

    def _sweep_ai_previews(self) -> None:
        """Let the AI surface retire its previews; a failure is only logged.

        The surface's `sweep` expires the previews past their window, follows the
        orders they placed and gives up on an approval nobody spent.  It is the
        same housekeeping the surface runs on its own reads, offered here so it
        happens even when no panel is open.  A sweep that raises costs this
        cycle nothing: one warning, no exception text, and the next cycle offers
        it again.
        """
        sweep = self.ai_sweep
        if sweep is None:
            return
        try:
            sweep()
        except Exception:  # noqa: BLE001 - housekeeping is not a cycle
            log.warning("ai preview sweep skipped: the sweep failed")

    # ------------------------------------------------ step 1: the book
    def _poll_markets(self) -> None:
        """Poll every product a bot row names, then measure the clock skew.

        A product is polled once however many bots share it, and a failing poll
        keeps that product's previous snapshot: an unpriceable product is
        reported, never filled in with an invented book.
        """
        for product in self._polled_products():
            self._poll_product(product)
        self._measure_clock()

    def _polled_products(self) -> list[str]:
        """Each distinct product of every bot row, whatever that bot's status."""
        products: list[str] = []
        for bot in self.store.list_bots():
            if bot["product"] not in products:
                products.append(bot["product"])
        return products

    def _poll_product(self, product: str) -> None:
        """Read one product's top of book and poll range into the snapshot cache.

        The range starts at this product's own last successful read, so a window
        is never counted twice; the first read looks back one full poll interval.
        """
        now = self.now()
        since = self._last_poll.get(product, now - self.limits.poll_seconds)
        try:
            market = self.market_for(product)
            bid, ask = market.best_bid_ask()
            low, high = market.range_since(since)
        except Exception as error:  # noqa: BLE001 - one product may not stop the rest
            log.warning("poll %s: %s", product, error)
            self.store.event("warn", f"poll {product} failed: {error}")
            return
        self.snapshots.put(
            MarketSnapshot(product, bid, ask, low, high, self.now())
        )
        self._last_poll[product] = self.now()

    def _measure_clock(self) -> None:
        """Store the skew between the exchange's clock and ours."""
        try:
            server = self.exchange.server_time()
        except Exception as error:  # noqa: BLE001 - the skew stays unknown
            log.warning("server time: %s", error)
            self.store.event("warn", f"server time unavailable: {error}")
            return
        self.snapshots.set_clock(server, self.now())

    # ------------------------------------------------ step 4: drawdown stops
    def _check_drawdowns(self) -> None:
        """The portfolio stop of each book, then each ACTIVE bot's own stop.

        An unknown portfolio mark (None: a product that cannot be priced) moves
        nothing: it neither halts nor ratchets, so a missing snapshot can never
        look like a drawdown.  A stop that has already fired does not fire again,
        which keeps one episode to one alert, and each book's portfolio halt is
        its own: the dry book's stop never stops the live bots.
        """
        for book in self._books_in_play():
            self._check_portfolio_drawdown(book)
        self._check_bot_drawdowns()

    def _books_in_play(self) -> list[str]:
        """Each book at least one bot row trades, dry first."""
        modes = {bot["mode"] for bot in self.store.list_bots()}
        return [book for book in BOOKS if book in modes]

    def _check_portfolio_drawdown(self, book: str = DRY) -> None:
        """Halt *book* alone when its portfolio mark is below its stop.

        One check per book, over the bots that trade it: the dry mark is the
        simulator's owners and the live mark the live account's, and neither is
        measured against the other.  The halt it raises is that book's own, so a
        dry-book drawdown never stops a live bot (or the other way round), and a
        book that is already halted says nothing new: one episode, one alert.
        """
        equity = self.gateway.portfolio_equity(book)
        if equity is None:
            return
        hwm = self.store.hwm(PORTFOLIO_OWNER, book)
        if hwm is None or hwm <= 0:
            return
        # The percentage is a cap, so it is read from the limits the gateway
        # checks every order against — the runtime ones, which an owner may have
        # lowered since this process started — and never from this runner's own
        # copy of the environment, which holds only the ceilings.
        pct = self.gateway.limits.portfolio_drawdown_pct
        floor = hwm * (1 - pct / 100)
        if equity >= floor or self.gateway.is_halted(book):
            return
        message = (
            f"portfolio drawdown: equity {equity} below {floor} "
            f"({pct}% of high-water mark {hwm} on the {book} book)"
        )
        log.error(message)
        self.gateway.halt(message, book)
        self.store.event("ALERT", message, kind="halt")

    def _check_bot_drawdowns(self) -> None:
        """Pause each ACTIVE bot whose equity is below its own book's drawdown stop.

        The pause records its own reason (`bot:paused_reason:<id>` = `drawdown`),
        so a bot stopped by its drawdown does not read like one its owner paused.
        """
        for bot in self.store.list_bots():
            if bot["status"] != ACTIVE:
                continue
            book = bot["mode"]
            mid = self._mid(bot["product"])
            if mid is None:
                continue
            hwm = self.store.hwm(bot["id"], book)
            if hwm is None or hwm <= 0:
                continue
            product = bot["product"]
            equity = self.ledger.equity(
                bot["id"], {product: mid}, product, book=book
            )
            pct = bot_drawdown_pct(bot)
            floor = hwm * (1 - pct / 100)
            if equity >= floor:
                continue
            self.store.set_bot_status(bot["id"], PAUSED)
            self.store.put(
                f"{PAUSED_REASON_PREFIX}{bot['id']}", PAUSE_REASON_DRAWDOWN
            )
            message = (
                f"bot {bot['id']} paused: drawdown equity {equity} below "
                f"{floor} ({pct}% of high-water mark {hwm} on the {book} book)"
            )
            log.error(message)
            self.store.event("ALERT", message, kind="bot_paused", owner=bot["id"])

    def _mid(self, product: str) -> Optional[D]:
        """The product's mid price, or None when its snapshot cannot price it.

        Usability is the gateway's own rule (`_is_unusable`), not a copy of it: a
        missing snapshot, a bid at or below zero, a crossed book, a timestamp
        from the future or one past the staleness window all answer None, so a
        caller skips its mark rather than valuing anything off a book no order
        could be checked against.
        """
        snap = self.snapshots.get(product)
        if snap is None or self.gateway._is_unusable(snap):
            return None
        return (snap.bid + snap.ask) / 2

    # ------------------------------------------------ step 5: the bots
    def _run_bots(self) -> list[str]:
        """Give each bot its turn; return the ids that raised, in processing order.

        One bot's failure cannot stop the others: it is logged and recorded
        against that bot, and the id comes back so the heartbeat can name it
        rather than leave the reader to reconstruct the cycle from the events.
        A bot whose book is halted gets no turn at all: that book's drawdown (or
        the global kill switch, which halts both) is stopping it, while a bot on
        the other book is unaffected.
        """
        failed: list[str] = []
        for row in self.store.list_bots():
            if self.gateway.is_halted(row["mode"]):
                continue
            try:
                self._process_bot(row["id"])
            except Exception as error:  # noqa: BLE001 - isolate one bot's failure
                log.exception("bot %s failed in cycle %s", row["id"], self.cycle_count)
                self.store.event(
                    "error",
                    f"bot {row['id']}: cycle failed: {error}",
                    kind="bot_paused",
                    owner=row["id"],
                )
                failed.append(row["id"])
        return failed

    # ------------------------------------------------ step 5d: an empty book
    def _check_idle_books(self) -> None:
        """Alert once while a grid that should be resting has nothing on the book.

        A grid's orders are its instrument: a bot whose first book is done, that
        is ACTIVE, has no row in a live status and nothing left to answer has a
        book that vanished — swept by hand, or never laid.  Only a strategy with
        a `recenter` (a level grid) is checked, and a bot whose first book is
        still retrying is not: it is mid-init, not idle.  Neither is a bot whose
        book is halted: a book held still by a halt was not swept away.

        One alert per episode: the kv key holds True from the alert until the
        condition clears, so three cycles over one empty book say it once and the
        next emptying after the book comes back says it again.
        """
        for bot in self.store.list_bots():
            if bot["status"] != ACTIVE or not bot["init_done"]:
                continue
            if self.gateway.is_halted(bot["mode"]):
                continue
            bot_id = bot["id"]
            strategy = self.strategies.get(bot["strategy"])
            if strategy is None or not hasattr(strategy, "recenter"):
                continue
            key = f"{IDLE_BOOK_PREFIX}{bot_id}"
            if self._book_is_idle(bot_id, bot["mode"]):
                if self.store.get(key) is not None:
                    continue
                message = f"bot {bot_id}: {IDLE_BOOK_NOTE}"
                log.error(message)
                self.store.event("ALERT", message, kind="alert")
                self.store.put(key, True)
                continue
            if self.store.get(key) is not None:
                self.store.put(key, None)

    def _book_is_idle(self, bot_id: str, book: str = DRY) -> bool:
        """True when this owner has no live order row and no fill to answer.

        Only *book*'s rows are read: the book a bot has left is frozen, so its
        resting rows there say nothing about the book the bot trades now.  The
        pending check reads the stored rows directly rather than through
        `_pending_fills`, which warns about a malformed row: a check that runs
        every cycle must not add warnings of its own.
        """
        if self.store.orders(owner=bot_id, statuses=LIVE_STATUSES, book=book):
            return False
        for row in self.store.orders(
            owner=bot_id, statuses=(FILLED, CANCELLED), book=book
        ):
            if row["filled_size"] > 0 and row["opposite"] == OPP_TODO:
                return False
        return True

    def _process_bot(self, bot_id: str) -> None:
        """One bot's turn: heal, read, decide, send, then record what it decided.

        The row is read again here, because step 4 may have paused it since the
        list was taken: a PAUSED or STOPPED bot gets no strategy call and no
        order, while the reconcile, the poll and the marks still cover it.

        The first book is recorded as done only in a turn where the strategy
        paused it for nothing and no place was refused for a reason that clears
        by itself.  Such a retry is safe: `_without_placed_levels` drops the
        levels already on the book, and a recenter's epoch keeps the replaced
        grid's rows out of that filter.  A benchmark baseline waits for a usable
        snapshot instead of being taken off a book nothing could be priced from.

        A strategy that pauses the bot writes its own reason (`strategy`), so it
        does not read like an owner's pause either.
        """
        bot = self.store.get_bot(bot_id)
        if bot is None or bot["status"] != ACTIVE:
            return
        product = bot["product"]
        strategy = self.strategies.get(bot["strategy"])
        if strategy is None:
            self.store.event(
                "warn", f"bot {bot_id}: unknown strategy {bot['strategy']!r}"
            )
            return
        snap = self.snapshots.get(product)
        if snap is None:
            self.store.event("warn", f"bot {bot_id}: no snapshot for {product}")
            return

        book = bot["mode"]
        self._heal(bot_id, bot, book)
        holding = self.ledger.holding(bot_id, product, book=book)
        view = BotView(
            bot_id=bot_id,
            product=product,
            params=bot["params"],
            state=bot["state"],
            holding=holding,
            open_orders=self.store.orders(
                owner=bot_id, statuses=LIVE_STATUSES, book=book
            ),
            pending_fills=self._pending_fills(bot_id, book),
            fee_rate=self.fee_rate,
            spec=self.spec_for(product),
            now=self.now(),
        )
        mid = self._mid(product)
        if mid is not None:
            self.benchmark.start(
                bot_id,
                base=holding.base,
                quote=holding.quote,
                price=mid,
                book=book,
            )

        init = not bot["init_done"]
        decision = self._decision(bot, strategy, snap, view, init=init, book=book)
        transient_refusal = self._submit_decision(
            bot, decision, product, init=init
        )
        if init and decision.pause_reason is None and not transient_refusal:
            self.store.set_init_done(bot_id)
        self._merge_state(bot, decision.state_update)
        if decision.pause_reason:
            self.store.set_bot_status(bot_id, PAUSED)
            self.store.put(
                f"{PAUSED_REASON_PREFIX}{bot_id}", PAUSE_REASON_STRATEGY
            )
            self.store.event(
                "warn",
                f"bot {bot_id} paused: {decision.pause_reason}",
                kind="bot_paused",
                owner=bot_id,
            )

    def _decision(
        self,
        bot: dict,
        strategy: Strategy,
        snap: MarketSnapshot,
        view: BotView,
        *,
        init: bool,
        book: str = DRY,
    ) -> Decision:
        """The first book once per bot, otherwise one tick's answer.

        While `init_done` is 0 the first book may already be partly on the book
        (a crash mid-init, or a refusal the next cycle retries), so a place intent
        for a (side, level) that this bot already holds today is dropped:
        re-placing it would double a level.  "Today" starts at the bot's init
        epoch, which a recenter stamps, so the replaced grid's rows say nothing
        about the new one and every level of the new grid is free again.
        """
        if not init:
            return strategy.decide(snap, view)
        decision = strategy.init_intents(snap, view)
        return replace(
            decision,
            intents=self._without_placed_levels(
                bot["id"], decision.intents, book
            ),
        )

    def _without_placed_levels(
        self, bot_id: str, intents: list[OrderIntent], book: str = DRY
    ) -> list[OrderIntent]:
        """*intents* without a place whose level this bot already holds today.

        Today begins at the bot's init epoch (`runner:init_since:<bot_id>`): a row
        older than that belongs to the grid a recenter replaced, so its level is
        free again on the new one.  With no epoch on record (a bot that was never
        recentered, or a value that is not a number) every row counts, which is
        what a crash mid-init needs: the rows already on the book are the ones a
        retried first book must not place twice.  Only *book*'s rows count: the
        grid being laid is the one on the book the bot trades now.
        """
        epoch = self._init_epoch(bot_id)
        taken = {
            (row["side"], row["level"])
            for row in self.store.orders(
                owner=bot_id, statuses=(PENDING_SUBMIT, OPEN, FILLED), book=book
            )
            if epoch is None or _stamp(row["created_at"]) >= epoch
        }
        kept: list[OrderIntent] = []
        for intent in intents:
            if intent.action == "place" and (intent.side, intent.level) in taken:
                log.warning(
                    "bot %s: init level %s %s is already on the book; not placed "
                    "twice",
                    bot_id,
                    intent.side,
                    intent.level,
                )
                continue
            kept.append(intent)
        return kept

    def _init_epoch(self, bot_id: str) -> Optional[float]:
        """When this bot's current grid started, or None when nothing stamps it.

        Read back from the kv table, so a value that is absent, or not a number
        (a hand-edited file, an older key), means "no epoch": every row counts as
        today's and the filter behaves as it did before recentering existed.  The
        stamp is the wall clock, the same one that stamped the `created_at`
        values it is compared with.
        """
        value = self.store.get(f"{INIT_SINCE_PREFIX}{bot_id}")
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _merge_state(self, bot: dict, state_update: Optional[dict]) -> None:
        """Fold a decision's state into the bot's own, key by key."""
        if state_update is None:
            return
        self.store.set_bot_state(
            bot["id"], {**(bot["state"] or {}), **state_update}
        )

    # ------------------------------------------------ step 5a: repairs
    def _heal(self, bot_id: str, bot: dict, book: str = DRY) -> None:
        """Repair the bookkeeping a crash or a refusal left, in two passes.

        Only *book*'s rows are read and written: a bot's turn is about the book
        it trades now, and the book it left is frozen.

        First, a row that names the fill it answers is the record of an accepted
        follow-up, so the fill's own annotations (parent id, cost basis) are
        written from it and the fill is retired when it is still pending.  A SELL
        row from the first book — no parent, no basis, a level above the center —
        gets the grid's center as its basis, which is where its own profit starts;
        without this the repair a crash needs would leave such a sell counted at
        no known cost.

        Second, a fill marked answered whose every follow-up is REJECTED or FAILED
        was not answered at all (the exchange refused it, or it never landed), so
        its mark goes back to `OPP_TODO` and the next decision offers it again.
        That retry is bounded: at `MAX_FOLLOW_UP_REJECTIONS` or more settled
        refusals — a FAILED child, or a REJECTED one whose note is not a post-only
        bounce, which is no answer at all — the fill is retired as `OPP_SKIPPED`
        with `FOLLOW_UP_REJECTED_NOTE` and one alert naming the reason instead, so
        a level the exchange will never take is not offered for ever.  A skipped
        row is no longer `OPP_PLACED`, so later cycles neither retry it nor alert
        again.  A fill with no follow-up row yet, or with any follow-up in another
        status, is left alone.

        Both passes run before the view is built, so the next decision cannot
        place the same follow-up a second time.  The first pass already refuses to
        retire a fill whose only follow-up failed; the second is what un-marks
        such a fill so it is offered again, or retires it once the refusals have
        added up.
        """
        for row in self.store.orders(owner=bot_id, book=book):
            fill_cid = row["consumes_fill"]
            if not fill_cid:
                if (
                    row["side"] == money.SELL
                    and row["parent_cid"] is None
                    and row["basis_per_base"] is None
                    and (row["level"] or 0) > 0
                ):
                    basis = self._init_basis(bot, row["side"])
                    if basis is not None:
                        self.store.update_order(
                            row["client_order_id"], basis_per_base=basis
                        )
                continue
            parent = self.store.order(fill_cid)
            fields: dict[str, Any] = {}
            if row["parent_cid"] is None:
                fields["parent_cid"] = fill_cid
            if (
                parent is not None
                and row["side"] == money.SELL
                and row["basis_per_base"] is None
            ):
                basis = self._basis_of(parent)
                if basis is not None:
                    fields["basis_per_base"] = basis
            if fields:
                self.store.update_order(row["client_order_id"], **fields)
            if parent is None:
                continue
            if parent["opposite"] == OPP_TODO and row["status"] not in (
                REJECTED,
                FAILED,
            ):
                self._retire_fill(fill_cid)

        rows = self.store.orders(owner=bot_id, book=book)
        children: dict[str, list[dict]] = {}
        for row in rows:
            for parent_cid in _parents_of(row):
                children.setdefault(parent_cid, []).append(row)
        for row in rows:
            if row["opposite"] != OPP_PLACED:
                continue
            cid = row["client_order_id"]
            follow_ups = children.get(cid)
            if not follow_ups:
                continue
            if not all(
                child["status"] in (REJECTED, FAILED) for child in follow_ups
            ):
                continue
            counted = [
                child
                for child in follow_ups
                if child["status"] == FAILED
                or "POST_ONLY" not in str(child["note"] or "")
            ]
            if len(counted) >= MAX_FOLLOW_UP_REJECTIONS:
                last = counted[-1]
                reason = str(last["note"] or "no reason recorded")
                self.store.update_order(
                    cid,
                    opposite=OPP_SKIPPED,
                    note=FOLLOW_UP_REJECTED_NOTE,
                )
                message = (
                    f"bot {bot_id}: fill {cid} was marked answered, but "
                    f"{len(counted)} follow-ups to it were rejected "
                    f"({', '.join(child['client_order_id'] for child in counted)}); "
                    f"last refusal: {reason}; not offered again"
                )
                log.error(message)
                self.store.event("ALERT", message, kind="alert")
                continue
            self.store.update_order(cid, opposite=OPP_TODO)
            message = (
                f"bot {bot_id}: fill {cid} was marked answered, but every "
                f"follow-up to it failed "
                f"({', '.join(child['client_order_id'] for child in follow_ups)}); "
                "offered again"
            )
            log.warning(message)
            self.store.event("warn", message, kind="bot_paused", owner=bot_id)

    # ------------------------------------------------ step 5b: pending fills
    def _pending_fills(self, bot_id: str, book: str = DRY) -> list[dict]:
        """The *book*'s fills still waiting for their opposite order, oldest first.

        Read from the stored rows, not from a reconcile report: a fill that was
        settled by a cycle which then died is still here.  The order is the
        legacy one — by `updated_at`, which is when the row settled, not when it
        was written — and a row with no client order id is warned about and
        passed on anyway (a strategy can only ignore it).
        """
        rows = [
            row
            for row in self.store.orders(
                owner=bot_id, statuses=(FILLED, CANCELLED), book=book
            )
            if row["filled_size"] > 0 and row["opposite"] == OPP_TODO
        ]
        rows.sort(
            key=lambda row: (
                _stamp(row["updated_at"]),
                row["client_order_id"] or "",
            )
        )
        for row in rows:
            if not row["client_order_id"]:
                message = (
                    f"bot {bot_id}: pending fill row with no client_order_id "
                    f"(order_id {row.get('order_id')}); it cannot be answered"
                )
                log.warning(message)
                self.store.event("warn", message)
        return rows

    # ------------------------------------------------ step 5f: sending
    def _submit_decision(
        self, bot: dict, decision: Decision, product: str, *, init: bool
    ) -> bool:
        """Send one decision: the cancels first, then the places.

        A cancel that does not go through holds back every place in the same
        decision (the order it names may have just filled, and a follow-up
        placed on that guess would double the position).  Held-back fills stay
        `OPP_TODO` and are retried on a later cycle; fills the strategy itself
        skipped are retired either way.

        Returns True when a place in the FIRST book's decision was refused with a
        transient code — halted, a stale, unusable or crossed snapshot, an
        unknown clock skew, a drawdown stop, a spent cap, or a currency the
        exchange is short of (UNALLOCATED_NEGATIVE, which clears once its owner's
        funds move) — so the caller leaves `init_done` at 0 and the next cycle
        offers the refused levels again.  Any other refusal (an order too large, a
        product not allowed, a level the sizing cannot fund) is settled: it would
        be refused just the same next cycle, so it must not hold the first book
        open for ever.  A decision that is not the first book always answers
        False.
        """
        bot_id = bot["id"]
        cancels = [i for i in decision.intents if i.action == "cancel"]
        places = [i for i in decision.intents if i.action != "cancel"]
        cancel_failed = False
        transient_refusal = False
        for intent in cancels:
            result = self.gateway.submit("bot", bot_id, intent, product)
            if result.ok:
                continue
            cancel_failed = True
            message = (
                f"bot {bot_id}: cancel {intent.cancel_cid} failed: "
                f"{result.refusal}; held back {len(places)} place intent(s)"
            )
            log.warning(message)
            self.store.event(
                "warn",
                message,
                kind="refusal",
                owner=bot_id,
                data={"code": result.refusal} if result.refusal else {},
            )
        if not cancel_failed:
            for intent in places:
                refusal = self._place(bot, intent, product, init=init)
                if init and refusal in TRANSIENT_REFUSALS:
                    transient_refusal = True
        self._skip_fills(decision.skipped_fills)
        return transient_refusal

    def _place(
        self, bot: dict, intent: OrderIntent, product: str, *, init: bool
    ) -> Optional[str]:
        """Send one place intent through the gateway and record the answer.

        A refusal is a warning and nothing else: the fill it would have answered
        stays pending, so the order is retried rather than lost.  The refusal
        code goes back to the caller, which is what tells a transient one (worth
        another cycle for the first book) from a settled one; None means the
        order was accepted.  An acceptance retires the fill it consumes and takes
        the annotations the gateway has no parameter for.
        """
        bot_id = bot["id"]
        result = self.gateway.submit("bot", bot_id, intent, product)
        if not result.ok:
            if init:
                message = (
                    f"bot {bot_id}: init refused {result.refusal} "
                    f"for level {intent.level}"
                )
                log.warning(message)
                self.store.event(
                    "warn",
                    message,
                    kind="refusal",
                    owner=bot_id,
                    data={"code": result.refusal} if result.refusal else {},
                )
            else:
                self._warn_refused(bot_id, intent, result.refusal)
            return result.refusal
        if result.cid:
            self._annotate(bot, intent, result.cid)
        if intent.consumes_fill:
            self._retire_fill(intent.consumes_fill)
            self.store.put(f"{REFUSED_PREFIX}{intent.consumes_fill}", None)
        return None

    def _warn_refused(
        self, bot_id: str, intent: OrderIntent, refusal: Optional[str]
    ) -> None:
        """Warn that a place was refused, once per fill and refusal code.

        A follow-up the exchange keeps refusing stays pending, so the same answer
        would otherwise be written every cycle.  The kv key holds the code last
        warned about for that fill (`runner:refused:<fill>`), so a repeat of it is
        silent while a different code is news again; the caller clears the key
        once the fill is finally answered.  A place that answers no fill has no
        such memory and warns every time.
        """
        if intent.consumes_fill:
            key = f"{REFUSED_PREFIX}{intent.consumes_fill}"
            if self.store.get(key) == refusal:
                return
            self.store.put(key, refusal)
        message = (
            f"bot {bot_id}: place refused {refusal} "
            f"(level {intent.level}, fill {intent.consumes_fill or '-'}); "
            "the fill stays pending"
        )
        log.warning(message)
        self.store.event(
            "warn",
            message,
            kind="refusal",
            owner=bot_id,
            data={"code": refusal} if refusal else {},
        )

    def _annotate(self, bot: dict, intent: OrderIntent, cid: str) -> None:
        """Write the parent id and the cost basis the gateway cannot take.

        A follow-up names the fill it answers, and a follow-up sell carries that
        fill's own cost per unit, so its profit is measurable once it trades.  An
        initial sell is marked at the grid's center, which is where its own
        profit starts; a buy has no basis to mark at all.
        """
        if intent.consumes_fill:
            self.store.update_order(
                cid,
                parent_cid=intent.consumes_fill,
                basis_per_base=self._parent_basis(intent),
            )
            return
        self.store.update_order(
            cid, basis_per_base=self._init_basis(bot, intent.side)
        )

    def _parent_basis(self, intent: OrderIntent) -> Optional[D]:
        """The cost per unit of the parent fill, for a follow-up sell."""
        if intent.side != money.SELL or not intent.consumes_fill:
            return None
        parent = self.store.order(intent.consumes_fill)
        if parent is None:
            return None
        return self._basis_of(parent)

    def _basis_of(self, parent: dict) -> Optional[D]:
        """What one unit of a filled buy cost, its fee included."""
        if parent["filled_size"] <= 0:
            return None
        return (parent["filled_value"] + parent["fees"]) / parent["filled_size"]

    def _init_basis(self, bot: dict, side: Optional[str]) -> Optional[D]:
        """An initial sell's basis: the configured center, when it has one.

        A buy has nothing to mark at all, and params without a usable center
        answer None rather than an invented cost per unit.
        """
        if side != money.SELL:
            return None
        try:
            return D(str((bot["params"] or {}).get("center")))
        except (ArithmeticError, ValueError, TypeError):
            return None

    def _retire_fill(self, cid: str) -> None:
        """Mark a fill answered, once, by whatever answered it."""
        row = self.store.order(cid)
        if row is None or row["opposite"] != OPP_TODO:
            return
        self.store.update_order(cid, opposite=OPP_PLACED)

    def _skip_fills(self, cids: list[str]) -> None:
        """Retire the fills the strategy itself decided to leave unanswered."""
        for cid in cids:
            if not isinstance(cid, str) or not cid:
                continue
            row = self.store.order(cid)
            if row is None or row["opposite"] != OPP_TODO:
                continue
            self.store.update_order(cid, opposite=OPP_SKIPPED)

    # ------------------------------------------------ step 6: marks
    def _ratchet_marks(self) -> None:
        """Move each bot's and each portfolio's high-water mark up to today's value.

        Only upwards: `update_hwm` keeps the larger of the two.  A STOPPED bot
        keeps its mark as it is, and an unknown portfolio mark is skipped rather
        than ratcheted from a partial sum.  A bot's mark is the mark of its own
        book, and the portfolio mark is written once per book over the bots that
        trade it, so switching books never carries one mark into the other.
        """
        for bot in self.store.list_bots():
            if bot["status"] == STOPPED:
                continue
            book = bot["mode"]
            mid = self._mid(bot["product"])
            if mid is None:
                continue
            product = bot["product"]
            self.store.update_hwm(
                bot["id"],
                self.ledger.equity(bot["id"], {product: mid}, product, book=book),
                book,
            )
        for book in self._books_in_play():
            equity = self.gateway.portfolio_equity(book)
            if equity is not None:
                self.store.update_hwm(PORTFOLIO_OWNER, equity, book)

    # ------------------------------------------------ step 6b: the trailing hold
    def _check_trailing_hold(self) -> None:
        """Alert a bot that has trailed its own starting mix for long enough.

        Housekeeping must never cost a cycle, so whatever this check raises is
        swallowed here with one warning and no exception text; the next cycle
        offers it again, and the episode's state is in the store either way.
        """
        try:
            self._trailing_holds()
        except Exception:  # noqa: BLE001 - a figure, not a cycle
            log.warning("trailing hold check skipped: the check failed")

    def _trailing_holds(self) -> None:
        """One trailing-hold check per bot, on the book the bot trades now.

        Every bot that is not STOPPED is measured: its equity at the product's
        usable mid against the shadow of the mix it started with on its own book
        (`Benchmark.vs_hold`, exactly as `/pnl` reads it), and the episode's own
        record decides whether that is news yet.  A bot whose product cannot be
        priced, or whose benchmark was never started, has no comparison to make
        and is skipped without writing anything: an unknown comparison is not a
        trailing hold and does not end one.
        """
        now = self.now()
        for bot in self.store.list_bots():
            if bot["status"] == STOPPED:
                continue
            bot_id = bot["id"]
            product = bot["product"]
            book = bot["mode"]
            mid = self._mid(product)
            if mid is None:
                continue
            equity = self.ledger.equity(
                bot_id, {product: mid}, product, book=book
            )
            try:
                vs_hold = self.benchmark.vs_hold(bot_id, equity, mid, book=book)
            except KeyError:
                # Never started on this book: there is no shadow to be behind.
                continue
            with self.store.tx():
                # The episode's mark and the event the runner raises with it are
                # ONE write: a store that will not take the event rolls the mark
                # back, so the next cycle owes the alert again instead of
                # recording an episode nothing was ever told about.
                alert = self.benchmark.trailing(
                    bot_id, book, vs_hold, now, self.trail_alert_days
                )
                if alert is not None:
                    days = alert["days_negative"]
                    message = (
                        f"bot {bot_id} has trailed holding for {days:.1f} days"
                    )
                    log.warning(message)
                    self.store.event(
                        "warn",
                        message,
                        kind="trailing_hold",
                        owner=bot_id,
                        data={"bot": bot_id, "book": book, "days_negative": days},
                    )

    # ------------------------------------------------ step 7: the exchange total
    def _check_unallocated(self) -> None:
        """Alert while an exchange holds less than the owners of its book are owed.

        Nothing here is traded away: a buy is already refused by the gateway with
        UNALLOCATED_NEGATIVE while a currency is short, and selling to rebalance
        the shortfall would spend one owner's money on another's.  One alert per
        episode and per book: the kv key holds the sorted list of short
        currencies, so a new alert is written only when that list changes, and
        the key is cleared when nothing is short.

        The live book is checked only while its account can be reached, and a
        totals read that fails there is logged (without its exception text) and
        skipped: a live account the engine cannot read must not stop the cycle
        the dry book still needs.
        """
        self._check_book_unallocated(DRY, self.exchange.totals())
        if not self.gateway.books.live_available():
            return
        try:
            live_totals = self.gateway.books.totals(LIVE)
        except Exception:  # noqa: BLE001 - an unreadable account is not a cycle
            log.warning("unallocated check skipped on the live book")
            return
        self._check_book_unallocated(LIVE, live_totals)

    def _check_book_unallocated(self, book: str, totals: dict) -> None:
        """The short-currency alert of one book, against that book's own totals."""
        key = UNALLOCATED_KEY if book == DRY else UNALLOCATED_LIVE_KEY
        short = sorted(
            currency
            for currency, value in self.ledger.unallocated(
                totals, book=book
            ).items()
            if value < 0
        )
        if not short:
            if self.store.get(key) is not None:
                self.store.put(key, None)
            return
        if self.store.get(key) == short:
            return
        message = (
            UNALLOCATED_PREFIX
            + ", ".join(short)
            + f" on the {book} book"
        )
        log.error(message)
        self.store.event("ALERT", message, kind="alert")
        self.store.put(key, short)

    # ------------------------------------------------ step 8: heartbeat
    def _heartbeat(self, errors: Optional[list[str]] = None) -> dict:
        """Write the heartbeat atomically and return the same payload.

        Written only by a cycle that reached this step: an exception earlier
        leaves the previous file in place, so the heartbeat's age is the honest
        measure of how long the engine has been failing.  `errors` names the bots
        that raised in this cycle's own step 5, in processing order: it is `[]`
        when every bot got through and also when a halt skipped that step, so a
        reader can tell one bot's failure from a cycle that never got there.
        """
        payload = {
            "ts": self.now(),
            "cycle": self.cycle_count,
            "bots_active": sum(
                1
                for bot in self.store.list_bots()
                if bot["status"] == ACTIVE
            ),
            "errors": list(errors or []),
        }
        path = self.heartbeat_path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + HEARTBEAT_TMP_SUFFIX)
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)
        return payload

    # ------------------------------------------------ pause, recenter and re-init
    def recenter(self, bot_id: str, new_center: Any) -> None:
        """Move a grid bot's center, then reinstate its book around the new one.

        The new params are built and put through the strategy's own checks BEFORE
        anything is touched, so a center that cannot build a grid changes nothing
        at all.  Then `_reinstate_book` pauses the bot, sweeps and retires its
        book and writes the new params with a new grid epoch, so the next cycle
        lays the new book.

        An abort (the book never settles) leaves the bot paused with its old
        params and grid in place, so the recenter can simply be retried.
        """
        with self.gateway.lock:
            bot = self.store.get_bot(bot_id)
            if bot is None:
                raise ValueError(f"no bot {bot_id!r}")
            strategy = self.strategies.get(bot["strategy"])
            if strategy is None:
                raise ValueError(
                    f"bot {bot_id}: unknown strategy {bot['strategy']!r}"
                )
            if bot["status"] == STOPPED:
                raise ValueError(f"bot {bot_id} is stopped; start it to recenter")
            recenter = _recenter_of(strategy, bot)
            new_params = self._recentered_params(
                bot, strategy, recenter, new_center
            )
            self._reinstate_book(
                bot,
                new_params,
                f"bot {bot_id}: recentered on {new_center}; the book re-inits",
            )

    def reinit_bot(self, bot_id: str) -> None:
        """Lay a bot's book again on the params it already has.

        The same write path as `recenter` without a new center: the bot is
        paused, its orders are swept off the exchange and reconciled until none
        of its rows is live, every fill still pending is retired as `recentered`,
        and the params it already had are written back with a new grid epoch and
        `init_done` cleared, so the next cycle lays a fresh book.

        A STOPPED bot is refused with `ValueError` (nothing is touched): a stop
        or a kill closed its book, and nothing here may re-open one.
        """
        with self.gateway.lock:
            bot = self.store.get_bot(bot_id)
            if bot is None:
                raise ValueError(f"no bot {bot_id!r}")
            if bot["status"] == STOPPED:
                raise ValueError(f"bot {bot_id} is stopped; start it to re-init")
            self._reinstate_book(
                bot,
                dict(bot["params"] or {}),
                f"bot {bot_id}: re-initialised; the book re-inits",
            )

    def is_pausing(self, bot_id: str) -> bool:
        """True while a pause of *bot_id* is still sweeping its book.

        A pause holds the cycle lock per pass and lets it go between them, so
        there is a window in which the bot row can be moved by another request
        while the sweep is still going.  A pause names its bot here for exactly
        that window, so the resume, recenter and mode routes can refuse instead of
        racing a sweep whose own final transaction would write over them.  The
        flag is in memory alone and cleared in a `finally`, so a pause that
        failed — or one that answered 409 — leaves nothing behind.
        """
        return bot_id in self._pausing

    def pause_bot(self, bot_id: str) -> tuple[int, str]:
        """Take a bot out of the market and leave it ready to lay its WHOLE book.

        Pause builds on the same reinstate path a recenter and a re-init take, in
        the order the parked rules require: the bot is written PAUSED first (no
        cycle may place while its book is in pieces), its *own* book is swept and
        reconciled until none of ITS rows is live, every fill still waiting for an
        opposite order is retired as `recentered`, and then ONE transaction
        (`_write_recentered`) writes the params it already had back with a new
        grid epoch, `init_done` cleared, the status PAUSED and `paused_reason`
        "owner".

        The new epoch is load-bearing: without it the resumed grid counts the
        replaced grid's filled rows as today's levels and lays a fraction of its
        orders (`_without_placed_levels`).  With it the filter sees no row of the
        old grid, so a resume lays every level again.  Retiring the pending fills
        for the same reason: a fill nobody answered must not be answered on a
        book that no longer exists.

        The lock is taken per pass and NEVER held for the wait between them, so a
        pause never queues a cycle (or the kill switch) behind its own waiting.
        Each pass reads the bot row again and refuses with `PauseChanged` unless
        the row is still the one the pause found — still PAUSED, still on the book
        being swept, with the same params and the same grid epoch — so a bot a
        stop or a kill marked STOPPED meanwhile is left stopped and nothing is
        written over the change.  While the sweep runs the bot is named in
        `is_pausing`, which is what makes the routes that would move it refuse.

        Answers `(how many live rows it had to clear, the status the bot had on
        entry)`, so a caller can tell a pause that did something from one that
        found an already-paused bot with a clean book.
        """
        with self.gateway.lock:
            bot = self.store.get_bot(bot_id)
            if bot is None:
                raise ValueError(f"no bot {bot_id!r}")
            prior_status = bot["status"]
            book = bot["mode"]
            if prior_status == STOPPED:
                raise ValueError(f"bot {bot_id} is stopped; start it to pause it")
            cleared = len(
                self.store.orders(
                    owner=bot_id, statuses=LIVE_STATUSES, book=book
                )
            )
            # The row's own facts, snapshotted BEFORE the status is written, so
            # the first pass already compares against them.
            entry = self._pause_entry(bot_id, bot)
            self._pausing.add(bot_id)
            self.store.set_bot_status(bot_id, PAUSED)
        try:
            exchange = self._exchange_for(book)
            self._sweep_for_pause(
                bot_id, book, exchange, entry, prior_status, cleared
            )
        finally:
            self._pausing.discard(bot_id)
        return cleared, prior_status

    def _pause_entry(self, bot_id: str, bot: dict) -> tuple[dict, str, Any]:
        """What a pause snapshots at entry: the params, the book, the grid epoch.

        Every pass compares the row it reads against this, so a change made while
        the pause was waiting ends the pause instead of being written over by the
        pause's own final transaction.
        """
        return (
            dict(bot["params"] or {}),
            bot["mode"],
            self.store.get(f"{INIT_SINCE_PREFIX}{bot_id}"),
        )

    def _pause_target(self, bot_id: str, book: str, entry: tuple) -> dict:
        """The bot row a pause may still write, or `PauseChanged` when it may not.

        Read under the cycle lock at the start of a pass.  The pause wrote PAUSED
        itself, so that is the status it has to find; the book being swept, the
        params it would write back and the grid epoch
        (`runner:init_since:<id>`) all have to be the ones snapshotted at entry.
        A bot a stop or a kill marked STOPPED meanwhile is the same refusal: it
        stays stopped and the pause writes nothing at all.
        """
        params, mode, init_since = entry
        changed = PauseChanged(
            f"bot {bot_id}: changed while it was being paused"
        )
        current = self.store.get_bot(bot_id)
        if current is None or current["status"] != PAUSED:
            raise changed
        if current["mode"] != book or current["mode"] != mode:
            raise changed
        if dict(current["params"] or {}) != params:
            raise changed
        if self.store.get(f"{INIT_SINCE_PREFIX}{bot_id}") != init_since:
            raise changed
        return current

    def _sweep_for_pause(
        self,
        bot_id: str,
        book: str,
        exchange: Any,
        entry: tuple,
        prior_status: str,
        cleared: int,
    ) -> None:
        """Sweep and reconcile *book*, then write the paused row, in one pass.

        The same repeated pass `_settle_recenter` makes, with the differences a
        pause needs: the pass runs under the cycle lock and the wait between
        passes runs outside it, and the pass that finds the book clear does the
        whole of the pause's write — every fill still waiting for an opposite
        order retired, then `_write_recentered` with the row's CURRENT params —
        inside that one critical section, so no write of a cycle or of another
        route can land between the check and the write.  The rows settle from the
        exchange on the reconcile that follows the sweep, not from the sweep's
        own answer.

        Cancelling is the kill path, and the kill path works while a book is
        halted, so a halt is never a reason to skip a sweep: the cancel always
        runs.  What a halt does end is the WAITING — a pass that still leaves a
        live row with the book halted raises at once (the caller's 502 path)
        instead of sweeping a book nothing may trade.  A row that moved under the
        pause raises `PauseChanged` (`_pause_target`) and writes nothing, so a
        kill that swept the book is never reported as a pause that left orders
        behind.
        """
        for attempt in range(RECENTER_SETTLE_TRIES):
            with self.gateway.lock:
                current = self._pause_target(bot_id, book, entry)
                self.gateway.cancel_all(scope="owner", owner=bot_id, book=book)
                reconcile(
                    self.store,
                    exchange,
                    now=self.now(),
                    gateway=self.gateway,
                    book=book,
                )
                if not self.store.orders(
                    owner=bot_id, statuses=LIVE_STATUSES, book=book
                ):
                    self._retire_pending_fills(bot_id, book)
                    spoke = prior_status != PAUSED or cleared > 0
                    self._write_recentered(
                        bot_id,
                        dict(current["params"] or {}),
                        PAUSED,
                        f"bot {bot_id}: paused; waiting orders cancelled",
                        kind="bot_paused" if spoke else None,
                        owner=bot_id if spoke else None,
                        data=(
                            {
                                "bot": bot_id,
                                "book": book,
                                "reason": PAUSE_REASON_OWNER,
                            }
                            if spoke
                            else None
                        ),
                        quiet=not spoke,
                        paused_reason=PAUSE_REASON_OWNER,
                    )
                    return
                if self.gateway.is_halted(book):
                    raise RuntimeError(
                        f"pause aborted: the {book} book is halted with rows "
                        "still live; press Pause again once it is cleared"
                    )
            if attempt < RECENTER_SETTLE_TRIES - 1:
                # OUTSIDE the lock: a pause never makes a cycle wait for it.
                self.sleep(RECENTER_SETTLE_WAIT_S)
        raise RuntimeError(
            "pause aborted: orders still live after "
            f"{RECENTER_SETTLE_TRIES} sweeps; press Pause again"
        )

    def _reinstate_book(self, bot: dict, params: dict, message: str) -> None:
        """Tear a bot's book down and write it back ready for a new one.

        Shared by `recenter` and `reinit_bot`, so a book is never taken apart one
        way and written back another.  In order: the bot is paused (no cycle may
        place while the book is in pieces), its orders are swept off the exchange
        and reconciled until none of its rows is live, every fill still pending
        is retired as `recentered` (an old fill must never be answered on a new
        grid), and the params, the new grid's epoch, `init_done` and the bot's own
        prior status are written together so the next cycle lays the new book —
        a bot that was already paused is still paused afterwards.
        """
        bot_id = bot["id"]
        prior_status = bot["status"]
        book = bot["mode"]
        self.store.set_bot_status(bot_id, PAUSED)
        self._settle_recenter(bot_id, book)
        self._retire_pending_fills(bot_id, book)
        self._write_recentered(bot_id, params, prior_status, message)

    def _recentered_params(
        self,
        bot: dict,
        strategy: Strategy,
        recenter: Callable[[dict, D], dict],
        new_center: Any,
    ) -> dict:
        """The params centered on *new_center*, validated against the product.

        Both the parse and the strategy's own checks raise `ValueError`, so a
        caller sees one error type for "that center cannot drive this grid".
        """
        try:
            center = D(str(new_center))
        except (ArithmeticError, ValueError, TypeError):
            raise ValueError(
                f"center must be a number, got {new_center!r}"
            ) from None
        if not center.is_finite():
            raise ValueError(
                f"center must be a finite number, got {new_center!r}"
            )
        try:
            new_params = recenter(bot["params"], center)
            strategy.validate(new_params, self.spec_for(bot["product"]))
        except (ArithmeticError, ValueError, TypeError) as error:
            raise ValueError(str(error)) from None
        return new_params

    def _exchange_for(self, book: str) -> Any:
        """The exchange one book's rows are settled from, or `LiveLocked`.

        The dry book's exchange is the simulator this runner was built with; the
        live book's is whatever the router reaches now.  There is no third
        answer: a caller that asks about the live book with no live account is
        refused rather than handed the simulator.
        """
        if book == DRY:
            return self.exchange
        live = self.gateway.books.live_exchange()
        if live is None:
            raise LiveLocked("the live book has no exchange")
        return live

    def _settle_recenter(self, bot_id: str, book: str = DRY) -> None:
        """Sweep, reconcile, and repeat until none of the bot's *book* rows is live.

        Every pass asks the kill path again, because one sweep is not a promise:
        the exchange may take only part of it, and the rows settle from the
        exchange on the reconcile that follows rather than from the sweep's own
        answer.  Both the sweep and the reconcile name the book: the rows being
        cleared are the rows of the book the bot is leaving, settled from that
        book's own exchange.  A book still live after `RECENTER_SETTLE_TRIES`
        passes aborts (the bot stays paused on its old grid) and says so in terms
        of retrying it.
        """
        exchange = self._exchange_for(book)
        for attempt in range(RECENTER_SETTLE_TRIES):
            self.gateway.cancel_all(scope="owner", owner=bot_id, book=book)
            reconcile(
                self.store,
                exchange,
                now=self.now(),
                gateway=self.gateway,
                book=book,
            )
            if not self.store.orders(
                owner=bot_id, statuses=LIVE_STATUSES, book=book
            ):
                return
            if attempt < RECENTER_SETTLE_TRIES - 1:
                self.sleep(RECENTER_SETTLE_WAIT_S)
        raise RuntimeError(
            "recenter aborted: orders still live after "
            f"{RECENTER_SETTLE_TRIES} sweeps; retry the recenter"
        )

    def _retire_pending_fills(self, bot_id: str, book: str = DRY) -> None:
        """Retire every *book* fill still waiting for an opposite, as `recentered`."""
        for row in self.store.orders(owner=bot_id, book=book):
            if row["opposite"] != OPP_TODO:
                continue
            self.store.update_order(
                row["client_order_id"],
                opposite=OPP_SKIPPED,
                note=RECENTER_NOTE,
            )

    def _write_recentered(
        self,
        bot_id: str,
        new_params: dict,
        status: str,
        message: str,
        *,
        kind: Optional[str] = None,
        owner: Optional[str] = None,
        data: Optional[dict] = None,
        quiet: bool = False,
        paused_reason: Optional[str] = None,
    ) -> None:
        """Write the new params, the new grid's epoch and the bot's status, once.

        One transaction on purpose: a reader that saw the new params without the
        epoch (or the other way round) could count the replaced grid's rows as
        today's and hold a level of the new one back.  Every write inside it goes
        through a store setter, which joins the caller's open transaction rather
        than opening one of its own.  The epoch is stored as
        `runner:init_since:<id>` with `store.put`, so `store.get` hands
        `_init_epoch` the float back.  It is stamped with the wall clock
        (`time.time()`), not with the injected `now`: the level filter compares it
        with a row's `created_at`, which the store stamps with the wall clock, so
        the two have to share a clock even when a caller moves `now`.

        *message* is the one info event the caller's path reports.  *kind*,
        *owner* and *data* are how a caller that has something to classify
        (a pause) tags that event; with no *kind* the plain info event this path
        has always written is written, so a recenter and a re-init are unchanged.
        *quiet* writes the row changes and no event at all, which is what a pause
        that found nothing to do needs.

        *paused_reason* is WHY the bot is paused, written here — in the same
        transaction — under `bot:paused_reason:<id>`; a pause passes `"owner"`.
        With none the key is left exactly as it was, so a recenter and a re-init
        say nothing about a pause nobody made.
        """
        with self.store.tx():
            self.store.set_bot_params(bot_id, new_params)
            self.store.set_init_done(bot_id, False)
            self.store.set_bot_status(bot_id, status)
            self.store.put(f"{INIT_SINCE_PREFIX}{bot_id}", time.time())
            if paused_reason is not None:
                self.store.put(
                    f"{PAUSED_REASON_PREFIX}{bot_id}", paused_reason
                )
        log.info(message)
        if quiet:
            return
        if kind is None:
            self.store.event("info", message)
            return
        self.store.event("info", message, kind=kind, owner=owner, data=data)

    # ------------------------------------------------ the book switch
    def switch_mode(
        self,
        bot_id: str,
        mode: str,
        capital_quote: Any = None,
        capital_base: Any = None,
    ) -> None:
        """Move a bot from one book to the other, or refuse it and change nothing.

        Runs under the cycle lock, and every check runs before anything is
        written: a refusal leaves the bot row, its orders, its high-water marks,
        its benchmark and the exchange exactly as they were.

        Dry to live: the live book is given its own capital budget, taken from
        what the real account still has unallocated in each of the two currencies.
        The bot is paused, ITS dry orders are swept off the simulator and settled
        until none of them is live, its pending fills are retired, and then one
        transaction writes the new mode and budget, a fresh live epoch (so live
        holdings start counting now), no live high-water mark, no live benchmark,
        a first book to lay again, and the bot's own prior status.  The dry book
        is left frozen exactly as it is: its history stays and it is simply no
        longer traded.

        Live to dry: the bot's live value at the product's mid becomes its dry
        capital, so nothing is created and nothing is lost in the move.  The same
        pause, sweep and retire run on the live book (through the live account
        alone), and one transaction writes the new mode and capital, a fresh epoch
        on BOTH books (the dry book restarts, and the live holdings are released
        back to the account's unallocated balance), no dry high-water mark, no dry
        benchmark, the simulated capital deposit, a first book to lay again and
        the bot's own prior status.

        Either way that same transaction re-bases BOTH books' portfolio marks to
        today's equity (`_rebase_portfolio_marks`): the portfolio each book's
        drawdown stop measures is a different one once this bot has left the old
        book and joined the new, and a mark carried over would halt the engine on
        the first cycle afterwards.

        *capital_quote* and *capital_base* are the one budget the caller sets: a
        switch to the live book requires both, and a switch to the dry book
        refuses them, because its capital is the live book's own value.

        A settle that cannot clear the old book (the exchange keeps answering
        with the orders still live) raises `SETTLE_FAILED` as a 503 instead of
        letting the abort out as a server fault: nothing past the pause was
        written, so the bot is left paused on the book it was already on and the
        whole switch can simply be retried.
        """
        with self.gateway.lock:
            bot = self.store.get_bot(bot_id)
            if bot is None:
                raise ValueError(f"no bot {bot_id!r}")
            if mode not in BOOKS:
                raise ValueError(f"unknown mode: {mode!r}")
            if bot["status"] == STOPPED:
                raise ModeRefused(
                    STOPPED_BOT,
                    409,
                    f"bot {bot_id} is stopped; start it to switch books",
                )
            if bot["mode"] == mode:
                raise ModeRefused(
                    ALREADY_LIVE if mode == LIVE else ALREADY_DRY,
                    409,
                    f"bot {bot_id} already trades the {mode} book",
                )
            try:
                if mode == LIVE:
                    self._switch_to_live(bot, capital_quote, capital_base)
                else:
                    self._switch_to_dry(bot, capital_quote, capital_base)
            except ModeRefused:
                raise
            except RuntimeError as error:
                # The settle's own abort, and nothing else: every refusal this
                # path raises on purpose is a ModeRefused, handled above.  The
                # bot is paused on its old book with nothing else written.
                log.warning(
                    "bot %s: switch to %s did not settle: %s", bot_id, mode, error
                )
                raise ModeRefused(
                    SETTLE_FAILED, 503, SETTLE_FAILED_MESSAGE
                ) from None

    def _switch_capital(
        self, capital_quote: Any, capital_base: Any
    ) -> tuple[D, D]:
        """The live budget a dry-to-live switch asks for, each amount >= 0.

        Both amounts are required and are read as `Decimal` strings: a boolean,
        an unusable number, a negative one and two zeros are all refused with
        `CAPITAL_INVALID` before anything is looked at.
        """
        if capital_quote is None or capital_base is None:
            raise ModeRefused(
                CAPITAL_INVALID,
                422,
                "a switch to the live book needs capital_quote and capital_base",
            )
        amounts: list[D] = []
        for name, raw in (
            ("capital_quote", capital_quote),
            ("capital_base", capital_base),
        ):
            if isinstance(raw, bool):
                raise ModeRefused(
                    CAPITAL_INVALID, 422, f"{name} must be a number, not a boolean"
                )
            try:
                amount = D(str(raw))
            except (ArithmeticError, ValueError, TypeError):
                raise ModeRefused(
                    CAPITAL_INVALID, 422, f"{name} must be a number"
                ) from None
            if not amount.is_finite() or amount < 0:
                raise ModeRefused(
                    CAPITAL_INVALID,
                    422,
                    f"{name} must be a finite number >= 0",
                )
            amounts.append(amount)
        quote, base = amounts
        if quote == 0 and base == 0:
            raise ModeRefused(
                CAPITAL_INVALID,
                422,
                "the live capital must be more than zero: both amounts are zero",
            )
        return quote, base

    def _switch_to_live(
        self, bot: dict, capital_quote: Any, capital_base: Any
    ) -> None:
        """Move one bot onto the live book, once every check has passed."""
        bot_id = bot["id"]
        quote, base = self._switch_capital(capital_quote, capital_base)
        switches = self.gateway.switches
        if not switches.ceiling or not switches.live_enabled():
            raise ModeRefused(
                LIVE_DISABLED,
                409,
                "live trading is switched off; turn it on before switching a bot",
            )
        if self.gateway.books.live_exchange() is None:
            raise ModeRefused(
                LIVE_LOCKED, 409, "there is no live exchange to trade on"
            )
        try:
            live_totals = self.gateway.books.totals(LIVE)
        except LiveLocked:
            raise ModeRefused(
                LIVE_LOCKED, 409, "there is no live exchange to trade on"
            ) from None
        base_currency, quote_currency = bot["product"].split("-", 1)
        unallocated = self.ledger.unallocated(live_totals, book=LIVE)
        short = [
            f"{amount} {currency}"
            for currency, amount in (
                (quote_currency, quote),
                (base_currency, base),
            )
            if unallocated.get(currency, D(0)) < amount
        ]
        if short:
            raise ModeRefused(
                LIVE_CAPITAL_SHORT,
                409,
                "the live book has less unallocated than this switch asks for: "
                + ", ".join(short),
            )

        prior_status = bot["status"]
        self.store.set_bot_status(bot_id, PAUSED)
        self._settle_recenter(bot_id, DRY)
        self._retire_pending_fills(bot_id, DRY)
        now = time.time()
        with self.store.tx():
            self.store.set_bot_book(
                bot_id,
                mode=LIVE,
                capital_quote=bot["capital_quote"],
                capital_base=bot["capital_base"],
                live_capital_quote=quote,
                live_capital_base=base,
            )
            self.store.set_book_epoch(LIVE, bot_id, now)
            self.store.reset_hwm(bot_id, LIVE)
            self.benchmark.forget(bot_id, LIVE)
            self.store.set_init_done(bot_id, False)
            self.store.put(f"{INIT_SINCE_PREFIX}{bot_id}", now)
            self.store.set_bot_status(bot_id, prior_status)
            self._rebase_portfolio_marks()
        message = f"bot {bot_id} switched to {LIVE}"
        log.info(message)
        self.store.event(
            "info",
            message,
            kind="live_switch",
            owner=bot_id,
            data={"bot": bot_id, "book": LIVE},
        )

    def _switch_to_dry(
        self, bot: dict, capital_quote: Any, capital_base: Any
    ) -> None:
        """Move one bot back onto the dry book, once every check has passed."""
        bot_id = bot["id"]
        if capital_quote is not None or capital_base is not None:
            raise ModeRefused(
                CAPITAL_INVALID,
                422,
                "a switch to the dry book takes its capital from the live book's "
                "value; send no capital",
            )
        product = bot["product"]
        mid = self._mid(product)
        if mid is None:
            raise ModeRefused(
                PRICE_UNKNOWN,
                503,
                f"cannot price {product}, so the live book's value is unknown",
            )
        value = self.ledger.equity(bot_id, {product: mid}, product, book=LIVE)
        if value <= 0:
            raise ModeRefused(
                CAPITAL_INVALID,
                422,
                f"the live book is worth {value}, which cannot fund the dry book",
            )
        live = self.gateway.books.live_exchange()
        if live is None and self.store.orders(
            owner=bot_id, statuses=LIVE_STATUSES, book=LIVE
        ):
            raise ModeRefused(
                LIVE_LOCKED,
                409,
                "the bot still has live orders and there is no live exchange to "
                "cancel them on",
            )

        prior_status = bot["status"]
        self.store.set_bot_status(bot_id, PAUSED)
        if live is not None:
            self._settle_recenter(bot_id, LIVE)
        self._retire_pending_fills(bot_id, LIVE)
        now = time.time()
        with self.store.tx():
            self.store.set_bot_book(
                bot_id,
                mode=DRY,
                capital_quote=value,
                capital_base=D(0),
                live_capital_quote=None,
                live_capital_base=None,
            )
            self.store.set_book_epoch(DRY, bot_id, now)
            self.store.set_book_epoch(LIVE, bot_id, now)
            self.store.reset_hwm(bot_id, DRY)
            self.benchmark.forget(bot_id, DRY)
            self.gateway.seed_dry(bot_id, value, D(0))
            self.store.set_init_done(bot_id, False)
            self.store.put(f"{INIT_SINCE_PREFIX}{bot_id}", now)
            self.store.set_bot_status(bot_id, prior_status)
            self._rebase_portfolio_marks()
        message = f"bot {bot_id} switched to {DRY}"
        log.info(message)
        self.store.event(
            "info",
            message,
            kind="live_switch",
            owner=bot_id,
            data={"bot": bot_id, "book": DRY},
        )

    # ------------------------------------------------ high-water marks
    def _rebase_portfolio_marks(self) -> None:
        """Write BOTH books' portfolio marks to today's equity, inside the caller's tx.

        A bot changing books changes what each book's portfolio is: the book it
        left has one fewer bot on it and the book it entered one more.  A mark
        left where it was would measure the new, smaller portfolio against the
        old, larger one and halt on the very next cycle, so both books' marks are
        re-based here, up or down, to what `portfolio_equity(book)` says now —
        after the new mode is written, so this bot already counts on the book it
        entered and no longer on the one it left.

        A book no bot trades, or one whose portfolio cannot be priced, has its
        mark reset instead: the next cycle ratchets a fresh one off the first
        equity it can measure, which is exactly what a book starting over wants.
        The write is the one `rebase_hwm` makes, done here directly so it joins
        the switch's own transaction rather than opening (and logging) a second
        one.
        """
        in_play = self._books_in_play()
        for book in BOOKS:
            equity = (
                self.gateway.portfolio_equity(book) if book in in_play else None
            )
            if equity is None:
                self.store.reset_hwm(PORTFOLIO_OWNER, book)
                continue
            # A privileged switch rebasing a mark downward forgives an
            # in-progress drawdown (accepted).
            with self.store.tx() as db:
                db.execute(
                    "INSERT INTO hwm(book,owner,value) VALUES(?,?,?) "
                    "ON CONFLICT(book,owner) DO UPDATE SET value=excluded.value",
                    (book, PORTFOLIO_OWNER, str(equity)),
                )

    def rebase_hwm(self, owner: str, equity: Any, book: str = DRY) -> None:
        """Write an owner's high-water mark on *book* to exactly *equity*, up or down.

        `store.update_hwm` only ratchets up, so a mark that has to come down —
        which is what clearing a sticky drawdown stop means — is written here, in
        one transaction, on the named book (the dry book by default, which is the
        book every bot traded before books existed).  The book is a bound
        parameter, so re-basing one book's mark never moves the other's.  The
        caller has priced its own equity and is saying so explicitly; nothing
        here decides whether the new mark is sensible.
        """
        if book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        value = D(str(equity))
        with self.store.tx() as db:
            db.execute(
                "INSERT INTO hwm(book,owner,value) VALUES(?,?,?) "
                "ON CONFLICT(book,owner) DO UPDATE SET value=excluded.value",
                (book, owner, str(value)),
            )
        message = f"hwm for {owner} re-based to {value}"
        log.info(message)
        self.store.event("info", message)

    # ------------------------------------------------ benchmark bookkeeping
    def forget_benchmark(self, bot_id: str) -> None:
        """Drop a bot's benchmark baseline on BOTH books, so a later start is fresh.

        Needed when a bot is deleted: the kv key outlives the bot row, and a new
        bot reusing the id would otherwise inherit the old shadow.  Both books'
        records go, so whichever book the reused id starts on has no baseline.
        """
        for book in BOOKS:
            self.benchmark.forget(bot_id, book)

    # ------------------------------------------------ the loop
    def run_forever(
        self,
        poll_seconds: Optional[float] = None,
        stop: Optional[threading.Event] = None,
    ) -> None:
        """Cycle until *stop* is set, retrying a failed cycle up to a limit.

        A failed cycle is logged and recorded, then the loop waits and tries
        again: the heartbeat it did not write is what tells the watchdog (and the
        healthcheck) that the engine is not getting through, so the heartbeat
        stays the watchdog's signal for a hiccup.  The raise here is the restart
        path for a loop that is not getting through at all: after
        `MAX_CONSECUTIVE_FAILURES` failures in a row the exception is re-raised,
        which ends the thread and lets the container start it again.  A cycle that
        succeeds resets the count, so an occasional failure never adds up.
        """
        poll = self.limits.poll_seconds if poll_seconds is None else poll_seconds
        event = stop if stop is not None else threading.Event()
        consecutive_failures = 0
        while not event.is_set():
            try:
                self.cycle()
            except Exception as error:  # noqa: BLE001 - survive a hiccup, not a wall
                consecutive_failures += 1
                log.exception("cycle %s failed", self.cycle_count)
                self.store.event(
                    "error",
                    f"cycle {self.cycle_count} failed: {error}",
                    kind="alert",
                )
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    raise
            else:
                consecutive_failures = 0
            event.wait(poll)


# ---------------------------------------------------------------- helpers


def _trail_alert_days(value: Any) -> int:
    """The days a bot may trail its mix before it is news: a positive whole number.

    A value that is absent, blank, not a whole number, or not positive is
    `DEFAULT_TRAIL_ALERT_DAYS`: a window nobody can read must not become one that
    never alerts, and a window of zero would alert on the first dip.
    """
    if value is None or isinstance(value, bool):
        return DEFAULT_TRAIL_ALERT_DAYS
    try:
        days = int(str(value).strip())
    except (TypeError, ValueError):
        return DEFAULT_TRAIL_ALERT_DAYS
    return days if days > 0 else DEFAULT_TRAIL_ALERT_DAYS


def _recenter_of(strategy: Strategy, bot: dict) -> Callable[[dict, D], dict]:
    """A strategy's recenter step, or `ValueError` when it has none.

    Only a level grid has a center to move, so a rebalancer is refused here
    rather than half-recentered.
    """
    try:
        return strategy.recenter
    except AttributeError:
        raise ValueError(
            f"bot {bot['id']}: strategy {bot['strategy']!r} has no center"
        ) from None


def _stamp(value: Any) -> float:
    """A stored timestamp as a float; an absent or unusable one is zero."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _parents_of(row: dict) -> tuple[str, ...]:
    """The fills one follow-up row answers: its `consumes_fill` and `parent_cid`.

    Both name the same fill once the repair has run, and either may be the only
    one a half-written row carries, so the child index counts each parent once.
    """
    parents: list[str] = []
    for name in ("consumes_fill", "parent_cid"):
        cid = row.get(name)
        if isinstance(cid, str) and cid and cid not in parents:
            parents.append(cid)
    return tuple(parents)