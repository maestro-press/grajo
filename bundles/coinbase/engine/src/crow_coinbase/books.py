"""books.py: the two books an order belongs to, and the switches that allow live.

A book is `dry` (the simulator, `DryRunExchange`) or `live` (the real account).
Everything else in the engine reads a book by name: a bot's `mode` says which one
it trades, an order row and a fill row carry the book they were written on, a
high-water mark is keyed by (book, owner), and the caps count one book at a time.
The two books are never one book: nothing here — or anywhere else — falls back
from one to the other.

`BookRouter` answers which exchange serves a book.  It holds no order-writing
method and calls none: placing and cancelling stay in the gateway, and seeding the
simulator stays in the gateway's own `seed_dry`.  Its live side is either nothing,
an `ExchangeRouter`, or a zero-argument factory that is asked again on every
access (so credentials that appear later are picked up), and a factory that raises
is "there is no live exchange right now", never an error the caller has to handle.
`dry_exchange_for` is the one place the dry book is built, so the engine and the
watchdog get the same simulator with the same product hooks.

`Switches` is the two kv flags an owner sets, plus the one ceiling that is not a
switch at all: `CROW_COINBASE_LIVE` in the environment.  The ceiling defaults to
true (the live path exists from P2 on), and every spelling that is not clearly
true is read as false, so a value nobody recognises forbids live rather than
allowing it.  `route_decision` is the single place that turns a bot's mode and
those switches into the book an order takes and the refusal it earns; a live-mode
owner refused live is never rerouted to the simulator.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only, so no import cycle at runtime
    from .router import ExchangeRouter

log = logging.getLogger("crow_coinbase.books")

# ---------------------------------------------------------------- the books
DRY = "dry"
LIVE = "live"
BOOKS = (DRY, LIVE)

# ---------------------------------------------------------------- refusal codes
LIVE_DISABLED = "LIVE_DISABLED"  # the ceiling, or a switch, says live may not trade
LIVE_LOCKED = "LIVE_LOCKED"  # live is allowed but no live exchange exists
LIVE_NEEDS_OWNER = "LIVE_NEEDS_OWNER"  # the route needs the owner's approval
APPROVAL_INVALID = "APPROVAL_INVALID"  # the approval the route needs was not given

# ---------------------------------------------------------------- the ceiling
# The environment variable that is the hard ceiling on live trading: it may
# forbid live whatever the switches say, and it can never allow more than they do.
ENV_LIVE = "CROW_COINBASE_LIVE"
# What a boolean env value may say, lower-cased and stripped.  A value on neither
# list is false, so an unreadable setting fails closed.
TRUE_WORDS = ("true", "1", "yes", "on")
FALSE_WORDS = ("false", "0", "no", "off")

# ---------------------------------------------------------------- the switches
SWITCH_LIVE = "live_enabled"
SWITCH_AI_LIVE = "ai_live_enabled"
SWITCH_NAMES = (SWITCH_LIVE, SWITCH_AI_LIVE)


class LiveLocked(Exception):
    """The live book was asked for and there is no live exchange to reach."""


class ModeRefused(RuntimeError):
    """A mode switch the engine refused, carrying the code and status it answers.

    `code` is the refusal code, `status` the HTTP status that code answers with,
    and `message` the plain reason.  The exception's own message starts with the
    code (`"LIVE_LOCKED: ..."`), which is how a runtime failure names the refusal
    it is, while `.message` is the reason alone for a caller that composes the
    two itself.
    """

    def __init__(self, code: str, status: int, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.status = status
        self.message = message


class BookRouter:
    """Which exchange serves which book, and the live account's own totals.

    `dry` is the simulator every engine has.  `live` is nothing (`None`), an
    `ExchangeRouter` over the real account, or a zero-argument callable answering
    one of those or `None`; the callable is asked on every access, so a live
    account that only becomes available later is picked up without the engine
    being rebuilt.  A callable that raises is answered as "no live exchange" and
    logged without its exception text: a missing credential is a state, not a
    fault to report the details of.
    """

    def __init__(self, dry: Any, live: Any = None) -> None:
        self.dry = dry
        self._live = live

    # ------------------------------------------------ the live side
    def live_exchange(self) -> "Optional[ExchangeRouter]":
        """The live account's exchange, or None when there is none right now."""
        live = self._live
        if live is None:
            return None
        if callable(live):
            try:
                return live()
            except Exception:  # noqa: BLE001 - no credentials is a state, not a fault
                log.warning(
                    "no live exchange: the live factory could not build one"
                )
                return None
        return live

    def live_available(self) -> bool:
        """True when a live exchange can be reached right now."""
        return self.live_exchange() is not None

    # ------------------------------------------------ per book
    def for_book(self, book: str) -> Any:
        """The exchange serving *book*; `LiveLocked` when the live one is missing."""
        if book == DRY:
            return self.dry
        if book == LIVE:
            exchange = self.live_exchange()
            if exchange is None:
                raise LiveLocked("the live book has no exchange")
            return exchange
        raise ValueError(f"unknown book: {book!r}")

    def totals(self, book: str) -> dict[str, Any]:
        """The account totals of *book*: the simulator's, or the live crypto one.

        The live book's totals are the crypto account's own (`crypto_totals`),
        never a merged view: the money this book allocates from is one account's.
        """
        if book == DRY:
            return self.dry.totals()
        if book == LIVE:
            exchange = self.live_exchange()
            if exchange is None:
                raise LiveLocked("the live book has no exchange")
            return exchange.crypto_totals()
        raise ValueError(f"unknown book: {book!r}")


def no_live_exchange() -> None:
    """The default live factory: no live exchange exists yet, so there is none."""
    return None


def dry_exchange_for(store, limits, market_for, fee_rate):
    """The simulator serving the dry book, over *store*, from *limits*.

    One simulated account serves both product kinds, so the dry book needs no
    second adapter: it is given the same product hooks the router has — the
    configured equity list, the configured crypto list, and the store's own query
    for an EQUITY row of a product — so a delisted symbol whose rows are EQUITY
    rows is still simulated as an equity.  Both the engine and the watchdog build
    the dry book this way, from the same environment and over the same store, and
    neither reaches for the live side at all.

    `DryRunExchange` is imported here rather than at the top of the module, so
    importing `books` still loads no simulator (and no store) of its own.
    """
    from .exchange import DryRunExchange

    return DryRunExchange(
        store.conn,
        market_for,
        fee_rate,
        is_equity=limits.is_equity,
        is_crypto=lambda product: product in limits.products,
        equity_rows=store.has_equity_rows,
    )


def ceiling_from_env(env: Mapping[str, str]) -> bool:
    """The live ceiling from *env*: absent is true, anything unclear is false.

    Only `CROW_COINBASE_LIVE` is read.  An absent key answers True — the live path
    exists from P2 on — while a key that is present answers True only for
    `true/1/yes/on`; blank, an unknown word and every other spelling answer False,
    because a ceiling nobody can read must forbid live rather than allow it.
    """
    raw = env.get(ENV_LIVE)
    if raw is None:
        return True
    return str(raw).strip().lower() in TRUE_WORDS


class Switches:
    """The two live switches in the kv table, and the ceiling above them.

    A switch is on only when its stored value is exactly the JSON boolean true;
    a missing key, a string "true", a 1 and anything else are off.  `set` writes
    one switch and refuses a name or a value it does not know rather than storing
    something the reader would then read as off.
    """

    def __init__(self, store: Any, env: Mapping[str, str]) -> None:
        self.store = store
        self.ceiling = ceiling_from_env(env)

    def _flag(self, name: str) -> bool:
        return self.store.get(name) is True

    def live_enabled(self) -> bool:
        """Whether the owner's switch allows any bot's live route."""
        return self._flag(SWITCH_LIVE)

    def ai_live_enabled(self) -> bool:
        """Whether the owner's switch allows the `ai` owner's live route."""
        return self._flag(SWITCH_AI_LIVE)

    def set(self, name: str, value: bool) -> None:
        """Write one switch; anything but one of the two names and a bool is refused."""
        if name not in SWITCH_NAMES:
            raise ValueError(f"unknown switch: {name!r}")
        if not isinstance(value, bool):
            raise ValueError(f"a switch is true or false, got {value!r}")
        self.store.put(name, value)

    def snapshot(self) -> dict:
        """Both switches and the ceiling, as the surface reports them."""
        return {
            "live_enabled": self.live_enabled(),
            "ai_live_enabled": self.ai_live_enabled(),
            "ceiling": self.ceiling,
        }


def route_decision(
    *,
    ceiling: bool,
    switch: bool,
    have_exchange: bool,
    mode: str,
) -> tuple[str, Optional[str]]:
    """The book a route takes and the refusal it earns, or `(book, None)`.

    A dry-mode owner always trades the simulator.  A live-mode owner takes the
    live book only when the ceiling allows it, their switch is on and a live
    exchange exists; otherwise the answer is still the live book with the refusal
    that stopped it — `LIVE_DISABLED` when the ceiling or the switch says no
    (checked first), `LIVE_LOCKED` when there is simply no live exchange.  A live
    route is never rerouted to the simulator.
    """
    if mode == DRY:
        return DRY, None
    if mode != LIVE:
        raise ValueError(f"unknown mode: {mode!r}")
    if not ceiling or not switch:
        return LIVE, LIVE_DISABLED
    if not have_exchange:
        return LIVE, LIVE_LOCKED
    return LIVE, None