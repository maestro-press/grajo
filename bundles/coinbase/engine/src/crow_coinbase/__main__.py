"""__main__.py: one process per engine — build the pieces, check them, run them.

`build_app` wires the real engine over a data directory: the sqlite store, the
dry-run exchange over that same file, the snapshot cache, the ledger, the two
live switches and the router that serves each book its own exchange, the order
gateway, the two strategies and the runner, and finally the HTTP app over all of
them.  The live book's exchange is the credentials slot's answer, and the slot
starts empty: an engine comes up pinned (if the owner ever connected a key) and
with no live account at all, so the live book is locked until a key is pushed to
it.  Equities ride that same slot: the shared key is the default (one account on
both sides of the router), and an optional second credential names the equity
account instead, judged at the push that brings it.  The dry exchange is built
with the same product hooks the router has, and the AI's equity capital is
seeded into it as dry USD once, at build.

Equities turn themselves OFF; they never refuse a start.  Coinbase's public
product endpoint answers 404 for a stock, so the engine may not need a public
equity read to come up: the one `EquityStatus` below is what says whether the
stock products can be traded, an injected `spec_for` is trusted (a caller that
brought its own specs needs no key), and the engine's own `spec_for` reads a
stock's spec from that status's AUTHENTICATED reads alone — a product
`limits.is_equity` names with no authenticated spec yet raises
`ProductUnavailable` in plain words rather than reaching for the public
endpoint, which is exactly what keeps the gateway's stock path off it.  Every
other product reads the public spec as it always did.  The one equity
configuration problem a start still refuses is equity live while the crypto
ceiling is off; everything else (an unconfirmed preview, a list whose products
turn out to be the other kind, a read that failed) is the runner's step 4c
alert, with crypto left untouched.  The token is read before anything on disk is
touched: an engine with no token is refused, not started with unauthenticated
routes.

`main` then does the three things a container needs, in this order:

    1. build, and answer `EXIT_REFUSED` for a configuration that may not start
    2. run the runner's own startup checks; any problem refuses the start too,
       and nothing is started (no thread, no socket)
    3. start the cycle loop on its own daemon thread, then serve the app

The runner's thread is the engine's life.  `_run_runner` ends the process when
the loop returns or raises: a loop that gave up (five failed cycles in a row) is
a container that has to be restarted, so it exits with `EXIT_RUNNER_DIED` in
every case — returning quietly would leave an API answering with a heartbeat
that never gets fresher.  `os._exit` is called as an attribute lookup on the
module, so a test can stand in for it.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional

import uvicorn

from .api import ENV_TOKEN, create_app, token_or_refuse
from .ai_orders import AiOrders, ai_order_mode
from .ai_orders import preview_ttl_s as ai_preview_ttl
from .auth import Authenticator, pin_exists
from .books import BookRouter, Switches, dry_exchange_for
from .credentials import CredentialSlot
from .equity_wiring import EquityStatus, wiring_from
from .exchange import (
    EQUITY_PREVIEW_CONFIRMED_KEY,
    EquityQuotePaused,
    LiveExchange,
    MarketData,
    ProductUnavailable,
)
from .gateway import OrderGateway
from .ledger import Ledger
from .limits import CapWindow, Limits, RuntimeLimits
from .runner import (
    TRAIL_ALERT_DAYS_ENV,
    Runner,
    StartupRefused,
    build_snapshot_cache,
)
from .store import Store
from .strategies.base import Strategy
from .strategies.grid import GridStrategy
from .strategies.rebalance import RebalanceStrategy
from .tiingo import TiingoPaused, TiingoQuotes

D = Decimal
log = logging.getLogger("crow_coinbase.main")

# ---------------------------------------------------------------- the process
# Every interface INSIDE the container; the host side of the published port is
# loopback only, so this address never reaches a network of its own.
HOST = "0.0.0.0"
PORT = 3062

# 3: the configuration may not be started at all (nothing was opened).
EXIT_REFUSED = 3
# 1: the cycle loop ended, so the process has to be replaced.
EXIT_RUNNER_DIED = 1

ENV_DATA_DIR = "CROW_COINBASE_DATA_DIR"
DEFAULT_DATA_DIR = "/data"
DATABASE_NAME = "engine.sqlite"
HEARTBEAT_NAME = "heartbeat"
RUNNER_THREAD_NAME = "coinbase-runner"


@dataclass(frozen=True)
class Engine:
    """One built engine: what serves requests, and what cycles underneath it.

    `auth` is the approval rail the app's privileged routes were built over, kept
    here so a later owner approval can pin its secret (`auth.set_secret`) without
    rebuilding the app.  `slot` is the owner's credentials — the one holder of the
    live route, in memory only — kept for the same reason: a request installs a
    key through it, and `/health` reports what it holds.  `ai_orders` is the AI's
    preview and approval surface the gateway's approval step and the app's five
    AI routes were built over; an engine built without one carries neither.
    `tiingo` is the stock-price client: the source the engine's own equity quotes
    read, and the object the app's three stock-price routes store a token in and
    forget it from, so a caller that brought its own client keeps the handle it
    brought.
    """

    app: Any
    runner: Runner
    store: Store
    gateway: OrderGateway
    exchange: Any
    limits: Any
    auth: Any = None
    slot: Any = None
    ai_orders: Any = None
    tiingo: Any = None


# ---------------------------------------------------------------- markets


class EquityQuoteSource:
    """The engine's own equity quote source: the client's read, pause converted.

    A stock-price client that is being rate-limited, or whose allowance is used
    up, answers with its own `TiingoPaused` — a pause, and not a fault of the
    engine, the owner or the product.  A product does not know that word, so this
    is the one conversion the engine makes: a pause becomes
    `EquityQuotePaused`, the refusal the runner reports once as news and stops
    calling a fault, and every other failure (`TiingoError` and the rest) is left
    exactly as it was for the market to report in its own words.

    The refusal text names the symbol and says the prices are paused; it is built
    here, so it can carry no token, URL or feed text — the client's sentences are
    the only ones it ever quotes, and those are fixed.

    It IS the client's own read with one conversion in front of it, and it says
    so: comparing it with the client's `last` (which is what a caller checking
    `market.equity_last` is asking) answers yes, because no second source was
    introduced.
    """

    __slots__ = ("source",)

    def __init__(self, source: Any) -> None:
        self.source = source

    def __call__(self, symbol: str) -> Any:
        """The client's last price for *symbol*, with a pause made the engine's."""
        try:
            return self.source.last(symbol)
        except TiingoPaused:
            raise EquityQuotePaused(f"{symbol}: stock prices are paused") from None

    def __eq__(self, other: object) -> bool:
        """True for this source, one over the same client, and the client's own read."""
        if other is self:
            return True
        if isinstance(other, EquityQuoteSource):
            return other.source is self.source
        return other == self.source.last

    def __hash__(self) -> int:
        return hash(self.source)

    def __repr__(self) -> str:
        """No token can be here: the client's own `repr` shows its state only."""
        return f"EquityQuoteSource({self.source!r})"


def tiingo_equity_last(client: TiingoQuotes) -> EquityQuoteSource:
    """The equity quote source `build_app` builds over the stock-price client.

    A thin wrapper over `client.last`: `TiingoPaused` becomes the engine's own
    `EquityQuotePaused` (the symbol and "stock prices are paused", so a reader
    can report a pause without reporting a fault), and every other error passes
    through untouched — a refused token stays a refused token, a stale print
    stays a stale print.  Nothing is cached, stored or converted twice.
    """
    return EquityQuoteSource(client)


def _cached_market_for(
    is_equity: Callable[[str], bool],
    equity_last: Optional[Callable[[str], Any]],
) -> Callable[[str], MarketData]:
    """A `market_for` that builds one public-data client per product, once.

    An equity product's client is given the equity quote source *equity_last* —
    the callable over its base symbol — and every other product's is given none,
    so a crypto product is never handed a quote source it has no use for and an
    equity's last print is the one thing it prices from.  `MarketData` is looked
    up on this module at call time, so a caller standing in for it sees every
    client that is built.
    """
    cache: dict[str, MarketData] = {}

    def market_for(product: str) -> MarketData:
        market = cache.get(product)
        if market is None:
            market = MarketData(
                product,
                equity_last=equity_last if is_equity(product) else None,
            )
            cache[product] = market
        return market

    return market_for


def _cached_spec_for(
    market_for: Callable[[str], MarketData],
) -> Callable[[str], Any]:
    """A `spec_for` that reads each product's spec off its market client once."""
    cache: dict[str, Any] = {}

    def spec_for(product: str) -> Any:
        spec = cache.get(product)
        if spec is None:
            spec = market_for(product).product()[0]
            cache[product] = spec
        return spec

    return spec_for


def _equity_aware_spec_for(
    is_equity: Callable[[str], bool],
    status: Any,
    public_spec_for: Callable[[str], Any],
) -> Callable[[str], Any]:
    """The engine's own `spec_for`: a stock's spec comes from the authenticated reads.

    A product `is_equity` names is answered from the equity status's kept specs —
    the ones an installed key's AUTHENTICATED product read gave — and, while
    nothing has confirmed it, with a `ProductUnavailable` in plain words.  It
    never asks the public product endpoint for a stock, because that endpoint
    answers 404 for one: the engine can come up and cycle without it.  Every
    other product asks *public_spec_for*, exactly as it always did.
    """

    def spec_for(product: str) -> Any:
        if is_equity(product):
            spec = status.spec_for(product)
            if spec is None:
                raise ProductUnavailable(
                    f"no authenticated product spec for {product} yet: connect a "
                    "key to read the stock products"
                )
            return spec
        return public_spec_for(product)

    return spec_for


def _book_mid(bid: Any, ask: Any) -> D:
    """The mid of the top of book, or a `ValueError` when it is not a price.

    A bid at or below zero, an ask that does not sit above the bid (a crossed
    book), and a mid that is not a finite positive number are all a book this
    engine cannot value anything with: raising here is what lets the surface
    answer 503 rather than counting a bot's base capital as nothing.
    """
    top_bid, top_ask = D(bid), D(ask)
    if not top_bid.is_finite() or not top_ask.is_finite():
        raise ValueError(f"the book is not finite: bid {bid}, ask {ask}")
    if top_bid <= 0:
        raise ValueError(f"the book has no bid: bid {bid}, ask {ask}")
    if top_ask <= top_bid:
        raise ValueError(f"the book is crossed: bid {bid}, ask {ask}")
    mid = (top_bid + top_ask) / 2
    if not mid.is_finite() or mid <= 0:
        raise ValueError(f"the book's mid is not a positive number: {mid}")
    return mid


def _price_for(
    snapshots: Any, market_for: Callable[[str], MarketData]
) -> Callable[[str], D]:
    """The mid a bot's base capital is valued at, from the cache or the book.

    A usable snapshot is the price the engine's own orders are checked against,
    so it is preferred; with none (a bot created before the first poll) the
    public top of book answers instead, and a book that cannot be read — no
    bid, a crossed one, a price that is not finite — raises to the caller.
    """

    def price_for(product: str) -> D:
        snap = snapshots.get(product)
        if snap is not None and snap.bid > 0 and snap.ask > snap.bid:
            return _book_mid(snap.bid, snap.ask)
        bid, ask = market_for(product).best_bid_ask()
        return _book_mid(bid, ask)

    return price_for


def _live_adapter(store: Store) -> Callable[[dict], Any]:
    """The builder the slot uses when the caller injects none: the real adapter.

    *creds* is `{"api_key": key name, "api_secret": private key}` — the pair the
    engine holds in memory and never writes down.  It is copied rather than kept
    by reference, so nothing here outlives the call with a reference to the dict
    a request built.

    The adapter is given the equity preview confirmation the store holds when it
    is BUILT, not when this engine started: an equity order sent through it needs
    that confirmation on record at send time, and the owner may record it after
    the engine came up.
    """

    def build(creds: dict) -> Any:
        return LiveExchange(
            dict(creds),
            equity_preview_confirmation=store.get(EQUITY_PREVIEW_CONFIRMED_KEY),
        )

    return build


# ---------------------------------------------------------------- building


def build_app(
    env: Mapping[str, str],
    *,
    data_dir: Optional[Path | str] = None,
    market_for: Optional[Callable[[str], Any]] = None,
    spec_for: Optional[Callable[[str], Any]] = None,
    equity_last: Optional[Callable[[str], Any]] = None,
    tiingo: Optional[TiingoQuotes] = None,
    now: Callable[[], float] = time.time,
    strategies: Optional[Mapping[str, Strategy]] = None,
    live_factory: Optional[Callable[[], Any]] = None,
    live_builder: Optional[Callable[[dict], Any]] = None,
) -> Engine:
    """Build the whole engine over *data_dir*, with the outside world injected.

    The token is checked first, before the data directory is created: a refused
    start leaves no file behind.  `market_for` and `spec_for` default to public
    market data (built lazily, so nothing here opens a socket), `now` is the
    clock the runner stamps the heartbeat with, and `strategies` defaults to the
    grid and the rebalancer.  `equity_last` is the equity quote source the
    default `market_for` gives every product `limits.is_equity` names — a
    callable over the base symbol answering `(price, timestamp)` — and an injected
    one wins over the Tiingo client below, so a caller that brought its own
    source never has it asked for a price.

    `tiingo` is the stock-price client the equity quotes come from, and with none
    this builds a fresh one: it holds the owner's token in memory alone (no
    environment variable and no compose file is read for it), it is the app's
    three stock-price routes' object, and it is kept on the `Engine` so the caller
    keeps the handle it brought.  `equity_last` still wins when it is given — the
    client is then only the routes' object, and an injected source is never
    wrapped — while with neither the engine's own quotes are
    `tiingo_equity_last(quotes)`: a thin wrapper over the client's `last` that
    turns a pause (`TiingoPaused`) into the engine's own `EquityQuotePaused`, so
    an equity product is priced from Tiingo's print, a paused feed is reported as
    a pause rather than as a fault, and an install with no token stores no price
    at all.  The client this builds is told how many equity products the engine
    trades, so its cache time is spread over all of them; a client the caller
    brought keeps its own count.

    The live book's exchange is the credentials slot's own answer, asked again on
    every access: with no key in memory it is None, which is what the live book
    answers `LIVE_LOCKED` to.  A `live_factory` passed in still wins over the slot
    — that is how a caller pins the live side to something of its own — and
    `live_builder(creds)` is how the slot builds the adapter one key pair names,
    defaulting to the real `LiveExchange` with the equity preview confirmation the
    store holds at the moment the adapter is built.  Both are injected so nothing
    in a test ever reaches the exchange, and neither is called at build time.  The
    two live switches come from the store and the live ceiling from *env*, and
    both are handed to the gateway (which decides every route) and to the app
    (which offers them).

    The approval rail is built here, over the same store and clock, with the
    install token file *env* names (or the one the installer publishes at the
    default path), and the app is built over it: a privileged route therefore
    needs the owner's MAC, and the rail is kept on the `Engine` so its secret can
    be pinned later.  The rail's pin answer is the store's own: `pin_exists` is
    asked on every approval, so a pin written by a later request takes the
    install token out of the rail without anything being rebuilt.

    The AI's order surface is built here too, over the same store: it owns the
    gateway's approval step (an `ai` order needs an approved, unspent, unexpired
    preview of exactly that order) and the five AI routes the app mounts.  Its
    mode and preview window come from *env*, read with the token and before
    anything is written; `main` turns a refusal of either into a start that never
    happens.

    The credentials slot is built over that same store and rail, and the app is
    given it: the three credentials routes exist on this engine, the live route
    is the slot's, and a restart therefore comes up pinned with no live exchange
    at all until the owner pushes the key again.  Equities ride that same slot:
    the one key it is given serves both accounts by default, and a second,
    optional credential names the equity account instead.  The equity half a
    second key is judged against is `equity_wiring.wiring_from`, built here over
    the runtime limits, the store, *env* and the `EquityStatus` the gateway and
    the spec lookups share.

    `EquityStatus` is what says whether the stock products may be traded: it is
    trusted when the caller injected its own `spec_for` (an embedding, a test) and
    unverified otherwise, and a key push is what verifies it against the
    AUTHENTICATED product reads.  The default `spec_for` is built over it, so a
    stock is answered from those reads and never from the public product
    endpoint — which answers 404 for one — and a stock the status has no spec for
    yet raises `ProductUnavailable` instead.

    The dry exchange is the engine's own simulator (`books.dry_exchange_for`),
    carrying the same product hooks the router has, and the AI's equity capital
    is seeded into it as USD once the gateway exists: without that a dry equity
    BUY would have no money behind its pool.

    The caps the engine reads are runtime ones: the environment is their ceiling,
    and the values in force live in this store's kv, read on every check.  That
    object is what the gateway, the runner's drawdown check and the surface
    share, so one cap set through the surface is the cap the next order is
    measured against.  The AI's live capital is that same object read through a
    callable, so the ledger reserves what the cap says now.
    """
    token = token_or_refuse(env.get(ENV_TOKEN))
    # The AI's order mode and preview window are read here, with the token and
    # before anything on disk is opened: a mode this build may not run in, or a
    # window nobody can read, is a start that leaves no file and no directory
    # behind ("autonomous" is P3's, not this build's).
    ai_order_mode(env)
    window = ai_preview_ttl(env)
    # The stock-price client: the caller's own when it brought one, otherwise a
    # fresh one holding no token.  It reaches the network only when the engine
    # asks it for a price and a token is in its memory.  The one built here is
    # told how many equity products are configured, so its cache time grows with
    # the products polled (more symbols, a longer wait each, the same allowance
    # spread over them).  `runtime_limits` is built below: the lambda reads it
    # when a cache time is asked for, which is only ever after this returns, and
    # a count it cannot read is one product.  A client the caller brought keeps
    # the count it was built with and is not re-aimed.
    quotes = (
        TiingoQuotes(product_count=lambda: len(runtime_limits.equity_products))
        if tiingo is None
        else tiingo
    )
    # The engine's own equity quotes are a thin wrapper over that client's read
    # (`tiingo_equity_last`), so a paused feed reaches the engine as its own
    # `EquityQuotePaused`; a source the caller injected still wins untouched.
    if equity_last is None:
        equity_last = tiingo_equity_last(quotes)
    target = (
        Path(data_dir)
        if data_dir is not None
        else Path(env.get(ENV_DATA_DIR) or DEFAULT_DATA_DIR)
    )
    target.mkdir(parents=True, exist_ok=True)

    limits = Limits.from_env(env)
    fee_rate = limits.maker_fee_pct / 100
    if market_for is None:
        market_for = _cached_market_for(limits.is_equity, equity_last)
    # Whether the caller brought its own product specs: an embedding (or a test)
    # that injects `spec_for` has already said what every product is, so the
    # equity status is TRUSTED and nothing has to be confirmed by a key push.
    injected_specs = spec_for is not None
    chosen = (
        dict(strategies)
        if strategies is not None
        else {"grid": GridStrategy(), "rebalance": RebalanceStrategy()}
    )

    store = Store(target / DATABASE_NAME)
    # The dry book is one simulated account serving both product kinds, so it is
    # built with the same product hooks the router has: the configured lists and
    # the store's own EQUITY-row query, so a symbol that left the equity list is
    # still stepped as the equity its resting orders were.
    exchange = dry_exchange_for(store, limits, market_for, fee_rate)
    # The parsed environment is the CEILING of every cap; what the engine reads
    # at run time is the runtime set over it, held in this store's kv under one
    # key, so a cap can be lowered while the engine runs and never raised above
    # the value this process started with.  The AI's live capital is the same
    # object read through a callable, so a cap change is the next read's capital.
    runtime_limits = RuntimeLimits(limits, store)
    # Whether the stock products may be traded right now, as the AUTHENTICATED
    # product reads answer it: it starts unverified (or trusted, when the caller
    # injected its own specs), a key push verifies it, and the runner's step 4c
    # reports the reason while one stands.
    equity_status = EquityStatus(
        store, runtime_limits, trusted=injected_specs
    )
    if spec_for is None:
        spec_for = _equity_aware_spec_for(
            runtime_limits.is_equity, equity_status, _cached_spec_for(market_for)
        )
    snapshots = build_snapshot_cache(limits)
    ledger = Ledger(
        store,
        fee_rate=fee_rate,
        ai_capital=lambda: runtime_limits.ai_capital_usd,
        equity_ai_capital=lambda: runtime_limits.equity_ai_capital_usd,
        is_equity=runtime_limits.is_equity,
    )
    caps = CapWindow(store, time.time)
    switches = Switches(store, env)
    rail = Authenticator.from_env(store, env, now, pinned=lambda: pin_exists(store))
    # The equity half of the account, as the slot and the router read it: the
    # configured lists, asked again on every use, and the store's own two queries.
    # The status rides it, so the slot's key push is what verifies the lists.
    wiring = wiring_from(runtime_limits, store, env, status=equity_status)
    slot = CredentialSlot(
        store,
        rail,
        _live_adapter(store) if live_builder is None else live_builder,
        now=now,
        equity=wiring,
    )
    books = BookRouter(
        exchange,
        slot.live_exchange if live_factory is None else live_factory,
    )
    # The AI's previews and approvals, built before the gateway so its approval
    # step can be this object's own, and attached after it so the object knows the
    # gateway it places through.  Until `attach` runs, the gateway's own default
    # refuses every `ai` order.
    ai_orders = AiOrders(store, ttl_s=window, now=time.time)
    gateway = OrderGateway(
        store=store,
        ledger=ledger,
        limits=runtime_limits,
        caps=caps,
        snapshots=snapshots,
        spec_for=spec_for,
        fee_rate=fee_rate,
        totals=exchange.totals,
        exchange=exchange,
        books=books,
        switches=switches,
        now=time.time,
        approval_check=ai_orders.approval_check,
        consume_approval=ai_orders.consume,
        equity_status=equity_status,
    )
    # The dry book's equity capital is seeded as USD once the gateway exists, so
    # the pool a dry equity BUY draws on holds the capital the live one would.
    gateway.seed_dry_equity_capital()
    ai_orders.attach(gateway)
    heartbeat_path = target / HEARTBEAT_NAME
    runner = Runner(
        store=store,
        gateway=gateway,
        exchange=exchange,
        snapshots=snapshots,
        strategies=chosen,
        env=env,
        market_for=market_for,
        spec_for=spec_for,
        now=now,
        heartbeat_path=heartbeat_path,
        ai_sweep=ai_orders.sweep_locked,
        trail_alert_days=env.get(TRAIL_ALERT_DAYS_ENV),
    )
    app = create_app(
        store=store,
        gateway=gateway,
        runner=runner,
        exchange=exchange,
        strategies=chosen,
        limits=runtime_limits,
        spec_for=spec_for,
        price_for=_price_for(snapshots, market_for),
        token=token,
        heartbeat_path=heartbeat_path,
        now=now,
        switches=switches,
        auth=rail,
        slot=slot,
        ai_orders=ai_orders,
        tiingo=quotes,
    )
    return Engine(
        app=app,
        runner=runner,
        store=store,
        gateway=gateway,
        exchange=exchange,
        limits=runtime_limits,
        auth=rail,
        slot=slot,
        ai_orders=ai_orders,
        tiingo=quotes,
    )


# ---------------------------------------------------------------- running


def _run_runner(runner: Any) -> None:
    """Run the cycle loop on this thread, and end the process whenever it stops.

    A raise and a plain return are the same outcome here: the engine has no loop,
    so the container has to start another one.  The error is logged first, so the
    reason survives into the log the restart replaces.
    """
    try:
        runner.run_forever()
        log.error("the runner returned; ending the process")
    except BaseException as error:  # noqa: BLE001 - any end of the loop ends us
        log.error("the runner stopped: %s", error)
    finally:
        os._exit(EXIT_RUNNER_DIED)


def main(
    env: Optional[Mapping[str, str]] = None,
    *,
    build: Callable[[Mapping[str, str]], Engine] = build_app,
    serve: Optional[Callable[..., Any]] = None,
) -> int:
    """Build, check, start the loop and serve; the exit code of a refused start.

    A `StartupRefused` (or any `ValueError` out of the configuration), and any
    problem the runner's own startup checks report, answer `EXIT_REFUSED` with
    nothing started: no thread, no socket.  Logging is configured first, so a
    refusal and the reasons for it reach the container's log.
    """
    logging.basicConfig(level=logging.INFO)
    source = os.environ if env is None else env
    run = uvicorn.run if serve is None else serve

    try:
        engine = build(source)
    except StartupRefused as error:
        log.error("refusing to start: %s", error)
        return EXIT_REFUSED
    except ValueError as error:
        log.error("refusing to start: %s", error)
        return EXIT_REFUSED

    problems = engine.runner.startup_checks()
    if problems:
        for problem in problems:
            log.error("startup check failed: %s", problem)
        return EXIT_REFUSED

    thread = threading.Thread(
        target=_run_runner,
        args=(engine.runner,),
        name=RUNNER_THREAD_NAME,
        daemon=True,
    )
    thread.start()
    run(engine.app, host=HOST, port=PORT)
    return 0


if __name__ == "__main__":
    sys.exit(main())