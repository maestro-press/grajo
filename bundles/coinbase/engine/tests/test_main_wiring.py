"""test_main_wiring.py: what `__main__` hands the engine when equities are on.

Every test here builds the REAL engine through `build_app` — a real `Store` on a
temporary data directory, the real dry-run simulator, gateway, ledger and runner
— and fakes only what sits outside the engine's own code:

* `FakeMarket` answers a fixed touch (and one fixed equity print), so no market
  client is ever built and nothing opens a socket.
* `FakeLiveBuilder` is the `live_builder` `build_app` takes.  It raises, because
  no test here pushes a key: an adapter built on one of these paths would be a
  call nothing asked for.
* `spec_for` is a table of `ProductSpec`s (or, where a test is about the kinds a
  live exchange would report, a stand-in object carrying only `product_type`).

The products are synthetic: `NVDA-USD` and `VOO-USD` on the equity side,
`BTC-USD` and `XRP-USDC` on the crypto one, and `VOO-USD` as the symbol that has
left the configured list but still has rows.

What the tests pin down:

* the dry simulator is handed all three product hooks — the configured equity
  list, the configured crypto list, and the store query for an equity row — so a
  delisted symbol with EQUITY rows is still simulated as an equity while a
  SPOT-only row never makes anything one,
* the AI's equity capital is seeded into the dry book once, only ever upward,
  and nothing is seeded with no capital or no equity products,
* a dry AI equity BUY of that capital is not refused `UNALLOCATED_NEGATIVE`,
* `_cached_market_for` gives an equity product the equity quote source, a crypto
  product none, and one market client per product,
* `main` refuses to start when equity live is asked for while the crypto live
  ceiling is off — and reports nothing else: neither the preview confirmation nor
  a product's kind is a startup problem any more (equities turn themselves off
  instead, which is the cycle's own check), so a start with a wrong listing or no
  confirmation on record is a start that happens, and a start reads no kind at
  all,
* the watchdog's process entry point builds the same dry exchange from the same
  environment, over the same store file.
"""

from __future__ import annotations

import secrets
import time
from decimal import Decimal as D

import crow_coinbase.__main__ as main_module
import crow_coinbase.watchdog as watchdog_module
from crow_coinbase.exchange import DryRunExchange
from crow_coinbase.gateway import UNALLOCATED_NEGATIVE
from crow_coinbase.money import ProductSpec
from crow_coinbase.store import OPEN
from crow_coinbase.strategies.base import MarketSnapshot, OrderIntent

# ---------------------------------------------------------------- test data
# A bearer token in the shape the engine starts with, built at runtime.
TOKEN = "test-token-" + secrets.token_hex(16)

# The products these tests trade: two equities, and two crypto products.
NVDA = "NVDA-USD"
VOO = "VOO-USD"
BTC = "BTC-USD"
XRP = "XRP-USDC"
CRYPTO = f"{BTC},{XRP}"

# The environment variables the wiring reads.
TOKEN_ENV = "CROW_COINBASE_ENGINE_TOKEN"
PRODUCTS_ENV = "CROW_COINBASE_PRODUCTS"
EQUITY_PRODUCTS_ENV = "CROW_COINBASE_EQUITY_PRODUCTS"
EQUITY_CAPITAL_ENV = "CROW_COINBASE_EQUITY_AI_CAPITAL_USD"
EQUITY_LIVE_ENV = "CROW_COINBASE_EQUITY_LIVE"
LIVE_ENV = "CROW_COINBASE_LIVE"
DATA_DIR_ENV = "CROW_COINBASE_DATA_DIR"

# The kv key the owner's confirmed equity preview is recorded under.
PREVIEW_KEY = "equity_preview_confirmed"

ENV = {
    TOKEN_ENV: TOKEN,
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    PRODUCTS_ENV: CRYPTO,
    "CROW_COINBASE_MAX_BOT_CAPITAL_USD": "100",
}


def env_for(**overrides: str) -> dict[str, str]:
    """The environment these tests build with, plus the values one test sets."""
    env = dict(ENV)
    env.update(overrides)
    return env


# ---------------------------------------------------------------- the outside world


class FakeMarket:
    """A public market with a fixed touch: no client, no request, no candles."""

    def __init__(self, bid=D("0.99"), ask=D("1.00")):
        self.bid, self.ask = D(bid), D(ask)

    def best_bid_ask(self):
        return self.bid, self.ask

    def range_since(self, since):
        return self.bid, self.ask

    def candles(self, start, end):
        return []

    def equity_quote(self):
        return D("100"), time.time()


_MARKETS: dict[str, FakeMarket] = {}


def market_for(product: str) -> FakeMarket:
    """One `FakeMarket` per product, so the dry book always has a price."""
    return _MARKETS.setdefault(product, FakeMarket())


class FakeLiveBuilder:
    """A `live_builder` that must never be asked for an adapter here."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, creds):
        self.calls += 1
        raise AssertionError("no live adapter may be built by this test")


# ---------------------------------------------------------------- specs


def equity_spec(product: str = NVDA, **overrides) -> ProductSpec:
    """An equity listing: cents on the price, fractional shares, USD quoted."""
    fields = dict(
        product_id=product,
        price_increment=D("0.01"),
        base_increment=D("0.0001"),
        quote_increment=D("0.01"),
        base_min_size=D("0.0001"),
        quote_min_size=D("1"),
        product_type="EQUITY",
        fractionable=True,
    )
    fields.update(overrides)
    return ProductSpec(**fields)


def spot_spec(product: str) -> ProductSpec:
    """A crypto listing, in the shape the crypto list's products have."""
    return ProductSpec(
        product,
        price_increment=D("0.0001"),
        base_increment=D("0.1"),
        quote_increment=D("0.01"),
        base_min_size=D("1"),
        quote_min_size=D("1"),
    )


def spec(product: str) -> ProductSpec:
    """The listing of *product*: an equity for the configured equities, else SPOT."""
    return equity_spec(product) if product in (NVDA, VOO) else spot_spec(product)


# ---------------------------------------------------------------- the harness


def build(env, data_dir, *, market=None, spec_for=None):
    """The real engine over *data_dir*, with the outside world injected."""
    return main_module.build_app(
        env,
        data_dir=data_dir,
        market_for=market_for if market is None else market,
        spec_for=spec if spec_for is None else spec_for,
        now=lambda: time.time(),
        live_builder=FakeLiveBuilder(),
    )


def insert_row(store, product: str, *, product_type: str, suffix: int = 1) -> None:
    """One order row written the engine's own way, on the dry book."""
    store.insert_order(
        f"cb-ai-B0-{suffix:012x}",
        "ai",
        "ai",
        product,
        "BUY",
        0,
        D("1"),
        D("1"),
        status=OPEN,
        book="dry",
        product_type=product_type,
    )


# ---------------------------------------------------------------- the dry exchange


def test_dry_exchange_hooks_wired(tmp_path):
    """The simulator gets the equity list, the crypto list and the row query."""
    engine = build(
        env_for(**{EQUITY_PRODUCTS_ENV: NVDA}),
        tmp_path / "hooks",
    )
    exchange = engine.exchange
    assert isinstance(exchange, DryRunExchange)

    # The configured equity list is the equity rule, and the crypto list is the
    # crypto one: a product is on one of them, never both.
    assert exchange.is_equity(NVDA)
    assert not exchange.is_equity(BTC)
    assert exchange.is_crypto(BTC)
    assert not exchange.is_crypto(NVDA)

    # A listed equity is owned by the equity side before it has any row.
    assert exchange.owns_equity(NVDA)
    assert not exchange.owns_equity(VOO)

    # A symbol that left the configured list keeps its EQUITY rows: the store
    # query is what still makes the simulator treat it as an equity.
    insert_row(engine.store, VOO, product_type="EQUITY")
    assert exchange.owns_equity(VOO)

    # A SPOT row never makes a product owned by the equity side.
    insert_row(engine.store, BTC, product_type="SPOT", suffix=2)
    assert not exchange.owns_equity(BTC)


# ---------------------------------------------------------------- the dry seed


def test_dry_equity_capital_seeded(tmp_path):
    """The AI's equity capital lands in the dry account once, and only upward."""
    root = tmp_path / "seed"
    engine = build(
        env_for(**{EQUITY_PRODUCTS_ENV: NVDA, EQUITY_CAPITAL_ENV: "100"}), root
    )
    assert engine.exchange.totals()["USD"] == D("100")

    # The ledger knows the same capital: the pool reserves exactly what the
    # account was given, so nothing of it is left unallocated.
    left = engine.gateway.ledger.unallocated(
        engine.exchange.totals(), book="dry"
    )
    assert left["USD"] == D("0")

    # A restart over the same data directory deposits nothing more.
    again = build(
        env_for(**{EQUITY_PRODUCTS_ENV: NVDA, EQUITY_CAPITAL_ENV: "100"}), root
    )
    assert again.exchange.totals()["USD"] == D("100")

    # A larger capital deposits only the increase it has not seen yet.
    raised = build(
        env_for(**{EQUITY_PRODUCTS_ENV: NVDA, EQUITY_CAPITAL_ENV: "150"}), root
    )
    assert raised.exchange.totals()["USD"] == D("150")

    # Nothing to seed: no capital at all, and no equity products at all.
    zero = build(
        env_for(**{EQUITY_PRODUCTS_ENV: NVDA, EQUITY_CAPITAL_ENV: "0"}),
        tmp_path / "zero",
    )
    assert "USD" not in zero.exchange.totals()

    no_equities = build(
        env_for(**{EQUITY_CAPITAL_ENV: "100"}), tmp_path / "no-equities"
    )
    assert "USD" not in no_equities.exchange.totals()


# ---------------------------------------------------------------- the chain


def test_dry_equity_buy_not_unallocated_negative(tmp_path):
    """An AI equity BUY of the seeded capital is not refused UNALLOCATED_NEGATIVE."""
    engine = build(
        env_for(**{EQUITY_PRODUCTS_ENV: NVDA, EQUITY_CAPITAL_ENV: "100"}),
        tmp_path / "buy",
    )
    assert engine.exchange.totals()["USD"] == D("100")

    # One equity print, equal on both sides, and a trusted clock.
    now = time.time()
    engine.runner.snapshots.put(
        MarketSnapshot(NVDA, D("100"), D("100"), D("100"), D("100"), now)
    )
    engine.runner.snapshots.set_clock(now, now)
    # The two facts these tests keep out of the chain: the session, and the AI's
    # approval, which a fake rail has already given.
    engine.gateway.session_open = lambda ts: True
    engine.gateway.approval_check = (
        lambda approval_id, intent, *, product, book: None
    )

    intent = OrderIntent(
        action="place",
        side="BUY",
        size=D("0.5"),
        limit_price=D("100"),
        level=0,
        cancel_cid=None,
        reason="test",
        approval_id="apr-1",
    )
    refusal = engine.gateway.check("ai", "ai", intent, NVDA)

    # 50 USD of notional against the seeded pool: the money step has nothing to
    # refuse it for.
    assert refusal != UNALLOCATED_NEGATIVE
    assert refusal is None


# ---------------------------------------------------------------- the markets


def test_cached_market_for_uses_equity_last(monkeypatch):
    """An equity product's market gets the equity quote source, a crypto one none."""
    built = []

    class RecordingMarket:
        """A `MarketData` stand-in: records what it was built with."""

        def __init__(self, product, equity_last=None):
            self.product = product
            self.equity_last = equity_last
            built.append(self)

    monkeypatch.setattr(main_module, "MarketData", RecordingMarket)

    def equity_last(symbol):
        return D("100"), 0

    market_for_one = main_module._cached_market_for(
        lambda product: product == NVDA, equity_last
    )
    equity = market_for_one(NVDA)
    crypto = market_for_one(BTC)

    assert equity.equity_last is equity_last
    assert crypto.equity_last is None
    assert [(market.product, market.equity_last) for market in built] == [
        (NVDA, equity_last),
        (BTC, None),
    ]

    # One client per product, however often a product is asked for.
    assert market_for_one(NVDA) is equity
    assert market_for_one(BTC) is crypto
    assert len(built) == 2

    # With no equity source at all, every market is built without one.
    silent = main_module._cached_market_for(lambda product: product == NVDA, None)
    assert silent(NVDA).equity_last is None
    assert silent(BTC).equity_last is None


# ---------------------------------------------------------------- startup


class RecordingServe:
    """A `serve` that records the call it must not get."""

    def __init__(self) -> None:
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return None


def test_startup_refuses_equity_live_without_crypto_live(tmp_path):
    """Equity live without the crypto ceiling refuses the start; nothing else does."""
    blocked = env_for(**{EQUITY_LIVE_ENV: "true", LIVE_ENV: "false"})
    engine = build(blocked, tmp_path / "ceiling")
    problems = engine.runner.startup_checks()
    assert any(
        EQUITY_LIVE_ENV in problem and LIVE_ENV in problem for problem in problems
    ), problems

    serve = RecordingServe()
    code = main_module.main(
        blocked,
        build=lambda env: build(env, tmp_path / "ceiling-main"),
        serve=serve,
    )
    assert code == main_module.EXIT_REFUSED
    assert serve.calls == []

    # With the ceiling on, equity live is not a problem at all: equities turn
    # themselves off on their own, so a start with no preview confirmation on
    # record has nothing to report and is a start that happens.
    startup = env_for(**{EQUITY_LIVE_ENV: "true", LIVE_ENV: "true"})
    engine = build(startup, tmp_path / "preview")
    assert engine.store.get(PREVIEW_KEY) is None
    assert engine.runner.startup_checks() == []


# ---------------------------------------------------------------- product kinds


def test_startup_reports_no_product_kind_problems(tmp_path):
    """A wrong or unreadable kind is no startup problem: equities turn off instead.

    The kind a listing reports, and a lookup that cannot answer at all, are the
    cycle's own business (the equity status written for it): the engine starts and
    leaves stock trading off.  What a start does not do either is read a kind it
    has no equity list for.
    """

    class Kind:
        """Whatever a live exchange would report as a product's kind."""

        def __init__(self, product_type):
            self.product_type = product_type

    class SpecUnreadable(RuntimeError):
        """A kind lookup that fails: a start must not turn that into a problem."""

    canary = "spec-source-said-" + secrets.token_hex(8)
    env = env_for(**{PRODUCTS_ENV: CRYPTO, EQUITY_PRODUCTS_ENV: NVDA})

    def checks(name, spec_for):
        engine = build(env, tmp_path / name, spec_for=spec_for)
        return engine.runner.startup_checks()

    # An EQUITY listing on the crypto list, and a SPOT listing on the equity one.
    assert checks("kind-crypto", lambda product: Kind("EQUITY")) == []
    assert checks("kind-equity", lambda product: Kind("SPOT")) == []

    # A lookup that raises says nothing about whether the engine may start.
    def unreadable(product):
        raise SpecUnreadable(canary)

    problems = checks("kind-error", unreadable)
    assert problems == []
    assert not any(canary in problem for problem in problems), problems

    # Each list naming products of its own kind has nothing to report either.
    def kinds(product):
        return Kind("EQUITY" if product in (NVDA, VOO) else "SPOT")

    assert checks("kind-ok", kinds) == []

    # A start reads no kind at all, whatever its lists say.
    class CountingSpec:
        """A kind table that counts how often anything reads it."""

        def __init__(self):
            self.calls = 0

        def __call__(self, product):
            self.calls += 1
            return Kind("SPOT")

    counted = CountingSpec()
    engine = build(env, tmp_path / "kind-none", spec_for=counted)
    counted.calls = 0
    assert engine.runner.startup_checks() == []
    assert counted.calls == 0


# ---------------------------------------------------------------- the watchdog


def test_watchdog_main_builds_router(tmp_path, monkeypatch):
    """The watchdog's own process builds the same dry exchange, over the same store."""
    instances = []

    class RecordingWatchdog:
        """A `Watchdog` stand-in: records how it was built, and passes once."""

        def __init__(
            self,
            data_dir,
            store,
            exchange_factory,
            policy,
            *,
            stale_after_s=None,
            now=None,
            env=None,
        ):
            self.data_dir = data_dir
            self.store = store
            self.exchange_factory = exchange_factory
            self.policy = policy
            self.stale_after_s = stale_after_s
            self.passes = 0
            instances.append(self)

        def check(self):
            self.passes += 1
            return "ok"

    monkeypatch.setattr(watchdog_module, "Watchdog", RecordingWatchdog)

    data_dir = tmp_path / "watchdog"
    data_dir.mkdir(parents=True, exist_ok=True)
    env = env_for(
        **{
            DATA_DIR_ENV: str(data_dir),
            LIVE_ENV: "false",
            EQUITY_PRODUCTS_ENV: NVDA,
        }
    )

    code = watchdog_module.main(env, max_checks=1, sleep=lambda seconds: None)

    assert code == 0
    assert len(instances) == 1
    recorder = instances[0]
    assert recorder.passes == 1

    # The captured factory builds the dry exchange over the watchdog's own store.
    exchange = recorder.exchange_factory()
    assert isinstance(exchange, DryRunExchange)
    assert exchange.is_equity(NVDA)
    assert exchange.is_crypto(BTC)
    assert not exchange.is_crypto(VOO)
    assert not exchange.owns_equity(VOO)

    # The row query reads the store file the factory was built over: an EQUITY
    # row written afterwards still makes the delisted symbol an equity.
    insert_row(recorder.store, VOO, product_type="EQUITY")
    assert exchange.owns_equity(VOO)