"""test_equity_status.py: equities that cannot be confirmed turn OFF, never stop the engine.

Coinbase's PUBLIC product endpoint answers 404 for a stock; only the
AUTHENTICATED product read returns it as an EQUITY.  So the engine may not need a
public equity read to start, and a listed stock may never stop the engine: the
equity half turns itself off (one alert, one fixed sentence), crypto runs exactly
as before, and equities turn themselves on after a key push whose authenticated
reads give EQUITY specs.

Every test builds the REAL engine through `build_app` — a real `Store` on a
temporary data directory, the real simulator, gateway, ledger and runner — and
fakes only what sits outside it:

* `Markets`/`FakeMarket` are the public market.  A crypto product answers a fixed
  touch and a SPOT listing; `NVDA-USD` answers no public listing at all (a
  `ProductUnavailable`, which is what a 404 becomes) and its quote is a test
  switch, so "the equities were never polled" and "the quote failed" are things a
  test can count.
* `FakeLive`/`NoSpecRead` are the `live_builder` fakes: an adapter that answers
  the two AUTHENTICATED product reads (`product_spec`, `product_type`), or not,
  or raises.  `RefusingLiveBuilder` is the builder no test that pushes no key may
  reach.
* `spec_for` is injected ONLY where a test is about the trusted (injected) path;
  everywhere else it is left out, so the engine's own default is what gets
  measured.

The products are synthetic: `NVDA-USD` on the equity list, `BTC-USD` on the
crypto one, and every amount is a round number.

What each test pins down:

* a public 404 on the equities does not stop the engine: the startup checks pass,
  `main` serves, crypto polls, `/status` says the equities are unavailable and
  why, an AI equity preview is refused `EQUITY_UNAVAILABLE`, exactly ONE alert is
  written per episode, and the crypto preview is untouched: an unfunded coin
  preview is refused on a crypto reason or not at all, never as an equity,
* a key push whose authenticated reads give EQUITY specs turns the equities on
  (specs kept, alert marker cleared, the default `spec_for` answers), a `clear`
  turns them off, and a `check` never turns them on,
* each way an authenticated read can disagree or fail has a reason of its own, the
  push is still ACCEPTED, crypto is untouched, and a read's own message appears in
  no event, log line or status,
* equity live without a recorded confirmation never stops the engine either: it is
  off with a reason of its own, and a live equity preview is refused
  `LIVE_DISABLED` until the confirmation is on record,
* a failing equity quote warns ONCE per episode (event and log), and again only
  after the source answers and then fails again,
* an injected `spec_for` is trusted: nothing needs a key push to work,
* `EquityStatus` itself: `verify` keeps the specs on success, `reset` drops them,
  `refusal` answers the two codes, and `verify` never raises.
"""

from __future__ import annotations

import base64
import contextlib
import logging
import secrets
import time
import uuid
from decimal import Decimal as D
from pathlib import Path

from fastapi.testclient import TestClient

import crow_coinbase.__main__ as main_module
import crow_coinbase.equity_wiring as equity_wiring_module
import crow_coinbase.gateway as gateway_module
from crow_coinbase.auth import KEY_KIND_INSTALL_TOKEN
from crow_coinbase.exchange import (
    EQUITY_DISPLAYED_ORDER_CONFIG,
    EQUITY_PREVIEW_CONFIRMED_KEY,
    EQUITY_TRADING_SESSION,
    ProductUnavailable,
)
from crow_coinbase.gateway import LIVE_DISABLED
from crow_coinbase.limits import Limits
from crow_coinbase.money import ProductSpec
from crow_coinbase.store import STOPPED, Store
from crow_coinbase.strategies.base import MarketSnapshot

# ---------------------------------------------------------------- test data
# The equity product, the crypto product, and the token the engine starts with.
NVDA = "NVDA-USD"
BTC = "BTC-USD"

TOKEN = "test-token-" + secrets.token_hex(16)
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# The environment variables the wiring reads.
ENV_TOKEN = "CROW_COINBASE_ENGINE_TOKEN"
PRODUCTS_ENV = "CROW_COINBASE_PRODUCTS"
EQUITY_PRODUCTS_ENV = "CROW_COINBASE_EQUITY_PRODUCTS"
EQUITY_CAPITAL_ENV = "CROW_COINBASE_EQUITY_AI_CAPITAL_USD"
EQUITY_LIVE_ENV = "CROW_COINBASE_EQUITY_LIVE"
LIVE_ENV = "CROW_COINBASE_LIVE"

# The three reasons a status can carry, and the one a live route adds.
UNVERIFIED = "EQUITY_KINDS_UNVERIFIED"
MISMATCH = "EQUITY_KIND_MISMATCH"
READ_FAILED = "EQUITY_KIND_READ_FAILED"
LIVE_UNCONFIRMED = "EQUITY_LIVE_UNCONFIRMED"

# The fixed sentences the alert and the AI surface answer with, as the contract
# fixes them: no value and no exception text is ever in one.
STOCKS_UNVERIFIED = (
    "Stock trading is off until a connected key confirms the stock products."
)
STOCKS_LIVE_UNCONFIRMED = (
    "Live stock trading is off: it has not been confirmed yet."
)
STOCKS_UNAVAILABLE_MESSAGE = (
    "Stock trading is off right now; Crow could not confirm the stock products yet."
)

# The codes only a stock order earns: the refusals the stock half of the surface
# speaks on top of the equity status's own `EQUITY_UNAVAILABLE`.  A crypto preview
# that answers one of them means the equities' trouble reached the coin's route.
EQUITY_ONLY_CODES = (
    "EQUITY_PREVIEW_UNCONFIRMED",
    "PRODUCT_TYPE_UNKNOWN",
    "NO_EQUITY_ACCOUNT",
    "TRADING_HALTED",
    "LIQUIDATE_ONLY",
    "MARKET_CLOSED",
    "PRICE_BAND",
    "FRACTIONAL_NOT_ALLOWED",
    "CAPITAL_CAP",
)

# The kv keys the runner keeps its two episodes under.
OFF_ALERT_KEY = "equity_off_alert"
QUOTE_WARN_KEY = f"equity_quote_warn:{NVDA}"

ENV = {
    ENV_TOKEN: TOKEN,
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    PRODUCTS_ENV: BTC,
    EQUITY_PRODUCTS_ENV: NVDA,
    EQUITY_CAPITAL_ENV: "100",
}

# The confirmation an equity live route needs on record.
CONFIRMATION = {
    "displayed_order_config": EQUITY_DISPLAYED_ORDER_CONFIG,
    "equity_trading_session": EQUITY_TRADING_SESSION,
}

# A key pair and a portfolio, all built at runtime: no header, key or portfolio id
# is a literal in this file.
PEM_BEGIN = "-----BEGIN "
PEM_END = "-----END "
PEM_EC = "EC "
PEM_SUFFIX = "PRIVATE KEY-----"

PORTFOLIO = uuid.uuid4().hex


def env_for(**overrides: str) -> dict[str, str]:
    """The environment these tests build with, plus the values one test sets."""
    env = dict(ENV)
    env.update(overrides)
    return env


def key_name() -> str:
    """A key name in the shape Coinbase answers, built at runtime."""
    return f"organizations/{uuid.uuid4().hex}/apiKeys/{uuid.uuid4().hex}"


def private_key() -> str:
    """A synthetic PEM private key, its header and footer built from parts."""
    body = base64.b64encode(secrets.token_bytes(48)).decode("ascii")
    header = PEM_BEGIN + PEM_EC + PEM_SUFFIX
    footer = PEM_END + PEM_EC + PEM_SUFFIX
    return "\n".join([header, body, footer])


def approve_secret() -> str:
    """An approval secret long enough to be one, built at runtime."""
    return "approve-" + secrets.token_hex(20)


def permissions() -> dict:
    """One acceptable key's permissions: view and trade, never move money out."""
    return {
        "can_view": True,
        "can_trade": True,
        "can_transfer": False,
        "portfolio_uuid": PORTFOLIO,
        "portfolio_type": "CONSUMER",
    }


# ---------------------------------------------------------------- the new names


def equity_status_class():
    """`equity_wiring.EquityStatus`, or a clear failure while it is absent."""
    status = getattr(equity_wiring_module, "EquityStatus", None)
    assert status is not None, (
        "crow_coinbase.equity_wiring.EquityStatus is missing: the engine has no "
        "status to report about its equities"
    )
    return status


def equity_unavailable() -> str:
    """The code an equity order earns while the equities cannot be confirmed."""
    code = getattr(gateway_module, "EQUITY_UNAVAILABLE", None)
    assert isinstance(code, str) and code, "gateway.EQUITY_UNAVAILABLE is not defined"
    return code


def assert_crypto_preview_untouched(answer: dict, product: str) -> None:
    """A crypto preview the equities' own trouble never reached, unfunded as it is.

    The AI has no crypto money in these engines, so the coin's preview stands on a
    crypto reason or none at all.  What it may never carry is the equities' code or
    any other stock-side one, and it stays the coin's own product either way.
    """
    refusal = answer["refusal"]
    assert refusal != equity_unavailable(), answer
    assert refusal not in EQUITY_ONLY_CODES, answer
    assert answer["product"] == product, answer


# ---------------------------------------------------------------- specs


def equity_spec(product: str = NVDA) -> ProductSpec:
    """An equity listing: cents on the price, fractional shares, USD quoted."""
    return ProductSpec(
        product,
        price_increment=D("0.01"),
        base_increment=D("0.0001"),
        quote_increment=D("0.01"),
        base_min_size=D("0.0001"),
        quote_min_size=D("1"),
        product_type="EQUITY",
        fractionable=True,
        fractional_notional_min_size=D("1"),
    )


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
    """The listing of *product*: an equity for the equity list, else SPOT.

    This is the INJECTED `spec_for` of the trusted path: it answers without an
    authenticated read, which is exactly what `trusted=True` means.
    """
    return equity_spec(product) if product == NVDA else spot_spec(product)


# ---------------------------------------------------------------- the public market


class FakeMarket:
    """One product's public market: a crypto touch, and no equity listing at all.

    A crypto product answers a fixed top of book and a SPOT public listing.  An
    equity product answers NO public listing (`ProductUnavailable`, which is what
    the endpoint's 404 becomes) and its quote is `quote_error`, so a test can
    count the reads that never happened and fail the ones that did.

    The product id is `pid`, never `product`: an attribute of that name would
    shadow this class's own `product()` read.
    """

    def __init__(self, product: str, *, price=D("100")) -> None:
        self.pid = product
        self.bid, self.ask = D("0.99"), D("1.00")
        self.price = D(price)
        self.touches = 0
        self.listing_reads = 0
        self.quotes = 0
        self.quote_error = None

    def best_bid_ask(self):
        self.touches += 1
        return self.bid, self.ask

    def range_since(self, since):
        return self.bid, self.ask

    def candles(self, start, end):
        return []

    def product(self):
        """The public listing: a coin's, and a 404 for a stock."""
        self.listing_reads += 1
        if self.pid == NVDA:
            raise ProductUnavailable("not supported")
        return spot_spec(self.pid), {"product_id": self.pid}

    def equity_quote(self):
        """The equity's one print, or the failure a test asked for."""
        self.quotes += 1
        if self.quote_error is not None:
            raise self.quote_error
        return self.price, time.time()


class Markets:
    """One `FakeMarket` per product, asked by the engine as its `market_for`."""

    def __init__(self) -> None:
        self.by_product: dict[str, FakeMarket] = {}

    def __call__(self, product: str) -> FakeMarket:
        return self.by_product.setdefault(product, FakeMarket(product))

    def __getitem__(self, product: str) -> FakeMarket:
        return self(product)


# ---------------------------------------------------------------- the authenticated reads


class FakeLive:
    """One live account: the two authenticated product reads, and little else.

    `specs` is what `product_spec` answers per product, `kinds` what
    `product_type` answers, and the two `*_error` fields make a read raise
    instead — which is how a failing authenticated read is exercised.  Everything
    else this fake does not offer raises, so a call nothing asked for is loud.
    """

    dry_run = False

    def __init__(
        self,
        *,
        specs=None,
        kinds=None,
        spec_error: BaseException | None = None,
        kind_error: BaseException | None = None,
    ) -> None:
        self.specs = dict(specs or {})
        self.kinds = dict(kinds or {})
        self.spec_error = spec_error
        self.kind_error = kind_error

    def key_permissions(self) -> dict:
        return permissions()

    def product_spec(self, product: str) -> ProductSpec:
        if self.spec_error is not None:
            raise self.spec_error
        return self.specs[product]

    def product_type(self, product: str) -> str:
        if self.kind_error is not None:
            raise self.kind_error
        return self.kinds[product]

    # What a reconcile or an unallocated check over the live book asks for.  There
    # are no live orders in these tests, and the account holds plenty of dollars,
    # so nothing is ever listed and nothing reads as short.
    def list_open_orders(self, product=None):
        return []

    def totals(self) -> dict:
        return {"USD": D("1000")}

    def balances(self) -> dict:
        return {"USD": D("1000")}

    def __getattr__(self, name: str):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        raise AssertionError(f"unexpected exchange call: {name}")


def healthy_account() -> FakeLive:
    """An account whose authenticated reads agree with the two configured lists."""
    return FakeLive(
        specs={NVDA: equity_spec(NVDA), BTC: spot_spec(BTC)},
        kinds={NVDA: "EQUITY", BTC: "SPOT"},
    )


class NoSpecRead:
    """An adapter that answers no authenticated product SPEC read at all."""

    dry_run = False

    def __init__(self, kinds=None) -> None:
        self.kinds = dict(kinds or {})

    def key_permissions(self) -> dict:
        return permissions()

    def product_type(self, product: str) -> str:
        return self.kinds[product]

    def list_open_orders(self, product=None):
        return []

    def totals(self) -> dict:
        return {"USD": D("1000")}

    def balances(self) -> dict:
        return {"USD": D("1000")}


class LiveBuilder:
    """`live_builder(creds)` answering one fake adapter, counting its calls."""

    def __init__(self, adapter) -> None:
        self.adapter = adapter
        self.calls = 0
        self.creds: list[dict] = []

    def __call__(self, creds) -> object:
        self.calls += 1
        self.creds.append(dict(creds))
        return self.adapter


class RefusingLiveBuilder:
    """A `live_builder` no test that pushes no key may reach."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, creds):
        self.calls += 1
        raise AssertionError("no live adapter may be built by this test")


# ---------------------------------------------------------------- the harness

MISSING = object()


def build(
    env,
    data_dir,
    *,
    markets: Markets | None = None,
    spec_for=MISSING,
    live_builder=None,
):
    """The real engine over *data_dir*, with only the outside world injected.

    `spec_for` is passed ONLY where a test is about the trusted path: left out,
    the engine builds its own — the one that must never read a public equity
    product.
    """
    options = dict(
        data_dir=data_dir,
        market_for=Markets() if markets is None else markets,
        now=time.time,
        live_builder=(
            RefusingLiveBuilder() if live_builder is None else live_builder
        ),
    )
    if spec_for is not MISSING:
        options["spec_for"] = spec_for
    return main_module.build_app(env, **options)


def pin_session(engine, is_open: bool = True) -> None:
    """Pin the regular session for both halves of the engine."""

    def session(ts: float) -> bool:
        return is_open

    engine.gateway.session_open = session
    engine.runner.session_open = session


def prime(engine, *, equity_price=D("100")) -> None:
    """Fund the dry book and give each product a usable snapshot, stamped now."""
    engine.exchange.deposit("USD", D("1000"), "test float")
    at = time.time()
    engine.runner.snapshots.put(
        MarketSnapshot(BTC, D("0.99"), D("1.00"), D("0.99"), D("1.00"), at)
    )
    engine.runner.snapshots.put(
        MarketSnapshot(
            NVDA, equity_price, equity_price, equity_price, equity_price, at
        )
    )
    engine.runner.snapshots.set_clock(at, at)


class RecordingServe:
    """A `serve` that records the call it is given."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return None


def run_main(monkeypatch, env, build_engine):
    """`main` with the cycle loop's own entry point recorded instead of run.

    The thread `main` starts would otherwise run cycles (and end the process) on
    the wall clock; recording the entry point is what makes "it served" an
    assertion about `main` alone.
    """
    serve = RecordingServe()
    started: list = []
    monkeypatch.setattr(main_module, "_run_runner", started.append)
    code = main_module.main(env, build=build_engine, serve=serve)
    return code, serve, started


def loop_started(started: list, timeout: float = 2.0) -> bool:
    """Whether the cycle loop was started, waiting briefly for its thread."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if started:
            return True
        time.sleep(0.01)
    return bool(started)


@contextlib.contextmanager
def status_client(engine):
    """A `TestClient` whose every request carries the bearer token."""
    with TestClient(engine.app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        yield client


def equity_block(engine) -> dict:
    """The `/status` equity block, as the surface reports it."""
    with status_client(engine) as client:
        answer = client.get("/status")
        assert answer.status_code == 200, answer.text
        body = answer.json()
    assert "equity" in body, body
    return body["equity"]


# ---------------------------------------------------------------- the events


def alert_events(store: Store) -> list[dict]:
    """Every warn `alert` event, oldest first: the equity half's own news."""
    rows = store.conn().execute(
        "SELECT level, kind, message FROM events "
        "WHERE kind='alert' AND level='warn' ORDER BY id"
    ).fetchall()
    return [dict(row) for row in rows]


def quote_warnings(store: Store, product: str = NVDA) -> list[str]:
    """Every `poll <product> failed` event, oldest first."""
    rows = store.conn().execute(
        "SELECT message FROM events WHERE message LIKE ? ORDER BY id",
        (f"poll {product} failed%",),
    ).fetchall()
    return [str(row["message"]) for row in rows]


def quote_logs(caplog, product: str = NVDA) -> list[str]:
    """Every runner log line about a failing quote for *product*."""
    prefix = f"poll {product}: quote unavailable"
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == "crow_coinbase.runner"
        and record.getMessage().startswith(prefix)
    ]


def every_event_text(store: Store) -> str:
    """Every event's message and stored data, as one blob a scan can read."""
    rows = store.conn().execute(
        "SELECT message, data_json FROM events ORDER BY id"
    ).fetchall()
    return "\n".join(f"{row['message']}\n{row['data_json']}" for row in rows)


# ---------------------------------------------------------------- the push


def push_key(engine):
    """Push one key pair through the slot, and answer the slot's own answer."""
    return engine.slot.set(
        key_name(),
        private_key(),
        approve_secret(),
        key_kind=KEY_KIND_INSTALL_TOKEN,
    )


# ================================================================ 1. the public 404


def test_public_404_on_equities_does_not_stop_the_engine(tmp_path, monkeypatch):
    """A stock the public endpoint does not answer turns the equities off, not the engine."""
    markets = Markets()
    holder: dict = {}

    def build_engine(env):
        engine = build(env, tmp_path / "engine", markets=markets)
        holder["engine"] = engine
        return engine

    code, serve, started = run_main(monkeypatch, env_for(), build_engine)
    assert code == 0
    assert len(serve.calls) == 1, serve.calls
    assert loop_started(started), "the cycle loop was never started"

    engine = holder["engine"]
    # Nothing about a public equity read can refuse the start, and nothing on the
    # interactive paths asks for one: the default `spec_for` consults the
    # authenticated specs alone.
    assert engine.runner.startup_checks() == []

    pin_session(engine)
    prime(engine)
    # The runner polls the products a bot row names, and only those, so a crypto
    # bot is what makes the crypto product polled.  It is stopped and has no
    # capital, so it lays no book, gets no strategy call and is not reported as
    # an idle book: the poll is all it does here.
    engine.store.create_bot(
        "poller",
        BTC,
        "grid",
        {"center": "1.0", "step_pct": "1.5", "levels_below": 3, "levels_above": 3},
        D("0"),
        D("0"),
    )
    engine.store.set_bot_status("poller", STOPPED)
    engine.runner.cycle()

    # Crypto polls exactly as it always did.
    assert engine.runner.snapshots.get(BTC) is not None
    assert markets[BTC].touches >= 1, markets[BTC].touches
    # And no public equity listing was ever read.
    assert markets[NVDA].listing_reads == 0, markets[NVDA].listing_reads
    assert markets[NVDA].quotes == 0, markets[NVDA].quotes

    block = equity_block(engine)
    assert block["enabled"] is True, block
    assert block["available"] is False, block
    assert block["reason"] == UNVERIFIED, block
    assert block["live_reason"] is None, block
    assert block["live"] is False, block

    # An AI stock order is refused with its own code, on the book it routes to.
    equity_preview = engine.ai_orders.preview(NVDA, "BUY", D("0.5"), D("100"))
    assert equity_preview["refusal"] == equity_unavailable(), equity_preview
    assert equity_preview["state"] == "rejected", equity_preview
    assert equity_preview["book"] == "dry", equity_preview
    assert equity_preview["message"] == STOCKS_UNAVAILABLE_MESSAGE, equity_preview
    # Not even refusing it read the public listing: there is nothing to read.
    assert markets[NVDA].listing_reads == 0, markets[NVDA].listing_reads

    # ONE alert per episode: a second cycle over the same reason says nothing.
    alerts = alert_events(engine.store)
    assert [row["message"] for row in alerts] == [STOCKS_UNVERIFIED], alerts
    assert engine.store.get(OFF_ALERT_KEY) is not None
    engine.runner.cycle()
    assert [row["message"] for row in alert_events(engine.store)] == [
        STOCKS_UNVERIFIED
    ], alert_events(engine.store)
    assert markets[NVDA].listing_reads == 0, markets[NVDA].listing_reads

    # The crypto preview is unaffected: the equities being off is not its news, so
    # it is never refused as an equity, and it is still the coin's own product.
    crypto_preview = engine.ai_orders.preview(BTC, "BUY", D("2"), D("1"))
    assert_crypto_preview_untouched(crypto_preview, BTC)


# ================================================================ 2. turning them on


def test_equities_turn_on_after_a_key_push_with_equity_specs(tmp_path):
    """A key whose authenticated reads give EQUITY specs is what turns equities on."""
    markets = Markets()
    builder = LiveBuilder(healthy_account())
    engine = build(
        env_for(), tmp_path / "turn-on", markets=markets, live_builder=builder
    )
    pin_session(engine)

    # Before any key: the equities are off, and the episode has rung once.
    engine.runner.cycle()
    assert engine.store.get(OFF_ALERT_KEY) is not None
    assert [row["message"] for row in alert_events(engine.store)] == [
        STOCKS_UNVERIFIED
    ], alert_events(engine.store)

    result = push_key(engine)
    assert result.state == "ok", result
    assert result.code is None, result
    assert builder.calls == 1, builder.creds

    block = equity_block(engine)
    assert block["reason"] is None, block
    assert block["available"] is True, block
    assert block["enabled"] is True, block
    assert block["live_reason"] is None, block

    # The default `spec_for` now answers the authenticated spec for the stock.
    assert engine.gateway.spec_for(NVDA).product_type == "EQUITY"

    # The alarm ends on the next cycle: the marker clears and no new alert is
    # written, because there is nothing left to say.
    engine.runner.cycle()
    assert engine.store.get(OFF_ALERT_KEY) is None
    assert [row["message"] for row in alert_events(engine.store)] == [
        STOCKS_UNVERIFIED
    ], alert_events(engine.store)

    # A stock preview is no longer refused for being unavailable: the session is
    # pinned open and the print is there, so it waits for an answer.
    prime(engine)
    equity_preview = engine.ai_orders.preview(NVDA, "BUY", D("0.5"), D("100"))
    assert equity_preview["refusal"] is None, equity_preview
    assert equity_preview["state"] == "pending", equity_preview

    # Clearing the key forgets the specs: the equities are unverified again.
    engine.slot.clear()
    assert engine.slot.live_exchange() is None
    block = equity_block(engine)
    assert block["available"] is False, block
    assert block["reason"] == UNVERIFIED, block

    # A check reads the key and keeps nothing: it never turns the equities on.
    checked = engine.slot.check(key_name(), private_key())
    assert checked.state == "ok", checked
    assert builder.calls == 2, builder.creds
    assert engine.slot.live_exchange() is None
    block = equity_block(engine)
    assert block["reason"] == UNVERIFIED, block
    assert block["available"] is False, block


# ================================================================ 3. the reasons


def test_status_reasons(tmp_path, caplog):
    """Each disagreement gets its own reason, the push stands, crypto is untouched."""
    caplog.set_level(logging.DEBUG)
    canary = "authenticated-read-said-" + secrets.token_hex(8)

    def case(name, adapter):
        """One engine, its key pushed, and the status the push left behind."""
        engine = build(
            env_for(),
            tmp_path / name,
            markets=Markets(),
            live_builder=LiveBuilder(adapter),
        )
        pin_session(engine)
        result = push_key(engine)
        # The key is ACCEPTED whatever the product reads said: a wrong or failed
        # read turns the equities off, it never refuses the owner's key.
        assert result.state == "ok", (name, result)
        assert result.code is None, (name, result)

        # Crypto is untouched by any of it: no equity code, no equity product.
        prime(engine)
        crypto_preview = engine.ai_orders.preview(BTC, "BUY", D("2"), D("1"))
        assert_crypto_preview_untouched(crypto_preview, BTC)

        # And no read's own words reach an event, a log line or an answer.
        with status_client(engine) as client:
            answer = client.get("/status")
            assert answer.status_code == 200, answer.text
            block = answer.json()["equity"]
        assert canary not in answer.text, (name, answer.text)
        assert canary not in every_event_text(engine.store), (
            name,
            every_event_text(engine.store),
        )
        assert canary not in caplog.text, (name, caplog.text)
        return block

    # The equity list names a product whose authenticated read says SPOT.
    block = case(
        "equity-kind",
        FakeLive(specs={NVDA: spot_spec(NVDA)}, kinds={BTC: "SPOT"}),
    )
    assert block["reason"] == MISMATCH, block
    assert block["available"] is False, block

    # The crypto list names a product whose authenticated read says EQUITY.
    block = case(
        "crypto-kind",
        FakeLive(
            specs={NVDA: equity_spec(NVDA)}, kinds={NVDA: "EQUITY", BTC: "EQUITY"}
        ),
    )
    assert block["reason"] == MISMATCH, block
    assert block["available"] is False, block

    # A read that raises is its own reason, and its message goes nowhere.
    block = case("read-failed", FakeLive(spec_error=RuntimeError(canary)))
    assert block["reason"] == READ_FAILED, block
    assert block["available"] is False, block

    # An adapter with no authenticated spec read at all is the same reason.
    block = case("no-spec-read", NoSpecRead(kinds={BTC: "SPOT"}))
    assert block["reason"] == READ_FAILED, block
    assert block["available"] is False, block


# ================================================================ 4. equity live


def test_equity_live_without_confirmation_never_stops_the_engine(
    tmp_path, monkeypatch
):
    """Equity live with no confirmed preview is OFF with a reason, not a refusal."""
    live_env = env_for(**{EQUITY_LIVE_ENV: "true", LIVE_ENV: "true"})
    markets = Markets()
    builder = LiveBuilder(healthy_account())
    engine = build(
        live_env, tmp_path / "live", markets=markets, live_builder=builder
    )

    # Nothing about the missing confirmation refuses the start.
    assert engine.runner.startup_checks() == []

    code, serve, started = run_main(
        monkeypatch,
        live_env,
        lambda env: build(env, tmp_path / "live-main", markets=Markets()),
    )
    assert code == 0
    assert len(serve.calls) == 1, serve.calls
    assert loop_started(started), "the cycle loop was never started"

    pin_session(engine)
    block = equity_block(engine)
    assert block["enabled"] is True, block
    assert block["live"] is False, block
    assert block["live_reason"] == LIVE_UNCONFIRMED, block

    # One alert per episode, and the second cycle says nothing new.
    engine.runner.cycle()
    assert [row["message"] for row in alert_events(engine.store)] == [
        STOCKS_UNVERIFIED
    ], alert_events(engine.store)
    engine.runner.cycle()
    assert len(alert_events(engine.store)) == 1, alert_events(engine.store)

    # Equity live while the crypto ceiling is off still refuses the start.
    blocked_env = env_for(**{EQUITY_LIVE_ENV: "true", LIVE_ENV: "false"})
    blocked = build(blocked_env, tmp_path / "blocked", markets=Markets())
    problems = blocked.runner.startup_checks()
    assert any(
        EQUITY_LIVE_ENV in problem and LIVE_ENV in problem for problem in problems
    ), problems
    code, serve, started = run_main(
        monkeypatch,
        blocked_env,
        lambda env: build(env, tmp_path / "blocked-main", markets=Markets()),
    )
    assert code == main_module.EXIT_REFUSED
    assert serve.calls == []
    assert started == []

    # A key whose authenticated reads give EQUITY specs makes the stock products
    # available; the live route is still off, for the confirmation's own reason.
    engine.gateway.switches.set("ai_live_enabled", True)
    result = push_key(engine)
    assert result.state == "ok", result

    # The reason changed with the specs, so the episode's sentence changes with
    # it: one MORE alert, and nothing after that.
    engine.runner.cycle()
    assert [row["message"] for row in alert_events(engine.store)] == [
        STOCKS_UNVERIFIED,
        STOCKS_LIVE_UNCONFIRMED,
    ], alert_events(engine.store)
    engine.runner.cycle()
    assert len(alert_events(engine.store)) == 2, alert_events(engine.store)

    block = equity_block(engine)
    assert block["reason"] is None, block
    assert block["available"] is True, block
    assert block["live_reason"] == LIVE_UNCONFIRMED, block
    assert block["live"] is False, block

    # A live stock preview is refused LIVE_DISABLED, and nothing is sent.
    live_preview = engine.ai_orders.preview(NVDA, "BUY", D("0.5"), D("100"))
    assert live_preview["book"] == "live", live_preview
    assert live_preview["refusal"] == LIVE_DISABLED, live_preview
    assert live_preview["state"] == "rejected", live_preview

    # With the confirmation on record the live route has nothing to complain of.
    engine.store.put(EQUITY_PREVIEW_CONFIRMED_KEY, dict(CONFIRMATION))
    block = equity_block(engine)
    assert block["live_reason"] is None, block
    assert block["live"] is True, block
    assert block["reason"] is None, block


# ================================================================ 5. one warning


def test_one_quote_warning_per_episode(tmp_path, caplog):
    """A failing equity quote warns once per episode, event and log alike."""
    caplog.set_level(logging.WARNING)
    markets = Markets()
    # An injected `spec_for` is trusted, so the equities are available and polled
    # from the first cycle: this test is about the quote, not about the kinds.
    engine = build(
        env_for(), tmp_path / "quote", markets=markets, spec_for=spec
    )
    pin_session(engine)
    assert engine.runner.startup_checks() == []

    markets[NVDA].quote_error = RuntimeError("quote unavailable")
    for _ in range(3):
        engine.runner.cycle()

    assert quote_warnings(engine.store) == [
        f"poll {NVDA} failed: quote unavailable (RuntimeError)"
    ], quote_warnings(engine.store)
    assert quote_logs(caplog) == [
        f"poll {NVDA}: quote unavailable (RuntimeError)"
    ], quote_logs(caplog)
    assert engine.store.get(QUOTE_WARN_KEY) is not None

    # The source answers again: the episode ends, and nothing new is written.
    markets[NVDA].quote_error = None
    engine.runner.cycle()
    assert engine.store.get(QUOTE_WARN_KEY) is None
    assert len(quote_warnings(engine.store)) == 1, quote_warnings(engine.store)
    assert len(quote_logs(caplog)) == 1, quote_logs(caplog)

    # It fails again: that is a SECOND episode, and it is news again.
    markets[NVDA].quote_error = RuntimeError("quote unavailable")
    engine.runner.cycle()
    assert len(quote_warnings(engine.store)) == 2, quote_warnings(engine.store)
    assert len(quote_logs(caplog)) == 2, quote_logs(caplog)


# ================================================================ 6. the trusted path


def test_injected_spec_for_is_trusted(tmp_path):
    """A caller that injects its own specs needs no key push at all."""
    markets = Markets()
    engine = build(
        env_for(), tmp_path / "trusted", markets=markets, spec_for=spec
    )
    pin_session(engine)
    assert engine.runner.startup_checks() == []

    block = equity_block(engine)
    assert block["enabled"] is True, block
    assert block["available"] is True, block
    assert block["reason"] is None, block
    assert block["live_reason"] is None, block

    # A cycle has nothing to alert about, and it polls the equities normally.
    engine.runner.cycle()
    assert alert_events(engine.store) == [], alert_events(engine.store)
    assert markets[NVDA].quotes >= 1, markets[NVDA].quotes

    prime(engine)
    equity_preview = engine.ai_orders.preview(NVDA, "BUY", D("0.5"), D("100"))
    assert equity_preview["refusal"] is None, equity_preview
    assert equity_preview["state"] == "pending", equity_preview


# ================================================================ 7. the status itself


def test_equity_status_unit(tmp_path):
    """`EquityStatus`: what `verify` keeps, what `reset` drops, what `refusal` says."""
    Status = equity_status_class()
    data = Path(tmp_path) / "unit"
    data.mkdir(parents=True, exist_ok=True)
    store = Store(data / "engine.db")
    # Equity live on, so the live reason has something to report.
    limits = Limits.from_env(env_for(**{EQUITY_LIVE_ENV: "true"}))

    status = Status(store, limits)
    # Nothing has been read yet: unverified, no spec, and both books refuse.
    assert status.reason() == UNVERIFIED
    assert status.spec_for(NVDA) is None
    assert status.refusal("dry") == equity_unavailable()
    assert status.refusal("live") == equity_unavailable()
    assert status.live_reason() == LIVE_UNCONFIRMED

    # A healthy account verifies, and the specs it read are kept.
    crypto, equity = healthy_account(), healthy_account()
    status.verify(crypto, equity)
    assert status.reason() is None
    kept = status.spec_for(NVDA)
    assert kept is not None, "verify kept no spec for the stock it read"
    assert kept.product_type == "EQUITY"
    assert status.spec_for(BTC) is None, "a crypto product is no equity spec"
    assert status.refusal("dry") is None
    # The live book is still off: equity live with no confirmation on record.
    assert status.live_reason() == LIVE_UNCONFIRMED
    assert status.refusal("live") == LIVE_DISABLED
    store.put(EQUITY_PREVIEW_CONFIRMED_KEY, dict(CONFIRMATION))
    assert status.live_reason() is None
    assert status.refusal("live") is None

    # A disagreement is a reason of its own, and the specs are dropped.
    status.verify(
        FakeLive(specs={NVDA: spot_spec(NVDA)}, kinds={BTC: "SPOT"}),
        FakeLive(specs={NVDA: spot_spec(NVDA)}, kinds={NVDA: "SPOT", BTC: "SPOT"}),
    )
    assert status.reason() == MISMATCH
    assert status.spec_for(NVDA) is None
    assert status.refusal("dry") == equity_unavailable()

    # A failing read never raises, never repeats its own text, and keeps nothing.
    canary = "verify-read-said-" + secrets.token_hex(8)
    unreadable = FakeLive(
        specs={NVDA: equity_spec(NVDA)},
        kinds={BTC: "SPOT"},
        spec_error=RuntimeError(canary),
    )
    status.verify(
        FakeLive(specs={NVDA: equity_spec(NVDA)}, kinds={BTC: "SPOT"}), unreadable
    )
    assert status.reason() == READ_FAILED
    assert status.spec_for(NVDA) is None
    assert canary not in str(status.reason())
    assert canary not in every_event_text(store)

    # An adapter with no authenticated spec read is the same reason.
    status.verify(NoSpecRead(kinds={BTC: "SPOT"}), NoSpecRead(kinds={BTC: "SPOT"}))
    assert status.reason() == READ_FAILED
    assert status.spec_for(NVDA) is None

    # `reset` forgets everything it kept.
    status.verify(healthy_account(), healthy_account())
    assert status.reason() is None
    status.reset()
    assert status.reason() == UNVERIFIED
    assert status.spec_for(NVDA) is None

    # A trusted status is the caller's own: nothing it reads or resets moves it.
    trusted = Status(store, limits, trusted=True)
    assert trusted.reason() is None
    trusted.verify(
        FakeLive(specs={NVDA: equity_spec(NVDA)}, kinds={BTC: "SPOT"}), unreadable
    )
    assert trusted.reason() is None
    trusted.reset()
    assert trusted.reason() is None