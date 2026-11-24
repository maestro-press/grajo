"""books.py and the dry/live split: routing, caps, keys, reconcile and the switch.

Every test runs against real engine objects: a real `Store` (plus a second one
for the live account's simulated balances), the real `DryRunExchange`, the real
`ExchangeRouter` over it, the real `OrderGateway`, `CapWindow`, `Ledger`,
`Runner` and the FastAPI app.  Only the outside world is faked: `FakeMarket`
answers the book and the poll range.

The live book is a SECOND `DryRunExchange` over a SECOND store file, wrapped in
an `ExchangeRouter`, and funded with `deposit`, so its `crypto_totals()` is the
"real account" the live book allocates from.  A `Recorder` wraps an exchange and
records the name of every attribute call made on it, so a test can assert one
exchange saw no call at all.

Nothing here opens a socket, waits on the wall clock beyond `time.time()` stamps,
or touches the real `~/.crow` data.
"""

from __future__ import annotations

import csv
import io
import os
import sqlite3
import subprocess
import sys
import time
from decimal import Decimal as D
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import crow_coinbase.store as store_module
from crow_coinbase.api import create_app
from crow_coinbase.benchmark import Benchmark
from crow_coinbase.books import (
    BOOKS,
    DRY,
    LIVE,
    LIVE_DISABLED,
    LIVE_LOCKED,
    BookRouter,
    LiveLocked,
    ModeRefused,
    Switches,
    ceiling_from_env,
    no_live_exchange,
    route_decision,
)
from crow_coinbase.exchange import DryRunExchange
from crow_coinbase.gateway import (
    DAILY_CAP,
    HALTED,
    PORTFOLIO_OWNER,
    UNALLOCATED_NEGATIVE,
    OrderGateway,
)
from crow_coinbase.ledger import Ledger
from crow_coinbase.limits import CapWindow, Limits
from crow_coinbase.money import ProductSpec
from crow_coinbase.reconcile import reconcile
from crow_coinbase.router import ExchangeRouter
from crow_coinbase.runner import Runner
from crow_coinbase.snapshot import SnapshotCache
from crow_coinbase.store import (
    ACTIVE,
    CANCELLED,
    FILLED,
    LIVE_STATUSES,
    OPEN,
    PAUSED,
    PENDING_SUBMIT,
    SCHEMA_VERSION,
    STOPPED,
    Store,
)
from crow_coinbase.strategies.base import MarketSnapshot, OrderIntent
from crow_coinbase.strategies.grid import GridStrategy
from crow_coinbase.strategies.rebalance import RebalanceStrategy

BOT = "b1"
PRODUCT = "XRP-USDC"
BASE = "XRP"
QUOTE = "USDC"

TOKEN = "test-token-" + "x" * 32
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

SPEC = ProductSpec(
    PRODUCT,
    price_increment=D("0.0001"),
    base_increment=D("0.1"),
    quote_increment=D("0.01"),
    base_min_size=D("1"),
    quote_min_size=D("1"),
)

FEE_RATE = D("0.005")

BASE_ENV = {
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": "XRP-USDC",
}

GRID_PARAMS = {
    "center": "1.0",
    "step_pct": "1.5",
    "levels_below": 3,
    "levels_above": 3,
    "quote_per_buy": "10",
    "rebuy_sizing": "proceeds",
}

MID = (D("0.99") + D("1.00")) / 2


# ---------------------------------------------------------------- the outside world


class FakeMarket:
    """A fixed book and a fixed poll window."""

    def __init__(self, bid=D("0.99"), ask=D("1.00")):
        self.bid, self.ask = D(bid), D(ask)
        self.low, self.high = self.bid, self.ask

    def best_bid_ask(self):
        return self.bid, self.ask

    def range_since(self, since):
        return self.low, self.high

    def candles(self, start, end):
        return []


class Recorder:
    """Wrap an exchange and record the name of every attribute call it receives."""

    def __init__(self, inner):
        object.__setattr__(self, "inner", inner)
        object.__setattr__(self, "calls", [])

    def __getattr__(self, name):
        target = getattr(self.inner, name)
        if not callable(target):
            return target

        def record(*args, **kwargs):
            self.calls.append(name)
            return target(*args, **kwargs)

        return record


def place_intent(side="BUY", size=D("10"), price=D("0.95"), level=-1):
    return OrderIntent(
        action="place",
        side=side,
        size=D(size),
        limit_price=D(price),
        level=level,
        cancel_cid=None,
        reason="test",
    )


# ---------------------------------------------------------------- the engine


class Engine:
    """One engine: a dry store/exchange, a second live account and a live router."""

    def __init__(
        self,
        root,
        *,
        env=None,
        live=True,
        capital_quote=D("100"),
        capital_base=D("50"),
        wrap=False,
        snapshot=True,
        float_funds=False,
    ):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.env = dict(BASE_ENV)
        if env:
            self.env.update(env)
        self.now = time.time

        self.store = Store(self.root / "engine.db")
        self.store.create_bot(
            BOT, PRODUCT, "grid", dict(GRID_PARAMS), D(capital_quote), D(capital_base)
        )
        self.market = FakeMarket()
        self.limits = Limits.from_env(self.env)
        self.snapshots = SnapshotCache(
            poll_seconds=self.limits.poll_seconds, now=self.now
        )
        self.strategies = {"grid": GridStrategy(), "rebalance": RebalanceStrategy()}

        self._dry_raw = DryRunExchange(
            self.store.conn, lambda product: self.market, FEE_RATE
        )
        self._live_store = Store(self.root / "live.db")
        self._live_sim = DryRunExchange(
            self._live_store.conn, lambda product: self.market, FEE_RATE
        )
        self._live_sim.deposit(QUOTE, D("1000"), "funding")
        self._live_sim.deposit(BASE, D("1000"), "funding")
        self._live_router_raw = (
            ExchangeRouter(self._live_sim, usd_one_pool=True) if live else None
        )

        self.dry_rec = None
        self.live_rec = None
        if wrap:
            self.dry_rec = Recorder(self._dry_raw)
            self.dry = self.dry_rec
            if self._live_router_raw is not None:
                self.live_rec = Recorder(self._live_router_raw)
            self.live_router = self.live_rec
        else:
            self.dry = self._dry_raw
            self.live_router = self._live_router_raw

        self.switches = Switches(self.store, self.env)
        self.books = BookRouter(self.dry, self.live_factory)
        self.ledger = Ledger(self.store, fee_rate=FEE_RATE)
        self.gateway = OrderGateway(
            store=self.store,
            ledger=self.ledger,
            limits=self.limits,
            caps=CapWindow(self.store, self.now),
            snapshots=self.snapshots,
            spec_for=lambda product: SPEC,
            fee_rate=FEE_RATE,
            totals=self.dry.totals,
            exchange=self.dry,
            books=self.books,
            switches=self.switches,
            now=self.now,
            sleep=lambda seconds: None,
        )
        if D(capital_quote) > 0 or D(capital_base) > 0:
            self.gateway.seed_dry(BOT, D(capital_quote), D(capital_base))

        self.runner = Runner(
            store=self.store,
            gateway=self.gateway,
            exchange=self.dry,
            snapshots=self.snapshots,
            strategies=self.strategies,
            env=self.env,
            market_for=lambda product: self.market,
            spec_for=lambda product: SPEC,
            now=self.now,
            heartbeat_path=self.root / "hb.json",
            sleep=lambda seconds: None,
        )

        if float_funds:
            self.dry.deposit(QUOTE, D("100000"), "test float")
            self.dry.deposit(BASE, D("100000"), "test float")
            self._live_sim.deposit(QUOTE, D("100000"), "test float")
            self._live_sim.deposit(BASE, D("100000"), "test float")

        if snapshot:
            self.prime()

    def live_factory(self):
        return self.live_router

    def close(self):
        self.store.close()
        self._live_store.close()

    def prime(self):
        now = self.now()
        self.snapshots.put(
            MarketSnapshot(
                PRODUCT,
                self.market.bid,
                self.market.ask,
                self.market.low,
                self.market.high,
                now,
            )
        )
        self.snapshots.set_clock(now, now)

    def price_for(self, product):
        return MID

    def add_bot(
        self,
        bot_id,
        *,
        capital_quote=D("0"),
        capital_base=D("0"),
        params=None,
        strategy="grid",
    ):
        self.store.create_bot(
            bot_id,
            PRODUCT,
            strategy,
            dict(GRID_PARAMS if params is None else params),
            D(capital_quote),
            D(capital_base),
        )
        if D(capital_quote) > 0 or D(capital_base) > 0:
            self.gateway.seed_dry(bot_id, D(capital_quote), D(capital_base))
        return self.store.get_bot(bot_id)

    def set_live(self, bot_id, live_quote, live_base):
        bot = self.store.get_bot(bot_id)
        self.store.set_bot_book(
            bot_id,
            mode="live",
            capital_quote=bot["capital_quote"],
            capital_base=bot["capital_base"],
            live_capital_quote=D(live_quote),
            live_capital_base=D(live_base),
        )
        return self.store.get_bot(bot_id)


@pytest.fixture
def engines(tmp_path):
    made = []
    count = {"n": 0}

    def build(**kwargs):
        index = count["n"]
        count["n"] += 1
        engine = Engine(tmp_path / f"engine{index}", **kwargs)
        made.append(engine)
        return engine

    yield build
    for engine in made:
        engine.close()


def gateway_for(engine, *, env=None, switches=None, books=None):
    """A gateway over the same store and dry exchange, with pieces swapped in."""
    return OrderGateway(
        store=engine.store,
        ledger=Ledger(engine.store, fee_rate=FEE_RATE),
        limits=Limits.from_env(engine.env if env is None else env),
        caps=CapWindow(engine.store, time.time),
        snapshots=engine.snapshots,
        spec_for=lambda product: SPEC,
        fee_rate=FEE_RATE,
        totals=engine.dry.totals,
        exchange=engine.dry,
        books=engine.books if books is None else books,
        switches=engine.switches if switches is None else switches,
        now=time.time,
        sleep=lambda seconds: None,
    )


_DEFAULT = object()


def make_app(engine, *, require_privileged=_DEFAULT):
    """The engine's app; the privileged gate is the real default unless injected."""
    extra = (
        {}
        if require_privileged is _DEFAULT
        else {"require_privileged": require_privileged}
    )
    return create_app(
        store=engine.store,
        gateway=engine.gateway,
        runner=engine.runner,
        exchange=engine.dry,
        strategies=engine.strategies,
        limits=engine.limits,
        spec_for=lambda product: SPEC,
        price_for=engine.price_for,
        token=TOKEN,
        heartbeat_path=engine.root / "hb.json",
        now=engine.now,
        switches=engine.switches,
        **extra,
    )


# ---------------------------------------------------------------- bot/order state


def bot_state(store, bot_id):
    bot = store.get_bot(bot_id)
    return {
        "mode": bot["mode"],
        "capital_quote": bot["capital_quote"],
        "capital_base": bot["capital_base"],
        "live_capital_quote": bot["live_capital_quote"],
        "live_capital_base": bot["live_capital_base"],
        "status": bot["status"],
        "init_done": bot["init_done"],
    }


def order_state(store, owner):
    return {
        (row["client_order_id"], row["book"]): (
            row["status"],
            row["filled_size"],
            row["filled_value"],
            row["fees"],
            row["opposite"],
        )
        for row in store.orders(owner=owner)
    }


def book_state(store, bot_id):
    return {
        "bot": bot_state(store, bot_id),
        "orders": order_state(store, bot_id),
        "hwm_dry": store.hwm(bot_id, "dry"),
        "hwm_live": store.hwm(bot_id, "live"),
        "bench_dry": store.get(f"bench:dry:{bot_id}"),
        "bench_live": store.get(f"bench:live:{bot_id}"),
        "epoch_dry": store.book_epoch("dry", bot_id),
        "epoch_live": store.book_epoch("live", bot_id),
    }


def raw_kv(store, key):
    row = store.conn().execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return None if row is None else row["value"]


# ---------------------------------------------------------------- the books


def test_dry_and_live_books_separate(engines):
    engine = engines(capital_quote=D("1000"), capital_base=D("500"))
    store = engine.store

    engine.add_bot("b2", capital_quote=D("0"), capital_base=D("0"))
    engine.set_live("b2", D("30"), D("20"))

    # A dry fill on the dry bot: it moves the dry book's holdings.
    cid = "cb-b1-B-9-000000000001"
    store.insert_order(
        cid, "b1", "bot", PRODUCT, "BUY", 9, D("0.95"), D("10"), book="dry",
        product_type="SPOT",
    )
    store.update_order(
        cid,
        status=FILLED,
        filled_size=D("10"),
        filled_value=D("9.5"),
        fees=D("0.05"),
    )
    store.conn().execute(
        "UPDATE orders SET created_at=? WHERE client_order_id=?",
        (engine.now() - 1000, cid),
    )
    engine.dry.deposit(BASE, D("10"), "cover the synthetic fill")

    real = engine.books.totals("live")
    sim = engine.dry.totals()

    # Only the live bot's capital is held against the real account.
    live_unalloc = engine.ledger.unallocated(real, book="live")
    assert live_unalloc == {
        QUOTE: real[QUOTE] - D("30"),
        BASE: real[BASE] - D("20"),
    }
    assert live_unalloc[QUOTE] > 0
    assert live_unalloc[BASE] > 0

    # Only dry capital and dry rows are held against the simulator.
    dry_unalloc = engine.ledger.unallocated(sim, book="dry")
    assert dry_unalloc == {
        QUOTE: sim[QUOTE] - (D("1000") - (D("9.5") + D("0.05"))),
        BASE: sim[BASE] - (D("500") + D("10")),
    }

    # A dry bot's large holdings never make the live book short: the live check
    # is judged on the live rows and the live capital alone.
    engine.switches.set("live_enabled", True)
    assert (
        engine.gateway.check(
            "bot", "b2", place_intent(size=D("5"), price=D("0.95")), PRODUCT
        )
        is None
    )
    assert engine.ledger.unallocated(real, book="live")[QUOTE] > 0

    # The book epoch hides rows older than it.
    before = engine.ledger.holding("b1", PRODUCT, book="dry")
    assert before.quote == D("1000") - D("9.55")
    assert before.base == D("500") + D("10")
    store.set_book_epoch("dry", "b1", engine.now())
    after = engine.ledger.holding("b1", PRODUCT, book="dry")
    assert after.quote == D("1000")
    assert after.base == D("500")


def test_dry_orders_dont_use_live_caps(engines):
    engine = engines(
        env={
            "CROW_COINBASE_DAILY_NOTIONAL_USD": "20",
            "CROW_COINBASE_ORDERS_PER_HOUR": "30",
        }
    )
    store = engine.store
    engine.set_live("b1", D("100"), D("100"))
    engine.switches.set("live_enabled", True)

    for index in range(3):
        cid = f"cb-b1-B+{index + 2}-{index:012x}"
        store.insert_order(
            cid, "b1", "bot", PRODUCT, "BUY", index + 2, D("100"), D("10"), book="dry",
            product_type="SPOT",
        )

    caps = engine.gateway.caps
    assert caps.daily_notional(None, book="dry") == D("3000")
    assert caps.daily_notional(None, book="live") == D("0")
    assert caps.orders_last_hour(None, book="dry") == 3
    assert caps.orders_last_hour(None, book="live") == 0

    # A dry-heavy day does not trip DAILY_CAP on a live route.
    assert (
        engine.gateway.check(
            "bot", "b1", place_intent(size=D("10"), price=D("0.95")), PRODUCT
        )
        is None
    )

    live_cid = "cb-b1-B+9-00ab00ab"
    store.insert_order(
        live_cid, "b1", "bot", PRODUCT, "BUY", 9, D("30"), D("1"), book="live",
        product_type="SPOT",
    )
    assert caps.daily_notional(None, book="dry") == D("3000")
    assert caps.orders_last_hour(None, book="dry") == 3
    assert caps.daily_notional(None, book="live") == D("30")

    # Live rows do trip it.
    assert (
        engine.gateway.check(
            "bot", "b1", place_intent(size=D("10"), price=D("0.95")), PRODUCT
        )
        == DAILY_CAP
    )


def test_reconcile_live_only_against_exchange(engines):
    engine = engines(wrap=True)
    store = engine.store
    now = engine.now()

    dry_cid = "cb-b1-B-1-0000000000d1"
    live_cid = "cb-b1-B-2-0000000000e1"
    pending_cid = "cb-b1-B-3-0000000000f1"
    stranger = "cb-b1-B+4-00000000ace1"

    store.insert_order(
        dry_cid,
        "b1",
        "bot",
        PRODUCT,
        "BUY",
        1,
        D("0.9"),
        D("1"),
        status=OPEN,
        order_id="dry-ex-1",
        book="dry",
        product_type="SPOT",
    )
    store.insert_order(
        live_cid,
        "b1",
        "bot",
        PRODUCT,
        "BUY",
        2,
        D("0.9"),
        D("1"),
        status=OPEN,
        order_id="live-ex-1",
        book="live",
        product_type="SPOT",
    )
    store.insert_order(
        pending_cid,
        "b1",
        "bot",
        PRODUCT,
        "BUY",
        3,
        D("0.9"),
        D("1"),
        status=PENDING_SUBMIT,
        book="live",
        product_type="SPOT",
    )
    store.conn().execute(
        "UPDATE orders SET created_at=? WHERE client_order_id=?",
        (now - 1000, pending_cid),
    )
    engine._live_sim.place_limit(stranger, PRODUCT, "BUY", D("1"), D("0.5"))

    engine.dry_rec.calls.clear()
    engine.live_rec.calls.clear()
    reconcile(store, engine.dry, now, gateway=None, book="dry")

    assert engine.live_rec.calls == []
    assert "get_order" in engine.dry_rec.calls
    assert store.order(live_cid)["status"] == OPEN
    assert store.order(pending_cid)["status"] == PENDING_SUBMIT
    assert store.order(stranger) is None
    assert store.order(dry_cid)["book"] == "dry"

    engine.dry_rec.calls.clear()
    engine.live_rec.calls.clear()
    reconcile(store, engine.live_router, now, gateway=None, book="live")

    assert engine.dry_rec.calls == []
    assert "list_open_orders" in engine.live_rec.calls
    # The live book's own rows are settled from the live exchange's answer.
    assert store.order(live_cid)["status"] == OPEN
    assert store.order(pending_cid)["status"] != PENDING_SUBMIT
    # A stranger seen on the live exchange is adopted onto the live book.
    assert store.order(stranger)["book"] == "live"
    assert store.order(stranger)["owner"] == "b1"
    assert store.order(dry_cid)["status"] == OPEN


# ---------------------------------------------------------------- the switch


def test_dry_to_live_rebase(engines):
    engine = engines()
    store = engine.store
    engine.prime()
    engine.switches.set("live_enabled", True)

    # Two resting dry orders and a dry history to keep frozen.
    assert engine.gateway.submit("bot", BOT, place_intent(), PRODUCT).ok is True
    assert (
        engine.gateway.submit(
            "bot", BOT, place_intent(side="SELL", size=D("5"), price=D("1.05"), level=2),
            PRODUCT,
        ).ok
        is True
    )
    assert all(
        row["status"] == OPEN
        for row in store.orders(owner=BOT, statuses=LIVE_STATUSES)
    )
    store.update_hwm(BOT, D("123"), "dry")
    engine.runner.benchmark.start(BOT, D("10"), D("50"), D("1"), book="dry")
    store.set_init_done(BOT, True)

    before = book_state(store, BOT)
    live_before = engine.ledger.unallocated(engine.books.totals("live"), book="live")
    assert live_before == {QUOTE: D("1000"), BASE: D("1000")}

    # More than the real unallocated balance: refused, nothing written.
    with pytest.raises(ModeRefused) as short:
        engine.runner.switch_mode(BOT, "live", capital_quote="5000", capital_base="0")
    assert short.value.code == "LIVE_CAPITAL_SHORT"
    assert short.value.status == 409
    assert book_state(store, BOT) == before

    # The live switch off: refused, nothing written.
    engine.switches.set("live_enabled", False)
    with pytest.raises(ModeRefused) as disabled:
        engine.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    assert disabled.value.code == LIVE_DISABLED
    assert book_state(store, BOT) == before
    engine.switches.set("live_enabled", True)

    # No live exchange at all: refused with zero calls on any exchange.
    engine.add_bot("b2", capital_quote=D("10"), capital_base=D("5"))
    dry_recorder = Recorder(engine._dry_raw)
    saved = (engine.gateway.books, engine.gateway.exchange, engine.runner.exchange)
    engine.gateway.books = BookRouter(dry_recorder, lambda: None)
    engine.gateway.exchange = dry_recorder
    engine.runner.exchange = dry_recorder
    try:
        with pytest.raises(ModeRefused) as locked:
            engine.runner.switch_mode("b2", "live", capital_quote="1", capital_base="0")
    finally:
        engine.gateway.books, engine.gateway.exchange, engine.runner.exchange = saved
    assert locked.value.code == LIVE_LOCKED
    assert dry_recorder.calls == []

    # The switch itself.
    engine.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")

    bot = store.get_bot(BOT)
    assert bot["mode"] == "live"
    assert bot["live_capital_quote"] == D("20")
    assert bot["live_capital_base"] == D("5")
    assert bot["capital_quote"] == D("100")
    assert bot["capital_base"] == D("50")
    assert bot["status"] == ACTIVE
    assert bot["init_done"] is False

    dry_rows = store.orders(owner=BOT, book="dry")
    assert dry_rows
    assert all(row["status"] == CANCELLED for row in dry_rows)

    assert store.hwm(BOT, "live") is None
    assert store.hwm(BOT, "dry") == D("123")
    assert store.get(f"bench:live:{BOT}") is None
    assert store.get(f"bench:dry:{BOT}") is not None

    held = engine.ledger.holding(BOT, PRODUCT, book="live")
    assert held.quote == D("20")
    assert held.base == D("5")

    live_after = engine.ledger.unallocated(engine.books.totals("live"), book="live")
    assert live_after == {
        QUOTE: live_before[QUOTE] - D("20"),
        BASE: live_before[BASE] - D("5"),
    }

    messages = [
        row["message"]
        for row in store.conn().execute("SELECT message FROM events").fetchall()
    ]
    assert f"bot {BOT} switched to live" in messages

    # The API path: privileged call injected, acknowledge_live required.
    api_engine = engine
    app = make_app(api_engine, require_privileged=lambda request: None)
    api_engine.add_bot("b3", capital_quote=D("10"), capital_base=D("5"))
    api_engine.add_bot("b4", capital_quote=D("0"), capital_base=D("0"))
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        live_before_b3 = api_engine.ledger.unallocated(
            api_engine.books.totals("live"), book="live"
        )
        response = client.post(
            "/bots/b3/mode",
            json={
                "mode": "live",
                "capital_quote": "20",
                "capital_base": "5",
                "acknowledge_live": True,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["mode"] == "live"
        assert body["live_capital_quote"] == "20"
        assert body["live_capital_base"] == "5"
        live_after_b3 = api_engine.ledger.unallocated(
            api_engine.books.totals("live"), book="live"
        )
        assert live_after_b3 == {
            QUOTE: live_before_b3[QUOTE] - D("20"),
            BASE: live_before_b3[BASE] - D("5"),
        }

        missing = client.post(
            "/bots/b4/mode",
            json={"mode": "live", "capital_quote": "5", "capital_base": "1"},
        )
        assert missing.status_code == 409
        assert missing.json()["detail"] == "live needs acknowledge_live: true"
        assert store.get_bot("b4")["mode"] == "dry"


def test_live_to_dry_rebase(engines):
    engine = engines()
    store = engine.store
    engine.prime()
    engine.switches.set("live_enabled", True)
    engine.set_live(BOT, D("100"), D("100"))

    buy = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert buy.ok is True
    sell = engine.gateway.submit(
        "bot", BOT, place_intent(side="SELL", size=D("5"), price=D("1.05"), level=2),
        PRODUCT,
    )
    assert sell.ok is True
    live_cids = [buy.cid, sell.cid]

    # Live filled history: a buy of 10 at 0.9, fee 0.045.
    history = "cb-b1-B-3-0000000000f1"
    store.insert_order(
        history, BOT, "bot", PRODUCT, "BUY", 3, D("0.9"), D("10"), book="live",
        product_type="SPOT",
    )
    store.update_order(
        history,
        status=FILLED,
        filled_size=D("10"),
        filled_value=D("9"),
        fees=D("0.045"),
    )

    # An old dry row the new dry epoch must stop counting.
    old_dry = "cb-b1-B-4-0000000000a1"
    store.insert_order(
        old_dry, BOT, "bot", PRODUCT, "BUY", 4, D("10"), D("100"), book="dry",
        product_type="SPOT",
    )
    store.update_order(
        old_dry,
        status=FILLED,
        filled_size=D("100"),
        filled_value=D("1000"),
        fees=D("0"),
    )
    store.conn().execute(
        "UPDATE orders SET created_at=? WHERE client_order_id=?",
        (engine.now() - 1000, old_dry),
    )
    store.update_hwm(BOT, D("999"), "dry")
    engine.runner.benchmark.start(BOT, D("1"), D("1"), D("1"), book="dry")
    store.set_init_done(BOT, True)

    expected_value = D("100") - D("9") - D("0.045") + (D("100") + D("10")) * MID
    assert expected_value == D("200.405")
    assert (
        engine.ledger.equity(BOT, {PRODUCT: MID}, PRODUCT, book="live")
        == expected_value
    )

    sim_before = engine.dry.totals()

    # Capital fields on a dry switch are refused.
    with pytest.raises(ModeRefused) as invalid:
        engine.runner.switch_mode(BOT, "dry", capital_quote="1")
    assert invalid.value.code == "CAPITAL_INVALID"
    assert invalid.value.status == 422
    assert store.get_bot(BOT)["mode"] == "live"

    engine.runner.switch_mode(BOT, "dry")

    bot = store.get_bot(BOT)
    assert bot["mode"] == "dry"
    assert bot["capital_quote"] == expected_value
    assert bot["capital_base"] == D("0")
    assert bot["live_capital_quote"] is None
    assert bot["live_capital_base"] is None
    assert bot["init_done"] is False

    assert store.orders(owner=BOT, book="live", statuses=LIVE_STATUSES) == []
    for live_cid in live_cids:
        assert store.order(live_cid)["status"] == CANCELLED
    open_live = [
        order
        for order in engine._live_sim.list_open_orders(None)
        if str(order.get("client_order_id") or "").startswith(f"cb-{BOT}-")
    ]
    assert open_live == []

    live_held = engine.ledger.holding(BOT, PRODUCT, book="live")
    assert live_held.quote == D("0")
    assert live_held.base == D("0")
    assert engine.ledger.unallocated(
        engine.books.totals("live"), book="live"
    ) == {QUOTE: D("1000"), BASE: D("1000")}

    dry_held = engine.ledger.holding(BOT, PRODUCT, book="dry")
    assert dry_held.quote == expected_value
    assert dry_held.base == D("0")
    assert store.book_epoch("dry", BOT) > engine.now() - 900

    assert store.hwm(BOT, "dry") is None
    assert store.get(f"bench:dry:{BOT}") is None
    with pytest.raises(KeyError):
        engine.runner.benchmark.value(BOT, MID, book="dry")

    sim_after = engine.dry.totals()
    assert sim_after[QUOTE] == sim_before[QUOTE] + expected_value
    assert sim_after[BASE] == sim_before[BASE]

    messages = [
        row["message"]
        for row in store.conn().execute("SELECT message FROM events").fetchall()
    ]
    assert f"bot {BOT} switched to dry" in messages

    # A live bot whose last value is zero cannot be rebased.
    engine.add_bot("b2", capital_quote=D("0"), capital_base=D("0"))
    engine.set_live("b2", D("0"), D("0"))
    with pytest.raises(ModeRefused) as zero:
        engine.runner.switch_mode("b2", "dry")
    assert zero.value.code == "CAPITAL_INVALID"
    assert store.get_bot("b2")["mode"] == "live"

    # No usable mid: PRICE_UNKNOWN and nothing changed.
    no_price = engines(snapshot=False)
    no_price.switches.set("live_enabled", True)
    no_price.set_live(BOT, D("100"), D("100"))
    before = book_state(no_price.store, BOT)
    with pytest.raises(ModeRefused) as unknown:
        no_price.runner.switch_mode(BOT, "dry")
    assert unknown.value.code == "PRICE_UNKNOWN"
    assert unknown.value.status == 503
    assert book_state(no_price.store, BOT) == before


def test_route_matrix(engines):
    expected_by_flags = {}
    for ceiling in (True, False):
        for switch in (True, False):
            for have in (True, False):
                for mode in (DRY, LIVE):
                    if mode == DRY:
                        expected = (DRY, None)
                    elif not ceiling or not switch:
                        expected = (LIVE, LIVE_DISABLED)
                    elif not have:
                        expected = (LIVE, LIVE_LOCKED)
                    else:
                        expected = (LIVE, None)
                    expected_by_flags[(ceiling, switch, have, mode)] = expected

    for (ceiling, switch, have, mode), expected in expected_by_flags.items():
        assert (
            route_decision(
                ceiling=ceiling, switch=switch, have_exchange=have, mode=mode
            )
            == expected
        )
    assert len(expected_by_flags) == 16

    with pytest.raises(ValueError):
        route_decision(
            ceiling=True, switch=True, have_exchange=True, mode="paper"
        )

    engine = engines(float_funds=True)
    store = engine.store
    engine.set_live(BOT, D("100"), D("100"))
    engine.add_bot("b2", capital_quote=D("100"), capital_base=D("100"))
    engine.prime()

    for book, suffix in ((DRY, "0000000da1"), (LIVE, "0000000ea1")):
        cid = f"cb-ai-S-1-{suffix}"
        store.insert_order(
            cid, "ai", "ai", PRODUCT, "SELL", 1, D("12"), D("1"), book=book,
            product_type="SPOT",
        )
        store.update_order(
            cid, status=FILLED, filled_size=D("1"), filled_value=D("12"), fees=D("0")
        )

    on = Switches(store, engine.env)
    on.set("live_enabled", True)
    on.set("ai_live_enabled", True)
    ceiling_off = Switches(store, {**engine.env, "CROW_COINBASE_LIVE": "false"})

    live_gateway = gateway_for(engine, switches=on, books=engine.books)
    off_gateway = gateway_for(engine, switches=ceiling_off, books=engine.books)
    no_live_gateway = gateway_for(
        engine, switches=on, books=BookRouter(engine.dry, None)
    )

    intent = place_intent(size=D("10"), price=D("0.95"))

    # A live-mode bot.
    assert off_gateway.check("bot", BOT, intent, PRODUCT) == LIVE_DISABLED
    on.set("live_enabled", False)
    assert live_gateway.check("bot", BOT, intent, PRODUCT) == LIVE_DISABLED
    on.set("live_enabled", True)
    assert no_live_gateway.check("bot", BOT, intent, PRODUCT) == LIVE_LOCKED
    assert live_gateway.check("bot", BOT, intent, PRODUCT) is None

    # The same for the `ai` owner, whose switch is `ai_live_enabled`.  The route
    # is read off `evaluate()`, the approval-free chain: `check()` runs the AI's
    # approval step as well, which is a different question from the route's.
    assert off_gateway.evaluate("ai", "ai", intent, PRODUCT)[0] == LIVE_DISABLED
    assert (
        no_live_gateway.evaluate("ai", "ai", intent, PRODUCT)[0] == LIVE_LOCKED
    )
    assert live_gateway.evaluate("ai", "ai", intent, PRODUCT)[0] is None
    on.set("ai_live_enabled", False)
    assert live_gateway.evaluate("ai", "ai", intent, PRODUCT)[0] is None
    on.set("ai_live_enabled", True)

    # A dry bot is unaffected by all of it.
    assert off_gateway.check("bot", "b2", intent, PRODUCT) is None
    assert no_live_gateway.check("bot", "b2", intent, PRODUCT) is None

    # A live-mode owner never reaches the dry exchange.
    recorded = engines(float_funds=True, wrap=True)
    recorded.set_live(BOT, D("100"), D("100"))
    recorded.switches.set("live_enabled", True)
    recorded.prime()
    recorded.dry_rec.calls.clear()
    recorded.live_rec.calls.clear()
    result = recorded.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert result.ok is True
    assert result.refusal is None
    assert "place_limit" in recorded.live_rec.calls
    assert "place_limit" not in recorded.dry_rec.calls


def test_live_route_without_exchange_makes_zero_calls(engines):
    engine = engines(wrap=True)
    store = engine.store
    engine.prime()

    placed = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert placed.ok is True
    dry_cid = placed.cid
    assert store.order(dry_cid)["book"] == "dry"

    engine.set_live(BOT, D("100"), D("100"))
    engine.switches.set("live_enabled", True)

    gateway = gateway_for(
        engine, switches=engine.switches, books=BookRouter(engine.dry, no_live_exchange)
    )
    live_rows_before = len(store.orders(owner=BOT, book="live"))

    stand_in = Recorder(engine._live_router_raw) if engine._live_router_raw else None
    engine.dry_rec.calls.clear()
    if engine.live_rec is not None:
        engine.live_rec.calls.clear()

    result = gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert result.ok is False
    assert result.refusal == LIVE_LOCKED
    assert result.cid is None
    assert len(store.orders(owner=BOT, book="live")) == live_rows_before
    assert engine.dry_rec.calls == []
    if engine.live_rec is not None:
        assert engine.live_rec.calls == []
    if stand_in is not None:
        assert stand_in.calls == []

    # The kill path still works, skipping the missing live exchange.
    engine.dry_rec.calls.clear()
    assert gateway.cancel_all(scope="all") == 1
    assert "cancel" in engine.dry_rec.calls
    remaining = [
        order["client_order_id"]
        for order in engine._dry_raw.list_open_orders(None)
        if order["client_order_id"] == dry_cid
    ]
    assert remaining == []

    with pytest.raises(LiveLocked):
        gateway.cancel_all(scope="owner", owner=BOT, book="live")


def test_live_bot_recenter_update_resume_need_mac(engines):
    engine = engines()
    engine.set_live(BOT, D("100"), D("100"))
    engine.prime()

    deny_app = make_app(engine)
    with TestClient(deny_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        recenter = client.post("/bots/b1/recenter", json={"center": "1.1"})
        assert recenter.status_code == 403
        assert recenter.json()["detail"] == "LIVE_NEEDS_OWNER"
        resume = client.post(
            "/bots/b1/resume", json={"acknowledge_rebase": True}
        )
        assert resume.status_code == 403
        assert resume.json()["detail"] == "LIVE_NEEDS_OWNER"

    # A dry bot needs no owner approval at all.
    engine.add_bot("b2", capital_quote=D("10"), capital_base=D("5"))
    engine.store.set_bot_status("b2", PAUSED)
    with TestClient(deny_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        assert (
            client.post("/bots/b2/recenter", json={"center": "1.1"}).status_code
            == 200
        )
        assert (
            client.post(
                "/bots/b2/resume", json={"acknowledge_rebase": True}
            ).status_code
            == 200
        )

    # With the privileged callable injected they proceed.
    open_app = make_app(engine, require_privileged=lambda request: None)
    with TestClient(open_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        assert (
            client.post("/bots/b1/recenter", json={"center": "1.1"}).status_code
            == 200
        )
        engine.store.set_bot_status("b1", PAUSED)
        assert (
            client.post(
                "/bots/b1/resume", json={"acknowledge_rebase": True}
            ).status_code
            == 200
        )

    # pause and stop stay bearer-only for a live bot.
    engine.add_bot("b3", capital_quote=D("10"), capital_base=D("5"))
    engine.set_live("b3", D("50"), D("50"))
    with TestClient(deny_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        assert client.post("/bots/b3/pause").status_code == 200
        assert client.post("/bots/b3/stop").status_code == 200
    assert engine.store.get_bot("b3")["status"] == STOPPED


def test_new_bot_always_dry(engines):
    engine = engines()
    app = make_app(engine)
    body = {
        "id": "nb1",
        "product": PRODUCT,
        "strategy": "grid",
        "params": GRID_PARAMS,
        "capital_quote": "10",
        "capital_base": "5",
    }
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        response = client.post("/bots", json=body)
        assert response.status_code == 201
        data = response.json()
        assert data["mode"] == "dry"
        assert data["live_capital_quote"] is None
        assert data["live_capital_base"] is None

        refused = client.post("/bots", json={**body, "id": "nb2", "mode": "live"})
        assert refused.status_code == 422
        refused_extra = client.post(
            "/bots", json={**body, "id": "nb3", "something": "else"}
        )
        assert refused_extra.status_code == 422

    row = engine.store.get_bot("nb1")
    assert row["mode"] == "dry"
    assert row["live_capital_quote"] is None
    assert row["live_capital_base"] is None
    assert engine.store.get_bot("nb2") is None
    assert engine.store.get_bot("nb3") is None


def test_privileged_routes_deny_by_default(engines):
    engine = engines()
    engine.prime()
    deny_app = make_app(engine)
    with TestClient(deny_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        mode_denied = client.post("/bots/b1/mode", json={"mode": "dry"})
        assert mode_denied.status_code == 403
        assert mode_denied.json()["detail"] == "APPROVAL_INVALID"

        malformed = client.post("/bots/b1/mode", json={})
        assert malformed.status_code == 403
        assert malformed.json()["detail"] == "APPROVAL_INVALID"

        switches_denied = client.post("/switches", json={"live_enabled": True})
        assert switches_denied.status_code == 403
        assert switches_denied.json()["detail"] == "APPROVAL_INVALID"

        halt_clear_denied = client.post(
            "/halt/clear", json={"acknowledge_rebase": True}
        )
        assert halt_clear_denied.status_code == 403
        assert halt_clear_denied.json()["detail"] == "APPROVAL_INVALID"

        halt_clear_malformed = client.post("/halt/clear", json={})
        assert halt_clear_malformed.status_code == 403
        assert halt_clear_malformed.json()["detail"] == "APPROVAL_INVALID"

        missing = client.post(
            "/switches",
            json={"live_enabled": True},
            headers={"Authorization": "Bearer wrong"},
        )
        assert missing.status_code == 401
        no_header = client.post(
            "/switches", json={"live_enabled": True}, headers={"Authorization": ""}
        )
        assert no_header.status_code == 401

    assert engine.store.get_bot(BOT)["mode"] == "dry"
    assert engine.store.get("live_enabled") in (None, False)
    assert engine.store.get("ai_live_enabled") in (None, False)

    open_app = make_app(engine, require_privileged=lambda request: None)
    with TestClient(open_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        turned_on = client.post("/switches", json={"live_enabled": True})
        assert turned_on.status_code == 200
        assert turned_on.json() == {
            "live_enabled": True,
            "ai_live_enabled": False,
            "ceiling": True,
        }
        switched = client.post(
            "/bots/b1/mode",
            json={
                "mode": "live",
                "capital_quote": "20",
                "capital_base": "5",
                "acknowledge_live": True,
            },
        )
        assert switched.status_code == 200
        assert switched.json()["mode"] == "live"

    ceiling_engine = engines(env={"CROW_COINBASE_LIVE": "false"})
    ceiling_app = make_app(ceiling_engine, require_privileged=lambda request: None)
    with TestClient(ceiling_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        assert ceiling_engine.switches.ceiling is False

        refused = client.post("/switches", json={"live_enabled": True})
        assert refused.status_code == 409
        assert refused.json()["detail"].startswith(LIVE_DISABLED)

        turned_off = client.post("/switches", json={"live_enabled": False})
        assert turned_off.status_code == 200
        assert turned_off.json() == {
            "live_enabled": False,
            "ai_live_enabled": False,
            "ceiling": False,
        }

        assert client.post("/switches", json={}).status_code == 422
        assert (
            client.post("/switches", json={"live_enabled": "yes"}).status_code
            == 422
        )


def test_ceiling_from_env():
    assert ceiling_from_env({}) is True
    for value in ("true", "TRUE", "1", "YES", " on "):
        assert ceiling_from_env({"CROW_COINBASE_LIVE": value}) is True, value
    for value in ("false", "0", "no", "off", "", "   ", "maybe", "tru"):
        assert ceiling_from_env({"CROW_COINBASE_LIVE": value}) is False, value


def test_book_required_keyword(tmp_path):
    store = Store(tmp_path / "s.db")
    try:
        store.create_bot("b1", PRODUCT, "grid", {}, D("10"), D("10"))
        cid = "cb-b1-B-1-000000000001"
        fill = {
            "trade_id": "t-1",
            "order_id": "ex-1",
            "side": "BUY",
            "size": D("1"),
            "price": D("0.9"),
            "commission": D("0"),
            "trade_time": "2025-01-01T00:00:00Z",
            "trade_type": "FILL",
        }

        with pytest.raises(TypeError):
            store.insert_order(
                cid, "b1", "bot", PRODUCT, "BUY", 1, D("0.9"), D("1"),
                product_type="SPOT",
            )
        with pytest.raises(TypeError):
            store.record_fill(fill, cid)

        with pytest.raises(ValueError):
            store.insert_order(
                cid, "b1", "bot", PRODUCT, "BUY", 1, D("0.9"), D("1"), book="paper",
                product_type="SPOT",
            )
        assert store.order(cid) is None

        store.insert_order(
            cid, "b1", "bot", PRODUCT, "BUY", 1, D("0.9"), D("1"), book="dry",
            product_type="SPOT",
        )
        assert store.order(cid)["book"] == "dry"

        with pytest.raises(ValueError):
            store.record_fill(fill, cid, book="live")
        assert store.has_fill("t-1") is False

        assert store.record_fill(fill, cid, book="dry") is True
        row = store.conn().execute(
            "SELECT book FROM fills WHERE trade_id='t-1'"
        ).fetchone()
        assert row["book"] == "dry"
    finally:
        store.close()


def test_hwm_and_benchmark_keys_per_book(tmp_path):
    store = Store(tmp_path / "s.db")
    try:
        store.update_hwm("o1", D("10"), "dry")
        store.update_hwm("o1", D("20"), "live")
        assert store.hwm("o1", "dry") == D("10")
        assert store.hwm("o1", "live") == D("20")

        store.reset_hwm("o1", "dry")
        assert store.hwm("o1", "dry") is None
        assert store.hwm("o1", "live") == D("20")
        store.reset_hwm("nobody", "dry")  # no row: a no-op

        benchmark = Benchmark(store)
        benchmark.start("o2", D("1"), D("2"), D("3"), book="live")
        assert store.get("bench:live:o2") is not None
        assert store.get("bench:dry:o2") is None

        benchmark.start("o3", D("1"), D("2"), D("3"), book="dry")
        assert store.get("bench:dry:o3") is not None
        assert store.get("bench:live:o3") is None

        # P1 data under the legacy key is still read for the dry book.
        store.put("benchmark:o4", {"base": "2", "quote": "3", "price": "4"})
        assert benchmark.value("o4", D("5"), book="dry") == D("13")
        assert benchmark.vs_hold("o4", D("20"), D("5"), book="dry") == D("7")
        benchmark.start("o4", D("1"), D("1"), D("1"), book="dry")
        assert store.get("bench:dry:o4") is None

        # Never for the live book.
        with pytest.raises(KeyError):
            benchmark.value("o4", D("5"), book="live")
        benchmark.start("o4", D("1"), D("1"), D("1"), book="live")
        assert store.get("bench:live:o4") is not None

        # Forgetting the dry book lets a later start take a fresh baseline.
        benchmark.forget("o4", "dry")
        assert store.get("bench:dry:o4") is None
        assert raw_kv(store, "benchmark:o4") == "null"
        benchmark.start("o4", D("10"), D("20"), D("30"), book="dry")
        assert benchmark.value("o4", D("1"), book="dry") == D("30")
    finally:
        store.close()


def test_pnl_and_fills_use_book(engines):
    engine = engines()
    store = engine.store
    engine.prime()

    # Dry history: a fill with a large commission and a realized gain.
    dry_cid = "cb-b1-S-1-000000000001"
    store.insert_order(
        dry_cid, BOT, "bot", PRODUCT, "SELL", 1, D("1"), D("10"), book="dry",
        product_type="SPOT",
    )
    store.update_order(
        dry_cid,
        status=FILLED,
        filled_size=D("10"),
        filled_value=D("100"),
        fees=D("5"),
        basis_per_base=D("5"),
    )
    store.record_fill(
        {
            "trade_id": "t-dry",
            "order_id": "ex-dry",
            "side": "SELL",
            "size": D("10"),
            "price": D("1"),
            "commission": D("5"),
            "trade_time": "2025-01-01T00:00:00Z",
            "trade_type": "FILL",
        },
        dry_cid,
        book="dry",
    )

    engine.set_live(BOT, D("20"), D("5"))

    # Live history: one fill, commission 1, a realized 0.95.
    live_cid = "cb-b1-S-2-000000000002"
    store.insert_order(
        live_cid, BOT, "bot", PRODUCT, "SELL", 2, D("1"), D("10"), book="live",
        product_type="SPOT",
    )
    store.update_order(
        live_cid,
        status=FILLED,
        filled_size=D("10"),
        filled_value=D("10"),
        fees=D("0.05"),
        basis_per_base=D("0.9"),
    )
    store.record_fill(
        {
            "trade_id": "t-live",
            "order_id": "ex-live",
            "side": "SELL",
            "size": D("10"),
            "price": D("1"),
            "commission": D("1"),
            "trade_time": "2025-02-01T00:00:00Z",
            "trade_type": "FILL",
        },
        live_cid,
        book="live",
    )

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)

        pnl = client.get("/pnl")
        assert pnl.status_code == 200
        entry = pnl.json()["bots"][BOT]
        assert entry["mode"] == "live"
        assert D(entry["realized"]) == D("0.95")
        assert D(entry["fees"]) == D("1")
        assert D(entry["equity"]) == D("24.975")

        fills = client.get(f"/bots/{BOT}/fills")
        assert fills.status_code == 200
        books = {row["trade_id"]: row["book"] for row in fills.json()}
        assert books == {"t-dry": "dry", "t-live": "live"}

        export = client.get("/export/fills.csv")
        assert export.status_code == 200
        reader = list(csv.DictReader(io.StringIO(export.text)))
        assert reader, export.text
        assert {row["trade_id"]: row["mode"] for row in reader} == {
            "t-dry": "dry",
            "t-live": "live",
        }


def test_kill_sweeps_both_books(engines):
    engine = engines(wrap=True)
    engine.prime()
    engine.switches.set("live_enabled", True)
    assert engine.gateway.submit("bot", BOT, place_intent(), PRODUCT).ok is True

    engine.set_live(BOT, D("100"), D("100"))
    assert engine.gateway.submit("bot", BOT, place_intent(), PRODUCT).ok is True

    app = make_app(engine)
    engine.dry_rec.calls.clear()
    engine.live_rec.calls.clear()
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        killed = client.post("/kill")
        assert killed.status_code == 200
        assert killed.json()["halted"] is True

    assert "cancel" in engine.dry_rec.calls
    assert "cancel" in engine.live_rec.calls

    # With no live exchange the kill still answers for the dry book.
    without_live = engines(wrap=True)
    without_live.prime()
    assert (
        without_live.gateway.submit("bot", BOT, place_intent(), PRODUCT).ok is True
    )
    without_live.gateway.books = BookRouter(without_live.dry, None)
    app = make_app(without_live)
    without_live.dry_rec.calls.clear()
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        killed = client.post("/kill")
        assert killed.status_code == 200
        assert killed.json()["halted"] is True
    assert "cancel" in without_live.dry_rec.calls


# ---------------------------------------------------------------- books.py itself


def test_book_router(tmp_path):
    store = Store(tmp_path / "s.db")
    try:
        market = FakeMarket()
        dry = DryRunExchange(store.conn, lambda product: market, FEE_RATE)
        live_exchange = DryRunExchange(store.conn, lambda product: market, FEE_RATE)
        live_exchange.deposit(QUOTE, D("10"), "fund the live account")
        router = ExchangeRouter(live_exchange, usd_one_pool=True)

        assert BOOKS == (DRY, LIVE)
        assert BOOKS == ("dry", "live")

        book_router = BookRouter(dry, router)
        assert book_router.for_book(DRY) is dry
        assert book_router.for_book(LIVE) is router
        assert book_router.live_exchange() is router
        assert book_router.live_available() is True
        assert book_router.totals(DRY) == dry.totals()
        assert book_router.totals(LIVE) == router.crypto_totals()
        with pytest.raises(ValueError):
            book_router.for_book("paper")

        # No live exchange: every live access is refused.
        missing = BookRouter(dry, lambda: None)
        assert missing.live_exchange() is None
        assert missing.live_available() is False
        with pytest.raises(LiveLocked):
            missing.for_book(LIVE)
        with pytest.raises(LiveLocked):
            missing.totals(LIVE)

        # The default factory has no credentials yet.
        defaulted = BookRouter(dry)
        assert defaulted.live_exchange() is None
        assert defaulted.live_available() is False
        with pytest.raises(LiveLocked):
            defaulted.for_book(LIVE)

        # A factory that raises is treated as no exchange.
        def boom():
            raise RuntimeError("credentials are missing")

        broken = BookRouter(dry, boom)
        assert broken.live_exchange() is None
        assert broken.live_available() is False

        # A factory that starts answering later is picked up.
        state = {"built": None}
        later = BookRouter(dry, lambda: state["built"])
        assert later.live_exchange() is None
        state["built"] = router
        assert later.live_exchange() is router
        assert later.live_available() is True
        assert later.for_book(LIVE) is router

        assert no_live_exchange() is None
    finally:
        store.close()


def test_switches_default_and_set(tmp_path):
    store = Store(tmp_path / "s.db")
    try:
        switches = Switches(store, {})
        assert switches.ceiling is True
        assert switches.live_enabled() is False
        assert switches.ai_live_enabled() is False
        assert switches.snapshot() == {
            "live_enabled": False,
            "ai_live_enabled": False,
            "ceiling": True,
        }

        # Anything that is not exactly the JSON boolean true reads False.
        for value in ("true", 1, {"on": True}, [True]):
            store.put("live_enabled", value)
            assert switches.live_enabled() is False, value

        switches.set("live_enabled", True)
        assert store.get("live_enabled") is True
        assert switches.live_enabled() is True
        switches.set("ai_live_enabled", True)
        assert store.get("ai_live_enabled") is True
        assert switches.ai_live_enabled() is True

        for name in ("live", "ceiling", "paper"):
            with pytest.raises(ValueError):
                switches.set(name, True)
        for value in ("true", 1, 0, None):
            with pytest.raises(ValueError):
                switches.set("live_enabled", value)

        off = Switches(store, {"CROW_COINBASE_LIVE": "false"})
        assert off.ceiling is False
        assert off.snapshot()["ceiling"] is False
    finally:
        store.close()


def test_books_module_is_import_clean():
    engine_root = Path(__file__).resolve().parents[1]
    src = engine_root / "src"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(src)!r})\n"
        "import crow_coinbase.books\n"
        "loaded = sorted(name for name in sys.modules "
        "if name.startswith('crow_coinbase'))\n"
        "assert 'crow_coinbase.store' not in sys.modules, loaded\n"
        "print('ok')\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src)
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=str(engine_root),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


# ---------------------------------------------------------------- P2 review fixes


def assert_no_book_halt(gateway):
    """The global flag and both books are clear."""
    assert gateway.is_halted() is False
    assert gateway.is_halted(DRY) is False
    assert gateway.is_halted(LIVE) is False


def engine_with_live_bot(engines):
    """One ACTIVE bot on the live book, the switch on and a fresh snapshot."""
    engine = engines()
    engine.switches.set("live_enabled", True)
    engine.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    return engine


def test_switch_never_trips_portfolio_drawdown(engines):
    # (a) Two dry bots, one switched to live after the dry portfolio mark was
    # ratcheted over both of them: the mark must not be left measuring the book
    # the other bot stayed on.
    first = engines()
    first.switches.set("live_enabled", True)
    first.add_bot("b2", capital_quote=D("10"), capital_base=D("5"))
    first.runner._ratchet_marks()
    dry_mark = first.store.hwm(PORTFOLIO_OWNER, DRY)
    assert dry_mark is not None and dry_mark > D("15")

    first.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    assert first.store.hwm(PORTFOLIO_OWNER, DRY) == first.gateway.portfolio_equity(
        DRY
    )
    assert first.store.hwm(PORTFOLIO_OWNER, LIVE) == first.gateway.portfolio_equity(
        LIVE
    )
    first.runner.cycle()
    assert_no_book_halt(first.gateway)

    # (b) Two live bots, one switched back to dry after the live mark was
    # ratcheted over both of them.
    second = engines()
    second.switches.set("live_enabled", True)
    second.add_bot("b2", capital_quote=D("10"), capital_base=D("5"))
    second.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    second.set_live("b2", D("30"), D("20"))
    second.runner.cycle()
    live_mark = second.store.hwm(PORTFOLIO_OWNER, LIVE)
    assert live_mark is not None and live_mark > D("50")

    second.runner.switch_mode(BOT, "dry")
    assert second.store.hwm(PORTFOLIO_OWNER, DRY) == second.gateway.portfolio_equity(
        DRY
    )
    assert second.store.hwm(
        PORTFOLIO_OWNER, LIVE
    ) == second.gateway.portfolio_equity(LIVE)
    second.runner.cycle()
    assert_no_book_halt(second.gateway)

    # (c) One bot dry -> live -> dry -> live: every bounce starts the book it
    # enters at today's value, and the book it leaves has no mark left over.
    third = engines()
    third.switches.set("live_enabled", True)
    third.runner.cycle()
    dry_high = third.store.hwm(PORTFOLIO_OWNER, DRY)
    assert dry_high is not None and dry_high > D("100")

    third.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    assert third.store.hwm(PORTFOLIO_OWNER, LIVE) == third.gateway.portfolio_equity(
        LIVE
    )
    assert third.store.hwm(PORTFOLIO_OWNER, DRY) is None
    third.runner.cycle()
    assert_no_book_halt(third.gateway)

    third.runner.switch_mode(BOT, "dry")
    assert third.store.hwm(PORTFOLIO_OWNER, DRY) == third.gateway.portfolio_equity(
        DRY
    )
    assert third.store.hwm(PORTFOLIO_OWNER, LIVE) is None
    third.runner.cycle()
    assert_no_book_halt(third.gateway)

    third.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    assert third.store.hwm(PORTFOLIO_OWNER, LIVE) == third.gateway.portfolio_equity(
        LIVE
    )
    assert third.store.hwm(PORTFOLIO_OWNER, DRY) is None
    third.runner.cycle()
    assert_no_book_halt(third.gateway)


def test_halt_clear_rebases_live_portfolio(engines):
    engine = engine_with_live_bot(engines)
    store = engine.store
    store.update_hwm(PORTFOLIO_OWNER, D("1000"), LIVE)
    engine.gateway.halt("live portfolio drawdown", LIVE)

    app = make_app(engine, require_privileged=lambda request: None)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        cleared = client.post("/halt/clear", json={"acknowledge_rebase": True})

    assert cleared.status_code == 200, cleared.text
    equity = engine.gateway.portfolio_equity(LIVE)
    assert equity is not None
    assert store.hwm(PORTFOLIO_OWNER, LIVE) == equity
    assert engine.gateway.is_halted(LIVE) is False
    assert engine.gateway.is_halted() is False

    engine.runner.cycle()
    assert engine.gateway.is_halted(LIVE) is False
    assert engine.gateway.is_halted() is False

    # A book in play that cannot be priced does not hold the clear: it is cleared
    # with its portfolio mark reset, and its `rebased` entry says null.
    broken = engine_with_live_bot(engines)
    bstore = broken.store
    bstore.set_init_done(BOT, True)
    bstore.update_hwm(PORTFOLIO_OWNER, D("1000"), LIVE)
    broken.gateway.halt("live portfolio drawdown", LIVE)
    broken.snapshots.put(
        MarketSnapshot(
            PRODUCT, D("1.02"), D("1.00"), D("1.00"), D("1.02"), time.time()
        )
    )
    assert broken.gateway.portfolio_equity(LIVE) is None

    broken_app = make_app(broken, require_privileged=lambda request: None)
    with TestClient(broken_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        cleared_broken = client.post(
            "/halt/clear", json={"acknowledge_rebase": True}
        )

    assert cleared_broken.status_code == 200, cleared_broken.text
    assert cleared_broken.json()["rebased"] == {
        f"{PORTFOLIO_OWNER}:{LIVE}": None
    }
    assert broken.gateway.is_halted(LIVE) is False
    assert broken.gateway.is_halted() is False
    assert bstore.hwm(PORTFOLIO_OWNER, LIVE) is None
    # The grid was re-initialised on the way through, as every clear does.
    assert isinstance(bstore.get(f"runner:init_since:{BOT}"), (int, float))


def test_halt_clear_needs_privilege(engines):
    engine = engines()
    store = engine.store
    engine.switches.set("live_enabled", True)
    engine.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    engine.runner.cycle()
    store.set_init_done(BOT, True)
    store.update_hwm(PORTFOLIO_OWNER, D("1000"), LIVE)
    engine.gateway.halt("live portfolio drawdown", LIVE)
    rows_before = order_state(store, BOT)
    states_before = bot_state(store, BOT)
    assert rows_before, "the live bot has a grid to re-initialise"

    deny_app = make_app(engine)
    with TestClient(deny_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        # The approval is answered before the body is looked at: a valid body,
        # no body at all and a malformed one are all the same 403.
        for body in ({"acknowledge_rebase": True}, None, {}):
            extra = {} if body is None else {"json": body}
            denied = client.post("/halt/clear", **extra)
            assert denied.status_code == 403, denied.text
            assert denied.json()["detail"] == "APPROVAL_INVALID"

        anonymous = client.post(
            "/halt/clear",
            json={"acknowledge_rebase": True},
            headers={"Authorization": ""},
        )
        assert anonymous.status_code == 401
        assert anonymous.json() == {"detail": "unauthorized"}

    # Nothing was cleared and no grid was re-initialised.
    assert engine.gateway.is_halted(LIVE) is True
    assert store.hwm(PORTFOLIO_OWNER, LIVE) == D("1000")
    assert order_state(store, BOT) == rows_before
    assert bot_state(store, BOT) == states_before


def test_drawdown_halt_is_per_book(engines):
    # (a) A dry-book portfolio drawdown halts the dry book alone.
    dry = engines()
    dry.switches.set("live_enabled", True)
    dry.add_bot("b2", capital_quote=D("30"), capital_base=D("20"))
    dry.set_live("b2", D("30"), D("20"))
    dry.store.update_hwm(PORTFOLIO_OWNER, D("1000"), DRY)
    dry.runner._check_drawdowns()

    assert dry.gateway.is_halted() is False
    assert dry.gateway.is_halted(DRY) is True
    assert dry.gateway.is_halted(LIVE) is False
    assert dry.store.get("halted") is None
    assert dry.gateway.check("bot", BOT, place_intent(), PRODUCT) == HALTED
    assert dry.gateway.check("bot", "b2", place_intent(), PRODUCT) is None

    # Step 5 skips the halted book's own bots, not the whole step: the live bot
    # still gets its turn while the dry bot places nothing.
    dry.runner.cycle()
    assert dry.store.orders(owner=BOT) == []
    assert dry.store.orders(owner="b2") != []

    # (b) A live-book drawdown halts the live book alone.
    live = engines()
    live.switches.set("live_enabled", True)
    live.add_bot("b2", capital_quote=D("30"), capital_base=D("20"))
    live.set_live("b2", D("30"), D("20"))
    live.store.update_hwm(PORTFOLIO_OWNER, D("1000"), LIVE)
    live.runner._check_drawdowns()

    assert live.gateway.is_halted() is False
    assert live.gateway.is_halted(DRY) is False
    assert live.gateway.is_halted(LIVE) is True
    assert live.gateway.check("bot", BOT, place_intent(), PRODUCT) is None
    assert live.gateway.check("bot", "b2", place_intent(), PRODUCT) == HALTED

    # The mirror: a live-book halt leaves the dry bot's turn alone.
    live.runner.cycle()
    assert live.store.orders(owner="b2") == []
    assert live.store.orders(owner=BOT) != []

    # (c) The kill switch stays global: it halts both books.
    killed = engines()
    killed.switches.set("live_enabled", True)
    killed.add_bot("b2", capital_quote=D("30"), capital_base=D("20"))
    killed.set_live("b2", D("30"), D("20"))
    app = make_app(killed)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        response = client.post("/kill")
    assert response.status_code == 200, response.text
    assert response.json()["halted"] is True

    assert killed.gateway.is_halted() is True
    assert killed.gateway.is_halted(DRY) is True
    assert killed.gateway.is_halted(LIVE) is True
    assert killed.gateway.check("bot", BOT, place_intent(), PRODUCT) == HALTED
    assert killed.gateway.check("bot", "b2", place_intent(), PRODUCT) == HALTED

    # (d) /status reports the global flag, each book, and each book's reason.
    def status_of(engine):
        status_app = make_app(engine)
        with TestClient(status_app, raise_server_exceptions=False) as client:
            client.headers.update(HEADERS)
            answer = client.get("/status")
        assert answer.status_code == 200, answer.text
        return answer.json()

    dry_status = status_of(dry)
    assert dry_status["halted"] is True
    assert dry_status["halted_books"] == {"dry": True, "live": False}
    assert dry_status["halt_reason"] is None
    assert dry_status["halt_reasons"]["live"] is None
    assert isinstance(dry_status["halt_reasons"]["dry"], str)
    assert "dry" in dry_status["halt_reasons"]["dry"]

    live_status = status_of(live)
    assert live_status["halted"] is True
    assert live_status["halted_books"] == {"dry": False, "live": True}
    assert live_status["halt_reason"] is None
    assert live_status["halt_reasons"]["dry"] is None
    assert isinstance(live_status["halt_reasons"]["live"], str)
    assert "live" in live_status["halt_reasons"]["live"]

    killed_status = status_of(killed)
    assert killed_status["halted"] is True
    assert killed_status["halted_books"] == {"dry": True, "live": True}
    assert killed_status["halt_reason"] == "kill switch"
    # The per-book reasons are the per-book flags; the kill set the global one.
    assert killed_status["halt_reasons"] == {"dry": None, "live": None}

    # (e) Clearing one book leaves the other; clearing with no book clears all,
    # and every flag is read back from the store by a fresh Gateway.
    flags = engines()
    flags.switches.set("live_enabled", True)
    flags.add_bot("b2", capital_quote=D("30"), capital_base=D("20"))
    flags.set_live("b2", D("30"), D("20"))
    flags.gateway.halt("dry drawdown", DRY)
    flags.gateway.halt("live drawdown", LIVE)
    assert flags.gateway.is_halted() is False
    assert flags.gateway.is_halted(DRY) is True
    assert flags.gateway.is_halted(LIVE) is True

    restarted = gateway_for(flags)
    assert restarted.is_halted() is False
    assert restarted.is_halted(DRY) is True
    assert restarted.is_halted(LIVE) is True
    assert restarted.check("bot", BOT, place_intent(), PRODUCT) == HALTED
    assert restarted.check("bot", "b2", place_intent(), PRODUCT) == HALTED

    restarted.clear_halt(DRY)
    assert restarted.is_halted(DRY) is False
    assert restarted.is_halted(LIVE) is True
    assert restarted.is_halted() is False
    assert restarted.check("bot", BOT, place_intent(), PRODUCT) is None
    assert restarted.check("bot", "b2", place_intent(), PRODUCT) == HALTED

    restarted.clear_halt()
    assert restarted.is_halted() is False
    assert restarted.is_halted(DRY) is False
    assert restarted.is_halted(LIVE) is False
    assert restarted.check("bot", BOT, place_intent(), PRODUCT) is None
    assert restarted.check("bot", "b2", place_intent(), PRODUCT) is None
    assert gateway_for(flags).is_halted(DRY) is False
    assert gateway_for(flags).is_halted(LIVE) is False


def test_settle_failure_leaves_bot_paused_on_old_book(engines):
    def never_sweeps(scope, owner=None, *, book=None):
        return 0

    # Dry -> live: the settle cannot clear the dry book, so the switch is a 503
    # and the bot is left paused on its old book.
    engine = engines()
    engine.switches.set("live_enabled", True)
    engine.runner.cycle()
    before = book_state(engine.store, BOT)
    engine.gateway.cancel_all = never_sweeps

    with pytest.raises(ModeRefused) as refused:
        engine.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    assert refused.value.code == "SETTLE_FAILED"
    assert refused.value.status == 503

    after = book_state(engine.store, BOT)
    assert after["bot"]["mode"] == DRY
    assert after["bot"]["status"] == PAUSED
    assert after["bot"]["capital_quote"] == before["bot"]["capital_quote"]
    assert after["bot"]["capital_base"] == before["bot"]["capital_base"]
    assert after["bot"]["live_capital_quote"] is None
    assert after["bot"]["live_capital_base"] is None
    assert after["orders"] == before["orders"]
    assert after["hwm_dry"] == before["hwm_dry"]
    assert after["hwm_live"] == before["hwm_live"]
    assert after["bench_dry"] == before["bench_dry"]
    assert after["bench_live"] == before["bench_live"]
    assert after["epoch_dry"] == before["epoch_dry"]
    assert after["epoch_live"] == before["epoch_live"]

    app = make_app(engine, require_privileged=lambda request: None)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        answer = client.post(
            "/bots/b1/mode",
            json={
                "mode": "live",
                "capital_quote": "20",
                "capital_base": "5",
                "acknowledge_live": True,
            },
        )
    assert answer.status_code == 503, answer.text
    assert answer.json()["detail"].startswith("SETTLE_FAILED")

    # Live -> dry: the same code, status and untouched old book.
    other = engines()
    other.switches.set("live_enabled", True)
    other.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    other.runner.cycle()
    before_live = book_state(other.store, BOT)
    other.gateway.cancel_all = never_sweeps

    with pytest.raises(ModeRefused) as back:
        other.runner.switch_mode(BOT, "dry")
    assert back.value.code == "SETTLE_FAILED"
    assert back.value.status == 503

    after_live = book_state(other.store, BOT)
    assert after_live["bot"]["mode"] == LIVE
    assert after_live["bot"]["status"] == PAUSED
    assert after_live["bot"]["capital_quote"] == before_live["bot"]["capital_quote"]
    assert after_live["bot"]["capital_base"] == before_live["bot"]["capital_base"]
    assert after_live["bot"]["live_capital_quote"] == before_live["bot"][
        "live_capital_quote"
    ]
    assert after_live["bot"]["live_capital_base"] == before_live["bot"][
        "live_capital_base"
    ]
    assert after_live["orders"] == before_live["orders"]
    assert after_live["hwm_dry"] == before_live["hwm_dry"]
    assert after_live["hwm_live"] == before_live["hwm_live"]
    assert after_live["bench_dry"] == before_live["bench_dry"]
    assert after_live["bench_live"] == before_live["bench_live"]
    assert after_live["epoch_dry"] == before_live["epoch_dry"]
    assert after_live["epoch_live"] == before_live["epoch_live"]


def test_pnl_excludes_first_dry_period(engines):
    engine = engines()
    store = engine.store
    engine.switches.set("live_enabled", True)
    engine.prime()

    old_stamp = time.time() - 1000
    old = "cb-b1-S-1-0000000000a1"
    store.insert_order(
        old, BOT, "bot", PRODUCT, "SELL", 1, D("1"), D("10"), book=DRY,
        product_type="SPOT",
    )
    store.update_order(
        old,
        status=FILLED,
        filled_size=D("10"),
        filled_value=D("10"),
        fees=D("1"),
        basis_per_base=D("0.5"),
    )
    store.record_fill(
        {
            "trade_id": "t-dry-old",
            "order_id": "ex-dry-old",
            "side": "SELL",
            "size": D("10"),
            "price": D("1"),
            "commission": D("1"),
            "trade_time": "2025-01-01T00:00:00Z",
            "trade_type": "FILL",
        },
        old,
        book=DRY,
    )
    store.conn().execute(
        "UPDATE orders SET created_at=? WHERE client_order_id=?", (old_stamp, old)
    )
    store.conn().execute(
        "UPDATE fills SET recorded_at=? WHERE trade_id=?",
        (old_stamp, "t-dry-old"),
    )

    engine.runner.switch_mode(BOT, "live", capital_quote="20", capital_base="5")
    engine.runner.switch_mode(BOT, "dry")

    new = "cb-b1-S-2-0000000000a2"
    store.insert_order(
        new, BOT, "bot", PRODUCT, "SELL", 2, D("1"), D("10"), book=DRY,
        product_type="SPOT",
    )
    store.update_order(
        new,
        status=FILLED,
        filled_size=D("10"),
        filled_value=D("20"),
        fees=D("0.5"),
        basis_per_base=D("1.0"),
    )
    store.record_fill(
        {
            "trade_id": "t-dry-new",
            "order_id": "ex-dry-new",
            "side": "SELL",
            "size": D("10"),
            "price": D("2"),
            "commission": D("0.5"),
            "trade_time": "2025-02-01T00:00:00Z",
            "trade_type": "FILL",
        },
        new,
        book=DRY,
    )

    epoch = store.book_epoch(DRY, BOT)
    assert epoch > old_stamp
    assert store.order(old)["created_at"] < epoch
    assert store.order(new)["created_at"] >= epoch

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        entry = client.get("/pnl").json()["bots"][BOT]
        fills = client.get(f"/bots/{BOT}/fills").json()
        export = client.get("/export/fills.csv")

    assert entry["mode"] == DRY
    # Only the current dry period: 10 sold for 20 less 0.5 fee at a 1.0 basis.
    assert D(entry["realized"]) == D("9.5")
    assert D(entry["fees"]) == D("0.5")

    # The per-bot fills list and the tax export still carry every fill.
    assert {row["trade_id"] for row in fills} == {"t-dry-old", "t-dry-new"}
    assert export.status_code == 200
    exported = list(csv.DictReader(io.StringIO(export.text)))
    assert {row["trade_id"] for row in exported} == {"t-dry-old", "t-dry-new"}


def test_book_halt_sweeps_its_own_book(engines):
    """A halt sweeps the book it halts, and the other book is left alone."""

    def two_books():
        engine = engines(wrap=True)
        engine.switches.set("live_enabled", True)
        engine.set_live(BOT, D("100"), D("100"))
        engine.add_bot("b2", capital_quote=D("50"), capital_base=D("20"))
        return engine

    def rest_one_on_each(engine):
        live = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
        dry = engine.gateway.submit("bot", "b2", place_intent(), PRODUCT)
        assert live.ok is True and live.cid
        assert dry.ok is True and dry.cid
        # Paused, so a cycle lays nothing: every cancel on either exchange comes
        # from the kill path alone.
        engine.store.set_bot_status(BOT, PAUSED)
        engine.store.set_bot_status("b2", PAUSED)
        return live.cid, dry.cid

    def open_cids(exchange):
        return {
            str(order.get("client_order_id") or "")
            for order in exchange.list_open_orders(None)
        }

    # The live book's own drawdown stop: the live orders are cancelled, the dry
    # order rests and the dry exchange is never asked to cancel anything.
    live_halt = two_books()
    live_cid, dry_cid = rest_one_on_each(live_halt)
    live_halt.gateway.halt("live portfolio drawdown", LIVE)
    live_halt.runner.cycle()

    assert live_cid not in open_cids(live_halt._live_sim)
    assert dry_cid in open_cids(live_halt._dry_raw)
    assert "cancel" in live_halt.live_rec.calls
    assert "cancel" not in live_halt.dry_rec.calls

    # The mirror: a dry-book halt takes the dry orders and leaves the live ones.
    dry_halt = two_books()
    live_cid, dry_cid = rest_one_on_each(dry_halt)
    dry_halt.gateway.halt("dry portfolio drawdown", DRY)
    dry_halt.runner.cycle()

    assert dry_cid not in open_cids(dry_halt._dry_raw)
    assert live_cid in open_cids(dry_halt._live_sim)
    assert "cancel" in dry_halt.dry_rec.calls
    assert "cancel" not in dry_halt.live_rec.calls

    # The global halt still sweeps both books.
    killed = two_books()
    live_cid, dry_cid = rest_one_on_each(killed)
    killed.gateway.halt("kill switch")
    killed.runner.cycle()

    assert dry_cid not in open_cids(killed._dry_raw)
    assert live_cid not in open_cids(killed._live_sim)
    assert "cancel" in killed.dry_rec.calls
    assert "cancel" in killed.live_rec.calls

    # No halt at all: nothing is swept on either book.
    quiet = two_books()
    live_cid, dry_cid = rest_one_on_each(quiet)
    quiet.runner.cycle()

    assert dry_cid in open_cids(quiet._dry_raw)
    assert live_cid in open_cids(quiet._live_sim)
    assert "cancel" not in quiet.dry_rec.calls
    assert "cancel" not in quiet.live_rec.calls


def test_stale_stopped_bot_does_not_block_halt_clear(engines):
    """A stopped bot with nothing left cannot make a book unpriceable."""
    fresh = engines()
    store = fresh.store
    store.create_bot("b9", "BTC-USDC", "grid", dict(GRID_PARAMS), D("0"), D("0"))
    store.set_bot_status("b9", STOPPED)

    # Nothing was ever polled for b9's product, and b9 holds nothing there.
    equity = D("100") + D("50") * MID
    assert fresh.gateway.portfolio_equity(DRY) == equity

    fresh.snapshots.put(
        MarketSnapshot(
            "BTC-USDC",
            D("9"),
            D("10"),
            D("9"),
            D("10"),
            time.time() - 10 * fresh.limits.poll_seconds,
        )
    )
    assert fresh.gateway.portfolio_equity(DRY) == equity

    # The same stopped bot still holding something on that product is part of
    # the mark: an unpriced holding is unknown, never zero.
    store.set_bot_book(
        "b9",
        mode=DRY,
        capital_quote=D("5"),
        capital_base=D("1"),
        live_capital_quote=None,
        live_capital_base=None,
    )
    assert fresh.gateway.portfolio_equity(DRY) is None

    # A book that still cannot be priced is cleared with its mark reset, while a
    # priced book is re-based to its equity.
    engine = engines(env={"CROW_COINBASE_PRODUCTS": f"{PRODUCT},BTC-USDC"})
    held = engine.store
    held.create_bot(
        "b2", "BTC-USDC", "grid", dict(GRID_PARAMS), D("0"), D("0")
    )
    engine.set_live("b2", D("10"), D("5"))
    engine.prime()
    assert engine.snapshots.get("BTC-USDC") is None
    assert engine.gateway.portfolio_equity(LIVE) is None
    equity_dry = engine.gateway.portfolio_equity(DRY)
    assert equity_dry is not None

    held.update_hwm(PORTFOLIO_OWNER, D("1000"), DRY)
    held.update_hwm(PORTFOLIO_OWNER, D("1000"), LIVE)
    engine.gateway.halt("dry portfolio drawdown", DRY)
    engine.gateway.halt("live portfolio drawdown", LIVE)

    app = make_app(engine, require_privileged=lambda request: None)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        cleared = client.post("/halt/clear", json={"acknowledge_rebase": True})

    assert cleared.status_code == 200, cleared.text
    body = cleared.json()
    assert body["halted"] is False
    assert body["rebased"][f"{PORTFOLIO_OWNER}:{LIVE}"] is None
    assert D(body["rebased"][f"{PORTFOLIO_OWNER}:{DRY}"]) == equity_dry
    assert held.hwm(PORTFOLIO_OWNER, LIVE) is None
    assert held.hwm(PORTFOLIO_OWNER, DRY) == equity_dry
    assert engine.gateway.is_halted() is False
    assert engine.gateway.is_halted(DRY) is False
    assert engine.gateway.is_halted(LIVE) is False


# ---------------------------------------------------------------- WAL (folded low)

REAL_CONNECT = sqlite3.connect


class _FakeCursor:
    """The one result row a `PRAGMA journal_mode` read needs."""

    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return (self.value,)


def patch_wal(monkeypatch, steps):
    """Answer the WAL pragma from *steps*; record attempts and closes."""
    state = {"attempts": 0, "closed": 0}

    class Flaky(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if str(sql).strip().lower().startswith("pragma journal_mode"):
                state["attempts"] += 1
                step = steps.pop(0) if steps else "wal"
                if isinstance(step, Exception):
                    raise step
                return _FakeCursor(step)
            return super().execute(sql, *args, **kwargs)

        def close(self):
            state["closed"] += 1
            return super().close()

    def connect(*args, **kwargs):
        kwargs["factory"] = Flaky
        return REAL_CONNECT(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect)
    monkeypatch.setattr(store_module.time, "sleep", lambda seconds: None)
    return state


def sqlite_failure(message, code=None):
    error = sqlite3.OperationalError(message)
    if code is not None:
        error.sqlite_errorcode = code
    return error


def test_wal_retry_only_on_busy_or_locked(tmp_path, monkeypatch):
    # Busy twice (the second an extended code), then WAL: the store opens.
    state = patch_wal(
        monkeypatch,
        [
            sqlite_failure("busy", sqlite3.SQLITE_BUSY),
            sqlite_failure("busy", sqlite3.SQLITE_BUSY | (9 << 8)),
            "wal",
        ],
    )
    store = Store(tmp_path / "retried.db")
    try:
        assert store.schema_version() == SCHEMA_VERSION
    finally:
        store.close()
    assert state["attempts"] == 3

    # LOCKED is the other retryable code.
    state = patch_wal(
        monkeypatch, [sqlite_failure("locked", sqlite3.SQLITE_LOCKED), "wal"]
    )
    locked = Store(tmp_path / "locked.db")
    try:
        assert locked.schema_version() == SCHEMA_VERSION
    finally:
        locked.close()
    assert state["attempts"] == 2

    # Any other OperationalError is raised at once, after one attempt.
    for index, error in enumerate(
        (sqlite_failure("no WAL for you"), sqlite_failure("disk", sqlite3.SQLITE_IOERR))
    ):
        state = patch_wal(monkeypatch, [error])
        with pytest.raises(sqlite3.OperationalError):
            Store(tmp_path / f"failed{index}.db")
        assert state["attempts"] == 1
        assert state["closed"] >= 1


def test_wal_must_report_wal(tmp_path, monkeypatch):
    state = patch_wal(monkeypatch, ["delete"])
    with pytest.raises(
        sqlite3.OperationalError, match="could not switch the database to WAL mode"
    ):
        Store(tmp_path / "not-wal.db")
    assert state["attempts"] == 1
    assert state["closed"] >= 1


# ---------------------------------------------------------------- pause sweeps the book
#
# Pausing a bot has to take the bot out of the market, not only out of the cycle:
# the runner skips a PAUSED bot, so a waiting order left on the exchange would go
# on filling with nothing to answer it.  Every test here goes through the route
# (`POST /bots/{id}/pause`) against a real engine, so what is asserted is what an
# owner's request actually did.


def open_cids_on(exchange):
    """The client order ids still resting on one exchange, as plain strings."""
    return {
        str(order.get("client_order_id") or "")
        for order in exchange.list_open_orders(None)
    }


def test_pause_cancels_only_that_bots_live_orders(engines):
    """Pause sweeps the paused bot's live book, and no other bot's."""
    engine = engines()
    store = engine.store
    engine.switches.set("live_enabled", True)
    engine.set_live(BOT, D("100"), D("100"))
    engine.add_bot("b2", capital_quote=D("0"), capital_base=D("0"))
    engine.set_live("b2", D("100"), D("100"))

    mine = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    other = engine.gateway.submit("bot", "b2", place_intent(), PRODUCT)
    assert mine.ok is True and mine.cid
    assert other.ok is True and other.cid
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=LIVE)
    assert store.orders(owner="b2", statuses=LIVE_STATUSES, book=LIVE)
    assert mine.cid in open_cids_on(engine._live_sim)
    assert other.cid in open_cids_on(engine._live_sim)

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
    assert paused.status_code == 200, paused.text

    # The paused bot is off the live book, in the store and on the exchange.
    resting = open_cids_on(engine._live_sim)
    assert mine.cid not in resting
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=LIVE) == []
    assert store.get_bot(BOT)["status"] == PAUSED

    # The other live bot's waiting order is untouched.
    assert other.cid in resting
    assert store.orders(owner="b2", statuses=LIVE_STATUSES, book=LIVE)
    assert store.get_bot("b2")["status"] == ACTIVE


def test_pause_cancels_dry_orders(engines):
    """A dry bot's waiting orders are swept too, and a neighbour's are not."""
    engine = engines()
    store = engine.store
    engine.add_bot("d2", capital_quote=D("100"), capital_base=D("0"))

    mine = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    other = engine.gateway.submit("bot", "d2", place_intent(), PRODUCT)
    assert mine.ok is True and mine.cid
    assert other.ok is True and other.cid
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=DRY)
    assert store.orders(owner="d2", statuses=LIVE_STATUSES, book=DRY)

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
    assert paused.status_code == 200, paused.text

    resting = open_cids_on(engine._dry_raw)
    assert mine.cid not in resting
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=DRY) == []
    assert store.get_bot(BOT)["status"] == PAUSED

    assert other.cid in resting
    assert store.orders(owner="d2", statuses=LIVE_STATUSES, book=DRY)
    assert store.get_bot("d2")["status"] == ACTIVE


def test_pause_cancel_failure_keeps_bot_paused_and_answers_502(engines):
    """A sweep that fails answers 502 without the reason, and Pause can be retried."""
    engine = engines()
    store = engine.store
    engine.switches.set("live_enabled", True)
    engine.set_live(BOT, D("100"), D("100"))
    placed = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert placed.ok is True and placed.cid
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=LIVE)

    secret = "secret-exchange-text-xyz"
    real_cancel_all = engine.gateway.cancel_all

    def explode(*args, **kwargs):
        raise RuntimeError(secret)

    engine.gateway.cancel_all = explode
    try:
        app = make_app(engine)
        with TestClient(app, raise_server_exceptions=False) as client:
            client.headers.update(HEADERS)
            failed = client.post(f"/bots/{BOT}/pause")
    finally:
        engine.gateway.cancel_all = real_cancel_all

    assert failed.status_code == 502, failed.text
    # The exception's own text never reaches the owner.
    assert secret not in failed.text
    assert failed.json()["detail"].startswith("PAUSE_INCOMPLETE")
    # The bot is out of the cycle whatever the sweep did, and the order is still
    # resting: only the retry can take it off.
    assert store.get_bot(BOT)["status"] == PAUSED
    assert placed.cid in open_cids_on(engine._live_sim)
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=LIVE)

    # Pause again once the exchange answers: a PAUSED bot is retried, not a 409.
    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        retried = client.post(f"/bots/{BOT}/pause")
    assert retried.status_code == 200, retried.text
    assert retried.json()["status"] == PAUSED
    assert placed.cid not in open_cids_on(engine._live_sim)
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=LIVE) == []


def test_pause_live_without_exchange_is_502_and_stays_paused(engines):
    """A live book with no exchange is a 502, and the bot stays PAUSED."""
    engine = engines()
    store = engine.store
    engine.switches.set("live_enabled", True)
    engine.set_live(BOT, D("100"), D("100"))
    placed = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert placed.ok is True and placed.cid
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=LIVE)
    before = order_state(store, BOT)

    # The live account is gone: nothing can sweep that book.
    engine.gateway.books = BookRouter(engine.dry, None)

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        failed = client.post(f"/bots/{BOT}/pause")

    assert failed.status_code == 502, failed.text
    assert failed.json()["detail"].startswith("PAUSE_INCOMPLETE")
    assert "the live book has no exchange" not in failed.text
    assert store.get_bot(BOT)["status"] == PAUSED
    # The rows are exactly where they were: a failed sweep writes no cancel.
    assert order_state(store, BOT) == before


def test_resume_after_pause_places_orders_again(engines):
    """Pause stops the book being traded; resume lays a fresh one."""
    engine = engines()
    store = engine.store

    engine.runner.cycle()
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=DRY)

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
        assert paused.status_code == 200, paused.text
        assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=DRY) == []

        # A paused bot is not processed, so a cycle lays nothing for it.
        engine.runner.cycle()
        assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=DRY) == []

        resumed = client.post(
            f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text

    assert store.get_bot(BOT)["status"] == ACTIVE

    # A resumed bot lays a fresh book: the pause leaves the bot ready for its
    # first book again (its grid re-initialises), so the next ACTIVE cycle
    # places the levels the cancel took off.
    engine.runner.cycle()
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=DRY)


REBALANCE_PARAMS = {
    "target_base_pct": 50,
    "band_pts": 7.5,
    "min_trade_quote": 2,
    "reprice_after_s": 600,
}


def test_pause_for_rebalance_bot_cancels_and_resume_replaces(engines):
    """A rebalancer's one waiting order is swept by Pause and replaced on resume."""
    engine = engines()
    store = engine.store
    # The grid bot the engine starts with is stopped, so the rebalancer is the
    # only thing trading and its order is the only one on the dry book.
    store.set_bot_status(BOT, STOPPED)
    engine.add_bot(
        "rb1",
        capital_quote=D("100"),
        capital_base=D("0"),
        strategy="rebalance",
        params=REBALANCE_PARAMS,
    )

    engine.runner.cycle()
    resting = store.orders(owner="rb1", statuses=LIVE_STATUSES, book=DRY)
    assert resting, "the rebalancer should have an order resting after a cycle"
    for row in resting:
        assert row["client_order_id"] in open_cids_on(engine._dry_raw)

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post("/bots/rb1/pause")
        assert paused.status_code == 200, paused.text
        assert paused.json()["status"] == PAUSED
        assert store.orders(owner="rb1", statuses=LIVE_STATUSES, book=DRY) == []
        for row in resting:
            assert row["client_order_id"] not in open_cids_on(engine._dry_raw)

        resumed = client.post(
            "/bots/rb1/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text

    # The weight is still out of band, so the next tick trades again: a fresh
    # order rests where the cancelled one did.
    engine.runner.cycle()
    replaced = store.orders(owner="rb1", statuses=LIVE_STATUSES, book=DRY)
    assert replaced
    assert {row["client_order_id"] for row in replaced}.isdisjoint(
        {row["client_order_id"] for row in resting}
    )


def test_pause_event_recorded(engines):
    """A pause that swept the book says so once, as `bot_paused`, and names no secret."""
    engine = engines()
    store = engine.store
    placed = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert placed.ok is True and placed.cid

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
        assert paused.status_code == 200, paused.text

    rows = store.conn().execute(
        "SELECT level, kind, owner, message, data_json FROM events "
        "WHERE kind=? AND owner=?",
        ("bot_paused", BOT),
    ).fetchall()
    assert rows, "the pause wrote no bot_paused event for the bot"
    latest = rows[-1]
    assert latest["owner"] == BOT
    message = str(latest["message"])
    assert "paus" in message.lower()
    # An event is a reader's account of what the request did: no token, no
    # exchange text, no exception text.
    assert TOKEN not in message
    assert TOKEN not in str(latest["data_json"] or "")


def test_pause_stays_bearer_only(engines):
    """A live bot's pause is the bearer token's alone, as it always was."""
    engine = engines()
    store = engine.store
    engine.switches.set("live_enabled", True)
    engine.set_live(BOT, D("100"), D("100"))
    placed = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert placed.ok is True and placed.cid

    # The module's own privileged gate denies every request (no approval wired
    # in), exactly as in test_live_bot_recenter_update_resume_need_mac: a pause
    # needs the owner's token and never the owner's approval.
    deny_app = make_app(engine)
    with TestClient(deny_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
    assert paused.status_code == 200, paused.text

    assert store.get_bot(BOT)["status"] == PAUSED
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=LIVE) == []
    assert placed.cid not in open_cids_on(engine._live_sim)


# ---------------------------------------------------------------- the pause fix
#
# A pause has to leave a bot exactly as the next cycle needs to find it: out of
# the market, with no fill still waiting for an answer, and ready to lay its
# WHOLE grid again.  These tests trade a real book into that state first, moving
# the price with candles (the way the dry-run exchange fills), so what a pause
# finds is not the tidy book a bot is created with.


# Wide enough that a test is about the pause rather than about a spent cap.
WIDE_ENV = {
    "CROW_COINBASE_DAILY_NOTIONAL_USD": "1000000",
    "CROW_COINBASE_ORDERS_PER_HOUR": "100000",
}


def _live_rows(store, bot, book=DRY):
    """One bot's live orders on one book, as their (side, level), oldest first."""
    return [
        (row["side"], row["level"])
        for row in store.orders(owner=bot, statuses=LIVE_STATUSES, book=book)
    ]


def _awaiting_opposite(store, bot, book=DRY):
    """The rows carrying a fill that is still waiting for its opposite order."""
    from crow_coinbase.store import OPP_TODO

    return [
        row
        for row in store.orders(owner=bot, book=book)
        if row["filled_size"] > 0 and row["opposite"] == OPP_TODO
    ]


def _bot_events(store, kind, bot):
    """The events of one kind written for one bot, oldest first."""
    return store.conn().execute(
        "SELECT id, level, kind, owner, message, data_json FROM events "
        "WHERE kind=? AND owner=? ORDER BY id",
        (kind, bot),
    ).fetchall()


def _move(engine, bid, ask):
    """Move the fake market, and give it ONE candle traded at those prices.

    The candle starts a second ahead of now, so it fills the orders that were
    already resting when the market moved and none of the ones placed after it:
    the pattern a real book shows the dry-run exchange.  The snapshot is primed
    so the next cycle (and a resume) prices the bot off the price it now sees.
    """
    low, high = D(bid), D(ask)
    engine.market.bid, engine.market.ask = low, high
    engine.market.low, engine.market.high = low, high
    stamp = time.time() + 1
    engine.market.candles = (
        lambda start, end, _low=low, _high=high, _stamp=stamp: [
            {"start": _stamp, "low": _low, "high": _high}
        ]
    )
    engine.prime()


def test_pause_resume_relays_the_whole_grid_after_trading(engines):
    """Pause and resume lay every level of the grid again, not one of six."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    fresh = _live_rows(store, BOT)
    assert len(fresh) == 6, fresh
    grid = set(fresh)

    # Trade the price down, up, down and up: fills and re-placements happen, so
    # the grid a pause finds is not the one it was first laid with.
    for bid, ask in (
        ("0.97", "0.975"),
        ("0.99", "1.00"),
        ("0.97", "0.975"),
        ("0.99", "1.00"),
    ):
        _move(engine, bid, ask)
        time.sleep(1.2)
        engine.runner.cycle()

    assert store.orders(owner=BOT, statuses=(FILLED,), book=DRY), (
        "the grid should have filled something before the pause"
    )

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
        assert paused.status_code == 200, paused.text
        resumed = client.post(
            f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text

    for _ in range(4):
        engine.runner.cycle()

    assert set(_live_rows(store, BOT)) == grid, (
        "the resumed grid is not the whole grid the bot traded before the pause"
    )
    assert _awaiting_opposite(store, BOT) == [], (
        "a paused-then-resumed bot still holds a fill waiting for an opposite"
    )


def test_fill_during_pause_sweep_is_not_left_awaiting_an_opposite(engines):
    """A fill the pause's own sweep books is retired, so resume lays one grid."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    fresh = set(_live_rows(store, BOT))
    assert len(fresh) == 6, fresh

    # One buy fills on the exchange itself, before any cycle has seen it: the
    # pause is what reconciles it, so the fill is booked by the sweep.
    _move(engine, "0.98", "0.9825")
    time.sleep(1.2)
    engine._dry_raw.advance(time.time() + 60)
    _move(engine, "0.99", "1.00")

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
        assert paused.status_code == 200, paused.text

        traded = [
            row
            for row in store.orders(owner=BOT, book=DRY)
            if row["filled_size"] > 0
        ]
        assert traded, "the buy should have filled before the pause"
        assert _awaiting_opposite(store, BOT) == [], (
            "a fill booked by the pause is left waiting for an opposite order"
        )

        resumed = client.post(
            f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text

    for _ in range(4):
        engine.runner.cycle()

    rows = _live_rows(store, BOT)
    assert set(rows) == fresh, rows
    assert len(rows) == len(set(rows)), f"a level is resting twice: {rows}"
    assert _awaiting_opposite(store, BOT) == []


def test_rebalance_bot_pause_resume_after_trading(engines):
    """A rebalancer comes back from a pause with exactly the order it held."""

    def prepared(build):
        """A stopped grid bot and one fresh rebalancer, its first order resting."""
        engine = build(env=dict(WIDE_ENV))
        engine.store.set_bot_status(BOT, STOPPED)
        engine.add_bot(
            "rb1",
            capital_quote=D("100"),
            capital_base=D("0"),
            strategy="rebalance",
            params=REBALANCE_PARAMS,
        )
        engine.runner.cycle()
        first = _live_rows(engine.store, "rb1")
        assert len(first) == 1, first
        return engine

    def trade_once(engine):
        """Fill the resting order on the exchange, then move the price back up."""
        _move(engine, "0.98", "0.9825")
        time.sleep(1.2)
        engine._dry_raw.advance(time.time() + 60)
        _move(engine, "1.40", "1.405")

    engine = prepared(engines)
    store = engine.store
    trade_once(engine)

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post("/bots/rb1/pause")
        assert paused.status_code == 200, paused.text

        traded = [
            row
            for row in store.orders(owner="rb1", book=DRY)
            if row["filled_size"] > 0
        ]
        assert traded, "the rebalancer should have traded before the pause"
        assert _awaiting_opposite(store, "rb1") == [], (
            "the pause left a rebalancer fill waiting for an opposite order"
        )

        resumed = client.post(
            "/bots/rb1/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text

    for _ in range(2):
        engine.runner.cycle()

    rows = _live_rows(store, "rb1")
    sides = [side for side, _level in rows]
    assert len(sides) == len(set(sides)), f"two orders of one side rest: {rows}"
    assert _awaiting_opposite(store, "rb1") == []

    # A rebalancer that was never paused holds the same order at rest, so the
    # pause left no doubled side behind and nothing missing.
    mirror = prepared(engines)
    trade_once(mirror)
    mirror.runner.cycle()
    mirror.runner.cycle()
    assert rows == _live_rows(mirror.store, "rb1")


def test_pause_does_not_hold_the_lock_while_waiting(engines):
    """A pause waits between passes without the lock, so /kill answers at once."""
    import threading

    engine = engines()
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT), "the bot needs orders a sweep cannot settle"

    engine.gateway.cancel_all = lambda *args, **kwargs: 0
    waiting = threading.Event()

    def wait_outside(seconds):
        """The pause's wait between passes: it must not be holding the lock."""
        waiting.set()
        time.sleep(0.4)

    engine.runner.sleep = wait_outside
    app = make_app(engine)
    answer = {}

    def press_pause():
        with TestClient(app, raise_server_exceptions=False) as client:
            client.headers.update(HEADERS)
            answer["pause"] = client.post(f"/bots/{BOT}/pause")

    thread = threading.Thread(target=press_pause)
    thread.start()
    try:
        assert waiting.wait(10), "the pause never reached its wait"
        started = time.monotonic()
        with TestClient(app, raise_server_exceptions=False) as client:
            client.headers.update(HEADERS)
            killed = client.post("/kill")
        elapsed = time.monotonic() - started
    finally:
        thread.join(timeout=60)

    assert not thread.is_alive(), "the pause never answered"
    assert killed.status_code == 200, killed.text
    assert killed.json()["halted"] is True
    assert elapsed < 2.0, f"the kill waited {elapsed:.2f}s behind the pause"

    paused = answer["pause"]
    # A kill that swept the book is not a pause that failed: the bot was changed
    # under the pause (it is STOPPED now), which is its own refusal and its own
    # answer, with nothing claimed about orders left behind.
    assert paused.status_code == 409, paused.text
    assert paused.json()["detail"].startswith("PAUSE_CHANGED")
    assert _bot_events(store, "alert", BOT) == []
    assert _bot_events(store, "bot_paused", BOT) == []
    # The kill's STOPPED is what the bot is: the pause's own final step must not
    # write PAUSED over it.
    assert store.get_bot(BOT)["status"] == STOPPED


def test_pause_stops_when_halted(engines):
    """A halt raised while the pause waits ends the pause, not the retries."""
    engine = engines()
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT), "the bot needs orders a sweep cannot settle"

    engine.gateway.cancel_all = lambda *args, **kwargs: 0
    waits = []

    def halt_on_first_wait(seconds):
        waits.append(seconds)
        if len(waits) == 1:
            engine.gateway.halt("test")
        time.sleep(0.4)

    engine.runner.sleep = halt_on_first_wait
    app = make_app(engine)
    started = time.monotonic()
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
    elapsed = time.monotonic() - started

    assert paused.status_code == 502, paused.text
    assert paused.json()["detail"].startswith("PAUSE_INCOMPLETE")
    assert len(waits) <= 2, f"the pause kept waiting after the halt: {len(waits)}"
    assert elapsed < 2.0, f"the pause took {elapsed:.2f}s after the halt"
    assert store.get_bot(BOT)["status"] == PAUSED


def test_pause_again_within_ten_seconds_is_debounced(engines):
    """A second pause of a bot just asked to pause is a 429, and sweeps nothing."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT)

    # The debounce is read off the app's clock (`create_app(now=...)`), so the
    # clock the app is built with is one the test moves.
    clock = {"now": time.time()}
    engine.now = lambda: clock["now"]

    real_cancel_all = engine.gateway.cancel_all
    sweeps = []

    def never_settles(*args, **kwargs):
        sweeps.append((args, kwargs))
        return 0

    engine.gateway.cancel_all = never_settles
    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        first = client.post(f"/bots/{BOT}/pause")
        assert first.status_code == 502, first.text
        assert store.get_bot(BOT)["status"] == PAUSED
        swept = len(sweeps)
        assert swept, "the failed pause should still have swept"

        again = client.post(f"/bots/{BOT}/pause")
        assert again.status_code == 429, again.text
        assert again.json()["detail"].startswith("PAUSE_TOO_SOON")
        assert len(sweeps) == swept, "a debounced pause swept the book anyway"

        clock["now"] += 11
        engine.gateway.cancel_all = real_cancel_all
        third = client.post(f"/bots/{BOT}/pause")
        assert third.status_code == 200, third.text

        # A bot that is ACTIVE is never debounced, even right after a resume.
        resumed = client.post(
            f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text
        fourth = client.post(f"/bots/{BOT}/pause")
        assert fourth.status_code == 200, fourth.text


def test_pause_events_are_quiet_and_tagged(engines):
    """A pause says `bot_paused` once when it did something, and alerts once an episode."""
    import json

    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT)

    clock = {"now": time.time()}
    engine.now = lambda: clock["now"]
    real_cancel_all = engine.gateway.cancel_all

    def arm(client):
        """An ACTIVE bot with a book resting again."""
        resumed = client.post(
            f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text
        engine.runner.cycle()
        assert _live_rows(store, BOT), "the bot laid no book to sweep"

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)

        # A successful pause of an ACTIVE bot is ONE event, tagged to its owner.
        first = client.post(f"/bots/{BOT}/pause")
        assert first.status_code == 200, first.text
        events = _bot_events(store, "bot_paused", BOT)
        assert len(events) == 1, events
        data = json.loads(events[0]["data_json"] or "{}")
        assert data.get("reason") == "owner", data

        # Nothing was left on the book, so a second pause (a clock apart) is quiet.
        clock["now"] += 11
        quiet = client.post(f"/bots/{BOT}/pause")
        assert quiet.status_code == 200, quiet.text
        assert len(_bot_events(store, "bot_paused", BOT)) == 1

        # Two failing pauses, a clock apart, are ONE alert for the episode.
        engine.gateway.cancel_all = lambda *args, **kwargs: 0
        arm(client)
        clock["now"] += 11
        failed = client.post(f"/bots/{BOT}/pause")
        assert failed.status_code == 502, failed.text
        clock["now"] += 11
        failed_again = client.post(f"/bots/{BOT}/pause")
        assert failed_again.status_code == 502, failed_again.text
        assert len(_bot_events(store, "alert", BOT)) == 1

        # A pause that completes ends the episode, so a later failure is news.
        engine.gateway.cancel_all = real_cancel_all
        clock["now"] += 11
        recovered = client.post(f"/bots/{BOT}/pause")
        assert recovered.status_code == 200, recovered.text

        engine.gateway.cancel_all = lambda *args, **kwargs: 0
        arm(client)
        clock["now"] += 11
        failed_later = client.post(f"/bots/{BOT}/pause")
        assert failed_later.status_code == 502, failed_later.text
        assert len(_bot_events(store, "alert", BOT)) == 2


# ---------------------------------------------------------------- the pause fix, again
#
# Cancelling is the kill path, and the kill path works while a book is halted, so
# a halt is never a reason to skip a cancel.  A halt, a kill, a stop or any other
# change to the bot row while a pause is waiting is a reason to STOP WAITING: the
# pause writes nothing then, and says the bot was changed rather than claiming
# orders may still be resting.  And for as long as a pause is in flight, the bot
# cannot be resumed, recentered or moved to the other book — those routes refuse
# instead of racing the sweep — while the bot does carry WHY it was paused, so an
# owner pause and a drawdown stop do not read alike.


def test_pause_cancels_while_the_book_is_halted(engines):
    """A halt stops trading, never the cancel: Pause still takes the book off."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    placed = engine.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert placed.ok is True and placed.cid
    assert placed.cid in open_cids_on(engine._dry_raw)

    engine.gateway.halt("test")
    assert engine.gateway.is_halted(DRY) is True

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")

    assert paused.status_code == 200, paused.text
    assert paused.json()["status"] == PAUSED
    # The order is off the exchange and its row is no longer live, whatever the
    # halt says about placing anything new.
    assert placed.cid not in open_cids_on(engine._dry_raw)
    assert _live_rows(store, BOT, DRY) == []
    assert store.orders(owner=BOT, statuses=LIVE_STATUSES, book=DRY) == []
    # The pause took the book off; it did not lift the halt that was in force.
    assert engine.gateway.is_halted() is True

    # The same on the live book, halted on its own.
    live = engines(env=dict(WIDE_ENV))
    live.switches.set("live_enabled", True)
    live.set_live(BOT, D("100"), D("100"))
    live_placed = live.gateway.submit("bot", BOT, place_intent(), PRODUCT)
    assert live_placed.ok is True and live_placed.cid
    assert live_placed.cid in open_cids_on(live._live_sim)

    live.gateway.halt("test", LIVE)
    assert live.gateway.is_halted(LIVE) is True

    live_app = make_app(live)
    with TestClient(live_app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        live_paused = client.post(f"/bots/{BOT}/pause")

    assert live_paused.status_code == 200, live_paused.text
    assert live_paused.json()["status"] == PAUSED
    assert live_placed.cid not in open_cids_on(live._live_sim)
    assert _live_rows(live.store, BOT, LIVE) == []
    assert live.store.orders(owner=BOT, statuses=LIVE_STATUSES, book=LIVE) == []
    assert live.gateway.is_halted(LIVE) is True


def test_kill_during_pause_is_not_an_incomplete_pause_alert(engines):
    """A kill under a waiting pause is a change, not a pause that failed."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT, DRY)

    real_cancel_all = engine.gateway.cancel_all
    engine.gateway.cancel_all = lambda *args, **kwargs: 0
    app = make_app(engine)
    answers = {}
    waits = []

    def kill_on_the_first_wait(seconds):
        """The pause's wait between passes: run a real kill in the middle of it."""
        waits.append(seconds)
        if len(waits) > 1:
            return
        # The kill does the sweeping: only the pause's own sweep is the no-op.
        engine.gateway.cancel_all = real_cancel_all
        with TestClient(app, raise_server_exceptions=False) as client:
            client.headers.update(HEADERS)
            answers["kill"] = client.post("/kill")

    engine.runner.sleep = kill_on_the_first_wait
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")

    assert answers["kill"].status_code == 200, answers["kill"].text
    assert waits, "the pause never reached its wait"
    # The bot was stopped under the pause, so the pause writes nothing: not the
    # PAUSED row, not a `bot_paused` event, and above all not the "orders may
    # still be on Coinbase" alert for a book the kill already swept.
    assert paused.status_code == 409, paused.text
    assert paused.json()["detail"].startswith("PAUSE_CHANGED")
    assert store.get_bot(BOT)["status"] == STOPPED
    assert _bot_events(store, "alert", BOT) == []
    assert _bot_events(store, "bot_paused", BOT) == []


def test_pause_in_progress_blocks_resume_recenter_and_mode(engines):
    """While a pause is sweeping, the other routes refuse rather than race it."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT, DRY)

    real_cancel_all = engine.gateway.cancel_all
    engine.gateway.cancel_all = lambda *args, **kwargs: 0
    app = make_app(engine, require_privileged=lambda request: None)
    blocked = {}
    injected = []

    def press_the_other_buttons(seconds):
        """The pause's wait between passes: ask the other three routes to move."""
        if injected:
            return
        injected.append(seconds)
        # The pause's own sweep is the only no-op from here on: the rest of the
        # engine works, so what these three answer is about the pause alone.
        engine.gateway.cancel_all = real_cancel_all
        with TestClient(app, raise_server_exceptions=False) as client:
            client.headers.update(HEADERS)
            blocked["resume"] = client.post(
                f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
            )
            blocked["recenter"] = client.post(
                f"/bots/{BOT}/recenter", json={"center": "1.1"}
            )
            blocked["mode"] = client.post(
                f"/bots/{BOT}/mode",
                json={
                    "mode": "live",
                    "capital_quote": "20",
                    "capital_base": "5",
                    "acknowledge_live": True,
                },
            )

    engine.runner.sleep = press_the_other_buttons
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")

        assert injected, "the pause never reached its wait"
        assert sorted(blocked) == ["mode", "recenter", "resume"]
        for name, answer in sorted(blocked.items()):
            assert answer.status_code == 409, (name, answer.text)
            assert answer.json()["detail"].startswith("PAUSE_IN_PROGRESS"), (
                name,
                answer.text,
            )

        # Once the sweep is allowed to settle, the pause finishes and the bot is
        # left paused on the book and the mode it had.
        assert paused.status_code == 200, paused.text
        assert paused.json()["status"] == PAUSED
        assert paused.json()["mode"] == DRY
        assert store.get_bot(BOT)["mode"] == DRY
        assert store.get_bot(BOT)["status"] == PAUSED

        # The flag is gone once the pause is over: a paused bot can be moved.
        recentered = client.post(f"/bots/{BOT}/recenter", json={"center": "1.1"})
        assert recentered.status_code == 200, recentered.text

        resumed = client.post(
            f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text
    assert store.get_bot(BOT)["status"] == ACTIVE


def test_pause_flag_clears_after_a_failed_pause(engines):
    """A pause that failed leaves no note behind: the resume is not refused."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT, DRY)

    # A sweep that never settles: the pause gives up after its own retries.
    engine.gateway.cancel_all = lambda *args, **kwargs: 0
    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        failed = client.post(f"/bots/{BOT}/pause")
        assert failed.status_code == 502, failed.text
        assert failed.json()["detail"].startswith("PAUSE_INCOMPLETE")
        resumed = client.post(
            f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
        )

    # The failed pause is over: "this bot is being paused" is not what a resume
    # of it is told, and the reason its pause wrote is cleared by the resume.
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["paused_reason"] is None
    assert store.get_bot(BOT)["status"] == ACTIVE


def test_pause_aborts_when_the_params_changed_under_it(engines):
    """A row changed under the pause ends it, and nothing of the pause is written."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT, DRY)

    real_cancel_all = engine.gateway.cancel_all
    engine.gateway.cancel_all = lambda *args, **kwargs: 0
    epoch_key = f"runner:init_since:{BOT}"
    epoch_before = raw_kv(store, epoch_key)
    changed = {**GRID_PARAMS, "center": "1.05"}
    injected = []

    def change_the_params(seconds):
        """The pause's wait between passes: retune the bot behind its back."""
        if injected:
            return
        injected.append(seconds)
        store.set_bot_params(BOT, dict(changed))
        engine.gateway.cancel_all = real_cancel_all

    engine.runner.sleep = change_the_params
    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")

    assert injected, "the pause never reached its wait"
    assert paused.status_code == 409, paused.text
    assert paused.json()["detail"].startswith("PAUSE_CHANGED")
    # No row of the pause's own was written: no new grid epoch, no re-init, the
    # params it would have written back are the ones the pause found, and no
    # event claims it paused anything.
    assert raw_kv(store, epoch_key) == epoch_before
    assert store.get_bot(BOT)["params"] == changed
    assert _bot_events(store, "bot_paused", BOT) == []


def test_paused_reason(engines):
    """A paused bot says why: the owner's pause, then the drawdown's own stop."""
    engine = engines()
    store = engine.store
    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)

        paused = client.post(f"/bots/{BOT}/pause")
        assert paused.status_code == 200, paused.text
        assert paused.json()["paused_reason"] == "owner"
        listed = {row["id"]: row for row in client.get("/bots").json()}
        assert listed[BOT]["paused_reason"] == "owner"

        resumed = client.post(
            f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
        )
        assert resumed.status_code == 200, resumed.text
        assert resumed.json()["paused_reason"] is None
        listed = {row["id"]: row for row in client.get("/bots").json()}
        assert listed[BOT]["paused_reason"] is None

    # The runner's own drawdown stop writes its own reason, not the owner's.
    store.update_hwm(BOT, D("1000"), DRY)
    engine.runner._check_drawdowns()
    assert store.get_bot(BOT)["status"] == PAUSED

    with TestClient(make_app(engine), raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        listed = {row["id"]: row for row in client.get("/bots").json()}
    reason = listed[BOT]["paused_reason"]
    assert isinstance(reason, str) and reason
    assert reason != "owner"


# ---------------------------------------------------------------- the note a pause leaves
#
# A pause writes WHY a bot is paused under the kv key `bot:paused_reason:<id>`.
# The note belongs to the pause, so it goes with the status: a bot that is
# stopped, or one the kill switch swept and stopped, is no longer paused for a
# reason.  And a note that is still in the store for a bot that is NOT paused is
# nobody's answer — the reason is reported only while the row says PAUSED — so a
# stale key never reads as an owner's pause.  A pause already sweeping its bot is
# also the answer to a second press: it is refused as a pause in flight and it
# sweeps nothing.


def test_stop_clears_the_paused_reason(engines):
    """A stopped bot carries no pause note: not in its row, not in the kv."""
    engine = engines()
    store = engine.store
    key = f"bot:paused_reason:{BOT}"
    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
        assert paused.status_code == 200, paused.text
        assert paused.json()["paused_reason"] == "owner"
        assert store.get(key) == "owner"
        listed = {row["id"]: row for row in client.get("/bots").json()}
        assert listed[BOT]["paused_reason"] == "owner"

        stopped = client.post(f"/bots/{BOT}/stop")
        assert stopped.status_code == 200, stopped.text
        assert store.get_bot(BOT)["status"] == STOPPED
        listed = {row["id"]: row for row in client.get("/bots").json()}
        assert listed[BOT]["paused_reason"] is None

    # The note itself is gone, not merely hidden behind the status: the bot was
    # stopped, so there is no pause left for it to explain.
    assert store.get(key) is None


def test_kill_clears_the_paused_reason(engines):
    """The kill switch clears the pause note of every bot it stops."""
    engine = engines()
    store = engine.store
    key = f"bot:paused_reason:{BOT}"
    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")
        assert paused.status_code == 200, paused.text
        assert store.get(key) == "owner"

        killed = client.post("/kill")
        assert killed.status_code == 200, killed.text
        assert store.get_bot(BOT)["status"] == STOPPED
        listed = {row["id"]: row for row in client.get("/bots").json()}
        assert listed[BOT]["paused_reason"] is None

    assert store.get(key) is None


def test_stale_reason_is_not_reported_unless_paused(engines):
    """A note left on an ACTIVE bot is not a reason: only a PAUSED row reports one."""
    engine = engines()
    store = engine.store
    key = f"bot:paused_reason:{BOT}"
    # A key no pause of this bot wrote, as a restart or an edited file can leave
    # behind: the bot itself never was paused.
    store.put(key, "owner")
    assert store.get(key) == "owner"
    assert store.get_bot(BOT)["status"] == ACTIVE

    app = make_app(engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        listed = {row["id"]: row for row in client.get("/bots").json()}

    assert listed[BOT]["status"] == ACTIVE
    assert listed[BOT]["paused_reason"] is None


def test_second_pause_while_one_is_sweeping_is_refused(engines):
    """A second Pause of a bot whose pause is still sweeping is refused, not swept."""
    engine = engines(env=dict(WIDE_ENV))
    store = engine.store
    engine.runner.cycle()
    assert _live_rows(store, BOT, DRY)

    real_cancel_all = engine.gateway.cancel_all
    # The first pause's own sweep never settles, so it reaches its wait.
    engine.gateway.cancel_all = lambda *args, **kwargs: 0
    app = make_app(engine, require_privileged=lambda request: None)
    answers = {}
    sweeps = []
    injected = []

    def counting_cancel_all(*args, **kwargs):
        """The real sweep, counted: nothing during the hook may reach it."""
        sweeps.append(1)
        return real_cancel_all(*args, **kwargs)

    def press_pause_again(seconds):
        """The pause's wait between passes: press Pause again and ask to resume."""
        if injected:
            return
        injected.append(seconds)
        # The sweep settles from here on, so the first pause finishes; what the
        # two requests in this hook answer is about the pause in flight alone.
        engine.gateway.cancel_all = counting_cancel_all
        answers["status_in_hook"] = store.get_bot(BOT)["status"]
        before = len(sweeps)
        with TestClient(app, raise_server_exceptions=False) as client:
            client.headers.update(HEADERS)
            answers["pause"] = client.post(f"/bots/{BOT}/pause")
            answers["resume"] = client.post(
                f"/bots/{BOT}/resume", json={"acknowledge_rebase": True}
            )
        answers["swept_in_hook"] = len(sweeps) - before

    engine.runner.sleep = press_pause_again
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        paused = client.post(f"/bots/{BOT}/pause")

    assert injected, "the pause never reached its wait"
    # The first pause wrote PAUSED before it swept, so the second press came
    # against a PAUSED bot — and still earned the in-flight refusal rather than
    # the debounce's 429 or a second 200.
    assert answers["status_in_hook"] == PAUSED
    second = answers["pause"]
    assert second.status_code == 409, second.text
    assert second.json()["detail"].startswith("PAUSE_IN_PROGRESS"), second.text
    # The refused press swept nothing: no cancel reached the exchange.
    assert answers["swept_in_hook"] == 0
    # A bot whose sweep is going cannot be resumed out from under it either.
    resume = answers["resume"]
    assert resume.status_code == 409, resume.text
    assert resume.json()["detail"].startswith("PAUSE_IN_PROGRESS"), resume.text
    # The first pause was the one being answered, and it finished the job.
    assert paused.status_code == 200, paused.text
    assert paused.json()["status"] == PAUSED
    assert store.get_bot(BOT)["status"] == PAUSED
    assert _live_rows(store, BOT, DRY) == []