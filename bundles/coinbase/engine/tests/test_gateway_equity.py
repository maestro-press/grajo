"""gateway.py: the equity chain, its caps, and the one send an equity order gets.

Synthetic fixtures only.  The store holds one crypto bot; the snapshot cache
holds equity quotes (an equity print is one price, so bid == ask) and one crypto
book; the exchange is a recording stand-in that answers either the happy path or
a scripted refusal.  An equity intent is `source="ai"`, `owner="ai"`, with an
approval id, and the approvals are a fake rail written over the store's own `kv`
table: the spend goes through the connection (and so the transaction) the
gateway hands it, which is how a spend rolls back with an order row that could
not be written.

The chain exercised here, first refusal wins:

    BAD_INTENT -> WRONG_OWNER -> HALTED -> route refusal
    -> LIVE_DISABLED (an equity order on a live route with equity_live off)
    -> NO_EQUITY_ACCOUNT -> PRODUCT_NOT_ALLOWED -> APPROVAL_REQUIRED
    -> TRADING_HALTED -> LIQUIDATE_ONLY -> MARKET_CLOSED -> STALE_MARKET
    -> CLOCK_SKEW -> PRICE_BAND -> TOO_SMALL -> FRACTIONAL_NOT_ALLOWED
    -> ORDER_TOO_LARGE -> DAILY_CAP -> CAPITAL_CAP / INSUFFICIENT_HOLDING
    -> RATE_CAP -> UNALLOCATED_NEGATIVE -> DRAWDOWN_STOP

Every test runs on the real wall clock except the ones that hand the gateway a
`now` of their own: `store.insert_order` stamps `created_at` with `time.time()`
and the `CapWindow` is built on the same clock, so the caps see the rows the
tests write.
"""

import time
from decimal import Decimal as D

import pytest

import crow_coinbase.exchange as exchange_mod
from crow_coinbase import reconcile as rec
from crow_coinbase import router as router_mod
from crow_coinbase.books import BookRouter, Switches
from crow_coinbase.exchange import DryRunExchange
from crow_coinbase.gateway import (
    APPROVAL_REQUIRED,
    CAPITAL_CAP,
    CLOCK_SKEW,
    DAILY_CAP,
    DRAWDOWN_STOP,
    EXCHANGE_REJECTED,
    FRACTIONAL_NOT_ALLOWED,
    HALTED,
    INSUFFICIENT_HOLDING,
    LIQUIDATE_ONLY,
    LIVE_DISABLED,
    MARKET_CLOSED,
    NO_EQUITY_ACCOUNT,
    ORDER_TOO_LARGE,
    PORTFOLIO_OWNER,
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
from crow_coinbase.ledger import Ledger
from crow_coinbase.limits import CapWindow, Limits
from crow_coinbase.money import ProductSpec
from crow_coinbase.router import ExchangeRouter
from crow_coinbase.snapshot import SnapshotCache
from crow_coinbase.store import CANCELLED, FILLED, OPEN, REJECTED, Store
from crow_coinbase.strategies.base import MarketSnapshot, OrderIntent

# The router's recording adapter double, kept in one place so both routing and
# adoption are exercised against the same stand-in.
from test_router import Fake as FakeAdapter

# ---------------------------------------------------------------- products

NVDA = "NVDA-USD"
VOO = "VOO-USD"
XRP = "XRP-USDC"
ETH = "ETH-USD"

FEE_RATE = D("0.005")
BID = D("0.99")
ASK = D("1.00")

# An equity product: whole-or-fractional shares, cents on the price, USD quoted.
def equity_spec(product=NVDA, **overrides):
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


SPOT_SPEC = ProductSpec(
    XRP,
    price_increment=D("0.0001"),
    base_increment=D("0.1"),
    quote_increment=D("0.01"),
    base_min_size=D("1"),
    quote_min_size=D("1"),
)

SPECS = {
    NVDA: equity_spec(NVDA),
    VOO: equity_spec(VOO),
    XRP: SPOT_SPEC,
    ETH: ProductSpec(
        ETH,
        price_increment=D("0.01"),
        base_increment=D("0.0001"),
        quote_increment=D("0.01"),
        base_min_size=D("0.0001"),
        quote_min_size=D("1"),
    ),
}

# ---------------------------------------------------------------- env names

EQUITY_PRODUCTS_ENV = "CROW_COINBASE_EQUITY_PRODUCTS"
EQUITY_CAPITAL_ENV = "CROW_COINBASE_EQUITY_AI_CAPITAL_USD"
EQUITY_MAX_ORDER_ENV = "CROW_COINBASE_EQUITY_MAX_ORDER_USD"
EQUITY_DAILY_ENV = "CROW_COINBASE_EQUITY_DAILY_NOTIONAL_USD"
EQUITY_LIVE_ENV = "CROW_COINBASE_EQUITY_LIVE"
PRODUCTS_ENV = "CROW_COINBASE_PRODUCTS"
ORDERS_HOUR_ENV = "CROW_COINBASE_ORDERS_PER_HOUR"
AI_DAILY_ENV = "CROW_COINBASE_AI_DAILY_NOTIONAL_USD"
AI_MODE_ENV = "CROW_COINBASE_AI_ORDER_MODE"

# The two equity products this engine trades, and a single-order cap wide enough
# that only the test that lowers it sees ORDER_TOO_LARGE.
EQUITY_ENV = {
    EQUITY_PRODUCTS_ENV: f"{NVDA},{VOO}",
    EQUITY_MAX_ORDER_ENV: "1000",
    PRODUCTS_ENV: f"{XRP},{ETH}",
}

# A fixed instant, for the tests that hand the gateway a clock of their own.
CLOCK = 1_800_000_000.0


# ---------------------------------------------------------------- harness


class FakeExchange:
    """A dry-book stand-in that records both write paths and answers from a script.

    `reason` is the exchange's own word for a refusal; with None the order is
    accepted and answers an order id built from the client order id.  Both write
    paths are recorded, so a test can see which one an order took.
    """

    dry_run = True

    def __init__(self, *, reason=None):
        self.calls = []
        self.reason = reason

    def place_limit(self, cid, product, side, size, price):
        self.calls.append(("place_limit", cid, product, side, size, price))
        return self._answer(cid)

    def place_equity_limit(self, cid, product, side, size, price):
        self.calls.append(("place_equity_limit", cid, product, side, size, price))
        return self._answer(cid)

    def _answer(self, cid):
        if self.reason is not None:
            return {"ok": False, "order_id": None, "reason": self.reason}
        return {"ok": True, "order_id": "ex-" + cid, "reason": None}

    def totals(self):
        return {}

    def list_open_orders(self, product=None):
        return []

    def cancel(self, order_ids):
        return {order_id: True for order_id in order_ids}


class RecordingDry(DryRunExchange):
    """The real simulator, with both write paths recorded as they are called."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = []

    def place_limit(self, cid, product, side, size, price):
        self.calls.append(("place_limit", cid, product, side, size, price))
        return super().place_limit(cid, product, side, size, price)

    def place_equity_limit(self, cid, product, side, size, price):
        self.calls.append(("place_equity_limit", cid, product, side, size, price))
        return super().place_equity_limit(cid, product, side, size, price)


class RecordingExchange:
    """Any attribute access records its name; a refused route must leave it empty."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append(name)
            return None

        return record


class FakeEquityAccount:
    """The equity account's own totals, and how often they were read."""

    def __init__(self, totals):
        self.totals_map = dict(totals)
        self.calls = 0

    def totals(self):
        self.calls += 1
        return dict(self.totals_map)


class RecordingLive:
    """A live exchange that records every call; `equity` is the account or None.

    `equity` is a real attribute (None when this install has no equity account),
    so `getattr(live, "equity", None)` answers what the chain asks it.
    """

    dry_run = False

    def __init__(self, *, totals=None, equity=None):
        self.calls = []
        self.crypto = dict(totals or {})
        self.equity = equity

    def crypto_totals(self):
        self.calls.append("crypto_totals")
        return dict(self.crypto)

    def place_limit(self, cid, product, side, size, price):
        self.calls.append(("place_limit", cid, product, side, size, price))
        return {"ok": True, "order_id": "live-" + cid, "reason": None}

    def place_equity_limit(self, cid, product, side, size, price):
        self.calls.append(("place_equity_limit", cid, product, side, size, price))
        return {"ok": True, "order_id": "live-" + cid, "reason": None}

    def list_open_orders(self, product=None):
        self.calls.append("list_open_orders")
        return []

    def cancel(self, order_ids):
        self.calls.append("cancel")
        return {order_id: True for order_id in order_ids}


class Approvals:
    """The gateway's approval rail, faked: approved fields plus a spend marker.

    `approve` records the five fields an approval covers and whether it is
    spendable at all.  `check` answers None only for exactly those fields of an
    approval that is still unconsumed — its spend marker is there — and
    `APPROVAL_REQUIRED` otherwise, so one approval places one order and never a
    second.  An approval made unspendable is checked by its fields alone: what it
    is missing is the spend, not the approval.  `consume` deletes the marker
    through the connection it is handed — the same connection and transaction
    that writes the order row — and raises `ApprovalGone` when there is no marker
    left, so an approval that was already spent cannot be spent again and a spend
    whose row failed to write is rolled back with it.
    """

    def __init__(self, store):
        self.store = store
        self.approved = {}

    def approve(
        self,
        approval_id,
        *,
        side="BUY",
        size=D("1"),
        limit_price=D("100"),
        product=NVDA,
        book="dry",
        spendable=True,
    ):
        self.approved[approval_id] = (
            side,
            D(size),
            D(limit_price),
            product,
            book,
            bool(spendable),
        )
        if spendable:
            self.store.put(self._key(approval_id), True)
        return approval_id

    def check(self, approval_id, intent, *, product, book):
        expected = self.approved.get(approval_id)
        if expected is None:
            return APPROVAL_REQUIRED
        fields, spendable = expected[:5], expected[5]
        found = (intent.side, intent.size, intent.limit_price, product, book)
        if found != fields:
            return APPROVAL_REQUIRED
        # The real rail takes an unconsumed approval only: one already spent is
        # no approval at all.
        if spendable and self.spent(approval_id):
            return APPROVAL_REQUIRED
        return None

    def consume(self, conn, approval_id):
        changed = conn.execute(
            "DELETE FROM kv WHERE key=?", (self._key(approval_id),)
        ).rowcount
        if changed != 1:
            raise ApprovalGone(approval_id)

    def spent(self, approval_id):
        row = (
            self.store.conn()
            .execute("SELECT 1 FROM kv WHERE key=?", (self._key(approval_id),))
            .fetchone()
        )
        return row is None

    @staticmethod
    def _key(approval_id):
        return f"test-approval:{approval_id}"


# ---------------------------------------------------------------- fixtures


def store_at(
    path,
    *,
    product=XRP,
    capital_quote=D("100"),
    capital_base=D("50"),
    params=None,
    bot_id="b1",
):
    """A store with one ACTIVE bot."""
    s = Store(path)
    s.create_bot(bot_id, product, "grid", params or {}, D(capital_quote), D(capital_base))
    return s


@pytest.fixture
def store(tmp_path):
    s = store_at(tmp_path / "s.db")
    yield s
    s.close()


@pytest.fixture
def make_store(tmp_path):
    """Extra stores (other products, other budgets) closed when the test ends."""
    created = []

    def build(name, **kwargs):
        s = store_at(tmp_path / name, **kwargs)
        created.append(s)
        return s

    yield build
    for s in created:
        s.close()


# ---------------------------------------------------------------- snapshots


def equity_snap(
    product=NVDA, price="100", *, bid=None, ask=None, ts=None, print_ts=None
):
    """One equity quote: one print, so both sides are the same price by default.

    An equity print carries its own time, so the snapshot keeps a `print_ts`
    beside the read `ts` the way the poll stores it.  Unless a caller gives one,
    the print is as fresh as the read: a snapshot built here is priced on the
    book the order runs on rather than refused for a print with no age.
    """
    last = D(price)
    read = time.time() if ts is None else ts
    return MarketSnapshot(
        product=product,
        bid=last if bid is None else D(bid),
        ask=last if ask is None else D(ask),
        low=last,
        high=last,
        ts=read,
        print_ts=read if print_ts is None else print_ts,
    )


def crypto_snap(product=XRP, *, bid=BID, ask=ASK, ts=None):
    return MarketSnapshot(
        product=product,
        bid=bid,
        ask=ask,
        low=D("0.9"),
        high=D("1.1"),
        ts=time.time() if ts is None else ts,
    )


def cache_with(*snaps, skew=0.0):
    """A cache holding *snaps*; skew=None leaves the clock unmeasured."""
    cache = SnapshotCache()
    for snap in snaps:
        cache.put(snap)
    if skew is not None:
        cache.set_clock(100.0 + skew, 100.0)  # server - local == skew
    return cache


def equity_cache(*snaps, skew=0.0):
    """NVDA at 100, VOO at 50 and the crypto bot's own book, unless told otherwise."""
    if not snaps:
        snaps = (equity_snap(NVDA, "100"), equity_snap(VOO, "50"), crypto_snap(XRP))
    return cache_with(*snaps, skew=skew)


# ---------------------------------------------------------------- totals


def equity_totals(usd="1000", **overrides):
    """One dry-book totals view: equity cash in USD beside the crypto currencies."""
    totals = {
        "USD": D(usd),
        "USDC": D("100"),
        "XRP": D("50"),
        "ETH": D("0"),
        NVDA.split("-", 1)[0]: D("0"),
        VOO.split("-", 1)[0]: D("0"),
    }
    for currency, amount in overrides.items():
        totals[currency.upper()] = D(amount)
    return totals


# ---------------------------------------------------------------- the gateway


def make_equity_gateway(
    store,
    *,
    env=None,
    capital="150",
    snaps=None,
    totals=None,
    specs=None,
    exchange=None,
    books=None,
    switches=None,
    approvals=None,
    session_open=None,
    now=time.time,
    **overrides,
):
    """A gateway over *store* whose limits, ledger and cache all name the equities.

    `capital` is the AI's equity capital: it is written into the limits the
    gateway reads and into the callable the ledger reads, so the two cannot
    disagree about how much money the pool has.
    """
    settings = dict(EQUITY_ENV)
    settings.update(env or {})
    settings[EQUITY_CAPITAL_ENV] = str(capital)
    limits = Limits.from_env(settings)
    ledger = Ledger(
        store,
        fee_rate=FEE_RATE,
        equity_ai_capital=lambda: limits.equity_ai_capital_usd,
        is_equity=limits.is_equity,
    )
    table = dict(SPECS)
    table.update(specs or {})
    if approvals is None:
        approvals = Approvals(store)
    kwargs = dict(
        store=store,
        ledger=ledger,
        limits=limits,
        caps=CapWindow(store, time.time),
        snapshots=equity_cache() if snaps is None else snaps,
        spec_for=lambda product: table[product],
        fee_rate=FEE_RATE,
        totals=(lambda: equity_totals()) if totals is None else totals,
        exchange=exchange,
        books=books,
        switches=switches,
        now=now,
        approval_check=approvals.check,
        consume_approval=approvals.consume,
        session_open=(lambda ts: True) if session_open is None else session_open,
        sleep=lambda seconds: None,
    )
    kwargs.update(overrides)
    return OrderGateway(**kwargs)


# ---------------------------------------------------------------- intents


def place(side="BUY", size=D("1"), price=D("100"), level=0, approval_id=None):
    """An equity-shaped place intent (an equity value, an ai owner, an approval)."""
    return OrderIntent(
        action="place",
        side=side,
        size=size,
        limit_price=price,
        level=level,
        cancel_cid=None,
        reason="test",
        approval_id=approval_id,
    )


def approved(
    approvals,
    approval_id="apr-1",
    *,
    side="BUY",
    size=D("1"),
    price=D("100"),
    product=NVDA,
    book="dry",
    spendable=True,
):
    """An intent the fake rail has approved for exactly its own five fields."""
    approvals.approve(
        approval_id,
        side=side,
        size=size,
        limit_price=price,
        product=product,
        book=book,
        spendable=spendable,
    )
    return place(side=side, size=size, price=price, approval_id=approval_id)


def crypto_place(side="BUY", size=D("10"), price=D("0.95"), approval_id=None):
    return place(side=side, size=size, price=price, approval_id=approval_id)


# ---------------------------------------------------------------- rows


def seed_order(
    store,
    *,
    owner="ai",
    source="ai",
    product=NVDA,
    side="BUY",
    price=D("100"),
    size=D("1"),
    status=OPEN,
    product_type="SPOT",
    book="dry",
    cid_suffix=1,
):
    """One order row written the engine's own way; SPOT unless the caller says."""
    cid = f"cb-{owner}-B0-{cid_suffix:012x}"
    store.insert_order(
        cid,
        owner,
        source,
        product,
        side,
        0,
        D(price),
        D(size),
        status=status,
        book=book,
        product_type=product_type,
    )
    return cid


def seed_filled_buy(
    store,
    *,
    product=NVDA,
    price=D("100"),
    size=D("10"),
    filled_value=None,
    fees=D("0"),
    status=FILLED,
    product_type="EQUITY",
    book="dry",
    cid_suffix=1,
):
    """A buy the exchange already filled: filled totals plus a terminal status."""
    cid = seed_order(
        store,
        product=product,
        price=price,
        size=size,
        status=status,
        product_type=product_type,
        book=book,
        cid_suffix=cid_suffix,
    )
    store.update_order(
        cid,
        filled_size=D(size),
        filled_value=D(price) * D(size) if filled_value is None else D(filled_value),
        fees=D(fees),
    )
    return cid


def seed_crypto_hour(store, count, *, owner="b1", source="bot"):
    """*count* crypto rows inside the rolling hour, each spending next to nothing."""
    for n in range(1, count + 1):
        seed_order(
            store,
            owner=owner,
            source=source,
            product=XRP,
            price=D("0.01"),
            size=D("1"),
            status=OPEN,
            cid_suffix=n,
        )


# ---------------------------------------------------------------- chain: halts"


def test_equity_chain_halted_beats_everything(store):
    dry = RecordingExchange()
    approvals = Approvals(store)

    # The approved order is allowed on the dry book...
    plain = make_equity_gateway(store, exchange=dry, approvals=approvals)
    intent = approved(approvals, size=D("1"), price=D("100"))
    assert plain.check("ai", "ai", intent, NVDA) is None
    assert dry.calls == []
    assert store.orders() == []

    # ... and the halt is the answer even where the route, the product and the
    # approval would each refuse: the halt is judged before all of them.
    live = RecordingLive(equity=FakeEquityAccount({"USD": D("1000")}))
    routed = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        books=BookRouter(dry, live),
        route_for=lambda owner: "live",
        is_halted=lambda: True,
    )
    assert routed.check("ai", "ai", intent, "TSLA-USD") == HALTED
    assert dry.calls == []
    assert live.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- chain: route


def test_equity_chain_live_disabled_beats_product_not_allowed(store):
    dry = RecordingExchange()
    live = RecordingLive(equity=FakeEquityAccount({"USD": D("1000")}))
    gw = make_equity_gateway(
        store,
        exchange=dry,
        books=BookRouter(dry, live),
        route_for=lambda owner: "live",  # the ai's own live switch stays off
    )

    # An id on neither list would be PRODUCT_NOT_ALLOWED on a dry route; the
    # route's own refusal is answered first.
    assert gw.check("ai", "ai", place(size=D("1")), "TSLA-USD") == LIVE_DISABLED
    assert dry.calls == []
    assert live.calls == []
    assert store.orders() == []


def test_equity_chain_no_equity_account(store):
    dry = RecordingExchange()
    live = RecordingLive(equity=None)  # a crypto-only install
    switchers = Switches(store, {})
    switchers.set("ai_live_enabled", True)

    # No equity snapshot is cached either, so STALE_MARKET would answer too.
    gw = make_equity_gateway(
        store,
        env={EQUITY_LIVE_ENV: "true"},
        exchange=dry,
        books=BookRouter(dry, live),
        switches=switchers,
        snaps=cache_with(crypto_snap(XRP)),
    )

    assert gw.check("ai", "ai", place(size=D("1")), NVDA) == NO_EQUITY_ACCOUNT
    assert dry.calls == []
    assert live.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- chain: product


def test_equity_chain_product_not_allowed(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    # A symbol on neither list.
    assert gw.check("ai", "ai", place(size=D("1")), "TSLA-USD") == (
        PRODUCT_NOT_ALLOWED
    )
    # ... answered before the approval step as well.
    unnamed = place(size=D("1"), approval_id="nobody-approved-this")
    assert gw.check("ai", "ai", unnamed, "TSLA-USD") == PRODUCT_NOT_ALLOWED

    # A listed equity, with the approval in place, is not refused.
    intent = approved(approvals, size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", intent, NVDA) is None

    assert dry.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- chain: approval


def test_equity_chain_approval_required_beats_trading_halted(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        specs={NVDA: equity_spec(NVDA, trading_halted=True)},
    )

    # The product is halted, and the approval step is still the answer.
    assert gw.check("ai", "ai", place(size=D("1")), NVDA) == APPROVAL_REQUIRED
    assert gw.check("ai", "ai", place(size=D("1"), approval_id=""), NVDA) == (
        APPROVAL_REQUIRED
    )
    unknown = place(size=D("1"), approval_id="apr-never-approved")
    assert gw.check("ai", "ai", unknown, NVDA) == APPROVAL_REQUIRED

    # With a usable approval the halted product is what refuses it.
    intent = approved(approvals, size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", intent, NVDA) == TRADING_HALTED

    assert dry.calls == []
    assert store.orders() == []


def test_equity_chain_trading_halted(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        specs={NVDA: equity_spec(NVDA, trading_halted=True, liquidate_only=True)},
    )

    # Halted and liquidate-only at once: the halt is the answer.
    intent = approved(approvals, size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", intent, NVDA) == TRADING_HALTED
    assert dry.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- chain: liquidate


def test_liquidate_only_sell_allowed(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    seed_filled_buy(store, size=D("10"), price=D("100"))
    # The session is closed too, so a sell that gets past LIQUIDATE_ONLY is
    # refused by the next step: the step itself is the buy's alone.
    gw = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        specs={NVDA: equity_spec(NVDA, liquidate_only=True)},
        totals=lambda: equity_totals(nvda="10"),
        session_open=lambda ts: False,
    )

    buy = approved(approvals, "apr-buy", size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", buy, NVDA) == LIQUIDATE_ONLY

    sell = approved(approvals, "apr-sell", side="SELL", size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", sell, NVDA) == MARKET_CLOSED

    assert dry.calls == []
    assert len(store.orders()) == 1


# ---------------------------------------------------------------- chain: session


def test_market_closed_nothing_sent(store):
    seen = []
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        snaps=cache_with(
            equity_snap(NVDA, "100", ts=CLOCK),
            equity_snap(VOO, "50", ts=CLOCK),
            crypto_snap(XRP, ts=CLOCK),
        ),
        session_open=lambda ts: bool(seen.append(ts)),
        now=lambda: CLOCK,
    )

    intent = approved(approvals, size=D("1"), price=D("100"))
    res = gw.submit("ai", "ai", intent, NVDA)

    assert res.ok is False
    assert res.refusal == MARKET_CLOSED
    # The session clock is asked with the gateway's own clock.
    assert seen == [CLOCK]
    assert dry.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- chain: market data


def test_equity_chain_stale_market(store):
    dry = RecordingExchange()
    approvals = Approvals(store)

    missing = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        snaps=cache_with(crypto_snap(XRP)),  # no equity snapshot at all
    )
    intent = approved(approvals, size=D("1"), price=D("100"))
    assert missing.check("ai", "ai", intent, NVDA) == STALE_MARKET

    stale = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        snaps=cache_with(
            crypto_snap(XRP), equity_snap(NVDA, "100", ts=CLOCK - 10_000), skew=None
        ),
        now=lambda: CLOCK,
    )
    assert stale.check("ai", "ai", intent, NVDA) == STALE_MARKET

    # An equity print is one price: bid == ask is usable, and an ask under the
    # bid is not.
    crossed = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        snaps=cache_with(crypto_snap(XRP), equity_snap(NVDA, bid="100", ask="99")),
    )
    assert crossed.check("ai", "ai", intent, NVDA) == STALE_MARKET

    assert dry.calls == []
    assert store.orders() == []


def test_equity_chain_clock_skew(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    # Small enough to be refused for its size once the clock is trusted.
    intent = approved(approvals, "apr-small", size=D("0.00005"), price=D("100"))

    ahead = make_equity_gateway(
        store, exchange=dry, approvals=approvals, snaps=equity_cache(skew=6.0)
    )
    assert ahead.check("ai", "ai", intent, NVDA) == CLOCK_SKEW

    unknown = make_equity_gateway(
        store, exchange=dry, approvals=approvals, snaps=equity_cache(skew=None)
    )
    assert unknown.check("ai", "ai", intent, NVDA) == CLOCK_SKEW

    trusted = make_equity_gateway(store, exchange=dry, approvals=approvals)
    assert trusted.check("ai", "ai", intent, NVDA) == TOO_SMALL

    assert dry.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- chain: price band


def test_price_band(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    seed_filled_buy(store, size=D("10"), price=D("100"))
    # The band is the only step that can refuse these orders: the daily budget,
    # the single-order cap and the AI's equity capital are all far above them, and
    # the account holds the pool the money step reads.  (`make_equity_gateway`
    # writes `capital` into the limits as well as the env, so the two agree.)
    gw = make_equity_gateway(
        store,
        env={
            EQUITY_DAILY_ENV: "100000",
            EQUITY_MAX_ORDER_ENV: "100000",
            EQUITY_CAPITAL_ENV: "100000",
        },
        capital="100000",
        exchange=dry,
        approvals=approvals,
        totals=lambda: equity_totals(usd="100000", nvda="10"),
    )

    # NVDA prints at 100: the buy band is 105.00 and the sell band is 95.00.
    inside_buy = approved(approvals, "apr-b1", size=D("1"), price=D("105.00"))
    assert gw.check("ai", "ai", inside_buy, NVDA) is None

    over_buy = approved(approvals, "apr-b2", size=D("1"), price=D("105.01"))
    assert gw.check("ai", "ai", over_buy, NVDA) == PRICE_BAND

    inside_sell = approved(
        approvals, "apr-s1", side="SELL", size=D("1"), price=D("95.00")
    )
    assert gw.check("ai", "ai", inside_sell, NVDA) is None

    under_sell = approved(
        approvals, "apr-s2", side="SELL", size=D("1"), price=D("94.99")
    )
    assert gw.check("ai", "ai", under_sell, NVDA) == PRICE_BAND

    assert dry.calls == []
    assert len(store.orders()) == 1


# ---------------------------------------------------------------- chain: size


def test_equity_chain_too_small(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    # Whole-share only, so the sizes below are fractional as well: TOO_SMALL is
    # answered first.
    gw = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        specs={NVDA: equity_spec(NVDA, fractionable=False)},
    )

    under_minimum = approved(approvals, "apr-a", size=D("0.00005"))
    assert gw.check("ai", "ai", under_minimum, NVDA) == TOO_SMALL

    under_quote_minimum = approved(approvals, "apr-b", size=D("0.0001"))
    assert gw.check("ai", "ai", under_quote_minimum, NVDA) == TOO_SMALL

    whole_share = approved(approvals, "apr-c", size=D("1"))
    assert gw.check("ai", "ai", whole_share, NVDA) is None

    assert dry.calls == []
    assert store.orders() == []


def test_fractional_rules(store):
    dry = RecordingExchange()
    approvals = Approvals(store)

    whole_only = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        specs={NVDA: equity_spec(NVDA, fractionable=False)},
    )
    fractional = approved(approvals, "apr-f1", size=D("1.5"), price=D("100"))
    assert whole_only.check("ai", "ai", fractional, NVDA) == FRACTIONAL_NOT_ALLOWED
    whole = approved(approvals, "apr-f2", size=D("1"), price=D("100"))
    assert whole_only.check("ai", "ai", whole, NVDA) is None

    # A fractionable product with a fractional notional floor: a fractional size
    # under the floor is refused, a whole share is not held to it.
    floored = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        specs={
            NVDA: equity_spec(NVDA, fractional_notional_min_size=D("250"))
        },
    )
    small_fraction = approved(approvals, "apr-f3", size=D("0.5"), price=D("100"))
    assert floored.check("ai", "ai", small_fraction, NVDA) == (
        FRACTIONAL_NOT_ALLOWED
    )
    one_share = approved(approvals, "apr-f4", size=D("1"), price=D("100"))
    assert floored.check("ai", "ai", one_share, NVDA) is None

    assert dry.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- chain: caps


def test_equity_chain_order_too_large(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    # 110 is over the equity single-order cap of 100 and over a capital of 0:
    # the single-order cap is the earlier refusal.
    capped = make_equity_gateway(
        store,
        env={EQUITY_MAX_ORDER_ENV: "100"},
        capital="0",
        exchange=dry,
        approvals=approvals,
    )
    big = approved(approvals, "apr-big", size=D("1.1"), price=D("100"))
    assert capped.check("ai", "ai", big, NVDA) == ORDER_TOO_LARGE

    roomy = make_equity_gateway(store, exchange=dry, approvals=approvals)
    inside = approved(approvals, "apr-inside", size=D("0.9"), price=D("100"))
    assert roomy.check("ai", "ai", inside, NVDA) is None

    assert dry.calls == []
    assert store.orders() == []


def test_equity_chain_daily_cap(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    # 195 of equity notional already placed today on the dry book.
    seed_order(store, price=D("195"), size=D("1"), status=CANCELLED, product_type="EQUITY")
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    # 195 + 200 is over the 200 daily budget, and 200 is over the 150 capital:
    # the daily budget is answered first.
    intent = approved(approvals, size=D("2"), price=D("100"))
    assert gw.check("ai", "ai", intent, NVDA) == DAILY_CAP

    assert dry.calls == []
    assert len(store.orders()) == 1


def test_equity_chain_capital_cap(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    seed_crypto_hour(store, 3)
    gw = make_equity_gateway(
        store,
        env={ORDERS_HOUR_ENV: "3"},
        exchange=dry,
        approvals=approvals,
    )

    # 200 of notional against 150 of capital, and three orders already in the
    # hour: the capital is the answer.
    intent = approved(approvals, size=D("2"), price=D("100"))
    assert gw.check("ai", "ai", intent, NVDA) == CAPITAL_CAP

    assert dry.calls == []
    assert len(store.orders()) == 3


def test_rate_cap_shared(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    seed_crypto_hour(store, 3)
    gw = make_equity_gateway(
        store, env={ORDERS_HOUR_ENV: "3"}, exchange=dry, approvals=approvals
    )

    # A crypto row exercises the same rolling-hour count an equity order does.
    intent = approved(approvals, size=D("0.1"), price=D("100"))
    assert gw.check("ai", "ai", intent, NVDA) == RATE_CAP

    assert dry.calls == []
    assert len(store.orders()) == 3


def test_equity_caps_separate(store, make_store):
    dry = FakeExchange()
    approvals = Approvals(store)

    # 1. A day of crypto notional spends none of the equity budget.
    seed_order(
        store, product=XRP, price=D("195"), size=D("1"), status=CANCELLED
    )
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)
    caps = gw.caps
    assert caps.daily_notional(None, book="dry", product_type="SPOT") == D("195")
    assert caps.daily_notional(None, book="dry", product_type="EQUITY") == D("0")
    small = approved(approvals, "apr-small", size=D("0.1"), price=D("100"))
    assert gw.check("ai", "ai", small, NVDA) is None

    # 2. A day of equity notional spends neither crypto sum.
    other = make_store("caps-separate.db")
    seed_order(
        other, price=D("195"), size=D("1"), status=CANCELLED, product_type="EQUITY"
    )
    other_approvals = Approvals(other)
    crypto = make_equity_gateway(other, exchange=dry, approvals=other_approvals)
    assert crypto.caps.daily_notional(None, book="dry", product_type="SPOT") == D("0")
    assert crypto.caps.daily_notional("ai", book="dry", product_type="SPOT") == D("0")

    # The ai has no crypto money, so an ai crypto buy answers the holding.  It
    # would answer DAILY_CAP for either crypto sum (195 + 9.5 is over the 200
    # global budget, and over the ai's own) if the equity notional were counted.
    ai_buy = approved(
        other_approvals, "apr-crypto", size=D("10"), price=D("0.95"), product=XRP
    )
    assert crypto.check("ai", "ai", ai_buy, XRP) == INSUFFICIENT_HOLDING

    assert dry.calls == []


# ---------------------------------------------------------------- capital pool


def test_capital_pool_shared_across_symbols(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    nvda = approved(approvals, "apr-nvda", size=D("1"), price=D("100"))
    first = gw.submit("ai", "ai", nvda, NVDA)
    assert first.ok is True
    assert first.refusal is None

    # 100 of the 150 pool is resting on NVDA, so a second 100 on VOO is over it.
    voo = approved(
        approvals, "apr-voo", size=D("2"), price=D("50"), product=VOO
    )
    second = gw.submit("ai", "ai", voo, VOO)
    assert second.ok is False
    assert second.refusal == CAPITAL_CAP

    assert [call[1] for call in dry.calls] == [first.cid]
    assert len(store.orders()) == 1


def test_capital_zero_blocks_buys_allows_sells(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    bought = seed_filled_buy(store, size=D("10"), price=D("100"))
    # The shares were bought three days ago, so they sit outside today's equity
    # budget: the empty capital is what refuses the buy, not the day's cap.
    store.update_order(bought, created_at=time.time() - 3 * 86400)
    gw = make_equity_gateway(
        store,
        capital="0",
        exchange=dry,
        approvals=approvals,
        totals=lambda: equity_totals(usd="0", nvda="10"),
    )

    buy = approved(approvals, "apr-buy", size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", buy, NVDA) == CAPITAL_CAP

    # The shares an earlier filled buy left behind may still be sold.
    sell = approved(approvals, "apr-sell", side="SELL", size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", sell, NVDA) is None

    assert dry.calls == []
    assert len(store.orders()) == 1


def test_capital_released_by_partial_expiry(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    # A partially filled buy that then expired: only what it actually spent
    # still counts against the pool.
    cid = seed_filled_buy(
        store,
        size=D("0.66"),
        price=D("100"),
        filled_value=D("40"),
        status="EXPIRED",
    )
    store.update_order(cid, filled_size=D("0.4"))
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    assert gw.ledger.equity_pool_used("dry") == D("40")

    inside = approved(approvals, "apr-inside", size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", inside, NVDA) is None

    over = approved(approvals, "apr-over", size=D("1.2"), price=D("100"))
    assert gw.check("ai", "ai", over, NVDA) == CAPITAL_CAP

    assert dry.calls == []


# ---------------------------------------------------------------- delisted symbols


def test_delisted_symbol_spend_still_counts_against_capital(store):
    """Spend on a symbol taken off the equity list still draws on the pool."""
    dry = FakeExchange()
    approvals = Approvals(store)
    # The AI bought 100 of NVDA earlier; NVDA is no longer on the equity list.
    seed_filled_buy(
        store, product=NVDA, price=D("100"), size=D("1"), filled_value=D("100")
    )
    gw = make_equity_gateway(
        store,
        env={EQUITY_PRODUCTS_ENV: VOO, EQUITY_DAILY_ENV: "1000"},
        exchange=dry,
        approvals=approvals,
    )
    assert gw.ledger.equity_pool_used("dry") == D("100")

    # 150 more against a 150 pool that already spent 100 is over it.
    voo = approved(approvals, "apr-voo", size=D("3"), price=D("50"), product=VOO)
    assert gw.check("ai", "ai", voo, VOO) == CAPITAL_CAP

    assert dry.calls == []


def test_equity_value_includes_delisted_shares(store):
    """The mark prices every share the AI holds, listed symbol or not."""
    dry = FakeExchange()
    approvals = Approvals(store)
    seed_filled_buy(
        store, product=NVDA, price=D("100"), size=D("1"), filled_value=D("100")
    )
    marked = make_equity_gateway(
        store,
        env={EQUITY_PRODUCTS_ENV: VOO},
        exchange=dry,
        approvals=approvals,
        snaps=cache_with(crypto_snap(XRP), equity_snap(NVDA, "110")),
    )

    # One share at a mid of 110, plus the 50 the pool has left (150 - 100).
    assert marked.equity_value("dry") == D("160")

    # A delisted share nobody can price makes the whole mark unknown.
    unpriceable = make_equity_gateway(
        store,
        env={EQUITY_PRODUCTS_ENV: VOO},
        exchange=dry,
        approvals=approvals,
        snaps=cache_with(crypto_snap(XRP)),
    )
    assert unpriceable.equity_value("dry") is None

    assert dry.calls == []


# ---------------------------------------------------------------- adoption


def listed_order(
    cid,
    *,
    product=NVDA,
    side="BUY",
    price="100",
    size="1",
    status="OPEN",
    filled_size="0",
    filled_value="0",
    order_id="ex-1",
):
    """One order in the shape an adapter's `list_open_orders` hands back."""
    return {
        "client_order_id": cid,
        "order_id": order_id,
        "product": product,
        "side": side,
        "price": price,
        "size": size,
        "status": status,
        "filled_size": filled_size,
        "filled_value": filled_value,
        "total_fees": "0",
    }


def router_open_list(router):
    """The whole book as *router* lists it, keyed the way a cycle keys it."""
    return {
        snap["client_order_id"]: snap
        for snap in router.list_open_orders(None)
        if str(snap.get("client_order_id") or "").startswith("cb-")
    }


def test_adopted_order_from_the_equity_account_is_an_equity_row(store):
    """An equity account's NVDA buy, on a symbol off the configured list."""
    cid = "cb-ai-B0-00000000abcd"
    log: list = []
    router = ExchangeRouter(
        FakeAdapter("crypto", log),
        FakeAdapter("equity", log, open_orders=[listed_order(cid)]),
        is_equity=lambda product: product == VOO,
        usd_one_pool=True,
    )

    # The router says which account each snapshot came from, and the equity one
    # is the account that holds the equities whatever the configured list says.
    open_list = router_open_list(router)
    assert open_list[cid]["account"] == "equity"

    rec._adopt_unknown(store, router, open_list, {}, set(), "dry")
    assert store.order(cid)["product_type"] == "EQUITY"

    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        env={EQUITY_PRODUCTS_ENV: VOO, EQUITY_DAILY_ENV: "1000"},
        exchange=FakeExchange(),
        approvals=approvals,
    )
    # The adopted buy rests at 100 of the 150 pool, so a further 100 on VOO goes
    # over it.
    assert gw.ledger.equity_pool_used("dry") == D("100")

    voo = approved(approvals, "a1", size=D("2"), price=D("50"), product=VOO)
    assert gw.check("ai", "ai", voo, VOO) == CAPITAL_CAP


def test_adopted_order_stays_equity_beside_earlier_equity_rows(store):
    """The same, on a symbol the store already holds EQUITY rows for."""
    cid = "cb-ai-B0-00000000abcd"
    seed_filled_buy(store, product=NVDA, price=D("10"), size=D("1"), cid_suffix=9)

    def has_equity_rows(product):
        return any(
            row["product"] == product and row["product_type"] == "EQUITY"
            for row in store.orders()
        )

    log: list = []
    router = ExchangeRouter(
        FakeAdapter("crypto", log),
        FakeAdapter("equity", log, open_orders=[listed_order(cid)]),
        is_equity=lambda product: product == VOO,
        equity_rows=has_equity_rows,
        usd_one_pool=True,
    )

    open_list = router_open_list(router)
    assert open_list[cid]["account"] == "equity"

    rec._adopt_unknown(store, router, open_list, {}, set(), "dry")
    assert store.order(cid)["product_type"] == "EQUITY"

    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        env={EQUITY_PRODUCTS_ENV: VOO, EQUITY_DAILY_ENV: "1000"},
        exchange=FakeExchange(),
        approvals=approvals,
    )
    # The 10 already paid and the 100 now resting draw on the one pool.
    assert gw.ledger.equity_pool_used("dry") == D("110")

    voo = approved(approvals, "a1", size=D("1"), price=D("50"), product=VOO)
    assert gw.check("ai", "ai", voo, VOO) == CAPITAL_CAP


def test_adopted_order_type_follows_the_account_then_the_router(store):
    """An account's tag decides an adopted row; an untagged one asks the router."""
    crypto_cid = "cb-ai-B0-00000000c1"
    equity_cid = "cb-ai-B0-00000000e1"
    log: list = []
    router = ExchangeRouter(
        FakeAdapter(
            "crypto",
            log,
            open_orders=[
                listed_order(crypto_cid, product=XRP, price="0.95", size="10")
            ],
        ),
        FakeAdapter("equity", log, open_orders=[listed_order(equity_cid)]),
        is_equity=lambda product: product == NVDA,
        is_crypto=lambda product: product == XRP,
        equity_rows=lambda product: product == XRP,
        usd_one_pool=True,
    )

    open_list = router_open_list(router)
    assert open_list[crypto_cid]["account"] == "crypto"
    assert open_list[equity_cid]["account"] == "equity"

    # A stray EQUITY row on a crypto product does not turn the crypto account's
    # own snapshot into an equity row.
    rec._adopt_unknown(
        store, router, {crypto_cid: open_list[crypto_cid]}, {}, set(), "dry"
    )
    assert store.order(crypto_cid)["product_type"] == "SPOT"

    # A snapshot that names no account falls back to the router's own answer
    # about the product.
    untagged = dict(open_list[equity_cid])
    untagged.pop("account")
    rec._adopt_unknown(store, router, {equity_cid: untagged}, {}, set(), "dry")
    assert store.order(equity_cid)["product_type"] == "EQUITY"

    # The public ownership answer: the crypto list wins over the stray row, and
    # a listed equity is the equity account's.
    assert router.owns_equity(XRP) is False
    assert router.owns_equity(NVDA) is True


def test_shared_adapter_adopts_a_crypto_order_as_spot(store):
    """One key on both sides is one account: its crypto order stays SPOT."""
    cid = "cb-ai-B0-00000000beef"
    same = FakeAdapter(
        "crypto",
        [],
        open_orders=[listed_order(cid, product=XRP, price="1", size="10")],
    )
    router = ExchangeRouter(
        same,
        same,
        is_equity=lambda product: product == NVDA,
        is_crypto=lambda product: product == XRP,
        usd_one_pool=True,
    )

    rec._adopt_unknown(store, router, rec._open_cb_orders(router), {}, set(), "dry")

    row = store.order(cid)
    assert row["product_type"] == "SPOT"
    assert row["product"] == XRP

    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        env={EQUITY_PRODUCTS_ENV: VOO, EQUITY_DAILY_ENV: "1000"},
        exchange=FakeExchange(),
        approvals=approvals,
    )
    # A crypto order spends nothing of the equity pool, so all 150 of it is still
    # there for a VOO buy of exactly that much.
    assert gw.ledger.equity_pool_used("dry") == D("0")
    voo = approved(approvals, "a1", size=D("3"), price=D("50"), product=VOO)
    assert gw.check("ai", "ai", voo, VOO) is None


def test_shared_adapter_adopts_a_delisted_equity_order_as_equity(store):
    """One key on both sides: an EQUITY row still makes the delisted orphan EQUITY."""
    cid = "cb-ai-B0-00000000abcd"
    seed_filled_buy(store, product=NVDA, price=D("10"), size=D("1"), cid_suffix=9)

    def has_equity_rows(product):
        return any(
            row["product"] == product and row["product_type"] == "EQUITY"
            for row in store.orders()
        )

    same = FakeAdapter("crypto", [], open_orders=[listed_order(cid)])
    router = ExchangeRouter(
        same,
        same,
        is_equity=lambda product: product == VOO,
        is_crypto=lambda product: product == XRP,
        equity_rows=has_equity_rows,
        usd_one_pool=True,
    )

    rec._adopt_unknown(store, router, rec._open_cb_orders(router), {}, set(), "dry")

    assert store.order(cid)["product_type"] == "EQUITY"

    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        env={EQUITY_PRODUCTS_ENV: VOO, EQUITY_DAILY_ENV: "1000"},
        exchange=FakeExchange(),
        approvals=approvals,
    )
    # The 10 already paid and the 100 now resting draw on the one pool.
    assert gw.ledger.equity_pool_used("dry") == D("110")

    voo = approved(approvals, "a1", size=D("1"), price=D("50"), product=VOO)
    assert gw.check("ai", "ai", voo, VOO) == CAPITAL_CAP


def test_shared_adapter_lists_every_reported_order_once(store):
    """One key on both sides is one book: no order is listed a second time."""
    crypto_cid = "cb-ai-B0-00000000c1"
    equity_cid = "cb-ai-B0-00000000e1"
    same = FakeAdapter(
        "crypto",
        [],
        open_orders=[
            listed_order(crypto_cid, product=XRP, price="1", size="10"),
            listed_order(equity_cid),
        ],
    )
    router = ExchangeRouter(
        same,
        same,
        is_equity=lambda product: product == NVDA,
        is_crypto=lambda product: product == XRP,
        usd_one_pool=True,
    )

    listed = router.list_open_orders(None)

    # Each order once, and its account is the one that owns its product.
    assert sorted(
        (snap["client_order_id"], snap.get("account")) for snap in listed
    ) == sorted([(crypto_cid, "crypto"), (equity_cid, "equity")])


def test_adopted_kind_keeps_a_crypto_product_spot_whatever_the_tag(store):
    """The crypto list wins over a snapshot's account tag: a coin is never equity."""

    class StandIn:
        """An exchange whose only product knowledge is the crypto list."""

        dry_run = True

        def is_crypto(self, product):
            return product == XRP

    exchange = StandIn()
    coin = listed_order("cb-ai-B0-00000000c1", product=XRP, price="1", size="10")

    # Untagged, and tagged EQUITY by an account that should not have listed it:
    # a crypto product's order is a SPOT row either way.
    assert rec._product_type_of(exchange, XRP, coin) == "SPOT"
    assert rec._product_type_of(exchange, XRP, dict(coin, account="equity")) == (
        "SPOT"
    )

    # A product the crypto list does not name keeps the tag's answer.
    equity = listed_order("cb-ai-B0-00000000e1")
    assert rec._product_type_of(exchange, NVDA, dict(equity, account="equity")) == (
        "EQUITY"
    )


def test_mixed_slot_rows_all_draw_on_the_one_equity_pool(store):
    """A SPOT row on a listed equity spends the pool beside the EQUITY rows."""
    approvals = Approvals(store)
    seed_filled_buy(store, product=NVDA, price=D("100"), size=D("1"), cid_suffix=1)
    seed_filled_buy(
        store,
        product=NVDA,
        price=D("40"),
        size=D("1"),
        product_type="SPOT",
        cid_suffix=2,
    )
    gw = make_equity_gateway(
        store,
        env={EQUITY_DAILY_ENV: "1000"},
        exchange=FakeExchange(),
        approvals=approvals,
    )

    # The slot is an equity slot, so what it paid is pool spend whichever kind
    # the rows themselves were written with.
    assert gw.ledger.equity_pool_used("dry") == D("140")

    # One figure read two ways: the capital less the pool is the slot's own
    # quote, and the mark adds the two shares it bought at their mid.
    cash = D("150") - D("140")
    assert gw.ledger.holding("ai", NVDA, book="dry").quote == cash
    assert gw.equity_value("dry") == D("2") * D("100") + cash

    voo = approved(approvals, "a1", size=D("1"), price=D("50"), product=VOO)
    assert gw.check("ai", "ai", voo, VOO) == CAPITAL_CAP


def test_ai_pool_cannot_spend_bot_usd(make_store):
    dry = FakeExchange()
    eth = make_store(
        "eth-bot.db", product=ETH, capital_quote=D("100"), capital_base=D("0")
    )
    approvals = Approvals(eth)
    gw = make_equity_gateway(
        eth,
        capital="100",
        exchange=dry,
        approvals=approvals,
        totals=lambda: {"USD": D("150"), "USDC": D("0"), ETH.split("-", 1)[0]: D("0")},
    )

    # The bot's 100 USD and the AI's 100 USD pool together are 200 of a 150
    # account: the AI's order may not spend the bot's cash.
    buy = approved(approvals, "apr-buy", size=D("0.9"), price=D("100"))
    assert gw.check("ai", "ai", buy, NVDA) == UNALLOCATED_NEGATIVE

    # With the cash actually there, the same order passes.
    funded = make_equity_gateway(
        eth,
        capital="100",
        exchange=dry,
        approvals=approvals,
        totals=lambda: {"USD": D("250"), "USDC": D("0"), ETH.split("-", 1)[0]: D("0")},
    )
    assert funded.check("ai", "ai", buy, NVDA) is None

    assert dry.calls == []


# ---------------------------------------------------------------- chain: money


def test_equity_chain_unallocated_negative(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    store.update_hwm(PORTFOLIO_OWNER, D("100000"), "dry")
    gw = make_equity_gateway(
        store, exchange=dry, approvals=approvals, totals=lambda: equity_totals(usd="100")
    )

    # The 150 pool is not on the account (100 is), and the portfolio mark would
    # stop trading too: the short account is the answer.
    intent = approved(approvals, size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", intent, NVDA) == UNALLOCATED_NEGATIVE

    assert dry.calls == []
    assert store.orders() == []


def test_equity_chain_drawdown_stop(store):
    dry = RecordingExchange()
    approvals = Approvals(store)
    # The dry portfolio (one XRP bot) is worth 149.75 at the XRP mid.
    store.update_hwm(PORTFOLIO_OWNER, D("200"), "dry")
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    intent = approved(approvals, size=D("1"), price=D("100"))
    assert gw.check("ai", "ai", intent, NVDA) == DRAWDOWN_STOP
    assert store.hwm(PORTFOLIO_OWNER) == D("200")

    assert dry.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- approvals


def test_bot_source_equity_refused(make_store):
    dry = FakeExchange()
    s = make_store(
        "bot-equity.db", product=NVDA, capital_quote=D("100"), capital_base=D("0")
    )
    gw = make_equity_gateway(s, exchange=dry)

    # Even a bot whose own row names the equity may not trade it.
    intent = place(size=D("1"), price=D("100"))
    assert gw.check("bot", "b1", intent, NVDA) == PRODUCT_NOT_ALLOWED
    assert gw.submit("bot", "b1", intent, NVDA).refusal == PRODUCT_NOT_ALLOWED
    assert gw.check("bot", "b1", intent) == PRODUCT_NOT_ALLOWED

    assert dry.calls == []
    assert s.orders() == []


def test_autonomous_mode_still_requires_approval(store):
    dry = FakeExchange()
    # An install whose crypto AI mode says autonomous still names an approval
    # for every equity order it places.
    gw = make_equity_gateway(
        store, env={AI_MODE_ENV: "autonomous"}, exchange=dry
    )

    assert gw.check("ai", "ai", place(size=D("1"), price=D("100")), NVDA) == (
        APPROVAL_REQUIRED
    )
    assert gw.check(
        "ai", "ai", place(size=D("1"), price=D("100"), approval_id=None), NVDA
    ) == APPROVAL_REQUIRED
    assert gw.check(
        "ai", "ai", place(size=D("1"), price=D("100"), approval_id=""), NVDA
    ) == APPROVAL_REQUIRED

    # The crypto path asks for one too, exactly as it did.
    assert gw.check("ai", "ai", crypto_place(), XRP) == APPROVAL_REQUIRED

    assert dry.calls == []
    assert store.orders() == []


def test_approval_replay_refused(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    intent = approved(approvals, size=D("1"), price=D("100"))
    first = gw.submit("ai", "ai", intent, NVDA)
    assert first.ok is True
    assert first.refusal is None

    second = gw.submit("ai", "ai", intent, NVDA)
    assert second.ok is False
    assert second.refusal == APPROVAL_REQUIRED

    assert len(dry.calls) == 1
    assert len(store.orders()) == 1
    assert store.orders()[0]["client_order_id"] == first.cid


APPROVAL_MISMATCHES = (
    ("size", dict(size=D("2"))),
    ("price", dict(price=D("101"))),
    ("side", dict(side="SELL")),
)


@pytest.mark.parametrize(
    "case,differing", APPROVAL_MISMATCHES, ids=[c[0] for c in APPROVAL_MISMATCHES]
)
def test_approval_mismatch_refused(store, case, differing):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    # The approval covers BUY 1 NVDA-USD at 100 on the dry book.
    approvals.approve("apr-1", side="BUY", size=D("1"), limit_price=D("100"))
    size = differing.get("size", D("1"))
    price = differing.get("price", D("100"))
    side = differing.get("side", "BUY")
    intent = place(side=side, size=size, price=price, approval_id="apr-1")

    assert gw.check("ai", "ai", intent, NVDA) == APPROVAL_REQUIRED
    assert gw.submit("ai", "ai", intent, NVDA).refusal == APPROVAL_REQUIRED

    assert dry.calls == []
    assert store.orders() == []


def test_approval_mismatch_on_product_refused(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    # Approved for NVDA, offered for VOO — same price, different instrument.
    approvals.approve(
        "apr-1", side="BUY", size=D("1"), limit_price=D("50"), product=NVDA
    )
    intent = place(size=D("1"), price=D("50"), approval_id="apr-1")

    assert gw.check("ai", "ai", intent, VOO) == APPROVAL_REQUIRED
    assert gw.submit("ai", "ai", intent, VOO).refusal == APPROVAL_REQUIRED

    assert dry.calls == []
    assert store.orders() == []


def test_approval_unknown_refused(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    intent = place(size=D("1"), price=D("100"), approval_id="apr-nowhere")
    assert gw.check("ai", "ai", intent, NVDA) == APPROVAL_REQUIRED
    assert gw.submit("ai", "ai", intent, NVDA).refusal == APPROVAL_REQUIRED

    assert dry.calls == []
    assert store.orders() == []


def test_approval_consumed_with_insert(store, monkeypatch):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)
    intent = approved(approvals, size=D("1"), price=D("100"))

    def refuse_the_row(*args, **kwargs):
        raise RuntimeError("the order row could not be written")

    monkeypatch.setattr(store, "insert_order", refuse_the_row)

    with pytest.raises(RuntimeError):
        gw.submit("ai", "ai", intent, NVDA)

    # The spend and the row are one transaction: the approval is unspent.
    assert store.orders() == []
    assert approvals.spent(intent.approval_id) is False
    assert dry.calls == []


def test_approval_consume_zero_rows_aborts_insert(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)
    # Approved by its fields, but with nothing left to spend: the second
    # approval of one preview cannot place a second order.
    intent = approved(
        approvals, "apr-1", size=D("1"), price=D("100"), spendable=False
    )

    res = gw.submit("ai", "ai", intent, NVDA)

    assert res.ok is False
    assert res.refusal == APPROVAL_REQUIRED
    assert dry.calls == []
    assert store.orders() == []


# ---------------------------------------------------------------- live route


def test_live_route_without_equity_live_refused(store):
    dry = RecordingExchange()
    account = FakeEquityAccount({"USD": D("1000")})
    live = RecordingLive(equity=account)
    switchers = Switches(store, {})
    switchers.set("ai_live_enabled", True)
    # equity_live keeps its default (off), so the live switch alone is not enough.
    gw = make_equity_gateway(
        store,
        exchange=dry,
        books=BookRouter(dry, live),
        switches=switchers,
    )

    assert gw.check("ai", "ai", place(size=D("1")), NVDA) == LIVE_DISABLED
    assert dry.calls == []
    assert live.calls == []
    assert account.calls == 0
    assert store.orders() == []


def test_live_equity_sent_to_equity_path(store):
    dry = RecordingExchange()
    account = FakeEquityAccount({"USD": D("1000")})
    live = RecordingLive(equity=account)
    switchers = Switches(store, {})
    switchers.set("ai_live_enabled", True)
    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        env={EQUITY_LIVE_ENV: "true"},
        exchange=dry,
        books=BookRouter(dry, live),
        switches=switchers,
        approvals=approvals,
    )

    intent = approved(approvals, size=D("1"), price=D("100"), book="live")
    res = gw.submit("ai", "ai", intent, NVDA)

    assert res.ok is True
    assert res.refusal is None
    assert res.cid == f"cb-ai-{intent.approval_id}"

    # The live account's equity path, once, and the crypto totals never read.
    assert [call[0] for call in live.calls] == ["place_equity_limit"]
    assert live.calls[0][1:] == (res.cid, NVDA, "BUY", D("1"), D("100"))
    assert account.calls >= 1
    assert dry.calls == []

    row = store.order(res.cid)
    assert row["book"] == "live"
    assert row["product_type"] == "EQUITY"
    assert row["status"] == OPEN


# ---------------------------------------------------------------- equity value


def test_equity_value_pool_definition(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    no_equity_snaps = cache_with(crypto_snap(XRP))
    gw = make_equity_gateway(
        store, exchange=dry, approvals=approvals, snaps=no_equity_snaps
    )

    # No shares anywhere: no snapshot is needed and the pool is all capital.
    assert gw.equity_value() == D("150")
    assert gw.equity_value("dry") == D("150")
    assert gw.equity_value("live") == D("150")

    # Ten shares bought at 100, marked at 110, plus what is left of the pool.
    seed_filled_buy(store, size=D("10"), price=D("100"), filled_value=D("1000"))
    marked = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        snaps=cache_with(crypto_snap(XRP), equity_snap(NVDA, "110")),
    )
    assert marked.ledger.equity_pool_used("dry") == D("1000")
    assert marked.equity_value() == D("10") * D("110") + (D("150") - D("1000"))
    assert marked.equity_value() == D("250")

    # A held symbol with no usable snapshot makes the whole figure unknown,
    # while a symbol held at zero needs no snapshot at all.
    seed_filled_buy(
        store, product=VOO, size=D("3"), price=D("50"), filled_value=D("150"), cid_suffix=2
    )
    unknown = make_equity_gateway(
        store,
        exchange=dry,
        approvals=approvals,
        snaps=cache_with(
            crypto_snap(XRP),
            equity_snap(NVDA, "110", ts=CLOCK),
            equity_snap(VOO, "50", ts=CLOCK - 10_000),
        ),
        now=lambda: CLOCK,
    )
    assert unknown.equity_value() is None

    assert dry.calls == []


# ---------------------------------------------------------------- execution


def test_equity_order_row_and_send(store):
    approvals = Approvals(store)
    dry = RecordingDry(
        store.conn,
        lambda product: None,  # never read: an equity order asks no book
        FEE_RATE,
        is_equity=lambda product: product in (NVDA, VOO),
    )
    dry.deposit("USD", D("1000"), "seed")
    dry.deposit("USDC", D("100"), "seed")
    dry.deposit("XRP", D("50"), "seed")
    gw = make_equity_gateway(
        store, exchange=dry, approvals=approvals, totals=dry.totals
    )

    intent = approved(approvals, size=D("1"), price=D("100"))
    res = gw.submit("ai", "ai", intent, NVDA)

    assert res.ok is True
    assert res.refusal is None
    assert res.cid == f"cb-ai-{intent.approval_id}"

    row = store.order(res.cid)
    assert row["product_type"] == "EQUITY"
    assert row["status"] == OPEN
    assert row["product"] == NVDA
    assert row["price"] == D("100")
    assert row["size"] == D("1")
    assert row["book"] == "dry"

    # One send, on the equity path, at exactly the approved price.
    assert [call[0] for call in dry.calls] == ["place_equity_limit"]
    assert dry.calls[0][1:] == (res.cid, NVDA, "BUY", D("1"), D("100"))

    resting = dry.list_open_orders()
    assert [order["client_order_id"] for order in resting] == [res.cid]
    assert len(store.orders()) == 1


def test_equity_reservation_zero_fee(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(
        store,
        capital="100",
        exchange=dry,
        approvals=approvals,
        totals=lambda: equity_totals(usd="100"),
    )

    # The whole 100 is available and the order costs exactly 100: no fee is
    # added, so it fits.
    intent = approved(approvals, size=D("1"), price=D("100"))
    res = gw.submit("ai", "ai", intent, NVDA)
    assert res.ok is True
    assert res.refusal is None

    held = gw.ledger.holding("ai", NVDA, book="dry")
    assert held.reserved_quote == D("100")
    assert held.available_quote == D("0")

    assert [call[0] for call in dry.calls] == ["place_equity_limit"]


SURFACED_REFUSALS = (
    exchange_mod.EQUITY_PREVIEW_UNCONFIRMED,
    router_mod.NO_EQUITY_ACCOUNT,
    exchange_mod.PRODUCT_TYPE_UNKNOWN,
)


@pytest.mark.parametrize("reason", SURFACED_REFUSALS)
def test_equity_preview_unconfirmed_surfaced(store, reason):
    dry = FakeExchange(reason=reason)
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    intent = approved(approvals, size=D("1"), price=D("100"))
    res = gw.submit("ai", "ai", intent, NVDA)

    # The code the exchange named is the refusal the caller reads, and the row
    # carries it as its note.
    assert res.ok is False
    assert res.refusal == reason
    assert len(dry.calls) == 1  # one attempt: an equity order is never repriced

    row = store.order(res.cid)
    assert row["status"] == REJECTED
    assert row["note"] == reason


def test_equity_other_exchange_refusal_is_rejected(store):
    dry = FakeExchange(reason="INSUFFICIENT_FUND")
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    intent = approved(approvals, size=D("1"), price=D("100"))
    res = gw.submit("ai", "ai", intent, NVDA)

    assert res.ok is False
    assert res.refusal == EXCHANGE_REJECTED
    assert len(dry.calls) == 1
    assert store.order(res.cid)["note"] == "INSUFFICIENT_FUND"


# ---------------------------------------------------------------- crypto path


def test_crypto_chain_unchanged(store):
    dry = FakeExchange()
    approvals = Approvals(store)
    gw = make_equity_gateway(store, exchange=dry, approvals=approvals)

    res = gw.submit("bot", "b1", crypto_place(size=D("10"), price=D("0.95")))
    assert res.ok is True
    assert res.refusal is None

    row = store.order(res.cid)
    assert row["product_type"] == "SPOT"
    assert row["status"] == OPEN
    assert [call[0] for call in dry.calls] == ["place_limit"]
    assert dry.calls[0][5] == D("0.95")  # the maker price, below the ask

    # A refusal still refuses, with nothing sent and nothing written.
    small = gw.submit("bot", "b1", crypto_place(size=D("0.5")))
    assert small.ok is False
    assert small.refusal == TOO_SMALL
    assert len(dry.calls) == 1
    assert len(store.orders()) == 1


# ---------------------------------------------------------------- the totals view


def test_gateway_totals_must_be_callable(store):
    """The dry book's totals are read on every step, so they are a callable."""
    dry = FakeExchange()

    # One reading of a mapping is a stale reading: a mapping is refused rather
    # than wrapped, so a caller cannot hand the chain a figure nobody updates.
    with pytest.raises(TypeError):
        make_equity_gateway(store, exchange=dry, totals={"USD": D("1")})

    # A callable is what the gateway takes, and what it reads on every call.
    gw = make_equity_gateway(
        store, exchange=dry, totals=lambda: equity_totals(usd="1")
    )
    assert gw.totals() == equity_totals(usd="1")