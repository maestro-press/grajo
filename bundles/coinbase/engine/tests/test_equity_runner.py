"""test_equity_runner.py: a cycle's equity half, and the router under the kill path.

Synthetic fixtures only: no network, no client, no request, and nothing waits on
the wall clock.  A real `Store` on a temporary file, the real `Ledger`, `Limits`,
`SnapshotCache`, `OrderGateway` and `Runner`; only the two Coinbase accounts and
the public market data are fakes.

The two accounts are two `FakeAccount` fakes behind a real `ExchangeRouter`:
`crypto` holds the spot products, `equity` holds the equities and is the only one
that carries an `is_equity`, and the router routes every call by product and
never by trying one account and falling back to the other.  `product_of` reads
the store's own order rows, because that is where an order id's product is known;
`usd_one_pool=False` because the two keys see two separate USD pools.

The rows an equity fixture needs are built the way the engine builds one: by
letting `reconcile` adopt what the exchange reports, so a row's product and
`product_type` are the engine's own answers and never the test's.  A row the
gateway placed is seeded directly, with the `EQUITY` kind the gateway writes.

`MarketSnapshot` for an equity is one print, so `bid == ask` is that print;
`EquityMarket.equity_quote()` is how a poll reads it, and it counts its calls so a
test can tell a poll that happened from one that only should have.
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal as D
from pathlib import Path

from crow_coinbase.books import BookRouter, Switches
from crow_coinbase.exchange import PermanentError
from crow_coinbase.gateway import APPROVAL_REQUIRED, GatewayResult, OrderGateway
from crow_coinbase.ledger import Ledger
from crow_coinbase.limits import CapWindow, Limits
from crow_coinbase.money import ProductSpec
from crow_coinbase.reconcile import reconcile
from crow_coinbase.router import ExchangeRouter
from crow_coinbase.runner import UNALLOCATED_LIVE_KEY, Runner
from crow_coinbase.snapshot import SnapshotCache
from crow_coinbase.store import FILLED, OPEN, PENDING_SUBMIT, Store
from crow_coinbase.strategies.base import Decision, MarketSnapshot, OrderIntent
from crow_coinbase.watchdog import cancel_all_cb_orders

# ---------------------------------------------------------------- products

NVDA = "NVDA-USD"
XRP = "XRP-USDC"

FEE_RATE = D("0.005")
EQUITY_CAPITAL = D("100")

# The one kv key the equity drawdown alert's episode lives under, and the owner
# the equity high-water mark is kept for.
EQUITY_ALERT_KEY = "equity_alert:dry"
EQUITY_HWM_OWNER = "_equity"
PORTFOLIO_OWNER = "_portfolio"

# The kv key the equity capital in force on the dry book is kept under, and the
# one event a capital changed at run time writes.
EQUITY_CAPITAL_KEY = "equity_capital:dry"
EQUITY_REBASE_EVENT = "equity capital changed; the equity high-water mark was reset"

# A string no exchange error may ever put into an event, a log line or a panel.
# It stands in for the URL or token a quote source's own message could carry.
CANARY = "secret-canary-token"

ENV = {
    "CROW_COINBASE_LIVE": "false",
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": XRP,
    "CROW_COINBASE_EQUITY_PRODUCTS": NVDA,
    "CROW_COINBASE_EQUITY_AI_CAPITAL_USD": str(EQUITY_CAPITAL),
    # The caps this file's orders are measured against: only the equity pool and
    # the equity mark are under test, so the money budgets are wide open.
    "CROW_COINBASE_AI_CAPITAL_USD": "0",
    "CROW_COINBASE_EQUITY_MAX_ORDER_USD": "1000",
    "CROW_COINBASE_EQUITY_DAILY_NOTIONAL_USD": "100000",
}

# The dry book's totals: no owner is short, whatever the fixture's rows are.  The
# shares are there because an equity fixture's filled buy is a synthetic row the
# simulated account has to back, exactly as its cash is.
DRY_TOTALS = {"USD": D("1000"), "USDC": D("1000"), "XRP": D("1000"), "NVDA": D("1000")}

SPECS = {
    NVDA: ProductSpec(
        NVDA,
        price_increment=D("0.01"),
        base_increment=D("0.0001"),
        quote_increment=D("0.01"),
        base_min_size=D("0.0001"),
        quote_min_size=D("1"),
        product_type="EQUITY",
        fractionable=True,
    ),
    XRP: ProductSpec(
        XRP,
        price_increment=D("0.0001"),
        base_increment=D("0.1"),
        quote_increment=D("0.01"),
        base_min_size=D("1"),
        quote_min_size=D("1"),
    ),
}


# ---------------------------------------------------------------- outside world


def cid_for(owner, n, side="B", level=0):
    """A client order id in the engine's own cb-<owner>-<side><level>-<hex> form."""
    return f"cb-{owner}-{side}{level:+d}-{n:012x}"


def order_snapshot(
    order_id,
    client_order_id,
    *,
    product=XRP,
    side="BUY",
    status="OPEN",
    price="1.0",
    size="10",
    filled_size="0",
    filled_value="0",
    total_fees="0",
):
    """One normalised exchange order snapshot, shaped like an adapter's own."""
    return {
        "order_id": order_id,
        "client_order_id": client_order_id,
        "product": product,
        "side": side,
        "status": status,
        "price": D(price),
        "size": D(size),
        "filled_size": D(filled_size),
        "filled_value": D(filled_value),
        "total_fees": D(total_fees),
    }


def trade_fill(trade_id, order_id, *, product=XRP, side="BUY", size="10", price="1.0"):
    return {
        "trade_id": trade_id,
        "order_id": order_id,
        "product": product,
        "side": side,
        "size": D(size),
        "price": D(price),
        "commission": D("0"),
        "trade_time": "2026-01-01T00:00:00Z",
        "trade_type": "FILL",
    }


class FakeAccount:
    """One Coinbase account: a scripted book, fills per order, and a call log.

    `book` is the account's open orders and `snapshots` is every order it can
    answer `get_order` about, so a test can model an order that left the open list
    without leaving the account.  `cancel` takes the cancelled orders off `book`,
    the way the real account does, and records the id list it was handed.
    """

    dry_run = True

    def __init__(self, name, *, totals=None, balances=None):
        self.name = name
        self.calls = []
        self.book = []
        self.snapshots = {}
        self.fills_by_order = {}
        self.totals_map = dict(totals or {})
        self.balances_map = dict(balances or {})
        self.fail_cancel = None

    # -- fixtures
    def add(self, snapshot):
        """Put one order on the account: it is open, and it answers get_order."""
        self.snapshots[snapshot["order_id"]] = dict(snapshot)
        self.book.append(dict(snapshot))
        return snapshot["order_id"]

    def settle(self, order_id, *, status, **fields):
        """Move an order's own snapshot to a terminal state, off the open list."""
        snapshot = dict(self.snapshots[order_id])
        snapshot["status"] = status
        snapshot.update(fields)
        self.snapshots[order_id] = snapshot
        self.book = [entry for entry in self.book if entry["order_id"] != order_id]
        return snapshot

    # -- reads
    def list_open_orders(self, product=None):
        self.calls.append(("list_open_orders", product))
        return [
            dict(entry)
            for entry in self.book
            if product is None or entry["product"] == product
        ]

    def get_order(self, order_id, product=None):
        self.calls.append(("get_order", order_id, product))
        snapshot = self.snapshots.get(order_id)
        if snapshot is None:
            raise PermanentError(f"{order_id}: 404 not found")
        return dict(snapshot)

    def fills(self, order_id, product=None):
        self.calls.append(("fills", order_id, product))
        return [dict(fill) for fill in self.fills_by_order.get(order_id, [])]

    def find_by_client_id(self, cid, since, product=None):
        self.calls.append(("find_by_client_id", cid, since, product))
        for snapshot in self.snapshots.values():
            if snapshot.get("client_order_id") == cid:
                return dict(snapshot)
        return None

    def totals(self):
        self.calls.append(("totals",))
        return dict(self.totals_map)

    def balances(self):
        self.calls.append(("balances",))
        return dict(self.balances_map)

    # -- writes
    def cancel(self, order_ids):
        ids = list(order_ids)
        self.calls.append(("cancel", tuple(ids)))
        if self.fail_cancel is not None:
            raise self.fail_cancel
        self.book = [entry for entry in self.book if entry["order_id"] not in ids]
        return {order_id: True for order_id in ids}

    def place_limit(self, cid, product, side, size, price):
        self.calls.append(("place_limit", cid, product))
        return {"ok": True, "order_id": f"{self.name}-{cid}", "reason": None}

    def place_equity_limit(self, cid, product, side, size, price):
        self.calls.append(("place_equity_limit", cid, product))
        return {"ok": True, "order_id": f"{self.name}-{cid}", "reason": None}

    def deposit(self, currency, amount, note):
        self.calls.append(("deposit", currency))

    def advance(self, now):
        self.calls.append(("advance", now))
        return []

    def server_time(self):
        self.calls.append(("server_time",))
        # The exchange's clock is this box's: a measured skew, not a huge one.
        return time.time()

    def maker_fee_rate(self):
        self.calls.append(("maker_fee_rate",))
        return None


class FakeEquityAccount(FakeAccount):
    """The equity account: the one adapter that says what an equity product is."""

    def __init__(self, name="equity", **kwargs):
        super().__init__(name, **kwargs)
        self.is_equity = lambda product: product == NVDA


class CryptoMarket:
    """The crypto book and poll window, and how often each was read."""

    def __init__(self, bid=D("0.99"), ask=D("1.00")):
        self.bid, self.ask = D(bid), D(ask)
        self.best_bid_ask_calls = 0

    def best_bid_ask(self):
        self.best_bid_ask_calls += 1
        return self.bid, self.ask

    def range_since(self, since):
        return self.bid, self.ask

    def candles(self, start, end):
        return []


class EquityMarket:
    """An equity quote: one print, so both sides are the same price.

    `fail` makes the next reads raise `error`, and every read is counted, so a
    test can tell an equity poll that ran from one that never should have.
    """

    def __init__(self, price=D("100"), *, error=None):
        self.price = D(price)
        self.quotes = 0
        self.fail = False
        self.error = (
            RuntimeError("equity quote unavailable") if error is None else error
        )

    def equity_quote(self):
        self.quotes += 1
        if self.fail:
            raise self.error
        return self.price, self.price


class Approvals:
    """The gateway's approval rail, faked: approved fields plus a spend marker."""

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
    ):
        self.approved[approval_id] = (side, D(size), D(limit_price), product, book)
        self.store.put(self._key(approval_id), True)
        return approval_id

    def check(self, approval_id, intent, *, product, book):
        fields = self.approved.get(approval_id)
        found = (intent.side, intent.size, intent.limit_price, product, book)
        if fields is None or found != fields:
            return APPROVAL_REQUIRED
        return None

    def consume(self, conn, approval_id):
        conn.execute("DELETE FROM kv WHERE key=?", (self._key(approval_id),))

    @staticmethod
    def _key(approval_id):
        return f"test-approval:{approval_id}"


class SpyStrategy:
    """A strategy that answers nothing, so a cycle places no order of its own."""

    def __init__(self, name="grid"):
        self.name = name

    def validate(self, params, spec=None):
        return None

    def fee_guard(self, params, maker_fee_pct):
        return None

    def init_intents(self, snap, view):
        return Decision([])

    def decide(self, snap, view):
        return Decision([])


# ---------------------------------------------------------------- the engine


class Engine:
    """One engine on a temporary directory, with the two accounts behind a router."""

    def __init__(
        self,
        root,
        *,
        env=None,
        live=False,
        equity_products=NVDA,
        equity_capital=EQUITY_CAPITAL,
        live_crypto_totals=None,
        live_equity_totals=None,
        bot=False,
    ):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.env = dict(ENV)
        self.env["CROW_COINBASE_EQUITY_PRODUCTS"] = equity_products
        self.env["CROW_COINBASE_EQUITY_AI_CAPITAL_USD"] = str(equity_capital)
        self.env.update(env or {})

        self.store = Store(self.root / "engine.sqlite")
        self.limits = Limits.from_env(self.env)

        self.dry = FakeAccount("dry", totals=DRY_TOTALS)
        self.crypto_live = FakeAccount(
            "live-crypto",
            totals={"USD": D("1000")}
            if live_crypto_totals is None
            else live_crypto_totals,
        )
        self.equity_live = FakeEquityAccount(
            totals={"USD": D("1000")}
            if live_equity_totals is None
            else live_equity_totals
        )
        self.live_router = ExchangeRouter(
            self.crypto_live,
            self.equity_live,
            is_equity=lambda product: self.limits.is_equity(product),
            product_of=self.product_of,
            usd_one_pool=False,
            equity_bases=("NVDA",),
        )
        self.books = BookRouter(self.dry, self.live_router if live else None)

        self.snapshots = SnapshotCache(
            poll_seconds=self.limits.poll_seconds, now=time.time
        )
        # A measured clock, so a place intent is not refused CLOCK_SKEW.
        self.snapshots.set_clock(time.time(), time.time())

        self.markets = {
            XRP: CryptoMarket(),
            NVDA: EquityMarket(),
        }
        self.crypto_market = self.markets[XRP]
        self.equity_market = self.markets[NVDA]
        self.market_asks = []

        self.ledger = Ledger(
            self.store,
            fee_rate=FEE_RATE,
            ai_capital=lambda: self.limits.ai_capital_usd,
            equity_ai_capital=lambda: self.limits.equity_ai_capital_usd,
            is_equity=lambda product: self.limits.is_equity(product),
        )
        self.switches = Switches(self.store, self.env)
        self.approvals = Approvals(self.store)
        self.gateway = OrderGateway(
            store=self.store,
            ledger=self.ledger,
            limits=self.limits,
            caps=CapWindow(self.store, time.time),
            snapshots=self.snapshots,
            spec_for=self.spec_for,
            fee_rate=FEE_RATE,
            totals=self.dry.totals,
            exchange=self.dry,
            books=self.books,
            switches=self.switches,
            approval_check=self.approvals.check,
            consume_approval=self.approvals.consume,
            session_open=lambda ts: True,
            sleep=lambda seconds: None,
        )

        if bot:
            self.store.create_bot("b1", XRP, "grid", {}, D("0"), D("0"))

    # -- collaborators
    def spec_for(self, product):
        return SPECS[product]

    def market_for(self, product):
        self.market_asks.append(product)
        market = self.markets.get(product)
        if market is None:
            raise RuntimeError(f"no market data for {product}")
        return market

    def product_of(self, order_id):
        """An order id's product, read from the store's own rows.

        That is where the engine knows it: the router must never guess between the
        two accounts, so an id no row names stays unknown.
        """
        row = (
            self.store.conn()
            .execute(
                "SELECT product FROM orders WHERE order_id=?", (str(order_id),)
            )
            .fetchone()
        )
        return row["product"] if row else None

    def runner(self, *, session_open=None, heartbeat=None):
        return Runner(
            store=self.store,
            gateway=self.gateway,
            exchange=self.dry,
            snapshots=self.snapshots,
            strategies={"grid": SpyStrategy()},
            env=self.env,
            market_for=self.market_for,
            spec_for=self.spec_for,
            heartbeat_path=(
                Path(heartbeat) if heartbeat is not None else self.root / "heartbeat"
            ),
            sleep=lambda seconds: None,
            session_open=(lambda ts: True) if session_open is None else session_open,
        )

    # -- fixtures
    def set_equity_capital(self, capital):
        """Put a new equity capital in force, as the runtime limits allow.

        The capital is read off the limits in force (`gateway.limits`) on every
        call, so replacing them is how a value changed at run time reaches the
        cycle: the ledger's own callable reads `self.limits` for the same reason.
        """
        self.env["CROW_COINBASE_EQUITY_AI_CAPITAL_USD"] = str(capital)
        self.limits = Limits.from_env(self.env)
        self.gateway.limits = self.limits
        return self.limits

    def reconcile(self, book="dry"):
        exchange = self.dry if book == "dry" else self.live_router
        return reconcile(
            self.store,
            exchange,
            now=time.time(),
            gateway=self.gateway,
            trades_csv=self.root / "trades.csv",
            book=book,
        )

    def order(
        self,
        client_order_id,
        *,
        owner="ai",
        product=NVDA,
        side="BUY",
        level=0,
        price="100",
        size="1",
        status=OPEN,
        order_id=None,
        book="dry",
        product_type="EQUITY",
        filled_size=None,
        filled_value=None,
        fees="0",
    ):
        """One order row written the engine's own way, settled as asked."""
        self.store.insert_order(
            client_order_id,
            owner,
            "ai" if owner == "ai" else "bot",
            product,
            side,
            level,
            D(price),
            D(size),
            status=status,
            order_id=order_id,
            book=book,
            product_type=product_type,
        )
        if filled_size is not None:
            self.store.update_order(
                client_order_id,
                filled_size=D(filled_size),
                filled_value=D(filled_value)
                if filled_value is not None
                else D(filled_size) * D(price),
                fees=D(fees),
            )
        return client_order_id

    def filled_equity_buy(self, *, size="4", price="100", fees="0", n=90):
        """A buy the equity account already filled: the pool's spend, and shares."""
        return self.order(
            cid_for("ai", n),
            product=NVDA,
            side="BUY",
            price=price,
            size=size,
            status=FILLED,
            order_id=f"ex-filled-{n}",
            book="dry",
            product_type="EQUITY",
            filled_size=size,
            filled_value=D(size) * D(price),
            fees=fees,
        )

    def snapshot(self, product, price, *, bid=None, ask=None):
        """Put one fresh print in the cache by hand."""
        last = D(price)
        self.snapshots.put(
            MarketSnapshot(
                product,
                last if bid is None else D(bid),
                last if ask is None else D(ask),
                last,
                last,
                time.time(),
            )
        )

    def close(self):
        self.store.close()


def events(store, level=None, kind=None):
    rows = store.conn().execute(
        "SELECT level, kind, message FROM events ORDER BY id"
    ).fetchall()
    found = [
        {"level": row["level"], "kind": row["kind"], "message": row["message"]}
        for row in rows
    ]
    if level is not None:
        found = [event for event in found if event["level"] == level]
    if kind is not None:
        found = [event for event in found if event["kind"] == kind]
    return found


def alerts(store):
    """The warn-level `alert` events: the equity drawdown alert's own shape."""
    return events(store, level="warn", kind="alert")


def rebases(store):
    """The events a changed equity capital wrote in a cycle, in order."""
    return [event for event in events(store) if event["message"] == EQUITY_REBASE_EVENT]


def quote_warnings(store):
    """The events a failing equity quote wrote: one per episode, per product."""
    return [
        event["message"]
        for event in events(store, level="warn")
        if f"poll {NVDA} failed" in event["message"]
    ]


def cancels(account):
    """Every id list the account was asked to cancel, in call order."""
    return [call[1] for call in account.calls if call[0] == "cancel"]


def cancelled_ids(account):
    return {order_id for ids in cancels(account) for order_id in ids}


def equity_intent(*, side="BUY", size=D("0.5"), price=D("70"), approval_id="apr-1"):
    return OrderIntent(
        action="place",
        side=side,
        size=D(size),
        limit_price=D(price),
        level=0,
        cancel_cid=None,
        reason="test",
        approval_id=approval_id,
    )


# ---------------------------------------------------------------- session sweep


def test_session_sweep_cancels_open_equity(tmp_path):
    """A closed session takes the ai's resting equity off both books, and nothing else."""
    engine = Engine(tmp_path / "closed", live=True, bot=True)
    dry_equity = engine.order(
        cid_for("ai", 1), product=NVDA, book="dry", order_id="ex-dry-eq"
    )
    live_equity = engine.order(
        cid_for("ai", 2), product=NVDA, book="live", order_id="ex-live-eq"
    )
    ai_crypto = engine.order(
        cid_for("ai", 3),
        product=XRP,
        book="dry",
        product_type="SPOT",
        price=D("1"),
        size=D("10"),
        order_id="ex-ai-crypto",
    )
    bot_crypto = engine.order(
        cid_for("b1", 4),
        owner="b1",
        product=XRP,
        book="dry",
        product_type="SPOT",
        price=D("1"),
        size=D("10"),
        order_id="ex-bot-crypto",
    )
    for snapshot in (
        order_snapshot("ex-dry-eq", dry_equity, product=NVDA, price="100", size="1"),
        order_snapshot("ex-ai-crypto", ai_crypto, product=XRP),
        order_snapshot("ex-bot-crypto", bot_crypto, product=XRP),
    ):
        engine.dry.add(snapshot)
    engine.equity_live.add(
        order_snapshot("ex-live-eq", live_equity, product=NVDA, price="100", size="1")
    )

    closed = engine.runner(session_open=lambda ts: False)
    payload = closed.cycle()

    assert payload["cycle"] == 1
    # Each equity row was taken off the account its own row belongs to.
    assert cancelled_ids(engine.dry) == {"ex-dry-eq"}
    assert cancelled_ids(engine.equity_live) == {"ex-live-eq"}
    assert cancelled_ids(engine.crypto_live) == set()
    # The crypto row and the bot's row are not the session's business.
    assert engine.store.order(ai_crypto)["status"] == OPEN
    assert engine.store.order(bot_crypto)["status"] == OPEN

    # An open session sweeps nothing at all.
    opened = Engine(tmp_path / "open", live=True, bot=True)
    opened_equity = opened.order(
        cid_for("ai", 5), product=NVDA, book="dry", order_id="ex-open-eq"
    )
    opened.dry.add(
        order_snapshot("ex-open-eq", opened_equity, product=NVDA, price="100", size="1")
    )
    opened.runner(session_open=lambda ts: True).cycle()
    assert cancels(opened.dry) == []
    assert cancels(opened.equity_live) == []
    assert opened.store.order(opened_equity)["status"] == OPEN

    # No equity rows: no cancel call on any account.
    crypto_only = Engine(tmp_path / "crypto-only", live=True, bot=True)
    only_ai = crypto_only.order(
        cid_for("ai", 6),
        product=XRP,
        book="dry",
        product_type="SPOT",
        price=D("1"),
        size=D("10"),
        order_id="ex-only-ai",
    )
    crypto_only.dry.add(order_snapshot("ex-only-ai", only_ai, product=XRP))
    crypto_only.runner(session_open=lambda ts: False).cycle()
    assert cancels(crypto_only.dry) == []
    assert cancels(crypto_only.equity_live) == []
    assert cancels(crypto_only.crypto_live) == []

    # A refusal from the gateway is a warning: the cycle still gets through, and
    # every row is still offered.
    refused = Engine(tmp_path / "refused", live=True, bot=True)
    refused_dry = refused.order(
        cid_for("ai", 7), product=NVDA, book="dry", order_id="ex-refused-dry"
    )
    refused_live = refused.order(
        cid_for("ai", 8), product=NVDA, book="live", order_id="ex-refused-live"
    )
    refused.dry.add(
        order_snapshot(
            "ex-refused-dry", refused_dry, product=NVDA, price="100", size="1"
        )
    )
    refused.equity_live.add(
        order_snapshot(
            "ex-refused-live", refused_live, product=NVDA, price="100", size="1"
        )
    )
    real_submit = refused.gateway.submit
    offered = []

    def refusing(source, owner, intent, product=None):
        if intent.action == "cancel":
            offered.append(intent.cancel_cid)
            return GatewayResult(False, intent.cancel_cid, "CANCEL_FAILED")
        return real_submit(source, owner, intent, product)

    refused.gateway.submit = refusing
    finished = refused.runner(session_open=lambda ts: False).cycle()

    assert finished["cycle"] == 1
    assert set(offered) == {refused_dry, refused_live}

    for created in (engine, opened, crypto_only, refused):
        created.close()


def test_session_sweep_cancels_pending_submit_equity_with_order_id(tmp_path):
    """A closed session also retires a pending equity row that already has an id."""
    engine = Engine(tmp_path / "pending", live=True)
    # The send's answer was lost, so the row is still pending — but the order is
    # on the account and a close has to take it off.
    sent = engine.order(
        cid_for("ai", 11),
        product=NVDA,
        book="dry",
        status=PENDING_SUBMIT,
        order_id="ex-pending-eq",
    )
    # A pending row that never reached the account has nothing to cancel.
    never_sent = engine.order(
        cid_for("ai", 12),
        product=NVDA,
        book="dry",
        status=PENDING_SUBMIT,
        order_id=None,
    )

    payload = engine.runner(session_open=lambda ts: False).cycle()

    assert payload["cycle"] == 1
    assert cancelled_ids(engine.dry) == {"ex-pending-eq"}
    assert cancels(engine.equity_live) == []
    assert cancels(engine.crypto_live) == []
    assert engine.store.order(sent)["status"] == PENDING_SUBMIT
    assert engine.store.order(never_sent)["status"] == PENDING_SUBMIT

    engine.close()


def test_session_sweep_warning_has_no_error_text(tmp_path, caplog):
    """A sweep whose cancel raises says the class only, and the cycle still finishes."""
    engine = Engine(tmp_path, live=True)
    resting = engine.order(
        cid_for("ai", 31), product=NVDA, book="dry", order_id="ex-sweep-raise"
    )
    engine.dry.add(
        order_snapshot("ex-sweep-raise", resting, product=NVDA, price="100", size="1")
    )

    def refusing_submit(source, owner, intent, product=None):
        raise RuntimeError(f"cancel backend said {CANARY}")

    engine.gateway.submit = refusing_submit

    with caplog.at_level(logging.WARNING, logger="crow_coinbase.runner"):
        payload = engine.runner(session_open=lambda ts: False).cycle()

    assert payload["cycle"] == 1
    assert "RuntimeError" in caplog.text
    assert CANARY not in caplog.text
    assert CANARY not in str(
        [event["message"] for event in events(engine.store)]
    )
    # The row was offered and left standing for the next pass.
    assert engine.store.order(resting)["status"] == OPEN

    engine.close()


# ---------------------------------------------------------------- equity polling


def test_equity_snapshot_only_in_session(tmp_path):
    """An equity is polled inside the session, and never outside it."""
    engine = Engine(tmp_path)

    opened = engine.runner(session_open=lambda ts: True)
    opened.cycle()

    assert NVDA in engine.market_asks
    assert engine.equity_market.quotes == 1
    cached = engine.snapshots.get(NVDA)
    assert cached is not None
    # An equity print is ONE price: bid == ask is the quote, not a crossed book.
    assert cached.bid == cached.ask == D("100")

    # Closed: the product is never asked for, and its snapshot is left alone.
    engine.market_asks.clear()
    engine.runner(session_open=lambda ts: False).cycle()
    assert NVDA not in engine.market_asks
    assert engine.equity_market.quotes == 1
    assert engine.snapshots.get(NVDA) == cached

    # A failing quote is a warning once per episode, and the previous snapshot
    # stands while the episode lasts: three failing cycles are still one warning.
    engine.snapshot(NVDA, "101")
    kept = engine.snapshots.get(NVDA)
    engine.equity_market.fail = True
    for _ in range(3):
        engine.runner(session_open=lambda ts: True).cycle()

    assert engine.snapshots.get(NVDA) == kept
    assert len(quote_warnings(engine.store)) == 1, quote_warnings(engine.store)

    # A quote that reads again ends the episode (and refreshes the snapshot), so
    # the next failure is news again.
    engine.equity_market.fail = False
    engine.runner(session_open=lambda ts: True).cycle()
    assert engine.snapshots.get(NVDA) is not None
    engine.equity_market.fail = True
    engine.runner(session_open=lambda ts: True).cycle()

    warned = quote_warnings(engine.store)
    assert len(warned) == 2, warned

    engine.close()


def test_equity_poll_failure_event_has_no_source_text(tmp_path, caplog):
    """A quote error's own text never reaches the event, the log line or a panel."""
    engine = Engine(tmp_path)
    engine.equity_market.fail = True
    engine.equity_market.error = RuntimeError(f"quote backend said {CANARY}")

    with caplog.at_level(logging.WARNING, logger="crow_coinbase.runner"):
        payload = engine.runner(session_open=lambda ts: True).cycle()

    assert payload["cycle"] == 1

    # The stored warning names the product and the class, and nothing else.
    warned = [
        event["message"]
        for event in events(engine.store, level="warn")
        if f"poll {NVDA}" in event["message"]
    ]
    assert len(warned) == 1
    assert warned[0].startswith(f"poll {NVDA} failed")
    assert "RuntimeError" in warned[0]
    assert CANARY not in warned[0]

    # Nor does the log record carry what the source said.
    assert "RuntimeError" in caplog.text
    assert CANARY not in caplog.text

    engine.close()


def test_no_equity_products_no_equity_calls(tmp_path):
    """With no equities configured a cycle makes no equity call at all."""
    engine = Engine(tmp_path, equity_products="", bot=True)
    # Registered, so a poll that reached for it would be visible.
    engine.markets[NVDA] = EquityMarket()

    equity_reads = []
    real_value = engine.gateway.equity_value

    def counting_value(book=None):
        equity_reads.append(book)
        return real_value(book)

    engine.gateway.equity_value = counting_value
    kills = []
    real_cancel_all = engine.gateway.cancel_all

    def counting_cancel_all(*args, **kwargs):
        kills.append((args, kwargs))
        return real_cancel_all(*args, **kwargs)

    engine.gateway.cancel_all = counting_cancel_all

    payload = engine.runner(session_open=lambda ts: True).cycle()

    assert payload["cycle"] == 1
    assert NVDA not in engine.market_asks
    assert engine.markets[NVDA].quotes == 0
    assert equity_reads == []
    assert kills == []

    # The crypto half is exactly as it was: its product was polled and cached.
    assert XRP in engine.market_asks
    assert engine.crypto_market.best_bid_ask_calls == 1
    cached = engine.snapshots.get(XRP)
    assert cached is not None
    assert cached.bid == D("0.99") and cached.ask == D("1.00")

    engine.close()


# ---------------------------------------------------------------- equity mark


def test_equity_alert_once_per_episode(tmp_path):
    """A drawdown is news once per episode, and the recovery ends the episode."""
    engine = Engine(tmp_path, equity_capital=D("500"))
    engine.filled_equity_buy(size="4", price="100")
    engine.snapshot(NVDA, "100")

    runner = engine.runner(session_open=lambda ts: False)
    runner.cycle()
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("500")
    assert alerts(engine.store) == []

    # 4 shares at 70 plus 100 of cash left is 380, under 80% of the 500 mark.
    engine.snapshot(NVDA, "70")
    for _ in range(3):
        runner.cycle()

    assert len(alerts(engine.store)) == 1
    assert engine.store.get(EQUITY_ALERT_KEY) is not None

    # Back at the mark: the episode is over, and nothing further is reported.
    engine.snapshot(NVDA, "100")
    runner.cycle()
    assert engine.store.get(EQUITY_ALERT_KEY) is None
    assert len(alerts(engine.store)) == 1

    # A second fall is a new episode, so it is news again.
    engine.snapshot(NVDA, "70")
    runner.cycle()
    assert len(alerts(engine.store)) == 2
    assert engine.store.get(EQUITY_ALERT_KEY) is not None

    engine.close()


def test_equity_alert_never_halts(tmp_path):
    """The equity alert rings; it never stops a book, and it never refuses an order."""
    engine = Engine(tmp_path, equity_capital=D("500"))
    engine.filled_equity_buy(size="4", price="100")
    engine.snapshot(NVDA, "100")

    runner = engine.runner(session_open=lambda ts: False)
    runner.cycle()

    engine.snapshot(NVDA, "70")
    runner.cycle()
    assert len(alerts(engine.store)) == 1

    assert engine.gateway.is_halted() is False
    assert engine.gateway.is_halted("dry") is False
    assert engine.gateway.is_halted("live") is False

    # An equity BUY that fits the pool and the caps is still allowed out.
    engine.approvals.approve(
        "apr-1", side="BUY", size=D("0.5"), limit_price=D("70"), product=NVDA
    )
    assert (
        engine.gateway.check("ai", "ai", equity_intent(), NVDA) is None
    )

    engine.close()


def test_equity_alert_skips_unknown_value(tmp_path):
    """A held symbol nobody can price is no drawdown: no alert, no ratchet, no clear."""
    engine = Engine(tmp_path, equity_capital=D("500"))
    engine.filled_equity_buy(size="4", price="100")
    engine.store.update_hwm(EQUITY_HWM_OWNER, D("500"), "dry")
    engine.store.put(EQUITY_ALERT_KEY, True)

    # No usable snapshot for NVDA at all, and 4 shares are held.
    assert engine.gateway.equity_value("dry") is None
    engine.runner(session_open=lambda ts: False).cycle()

    assert alerts(engine.store) == []
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("500")
    assert engine.store.get(EQUITY_ALERT_KEY) is True

    engine.close()


def test_equity_hwm_ratchets_only_up(tmp_path):
    """The equity mark follows the value up and never follows it down."""
    engine = Engine(tmp_path, equity_capital=D("500"))
    engine.filled_equity_buy(size="4", price="100")
    engine.snapshot(NVDA, "100")

    runner = engine.runner(session_open=lambda ts: False)
    runner.cycle()
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("500")

    # 4 shares at 120 plus 100 left is 580.
    engine.snapshot(NVDA, "120")
    runner.cycle()
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("580")

    # 4 shares at 95 plus 100 left is 480, and the mark does not move.
    engine.snapshot(NVDA, "95")
    runner.cycle()
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("580")

    engine.close()


def test_equity_hwm_rebased_when_capital_changes(tmp_path):
    """A capital changed at run time rebases the equity mark, once, with no amounts."""
    engine = Engine(tmp_path, equity_capital=D("500"))
    runner = engine.runner(session_open=lambda ts: False)

    # Nothing stored yet: the first cycle records the capital and resets nothing.
    runner.cycle()
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("500")
    assert engine.store.get(EQUITY_CAPITAL_KEY) == "500"
    assert rebases(engine.store) == []

    # An episode marker that belonged to the old mark is stale once it is rebased.
    engine.store.put(EQUITY_ALERT_KEY, True)

    # A capital changed at run time: the next cycle runs off the new limits.
    engine.set_equity_capital(D("300"))
    restarted = engine.runner(session_open=lambda ts: False)
    restarted.cycle()

    # The mark is the NEW capital, not the old high the ratchet alone would keep.
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("300")
    assert engine.store.get(EQUITY_CAPITAL_KEY) == "300"
    assert engine.store.get(EQUITY_ALERT_KEY) is None
    reset = rebases(engine.store)
    assert len(reset) == 1
    assert reset[0]["level"] == "info"
    assert not any(ch.isdigit() for ch in reset[0]["message"])
    assert alerts(engine.store) == []

    # The same capital on a later cycle is not news again.
    restarted.cycle()
    assert len(rebases(engine.store)) == 1
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("300")
    assert engine.store.get(EQUITY_ALERT_KEY) is None

    engine.close()


def test_equity_hwm_rebase_runs_with_unknown_value(tmp_path):
    """A held symbol nobody can price still rebases the mark, and rings nothing."""
    engine = Engine(tmp_path, equity_capital=D("500"))
    # 4 shares and no snapshot for them: the book cannot be valued at all.
    engine.filled_equity_buy(size="4", price="100")
    runner = engine.runner(session_open=lambda ts: False)

    assert engine.gateway.equity_value("dry") is None

    # No value: nothing is marked, and only the capital is recorded.
    runner.cycle()
    assert engine.store.get(EQUITY_CAPITAL_KEY) == "500"
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") is None
    assert alerts(engine.store) == []

    engine.set_equity_capital(D("300"))
    restarted = engine.runner(session_open=lambda ts: False)
    restarted.cycle()

    # The rebase runs before the value is read, so it happened with no value.
    assert engine.store.get(EQUITY_CAPITAL_KEY) == "300"
    assert len(rebases(engine.store)) == 1
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") is None
    assert alerts(engine.store) == []

    engine.close()


def test_portfolio_equity_ignores_equity(tmp_path):
    """The portfolio mark is the bots' book: ai equities never enter it."""
    engine = Engine(tmp_path, equity_capital=D("500"), bot=True)
    engine.snapshot(NVDA, "100")

    runner = engine.runner(session_open=lambda ts: False)
    runner.cycle()
    bot_equity = engine.gateway.portfolio_equity("dry")
    bot_mark = engine.store.hwm(PORTFOLIO_OWNER, "dry")
    assert bot_mark == bot_equity
    # The equity is marked on its own key, beside the portfolio and never in it.
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == D("500")

    engine.filled_equity_buy(size="4", price="100")
    runner.cycle()

    assert engine.gateway.portfolio_equity("dry") == bot_equity
    assert engine.store.hwm(PORTFOLIO_OWNER, "dry") == bot_mark
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") == engine.gateway.equity_value(
        "dry"
    )
    assert engine.store.hwm(EQUITY_HWM_OWNER, "dry") != engine.store.hwm(
        PORTFOLIO_OWNER, "dry"
    )

    engine.close()


def test_live_unallocated_alert_reads_merged_totals(tmp_path):
    """The live shortfall is measured on the whole account, both pools together."""
    engine = Engine(
        tmp_path,
        live=True,
        equity_capital=D("100"),
        live_crypto_totals={"USD": D("0")},
        live_equity_totals={"USD": D("150")},
    )

    # The ai's equity pool is 100 of the 150 the account really holds: nothing
    # is short.  Read from the crypto account alone, the same 100 would be a
    # shortfall of 100, which is the alert this check must not write.
    assert engine.ledger.unallocated({"USD": D("0")}, book="live")["USD"] < 0

    runner = engine.runner(session_open=lambda ts: True)
    runner._check_unallocated()

    assert events(engine.store, level="ALERT") == []
    assert engine.store.get(UNALLOCATED_LIVE_KEY) is None

    engine.close()


# ---------------------------------------------------------------- the kill path


def live_fixture(engine):
    """Two resting orders on the live account, one of them an equity, plus a stranger.

    Both `cb-` orders arrive at the exchange with no row of the engine's own, so
    each row here is the one `reconcile` adopts — the product and the kind are
    then the engine's answers, never the test's.
    """
    crypto_cid = cid_for("ai", 11)
    equity_cid = cid_for("ai", 12)
    engine.crypto_live.add(
        order_snapshot("oid-crypto", crypto_cid, product=XRP, price="0.99", size="10")
    )
    engine.equity_live.add(
        order_snapshot("oid-equity", equity_cid, product=NVDA, price="100", size="1")
    )
    engine.crypto_live.add(
        order_snapshot("oid-manual", "manual-1", product=XRP, price="0.99", size="10")
    )
    engine.reconcile("live")
    return crypto_cid, equity_cid


def test_halt_cancels_equity_orders_two_key(tmp_path):
    """A global halt takes the live book's cb- orders off the account that holds each."""
    engine = Engine(tmp_path, live=True)
    crypto_cid, equity_cid = live_fixture(engine)

    # The router routes by the row's product, so the row has to be the kind the
    # account it came from says it is.
    assert engine.store.order(crypto_cid)["product_type"] == "SPOT"
    assert engine.store.order(equity_cid)["product_type"] == "EQUITY"
    assert engine.store.order(equity_cid)["owner"] == "ai"

    engine.gateway.halt("kill switch")
    engine.reconcile("live")

    assert cancels(engine.equity_live) == [("oid-equity",)]
    assert cancels(engine.crypto_live) == [("oid-crypto",)]
    # Somebody else's order is never swept, however live it is.
    assert "oid-manual" not in cancelled_ids(engine.crypto_live)
    assert any(
        entry["order_id"] == "oid-manual"
        for entry in engine.crypto_live.list_open_orders(None)
    )

    engine.close()


def test_kill_cancels_equity_orders_two_key(tmp_path):
    """`cancel_all` sweeps both accounts, and the owner scope sweeps only its own."""
    engine = Engine(tmp_path, live=True)
    crypto_cid, equity_cid = live_fixture(engine)
    assert engine.store.order(equity_cid)["product_type"] == "EQUITY"

    engine.gateway.cancel_all(scope="all")

    assert cancels(engine.equity_live) == [("oid-equity",)]
    assert cancels(engine.crypto_live) == [("oid-crypto",)]
    assert "oid-manual" not in cancelled_ids(engine.crypto_live)

    # Back on the book, beside somebody else's cb- order, for the owner scope.
    engine.crypto_live.calls.clear()
    engine.equity_live.calls.clear()
    engine.crypto_live.add(
        order_snapshot("oid-crypto", crypto_cid, product=XRP, price="0.99", size="10")
    )
    engine.equity_live.add(
        order_snapshot("oid-equity", equity_cid, product=NVDA, price="100", size="1")
    )
    engine.crypto_live.add(
        order_snapshot("oid-other", cid_for("b9", 13), product=XRP, price="0.99", size="5")
    )
    engine.reconcile("live")

    engine.gateway.cancel_all(scope="owner", owner="ai")

    assert cancels(engine.equity_live) == [("oid-equity",)]
    assert cancels(engine.crypto_live) == [("oid-crypto",)]
    assert "oid-other" not in cancelled_ids(engine.crypto_live)

    engine.close()


def test_watchdog_sweeps_equity_key(tmp_path):
    """The watchdog's sweep names every account's cb- ids, and only those."""
    engine = Engine(tmp_path, live=True)
    _crypto_cid, equity_cid = live_fixture(engine)
    assert engine.store.order(equity_cid)["product_type"] == "EQUITY"

    engine.crypto_live.calls.clear()
    engine.equity_live.calls.clear()
    before = len(events(engine.store))

    requested = cancel_all_cb_orders(engine.live_router, engine.store)

    assert requested == 2
    assert cancels(engine.crypto_live) == [("oid-crypto",)]
    assert cancels(engine.equity_live) == [("oid-equity",)]
    # The stranger's order is on neither list, and requested from neither account.
    assert "oid-manual" not in cancelled_ids(engine.crypto_live)
    assert "oid-manual" not in cancelled_ids(engine.equity_live)
    # One request, one event.
    assert len(events(engine.store)) == before + 1

    engine.close()


def test_reconcile_settles_equity_row_via_equity_adapter(tmp_path):
    """An equity row's own reads are the equity account's, and never the crypto one."""
    engine = Engine(tmp_path, live=True)
    equity_cid = cid_for("ai", 21)
    engine.equity_live.add(
        order_snapshot("oid-eq", equity_cid, product=NVDA, price="100", size="1")
    )
    engine.reconcile("live")

    row = engine.store.order(equity_cid)
    assert row is not None
    assert row["product_type"] == "EQUITY"
    assert row["book"] == "live"

    # The order fills on the equity account and leaves the open list.
    engine.equity_live.settle(
        "oid-eq",
        status="FILLED",
        filled_size=D("1"),
        filled_value=D("100"),
        total_fees=D("0.5"),
    )
    engine.equity_live.fills_by_order["oid-eq"] = [
        trade_fill("t-eq", "oid-eq", product=NVDA, size="1", price="100")
    ]
    engine.crypto_live.calls.clear()
    engine.equity_live.calls.clear()

    engine.reconcile("live")

    settled = engine.store.order(equity_cid)
    assert settled["status"] == FILLED
    assert settled["filled_size"] == D("1")

    # Both per-order reads went to the equity account, with the row's product.
    assert ("get_order", "oid-eq", NVDA) in engine.equity_live.calls
    assert ("fills", "oid-eq", NVDA) in engine.equity_live.calls
    # ... and the crypto account was never asked about it at all.
    assert [
        call for call in engine.crypto_live.calls if call[0] in ("get_order", "fills")
    ] == []

    # The fill was booked once, and the pool counts what was paid, not the size.
    fills = engine.store.conn().execute(
        "SELECT trade_id FROM fills WHERE client_order_id=?", (equity_cid,)
    ).fetchall()
    assert [row["trade_id"] for row in fills] == ["t-eq"]
    assert engine.ledger.equity_pool_used("live") == D("100.5")

    engine.close()