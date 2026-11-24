"""test_ai_orders_equity.py: the AI surface over an equity product.

Every test here builds the REAL engine through `build_app`: a real `Store` on a
temporary data directory, the real dry-run exchange, gateway, runner, runtime
caps, approval rail and AI order surface.  Only the outside world is faked:
`Markets` answers a fixed crypto touch and one fixed equity print (no client, no
request, no socket), and the live book is a SECOND `DryRunExchange` over a
second store file, wrapped in an `ExchangeRouter` and handed to `build_app` as
its `live_factory`.

`RecordingDry` wraps a book's exchange and records every write call, so
"nothing was sent" and "only the equity path was used" are assertions about real
calls rather than about a stub.  `Session` is the mutable flag both the gateway
and the runner are pinned to, so an open or a closed session is one assignment.

The equity products and the amounts here are synthetic: `NVDA-USD` on the equity
list, `XRP-USDC` on the crypto one, a stock print of 100 and the equity caps at
their env defaults (100 for one order, 200 a day) with 100 of AI equity capital.

What each test pins down:

* an equity preview answers the five equity limits in the contract's order (the
  crypto caps are not among them), the money left for stocks, the session it was
  taken in, and sends nothing; with the session closed the refusal is
  `MARKET_CLOSED` and the equity block says the session is shut,
* an equity refusal carries a plain sentence of its own — never the generic
  message, no digits — now and later from `AiOrders.list()`, and every code the
  contract names has one,
* an equity place with no approval behind it is `APPROVAL_REQUIRED` and writes
  nothing; an approval taken for a different price is refused and left unspent,
* an approved preview places one dry equity order on the equity path (never the
  crypto one), a second approval of it is `NOT_PENDING`, and a quote that moves
  through the stored limit fills it in one cycle with no fee,
* an equity preview on a live route is `LIVE_DISABLED` while equity live is off,
  and neither exchange is written to,
* the portfolio mark is the bots' book: an AI equity fill moves it not at all,
  and a missing stock snapshot cannot make it unknown,
* a crypto preview's answer carries no equity block and the original five limit
  names in the original order.
"""

from __future__ import annotations

import contextlib
import json
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal as D
from pathlib import Path
from typing import Any, Optional

import pytest

from crow_coinbase import market_hours
from crow_coinbase.__main__ import build_app
from crow_coinbase.exchange import DryRunExchange
from crow_coinbase.gateway import (
    APPROVAL_REQUIRED,
    CAPITAL_CAP,
    EQUITY_PREVIEW_UNCONFIRMED,
    FRACTIONAL_NOT_ALLOWED,
    LIQUIDATE_ONLY,
    LIVE_DISABLED,
    MARKET_CLOSED,
    NO_EQUITY_ACCOUNT,
    PRICE_BAND,
    PRODUCT_TYPE_UNKNOWN,
    TRADING_HALTED,
)
from crow_coinbase.money import ProductSpec
from crow_coinbase.router import ExchangeRouter
from crow_coinbase.store import FILLED, OPEN, Store
from crow_coinbase.strategies.base import MarketSnapshot, OrderIntent

# ---------------------------------------------------------------- test data
EQUITY = "NVDA-USD"
PRODUCT = "XRP-USDC"
BASE = "XRP"
QUOTE = "USDC"

FEE_RATE = D("0.005")
EQUITY_CAPITAL = D("100")

# 32+ characters, no whitespace: the shortest bearer token the engine starts with.
TOKEN = "test-token-" + secrets.token_hex(16)

# The environment every engine here starts from.  The equity products and
# capital are named; the equity caps are left at their defaults on purpose.
BASE_ENV = {
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": PRODUCT,
    "CROW_COINBASE_MAX_BOT_CAPITAL_USD": "100",
    "CROW_COINBASE_LIVE": "true",
    "CROW_COINBASE_EQUITY_PRODUCTS": EQUITY,
    "CROW_COINBASE_EQUITY_AI_CAPITAL_USD": str(EQUITY_CAPITAL),
}

# The env names a per-case engine overrides, named here so a rename fails.
EQUITY_CAPITAL_ENV = "CROW_COINBASE_EQUITY_AI_CAPITAL_USD"

DAY_S = 86400.0

# One preview's states, as the table holds them.
PENDING = "pending"
APPROVED = "approved"
PLACED = "placed"
REJECTED = "rejected"

# The five limits an EQUITY preview reports, in the contract's order, and the
# five a crypto preview still reports.
EQUITY_LIMIT_NAMES = (
    "equity_max_order_usd",
    "equity_daily_notional_usd",
    "equity_ai_capital_usd",
    "ai_orders_per_hour",
    "orders_per_hour",
)
CRYPTO_LIMIT_NAMES = (
    "ai_max_order_usd",
    "ai_daily_notional_usd",
    "daily_notional_usd",
    "ai_orders_per_hour",
    "orders_per_hour",
)
CRYPTO_ONLY_LIMIT_NAMES = (
    "ai_max_order_usd",
    "ai_daily_notional_usd",
    "daily_notional_usd",
)
LIMIT_KEYS = {"name", "limit", "used_after"}

# The codes the equity half of the surface has to speak, imported from the
# modules that own them.  `EQUITY_UNAVAILABLE` is the one the equity status owns,
# and it is read through `equity_unavailable()` so a build without it fails a test
# rather than the whole module.
PLAIN_MESSAGE_CODES = (
    MARKET_CLOSED,
    PRICE_BAND,
    FRACTIONAL_NOT_ALLOWED,
    CAPITAL_CAP,
    TRADING_HALTED,
    LIQUIDATE_ONLY,
    NO_EQUITY_ACCOUNT,
    EQUITY_PREVIEW_UNCONFIRMED,
    PRODUCT_TYPE_UNKNOWN,
)

# The sentence each of those two equity codes reads as: plain words, no value,
# and nothing of the generic message.
EQUITY_PREVIEW_UNCONFIRMED_TEXT = "Live stock trading hasn't been confirmed yet."
EQUITY_UNAVAILABLE_TEXT = (
    "Stock trading is off right now; Crow could not confirm the stock products yet."
)


def equity_unavailable() -> str:
    """The code the equity half answers while stock trading is off."""
    import crow_coinbase.gateway as gateway_module

    code = getattr(gateway_module, "EQUITY_UNAVAILABLE", None)
    assert isinstance(code, str) and code, "EQUITY_UNAVAILABLE is not defined"
    return code


def ai_module():
    """The AI orders module, imported where a test needs it."""
    import crow_coinbase.ai_orders as module

    return module


# ---------------------------------------------------------------- outside world


class FakeMarket:
    """A public market with a fixed touch and one fixed equity print.

    `bid`/`ask` are the crypto book a poll and a candle read; `price` is the
    equity's one print, so both sides of an equity quote are it.  A test moves
    `price` to walk a resting buy through its limit.
    """

    def __init__(self, *, bid="0.99", ask="1.00", price="100"):
        self.bid, self.ask = D(bid), D(ask)
        self.price = D(price)

    def best_bid_ask(self):
        return self.bid, self.ask

    def range_since(self, since):
        return self.bid, self.ask

    def candles(self, start, end):
        return []

    def equity_quote(self):
        return self.price, self.price


class Markets:
    """One `FakeMarket` per product, asked by the engine as its `market_for`."""

    def __init__(self):
        self.by_product = {
            PRODUCT: FakeMarket(),
            EQUITY: FakeMarket(price="100"),
        }

    def __call__(self, product: str) -> FakeMarket:
        return self.by_product[product]

    @property
    def equity(self) -> FakeMarket:
        return self.by_product[EQUITY]


class Specs:
    """The listings the engine reads: EQUITY for the stock, SPOT for the coin.

    The equity spec is fractionable, with cents on the price and a one-dollar
    fractional notional floor: every fraction these tests place is worth more
    than the floor, and a whole share is never held to it.  `fractionable` is
    mutable so a test can offer a whole-shares listing without a rebuild.
    """

    def __init__(self):
        self.fractionable = True

    def __call__(self, product: str) -> ProductSpec:
        if product == EQUITY:
            return ProductSpec(
                EQUITY,
                price_increment=D("0.01"),
                base_increment=D("0.0001"),
                quote_increment=D("0.01"),
                base_min_size=D("0.0001"),
                quote_min_size=D("1"),
                product_type="EQUITY",
                fractionable=self.fractionable,
                fractional_notional_min_size=D("1"),
            )
        return ProductSpec(
            product,
            price_increment=D("0.0001"),
            base_increment=D("0.1"),
            quote_increment=D("0.01"),
            base_min_size=D("1"),
            quote_min_size=D("1"),
        )


class Session:
    """The session answer the gateway and the runner are both pinned to."""

    def __init__(self, is_open: bool = True) -> None:
        self.is_open = bool(is_open)

    def __call__(self, ts: float) -> bool:
        return self.is_open


class Clock:
    """A clock the test moves by hand, starting from the wall clock."""

    def __init__(self, at: Optional[float] = None) -> None:
        self.at = time.time() if at is None else float(at)

    def __call__(self) -> float:
        return self.at

    def advance(self, seconds: float) -> float:
        self.at += float(seconds)
        return self.at


class RecordingDry:
    """An exchange, wrapped: records every write path it is asked for.

    A crypto place is `place_calls`; every other write (an equity place, a
    deposit, a cancel) is `writes`.  Everything else is the wrapped exchange's,
    so the gateway, the ledger and reconcile see the book they always did.
    """

    def __init__(self, inner):
        object.__setattr__(self, "inner", inner)
        object.__setattr__(self, "place_calls", [])
        object.__setattr__(self, "writes", [])

    def place_limit(self, cid, product, side, size, price):
        self.place_calls.append((cid, product, side, D(size), D(price)))
        return self.inner.place_limit(cid, product, side, size, price)

    def deposit(self, currency, amount, note):
        self.writes.append("deposit")
        return self.inner.deposit(currency, amount, note)

    def cancel(self, order_ids):
        self.writes.append("cancel")
        return self.inner.cancel(order_ids)

    def place_equity_limit(self, cid, product, side, size, price):
        self.writes.append("place_equity_limit")
        return self.inner.place_equity_limit(cid, product, side, size, price)

    def __getattr__(self, name):
        return getattr(self.inner, name)


# ---------------------------------------------------------------- the harness


@dataclass
class Harness:
    """One engine, both its books, and the collaborators a test moves."""

    engine: Any
    clock: Clock
    markets: Markets
    specs: Specs
    session: Session
    dry: RecordingDry
    live: Optional[RecordingDry] = None
    live_store: Optional[Store] = None

    @property
    def store(self) -> Store:
        return self.engine.store

    @property
    def gateway(self):
        return self.engine.gateway


def build_engine(root, *, env: Optional[dict] = None, live: bool = True) -> Harness:
    """The real engine over *root*, with both books and a fake market."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = root / "install_token"
    install_token = "install-" + secrets.token_hex(20)
    token_path.write_text(install_token + "\n", encoding="utf-8")

    clock = Clock()
    markets = Markets()
    specs = Specs()
    session = Session()

    live_store = None
    live_rec = None
    if live:
        live_store = Store(root / "live.db")
        live_sim = DryRunExchange(live_store.conn, markets, FEE_RATE)
        for currency in (QUOTE, BASE):
            live_sim.deposit(currency, D("1000"), "funding")
        live_rec = RecordingDry(ExchangeRouter(live_sim, usd_one_pool=True))

    configuration = dict(BASE_ENV)
    configuration["CROW_COINBASE_ENGINE_TOKEN"] = TOKEN
    configuration["CROW_COINBASE_INSTALL_TOKEN_FILE"] = str(token_path)
    configuration.update(env or {})

    engine = build_app(
        configuration,
        data_dir=data_dir,
        market_for=markets,
        spec_for=specs,
        now=clock,
        live_factory=(lambda: live_rec) if live else (lambda: None),
    )

    # The simulator every dry order reaches is the wrapped one, so a test can
    # see (and count) the sends; nothing is written here.
    for currency in (QUOTE, BASE):
        engine.exchange.deposit(currency, D("100000"), "test float")
    dry = RecordingDry(engine.exchange)
    engine.gateway.books.dry = dry

    # The session is one flag: whichever half of the engine asks, the test's
    # answer is the one handed over.
    engine.gateway.session_open = session
    engine.runner.session_open = session

    return Harness(
        engine=engine,
        clock=clock,
        markets=markets,
        specs=specs,
        session=session,
        dry=dry,
        live=live_rec,
        live_store=live_store,
    )


def pin_session(h: Harness, is_open: bool) -> None:
    h.session.is_open = bool(is_open)


def close(h: Harness) -> None:
    """Close every store the engine opened, so the next build starts clean."""
    for store in (h.engine.store, h.live_store):
        if store is None:
            continue
        with contextlib.suppress(Exception):
            store.close()


def prime(h: Harness, *, equity_price="100", ts: Optional[float] = None) -> None:
    """A usable snapshot per product, stamped now, with a measured clock."""
    at = time.time() if ts is None else float(ts)
    h.markets.equity.price = D(equity_price)
    for product, bid, ask in (
        (PRODUCT, D("0.99"), D("1.00")),
        (EQUITY, D(equity_price), D(equity_price)),
    ):
        h.engine.runner.snapshots.put(
            MarketSnapshot(product, bid, ask, bid, ask, at)
        )
    h.engine.runner.snapshots.set_clock(at, at)


def drop_snapshot(h: Harness, product: str) -> None:
    """Forget one product's snapshot, as an install that never polled it has."""
    cache = h.engine.runner.snapshots
    with cache._lock:
        cache._snapshots.pop(product, None)


def fund_ai(h: Harness, quote="10000") -> str:
    """Give the AI a dry quote holding: one settled sell, backdated out of the caps."""
    amount = D(quote)
    cid = f"cb-ai-S0-{secrets.token_hex(6)}"
    h.store.insert_order(
        cid,
        "ai",
        "ai",
        PRODUCT,
        "SELL",
        0,
        D("1.00"),
        amount,
        status=OPEN,
        book="dry",
        product_type="SPOT",
    )
    h.store.update_order(
        cid,
        status=FILLED,
        filled_size=amount,
        filled_value=amount * D("1.00"),
        fees=D("0"),
    )
    h.store.conn().execute(
        "UPDATE orders SET created_at=? WHERE client_order_id=?",
        (time.time() - 5 * DAY_S, cid),
    )
    return cid


# ---------------------------------------------------------------- rows / answers


def preview_row(store: Store, preview_id: str) -> Optional[dict]:
    row = store.conn().execute(
        "SELECT * FROM ai_previews WHERE id=?", (preview_id,)
    ).fetchone()
    return None if row is None else dict(row)


def order_count(store: Store) -> int:
    return int(store.conn().execute("SELECT COUNT(*) FROM orders").fetchone()[0])


def limits_by_name(body: dict) -> dict[str, dict]:
    """The limit entries of an answer, by name, each in the surface's own shape."""
    entries = body["limits"]
    assert isinstance(entries, list), body
    found: dict[str, dict] = {}
    for entry in entries:
        assert set(entry) == LIMIT_KEYS, entry
        found[entry["name"]] = entry
    return found


def equity_intent(
    *, side="BUY", size="0.5", price="100", approval_id=None
) -> OrderIntent:
    """An equity-shaped place intent: the fields an approval would cover."""
    fields: dict[str, Any] = dict(
        action="place",
        side=side,
        size=D(size),
        limit_price=D(price),
        level=0,
        cancel_cid=None,
        reason="test",
    )
    if approval_id is not None:
        fields["approval_id"] = approval_id
    return OrderIntent(**fields)


def approve_intent_preview(h: Harness, answer: dict) -> dict:
    """Move one preview row to `approved` without placing it.

    The row and its hash are the surface's own; only the transition an approval
    would make is written here, so the next `submit` is measured against an
    approved, unspent, unexpired preview of that exact order.
    """
    h.store.conn().execute(
        "UPDATE ai_previews SET state=?, approved_at=? WHERE id=?",
        (APPROVED, time.time(), answer["preview_id"]),
    )
    return answer


def assert_no_writes(h: Harness, label: str = "") -> None:
    """No exchange of either book was written to."""
    assert h.dry.place_calls == [], (label, h.dry.place_calls)
    assert h.dry.writes == [], (label, h.dry.writes)
    if h.live is not None:
        assert h.live.place_calls == [], (label, h.live.place_calls)
        assert h.live.writes == [], (label, h.live.writes)


def approved_equity_buy(h: Harness, *, size="0.5", price="100"):
    """Preview then approve one equity buy on the dry book, and answer both."""
    answer = h.engine.ai_orders.preview(EQUITY, "BUY", D(size), D(price))
    assert answer["state"] == PENDING, answer
    placed = h.engine.ai_orders.approve(answer["preview_id"], answer["hash"])
    assert placed["state"] == PLACED, placed
    return answer, placed


def fill_equity(h: Harness, monkeypatch) -> dict:
    """Walk the quote through a resting equity buy and run one cycle.

    The simulator retires a resting equity order at its own day's close, read off
    the NYSE calendar; that clock is pinned to a moment still ahead so the step
    fills the order instead of expiring it, whatever time of day (or week) the
    test runs.  The engine's own session answer is the test's flag, pinned open.
    """
    monkeypatch.setattr(
        market_hours, "session_close", lambda ts: h.clock() + 3600.0
    )
    h.markets.equity.price = D("99")
    pin_session(h, True)
    return h.engine.runner.cycle()


# ================================================================ the preview


def test_equity_preview_shows_caps_and_session(tmp_path):
    """An equity preview answers the equity limits, the money left and the session."""
    h = build_engine(tmp_path / "equity-preview")
    prime(h)
    module = ai_module()
    limits = h.gateway.limits
    # The caps this engine reads are the env defaults the preview shows.
    assert limits.equity_max_order_usd == D("100"), limits
    assert limits.equity_daily_notional_usd == D("200"), limits
    assert limits.equity_ai_capital_usd == D("100"), limits
    orders_before = order_count(h.store)

    pin_session(h, True)
    answer = h.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("100"))

    assert answer["state"] == PENDING, answer
    assert answer["book"] == "dry", answer
    assert answer["product"] == EQUITY, answer
    assert answer["side"] == "BUY", answer
    assert D(answer["size"]) == D("0.5"), answer
    assert D(answer["limit_price"]) == D("100"), answer
    assert D(answer["notional"]) == D("50"), answer
    assert answer["refusal"] is None, answer
    assert answer["message"] is None, answer

    # The five equity limits, in the contract's order, and nothing of crypto's.
    names = [entry["name"] for entry in answer["limits"]]
    assert names == list(EQUITY_LIMIT_NAMES), names
    for name in CRYPTO_ONLY_LIMIT_NAMES:
        assert name not in names, (name, names)

    by_name = limits_by_name(answer)
    expected = {
        "equity_max_order_usd": ("100", "50"),
        "equity_daily_notional_usd": ("200", "50"),
        "equity_ai_capital_usd": ("100", "50"),
    }
    for name, (limit, used) in expected.items():
        entry = by_name[name]
        assert D(str(entry["limit"])) == D(limit), (name, entry)
        assert D(str(entry["used_after"])) == D(used), (name, entry)
    for name in ("ai_orders_per_hour", "orders_per_hour"):
        entry = by_name[name]
        assert int(entry["used_after"]) == 1, (name, entry)

    # The equity block: the session it was taken in and the money left for
    # stocks, each figure a money text (`_money`'s own shape) holding the value
    # the contract names.
    money = module._money
    equity = answer["equity"]
    assert set(equity) == {
        "session_open",
        "pool_capital",
        "pool_used",
        "pool_left",
        "pool_left_after",
    }, equity
    assert equity["session_open"] is True, equity
    expected_block = (
        ("pool_capital", D("100")),
        ("pool_used", D("0")),
        ("pool_left", D("100")),
        ("pool_left_after", D("50")),
    )
    for field, expected in expected_block:
        text = equity[field]
        assert isinstance(text, str), (field, text)
        assert D(text) == expected, (field, text)
    # The three figures that cannot carry a trailing zero are the surface's own
    # text; the after figure is the notional's decimal text, which the value
    # check above pins.
    assert equity["pool_capital"] == money(D("100")), equity
    assert equity["pool_used"] == money(D("0")), equity
    assert equity["pool_left"] == money(D("100")), equity
    assert D(equity["pool_left_after"]) == D("50"), equity

    # A preview sends nothing anywhere and writes no order row.
    assert_no_writes(h)
    assert order_count(h.store) == orders_before
    assert preview_row(h.store, answer["preview_id"])["state"] == PENDING

    # With the session closed the same preview is refused, and the equity block
    # still says so.
    pin_session(h, False)
    closed = h.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("100"))
    assert closed["state"] == REJECTED, closed
    assert closed["refusal"] == MARKET_CLOSED, closed
    assert isinstance(closed["message"], str) and closed["message"], closed
    assert closed["message"] != module.GENERIC_MESSAGE, closed
    assert closed["equity"]["session_open"] is False, closed

    assert_no_writes(h)
    assert order_count(h.store) == orders_before
    assert preview_row(h.store, closed["preview_id"])["state"] == REJECTED
    close(h)


# ================================================================ the refusals


def test_equity_refusals_have_plain_messages(tmp_path):
    """Every equity refusal reads as its own plain sentence, now and when listed."""
    module = ai_module()

    # Every code the contract names has a sentence of its own: no value, no
    # secret, no digit, and never the generic message.
    codes = PLAIN_MESSAGE_CODES + (equity_unavailable(),)
    for code in codes:
        assert code in module.MESSAGES, code
        message = module.MESSAGES[code]
        assert isinstance(message, str) and message, code
        assert message != module.GENERIC_MESSAGE, code
        assert not any(ch.isdigit() for ch in message), (code, message)

    # Two of them say exactly what the owner has to be told: the live route has
    # no confirmation yet, and stock trading is off until the products are known.
    assert (
        module.MESSAGES[EQUITY_PREVIEW_UNCONFIRMED]
        == EQUITY_PREVIEW_UNCONFIRMED_TEXT
    )
    assert module.MESSAGES[equity_unavailable()] == EQUITY_UNAVAILABLE_TEXT

    def assert_refused(h, answer, code):
        """One refused preview, with its sentence, now and from the listing."""
        assert answer["state"] == REJECTED, (code, answer)
        assert answer["refusal"] == code, (code, answer)
        assert answer["message"] == module.MESSAGES[code], (code, answer)
        assert answer["message"] != module.GENERIC_MESSAGE, code
        stored = preview_row(h.store, answer["preview_id"])
        assert stored is not None, code
        assert stored["state"] == REJECTED, (code, stored)
        assert stored["refusal"] == code, (code, stored)
        listed = {
            item["preview_id"]: item for item in h.engine.ai_orders.list()
        }
        assert listed[answer["preview_id"]]["message"] == module.MESSAGES[code], code
        assert_no_writes(h, code)

    # ---- PRICE_BAND: a limit far outside the band around the print
    band = build_engine(tmp_path / "refuse-price-band")
    prime(band)
    before = order_count(band.store)
    answer = band.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("106.00"))
    assert_refused(band, answer, PRICE_BAND)
    assert order_count(band.store) == before
    close(band)

    # ---- CAPITAL_CAP: over the 60 of capital, under the 100 order cap
    capital = build_engine(
        tmp_path / "refuse-capital",
        env={EQUITY_CAPITAL_ENV: "60"},
    )
    prime(capital)
    before = order_count(capital.store)
    answer = capital.engine.ai_orders.preview(EQUITY, "BUY", D("1"), D("100"))
    assert_refused(capital, answer, CAPITAL_CAP)
    assert order_count(capital.store) == before
    close(capital)

    # ---- MARKET_CLOSED: the same order, out of session
    closed = build_engine(tmp_path / "refuse-market-closed")
    prime(closed)
    pin_session(closed, False)
    before = order_count(closed.store)
    answer = closed.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("100"))
    assert_refused(closed, answer, MARKET_CLOSED)
    assert order_count(closed.store) == before
    close(closed)

    # ---- FRACTIONAL_NOT_ALLOWED: a whole-shares listing offered half a share
    whole = build_engine(tmp_path / "refuse-fractional")
    whole.specs.fractionable = False
    prime(whole)
    before = order_count(whole.store)
    answer = whole.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("100"))
    assert_refused(whole, answer, FRACTIONAL_NOT_ALLOWED)
    assert order_count(whole.store) == before
    close(whole)


# ================================================================ the approval
# in the chain


def test_equity_place_without_approval_refused(tmp_path):
    """An equity place needs an approved preview of exactly that order."""
    h = build_engine(tmp_path / "no-approval")
    prime(h)
    before = order_count(h.store)

    bare = h.gateway.submit("ai", "ai", equity_intent(), product=EQUITY)
    assert bare.ok is False
    assert bare.refusal == APPROVAL_REQUIRED, bare
    assert bare.cid is None
    assert order_count(h.store) == before
    assert_no_writes(h)

    # An approval taken for another price is no approval for this order, and it
    # stays unspent.
    answer = h.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("100"))
    assert answer["state"] == PENDING, answer
    approve_intent_preview(h, answer)

    mismatched = h.gateway.submit(
        "ai",
        "ai",
        equity_intent(price="99", approval_id=answer["preview_id"]),
        product=EQUITY,
    )
    assert mismatched.ok is False, mismatched
    assert mismatched.refusal == APPROVAL_REQUIRED, mismatched
    assert mismatched.cid is None

    stored = preview_row(h.store, answer["preview_id"])
    assert stored["state"] == APPROVED, stored
    assert stored["consumed_at"] is None, stored
    assert order_count(h.store) == before
    assert_no_writes(h)
    close(h)


# ================================================================ the one send


def test_equity_place_approved_dry_fills(tmp_path, monkeypatch):
    """An approved preview is one dry equity order, filled by the next cycle."""
    h = build_engine(tmp_path / "approved")
    prime(h)
    module = ai_module()

    seen: list[OrderIntent] = []
    real_submit = h.gateway.submit

    def spy(source, owner, intent, product=None):
        seen.append(intent)
        return real_submit(source, owner, intent, product)

    h.gateway.submit = spy

    answer = h.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("100"))
    preview_id = answer["preview_id"]
    assert answer["state"] == PENDING, answer

    placed = h.engine.ai_orders.approve(preview_id, answer["hash"])
    cid = f"cb-ai-{preview_id}"
    assert placed == {
        "preview_id": preview_id,
        "state": PLACED,
        "cid": cid,
        "book": "dry",
    }, placed

    # The one send went through the gateway as an intent carrying the approval.
    assert len(seen) == 1, seen
    sent = seen[0]
    assert isinstance(sent, OrderIntent), sent
    assert sent.action == "place", sent
    assert sent.approval_id == preview_id, sent
    assert sent.side == "BUY", sent
    assert sent.size == D("0.5"), sent
    assert sent.limit_price == D("100"), sent

    # The order row is an equity row on the dry book, under the preview's cid.
    row = h.store.order(cid)
    assert row is not None
    assert row["client_order_id"] == cid, row
    assert row["product"] == EQUITY, row
    assert row["product_type"] == "EQUITY", row
    assert row["book"] == "dry", row
    assert row["status"] == OPEN, row
    assert D(row["size"]) == D("0.5"), row
    assert D(row["price"]) == D("100"), row

    # The equity write path, once, and never the crypto one.
    assert h.dry.writes == ["place_equity_limit"], h.dry.writes
    assert h.dry.place_calls == [], h.dry.place_calls
    assert preview_row(h.store, preview_id)["state"] == PLACED

    # One preview places one order: the second answer is not a second send.
    with pytest.raises(module.AiRefused) as caught:
        h.engine.ai_orders.approve(preview_id, answer["hash"])
    assert caught.value.code == module.NOT_PENDING, caught.value
    assert len(seen) == 1, seen
    assert h.dry.writes == ["place_equity_limit"], h.dry.writes

    # The quote moves strictly below the stored limit: the next cycle fills it.
    fill_equity(h, monkeypatch)

    filled = h.store.order(cid)
    assert filled["status"] == FILLED, filled
    assert D(filled["filled_size"]) == D("0.5"), filled
    assert D(filled["filled_value"]) == D("50"), filled
    assert D(filled["fees"]) == D("0"), filled

    held = h.gateway.ledger.holding("ai", EQUITY, book="dry")
    assert held.base == D("0.5"), held
    assert h.gateway.ledger.equity_pool_used("dry") == D("50")
    assert h.dry.writes == ["place_equity_limit"], h.dry.writes
    assert h.dry.place_calls == [], h.dry.place_calls
    close(h)


# ================================================================ the live route


def test_equity_on_live_route_without_equity_live_refused(tmp_path):
    """The AI's live route does not carry an equity order while equity live is off."""
    h = build_engine(tmp_path / "live-equity-off")
    prime(h)
    gateway = h.gateway

    assert gateway.switches.ceiling is True
    assert gateway.limits.equity_live is False
    gateway.switches.set("ai_live_enabled", True)
    assert gateway.route_for("ai") == "live"
    assert h.live is not None

    answer = h.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("100"))

    assert answer["state"] == REJECTED, answer
    assert answer["refusal"] == LIVE_DISABLED, answer
    assert answer["book"] == "live", answer
    assert preview_row(h.store, answer["preview_id"])["refusal"] == LIVE_DISABLED
    assert_no_writes(h)
    assert order_count(h.store) == 0
    close(h)


# ================================================================ the marks


def test_portfolio_equity_skips_ai_equities(tmp_path, monkeypatch):
    """The portfolio mark is the bots' book: the AI's shares never enter it."""
    h = build_engine(tmp_path / "portfolio")
    prime(h)
    gateway = h.gateway

    # No bots: the mark is the empty book, and it is a number, not unknown.
    before = gateway.portfolio_equity("dry")
    assert before is not None
    assert before == D("0")

    approved_equity_buy(h)
    fill_equity(h, monkeypatch)

    after = gateway.portfolio_equity("dry")
    assert after is not None
    assert after == before, (before, after)

    # Off hours, with no stock snapshot at all: the AI's shares still cannot make
    # the bots' mark unknown.
    drop_snapshot(h, EQUITY)
    assert h.engine.runner.snapshots.get(EQUITY) is None
    off_hours = gateway.portfolio_equity("dry")
    assert off_hours is not None
    assert off_hours == before, (before, off_hours)
    close(h)


# ================================================================ crypto unchanged


def test_crypto_preview_answer_unchanged(tmp_path):
    """A crypto preview answers as it always did: five names, and no equity block."""
    h = build_engine(tmp_path / "crypto-preview")
    fund_ai(h)
    prime(h)

    answer = h.engine.ai_orders.preview(PRODUCT, "BUY", D("5"), D("0.98"))

    assert answer["state"] == PENDING, answer
    assert "equity" not in answer, answer
    names = [entry["name"] for entry in answer["limits"]]
    assert names == list(CRYPTO_LIMIT_NAMES), names
    limits = limits_by_name(answer)
    assert D(str(limits["ai_max_order_usd"]["limit"])) == D("25"), limits
    assert D(str(limits["ai_daily_notional_usd"]["limit"])) == D("50"), limits
    assert D(str(limits["daily_notional_usd"]["limit"])) == D("200"), limits

    stored = preview_row(h.store, answer["preview_id"])
    payload = json.loads(stored["payload_json"])
    assert "equity" not in payload, payload
    close(h)