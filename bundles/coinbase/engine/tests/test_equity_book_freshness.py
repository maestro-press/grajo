"""test_equity_book_freshness.py: how old a stock print may be, per book.

The decision this file pins down: a PRACTICE (dry) stock order may be priced from
a print up to five minutes old, while a LIVE stock order may never be priced from
one older than two minutes.  The bound is a fact of the BOOK and of nothing else
— no caller passes a number of seconds — so the pieces are:

* `exchange.equity_max_age_for(book)`: `"dry"` answers 300, everything else (the
  live book, no book, an unknown or wrongly typed one) answers the strict 120, so
  a wrong answer is never the LOOSER one.  `EQUITY_FRESHNESS_CEILING_S` is the
  loosest bound in the table (300), and nothing a caller passes can write into
  that table.
* `MarketData.equity_print`/`equity_quote`: a print 200 s old prices the dry book
  and is refused for the live one — the refusal names the bound actually applied
  — a print past 300 s is refused for dry too, and the constructor's
  `equity_max_age_s` can only TIGHTEN what the book allows.
* the dry simulator's equity fills and the runner's poll both read the PRACTICE
  print, and the poll keeps the print's own time (`MarketSnapshot.print_ts`)
  beside the time it polled.
* the gateway's equity place chain judges a snapshot that carries a `print_ts` by
  that print: one 200 s snapshot prices a dry order and is refused
  `STALE_MARKET` on the live book, so a live order can never be priced from a
  print the practice bound accepted.  A snapshot with NO print time is refused by
  the live book too (and by any book string this build does not know), while the
  practice book keeps judging it by the read's stamp exactly as it always did.
* the gateway's equity MARK (`equity_value`) reads that same bound per book: a
  held share marked from a print past it — or from one with no print time at all,
  on a book that is not practice — makes the whole figure None, and the runner's
  drawdown check treats None as "skip this cycle", so a print no order could use
  can neither ring an alert, nor clear one, nor move the equity mark.

Nothing here reaches the network, a real account or the wall clock's own idea of
which day it is.  The stock's price is one synthetic print whose age a test sets,
and the NYSE calendar is pinned open wherever a quote is read: a test that ran at
the weekend would otherwise see every print refused for the session rather than
for its age.
"""

from __future__ import annotations

import secrets
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal as D
from pathlib import Path
from typing import Any, Optional

import pytest

import crow_coinbase.exchange as exchange_mod
from crow_coinbase import market_hours
from crow_coinbase.__main__ import build_app
from crow_coinbase.books import DRY, LIVE
from crow_coinbase.exchange import (
    DEFAULT_EQUITY_QUOTE_MAX_AGE_S,
    DryRunExchange,
    MarketData,
    ProductUnavailable,
)
from crow_coinbase.gateway import STALE_MARKET
from crow_coinbase.money import ProductSpec
from crow_coinbase.router import ExchangeRouter
from crow_coinbase.runner import EQUITY_ALERT_PREFIX, EQUITY_HWM_OWNER
from crow_coinbase.store import FILLED
from crow_coinbase.strategies.base import MarketSnapshot, OrderIntent

# ---------------------------------------------------------------- test data
# The stock and the coin this file's engines are configured with.
EQUITY = "NVDA-USD"
PRODUCT = "XRP-USDC"
COIN = "XRP"

FEE_RATE = D("0.005")
EQUITY_CAPITAL = D("100")

# 32+ characters, no whitespace: the shortest bearer token the engine starts with.
TOKEN = "test-token-" + secrets.token_hex(16)

# The environment every engine here starts from.  The equity caps are left at
# their env defaults on purpose (100 for one order, 200 a day): the orders this
# file measures are worth 50, so no cap is what refuses them.
BASE_ENV = {
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": PRODUCT,
    "CROW_COINBASE_MAX_BOT_CAPITAL_USD": "100",
    "CROW_COINBASE_EQUITY_PRODUCTS": EQUITY,
    "CROW_COINBASE_EQUITY_AI_CAPITAL_USD": str(EQUITY_CAPITAL),
    # The AI's crypto pool is not under test here; 0 keeps it out of the way.
    "CROW_COINBASE_AI_CAPITAL_USD": "0",
}

# A fixed instant inside the regular session -- Wed 2026-07-15 14:00:00 UTC,
# 10:00 in New York -- so an exchange-level test's print and clock are both in
# session without asking the wall clock what day it is.
T = datetime(2026, 7, 15, 14, 0, tzinfo=timezone.utc).timestamp()

# The close of a session a test has pinned open: nothing expires during a test.
NEVER_CLOSES = float("inf")

# The two ages this file leans on: past the live bound and inside the practice one.
TWO_MINUTES = 120.0
TWO_HUNDRED_S = 200.0
FIVE_MINUTES = 300.0


@pytest.fixture(autouse=True)
def pinned_calendar(monkeypatch):
    """Pin the NYSE calendar open for every test in this file.

    These tests measure a print's AGE, never the trading calendar, and a bound
    read on a Saturday would refuse every print for the session instead — which
    is a different refusal than the one under test.  The session is pinned open
    and never closes, which is also what keeps a resting order from expiring
    under a test that only steps it once.
    """
    monkeypatch.setattr(market_hours, "is_regular_session", lambda ts: True)
    monkeypatch.setattr(market_hours, "session_close", lambda ts: NEVER_CLOSES)


# ---------------------------------------------------------------- the bound


def exchange_name(name: str) -> Any:
    """One name the exchange module has to publish, or a clear failure."""
    value = getattr(exchange_mod, name, None)
    assert value is not None, (
        f"crow_coinbase.exchange.{name} is missing: one book's print age cannot "
        f"be told from another's without it"
    )
    return value


def bound_for(book: Any) -> float:
    """The print age one book allows, asked of the engine's own function."""
    return exchange_name("equity_max_age_for")(book)


def market_bound_table() -> dict:
    return exchange_name("EQUITY_MAX_AGE_BY_BOOK")


def freshness_ceiling() -> float:
    return exchange_name("EQUITY_FRESHNESS_CEILING_S")


def test_the_dry_book_prices_from_a_five_minute_print():
    """Practice trading accepts a print up to five minutes old."""
    assert bound_for(DRY) == FIVE_MINUTES


def test_every_book_but_dry_keeps_the_strict_bound():
    """Only the practice book is wider; everything else answers the strict 120.

    The list is the contract's: the live book, no book at all, an empty string, a
    padded spelling, a number and an unknown word.  A bound that is not the
    practice one has to be the STRICT one, so a wrong answer is never looser than
    the live rule.
    """
    for book in ("live", None, "", "DRY ", "Dry", "dry ", "practice", 300, 300.0):
        assert bound_for(book) == TWO_MINUTES, book
        assert bound_for(book) == DEFAULT_EQUITY_QUOTE_MAX_AGE_S, book
    # No book's answer is looser than the table's own ceiling.
    for book in (DRY, "live", None, "", "practice"):
        assert bound_for(book) <= freshness_ceiling(), book


def test_the_bound_table_cannot_be_written_through_the_function():
    """Nothing a caller passes can add, change or remove a bound.

    The table is the one place the two bounds live, and the function only reads
    it: an unknown book is answered, never recorded, and a caller is handed a
    number rather than the table it came from.
    """
    table = market_bound_table()
    before = dict(table)
    for book in (None, "", "practice", "DRY", "dry ", 0, 300.0):
        bound_for(book)
    assert dict(table) == before, "asking about an unknown book wrote into the table"
    assert set(before) == {DRY, "live"}, before
    assert before[DRY] == FIVE_MINUTES, before
    assert before["live"] == TWO_MINUTES, before

    answer = bound_for(DRY)
    assert isinstance(answer, (int, float)) and not isinstance(answer, bool), answer
    assert not hasattr(answer, "__setitem__"), answer


def test_the_freshness_ceiling_is_the_loosest_bound_in_the_table():
    """The ceiling is the 300 s practice bound, and the table's own maximum."""
    ceiling = freshness_ceiling()
    assert ceiling == FIVE_MINUTES
    assert ceiling == max(market_bound_table().values())
    assert bound_for(DRY) == ceiling
    assert bound_for(LIVE) < ceiling


# ---------------------------------------------------------------- the quote


class Print:
    """One equity print, and the clock every quote of it is judged against.

    `at` is the instant the reader's clock says it is and `age_s` how long before
    that the print was made, so `stamp()` is the print's own epoch time and
    `age_s` is exactly the age a refusal is about.  Both are mutable: a test sets
    the age it wants to measure and leaves the clock where it is.
    """

    def __init__(self, price="100", *, age_s: float = 0.0, at: Optional[float] = None):
        self.price = D(price)
        self.age_s = float(age_s)
        self.at = time.time() if at is None else float(at)

    def now(self) -> float:
        return self.at

    def stamp(self) -> float:
        return self.at - self.age_s

    def source(self, base: str) -> tuple[D, float]:
        """`equity_last`'s answer: the price, and when it was printed."""
        return self.price, self.stamp()

    def market(self, product: str = EQUITY, **options: Any) -> MarketData:
        """A `MarketData` over this print, judged against this clock."""
        return MarketData(
            product,
            client=object(),
            equity_last=self.source,
            now=self.now,
            **options,
        )

    def printed(self, book: Any = LIVE, product: str = EQUITY) -> tuple:
        """`equity_print`'s answer for one book."""
        return equity_print_of(self.market(product), book)

    def quote(self, book: Any = LIVE, product: str = EQUITY) -> tuple:
        """`equity_quote`'s answer for one book."""
        return self.market(product).equity_quote(book=book)


def equity_print_of(market: MarketData, book: Any = LIVE) -> tuple:
    """`MarketData.equity_print`'s answer, or a clear failure while it is absent."""
    printer = getattr(market, "equity_print", None)
    assert printer is not None, (
        "MarketData.equity_print is missing: a reader cannot keep a print's own "
        "time apart from the time it read it"
    )
    return printer(book=book)


def test_a_print_two_hundred_seconds_old_prices_a_dry_quote():
    """The practice book is priced from a 200 s print, and keeps its own time."""
    printed = Print(age_s=TWO_HUNDRED_S, at=T)

    price, stamp = printed.printed(book=DRY)
    assert price == D("100")
    assert stamp == printed.stamp(), (stamp, printed.stamp())
    # The quote is that one print on both sides, off the same 200 s answer.
    assert printed.quote(book=DRY) == (D("100"), D("100"))


def test_a_print_two_hundred_seconds_old_is_refused_for_the_live_book():
    """The live book keeps the strict bound, and says which one it applied."""
    printed = Print(age_s=TWO_HUNDRED_S, at=T)

    for read in (
        lambda: printed.printed(book=LIVE),
        lambda: printed.quote(book=LIVE),
    ):
        with pytest.raises(ProductUnavailable) as caught:
            read()
        text = str(caught.value)
        assert "120" in text, text
        assert "bound" in text, text


def test_a_quote_with_no_book_is_judged_as_live():
    """Reading with no book at all asks the live question, and gets the live bound."""
    printed = Print(age_s=TWO_HUNDRED_S, at=T)

    with pytest.raises(ProductUnavailable):
        printed.market().equity_print()
    with pytest.raises(ProductUnavailable):
        printed.market().equity_quote()


def test_an_unknown_book_is_judged_as_live():
    """An unknown or wrongly typed book is the strict one, never the practice one."""
    printed = Print(age_s=TWO_HUNDRED_S, at=T)

    for book in ("practice", "", None, "DRY", "Dry Run"):
        with pytest.raises(ProductUnavailable):
            printed.printed(book=book)
        with pytest.raises(ProductUnavailable):
            printed.quote(book=book)


def test_a_print_past_the_practice_bound_is_refused_for_dry():
    """301 s is past five minutes, so not even the practice book prices it."""
    printed = Print(age_s=301.0, at=T)

    with pytest.raises(ProductUnavailable) as caught:
        printed.printed(book=DRY)
    text = str(caught.value)
    assert "300" in text, text
    assert "bound" in text, text
    with pytest.raises(ProductUnavailable):
        printed.quote(book=DRY)


def test_each_bound_is_inclusive_at_its_own_second():
    """Exactly 300 s passes for dry and exactly 120 s for live; a hair more does not."""
    assert Print(age_s=FIVE_MINUTES, at=T).printed(book=DRY) == (
        D("100"),
        T - FIVE_MINUTES,
    )
    assert Print(age_s=TWO_MINUTES, at=T).printed(book=LIVE) == (
        D("100"),
        T - TWO_MINUTES,
    )

    with pytest.raises(ProductUnavailable):
        Print(age_s=FIVE_MINUTES + 0.5, at=T).printed(book=DRY)
    with pytest.raises(ProductUnavailable):
        Print(age_s=TWO_MINUTES + 0.5, at=T).printed(book=LIVE)


def test_a_given_max_age_can_only_tighten_the_book_bound():
    """`equity_max_age_s` shortens what a book allows, and never lengthens it."""
    # 100 s is inside both bounds, and outside a given 60.
    assert Print(age_s=100.0, at=T).printed(book=DRY) == (D("100"), T - 100.0)
    with pytest.raises(ProductUnavailable):
        Print(age_s=100.0, at=T).market(equity_max_age_s=60.0).equity_quote(
            book=DRY
        )
    # The given bound, not the book's own, is what the refusal names.
    with pytest.raises(ProductUnavailable) as caught:
        Print(age_s=100.0, at=T).market(equity_max_age_s=60.0).equity_print(
            book=DRY
        )
    assert "60" in str(caught.value), str(caught.value)

    # 70 s is inside five minutes and outside a given 60, on the practice book.
    assert Print(age_s=70.0, at=T).printed(book=DRY) == (D("100"), T - 70.0)
    with pytest.raises(ProductUnavailable):
        Print(age_s=70.0, at=T).market(equity_max_age_s=60.0).equity_quote(book=DRY)


def test_a_given_max_age_can_never_loosen_a_book_bound():
    """A large number given to the constructor is no permission to accept more."""
    # 1000 given does not let the live book price a 200 s print...
    with pytest.raises(ProductUnavailable):
        Print(age_s=TWO_HUNDRED_S, at=T).market(equity_max_age_s=1000.0).equity_quote(
            book=LIVE
        )
    # ...nor the practice book price one past five minutes.
    with pytest.raises(ProductUnavailable) as caught:
        Print(age_s=350.0, at=T).market(equity_max_age_s=1000.0).equity_print(
            book=DRY
        )
    assert "300" in str(caught.value), str(caught.value)


def test_there_is_no_keyword_that_takes_a_number_of_seconds():
    """The bound comes from the book; no caller hands one over under another name."""
    printed = Print(at=T)

    with pytest.raises(TypeError):
        printed.market(max_age_s=999)
    with pytest.raises(TypeError):
        printed.market(max_age_seconds=999)


# ---------------------------------------------------------------- the dry fills


def new_db() -> sqlite3.Connection:
    """One in-memory SQLite connection, autocommit, for a simulator's own book."""
    return sqlite3.connect(":memory:", isolation_level=None)


def resting_buy(
    db: sqlite3.Connection, cid: str, *, price="100", size="1", created_at: float
) -> str:
    """A resting buy written straight onto the simulator's book (no place path)."""
    order_id = f"sim-{cid}"
    db.execute(
        "INSERT INTO sim_orders(order_id,client_order_id,product,side,price,size,"
        "status,created_at,fee) VALUES(?,?,?,?,?,?,'OPEN',?,'0')",
        (order_id, cid, EQUITY, "BUY", str(price), str(size), created_at),
    )
    return order_id


def practice_sim(market: MarketData):
    """A seeded dry-run exchange whose stock is the equity it simulates."""
    db = new_db()
    exchange = DryRunExchange(
        lambda: db,
        lambda product: market,
        FEE_RATE,
        is_equity=lambda product: product == EQUITY,
    )
    exchange.deposit("USD", D("1000"), "seed")
    exchange.deposit(COIN, D("1000"), "seed")
    return exchange, db


def test_a_dry_fill_uses_the_practice_bound():
    """A resting equity buy fills off a 200 s print, which the live book refuses."""
    printed = Print(price="99.99", age_s=TWO_HUNDRED_S, at=T + TWO_HUNDRED_S)
    exchange, db = practice_sim(printed.market())
    order_id = resting_buy(db, "cb-ai-B+0-practice", created_at=T)

    assert exchange.advance(T + TWO_HUNDRED_S) == ["cb-ai-B+0-practice"]

    filled = exchange.get_order(order_id)
    assert filled["status"] == "FILLED", filled
    assert filled["filled_size"] == D("1"), filled
    # It filled off the practice print, and the live book would not have it.
    with pytest.raises(ProductUnavailable):
        printed.quote(book=LIVE)


def test_a_dry_fill_refuses_a_print_past_the_practice_bound():
    """301 s is past even the practice bound, so the resting order stays open."""
    printed = Print(price="99.99", age_s=301.0, at=T + 301.0)
    exchange, db = practice_sim(printed.market())
    order_id = resting_buy(db, "cb-ai-B+0-too-old", created_at=T)

    assert exchange.advance(T + 301.0) == []

    standing = exchange.get_order(order_id)
    assert standing["status"] == "OPEN", standing
    assert standing["filled_size"] == D("0"), standing
    # No funds moved either: `totals()` answers one row per currency the simulated
    # account holds, so a fill that never happened adds no share of the stock and
    # leaves the cash where it was.
    totals = exchange.totals()
    assert totals.get(EQUITY.split("-", 1)[0], D("0")) == D("0"), totals
    assert totals.get("USD") == D("1000"), totals


# ---------------------------------------------------------------- the harness


class Clock:
    """The engine's own clock: one fixed instant, in epoch seconds."""

    def __init__(self, at: Optional[float] = None) -> None:
        self.at = time.time() if at is None else float(at)

    def __call__(self) -> float:
        return self.at


class CoinMarket:
    """The crypto product's public market: a fixed touch, and no candles."""

    def __init__(self, bid="0.99", ask="1.00") -> None:
        self.bid, self.ask = D(bid), D(ask)

    def best_bid_ask(self):
        return self.bid, self.ask

    def range_since(self, since):
        return self.bid, self.ask

    def candles(self, start, end):
        return []


def specs(product: str) -> ProductSpec:
    """The listings the engine prices from: EQUITY for the stock, SPOT for the coin."""
    if product == EQUITY:
        return ProductSpec(
            EQUITY,
            price_increment=D("0.01"),
            base_increment=D("0.0001"),
            quote_increment=D("0.01"),
            base_min_size=D("0.0001"),
            quote_min_size=D("1"),
            product_type="EQUITY",
            fractionable=True,
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


def live_router_over(markets: dict) -> ExchangeRouter:
    """The live book: two funded simulators behind a router.

    Two accounts, so two USD pools: the stock's shares and cash live on the equity
    side and the coin's on the crypto side, exactly as they do on a live install
    with a second key.  Each simulator's `conn_factory` is a no-argument answer to
    its own one in-memory database, which is the shape `Store.conn` has: called
    once per step, and always the same book.
    """
    crypto_db = new_db()
    crypto = DryRunExchange(lambda: crypto_db, markets.__getitem__, FEE_RATE)
    equity_db = new_db()
    equity = DryRunExchange(
        lambda: equity_db,
        markets.__getitem__,
        FEE_RATE,
        is_equity=lambda product: product == EQUITY,
    )
    crypto.deposit("USD", D("1000"), "funding")
    equity.deposit("USD", D("1000"), "funding")
    equity.deposit(EQUITY.split("-", 1)[0], D("1000"), "funding")
    return ExchangeRouter(
        crypto,
        equity,
        is_equity=lambda product: product == EQUITY,
        is_crypto=lambda product: product == PRODUCT,
        usd_one_pool=False,
        equity_bases=(EQUITY.split("-", 1)[0],),
    )


@dataclass
class Book:
    """One engine, both its books, and the one print its stock is priced from."""

    engine: Any
    clock: Clock
    printed: Print

    @property
    def runner(self):
        return self.engine.runner

    @property
    def gateway(self):
        return self.engine.gateway

    @property
    def snapshots(self):
        return self.engine.runner.snapshots


def build_book(root, *, price="100", live: bool = False) -> Book:
    """The real engine over *root*, with the stock priced from one aged print.

    `spec_for` is injected, so the stock products are confirmed by the caller's own
    answer (that is what a trusted status means) and no key push stands in front
    of the staleness step these tests measure.  With `live=True` the live book is
    an `ExchangeRouter` over two funded simulators, so the chain reaches its money
    checks on the live book as well as the dry one instead of stopping earlier.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    install = root / "install_token"
    install.write_text("install-" + secrets.token_hex(20) + "\n", encoding="utf-8")

    at = time.time()
    clock = Clock(at)
    printed = Print(price=price, at=at)
    markets: dict = {EQUITY: printed.market(), PRODUCT: CoinMarket()}
    live_router = live_router_over(markets) if live else None

    configuration = dict(BASE_ENV)
    configuration["CROW_COINBASE_ENGINE_TOKEN"] = TOKEN
    configuration["CROW_COINBASE_INSTALL_TOKEN_FILE"] = str(install)

    engine = build_app(
        configuration,
        data_dir=root / "data",
        market_for=lambda product: markets[product],
        spec_for=specs,
        now=clock,
        live_factory=((lambda: live_router) if live else (lambda: None)),
    )
    # One session answer for both halves, pinned open, and a measured clock: a
    # place intent is never refused CLOCK_SKEW.
    engine.gateway.session_open = lambda ts: True
    engine.runner.session_open = lambda ts: True
    engine.runner.snapshots.set_clock(at, at)
    return Book(engine=engine, clock=clock, printed=printed)


def age_and_poll(book: Book, age_s: float) -> Optional[MarketSnapshot]:
    """Make the harness's one print *age_s* old, poll it, and answer the snapshot.

    The print is re-stamped against the wall clock the gateway reads, so the age
    the chain measures is the age this test asked for and not also the seconds a
    build took.
    """
    book.printed.at = time.time()
    book.printed.age_s = float(age_s)
    book.runner._poll_equity_products()
    return book.snapshots.get(EQUITY)


def equity_intent(*, side="BUY", size="0.5", price="100") -> OrderIntent:
    """An equity-shaped place intent: the fields the chain reads."""
    return OrderIntent(
        action="place",
        side=side,
        size=D(size),
        limit_price=D(price),
        level=0,
        cancel_cid=None,
        reason="test",
    )


def refusal(book: Book, named_book: str, *, intent: Optional[OrderIntent] = None):
    """The equity place chain's refusal for one book of the harness's engine.

    The evaluator is asked directly: the live route's own switches and the preview
    confirmation are other tests' subject, and the staleness step is what this
    measures, so the chain is entered at the equity half with the book named.
    """
    return book.gateway._evaluate_equity_place(
        "ai", "ai", intent or equity_intent(), EQUITY, named_book
    )


# ---------------------------------------------------------------- the poll


def test_the_poll_stores_a_practice_print_and_the_time_it_was_printed(tmp_path):
    """A 200 s print is stored for practice, with the print's own time kept.

    `print_ts` is when the price was made and `ts` is when the poll read it, so a
    reader can tell a fresh read of an old price from a fresh price.
    """
    book = build_book(tmp_path / "poll-practice")
    polled_at = book.clock.at

    snapshot = age_and_poll(book, TWO_HUNDRED_S)

    assert snapshot is not None, "the practice bound refused a print it accepts"
    assert snapshot.product == EQUITY
    assert snapshot.bid == snapshot.ask == D("100")
    assert snapshot.ts == polled_at, (snapshot.ts, polled_at)
    assert snapshot.print_ts == book.printed.stamp(), (
        snapshot.print_ts,
        book.printed.stamp(),
    )
    # The two times are different, and the print's is the older one: the poll
    # happened now, the price was made five minutes ago.
    assert snapshot.print_ts < snapshot.ts


def test_the_poll_stores_nothing_past_the_practice_bound(tmp_path):
    """A 301 s print is no practice print either, so the cache keeps no snapshot."""
    book = build_book(tmp_path / "poll-too-old")

    assert age_and_poll(book, 301.0) is None
    assert book.snapshots.get(EQUITY) is None


# ---------------------------------------------------------------- the gateway


def test_a_practice_order_is_priced_from_the_polled_practice_print(tmp_path):
    """The AI's own dry preview is not refused for a 200 s print."""
    book = build_book(tmp_path / "dry-priced", live=True)
    snapshot = age_and_poll(book, TWO_HUNDRED_S)
    assert snapshot is not None and snapshot.print_ts is not None

    answer = book.engine.ai_orders.preview(EQUITY, "BUY", D("0.5"), D("100"))

    assert answer["book"] == DRY, answer
    assert answer["refusal"] != STALE_MARKET, answer
    assert answer["refusal"] is None, answer
    assert answer["state"] == "pending", answer

    # The chain's own answer for the practice book, entered at its equity half.
    practice = refusal(book, DRY)
    assert practice[0] is None, practice
    assert practice[1] == DRY, practice
    assert practice[2] == EQUITY, practice


def test_the_same_print_is_refused_for_a_live_order(tmp_path):
    """The poll accepted it for practice; the live book still refuses the print."""
    book = build_book(tmp_path / "live-refused", live=True)
    snapshot = age_and_poll(book, TWO_HUNDRED_S)
    assert snapshot is not None, "the practice poll refused its own print"
    assert snapshot.print_ts is not None

    live = refusal(book, LIVE)

    assert live[0] == STALE_MARKET, live
    # Nothing of the order was decided: the print is the step that stopped it.
    assert live[3] is None, live
    assert live[5] is None, live
    # The same snapshot, on the practice book, is a usable one.
    assert refusal(book, DRY)[0] is None


def test_a_print_a_hundred_seconds_old_passes_on_both_books(tmp_path):
    """Inside two minutes, neither book has anything to say about the print."""
    book = build_book(tmp_path / "both-books", live=True)
    snapshot = age_and_poll(book, 100.0)
    assert snapshot is not None and snapshot.print_ts is not None

    for named_book in (DRY, LIVE):
        answer = refusal(book, named_book)
        assert answer[0] is None, (named_book, answer)
        assert answer[1] == named_book, (named_book, answer)
        assert answer[2] == EQUITY, (named_book, answer)
        assert answer[5] == D("100"), (named_book, answer)


def test_a_snapshot_with_no_print_time_is_judged_by_its_stamp(tmp_path):
    """Practice still judges it by its stamp; the live book refuses it outright.

    A snapshot carrying no `print_ts` is one built before prints carried their own
    time.  The practice book reads it exactly as it always did — a fresh stamp
    prices an order and an old one is `STALE_MARKET` — while the live book will
    not price from a price whose own age it cannot know: no print time is no live
    print, and a book string this build does not know is judged as the live one.
    """
    book = build_book(tmp_path / "no-print-time", live=True)

    # A fresh snapshot with no print time: the practice book prices it ...
    book.snapshots.put(
        MarketSnapshot(EQUITY, D("100"), D("100"), D("100"), D("100"), book.clock.at)
    )
    stamped = book.snapshots.get(EQUITY)
    assert stamped is not None
    assert getattr(stamped, "print_ts", None) is None, stamped

    assert refusal(book, DRY)[0] is None
    # ... and the live book does not, whatever the read's own stamp says: a print
    # with no time of its own is never a live print, and neither is it one for a
    # book string this build has never heard of.
    for named_book in (LIVE, "practice", ""):
        assert refusal(book, named_book)[0] == STALE_MARKET, named_book

    # The same snapshot with an old stamp is refused by the practice book too, as
    # before: the old rule is the snapshot's own time, and it has not been relaxed.
    book.snapshots.put(
        MarketSnapshot(
            EQUITY,
            D("100"),
            D("100"),
            D("100"),
            D("100"),
            book.clock.at - TWO_HUNDRED_S,
        )
    )
    for named_book in (DRY, LIVE, "practice"):
        assert refusal(book, named_book)[0] == STALE_MARKET, named_book


# ---------------------------------------------------------------- the explicit


@pytest.mark.parametrize("age_s", [119.0, 121.0, 200.0, 299.0])
def test_a_live_order_is_never_priced_from_a_print_past_the_live_bound(
    tmp_path, age_s
):
    """119 s prices a live order; 121, 200 and 299 never do, whatever practice takes.

    This is the rule the whole file exists for: the practice book accepts all four
    ages, and the live book accepts only the one inside its own two minutes.
    """
    book = build_book(tmp_path / f"live-{int(age_s)}", live=True)
    snapshot = age_and_poll(book, age_s)
    assert snapshot is not None, age_s
    assert snapshot.print_ts == book.printed.stamp(), age_s

    live = refusal(book, LIVE)
    if age_s <= TWO_MINUTES:
        assert live[0] is None, live
        assert live[1] == LIVE, live
        assert live[5] == D("100"), live
    else:
        assert live[0] == STALE_MARKET, live

    # The practice book prices every one of these ages.
    assert refusal(book, DRY)[0] is None, age_s


# ---------------------------------------------------------------- the equity mark
#
# The mark the drawdown check reads is the same question as the order's: may this
# book use this print?  A held share whose print the book may not use leaves the
# WHOLE figure unknown (None), and the runner's check already has a meaning for
# that — skip the cycle — so a print no order could be priced from can neither
# ring an alert, nor clear one, nor move the mark.


# The AI's half share of the harness's stock, and the cash the pool has left
# beside it: half of the 100 capital is spent, so the book is marked as 0.5 * 100
# of shares plus the 50 of cash that bought them, which is the capital it started
# with.  That is all a test asking "was it valued at all" needs.
HELD_SIZE = "0.5"
HELD_PRICE = "100"
HELD_SHARES = D(HELD_SIZE) * D(HELD_PRICE)
HELD_CASH = EQUITY_CAPITAL - HELD_SHARES
HELD_VALUE = HELD_SHARES + HELD_CASH


def seed_held_equity(book: Book, named_book: str) -> str:
    """A filled AI equity buy on one book: the shares held, and the pool's spend."""
    cid = f"cb-ai-B+0-held-{named_book}"
    store = book.engine.store
    store.insert_order(
        cid,
        "ai",
        "ai",
        EQUITY,
        "BUY",
        0,
        D(HELD_PRICE),
        D(HELD_SIZE),
        status=FILLED,
        order_id=f"ex-held-{named_book}",
        book=named_book,
        product_type="EQUITY",
    )
    store.update_order(
        cid,
        filled_size=D(HELD_SIZE),
        filled_value=D(HELD_SIZE) * D(HELD_PRICE),
        fees=D("0"),
    )
    return cid


def store_print(book: Book, age_s: Optional[float]) -> MarketSnapshot:
    """Store the snapshot a poll of a print *age_s* old keeps, and answer it.

    The read is stamped now and the print `age_s` before now, which is exactly what
    the poll stores for a print that old.  Writing it here rather than polling is
    what lets a print past the source's own refusal still reach the mark under
    test: the poll judges the print once, and the mark judges it again per book.
    """
    stamp = book.clock.at
    snap = MarketSnapshot(
        EQUITY,
        D(HELD_PRICE),
        D(HELD_PRICE),
        D(HELD_PRICE),
        D(HELD_PRICE),
        stamp,
        None if age_s is None else stamp - float(age_s),
    )
    book.snapshots.put(snap)
    return snap


def test_a_live_holding_is_valued_from_a_print_inside_two_minutes(tmp_path):
    """A held equity on the live book is marked from a print 119 s old."""
    book = build_book(tmp_path / "live-marked")
    seed_held_equity(book, LIVE)
    stored = store_print(book, 119.0)
    assert stored.print_ts is not None
    assert book.clock.at - stored.print_ts == pytest.approx(119.0)

    assert book.gateway.equity_value(LIVE) == HELD_VALUE


@pytest.mark.parametrize("age_s", [121.0, 299.0, None])
def test_a_live_holding_is_never_valued_from_a_print_the_live_book_refuses(
    tmp_path, age_s
):
    """121 s, 299 s and a print with no time of its own leave the live mark unknown.

    299 s is the age the practice book accepts; the live book may not use it, and
    a print whose own time is unknown is no live price at all.  The whole figure
    is None, never a partial sum without the shares.
    """
    book = build_book(tmp_path / f"live-unmarked-{age_s}")
    seed_held_equity(book, LIVE)
    stored = store_print(book, age_s)
    assert book.snapshots.get(EQUITY) is stored
    if age_s is None:
        assert stored.print_ts is None
    else:
        assert book.clock.at - stored.print_ts == pytest.approx(age_s)

    assert book.gateway.equity_value(LIVE) is None


def test_a_dry_holding_is_valued_from_a_299_s_print(tmp_path):
    """The practice book marks a held equity from a print five minutes old."""
    book = build_book(tmp_path / "dry-marked")
    seed_held_equity(book, DRY)
    stored = store_print(book, 299.0)
    assert stored.print_ts is not None

    assert book.gateway.equity_value(DRY) == HELD_VALUE

    # A snapshot with no print time of its own is judged by its stamp, which is
    # fresh: the practice rule for it has not changed either.
    store_print(book, None)
    assert book.gateway.equity_value(DRY) == HELD_VALUE


def test_a_dry_holding_cannot_be_valued_from_a_print_past_the_practice_bound(tmp_path):
    """301 s is past even five minutes, so the practice mark is unknown too."""
    book = build_book(tmp_path / "dry-unmarked")
    seed_held_equity(book, DRY)
    stored = store_print(book, 301.0)
    assert stored.print_ts is not None

    assert book.gateway.equity_value(DRY) is None


def alert_events(book: Book) -> list[dict]:
    """The warn-level `alert` events the engine has written, in order."""
    rows = book.engine.store.conn().execute(
        "SELECT level, kind, message FROM events ORDER BY id"
    ).fetchall()
    return [
        {"level": row["level"], "kind": row["kind"], "message": row["message"]}
        for row in rows
        if row["level"] == "warn" and row["kind"] == "alert"
    ]


def test_the_drawdown_check_skips_a_live_print_it_may_not_use(tmp_path):
    """A stale live print is no cycle at all: no alert, no marker, no new mark.

    The runner marks the equity book the AI routes to and reads it through
    `gateway.equity_value`, which answers None for a live print past two minutes.
    None is the check's existing "skip this cycle": a print no order could be
    priced from can neither ring an alert, nor clear a standing episode, nor move
    the high-water mark.  A print the book MAY use, below the floor, is the alert
    it always was.
    """
    book = build_book(tmp_path / "live-drawdown")
    seed_held_equity(book, LIVE)
    # The check reads the book the AI routes to, and this engine's AI live switch
    # is off, so the route is pinned to the book under test.
    book.gateway.route_for = lambda owner: LIVE

    store = book.engine.store
    key = f"{EQUITY_ALERT_PREFIX}{LIVE}"
    mark = D("500")
    store.update_hwm(EQUITY_HWM_OWNER, mark, LIVE)
    pct = book.gateway.limits.equity_drawdown_alert_pct
    floor = mark * (1 - pct / 100)
    assert HELD_VALUE < floor, (HELD_VALUE, floor)

    # A print 121 s old is no live figure: the cycle is skipped, so nothing rings
    # and nothing is marked.
    store_print(book, 121.0)
    assert book.snapshots.get(EQUITY) is not None
    assert book.gateway.equity_value(LIVE) is None
    book.runner._check_equity_drawdown()

    assert alert_events(book) == []
    assert store.get(key) is None, "a skipped cycle opened an episode"
    assert store.hwm(EQUITY_HWM_OWNER, LIVE) == mark

    # A fresh print of the same price, below the floor, is the alert as before.
    store_print(book, 0.0)
    assert book.gateway.equity_value(LIVE) == HELD_VALUE
    book.runner._check_equity_drawdown()

    assert len(alert_events(book)) == 1, alert_events(book)
    assert store.get(key) is True
    assert store.hwm(EQUITY_HWM_OWNER, LIVE) == mark

    # And a stale print after it changes none of that: the episode stands, no
    # second alert is written and the mark does not follow an unusable price.
    store_print(book, 121.0)
    book.runner._check_equity_drawdown()

    assert len(alert_events(book)) == 1, alert_events(book)
    assert store.get(key) is True, "a skipped cycle cleared the episode marker"
    assert store.hwm(EQUITY_HWM_OWNER, LIVE) == mark