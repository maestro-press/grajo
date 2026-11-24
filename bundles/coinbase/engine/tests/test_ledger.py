"""ledger.py: one owner's holdings, derived from order rows plus its capital."""

from decimal import Decimal as D

import pytest

from crow_coinbase.ledger import Holding, Ledger
from crow_coinbase.store import (
    CANCELLED,
    FILLED,
    OPEN,
    PENDING_SUBMIT,
    Store,
)

XRP = "XRP-USDC"
BTC = "BTC-USDC"
FEE = D("0.005")


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "s.db")
    yield s
    s.close()


def ocid(owner, n):
    """A client order id in the engine's `cb-<owner>-...` form."""
    return f"cb-{owner}-{n:012d}"


def make_bot(store, bot_id="b1", product=XRP, quote="100", base="0"):
    store.create_bot(bot_id, product, "grid", {}, D(quote), D(base))


def place(store, cid, owner, side, price, size, product=XRP, level=0, status=OPEN, book="dry"):
    store.insert_order(
        cid, owner, "grid", product, side, level, D(price), D(size), status=status,
        book=book, product_type="SPOT",
    )


def snapshot(store, cid, size, value, fees="0"):
    """Set an order's absolute fill totals from the exchange's order snapshot.

    `update_order` is the only writer of filled_size / filled_value / fees; the
    fills table is bookkeeping and never moves a holding.
    """
    store.update_order(cid, filled_size=D(size), filled_value=D(value), fees=D(fees))


def check(h, quote, base, reserved_quote="0", reserved_base="0"):
    assert h.quote == D(quote)
    assert h.base == D(base)
    assert h.reserved_quote == D(reserved_quote)
    assert h.reserved_base == D(reserved_base)
    assert h.available_quote == h.quote - h.reserved_quote
    assert h.available_base == h.base - h.reserved_base


def test_ledger_requires_fee_rate(store):
    """A fee rate is an explicit decision: there is no default to fall back on."""
    with pytest.raises(TypeError):
        Ledger(store)


def test_create_bot_starts_with_its_capital(store):
    make_bot(store, "b1", XRP, "100", "50")

    h = Ledger(store, fee_rate=FEE).holding("b1")

    assert h == Holding(D("100"), D("50"), D("0"), D("0"))
    assert h.available_quote == D("100")
    assert h.available_base == D("50")


def test_fill_moves_holding(store):
    make_bot(store, "b1", XRP, "100", "50")
    led = Ledger(store, fee_rate=FEE)

    cid_buy = ocid("b1", 1)
    place(store, cid_buy, "b1", "BUY", "1", "10", level=-1)
    snapshot(store, cid_buy, "10", "10", "0.05")
    store.update_order(cid_buy, status=FILLED)

    check(led.holding("b1"), "89.95", "60")

    cid_sell = ocid("b1", 2)
    place(store, cid_sell, "b1", "SELL", "2", "5", level=1)
    snapshot(store, cid_sell, "5", "10", "0.02")
    store.update_order(cid_sell, status=FILLED)

    # 89.95 + (5 * 2 - 0.02), base 60 - 5
    check(led.holding("b1"), "99.93", "55")


def test_open_order_reserves_and_cancel_releases(store):
    make_bot(store, "b1", XRP, "100", "50")
    led = Ledger(store, fee_rate=FEE)

    cid_buy = ocid("b1", 1)
    place(store, cid_buy, "b1", "BUY", "2", "10", level=-1)
    h = led.holding("b1")
    assert h.quote == D("100")  # a resting order moves nothing between totals
    assert h.reserved_quote == D("20.10")  # 10 * 2 * 1.005, fee included
    assert h.available_quote == D("79.90")

    cid_sell = ocid("b1", 2)
    place(store, cid_sell, "b1", "SELL", "2", "4", level=1)
    h = led.holding("b1")
    assert h.reserved_quote == D("20.10")
    assert h.reserved_base == D("4")
    assert h.available_base == D("46")

    cid_pending = ocid("b1", 3)
    place(store, cid_pending, "b1", "BUY", "3", "1", status=PENDING_SUBMIT)
    h = led.holding("b1")
    assert h.reserved_quote == D("20.10") + D("3.015")  # 1 * 3 * 1.005
    assert h.reserved_base == D("4")

    # A partially filled live buy reserves only the remaining size.
    cid_part = ocid("b1", 4)
    place(store, cid_part, "b1", "BUY", "1", "10", level=-2)
    snapshot(store, cid_part, "4", "4", "0.004")
    h = led.holding("b1")
    assert h.quote == D("100") - D("4") - D("0.004")
    assert h.base == D("54")
    assert h.reserved_quote == D("23.115") + D("6.03")  # 6 left at 1 * 1.005
    assert h.reserved_base == D("4")

    for cid in (cid_buy, cid_sell, cid_pending, cid_part):
        store.update_order(cid, status=CANCELLED)

    h = led.holding("b1")
    check(h, "95.996", "54")  # the partial fill stays, every hold is released


def test_buy_reservation_depends_on_fee_rate(store):
    make_bot(store, "b1", XRP, "100", "0")
    # size 10 at 2: the reservation includes the maker fee.
    place(store, ocid("b1", 1), "b1", "BUY", "2", "10", level=-1)

    free = Ledger(store, fee_rate=D("0")).holding("b1")
    assert free.reserved_quote == D("20")

    charged = Ledger(store, fee_rate=FEE).holding("b1")
    assert charged.reserved_quote == D("20.10")


def test_sell_cancelled_after_partial_fill_releases_base(store):
    make_bot(store, "b1", XRP, "100", "50")
    led = Ledger(store, fee_rate=FEE)

    cid = ocid("b1", 1)
    place(store, cid, "b1", "SELL", "2", "10", level=1)
    snapshot(store, cid, "4", "8", "0.04")

    h = led.holding("b1")
    assert h.base == D("46")  # 50 - 4 sold
    assert h.quote == D("107.96")  # 100 + 8 - 0.04 fee
    assert h.reserved_base == D("6")  # only the unsold 6 is still held
    assert h.reserved_quote == D("0")

    store.update_order(cid, status=CANCELLED)

    h = led.holding("b1")
    check(h, "107.96", "46")  # the partial fill stays, the hold is released


def test_two_bots_same_product_isolated(store):
    make_bot(store, "b1", XRP, "100", "50")
    make_bot(store, "b2", XRP, "70", "20")

    cid = ocid("b1", 1)
    place(store, cid, "b1", "BUY", "1", "10", level=-1)
    snapshot(store, cid, "10", "10", "0.01")
    store.update_order(cid, status=FILLED)

    led = Ledger(store, fee_rate=FEE)
    check(led.holding("b1"), "89.99", "60")
    check(led.holding("b2"), "70", "20")


def test_holding_filters_by_product_and_requires_it_without_a_bot(store):
    make_bot(store, "b1", XRP, "100", "50")
    led = Ledger(store, fee_rate=FEE)

    with pytest.raises(ValueError):
        led.holding("nobot")  # no bot row and no product to fall back on

    check(led.holding("nobot", XRP), "0", "0")
    check(led.holding("orphan", XRP), "0", "0")
    check(led.holding("ai", XRP), "0", "0")

    # A bot's own product is the default; another product's rows are not mixed in.
    cid = ocid("b1", 1)
    place(store, cid, "b1", "BUY", "60000", "0.01", product=BTC, level=-1)
    snapshot(store, cid, "0.01", "600", "6")
    store.update_order(cid, status=FILLED)

    check(led.holding("b1"), "100", "50")


def test_orphan_holding_comes_only_from_its_fills(store):
    cid = ocid("orphan", 1)
    place(store, cid, "orphan", "BUY", "1", "10", level=-1)
    snapshot(store, cid, "10", "10", "0.05")
    store.update_order(cid, status=FILLED)

    h = Ledger(store, fee_rate=FEE).holding("orphan", XRP)

    assert h.quote == -(D("10") + D("0.05"))  # capital 0, only the fill's cost
    assert h.base == D("10")
    assert h.reserved_quote == D("0")
    assert h.reserved_base == D("0")

    assert store.get_bot("orphan") is None
    assert store.list_bots() == []
    with pytest.raises(ValueError):
        store.create_bot("orphan", XRP, "grid", {}, D("100"), D("50"))


def test_equity_uses_totals_and_prices(store):
    make_bot(store, "b1", XRP, "100", "50")
    led = Ledger(store, fee_rate=FEE)

    assert led.equity("b1", {XRP: D("2")}) == D("200")  # 100 + 50 * 2

    # A resting order only reserves: totals (and so equity) are unchanged.
    place(store, ocid("b1", 1), "b1", "BUY", "1", "10", level=-1)
    assert led.equity("b1", {XRP: D("2")}) == D("200")

    cid = ocid("b1", 2)
    place(store, cid, "b1", "BUY", "1", "10", level=-2)
    snapshot(store, cid, "10", "10", "0.05")
    store.update_order(cid, status=FILLED)

    # quote 89.95, base 60
    assert led.equity("b1", {XRP: D("2")}) == D("209.95")
    assert led.equity("b1", {XRP: D("1")}) == D("149.95")


def test_unallocated_zero_with_resting_order(store):
    make_bot(store, "b1", XRP, "100", "50")
    place(store, ocid("b1", 1), "b1", "BUY", "1", "10", level=-1)
    place(store, ocid("b1", 2), "b1", "SELL", "2", "4", level=1)

    # Totals include the holds, so a non-zero fee rate changes nothing here.
    out = Ledger(store, fee_rate=FEE).unallocated({"USDC": D("100"), "XRP": D("50")})

    assert out == {"USDC": D("0"), "XRP": D("0")}


def test_unallocated_per_currency_shared_usdc(store):
    make_bot(store, "x", XRP, "100", "0")
    make_bot(store, "y", BTC, "60", "0")
    led = Ledger(store, fee_rate=FEE)

    out = led.unallocated({"USDC": D("170"), "XRP": D("0"), "BTC": D("0")})
    assert out == {"USDC": D("10"), "XRP": D("0"), "BTC": D("0")}

    # A bot's base capital counts against the base currency too.
    make_bot(store, "z", XRP, "0", "50")
    out = led.unallocated({"USDC": D("170"), "XRP": D("50"), "BTC": D("0")})
    assert out == {"USDC": D("10"), "XRP": D("0"), "BTC": D("0")}


def test_unallocated_negative_when_exchange_short(store):
    make_bot(store, "b1", XRP, "100", "50")
    led = Ledger(store, fee_rate=FEE)

    out = led.unallocated({"USDC": D("80"), "XRP": D("40")})
    assert out["USDC"] == D("-20")
    assert out["XRP"] == D("-10")

    # A currency missing from totals counts as 0.
    out = led.unallocated({})
    assert out["USDC"] == D("-100")
    assert out["XRP"] == D("-50")

    out = led.unallocated({"USDC": D("100")})
    assert out["USDC"] == D("0")
    assert out["XRP"] == D("-50")


def test_unallocated_counts_orphan_owner(store):
    led = Ledger(store, fee_rate=FEE)
    totals = {"USDC": D("100"), "XRP": D("0")}
    before = led.unallocated(totals)
    assert before == {"USDC": D("100"), "XRP": D("0")}

    cid = ocid("orphan", 1)
    place(store, cid, "orphan", "BUY", "1", "10", level=-1)
    snapshot(store, cid, "10", "10", "0.05")
    store.update_order(cid, status=FILLED)

    after = led.unallocated(totals)

    # The orphan's filled buy shifts unallocated by exactly its cost + fee and its
    # size, the same shift a bot owner's fill makes.
    assert after["USDC"] == before["USDC"] + D("10.05")
    assert after["XRP"] == before["XRP"] - D("10")


# ---------------------------------------------------------------- the equity pool

NVDA = "NVDA-USD"
VOO = "VOO-USD"
EQUITIES = (NVDA, VOO)


class Capital:
    """A mutable AI equity capital, read on every call like the engine's own."""

    def __init__(self, amount="150"):
        self.amount = D(amount)

    def __call__(self):
        return self.amount


def equity_ledger(store, *, capital="150", fee=FEE, ai_capital=None):
    """A ledger whose equities are NVDA-USD and VOO-USD, and whose capital is *capital*."""
    return Ledger(
        store,
        fee_rate=fee,
        ai_capital=ai_capital,
        equity_ai_capital=capital if callable(capital) else Capital(capital),
        is_equity=lambda product: product in EQUITIES,
    )


def place_equity(
    store,
    cid,
    owner,
    side,
    price,
    size,
    product=NVDA,
    level=0,
    status=OPEN,
    product_type="EQUITY",
    book="dry",
):
    """One equity order row: the product type is what makes it a pool member."""
    store.insert_order(
        cid,
        owner,
        "ai",
        product,
        side,
        level,
        D(price),
        D(size),
        status=status,
        book=book,
        product_type=product_type,
    )


def test_equity_pool_is_one_usd_pool_across_symbols(store):
    """The AI's equities share ONE quote pool per book, whatever the symbol."""
    led = equity_ledger(store, capital="150")
    place_equity(store, ocid("ai", 1), "ai", "BUY", "100", "1", product=NVDA, level=-1)

    nvda = led.holding("ai", NVDA, book="dry")
    voo = led.holding("ai", VOO, book="dry")

    assert nvda.quote == D("150")
    assert nvda.reserved_quote == D("100")
    assert nvda.available_quote == D("50")

    # The other symbol reads the same pool and the same reservation: 100 spent on
    # NVDA leaves 50 for VOO, and the reservation is not counted twice.
    assert voo.quote == D("150")
    assert voo.reserved_quote == D("100")
    assert voo.available_quote == D("50")

    # Each product keeps its own base side.
    assert nvda.base == D("0")
    assert voo.base == D("0")


def test_equity_buy_reservation_pays_no_fee_but_crypto_does(store):
    make_bot(store, "b1", XRP, "100", "0")
    led = equity_ledger(store, capital="150")
    place_equity(store, ocid("ai", 1), "ai", "BUY", "100", "2", level=-1)
    place(store, ocid("b1", 1), "b1", "BUY", "2", "10", level=-1)

    # An equity BUY holds exactly size * price; a crypto one still holds the fee.
    assert led.holding("ai", NVDA, book="dry").reserved_quote == D("200")
    assert led.holding("b1").reserved_quote == D("20.10")


def test_equity_pool_used_formula(store):
    """Live buys at their whole size, finished buys at their cost, sells at their net."""
    led = equity_ledger(store, capital="150")

    place_equity(store, ocid("ai", 1), "ai", "BUY", "100", "1", level=-1)

    finished = ocid("ai", 2)
    place_equity(store, finished, "ai", "BUY", "20", "2", status=FILLED)
    snapshot(store, finished, "2", "40", "0.2")

    sold = ocid("ai", 3)
    place_equity(store, sold, "ai", "SELL", "25", "2", status=FILLED)
    snapshot(store, sold, "2", "50", "0.25")

    # A SPOT row of the same owner on the same book is not part of the pool.
    place(store, ocid("ai", 4), "ai", "BUY", "1", "7", product=XRP)

    assert led.equity_pool_used("dry") == D("100") + D("40.2") - D("49.75")
    assert led.equity_pool_used("dry") == D("90.45")
    assert led.equity_pool_used("live") == D("0")


def test_equity_pool_used_honours_epoch_and_book(store):
    """A row the book's epoch left behind is not the pool's spend, nor is the other
    book's."""
    led = equity_ledger(store, capital="150")

    # A row from the period the AI has already left on the dry book.
    old = ocid("ai", 1)
    place_equity(store, old, "ai", "BUY", "100", "1", status=FILLED)
    snapshot(store, old, "1", "100", "0")
    store.update_order(old, created_at=1000.0)

    store.set_book_epoch("dry", "ai", 2000.0)

    # One row written after the epoch, and one on the other book.
    fresh = ocid("ai", 2)
    place_equity(store, fresh, "ai", "BUY", "50", "2", status=FILLED)
    snapshot(store, fresh, "2", "100", "0")
    store.update_order(fresh, created_at=3000.0)

    other = ocid("ai", 3)
    place_equity(store, other, "ai", "BUY", "20", "3", status=FILLED, book="live")
    snapshot(store, other, "3", "60", "0")
    store.update_order(other, created_at=3000.0)

    # Only the row written after the dry book's epoch is that book's spend...
    assert led.equity_pool_used("dry") == D("100")
    # ...and the epoch is per book: the live book's row is its own, unhidden.
    assert led.equity_pool_used("live") == D("60")

    # Without the epoch every row of the dry book counts, the old one included.
    store.set_book_epoch("dry", "ai", 0.0)
    assert led.equity_pool_used("dry") == D("200")
    assert led.equity_pool_used("live") == D("60")


def test_equity_pool_used_is_not_clamped(store):
    """A sell that brought back more than the buys spent reads negative here."""
    led = equity_ledger(store, capital="150")
    sold = ocid("ai", 1)
    place_equity(store, sold, "ai", "SELL", "100", "5", status=FILLED)
    snapshot(store, sold, "5", "500", "0")

    assert led.equity_pool_used("dry") == D("-500")


def test_unallocated_adds_the_equity_pool_once(store):
    led = equity_ledger(store, capital="150")
    place_equity(store, ocid("ai", 1), "ai", "BUY", "100", "1", product=NVDA, level=-1)
    place_equity(store, ocid("ai", 2), "ai", "BUY", "50", "2", product=VOO, level=-1)

    out = led.unallocated({"USD": D("400"), "NVDA": D("0"), "VOO": D("0")}, book="dry")

    # 150 of pool, counted once — not 150 twice, once per equity product.
    assert out["USD"] == D("250")
    assert out["NVDA"] == D("0")
    assert out["VOO"] == D("0")


def test_unallocated_counts_the_equity_base_side(store):
    led = equity_ledger(store, capital="0")
    bought = ocid("ai", 1)
    place_equity(store, bought, "ai", "BUY", "100", "2", status=FILLED)
    snapshot(store, bought, "2", "200", "0")

    out = led.unallocated({"USD": D("0"), "NVDA": D("3")}, book="dry")

    # The base side is still per product...
    assert out["NVDA"] == D("1")
    # ... and a pool floored at zero is not a negative holding handed to anyone.
    assert out["USD"] == D("0")


def test_live_usdc_pool_ignores_equity_slots(store):
    led = equity_ledger(store, capital="150", ai_capital=Capital("50"))
    place(store, ocid("ai", 1), "ai", "BUY", "1", "10", product=XRP, book="live")
    place_equity(store, ocid("ai", 2), "ai", "BUY", "100", "1", product=NVDA, book="live")
    sold = ocid("ai", 3)
    place_equity(store, sold, "ai", "SELL", "20", "2", product=VOO, status=FILLED, book="live")
    snapshot(store, sold, "2", "40", "0")

    # The AI's crypto quote side is its own USDC pool: no equity row is in it.
    usdc = led.holding("ai", XRP, book="live")
    assert usdc.quote == D("50")
    assert usdc.reserved_quote == D("10.05")

    equity = led.holding("ai", NVDA, book="live")
    assert equity.quote == D("190")  # 150 of capital plus the 40 the sell brought in
    assert equity.reserved_quote == D("100")
    assert equity.available_quote == D("90")

    # USD is the equity pool, added once: the equity sell's proceeds are not
    # also reserved as a crypto-side USD pool.
    out = led.unallocated({"USDC": D("50"), "USD": D("250")}, book="live")
    assert out["USDC"] == D("0")
    assert out["USD"] == D("60")


def test_equity_pool_floors_at_zero_when_capital_is_lowered(store):
    capital = Capital("500")
    led = equity_ledger(store, capital=capital)
    bought = ocid("ai", 1)
    place_equity(store, bought, "ai", "BUY", "100", "3", status=FILLED)
    snapshot(store, bought, "3", "300", "0")

    assert led.holding("ai", NVDA, book="dry").quote == D("200")

    capital.amount = D("100")  # lowered under what was already spent
    held = led.holding("ai", NVDA, book="dry")
    assert held.quote == D("0")
    assert held.available_quote == D("0")

    # Money that is gone cannot be subtracted from the account as a credit.
    assert led.unallocated({"USD": D("300"), "NVDA": D("3")}, book="dry")["USD"] == (
        D("300")
    )


def test_equity_pool_is_read_per_book(store):
    led = equity_ledger(store, capital="150")
    place_equity(store, ocid("ai", 1), "ai", "BUY", "100", "1", book="dry")
    place_equity(store, ocid("ai", 2), "ai", "BUY", "50", "1", book="live")

    assert led.equity_pool_used("dry") == D("100")
    assert led.equity_pool_used("live") == D("50")
    assert led.holding("ai", NVDA, book="dry").available_quote == D("50")
    assert led.holding("ai", NVDA, book="live").available_quote == D("100")


def test_ledger_without_equity_settings_still_reads_row_types(store):
    """No callables: the pool still counts an EQUITY row by the row's own kind."""
    led = Ledger(store, fee_rate=FEE)
    place_equity(store, ocid("ai", 1), "ai", "BUY", "100", "1", level=-1)
    # A SPOT row of the same owner on the same book spends none of the pool.
    place(store, ocid("ai", 2), "ai", "BUY", "1", "7", product=XRP)

    # Nothing tells this ledger what an equity is, so the resting EQUITY buy is
    # read from the row's own product type and the crypto row is not in it.
    assert led.equity_pool_used("dry") == D("100")
    assert led.holding("ai", NVDA, book="dry").quote == D("0")

    # Both new settings are keyword-only.
    with pytest.raises(TypeError):
        Ledger(store, FEE, equity_ai_capital=lambda: D("1"))


def test_delisted_symbol_stays_in_the_equity_pool(store):
    """A symbol off the equity list that still has EQUITY rows is still equity."""
    listed = {NVDA, VOO}
    led = Ledger(
        store,
        fee_rate=FEE,
        equity_ai_capital=Capital("150"),
        is_equity=lambda product: product in listed,
    )
    bought = ocid("ai", 1)
    place_equity(store, bought, "ai", "BUY", "100", "1", status=FILLED)
    snapshot(store, bought, "1", "100", "0")

    # The symbol is delisted: only VOO-USD is on the equity list now.
    listed.discard(NVDA)

    # The pool's spend is the row's own kind, never the configured list.
    assert led.equity_pool_used("dry") == D("100")

    # The share the AI still holds is still an equity, so it prices off the pool.
    held = led.holding("ai", NVDA, book="dry")
    assert held.base == D("1")
    assert held.equity is True
    assert led.holding("ai", VOO, book="dry").available_quote == D("50")

    # 150 of capital less the 100 already spent leaves 50 in the pool, and the
    # share the AI holds is subtracted from its own currency: 150 - 50 = 100 of
    # USD, and the one NVDA share with the AI is 0 unallocated.
    out = led.unallocated({"USD": D("150"), "NVDA": D("1")}, book="dry")
    assert out["USD"] == D("100")
    assert out["NVDA"] == D("0")
    assert all(value >= 0 for value in out.values()), out

    products = led.equity_products("dry")
    assert NVDA in products
    assert XRP not in products