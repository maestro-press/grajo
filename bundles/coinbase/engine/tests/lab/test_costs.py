"""lab/costs.py: orders, cost models, the FIFO tax-lot book and tax due.

Every expected number is written out as a literal with the arithmetic that
produces it beside it.
"""

from datetime import datetime, timezone
from decimal import Decimal as D

import pytest

from crow_coinbase.lab.costs import (
    CostModel,
    Lots,
    Order,
    RealizedGain,
    WashSaleFlag,
    liquidation_tax,
    tax_due,
)

UTC = timezone.utc

CRYPTO = CostModel(
    "XRP-USDC",
    taker=D("0.01"),
    maker=D("0.005"),
    slippage=D("0.001"),
    st_tax_rate=D("0.30"),
    lt_tax_rate=D("0.15"),
)

STOCK0 = CostModel(
    "NVDA",
    taker=D("0"),
    maker=D("0"),
    slippage=D("0"),
    st_tax_rate=D("0.30"),
    lt_tax_rate=D("0.15"),
)


def utc(year, month, day, hour=0, minute=0):
    """A timezone-aware UTC datetime at that clock reading."""
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def realized_piece(gain, long_term, sold):
    """One realized piece made by hand, with a dummy acquisition date."""
    return RealizedGain(
        qty=D("1"),
        gain=D(gain),
        long_term=long_term,
        ts_sold=sold,
        ts_acquired=utc(2020, 1, 1),
    )


def test_lots_365_short_366_long():
    # acquired 2023-01-01, sold 2024-01-01: exactly one calendar year, so short
    book = Lots("crypto")
    book.buy(utc(2023, 1, 1), D("1"), D("100"))
    pieces = book.sell(utc(2024, 1, 1), D("1"), D("150"))
    assert len(pieces) == 1
    assert pieces[0].qty == D("1")
    assert pieces[0].gain == D("50")  # 1*150 - 1*100
    assert pieces[0].long_term is False

    # one day past the anniversary: long
    book = Lots("crypto")
    book.buy(utc(2023, 1, 1), D("1"), D("100"))
    pieces = book.sell(utc(2024, 1, 2), D("1"), D("150"))
    assert len(pieces) == 1
    assert pieces[0].gain == D("50")  # 1*150 - 1*100
    assert pieces[0].long_term is True

    # 2024-01-01 to 2025-01-01 spans 366 days but is not past the anniversary
    book = Lots("crypto")
    book.buy(utc(2024, 1, 1), D("1"), D("100"))
    pieces = book.sell(utc(2025, 1, 1), D("1"), D("150"))
    assert len(pieces) == 1
    assert pieces[0].long_term is False

    # 2024-01-01 to 2025-01-02 is past the anniversary: long
    book = Lots("crypto")
    book.buy(utc(2024, 1, 1), D("1"), D("100"))
    pieces = book.sell(utc(2025, 1, 2), D("1"), D("150"))
    assert len(pieces) == 1
    assert pieces[0].gain == D("50")  # 1*150 - 1*100
    assert pieces[0].long_term is True


def test_lots_fifo_partial():
    book = Lots("crypto")
    book.buy(utc(2023, 1, 1), D("1"), D("100"))
    book.buy(utc(2023, 2, 1), D("1"), D("200"))
    pieces = book.sell(utc(2023, 6, 1), D("1.5"), D("300"))
    assert [(p.qty, p.gain) for p in pieces] == [
        (D("1"), D("200")),  # 1*300 - 1*100
        (D("0.5"), D("50")),  # 0.5*300 - 0.5*200
    ]
    assert [p.long_term for p in pieces] == [False, False]
    assert book.holdings() == D("0.5")
    # the returned pieces are the same objects kept in `realized`, in order
    assert len(book.realized) == 2
    assert pieces[0] is book.realized[0]
    assert pieces[1] is book.realized[1]

    rest = book.sell(utc(2023, 7, 1), D("0.5"), D("250"))
    assert len(rest) == 1
    assert rest[0].gain == D("25")  # 0.5*250 - 0.5*200 = 125 - 100
    assert rest[0].long_term is False
    assert book.holdings() == D("0")

    with pytest.raises(ValueError):
        book.sell(utc(2023, 8, 1), D("1"), D("250"))

    # a fee on the buy joins the basis, a fee on the sell is allocated pro rata
    book = Lots("crypto")
    book.buy(utc(2023, 1, 1), D("2"), D("100"), fee=D("2"))
    fee_pieces = book.sell(utc(2023, 2, 1), D("1"), D("120"), fee=D("1.2"))
    assert len(fee_pieces) == 1
    assert fee_pieces[0].qty == D("1")
    assert fee_pieces[0].gain == D("17.8")  # 120 - 1.2 - 202/2 = 120 - 1.2 - 101


def test_tax_year_netting_and_carryforward():
    realized = [
        # 2023: st = 1000 - 400 = 600, lt = -300 -> cross-net 600-300 = 300 st
        realized_piece("1000", False, utc(2023, 6, 1)),
        realized_piece("-400", False, utc(2023, 7, 1)),
        realized_piece("-300", True, utc(2023, 8, 1)),
        # 2024: st = -500, lt = 200 -> cross-net 200-500 = -300 lt carry
        realized_piece("-500", False, utc(2024, 6, 1)),
        realized_piece("200", True, utc(2024, 7, 1)),
        # 2025: lt = 1000 - 300 carried = 700
        realized_piece("1000", True, utc(2025, 6, 1)),
        # 2026: st = -200 -> carries
        realized_piece("-200", False, utc(2026, 6, 1)),
        # 2027: st = 500 - 200 carried = 300
        realized_piece("500", False, utc(2027, 6, 1)),
    ]
    assert tax_due(realized, CRYPTO) == {
        2023: D("90"),  # 300*0.30
        2024: D("0"),  # nothing left taxable
        2025: D("105"),  # 700*0.15
        2026: D("0"),  # a loss year
        2027: D("90"),  # 300*0.30
    }


def test_crypto_taxed_no_wash_sale():
    book = Lots("crypto")
    book.buy(utc(2024, 3, 1), D("10"), D("100"))
    loss = book.sell(utc(2024, 3, 5), D("10"), D("80"))
    assert len(loss) == 1
    assert loss[0].gain == D("-200")  # 10*80 - 10*100

    # the very same loss repurchased five days later: no wash-sale rule
    book.buy(utc(2024, 3, 10), D("10"), D("80"))
    assert book.wash_sale_flags() == []
    assert book.realized[0].gain == D("-200")
    assert book.realized[0].disallowed == D("0")

    # the replacement lot keeps its own untouched basis of 10*80 = 800
    again = book.sell(utc(2024, 4, 1), D("10"), D("100"))
    assert len(again) == 1
    assert again[0].gain == D("200")  # 10*100 - 10*80
    assert again[0].long_term is False

    # crypto gains are taxed like any other short-term gain
    gain = realized_piece("100", False, utc(2024, 6, 1))
    assert tax_due([gain], CRYPTO) == {2024: D("30")}  # 100*0.30


def test_stock_wash_sale_flagged_basis_carried():
    # (1) full replacement: the whole 200 loss is disallowed
    book = Lots("stock")
    book.buy(utc(2024, 3, 1), D("10"), D("100"))
    book.sell(utc(2024, 3, 5), D("10"), D("80"))
    assert book.realized[0].gain == D("-200")  # 10*80 - 10*100
    book.buy(utc(2024, 3, 20), D("10"), D("85"))
    flags = book.wash_sale_flags()
    assert len(flags) == 1
    assert isinstance(flags[0], WashSaleFlag)
    assert flags[0].qty == D("10")
    assert flags[0].disallowed_loss == D("200")  # (100-80)*10
    assert flags[0].ts == utc(2024, 3, 20)  # the later of sale and buy
    assert book.realized[0].gain == D("0")  # -200 + 200
    assert book.realized[0].disallowed == D("200")
    out = book.sell(utc(2024, 5, 1), D("10"), D("110"))
    assert len(out) == 1
    assert out[0].gain == D("50")  # 10*110 - (10*85 + 200) = 1100 - 1050

    # (2) partial replacement: only four units carry the disallowed loss
    book = Lots("stock")
    book.buy(utc(2024, 3, 1), D("10"), D("100"))
    book.sell(utc(2024, 3, 5), D("10"), D("80"))
    book.buy(utc(2024, 3, 20), D("4"), D("85"))
    flags = book.wash_sale_flags()
    assert [(f.qty, f.disallowed_loss) for f in flags] == [(D("4"), D("80"))]  # 20*4
    assert book.realized[0].gain == D("-120")  # -200 + 80
    partial = book.sell(utc(2024, 4, 1), D("4"), D("105"))
    assert len(partial) == 1
    # basis 4*85 + 80 = 420, per unit 105: 4*105 - 420 = 0
    assert partial[0].gain == D("0")

    # (3) a purchase already held when the loss is sold: FIFO sells the older
    # lot, and the newer lot's basis takes the disallowed loss
    book = Lots("stock")
    book.buy(utc(2024, 4, 1), D("10"), D("100"))
    book.buy(utc(2024, 4, 20), D("10"), D("100"))
    loss = book.sell(utc(2024, 4, 25), D("10"), D("90"))
    assert len(loss) == 1
    assert loss[0].gain == D("-100")  # 10*90 - 10*100
    flags = book.wash_sale_flags()
    assert [(f.qty, f.disallowed_loss) for f in flags] == [(D("10"), D("100"))]  # 10*10
    kept = book.sell(utc(2024, 6, 1), D("10"), D("110"))
    assert len(kept) == 1
    # basis 10*100 + 100 = 1100: 10*110 - 1100 = 0
    assert kept[0].gain == D("0")

    # (4) 31 days after the sale is outside the window: no flag, basis untouched
    book = Lots("stock")
    book.buy(utc(2024, 3, 1), D("10"), D("100"))
    book.sell(utc(2024, 3, 5), D("10"), D("80"))
    book.buy(utc(2024, 4, 5), D("10"), D("85"))  # 2024-03-05 + 30 days = 2024-04-04
    assert book.wash_sale_flags() == []
    assert book.realized[0].gain == D("-200")
    assert book.realized[0].disallowed == D("0")


def test_tax_rates_required():
    with pytest.raises(TypeError):
        CostModel("XRP-USDC", D("0.01"), D("0.005"), D("0.001"))

    with pytest.raises(ValueError):
        CostModel(
            "XRP-USDC", D("0.01"), D("0.005"), D("0.001"),
            st_tax_rate=None, lt_tax_rate=D("0.15"),
        )
    with pytest.raises(ValueError):
        CostModel(
            "XRP-USDC", D("0.01"), D("0.005"), D("0.001"),
            st_tax_rate=D("1.5"), lt_tax_rate=D("0.15"),
        )
    with pytest.raises(ValueError):
        CostModel(
            "XRP-USDC", D("0.01"), D("0.005"), D("0.001"),
            st_tax_rate=D("-0.1"), lt_tax_rate=D("0.15"),
        )
    with pytest.raises(ValueError):
        CostModel(
            "XRP-USDC", D("0.01"), D("0.005"), D("0.001"),
            st_tax_rate=D("0.30"), lt_tax_rate=None,
        )
    with pytest.raises(ValueError):
        CostModel(
            "XRP-USDC", D("0.01"), D("0.005"), D("0.001"),
            st_tax_rate=D("0.30"), lt_tax_rate=D("1.01"),
        )

    crypto = CostModel.for_crypto(
        "XRP-USDC",
        st_tax_rate=D("0.30"),
        lt_tax_rate=D("0.15"),
        slippage=D("0.001"),
    )
    assert crypto.asset_class == "crypto"
    assert crypto.taker == D("0.009")
    assert crypto.maker == D("0.005")
    assert crypto.slippage == D("0.001")

    stock = CostModel.for_stock("NVDA", st_tax_rate=D("0.30"), lt_tax_rate=D("0.15"))
    assert stock.asset_class == "stock"
    assert stock.taker == D("0")
    assert stock.maker == D("0")
    assert stock.slippage == D("0.0005")


def test_order_validation():
    # a market order carries exactly one of qty and notional
    with pytest.raises(ValueError):
        Order("BUY")
    with pytest.raises(ValueError):
        Order("BUY", qty=D("1"), notional=D("100"))
    with pytest.raises(ValueError):
        Order("BUY", qty=D("0"))
    with pytest.raises(ValueError):
        Order("SELL", notional=D("-5"))

    # a limit order carries qty and limit_price, never a notional
    with pytest.raises(ValueError):
        Order("BUY", kind="limit", qty=D("1"))
    with pytest.raises(ValueError):
        Order("BUY", kind="limit", limit_price=D("100"))
    with pytest.raises(ValueError):
        Order("BUY", kind="limit", qty=D("1"), limit_price=D("100"), notional=D("100"))

    market = Order("BUY", qty=D("1"))
    assert market.side == "BUY"
    assert market.qty == D("1")
    assert market.notional is None
    assert market.kind == "market"
    assert market.limit_price is None

    assert Order("SELL", notional=D("100")).notional == D("100")
    resting = Order("BUY", kind="limit", qty=D("1"), limit_price=D("100"))
    assert resting.kind == "limit"
    assert resting.limit_price == D("100")
    assert resting.notional is None


def test_liquidation_tax():
    book = Lots("stock")
    book.buy(utc(2024, 1, 1), D("10"), D("100"))
    realized = []

    # 10*150 - 10*100 = 500 short-term -> 500*0.30 = 150
    assert (
        liquidation_tax(book, realized, D("0"), D("150"), utc(2024, 6, 1), STOCK0)
        == D("150")
    )
    # the same, with 40 already paid: 150 - 40
    assert (
        liquidation_tax(book, realized, D("40"), D("150"), utc(2024, 6, 1), STOCK0)
        == D("110")
    )
    # marked a day past the anniversary: long-term -> 500*0.15 = 75
    assert (
        liquidation_tax(book, realized, D("0"), D("150"), utc(2025, 1, 2), STOCK0)
        == D("75")
    )

    # the book and the realized list handed in are left alone
    assert book.holdings() == D("10")
    assert realized == []


def test_tax_due_cross_side_netting_keeps_the_class():
    # 40% short-term, 15% long-term: a loss left over after it is netted
    # against the other side carries forward in its own class
    rates = CostModel(
        "XRP-USDC",
        taker=D("0.01"),
        maker=D("0.005"),
        slippage=D("0.001"),
        st_tax_rate=D("0.40"),
        lt_tax_rate=D("0.15"),
    )

    # (a) 2024: st -10000 against lt +4000, so the long-term gain is used up and
    # 6000 of short-term loss carries.  2025: st 6000 - 6000 = 0, lt 6000, and
    # 6000 * 0.15 = 900.
    assert tax_due(
        [
            realized_piece("-10000", False, utc(2024, 6, 1)),
            realized_piece("4000", True, utc(2024, 7, 1)),
            realized_piece("6000", False, utc(2025, 6, 1)),
            realized_piece("6000", True, utc(2025, 7, 1)),
        ],
        rates,
    ) == {2024: D("0"), 2025: D("900")}

    # (b) the mirror: 2024 lt -10000 against st +4000 leaves 6000 of long-term
    # loss to carry.  2025: lt 6000 - 6000 = 0, st 6000, and 6000 * 0.40 = 2400.
    assert tax_due(
        [
            realized_piece("4000", False, utc(2024, 6, 1)),
            realized_piece("-10000", True, utc(2024, 7, 1)),
            realized_piece("6000", False, utc(2025, 6, 1)),
            realized_piece("6000", True, utc(2025, 7, 1)),
        ],
        rates,
    ) == {2024: D("0"), 2025: D("2400")}

    # (c) both sides lose in 2024 and each carries on its own side.  2025:
    # st 5000 - 3000 = 2000 and lt 5000 - 2000 = 3000, so
    # 2000 * 0.40 + 3000 * 0.15 = 800 + 450 = 1250.
    assert tax_due(
        [
            realized_piece("-3000", False, utc(2024, 6, 1)),
            realized_piece("-2000", True, utc(2024, 7, 1)),
            realized_piece("5000", False, utc(2025, 6, 1)),
            realized_piece("5000", True, utc(2025, 7, 1)),
        ],
        rates,
    ) == {2024: D("0"), 2025: D("1250")}


def test_sell_exact_holdings_closes_book_despite_decimal_dust():
    # Five lots bought the same day from quantities whose exact total needs 30
    # digits, more than the 28 a running Decimal sum keeps.
    quantities = [
        D("921.4597726167156091405273418"),
        D("396.2585561329102386441181073"),
        D("116.1266452466772391276979083"),
        D("10623.61615185612318050057663"),
        D("898.0548165911049496047060587"),
    ]

    def built():
        book = Lots("stock")
        for qty in quantities:
            book.buy(utc(2024, 3, 1), qty, D("100"))
        return book

    # 921.4597726167156091405273418 + 396.2585561329102386441181073
    # + 116.1266452466772391276979083 + 10623.61615185612318050057663
    # + 898.0548165911049496047060587 = 12955.5159424435312170176260461,
    # which the lot-by-lot sum keeps as 12955.51594244353121701762605
    book = built()
    held = book.holdings()
    assert held == D("12955.51594244353121701762605")

    # selling every unit the book reports closes every lot, leaving nothing
    pieces = book.sell(utc(2024, 6, 1), held, D("100"))
    assert book.holdings() == D("0")
    assert book.lots == []
    assert [p.qty for p in pieces] == quantities  # FIFO, oldest lot first
    # each piece: qty*100 - 0 - qty*100 = 0
    assert [p.gain for p in pieces] == [D("0")] * 5

    # a sale above what is held by a visible 0.001 is still refused
    over = built()
    with pytest.raises(ValueError):
        over.sell(utc(2024, 6, 1), held + D("0.001"), D("100"))

    # a partial sale of 1000 leaves the rest:
    # 12955.51594244353121701762605 - 1000 = 11955.51594244353121701762605
    part = built()
    part.sell(utc(2024, 6, 1), D("1000"), D("100"))
    assert part.holdings() == D("11955.51594244353121701762605")


def test_feb_29_anniversary_is_feb_28():
    # acquired 2024-02-29: the first calendar anniversary is 2025-02-28, so a
    # sale on that day is short-term and one day later is long-term
    book = Lots("crypto")
    book.buy(utc(2024, 2, 29), D("1"), D("100"))
    pieces = book.sell(utc(2025, 2, 28), D("1"), D("150"))
    assert len(pieces) == 1
    assert pieces[0].gain == D("50")  # 1*150 - 1*100
    assert pieces[0].long_term is False

    book = Lots("crypto")
    book.buy(utc(2024, 2, 29), D("1"), D("100"))
    pieces = book.sell(utc(2025, 3, 1), D("1"), D("150"))
    assert len(pieces) == 1
    assert pieces[0].gain == D("50")  # 1*150 - 1*100
    assert pieces[0].long_term is True