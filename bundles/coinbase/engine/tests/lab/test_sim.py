"""lab/sim.py: the next-open market-fill simulator, its timing and its flags.

Every expected number is written out as a literal with the arithmetic that
produces it beside it.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

import pytest

from crow_coinbase.lab import costs as lab_costs
from crow_coinbase.lab.costs import CostModel, Increments, Order
from crow_coinbase.lab.sim import reaction_bar_ts, simulate
from crow_coinbase.lab.store import Bar, Event

UTC = timezone.utc

XRP = "XRP-USDC"
NVDA = "NVDA"

CRYPTO = CostModel(
    XRP,
    taker=D("0.01"),
    maker=D("0.005"),
    slippage=D("0.001"),
    st_tax_rate=D("0.30"),
    lt_tax_rate=D("0.15"),
)
# The same model with no slippage, so a fill price is the bar's open exactly.
CRYPTO0 = CostModel(
    XRP,
    taker=D("0.01"),
    maker=D("0.005"),
    slippage=D("0"),
    st_tax_rate=D("0.30"),
    lt_tax_rate=D("0.15"),
)
STOCK0 = CostModel(
    NVDA,
    taker=D("0"),
    maker=D("0"),
    slippage=D("0"),
    st_tax_rate=D("0.30"),
    lt_tax_rate=D("0.15"),
)

# What every run reports it leaves out, in this order.
NOTES = [
    "$3,000 capital loss offset not modelled (conservative)",
    "wash-sale holding-period tacking not modelled (conservative)",
    "unused loss carryforward given zero value at liquidation",
]


def utc(year, month, day, hour=0, minute=0):
    """A timezone-aware UTC datetime at that clock reading."""
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def daily_bars(symbol, rows):
    """Daily bars stamped 00:00 UTC from (ts, open, close) rows.

    A row may pass None as its close, meaning close == open.  high is
    max(open, close) + 1, low is min(open, close) - 1, volume is 1.
    """
    out = []
    for ts, open_, close in rows:
        o = D(open_)
        c = o if close is None else D(close)
        out.append(
            Bar(
                symbol=symbol,
                interval="1d",
                ts=ts,
                open=o,
                high=(c if c > o else o) + D("1"),
                low=(c if c < o else o) - D("1"),
                close=c,
                volume=D("1"),
            )
        )
    return out


def flat(symbol, days, price):
    """One flat daily bar per timestamp in *days*."""
    return daily_bars(symbol, [(ts, price, price) for ts in days])


def curve_value(result, ts):
    """The equity the curve holds at *ts*."""
    return dict(result.curve)[ts]


def flag_kinds(result):
    return [flag.kind for flag in result.flags]


def test_no_lookahead_next_open():
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3), utc(2024, 1, 4)]
    bars = daily_bars(
        XRP,
        [(days[0], "10", "10"), (days[1], "20", "20"),
         (days[2], "30", "30"), (days[3], "40", "40")],
    )
    seen = []

    def decide(ctx):
        seen.append((len(ctx.bars), ctx.bars[-1].ts, ctx.now))
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("1"))]
        return None

    result = simulate(bars, [], decide, D("1000"), D("0"), CRYPTO0)

    # at bar i the rule sees bars 0..i inclusive, and now is that bar's stamp
    assert seen == [
        (1, days[0], days[0]),
        (2, days[1], days[1]),
        (3, days[2], days[2]),
        (4, days[3], days[3]),
    ]
    # the day-0 decision fills at the day-1 open, never at the day-0 open
    assert len(result.trades) == 1
    assert result.trades[0].ts == days[1]
    assert result.trades[0].price == D("20")
    assert result.trades[0].qty == D("1")


def test_event_hidden_before_announced():
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3), utc(2024, 1, 4)]
    bars = flat(XRP, days, "100")
    # scheduled for day 4, but known from day 2 on
    earnings = Event(
        XRP, "earnings", at=utc(2024, 1, 5), announced_at=days[2],
        session="post", note="",
    )
    counts = []

    def decide(ctx):
        counts.append(len(ctx.events))
        return None

    simulate(bars, [earnings], decide, D("1000"), D("0"), CRYPTO0)
    assert counts == [0, 0, 1, 1]

    # a second event announced on day 3 joins the visible set from that bar on
    lockup = Event(
        XRP, "lockup", at=utc(2024, 1, 5), announced_at=days[3],
        session="post", note="",
    )
    counts_with_two = []

    def decide_two(ctx):
        counts_with_two.append(len(ctx.events))
        return None

    simulate(bars, [earnings, lockup], decide_two, D("1000"), D("0"), CRYPTO0)
    assert counts_with_two == [0, 0, 1, 2]


def test_post_close_event_next_session():
    stamps = [utc(2024, 1, day) for day in (8, 9, 10, 11, 12, 15)]  # Mon..Fri, Mon

    def event(at, session):
        return Event(
            NVDA, "earnings", at=at, announced_at=at - timedelta(days=3),
            session=session, note="",
        )

    # released after Wednesday's close: the Thursday session reacts
    assert reaction_bar_ts(event(utc(2024, 1, 10, 21), "post"), stamps) == utc(2024, 1, 11)
    # the same instant tagged "pre": Wednesday's own bar reacts
    assert reaction_bar_ts(event(utc(2024, 1, 10, 21), "pre"), stamps) == utc(2024, 1, 10)
    # after Friday's close the next session is Monday
    assert reaction_bar_ts(event(utc(2024, 1, 12, 21), "post"), stamps) == utc(2024, 1, 15)
    # nothing follows the last bar
    assert reaction_bar_ts(event(utc(2024, 1, 15, 21), "post"), stamps) is None


def test_market_fill_is_taker():
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3)]
    bars = flat(XRP, days, "100")

    def decide(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("1"))]
        return None

    result = simulate(bars, [], decide, D("1000"), D("0"), CRYPTO)

    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.kind == "market"
    assert trade.maker is False
    assert trade.side == "BUY"
    assert trade.price == D("100.1")  # 100 * (1 + 0.001)
    assert trade.fee == D("1.001")  # 1 * 100.1 * 0.01
    assert result.fees == D("1.001")
    assert result.final_cash == D("898.899")  # 1000 - 100.1 - 1.001
    assert result.final_base == D("1")


def test_slippage_direction():
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3)]
    bars = flat(XRP, days, "100")

    def sell_once(ctx):
        if len(ctx.bars) == 1:
            return [Order("SELL", qty=D("1"))]
        return None

    sold = simulate(bars, [], sell_once, D("1000"), D("1"), CRYPTO)
    assert len(sold.trades) == 1
    assert sold.trades[0].price == D("99.9")  # 100 * (1 - 0.001)
    assert sold.trades[0].fee == D("0.999")  # 99.9 * 0.01
    assert sold.final_cash == D("1098.901")  # 1000 + 99.9 - 0.999
    assert sold.final_base == D("0")

    def buy_once(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("1"))]
        return None

    bought = simulate(bars, [], buy_once, D("1000"), D("0"), CRYPTO)
    assert len(bought.trades) == 1
    assert bought.trades[0].price == D("100.1")  # 100 * (1 + 0.001)
    assert bought.trades[0].price > bars[0].open


def test_increment_rounding():
    costs = CostModel(
        XRP,
        taker=D("0.01"),
        maker=D("0"),
        slippage=D("0"),
        st_tax_rate=D("0.30"),
        lt_tax_rate=D("0.15"),
        increments=Increments(base=D("0.1"), quote=D("0.01")),
    )
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3), utc(2024, 1, 4)]
    bars = flat(XRP, days, "100")

    def decide(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", notional=D("1000"))]
        if len(ctx.bars) == 2:
            return [Order("SELL", qty=D("9.95"))]
        if len(ctx.bars) == 3:
            return [Order("BUY", qty=D("0.05"))]
        return None

    result = simulate(bars, [], decide, D("2000"), D("0"), costs)

    bought = result.trades[0]
    assert bought.side == "BUY"
    # 1000 / (100 * 1.01) = 9.9009900..., floored to the 0.1 step
    assert bought.qty == D("9.9")
    assert bought.price == D("100")
    assert bought.fee == D("9.9")  # 9.9*100 * 0.01
    # cash 2000 - 990 - 9.9 = 1000.1, equity 1000.1 + 9.9*100
    assert curve_value(result, days[1]) == D("1990.1")

    sold = result.trades[1]
    assert sold.side == "SELL"
    assert sold.qty == D("9.9")  # 9.95 floored to the 0.1 step
    assert sold.price == D("100")
    assert sold.fee == D("9.9")  # 9.9*100 * 0.01

    assert len(result.trades) == 2
    assert result.final_cash == D("1980.2")  # 1000.1 + 990 - 9.9
    assert result.final_base == D("0")
    assert result.fees == D("19.8")  # 9.9 + 9.9

    # 0.05 is below one 0.1 step: nothing fills and the order is reported
    assert len(result.dropped) == 1
    assert result.dropped[0].qty == D("0.05")
    assert "below_increment" in flag_kinds(result)


def test_year_end_tax_cash_out():
    days = [
        utc(2023, 12, 28),
        utc(2023, 12, 29),
        utc(2023, 12, 30),
        utc(2023, 12, 31),
        utc(2024, 1, 1),
        utc(2024, 1, 2),
    ]
    bars = daily_bars(
        NVDA,
        [
            (days[0], "10", "10"),
            (days[1], "10", "10"),
            (days[2], "20", "20"),
            (days[3], "20", "20"),
            (days[4], "20", "20"),
            (days[5], "20", "20"),
        ],
    )

    def decide(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("10"))]  # fills Dec-29 at 10
        if len(ctx.bars) == 2:
            return [Order("SELL", qty=D("10"))]  # fills Dec-30 at 20
        return None

    result = simulate(bars, [], decide, D("1000"), D("0"), STOCK0)

    assert len(result.realized) == 1
    assert result.realized[0].gain == D("100")  # 10*20 - 10*10
    assert result.realized[0].long_term is False

    assert curve_value(result, days[3]) == D("1100")  # 1000 - 100 + 200 in cash
    # the 2023 tax of 100*0.30 = 30 leaves cash at the first 2024 bar
    assert curve_value(result, days[4]) == D("1070")
    assert result.tax_payments == [(days[4], D("30"))]
    assert result.taxes_by_year == {2023: D("30")}
    assert result.final_equity == D("1070")
    assert result.final_equity_after_liquidation_tax == D("1070")


def test_gap_fill_flagged():
    # day 2 is missing, so the day-1 decision waits and fills two days later
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 4)]
    bars = daily_bars(
        XRP, [(days[0], "10", "10"), (days[1], "20", "20"), (days[2], "30", "30")]
    )

    def decide(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("1"))]  # fills day 1: one interval, no gap
        if len(ctx.bars) == 2:
            return [Order("BUY", qty=D("1"))]  # fills day 3: a two-day jump
        return None

    result = simulate(bars, [], decide, D("1000"), D("0"), CRYPTO0)
    assert len(result.trades) == 2
    gaps = [flag for flag in result.flags if flag.kind == "gap_fill"]
    assert [flag.ts for flag in gaps] == [days[2]]

    def stock_fill_over(rows):
        stock_bars = flat(NVDA, rows, "10")

        def decide_once(ctx):
            if len(ctx.bars) == 1:
                return [Order("BUY", qty=D("1"))]
            return None

        return simulate(stock_bars, [], decide_once, D("1000"), D("0"), STOCK0)

    # a weekend is 3 days and a holiday Friday 4 days; neither is a gap
    weekend = stock_fill_over([utc(2024, 1, 5), utc(2024, 1, 8)])
    assert [flag for flag in weekend.flags if flag.kind == "gap_fill"] == []
    four_days = stock_fill_over([utc(2024, 1, 4), utc(2024, 1, 8)])
    assert [flag for flag in four_days.flags if flag.kind == "gap_fill"] == []
    # five days is longer than the stock maximum
    five_days = stock_fill_over([utc(2024, 1, 4), utc(2024, 1, 9)])
    assert [flag.ts for flag in five_days.flags if flag.kind == "gap_fill"] == [
        utc(2024, 1, 9)
    ]


def test_last_bar_order_dropped():
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3)]
    bars = flat(XRP, days, "100")
    late = []

    def decide(ctx):
        if len(ctx.bars) == 3:
            order = Order("BUY", qty=D("1"))
            late.append(order)
            return [order]
        return None

    result = simulate(bars, [], decide, D("1000"), D("0"), CRYPTO)
    assert result.trades == []
    assert len(result.dropped) == 1
    assert result.dropped[0].qty == D("1")
    assert "last_bar_order_dropped" in flag_kinds(result)
    assert result.final_cash == D("1000")
    assert result.final_base == D("0")


def test_initial_orders_fill_first_open():
    days = [utc(2024, 1, 1), utc(2024, 1, 2)]
    bars = daily_bars(NVDA, [(days[0], "20", "20"), (days[1], "30", "30")])

    result = simulate(
        bars,
        [],
        lambda ctx: None,
        D("1000"),
        D("0"),
        STOCK0,
        initial_orders=[Order("BUY", qty=D("10"))],
    )

    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == days[0]
    assert trade.side == "BUY"
    assert trade.qty == D("10")
    assert trade.price == D("20")  # the first bar's open
    assert trade.fee == D("0")
    assert result.final_cash == D("800")  # 1000 - 10*20
    assert result.final_base == D("10")


def test_liquidation_equity():
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3)]
    bars = daily_bars(
        NVDA,
        [(days[0], "100", "100"), (days[1], "100", "100"), (days[2], "100", "150")],
    )

    result = simulate(bars, [], lambda ctx: None, D("0"), D("10"), STOCK0)

    assert result.trades == []
    assert result.final_equity == D("1500")  # 0 cash + 10*150
    assert result.taxes_by_year == {}
    # the starting lot was acquired at 100 (the first open); marked 150 on
    # 2024-01-03 the 10*(150-100) = 500 gain is short-term: 500*0.30 = 150
    assert result.final_equity_after_liquidation_tax == D("1350")


def test_limit_order_refused():
    days = [utc(2024, 1, 1), utc(2024, 1, 2)]
    bars = flat(XRP, days, "100")
    resting = Order("BUY", kind="limit", qty=D("1"), limit_price=D("90"))

    with pytest.raises(ValueError):
        simulate(
            bars, [], lambda ctx: None, D("1000"), D("0"), CRYPTO,
            initial_orders=[resting],
        )

    def decide(ctx):
        if len(ctx.bars) == 1:
            return [Order("SELL", kind="limit", qty=D("1"), limit_price=D("110"))]
        return None

    with pytest.raises(ValueError):
        simulate(bars, [], decide, D("1000"), D("1"), CRYPTO)


def test_unsorted_bars_refused():
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3)]
    ordered = flat(XRP, days, "100")

    with pytest.raises(ValueError):
        simulate(
            [ordered[1], ordered[0], ordered[2]], [], lambda ctx: None,
            D("1000"), D("0"), CRYPTO,
        )

    with pytest.raises(ValueError):
        simulate([], [], lambda ctx: None, D("1000"), D("0"), CRYPTO)


def test_context_lots_is_a_snapshot():
    days = [utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3), utc(2024, 1, 4)]
    bars = flat(XRP, days, "100")

    def orders(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("2"))]  # fills day 1
        if len(ctx.bars) == 3:
            return [Order("SELL", qty=D("1"))]  # fills day 3
        return None

    seen = []

    def reading(ctx):
        seen.append((ctx.lots.holdings(), ctx.base))
        return orders(ctx)

    clean = simulate(bars, [], reading, D("1000"), D("5"), CRYPTO0)
    # 5 held at bar 0, 5 + 2 = 7 after the buy fills, 7 - 1 = 6 after the sale
    assert [pair[0] for pair in seen] == [D("5"), D("7"), D("7"), D("6")]
    assert [pair[0] for pair in seen] == [pair[1] for pair in seen]

    def scribbling(ctx):
        # the book a rule is handed agrees with the run before the rule edits it
        assert ctx.lots.holdings() == ctx.base
        ctx.lots.buy(ctx.now, D("3"), D("70"))
        ctx.lots.sell(ctx.now, D("1"), D("70"))
        return orders(ctx)

    dirty = simulate(bars, [], scribbling, D("1000"), D("5"), CRYPTO0)
    assert dirty.final_cash == clean.final_cash
    assert dirty.final_base == clean.final_base
    assert [(t.side, t.qty) for t in dirty.trades] == [
        (t.side, t.qty) for t in clean.trades
    ]


def test_no_deep_copy_per_bar(monkeypatch):
    real = lab_costs.copy.deepcopy
    counted = {"n": 0}

    def counting(value, memo=None, *args, **kwargs):
        # copy's own recursion passes its memo along, so only a call made without
        # one is a fresh copy of a whole book
        if memo is None:
            counted["n"] += 1
        return real(value, memo, *args, **kwargs)

    monkeypatch.setattr(lab_costs.copy, "deepcopy", counting)

    def decide(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("1"))]
        if len(ctx.bars) == 2:
            return [Order("SELL", qty=D("1"))]
        return None

    short_days = [utc(2024, 1, 1) + timedelta(days=offset) for offset in range(10)]
    long_days = [utc(2024, 1, 1) + timedelta(days=offset) for offset in range(60)]

    short = simulate(
        flat(XRP, short_days, "100"), [], decide, D("1000"), D("0"), CRYPTO0
    )
    short_copies = counted["n"]
    counted["n"] = 0
    long = simulate(
        flat(XRP, long_days, "100"), [], decide, D("1000"), D("0"), CRYPTO0
    )
    long_copies = counted["n"]

    # the same one buy and one sell in both runs, six times as many bars in the
    # second
    assert [t.side for t in short.trades] == [t.side for t in long.trades]
    assert [t.side for t in long.trades] == ["BUY", "SELL"]
    assert short_copies == long_copies


def test_notes_and_wash_sale_count_on_a_stock():
    days = [utc(2024, 3, 1) + timedelta(days=offset) for offset in range(5)]
    bars = daily_bars(
        NVDA,
        [
            (days[0], "100", "100"),
            (days[1], "100", "100"),  # the buy fills here at 100
            (days[2], "80", "80"),  # the sell fills here at 80
            (days[3], "80", "80"),
            (days[4], "85", "85"),  # the replacement buys here at 85
        ],
    )

    def decide(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("10"))]
        if len(ctx.bars) == 2:
            return [Order("SELL", qty=D("10"))]
        if len(ctx.bars) == 4:
            return [Order("BUY", qty=D("10"))]
        return None

    result = simulate(bars, [], decide, D("2000"), D("0"), STOCK0)

    assert result.notes == NOTES
    # 10*80 - 10*100 = -200 sold on 2024-03-03, replaced on 2024-03-05 with the
    # whole 200 disallowed and carried into the replacement's basis
    assert len(result.realized) == 1
    assert result.realized[0].gain == D("0")  # -200 + 200
    assert result.realized[0].disallowed == D("200")
    assert result.wash_sale_count == 1


def test_notes_and_no_wash_sale_on_a_crypto_pair():
    days = [utc(2024, 3, 1) + timedelta(days=offset) for offset in range(5)]
    bars = daily_bars(
        XRP,
        [
            (days[0], "100", "100"),
            (days[1], "100", "100"),  # the buy fills here at 100
            (days[2], "80", "80"),  # the sell fills here at 80
            (days[3], "80", "80"),
            (days[4], "85", "85"),  # the replacement buys here at 85
        ],
    )

    def decide(ctx):
        if len(ctx.bars) == 1:
            return [Order("BUY", qty=D("10"))]
        if len(ctx.bars) == 2:
            return [Order("SELL", qty=D("10"))]
        if len(ctx.bars) == 4:
            return [Order("BUY", qty=D("10"))]
        return None

    result = simulate(bars, [], decide, D("2000"), D("0"), CRYPTO0)

    assert result.notes == NOTES
    assert result.wash_sale_count == 0
    # a pair keeps the whole loss: 10*80 - 8 sell fee - (10*100 + 10 buy fee)
    assert len(result.realized) == 1
    assert result.realized[0].gain == D("-218")
    assert result.realized[0].disallowed == D("0")


# ---------------------------------------------------------------- contributions


# Ten weekday bars, two ISO weeks: Monday 26 February to Friday 1 March 2024,
# then Monday 4 March to Friday 8 March 2024.
CONTRIBUTION_DAYS = [
    utc(2024, 2, 26),
    utc(2024, 2, 27),
    utc(2024, 2, 28),
    utc(2024, 2, 29),
    utc(2024, 3, 1),
    utc(2024, 3, 4),
    utc(2024, 3, 5),
    utc(2024, 3, 6),
    utc(2024, 3, 7),
    utc(2024, 3, 8),
]

WEEKLY_FIFTY = {"amount": D("50"), "every": "week"}


def test_simulate_contribution_weekly():
    bars = flat(XRP, CONTRIBUTION_DAYS, "100")

    result = simulate(
        bars,
        [],
        lambda ctx: None,
        D("0"),
        D("0"),
        CRYPTO0,
        contribution=WEEKLY_FIFTY,
    )

    # two week starts, one $50 contribution at each: 50 + 50 = 100
    assert result.total_contributed == D("100")
    assert result.contributions == [
        (CONTRIBUTION_DAYS[0], D("50")),
        (CONTRIBUTION_DAYS[5], D("50")),
    ]
    # nothing is bought, so each bar's equity is the cash contributed so far
    assert [equity for _, equity in result.curve] == [D("50")] * 5 + [
        D("100")
    ] * 5
    assert result.final_cash == D("100")


def test_simulate_contribution_default_is_unfunded():
    bars = flat(XRP, CONTRIBUTION_DAYS, "100")

    result = simulate(bars, [], lambda ctx: None, D("250"), D("0"), CRYPTO0)

    assert result.total_contributed == D("0")
    assert result.contributions == []
    assert result.final_cash == D("250")


def test_simulate_contribution_is_available_to_the_decide_that_bar():
    bars = flat(XRP, CONTRIBUTION_DAYS, "100")
    seen = []

    def decide(ctx):
        seen.append(ctx.cash)
        return None

    result = simulate(
        bars,
        [],
        decide,
        D("20"),
        D("0"),
        CRYPTO0,
        contribution=WEEKLY_FIFTY,
    )

    # the contribution lands before the bar's fills and before its decide:
    # 20 + 50 = 70 on the first bar, and 20 + 50 + 50 = 120 from the second week
    assert seen[0] == D("70")
    assert seen[5] == D("120")
    assert result.curve[0][1] == D("70")


@pytest.mark.parametrize(
    "contribution",
    [
        5,  # not a dict
        {"amount": D("50")},  # no "every"
        {"amount": D("0"), "every": "week"},  # nothing to contribute
        {"amount": 50, "every": "week"},  # an int, not a Decimal
        {"amount": D("50"), "every": "day"},  # not a weekly schedule
    ],
)
def test_simulate_contribution_refused(contribution):
    bars = flat(XRP, CONTRIBUTION_DAYS, "100")

    with pytest.raises(ValueError, match="contribution"):
        simulate(
            bars,
            [],
            lambda ctx: None,
            D("0"),
            D("0"),
            CRYPTO0,
            contribution=contribution,
        )


def test_simulate_contribution_counts_week_starts_only():
    # Monday, Tuesday, then Thursday of one ISO week: the skipped Wednesday in
    # the middle is no new week, so 50 is contributed once
    gapped = flat(
        XRP,
        [utc(2024, 2, 26), utc(2024, 2, 27), utc(2024, 2, 29)],
        "100",
    )
    mid_week = simulate(
        gapped,
        [],
        lambda ctx: None,
        D("0"),
        D("0"),
        CRYPTO0,
        contribution=WEEKLY_FIFTY,
    )
    assert mid_week.contributions == [(utc(2024, 2, 26), D("50"))]
    assert mid_week.total_contributed == D("50")

    # Friday 1 March and Monday 4 March are two ISO weeks, and bar 0 always
    # counts, so each carries a contribution
    across_weekend = flat(
        XRP, [utc(2024, 3, 1), utc(2024, 3, 4)], "100"
    )
    two_weeks = simulate(
        across_weekend,
        [],
        lambda ctx: None,
        D("0"),
        D("0"),
        CRYPTO0,
        contribution=WEEKLY_FIFTY,
    )
    assert two_weeks.contributions == [
        (utc(2024, 3, 1), D("50")),
        (utc(2024, 3, 4), D("50")),
    ]
    assert two_weeks.total_contributed == D("100")


def test_accepted_refuses_gates_with_a_clear_message():
    from crow_coinbase.lab.sim import Decision, Gates, _accepted

    # A bare Gates is a decision for the grid simulator, so the market
    # simulator says so instead of walking it as a list of orders.
    with pytest.raises(ValueError, match="grid") as caught:
        _accepted(Gates(grid_armed=False))

    assert type(caught.value) is ValueError
    message = str(caught.value)
    assert "Gates" in message
    assert "market" in message

    # A Decision carries its gates beside its orders, and the orders still pass
    # through untouched.
    order = Order("BUY", qty=D("1"))
    assert _accepted(
        Decision(orders=(order,), gates=Gates(grid_armed=False))
    ) == [order]