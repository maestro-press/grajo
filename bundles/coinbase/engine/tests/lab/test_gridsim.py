"""lab/gridsim.py: the intrabar limit-fill grid, its gates and its round trips.

Bars are daily at 00:00 UTC.  Bar 0 is flat at 100, so the grid it builds is
centred on that price and its three levels are 90, 100 and 110.  Every expected
number is written out as a literal with the arithmetic that produces it beside
it.
"""

import random
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

import pytest

from crow_coinbase.lab import costs as lab_costs
from crow_coinbase.lab.costs import CostModel, Increments, Order
from crow_coinbase.lab.gridsim import simulate_grid
from crow_coinbase.lab.sim import Gates, simulate
from crow_coinbase.lab.store import Bar

UTC = timezone.utc
XRP = "XRP-USDC"

# 1% taker, 0.5% maker, 0.1% slippage, a two-decimal product's size and price
# steps.
G = CostModel(
    XRP,
    taker=D("0.01"),
    maker=D("0.005"),
    slippage=D("0.001"),
    st_tax_rate=D("0.30"),
    lt_tax_rate=D("0.15"),
    increments=Increments(base=D("0.01"), quote=D("0.01")),
)

# Center 100 with a 10% step: levels 90, 100, 110, so pair A is (90, 100) and
# pair B is (100, 110).  A pair's buy sits at its lower level: 1000 / 90 =
# 11.1111 floored to the 0.01 size step is 11.11.  Pair B's sell sits at its
# upper level with 1000 / 100 = 10 units.
P = {
    "center": D("100"),
    "step_pct": D("0.1"),
    "levels_below": 1,
    "levels_above": 1,
    "quote_per_buy": D("1000"),
}

START = datetime(2024, 1, 1, tzinfo=UTC)

# What every run reports it leaves out, in this order.
NOTES = [
    "$3,000 capital loss offset not modelled (conservative)",
    "wash-sale holding-period tacking not modelled (conservative)",
    "unused loss carryforward given zero value at liquidation",
]

FLAT_AT_100 = (100, 100, 100, 100)


def bars_from(rows):
    """Daily bars from 2024-01-01, one per (open, high, low, close) row."""
    return [
        Bar(
            symbol=XRP,
            interval="1d",
            ts=START + timedelta(days=offset),
            open=D(open_),
            high=D(high),
            low=D(low),
            close=D(close),
            volume=D("1"),
        )
        for offset, (open_, high, low, close) in enumerate(rows)
    ]


def always_armed(ctx):
    """A static grid: armed at every boundary, never re-centred."""
    return Gates(grid_armed=True)


def flag_kinds(result):
    return [flag.kind for flag in result.flags]


def test_touch_not_through_no_fill():
    bars = bars_from(
        [
            FLAT_AT_100,
            (100, 110, 90, 100),  # high == 110 and low == 90: touching only
            (100, "110.01", "89.99", 100),  # both traded through
        ]
    )

    touched = simulate_grid(bars[:2], [], always_armed, P, D("2000"), D("10"), G)
    # the bar reaches both limits and passes neither, so nothing fills
    assert touched.trades == []
    assert touched.final_cash == D("2000")
    assert touched.final_base == D("10")

    through = simulate_grid(bars, [], always_armed, P, D("2000"), D("10"), G)
    # both sides fill as maker at their own limit; equal end-of-bar equity
    # either way, so the tie keeps the BUYs-first processing order
    assert len(through.trades) == 2
    buy, sell = through.trades
    assert buy.ts == bars[2].ts
    assert buy.side == "BUY"
    assert buy.qty == D("11.11")  # floor(1000 / 90, 0.01)
    assert buy.price == D("90")  # the limit: a maker fill pays no slippage
    assert buy.fee == D("4.9995")  # 11.11 * 90 * 0.005
    assert buy.maker is True
    assert buy.kind == "limit"
    assert sell.ts == bars[2].ts
    assert sell.side == "SELL"
    assert sell.qty == D("10")  # 1000 / 100
    assert sell.price == D("110")
    assert sell.fee == D("5.5")  # 10 * 110 * 0.005
    assert sell.maker is True
    assert sell.kind == "limit"
    assert through.fees == D("10.4995")  # 4.9995 + 5.5
    # 2000 + 1100 - 5.5 - 999.9 - 4.9995
    assert through.final_cash == D("2089.6005")
    assert through.final_base == D("11.11")  # 10 - 10 + 11.11
    # the bought pair never got a bar to sell on
    assert through.round_trips == 0


def test_through_fills_at_limit_maker():
    bars = bars_from([FLAT_AT_100, (100, 101, 89, 95)])
    result = simulate_grid(bars, [], always_armed, P, D("2000"), D("10"), G)

    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == bars[1].ts
    assert trade.side == "BUY"
    assert trade.qty == D("11.11")  # floor(1000 / 90, 0.01)
    assert trade.price == D("90")  # exactly the limit, no slippage
    assert trade.maker is True
    assert trade.kind == "limit"
    assert trade.fee == D("4.9995")  # 11.11 * 90 * 0.005
    # the buy is the only fill: the sell at 110 was not reached (high 101)
    assert result.fees == D("4.9995")
    assert result.final_cash == D("995.1005")  # 2000 - 999.9 - 4.9995
    assert result.final_base == D("21.11")  # 10 + 11.11
    # pair A's buy filled but never sold, pair B's sell had no buy
    assert result.round_trips == 0


def test_both_sides_worse_ordering():
    bars = bars_from([FLAT_AT_100, (100, 115, 85, 100)])
    # 500 cash cannot pay for the 11.11 bought at 90 once fees are added
    result = simulate_grid(bars, [], always_armed, P, D("500"), D("10"), G)

    # BUYs first: 999.9 + 4.9995 = 1004.8995 > 500, so the buy is skipped and
    # the sell takes cash to 500 + 1100 - 5.5 = 1594.5 with base 0, marking
    # 1594.5 at the close; SELLs first: 1594.5 - 1004.8995 = 589.6005 in cash
    # with 11.11 base, marking 589.6005 + 1111 = 1700.6005.  The lower one wins.
    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == bars[1].ts
    assert trade.side == "SELL"
    assert trade.qty == D("10")
    assert trade.price == D("110")
    assert trade.fee == D("5.5")  # 10 * 110 * 0.005
    assert trade.maker is True
    assert trade.kind == "limit"
    assert result.final_cash == D("1594.5")  # 500 + 1100 - 5.5
    assert result.final_base == D("0")  # 10 - 10
    assert any(
        flag.kind == "insufficient_cash" and flag.ts == bars[1].ts
        for flag in result.flags
    )


def test_disarm_cancels():
    bars = bars_from(
        [
            FLAT_AT_100,
            (100, 101, 99, 100),  # calm: the resting orders are untouched
            (100, 120, 80, 100),  # wild, but the grid is off
            (100, 101, 99, 100),  # calm: armed again after this bar
            (100, 101, 89, 95),  # the rebuilt buy at 90 trades through
        ]
    )

    def gates(ctx):
        index = len(ctx.bars) - 1
        # off from bar 1's boundary, back on at bar 3's boundary
        if index in (1, 2):
            return Gates(grid_armed=False)
        return Gates(grid_armed=True)

    result = simulate_grid(bars, [], gates, P, D("2000"), D("10"), G)

    # the wild bar 2 traded through both levels with the grid off, so the one
    # fill is the rebuilt buy at bar 4
    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == bars[4].ts
    assert trade.side == "BUY"
    assert trade.qty == D("11.11")  # floor(1000 / 90, 0.01)
    assert trade.price == D("90")
    assert trade.maker is True
    assert trade.kind == "limit"
    assert trade.fee == D("4.9995")  # 11.11 * 90 * 0.005
    assert result.final_cash == D("995.1005")  # 2000 - 999.9 - 4.9995
    assert result.final_base == D("21.11")  # 10 + 11.11


def test_recenter_rebuilds():
    bars = bars_from(
        [
            FLAT_AT_100,
            (100, 101, 99, 100),  # re-centre on 200 after this bar
            (100, 201, 85, 100),  # the old buy at 90 would have filled here
        ]
    )

    def gates(ctx):
        if len(ctx.bars) - 1 == 1:
            return Gates(grid_armed=True, recenter_to=D("200"))
        return Gates(grid_armed=True)

    result = simulate_grid(bars, [], gates, P, D("2000"), D("10"), G)

    # center 200 at step 0.1: levels 180, 200, 220.  The reference is the close
    # of bar 1, 100, so both pairs are sell pairs: (180, 200) needs
    # floor(1000 / 180, 0.01) = 5.55 and (200, 220) needs 1000 / 200 = 5.00,
    # which does not fit in the 10 - 5.55 = 4.45 left, so that pair is idle.
    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == bars[2].ts
    assert trade.side == "SELL"
    assert trade.qty == D("5.55")
    assert trade.price == D("200")
    assert trade.maker is True
    assert trade.kind == "limit"
    assert trade.fee == D("5.55")  # 5.55 * 200 * 0.005
    assert result.final_cash == D("3104.45")  # 2000 + 1110 - 5.55
    assert result.final_base == D("4.45")  # 10 - 5.55
    assert "insufficient_base" in flag_kinds(result)
    # the sell's pair never had a buy filled
    assert result.round_trips == 0


def test_marketable_recenter_is_taker():
    bars = bars_from(
        [
            FLAT_AT_100,
            (100, 101, 99, 100),  # re-centre on 90 after this bar
            (85, 86, 83, 84),  # the fresh buy at 90 is already marketable
        ]
    )

    def gates(ctx):
        if len(ctx.bars) - 1 == 1:
            return Gates(grid_armed=True, recenter_to=D("90"))
        return Gates(grid_armed=True)

    result = simulate_grid(bars, [], gates, P, D("2000"), D("10"), G)

    # center 90 at step 0.1: levels 81, 90, 99.  Both pairs have their lower
    # level below the reference 100, so both want a buy: floor(1000 / 81, 0.01)
    # = 12.34 and floor(1000 / 90, 0.01) = 11.11.  Bar 2 opens at 85, so the
    # buy at 90 fills at min(85 * 1.001, 90) = 85.085 as a taker, and the buy
    # at 81 is untouched (low 83 > 81).
    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == bars[2].ts
    assert trade.side == "BUY"
    assert trade.qty == D("11.11")
    assert trade.price == D("85.085")  # 85 * (1 + 0.001)
    assert trade.maker is False
    assert trade.kind == "market"
    assert trade.fee == D("9.4529435")  # 11.11 * 85.085 * 0.01
    # 2000 - 11.11 * 85.085 - 9.4529435 = 2000 - 945.29435 - 9.4529435
    assert result.final_cash == D("1045.2527065")
    assert result.final_base == D("21.11")  # 10 + 11.11


# A round trip pays the maker fee on both legs, 0.005 * 1000 twice, so about
# 1000 * 2 * 0.005 = 10 of the quote spent per buy.  The band the mean has to
# fall in is -10 * 2.0 to -10 * 0.5, stated rather than fitted: the grid's gross
# gain per step is smaller than that fee, and the inventory a random walk leaves
# behind marks against the grid as well.
ROUND_TRIP_FEE = D("10")  # 2 * 0.005 * 1000
MEAN_PER_ROUND_TRIP_FLOOR = D("-20")  # -10 * 2.0
MEAN_PER_ROUND_TRIP_CEILING = D("-5")  # -10 * 0.5


def _random_walk(rng, bars=600, steps=30, step=0.0015, start=100.0):
    """OHLC rows from a seeded mean-zero multiplicative walk, in floats."""
    price = start
    rows = []
    for _ in range(bars):
        open_ = price
        high = low = price
        for _ in range(steps):
            price *= 1.0 + (step if rng.random() < 0.5 else -step)
            if price > high:
                high = price
            if price < low:
                low = price
        rows.append((open_, high, low, price))
    return rows


def _two_decimal(rows):
    """The float rows as two-decimal price strings for the Bar values."""
    return [
        (f"{open_:.2f}", f"{high:.2f}", f"{low:.2f}", f"{close:.2f}")
        for open_, high, low, close in rows
    ]


def test_static_grid_random_walk_negative_after_fees():
    costs = CostModel(
        XRP,
        taker=D("0.01"),
        maker=D("0.005"),
        slippage=D("0.001"),
        st_tax_rate=D("0"),
        lt_tax_rate=D("0"),
        increments=Increments(base=D("0.0001"), quote=D("0.01")),
    )
    params = {
        "center": D("100"),
        "step_pct": D("0.005"),
        "levels_below": 20,
        "levels_above": 20,
        "quote_per_buy": D("1000"),
    }
    start_cash = D("1000000")

    kept = []
    for seed in range(60):
        bars = bars_from(_two_decimal(_random_walk(random.Random(seed))))
        result = simulate_grid(
            bars, [], always_armed, params, start_cash, D("0"), costs
        )
        if result.round_trips >= 10:
            kept.append((result.final_equity - start_cash, result.round_trips))

    # a run that never completes ten round trips says nothing about the cost
    # per round trip, so it is left out of the mean
    assert len(kept) >= 10, f"only {len(kept)} of 60 runs qualified"

    mean = sum((pnl / round_trips for pnl, round_trips in kept), D("0")) / len(kept)
    assert MEAN_PER_ROUND_TRIP_FLOOR <= mean <= MEAN_PER_ROUND_TRIP_CEILING, (
        f"mean net {mean} per round trip is outside "
        f"[{MEAN_PER_ROUND_TRIP_FLOOR}, {MEAN_PER_ROUND_TRIP_CEILING}] "
        f"for a fee of {ROUND_TRIP_FEE} per round trip over {len(kept)} runs"
    )


def test_grid_params_validation():
    bars = bars_from([FLAT_AT_100])

    def run(params):
        return simulate_grid(bars, [], always_armed, params, D("2000"), D("10"), G)

    # the well-formed grid builds and has no bar left to fill on
    assert run(P).trades == []

    for key in ("center", "step_pct", "levels_below", "levels_above", "quote_per_buy"):
        params = dict(P)
        del params[key]
        with pytest.raises(ValueError):
            run(params)

    # a step of zero or less has no level above its pair's lower level
    for step in (D("0"), D("-0.1")):
        with pytest.raises(ValueError):
            run(dict(P, step_pct=step))

    with pytest.raises(ValueError):
        run(dict(P, levels_below=-1))
    with pytest.raises(ValueError):
        run(dict(P, levels_above=-1))
    with pytest.raises(ValueError):
        run(dict(P, quote_per_buy=D("0")))


def test_rearmed_rung_fills_at_its_limit_as_taker():
    # levels 99, 100 and 101: pair 0 buys at 99 with floor(1000/99, 0.01) = 10.10
    # and pair 1 buys at 100 with 1000/100 = 10.00; their sells sit at 100 and 101
    params = {
        "center": D("100"),
        "step_pct": D("0.01"),
        "levels_below": 1,
        "levels_above": 1,
        "quote_per_buy": D("1000"),
    }
    bars = bars_from(
        [
            (101, 101, 101, 101),  # close 101: both pairs want a buy
            (101, "101.5", "98.5", "101.5"),  # low 98.5 clears both buy limits
            ("101.45", "101.5", "101.4", "101.45"),  # both sells are marketable
        ]
    )

    result = simulate_grid(bars, [], always_armed, params, D("10000"), D("0"), G)

    maker_fills = sorted(
        [
            (trade.price, trade.qty, trade.fee, trade.maker)
            for trade in result.trades
            if trade.ts == bars[1].ts
        ]
    )
    assert maker_fills == [
        (D("99"), D("10.10"), D("4.9995"), True),  # 10.10 * 99 * 0.005
        (D("100"), D("10.00"), D("5.00"), True),  # 10.00 * 100 * 0.005
    ]

    taker_fills = sorted(
        [
            (trade.price, trade.qty, trade.fee, trade.maker)
            for trade in result.trades
            if trade.ts == bars[2].ts
        ]
    )
    # a rung re-armed at the previous boundary fills as a taker at its own limit,
    # not at the slipped open of 101.45 or 101.34855
    assert taker_fills == [
        (D("100"), D("10.10"), D("10.10"), False),  # 10.10 * 100 * 0.01
        (D("101"), D("10.00"), D("10.10"), False),  # 10.00 * 101 * 0.01
    ]
    assert len(result.trades) == 4
    # 10000 - 1000 - 5 - 999.90 - 4.9995 + 1010 - 10.10 + 1010 - 10.10
    assert result.final_cash == D("9989.9005")
    assert result.final_base == D("0")


def test_initial_orders_fill_first_open_taker():
    bars = bars_from([FLAT_AT_100, FLAT_AT_100, FLAT_AT_100])

    def gates(ctx):
        return Gates(grid_armed=False)

    result = simulate_grid(
        bars,
        [],
        gates,
        P,
        D("10000"),
        D("0"),
        G,
        initial_orders=[Order("BUY", qty=D("10"))],
    )

    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == bars[0].ts
    assert trade.side == "BUY"
    assert trade.qty == D("10")
    assert trade.price == D("100.1")  # 100 * (1 + 0.001)
    assert trade.fee == D("10.01")  # 10 * 100.1 * 0.01
    assert trade.maker is False
    # 10000 - 1001.0 - 10.01
    assert result.final_cash == D("8988.99")
    assert result.final_base == D("10")


def test_initial_orders_match_simulate():
    bars = bars_from([FLAT_AT_100, FLAT_AT_100, FLAT_AT_100])
    order = Order("BUY", qty=D("10"))

    alone = simulate(
        bars, [], lambda ctx: None, D("10000"), D("0"), G, initial_orders=[order]
    )
    gridded = simulate_grid(
        bars, [], always_armed, P, D("10000"), D("0"), G, initial_orders=[order]
    )

    # the flat bars leave every rung untouched, so only the opening fill differs
    assert len(gridded.trades) == 1
    assert gridded.trades == alone.trades
    assert gridded.curve == alone.curve


def test_veto_buys_until_refused():
    bars = bars_from([FLAT_AT_100, FLAT_AT_100])

    def gates(ctx):
        return Gates(grid_armed=True, veto_buys_until=START + timedelta(days=1))

    # a buy veto has no meaning for the grid simulator, so it refuses the run
    with pytest.raises(ValueError, match="veto_buys_until"):
        simulate_grid(bars, [], gates, P, D("2000"), D("10"), G)


def test_notes_and_no_wash_sale_on_a_crypto_pair():
    bars = bars_from([FLAT_AT_100, (100, 101, 89, 95)])
    result = simulate_grid(bars, [], always_armed, P, D("2000"), D("10"), G)

    assert result.notes == NOTES
    assert result.wash_sale_count == 0


def test_notes_and_wash_sale_count_on_a_stock_grid():
    nvda = "NVDA"
    # no fee and no slippage, so a fill is the price the ladder states
    stock = CostModel(
        nvda,
        taker=D("0"),
        maker=D("0"),
        slippage=D("0"),
        st_tax_rate=D("0.30"),
        lt_tax_rate=D("0.15"),
        increments=Increments(base=D("0.01"), quote=D("0.01")),
    )
    rows = [
        (200, 200, 100, 100),  # the starting 10 units cost 200 each at this open
        (100, 115, 99, 100),  # the sell at 110 fills: 10*110 - 10*200 = -900
        # low 95 stays above the 90 buy rung, so pair A buys nothing; pair B's
        # sell at 110 filled on bar 1, which re-armed its buy at 100, and that
        # buy is marketable at this bar's open of 100 (a taker fill, and the fee
        # is zero here): one replacement lot inside 30 days, one match
        (100, 101, 95, 100),
        (100, 101, 99, 100),
    ]
    bars = [
        Bar(
            symbol=nvda,
            interval="1d",
            ts=START + timedelta(days=offset),
            open=D(open_),
            high=D(high),
            low=D(low),
            close=D(close),
            volume=D("1"),
        )
        for offset, (open_, high, low, close) in enumerate(rows)
    ]

    result = simulate_grid(bars, [], always_armed, P, D("5000"), D("10"), stock)

    assert result.notes == NOTES
    assert len(result.realized) == 1
    assert result.realized[0].gain == D("0")  # -900 + 900 disallowed
    assert result.realized[0].disallowed == D("900")
    assert result.wash_sale_count == 1


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

    def rows_for(days):
        rows = [FLAT_AT_100, (100, 101, 85, 100)]  # one buy at 90 on bar 1
        # Padding flat at 100 would fill: the buy at 90 re-armed pair A's sell at
        # 100, and a flat open of 100 is marketable for it.  These bars open at
        # 95 and top out at 96, under the re-armed sell at 100 and under pair B's
        # sell at 110, and there is no buy rung left to reach on the low side, so
        # nothing fills and the one buy is the whole run's trade list.
        pad = [(95, 96, 94, 95)] * (days - len(rows))
        return bars_from(rows + pad)

    short = simulate_grid(rows_for(10), [], always_armed, P, D("2000"), D("10"), G)
    short_copies = counted["n"]
    counted["n"] = 0
    long = simulate_grid(rows_for(60), [], always_armed, P, D("2000"), D("10"), G)
    long_copies = counted["n"]

    # the same single buy in both runs, six times as many bars in the second
    assert [(t.side, t.qty) for t in short.trades] == [
        (t.side, t.qty) for t in long.trades
    ]
    assert len(long.trades) == 1
    assert short_copies == long_copies


# ---------------------------------------------------------------- step overrides

# 1% taker, 0.5% maker, no slippage, with a two-decimal product's size and price
# steps: a maker fill pays exactly its own limit, so only the fee moves the cash.
NO_SLIP = CostModel(
    XRP,
    taker=D("0.01"),
    maker=D("0.005"),
    slippage=D("0"),
    st_tax_rate=D("0.30"),
    lt_tax_rate=D("0.15"),
    increments=Increments(base=D("0.01"), quote=D("0.01")),
)

# Centre 100 at a 1% step with one level each side: levels 99, 100 and 101.  A
# pair's buy spends 980 of quote, so pair 0 buys floor(980 / 99, 0.01) = 9.89
# units at 99 on that ladder.
STEP_P = {
    "center": D("100"),
    "step_pct": D("0.01"),
    "levels_below": 1,
    "levels_above": 1,
    "quote_per_buy": D("980"),
}

# Two flat bars at 100, a dip whose low of 98.5 stops above 98, then a dip whose
# low of 97.5 trades through it.  The 1% ladder's buy at 99 and a 2% ladder's buy
# at 98 therefore fill on different bars.
STEP_BARS = [
    FLAT_AT_100,
    FLAT_AT_100,
    (100, 100, "98.5", 99),
    (99, 99, "97.5", 98),
]


def test_gates_step_pct_widens_ladder():
    def widened(ctx):
        if len(ctx.bars) - 1 == 1:
            return Gates(step_pct=D("0.02"))
        return Gates()

    bars = bars_from(STEP_BARS)
    result = simulate_grid(bars, [], widened, STEP_P, D("10000"), D("0"), NO_SLIP)

    # Bar 0's close of 100 builds the 1% ladder.  Bar 1 asks for a 2% step, which
    # rebuilds it on the same centre 100 from bar 1's close of 100: levels 98,
    # 100 and 102, so pair 0 is a BUY at 98 of floor(980 / 98, 0.01) = 10 units.
    # Bar 2's low of 98.5 stays above 98, so nothing fills there; bar 3's low of
    # 97.5 trades through 98 as a maker fill at exactly its limit.
    #   10 * 98 = 980 notional, fee 980 * 0.005 = 4.9
    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == bars[3].ts
    assert trade.side == "BUY"
    assert trade.qty == D("10")
    assert trade.price == D("98")
    assert trade.fee == D("4.9")
    assert trade.maker is True
    assert trade.kind == "limit"
    assert result.final_cash == D("9015.1")  # 10000 - 980 - 4.9
    assert result.final_base == D("10")

    # The same bars with no step override keep the 1% ladder, and bar 2's low of
    # 98.5 trades through its buy at 99.
    #   floor(980 / 99, 0.01) = 9.89 units, 9.89 * 99 = 979.11 notional,
    #   fee 979.11 * 0.005 = 4.89555
    def unchanged(ctx):
        return Gates()

    kept = simulate_grid(bars, [], unchanged, STEP_P, D("10000"), D("0"), NO_SLIP)

    assert len(kept.trades) == 1
    old = kept.trades[0]
    assert old.ts == bars[2].ts
    assert old.side == "BUY"
    assert old.qty == D("9.89")
    assert old.price == D("99")
    assert old.fee == D("4.89555")
    assert old.maker is True
    assert old.kind == "limit"
    assert kept.final_base == D("9.89")


def test_gates_step_pct_must_be_positive():
    bars = bars_from(STEP_BARS)

    for bad in (D("0"), D("-0.01")):
        def gates(ctx, step=bad):
            if len(ctx.bars) - 1 == 1:
                return Gates(step_pct=step)
            return Gates()

        with pytest.raises(ValueError, match="step_pct"):
            simulate_grid(bars, [], gates, STEP_P, D("10000"), D("0"), NO_SLIP)


def test_gates_step_pct_none_keeps_step():
    # The 2% step is asked for once, at bar 1, and every later boundary carries a
    # None step, which leaves the current step alone: the 98/100/102 ladder
    # stays put and bar 3's low of 97.5 is the run's only fill.
    def gates(ctx):
        if len(ctx.bars) - 1 == 1:
            return Gates(step_pct=D("0.02"))
        return Gates()

    bars = bars_from(STEP_BARS)
    result = simulate_grid(bars, [], gates, STEP_P, D("10000"), D("0"), NO_SLIP)

    assert len(result.trades) == 1
    trade = result.trades[0]
    assert trade.ts == bars[3].ts
    assert trade.side == "BUY"
    assert trade.qty == D("10")  # floor(980 / 98, 0.01)
    assert trade.price == D("98")
    assert trade.fee == D("4.9")  # 10 * 98 * 0.005
    assert trade.maker is True
    assert result.final_cash == D("9015.1")  # 10000 - 980 - 4.9
    assert result.final_base == D("10")
    # Two ladder builds (bar 0 and the widened one at bar 1) and no rebuild on
    # the None boundaries between them: each build's idle pair 1 sell is flagged
    # for want of a holding, and a third build would add a third flag.
    assert flag_kinds(result).count("insufficient_base") == 2