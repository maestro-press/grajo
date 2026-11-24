"""lab/metrics.py: curve statistics, the three benchmarks and the beats rule.

Every expected number is written out as a literal with the arithmetic that
produces it beside it.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal as D
from types import SimpleNamespace

import pytest

from crow_coinbase.lab.costs import CostModel
from crow_coinbase.lab.metrics import (
    after_tax_return,
    annualize,
    beats,
    buy_and_hold,
    fifty_fifty,
    lump_sum,
    max_drawdown,
    net_return,
    period_returns,
    scheduled,
    sharpe,
)
from crow_coinbase.lab.store import Bar

UTC = timezone.utc

XRP = "XRP-USDC"
NVDA = "NVDA"

# Crypto with a taker fee and slippage: a buy pays open * 1.001 and a 1% fee.
CRYPTO = CostModel(
    XRP,
    taker=D("0.01"),
    maker=D("0.005"),
    slippage=D("0.001"),
    st_tax_rate=D("0.30"),
    lt_tax_rate=D("0.15"),
)
# No taker fee and no slippage, so a fill price is the bar's open exactly.
ZERO_COST_STOCK = CostModel.for_stock(
    NVDA, st_tax_rate=D("0.30"), lt_tax_rate=D("0.15"), slippage=D("0")
)


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
    return daily_bars(symbol, [(ts, price, None) for ts in days])


def curve_of(equities, start_day=1):
    """An equity curve of consecutive daily UTC stamps from the given equities."""
    stamps = [utc(2024, 1, start_day + offset) for offset in range(len(equities))]
    return [(ts, D(value)) for ts, value in zip(stamps, equities)]


def test_known_curve_values():
    curve = curve_of(["100", "110", "99", "108.9"])

    # 108.9 / 100 - 1
    assert net_return(curve) == D("0.089")
    # peak 110, trough 99: (110 - 99) / 110
    assert max_drawdown(curve) == D("0.1")
    # 110/100 - 1 = 0.1, 99/110 - 1 = -0.1, 108.9/99 - 1 = 0.1
    assert period_returns(curve) == pytest.approx([0.1, -0.1, 0.1], abs=1e-12)

    returns = period_returns(curve)
    # mean 0.1/3 = 0.033333333, squared deviations 1/225 + 4/225 + 1/225 =
    # 0.026666667, sample variance 0.026666667/2 = 0.013333333, sd
    # 0.115470054; 0.033333333 / 0.115470054 = 0.288675135
    assert sharpe(returns) == pytest.approx(0.28867513459, abs=1e-9)
    # 0.288675135 * sqrt(4) = 0.288675135 * 2 = 0.577350269
    assert annualize(sharpe(returns), 4) == pytest.approx(0.57735026919, abs=1e-9)

    # a single point carries no change
    assert net_return([(utc(2024, 1, 1), D("100"))]) is None
    # 100 then 110 never falls below its running peak
    assert max_drawdown(curve_of(["100", "110"])) == D("0")

    for reader in (net_return, max_drawdown, period_returns):
        with pytest.raises(ValueError):
            reader([])


def test_sharpe_zero_variance_none():
    # deviations from the 0.01 mean are all 0, so the sample variance is 0
    assert sharpe([0.01, 0.01, 0.01]) is None
    # one point has no sample standard deviation
    assert sharpe([0.01]) is None
    assert sharpe([]) is None

    assert annualize(None, 252) is None
    with pytest.raises(ValueError):
        annualize(1.0, 0)


def test_benchmarks_same_start_position_costs_taxes():
    days = [utc(2024, 1, day) for day in (1, 2, 3, 4, 5)]
    bars = daily_bars(
        XRP,
        [
            (days[0], "100", "100"),
            (days[1], "100", "100"),
            (days[2], "100", "100"),
            (days[3], "100", "100"),
            (days[4], "100", "200"),
        ],
    )
    cash = D("1011.01")
    events = []

    lump = lump_sum(bars, events, cash, CRYPTO)
    hold = buy_and_hold(bars, events, cash, CRYPTO)
    drip = scheduled(bars, events, cash, CRYPTO, tranches=2, spacing_bars=2)
    balanced = fifty_fifty(bars, events, cash, CRYPTO)

    # fill price 100 * (1 + 0.001) = 100.1; qty 1011.01 / (100.1 * 1.01) =
    # 1011.01 / 101.101 = 10; fee 10 * 100.1 * 0.01 = 1001 * 0.01 = 10.01
    for result in (lump, hold):
        assert len(result.trades) == 1
        trade = result.trades[0]
        assert trade.ts == bars[0].ts
        assert trade.side == "BUY"
        assert trade.qty == D("10")
        assert trade.price == D("100.1")
        assert trade.fee == D("10.01")
        assert trade.maker is False
        assert result.final_cash == D("0")  # 1011.01 - 1001 - 10.01
        assert result.final_base == D("10")
        assert result.final_equity == D("2000")  # 10 * 200
        # basis 1001 + 10.01 = 1011.01; gain 2000 - 1011.01 = 988.99;
        # short-term tax 988.99 * 0.30 = 296.697; 2000 - 296.697 = 1703.303
        assert result.final_equity_after_liquidation_tax == D("1703.303")

    # tranche notional 1011.01 / 2 = 505.505; qty 505.505 / 101.101 = 5;
    # fee 5 * 100.1 * 0.01 = 500.5 * 0.01 = 5.005; tranche 1 is ordered at
    # bar index 1*2 - 1 = 1 and fills at bar 2's open
    assert len(drip.trades) == 2
    first = drip.trades[0]
    assert first.ts == bars[0].ts
    assert first.side == "BUY"
    assert first.qty == D("5")
    assert first.price == D("100.1")
    assert first.fee == D("5.005")
    assert first.maker is False
    assert drip.trades[1].ts == bars[2].ts
    assert drip.trades[1].side == "BUY"
    assert drip.trades[1].qty == D("5")

    # half the cash: 505.505 / 101.101 = 5, fee 500.5 * 0.01 = 5.005; the
    # weight 500 / 1005.505 = 0.4973 stays inside the 7.5 point band
    assert len(balanced.trades) == 1
    opening = balanced.trades[0]
    assert opening.ts == bars[0].ts
    assert opening.side == "BUY"
    assert opening.qty == D("5")
    assert opening.price == D("100.1")
    assert opening.fee == D("5.005")
    assert opening.maker is False

    # each book holds an unrealized gain at the last close, so the tax on
    # closing it leaves less than the marked equity
    for result in (lump, balanced):
        assert result.final_equity_after_liquidation_tax < result.final_equity


def test_buy_and_hold_equals_lump_sum():
    days = [utc(2024, 1, day) for day in (1, 2, 3)]
    bars = daily_bars(
        NVDA,
        [(days[0], "50", "50"), (days[1], "60", "55"), (days[2], "55", "70")],
    )

    lump = lump_sum(bars, [], D("2500"), ZERO_COST_STOCK)
    hold = buy_and_hold(bars, [], D("2500"), ZERO_COST_STOCK)

    # 2500 / 50 = 50 units bought at the first open, then held
    assert lump.trades[0].qty == D("50")
    assert hold.trades == lump.trades
    assert hold.curve == lump.curve
    assert hold.final_cash == lump.final_cash
    assert hold.final_base == lump.final_base
    assert hold.final_equity == lump.final_equity


def test_fifty_fifty_trades_back_to_half():
    days = [utc(2024, 1, day) for day in (1, 2, 3, 4)]
    bars = daily_bars(
        NVDA,
        [
            (days[0], "100", "100"),
            (days[1], "100", "160"),
            (days[2], "160", "160"),
            (days[3], "160", "160"),
        ],
    )

    result = fifty_fifty(bars, [], D("1000"), ZERO_COST_STOCK)

    # 500 / 100 = 5 units bought at bar 0's open, 500 left in cash
    # bar 1 close 160: base 5*160 = 800, equity 500 + 800 = 1300, weight
    # 800/1300 = 0.615 > 0.575; target 1300/2 = 650, diff 650 - 800 = -150,
    # sell 150/160 = 0.9375 filled at bar 2's open 160
    assert len(result.trades) == 2
    opening = result.trades[0]
    assert opening.ts == bars[0].ts
    assert opening.side == "BUY"
    assert opening.qty == D("5")

    sale = result.trades[1]
    assert sale.ts == bars[2].ts
    assert sale.side == "SELL"
    assert sale.qty == D("0.9375")
    assert sale.price == D("160")

    assert result.final_cash == D("650")  # 500 + 0.9375*160 = 500 + 150
    assert result.final_base == D("4.0625")  # 5 - 0.9375
    assert result.final_equity == D("1300")  # 650 + 4.0625*160

    # at bar 1 close 110: base 5*110 = 550, cash 500, equity 1050, weight
    # 550/1050 = 0.5238, inside the band, so only the opening buy happens
    inside = daily_bars(
        NVDA,
        [
            (days[0], "100", "100"),
            (days[1], "100", "110"),
            (days[2], "110", "110"),
            (days[3], "110", "110"),
        ],
    )
    quiet = fifty_fifty(inside, [], D("1000"), ZERO_COST_STOCK)
    assert len(quiet.trades) == 1
    assert quiet.trades[0].side == "BUY"

    # the band is a percentage of equity strictly between 0 and 50 points
    with pytest.raises(ValueError):
        fifty_fifty(bars, [], D("1000"), ZERO_COST_STOCK, band_pts=D("0"))
    with pytest.raises(ValueError):
        fifty_fifty(bars, [], D("1000"), ZERO_COST_STOCK, band_pts=D("50"))


def test_scheduled_validation():
    days = [utc(2024, 1, 1) + timedelta(days=offset) for offset in range(5)]
    bars = flat(NVDA, days, "100")

    with pytest.raises(ValueError):
        scheduled(bars, [], D("900"), ZERO_COST_STOCK, tranches=0, spacing_bars=2)
    with pytest.raises(ValueError):
        scheduled(bars, [], D("900"), ZERO_COST_STOCK, tranches=2, spacing_bars=0)

    # tranche k is ordered at bar index k*10 - 1, so over five bars only
    # tranche 0 (the initial order, at bar 0's open) is ever filled
    result = scheduled(
        bars, [], D("900"), ZERO_COST_STOCK, tranches=3, spacing_bars=10
    )
    assert len(result.trades) == 1
    assert result.trades[0].ts == bars[0].ts
    assert result.trades[0].side == "BUY"
    # 900 / 3 = 300 spent at the open price 100, so 300 / 100 = 3 units
    assert result.trades[0].qty == D("3")
    assert result.trades[0].price == D("100")
    assert result.trades[0].fee == D("0")


def test_beats_requires_both():
    start = D("100")
    # peak 120, trough 96: drawdown (120 - 96) / 120 = 0.2; after-tax return
    # 110/100 - 1 = 0.10
    benchmark = SimpleNamespace(
        curve=curve_of(["100", "120", "96"]),
        final_equity_after_liquidation_tax=D("110"),
    )

    # (a) return 120/100 - 1 = 0.20 but drawdown (130 - 91)/130 = 0.3 > 0.2
    deep = SimpleNamespace(
        curve=curve_of(["100", "130", "91"]),
        final_equity_after_liquidation_tax=D("120"),
    )
    assert beats(deep, [benchmark], start) is False

    # (b) drawdown (105 - 100)/105 = 0.0476 <= 0.2 but return 105/100 - 1 =
    # 0.05 < 0.10
    shallow = SimpleNamespace(
        curve=curve_of(["100", "105", "100"]),
        final_equity_after_liquidation_tax=D("105"),
    )
    assert beats(shallow, [benchmark], start) is False

    # (c) return 0.20 and drawdown (110 - 99)/110 = 0.1 <= 0.2
    both = SimpleNamespace(
        curve=curve_of(["100", "110", "99"]),
        final_equity_after_liquidation_tax=D("120"),
    )
    assert beats(both, [benchmark], start) is True

    # (d) the same 0.10 return, with the shallow 0.0476 drawdown, does not beat
    level = SimpleNamespace(
        curve=curve_of(["100", "105", "100"]),
        final_equity_after_liquidation_tax=D("110"),
    )
    assert beats(level, [benchmark], start) is False

    # (e) drawdown (125 - 100)/125 = 0.2, equal to the benchmark's 0.2
    matched = SimpleNamespace(
        curve=curve_of(["100", "125", "100"]),
        final_equity_after_liquidation_tax=D("120"),
    )
    assert beats(matched, [benchmark], start) is True

    # (f) a second benchmark returns 130/100 - 1 = 0.30, more than 0.20
    stronger = SimpleNamespace(
        curve=curve_of(["100", "140", "120"]),
        final_equity_after_liquidation_tax=D("130"),
    )
    assert beats(both, [benchmark, stronger], start) is False

    with pytest.raises(ValueError):
        beats(both, [], start)


def test_after_tax_return():
    result = SimpleNamespace(final_equity_after_liquidation_tax=D("1703.303"))

    # 1703.303 / 1011.01 - 1
    assert after_tax_return(result, D("1011.01")) == (
        D("1703.303") / D("1011.01") - D("1")
    )

    with pytest.raises(ValueError):
        after_tax_return(result, D("0"))


# ---------------------------------------------------------------- contributions


def test_period_returns_with_contributions():
    t0, t1, t2 = utc(2024, 1, 1), utc(2024, 1, 2), utc(2024, 1, 3)
    curve = [(t0, D("50")), (t1, D("55")), (t2, D("105"))]

    # the $50 that lands at t2 is new money, not a return: 55 / 50 - 1 = 0.1
    # and (105 - 50) / 55 - 1 = 0
    assert period_returns(curve, [(t2, D("50"))]) == pytest.approx(
        [0.1, 0.0], abs=1e-12
    )

    # a contribution at the first point only lifts the starting equity, so the
    # single step is still 55 / 50 - 1 = 0.1
    assert period_returns(curve[:2], [(t0, D("50"))]) == pytest.approx(
        [0.1], abs=1e-12
    )

    # no contributions read exactly as before: 55 / 50 - 1 = 0.1 and
    # 105 / 55 - 1 = 0.909090909...
    assert period_returns(curve, None) == pytest.approx(
        [0.1, 0.9090909090909091], abs=1e-12
    )
    assert period_returns(curve, []) == pytest.approx(
        [0.1, 0.9090909090909091], abs=1e-12
    )


def test_after_tax_return_counts_contributions():
    funded = SimpleNamespace(
        final_equity_after_liquidation_tax=D("150"),
        total_contributed=D("100"),
    )

    # 150 / (100 + 100) - 1 = -0.25: the $100 contributed is part of the base
    assert after_tax_return(funded, D("100")) == D("-0.25")

    # a result with no total_contributed is unfunded: 150 / 100 - 1 = 0.5
    unfunded = SimpleNamespace(final_equity_after_liquidation_tax=D("150"))
    assert after_tax_return(unfunded, D("100")) == D("0.5")


def test_after_tax_return_from_no_start_cash():
    # A funded run may start from no cash at all: the money put in is the base.
    funded = SimpleNamespace(
        final_equity_after_liquidation_tax=D("150"),
        total_contributed=D("100"),
    )

    # 150 / (0 + 100) - 1 = 0.5
    assert after_tax_return(funded, D("0")) == D("0.5")

    # nothing started and nothing contributed: no base to measure against
    empty = SimpleNamespace(
        final_equity_after_liquidation_tax=D("150"),
        total_contributed=D("0"),
    )
    with pytest.raises(ValueError):
        after_tax_return(empty, D("0"))

    # a negative start is refused whatever was contributed
    with pytest.raises(ValueError):
        after_tax_return(funded, D("-1"))


# ---------------------------------------------------------------- funded runs

# The funding schedule of a rule that buys a fixed amount every week.
FUNDED_WEEK = {"amount": D("50"), "every": "week"}

# Ten weekday bars: Monday 26 February to Friday 1 March 2024, then Monday
# 4 March to Friday 8 March 2024, so two week starts land inside them.
FUNDED_WEEKDAYS = [
    utc(2024, 2, 26) + timedelta(days=offset) for offset in range(5)
] + [utc(2024, 3, 4) + timedelta(days=offset) for offset in range(5)]

PRICE_FALL_STAMPS = [
    utc(2024, 2, 26) + timedelta(days=offset) for offset in range(8)
]


def price_fall_curve():
    """The marks and the contributions of a funded run whose price halved.

    Week one starts Monday 26 February 2024: the $50 lands on that bar and is
    ordered there, and it buys 0.5 units at Tuesday's 100 open, so the price
    staying at 100 through Friday marks 0.5 * 100 = 50 at each close.

    Monday 4 March the second $50 lands beside the same 0.5 units while the
    price has halved to 50, so that close marks 50 + 0.5 * 50 = 75; the buy the
    $50 orders fills at Tuesday's 50 and leaves the mark at 75.

    The recorded marks therefore run 50, 50, 50, 50, 50, 75, 75, 75 while the
    investment itself lost half its price.  The two $50 contributions are
    stamped at the two Mondays.
    """
    curve = [
        (PRICE_FALL_STAMPS[0], D("50")),
        (PRICE_FALL_STAMPS[1], D("50")),
        (PRICE_FALL_STAMPS[2], D("50")),
        (PRICE_FALL_STAMPS[3], D("50")),
        (PRICE_FALL_STAMPS[4], D("50")),
        (PRICE_FALL_STAMPS[5], D("75")),
        (PRICE_FALL_STAMPS[6], D("75")),
        (PRICE_FALL_STAMPS[7], D("75")),
    ]
    contributions = [
        (PRICE_FALL_STAMPS[0], D("50")),
        (PRICE_FALL_STAMPS[5], D("50")),
    ]
    return curve, contributions


def test_max_drawdown_with_deposits_shows_the_price_fall():
    curve, contributions = price_fall_curve()

    # the raw marks never fall below their running peak of 50, so read alone the
    # curve carries no drawdown at all
    assert max_drawdown(curve) == D("0")

    # read net of the money put in, the step from 50 to 75 is
    # (75 - 50) / 50 = 0.5 of the equity gone: the index goes 1 -> 0.5 and the
    # drawdown is the half of its price the investment lost
    assert max_drawdown(curve, contributions) == D("0.5")


def test_max_drawdown_reads_the_old_way_without_contributions():
    # 100 -> 120 -> 96: the fall is (120 - 96) / 120 = 0.2
    falling = curve_of(["100", "120", "96"])
    assert max_drawdown(falling) == D("0.2")
    assert max_drawdown(falling, None) == D("0.2")
    assert max_drawdown(falling, []) == D("0.2")


def test_beats_reads_the_drawdown_net_of_contributions():
    curve, contributions = price_fall_curve()

    # 150 / (0 + 100) - 1 = 0.5 of the money put in, and a raw drawdown of 0
    rule = SimpleNamespace(
        curve=curve,
        contributions=contributions,
        total_contributed=D("100"),
        final_equity_after_liquidation_tax=D("150"),
    )
    # 140 / (0 + 100) - 1 = 0.4, with a drawdown of (120 - 100) / 120 = 0.166...
    benchmark = SimpleNamespace(
        curve=curve_of(["100", "120", "100"]),
        contributions=None,
        total_contributed=D("100"),
        final_equity_after_liquidation_tax=D("140"),
    )

    # The rule earns more, 0.5 against 0.4, and its raw marks rise, so a
    # drawdown read off the marks alone would let it through; read net of the
    # contributions it falls 0.5 from its peak, deeper than the benchmark's
    # 0.166..., so it does not beat it.
    assert beats(rule, [benchmark], D("0")) is False


def test_funded_buy_and_hold_buys_every_contribution():
    bars = flat(NVDA, FUNDED_WEEKDAYS, "100")

    result = buy_and_hold(
        bars, [], D("0"), ZERO_COST_STOCK, contribution=FUNDED_WEEK
    )

    # Two deposits of 50, on Monday 26 February and Monday 4 March: 2 * 50 = 100.
    assert [amount for _, amount in result.contributions] == [D("50"), D("50")]
    assert [ts for ts, _ in result.contributions] == [
        FUNDED_WEEKDAYS[0],
        FUNDED_WEEKDAYS[5],
    ]
    assert result.total_contributed == D("100")

    # each deposit is ordered at its own Monday bar and fills at the next open:
    # 50 / 100 = 0.5 units on Tuesday 27 February and 0.5 on Tuesday 5 March
    assert [trade.ts for trade in result.trades] == [
        FUNDED_WEEKDAYS[1],
        FUNDED_WEEKDAYS[6],
    ]
    assert [trade.qty for trade in result.trades] == [D("0.5"), D("0.5")]
    assert result.final_base == D("1")
    assert result.final_cash == D("0")
    assert result.final_equity == D("100")


def test_funded_fifty_fifty_trades_back_to_half_after_a_contribution():
    bars = flat(NVDA, FUNDED_WEEKDAYS, "100")

    result = fifty_fifty(
        bars, [], D("0"), ZERO_COST_STOCK, contribution=FUNDED_WEEK
    )

    # Monday 26 February: the deposit leaves equity at 50 and the weight at 0,
    # so the order is 50 / 2 = 25 and it fills at Tuesday's 100 open for 0.25
    # units with 25 left in cash, a weight of 0.5 that the rest of the week
    # leaves alone.
    # Monday 4 March: cash 25 + 50 = 75 and 0.25 units mark 75 + 25 = 100, a
    # weight of 0.25, so the order is 100 / 2 - 25 = 25 and it fills at
    # Tuesday's open for 0.25 units with 50 left in cash.
    assert result.total_contributed == D("100")
    assert [trade.ts for trade in result.trades] == [
        FUNDED_WEEKDAYS[1],
        FUNDED_WEEKDAYS[6],
    ]
    assert [trade.qty for trade in result.trades] == [D("0.25"), D("0.25")]
    assert result.final_base == D("0.5")
    assert result.final_cash == D("50")
    assert result.final_equity == D("100")