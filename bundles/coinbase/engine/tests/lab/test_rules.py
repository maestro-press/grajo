"""lab/rules: the band, regime, grid-gate and event-veto rule modules.

Every expected money value is a literal with the arithmetic that produces it in
a comment beside it.  The two statistical series are seeded, and the grid-gate
decision test searches for the indices it uses instead of hard-coding them.
"""

import math
import random
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal as D
from types import SimpleNamespace

import pytest

from crow_coinbase.lab.costs import BUY, SELL, CostModel, Lots, Order
from crow_coinbase.lab.rules import band, event_veto, grid_gate, regime
from crow_coinbase.lab.rules.base import (
    base_weight,
    check_rule_module,
    closes,
    orders_to_weight,
    require_asset,
)
from crow_coinbase.lab.sim import Gates, LabContext, PastBars, simulate
from crow_coinbase.lab.store import Bar, Event

UTC = timezone.utc


def utc(year, month, day, hour=0):
    """A timezone-aware UTC datetime at that clock reading."""
    return datetime(year, month, day, hour, tzinfo=UTC)


def make_bars(symbol, rows):
    """Daily bars from (ts, open, high, low, close) rows, one unit of volume."""
    out = []
    for ts, open_, high, low, close in rows:
        out.append(
            Bar(
                symbol=symbol,
                interval="1d",
                ts=ts,
                open=D(str(open_)),
                high=D(str(high)),
                low=D(str(low)),
                close=D(str(close)),
                volume=D("1"),
            )
        )
    return out


def ctx(rows, n=None, cash=D("1000"), base=D("0"), events=(), asset_class="crypto"):
    """The context a rule sees at the last bar of the first n rows."""
    count = n or len(rows)
    return LabContext(
        bars=PastBars(rows, count),
        events=list(events),
        cash=cash,
        base=base,
        lots=Lots(asset_class),
        now=rows[count - 1].ts,
    )


# ---------------------------------------------------------------- base helpers


def test_base_helpers():
    rows = make_bars(
        "XRP-USDC",
        [
            (utc(2024, 1, day), 10 * day, 10 * day, 10 * day, 10 * day)
            for day in range(1, 6)
        ],
    )
    view = ctx(rows)
    assert closes(view.bars, 3) == [D("30"), D("40"), D("50")]

    flat = make_bars("XRP-USDC", [(utc(2024, 1, 1), 100, 101, 99, 100)])
    held = ctx(flat, cash=D("500"), base=D("5"))
    # 5 * 100 / (500 + 5 * 100) = 500 / 1000 = 0.5
    assert base_weight(held) == D("0.5")

    empty = LabContext(
        bars=PastBars([], 0),
        events=[],
        cash=D("1000"),
        base=D("0"),
        lots=Lots("crypto"),
        now=utc(2024, 1, 1),
    )
    assert base_weight(empty) is None

    # equity 1000, so 0.6 * 1000 - 500 = 100 goes into a buy
    assert orders_to_weight(held, D("0.6")) == (Order(BUY, notional=D("100")),)
    # 0.4 * 1000 - 500 = -100, sold at 100 a unit: 100 / 100 = 1
    assert orders_to_weight(held, D("0.4")) == (Order(SELL, qty=D("1")),)
    assert orders_to_weight(held, D("0.5")) == ()


# ---------------------------------------------------------------- band


def test_band_trades_to_edge():
    flat = make_bars("XRP-USDC", [(utc(2024, 1, 1), 100, 101, 99, 100)])
    decide = band.make({"band_pts": 7.5})

    # 350 + 6.5 * 100 = 1000; w = 650 / 1000 = 0.65 is above the 0.5 + 0.075
    # edge; the sale takes it back to 0.575: 650 - 575 = 75 at 100 a unit
    assert decide(ctx(flat, cash=D("350"), base=D("6.5"))) == (
        Order(SELL, qty=D("0.75")),
    )

    # 650 + 3.5 * 100 = 1000; w = 350 / 1000 = 0.35 is below the 0.5 - 0.075
    # edge; the buy takes it back to 0.425: 425 - 350 = 75
    assert decide(ctx(flat, cash=D("650"), base=D("3.5"))) == (
        Order(BUY, notional=D("75")),
    )

    # 425 + 5.75 * 100 = 1000, so w = 575 / 1000 = 0.575 is the edge itself
    assert decide(ctx(flat, cash=D("425"), base=D("5.75"))) is None
    # w = 500 / 1000 = 0.5 sits inside the band
    assert decide(ctx(flat, cash=D("500"), base=D("5"))) is None

    # the 4-point config's edge is 0.54: 400 + 600 = 1000, w = 0.6,
    # and 600 - 540 = 60 sold at 100 a unit
    narrow = band.make({"band_pts": 4})
    assert narrow(ctx(flat, cash=D("400"), base=D("6"))) == (
        Order(SELL, qty=D("0.6")),
    )


def test_band_past_only():
    shared = [
        (utc(2024, 1, 1 + i), 100 + i, 101 + i, 99 + i, 100 + i)
        for i in range(5)
    ]
    later = [
        (utc(2024, 1, 6 + i), 105 + i, 106 + i, 104 + i, 105 + i)
        for i in range(3)
    ]
    wild = [
        (utc(2024, 1, 6 + i), 10 * (105 + i), 10 * (106 + i),
         10 * (104 + i), 10 * (105 + i))
        for i in range(3)
    ]
    calm = band.make({"band_pts": 5})(ctx(make_bars("XRP-USDC", shared + later), 5))
    other = band.make({"band_pts": 5})(
        ctx(make_bars("XRP-USDC", shared + wild), 5)
    )
    assert calm == other
    # 0.45 * 1000 - 0 = 450 bought back to the lower edge
    assert calm == (Order(BUY, notional=D("450")),)


# ---------------------------------------------------------------- regime


def test_regime_past_only():
    params = {"n": 10, "step_pct": 0.02, "levels": 3, "quote_per_buy": 250}
    start = utc(2024, 1, 1)
    shared = [
        (start + timedelta(days=i), 100 + i, 101 + i, 99 + i, 100 + i)
        for i in range(30)
    ]
    later = [
        (start + timedelta(days=30 + i), 130 + i, 131 + i, 129 + i, 130 + i)
        for i in range(5)
    ]
    wild = [
        (start + timedelta(days=30 + i), 10 * (130 + i), 10 * (131 + i),
         10 * (129 + i), 10 * (130 + i))
        for i in range(5)
    ]
    calm = regime.make(params)(ctx(make_bars("XRP-USDC", shared + later), 30))
    other = regime.make(params)(ctx(make_bars("XRP-USDC", shared + wild), 30))
    assert calm == other
    assert calm == Gates(grid_armed=True)


def test_regime_disarms_in_synthetic_trend():
    params = {"n": 5, "step_pct": 0.02, "levels": 3, "quote_per_buy": 250}
    start = utc(2024, 1, 1)

    rising = []
    for i in range(10):
        price = D(100 + i)
        rising.append(
            (start + timedelta(days=i), price, price + D("0.5"),
             price - D("0.5"), price)
        )
    trend = make_bars("XRP-USDC", rising)
    # the channel over bars 4..8 tops out at 108.5 and the last close is 109
    assert regime.regime_state(trend, 5) == "up"
    assert regime.make(params)(ctx(trend)) == Gates(grid_armed=False)

    flat_bars = make_bars(
        "XRP-USDC",
        [
            (start + timedelta(days=i), D("100"), D("100.5"), D("99.5"), D("100"))
            for i in range(20)
        ],
    )
    flat_gates = regime.make(params)(ctx(flat_bars))
    assert flat_gates == Gates(grid_armed=True)
    assert flat_gates.recenter_to is None

    flip = make_bars(
        "XRP-USDC",
        [
            (start + timedelta(days=i), D(100 + i), D(100 + i) + D("0.5"),
             D(100 + i) - D("0.5"), D(100 + i))
            for i in range(6)
        ]
        + [(start + timedelta(days=6), D("104"), D("104.5"), D("103.5"),
            D("104"))],
    )
    # bars 1..5 carry highs 101.5..105.5 with lows 100.5..104.5, so the 104
    # close sits inside; one bar earlier the 105 close clears the 104.5 high
    assert regime.regime_state(flip, 5) == "range"
    assert regime.regime_state(flip[:-1], 5) == "up"
    assert regime.make(params)(ctx(flip)) == Gates(
        grid_armed=True, recenter_to=D("104")
    )


def test_regime_initial_grid():
    params = {"n": 10, "step_pct": 0.02, "levels": 3, "quote_per_buy": 250}
    start = utc(2024, 1, 1)
    rows = make_bars(
        "XRP-USDC",
        [
            (start + timedelta(days=i), D(100 + i), D(101 + i), D(99 + i),
             D(100 + i))
            for i in range(3)
        ],
    )
    grid = regime.initial_grid(params, PastBars(rows, 3))
    assert grid == {
        "center": D("102"),
        "step_pct": D("0.02"),
        "levels_below": 3,
        "levels_above": 3,
        "quote_per_buy": D("250"),
    }


# ---------------------------------------------------------------- grid gate


def test_variance_ratio_hand_values():
    # N = 4 and mu = 0.  Every two-step change is 0, so vr = 0; the one-step
    # changes are 1, -1, 1, -1, so delta(1) = 3 / 4**2 = 3/16 and
    # z = -1 / sqrt(3/16)
    vr, z = grid_gate.variance_ratio([0.0, 1.0, 0.0, 1.0, 0.0], 2)
    assert vr == 0.0
    assert z == pytest.approx(-2.3094010767585, rel=1e-12)

    # N = 6: delta(1) = 5 / 6**2 = 5/36 and z = -1 / sqrt(5/36)
    vr, z = grid_gate.variance_ratio([0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0], 2)
    assert vr == 0.0
    assert z == pytest.approx(-2.6832815729997, rel=1e-12)

    # a straight line leaves no spread in its one-step changes
    assert grid_gate.variance_ratio([0.0, 1.0, 2.0, 3.0, 4.0], 2) is None
    # q below 2 has no theta sum
    assert grid_gate.variance_ratio([0.0, 1.0, 0.0, 1.0, 0.0], 1) is None
    # N = 2 is not greater than q = 2
    assert grid_gate.variance_ratio([0.0, 1.0, 2.0], 2) is None


def test_variance_ratio_q3_hand_values():
    # N = 9 one-bar changes 1, 2, -1, 2, -1, 3, -1, 2, -1, so mu = 6/9 = 2/3 and
    # sum (dX - mu)**2 = 22, which makes the one-bar spread 22/8 = 11/4.
    # m = 3 * (9 - 3 + 1) * (1 - 3/9) = 3 * 7 * 2/3 = 14.  The three-step terms
    # X[k] - X[k-3] - 3*mu = X[k] - X[k-3] - 2 for k = 3..9 are
    # 0, 1, -2, 2, -1, 2, -2, squares summing to 18, so the three-bar spread is
    # 18/14 = 9/7 and vr = (9/7) / (11/4) = 36/77.
    # The lag weights are (2*(q - j)/q)**2 = (4/3)**2 for j = 1 and (2/3)**2 for
    # j = 2, over the lagged products of the squared changes divided by 22**2:
    # (16/9)*(4466/81) and (4/9)*(3724/81), so
    # theta = (21588/88209) = 7196/29403 = 0.2447369316 and
    # z = (36/77 - 1) / sqrt(7196/29403) = -1.0763248720.
    vr, z = grid_gate.variance_ratio(
        [0.0, 1.0, 3.0, 2.0, 4.0, 3.0, 6.0, 5.0, 7.0, 6.0], 3
    )
    assert vr == pytest.approx(36 / 77, rel=1e-12)
    assert z == pytest.approx(-1.0763248719615577, rel=1e-12)

    # The second series carries changes 2, -1, 2, -2, 3, -2, 3, -2 with
    # mu = 3/8: sum (dX - mu)**2 = 2424/64 = 303/8, so the one-bar spread is
    # 303/56; m = 3 * (8 - 3 + 1) * (1 - 3/8) = 90/8, and the three-step terms
    # X[k] - X[k-3] - 9/8 for k = 3..8 are 15/8, -17/8, 15/8, -17/8, 23/8,
    # -17/8, squares summing to 1846/64, so the three-bar spread is
    # (1846/64) / (90/8) = 923/360 and vr = (923/360) / (303/56) = 6461/13635.
    # The same weights over this series' products give
    # theta = 82079/367236 + 601894/13220496 = 0.2690321 and
    # z = (6461/13635 - 1) / sqrt(0.2690321) = -1.0143881499.
    vr, z = grid_gate.variance_ratio(
        [0.0, 2.0, 1.0, 3.0, 1.0, 4.0, 2.0, 5.0, 3.0], 3
    )
    assert vr == pytest.approx(6461 / 13635, rel=1e-12)
    assert z == pytest.approx(-1.0143881499382092, rel=1e-12)


def test_grid_gate_past_only():
    params = {
        "q": 2,
        "k": 1.0,
        "lookback": 60,
        "floor_pct": 0.015,
        "levels": 3,
        "quote_per_buy": 250,
    }
    start = utc(2024, 1, 1)
    shared = []
    for i in range(80):
        close = 100 + (i % 2) * 2
        shared.append((start + timedelta(days=i), close, 103, 99, close))
    later = [
        (start + timedelta(days=80 + i), 120 + i, 121 + i, 119 + i, 120 + i)
        for i in range(10)
    ]
    wild = [
        (start + timedelta(days=80 + i), 10 * (120 + i), 10 * (121 + i),
         10 * (119 + i), 10 * (120 + i))
        for i in range(10)
    ]
    calm = grid_gate.make(params)(ctx(make_bars("XRP-USDC", shared + later), 80))
    other = grid_gate.make(params)(
        ctx(make_bars("XRP-USDC", shared + wild), 80)
    )
    assert calm == other


def test_grid_gate_closed_random_walk():
    params = {
        "q": 2,
        "k": 1.0,
        "lookback": 60,
        "floor_pct": 0.015,
        "levels": 3,
        "quote_per_buy": 250,
    }
    rng = random.Random(21)
    start = utc(2024, 1, 1)
    rows = []
    level = 0.0
    for index in range(600):
        level += rng.gauss(0.0, 0.01)
        close = 100.0 * math.exp(level)
        rows.append(
            (
                start + timedelta(days=index),
                close,
                close * 1.001,
                close * 0.999,
                close,
            )
        )
    bars = make_bars("XRP-USDC", rows)

    open_bars = sum(
        1
        for t in range(100, 600)
        if grid_gate.is_open(params, PastBars(bars, t + 1)) is True
    )
    # a random walk carries a variance ratio near 1, so it rarely reads as
    # mean-reverting; 100..599 is 500 indices
    assert open_bars / 500 <= 0.2


def test_grid_gate_open_mean_reverting():
    params = {
        "q": 2,
        "k": 1.0,
        "lookback": 60,
        "floor_pct": 0.015,
        "levels": 3,
        "quote_per_buy": 250,
    }
    rng = random.Random(22)
    start = utc(2024, 1, 1)
    rows = []
    for index in range(600):
        close = 100.0 * math.exp(0.01 * rng.gauss(0.0, 1.0))
        rows.append(
            (
                start + timedelta(days=index),
                close,
                close * 1.001,
                close * 0.999,
                close,
            )
        )
    bars = make_bars("XRP-USDC", rows)

    open_bars = sum(
        1
        for t in range(100, 600)
        if grid_gate.is_open(params, PastBars(bars, t + 1)) is True
    )
    assert open_bars / 500 >= 0.9


def test_spacing_floor():
    start = utc(2024, 1, 1)
    rows = make_bars(
        "XRP-USDC",
        [
            (start + timedelta(days=i), D(price), D(price), D(price), D(price))
            for i, price in enumerate((100, 101, 100, 101, 100))
        ],
    )
    # ln(101/100) = 0.009950330853168092; the four returns +a -a +a -a have
    # sample sd 0.011489652393204873, so step = 1.0 * sd * sqrt(4) =
    # 0.022979304786409745, above the 0.015 floor
    params = {
        "q": 4,
        "k": 1.0,
        "lookback": 4,
        "floor_pct": 0.015,
        "levels": 3,
        "quote_per_buy": 250,
    }
    assert float(grid_gate.grid_step(params, rows)) == pytest.approx(
        0.022979304786409745, rel=1e-9
    )

    # 0.5 * 0.011489652393204873 * sqrt(2) = 0.008124... is below the floor
    floored = {
        "q": 2,
        "k": 0.5,
        "lookback": 4,
        "floor_pct": 0.015,
        "levels": 3,
        "quote_per_buy": 250,
    }
    assert grid_gate.grid_step(floored, rows) == D("0.015")

    # lookback 4 needs five closes
    assert grid_gate.grid_step(params, rows[:4]) is None


def test_grid_gate_decisions():
    params = {
        "q": 2,
        "k": 1.0,
        "lookback": 60,
        "floor_pct": 0.015,
        "levels": 3,
        "quote_per_buy": 250,
    }
    rng = random.Random(22)
    start = utc(2024, 1, 1)
    rows = []
    for index in range(120):
        close = 100.0 * math.exp(0.01 * rng.gauss(0.0, 1.0))
        rows.append(
            (
                start + timedelta(days=index),
                close,
                close * 1.001,
                close * 0.999,
                close,
            )
        )
    bars = make_bars("XRP-USDC", rows)
    decide = grid_gate.make(params)

    def open_at(index):
        return grid_gate.is_open(params, PastBars(bars, index + 1))

    # t = 60 is the first bar the gate can be read at (61 bars is the lookback
    # plus one); one bar earlier the window is short, so is_open is None there,
    # which is not True: that first evaluable bar is a closed-to-open boundary
    turning = None
    for t in range(60, len(bars)):
        if open_at(t) is True and grid_gate.is_open(params, PastBars(bars, t)) is not True:
            turning = t
            break
    assert turning is not None, "no closed-to-open boundary in the series"

    close = bars[turning].close
    # w = 5 * close / (500 + 5 * close) is the base weight at cash 500, base 5
    weight = D("5") * close / (D("500") + D("5") * close)
    step = grid_gate.grid_step(params, PastBars(bars, turning + 1))
    # centre = close * (1 - (w - 0.5) * 2 * step), leaning against the holding
    centre = close * (D("1") - (weight - D("0.5")) * D("2") * step)
    assert decide(ctx(bars, turning + 1, cash=D("500"), base=D("5"))) == Gates(
        grid_armed=True, recenter_to=centre, step_pct=step
    )

    continuing = None
    for t in range(turning + 1, len(bars)):
        if open_at(t) is True and open_at(t - 1) is True:
            continuing = t
            break
    assert continuing is not None, "no two consecutive open bars in the series"
    assert decide(
        ctx(bars, continuing + 1, cash=D("500"), base=D("5"))
    ) == Gates(grid_armed=True)

    # the seeded random walk of the closed-gate test reads as a walk rather
    # than as mean-reverting, so its gate is shut at some bar
    walk_rng = random.Random(21)
    walk_rows = []
    level = 0.0
    for index in range(600):
        level += walk_rng.gauss(0.0, 0.01)
        walk_close = 100.0 * math.exp(level)
        walk_rows.append(
            (
                start + timedelta(days=index),
                walk_close,
                walk_close * 1.001,
                walk_close * 0.999,
                walk_close,
            )
        )
    walk_bars = make_bars("XRP-USDC", walk_rows)

    closed = None
    for t in range(100, len(walk_bars)):
        if grid_gate.is_open(params, PastBars(walk_bars, t + 1)) is False:
            closed = t
            break
    assert closed is not None, "no closed bar in the random walk"
    assert decide(
        ctx(walk_bars, closed + 1, cash=D("500"), base=D("5"))
    ) == Gates(grid_armed=False)


# ---------------------------------------------------------------- event veto


def _earnings(announced_at=None):
    return Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 5, 22, 20),
        announced_at=utc(2024, 5, 6) if announced_at is None else announced_at,
        session="post",
    )


def test_veto_window():
    earnings = _earnings()
    assert event_veto.reaction_date(earnings) == date(2024, 5, 23)
    reaction = date(2024, 5, 23)

    # the next session after Monday 20 May is Tuesday 21, leaving Wed 22 and
    # Thu 23 before the reaction
    assert event_veto.sessions_before(date(2024, 5, 20), reaction) == 2
    # from Friday 17 May the next session is Monday 20: Tue 21, Wed 22, Thu 23
    assert event_veto.sessions_before(date(2024, 5, 17), reaction) == 3
    # from Thursday 16 May the next session is Friday 17: Mon..Thu is four
    assert event_veto.sessions_before(date(2024, 5, 16), reaction) == 4
    # from Wednesday 22 May the next session is the reaction itself
    assert event_veto.sessions_before(date(2024, 5, 22), reaction) == 0

    assert event_veto.veto_active([earnings], utc(2024, 5, 20), 3) is True
    assert event_veto.veto_active([earnings], utc(2024, 5, 17), 3) is True
    assert event_veto.veto_active([earnings], utc(2024, 5, 16), 3) is False
    assert event_veto.veto_active([earnings], utc(2024, 5, 22), 3) is False
    assert event_veto.veto_active([earnings], utc(2024, 5, 20), 0) is False

    custom = Event(
        symbol="NVDA",
        kind="custom",
        at=utc(2024, 5, 22, 20),
        announced_at=utc(2024, 5, 6),
        session="post",
    )
    listing = Event(
        symbol="NVDA",
        kind="listing",
        at=utc(2024, 5, 22, 20),
        announced_at=utc(2024, 5, 6),
        session="post",
    )
    assert event_veto.veto_active([custom], utc(2024, 5, 20), 3) is False
    assert event_veto.veto_active([listing], utc(2024, 5, 20), 3) is False

    pre = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 5, 23, 12),
        announced_at=utc(2024, 5, 6),
        session="pre",
    )
    assert event_veto.reaction_date(pre) == date(2024, 5, 23)

    # a 20:00 release on Friday 24 May belongs to the next session, but
    # Memorial Day Monday 27 May is a closure, so the next session is
    # Tuesday 28 May and the reaction is there
    friday_post = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 5, 24, 20),
        announced_at=utc(2024, 5, 6),
        session="post",
    )
    assert event_veto.reaction_date(friday_post) == date(2024, 5, 28)

    # a Saturday 25 May release with no session tag also moves to the first
    # session after it: the weekend, then Memorial Day Monday 27 May as a
    # closure, so Tuesday 28 May
    saturday_none = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 5, 25, 12),
        announced_at=utc(2024, 5, 6),
        session="none",
    )
    assert event_veto.reaction_date(saturday_none) == date(2024, 5, 28)


def _scheduled(at, session, kind="earnings", announced_at=None):
    """An event of *kind* at *at*, announced in January 2018 by default."""
    return Event(
        symbol="NVDA",
        kind=kind,
        at=at,
        announced_at=utc(2018, 1, 2) if announced_at is None else announced_at,
        session=session,
    )


def test_nyse_holidays_are_not_sessions():
    holidays = event_veto.NYSE_HOLIDAYS
    # Thanksgiving 2026, the 2025 mourning day, the 2018 mourning day and
    # Christmas Eve 2027 are full closures
    assert date(2026, 11, 26) in holidays
    assert date(2025, 1, 9) in holidays
    assert date(2018, 12, 5) in holidays
    assert date(2027, 12, 24) in holidays
    # the day after Thanksgiving 2026 (Friday 27) closes early and is still a
    # session, and so is the ordinary Wednesday 25 before the holiday
    assert date(2026, 11, 27) not in holidays
    assert date(2026, 11, 25) not in holidays


def _year_counts(calendar, first_year=2016, last_year=2025):
    """How many dates of *calendar* fall in each year from first to last."""
    counts = {year: 0 for year in range(first_year, last_year + 1)}
    for day in calendar:
        if day.year in counts:
            counts[day.year] += 1
    return counts


def test_nyse_full_closures_2016_to_2025():
    holidays = event_veto.NYSE_HOLIDAYS

    # Good Friday 2016, the 2018 mourning day, the first Juneteenth, the 2025
    # mourning day, the Christmases of 2016 and 2021 observed on the Friday or
    # the Monday, the New Year days of 2017 and 2023 observed on the Monday,
    # and the Christmas of 2022 observed on Monday 26 December
    for day in (
        date(2016, 3, 25),
        date(2018, 12, 5),
        date(2022, 6, 20),
        date(2025, 1, 9),
        date(2016, 12, 26),
        date(2021, 12, 24),
        date(2017, 1, 2),
        date(2023, 1, 2),
        date(2022, 12, 26),
    ):
        assert day in holidays

    # Friday 31 December 2021 traded (New Year's Day 2022 fell on the Saturday
    # and was not observed on the Friday), and Friday 25 November 2016 and
    # Wednesday 3 July 2024 closed early, which leaves them sessions
    for day in (date(2021, 12, 31), date(2016, 11, 25), date(2024, 7, 3)):
        assert day not in holidays

    # 9 + 9 + 10 + 9 + 9 + 9 + 9 + 10 + 10 + 11 = 95 closures
    counts = _year_counts(holidays)
    assert counts == {
        2016: 9,
        2017: 9,
        2018: 10,
        2019: 9,
        2020: 9,
        2021: 9,
        2022: 9,
        2023: 10,
        2024: 10,
        2025: 11,
    }
    assert sum(counts.values()) == 95


def test_nyse_early_closes_are_sessions():
    early = event_veto.NYSE_EARLY_CLOSES

    # the day after Thanksgiving 2016, Christmas Eve 2018 and the day before
    # Independence Day 2025, and the three later ones the calendar carries
    for day in (
        date(2016, 11, 25),
        date(2018, 12, 24),
        date(2025, 7, 3),
        date(2026, 11, 27),
        date(2026, 12, 24),
        date(2027, 11, 26),
    ):
        assert day in early

    # 1 + 2 + 3 + 3 + 2 + 1 + 1 + 2 + 3 + 3 = 21 early closes over 2016 to 2025;
    # the 2026 and 2027 ones sit outside those years
    counts = _year_counts(early)
    assert counts == {
        2016: 1,
        2017: 2,
        2018: 3,
        2019: 3,
        2020: 2,
        2021: 1,
        2022: 1,
        2023: 2,
        2024: 3,
        2025: 3,
    }
    assert sum(counts.values()) == 21

    # an early close is still a trading session, so it is never a full closure
    assert early.isdisjoint(event_veto.NYSE_HOLIDAYS)


def test_sessions_count_past_good_friday_2016():
    assert date(2016, 3, 25) in event_veto.NYSE_HOLIDAYS
    # Wednesday 23 March 2016: the next session is Thursday 24, then Friday 25
    # is a holiday (+0), the weekend carries no session, and Monday 28 is the
    # reaction (+1)
    assert event_veto.sessions_before(date(2016, 3, 23), date(2016, 3, 28)) == 1

    # a 20:00 release on Thursday 24 March reacts on Monday 28, across Good
    # Friday and the weekend
    good_friday_eve = _scheduled(
        utc(2016, 3, 24, 20), "post", announced_at=utc(2016, 1, 4)
    )
    assert event_veto.reaction_date(good_friday_eve) == date(2016, 3, 28)


def test_post_close_release_before_holiday_reacts_next_session():
    # a 20:00 release on Wednesday 25 November 2026 (Thanksgiving eve):
    # Thursday 26 is a holiday, so the reaction is Friday 27
    thanksgiving_eve = _scheduled(utc(2026, 11, 25, 20), "post")
    assert event_veto.reaction_date(thanksgiving_eve) == date(2026, 11, 27)

    # Thursday 2 April 2026 before Good Friday: Friday 3 is a holiday and the
    # weekend follows it, so the reaction is Monday 6 April
    good_friday_eve = _scheduled(utc(2026, 4, 2, 20), "post")
    assert event_veto.reaction_date(good_friday_eve) == date(2026, 4, 6)

    # Thursday 24 December 2026 closes early but is a session; Christmas Day
    # Friday 25 is a holiday and the weekend follows, so the reaction is
    # Monday 28 December
    christmas_eve = _scheduled(utc(2026, 12, 24, 20), "post")
    assert event_veto.reaction_date(christmas_eve) == date(2026, 12, 28)

    # Wednesday 8 January 2025: Thursday 9 is the mourning day, so the
    # reaction is Friday 10 January
    new_year_week = _scheduled(utc(2025, 1, 8, 20), "post")
    assert event_veto.reaction_date(new_year_week) == date(2025, 1, 10)


def test_pre_open_release_on_a_holiday_moves_to_next_session():
    # a 12:00 pre-open release on Thursday 9 January 2025 falls on the mourning
    # day, so it moves to the next session, Friday 10 January
    mourning_day = _scheduled(utc(2025, 1, 9, 12), "pre")
    assert event_veto.reaction_date(mourning_day) == date(2025, 1, 10)

    # Friday 27 November 2026 is an early close after Thanksgiving and still a
    # session, so a pre-open release that day stays on it
    half_day = _scheduled(utc(2026, 11, 27, 12), "pre")
    assert event_veto.reaction_date(half_day) == date(2026, 11, 27)


def test_sessions_before_skips_holidays():
    # Monday 23 November 2026: the next session is Tuesday 24, so the count
    # runs over Wednesday 25 (+1), Thursday 26 (a holiday, +0) and the reaction
    # Friday 27 (+1), which is two rather than three
    assert (
        event_veto.sessions_before(date(2026, 11, 23), date(2026, 11, 27)) == 2
    )
    # Wednesday 25 November: Thursday 26 is a holiday, so the next session is
    # the reaction itself on Friday 27, which leaves nothing to count
    assert (
        event_veto.sessions_before(date(2026, 11, 25), date(2026, 11, 27)) == 0
    )
    # Wednesday 8 January 2025: the next session is Friday 10 (Thursday 9 is a
    # holiday), then Monday 13 (+1) and Tuesday 14 (+1), which is two
    assert event_veto.sessions_before(date(2025, 1, 8), date(2025, 1, 14)) == 2


def test_veto_active_counts_sessions_around_a_holiday():
    # the announced release on Wednesday 25 November 2026 at 20:00 reacts on
    # Friday 27 November
    earnings = _scheduled(utc(2026, 11, 25, 20), "post")
    assert event_veto.reaction_date(earnings) == date(2026, 11, 27)

    # Tuesday 24 November: the next session is Wednesday 25, then Thursday 26
    # (a holiday, +0) and Friday 27 (+1), so the reaction is one session ahead
    assert (
        event_veto.sessions_before(date(2026, 11, 24), date(2026, 11, 27)) == 1
    )
    assert event_veto.veto_active([earnings], utc(2026, 11, 24), 1) is True

    # Monday 23 November: the next session is Tuesday 24, then Wednesday 25
    # (+1) and Friday 27 across the holiday (+1), so the reaction is two
    # sessions ahead: a one-session window is shut, a two-session one is open
    assert event_veto.veto_active([earnings], utc(2026, 11, 23), 1) is False
    assert event_veto.veto_active([earnings], utc(2026, 11, 23), 2) is True

    # a window of 0 days holds nothing back even one session out
    assert event_veto.veto_active([earnings], utc(2026, 11, 24), 0) is False


def test_a_weekday_that_is_not_listed_is_still_a_session():
    # Friday 31 December 2021 was a full trading day: New Year's Day 2022 fell
    # on the Saturday and was not observed on the Friday, so neither date is a
    # full closure and the 31st is a session
    assert date(2021, 12, 31) not in event_veto.NYSE_HOLIDAYS
    assert date(2022, 1, 1) not in event_veto.NYSE_HOLIDAYS
    # a 20:00 release on Thursday 30 December 2021 reacts on Friday 31
    new_year_eve = _scheduled(utc(2021, 12, 30, 20), "post")
    assert event_veto.reaction_date(new_year_eve) == date(2021, 12, 31)


def _weekdays(start, end):
    """A UTC stamp for every weekday from *start* to *end* inclusive."""
    stamps = []
    day = start
    while day <= end:
        if day.weekday() < 5:
            stamps.append(utc(day.year, day.month, day.day))
        day += timedelta(days=1)
    return stamps


def _stock_costs():
    """The stock model these runs carry: no taker fee, no slippage, no step."""
    return CostModel.for_stock(
        "NVDA", st_tax_rate=D("0.30"), lt_tax_rate=D("0.15"), slippage=D("0")
    )


def _funded_run(bars, events, params):
    """One funded event-veto run over *bars* from no cash."""
    return simulate(
        bars,
        events,
        event_veto.make(params),
        D("0"),
        D("0"),
        _stock_costs(),
        contribution=event_veto.FUNDING,
    )


def test_event_veto_moves_a_buy_inside_the_window():
    # Every weekday from Monday 26 February to Friday 22 March 2024, flat at
    # 100, with no exchange closure in the span: 20 bars and four week starts.
    stamps = _weekdays(date(2024, 2, 26), date(2024, 3, 22))
    assert len(stamps) == 20
    bars = make_bars("NVDA", [(ts, 100, 101, 99, 100) for ts in stamps])

    # a 20:00 release on Thursday 7 March reacts on Friday 8 March
    earnings = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 3, 7, 20),
        announced_at=utc(2024, 2, 20),
        session="post",
    )

    no_veto = _funded_run(bars, [earnings], {"amount": 50, "veto_days": 0})
    short_window = _funded_run(
        bars, [earnings], {"amount": 50, "veto_days": 2}
    )
    vetoed = _funded_run(bars, [earnings], {"amount": 50, "veto_days": 3})

    # The week starting Monday 26 February buys at that bar's close and fills
    # Tuesday 27 February in both runs: 50 / 100 = 0.5 units.
    assert no_veto.trades[0].ts == utc(2024, 2, 27)
    assert no_veto.trades[0].qty == D("0.5")
    assert vetoed.trades[0] == no_veto.trades[0]

    # No window: Monday 4 March fills Tuesday 5 March, and nothing fills on the
    # reaction's own bar (Friday 8 March) or on the Fridays after it.
    assert [trade.ts for trade in no_veto.trades] == [
        utc(2024, 2, 27),
        utc(2024, 3, 5),
        utc(2024, 3, 12),
        utc(2024, 3, 19),
    ]

    # A three-session window: Monday 4 March has Wednesday 6, Thursday 7 and
    # Friday 8 before the reaction, so it is vetoed; the buy stays due through
    # Tuesday and Wednesday and leaves on Thursday 7 March, filling Friday
    # 8 March.
    assert [trade.ts for trade in vetoed.trades] == [
        utc(2024, 2, 27),
        utc(2024, 3, 8),
        utc(2024, 3, 12),
        utc(2024, 3, 19),
    ]

    # A two-session window starts later than the scheduled bar: Monday 4 March
    # is three sessions out, past the window, so that week buys as if unwatched
    # and only the later sessions of the week are held back.
    assert [trade.ts for trade in short_window.trades] == [
        utc(2024, 2, 27),
        utc(2024, 3, 5),
        utc(2024, 3, 12),
        utc(2024, 3, 19),
    ]

    # Four week starts fund four $50 buys in both runs: 4 * 50 = 200.
    assert no_veto.total_contributed == D("200")
    assert vetoed.total_contributed == D("200")

    # A flat price with no costs marks the same equity whichever bar the buy
    # filled on, so these two runs differ in their fills, not in their marks.
    assert vetoed.curve == no_veto.curve


def test_event_veto_carries_a_vetoed_week_until_the_window_shuts():
    rows = make_bars(
        "NVDA",
        [
            (utc(2024, 3, day), 100, 101, 99, 100)
            for day in (4, 5, 6, 7, 8, 11, 12)
        ],
    )
    # A 20:00 release on Tuesday 12 March reacts on Wednesday 13 March: six
    # sessions after Monday 4 March (Wed 6, Thu 7, Fri 8, Mon 11, Tue 12,
    # Wed 13).
    earnings = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 3, 12, 20),
        announced_at=utc(2024, 1, 2),
        session="post",
    )
    decide = event_veto.make({"amount": 50, "veto_days": 6})

    def answer(count, cash=D("1000")):
        return decide(
            ctx(
                rows,
                count,
                cash=cash,
                events=[earnings],
                asset_class="stock",
            )
        )

    # the first week's buy stays due through every session of that week
    assert answer(1) is None
    assert answer(2) is None
    assert answer(3) is None
    assert answer(4) is None
    assert answer(5) is None
    # Monday 11 March is a second week start and is still inside the window
    assert answer(6) is None
    # Tuesday 12 March is the reaction's eve: two weeks are due, so the buy is
    # min(1000, 50 * 2) = 100
    assert answer(7) == (Order(BUY, notional=D("100")),)

    # the same two weeks with only 80 of cash: min(80, 100) = 80
    capped = event_veto.make({"amount": 50, "veto_days": 6})
    for count in range(1, 7):
        capped(
            ctx(
                rows,
                count,
                cash=D("80"),
                events=[earnings],
                asset_class="stock",
            )
        )
    assert capped(
        ctx(
            rows,
            7,
            cash=D("80"),
            events=[earnings],
            asset_class="stock",
        )
    ) == (Order(BUY, notional=D("80")),)


def test_event_veto_unannounced_event_and_no_veto_control_keep_the_schedule():
    # two weeks of weekdays: Monday 13 May to Friday 24 May 2024
    stamps = _weekdays(date(2024, 5, 13), date(2024, 5, 24))
    assert len(stamps) == 10
    bars = make_bars("NVDA", [(ts, 100, 101, 99, 100) for ts in stamps])

    # a 20:00 release on Wednesday 22 May reacts on Thursday 23 May
    earnings = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 5, 22, 20),
        announced_at=utc(2024, 5, 6),
        session="post",
    )

    # Monday 20 May is two sessions from the reaction (Wed 22, Thu 23), inside a
    # three-session window, so the second week's buy leaves Wednesday 22 May and
    # fills Thursday 23 May
    watched = _funded_run(bars, [earnings], {"amount": 50, "veto_days": 3})
    assert [trade.ts for trade in watched.trades] == [
        utc(2024, 5, 14),
        utc(2024, 5, 23),
    ]

    # announced at noon on 21 May, the event is not visible at the 20 May bar, so
    # that week's buy leaves on time and fills Tuesday 21 May
    late = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 5, 22, 20),
        announced_at=utc(2024, 5, 21, 12),
        session="post",
    )
    unannounced = _funded_run(bars, [late], {"amount": 50, "veto_days": 3})
    assert [trade.ts for trade in unannounced.trades] == [
        utc(2024, 5, 14),
        utc(2024, 5, 21),
    ]

    # veto_days 0 is the no-veto control, even with the early announcement
    control = _funded_run(bars, [earnings], {"amount": 50, "veto_days": 0})
    assert [trade.ts for trade in control.trades] == [
        utc(2024, 5, 14),
        utc(2024, 5, 21),
    ]


def test_event_veto_funded_cash_never_runs_out():
    # 520 weekdays from Monday 6 January 2020: 520 // 5 = 104 whole weeks, so a
    # week-start bar every fifth bar and a Friday as the last bar
    stamps = []
    day = date(2020, 1, 6)
    while len(stamps) < 520:
        if day.weekday() < 5:
            stamps.append(utc(day.year, day.month, day.day))
        day += timedelta(days=1)
    assert len(stamps) == 520
    assert stamps[-1].weekday() == 4
    bars = make_bars("NVDA", [(ts, 100, 101, 99, 100) for ts in stamps])
    costs = _stock_costs()

    cash_seen = []
    plain = event_veto.make({"amount": 50, "veto_days": 3})

    def record(view):
        cash_seen.append(view.cash)
        return plain(view)

    quiet = simulate(
        bars,
        [],
        record,
        D("0"),
        D("0"),
        costs,
        contribution=event_veto.FUNDING,
    )

    assert quiet.dropped == []
    assert quiet.final_cash >= 0
    assert cash_seen and all(cash >= 0 for cash in cash_seen)
    quiet_buys = [trade for trade in quiet.trades if trade.side == "BUY"]
    # 104 week starts, every one of them before the last bar, so every one of
    # them buys and no order is left for the last bar to drop
    assert len(quiet_buys) == 104
    assert all(trade.qty > 0 for trade in quiet_buys)

    # An earnings release on every 60th weekday from bar 32 on: 32, 92, ...,
    # 512 are nine Wednesday reactions, each announced 14 days before.
    events = []
    for index in range(32, 520, 60):
        stamp = stamps[index]
        at = utc(stamp.year, stamp.month, stamp.day, 12)
        events.append(
            Event(
                symbol="NVDA",
                kind="earnings",
                at=at,
                announced_at=at - timedelta(days=14),
                session="none",
            )
        )
    assert len(events) == 9

    event_cash = []
    watched = event_veto.make({"amount": 50, "veto_days": 3})

    def record_events(view):
        event_cash.append(view.cash)
        return watched(view)

    with_events = simulate(
        bars,
        events,
        record_events,
        D("0"),
        D("0"),
        costs,
        contribution=event_veto.FUNDING,
    )

    assert with_events.dropped == []
    assert with_events.final_cash >= 0
    assert event_cash and all(cash >= 0 for cash in event_cash)
    event_buys = [trade for trade in with_events.trades if trade.side == "BUY"]
    # A window can slip a week's fill to a later session of the same week but
    # never skips it, so 104 - 6 = 98 is a floor on the buys of 104 weeks.
    assert len(event_buys) >= 98
    assert all(trade.qty > 0 for trade in event_buys)


# ---------------------------------------------------------------- the module surface


def test_grid_sizes_at_least_4():
    for module in (band, regime, grid_gate, event_veto):
        assert len(module.GRID) >= 4
        assert check_rule_module(module) is None

    def rule(**overrides):
        values = dict(
            RULE_ID="x",
            HYPOTHESIS="h",
            GRID=[{}, {}, {}, {}],
            ASSETS=("crypto",),
            INITIAL_BASE_FRACTION=D("0.5"),
            SIMULATOR="market",
            make=lambda params: None,
        )
        values.update(overrides)
        return SimpleNamespace(**values)

    with pytest.raises(ValueError):
        check_rule_module(rule(GRID=[{}, {}, {}]))

    missing_make = rule()
    del missing_make.make
    with pytest.raises(ValueError):
        check_rule_module(missing_make)

    with pytest.raises(ValueError):
        check_rule_module(rule(ASSETS=("fx",)))

    with pytest.raises(ValueError):
        check_rule_module(rule(INITIAL_BASE_FRACTION=D("1.5")))

    # The simulator that reads a rule's answer is part of the shape now: a
    # module that names none, or names one the lab does not run, is refused.
    with pytest.raises(ValueError, match="SIMULATOR"):
        check_rule_module(rule(SIMULATOR="bogus"))

    missing_simulator = rule()
    del missing_simulator.SIMULATOR
    with pytest.raises(ValueError, match="SIMULATOR"):
        check_rule_module(missing_simulator)


def test_check_rule_module_funding():
    """A rule may declare the fixed weekly contribution its schedule spends."""

    def rule(**overrides):
        values = dict(
            RULE_ID="x",
            HYPOTHESIS="h",
            GRID=[{}, {}, {}, {}],
            ASSETS=("crypto",),
            INITIAL_BASE_FRACTION=D("0.5"),
            SIMULATOR="market",
            make=lambda params: None,
        )
        values.update(overrides)
        return SimpleNamespace(**values)

    # no FUNDING at all is fine: an unfunded rule needs none
    assert check_rule_module(rule()) is None
    assert check_rule_module(event_veto) is None

    funded = rule(FUNDING={"amount": D("50"), "every": "week"})
    assert check_rule_module(funded) is None

    for bad in (
        [{"amount": D("50"), "every": "week"}],  # not a dict
        {"amount": 50, "every": "week"},  # an int, not a Decimal
        {"amount": D("0"), "every": "week"},  # nothing to contribute
        {"amount": D("50"), "every": "month"},  # not a weekly schedule
    ):
        with pytest.raises(ValueError, match="FUNDING"):
            check_rule_module(rule(FUNDING=bad))


def test_assets_enforced():
    assert band.RULE_ID == "band"
    assert regime.RULE_ID == "regime"
    assert grid_gate.RULE_ID == "grid_gate"
    assert event_veto.RULE_ID == "event_veto"

    assert band.ASSETS == ("crypto",)
    assert regime.ASSETS == ("crypto",)
    assert grid_gate.ASSETS == ("crypto",)
    assert event_veto.ASSETS == ("stock",)

    require_asset(band, "crypto")
    with pytest.raises(ValueError, match="asset class"):
        require_asset(band, "stock")

    require_asset(regime, "crypto")
    with pytest.raises(ValueError, match="asset class"):
        require_asset(regime, "stock")

    require_asset(grid_gate, "crypto")
    with pytest.raises(ValueError, match="asset class"):
        require_asset(grid_gate, "stock")

    require_asset(event_veto, "stock")
    with pytest.raises(ValueError, match="asset class"):
        require_asset(event_veto, "crypto")


def test_insufficient_history_no_decision():
    empty = LabContext(
        bars=PastBars([], 0),
        events=[],
        cash=D("1000"),
        base=D("0"),
        lots=Lots("crypto"),
        now=utc(2024, 5, 1),
    )
    assert band.make({"band_pts": 5})(empty) is None

    start = utc(2024, 1, 1)
    six = make_bars(
        "XRP-USDC",
        [(start + timedelta(days=i), 100, 101, 99, 100) for i in range(6)],
    )
    # n = 5 needs n + 2 = 7 bars
    assert regime.make(
        {"n": 5, "step_pct": 0.02, "levels": 3, "quote_per_buy": 250}
    )(ctx(six)) is None

    sixty = make_bars(
        "XRP-USDC",
        [(start + timedelta(days=i), 100, 101, 99, 100) for i in range(60)],
    )
    # lookback 60 needs 61 bars
    assert grid_gate.make(
        {
            "q": 2,
            "k": 1.0,
            "lookback": 60,
            "floor_pct": 0.015,
            "levels": 3,
            "quote_per_buy": 250,
        }
    )(ctx(sixty)) is None


def test_event_veto_weekly_amount_single_bar():
    one = make_bars("NVDA", [(utc(2024, 5, 13), 100, 101, 99, 100)])

    # a single bar is a week start, so the week's $50 buy is due
    assert event_veto.make({"amount": 50, "veto_days": 3})(
        ctx(one, cash=D("1000"), asset_class="stock")
    ) == (Order(BUY, notional=D("50")),)

    # the buy is capped by the cash held
    assert event_veto.make({"amount": 50, "veto_days": 3})(
        ctx(one, cash=D("30"), asset_class="stock")
    ) == (Order(BUY, notional=D("30")),)

    # with no cash the notional is 0, which is no order
    assert event_veto.make({"amount": 50, "veto_days": 3})(
        ctx(one, cash=D("0"), asset_class="stock")
    ) is None


# ---------------------------------------------------------------- null schedule


def test_event_veto_declares_its_funding():
    # the schedule buys a fixed $50 a week, funded by a fixed $50 a week
    assert event_veto.FUNDING == {"amount": D("50"), "every": "week"}
    assert event_veto.INITIAL_BASE_FRACTION == D("0")
    # params carry plain numbers so they serialize to JSON; make() converts them
    assert event_veto.GRID == [
        {"amount": 50, "veto_days": days} for days in (1, 2, 3, 5)
    ]


def test_event_veto_grid_drops_the_null_schedule():
    # veto_days 0 is null_params' own schedule, so a grid config equal to the
    # benchmark would test nothing: the grid holds only windows that hold
    # something back
    days = [config["veto_days"] for config in event_veto.GRID]
    assert days == [1, 2, 3, 5]
    assert 0 not in days
    for config in event_veto.GRID:
        assert config["veto_days"] != 0
        assert config["amount"] == 50


def test_event_veto_null_params():
    # the null schedule of the veto is the same funded buy plan with the window
    # shut
    params = {"amount": 50, "veto_days": 3}
    null = event_veto.null_params(params)
    assert null == {"amount": 50, "veto_days": 0}
    # a copy: the caller's own window is left where it was
    assert null is not params
    assert params == {"amount": 50, "veto_days": 3}

    # every config of the grid maps to itself with veto_days 0, and mapping the
    # grid leaves the grid's own configs alone
    before = [dict(config) for config in event_veto.GRID]
    assert before
    for config in event_veto.GRID:
        zeroed = event_veto.null_params(config)
        assert zeroed["veto_days"] == 0
        assert set(zeroed) == set(config)
        assert zeroed["amount"] == config["amount"]
    assert [dict(config) for config in event_veto.GRID] == before


# ---------------------------------------------------------------- the simulator


def test_rule_modules_declare_their_simulator():
    # The answer a rule gives decides which simulator can read it: a band's
    # orders fill at the next open, and a gate about a ladder belongs to the
    # intrabar ladder simulator.
    assert band.SIMULATOR == "market"
    assert event_veto.SIMULATOR == "market"
    assert regime.SIMULATOR == "grid"
    assert grid_gate.SIMULATOR == "grid"