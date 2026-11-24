"""Curve statistics, the three benchmarks and the beats rule for the lab.

A curve is the equity the market-fill simulator marked at each bar's close,
`list[tuple[datetime, Decimal]]`, so its money stays `Decimal`: returns and the
per-period Sharpe ratio are the only floats here, because they compare against
each other rather than settle anything.

The benchmarks exist so a rule can be read against a plain alternative that
starts from the same cash, pays the same fees and slippage, and owes the same
tax when the book is closed:

* `lump_sum` (and `buy_and_hold`, which is the same run) buys everything at the
  first open and then holds.
* `scheduled` splits the cash into equal tranches and buys one every
  `spacing_bars` bars, so some cash waits for a later open.
* `fifty_fifty` holds half the equity in the asset and half in cash, and trades
  back to that half only when the weight drifts past a band.

Nothing here reaches an exchange: a benchmark is a decision function handed to
the simulator, and a statistic is arithmetic over the curve it produced.  A run
funded by a weekly contribution puts new money into the curve, so its returns,
its drawdown and its after-tax gain are read net of what was contributed:
`period_returns` takes the contributions themselves, `max_drawdown` reads an
index compounded from those step returns, and `after_tax_return` reads the
result's own `total_contributed` from the start equity.  A benchmark handed the
same weekly schedule spends each deposit as it lands, so the comparison is
between two runs funded the same way.
"""

from __future__ import annotations

import math
import statistics
from datetime import datetime
from decimal import Decimal
from typing import Optional

from .costs import BUY, SELL, CostModel, Order
from .sim import SimResult, simulate

D = Decimal

__all__ = [
    "after_tax_return",
    "annualize",
    "beats",
    "buy_and_hold",
    "fifty_fifty",
    "lump_sum",
    "max_drawdown",
    "net_return",
    "period_returns",
    "scheduled",
    "sharpe",
]

# The balanced weight and the default drift band, in percentage points.
HALF = D("0.5")
DEFAULT_BAND_PTS = D("7.5")
HUNDRED = D("100")
FIFTY = D("50")


# ---------------------------------------------------------------- value helpers


def _decimal(value: object, name: str) -> D:
    """A Decimal from a Decimal, str or int.  A float is refused."""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(
            f"{name} must be a Decimal, not {type(value).__name__}: {value!r}"
        )
    try:
        return D(str(value))
    except Exception as exc:  # noqa: BLE001 - re-raised with the field name
        raise ValueError(f"{name} is not a decimal value: {value!r}") from exc


def _positive(value: object, name: str) -> D:
    out = _decimal(value, name)
    if out <= 0:
        raise ValueError(f"{name} must be positive: {value!r}")
    return out


def _points(curve) -> list:
    """The curve as a list; a curve with no point carries no statistic."""
    points = list(curve)
    if not points:
        raise ValueError("a curve needs at least one point")
    return points


def _whole(value: object, name: str) -> int:
    """A whole number of at least 1, from an int or an integral Decimal."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a whole number: {value!r}")
    if isinstance(value, int):
        out = value
    else:
        number = _decimal(value, name)
        if number != number.to_integral_value():
            raise ValueError(f"{name} must be a whole number: {value!r}")
        out = int(number)
    if out < 1:
        raise ValueError(f"{name} must be at least 1: {value!r}")
    return out


# ---------------------------------------------------------------- curve reads


def net_return(curve: list[tuple[datetime, D]]) -> Optional[D]:
    """The curve's whole change as a fraction: last equity over first, less 1.

    None when the curve is a single point (no change to measure) or when its
    first equity is not positive, so there is no base to measure against.
    """
    points = _points(curve)
    first = _decimal(points[0][1], "curve equity")
    if len(points) < 2 or first <= 0:
        return None
    last = _decimal(points[-1][1], "curve equity")
    return last / first - D("1")


def max_drawdown(curve: list[tuple[datetime, D]], contributions=None) -> D:
    """The deepest peak-to-trough fall, as a non-negative fraction of the peak.

    Read alone, the running peak starts at the first equity, which must be
    positive.  A curve that never falls below its running peak has a drawdown of
    0, and so does a one-point curve.

    *contributions* is None or a list of (stamp, amount) the run put in, read the
    way `period_returns` reads them.  With one, the fall is read off an index
    that starts at 1 and multiplies by the exact ratio `(e_i - c_i) / e_{i-1}` at
    each step, so a deposit is not read as a rise and a deposit that hides a
    fall in the marks no longer flattens the drawdown.  A step whose starting
    equity is not positive raises ValueError.
    """
    points = _points(curve)
    if contributions is None:
        peak = _positive(points[0][1], "the curve's first equity")
        worst = D("0")
        for _, value in points[1:]:
            equity = _decimal(value, "curve equity")
            if equity > peak:
                peak = equity
                continue
            fall = (peak - equity) / peak
            if fall > worst:
                worst = fall
        return worst

    added: dict = {}
    for ts, amount in contributions:
        added[ts] = added.get(ts, D("0")) + _decimal(
            amount, "contribution amount"
        )
    index = D("1")
    peak = D("1")
    worst = D("0")
    previous = _decimal(points[0][1], "curve equity")
    for ts, value in points[1:]:
        if previous <= 0:
            raise ValueError(
                f"a period needs a positive starting equity: {previous!r}"
            )
        equity = _decimal(value, "curve equity")
        index = index * (equity - added.get(ts, D("0"))) / previous
        previous = equity
        if index > peak:
            peak = index
            continue
        fall = (peak - index) / peak
        if fall > worst:
            worst = fall
    return worst


def period_returns(
    curve: list[tuple[datetime, D]], contributions=None
) -> list[float]:
    """One float return per step: `e_i / e_{i-1} - 1`, so n-1 of them.

    *contributions* is None or a list of (stamp, amount) the run put in.  The
    money added at a step's own stamp is new capital rather than a gain, so the
    step reads `(e_i - c_i) / e_{i-1} - 1`, with `c_i` the sum of the amounts
    stamped at that point; a contribution at the first point only lifts the
    starting equity and so produces no return.  With None or nothing stamped the
    result is the plain reading above.

    A step whose starting equity is not positive has no meaningful return and
    raises ValueError.
    """
    points = _points(curve)
    added: dict = {}
    for ts, amount in contributions or ():
        added[ts] = added.get(ts, D("0")) + _decimal(
            amount, "contribution amount"
        )
    previous = _decimal(points[0][1], "curve equity")
    returns: list[float] = []
    for ts, value in points[1:]:
        if previous <= 0:
            raise ValueError(
                f"a period needs a positive starting equity: {previous!r}"
            )
        equity = _decimal(value, "curve equity")
        returns.append(
            float((equity - added.get(ts, D("0"))) / previous - D("1"))
        )
        previous = equity
    return returns


# ---------------------------------------------------------------- ratios


def sharpe(returns: list[float]) -> Optional[float]:
    """Mean return over its sample standard deviation, per period.

    Not annualized (see `annualize`).  None when there are fewer than two
    returns, or when they are all the same so the sample standard deviation is
    0 and the ratio would divide by nothing.
    """
    values = [float(value) for value in returns]
    if len(values) < 2:
        return None
    spread = statistics.stdev(values)
    if spread == 0:
        return None
    return statistics.mean(values) / spread


def annualize(
    sr: Optional[float], periods_per_year: int | float
) -> Optional[float]:
    """A per-period Sharpe ratio scaled by the square root of the period count.

    None stays None.  A period count that is not positive raises ValueError.
    """
    if isinstance(periods_per_year, bool) or not isinstance(
        periods_per_year, (int, float)
    ):
        raise ValueError(
            f"periods_per_year must be a number, not "
            f"{type(periods_per_year).__name__}: {periods_per_year!r}"
        )
    if periods_per_year <= 0:
        raise ValueError(
            f"periods_per_year must be positive: {periods_per_year!r}"
        )
    if sr is None:
        return None
    return float(sr) * math.sqrt(float(periods_per_year))


def after_tax_return(result, start_equity: D) -> D:
    """The gain after closing the book, as a fraction of the money put in.

    Only `final_equity_after_liquidation_tax` and `total_contributed` are read,
    so any result object carrying them works; a result with no
    `total_contributed` (a result from before funded runs) counts as unfunded.
    The base is the starting equity plus everything the run contributed, so the
    money added is not read as a gain, and it is the base that has to be
    positive: a funded run may start from no cash at all, with the contributions
    as its whole base.  A starting equity below 0 raises ValueError whatever was
    contributed, and so does a base of 0.
    """
    start = _decimal(start_equity, "start_equity")
    if start < 0:
        raise ValueError(
            f"start_equity must not be negative: {start_equity!r}"
        )
    final = _decimal(
        result.final_equity_after_liquidation_tax,
        "final_equity_after_liquidation_tax",
    )
    contributed = _decimal(
        getattr(result, "total_contributed", D("0")), "total_contributed"
    )
    base = start + contributed
    if base <= 0:
        raise ValueError(
            f"the money put in must be positive: start_equity "
            f"{start_equity!r} plus contributions "
            f"{getattr(result, 'total_contributed', D('0'))!r}"
        )
    return final / base - D("1")


def beats(rule, benchmarks, start_equity: D) -> bool:
    """Whether a rule beats every benchmark on both return and drawdown.

    It has to earn a strictly higher after-tax return against each benchmark and
    keep a drawdown no deeper than that benchmark's (equal is allowed), all from
    the same starting equity.  Each drawdown is read net of the contributions
    its own run carried, so a funded rule and a funded benchmark are compared on
    the same footing.  No benchmark at all raises ValueError.
    """
    rivals = list(benchmarks)
    if not rivals:
        raise ValueError("beats needs at least one benchmark to compare against")
    rule_return = after_tax_return(rule, start_equity)
    rule_drawdown = max_drawdown(
        rule.curve, getattr(rule, "contributions", None) or None
    )
    for rival in rivals:
        if not rule_return > after_tax_return(rival, start_equity):
            return False
        if rule_drawdown > max_drawdown(
            rival.curve, getattr(rival, "contributions", None) or None
        ):
            return False
    return True


# ---------------------------------------------------------------- benchmarks


def _hold(context):
    """A rule that never trades, so a benchmark buys once and then holds."""
    return None


def _spend_every_bar(context):
    """A rule that buys with whatever cash it holds at each bar, and holds.

    A funded benchmark is handed this decide instead of `_hold`: each weekly
    contribution lands in cash at a week-start bar and is bought at the next
    open, so the money put in is invested rather than left idle.
    """
    if context.cash > 0:
        return [Order(BUY, notional=context.cash)]
    return None


def lump_sum(
    bars: list,
    events: list,
    cash: D,
    costs: CostModel,
    *,
    max_gap=None,
    contribution=None,
) -> SimResult:
    """Buy the whole cash amount at bar 0's open, as a taker, then hold.

    The opening fill pays slippage and the taker fee, so what the run holds is
    what the cash actually bought.

    *contribution* is None for a benchmark run from its starting cash alone, or
    a weekly funding dict.  A funded benchmark buys what the starting cash
    affords at bar 0's open — no initial order at all when the cash is 0 — and
    then spends every contribution at the open after it lands, so its curve is
    funded the way the rule it is read against is.
    """
    start = _decimal(cash, "cash")
    if contribution is None:
        return simulate(
            bars,
            events,
            _hold,
            start,
            D("0"),
            costs,
            initial_orders=[Order(BUY, notional=start)],
            max_gap=max_gap,
        )
    opening = [Order(BUY, notional=start)] if start > 0 else []
    return simulate(
        bars,
        events,
        _spend_every_bar,
        start,
        D("0"),
        costs,
        initial_orders=opening,
        max_gap=max_gap,
        contribution=contribution,
    )


def buy_and_hold(
    bars: list,
    events: list,
    cash: D,
    costs: CostModel,
    *,
    max_gap=None,
    contribution=None,
) -> SimResult:
    """The `lump_sum` run, under the name the comparison reads better with."""
    return lump_sum(
        bars, events, cash, costs, max_gap=max_gap, contribution=contribution
    )


def scheduled(
    bars: list,
    events: list,
    cash: D,
    costs: CostModel,
    *,
    tranches: int,
    spacing_bars: int,
    max_gap=None,
) -> SimResult:
    """Buy the cash in `tranches` equal amounts, one every `spacing_bars` bars.

    Tranche k is bought at the open of bar `k * spacing_bars`: tranche 0 is the
    initial order and fills at bar 0's open, and every later one is ordered when
    the simulator shows bar `k * spacing_bars - 1`, so it fills on the very next
    open.  A tranche whose bar is past the last one is never ordered, and the
    cash it would have spent stays in cash.
    """
    count = _whole(tranches, "tranches")
    spacing = _whole(spacing_bars, "spacing_bars")
    start = _decimal(cash, "cash")
    tranche = start / count

    def decide(context):
        step = len(context.bars)
        if step % spacing:
            return None
        which = step // spacing
        if which < 1 or which >= count:
            return None
        return [Order(BUY, notional=tranche)]

    return simulate(
        bars,
        events,
        decide,
        start,
        D("0"),
        costs,
        initial_orders=[Order(BUY, notional=tranche)],
        max_gap=max_gap,
    )


def fifty_fifty(
    bars: list,
    events: list,
    cash: D,
    costs: CostModel,
    *,
    band_pts: D = DEFAULT_BAND_PTS,
    max_gap=None,
    contribution=None,
) -> SimResult:
    """Hold half the equity in the asset and half in cash, trading back to half.

    The run opens by buying half the cash.  At each bar it marks the holding at
    that bar's close; when the holding's weight has drifted further from a half
    than `band_pts` percentage points, it trades back to exactly half — a buy of
    the shortfall, or a sale of the excess — and that order fills at the next
    bar's open as a taker.  A weight exactly at the band edge is left alone.  A
    band that is not above 0 and below 50 points raises ValueError.

    *contribution* is None for an unfunded run, or a weekly funding dict, which
    the run is handed as its own funding schedule.  A funded run keeps the same
    decide and band: its opening half-buy is ordered only when the starting cash
    is above 0, and each deposit that lands sits in cash until the band
    triggers a rebalance, which then trades the holding back to half.
    """
    band = _decimal(band_pts, "band_pts")
    if not D("0") < band < FIFTY:
        raise ValueError(
            f"band_pts must be above 0 and below {FIFTY}: {band_pts!r}"
        )
    edge = band / HUNDRED
    start = _decimal(cash, "cash")

    def decide(context):
        close = context.bars[-1].close
        held = context.base * close
        equity = context.cash + held
        if equity <= 0:
            return None
        weight = held / equity
        if abs(weight - HALF) <= edge:
            return None
        target = equity / 2
        diff = target - held
        if diff > 0:
            return [Order(BUY, notional=diff)]
        if diff < 0:
            return [Order(SELL, qty=-diff / close)]
        return None

    opening = [Order(BUY, notional=start / 2)] if start > 0 else []
    return simulate(
        bars,
        events,
        decide,
        start,
        D("0"),
        costs,
        initial_orders=opening,
        max_gap=max_gap,
        contribution=contribution,
    )