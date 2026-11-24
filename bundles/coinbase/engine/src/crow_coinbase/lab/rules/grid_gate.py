"""R3: build the ladder only while the series reads as mean-reverting.

The hypothesis: a ladder of resting rungs is paid the spread of a series that
comes back to where it was, and is run over by one that keeps going, so the
ladder should stand only while the recent walk looks mean-reverting rather than a
random walk.  The reading is a variance ratio: the spread of `q`-bar changes
over the spread of one-bar changes, which sits near one for a random walk, above
one for a trending series and below one for a series that reverts.  A
standardised value of that ratio is compared against a fixed bar, and the ladder
is armed while the value is at or below it.

The ladder's spacing is the series' own recent one-bar spread, scaled by `k` and
by the square root of the horizon, with a floor so a quiet stretch cannot stack
rungs on top of each other.  Every read is of the bars up to the bar the rule is
asked at.

Nothing here needs more than the arithmetic of a list of prices: the ratio is
taken over the logs of the closes, and the answers are the arm gate and the
spacing.
"""

from __future__ import annotations

import math
import statistics
from decimal import Decimal
from typing import Optional

from ..sim import Gates
from .base import HALF, base_weight

D = Decimal

__all__ = [
    "ASSETS",
    "GRID",
    "HYPOTHESIS",
    "INITIAL_BASE_FRACTION",
    "RULE_ID",
    "SIMULATOR",
    "VR_ARM_Z",
    "grid_step",
    "initial_grid",
    "is_open",
    "make",
    "variance_ratio",
]

RULE_ID = "grid_gate"

# The answer is a decision about a ladder, so the grid simulator.
SIMULATOR = "grid"

HYPOTHESIS = (
    "a grid earns a series that reverts and is run over by one that walks, so "
    "the ladder stands only while the recent variance ratio reads as "
    "mean-reverting"
)

GRID = [
    {
        "q": q,
        "k": k,
        "lookback": 60,
        "floor_pct": 0.015,
        "levels": 3,
        "quote_per_buy": 250,
    }
    for q in (2, 4)
    for k in (1.0, 1.5)
]

ASSETS = ("crypto",)

INITIAL_BASE_FRACTION = D("0.5")

# The standardised variance ratio at or below which the ladder stands.
VR_ARM_Z = -1.645

# A spread at or below this is no spread at all, so a ratio cannot be formed.
NO_SPREAD = 1e-18


# ---------------------------------------------------------------- parameters


def _number(params: dict, key: str) -> float:
    """A config value as a float."""
    return float(D(str(params[key])))


def _count(params: dict, key: str) -> int:
    """A config value as a whole number."""
    return int(D(str(params[key])))


# ---------------------------------------------------------------- the ratio


def variance_ratio(log_prices: list, q: int) -> Optional[tuple]:
    """The variance ratio at horizon *q* and a standardised value of it.

    With `X` the log prices and `N` the number of one-bar changes,
    `dX[k] = X[k] - X[k-1]` and `mu` the mean change, the one-bar spread is
    `sum (dX[k] - mu)**2 / (N - 1)` and the `q`-bar spread is
    `sum (X[k] - X[k-q] - q*mu)**2 / m`, with
    `m = q * (N - q + 1) * (1 - q / N)`.  The ratio of the two sits near one for
    a random walk.

    The standardised value divides `ratio - 1` by the square root of a weighted
    sum of lagged products of the centred one-bar changes: for each lag `j` the
    products `(dX[k] - mu)**2 * (dX[k-j] - mu)**2` summed over the changes past
    `j`, divided by the square of the one-bar spread sum, weighted by
    `(2 * (q - j) / q)**2`.

    None when there is no ratio to form: a horizon below two, a series no longer
    than the horizon, no spread in the one-bar changes, or a weight sum that is
    not positive.
    """
    series = [float(value) for value in log_prices]
    horizon = int(q)
    if horizon < 2:
        return None
    n = len(series) - 1
    if n <= horizon:
        return None

    mu = (series[n] - series[0]) / n
    changes = [series[k] - series[k - 1] for k in range(1, n + 1)]
    squares = [(value - mu) * (value - mu) for value in changes]
    spread_sum = math.fsum(squares)
    sigma_a = spread_sum / (n - 1)
    if sigma_a <= NO_SPREAD:
        return None

    scale = horizon * (n - horizon + 1) * (1.0 - horizon / n)
    sigma_c = (
        math.fsum(
            (series[k] - series[k - horizon] - horizon * mu) ** 2
            for k in range(horizon, n + 1)
        )
        / scale
    )
    ratio = sigma_c / sigma_a

    theta = 0.0
    for lag in range(1, horizon):
        weight = (2.0 * (horizon - lag) / horizon) ** 2
        products = math.fsum(
            squares[k - 1] * squares[k - lag - 1]
            for k in range(lag + 1, n + 1)
        )
        theta += weight * products / (spread_sum * spread_sum)
    if theta <= 0.0:
        return None
    return ratio, (ratio - 1.0) / math.sqrt(theta)


# ---------------------------------------------------------------- the window


def _window(bars, lookback: int) -> Optional[list]:
    """The last `lookback + 1` bars, or None when there are fewer."""
    rows = list(bars)
    if lookback < 1 or len(rows) < lookback + 1:
        return None
    return rows[len(rows) - (lookback + 1) :]


def grid_step(params: dict, bars) -> Optional[D]:
    """The ladder's spacing as a share of price, or None.

    The one-bar log returns of the last `lookback + 1` closes give a sample
    standard deviation, which is scaled by `k` and by the square root of the
    horizon; the result is held at or above `floor_pct`.  None when the window
    is too short to give a spread.
    """
    lookback = _count(params, "lookback")
    horizon = _count(params, "q")
    window = _window(bars, lookback)
    if window is None or lookback < 2:
        return None
    returns = [
        math.log(float(window[index].close) / float(window[index - 1].close))
        for index in range(1, len(window))
    ]
    spread = statistics.stdev(returns)
    step = max(
        _number(params, "k") * spread * math.sqrt(horizon),
        _number(params, "floor_pct"),
    )
    return D(str(step))


def is_open(params: dict, bars) -> Optional[bool]:
    """Whether the ladder stands at the last bar of *bars*, or None.

    The ratio is taken over the logs of the last `lookback + 1` closes at
    horizon `q`, and the answer is True when its standardised value is at or
    below `VR_ARM_Z`.  None when the window is too short or the ratio cannot be
    formed, which is not the same answer as False: nothing is decided there.
    """
    lookback = _count(params, "lookback")
    horizon = _count(params, "q")
    window = _window(bars, lookback)
    if window is None:
        return None
    prices = [math.log(float(bar.close)) for bar in window]
    found = variance_ratio(prices, horizon)
    if found is None:
        return None
    return found[1] <= VR_ARM_Z


# ---------------------------------------------------------------- the rule


def initial_grid(params: dict, history) -> dict:
    """The ladder `simulate_grid` starts from, centred on the last close.

    The spacing is the series' own recent spread and falls back to `floor_pct`
    when there are too few bars to read one.
    """
    rows = history
    total = len(rows)
    if total == 0:
        raise ValueError("initial_grid needs at least one bar to centre on")
    step = grid_step(params, rows)
    if step is None:
        step = D(str(params["floor_pct"]))
    levels = params["levels"]
    return {
        "center": rows[total - 1].close,
        "step_pct": step,
        "levels_below": levels,
        "levels_above": levels,
        "quote_per_buy": D(str(params["quote_per_buy"])),
    }


def make(params: dict):
    """A decide that arms the ladder while the series reads as reverting.

    The bar the ladder comes back is the one that puts the series under the bar
    for the first time: its spacing is the series' own recent spread and its
    centre leans against the holding, so a book heavy in the asset centres the
    ladder below the price and a light one centres it above.
    """
    lookback = _count(params, "lookback")

    def decide_gates(ctx):
        if len(ctx.bars) < lookback + 1:
            return None
        now = is_open(params, ctx.bars)
        if now is None:
            return None
        if not now:
            return Gates(grid_armed=False)
        before = is_open(params, ctx.bars[:-1])
        if before is not True:
            weight = base_weight(ctx)
            if weight is None:
                weight = HALF
            step = grid_step(params, ctx.bars)
            row = ctx.bars[len(ctx.bars) - 1]
            center = row.close * (D("1") - (weight - HALF) * D("2") * step)
            return Gates(grid_armed=True, recenter_to=center, step_pct=step)
        return Gates(grid_armed=True)

    return decide_gates