"""R2: run the ladder only while price sits inside its own recent channel.

The hypothesis: a ladder of resting rungs earns the oscillation of a ranging
market and is run over by a trend, so the ladder should stand while price is
inside a channel and come down while price walks out of one.  The channel is the
highest high and the lowest low of the `n` bars before the latest one, so a
latest close above that high is an up state, below that low a down state, and
anything else is a range.

The gate answers the grid simulator: armed while the state is range (and
re-centred on the latest close at the bar the state becomes range again, since a
range entered from a trend is a fresh level), disarmed while it is up or down.
The rule reads the bars up to the bar it is asked at and nothing later.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Optional

from ..sim import Gates
from .base import closes

D = Decimal

__all__ = [
    "ASSETS",
    "DOWN",
    "GRID",
    "HYPOTHESIS",
    "INITIAL_BASE_FRACTION",
    "RANGE",
    "RULE_ID",
    "SIMULATOR",
    "UP",
    "initial_grid",
    "make",
    "regime_state",
]

RULE_ID = "regime"

# The answer is a decision about a ladder, so the grid simulator.
SIMULATOR = "grid"

HYPOTHESIS = (
    "a grid earns a ranging market and is run over by a trending one, so it is "
    "built while price stays inside its recent channel and is taken down as "
    "soon as price leaves it"
)

GRID = [
    {"n": n, "step_pct": 0.02, "levels": 3, "quote_per_buy": 250}
    for n in (10, 20, 40, 80)
]

ASSETS = ("crypto",)

INITIAL_BASE_FRACTION = D("0.5")

UP, DOWN, RANGE = "up", "down", "range"


# ---------------------------------------------------------------- the channel


def regime_state(bars, n: int) -> Optional[str]:
    """`up`, `down` or `range` for the latest bar of *bars*, or None.

    The channel is built from the `n` bars before the latest one, so the latest
    close is compared against a window it does not belong to.  None when there
    are fewer than `n + 1` bars to read.
    """
    rows = bars
    count = int(n)
    total = len(rows)
    if count < 1 or total < count + 1:
        return None
    latest = total - 1
    window = rows[latest - count : latest]
    high = max(bar.high for bar in window)
    low = min(bar.low for bar in window)
    close = rows[latest].close
    if close > high:
        return UP
    if close < low:
        return DOWN
    return RANGE


# ---------------------------------------------------------------- the rule


def initial_grid(params: dict, history) -> dict:
    """The ladder `simulate_grid` starts from, centred on the last close.

    `history` is a read-only window ending at the bar the ladder is built from,
    so the centre is that bar's own close.
    """
    rows = history
    total = len(rows)
    if total == 0:
        raise ValueError("initial_grid needs at least one bar to centre on")
    levels = params["levels"]
    return {
        "center": rows[total - 1].close,
        "step_pct": D(str(params["step_pct"])),
        "levels_below": levels,
        "levels_above": levels,
        "quote_per_buy": D(str(params["quote_per_buy"])),
    }


def make(params: dict):
    """A decide that arms the ladder in a range and disarms it in a trend."""
    count = int(D(str(params["n"])))

    def decide_gates(ctx):
        if len(ctx.bars) < count + 2:
            return None
        now = regime_state(ctx.bars, count)
        before = regime_state(ctx.bars[:-1], count)
        if now in (UP, DOWN):
            return Gates(grid_armed=False)
        if now == RANGE and before != RANGE:
            # A range after a trend is a fresh level: the ladder is rebuilt
            # around the close that put price back inside the channel.
            return Gates(grid_armed=True, recenter_to=closes(ctx.bars, 1)[0])
        return Gates(grid_armed=True)

    return decide_gates