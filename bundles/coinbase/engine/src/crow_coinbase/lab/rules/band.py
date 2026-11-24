"""R1: hold the asset near half the book, trading only when the band is left.

The hypothesis: a pair that swings around a level leaves a holding that drifts
away from its target share, and trimming that drift back to a fixed edge turns
the swing into a small, repeatable gain that survives the taker fee.  The band is
a share of equity either side of one half, so a wide band trades seldom and a
narrow one trades often; whatever the width, a rule that only acts on the drift
does nothing while the holding sits inside its band.

The rule acts on the drift alone: once the holding's share of equity has left
the band it is taken back to the edge it crossed, never past it, and a holding
exactly on an edge does nothing.  It reads the bars up to the bar it is asked at
and nothing later.
"""

from __future__ import annotations

from decimal import Decimal

from .base import HALF, base_weight, orders_to_weight

D = Decimal

__all__ = [
    "ASSETS",
    "GRID",
    "HYPOTHESIS",
    "INITIAL_BASE_FRACTION",
    "RULE_ID",
    "SIMULATOR",
    "make",
]

RULE_ID = "band"

# The answer is market orders filled at the next open, so the market simulator.
SIMULATOR = "market"

HYPOTHESIS = (
    "a holding that has drifted out of a fixed band around half of equity, taken "
    "back to the edge of that band, earns the swing of a ranging pair"
)

GRID = [
    {"band_pts": band_pts} for band_pts in (4, 5, 6, 7.5, 10)
]

ASSETS = ("crypto",)

INITIAL_BASE_FRACTION = D("0.5")

PERCENT = D("100")


def make(params: dict):
    """A decide that trims the holding back to the edge it crossed.

    `band_pts` is the band's half width in percentage points of equity, so 5
    puts the edges at 0.45 and 0.55 of the book.  The decide answers with the
    market orders that take the holding to the edge, or with None when the
    holding is inside the band (or its share cannot be read at all).
    """
    half_width = D(str(params["band_pts"])) / PERCENT
    upper = HALF + half_width
    lower = HALF - half_width

    def decide(ctx):
        weight = base_weight(ctx)
        if weight is None:
            return None
        if weight > upper:
            return orders_to_weight(ctx, upper)
        if weight < lower:
            return orders_to_weight(ctx, lower)
        return None

    return decide