"""The shape every rule module carries, and the weight arithmetic rules share.

A rule module is an object with `RULE_ID`, `HYPOTHESIS`, `GRID` (one dict of
parameters per config), `ASSETS`, `INITIAL_BASE_FRACTION`, a `SIMULATOR` naming
the simulator that reads its answer, and a `make(params)` that builds the decide
callable the simulator drives; a rule a grid simulator drives also carries an
`initial_grid(params, history)`.  A rule whose schedule pays for itself carries
`FUNDING`, the fixed weekly contribution its buys spend.  `check_rule_module`
reads that shape without running the rule, `require_asset` refuses a rule handed
costs for an asset class it does not declare, and the weight helpers turn a
target holding into the market orders that reach it.

Every rule reads the context it is handed and nothing else: the bars up to the
bar it is asked at, the events already announced by then, the cash, the base
holding and the bar's own stamp.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Optional

from ..costs import BUY, SELL, Order

D = Decimal

__all__ = [
    "HALF",
    "base_weight",
    "check_rule_module",
    "closes",
    "orders_to_weight",
    "require_asset",
]

# Half the book in the asset is the neutral holding the rules that follow are
# written around.
HALF = D("0.5")

# The asset classes a rule may declare in its ASSETS.
ASSET_CLASSES = ("crypto", "stock")

# The simulators a rule's answer can be read by.
SIMULATORS = ("market", "grid")

# A search needs several configs to compare against one another.
MIN_GRID_CONFIGS = 4


# ---------------------------------------------------------------- module shape


def check_rule_module(module) -> None:
    """Refuse *module* with ValueError, naming the field, unless it is a rule.

    A rule carries a non-empty `RULE_ID` and `HYPOTHESIS`, a callable `make`,
    `GRID` as a list of at least `MIN_GRID_CONFIGS` parameter dicts, `ASSETS` as
    a non-empty tuple of asset classes this lab runs, `INITIAL_BASE_FRACTION` as
    a Decimal within [0, 1], and a `SIMULATOR` naming one of `SIMULATORS`.  An
    `initial_grid` is not required here: a market-simulator rule needs none.
    `FUNDING`, when carried, is the fixed weekly contribution the schedule
    spends: a dict whose `amount` is a Decimal above 0 and whose `every` is
    "week".
    """
    rule_id = getattr(module, "RULE_ID", None)
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError(f"RULE_ID must be a non-empty string: {rule_id!r}")

    hypothesis = getattr(module, "HYPOTHESIS", None)
    if not isinstance(hypothesis, str) or not hypothesis:
        raise ValueError(
            f"rule {rule_id!r}: HYPOTHESIS must be a non-empty string, got "
            f"{hypothesis!r}"
        )

    make = getattr(module, "make", None)
    if not callable(make):
        raise ValueError(
            f"rule {rule_id!r}: make must be callable, got {type(make).__name__}"
        )

    grid = getattr(module, "GRID", None)
    if not isinstance(grid, list):
        raise ValueError(
            f"rule {rule_id!r}: GRID must be a list of parameter dicts, got "
            f"{type(grid).__name__}"
        )
    if len(grid) < MIN_GRID_CONFIGS:
        raise ValueError(
            f"rule {rule_id!r}: GRID holds {len(grid)} configs, fewer than the "
            f"{MIN_GRID_CONFIGS} a search needs"
        )
    for index, config in enumerate(grid):
        if not isinstance(config, dict):
            raise ValueError(
                f"rule {rule_id!r}: GRID[{index}] must be a dict, got "
                f"{type(config).__name__}"
            )

    assets = getattr(module, "ASSETS", None)
    if not isinstance(assets, tuple) or not assets:
        raise ValueError(
            f"rule {rule_id!r}: ASSETS must be a non-empty tuple of asset "
            f"classes, got {assets!r}"
        )
    for asset_class in assets:
        if asset_class not in ASSET_CLASSES:
            raise ValueError(
                f"rule {rule_id!r}: ASSETS carries {asset_class!r}, which is "
                f"not one of {list(ASSET_CLASSES)}"
            )

    fraction = getattr(module, "INITIAL_BASE_FRACTION", None)
    if not isinstance(fraction, D):
        raise ValueError(
            f"rule {rule_id!r}: INITIAL_BASE_FRACTION must be a Decimal, got "
            f"{type(fraction).__name__}"
        )
    if fraction < 0 or fraction > 1:
        raise ValueError(
            f"rule {rule_id!r}: INITIAL_BASE_FRACTION must sit within [0, 1], "
            f"got {fraction}"
        )

    simulator = getattr(module, "SIMULATOR", None)
    if simulator not in SIMULATORS:
        raise ValueError(
            f"rule {rule_id!r}: SIMULATOR must be one of {list(SIMULATORS)}, "
            f"got {simulator!r}"
        )

    funding = getattr(module, "FUNDING", None)
    if funding is not None:
        if not isinstance(funding, dict):
            raise ValueError(
                f"rule {rule_id!r}: FUNDING must be a dict, got "
                f"{type(funding).__name__}"
            )
        amount = funding.get("amount")
        if not isinstance(amount, D) or amount <= 0:
            raise ValueError(
                f"rule {rule_id!r}: FUNDING 'amount' must be a Decimal above "
                f"0, got {amount!r}"
            )
        every = funding.get("every")
        if every != "week":
            raise ValueError(
                f"rule {rule_id!r}: FUNDING 'every' must be 'week', got "
                f"{every!r}"
            )


def require_asset(module, asset_class: str) -> None:
    """Refuse *asset_class* with ValueError when the rule does not declare it."""
    assets = tuple(getattr(module, "ASSETS", ()) or ())
    if asset_class not in assets:
        raise ValueError(
            f"asset class {asset_class!r} is not in rule "
            f"{getattr(module, 'RULE_ID', '?')!r}'s ASSETS {assets}"
        )


# ---------------------------------------------------------------- reads


def closes(bars, n: int) -> list:
    """The last *n* closes of *bars*, oldest first, and fewer when there are fewer.

    *bars* is a read-only window or a plain list, so the window a rule is handed
    answers here without being copied.
    """
    rows = list(bars)
    count = int(n)
    if count <= 0 or not rows:
        return []
    return [bar.close for bar in rows[len(rows) - count :]]


# ---------------------------------------------------------------- weights


def _at_latest(bars):
    """The latest bar, or None when the window holds none."""
    rows = bars
    total = len(rows)
    if total == 0:
        return None
    return rows[total - 1]


def base_weight(ctx) -> Optional[D]:
    """The holding's share of equity at the latest close, or None.

    None when there is no bar to mark against, or when equity — cash plus the
    holding at that close — is not positive, because a share of nothing is not
    a target a rule can act on.
    """
    bar = _at_latest(ctx.bars)
    if bar is None:
        return None
    equity = ctx.cash + ctx.base * bar.close
    if equity <= 0:
        return None
    return ctx.base * bar.close / equity


def orders_to_weight(ctx, target: D) -> tuple:
    """The market orders that take the holding to *target* of equity.

    Equity is marked at the latest close, so the sale size is the difference
    over that close.  A target above the holding buys the difference in notional
    and one below it sells the units that difference is worth; a target equal to
    the holding trades nothing.  An empty window, or an equity that is not
    positive, answers with no orders at all.
    """
    bar = _at_latest(ctx.bars)
    if bar is None:
        return ()
    price = bar.close
    if price <= 0:
        return ()
    equity = ctx.cash + ctx.base * price
    if equity <= 0:
        return ()
    diff = D(str(target)) * equity - ctx.base * price
    if diff > 0:
        return (Order(BUY, notional=diff),)
    if diff < 0:
        return (Order(SELL, qty=-diff / price),)
    return ()