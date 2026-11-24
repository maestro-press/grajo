"""The intrabar limit-fill grid simulator for the research lab.

A grid is a ladder of limit rungs around a centre price with arithmetic
spacing: level j sits at `center * (1 + j * step_pct)`.  Two adjacent levels are
a pair, and a pair carries at most one resting order — a BUY at its lower level
while the pair is empty, or a SELL at its upper level once a buy has filled on
it, or once a build has allocated part of the holding to it.  A fill on one side
of a pair re-arms the other side for the next bar only, never inside the bar it
filled on.

A rung that is already marketable the moment it becomes live — the bar's open
is at or through its limit — fills at that open as a taker.  Which open price
it takes depends on where the rung came from: a rung the build placed at a gate
boundary pays the open with slippage against the trade, capped at its own
limit, while a rung a fill re-armed on the previous bar fills at exactly its own
limit.  Every other rung stays resting and fills at exactly its own limit price
as a maker, and only when the bar trades through it: a buy needs `low < limit`,
a sell needs `high > limit`.  Reaching a limit is not trading through it, and no
slippage is charged on a maker fill.

A bar that would fill both a buy and a sell is decided against the strategy: the
two processing orders (buys first, and sells first, each side nearest the open
first, takers before makers) are valued on the cash and holding the bar opened
with, and the order that ends the bar with the lower equity is the one kept; an
equal outcome keeps the buys-first order.

Cash and inventory are enforced fill by fill.  An order the run cannot settle
stays resting and is flagged.  Gates apply at each bar boundary: the grid can be
disarmed, which takes every rung off the book, and re-armed or re-centred, which
rebuilds the ladder from that bar's close and the holding the run has left, or
given a new step, which rebuilds it around the centre it already has.

Accounting matches the market-fill simulator: every fill goes through the FIFO
lot book, tax is paid in cash at the first bar of a new year, equity marks at
each close, and the result also reports the equity net of the tax that closing
the book would cost.  It also names the modelling gaps every run leaves, and
counts the wash-sale matches on the final book.

Nothing here reaches an exchange: a fill is arithmetic on a bar.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR
from typing import Optional

from .costs import BUY, SELL, CostModel, Lots, liquidation_tax, tax_due
from .sim import (
    INTERVAL_LENGTH,
    STOCK_MAX_GAP,
    UNMODELLED,
    Flag,
    Gates,
    LabContext,
    PastBars,
    SimResult,
    _Ledger,
    _accepted,
    _at_least_zero,
    _check_bars,
    _decimal,
    _floor_to,
    _utc,
)
from .store import Bar, Event

D = Decimal

__all__ = ["GridResult", "simulate_grid"]

PARAM_KEYS = ("center", "step_pct", "levels_below", "levels_above", "quote_per_buy")


# ---------------------------------------------------------------- value helpers


def _whole(value: object, name: str) -> int:
    """A non-negative whole number from an int, or an integral Decimal/str."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a whole number, not bool: {value!r}")
    if isinstance(value, int):
        out = value
    else:
        counted = _decimal(value, name)
        whole = counted.to_integral_value()
        if whole != counted:
            raise ValueError(f"{name} must be a whole number: {value!r}")
        out = int(whole)
    if out < 0:
        raise ValueError(f"{name} must not be negative: {value!r}")
    return out


def _params(values: object) -> tuple:
    """The five grid fields, validated, as (center, step, below, above, quote)."""
    if not isinstance(values, Mapping):
        raise ValueError(
            f"grid_params must be a mapping, got {type(values).__name__}"
        )
    for key in PARAM_KEYS:
        if key not in values:
            raise ValueError(f"grid_params is missing {key!r}")
    center = _decimal(values["center"], "center")
    step = _decimal(values["step_pct"], "step_pct")
    quote = _decimal(values["quote_per_buy"], "quote_per_buy")
    below = _whole(values["levels_below"], "levels_below")
    above = _whole(values["levels_above"], "levels_above")
    if center <= 0:
        raise ValueError(f"center must be positive: {values['center']!r}")
    if step <= 0:
        raise ValueError(f"step_pct must be positive: {values['step_pct']!r}")
    if quote <= 0:
        raise ValueError(
            f"quote_per_buy must be positive: {values['quote_per_buy']!r}"
        )
    return center, step, below, above, quote


def _levels(center: D, step: D, below: int, above: int) -> list:
    """The ladder's levels, ascending, exact in Decimal arithmetic."""
    out = []
    for offset in range(-below, above + 1):
        level = center * (D("1") + D(offset) * step)
        if level <= 0:
            raise ValueError(
                f"level {offset} of a grid centred on {center} at step {step} "
                f"is not positive: {level}"
            )
        out.append(level)
    return out


def _round_price(price: D, step: Optional[D], upward: bool) -> D:
    """*price* on the product's price step, up for a sale and down for a buy."""
    if step is None:
        return price
    rounding = ROUND_CEILING if upward else ROUND_FLOOR
    return (price / step).to_integral_value(rounding=rounding) * step


def _pair_qty(quote_per_buy: D, level: D, base_step: Optional[D]) -> D:
    """The size a pair trades: the quote outlay over its lower level, floored."""
    return _floor_to(quote_per_buy / level, base_step)


# ---------------------------------------------------------------- the ladder


@dataclass
class _Rung:
    """One pair's resting order: the side it offers, its limit and its size.

    `boundary` says where the rung came from: True for one the build placed at a
    gate boundary (start, re-centre, re-arm after a disarm), which fills at the
    open with slippage capped at its limit; False for one a fill re-armed on the
    previous bar, which fills at its own limit.
    """

    side: str
    price: D
    qty: D
    fresh: bool = True
    bought: bool = False
    boundary: bool = True


@dataclass(frozen=True)
class _Fill:
    """One fill a bar would produce, before cash and holdings are consulted."""

    pair: int
    side: str
    price: D
    qty: D
    rate: D
    maker: bool


@dataclass
class _Grid:
    """The ladder built at one boundary, and the rungs standing on it."""

    center: D
    buy_price: list
    sell_price: list
    buy_qty: list
    rungs: list


@dataclass
class _Tally:
    """The run's completed round trips."""

    round_trips: int = 0


@dataclass
class GridResult(SimResult):
    """A `SimResult` plus the buy-then-sell pairs the run completed."""

    round_trips: int = 0


def _build_grid(
    center: D,
    step: D,
    below: int,
    above: int,
    quote_per_buy: D,
    reference: D,
    base: D,
    costs: CostModel,
    ts: datetime,
) -> tuple:
    """Build the ladder around *center* from *reference* and the *base* held.

    Every pair below the reference price is a BUY at its lower level.  A pair at
    or above the reference is a SELL at its upper level, which needs inventory:
    the holding is allocated from the lowest pair upward, and a pair whose size
    the unallocated holding cannot cover stays empty and is flagged.
    """
    levels = _levels(center, step, below, above)
    increments = costs.increments
    quote_step = increments.quote if increments is not None else None
    base_step = increments.base if increments is not None else None

    pairs = len(levels) - 1
    buy_price: list = []
    sell_price: list = []
    buy_qty: list = []
    for pair in range(pairs):
        lower, upper = levels[pair], levels[pair + 1]
        buy_price.append(_round_price(lower, quote_step, upward=False))
        sell_price.append(_round_price(upper, quote_step, upward=True))
        buy_qty.append(_pair_qty(quote_per_buy, lower, base_step))

    rungs: list = [None] * pairs
    flags: list = []
    unallocated = base
    for pair in range(pairs):
        qty = buy_qty[pair]
        if qty <= 0:
            traded = quote_per_buy / levels[pair]
            flags.append(
                Flag(
                    "below_increment",
                    ts,
                    f"a pair at {levels[pair]} trades {traded}, below one "
                    f"size step {base_step}",
                )
            )
            continue
        if levels[pair] < reference:
            rungs[pair] = _Rung(side=BUY, price=buy_price[pair], qty=qty)
            continue
        if qty > unallocated:
            flags.append(
                Flag(
                    "insufficient_base",
                    ts,
                    f"a pair selling {qty} at {sell_price[pair]} has only "
                    f"{unallocated} of the holding left to allocate",
                )
            )
            continue
        unallocated -= qty
        rungs[pair] = _Rung(side=SELL, price=sell_price[pair], qty=qty)

    return _Grid(
        center=center,
        buy_price=buy_price,
        sell_price=sell_price,
        buy_qty=buy_qty,
        rungs=rungs,
    ), flags


# ---------------------------------------------------------------- fills


def _due_fills(rungs: list, bar: Bar, costs: CostModel) -> list:
    """Every fill this bar produces, taker and maker, before cash is checked.

    A live rung the bar's open has already reached fills at that open: a rung
    the build placed at a boundary pays the open with slippage against the
    trade, capped at its limit, and a rung a fill re-armed pays its own limit.
    """
    slippage = costs.slippage
    fills: list = []
    for pair, rung in enumerate(rungs):
        if rung is None:
            continue
        if rung.fresh and rung.side == BUY and rung.price >= bar.open:
            if rung.boundary:
                price = min(bar.open * (D("1") + slippage), rung.price)
            else:
                price = rung.price
            fills.append(
                _Fill(
                    pair=pair,
                    side=BUY,
                    price=price,
                    qty=rung.qty,
                    rate=costs.taker,
                    maker=False,
                )
            )
            continue
        if rung.fresh and rung.side == SELL and rung.price <= bar.open:
            if rung.boundary:
                price = max(bar.open * (D("1") - slippage), rung.price)
            else:
                price = rung.price
            fills.append(
                _Fill(
                    pair=pair,
                    side=SELL,
                    price=price,
                    qty=rung.qty,
                    rate=costs.taker,
                    maker=False,
                )
            )
            continue
        if rung.side == BUY and bar.low < rung.price:
            fills.append(
                _Fill(
                    pair=pair,
                    side=BUY,
                    price=rung.price,
                    qty=rung.qty,
                    rate=costs.maker,
                    maker=True,
                )
            )
        elif rung.side == SELL and bar.high > rung.price:
            fills.append(
                _Fill(
                    pair=pair,
                    side=SELL,
                    price=rung.price,
                    qty=rung.qty,
                    rate=costs.maker,
                    maker=True,
                )
            )
    return fills


def _distance(fill: _Fill, bar: Bar) -> tuple:
    """Nearest the bar's open first, then lowest pair, for a stable order."""
    gap = bar.open - fill.price
    return (gap if gap >= 0 else -gap, fill.pair)


def _ordered(fills: list, bar: Bar) -> list:
    """One side's fills in processing order: takers first, each nearest the open."""
    takers = [fill for fill in fills if not fill.maker]
    makers = [fill for fill in fills if fill.maker]
    return sorted(takers, key=lambda fill: _distance(fill, bar)) + sorted(
        makers, key=lambda fill: _distance(fill, bar)
    )


def _outcome(ledger: _Ledger, plan: list, close: D) -> D:
    """The end-of-bar equity *plan* would leave, enforcing cash and holdings.

    Only cash and the holding decide which fills of an order settle, so this is
    the same arithmetic the ledger performs, without touching the lot book.
    """
    cash, base = ledger.cash, ledger.base
    for fill in plan:
        notional = fill.qty * fill.price
        fee = notional * fill.rate
        if fill.side == BUY:
            if notional + fee > cash:
                continue
            cash -= notional + fee
            base += fill.qty
        else:
            if fill.qty > base:
                continue
            cash += notional - fee
            base -= fill.qty
    return cash + base * close


def _apply(
    ledger: _Ledger,
    grid: _Grid,
    plan: list,
    bar: Bar,
    flags: list,
    tally: _Tally,
) -> int:
    """Settle *plan* in order; returns how many fills settled.

    A buy the cash cannot cover and a sale the holding cannot cover are skipped:
    that rung stays where it is, and the bar is flagged.
    """
    settled = 0
    for fill in plan:
        rung = grid.rungs[fill.pair]
        if rung is None or rung.side != fill.side:
            continue
        notional = fill.qty * fill.price
        fee = notional * fill.rate
        if fill.side == BUY:
            if notional + fee > ledger.cash:
                flags.append(
                    Flag(
                        "insufficient_cash",
                        bar.ts,
                        f"a buy of {fill.qty} at {fill.price} needs "
                        f"{notional + fee} with {ledger.cash} in cash",
                    )
                )
                rung.fresh = False
                continue
            ledger.fill_at(bar, BUY, fill.qty, fill.price, fill.rate, fill.maker)
            # The pair now offers the sale of what it bought, at its own limit.
            rung.side = SELL
            rung.price = grid.sell_price[fill.pair]
            rung.fresh = True
            rung.bought = True
            rung.boundary = False
        else:
            if fill.qty > ledger.base:
                flags.append(
                    Flag(
                        "insufficient_base",
                        bar.ts,
                        f"a sale of {fill.qty} at {fill.price} with "
                        f"{ledger.base} held",
                    )
                )
                rung.fresh = False
                continue
            ledger.fill_at(bar, SELL, fill.qty, fill.price, fill.rate, fill.maker)
            if rung.bought:
                tally.round_trips += 1
                rung.bought = False
            # The pair waits to buy its step back, at its own limit.
            rung.side = BUY
            rung.price = grid.buy_price[fill.pair]
            rung.qty = grid.buy_qty[fill.pair]
            rung.fresh = True
            rung.boundary = False
        settled += 1
    return settled


def _fill_bar(
    ledger: _Ledger,
    grid: _Grid,
    bar: Bar,
    costs: CostModel,
    flags: list,
    tally: _Tally,
) -> bool:
    """Fill what this bar reaches; True when anything settled.

    Every rung that survives the bar stops being fresh: only a rung built or
    re-armed at this bar's boundary is marketable at the next open.
    """
    fills = _due_fills(grid.rungs, bar, costs)
    for rung in grid.rungs:
        if rung is not None:
            rung.fresh = False
    if not fills:
        return False
    buys = [fill for fill in fills if fill.side == BUY]
    sells = [fill for fill in fills if fill.side == SELL]
    plan = _ordered(buys, bar) + _ordered(sells, bar)
    if buys and sells:
        other = _ordered(sells, bar) + _ordered(buys, bar)
        if _outcome(ledger, other, bar.close) < _outcome(ledger, plan, bar.close):
            plan = other
    return _apply(ledger, grid, plan, bar, flags, tally) > 0


# ---------------------------------------------------------------- the run


def simulate_grid(
    bars: list,
    events: list,
    decide_gates,
    grid_params: dict,
    start_cash: D,
    start_base: D,
    costs: CostModel,
    *,
    initial_orders=(),
    max_gap: Optional[timedelta] = None,
) -> GridResult:
    """Run one intrabar limit-fill grid simulation over *bars*.

    *start_base* is already held when bar 0 opens: one lot acquired at that
    stamp for the first open, with no fee.  *initial_orders* are market orders
    filled at bar 0's open before anything else, and before the first ladder is
    built, so the grid sees the holding they leave.  *decide_gates* is handed a
    `LabContext` at each bar, after that bar's fills and equity mark, and
    answers with a `Gates` (or None, meaning `Gates()`) that applies at the
    boundary it was asked at.  A `step_pct` in those gates is the spacing of a
    rebuilt ladder: one that differs from the spacing the run holds rebuilds
    the ladder around its current centre (or around `recenter_to`, when that is
    also given) at the new spacing and becomes the spacing from then on, one
    equal to the current spacing changes nothing, and None leaves the spacing
    alone; zero or a negative value is refused.  `band_pts` carries no meaning
    here, and a `veto_buys_until` is refused: the grid has no buy veto to apply
    it to.  A gap longer than *max_gap* between two bars a fill lands on is
    flagged.  The result's `notes` name the modelling gaps the run leaves and
    `wash_sale_count` is how many wash-sale matches the final book carries.
    """
    rows = bars if isinstance(bars, list) else list(bars)
    _check_bars(rows)
    if not isinstance(costs, CostModel):
        raise ValueError(f"costs must be a CostModel, got {type(costs).__name__}")
    center, current_step, below, above, quote_per_buy = _params(grid_params)
    cash = _at_least_zero(start_cash, "start_cash")
    base = _at_least_zero(start_base, "start_base")
    if not callable(decide_gates):
        raise ValueError(
            f"decide_gates must be callable, got {type(decide_gates).__name__}"
        )
    first = rows[0]
    if max_gap is None:
        max_gap = (
            INTERVAL_LENGTH[first.interval]
            if costs.asset_class == "crypto"
            else STOCK_MAX_GAP
        )
    if not isinstance(max_gap, timedelta) or max_gap <= timedelta(0):
        raise ValueError(f"max_gap must be a positive timedelta: {max_gap!r}")

    event_list = list(events or ())
    for event in event_list:
        if not isinstance(event, Event):
            raise ValueError(f"expected an Event, got {type(event).__name__}")
        _utc(event.announced_at, "event.announced_at")

    book = Lots(costs.asset_class)
    if base > 0:
        book.buy(first.ts, base, first.open)
    ledger = _Ledger(costs, book, cash, base)

    curve: list[tuple[datetime, D]] = []
    tax_payments: list[tuple[datetime, D]] = []
    flags: list = []
    dropped: list = []
    tally = _Tally()
    grid: Optional[_Grid] = None
    armed = False
    pending = _accepted(tuple(initial_orders))

    for index, bar in enumerate(rows):
        if index > 0:
            previous = rows[index - 1]
            if bar.ts.year != previous.ts.year:
                due = sum(tax_due(ledger.realized, costs).values(), D("0"))
                paid = sum((amount for _, amount in tax_payments), D("0"))
                amount = due - paid
                if amount != 0:
                    ledger.cash -= amount
                    tax_payments.append((bar.ts, amount))
                    if ledger.cash < 0:
                        flags.append(
                            Flag(
                                "tax_cash_shortfall",
                                bar.ts,
                                f"a tax payment of {amount} leaves cash "
                                f"{ledger.cash}",
                            )
                        )
        filled = False
        if pending:
            for order in pending:
                if ledger.fill_market(order, bar, dropped, flags):
                    filled = True
            pending = []
        if grid is not None and armed:
            filled = _fill_bar(ledger, grid, bar, costs, flags, tally) or filled
        if index > 0 and filled:
            gap = bar.ts - rows[index - 1].ts
            if gap > max_gap:
                flags.append(
                    Flag(
                        "gap_fill",
                        bar.ts,
                        f"a fill came {gap} after the previous bar",
                    )
                )
        curve.append((bar.ts, ledger.equity(bar.close)))

        visible = [event for event in event_list if event.announced_at <= bar.ts]
        context = LabContext(
            bars=PastBars(rows, index + 1),
            events=visible,
            cash=ledger.cash,
            base=ledger.base,
            lots=ledger.book.open_copy(),
            now=bar.ts,
        )
        gates = decide_gates(context)
        if gates is None:
            gates = Gates()
        elif not isinstance(gates, Gates):
            raise ValueError(
                f"decide_gates must return a Gates or None, got "
                f"{type(gates).__name__}"
            )
        if gates.veto_buys_until is not None:
            raise ValueError(
                "veto_buys_until is not supported by the grid simulator"
            )

        requested_step: Optional[D] = None
        if gates.step_pct is not None:
            requested_step = _decimal(gates.step_pct, "step_pct")
            if requested_step <= 0:
                raise ValueError(
                    f"step_pct must be positive: {gates.step_pct!r}"
                )

        if not gates.grid_armed:
            armed = False
            if grid is not None:
                grid.rungs = [None] * len(grid.rungs)
            continue
        wanted: Optional[D] = None
        if gates.recenter_to is not None:
            wanted = _decimal(gates.recenter_to, "recenter_to")
            if wanted <= 0:
                raise ValueError(
                    f"recenter_to must be positive: {gates.recenter_to!r}"
                )
        elif grid is None:
            wanted = center
        elif not armed:
            # Re-armed after a disarm: the last centre used is the one rebuilt.
            wanted = grid.center
        if requested_step is not None and requested_step != current_step:
            # A new spacing rebuilds the ladder around the centre it already
            # has, or around the one `recenter_to` names when that is given too.
            current_step = requested_step
            if wanted is None:
                wanted = grid.center
        if wanted is not None:
            grid, build_flags = _build_grid(
                wanted,
                current_step,
                below,
                above,
                quote_per_buy,
                bar.close,
                ledger.base,
                costs,
                bar.ts,
            )
            flags.extend(build_flags)
        armed = True

    last = rows[-1]
    ledger.book.settle()
    paid = sum((amount for _, amount in tax_payments), D("0"))
    final_equity = ledger.equity(last.close)
    liquidation = liquidation_tax(
        ledger.book, ledger.realized, paid, last.close, last.ts, costs
    )
    return GridResult(
        curve=curve,
        trades=ledger.trades,
        fees=ledger.fees,
        realized=ledger.realized,
        taxes_by_year=tax_due(ledger.realized, costs),
        tax_payments=tax_payments,
        final_cash=ledger.cash,
        final_base=ledger.base,
        final_equity=final_equity,
        final_equity_after_liquidation_tax=final_equity - liquidation,
        flags=flags,
        dropped=dropped,
        notes=list(UNMODELLED),
        wash_sale_count=len(ledger.book.wash_sale_flags()),
        round_trips=tally.round_trips,
    )