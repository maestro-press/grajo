"""The next-open market-fill simulator for the research lab.

Time is the bar's own open stamp.  At bar `i` a rule is shown bars `0..i` (never
later), the events already announced by that stamp, the cash, the base holding
and the open lots; whatever it asks for is filled at bar `i+1`'s open
and never at the bar it saw.  Fills are taker: a buy pays `open * (1 +
slippage)`, a sell receives `open * (1 - slippage)`, and the fee is the taker
rate on the traded notional.  Sizes are floored to the product's size step.

A run may also be funded: a fixed weekly contribution is added to cash at each
bar that starts a new UTC ISO week, before that bar's orders fill and before the
rule is asked, and the result reports every contribution and their total.  The
curve then rises with the money put in as well as with the holding's own gain.

Every sale goes through the FIFO lot book, so realized pieces and the tax on
them are part of the run.  Tax is paid in cash at the first bar of a new year:
the amount owed over everything realized so far, minus what has already been
paid, which can be negative after a correction.  The equity curve marks the
holding at each bar's close, and the end of the run also reports the equity net
of the tax that closing the book would cost.

Flags record what the numbers alone would hide: a fill after a data gap, an
order the last bar left unfilled, an order that could not be filled at all, a
tax payment that pushed cash negative.  The result also names the modelling
gaps the run leaves (`UNMODELLED`) and how many wash-sale matches the book
ended with.

Nothing here reaches an exchange: a fill is arithmetic on a bar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_FLOOR
from typing import Optional

from .costs import (
    LIMIT,
    CostModel,
    Lots,
    Order,
    RealizedGain,
    liquidation_tax,
    tax_due,
)
from .store import Bar, Event

D = Decimal

__all__ = [
    "Decision",
    "Flag",
    "Gates",
    "LabContext",
    "PastBars",
    "SimResult",
    "Trade",
    "UNMODELLED",
    "reaction_bar_ts",
    "simulate",
]

HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
# One interval of slack for crypto; a weekend plus a holiday for stocks.
STOCK_MAX_GAP = timedelta(days=4)
INTERVAL_LENGTH = {"1h": HOUR, "1d": DAY}

MARKET = "market"
BUY = "BUY"
SELL = "SELL"

POST, PRE, NONE = "post", "pre", "none"

# The modelling gaps every run reports it leaves, in this order.
UNMODELLED = (
    "$3,000 capital loss offset not modelled (conservative)",
    "wash-sale holding-period tacking not modelled (conservative)",
    "unused loss carryforward given zero value at liquidation",
)


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


def _at_least_zero(value: object, name: str) -> D:
    out = _decimal(value, name)
    if out < 0:
        raise ValueError(f"{name} must not be negative: {value!r}")
    return out


def _weekly_amount(value: object) -> Optional[D]:
    """The fixed amount a funded run adds each week, or None when unfunded.

    A schedule is None or a dict carrying `amount`, a positive Decimal, and
    `every` as "week"; anything else is refused.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(
            f"contribution must be None or a dict, not "
            f"{type(value).__name__}: {value!r}"
        )
    if "amount" not in value or "every" not in value:
        raise ValueError(
            f"contribution needs an 'amount' and an 'every': {value!r}"
        )
    amount = value["amount"]
    if not isinstance(amount, Decimal) or amount <= 0:
        raise ValueError(
            f"contribution 'amount' must be a Decimal above 0: {amount!r}"
        )
    every = value["every"]
    if every != "week":
        raise ValueError(
            f"contribution 'every' must be 'week', not {every!r}"
        )
    return amount


def _week_start(bar: Bar, previous: Optional[Bar]) -> bool:
    """Whether *bar* starts a UTC ISO week, the first bar always doing so."""
    if previous is None:
        return True
    return bar.ts.isocalendar()[:2] != previous.ts.isocalendar()[:2]


def _utc(moment: object, name: str) -> datetime:
    """*moment* refused unless it is a timezone-aware datetime, as UTC."""
    if not isinstance(moment, datetime):
        raise ValueError(f"{name} must be a datetime, got {type(moment).__name__}")
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"{name} must be timezone-aware: {moment!r}")
    return moment.astimezone(timezone.utc)


def _floor_to(qty: D, step: Optional[D]) -> D:
    """*qty* rounded down to a multiple of *step* (unchanged when there is none)."""
    if step is None:
        return qty
    return (qty / step).to_integral_value(rounding=ROUND_FLOOR) * step


# ---------------------------------------------------------------- rule surface


@dataclass(frozen=True)
class Gates:
    """What a rule asks the grid simulator to do at the next bar boundary.

    `grid_armed` False takes every rung off the book, and `recenter_to` moves
    the centre the ladder is rebuilt around.  `step_pct`, when given, is the
    spacing that rebuilt ladder uses: a value different from the spacing the
    run already holds asks for a rebuild around the centre it has (or around
    `recenter_to`, when that is also given), and None leaves the spacing alone.
    `veto_buys_until` is the market simulator's buy veto, which the grid
    simulator refuses, and `band_pts` is a band width a rule may carry for its
    own use; neither simulator reads that one.
    """

    grid_armed: bool = True
    recenter_to: Optional[D] = None
    veto_buys_until: Optional[datetime] = None
    band_pts: Optional[D] = None
    step_pct: Optional[D] = None


@dataclass(frozen=True)
class Decision:
    """A rule's answer for one bar: orders to fill next, and grid gates."""

    orders: tuple = ()
    gates: Gates = Gates()


class PastBars:
    """A read-only window over the first *limit* bars of a bar list.

    Nothing is copied: the object keeps the caller's list and a count, so a rule
    cannot see a bar the run has not reached yet and cannot edit the run's data.
    """

    __slots__ = ("_rows", "_limit")

    def __init__(self, rows: list, limit: int):
        if limit < 0:
            raise ValueError(f"limit must not be negative: {limit!r}")
        self._rows = rows
        self._limit = int(limit)

    def __len__(self) -> int:
        return self._limit

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(self._limit)
            return [self._rows[position] for position in range(start, stop, step)]
        if not isinstance(index, int):
            raise TypeError(
                f"bar indices must be integers, not {type(index).__name__}"
            )
        position = index + self._limit if index < 0 else index
        if position < 0 or position >= self._limit:
            raise IndexError(f"bar index out of range: {index}")
        return self._rows[position]

    def __iter__(self):
        for position in range(self._limit):
            yield self._rows[position]

    def __repr__(self) -> str:
        return f"PastBars({self._limit} of {len(self._rows)} bars)"


@dataclass(frozen=True)
class LabContext:
    """What a rule is allowed to read at one bar.

    `lots` is the rule's own view of the book: copies of the open lots only,
    with no realized results, loss slots or wash-sale flags, so a rule can read
    it, or write to it, without touching the run.
    """

    bars: PastBars
    events: list
    cash: D
    base: D
    lots: Lots
    now: datetime


@dataclass(frozen=True)
class Flag:
    """Something the curve alone does not show."""

    kind: str
    ts: datetime
    detail: str = ""


@dataclass(frozen=True)
class Trade:
    """One fill."""

    ts: datetime
    side: str
    qty: D
    price: D
    fee: D
    kind: str
    maker: bool


@dataclass
class SimResult:
    """Everything one run produced.

    `notes` names the modelling gaps the run leaves (see `UNMODELLED`) and
    `wash_sale_count` is how many wash-sale matches the final book carries.
    `contributions` is every (stamp, amount) a funded run added to cash and
    `total_contributed` their sum, which is D("0") for an unfunded run.
    """

    curve: list
    trades: list
    fees: D
    realized: list
    taxes_by_year: dict
    tax_payments: list
    final_cash: D
    final_base: D
    final_equity: D
    final_equity_after_liquidation_tax: D
    flags: list
    dropped: list
    notes: list = field(default_factory=list)
    wash_sale_count: int = 0
    contributions: list = field(default_factory=list)
    total_contributed: D = D("0")


# ---------------------------------------------------------------- event timing


def reaction_bar_ts(
    event: Event, bar_timestamps: list[datetime]
) -> Optional[datetime]:
    """The first bar an event can be traded on, or None when no bar is left.

    A release after the close (`post`) belongs to the next session, so the first
    bar on a later UTC date reacts.  A release before the open (`pre`) belongs to
    the same session, so a bar on the same UTC date reacts.  `none` means no
    session tag: the first bar at or after the instant reacts.
    """
    if not isinstance(event, Event):
        raise ValueError(f"expected an Event, got {type(event).__name__}")
    instant = _utc(event.at, "event.at")
    day = instant.date()
    if event.session not in (POST, PRE, NONE):
        raise ValueError(f"unknown event session: {event.session!r}")
    for stamp in bar_timestamps:
        moment = _utc(stamp, "bar ts")
        if event.session == POST:
            if moment.date() > day:
                return stamp
        elif event.session == PRE:
            if moment.date() >= day:
                return stamp
        else:
            if moment >= instant:
                return stamp
    return None


# ---------------------------------------------------------------- the book


class _Ledger:
    """Cash, base holding and the lot book, with one fill at a time."""

    def __init__(self, costs: CostModel, book: Lots, cash: D, base: D):
        self.costs = costs
        self.book = book
        self.cash = cash
        self.base = base
        self.trades: list[Trade] = []
        self.realized: list[RealizedGain] = []
        self.fees = D("0")

    def equity(self, price: D) -> D:
        return self.cash + self.base * price

    def fill_market(
        self, order: Order, bar: Bar, dropped: list, flags: list
    ) -> bool:
        """Fill one market order at *bar*'s open; False when nothing filled."""
        if order.kind != MARKET:
            raise ValueError("a limit order fills in the grid simulator, not here")
        buying = order.side == BUY
        slippage = self.costs.slippage
        taker = self.costs.taker
        step = self.costs.increments.base if self.costs.increments else None
        price = (
            bar.open * (D("1") + slippage)
            if buying
            else bar.open * (D("1") - slippage)
        )
        if price <= 0:
            raise ValueError(f"fill price is not positive: {price!r}")

        if order.qty is not None:
            wanted = order.qty
        else:
            # A notional buy spends the whole amount, fee included.
            wanted = order.notional / (price * (D("1") + taker))
        qty = _floor_to(wanted, step)

        if buying:
            affordable = _floor_to(self.cash / (price * (D("1") + taker)), step)
            if qty > affordable:
                qty = affordable
        else:
            held = _floor_to(self.base, step)
            if qty > held:
                qty = held

        if qty <= 0:
            if wanted > 0 and _floor_to(wanted, step) <= 0:
                kind = "below_increment"
                detail = f"{order.side} {wanted} is below one size step {step}"
            elif buying:
                kind = "insufficient_cash"
                detail = f"{order.side} {wanted} needs more cash than {self.cash}"
            else:
                kind = "nothing_to_sell"
                detail = f"{order.side} {wanted} with {self.base} held"
            dropped.append(order)
            flags.append(Flag(kind, bar.ts, detail))
            return False

        notional = qty * price
        fee = notional * taker
        if buying:
            self.cash -= notional + fee
            self.base += qty
            self.book.buy(bar.ts, qty, price, fee)
        else:
            self.cash += notional - fee
            self.base -= qty
            self.realized.extend(self.book.sell(bar.ts, qty, price, fee))
            # A replacement already held at the sale is matched here, so the
            # tax this run pays sees the carried basis.
            self.book.settle()
        self.fees += fee
        self.trades.append(
            Trade(
                ts=bar.ts,
                side=order.side,
                qty=qty,
                price=price,
                fee=fee,
                kind=MARKET,
                maker=False,
            )
        )
        return True

    def fill_at(
        self, bar: Bar, side: str, qty: D, price: D, rate: D, maker: bool
    ) -> None:
        """Book one fill the caller has already priced and found affordable.

        The grid simulator knows each resting order's own limit price and
        whether the bar traded through it, so the price arithmetic stays there
        and this method only settles: the fee is `rate` on the notional, the
        lot book takes the purchase or the sale, and the trade records whether
        it was a maker or a taker fill.
        """
        if side not in (BUY, SELL):
            raise ValueError(f"side must be {BUY!r} or {SELL!r}: {side!r}")
        if qty <= 0:
            raise ValueError(f"qty must be positive: {qty!r}")
        if price <= 0:
            raise ValueError(f"price must be positive: {price!r}")
        notional = qty * price
        fee = notional * rate
        if side == BUY:
            self.cash -= notional + fee
            self.base += qty
            self.book.buy(bar.ts, qty, price, fee)
        else:
            self.cash += notional - fee
            self.base -= qty
            self.realized.extend(self.book.sell(bar.ts, qty, price, fee))
            # A replacement already held at the sale is matched here, so the
            # tax this run pays sees the carried basis.
            self.book.settle()
        self.fees += fee
        self.trades.append(
            Trade(
                ts=bar.ts,
                side=side,
                qty=qty,
                price=price,
                fee=fee,
                kind=LIMIT if maker else MARKET,
                maker=maker,
            )
        )


# ---------------------------------------------------------------- validation


def _check_bars(rows: list) -> None:
    """One symbol, one interval, strictly ascending timestamps, not empty."""
    if not rows:
        raise ValueError("simulate needs at least one bar")
    first = rows[0]
    if not isinstance(first, Bar):
        raise ValueError(f"expected a Bar, got {type(first).__name__}")
    previous: Optional[Bar] = None
    for bar in rows:
        if not isinstance(bar, Bar):
            raise ValueError(f"expected a Bar, got {type(bar).__name__}")
        _utc(bar.ts, "bar ts")
        if bar.symbol != first.symbol or bar.interval != first.interval:
            raise ValueError(
                f"all bars must share one symbol and interval: "
                f"({bar.symbol!r}, {bar.interval!r}) does not belong to "
                f"({first.symbol!r}, {first.interval!r})"
            )
        if previous is not None and not bar.ts > previous.ts:
            raise ValueError(
                f"bars must be in ascending timestamp order: {bar.ts!r} "
                f"follows {previous.ts!r}"
            )
        previous = bar


def _accepted(value) -> list[Order]:
    """The market orders a decision carries; a limit order is refused here."""
    if value is None:
        return []
    if isinstance(value, Gates):
        raise ValueError(
            "a Gates value is a decision for the grid simulator, not market "
            "orders: this rule runs on the grid simulator, so run it with sim "
            "'grid' (the market simulator was handed a Gates)"
        )
    if isinstance(value, Decision):
        value = value.orders
    elif isinstance(value, Order):
        value = (value,)
    orders: list[Order] = []
    for item in value:
        if not isinstance(item, Order):
            raise ValueError(f"expected an Order, got {type(item).__name__}")
        if item.kind != MARKET:
            raise ValueError("a limit order fills in the grid simulator, not here")
        orders.append(item)
    return orders


# ---------------------------------------------------------------- the run


def simulate(
    bars: list,
    events: list,
    decide,
    start_cash: D,
    start_base: D,
    costs: CostModel,
    *,
    initial_orders=(),
    max_gap: Optional[timedelta] = None,
    contribution=None,
) -> SimResult:
    """Run one continuous next-open simulation over *bars*.

    *start_base* is already held when bar 0 opens: one lot acquired at that
    stamp for the first open, with no fee.  *initial_orders* fill at bar 0's open
    before anything else.  *decide* is handed a `LabContext` at each bar and may
    answer with a `Decision`, a sequence of market orders, or None; its orders
    fill at the next bar's open.  A gap longer than *max_gap* between two bars
    that a fill lands on is flagged.

    *contribution* is None for a run from its starting cash alone, or
    `{"amount": Decimal, "every": "week"}` for one funded by a fixed amount
    added to cash at each bar that starts a new week (bar 0 always does), before
    that bar's orders fill.
    """
    rows = bars if isinstance(bars, list) else list(bars)
    _check_bars(rows)
    if not isinstance(costs, CostModel):
        raise ValueError(f"costs must be a CostModel, got {type(costs).__name__}")
    cash = _at_least_zero(start_cash, "start_cash")
    base = _at_least_zero(start_base, "start_base")
    first = rows[0]
    if max_gap is None:
        max_gap = (
            INTERVAL_LENGTH[first.interval]
            if costs.asset_class == "crypto"
            else STOCK_MAX_GAP
        )
    if not isinstance(max_gap, timedelta) or max_gap <= timedelta(0):
        raise ValueError(f"max_gap must be a positive timedelta: {max_gap!r}")
    weekly = _weekly_amount(contribution)

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
    contributions: list[tuple[datetime, D]] = []
    tax_payments: list[tuple[datetime, D]] = []
    flags: list[Flag] = []
    dropped: list[Order] = []
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
        if weekly is not None and _week_start(
            bar, rows[index - 1] if index > 0 else None
        ):
            ledger.cash += weekly
            contributions.append((bar.ts, weekly))
        filled = False
        for order in pending:
            if ledger.fill_market(order, bar, dropped, flags):
                filled = True
        pending = []
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

        visible = [
            event for event in event_list if event.announced_at <= bar.ts
        ]
        context = LabContext(
            bars=PastBars(rows, index + 1),
            events=visible,
            cash=ledger.cash,
            base=ledger.base,
            lots=ledger.book.open_copy(),
            now=bar.ts,
        )
        pending = _accepted(decide(context))

    if pending:
        dropped.extend(pending)
        flags.append(
            Flag(
                "last_bar_order_dropped",
                rows[-1].ts,
                f"{len(pending)} order(s) had no bar left to fill on",
            )
        )

    last = rows[-1]
    ledger.book.settle()
    paid = sum((amount for _, amount in tax_payments), D("0"))
    final_equity = ledger.equity(last.close)
    liquidation = liquidation_tax(
        ledger.book, ledger.realized, paid, last.close, last.ts, costs
    )
    return SimResult(
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
        contributions=contributions,
        total_contributed=sum(
            (amount for _, amount in contributions), D("0")
        ),
    )