"""When to buy: one cash amount, several entry timings, one horizon.

The study answers one question for one stock at a time: with a fixed amount of
cash and a horizon long enough that every lot is long-term, how does the outcome
differ between buying at once, splitting the purchase in two, and waiting for the
price to stand above its own recent average?  Every timing runs through the
next-open simulator over the same bars, from the same cash and with the same
costs, so what the tables report is the difference between the timings and
nothing else.

A window variant repeats a timing with a rule that holds a buy back while an
earnings release or a lockup expiry sits within a few sessions of the decision,
and the same comparison runs again over a series whose daily log-returns have had
their mean taken out, so an entry timing can be read apart from the drift of the
sample it is measured on.

Nothing here passes or fails a timing.  The report says what the numbers are and
what the sample behind them can carry.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional

# `_anniversary` is private to `..costs` and is imported here on purpose: the
# study asks the same calendar-anniversary question the tax lot book asks, and
# writing that rule out a second time would let the two answers drift apart.
from ..costs import BUY, CostModel, Order, _anniversary
from ..metrics import max_drawdown
from ..rules.event_veto import veto_active
from ..sim import LabContext, PastBars, SimResult, simulate
from ..store import Bar, Event

D = Decimal

__all__ = [
    "DEFAULT_SEED",
    "MIN_BOOTSTRAP_BLOCKS",
    "MIN_HORIZON_DAYS",
    "OptionResult",
    "SPLIT_GAP_DAYS",
    "SeriesResult",
    "StartOutcome",
    "StudyResult",
    "TREND_DEADLINES",
    "TREND_N",
    "block_bootstrap_ci",
    "check_long_term",
    "count_nonoverlapping",
    "percentile",
    "remove_drift",
    "run_study",
]

# A horizon of one year plus the longest wait the options can add: the 14-day
# split, the longest trend deadline (40 sessions, about 56 calendar days) and the
# shifts an event window puts on a buy, so every lot is long-term at the horizon.
MIN_HORIZON_DAYS = 450

# How long after the first fill the second half of a split purchase waits.
SPLIT_GAP_DAYS = 14

# The averages a trend entry reads, and the sessions it may wait for one.
TREND_N = (20, 50, 100)
TREND_DEADLINES = (10, 20, 40)

DEFAULT_SEED = 20261119

# The fewest blocks a bootstrap interval is read from: with fewer the resample
# only repeats the same few stretches of the series.
MIN_BOOTSTRAP_BLOCKS = 4

# The event kinds that give a series its window variants.
WINDOW_KINDS = ("earnings", "lockup")


# ---------------------------------------------------------------- value helpers


def _decimal(value: object, name: str) -> D:
    """A Decimal from a Decimal, str or int.  A float is refused."""
    if isinstance(value, D):
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


def _whole(value: object, name: str, minimum: Optional[int] = None) -> int:
    """A whole number, from an int and not from a bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a whole number: {value!r}")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}: {value!r}")
    return value


def _number(value: object, name: str) -> float:
    """A finite float from an int or a float."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number: {value!r}")
    out = float(value)
    if not math.isfinite(out):
        raise ValueError(f"{name} must be finite: {value!r}")
    return out


def _utc(moment: object, name: str) -> datetime:
    """*moment* refused unless it is a timezone-aware datetime."""
    if not isinstance(moment, datetime):
        raise ValueError(f"{name} must be a datetime, got {type(moment).__name__}")
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"{name} must be timezone-aware: {moment!r}")
    return moment


# ---------------------------------------------------------------- pure helpers


def remove_drift(bars: list) -> list:
    """The same series with the mean of its daily log-returns taken out.

    With `r_i = ln(close_i / close_{i-1})` for i >= 1 and `mu` their sample mean,
    every price of bar i is multiplied by `exp(-mu * i)`, so bar 0 is unchanged
    and the new log-returns average zero.  The stamps, the symbol, the interval,
    the volume and the adjustment factor come through as they were.  Fewer than
    two bars, or a close that is not positive, raises ValueError.
    """
    rows = list(bars)
    if len(rows) < 2:
        raise ValueError(
            f"remove_drift needs at least two bars: got {len(rows)}"
        )
    for bar in rows:
        if not isinstance(bar, Bar):
            raise ValueError(f"expected a Bar, got {type(bar).__name__}")
        _utc(bar.ts, "bar ts")
    closes = [float(bar.close) for bar in rows]
    for close in closes:
        if close <= 0:
            raise ValueError(
                "every close must be positive to take a log-return"
            )
    returns = [
        math.log(closes[index] / closes[index - 1])
        for index in range(1, len(closes))
    ]
    mu = math.fsum(returns) / len(returns)
    out: list = []
    for index, bar in enumerate(rows):
        factor = D(str(math.exp(-mu * index)))
        out.append(
            Bar(
                symbol=bar.symbol,
                interval=bar.interval,
                ts=bar.ts,
                open=bar.open * factor,
                high=bar.high * factor,
                low=bar.low * factor,
                close=bar.close * factor,
                volume=bar.volume,
                adj_factor=bar.adj_factor,
            )
        )
    return out


def check_long_term(buy_stamps, stop_ts: datetime) -> None:
    """Refuse a book that still holds a short-term lot at the stop.

    A buy stamped *b* is long-term at the stop when the stop's calendar date is
    strictly past the first anniversary of the buy's date, where the anniversary
    of a 29 February acquisition is 28 February of the next year.  A buy that is
    not long-term by then raises ValueError naming that buy and the stop.
    """
    for stamp in buy_stamps:
        if not stop_ts.date() > _anniversary(stamp.date()):
            raise ValueError(
                f"a buy at {stamp.isoformat()} is not long-term at the stop "
                f"{stop_ts.isoformat()}"
            )


def percentile(sorted_values: list, p: float) -> float:
    """The value at percentile *p* of an ascending series, by interpolation.

    The position is `(n - 1) * p / 100`; a position that falls between two values
    is read as the linear blend of them, so the median of an even count sits
    midway between the two middle values.  Nothing to read, or a *p* outside
    [0, 100], raises ValueError.
    """
    values = list(sorted_values)
    if not values:
        raise ValueError("percentile needs at least one value")
    share = _number(p, "p")
    if not 0.0 <= share <= 100.0:
        raise ValueError(f"p must sit within [0, 100]: {p!r}")
    if len(values) == 1:
        return float(values[0])
    position = (len(values) - 1) * (share / 100.0)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(values[int(position)])
    weight = position - lower
    return float(values[lower]) * (1.0 - weight) + float(values[upper]) * weight


def block_bootstrap_ci(
    values: list,
    statistic,
    block_len: int,
    n_boot: int,
    seed: int,
    level: float = 0.95,
) -> Optional[tuple]:
    """A percentile interval for *statistic*, from a circular block bootstrap.

    Each of the `n_boot` resamples takes blocks of `block_len` neighbouring
    values from a random start, wrapping around the end of the series, and keeps
    adding blocks until it holds as many values as the series does (the last
    block is cut short).  Keeping neighbours together is what makes the interval
    wide enough for a series whose values are related to the ones next to them: a
    block length of 1 gives the ordinary independent resample.

    The interval is the `100 * (1 - level) / 2` and `100 * (1 + level) / 2`
    percentiles of the sorted statistics.  Fewer than two values raises
    ValueError, and a block length outside [1, len(values)] is clamped into it.
    None when fewer than `MIN_BOOTSTRAP_BLOCKS` blocks of that length fit in the
    series (`block_len * 4 > len(values)`): a resample that holds so few blocks
    only repeats the same few stretches, so no interval is reported rather than
    a collapsed one.
    """
    rows = [float(value) for value in values]
    if len(rows) < 2:
        raise ValueError(
            f"a bootstrap needs at least two values: got {len(rows)}"
        )
    length = _whole(block_len, "block_len")
    length = min(max(length, 1), len(rows))
    boots = _whole(n_boot, "n_boot", 1)
    interval = _number(level, "level")
    if not 0.0 < interval < 1.0:
        raise ValueError(f"level must sit inside (0, 1): {level!r}")
    count = len(rows)
    if length * MIN_BOOTSTRAP_BLOCKS > count:
        return None
    rng = random.Random(seed)
    statistics_seen: list[float] = []
    for _ in range(boots):
        sample: list[float] = []
        while len(sample) < count:
            start = rng.randrange(count)
            block = rows[start : start + length]
            if len(block) < length:
                block = block + rows[: length - len(block)]
            sample.extend(block)
        statistics_seen.append(float(statistic(sample[:count])))
    statistics_seen.sort()
    low = percentile(statistics_seen, 100.0 * (1.0 - interval) / 2.0)
    high = percentile(statistics_seen, 100.0 * (1.0 + interval) / 2.0)
    return (low, high)


def count_nonoverlapping(windows: list) -> int:
    """How many of the windows fit without sharing a bar, taken greedily.

    The windows are `(start_index, end_index)` pairs in ascending start order.
    The first is taken, then each next one whose start is at or after the end of
    the window taken before it, so a window may begin on the bar a previous one
    ends on.
    """
    taken = 0
    previous_end: Optional[int] = None
    for start, end in windows:
        if previous_end is None or start >= previous_end:
            taken += 1
            previous_end = end
    return taken


# ---------------------------------------------------------------- index helpers


def _index_at_or_after(stamps: list, moment: datetime) -> Optional[int]:
    """The first index whose stamp is at or after *moment*, or None."""
    low, high = 0, len(stamps)
    while low < high:
        middle = (low + high) // 2
        if stamps[middle] < moment:
            low = middle + 1
        else:
            high = middle
    return low if low < len(stamps) else None


def _last_at_or_before(stamps: list, moment: datetime) -> int:
    """The last index whose stamp is at or before *moment*, or -1."""
    low, high = 0, len(stamps)
    while low < high:
        middle = (low + high) // 2
        if stamps[middle] <= moment:
            low = middle + 1
        else:
            high = middle
    return low - 1


def _window_stop(stamps: list, start: int, horizon_days: int) -> Optional[int]:
    """The last bar of a start's horizon window, or None when it has none.

    The horizon is `horizon_days` calendar days after the start bar's stamp; the
    window runs to the last bar at or before that instant.  A start whose bars
    end before the horizon is reached has no window.
    """
    target = stamps[start] + timedelta(days=horizon_days)
    if stamps[-1] < target:
        return None
    stop = _last_at_or_before(stamps, target)
    if stop < start:
        return None
    return stop


# ---------------------------------------------------------------- result types


@dataclass
class StartOutcome:
    """One option's run from one start: what it bought and what it ended with.

    `buy_ts` is the fill stamp of every buy in order, `spent` is the cash the run
    committed, `value_pretax` the equity at the window's last close and
    `value_after_tax` that equity net of the tax closing the book would owe.
    `in_deep_drawdown` says whether the start itself sat well below the highest
    close the series had reached by then.
    """

    start_index: int
    start_ts: datetime
    buy_ts: list
    spent: D
    value_pretax: D
    value_after_tax: D
    max_drawdown: D
    in_deep_drawdown: bool


@dataclass
class OptionResult:
    """One entry timing over every start of one series, and its summary."""

    name: str
    veto: bool
    starts: list
    summary: dict


@dataclass
class SeriesResult:
    """One series' options, with how many starts it ran and how many stood alone."""

    label: str
    symbol: str
    drift_removed: bool
    control: bool
    n_starts: int
    n_nonoverlap: int
    options: dict


@dataclass
class StudyResult:
    """The parameters a study ran with and every series it produced."""

    params: dict
    series: dict

    def to_markdown(self) -> str:
        """The study as a plain-words report with one table per series."""
        cash = str(self.params.get("cash", ""))
        lines = [
            "# When to buy: one cash amount, several entry timings",
            "",
        ]
        lines.extend(_CAVEATS)
        lines.append("")
        lines.append(_DRIFT_NOTE)
        for label, found in self.series.items():
            lines.append("")
            lines.append(f"## {label}")
            lines.append("")
            lines.append(_series_line(found))
            lines.append("")
            columns = [
                "option",
                "starts",
                "non-overlapping windows",
                "median after tax",
                "median interval",
                "p10 after tax",
                "p90 after tax",
                "share above lump",
                "share interval",
                "median drawdown",
                "worst drawdown",
                "deep-drawdown starts",
                f"median difference vs lump on ${cash}",
                "median before tax",
            ]
            lines.append("| " + " | ".join(columns) + " |")
            lines.append("|" + "|".join(["---"] * len(columns)) + "|")
            for name, option in found.options.items():
                lines.append(_table_row(name, option, found))
        lines.append("")
        lines.append(_CLOSING)
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- report text

_CAVEATS = (
    "This is one stock at a time: what it says about that one stock is all it "
    "says, and another name would give another table.",
    "The names it is run on are ones that went up over the sample, so the "
    "comparison starts from a sample that was friendly to owning them at all.",
    "The windows overlap, so the starts are not independent looks at the same "
    "prices: overlapping windows share most of their bars, and the effective "
    "sample is much smaller than the number of starts makes it look.",
    "A finished table describes prices that have already happened and is not a "
    "prediction of any future entry.",
)

_DRIFT_NOTE = (
    'A series marked "no median drift" has each daily log-return reduced by the '
    "mean of that series' log-returns, so its log-returns average zero and the "
    "sample's own drift is taken out of the comparison. What is left is not a "
    "flat market: subtracting the mean of log-returns leaves the arithmetic "
    "drift of about sigma^2/2, which a log series keeps even when its mean "
    "log-return is zero."
)

_CLOSING = (
    "In one line: one stock at a time, names that went up, overlapping windows, "
    "and not a prediction."
)


def _money_text(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:,.2f}"


def _share_text(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value * 100.0:.1f}%"


def _pair_text(pair: Optional[tuple]) -> str:
    if pair is None:
        return "n/a"
    return f"{pair[0]:,.2f} to {pair[1]:,.2f}"


def _share_pair_text(pair: Optional[tuple]) -> str:
    if pair is None:
        return "n/a"
    return f"{pair[0] * 100.0:.1f}% to {pair[1] * 100.0:.1f}%"


def _series_line(found: SeriesResult) -> str:
    if found.control:
        return (
            "A control series: it carries no events, so it has no window "
            f"variants, and it ran {found.n_starts} starts over "
            f"{found.n_nonoverlap} non-overlapping windows."
        )
    kind = (
        "The same prices with the mean of their daily log-returns taken out."
        if found.drift_removed
        else "The prices as they were."
    )
    return (
        f"{kind} It ran {found.n_starts} starts over {found.n_nonoverlap} "
        "non-overlapping windows."
    )


def _table_row(name: str, option: OptionResult, found: SeriesResult) -> str:
    summary = option.summary
    deep = summary.get("deep_drawdown") or {}
    cells = [
        name,
        str(summary.get("n_starts")),
        str(found.n_nonoverlap),
        _money_text(summary.get("value_after_tax_median")),
        _pair_text(summary.get("median_ci")),
        _money_text(summary.get("value_after_tax_p10")),
        _money_text(summary.get("value_after_tax_p90")),
        _share_text(summary.get("share_beating_lump")),
        _share_pair_text(summary.get("share_beating_lump_ci")),
        _share_text(summary.get("max_drawdown_median")),
        _share_text(summary.get("max_drawdown_worst")),
        str(deep.get("n", 0)),
        _money_text(summary.get("dollar_median_diff")),
        _money_text(summary.get("value_pretax_median")),
    ]
    return "| " + " | ".join(cells) + " |"


# ---------------------------------------------------------------- run machinery


def _nothing(context: LabContext):
    """A decide that asks for nothing."""
    return None


def _with_history(decide, bars: list, offset: int):
    """*decide* shown a window over the whole series, still stopping at its bar.

    The run itself is handed only its own slice, so the context it builds holds
    that slice's bars.  The wrapper swaps in a read-only window over every bar of
    the series up to the bar the run has reached, which lets a rule read the bars
    before its window and never one after it.
    """

    def bounded(context: LabContext):
        return decide(
            replace(context, bars=PastBars(bars, offset + len(context.bars)))
        )

    return bounded


def _order_at(index: int, notional: D):
    """A decide that buys *notional* at the decision bar *index*."""

    def decide(context: LabContext):
        if len(context.bars) - 1 == index:
            return (Order(BUY, notional=notional),)
        return None

    return decide


def _trend_decision(flags: list, start: int, deadline: int, veto: bool, days: int):
    """A decide that buys once the close stands above its average, or on time.

    The close of the decision bar is above the mean of the last n closes when
    `flags` says so at that bar; the deadline buys after `deadline` decision bars
    whatever the prices did.  A due buy with a window open is carried to the next
    decision bar, and nothing is bought once the first buy has gone through.
    """
    state = {"bought": False, "carried": False}

    def decide(context: LabContext):
        if state["bought"]:
            return None
        index = len(context.bars) - 1
        if not (
            state["carried"] or flags[index] or index - start >= deadline
        ):
            return None
        if veto and veto_active(context.events, context.now, days):
            state["carried"] = True
            return None
        state["bought"] = True
        state["carried"] = False
        return (Order(BUY, notional=context.cash),)

    return decide


def _deep_flags(closes: list, deep_drawdown: D) -> list:
    """Whether each bar's close is that far below the highest close so far."""
    flags: list = []
    peak: Optional[D] = None
    floor = D("1") - deep_drawdown
    for close in closes:
        if peak is None or close > peak:
            peak = close
        flags.append(close <= peak * floor)
    return flags


def _trend_flags(closes: list, n: int) -> list:
    """Whether each bar's close is above the mean of the last n closes.

    The mean includes the bar itself, and a bar that has fewer than n closes
    behind it is never above its average.  A rolling sum keeps the pass linear.
    """
    flags: list = []
    total = D("0")
    span = D(n)
    for index, close in enumerate(closes):
        total += close
        if index >= n:
            total -= closes[index - n]
        flags.append(index + 1 >= n and close * span > total)
    return flags


class _Run:
    """One series' bars, events and costs, and the runs the study asks of it."""

    def __init__(
        self,
        bars: list,
        events: list,
        cash: D,
        costs: CostModel,
        veto_days: int,
        deep_drawdown: D,
    ):
        self.bars = list(bars)
        self.events = list(events)
        self.cash = cash
        self.costs = costs
        self.veto_days = veto_days
        self.stamps = [bar.ts for bar in self.bars]
        closes = [bar.close for bar in self.bars]
        self.deep_flags = _deep_flags(closes, deep_drawdown)
        self.trend_flags = {n: _trend_flags(closes, n) for n in TREND_N}

    def simulate(
        self,
        stop: int,
        window_start: int,
        initial: tuple,
        decide,
    ) -> SimResult:
        """One run over `bars[window_start : stop + 1]` from cash and no holding."""
        return simulate(
            self.bars[window_start : stop + 1],
            self.events,
            _with_history(decide, self.bars, window_start),
            self.cash,
            D("0"),
            self.costs,
            initial_orders=initial,
        )

    def outcome(self, start: int, stop: int, result: SimResult) -> StartOutcome:
        """The start's outcome, read off the run it produced.

        *stop* is the last bar of the start's window, and every buy the run left
        on the book has to be long-term at it.
        """
        buy_ts = [trade.ts for trade in result.trades if trade.side == BUY]
        check_long_term(buy_ts, self.bars[stop].ts)
        return StartOutcome(
            start_index=start,
            start_ts=self.bars[start].ts,
            buy_ts=buy_ts,
            spent=self.cash - result.final_cash,
            value_pretax=result.final_equity,
            value_after_tax=result.final_equity_after_liquidation_tax,
            max_drawdown=max_drawdown(result.curve),
            in_deep_drawdown=self.deep_flags[start],
        )

    def visible(self, index: int) -> list:
        """The events already announced when the bar at *index* opens."""
        moment = self.stamps[index]
        return [
            event for event in self.events if event.announced_at <= moment
        ]

    def first_veto_free(
        self, first: int, last: int
    ) -> Optional[int]:
        """The first decision bar in [first, last] with no event window open."""
        for index in range(max(first, 0), last + 1):
            if not veto_active(
                self.visible(index), self.stamps[index], self.veto_days
            ):
                return index
        return None

    def index_at_or_after(self, moment: datetime) -> Optional[int]:
        """The first bar stamped at or after *moment*, or None."""
        return _index_at_or_after(self.stamps, moment)


@dataclass(frozen=True)
class _Plan:
    """Everything one series' run needs, decided before it starts."""

    label: str
    symbol: str
    bars: list
    events: list
    starts: list
    stops: dict
    control: bool
    drift_removed: bool
    with_veto: bool
    cash: D
    costs: CostModel
    veto_days: int
    deep_drawdown: D
    block_len: int
    n_boot: int
    seed: int


def _option_specs(with_veto: bool) -> list:
    """The options a series runs, as (name, kind, parameter, veto) rows."""
    specs = [
        ("lump", "lump", None, False),
        ("split2", "split2", None, False),
    ]
    for n in TREND_N:
        for deadline in TREND_DEADLINES:
            specs.append((f"trend N={n} D={deadline}", "trend", (n, deadline), False))
    if with_veto:
        for name, kind, parameter, _ in list(specs):
            specs.append((f"{name} +veto", kind, parameter, True))
    return specs


def _outcomes(
    run: _Run, plan: _Plan, kind: str, parameter, veto: bool, lump_runs: dict
):
    """Every start's outcome for one option, leaving out the starts it drops.

    `lump_runs` holds the plain lump run of each start, which a window variant
    whose first buy lands where the plain one did reads instead of running the
    same simulation a second time.
    """
    cash = plan.cash
    out: list = []
    if kind == "lump":
        initial = (Order(BUY, notional=cash),)
        for start in plan.starts:
            stop = plan.stops[start]
            decision = run.first_veto_free(
                start - 1 if start >= 1 else start, stop - 1
            )
            if decision is None:
                continue
            if decision + 1 == start:
                out.append(run.outcome(start, stop, lump_runs[start]))
                continue
            result = run.simulate(stop, decision + 1, initial, _nothing)
            out.append(run.outcome(start, stop, result))
        return out
    half = cash / 2
    if kind == "split2":
        initial = (Order(BUY, notional=half),)
        for start in plan.starts:
            stop = plan.stops[start]
            if veto:
                decision = run.first_veto_free(
                    start - 1 if start >= 1 else start, stop - 1
                )
                if decision is None:
                    continue
                window_start = decision + 1
                target = run.bars[window_start].ts + timedelta(
                    days=SPLIT_GAP_DAYS
                )
                second = run.index_at_or_after(target)
                buy_at = (
                    None
                    if second is None
                    else run.first_veto_free(second - 1, stop - 1)
                )
            else:
                window_start = start
                target = run.bars[start].ts + timedelta(days=SPLIT_GAP_DAYS)
                second = run.index_at_or_after(target)
                buy_at = (
                    second - 1
                    if second is not None and second <= stop
                    else None
                )
            decide = _nothing if buy_at is None else _order_at(buy_at, half)
            result = run.simulate(stop, window_start, initial, decide)
            out.append(run.outcome(start, stop, result))
        return out
    n, deadline = parameter
    flags = run.trend_flags[n]
    for start in plan.starts:
        stop = plan.stops[start]
        decide = _trend_decision(flags, start, deadline, veto, run.veto_days)
        result = run.simulate(stop, start, (), decide)
        out.append(run.outcome(start, stop, result))
    return out


def _median(values: list) -> Optional[float]:
    if not values:
        return None
    return float(statistics.median(values))


def _at_percentile(values: list, p: float) -> Optional[float]:
    if not values:
        return None
    return percentile(sorted(values), p)


def _mean(values: list) -> Optional[float]:
    if not values:
        return None
    return float(sum(values) / len(values))


def _block_starts(starts: list, block_len: int) -> int:
    """The study's block length, a count of bars, as a count of starts.

    The bootstrap resamples the sequence of starts, so a block given in bars is
    turned into a length in starts through the median gap between neighbouring
    starts.
    """
    ordered = sorted(starts)
    if len(ordered) < 2:
        stride = 1.0
    else:
        gaps = [
            float(later - earlier)
            for earlier, later in zip(ordered, ordered[1:])
        ]
        stride = float(statistics.median(gaps))
    if stride < 1.0:
        stride = 1.0
    return max(1, int(math.ceil(block_len / stride)))


def _summary(
    name: str,
    outcomes: list,
    lump_by_start: dict,
    block_starts: int,
    n_boot: int,
    seed: int,
) -> dict:
    """One option's numbers over its starts, and how it sits against a lump sum."""
    count = len(outcomes)
    after = [float(item.value_after_tax) for item in outcomes]
    before = [float(item.value_pretax) for item in outcomes]
    falls = [float(item.max_drawdown) for item in outcomes]
    plain = name == "lump"

    share: Optional[float] = None
    share_ci: Optional[tuple] = None
    dollar: Optional[float] = None
    dollar_before: Optional[float] = None
    if not plain and count:
        beaten = [
            1.0
            if item.value_after_tax
            > lump_by_start[item.start_index].value_after_tax
            else 0.0
            for item in outcomes
        ]
        share = _mean(beaten)
        if count >= 2:
            share_ci = block_bootstrap_ci(
                beaten, statistics.mean, block_starts, n_boot, seed
            )
        dollar = float(
            statistics.median(
                [
                    item.value_after_tax
                    - lump_by_start[item.start_index].value_after_tax
                    for item in outcomes
                ]
            )
        )
        dollar_before = float(
            statistics.median(
                [
                    item.value_pretax
                    - lump_by_start[item.start_index].value_pretax
                    for item in outcomes
                ]
            )
        )

    median_ci: Optional[tuple] = None
    if count >= 2:
        median_ci = block_bootstrap_ci(
            after, statistics.median, block_starts, n_boot, seed
        )
    # A series short enough that fewer than `MIN_BOOTSTRAP_BLOCKS` blocks fit
    # gets no interval at all; the report says so in words beside the table.
    ci_note: Optional[str] = None
    if count >= 2 and median_ci is None:
        ci_note = (
            f"the bootstrap interval is n/a here: fewer than "
            f"{MIN_BOOTSTRAP_BLOCKS} blocks of {block_starts} starts fit in the "
            f"{count} starts this option ran, so a resample would only repeat "
            f"the same few windows"
        )

    deep = [item for item in outcomes if item.in_deep_drawdown]
    deep_share: Optional[float] = None
    if not plain and deep:
        deep_share = _mean(
            [
                1.0
                if item.value_after_tax
                > lump_by_start[item.start_index].value_after_tax
                else 0.0
                for item in deep
            ]
        )

    return {
        "n_starts": count,
        "value_pretax_median": _median(before),
        "value_pretax_p10": _at_percentile(before, 10.0),
        "value_pretax_p90": _at_percentile(before, 90.0),
        "value_after_tax_median": _median(after),
        "value_after_tax_p10": _at_percentile(after, 10.0),
        "value_after_tax_p90": _at_percentile(after, 90.0),
        "median_ci": median_ci,
        "ci_note": ci_note,
        "share_beating_lump": share,
        "share_beating_lump_ci": share_ci,
        "max_drawdown_median": _median(falls),
        "max_drawdown_worst": (max(falls) if falls else None),
        "deep_drawdown": {
            "n": len(deep),
            "median_value_after_tax": _median(
                [float(item.value_after_tax) for item in deep]
            ),
            "share_beating_lump": deep_share,
        },
        "dollar_median_diff": dollar,
        "dollar_median_diff_pretax": dollar_before,
    }


def _series_result(plan: _Plan) -> SeriesResult:
    """Run every option of one series and summarise each one."""
    run = _Run(
        plan.bars,
        plan.events,
        plan.cash,
        plan.costs,
        plan.veto_days,
        plan.deep_drawdown,
    )
    initial = (Order(BUY, notional=plan.cash),)
    lump_runs: dict = {}
    lump_outcomes: list = []
    for start in plan.starts:
        stop = plan.stops[start]
        result = run.simulate(stop, start, initial, _nothing)
        lump_runs[start] = result
        lump_outcomes.append(run.outcome(start, stop, result))
    lump_by_start = {item.start_index: item for item in lump_outcomes}

    blocks = _block_starts(plan.starts, plan.block_len)
    options: dict = {}
    for name, kind, parameter, veto in _option_specs(plan.with_veto):
        outcomes = (
            lump_outcomes
            if kind == "lump" and not veto
            else _outcomes(run, plan, kind, parameter, veto, lump_runs)
        )
        options[name] = OptionResult(
            name=name,
            veto=veto,
            starts=outcomes,
            summary=_summary(
                name, outcomes, lump_by_start, blocks, plan.n_boot, plan.seed
            ),
        )

    windows = [(start, plan.stops[start]) for start in plan.starts]
    return SeriesResult(
        label=plan.label,
        symbol=plan.symbol,
        drift_removed=plan.drift_removed,
        control=plan.control,
        n_starts=len(plan.starts),
        n_nonoverlap=count_nonoverlapping(windows),
        options=options,
    )


def _start_plan(
    bars: list,
    horizon_days: int,
    explicit: Optional[list],
    first_start: int,
    stride: int,
    symbol: str,
) -> tuple:
    """The starts of one series and the last bar of each one's window."""
    stamps = [bar.ts for bar in bars]
    chosen = (
        explicit
        if explicit is not None
        else list(range(first_start, len(bars), stride))
    )
    starts: list = []
    stops: dict = {}
    for index in chosen:
        if index >= len(stamps):
            raise ValueError(
                f"start {index} is past the {len(stamps)} bars of {symbol!r}"
            )
        stop = _window_stop(stamps, index, horizon_days)
        if stop is None:
            if explicit is None:
                continue
            raise ValueError(
                f"start {index} of {symbol!r} has no window of "
                f"{horizon_days} days in its {len(stamps)} bars, so the lots it "
                f"bought would not be long-term at the horizon"
            )
        starts.append(index)
        stops[index] = stop
    if not starts:
        raise ValueError(
            f"no start of {symbol!r} has a window of {horizon_days} days in its "
            f"{len(stamps)} bars"
        )
    return starts, stops


def _require_block_span(
    block_len: object, block: int, starts: list, stops: dict, symbol: str
) -> None:
    """Refuse a block shorter than the longest window one series' starts run.

    A block is measured in bars, so it has to cover the whole overlap between
    neighbouring starts: otherwise a resample over the starts would cut a
    start's own window into pieces that do not appear together anywhere in the
    series.  *block_len* is the caller's value, used for the message.
    """
    longest = max(stops[index] - index + 1 for index in starts)
    if block < longest:
        raise ValueError(
            f"block_len must be at least the longest window of {symbol!r}, "
            f"{longest} bars, so a bootstrap block spans the overlap between "
            f"neighbouring starts: {block_len!r}"
        )


def _bars_of(rows, symbol: str) -> list:
    """One symbol's bars, refused unless they are Bars in ascending time order."""
    bars = list(rows)
    if not bars:
        raise ValueError(f"no bars for {symbol!r}")
    previous: Optional[datetime] = None
    for bar in bars:
        if not isinstance(bar, Bar):
            raise ValueError(f"expected a Bar, got {type(bar).__name__}")
        moment = _utc(bar.ts, "bar ts")
        if previous is not None and not moment > previous:
            raise ValueError(
                f"the bars of {symbol!r} must ascend in time: {moment!r} "
                f"follows {previous!r}"
            )
        previous = moment
    return bars


def _events_of(events) -> list:
    """A series' events, refused unless they are Events with an announced stamp."""
    out = list(events)
    for event in out:
        if not isinstance(event, Event):
            raise ValueError(f"expected an Event, got {type(event).__name__}")
        _utc(event.announced_at, "event.announced_at")
    return out


def run_study(
    bars_by_symbol: dict,
    events_by_symbol: dict,
    cash: D,
    horizon_days: int,
    costs: CostModel,
    block_len: int,
    *,
    controls: tuple = ("SPY", "QQQ"),
    veto_days: int = 3,
    stride: int = 21,
    first_start: int = 200,
    starts: Optional[list] = None,
    n_boot: int = 1000,
    seed: int = DEFAULT_SEED,
    deep_drawdown: D = D("0.30"),
) -> StudyResult:
    """Compare entry timings for one cash amount over a fixed horizon.

    Every symbol runs from the same cash, with `costs` renamed to that symbol so
    one fee, slippage and tax schedule applies throughout.  A symbol listed in
    `controls` runs as a single control series with no events and no window
    variants; any other symbol runs twice, once as it is and once with the mean
    of its daily log-returns taken out, and gets a set of window variants when
    its events include an earnings release or a lockup expiry.

    A start is an index into the series; its window runs to the last bar of the
    horizon and every simulation covers exactly that window, so the outcomes of
    one start are comparable across options.  `starts` gives the indices
    explicitly and must all have a full window; otherwise the starts are every
    `stride` bars from `first_start` that do.

    A horizon shorter than `MIN_HORIZON_DAYS` raises ValueError, because a lot
    bought at its far end has to be long-term at the horizon.

    `block_len` is a number of bars: it is the length of one bootstrap block
    over the starts of a series, and it has to be at least the longest window a
    series runs (`max(stop - start + 1)` over its starts), so a block spans the
    overlap between neighbouring starts instead of cutting a window apart.  A
    shorter block raises ValueError.
    """
    money = _positive(cash, "cash")
    horizon = _whole(horizon_days, "horizon_days")
    if horizon < MIN_HORIZON_DAYS:
        raise ValueError(
            f"horizon_days must be at least {MIN_HORIZON_DAYS} so every lot is "
            f"long-term at the horizon: {horizon_days!r}"
        )
    block = _whole(block_len, "block_len", 1)
    window_days = _whole(veto_days, "veto_days", 0)
    step = _whole(stride, "stride", 1)
    first = _whole(first_start, "first_start", 0)
    boots = _whole(n_boot, "n_boot", 1)
    deep = _decimal(deep_drawdown, "deep_drawdown")
    if not D("0") <= deep <= D("1"):
        raise ValueError(
            f"deep_drawdown must sit within [0, 1]: {deep_drawdown!r}"
        )
    if not isinstance(costs, CostModel):
        raise ValueError(
            f"costs must be a CostModel, got {type(costs).__name__}"
        )
    if not bars_by_symbol:
        raise ValueError("run_study needs at least one symbol's bars")
    guard = tuple(controls) if controls is not None else ()
    explicit = (
        None
        if starts is None
        else [_whole(index, "start", 0) for index in starts]
    )

    series: dict = {}
    for symbol, rows in bars_by_symbol.items():
        bars = _bars_of(rows, symbol)
        control = symbol in guard
        events = (
            []
            if control
            else _events_of((events_by_symbol or {}).get(symbol, ()))
        )
        with_veto = any(event.kind in WINDOW_KINDS for event in events)
        costs_for_symbol = replace(costs, asset=symbol)
        common = dict(
            cash=money,
            costs=costs_for_symbol,
            veto_days=window_days,
            deep_drawdown=deep,
            block_len=block,
            n_boot=boots,
            seed=seed,
        )
        chosen, stops = _start_plan(bars, horizon, explicit, first, step, symbol)
        _require_block_span(block_len, block, chosen, stops, symbol)
        series[symbol] = _series_result(
            _Plan(
                label=symbol,
                symbol=symbol,
                bars=bars,
                events=events,
                starts=chosen,
                stops=stops,
                control=control,
                drift_removed=False,
                with_veto=with_veto,
                **common,
            )
        )
        if control:
            continue
        drifted = remove_drift(bars)
        other_starts, other_stops = _start_plan(
            drifted, horizon, explicit, first, step, symbol
        )
        _require_block_span(block_len, block, other_starts, other_stops, symbol)
        label = f"{symbol} (no median drift)"
        series[label] = _series_result(
            _Plan(
                label=label,
                symbol=symbol,
                bars=drifted,
                events=events,
                starts=other_starts,
                stops=other_stops,
                control=False,
                drift_removed=True,
                with_veto=with_veto,
                **common,
            )
        )

    params = {
        "cash": str(money),
        "horizon_days": horizon,
        "block_len": block,
        "veto_days": window_days,
        "stride": step,
        "n_boot": boots,
        "seed": seed,
        "deep_drawdown": str(deep),
        "controls": list(guard),
    }
    return StudyResult(params=params, series=series)