"""R5: a funded weekly stock buy that waits out an earnings or lockup window.

The hypothesis: a scheduled accumulation in a single name is exposed to the jump
a scheduled event puts in the price, and a buy that waits until the last few
sessions before the event has passed buys the same units at a price that is not
the event's reaction.  The window is counted in sessions, not in clock days,
where a session is a weekday that is not an exchange holiday, so a weekend or a
holiday in the middle of it does not shorten it.

The schedule buys a fixed $50 at the start of every UTC ISO week, and the run is
funded by the same fixed $50 a week: the money is contributed first and then
spent, so the cash never falls to dust and a veto has something to move.  A week
whose buy waits is not lost — it stays owing, and the first bar the window is
shut spends one week's amount for each week it carries, as far as the cash held
reaches.  `run` starts a funded rule from no cash by default, and refuses a
starting cash above one weekly amount: a larger starting cash would sit idle
beside the schedule instead of funding it.

The simulator pays the week's deposit on the first bar of a slice even when that
bar falls in the middle of a week, while the rule reads the bars before its
slice as well and so does not count that bar as a week start.  A train or test
slice that starts mid-week therefore leaves one deposit idle in cash, the same
one in the rule's own run and in its no-veto benchmark.

Only the events already announced by the bar are in scope — the simulator hands
in those and nothing later — and only an earnings release or a lockup expiry
opens a window: a listing or a custom event does not.  A buy that falls due
while a window is open is carried until the first bar the window is shut, so the
schedule slips rather than being skipped.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

from ..costs import BUY, Order

D = Decimal

# null_params is the same schedule with the veto switched off: R5's benchmark.

__all__ = [
    "AMOUNT",
    "ASSETS",
    "FUNDING",
    "GRID",
    "HYPOTHESIS",
    "INITIAL_BASE_FRACTION",
    "NYSE_EARLY_CLOSES",
    "NYSE_HOLIDAYS",
    "RULE_ID",
    "SIMULATOR",
    "make",
    "null_params",
    "reaction_date",
    "sessions_before",
    "veto_active",
]

RULE_ID = "event_veto"

# The answer is market orders filled at the next open, so the market simulator.
SIMULATOR = "market"

# What one week of the schedule buys, and the contribution that funds it: the
# same $50 into the run at the start of every week, and then out of the cash.
AMOUNT = D("50")

FUNDING = {"amount": AMOUNT, "every": "week"}

HYPOTHESIS = (
    "a scheduled buy held back until the sessions before an earnings release or "
    "a lockup expiry have passed avoids paying the event's reaction"
)

# Every config holds something back: veto_days 0 is the null schedule itself, so
# a config equal to the benchmark would test nothing.  The params carry plain
# numbers so they serialize to JSON; make() reads them as Decimals.
GRID = [
    {"amount": 50, "veto_days": days} for days in (1, 2, 3, 5)
]

ASSETS = ("stock",)

INITIAL_BASE_FRACTION = D("0")

# The event kinds whose window holds a buy back.
WINDOW_KINDS = ("earnings", "lockup")

# Saturday and Sunday, the two weekdays that never carry a session.
NO_SESSION = (5, 6)

# The full closures of 2016 to 2027, as pinned in the lab's facts: the nyse.com
# schedule pages and the ICE/NYSE releases for the two mourning days 2018-12-05
# and 2025-01-09.  Early closes are sessions, and they are listed in
# NYSE_EARLY_CLOSES for reference.
NYSE_HOLIDAYS: frozenset[date] = frozenset(
    {
        # 2016
        date(2016, 1, 1),
        date(2016, 1, 18),
        date(2016, 2, 15),
        date(2016, 3, 25),
        date(2016, 5, 30),
        date(2016, 7, 4),
        date(2016, 9, 5),
        date(2016, 11, 24),
        date(2016, 12, 26),
        # 2017
        date(2017, 1, 2),
        date(2017, 1, 16),
        date(2017, 2, 20),
        date(2017, 4, 14),
        date(2017, 5, 29),
        date(2017, 7, 4),
        date(2017, 9, 4),
        date(2017, 11, 23),
        date(2017, 12, 25),
        # 2018
        date(2018, 1, 1),
        date(2018, 1, 15),
        date(2018, 2, 19),
        date(2018, 3, 30),
        date(2018, 5, 28),
        date(2018, 7, 4),
        date(2018, 9, 3),
        date(2018, 11, 22),
        date(2018, 12, 5),
        date(2018, 12, 25),
        # 2019
        date(2019, 1, 1),
        date(2019, 1, 21),
        date(2019, 2, 18),
        date(2019, 4, 19),
        date(2019, 5, 27),
        date(2019, 7, 4),
        date(2019, 9, 2),
        date(2019, 11, 28),
        date(2019, 12, 25),
        # 2020
        date(2020, 1, 1),
        date(2020, 1, 20),
        date(2020, 2, 17),
        date(2020, 4, 10),
        date(2020, 5, 25),
        date(2020, 7, 3),
        date(2020, 9, 7),
        date(2020, 11, 26),
        date(2020, 12, 25),
        # 2021
        date(2021, 1, 1),
        date(2021, 1, 18),
        date(2021, 2, 15),
        date(2021, 4, 2),
        date(2021, 5, 31),
        date(2021, 7, 5),
        date(2021, 9, 6),
        date(2021, 11, 25),
        date(2021, 12, 24),
        # 2022
        date(2022, 1, 17),
        date(2022, 2, 21),
        date(2022, 4, 15),
        date(2022, 5, 30),
        date(2022, 6, 20),
        date(2022, 7, 4),
        date(2022, 9, 5),
        date(2022, 11, 24),
        date(2022, 12, 26),
        # 2023
        date(2023, 1, 2),
        date(2023, 1, 16),
        date(2023, 2, 20),
        date(2023, 4, 7),
        date(2023, 5, 29),
        date(2023, 6, 19),
        date(2023, 7, 4),
        date(2023, 9, 4),
        date(2023, 11, 23),
        date(2023, 12, 25),
        # 2024
        date(2024, 1, 1),
        date(2024, 1, 15),
        date(2024, 2, 19),
        date(2024, 3, 29),
        date(2024, 5, 27),
        date(2024, 6, 19),
        date(2024, 7, 4),
        date(2024, 9, 2),
        date(2024, 11, 28),
        date(2024, 12, 25),
        # 2025
        date(2025, 1, 1),
        date(2025, 1, 9),
        date(2025, 1, 20),
        date(2025, 2, 17),
        date(2025, 4, 18),
        date(2025, 5, 26),
        date(2025, 6, 19),
        date(2025, 7, 4),
        date(2025, 9, 1),
        date(2025, 11, 27),
        date(2025, 12, 25),
        # 2026
        date(2026, 1, 1),
        date(2026, 1, 19),
        date(2026, 2, 16),
        date(2026, 4, 3),
        date(2026, 5, 25),
        date(2026, 6, 19),
        date(2026, 7, 3),
        date(2026, 9, 7),
        date(2026, 11, 26),
        date(2026, 12, 25),
        # 2027
        date(2027, 1, 1),
        date(2027, 1, 18),
        date(2027, 2, 15),
        date(2027, 3, 26),
        date(2027, 5, 31),
        date(2027, 6, 18),
        date(2027, 7, 5),
        date(2027, 9, 6),
        date(2027, 11, 25),
        date(2027, 12, 24),
    }
)

# The sessions that close early.  They are still trading days, so they are not in
# NYSE_HOLIDAYS: 2016 to 2025 from the lab's facts, plus the three later ones the
# calendar carries.
NYSE_EARLY_CLOSES: frozenset[date] = frozenset(
    {
        # 2016
        date(2016, 11, 25),
        # 2017
        date(2017, 7, 3),
        date(2017, 11, 24),
        # 2018
        date(2018, 7, 3),
        date(2018, 11, 23),
        date(2018, 12, 24),
        # 2019
        date(2019, 7, 3),
        date(2019, 11, 29),
        date(2019, 12, 24),
        # 2020
        date(2020, 11, 27),
        date(2020, 12, 24),
        # 2021
        date(2021, 11, 26),
        # 2022
        date(2022, 11, 25),
        # 2023
        date(2023, 7, 3),
        date(2023, 11, 24),
        # 2024
        date(2024, 7, 3),
        date(2024, 11, 29),
        date(2024, 12, 24),
        # 2025
        date(2025, 7, 3),
        date(2025, 11, 28),
        date(2025, 12, 24),
        # 2026 and 2027
        date(2026, 11, 27),
        date(2026, 12, 24),
        date(2027, 11, 26),
    }
)

# The session tag of a release made after the close; every other tag belongs to
# the event's own date.
POST = "post"


# ---------------------------------------------------------------- session days


def _utc_date(moment: datetime) -> date:
    """The UTC date of a timezone-aware datetime; a naive one is refused."""
    if not isinstance(moment, datetime):
        raise ValueError(f"expected a datetime, got {type(moment).__name__}")
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"datetime must be timezone-aware: {moment!r}")
    return moment.astimezone(timezone.utc).date()


def _is_session(day: date) -> bool:
    """Whether *day* is a weekday that is not an exchange holiday."""
    return day.weekday() not in NO_SESSION and day not in NYSE_HOLIDAYS


def _next_session(day: date) -> date:
    """The first session after *day*."""
    step = day + timedelta(days=1)
    while not _is_session(step):
        step += timedelta(days=1)
    return step


def _on_a_session(day: date) -> date:
    """*day* itself when it is a session, else the first session after it."""
    if _is_session(day):
        return day
    return _next_session(day)


def reaction_date(event) -> date:
    """The session an event moves the price.

    A release after the close belongs to the next session, so its date is the
    first session after the event's own UTC date.  A release before the open, or
    one with no session tag, belongs to its own date, moved forward to the first
    session when that date is not one: a weekend or an exchange holiday.
    """
    day = _utc_date(event.at)
    if event.session == POST:
        return _next_session(day)
    return _on_a_session(day)


def sessions_before(now_date: date, reaction: date) -> int:
    """How many sessions lie between a decision today and *reaction*.

    A decision taken at today's close fills in the next session, so the count
    starts after the first session following *now_date* and runs up to and
    including *reaction*, counting sessions only: weekends and exchange holidays
    are skipped.  It is 0 when the reaction is that next session or earlier.
    """
    first = _next_session(now_date)
    if reaction <= first:
        return 0
    count = 0
    day = first + timedelta(days=1)
    while day <= reaction:
        if _is_session(day):
            count += 1
        day += timedelta(days=1)
    return count


def veto_active(events, now: datetime, days: int) -> bool:
    """Whether a buy at *now* falls inside an event window.

    True when some earnings release or lockup expiry for the instrument reacts
    in at least one and at most `days` sessions from now, so the window is the
    stretch that runs up to the reaction and excludes the reaction itself.  A
    session is a weekday that is not an exchange holiday; a window of 0 days
    holds nothing back.
    """
    window = int(days)
    if window <= 0:
        return False
    today = _utc_date(now)
    for event in events:
        if event.kind not in WINDOW_KINDS:
            continue
        ahead = sessions_before(today, reaction_date(event))
        if 1 <= ahead <= window:
            return True
    return False


# ---------------------------------------------------------------- the rule


def _week_start(bars) -> bool:
    """Whether the latest bar of *bars* starts a UTC ISO week.

    The first bar a run shows always counts as a start; after that a bar starts a
    week when its (year, week) differs from the previous bar's, so a week the
    data opens part-way through still carries one buy.
    """
    if len(bars) < 2:
        return True
    return bars[-1].ts.isocalendar()[:2] != bars[-2].ts.isocalendar()[:2]


def make(params: dict):
    """A decide that spends a fixed `amount` on every scheduled week.

    A bar starts a week when it is the first bar the run shows, or when its UTC
    ISO (year, week) differs from the previous bar's; each such bar leaves one
    buy owing.  A buy that comes due inside an event window stays owing: the
    decide answers None on that bar and carries the weeks to the first bar the
    window is shut, where it spends `amount` for each week carried, capped by the
    cash the run holds at that bar.  With no cash left to spend the owing weeks
    are cleared rather than carried, because there is nothing to buy with.
    """
    amount = D(str(params["amount"]))
    days = int(D(str(params["veto_days"])))
    state = {"pending": 0}

    def decide(ctx):
        if _week_start(ctx.bars):
            state["pending"] += 1
        if state["pending"] == 0:
            return None
        if veto_active(ctx.events, ctx.now, days):
            return None
        notional = min(ctx.cash, amount * state["pending"])
        state["pending"] = 0
        if notional > 0:
            return (Order(BUY, notional=notional),)
        return None

    return decide


def null_params(params: dict) -> dict:
    """The same schedule with the veto switched off: the benchmark R5 is judged
    against.

    A copy of the config carrying the same `amount` and a `veto_days` of 0, so no
    event window ever holds a week's buy back and each buy lands on the week's
    own bar.  The dict handed in is left as it was.
    """
    zeroed = dict(params)
    zeroed["veto_days"] = 0
    return zeroed