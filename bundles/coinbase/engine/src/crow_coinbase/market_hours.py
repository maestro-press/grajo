"""The NYSE regular-session clock, read in UTC epochs.

A session is a weekday that is not a holiday, from the 09:30 ET bell (inclusive)
to the close (exclusive).  Most closes are 16:00 ET; the handful of dates in
`NYSE_EARLY_CLOSES` close at 13:00 ET.  Both tables are writable facts, not
computed ones: the exchange publishes them a year ahead and a half day nobody
recorded is a real risk, so they live here as literal dates a reviewer can read.

The tables cover the years in `COVERED_YEARS` (and whatever years their dates
name).  A date outside them is closed — never assumed open — and the first such
date in a year logs one warning naming that year, so a daemon polling the clock
says it once rather than on every cycle.

Times are converted through `zoneinfo` and the system's tz database, so the
daylight-saving switch is the tz database's problem, never this module's.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, time
from typing import Optional
from zoneinfo import ZoneInfo

_ET = ZoneInfo("America/New_York")
log = logging.getLogger("crow_coinbase.market_hours")

# The regular session's edges, in New York wall-clock time.
OPEN_TIME = time(9, 30)
CLOSE_TIME = time(16, 0)
EARLY_CLOSE_TIME = time(13, 0)

# The years these tables are meant to cover.  The set actually used also takes
# in every year a date in either table names, so a table extended by hand
# without touching this constant still counts as covered.
COVERED_YEARS = (2026, 2027)

NYSE_HOLIDAYS: frozenset[date] = frozenset(
    {
        # 2026
        date(2026, 1, 1),  # New Year's Day
        date(2026, 1, 19),  # Martin Luther King Jr. Day
        date(2026, 2, 16),  # Washington's Birthday
        date(2026, 4, 3),  # Good Friday
        date(2026, 5, 25),  # Memorial Day
        date(2026, 6, 19),  # Juneteenth
        date(2026, 7, 3),  # Independence Day observed
        date(2026, 9, 7),  # Labor Day
        date(2026, 11, 26),  # Thanksgiving
        date(2026, 12, 25),  # Christmas
        # 2027
        date(2027, 1, 1),  # New Year's Day
        date(2027, 1, 18),  # Martin Luther King Jr. Day
        date(2027, 2, 15),  # Washington's Birthday
        date(2027, 3, 26),  # Good Friday
        date(2027, 5, 31),  # Memorial Day
        date(2027, 6, 18),  # Juneteenth observed
        date(2027, 7, 5),  # Independence Day observed
        date(2027, 9, 6),  # Labor Day
        date(2027, 11, 25),  # Thanksgiving
        date(2027, 12, 24),  # Christmas observed
    }
)

NYSE_EARLY_CLOSES: frozenset[date] = frozenset(
    {
        date(2026, 11, 27),  # the Friday after Thanksgiving
        date(2026, 12, 24),  # Christmas Eve
        date(2027, 11, 26),  # the Friday after Thanksgiving
    }
)

_COVERED: frozenset[int] = frozenset(
    set(COVERED_YEARS)
    | {day.year for day in NYSE_HOLIDAYS}
    | {day.year for day in NYSE_EARLY_CLOSES}
)

# The years already reported as uncovered: one warning each, then silence.
_WARNED_YEARS: set[int] = set()


def _covered(day: date) -> bool:
    """Whether the tables know this year.  An unknown year is closed, said once."""
    if day.year in _COVERED:
        return True
    if day.year not in _WARNED_YEARS:
        _WARNED_YEARS.add(day.year)
        log.warning(
            "%d is not in the market calendar: every day in it is treated as closed",
            day.year,
        )
    return False


def _close_time(day: date) -> Optional[time]:
    """The New York wall-clock close of a day that has a session, else None."""
    if day.weekday() > 4:  # Saturday, Sunday
        return None
    if day in NYSE_HOLIDAYS:
        return None
    if day in NYSE_EARLY_CLOSES:
        return EARLY_CLOSE_TIME
    return CLOSE_TIME


def is_regular_session(ts: float) -> bool:
    """Whether the NYSE regular session is open at epoch `ts`.

    The bell is inclusive and the close exclusive, so 09:30:00 ET is a session
    time and 16:00:00 ET is not.
    """
    moment = datetime.fromtimestamp(ts, _ET)
    day = moment.date()
    if not _covered(day):
        return False
    close = _close_time(day)
    if close is None:
        return False
    return OPEN_TIME <= moment.time() < close


def session_close(ts: float) -> Optional[float]:
    """The epoch of the close of the New York day `ts` falls on.

    The answer depends on the calendar day only, not on whether `ts` is inside
    the session: an order placed at 07:00 ET and one placed at 15:00 ET share
    the same close.  None means that day has no session at all.
    """
    moment = datetime.fromtimestamp(ts, _ET)
    day = moment.date()
    if not _covered(day):
        return None
    close = _close_time(day)
    if close is None:
        return None
    return datetime.combine(day, close, tzinfo=_ET).timestamp()