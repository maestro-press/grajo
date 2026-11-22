"""market_hours.py: the NYSE regular session clock, read here in UTC epochs.

Every epoch below is built by `utc()` from a UTC wall clock reading, so the
tests never consult America/New_York themselves: the New York offsets (UTC-4
in summer, UTC-5 in winter) are worked out by hand in the comments.
"""

import logging
from datetime import date, datetime, timezone

from crow_coinbase import market_hours as MH


def utc(y, mo, d, h=0, mi=0, s=0, us=0):
    """Epoch seconds for a UTC wall clock reading; the tests never use the real one."""
    return datetime(y, mo, d, h, mi, s, us, tzinfo=timezone.utc).timestamp()


def test_regular_session_edges():
    # EDT (UTC-4): the bell is 13:30Z and the close is 20:00Z.
    assert MH.is_regular_session(utc(2026, 7, 15, 13, 29, 59)) is False
    assert MH.is_regular_session(utc(2026, 7, 15, 13, 30, 0)) is True
    assert MH.is_regular_session(utc(2026, 7, 15, 19, 59, 59)) is True
    assert MH.is_regular_session(utc(2026, 7, 15, 20, 0, 0)) is False

    # EST (UTC-5): the bell is 14:30Z and the close is 21:00Z.
    assert MH.is_regular_session(utc(2026, 12, 2, 14, 29, 59)) is False
    assert MH.is_regular_session(utc(2026, 12, 2, 14, 30, 0)) is True
    assert MH.is_regular_session(utc(2026, 12, 2, 20, 59, 59)) is True
    assert MH.is_regular_session(utc(2026, 12, 2, 21, 0, 0)) is False

    # The DST switch happened on Sunday 2026-03-08, so Monday the 9th is
    # already EDT: 13:30Z is the bell, not 14:30Z.
    assert MH.is_regular_session(utc(2026, 3, 9, 13, 30, 0)) is True
    assert MH.is_regular_session(utc(2026, 3, 9, 13, 29, 59)) is False


def test_weekend_closed():
    assert MH.is_regular_session(utc(2026, 7, 18, 15, 0, 0)) is False  # Saturday
    assert MH.is_regular_session(utc(2026, 7, 19, 15, 0, 0)) is False  # Sunday


def test_holiday_closed():
    # 15:00Z is mid-session on both coasts' winter and summer clocks, so only
    # the calendar can make these closed.
    assert MH.is_regular_session(utc(2026, 7, 3, 15, 0, 0)) is False  # Fri, July 4th observed
    assert MH.is_regular_session(utc(2026, 11, 26, 15, 0, 0)) is False  # Thanksgiving
    assert MH.is_regular_session(utc(2026, 12, 25, 15, 0, 0)) is False  # Christmas
    assert MH.is_regular_session(utc(2027, 1, 18, 15, 0, 0)) is False  # MLK Day
    assert MH.is_regular_session(utc(2027, 12, 24, 15, 0, 0)) is False  # Christmas observed

    # The day after Thanksgiving is not a holiday: it is a shortened session,
    # covered by test_early_close.
    assert MH.is_regular_session(utc(2027, 11, 25, 15, 0, 0)) is False  # Thanksgiving 2027
    assert date(2026, 11, 26) in MH.NYSE_HOLIDAYS


def test_holiday_table_matches_nyse():
    assert {d for d in MH.NYSE_HOLIDAYS if d.year == 2026} == {
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
    }
    assert {d for d in MH.NYSE_HOLIDAYS if d.year == 2027} == {
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
    assert set(MH.NYSE_EARLY_CLOSES) == {
        date(2026, 11, 27),  # the Friday after Thanksgiving
        date(2026, 12, 24),  # Christmas Eve
        date(2027, 11, 26),  # the Friday after Thanksgiving
    }

    # Both tables hold dates, and no day is in both: a holiday is not a session.
    assert all(isinstance(d, date) for d in MH.NYSE_HOLIDAYS)
    assert all(isinstance(d, date) for d in MH.NYSE_EARLY_CLOSES)
    assert not set(MH.NYSE_HOLIDAYS) & set(MH.NYSE_EARLY_CLOSES)


def test_early_close():
    # Friday 2026-11-27 is EST (UTC-5): the bell is 14:30Z and the close is
    # 13:00 ET = 18:00Z, three hours early.
    assert MH.is_regular_session(utc(2026, 11, 27, 17, 59, 59)) is True
    assert MH.is_regular_session(utc(2026, 11, 27, 18, 0, 0)) is False
    assert MH.is_regular_session(utc(2026, 11, 27, 14, 29, 59)) is False
    assert MH.is_regular_session(utc(2026, 11, 27, 14, 30, 0)) is True

    # Thursday 2026-12-24 closes at 13:00 ET = 18:00Z too.
    assert MH.is_regular_session(utc(2026, 12, 24, 17, 59, 59)) is True
    assert MH.is_regular_session(utc(2026, 12, 24, 18, 0, 0)) is False

    # By contrast the ordinary close that same week is 21:00Z.
    assert MH.is_regular_session(utc(2026, 12, 23, 18, 0, 0)) is True
    assert MH.is_regular_session(utc(2026, 12, 23, 21, 0, 0)) is False


def test_outside_table_years_closed(caplog):
    # The covered years are 2026 and 2027 only; anything else is closed, and
    # said once per year so a daemon does not log it on every poll.
    MH._WARNED_YEARS.clear()
    try:
        with caplog.at_level(logging.WARNING, logger="crow_coinbase.market_hours"):
            assert MH.is_regular_session(utc(2025, 6, 10, 15, 0, 0)) is False
            assert MH.is_regular_session(utc(2025, 6, 10, 16, 0, 0)) is False
            warned_2025 = [r for r in caplog.records if "2025" in r.getMessage()]
            assert len(warned_2025) == 1
            assert warned_2025[0].levelno == logging.WARNING
            assert len(MH._WARNED_YEARS) == 1

            assert MH.is_regular_session(utc(2028, 6, 13, 15, 0, 0)) is False
            warned_2028 = [r for r in caplog.records if "2028" in r.getMessage()]
            assert len(warned_2028) == 1
            assert warned_2028[0].levelno == logging.WARNING
            assert len(MH._WARNED_YEARS) == 2

            # A second uncovered year adds its own warning, and only that one.
            assert len(caplog.records) == 2
            assert len([r for r in caplog.records if "2025" in r.getMessage()]) == 1
    finally:
        MH._WARNED_YEARS.clear()


def test_session_close():
    # A full EDT session (UTC-4) closes at 20:00Z. Any time of that New York
    # day gives the same answer, whether the market is open or not.
    edt_close = utc(2026, 7, 15, 20, 0, 0)
    for h, mi in ((13, 30), (15, 0), (19, 0), (23, 0)):
        got = MH.session_close(utc(2026, 7, 15, h, mi, 0))
        assert got == edt_close
        assert isinstance(got, float)

    # EST (UTC-5) closes at 21:00Z.
    assert MH.session_close(utc(2026, 12, 2, 15, 0, 0)) == utc(2026, 12, 2, 21, 0, 0)
    assert MH.session_close(utc(2026, 12, 2, 20, 0, 0)) == utc(2026, 12, 2, 21, 0, 0)

    # An early-close day (2026-11-27, EST) closes at 13:00 ET = 18:00Z.
    assert MH.session_close(utc(2026, 11, 27, 15, 0, 0)) == utc(
        2026, 11, 27, 18, 0, 0
    )

    # No session, no close: a weekend, a holiday, and a year the tables do not
    # cover at all.
    assert MH.session_close(utc(2026, 7, 18, 15, 0, 0)) is None  # Saturday
    assert MH.session_close(utc(2026, 7, 19, 15, 0, 0)) is None  # Sunday
    assert MH.session_close(utc(2026, 11, 26, 15, 0, 0)) is None  # Thanksgiving
    assert MH.session_close(utc(2025, 6, 10, 15, 0, 0)) is None  # uncovered year