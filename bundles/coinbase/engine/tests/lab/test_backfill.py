"""lab/backfill.py: crypto paging, first-available search, stock CSV, gap report."""

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal as D

import pytest

from crow_coinbase.lab.backfill import (
    BackfillReport,
    backfill_crypto,
    first_available,
    gap_report,
    import_stock_csv,
)
from crow_coinbase.lab.store import Bar, LabStore

UTC = timezone.utc

XRP = "XRP-USDC"
NVDA = "NVDA"
SPY = "SPY"

DAY = 86400  # one day of unix seconds
WINDOW = 300 * DAY  # one page of daily candles: 300 * 86400 s


def utc(year, month, day, hour=0, minute=0):
    """A timezone-aware UTC datetime at that clock reading."""
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def epoch(moment):
    """Unix seconds of an aware UTC datetime, the way the public API takes them."""
    return int(moment.timestamp())


# ---------------------------------------------------------------- fake client


class _CandlesResponse:
    """The public client's response shape: `.to_dict()` gives {"candles": [...]}."""

    def __init__(self, candles):
        self._candles = candles

    def to_dict(self):
        return {"candles": list(self._candles)}


class FakeClient:
    """`get_public_candles` over hand-built candles, recording every call.

    Candles are supplied as {unix seconds: {"open","high","low","close",
    "volume"}} and come back the way the public API serves them: as strings, in
    descending order, capped at the 300 most recent candles whose start lies in
    the inclusive [start, end] window.  Every call is appended to `calls` as
    (product_id, start, end, granularity).
    """

    def __init__(self, candles=None):
        self.candles = dict(candles or {})
        self.calls = []

    def get_public_candles(self, product_id, start, end, granularity):
        start_sec, end_sec = int(start), int(end)
        self.calls.append((product_id, start_sec, end_sec, granularity))
        picked = [
            (ts, row)
            for ts, row in self.candles.items()
            if start_sec <= ts <= end_sec
        ]
        picked.sort(key=lambda item: item[0], reverse=True)
        picked = picked[:300]
        return _CandlesResponse(
            [
                {
                    "start": str(ts),
                    "open": str(row["open"]),
                    "high": str(row["high"]),
                    "low": str(row["low"]),
                    "close": str(row["close"]),
                    "volume": str(row["volume"]),
                }
                for ts, row in picked
            ]
        )


# ---------------------------------------------------------------- fixtures


def flat_candle(price):
    """One candle of *price* in all four price columns."""
    text = str(D(price))
    return {"open": text, "high": text, "low": text, "close": text, "volume": "100"}


def daily_series(first_day, count, start_price=D("1.00"), step=D("0.01")):
    """{ts: OHLCV} of flat daily candles from *first_day*, one per day.

    Candle i is priced start_price + i*step, so the closes run 1.00, 1.01, ...
    """
    candles = {}
    for i in range(count):
        price = start_price + step * i
        candles[epoch(first_day + timedelta(days=i))] = flat_candle(price)
    return candles


def bar(ts, price, symbol, interval="1d"):
    """A stored bar whose four price columns all sit at *price*."""
    value = D(price)
    return Bar(
        symbol=symbol,
        interval=interval,
        ts=ts,
        open=value,
        high=value,
        low=value,
        close=value,
        volume=D("1"),
    )


def snapshot(store, symbol, interval, start, end):
    """Every stored bar in range, as the text it round-trips as."""
    return [
        (
            b.ts,
            str(b.open),
            str(b.high),
            str(b.low),
            str(b.close),
            str(b.volume),
            str(b.adj_factor),
        )
        for b in store.bars(symbol, interval, start, end)
    ]


@pytest.fixture
def store(tmp_path):
    s = LabStore(tmp_path / "lab.db")
    yield s
    s.close()


# ---------------------------------------------------------------- crypto paging


def test_crypto_paging_no_overlap(store):
    day0 = utc(2024, 1, 1)
    # 650 daily candles at day0 .. day0+649d, so the range end is day0+650d.
    end = day0 + timedelta(days=650)
    client = FakeClient(daily_series(day0, 650))

    report = backfill_crypto(store, client, XRP, "1d", day0, end)

    assert isinstance(report, BackfillReport)
    # 650 = 300 + 300 + 50: three pages, the last one the 50-day remainder.
    assert report.pages == 3
    assert report.rows_written == 650
    assert report.bad_rows == []
    assert report.first_ts == day0
    assert report.last_ts == day0 + timedelta(days=649)

    calls = client.calls
    assert len(calls) == 3
    assert [c[0] for c in calls] == [XRP, XRP, XRP]
    assert [c[3] for c in calls] == ["ONE_DAY", "ONE_DAY", "ONE_DAY"]
    # Oldest page first, each page starting one 300-day window after the last.
    assert [c[1] for c in calls] == [
        epoch(day0),
        epoch(day0) + WINDOW,
        epoch(day0) + 2 * WINDOW,
    ]
    assert all(a[1] < b[1] for a, b in zip(calls, calls[1:]))

    widths = [c[2] - c[1] for c in calls]
    # The public window includes both of its ends, so a page may stop up to a
    # minute short of its boundary and still carry exactly 300 candles.
    assert WINDOW - 60 <= widths[0] <= WINDOW
    assert WINDOW - 60 <= widths[1] <= WINDOW
    assert 50 * DAY - 60 <= widths[2] <= 50 * DAY

    got = store.bars(XRP, "1d", day0, end)
    assert len(got) == 650
    # One bar a day from the first candle to the last: no duplicates, no holes.
    assert [b.ts for b in got] == [day0 + timedelta(days=i) for i in range(650)]
    assert got[0].close == D("1.00")
    assert got[-1].close == D("7.49")  # 1.00 + 649 * 0.01 out of the fake's data
    assert {b.adj_factor for b in got} == {D("1")}
    assert {b.interval for b in got} == {"1d"}
    assert {b.symbol for b in got} == {XRP}


def test_rerun_idempotent(store):
    day0 = utc(2024, 1, 1)
    end = day0 + timedelta(days=650)
    client = FakeClient(daily_series(day0, 650))

    first = backfill_crypto(store, client, XRP, "1d", day0, end)
    after_first = snapshot(store, XRP, "1d", day0, end)
    assert first.rows_written == 650
    assert len(after_first) == 650

    second = backfill_crypto(store, client, XRP, "1d", day0, end)
    after_second = snapshot(store, XRP, "1d", day0, end)

    # The rerun rewrites the same 650 rows and adds nothing.
    assert second.rows_written == 650
    assert second.pages == first.pages == 3
    assert second.bad_rows == []
    assert len(after_second) == 650
    assert after_second == after_first


# ---------------------------------------------------------------- first available


def test_first_available():
    # A known start: the data begins 2024-03-01 and runs to 2024-12-31
    # (2024-03-01 + 305 days = 2024-12-31), asked from 2025-01-01.
    client = FakeClient(daily_series(utc(2024, 3, 1), 306))
    got = first_available(client, XRP, "1d", now=utc(2025, 1, 1))

    assert got == utc(2024, 3, 1)
    assert got.utcoffset() == timedelta(0)
    assert [c[3] for c in client.calls] == ["ONE_DAY"] * len(client.calls)

    # A suspension: three empty 300-day windows (between 2019-06-11 and
    # 2023-01-01) sit between an older segment and a newer one, and the search
    # crosses them to reach 2019-06-01.
    older = daily_series(utc(2019, 6, 1), 10)  # 2019-06-01 .. 2019-06-10
    newer = daily_series(utc(2023, 1, 1), 90)  # 2023-01-01 .. 2023-03-31
    client = FakeClient({**older, **newer})
    got = first_available(client, XRP, "1d", now=utc(2024, 1, 1))

    assert got == utc(2019, 6, 1)
    gap_lo, gap_hi = epoch(utc(2019, 6, 11)), epoch(utc(2023, 1, 1))
    # At least one window it fetched lies entirely inside the empty stretch.
    assert any(c[1] >= gap_lo and c[2] <= gap_hi for c in client.calls)

    # No data at all: nothing to report, and the search gives up on the
    # consecutive-empty-window rule long before the 200-window cap.
    client = FakeClient()
    assert first_available(client, XRP, "1d", now=utc(2024, 1, 1)) is None
    assert 1 <= len(client.calls) <= 5


# ---------------------------------------------------------------- stock CSV


def test_stock_back_adjust_consistent_ohlc(store):
    csv_text = (
        "date,open,high,low,close,volume,adjClose,divCash,splitFactor\n"
        "2024-06-10,98,102,97,100,500,10,0,10\n"
        "2024-06-11,10,10.4,9.8,10,5000,10,0,1\n"
    )

    report = import_stock_csv(store, NVDA, csv_text, "tiingo")

    assert report.rows_written == 2
    assert report.bad_rows == []
    assert report.source == "tiingo"

    got = store.bars(NVDA, "1d", utc(2024, 6, 10), utc(2024, 6, 12))
    assert [b.ts for b in got] == [utc(2024, 6, 10), utc(2024, 6, 11)]
    day1, day2 = got

    # Day 1, the pre-split side: f = 10 / 100 = 0.1, so the raw
    # 98 / 102 / 97 / 100 becomes 9.8 / 10.2 / 9.7 / 10 and volume stays raw.
    assert day1.open == D("9.8")  # 98 * 0.1
    assert day1.high == D("10.2")  # 102 * 0.1
    assert day1.low == D("9.7")  # 97 * 0.1
    assert day1.close == D("10")  # 100 * 0.1
    assert day1.adj_factor == D("0.1")  # 10 / 100
    assert day1.volume == D("500")

    # Day 2, the post-split side: f = 10 / 10 = 1, so the raw row is kept.
    assert day2.open == D("10")
    assert day2.high == D("10.4")
    assert day2.low == D("9.8")
    assert day2.close == D("10")
    assert day2.adj_factor == D("1")
    assert day2.volume == D("5000")

    # One factor scales all four prices, so the adjusted OHLC stays ordered and
    # the close does not jump across the 10:1 split.
    for b in (day1, day2):
        assert b.low <= b.open <= b.high
        assert b.low <= b.close <= b.high
    assert day1.close == day2.close


def test_bad_row_reported(store):
    csv_text = (
        "date,open,high,low,close,volume,adjClose\n"
        "2024-06-10,10,10.5,9.5,10.2,1000,10.2\n"  # line 2: imported
        "2024-06-11,10,10.5,9.5,abc,1000,10.2\n"  # line 3: close is not numeric
        "2024-06-12,10,9.0,9.5,9.8,1000,9.8\n"  # line 4: high 9.0 < low 9.5
    )

    report = import_stock_csv(store, NVDA, csv_text, "tiingo")

    # The good row still lands; the two bad rows are reported by file line
    # number, counting the header as line 1.
    assert report.rows_written == 1
    assert [locator for locator, _reason in report.bad_rows] == ["line 3", "line 4"]
    assert all(isinstance(reason, str) and reason for _, reason in report.bad_rows)

    got = store.bars(NVDA, "1d", utc(2024, 6, 1), utc(2024, 7, 1))
    assert [b.ts for b in got] == [utc(2024, 6, 10)]
    assert got[0].close == D("10.2")  # f = 10.2 / 10.2 = 1
    assert got[0].adj_factor == D("1")


def test_backfill_bad_candle_reported(store):
    day0 = utc(2024, 1, 1)
    bad_ts = epoch(day0 + timedelta(days=1))
    candles = {
        epoch(day0): flat_candle("1.00"),
        # Low 2.00 sits above high 1.00, with open and close between them.
        bad_ts: {
            "open": "1.50",
            "high": "1.00",
            "low": "2.00",
            "close": "1.50",
            "volume": "100",
        },
        epoch(day0 + timedelta(days=2)): flat_candle("1.02"),
    }
    client = FakeClient(candles)

    report = backfill_crypto(
        store, client, XRP, "1d", day0, day0 + timedelta(days=3)
    )

    # The bad candle is skipped and named by its start, the other two are kept.
    assert report.pages == 1
    assert report.rows_written == 2
    assert len(report.bad_rows) == 1
    locator, reason = report.bad_rows[0]
    assert locator == f"candle start={bad_ts}"
    assert isinstance(reason, str) and reason

    got = store.bars(XRP, "1d", day0, day0 + timedelta(days=3))
    assert [b.ts for b in got] == [day0, day0 + timedelta(days=2)]


# ---------------------------------------------------------------- gap report


def test_gap_report_crypto_suspension_window(store):
    days = [utc(2020, 1, d) for d in (1, 2, 3, 4, 5, 10, 11, 12)]
    store.upsert_bars(XRP, "1d", [bar(ts, "1.00", XRP) for ts in days])

    # 2020-01-06 .. 2020-01-09 sit between the two runs of bars.
    assert gap_report(store, XRP, "1d", "crypto", frozenset()) == [
        (date(2020, 1, 6), date(2020, 1, 9))
    ]


def test_gap_report_nyse_holidays(store):
    # Mon 2024-01-15, Tue 2024-01-16, Thu 2024-01-18: Wed the 17th is missing.
    store.upsert_bars(
        NVDA, "1d", [bar(utc(2024, 1, d), "10.00", NVDA) for d in (15, 16, 18)]
    )

    # A holiday is never expected, so nothing is reported for the 17th.
    assert gap_report(store, NVDA, "1d", "nyse", frozenset({date(2024, 1, 17)})) == []
    # With no holiday on file the same Wednesday is the one missing session.
    assert gap_report(store, NVDA, "1d", "nyse", frozenset()) == [
        (date(2024, 1, 17), date(2024, 1, 17))
    ]

    # Fri 2024-01-19 to Mon 2024-01-22: the weekend in between is never a gap.
    store.upsert_bars(
        SPY,
        "1d",
        [bar(utc(2024, 1, 19), "10.00", SPY), bar(utc(2024, 1, 22), "10.00", SPY)],
    )
    assert gap_report(store, SPY, "1d", "nyse", frozenset()) == []

    # The NYSE calendar is a daily one: an hourly series has no sessions to expect.
    with pytest.raises(ValueError):
        gap_report(store, NVDA, "1h", "nyse", frozenset())


# ---------------------------------------------------------------- refusals


def test_naive_datetime_refused(store):
    day0 = utc(2024, 1, 1)
    end = day0 + timedelta(days=10)
    client = FakeClient(daily_series(day0, 10))

    with pytest.raises(ValueError):
        backfill_crypto(store, client, XRP, "1d", day0.replace(tzinfo=None), end)
    with pytest.raises(ValueError):
        backfill_crypto(store, client, XRP, "1d", day0, end.replace(tzinfo=None))
    # An empty or a backwards range is refused as well.
    with pytest.raises(ValueError):
        backfill_crypto(store, client, XRP, "1d", end, end)
    with pytest.raises(ValueError):
        backfill_crypto(store, client, XRP, "1d", end, day0)

    # None of the refused calls reached the client or wrote a bar.
    assert client.calls == []
    assert store.bars(XRP, "1d", day0, end) == []


def test_still_forming_candle_dropped(store):
    start = utc(2024, 1, 1, 8)
    end = utc(2024, 1, 1, 11)
    client = FakeClient(
        {
            epoch(utc(2024, 1, 1, 8)): flat_candle("1.00"),
            epoch(utc(2024, 1, 1, 9)): flat_candle("1.01"),
            epoch(utc(2024, 1, 1, 10)): flat_candle("1.02"),
        }
    )

    # the 10:00 candle runs until 11:00, so at 10:30 it is still forming and is
    # neither stored nor counted
    forming = backfill_crypto(
        store, client, XRP, "1h", start, end, now=utc(2024, 1, 1, 10, 30)
    )
    assert forming.rows_written == 2
    assert [b.ts for b in store.bars(XRP, "1h", start, end)] == [
        utc(2024, 1, 1, 8),
        utc(2024, 1, 1, 9),
    ]

    # at 11:00 that candle has closed, so all three land
    closed = backfill_crypto(
        store, client, XRP, "1h", start, end, now=utc(2024, 1, 1, 11, 0)
    )
    assert closed.rows_written == 3
    assert [b.ts for b in store.bars(XRP, "1h", start, end)] == [
        utc(2024, 1, 1, 8),
        utc(2024, 1, 1, 9),
        utc(2024, 1, 1, 10),
    ]