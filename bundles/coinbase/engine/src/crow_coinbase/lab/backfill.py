"""Offline back-fill for the research lab: candles, stock CSV and gap reports.

Every function here is pure over an injected data source and an injected
`LabStore`.  The candle client arrives as an argument with the
`get_public_candles` shape; stock history arrives as CSV text already in hand.
The module opens no connection, holds no credential and reads no file for one,
so it works with the network down.

Money and prices are `Decimal` throughout and a float is refused rather than
converted.  Every datetime is timezone-aware UTC, and a naive one raises
`ValueError` instead of being guessed at.

Candle pages are 300 candles wide and walked oldest first.  The public window
includes both of its ends, so the requested end is the page boundary minus one
second; a candle is kept only when `page_start <= ts < page_end`, which keeps
adjacent pages from returning the same boundary candle twice.  Paging the same
range again rewrites the same rows and adds none.  A candle that has not closed
yet is still forming and is dropped, so a partial bar never reaches the store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal as D
from decimal import InvalidOperation
from typing import Any, Iterator, Literal, Optional

from .store import Bar, LabStore

__all__ = [
    "BackfillReport",
    "backfill_crypto",
    "first_available",
    "gap_report",
    "import_stock_csv",
]

UTC = timezone.utc
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# One page holds at most 300 candles of the interval being asked for.
PAGE_CANDLES = 300
_GRANULARITY = {"1h": "ONE_HOUR", "1d": "ONE_DAY"}
_WINDOW = {
    "1h": timedelta(hours=PAGE_CANDLES),
    "1d": timedelta(days=PAGE_CANDLES),
}

# How much time one candle of each interval covers.
_CANDLE_LENGTH = {"1h": timedelta(hours=1), "1d": timedelta(days=1)}

CALENDARS = ("crypto", "nyse")

# Stock CSV: the required columns, matched case-insensitively; anything else in
# the header (divCash, splitFactor, adjOpen, ...) is ignored.
STOCK_COLUMNS = ("date", "open", "high", "low", "close", "volume", "adjclose")
_STOCK_PRICES = ("open", "high", "low", "close")

# The wide range the gap report reads stored bars over.
_LAB_FLOOR = datetime(1990, 1, 1, tzinfo=UTC)
_LAB_CEILING = datetime(2100, 1, 1, tzinfo=UTC)


@dataclass
class BackfillReport:
    """What one back-fill did: rows, pages, the refusals, and the span."""

    rows_written: int = 0
    pages: int = 0
    bad_rows: list[tuple[str, str]] = field(default_factory=list)
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    source: str = ""


# ---------------------------------------------------------------- value helpers


def _utc(moment: Any, name: str = "datetime") -> datetime:
    """*moment* rendered as UTC; a naive (or non-) datetime is refused."""
    if not isinstance(moment, datetime):
        raise ValueError(f"{name} must be a datetime: {moment!r}")
    info = moment.tzinfo
    if info is None or info.utcoffset(moment) is None:
        raise ValueError(f"{name} must be timezone-aware: {moment!r}")
    return moment.astimezone(UTC)


def _unix_seconds(moment: datetime) -> int:
    """Whole unix seconds of an aware datetime (sub-second part dropped)."""
    delta = _utc(moment) - _EPOCH
    return delta.days * 86400 + delta.seconds


def _moment(seconds: int) -> datetime:
    """The aware UTC datetime *seconds* unix seconds after the epoch."""
    return _EPOCH + timedelta(seconds=seconds)


def _whole_seconds(value: Any) -> int:
    """A whole count of unix seconds from an int, str or Decimal field."""
    if isinstance(value, bool) or value is None:
        raise ValueError(f"not a whole number of seconds: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ValueError(f"seconds must not be a float: {value!r}")
    try:
        number = value if isinstance(value, D) else D(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"not a number: {value!r}") from exc
    if not number.is_finite() or number != number.to_integral_value():
        raise ValueError(f"not a whole number of seconds: {value!r}")
    return int(number)


def _decimal(value: Any, name: str) -> D:
    """A finite Decimal from a data field; blank, odd and float are refused."""
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{name} is missing")
    if isinstance(value, D):
        number = value
    elif isinstance(value, (int, str)):
        text = str(value).strip()
        if not text:
            raise ValueError(f"{name} is blank")
        try:
            number = D(text)
        except InvalidOperation as exc:
            raise ValueError(f"{name} is not a number: {value!r}") from exc
    else:
        raise ValueError(f"{name} is not a number: {value!r}")
    if not number.is_finite():
        raise ValueError(f"{name} is not a finite number: {value!r}")
    return number


def _interval(interval: Any) -> str:
    """The interval key, refused unless it is one the lab stores."""
    if interval not in _WINDOW:
        raise ValueError(
            f"invalid interval {interval!r}; expected one of {sorted(_WINDOW)}"
        )
    return interval


# ---------------------------------------------------------------- candles


class _BadCandle(Exception):
    """One candle the store will not take, with the locator to report it by."""

    def __init__(self, locator: str, reason: str):
        super().__init__(reason)
        self.locator = locator
        self.reason = reason


def _candle_start(raw: Any) -> int:
    """The candle's own start as whole unix seconds, else `_BadCandle`."""
    if not isinstance(raw, dict):
        raise _BadCandle("candle start=None", "candle is not an object")
    raw_start = raw.get("start")
    try:
        return _whole_seconds(raw_start)
    except ValueError as exc:
        raise _BadCandle(f"candle start={raw_start}", f"start: {exc}") from exc


def _candle_bar(raw: Any, seconds: int, product_id: str, interval: str) -> Bar:
    """The stored Bar of one candle, else `_BadCandle` with a reason.

    A candle is refused when a field is missing, blank or non-numeric, when a
    price is not positive, when low sits above high, or when open or close falls
    outside the low/high range: such a row would poison a study downstream.
    """
    if not isinstance(raw, dict):
        raise _BadCandle("candle start=None", "candle is not an object")
    locator = f"candle start={seconds}"
    values: dict[str, D] = {}
    for name in ("open", "high", "low", "close", "volume"):
        try:
            values[name] = _decimal(raw.get(name), name)
        except ValueError as exc:
            raise _BadCandle(locator, str(exc)) from exc
    open_, high, low, close = (
        values["open"],
        values["high"],
        values["low"],
        values["close"],
    )
    if min(open_, high, low, close) <= 0:
        raise _BadCandle(locator, "a price is not positive")
    if low > high:
        raise _BadCandle(locator, "low sits above high")
    if not low <= open_ <= high:
        raise _BadCandle(locator, "open is outside the low/high range")
    if not low <= close <= high:
        raise _BadCandle(locator, "close is outside the low/high range")
    return Bar(
        symbol=product_id,
        interval=interval,
        ts=_moment(seconds),
        open=open_,
        high=high,
        low=low,
        close=close,
        volume=values["volume"],
        adj_factor=D("1"),
    )


def _candles(response: Any) -> list:
    """The candle list out of a public-candle response object."""
    to_dict = getattr(response, "to_dict", None)
    payload = to_dict() if callable(to_dict) else response
    if not isinstance(payload, dict):
        return []
    candles = payload.get("candles")
    return list(candles) if isinstance(candles, (list, tuple)) else []


def _track(report: BackfillReport, moment: datetime) -> None:
    """Widen the reported span to include *moment*."""
    if report.first_ts is None or moment < report.first_ts:
        report.first_ts = moment
    if report.last_ts is None or moment > report.last_ts:
        report.last_ts = moment


# ---------------------------------------------------------------- crypto paging


def backfill_crypto(
    store: LabStore,
    client: Any,
    product_id: str,
    interval: Literal["1h", "1d"],
    start: datetime,
    end: datetime,
    *,
    now: Optional[datetime] = None,
) -> BackfillReport:
    """Store every candle of the half-open range [start, end), oldest page first.

    Page k covers [start + k*W, min(start + (k+1)*W, end)) with W the width of
    300 candles, and a candle is kept only when its own start lies inside that
    half-open window.  `pages` counts every call made, empty windows included:
    an exchange suspension is a normal, empty answer and not an error.

    A candle whose own span (its start plus one interval) ends after *now*
    (default: the current UTC time) is still forming.  It is dropped, so it
    counts in neither `rows_written` nor the reported span.
    """
    key = _interval(interval)
    first = _utc(start, "start")
    last = _utc(end, "end")
    if first >= last:
        raise ValueError(f"start must be before end: {first!r} >= {last!r}")
    moment_now = datetime.now(UTC) if now is None else _utc(now, "now")
    window = _WINDOW[key]
    length = _CANDLE_LENGTH[key]
    granularity = _GRANULARITY[key]
    report = BackfillReport()
    page = 0
    while True:
        page_start = first + window * page
        if page_start >= last:
            break
        page_end = min(page_start + window, last)
        page_start_sec = _unix_seconds(page_start)
        page_end_sec = _unix_seconds(page_end)
        report.pages += 1
        # The public window includes both ends: ask for the boundary minus a
        # second so the next page does not serve the same candle again.
        response = client.get_public_candles(
            product_id,
            start=str(page_start_sec),
            end=str(page_end_sec - 1),
            granularity=granularity,
        )
        bars: list[Bar] = []
        for raw in _candles(response):
            try:
                seconds = _candle_start(raw)
            except _BadCandle as bad:
                report.bad_rows.append((bad.locator, bad.reason))
                continue
            # A candle outside this half-open page belongs to another page (or
            # to none), so it is dropped instead of being stored twice.
            if not page_start_sec <= seconds < page_end_sec:
                continue
            # A candle that has not closed yet is a partial bar: dropped, and
            # neither stored nor reported.
            if _moment(seconds) + length > moment_now:
                continue
            try:
                bars.append(_candle_bar(raw, seconds, product_id, key))
            except _BadCandle as bad:
                report.bad_rows.append((bad.locator, bad.reason))
        bars.sort(key=lambda candle_bar: candle_bar.ts)
        report.rows_written += store.upsert_bars(product_id, key, bars)
        for candle_bar in bars:
            _track(report, candle_bar.ts)
        page += 1
    return report


def first_available(
    client: Any,
    product_id: str,
    interval: Literal["1h", "1d"],
    now: Optional[datetime] = None,
    max_empty_windows: int = 5,
    max_windows: int = 200,
) -> Optional[datetime]:
    """The earliest candle start reachable by walking pages backwards from *now*.

    A run of empty windows shorter than `max_empty_windows` does not end the
    search, so a suspension between an older segment and a newer one is crossed;
    a long enough run after data ends it, and a long enough run before any data
    means there is nothing to find (`None`).  `max_windows` caps the calls.
    """
    key = _interval(interval)
    if max_empty_windows < 1:
        raise ValueError(f"max_empty_windows must be at least 1: {max_empty_windows!r}")
    if max_windows < 1:
        raise ValueError(f"max_windows must be at least 1: {max_windows!r}")
    newest = datetime.now(UTC) if now is None else _utc(now, "now")
    window = _WINDOW[key]
    granularity = _GRANULARITY[key]
    earliest: Optional[int] = None
    seen_data = False
    empty_run = 0
    fetched = 0
    while fetched < max_windows:
        page_end = newest - window * fetched
        page_start = page_end - window
        page_start_sec = _unix_seconds(page_start)
        page_end_sec = _unix_seconds(page_end)
        response = client.get_public_candles(
            product_id,
            start=str(page_start_sec),
            end=str(page_end_sec - 1),
            granularity=granularity,
        )
        fetched += 1
        starts: list[int] = []
        for raw in _candles(response):
            raw_start = raw.get("start") if isinstance(raw, dict) else None
            try:
                seconds = _whole_seconds(raw_start)
            except ValueError:
                continue
            if page_start_sec <= seconds < page_end_sec:
                starts.append(seconds)
        if starts:
            seen_data = True
            empty_run = 0
            page_earliest = min(starts)
            if earliest is None or page_earliest < earliest:
                earliest = page_earliest
            continue
        empty_run += 1
        if empty_run >= max_empty_windows:
            break
    if earliest is None:
        return None
    return _moment(earliest)


# ---------------------------------------------------------------- stock CSV


def _split_row(text: str) -> list[str]:
    """The comma-separated fields of one CSV line, quote-aware and stripped."""
    fields: list[str] = []
    current: list[str] = []
    quoted = False
    for char in text:
        if char == '"':
            quoted = not quoted
            continue
        if char == "," and not quoted:
            fields.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    fields.append("".join(current).strip())
    return fields


def _stock_header(lines: list[str]) -> tuple[int, dict[str, int], int]:
    """(header line number, column name -> field index, header field count)."""
    for index, text in enumerate(lines):
        if not text.strip():
            continue
        fields = _split_row(text)
        columns: dict[str, int] = {}
        for position, name in enumerate(fields):
            key = name.strip().lower()
            if key and key not in columns:
                columns[key] = position
        return index + 1, columns, len(fields)
    raise ValueError("the CSV text has no header row")


def _stock_date(raw: Any) -> date:
    """The row's session date from a YYYY-MM-DD field."""
    text = str(raw).strip()
    if not text:
        raise ValueError("date is blank")
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"date is not YYYY-MM-DD: {raw!r}") from exc


def _stock_price(raw: Any, name: str) -> D:
    """A strictly positive price from a CSV field."""
    value = _decimal(raw, name)
    if value <= 0:
        raise ValueError(f"{name} is not positive: {raw!r}")
    return value


def _at_midnight(day: date) -> datetime:
    """That session date at 00:00 UTC."""
    return datetime(day.year, day.month, day.day, tzinfo=UTC)


def import_stock_csv(
    store: LabStore,
    symbol: str,
    csv_text: str,
    source: str,
) -> BackfillReport:
    """Store daily bars from CSV text, back-adjusted by one factor per row.

    The factor is `f = adjClose / close`, and the same `f` scales open, high, low
    and close, so a row's adjusted prices stay ordered and the close does not
    jump across a split; `volume` is the raw volume and `adj_factor` is `f`.  A
    row with a bad date, a missing/blank/non-numeric field, a non-positive
    price, `high < low` or `adjClose <= 0` is left out and reported by its file
    line number (the header is line 1).  The rest still land.
    """
    report = BackfillReport(source=str(source))
    lines = str(csv_text).splitlines()
    try:
        header_line, columns, width = _stock_header(lines)
    except ValueError as exc:
        report.bad_rows.append(("line 1", str(exc)))
        return report
    missing = [name for name in STOCK_COLUMNS if name not in columns]
    if missing:
        report.bad_rows.append(
            (f"line {header_line}", "missing column(s): " + ", ".join(missing))
        )
        return report
    bars: list[Bar] = []
    for offset in range(header_line, len(lines)):
        text = lines[offset]
        line_no = offset + 1
        if not text.strip():
            continue
        fields = _split_row(text)
        if len(fields) < width:
            report.bad_rows.append(
                (
                    f"line {line_no}",
                    f"has {len(fields)} field(s), the header has {width}",
                )
            )
            continue
        try:
            day = _stock_date(fields[columns["date"]])
            prices = {
                name: _stock_price(fields[columns[name]], name)
                for name in _STOCK_PRICES
            }
            volume = _decimal(fields[columns["volume"]], "volume")
            adjusted_close = _stock_price(fields[columns["adjclose"]], "adjClose")
            if prices["high"] < prices["low"]:
                raise ValueError("high sits below low")
        except ValueError as exc:
            report.bad_rows.append((f"line {line_no}", str(exc)))
            continue
        factor = adjusted_close / prices["close"]
        bars.append(
            Bar(
                symbol=symbol,
                interval="1d",
                ts=_at_midnight(day),
                open=prices["open"] * factor,
                high=prices["high"] * factor,
                low=prices["low"] * factor,
                close=prices["close"] * factor,
                volume=volume,
                adj_factor=factor,
            )
        )
    if bars:
        bars.sort(key=lambda row: row.ts)
        report.rows_written = store.upsert_bars(symbol, "1d", bars)
        report.first_ts = bars[0].ts
        report.last_ts = bars[-1].ts
    return report


# ---------------------------------------------------------------- gap report


def _day(moment: datetime) -> datetime:
    """That UTC day at 00:00."""
    moment = _utc(moment)
    return datetime(moment.year, moment.month, moment.day, tzinfo=UTC)


def _hour(moment: datetime) -> datetime:
    """That UTC hour at its start."""
    moment = _utc(moment)
    return datetime(
        moment.year, moment.month, moment.day, moment.hour, tzinfo=UTC
    )


def _day_points(
    first: datetime, last: datetime, calendar: str, holidays: frozenset
) -> Iterator[datetime]:
    """Every day from *first* to *last* the calendar expects a bar on."""
    day = first
    while day <= last:
        weekday = day.weekday()
        if calendar == "crypto" or (
            weekday < 5 and day.date() not in holidays
        ):
            yield day
        day += timedelta(days=1)


def _hour_points(first: datetime, last: datetime) -> Iterator[datetime]:
    """Every hour from *first* to *last*."""
    moment = first
    while moment <= last:
        yield moment
        moment += timedelta(hours=1)


def _missing_runs(points: list[datetime], present: set) -> list[tuple[datetime, datetime]]:
    """Maximal runs of consecutive expected points that have no bar.

    Runs are adjacency in the expected calendar: a weekend or a holiday is not
    an expected point, so it does not split a run in two.
    """
    runs: list[tuple[datetime, datetime]] = []
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    for point in points:
        if point in present:
            if start is not None:
                runs.append((start, end))
                start = end = None
            continue
        if start is None:
            start = end = point
        else:
            end = point
    if start is not None:
        runs.append((start, end))
    return runs


def gap_report(
    store: LabStore,
    symbol: str,
    interval: Literal["1h", "1d"],
    calendar: Literal["crypto", "nyse"],
    holidays: frozenset[date],
) -> list[tuple[date, date]]:
    """Runs of expected-but-missing bars between the first and last stored bar.

    Each run comes back as (date of the first missing bar, date of the last),
    both inclusive, ascending.  The crypto calendar expects every day (1d) or
    every hour (1h); the NYSE calendar is a daily one, so it expects Monday to
    Friday outside the `holidays` given, and refuses an hourly series.  Fewer
    than two stored bars means there is no interior to report on.
    """
    key = _interval(interval)
    if calendar not in CALENDARS:
        raise ValueError(
            f"invalid calendar {calendar!r}; expected one of {list(CALENDARS)}"
        )
    if calendar == "nyse" and key == "1h":
        raise ValueError("the nyse calendar is a daily one; 1h bars have no sessions")
    kept = frozenset(holidays) if holidays else frozenset()
    bars = store.bars(symbol, key, _LAB_FLOOR, _LAB_CEILING)
    if len(bars) < 2:
        return []
    if key == "1d":
        present = {_day(row.ts) for row in bars}
        ordered = sorted(present)
        points = list(_day_points(ordered[0], ordered[-1], calendar, kept))
    else:
        present = {_hour(row.ts) for row in bars}
        ordered = sorted(present)
        points = list(_hour_points(ordered[0], ordered[-1]))
    return [
        (start.date(), end.date()) for start, end in _missing_runs(points, present)
    ]