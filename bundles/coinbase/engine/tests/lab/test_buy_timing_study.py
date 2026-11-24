"""lab/studies/buy_timing.py: the when-to-buy study, its helpers and its report.

Every expected money value is a literal with the arithmetic that produces it in
a comment beside it, and the statistical series are seeded.

Index facts for weekday bars from Monday 2024-01-01: index 5k is a Monday, and a
450 calendar day window of a Monday start ends on bar s + 322 (450 = 64 weeks +
2 days = 320 + 2 bars), so a start needs s + 323 bars.
"""

import math
import random
import statistics
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal as D

import pytest

from crow_coinbase.lab.costs import CostModel
from crow_coinbase.lab.store import Bar, Event
from crow_coinbase.lab.studies.buy_timing import (
    block_bootstrap_ci,
    count_nonoverlapping,
    percentile,
    remove_drift,
    run_study,
)

UTC = timezone.utc

# No taker fee, no slippage and no tax, so a fill price is the bar's open.
ZERO = CostModel.for_stock(
    "NVDA", st_tax_rate=D("0"), lt_tax_rate=D("0"), slippage=D("0")
)
# The same model with 1% of slippage on each fill.
SLIP = CostModel.for_stock(
    "NVDA", st_tax_rate=D("0"), lt_tax_rate=D("0"), slippage=D("0.01")
)

# The eleven base options: lump, split2 and the 3 x 3 trend grid.
BASE_OPTIONS = frozenset(
    {"lump", "split2"}
    | {f"trend N={n} D={d}" for n in (20, 50, 100) for d in (10, 20, 40)}
)


def utc(year, month, day, hour=0):
    """A timezone-aware UTC datetime at that clock reading."""
    return datetime(year, month, day, hour, tzinfo=UTC)


def weekday_bars(symbol, rows, start=date(2024, 1, 1)):
    """One daily bar per weekday from *start*, from (open, close) rows.

    Weekend days carry no bar, so row k lands on the k-th weekday from *start*.
    high is max(open, close) + 1, low is min(open, close) - 1, volume is 1 and
    the stamp is 00:00 UTC of that weekday.
    """
    out = []
    day = start
    for open_, close in rows:
        while day.weekday() >= 5:
            day += timedelta(days=1)
        o = D(str(open_))
        c = D(str(close))
        out.append(
            Bar(
                symbol=symbol,
                interval="1d",
                ts=datetime(day.year, day.month, day.day, tzinfo=UTC),
                open=o,
                high=(c if c > o else o) + D("1"),
                low=(c if c < o else o) - D("1"),
                close=c,
                volume=D("1"),
            )
        )
        day += timedelta(days=1)
    return out


def flat_rows(price, n):
    """*n* (open, close) rows that do not move."""
    return [(price, price) for _ in range(n)]


def option(result, label, name):
    """The named option of the named series."""
    return result.series[label].options[name]


def fills(result, label, name):
    """The fill stamps of the named option's first start."""
    return result.series[label].options[name].starts[0].buy_ts


def earnings_event(symbol="NVDA"):
    """An earnings release on Tue 16 January 2024 after the close."""
    return Event(
        symbol=symbol,
        kind="earnings",
        at=utc(2024, 1, 16, 20),
        announced_at=utc(2024, 1, 2),
        session="post",
        note="",
    )


def walk_bars(symbol, seed=2, count=600):
    """A seeded walk: closes 100*exp(cumulative gauss), open = last close."""
    rng = random.Random(seed)
    closes = []
    level = 0.0
    for _ in range(count):
        level += rng.gauss(0.0005, 0.01)
        closes.append(100.0 * math.exp(level))
    rows = [(100.0, closes[0])] + [
        (closes[index - 1], closes[index]) for index in range(1, count)
    ]
    return weekday_bars(symbol, rows)


def nvda_study(**overrides):
    """The flat NVDA study the validation and block-length tests start from.

    With weekday bars from 2024-01-01 and a 450-day horizon, start 0's window
    runs over bars 0..322, so it spans 323 bars, and a bootstrap block of 400
    bars is not shorter than any window the study runs.
    """
    values = dict(
        bars_by_symbol={"NVDA": weekday_bars("NVDA", flat_rows(100, 340))},
        events_by_symbol={},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )
    values.update(overrides)
    return run_study(**values)


# ---------------------------------------------------------------- the study


def test_dollar_difference():
    # 200 at bar 0's open of 100 buys 2 units, marked at the last close of 110:
    # 2 * 110 = 220.
    rows = flat_rows(100, 10) + flat_rows(110, 330)
    bars = weekday_bars("NVDA", rows)
    result = run_study(
        {"NVDA": bars},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )

    lump = option(result, "NVDA", "lump")
    assert lump.starts[0].buy_ts == [bars[0].ts]
    assert lump.summary["value_after_tax_median"] == pytest.approx(
        220.0, abs=1e-6
    )
    assert lump.summary["dollar_median_diff"] is None
    assert lump.summary["share_beating_lump"] is None

    # bar 10 is Mon 15 January, exactly 14 days after bar 0
    assert bars[10].ts == utc(2024, 1, 15)
    # the first half's 100 buys 1 unit at 100; the second half waits for bar 10,
    # whose open is 110, so it buys 100 / 110 units: 110 * (1 + 100 / 110) = 210,
    # and 210 - 220 = -10.
    split = option(result, "NVDA", "split2")
    assert split.starts[0].buy_ts == [bars[0].ts, bars[10].ts]
    assert split.summary["dollar_median_diff"] == pytest.approx(-10.0, abs=1e-6)
    assert split.summary["dollar_median_diff_pretax"] == pytest.approx(
        -10.0, abs=1e-6
    )
    assert split.summary["share_beating_lump"] == 0.0


def test_same_cash_costs():
    rows = flat_rows(100, 10) + flat_rows(110, 330)
    result = run_study(
        {"NVDA": weekday_bars("NVDA", rows), "SPY": weekday_bars("SPY", rows)},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=SLIP,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )

    # a buy pays 100 * 1.01 = 101, so 200 / 101 units, and the last close of 110
    # marks them at 110 * 200 / 101 = 217.82178217821782
    lump = option(result, "NVDA", "lump")
    assert lump.starts[0].value_after_tax == pytest.approx(
        D("217.82178217821782"), abs=1e-6
    )

    # every option spends the whole 200: the trend options that never see their
    # condition buy at their deadline, so no cash is left waiting.
    for label, series in result.series.items():
        for name, found in series.options.items():
            assert found.starts
            for outcome in found.starts:
                assert outcome.spent == pytest.approx(D("200"), abs=1e-9), (
                    label,
                    name,
                )

    # the study puts each symbol's own name on the model it runs, so a model
    # named for another asset still runs over the NVDA series
    elsewhere = run_study(
        {"NVDA": weekday_bars("NVDA", rows)},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=CostModel.for_stock(
            "XYZ", st_tax_rate=D("0"), lt_tax_rate=D("0"), slippage=D("0.01")
        ),
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )
    other_lump = option(elsewhere, "NVDA", "lump").starts[0]
    assert other_lump.value_after_tax == pytest.approx(
        D("217.82178217821782"), abs=1e-6
    )


def test_deadline_forces_buy():
    # close_i = 400 - i and open_i = the previous close, so bar 11 opens at 390
    # and the closes fall every session.
    falls = [(400, 400)] + [(401 - i, 400 - i) for i in range(1, 340)]
    bars = weekday_bars("NVDA", falls)
    result = run_study(
        {"NVDA": bars},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )

    # a falling close is never above its own average, so the buy waits for the
    # deadline at k = D and fills at bar D + 1's open
    for n in (20, 50, 100):
        for d in (10, 20, 40):
            assert fills(result, "NVDA", f"trend N={n} D={d}") == [
                bars[d + 1].ts
            ]

    # 200 / 390 units; the window of start 0 ends at bar 322 (the 450-day
    # boundary), whose close is 400 - 322 = 78, so 200 / 390 * 78 = 40
    assert bars[322].close == D("78")
    deadline = option(result, "NVDA", "trend N=20 D=10").starts[0]
    assert deadline.buy_ts == [bars[11].ts]
    assert deadline.value_after_tax == pytest.approx(D("40"), abs=1e-6)

    # close_i = 100 + i and open_i = the previous close
    rises = [(100, 100)] + [(100 + i - 1, 100 + i) for i in range(1, 340)]
    up = weekday_bars("NVDA", rises)
    rising = run_study(
        {"NVDA": up},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )

    # 20 bars are first seen at bar 19, whose close of 119 is above the mean of
    # 100..119 = 109.5, so the buy is decided there and fills at bar 20
    assert fills(rising, "NVDA", "trend N=20 D=40") == [up[20].ts]
    # the deadline of 10 comes before 20 bars are seen: bar 11's open
    assert fills(rising, "NVDA", "trend N=20 D=10") == [up[11].ts]
    # 50 bars need k = 49, past the deadline of 40: bar 41's open
    assert fills(rising, "NVDA", "trend N=50 D=40") == [up[41].ts]


def test_veto_shifts_buy():
    rows = flat_rows(100, 340)
    bars = weekday_bars("NVDA", rows)
    result = run_study(
        {"NVDA": bars, "SPY": weekday_bars("SPY", rows)},
        {"NVDA": [earnings_event()]},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[10],
        n_boot=40,
    )

    # bar 10 is Mon 15 January, a holiday, and the release after Tue 16
    # January's close reacts on Wed 17 January.  The next session after Fri 12
    # and the next session after Mon 15 are both Tue 16, so with 3 veto days the
    # window holds a decision at Fri 12 and at Mon 15 (one session out each) but
    # not one at Tue 16 (0): the buy leaves at the decision on bar 11 and fills
    # at bar 12.
    assert bars[10].ts == utc(2024, 1, 15)
    assert fills(result, "NVDA", "lump") == [bars[10].ts]
    assert fills(result, "NVDA", "lump +veto") == [bars[12].ts]

    # with no events the same options buy where they did with the events in play
    plain = run_study(
        {"NVDA": weekday_bars("NVDA", rows)},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[10],
        n_boot=40,
    )
    for name in plain.series["NVDA"].options:
        with_events = option(result, "NVDA", name).starts[0]
        without = option(plain, "NVDA", name).starts[0]
        assert with_events.buy_ts == without.buy_ts
        assert with_events.value_after_tax == without.value_after_tax

    # a control carries no events, so it gets no window variants
    assert [n for n in result.series["SPY"].options if n.endswith("+veto")] == []
    # nor does a stock without an event
    assert [n for n in plain.series["NVDA"].options if n.endswith("+veto")] == []

    custom = run_study(
        {"NVDA": weekday_bars("NVDA", rows)},
        {
            "NVDA": [
                Event(
                    symbol="NVDA",
                    kind="custom",
                    at=utc(2024, 1, 16, 20),
                    announced_at=utc(2024, 1, 2),
                    session="post",
                    note="",
                )
            ]
        },
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[10],
        n_boot=40,
    )
    assert [n for n in custom.series["NVDA"].options if n.endswith("+veto")] == []


def test_every_grid_point_reported():
    rows = flat_rows(100, 340)
    result = run_study(
        {"NVDA": weekday_bars("NVDA", rows), "SPY": weekday_bars("SPY", rows)},
        {"NVDA": [earnings_event()]},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )

    assert set(result.series) == {"NVDA", "NVDA (no median drift)", "SPY"}

    # eleven base options and the same eleven behind the veto
    for label in ("NVDA", "NVDA (no median drift)"):
        assert set(result.series[label].options) == set(BASE_OPTIONS) | {
            f"{name} +veto" for name in BASE_OPTIONS
        }
    # a control has no events, so it has only the base options
    assert set(result.series["SPY"].options) == set(BASE_OPTIONS)

    assert result.series["SPY"].control is True
    assert result.series["SPY"].drift_removed is False
    assert result.series["NVDA"].control is False
    assert result.series["NVDA"].drift_removed is False
    assert result.series["NVDA (no median drift)"].control is False
    assert result.series["NVDA (no median drift)"].drift_removed is True


def test_nonoverlap_count():
    # (0, 8) is taken, then (10, 18) and (20, 28)
    assert (
        count_nonoverlapping(
            [(0, 8), (5, 13), (10, 18), (15, 23), (20, 28), (25, 33)]
        )
        == 3
    )
    assert count_nonoverlapping([]) == 0
    # a window starting exactly where the previous one ends is taken
    assert count_nonoverlapping([(0, 5), (5, 9)]) == 2

    bars = weekday_bars("NVDA", flat_rows(100, 1030))
    result = run_study(
        {"NVDA": bars},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0, 100, 325, 350, 700],
        n_boot=40,
    )
    series = result.series["NVDA"]
    # the windows end at 322, 422, 647, 672 and 1022, so the ones taken are
    # 0 (ends 322), 325 (ends 647) and 700 (ends 1022)
    assert series.n_starts == 5
    assert series.n_nonoverlap == 3


def test_block_bootstrap_ci_wider_than_naive():
    rng = random.Random(4)
    values = []
    level = 0.0
    for _ in range(400):
        level = 0.95 * level + rng.gauss(0.0, 1.0)
        values.append(level)

    block_lo, block_hi = block_bootstrap_ci(values, statistics.mean, 40, 400, 1)
    naive_lo, naive_hi = block_bootstrap_ci(values, statistics.mean, 1, 400, 1)
    # the naive resample treats the 400 values as independent, so it reads the
    # autocorrelated spread as far tighter than the blocks do
    assert block_hi - block_lo > 1.5 * (naive_hi - naive_lo)
    assert block_lo < block_hi

    assert block_bootstrap_ci(values, statistics.mean, 40, 400, 1) == (
        block_lo,
        block_hi,
    )
    assert block_bootstrap_ci(values, statistics.mean, 40, 400, 2) != (
        block_lo,
        block_hi,
    )

    # 50% of a sorted four sits midway between 2 and 3
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([1, 2, 3, 4], 0) == 1
    assert percentile([1, 2, 3, 4], 100) == 4
    with pytest.raises(ValueError):
        percentile([], 50)


def test_block_bootstrap_ci_few_blocks_is_none():
    values = [float(index) for index in range(20)]

    # 20 * 4 = 80 values of blocks against the 20 there are: not even two blocks
    # fit, so no interval is reported rather than a collapsed one
    assert block_bootstrap_ci(values, statistics.mean, 20, 50, 1) is None

    # 5 * 4 = 20 is exactly four blocks in 20 values
    four = block_bootstrap_ci(values, statistics.mean, 5, 50, 1)
    assert isinstance(four, tuple)
    assert len(four) == 2
    assert four[0] <= four[1]

    # 6 * 4 = 24 leaves only three whole blocks in 20 values
    assert block_bootstrap_ci(values, statistics.mean, 6, 50, 1) is None


def test_drift_removed_series_zero_mean():
    bars = weekday_bars("NVDA", [(100, 100), (100, 110), (110, 121)])
    out = remove_drift(bars)

    # ln(110/100) and ln(121/110) are both ln 1.1, so the mean is ln 1.1 and
    # every return becomes 0: 110 / 1.1 = 100 and 121 / 1.21 = 100
    for bar in out:
        assert bar.close == pytest.approx(D("100"), abs=1e-9)
    # bar 1's high is max(100, 110) + 1 = 111, so 111 / 1.1 = 100.909090...
    assert out[1].high == pytest.approx(D("111") / D("1.1"), abs=1e-9)
    # bar 2's open of 110 becomes 110 / 1.21 = 90.909090...
    assert out[2].open == pytest.approx(D("110") / D("1.21"), abs=1e-9)
    assert [bar.ts for bar in out] == [bar.ts for bar in bars]
    assert [bar.symbol for bar in out] == [bar.symbol for bar in bars]

    walk = walk_bars("NVDA", seed=8, count=300)
    flat_out = remove_drift(walk)
    returns = [
        math.log(float(later.close) / float(earlier.close))
        for earlier, later in zip(flat_out, flat_out[1:])
    ]
    assert statistics.mean(returns) == pytest.approx(0.0, abs=1e-9)
    assert len(flat_out) == len(walk)
    assert [bar.ts for bar in flat_out] == [bar.ts for bar in walk]

    with pytest.raises(ValueError):
        remove_drift(walk[:1])
    with pytest.raises(ValueError):
        remove_drift([])


def test_horizon_and_input_validation():
    # 449 days is one short of the shortest horizon that leaves every lot
    # long-term
    with pytest.raises(ValueError):
        nvda_study(horizon_days=449)
    with pytest.raises(ValueError):
        nvda_study(cash=D("0"))
    # start 330 would need bar 330 + 322 = 652, and the series has 340
    with pytest.raises(ValueError):
        nvda_study(starts=[330])
    with pytest.raises(ValueError):
        nvda_study(block_len=0)


def test_block_len_shorter_than_window_refused():
    # the window of start 0 runs over bars 0..322, so it spans 323 bars
    with pytest.raises(ValueError, match="block_len"):
        nvda_study(block_len=322)
    with pytest.raises(ValueError, match="block_len"):
        nvda_study(block_len=1)
    # a block as long as the longest window the study runs is accepted
    accepted = nvda_study(block_len=323)
    assert accepted.params["block_len"] == 323
    assert accepted.series["NVDA"].n_starts == 1


def test_check_long_term_hand_cases():
    from crow_coinbase.lab.studies.buy_timing import check_long_term

    # a lot bought on 2024-01-01 is long-term only after 2025-01-01, so the
    # anniversary itself is short-term
    with pytest.raises(ValueError):
        check_long_term([utc(2024, 1, 1)], utc(2025, 1, 1))
    check_long_term([utc(2024, 1, 1)], utc(2025, 1, 2))

    # a 29 February acquisition has its next-year anniversary on 28 February,
    # so 2025-02-28 is still the anniversary and 2025-03-01 is past it
    with pytest.raises(ValueError):
        check_long_term([utc(2024, 2, 29)], utc(2025, 2, 28))
    check_long_term([utc(2024, 2, 29)], utc(2025, 3, 1))

    check_long_term([], utc(2025, 1, 1))

    # the 2023-01-03 lot is past its anniversary by 2024-12-31; the 2024-06-01
    # one is not, and that is the stamp the message has to name
    with pytest.raises(ValueError) as caught:
        check_long_term([utc(2023, 1, 3), utc(2024, 6, 1)], utc(2024, 12, 31))
    assert "2024-06-01" in str(caught.value)


def test_every_run_leaves_only_long_term_lots():
    from crow_coinbase.lab.studies.buy_timing import check_long_term

    bars = weekday_bars("NVDA", flat_rows(100, 340))
    result = run_study(
        {"NVDA": bars},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )

    # 2024-01-01 is a Monday, so bar 322 is 64 weeks (320 bars) and two weekdays
    # on: 2024-01-01 + 448 days = 2025-03-26, which is also 450 days after the
    # start bar, so it is the last bar of start 0's window
    stop_ts = bars[322].ts
    assert stop_ts == utc(2025, 3, 26)

    for label, found in result.series.items():
        for name, option_found in found.options.items():
            assert len(option_found.starts) == 1
            outcome = option_found.starts[0]
            assert outcome.start_index == 0
            for stamp in outcome.buy_ts:
                assert stop_ts - stamp > timedelta(days=365), (
                    label,
                    name,
                    stamp,
                )
            check_long_term(outcome.buy_ts, stop_ts)


def test_markdown_caveats():
    rows = flat_rows(100, 10) + flat_rows(110, 330)
    result = run_study(
        {"NVDA": weekday_bars("NVDA", rows)},
        {},
        cash=D("300"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0],
        n_boot=40,
    )
    md = result.to_markdown()

    for phrase in (
        "one stock",
        "went up",
        "overlapping",
        "not a prediction",
        "no median drift",
        "$300",
    ):
        assert phrase in md
    for name in ("lump", "split2", "trend N=20 D=10", "trend N=100 D=40"):
        assert name in md

    lowered = md.lower()
    for word in ("best", "optimal", "recommend"):
        assert word not in lowered


def test_summary_fields_with_several_starts():
    # Starts 400 bars apart, which is also the block length: the block is
    # ceil(400 / 400) = 1 start long, so four such blocks fit inside these ten
    # starts and the interval is computed rather than reported as n/a.
    starts = (0, 400, 800, 1200, 1600, 2000, 2400, 2800, 3200, 3600)

    def study():
        return run_study(
            {"NVDA": walk_bars("NVDA", seed=2, count=4000)},
            {},
            cash=D("200"),
            horizon_days=450,
            costs=ZERO,
            block_len=400,
            controls=("SPY", "QQQ"),
            starts=list(starts),
            n_boot=40,
        )

    first = study()
    second = study()
    series = first.series["NVDA"]
    # the last start, 3600, needs bar 3600 + 322 = 3922 and the series has 4000
    assert series.n_starts == 10

    for name, found in series.options.items():
        summary = found.summary
        assert summary["n_starts"] == 10
        assert (
            summary["value_after_tax_p10"]
            <= summary["value_after_tax_median"]
            <= summary["value_after_tax_p90"]
        )
        ci_lo, ci_hi = summary["median_ci"]
        assert ci_lo <= ci_hi
        worst = summary["max_drawdown_worst"]
        middle = summary["max_drawdown_median"]
        assert worst >= middle >= 0
        share = summary["share_beating_lump"]
        if name == "lump":
            assert share is None
        else:
            assert 0.0 <= share <= 1.0
            share_lo, share_hi = summary["share_beating_lump_ci"]
            assert share_lo <= share_hi
        # the same seed and the same data leave every summary where it was
        assert second.series["NVDA"].options[name].summary == summary


def test_short_series_interval_is_not_available():
    # two starts a hundred bars apart: the 400-bar block is ceil(400 / 100) = 4
    # starts long, and four blocks need 16 of the 2 starts there are
    bars = weekday_bars("NVDA", flat_rows(100, 500))
    result = run_study(
        {"NVDA": bars},
        {},
        cash=D("200"),
        horizon_days=450,
        costs=ZERO,
        block_len=400,
        controls=("SPY", "QQQ"),
        starts=[0, 100],
        n_boot=40,
    )

    found = option(result, "NVDA", "lump")
    assert found.summary["n_starts"] == 2
    assert found.summary["median_ci"] is None
    note = found.summary["ci_note"]
    assert isinstance(note, str)
    assert "n/a" in note
    assert "4" in note
    assert "block" in note

    # the report reads the interval off the summary, so the cell says n/a
    md = result.to_markdown()
    row = next(line for line in md.splitlines() if line.startswith("| lump |"))
    assert "n/a" in row