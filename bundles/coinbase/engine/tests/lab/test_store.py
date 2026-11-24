"""lab/store.py: the research lab's SQLite store — bars, events, rules, runs, studies."""

import sqlite3
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

import pytest

from crow_coinbase.lab.store import Bar, Event, LabStore, LabStoreError, TrialRow

UTC = timezone.utc

XRP = "XRP-USDC"
ADA = "ADA-USDC"
NVDA = "NVDA"

PROJECT = "proj-a"
OTHER_PROJECT = "proj-b"

# One grid, spelled the same way wherever a re-register has to match it.
GRID = [{"fast": 5, "slow": 20}]


def utc(year, month, day, hour=0, minute=0):
    """A timezone-aware UTC datetime at that clock reading."""
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def naive(year, month, day):
    """The same clock reading with no tzinfo at all."""
    return datetime(year, month, day)


def bar(ts, close, symbol=XRP, interval="1d", adj_factor=D("1")):
    """A bar whose four price columns all sit at *close*, with unit volume."""
    price = D(close)
    return Bar(
        symbol=symbol,
        interval=interval,
        ts=ts,
        open=price,
        high=price,
        low=price,
        close=price,
        volume=D("1"),
        adj_factor=D(adj_factor),
    )


@pytest.fixture
def store(tmp_path):
    s = LabStore(tmp_path / "lab.db")
    yield s
    s.close()


def test_upsert_idempotent(store):
    rows = [bar(utc(2026, 1, 1), "100"), bar(utc(2026, 1, 2), "101")]
    assert store.upsert_bars(XRP, "1d", rows) == 2

    # The same two rows again: nothing added, nothing lost.
    assert store.upsert_bars(XRP, "1d", rows) == 2
    got = store.bars(XRP, "1d", utc(2026, 1, 1), utc(2026, 2, 1))
    assert [b.close for b in got] == [D("100"), D("101")]
    assert len(got) == 2

    # One row replaced and one new row: two written, the table holds three.
    assert (
        store.upsert_bars(
            XRP,
            "1d",
            [bar(utc(2026, 1, 2), "150"), bar(utc(2026, 1, 3), "90")],
        )
        == 2
    )
    got = store.bars(XRP, "1d", utc(2026, 1, 1), utc(2026, 2, 1))
    assert [b.close for b in got] == [D("100"), D("150"), D("90")]
    assert len(got) == 3

    # A different interval is a different row set.
    assert (
        store.upsert_bars(XRP, "1h", [bar(utc(2026, 1, 2), "101", interval="1h")])
        == 1
    )
    assert [b.close for b in store.bars(XRP, "1h", utc(2026, 1, 1), utc(2026, 2, 1))] == [
        D("101")
    ]
    assert [b.close for b in store.bars(XRP, "1d", utc(2026, 1, 1), utc(2026, 2, 1))] == [
        D("100"),
        D("150"),
        D("90"),
    ]


def test_bars_range_sorted(store):
    # Written newest first; the range read comes back oldest first.
    store.upsert_bars(
        XRP,
        "1d",
        [
            bar(utc(2026, 1, 3), "3"),
            bar(utc(2026, 1, 1), "1"),
            bar(utc(2026, 1, 2), "2"),
        ],
    )

    got = store.bars(XRP, "1d", utc(2025, 12, 31), utc(2026, 1, 4))
    assert [b.ts for b in got] == [utc(2026, 1, 1), utc(2026, 1, 2), utc(2026, 1, 3)]
    assert all(isinstance(b, Bar) for b in got)
    assert all(b.ts.utcoffset() == timedelta(0) for b in got)

    # start is inclusive, end is exclusive
    assert [b.ts for b in store.bars(XRP, "1d", utc(2026, 1, 2), utc(2026, 1, 3))] == [
        utc(2026, 1, 2)
    ]
    assert store.bars(XRP, "1d", utc(2026, 1, 4), utc(2026, 2, 1)) == []
    assert store.bars(XRP, "1d", utc(2025, 11, 1), utc(2026, 1, 1)) == []

    # Another product's bars never come back under this symbol.
    assert store.bars(ADA, "1d", utc(2026, 1, 1), utc(2026, 2, 1)) == []

    # Decimals keep their written text: 0.1 reads back as 0.1 and nothing longer.
    store.upsert_bars(
        XRP,
        "1d",
        [bar(utc(2026, 1, 4), D("0.1"), adj_factor=D("0.000000000000000001"))],
    )
    last = store.bars(XRP, "1d", utc(2026, 1, 4), utc(2026, 1, 5))[0]
    assert last.close == D("0.1")
    assert str(last.close) == "0.1"
    assert isinstance(last.close, D)
    assert last.adj_factor == D("0.000000000000000001")
    assert str(last.adj_factor) == "0.000000000000000001"


def test_events_filtered(store):
    earnings_at = utc(2026, 2, 3, 13, 30)
    earnings_announced = utc(2026, 1, 27, 21, 0)
    lockup_at = utc(2026, 2, 9, 13, 30)
    lockup_announced = utc(2026, 2, 2, 12, 0)

    # The later event goes in first, so the ascending read below is the store's own.
    store.add_event(XRP, "lockup", lockup_at, lockup_announced, "pre", "unlock")
    store.add_event(XRP, "earnings", earnings_at, earnings_announced, "post", "q4 call")
    store.add_event(ADA, "custom", utc(2026, 2, 5), utc(2026, 1, 30), "none", "")

    got = store.events(XRP, utc(2026, 2, 1), utc(2026, 2, 28))
    assert all(isinstance(e, Event) and e.symbol == XRP for e in got)
    assert [e.kind for e in got] == ["earnings", "lockup"]
    assert [e.at for e in got] == [earnings_at, lockup_at]
    assert [e.announced_at for e in got] == [earnings_announced, lockup_announced]
    assert [(e.session, e.note) for e in got] == [
        ("post", "q4 call"),
        ("pre", "unlock"),
    ]

    # start inclusive, end exclusive
    assert [e.kind for e in store.events(XRP, earnings_at, lockup_at)] == ["earnings"]
    assert store.events(XRP, utc(2026, 3, 1), utc(2026, 4, 1)) == []
    assert store.events(XRP, utc(2026, 1, 1), utc(2026, 2, 1)) == []


def test_register_conflict_refused(store):
    store.register_rule(PROJECT, "sma_cross", "fast cross of slow", GRID)

    # An equal grid is not a conflict.
    store.register_rule(
        PROJECT, "sma_cross", "fast cross of slow", [{"fast": 5, "slow": 20}]
    )

    for changed in (
        [{"fast": 10, "slow": 20}],
        [{"fast": 5, "slow": 20}, {"fast": 5}],
        [{"fast": 5}],
        [],
    ):
        with pytest.raises(LabStoreError):
            store.register_rule(PROJECT, "sma_cross", "fast cross of slow", changed)

    rule = store.get_rule(PROJECT, "sma_cross")
    assert rule["rule_id"] == "sma_cross"
    assert rule["hypothesis"] == "fast cross of slow"
    assert rule["grid"] == [{"fast": 5, "slow": 20}]
    assert rule["registered_at"] is not None

    # The same rule id under another project is its own row.
    store.register_rule(OTHER_PROJECT, "sma_cross", "other", [{"fast": 10, "slow": 20}])
    assert store.get_rule(OTHER_PROJECT, "sma_cross")["grid"] == [
        {"fast": 10, "slow": 20}
    ]
    assert store.get_rule(PROJECT, "sma_cross")["grid"] == [{"fast": 5, "slow": 20}]
    assert store.get_rule(PROJECT, "missing") is None


def test_registered_at_store_set(store):
    before = datetime.now(UTC)
    store.register_rule(PROJECT, "sma_cross", "fast cross of slow", GRID)
    after = datetime.now(UTC)

    first = store.get_rule(PROJECT, "sma_cross")["registered_at"]
    assert isinstance(first, datetime)
    assert first.tzinfo is not None
    assert first.utcoffset() == timedelta(0)
    assert before - timedelta(seconds=10) <= first <= after + timedelta(seconds=10)

    # There is no registered_at argument: the store is the one that stamps it.
    with pytest.raises(TypeError):
        store.register_rule(
            PROJECT, "sma_cross", "fast cross of slow", GRID, registered_at=first
        )

    # An identical re-register leaves the stamp alone.
    store.register_rule(
        PROJECT, "sma_cross", "fast cross of slow", [{"fast": 5, "slow": 20}]
    )
    assert store.get_rule(PROJECT, "sma_cross")["registered_at"] == first


def test_register_new_version_keeps_history(store):
    first = [{"fast": 5, "slow": 20}]
    second = [{"fast": 10, "slow": 20}]
    third = [{"fast": 10, "slow": 30}]

    # A first registration is version 1, and a run against its params is a trial.
    assert (
        store.register_rule(PROJECT, "sma_cross", "fast cross of slow", first)
        == 1
    )
    store.record_run(
        PROJECT, XRP, "1d", "sma_cross", {"fast": 5, "slow": 20}, "hash-v1", 0.4, {}
    )
    assert [row.data_hash for row in store.trials(PROJECT, "1d", "crypto")] == [
        "hash-v1"
    ]

    # A changed grid is a conflict unless the caller says it is a new version.
    with pytest.raises(LabStoreError, match="new rule version"):
        store.register_rule(PROJECT, "sma_cross", "fast cross of slow", second)

    assert (
        store.register_rule(
            PROJECT, "sma_cross", "fast cross of slow", second, new_version=True
        )
        == 2
    )
    rule = store.get_rule(PROJECT, "sma_cross")
    assert rule["rule_id"] == "sma_cross"
    assert rule["grid"] == [{"fast": 10, "slow": 20}]
    assert rule["version"] == 2
    # A new version redefines the design; it does not erase the looks already
    # spent, so the v1 trial is still a trial.
    assert [
        (row.rule_id, row.params, row.data_hash)
        for row in store.trials(PROJECT, "1d", "crypto")
    ] == [("sma_cross", {"fast": 5, "slow": 20}, "hash-v1")]

    # The current grid asked for again as a new version is a no-op, not a v3.
    assert (
        store.register_rule(
            PROJECT, "sma_cross", "fast cross of slow", second, new_version=True
        )
        == 2
    )
    assert store.get_rule(PROJECT, "sma_cross")["version"] == 2

    # One more change is version 3, and every trial of the older grids remains.
    assert (
        store.register_rule(
            PROJECT, "sma_cross", "fast cross of slow", third, new_version=True
        )
        == 3
    )
    rule = store.get_rule(PROJECT, "sma_cross")
    assert rule["grid"] == [{"fast": 10, "slow": 30}]
    assert rule["version"] == 3
    assert [
        (row.rule_id, row.params, row.data_hash)
        for row in store.trials(PROJECT, "1d", "crypto")
    ] == [("sma_cross", {"fast": 5, "slow": 20}, "hash-v1")]


def test_register_new_version_needs_existing_rule(store):
    # There is no version 1 to build on, so there is nothing to supersede.
    with pytest.raises(LabStoreError, match="nothing to supersede"):
        store.register_rule(
            PROJECT, "sma_cross", "fast cross of slow", GRID, new_version=True
        )

    # The refused call left no row behind: the id is still free for its v1.
    assert (
        store.register_rule(PROJECT, "sma_cross", "fast cross of slow", GRID)
        == 1
    )


def test_grid_matches_registered(store):
    grid = [{"fast": 5, "slow": 20}, {"fast": 10, "slow": 20}]
    store.register_rule(PROJECT, "sma_cross", "fast cross of slow", grid)

    assert store.grid_matches_registered(PROJECT, "sma_cross", grid) is True
    # An equal grid built afresh, with its keys written in another order.
    assert (
        store.grid_matches_registered(
            PROJECT,
            "sma_cross",
            [{"slow": 20, "fast": 5}, {"fast": 10, "slow": 20}],
        )
        is True
    )
    # One value changed, and a config dropped, are both another design.
    assert (
        store.grid_matches_registered(
            PROJECT,
            "sma_cross",
            [{"fast": 6, "slow": 20}, {"fast": 10, "slow": 20}],
        )
        is False
    )
    assert (
        store.grid_matches_registered(
            PROJECT, "sma_cross", [{"fast": 5, "slow": 20}]
        )
        is False
    )
    # An unregistered rule has no grid to match, and another project's row of the
    # same id is another rule.
    assert store.grid_matches_registered(PROJECT, "missing", grid) is False
    assert store.grid_matches_registered(OTHER_PROJECT, "sma_cross", grid) is False

    # The current version is the one read: the old grid stops matching once the
    # new one is registered, and the new one starts.
    wider = [{"fast": 6, "slow": 20}, {"fast": 10, "slow": 20}]
    assert (
        store.register_rule(
            PROJECT, "sma_cross", "fast cross of slow", wider, new_version=True
        )
        == 2
    )
    assert store.grid_matches_registered(PROJECT, "sma_cross", grid) is False
    assert store.grid_matches_registered(PROJECT, "sma_cross", wider) is True


def test_grid_matches_registered_decimal_grid(store):
    # A grid carrying Decimals compares the way it was stored: an equal Decimal
    # grid matches, and a Decimal that moves by one thousandth does not.
    grid = [
        {"floor_pct": D("0.011"), "k": 1},
        {"floor_pct": D("0.02"), "k": 2},
    ]
    store.register_rule(PROJECT, "sma_cross", "fast cross of slow", grid)

    assert (
        store.grid_matches_registered(
            PROJECT,
            "sma_cross",
            [
                {"floor_pct": D("0.011"), "k": 1},
                {"floor_pct": D("0.02"), "k": 2},
            ],
        )
        is True
    )
    assert (
        store.grid_matches_registered(
            PROJECT,
            "sma_cross",
            [
                {"floor_pct": D("0.012"), "k": 1},
                {"floor_pct": D("0.02"), "k": 2},
            ],
        )
        is False
    )


def test_register_rejects_reserved_at_sign(store):
    # "@" belongs to the store's own version rows, so a caller may not pass one
    # as a base id.
    with pytest.raises(ValueError):
        store.register_rule(PROJECT, "band@v2", "fast cross of slow", GRID)

    # Nothing was written under that id: the base id is still free for its v1.
    assert (
        store.register_rule(PROJECT, "band", "fast cross of slow", GRID) == 1
    )


def test_record_run_dedupes(store):
    store.register_rule(PROJECT, "sma_cross", "fast cross of slow", GRID)
    result = {"trades": 3, "final_equity": "101"}

    first = store.record_run(
        PROJECT, XRP, "1d", "sma_cross", {"fast": 5, "slow": 20}, "hash-a", 0.5, result
    )
    assert isinstance(first, int)

    # Same rule, same parameters written in another key order, same data hash.
    again = store.record_run(
        PROJECT, XRP, "1d", "sma_cross", {"slow": 20, "fast": 5}, "hash-a", 0.5, result
    )
    assert again == first

    # A different data hash is a different trial.
    other = store.record_run(
        PROJECT, XRP, "1d", "sma_cross", {"fast": 5, "slow": 20}, "hash-b", 0.5, result
    )
    assert other != first

    trials = store.trials(PROJECT, "1d", "crypto")
    assert len(trials) == 2  # the repeat wrote no row
    assert [t.data_hash for t in trials] == ["hash-a", "hash-b"]
    assert [t.excess_sharpe for t in trials] == [0.5, 0.5]
    assert trials[0].params == {"fast": 5, "slow": 20}


def test_trials_across_rules_and_assets_per_interval(store):
    store.register_rule(PROJECT, "sma_cross", "fast cross of slow", GRID)
    store.register_rule(PROJECT, "breakout", "20 day breakout", [{"n": 20}])
    store.register_rule(OTHER_PROJECT, "sma_cross", "fast cross of slow", GRID)

    store.record_run(
        PROJECT, XRP, "1d", "sma_cross", {"fast": 5}, "xrp-sma-1d", 0.25, {}
    )
    store.record_run(
        PROJECT, ADA, "1d", "sma_cross", {"fast": 5}, "ada-sma-1d", -0.5, {}
    )
    store.record_run(
        PROJECT, XRP, "1d", "breakout", {"n": 20}, "xrp-break-1d", None, {}
    )
    store.record_run(
        PROJECT, ADA, "1d", "breakout", {"n": 20}, "ada-break-1d", 0.75, {}
    )
    # Neither of these belongs to the 1d crypto read below.
    store.record_run(
        PROJECT, XRP, "1h", "sma_cross", {"fast": 5}, "xrp-sma-1h", 0.1, {}
    )
    store.record_run(
        PROJECT, NVDA, "1d", "sma_cross", {"fast": 5}, "nvda-sma-1d", 0.9, {}
    )
    store.record_run(
        OTHER_PROJECT, XRP, "1d", "sma_cross", {"fast": 5}, "xrp-sma-1d", 0.3, {}
    )

    got = store.trials(PROJECT, "1d", "crypto")
    assert all(isinstance(t, TrialRow) for t in got)
    assert [(t.asset, t.rule_id) for t in got] == [
        (XRP, "sma_cross"),
        (ADA, "sma_cross"),
        (XRP, "breakout"),
        (ADA, "breakout"),
    ]
    assert [t.excess_sharpe for t in got] == [0.25, -0.5, None, 0.75]
    assert got[2].excess_sharpe is None
    assert [t.project_id for t in got] == [PROJECT, PROJECT, PROJECT, PROJECT]
    assert [t.interval for t in got] == ["1d", "1d", "1d", "1d"]
    assert [t.data_hash for t in got] == [
        "xrp-sma-1d",
        "ada-sma-1d",
        "xrp-break-1d",
        "ada-break-1d",
    ]
    assert got[0].params == {"fast": 5}

    # Another project's runs are never returned, and the class split is by symbol.
    other_trials = store.trials(OTHER_PROJECT, "1d", "crypto")
    assert [(t.asset, t.rule_id) for t in other_trials] == [(XRP, "sma_cross")]
    assert [t.excess_sharpe for t in other_trials] == [0.3]
    assert [(t.asset, t.excess_sharpe) for t in store.trials(PROJECT, "1d", "stock")] == [
        (NVDA, 0.9)
    ]
    assert [(t.asset, t.interval) for t in store.trials(PROJECT, "1h", "crypto")] == [
        (XRP, "1h")
    ]


def test_newer_schema_refused(tmp_path):
    path = tmp_path / "lab.db"
    LabStore(path).close()

    raw = sqlite3.connect(path)
    try:
        raw.execute("PRAGMA user_version=2")
        raw.commit()
    finally:
        raw.close()

    with pytest.raises(LabStoreError) as err:
        LabStore(path)
    message = str(err.value)
    assert "2" in message
    assert "1" in message


def test_project_id_required(store):
    store.register_rule(PROJECT, "sma_cross", "fast cross of slow", GRID)

    for bad in ("", None):
        with pytest.raises(ValueError):
            store.register_rule(bad, "r1", "20 day breakout", [{"n": 20}])
        with pytest.raises(ValueError):
            store.record_run(
                bad, XRP, "1d", "sma_cross", {"fast": 5}, "hash-a", 0.1, {}
            )
        with pytest.raises(ValueError):
            store.record_study(bad, "sweep", {"rows": 0})

    # None of the refused calls left a row behind.
    assert store.get_rule(PROJECT, "r1") is None
    assert store.trials(PROJECT, "1d", "crypto") == []
    assert store.get_rule(PROJECT, "sma_cross")["grid"] == GRID


def test_naive_datetime_refused(store):
    start = utc(2026, 1, 1)
    end = utc(2026, 2, 1)

    with pytest.raises(ValueError):
        store.upsert_bars(XRP, "1d", [bar(naive(2026, 1, 1), "1")])
    with pytest.raises(ValueError):
        store.bars(XRP, "1d", naive(2026, 1, 1), end)
    with pytest.raises(ValueError):
        store.bars(XRP, "1d", start, naive(2026, 2, 1))
    with pytest.raises(ValueError):
        store.add_event(XRP, "earnings", naive(2026, 1, 5), utc(2026, 1, 1), "post", "")
    with pytest.raises(ValueError):
        store.add_event(XRP, "earnings", utc(2026, 1, 5), naive(2026, 1, 1), "post", "")
    with pytest.raises(ValueError):
        store.events(XRP, naive(2026, 1, 1), end)
    with pytest.raises(ValueError):
        store.events(XRP, start, naive(2026, 2, 1))

    # Nothing was written along the way.
    assert store.bars(XRP, "1d", start, end) == []
    assert store.events(XRP, start, end) == []


def test_events_announced_after_event_refused(store):
    at = utc(2026, 2, 3, 13, 30)

    with pytest.raises(ValueError):
        store.add_event(XRP, "earnings", at, utc(2026, 2, 3, 13, 31), "post", "late")
    with pytest.raises(ValueError):
        store.add_event(XRP, "earnings", at, utc(2026, 2, 4), "post", "later")
    assert store.events(XRP, utc(2026, 2, 1), utc(2026, 3, 1)) == []

    # Announced at the same instant as the event is not "after" it.
    store.add_event(XRP, "earnings", at, at, "post", "same instant")
    got = store.events(XRP, utc(2026, 2, 1), utc(2026, 3, 1))
    assert [(e.at, e.announced_at) for e in got] == [(at, at)]


def test_record_run_key_carries_asset_and_interval(store):
    store.register_rule(PROJECT, "sma_cross", "fast cross of slow", GRID)
    params = {"fast": 5, "slow": 20}

    first = store.record_run(
        PROJECT, XRP, "1d", "sma_cross", params, "hash-a", 0.5, {}
    )
    assert isinstance(first, int)

    # the whole key written out again is the row already on file
    assert (
        store.record_run(
            PROJECT,
            XRP,
            "1d",
            "sma_cross",
            {"fast": 5, "slow": 20},
            "hash-a",
            0.5,
            {},
        )
        == first
    )

    # another asset of the same project, rule, parameters and data hash is its
    # own trial, and so is another interval of the same asset
    other_asset = store.record_run(
        PROJECT, ADA, "1d", "sma_cross", params, "hash-a", 0.5, {}
    )
    assert other_asset != first

    other_interval = store.record_run(
        PROJECT, XRP, "1h", "sma_cross", params, "hash-a", 0.5, {}
    )
    assert other_interval != first
    assert other_interval != other_asset

    assert [
        (t.asset, t.interval) for t in store.trials(PROJECT, "1d", "crypto")
    ] == [(XRP, "1d"), (ADA, "1d")]
    assert [
        (t.asset, t.interval) for t in store.trials(PROJECT, "1h", "crypto")
    ] == [(XRP, "1h")]