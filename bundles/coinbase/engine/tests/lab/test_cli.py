"""lab/__main__.py: the command line — flags, refusals and the database guard.

Every case runs `main()` in-process against a database under `tmp_path`, with
the candle client, the Tiingo fetcher and the clock injected, so nothing here
reads a file outside the test's own directory or opens a connection.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D
from urllib.parse import parse_qs, urlsplit

import pytest

from crow_coinbase.lab import __main__ as cli
from crow_coinbase.lab.__main__ import build_parser, check_db_schema, main
from crow_coinbase.lab.rules import band, event_veto, grid_gate, regime
from crow_coinbase.lab.store import Bar, LabStore

UTC = timezone.utc

PROJECT = "proj-a"
XRP = "XRP-USDC"
NVDA = "NVDA"
AMD = "AMD"

DAY = timedelta(days=1)
HOUR = timedelta(hours=1)

# The two rates every `run` and `study-buys` has to state.
RATES = {"--st-tax-rate": "0.3", "--lt-tax-rate": "0.15"}
TAX = ["--st-tax-rate", "0.3", "--lt-tax-rate", "0.15"]

# The rule modules the CLI maps by RULE_ID.
RULE_MODULES = {
    "band": band,
    "regime": regime,
    "grid_gate": grid_gate,
    "event_veto": event_veto,
}

# band's grid as it stands, beside two hand-built variants of it: the grid the
# rule carried before its first config was widened, and the same grid with its
# last config changed.  RULE_MODULES holds the module objects themselves, so a
# monkeypatched GRID is the one every command reads.
BAND_GRID_NOW = [
    {"band_pts": 4},
    {"band_pts": 5},
    {"band_pts": 6},
    {"band_pts": 7.5},
    {"band_pts": 10},
]
BAND_GRID_OLD = [
    {"band_pts": 3},
    {"band_pts": 5},
    {"band_pts": 6},
    {"band_pts": 7.5},
    {"band_pts": 10},
]
BAND_GRID_CHANGED = [
    {"band_pts": 4},
    {"band_pts": 5},
    {"band_pts": 6},
    {"band_pts": 9},
    {"band_pts": 10},
]

# A Tiingo-style daily CSV: one row per session, the adjusted columns beside the
# raw ones and the two corporate-action columns at the end.
TIINGO_HEADER = (
    "date,close,high,low,open,volume,adjClose,adjHigh,adjLow,adjOpen,"
    "adjVolume,divCash,splitFactor"
)
TIINGO_ROWS = [
    "2024-06-10,100,102,97,98,500,100,102,97,98,500,0,1",
    "2024-06-11,101,103,99,100,600,101,103,99,100,600,0,1",
    "2024-06-12,102,104,100,101,700,102,104,100,101,700,0,1",
]
TIINGO_CSV = "\n".join([TIINGO_HEADER, *TIINGO_ROWS]) + "\n"


# ---------------------------------------------------------------- helpers


def utc(year, month, day, hour=0, minute=0):
    """A timezone-aware UTC datetime at that clock reading."""
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def epoch(moment):
    """Unix seconds of an aware UTC datetime, the unit the public API takes."""
    return int(moment.timestamp())


def flat_candle(price):
    """One candle of *price* in all four price columns."""
    text = str(D(price))
    return {"open": text, "high": text, "low": text, "close": text, "volume": "100"}


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


def base_args(tmp_path, name="lab.db"):
    """The `--db` pair every subcommand takes."""
    return ["--db", str(tmp_path / name)]


def store_bars(path, symbol, count, *, interval="1d", start=None, price="1.00"):
    """Store *count* consecutive daily (or hourly) bars of one symbol."""
    first = utc(2024, 1, 1) if start is None else start
    step = DAY if interval == "1d" else HOUR
    lab = LabStore(path)
    try:
        lab.upsert_bars(
            symbol,
            interval,
            [
                bar(first + step * index, price, symbol, interval)
                for index in range(count)
            ],
        )
    finally:
        lab.close()


def read_bars(path, symbol, interval="1d"):
    """Every stored bar of one symbol and interval, oldest first."""
    lab = LabStore(path)
    try:
        return lab.bars(symbol, interval, utc(1990, 1, 1), utc(2100, 1, 1))
    finally:
        lab.close()


def read_events(path, symbol):
    """Every stored event of one symbol over the lab's whole calendar."""
    lab = LabStore(path)
    try:
        return lab.events(symbol, utc(2016, 1, 1), utc(2027, 1, 1))
    finally:
        lab.close()


def recorded_trials(path, project, interval, asset_class):
    """The runs a project has recorded at one interval in one asset class."""
    lab = LabStore(path)
    try:
        return lab.trials(project, interval, asset_class)
    finally:
        lab.close()


def run_args(
    db, *, tax=None, rule="band", asset=XRP, interval="1d", project=PROJECT
):
    """A complete `run` command line, with the tax rates spelled out."""
    argv = [
        "run",
        "--db",
        db,
        "--project-id",
        project,
        "--rule",
        rule,
        "--asset",
        asset,
        "--interval",
        interval,
        "--train-len",
        "10",
        "--test-len",
        "5",
    ]
    argv.extend(TAX if tax is None else tax)
    return argv


def study_args(db, *, tax=None, symbols="NVDA,AMD", project=PROJECT):
    """A complete `study-buys` command line, with the tax rates spelled out."""
    argv = [
        "study-buys",
        "--db",
        db,
        "--project-id",
        project,
        "--symbols",
        symbols,
    ]
    argv.extend(TAX if tax is None else tax)
    return argv


def write_earnings_csv(path, rows):
    """The earnings CSV under *path*, with its header as line 1."""
    text = "\n".join(["release_date,announced_date,session", *rows]) + "\n"
    path.write_text(text, encoding="utf-8")
    return str(path)


def as_text(value):
    """A date, datetime or string as YYYY-MM-DD text."""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


# ---------------------------------------------------------------- project id


def test_cli_requires_project_id(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    cases = [
        [
            "run",
            "--db",
            db,
            "--rule",
            "band",
            "--asset",
            XRP,
            "--interval",
            "1d",
            "--train-len",
            "10",
            "--test-len",
            "5",
            "--st-tax-rate",
            "0.3",
            "--lt-tax-rate",
            "0.15",
        ],
        ["register", "--db", db, "--rule", "band"],
        [
            "study-buys",
            "--db",
            db,
            "--symbols",
            "NVDA",
            "--st-tax-rate",
            "0.3",
            "--lt-tax-rate",
            "0.15",
        ],
    ]

    for argv in cases:
        with pytest.raises(SystemExit) as caught:
            main(argv)
        assert caught.value.code == 2
        err = capsys.readouterr().err
        assert "--project-id" in err, argv


# ---------------------------------------------------------------- tax rates


@pytest.mark.parametrize("subcommand", ["run", "study-buys"])
@pytest.mark.parametrize(
    "missing",
    [
        ("--st-tax-rate",),
        ("--lt-tax-rate",),
        ("--st-tax-rate", "--lt-tax-rate"),
    ],
)
def test_cli_requires_tax_rates(tmp_path, capsys, subcommand, missing):
    db = str(tmp_path / "lab.db")
    tax = []
    for flag in ("--st-tax-rate", "--lt-tax-rate"):
        if flag not in missing:
            tax.extend([flag, RATES[flag]])
    argv = run_args(db, tax=tax) if subcommand == "run" else study_args(db, tax=tax)

    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2
    err = capsys.readouterr().err
    for flag in missing:
        assert flag in err, err


# ---------------------------------------------------------------- refusals


def test_cli_run_unregistered_refused(tmp_path, capsys):
    db = tmp_path / "lab.db"
    # 30 consecutive daily bars, so the range is long enough for a walk forward.
    store_bars(db, XRP, 30)

    code = main(run_args(str(db)))
    captured = capsys.readouterr()

    # `band` was never registered in this project, so nothing runs and nothing
    # is recorded.
    assert code == 2
    assert "refused" in captured.err
    assert "not registered" in captured.err
    assert recorded_trials(db, PROJECT, "1d", "crypto") == []


def test_cli_rule_asset_mismatch_refused(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
        == 0
    )
    capsys.readouterr()
    store_bars(db, NVDA, 30)

    code = main(run_args(db, rule="band", asset=NVDA))
    captured = capsys.readouterr()

    # `band` declares the crypto class only, and NVDA has no "-".
    assert code == 2
    assert "refused" in captured.err
    assert "ASSETS" in captured.err
    assert recorded_trials(db, PROJECT, "1d", "stock") == []

    # The other way round: event_veto is a stock rule, XRP-USDC is a pair.
    assert (
        main(
            [
                "register",
                "--db",
                db,
                "--project-id",
                PROJECT,
                "--rule",
                "event_veto",
            ]
        )
        == 0
    )
    capsys.readouterr()

    code = main(run_args(db, rule="event_veto", asset=XRP))
    captured = capsys.readouterr()

    assert code == 2
    assert "refused" in captured.err
    assert "ASSETS" in captured.err
    assert recorded_trials(db, PROJECT, "1d", "crypto") == []


# ---------------------------------------------------------------- register


def test_cli_register_and_conflict(tmp_path, capsys):
    db = str(tmp_path / "lab.db")

    code = main(["register", "--db", db, "--project-id", PROJECT, "--rule", "all"])
    out = capsys.readouterr().out

    assert code == 0
    lines = out.splitlines()
    for rule_id in RULE_MODULES:
        assert any(rule_id in line for line in lines), out

    # Registering the same set again is a no-op that still succeeds.
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "all"])
        == 0
    )
    capsys.readouterr()

    lab = LabStore(db)
    try:
        stored = {
            rule_id: lab.get_rule(PROJECT, rule_id) for rule_id in RULE_MODULES
        }
    finally:
        lab.close()

    for rule_id, module in RULE_MODULES.items():
        assert stored[rule_id] is not None, rule_id
        assert stored[rule_id]["grid"] == module.GRID, rule_id


def test_cli_register_new_version_counts_old_trials(tmp_path, capsys, monkeypatch):
    db = str(tmp_path / "lab.db")
    # 30 consecutive daily bars hold four 10 + 5 windows.
    store_bars(db, XRP, 30)

    # The grid band carried before its first config was widened.
    monkeypatch.setattr(band, "GRID", BAND_GRID_OLD)
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
        == 0
    )
    capsys.readouterr()

    code = main(run_args(db))
    capsys.readouterr()
    assert code == 0
    old = recorded_trials(db, PROJECT, "1d", "crypto")
    # one trial per config of the old grid
    assert len(old) == 5

    # The design is changed to the grid that stands: the run is refused and
    # writes nothing.
    monkeypatch.setattr(band, "GRID", BAND_GRID_NOW)
    code = main(run_args(db))
    err = capsys.readouterr().err
    assert code == 2
    assert "different grid" in err
    assert "new rule version" in err
    assert recorded_trials(db, PROJECT, "1d", "crypto") == old

    # Registering the changed grid without the flag is still the conflict.
    code = main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
    err = capsys.readouterr().err
    assert code == 2
    assert "new rule version" in err

    # With the flag the changed grid becomes version 2, and the line says the
    # trials already run against the old grid still count.
    code = main(
        [
            "register",
            "--db",
            db,
            "--project-id",
            PROJECT,
            "--rule",
            "band",
            "--new-version",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "version 2" in out
    assert "still count" in out

    # The run now goes through, and it adds to the old trials instead of
    # replacing them: the four configs both grids share are the same trials, and
    # the config the new grid changed is one more.
    code = main(run_args(db))
    capsys.readouterr()
    assert code == 0
    now = recorded_trials(db, PROJECT, "1d", "crypto")
    old_keys = [(row.rule_id, row.params, row.data_hash) for row in old]
    new_keys = [(row.rule_id, row.params, row.data_hash) for row in now]
    for key in old_keys:
        assert key in new_keys
    assert len(now) > len(old)
    assert len(now) == 6


def test_cli_register_new_version_unchanged_grid_says_so(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
        == 0
    )
    capsys.readouterr()

    # The same grid again with the flag: the store keeps the version already on
    # file, so the line says so and says nothing about old trials counting.
    code = main(
        [
            "register",
            "--db",
            db,
            "--project-id",
            PROJECT,
            "--rule",
            "band",
            "--new-version",
        ]
    )
    out = capsys.readouterr().out

    assert code == 0
    assert "is unchanged in project" in out
    assert "(version 1)" in out
    assert "no new version registered" in out
    assert "still count" not in out

    lab = LabStore(db)
    try:
        assert lab.get_rule(PROJECT, "band")["version"] == 1
    finally:
        lab.close()


def test_cli_register_all_new_version_writes_nothing(
    tmp_path, capsys, monkeypatch
):
    db = str(tmp_path / "lab.db")
    # Only band is registered, so the other three have nothing to supersede.
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
        == 0
    )
    capsys.readouterr()

    # band's grid is changed, so band on its own would become version 2.
    monkeypatch.setattr(band, "GRID", BAND_GRID_CHANGED)

    code = main(
        [
            "register",
            "--db",
            db,
            "--project-id",
            PROJECT,
            "--rule",
            "all",
            "--new-version",
        ]
    )
    err = capsys.readouterr().err

    # The run stops on the rule with nothing to supersede, by name, before it
    # writes anything at all.
    assert code == 2
    assert "refused" in err
    assert "regime" in err
    assert "not registered" in err

    lab = LabStore(db)
    try:
        assert lab.get_rule(PROJECT, "band")["version"] == 1
        assert lab.get_rule(PROJECT, "regime") is None
    finally:
        lab.close()


def test_cli_register_rule_without_a_simulator_refused(
    tmp_path, capsys, monkeypatch
):
    db = str(tmp_path / "lab.db")
    # A module naming no simulator cannot say which one reads its answer, so the
    # command refuses it instead of raising on the way through.
    monkeypatch.delattr(band, "SIMULATOR")

    code = main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
    captured = capsys.readouterr()

    assert code == 2
    assert "refused" in captured.err
    assert "SIMULATOR" in captured.err
    assert "Traceback" not in captured.err

    lab = LabStore(db)
    try:
        assert lab.get_rule(PROJECT, "band") is None
    finally:
        lab.close()


def test_cli_register_new_version_flag_parses():
    parser = build_parser()

    args = parser.parse_args(
        [
            "register",
            "--db",
            "x",
            "--project-id",
            "p",
            "--rule",
            "band",
            "--new-version",
        ]
    )
    assert args.command == "register"
    assert args.rule == ["band"]
    assert args.new_version is True

    # Without the flag the command is the one it always was.
    plain = parser.parse_args(
        ["register", "--db", "x", "--project-id", "p", "--rule", "band"]
    )
    assert plain.new_version is False


# ---------------------------------------------------------------- run verdicts


def test_cli_run_short_data_is_a_normal_verdict(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
        == 0
    )
    capsys.readouterr()
    # 8 bars is short of the 10 + 5 a single window needs.
    store_bars(db, XRP, 8)

    code = main(run_args(db))
    out = capsys.readouterr().out

    # A sample too short to decide is an answer, not a refusal.
    assert code == 0
    assert "status: not_enough_data" in out


def test_cli_run_changed_grid_refused(tmp_path, capsys, monkeypatch):
    db = str(tmp_path / "lab.db")
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
        == 0
    )
    capsys.readouterr()
    # 30 consecutive daily bars, so the walk forward has windows to fill.
    store_bars(db, XRP, 30)

    # The module's grid no longer matches what was pre-registered, so the run is
    # refused and nothing is recorded.
    monkeypatch.setattr(band, "GRID", BAND_GRID_CHANGED)

    code = main(run_args(db))
    err = capsys.readouterr().err

    assert code == 2
    assert "refused" in err
    assert err.lstrip().startswith("refused:")
    assert "band" in err
    assert PROJECT in err
    assert "new rule version" in err
    assert recorded_trials(db, PROJECT, "1d", "crypto") == []


def test_cli_run_same_grid_proceeds(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
        == 0
    )
    capsys.readouterr()
    store_bars(db, XRP, 30)

    code = main(run_args(db))
    out = capsys.readouterr().out

    # The grid on file is the one the module carries, so the walk runs and its
    # configs are recorded.
    assert code == 0
    assert "status: " in out
    assert len(recorded_trials(db, PROJECT, "1d", "crypto")) > 0


def test_cli_run_has_no_step_flag():
    # The walk forward steps by the test length, and the flag that used to
    # override it is gone, so argparse refuses it.
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(run_args("x") + ["--step", "5"])

    assert caught.value.code == 2


# ---------------------------------------------------------------- study-buys parsing


def test_cli_study_buys_arg_parsing():
    parser = build_parser()

    args = parser.parse_args(
        [
            "study-buys",
            "--db",
            "x",
            "--project-id",
            "p",
            "--symbols",
            " nvda, AMD ",
            "--st-tax-rate",
            "0.3",
            "--lt-tax-rate",
            "0.15",
        ]
    )

    assert args.symbols == ["NVDA", "AMD"]
    assert args.controls == ["SPY", "QQQ"]
    assert isinstance(args.cash, D)
    assert args.cash == D("10000")
    assert args.horizon_days == 450
    assert args.block_len == 330
    assert args.veto_days == 3
    assert args.stride == 21
    assert args.n_boot == 1000
    assert isinstance(args.st_tax_rate, D)
    assert args.st_tax_rate == D("0.3")
    assert isinstance(args.lt_tax_rate, D)
    assert args.lt_tax_rate == D("0.15")

    with_controls = parser.parse_args(
        [
            "study-buys",
            "--db",
            "x",
            "--project-id",
            "p",
            "--symbols",
            "nvda",
            "--controls",
            " vti , BND ",
            "--st-tax-rate",
            "0.3",
            "--lt-tax-rate",
            "0.15",
        ]
    )
    assert with_controls.controls == ["VTI", "BND"]

    # An empty symbol list, an empty entry and a non-numeric cash are argparse
    # errors rather than something the study has to refuse later.
    for bad_symbols in ("", "NVDA,,"):
        with pytest.raises(SystemExit):
            parser.parse_args(
                [
                    "study-buys",
                    "--db",
                    "x",
                    "--project-id",
                    "p",
                    "--symbols",
                    bad_symbols,
                    "--st-tax-rate",
                    "0.3",
                    "--lt-tax-rate",
                    "0.15",
                ]
            )

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "study-buys",
                "--db",
                "x",
                "--project-id",
                "p",
                "--symbols",
                "NVDA",
                "--cash",
                "abc",
                "--st-tax-rate",
                "0.3",
                "--lt-tax-rate",
                "0.15",
            ]
        )

    # study-nvda was replaced by `--symbols` and is not a subcommand any more.
    with pytest.raises(SystemExit):
        parser.parse_args(["study-nvda", "--db", "x"])


def test_cli_study_buys_missing_bars_refused(tmp_path, capsys):
    db = str(tmp_path / "lab.db")

    code = main(study_args(db))
    captured = capsys.readouterr()

    assert code == 2
    assert "refused" in captured.err
    assert "no bars stored for NVDA" in captured.err


def test_cli_study_buys_records_the_study(tmp_path, capsys, monkeypatch):
    db = tmp_path / "lab.db"
    for symbol in ("NVDA", "AMD", "SPY", "QQQ"):
        store_bars(db, symbol, 3)

    calls = []

    class FakeStudy:
        """The little of a StudyResult the CLI reads."""

        params = {"cash": "10000"}

        def to_markdown(self):
            return "# study text\n"

    def fake_run_study(*args, **kwargs):
        calls.append({"args": args, "kwargs": dict(kwargs)})
        return FakeStudy()

    monkeypatch.setattr(cli, "run_study", fake_run_study)

    code = main(study_args(str(db)))
    out = capsys.readouterr().out

    assert code == 0
    assert "# study text" in out
    assert len(calls) == 1

    # The call is read by name, whether the arguments arrive as keywords or in
    # the order `run_study` declares them.
    fields = {}
    for index, name in enumerate(
        (
            "bars_by_symbol",
            "events_by_symbol",
            "cash",
            "horizon_days",
            "costs",
            "block_len",
        )
    ):
        if index < len(calls[0]["args"]):
            fields[name] = calls[0]["args"][index]
    fields.update(calls[0]["kwargs"])

    assert set(fields["bars_by_symbol"]) == {"NVDA", "AMD", "SPY", "QQQ"}
    assert fields["controls"] == ("SPY", "QQQ")
    assert fields["costs"].asset == "NVDA"
    assert fields["costs"].st_tax_rate == D("0.3")

    lab = LabStore(db)
    try:
        studies = lab.studies(PROJECT)
    finally:
        lab.close()

    assert len(studies) == 1
    assert studies[0]["name"] == "study-buys"
    assert studies[0]["result"]["markdown"] == "# study text\n"
    assert studies[0]["result"]["params"] == {"cash": "10000"}


# ---------------------------------------------------------------- import-earnings


def test_cli_import_earnings_amd_fourteen_day_rule(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    csv_file = write_earnings_csv(
        tmp_path / "amd-earnings.csv",
        [
            "2023-01-31,,post",  # line 2: no announcement on file
            "2025-11-04,,post",  # line 3: no announcement on file
            "2026-11-03,2026-10-06,post",  # line 4: announcement on file
            "2020-10-27,2020-10-15,pre",  # line 5: announcement on file
        ],
    )

    code = main(
        [
            "import-earnings",
            "--db",
            db,
            "--project-id",
            PROJECT,
            "--symbol",
            AMD,
            "--csv-file",
            csv_file,
        ]
    )
    out = capsys.readouterr().out

    assert code == 0
    # 4 rows loaded, and 2 of them carry an assumed announcement date.
    assert re.search(r"\b4\b", out), out
    assert re.search(r"\b2\b", out), out
    assert "assumed" in out

    events = read_events(db, AMD)
    assert [event.at for event in events] == [
        utc(2020, 10, 27),
        utc(2023, 1, 31),
        utc(2025, 11, 4),
        utc(2026, 11, 3),
    ]
    # Only the 2020-10-27 row is tagged pre-market.
    assert [event.session for event in events] == ["pre", "post", "post", "post"]
    # The two rows with a blank announcement take release minus 14 days:
    # 2023-01-31 - 14 days = 2023-01-17 and 2025-11-04 - 14 days = 2025-10-21.
    assert [event.announced_at for event in events] == [
        utc(2020, 10, 15),
        utc(2023, 1, 17),
        utc(2025, 10, 21),
        utc(2026, 10, 6),
    ]
    for event in events:
        assert event.kind == "earnings"
        assert event.at.utcoffset() == timedelta(0)
        assert event.announced_at.utcoffset() == timedelta(0)
        assert (event.at.hour, event.at.minute) == (0, 0)
        assert (event.announced_at.hour, event.announced_at.minute) == (0, 0)

    assumed = [event for event in events if "release minus 14 days" in event.note]
    assert [event.at for event in assumed] == [utc(2023, 1, 31), utc(2025, 11, 4)]


def test_cli_import_earnings_skips_bad_rows(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    csv_file = write_earnings_csv(
        tmp_path / "amd-bad-rows.csv",
        [
            "2024-05-01,2024-05-10,post",  # line 2: announced after the release
            "not-a-date,,post",  # line 3: the date does not parse
            "2024-06-03,2024-05-20,sideways",  # line 4: session is not pre/post
            "2024-07-01,,pre",  # line 5: lands
        ],
    )

    code = main(
        [
            "import-earnings",
            "--db",
            db,
            "--project-id",
            PROJECT,
            "--symbol",
            AMD,
            "--csv-file",
            csv_file,
        ]
    )
    out = capsys.readouterr().out

    assert code == 0
    for line_no in (2, 3, 4):
        assert re.search(rf"\b{line_no}\b", out), out

    landed = [event for event in read_events(db, AMD) if event.at.year == 2024]
    # The one good row lands, its announcement assumed: 2024-07-01 - 14 days
    # = 2024-06-17.
    assert [(event.at, event.announced_at, event.session) for event in landed] == [
        (utc(2024, 7, 1), utc(2024, 6, 17), "pre"),
    ]


# ---------------------------------------------------------------- import-stock


def test_cli_import_stock_sources(tmp_path, capsys):
    db = str(tmp_path / "lab.db")

    code = main(
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            NVDA,
            "--csv-text",
            TIINGO_CSV,
        ]
    )
    assert code == 0
    capsys.readouterr()

    stored = read_bars(db, NVDA)
    assert len(stored) == 3
    assert [item.ts for item in stored] == [
        utc(2024, 6, 10),
        utc(2024, 6, 11),
        utc(2024, 6, 12),
    ]
    # Each row's adjClose equals its close, so f = 100/100, 101/101, 102/102 = 1.
    assert [item.close for item in stored] == [D("100"), D("101"), D("102")]
    assert {item.adj_factor for item in stored} == {D("1")}

    csv_file = tmp_path / "amd.csv"
    csv_file.write_text(TIINGO_CSV, encoding="utf-8")

    code = main(
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            AMD,
            "--csv-file",
            str(csv_file),
        ]
    )
    assert code == 0
    capsys.readouterr()
    assert len(read_bars(db, AMD)) == 3

    refusals = [
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            NVDA,
            "--csv-text",
            TIINGO_CSV,
            "--csv-file",
            str(csv_file),
        ],
        ["import-stock", "--db", db, "--symbol", NVDA],
    ]
    for argv in refusals:
        code = main(argv)
        err = capsys.readouterr().err
        assert code == 2
        assert "refused" in err
        assert "give exactly one of" in err


# ---------------------------------------------------------------- tiingo token


def tiingo_fake(calls, csv_text=TIINGO_CSV):
    """A `tiingo_fetch` that records its arguments and serves *csv_text*."""

    def fetch(symbol, token, start_date=None):
        calls.append({"symbol": symbol, "token": token, "start_date": start_date})
        return csv_text

    return fetch


def token_file(tmp_path, name, text):
    """A file holding *text*, returned as its path string."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


class TiingoResponse:
    """The part of an http response the Tiingo fetcher reads."""

    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class TiingoOpener:
    """An opener that answers every request with one body and records it.

    Nothing here opens a connection: it stands in for the network the real
    fetcher would otherwise reach for.
    """

    def __init__(self, body=b""):
        self.body = body
        self.requests = []

    def __call__(self, request, *args, **kwargs):
        self.requests.append(request)
        return TiingoResponse(self.body)

    @property
    def urls(self):
        return [
            getattr(request, "full_url", None) or str(request)
            for request in self.requests
        ]


def real_fetcher_over(opener):
    """The real `fetch_tiingo_csv`, handed *opener* instead of the network."""
    real = cli.fetch_tiingo_csv

    def fetch(symbol, token, start_date=None, **kwargs):
        return real(symbol, token, start_date, opener=opener, **kwargs)

    return fetch


def query_of(url):
    """The parsed query string of *url*."""
    return parse_qs(urlsplit(url).query, keep_blank_values=True)


def test_cli_tiingo_token_file_source(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("TIINGO_API_TOKEN", raising=False)
    db = str(tmp_path / "a.db")
    calls = []
    token_path = token_file(tmp_path, "token.txt", "FAKE-TOKEN-123\n")

    code = main(
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            NVDA,
            "--tiingo",
            "--start-date",
            "2024-01-02",
            "--tiingo-token-file",
            token_path,
        ],
        tiingo_fetch=tiingo_fake(calls),
    )
    captured = capsys.readouterr()

    assert code == 0
    assert len(calls) == 1
    # The file's text is stripped before it is handed to the fetch.
    assert calls[0]["token"] == "FAKE-TOKEN-123"
    assert calls[0]["symbol"] == NVDA
    assert as_text(calls[0]["start_date"]) == "2024-01-02"
    # The token is never printed, in either stream.
    assert "FAKE-TOKEN-123" not in captured.out
    assert "FAKE-TOKEN-123" not in captured.err
    assert len(read_bars(db, NVDA)) == 3


def test_cli_tiingo_token_from_environment(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("TIINGO_API_TOKEN", "FAKE-ENV-456")
    db = str(tmp_path / "b.db")
    calls = []

    code = main(
        ["import-stock", "--db", db, "--symbol", NVDA, "--tiingo"],
        tiingo_fetch=tiingo_fake(calls),
    )
    captured = capsys.readouterr()

    assert code == 0
    assert calls[0]["token"] == "FAKE-ENV-456"
    # No --start-date given, so the fetch is asked for the whole history.
    assert as_text(calls[0]["start_date"]) == "1980-01-01"
    assert "FAKE-ENV-456" not in captured.out
    assert "FAKE-ENV-456" not in captured.err


def test_cli_tiingo_token_from_named_environment_variable(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv("TIINGO_API_TOKEN", "FAKE-OTHER-000")
    monkeypatch.setenv("MY_TOKEN_VAR", "FAKE-ENV-789")
    db = str(tmp_path / "c.db")
    calls = []

    code = main(
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            NVDA,
            "--tiingo",
            "--tiingo-token-env",
            "MY_TOKEN_VAR",
        ],
        tiingo_fetch=tiingo_fake(calls),
    )
    captured = capsys.readouterr()

    assert code == 0
    # The named variable wins over the default name.
    assert calls[0]["token"] == "FAKE-ENV-789"
    assert "FAKE-ENV-789" not in captured.out
    assert "FAKE-ENV-789" not in captured.err


def test_cli_tiingo_without_a_token_refused(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("TIINGO_API_TOKEN", raising=False)
    db = str(tmp_path / "d.db")
    calls = []

    code = main(
        ["import-stock", "--db", db, "--symbol", NVDA, "--tiingo"],
        tiingo_fetch=tiingo_fake(calls),
    )
    captured = capsys.readouterr()

    assert code == 2
    assert "refused" in captured.err
    # The refusal names both ways of supplying a token.
    assert "--tiingo-token-file" in captured.err
    assert "TIINGO_API_TOKEN" in captured.err
    assert calls == []
    assert read_bars(db, NVDA) == []


def test_cli_tiingo_token_file_wins_over_the_environment(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv("TIINGO_API_TOKEN", "FAKE-ENV-456")
    db = str(tmp_path / "e.db")
    calls = []
    token_path = token_file(tmp_path, "token.txt", "FAKE-FILE-111\n")

    code = main(
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            NVDA,
            "--tiingo",
            "--tiingo-token-file",
            token_path,
        ],
        tiingo_fetch=tiingo_fake(calls),
    )
    capsys.readouterr()

    assert code == 0
    assert calls[0]["token"] == "FAKE-FILE-111"


def test_cli_tiingo_missing_token_file_refused(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("TIINGO_API_TOKEN", raising=False)
    db = str(tmp_path / "f.db")
    calls = []

    code = main(
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            NVDA,
            "--tiingo",
            "--tiingo-token-file",
            str(tmp_path / "no-such-token.txt"),
        ],
        tiingo_fetch=tiingo_fake(calls),
    )
    captured = capsys.readouterr()

    assert code == 2
    assert "refused" in captured.err
    assert calls == []
    assert read_bars(db, NVDA) == []


# ---------------------------------------------------------------- tiingo defaults


def test_cli_two_line_token_file_refused_without_a_request(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.delenv("TIINGO_API_TOKEN", raising=False)
    db = str(tmp_path / "g.db")
    token_path = token_file(tmp_path, "two-line-token.txt", "FAKE-ONE\nFAKE-TWO\n")
    opener = TiingoOpener(TIINGO_CSV.encode("utf-8"))
    # The real fetcher, driven over a fake opener: a token of two lines has to be
    # refused before a request is even built.
    monkeypatch.setattr(cli, "fetch_tiingo_csv", real_fetcher_over(opener))

    code = main(
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            NVDA,
            "--tiingo",
            "--tiingo-token-file",
            token_path,
        ]
    )
    captured = capsys.readouterr()

    assert code != 0
    # Neither line of the token is quoted back, in either stream.
    for part in ("FAKE-ONE", "FAKE-TWO"):
        assert part not in captured.out
        assert part not in captured.err
    assert (
        "The Tiingo token is not valid: it must be one line of letters and digits."
        in captured.err
    )
    assert opener.requests == []
    assert read_bars(db, NVDA) == []


def test_cli_tiingo_without_a_start_date_asks_from_1980(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv("TIINGO_API_TOKEN", "FAKE-ENV-456")
    db = str(tmp_path / "h.db")
    calls = []

    code = main(
        ["import-stock", "--db", db, "--symbol", NVDA, "--tiingo"],
        tiingo_fetch=tiingo_fake(calls),
    )
    capsys.readouterr()

    assert code == 0
    assert as_text(calls[0]["start_date"]) == "1980-01-01"


def test_cli_import_stock_help_names_the_default_start_date(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["import-stock", "--help"])

    out = capsys.readouterr().out

    assert caught.value.code == 0
    assert "1980-01-01" in out


def test_cli_tiingo_start_date_default_reaches_the_request(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.delenv("TIINGO_API_TOKEN", raising=False)
    db = str(tmp_path / "i.db")
    token_path = token_file(tmp_path, "tok.txt", "FAKE-TOKEN-123\n")
    opener = TiingoOpener(TIINGO_CSV.encode("utf-8"))
    monkeypatch.setattr(cli, "fetch_tiingo_csv", real_fetcher_over(opener))

    code = main(
        [
            "import-stock",
            "--db",
            db,
            "--symbol",
            NVDA,
            "--tiingo",
            "--tiingo-token-file",
            token_path,
        ]
    )
    capsys.readouterr()

    assert code == 0
    assert len(opener.requests) == 1
    assert query_of(opener.urls[0]).get("startDate") == ["1980-01-01"]
    assert len(read_bars(db, NVDA)) == 3


# ---------------------------------------------------------------- backfill and gaps


class _CandleResponse:
    """The public client's response shape: `.to_dict()` gives {"candles": [...]}."""

    def __init__(self, candles):
        self._candles = candles

    def to_dict(self):
        return {"candles": list(self._candles)}


class FakeCandleClient:
    """`get_public_candles` over hand-built candles, recording every call."""

    def __init__(self, candles):
        self.candles = dict(candles)
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
        return _CandleResponse(
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


def test_cli_backfill_gaps_first_available(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    client = FakeCandleClient(
        {
            epoch(utc(2024, 1, 1)): flat_candle("1.00"),
            epoch(utc(2024, 1, 2)): flat_candle("1.01"),
            epoch(utc(2024, 1, 3)): flat_candle("1.02"),
        }
    )

    code = main(
        [
            "backfill-crypto",
            "--db",
            db,
            "--product",
            XRP,
            "--interval",
            "1d",
            "--start",
            "2024-01-01",
            "--end",
            "2024-01-04",
        ],
        candle_client=client,
        now=utc(2024, 1, 5),
    )
    capsys.readouterr()

    assert code == 0
    stored = read_bars(db, XRP)
    assert [item.ts for item in stored] == [
        utc(2024, 1, 1),
        utc(2024, 1, 2),
        utc(2024, 1, 3),
    ]

    code = main(
        ["first-available", "--db", db, "--product", XRP, "--interval", "1d"],
        candle_client=client,
        now=utc(2024, 1, 5),
    )
    out = capsys.readouterr().out

    assert code == 0
    assert "2024-01-01" in out

    code = main(
        ["gaps", "--db", db, "--symbol", XRP, "--interval", "1d", "--calendar", "crypto"]
    )
    out = capsys.readouterr().out

    # 2024-01-01, 01-02 and 01-03 are consecutive, so nothing is missing.
    assert code == 0
    assert "no gaps" in out

    lab = LabStore(db)
    try:
        # A bar at 01-05 leaves 01-04 the one missing day.
        lab.upsert_bars(XRP, "1d", [bar(utc(2024, 1, 5), "1.03", XRP)])
    finally:
        lab.close()

    code = main(
        ["gaps", "--db", db, "--symbol", XRP, "--interval", "1d", "--calendar", "crypto"]
    )
    out = capsys.readouterr().out

    assert code == 0
    assert "2024-01-04 to 2024-01-04" in out

    code = main(
        ["gaps", "--db", db, "--symbol", XRP, "--interval", "1h", "--calendar", "nyse"]
    )
    err = capsys.readouterr().err

    # The NYSE calendar is a daily one, so an hourly series is refused.
    assert code == 2
    assert "refused" in err


# ---------------------------------------------------------------- database guard


OLD_RUNS = (
    "CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "project_id TEXT NOT NULL, rule_id TEXT NOT NULL, "
    "params_json TEXT NOT NULL, data_hash TEXT NOT NULL, "
    "result_json TEXT NOT NULL, created_at TEXT NOT NULL, "
    "UNIQUE (project_id, rule_id, params_json, data_hash))"
)


def _runs_statement(path):
    """The CREATE statement of the `runs` table as sqlite_master holds it."""
    raw = sqlite3.connect(path)
    try:
        row = raw.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='runs'"
        ).fetchone()
    finally:
        raw.close()
    return None if row is None else row[0]


def test_cli_old_database_refused(tmp_path, capsys):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    raw.isolation_level = None
    raw.execute(OLD_RUNS)
    raw.execute("PRAGMA user_version=1")
    raw.close()

    statement = _runs_statement(path)
    before = path.read_bytes()

    for argv in (
        [
            "gaps",
            "--db",
            str(path),
            "--symbol",
            XRP,
            "--interval",
            "1d",
            "--calendar",
            "crypto",
        ],
        ["register", "--db", str(path), "--project-id", PROJECT, "--rule", "band"],
    ):
        code = main(argv)
        err = capsys.readouterr().err

        assert code == 2
        assert "older version of the lab" in err
        # The refusal leaves the file exactly as it found it.
        assert path.read_bytes() == before
        assert path.stat().st_size == len(before)
        assert _runs_statement(path) == statement


def test_cli_db_guard_passes_current_files(tmp_path):
    # A path that does not exist yet passes.
    check_db_schema(str(tmp_path / "fresh.db"))

    # So does a database the current store made.
    lab = LabStore(tmp_path / "current.db")
    lab.close()
    check_db_schema(str(tmp_path / "current.db"))


# ---------------------------------------------------------------- the simulator


def oscillating_bars(symbol, count, *, interval="1d", start=None):
    """*count* bars whose close swings 0.95 to 1.04 around 1.00, with a spread.

    The shape is a deterministic ten-bar oscillation,
    close = 1.00 + 0.05 * ((i % 10) - 5) / 5, and each bar carries 0.01 either
    side of its close, so a channel rule sees a range rather than a trend.
    """
    first = utc(2024, 1, 1) if start is None else start
    step = DAY if interval == "1d" else HOUR
    rows = []
    for index in range(count):
        close = D("1.00") + D("0.05") * (D(index % 10) - D("5")) / D("5")
        rows.append(
            Bar(
                symbol=symbol,
                interval=interval,
                ts=first + step * index,
                open=close,
                high=close + D("0.01"),
                low=close - D("0.01"),
                close=close,
                volume=D("1"),
            )
        )
    return rows


def store_oscillating_bars(path, symbol, count, *, interval="1d"):
    """Store `oscillating_bars` for one symbol and interval."""
    lab = LabStore(path)
    try:
        lab.upsert_bars(
            symbol,
            interval,
            oscillating_bars(symbol, count, interval=interval),
        )
    finally:
        lab.close()


def printed_numbers(out):
    """The numbers block `run` prints under its status and reason lines."""
    import json

    lines = out.splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith("{")
    )
    return json.loads("\n".join(lines[start:]))


def test_cli_run_regime_end_to_end_picks_grid_sim(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(
            ["register", "--db", db, "--project-id", PROJECT, "--rule", "regime"]
        )
        == 0
    )
    capsys.readouterr()

    # The widest config of regime.GRID reads the 80 bars before the latest one,
    # so a train slice of 90 bars holds it whole; a test slice of 30 then gives
    # the walk (180 - 90) // 30 = 3 windows over the 180 stored bars.
    store_oscillating_bars(db, XRP, 180)

    argv = run_args(db, rule="regime")
    argv[argv.index("--train-len") + 1] = "90"
    argv[argv.index("--test-len") + 1] = "30"

    # No --sim: the simulator is the one the rule declares, so a rule whose
    # answer is a decision about a ladder is owed the ladder's simulator.
    code = main(argv)
    captured = capsys.readouterr()

    assert code == 0
    lines = captured.out.splitlines()
    assert any(line.startswith("status: ") for line in lines), captured.out
    numbers = printed_numbers(captured.out)
    assert numbers["sim"] == "grid"


@pytest.mark.parametrize(
    "rule, given",
    [("regime", "market"), ("band", "grid")],
)
def test_cli_run_mismatched_sim_refused(tmp_path, capsys, rule, given):
    db = str(tmp_path / "lab.db")
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", rule])
        == 0
    )
    capsys.readouterr()
    store_oscillating_bars(db, XRP, 40)

    code = main(run_args(db, rule=rule) + ["--sim", given])
    captured = capsys.readouterr()

    # The rule runs on one simulator and the flag names another, so the command
    # declines before anything is walked forward or recorded.
    assert code == 2
    assert captured.err.lstrip().startswith("refused:")
    assert rule in captured.err
    assert "market" in captured.err
    assert "grid" in captured.err
    assert recorded_trials(db, PROJECT, "1d", "crypto") == []


def test_cli_run_matching_sim_accepted(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(["register", "--db", db, "--project-id", PROJECT, "--rule", "band"])
        == 0
    )
    capsys.readouterr()
    store_oscillating_bars(db, XRP, 60)

    code = main(run_args(db, rule="band") + ["--sim", "market"])
    captured = capsys.readouterr()

    # band runs on the market simulator, so naming it is not a refusal.
    assert code != 2
    assert "refused" not in captured.err


# ---------------------------------------------------------------- funded runs


def test_cli_run_funded_rule_defaults_to_no_start_cash(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(
            [
                "register",
                "--db",
                db,
                "--project-id",
                PROJECT,
                "--rule",
                "event_veto",
            ]
        )
        == 0
    )
    capsys.readouterr()
    # 30 daily bars hold four 10 + 5 windows.
    store_bars(db, NVDA, 30)

    code = main(run_args(db, rule="event_veto", asset=NVDA))
    captured = capsys.readouterr()

    # A funded rule pays its own way in, so no --start-cash means no cash.
    assert code == 0
    numbers = printed_numbers(captured.out)
    assert numbers["funded"] is True

    # The trial the walk recorded carries the start cash and the funding it ran
    # with, so the same rule walked another way is a trial of its own.
    recorded = recorded_trials(db, PROJECT, "1d", "stock")
    assert recorded
    for row in recorded:
        assert row.params["_walk"]["start_cash"] == "0"
        assert row.params["_walk"]["funding"] == {
            "amount": "50",
            "every": "week",
        }


def test_cli_run_funded_rule_refuses_start_cash_above_one_week(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(
            [
                "register",
                "--db",
                db,
                "--project-id",
                PROJECT,
                "--rule",
                "event_veto",
            ]
        )
        == 0
    )
    capsys.readouterr()
    store_bars(db, NVDA, 30)

    code = main(
        run_args(db, rule="event_veto", asset=NVDA) + ["--start-cash", "51"]
    )
    captured = capsys.readouterr()

    # 51 is more than the 50 a week that funds the rule, so the command declines
    # before anything is walked forward or recorded.
    assert code == 2
    assert captured.err.lstrip().startswith("refused:")
    assert "at most 50" in captured.err
    assert recorded_trials(db, PROJECT, "1d", "stock") == []

    # one weekly amount itself is the most a run may start with
    allowed = main(
        run_args(db, rule="event_veto", asset=NVDA) + ["--start-cash", "50"]
    )
    assert allowed != 2


def test_cli_run_unfunded_rule_keeps_the_default_start_cash(tmp_path, capsys):
    db = str(tmp_path / "lab.db")
    assert (
        main(
            ["register", "--db", db, "--project-id", PROJECT, "--rule", "band"]
        )
        == 0
    )
    capsys.readouterr()
    store_oscillating_bars(db, XRP, 60)

    code = main(run_args(db, rule="band"))
    capsys.readouterr()

    # A rule with no funding starts from the lab's own 10000, and its trial key
    # carries the four walk settings and nothing about that cash: a re-run of it
    # from another start cash is the trial already on file.
    assert code == 0
    recorded = recorded_trials(db, PROJECT, "1d", "crypto")
    assert recorded
    for row in recorded:
        walk = row.params["_walk"]
        assert walk == {
            "train_len": 10,  # run_args: --train-len 10
            "test_len": 5,  # run_args: --test-len 5
            "n_groups": 16,  # the default block count of evaluate_edge_rule
            "sim": "market",  # band.SIMULATOR
        }
        assert "start_cash" not in walk
        assert "funding" not in walk