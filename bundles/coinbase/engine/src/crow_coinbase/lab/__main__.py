"""The lab's command line: one subcommand for each step of the research loop.

Every subcommand takes the database file with `--db`, opens it through
`LabStore` and prints what it did.  A command that declines to run says so on
stderr as `refused: <sentence>` and returns 2; argparse reports a missing or
malformed flag in its own way and exits 2 through SystemExit.  A verdict of
`not_enough_data` or `fail` is an answer rather than a refusal, so it returns 0.

The candle client and the Tiingo fetcher are injected, so a command can be
driven over a stand-in for the network; the only place a request is made is
`feeds.py`, and only when its real opener is in use.

Money flags are parsed as Decimals and never as floats.  A date given without an
offset is read as UTC.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
import sys
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal as D
from decimal import InvalidOperation
from pathlib import Path

from .backfill import (
    backfill_crypto,
    first_available,
    gap_report,
    import_stock_csv,
)
from .costs import CostModel
from .feeds import FeedError, PublicCandles, fetch_tiingo_csv
from .rules import band, event_veto, grid_gate, regime
from .rules.base import check_rule_module
from .rules.event_veto import NYSE_HOLIDAYS
from .store import LabStore, LabStoreError
from .studies.buy_timing import run_study
from .validate import evaluate_edge_rule

__all__ = ["build_parser", "check_db_schema", "main"]

UTC = timezone.utc

# The wide window every subcommand reads stored market data over.
LAB_FLOOR = datetime(1990, 1, 1, tzinfo=UTC)
LAB_CEILING = datetime(2100, 1, 1, tzinfo=UTC)

INTERVALS = ("1h", "1d")
CALENDARS = ("crypto", "nyse")
SIMULATORS = ("market", "grid")

# The rules the command line knows, by the id each module carries.
RULE_MODULES = {
    module.RULE_ID: module for module in (band, regime, grid_gate, event_veto)
}
ALL_RULES = "all"
RULE_CHOICES = tuple(sorted(RULE_MODULES)) + (ALL_RULES,)

STUDY_NAME = "study-buys"
DEFAULT_CONTROLS = ("SPY", "QQQ")
DEFAULT_CASH = D("10000")
DEFAULT_HORIZON_DAYS = 450
DEFAULT_BLOCK_LEN = 330
DEFAULT_VETO_DAYS = 3
DEFAULT_STRIDE = 21
DEFAULT_N_BOOT = 1000

# The environment variable a Tiingo token is read from unless another name is
# given, and the reason a missing token names both ways of supplying one.
DEFAULT_TOKEN_ENV = "TIINGO_API_TOKEN"

# The first day a Tiingo import asks for when no --start-date is given: the
# daily feed's history reaches back this far, so the whole of it is stored.
DEFAULT_TIINGO_START = date(1980, 1, 1)

# An earnings row with no announcement on file is stamped this many days before
# its release, and the note says so in as many words.
ASSUMED_ANNOUNCEMENT_DAYS = 14
EARNINGS_HEADER = ("release_date", "announced_date", "session")
EARNINGS_SESSIONS = ("pre", "post")
DEFAULT_SESSION = "post"
ASSUMED_NOTE = "announced_at assumed: release minus 14 days"

# The columns a current runs table keys a trial on.
RUN_KEY_COLUMNS = ("asset", "interval", "rule_id")

# The crypto factory asks for a slippage and carries no default of its own, so
# the lab's own default is the one the stock factory also uses.
DEFAULT_SLIPPAGE = D("0.0005")


class Refusal(Exception):
    """The command declined to run, carrying the sentence that says why."""


# ---------------------------------------------------------------- text helpers


def _sentence(text) -> str:
    """*text* as one plain line."""
    words = " ".join(str(text).split())
    return words or "the command could not be completed"


def _refuse(text) -> int:
    """Say why on stderr and report the exit code of a refusal."""
    print(f"refused: {_sentence(text)}", file=sys.stderr)
    return 2


def _moment_text(moment) -> str:
    """A datetime (or date) as ISO text, or "none"."""
    return "none" if moment is None else moment.isoformat()


def _midnight(day: date) -> datetime:
    """That calendar date at 00:00 UTC."""
    return datetime(day.year, day.month, day.day, tzinfo=UTC)


# ---------------------------------------------------------------- flag types


def _decimal_arg(text) -> D:
    """A Decimal from a command-line flag; a bad value is an argparse error."""
    try:
        value = D(str(text).strip())
    except (InvalidOperation, ValueError) as exc:
        raise argparse.ArgumentTypeError(
            f"not a decimal number: {text!r}"
        ) from exc
    if not value.is_finite():
        raise argparse.ArgumentTypeError(f"not a finite number: {text!r}")
    return value


def _iso_moment(text) -> datetime:
    """An ISO date or datetime, read as UTC when it carries no offset."""
    try:
        moment = datetime.fromisoformat(str(text).strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"not an ISO date or datetime: {text!r}"
        ) from exc
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _iso_date(text) -> date:
    """A YYYY-MM-DD calendar date."""
    try:
        return date.fromisoformat(str(text).strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"not a YYYY-MM-DD date: {text!r}"
        ) from exc


def _symbol_list(text) -> list:
    """A comma-separated ticker list, upper-cased, with no empty entry."""
    names: list = []
    for chunk in str(text).split(","):
        name = chunk.strip().upper()
        if not name:
            raise argparse.ArgumentTypeError(
                f"an entry in the ticker list is empty: {text!r}"
            )
        names.append(name)
    return names


# ---------------------------------------------------------------- database guard


def _identifier_words(statement: str) -> set:
    """The identifier-shaped words of a CREATE statement, lower-cased.

    A statement spells out each column's type as well as its name ("asset TEXT
    NOT NULL"), so the run key is read as the three column names rather than as
    one run of text.
    """
    words: set = set()
    current: list = []
    for char in statement:
        if char.isalnum() or char == "_":
            current.append(char)
        elif current:
            words.add("".join(current).lower())
            current = []
    if current:
        words.add("".join(current).lower())
    return words


def _runs_statement(file: Path):
    """The runs table's CREATE statement, or None when the file has no runs table."""
    uri = file.resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    try:
        row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='runs'"
        ).fetchone()
    finally:
        db.close()
    if row is None or row[0] is None:
        return None
    return str(row[0])


def check_db_schema(path) -> None:
    """Refuse a lab database whose run key predates the asset and the interval.

    The file is read read-only, so a refusal leaves it exactly as it was found: a
    database made before a run was keyed on (asset, interval, rule) cannot hold
    the trials this lab counts, and the fix is a fresh file.  A path that does
    not exist yet, an empty file and a file without a runs table all pass, since
    there is no older row to misread.
    """
    file = Path(str(path))
    try:
        if not file.exists() or file.stat().st_size == 0:
            return
    except OSError:
        return
    statement = _runs_statement(file)
    if statement is None:
        return
    words = _identifier_words(statement)
    if all(name in words for name in RUN_KEY_COLUMNS):
        return
    raise Refusal(
        f"{path} was created by an older version of the lab (its run key is "
        f"missing asset and interval); delete it or give a new --db path"
    )


# ---------------------------------------------------------------- reporting


def _print_left_out(report) -> None:
    """One line per row a back-fill could not take."""
    for locator, reason in report.bad_rows:
        print(f"  {locator}: {reason}")


def _print_rows(label: str, report) -> None:
    """What one CSV import wrote, and how many rows it left out."""
    print(f"wrote {report.rows_written} bars for {label}")
    print(f"rows left out: {len(report.bad_rows)}")
    _print_left_out(report)


# ---------------------------------------------------------------- read helpers


def _read_text(path) -> str:
    """The whole text of a file, refused with a plain sentence."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal(f"could not read {path}") from exc


def _write_text(path, text: str) -> None:
    """Write *text* to a file, refused with a plain sentence."""
    try:
        Path(path).write_text(text, encoding="utf-8")
    except OSError as exc:
        raise Refusal(f"could not write {path}") from exc


def _stored_bars(store, symbol: str) -> list:
    """Every daily bar of one symbol the store holds."""
    rows = store.bars(symbol, "1d", LAB_FLOOR, LAB_CEILING)
    if not rows:
        raise Refusal(f"no bars stored for {symbol}: run import-stock first")
    return rows


# ---------------------------------------------------------------- costs


def _crypto_costs(args) -> CostModel:
    """The crypto cost model of a run, from the flags it carries."""
    extras = {}
    if args.taker is not None:
        extras["taker"] = args.taker
    if args.maker is not None:
        extras["maker"] = args.maker
    slippage = DEFAULT_SLIPPAGE if args.slippage is None else args.slippage
    return CostModel.for_crypto(
        args.asset,
        st_tax_rate=args.st_tax_rate,
        lt_tax_rate=args.lt_tax_rate,
        slippage=slippage,
        **extras,
    )


def _stock_costs(args, asset: str) -> CostModel:
    """The stock cost model of an asset; the taker and maker flags are refused."""
    if getattr(args, "taker", None) is not None or getattr(args, "maker", None) is not None:
        raise Refusal("taker and maker apply to crypto only")
    extras = {}
    if args.slippage is not None:
        extras["slippage"] = args.slippage
    return CostModel.for_stock(
        asset,
        st_tax_rate=args.st_tax_rate,
        lt_tax_rate=args.lt_tax_rate,
        **extras,
    )


def _run_costs(args) -> CostModel:
    """The cost model of a `run`: crypto for a pair symbol, stock otherwise."""
    if "-" in args.asset:
        return _crypto_costs(args)
    return _stock_costs(args, args.asset)


# ---------------------------------------------------------------- backfill


def _candle_client(candle_client):
    """The injected candle client, or the real one when none was injected."""
    return PublicCandles() if candle_client is None else candle_client


def _handle_backfill_crypto(args, moment, candle_client, tiingo_fetch) -> int:
    client = _candle_client(candle_client)
    start = args.start
    if start is None:
        start = first_available(client, args.product, args.interval, moment)
        if start is None:
            raise Refusal(f"no candles found for {args.product}")
    end = moment if args.end is None else args.end
    store = LabStore(args.db)
    try:
        report = backfill_crypto(
            store,
            client,
            args.product,
            args.interval,
            start,
            end,
            now=moment,
        )
    finally:
        store.close()
    print(f"wrote {report.rows_written} bars for {args.product}")
    print(f"pages: {report.pages}")
    print(f"span: {_moment_text(report.first_ts)} to {_moment_text(report.last_ts)}")
    print(f"rows left out: {len(report.bad_rows)}")
    _print_left_out(report)
    return 0


def _handle_first_available(args, moment, candle_client, tiingo_fetch) -> int:
    client = _candle_client(candle_client)
    found = first_available(client, args.product, args.interval, moment)
    print("none found" if found is None else found.isoformat())
    return 0


def _handle_gaps(args, moment, candle_client, tiingo_fetch) -> int:
    holidays = NYSE_HOLIDAYS if args.calendar == "nyse" else frozenset()
    store = LabStore(args.db)
    try:
        found = gap_report(
            store, args.symbol, args.interval, args.calendar, holidays
        )
    finally:
        store.close()
    if not found:
        print("no gaps")
        return 0
    for first, last in found:
        print(f"{first.isoformat()} to {last.isoformat()}")
    return 0


# ---------------------------------------------------------------- stock history


def _tiingo_token(args) -> str:
    """The Tiingo token from its file or from the named environment variable."""
    env_name = args.tiingo_token_env or DEFAULT_TOKEN_ENV
    if args.tiingo_token_file is not None:
        token = _read_text(args.tiingo_token_file).strip()
        if token:
            return token
        raise Refusal(
            f"the token file {args.tiingo_token_file} is empty; give the token "
            f"with --tiingo-token-file PATH or in the environment variable "
            f"{env_name}"
        )
    token = os.environ.get(env_name, "").strip()
    if token:
        return token
    raise Refusal(
        f"no Tiingo token: give it with --tiingo-token-file PATH or in the "
        f"environment variable {env_name}"
    )


def _tiingo_text(args, tiingo_fetch) -> str:
    """The CSV text of one symbol, read through the injected fetcher.

    Without --start-date the whole history is asked for, from the first day the
    daily feed holds.
    """
    token = _tiingo_token(args)
    fetcher = fetch_tiingo_csv if tiingo_fetch is None else tiingo_fetch
    start = DEFAULT_TIINGO_START if args.start_date is None else args.start_date
    return fetcher(args.symbol, token, start)


def _stock_text(args, tiingo_fetch) -> tuple:
    """The CSV text of an import and the source label stored with it."""
    given = (
        (1 if args.csv_file is not None else 0)
        + (1 if args.csv_text is not None else 0)
        + (1 if args.tiingo else 0)
    )
    if given != 1:
        raise Refusal("give exactly one of --csv-file, --csv-text, --tiingo")
    if args.tiingo:
        return _tiingo_text(args, tiingo_fetch), "tiingo"
    if args.csv_file is not None:
        return _read_text(args.csv_file), "csv-file"
    return args.csv_text, "csv-text"


def _handle_import_stock(args, moment, candle_client, tiingo_fetch) -> int:
    text, source = _stock_text(args, tiingo_fetch)
    store = LabStore(args.db)
    try:
        report = import_stock_csv(store, args.symbol, text, source)
    finally:
        store.close()
    _print_rows(args.symbol, report)
    return 0


# ---------------------------------------------------------------- events


def _csv_date(text, name: str) -> date:
    """A YYYY-MM-DD field of an earnings row."""
    cleaned = str(text).strip()
    if not cleaned:
        raise ValueError(f"{name} is blank")
    try:
        return date.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError(f"{name} is not YYYY-MM-DD: {text!r}") from exc


def _earnings_event(cells, source):
    """One earnings row as (release, announced_at, session, note, assumed).

    A blank announcement date stands for an announcement that could not be
    found: the event is stamped `ASSUMED_ANNOUNCEMENT_DAYS` before its release
    and the note says so.  A row whose dates or session do not read raises
    ValueError, so the caller can report the line and keep the rest.
    """
    release = _csv_date(cells[0], "the release date")
    announced_raw = cells[1]
    assumed = not announced_raw
    if assumed:
        announced = release - timedelta(days=ASSUMED_ANNOUNCEMENT_DAYS)
    else:
        announced = _csv_date(announced_raw, "the announced date")
        if announced > release:
            raise ValueError("the announced date is after the release date")
    session = (cells[2] or DEFAULT_SESSION).lower()
    if session not in EARNINGS_SESSIONS:
        raise ValueError("the session is not pre or post")
    note = ASSUMED_NOTE if assumed else ""
    if source:
        note = f"{note}; source: {source}" if note else f"source: {source}"
    return _midnight(release), _midnight(announced), session, note, assumed


def _earnings_rows(path) -> list:
    """The data rows of the earnings CSV, each with its file line number.

    The header is line 1, so the first data row is line 2; the columns are read
    by name, and a row shorter than the header is padded with blanks.
    """
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            records = [
                (reader.line_num, [cell.strip() for cell in row]) for row in reader
            ]
    except OSError as exc:
        raise Refusal(f"could not read {path}") from exc
    except csv.Error as exc:
        raise Refusal(f"could not read {path} as CSV: {exc}") from exc
    if not records:
        raise Refusal(f"the earnings file {path} is empty")
    header = [cell.lower() for cell in records[0][1]]
    if any(name not in header for name in EARNINGS_HEADER):
        raise Refusal(
            "the earnings CSV needs a " + ", ".join(EARNINGS_HEADER) + " header"
        )
    positions = [header.index(name) for name in EARNINGS_HEADER]
    rows: list = []
    for line_no, cells in records[1:]:
        if not any(cells):
            continue
        picked = [
            cells[position] if position < len(cells) else ""
            for position in positions
        ]
        rows.append((line_no, picked))
    return rows


def _handle_import_earnings(args, moment, candle_client, tiingo_fetch) -> int:
    rows = _earnings_rows(args.csv_file)
    loaded = 0
    assumed = 0
    skipped: list = []
    store = LabStore(args.db)
    try:
        for line_no, cells in rows:
            try:
                at, announced_at, session, note, was_assumed = _earnings_event(
                    cells, args.source
                )
            except ValueError as exc:
                skipped.append((line_no, str(exc)))
                continue
            store.add_event(
                args.symbol,
                "earnings",
                at=at,
                announced_at=announced_at,
                session=session,
                note=note,
            )
            loaded += 1
            if was_assumed:
                assumed += 1
    finally:
        store.close()
    print(f"loaded {loaded} earnings rows for {args.symbol}")
    print(f"{assumed} announcement dates assumed (release minus 14 days)")
    for line_no, reason in skipped:
        print(f"skipped line {line_no}: {reason}")
    return 0


# ---------------------------------------------------------------- register


def _chosen_rules(names) -> list:
    """The rule modules named on the command line, `all` taken as every one."""
    chosen: list = []
    for name in names:
        if name == ALL_RULES:
            chosen.extend(RULE_MODULES[rule_id] for rule_id in RULE_MODULES)
        else:
            chosen.append(RULE_MODULES[name])
    return chosen


def _handle_register(args, moment, candle_client, tiingo_fetch) -> int:
    modules = _chosen_rules(args.rule)
    # Every chosen module is read before the first write, so `--rule all` with
    # one module that is not a rule refuses without having registered the ones
    # before it.
    for module in modules:
        check_rule_module(module)
    store = LabStore(args.db)
    try:
        # A new version supersedes the one on file, so a whole `--new-version`
        # run is settled first: a rule this project has not registered refuses
        # the run by name and leaves every other rule as it was.
        versions: dict = {}
        if args.new_version:
            for module in modules:
                before = store.get_rule(args.project_id, module.RULE_ID)
                if before is None:
                    return _refuse(
                        f"rule {module.RULE_ID!r} is not registered in project "
                        f"{args.project_id!r}: there is nothing to supersede"
                    )
                versions[module.RULE_ID] = before["version"]
        for module in modules:
            version = store.register_rule(
                args.project_id,
                module.RULE_ID,
                module.HYPOTHESIS,
                module.GRID,
                new_version=args.new_version,
            )
            if args.new_version and version == versions[module.RULE_ID]:
                # The store kept the version on file because the grid is the one
                # already registered, so there is no new version to announce and
                # no older grid for the trials to have been run against.
                print(
                    f"rule {module.RULE_ID} is unchanged in project "
                    f"{args.project_id} (version {version}); no new version "
                    "registered"
                )
            elif version > 1:
                line = (
                    f"registered rule {module.RULE_ID} version {version} in "
                    f"project {args.project_id}"
                )
                if args.new_version:
                    line += "; old-grid trials still count toward N"
                print(line)
            else:
                print(
                    f"registered rule {module.RULE_ID} in project "
                    f"{args.project_id}"
                )
    finally:
        store.close()
    return 0


# ---------------------------------------------------------------- run


def _weekly_funding(module):
    """The weekly amount that funds a rule's schedule, or None when it has none."""
    funding = getattr(module, "FUNDING", None)
    if funding is None:
        return None
    raw = funding.get("amount") if isinstance(funding, dict) else None
    if raw is None:
        raise ValueError(
            f"rule {module.RULE_ID} carries a FUNDING without a weekly amount: "
            f"{funding!r}"
        )
    return D(str(raw))


def _handle_run(args, moment, candle_client, tiingo_fetch) -> int:
    module = RULE_MODULES[args.rule]
    # The walk moves forward by one test window; there is no flag to change it.
    step = args.test_len
    # A rule's answer is read by one simulator, so the flag may name that one
    # and nothing else: naming the other is refused before anything runs.
    sim = module.SIMULATOR
    if args.sim is not None and args.sim != sim:
        return _refuse(
            f"rule {module.RULE_ID} runs on the {sim} simulator, not "
            f"{args.sim}; drop --sim or pass --sim {sim}"
        )
    # A funded rule pays its own way in, so it starts from no cash unless the
    # flag says otherwise, and the flag can never put more than one weekly
    # amount of idle cash beside the schedule.  Any other rule starts from the
    # lab's own cash.
    funding = _weekly_funding(module)
    start_cash = args.start_cash
    if start_cash is None:
        start_cash = DEFAULT_CASH if funding is None else D("0")
    elif funding is not None and start_cash > funding:
        return _refuse(
            f"rule {module.RULE_ID} is funded by {funding} a week, so "
            f"--start-cash may be at most {funding}; the default is 0"
        )
    costs = _run_costs(args)
    store = LabStore(args.db)
    try:
        bars = store.bars(args.asset, args.interval, LAB_FLOOR, LAB_CEILING)
        events = store.events(args.asset, LAB_FLOOR, LAB_CEILING)
        verdict = evaluate_edge_rule(
            store,
            args.project_id,
            module,
            bars,
            events,
            costs,
            train_len=args.train_len,
            test_len=args.test_len,
            step=step,
            sim=sim,
            start_cash=start_cash,
        )
    finally:
        store.close()
    print(f"status: {verdict.status}")
    for reason in verdict.reasons:
        print(reason)
    print(json.dumps(verdict.numbers, indent=2, sort_keys=True))
    return 0


# ---------------------------------------------------------------- study


def _study_bars(store, symbols, controls) -> dict:
    """The daily bars of every symbol and control, in the order given."""
    bars: dict = {}
    for symbol in list(symbols) + list(controls):
        if symbol in bars:
            continue
        bars[symbol] = _stored_bars(store, symbol)
    return bars


def _study_events(store, symbols, controls) -> dict:
    """The events of every symbol that is not a control."""
    events: dict = {}
    for symbol in symbols:
        if symbol in controls:
            continue
        events[symbol] = store.events(symbol, LAB_FLOOR, LAB_CEILING)
    return events


def _handle_study_buys(args, moment, candle_client, tiingo_fetch) -> int:
    controls = list(args.controls)
    store = LabStore(args.db)
    try:
        bars_by_symbol = _study_bars(store, args.symbols, controls)
        events_by_symbol = _study_events(store, args.symbols, controls)
        costs = _stock_costs(args, args.symbols[0])
        result = run_study(
            bars_by_symbol,
            events_by_symbol,
            args.cash,
            args.horizon_days,
            costs,
            args.block_len,
            controls=tuple(controls),
            veto_days=args.veto_days,
            stride=args.stride,
            n_boot=args.n_boot,
        )
        markdown = result.to_markdown()
        store.record_study(
            args.project_id,
            STUDY_NAME,
            {"params": result.params, "markdown": markdown},
        )
    finally:
        store.close()
    if args.out is not None:
        _write_text(args.out, markdown)
    sys.stdout.write(markdown if markdown.endswith("\n") else markdown + "\n")
    return 0


# ---------------------------------------------------------------- parser


def _add_db(sub) -> None:
    sub.add_argument("--db", required=True, help="the lab database file")


def _add_project(sub) -> None:
    sub.add_argument("--project-id", required=True, help="the project the work belongs to")


def _add_tax_rates(sub) -> None:
    sub.add_argument(
        "--st-tax-rate",
        type=_decimal_arg,
        required=True,
        help="the short-term tax rate the run settles at",
    )
    sub.add_argument(
        "--lt-tax-rate",
        type=_decimal_arg,
        required=True,
        help="the long-term tax rate the run settles at",
    )


def _add_crypto_history(sub) -> None:
    _add_db(sub)
    sub.add_argument("--product", required=True, help="the pair, e.g. XRP-USDC")
    sub.add_argument("--interval", required=True, choices=INTERVALS)


def build_parser() -> argparse.ArgumentParser:
    """The command line: one subparser per step of the loop."""
    parser = argparse.ArgumentParser(
        prog="python -m crow_coinbase.lab",
        description="the offline research lab: market data, rules and studies",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    backfill = subparsers.add_parser(
        "backfill-crypto", help="store public candles for a crypto pair"
    )
    _add_crypto_history(backfill)
    backfill.add_argument("--start", type=_iso_moment, default=None)
    backfill.add_argument("--end", type=_iso_moment, default=None)
    backfill.set_defaults(handler=_handle_backfill_crypto)

    first = subparsers.add_parser(
        "first-available", help="the earliest candle the product answers with"
    )
    _add_crypto_history(first)
    first.set_defaults(handler=_handle_first_available)

    stock = subparsers.add_parser(
        "import-stock", help="store daily bars from a CSV or from Tiingo"
    )
    _add_db(stock)
    stock.add_argument("--symbol", required=True)
    stock.add_argument("--csv-file", default=None, help="a CSV file of daily rows")
    stock.add_argument("--csv-text", default=None, help="the CSV text itself")
    stock.add_argument(
        "--tiingo", action="store_true", help="read the rows from the Tiingo feed"
    )
    stock.add_argument(
        "--start-date",
        type=_iso_date,
        default=None,
        help=(
            "the first day to read; without it the history from 1980-01-01, "
            "the feed's first day"
        ),
    )
    stock.add_argument(
        "--tiingo-token-file",
        default=None,
        help="a file holding the Tiingo token",
    )
    stock.add_argument(
        "--tiingo-token-env",
        default=DEFAULT_TOKEN_ENV,
        help="the environment variable to read the Tiingo token from",
    )
    stock.set_defaults(handler=_handle_import_stock)

    earnings = subparsers.add_parser(
        "import-earnings", help="store earnings releases as lab events"
    )
    _add_db(earnings)
    _add_project(earnings)
    earnings.add_argument("--symbol", required=True)
    earnings.add_argument("--csv-file", required=True)
    earnings.add_argument("--source", default=None)
    earnings.set_defaults(handler=_handle_import_earnings)

    gaps = subparsers.add_parser(
        "gaps", help="the stretches of the calendar with no stored bar"
    )
    _add_db(gaps)
    gaps.add_argument("--symbol", required=True)
    gaps.add_argument("--interval", required=True, choices=INTERVALS)
    gaps.add_argument("--calendar", required=True, choices=CALENDARS)
    gaps.set_defaults(handler=_handle_gaps)

    register = subparsers.add_parser(
        "register",
        help=(
            "register a rule and its grid under the project, or a new version "
            "of its design"
        ),
    )
    _add_db(register)
    _add_project(register)
    register.add_argument(
        "--rule", action="append", required=True, choices=RULE_CHOICES
    )
    register.add_argument(
        "--new-version",
        action="store_true",
        help=(
            "store a changed grid as the next version of the rule's design; "
            "the trials already run against the old grid keep counting"
        ),
    )
    register.set_defaults(handler=_handle_register)

    run = subparsers.add_parser("run", help="walk one rule forward and weigh it")
    _add_db(run)
    _add_project(run)
    run.add_argument("--rule", required=True, choices=tuple(sorted(RULE_MODULES)))
    run.add_argument("--asset", required=True)
    run.add_argument("--interval", required=True, choices=INTERVALS)
    run.add_argument("--train-len", type=int, required=True)
    run.add_argument("--test-len", type=int, required=True)
    run.add_argument(
        "--sim",
        choices=SIMULATORS,
        default=None,
        help=(
            "the simulator to walk forward; without it the rule's own "
            "simulator, and refused when it names another one"
        ),
    )
    run.add_argument(
        "--start-cash",
        type=_decimal_arg,
        default=None,
        help=(
            "the cash the run starts with; without it a funded rule starts "
            f"from 0 and every other rule from {DEFAULT_CASH}"
        ),
    )
    run.add_argument("--taker", type=_decimal_arg, default=None)
    run.add_argument("--maker", type=_decimal_arg, default=None)
    run.add_argument("--slippage", type=_decimal_arg, default=None)
    _add_tax_rates(run)
    run.set_defaults(handler=_handle_run)

    study = subparsers.add_parser(
        "study-buys", help="compare entry timings over one horizon"
    )
    _add_db(study)
    _add_project(study)
    study.add_argument("--symbols", type=_symbol_list, required=True)
    study.add_argument(
        "--controls", type=_symbol_list, default=list(DEFAULT_CONTROLS)
    )
    study.add_argument("--cash", type=_decimal_arg, default=DEFAULT_CASH)
    study.add_argument("--horizon-days", type=int, default=DEFAULT_HORIZON_DAYS)
    study.add_argument("--block-len", type=int, default=DEFAULT_BLOCK_LEN)
    study.add_argument("--veto-days", type=int, default=DEFAULT_VETO_DAYS)
    study.add_argument("--stride", type=int, default=DEFAULT_STRIDE)
    study.add_argument("--n-boot", type=int, default=DEFAULT_N_BOOT)
    study.add_argument("--out", default=None, help="a file to write the report to")
    study.add_argument("--slippage", type=_decimal_arg, default=None)
    _add_tax_rates(study)
    study.set_defaults(handler=_handle_study_buys)

    return parser


# ---------------------------------------------------------------- entry point


def _moment_now(now) -> datetime:
    """The clock the command answers with, as timezone-aware UTC."""
    if now is None:
        return datetime.now(UTC)
    if not isinstance(now, datetime):
        raise Refusal(f"now must be a datetime: {now!r}")
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise Refusal(f"now must be timezone-aware: {now!r}")
    return now.astimezone(UTC)


def main(argv=None, *, candle_client=None, tiingo_fetch=None, now=None) -> int:
    """Run one subcommand, print what it did and report 0, or refuse with 2."""
    args = build_parser().parse_args(argv)
    try:
        moment = _moment_now(now)
        check_db_schema(args.db)
    except Refusal as exc:
        return _refuse(exc)
    except sqlite3.Error as exc:
        return _refuse(exc)
    try:
        return args.handler(args, moment, candle_client, tiingo_fetch)
    except Refusal as exc:
        return _refuse(exc)
    except (ValueError, LabStoreError, FeedError, sqlite3.Error, OSError) as exc:
        return _refuse(exc)


if __name__ == "__main__":
    sys.exit(main())