"""migrations.py: the v1 -> v2 schema step, its backup, and event retention.

Every test works on a real SQLite file in `tmp_path`.  `FIXTURE` is the P1
database one base-commit Store wrote; it is copied into `tmp_path` before
anything opens it, so the file in `fixtures/` is only ever read as bytes.
`Store` is the only writer, and the one test that needs a broken migration
monkeypatches the step table rather than the store.

`crow_coinbase.migrations` is imported inside the tests that name it, so a
missing module fails those tests alone instead of the whole file.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from decimal import Decimal as D
from pathlib import Path

import pytest

from crow_coinbase.store import CANCELLED, FILLED, OPEN, Store

FIXTURE = Path(__file__).parent / "fixtures" / "engine-v1.sqlite"

# The v1 rows the fixture holds.
OLD_BOTS = {"g1", "r1"}
OLD_ORDERS = {
    "cb-g1-B-1-000000000001": (OPEN, "60000"),
    "cb-g1-S-2-000000000002": (FILLED, "61000"),
    "cb-ai-B-1-000000000003": (CANCELLED, "3000"),
}
OLD_EVENTS = [
    ("info", "engine started"),
    ("warn", "stale data"),
    ("info", "bot g1 placed 2 orders"),
]
DAY_S = 86400.0


def copy_fixture(tmp_path, name="engine.sqlite"):
    """The v1 fixture as a writable file of the test's own."""
    dest = tmp_path / name
    shutil.copyfile(FIXTURE, dest)
    return dest


def columns(conn, table):
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def added(conn, table):
    """True when *table* exists."""
    row = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row[0] == 1


def add_event(store, message, ts=None):
    """Write one event through the store and stamp its ts; return its id."""
    store.event("info", message)
    event_id = store.conn().execute("SELECT MAX(id) FROM events").fetchone()[0]
    if ts is not None:
        store.conn().execute("UPDATE events SET ts=? WHERE id=?", (ts, event_id))
    return event_id


def event_ids(store):
    return {row[0] for row in store.conn().execute("SELECT id FROM events")}


# ---------------------------------------------------------------- v1 -> v2


def test_v1_db_migrates_to_v2_with_backup(tmp_path):
    path = copy_fixture(tmp_path)
    store = Store(path)
    try:
        assert store.schema_version() == 2
        assert [row[0] for row in store.conn().execute(
            "SELECT version FROM schema_version"
        )] == [2]

        backup = tmp_path / "engine.pre-v2.sqlite"
        assert backup.exists()
        raw = sqlite3.connect(backup)
        try:
            assert raw.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()[0] == 1
            assert raw.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 3
            assert columns(raw, "events") == ["ts", "level", "message"]
        finally:
            raw.close()

        db = store.conn()
        bots = {row["id"]: dict(row) for row in db.execute("SELECT * FROM bots")}
        assert set(bots) == OLD_BOTS
        assert {bot["mode"] for bot in bots.values()} == {"dry"}
        assert bots["g1"]["product"] == "BTC-USDC"
        assert bots["g1"]["strategy"] == "grid"
        assert D(bots["g1"]["capital_quote"]) == D("50")
        assert bots["r1"]["product"] == "ETH-USDC"
        assert bots["r1"]["strategy"] == "rebalance"
        assert D(bots["r1"]["capital_base"]) == D("0.01")

        orders = {
            row["client_order_id"]: dict(row)
            for row in db.execute("SELECT * FROM orders")
        }
        assert set(orders) == set(OLD_ORDERS)
        assert {order["book"] for order in orders.values()} == {"dry"}
        assert {order["product_type"] for order in orders.values()} == {"SPOT"}
        for cid, (status, price) in OLD_ORDERS.items():
            assert orders[cid]["status"] == status, cid
            assert D(orders[cid]["price"]) == D(price), cid
        assert orders["cb-g1-S-2-000000000002"]["order_id"] == "ex-2"
        assert orders["cb-g1-S-2-000000000002"]["owner"] == "g1"
        assert orders["cb-ai-B-1-000000000003"]["owner"] == "ai"

        fill = db.execute("SELECT * FROM fills WHERE trade_id='t-1'").fetchone()
        assert fill is not None
        assert fill["book"] == "dry"
        assert fill["client_order_id"] == "cb-g1-S-2-000000000002"
        assert fill["owner"] == "g1"
        assert D(fill["size"]) == D("0.0005")
        assert D(fill["price"]) == D("61000")
        assert D(fill["commission"]) == D("0.15")

        assert store.get("halted") is False
        assert store.get("poll_seconds") == 60

        assert store.hwm("g1") == D("50.5")
        assert store.hwm("ai") == D("25")
        assert store.hwm("portfolio") == D("120")

        events = db.execute(
            "SELECT id, ts, level, message, kind, owner, data_json FROM events "
            "ORDER BY id"
        ).fetchall()
        assert [row["id"] for row in events] == [1, 2, 3]
        assert [(row["level"], row["message"]) for row in events] == OLD_EVENTS
        assert [row["kind"] for row in events] == ["info", "info", "info"]
        assert [row["owner"] for row in events] == [None, None, None]
        assert [row["data_json"] for row in events] == ["{}", "{}", "{}"]
        assert all(row["ts"] is not None for row in events)

        for table, wanted in (
            (
                "ai_previews",
                {
                    "id",
                    "created_at",
                    "expires_at",
                    "state",
                    "product",
                    "side",
                    "size",
                    "limit_price",
                    "book",
                    "hash",
                    "payload_json",
                    "refusal",
                    "approved_at",
                    "cid",
                },
            ),
            ("nonces", {"nonce", "seen_at", "ts"}),
        ):
            assert added(db, table), table
            assert wanted <= set(columns(db, table)), table
            assert count(db, table) == 0, table

        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE bots SET mode='weird' WHERE id='g1'")
        assert db.execute("SELECT mode FROM bots WHERE id='g1'").fetchone()[0] == "dry"
    finally:
        store.close()


def test_migration_idempotent(tmp_path):
    from crow_coinbase.migrations import migrate

    path = copy_fixture(tmp_path)
    backup = tmp_path / "engine.pre-v2.sqlite"

    store = Store(path)
    try:
        assert store.schema_version() == 2
        assert backup.exists()
        before = backup.read_bytes()
        counts = {
            table: count(store.conn(), table)
            for table in ("bots", "orders", "fills", "events", "hwm", "kv")
        }

        assert migrate(store.conn(), store.path) == 2
        assert store.schema_version() == 2
        assert {
            table: count(store.conn(), table)
            for table in ("bots", "orders", "fills", "events", "hwm", "kv")
        } == counts
        assert backup.read_bytes() == before
        assert sorted(
            entry.name for entry in tmp_path.glob("engine.pre-v*.sqlite")
        ) == ["engine.pre-v2.sqlite"]
    finally:
        store.close()

    again = Store(path)
    try:
        assert again.schema_version() == 2
        assert backup.read_bytes() == before
    finally:
        again.close()

    # The copy kept is the oldest one: it is still the v1 database.
    raw = sqlite3.connect(backup)
    try:
        assert raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1
    finally:
        raw.close()

    fresh_dir = tmp_path / "fresh"
    fresh_dir.mkdir()
    fresh = Store(fresh_dir / "new.sqlite")
    try:
        assert fresh.schema_version() == 2
    finally:
        fresh.close()
    assert list(fresh_dir.glob("engine.pre-v*.sqlite")) == []


def test_failed_step_rolls_back_and_keeps_v1(tmp_path, monkeypatch):
    from crow_coinbase import migrations

    path = copy_fixture(tmp_path)
    backup = tmp_path / "engine.pre-v2.sqlite"

    def exploding_step(conn):
        migrations._to_v2(conn)
        raise RuntimeError("the v2 step died after its DDL")

    with monkeypatch.context() as patch:
        patch.setattr(migrations, "_STEPS", {2: exploding_step})
        with pytest.raises(migrations.MigrationError) as err:
            Store(path)
    assert str(err.value) == "migration to v2 failed"

    assert backup.exists()

    raw = sqlite3.connect(path)
    try:
        assert raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1
        assert columns(raw, "events") == ["ts", "level", "message"]
        assert columns(raw, "hwm") == ["owner", "value"]
        assert "mode" not in columns(raw, "bots")
        assert "book" not in columns(raw, "orders")
        assert "book" not in columns(raw, "fills")
        assert not added(raw, "ai_previews")
        assert not added(raw, "nonces")
        assert count(raw, "orders") == 3
        assert count(raw, "events") == 3
        assert raw.execute("SELECT COUNT(*) FROM hwm").fetchone()[0] == 3
    finally:
        raw.close()

    store = Store(path)
    try:
        assert store.schema_version() == 2
        assert columns(store.conn(), "hwm") == ["book", "owner", "value"]
        assert columns(store.conn(), "events") == [
            "id",
            "ts",
            "level",
            "kind",
            "owner",
            "message",
            "data_json",
        ]
        assert store.hwm("g1") == D("50.5")
        assert [row["id"] for row in store.conn().execute(
            "SELECT id FROM events ORDER BY id"
        )] == [1, 2, 3]
    finally:
        store.close()

    # The failed attempt's copy is the one kept, and it is the v1 database.
    raw = sqlite3.connect(backup)
    try:
        assert raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1
    finally:
        raw.close()


# ---------------------------------------------------------------- events


def test_event_ids_never_reused_after_retention(tmp_path):
    now = time.time()
    old = now - 100 * DAY_S
    store = Store(tmp_path / "s.db")
    try:
        first = add_event(store, "old-1", old)
        second = add_event(store, "old-2", old)
        newest = add_event(store, "new-1", now)

        assert store.prune_events(now) == 2
        assert event_ids(store) == {newest}
        assert newest > second > first

        # Every event old: the single newest one is kept, whatever its age.
        store.conn().execute("UPDATE events SET ts=?", (old,))
        keep = add_event(store, "old-3", old)
        kept = add_event(store, "old-4", old)
        assert store.prune_events(now) == 2
        assert event_ids(store) == {kept}
        assert kept > keep

        # An id already used is never handed out again, even after its row goes.
        store.conn().execute("DELETE FROM events WHERE id=?", (kept,))
        after_delete = add_event(store, "after-delete", now)
        assert after_delete > kept

        assert store.get("events_pruned_at") is None

        daily_old = add_event(store, "daily-old", old)
        daily_new = add_event(store, "daily-new", now)
        assert store.prune_events_daily(now=now) == 1
        assert store.get("events_pruned_at") == pytest.approx(now)
        remaining = event_ids(store)
        assert daily_old not in remaining
        assert daily_new in remaining

        # Not due inside 24 h: nothing is deleted, and the stamp stays put.
        stale = add_event(store, "daily-old-2", old)
        assert store.prune_events_daily(now=now + 3600) == 0
        assert stale in event_ids(store)
        assert store.get("events_pruned_at") == pytest.approx(now)

        later = now + DAY_S + 1
        newest_row = add_event(store, "daily-new-2", now + 7200)
        assert store.prune_events_daily(now=later) == 1
        remaining = event_ids(store)
        assert stale not in remaining
        assert newest_row in remaining
        assert store.get("events_pruned_at") == pytest.approx(later)
    finally:
        store.close()


def test_old_event_callers_work(tmp_path):
    from crow_coinbase import api as api_module

    path = copy_fixture(tmp_path)
    store = Store(path)
    try:
        store.event("info", "msg")
        store.event("warn", "msg")
        store.event("info", "m", kind="refusal", owner="g1", data={"x": 1})

        rows = store.conn().execute(
            "SELECT level, message, kind, owner, data_json FROM events ORDER BY id"
        ).fetchall()
        assert [
            (row["level"], row["message"], row["kind"], row["owner"], row["data_json"])
            for row in rows[len(OLD_EVENTS):]
        ] == [
            ("info", "msg", "info", None, "{}"),
            ("warn", "msg", "info", None, "{}"),
            ("info", "m", "refusal", "g1", json.dumps({"x": 1})),
        ]

        store.event(api_module.ALERT_LEVEL, "a drawdown alert")
        alerts = api_module._alert_rows(store)
        assert [alert["message"] for alert in alerts] == ["a drawdown alert"]
        assert isinstance(alerts[0]["ts"], float)
    finally:
        store.close()


# ---------------------------------------------------------------- hwm


def test_hwm_rebuilt_with_book(tmp_path):
    path = copy_fixture(tmp_path)
    store = Store(path)
    try:
        info = list(store.conn().execute("PRAGMA table_info(hwm)"))
        assert [row[1] for row in info] == ["book", "owner", "value"]
        assert [(row[1], row[5]) for row in info if row[5]] == [
            ("book", 1),
            ("owner", 2),
        ]

        # The v1 rows came across on the dry book.
        assert store.hwm("g1") == D("50.5")
        assert store.hwm("g1", book="dry") == D("50.5")
        assert store.hwm("ai") == D("25")
        assert store.hwm("portfolio") == D("120")

        assert store.update_hwm("g1", D("60")) == D("60")
        assert store.update_hwm("g1", D("10")) == D("60")
        assert store.hwm("g1") == D("60")

        assert store.hwm("g1", book="live") is None
        assert store.update_hwm("g1", D("5"), book="live") == D("5")
        assert store.hwm("g1", book="live") == D("5")
        assert store.hwm("g1") == D("60")

        rows = [
            tuple(row)
            for row in store.conn().execute(
                "SELECT book, owner, value FROM hwm ORDER BY book, owner"
            )
        ]
        assert rows == [
            ("dry", "ai", "25"),
            ("dry", "g1", "60"),
            ("dry", "portfolio", "120"),
            ("live", "g1", "5"),
        ]
    finally:
        store.close()


# ---------------------------------------------------------------- the cycle


def test_runner_cycle_prunes_events(tmp_path, monkeypatch):
    from test_runner import make_env

    env = make_env(tmp_path / "env")
    store = env.store
    try:
        old_ts = time.time() - 100 * DAY_S
        old = add_event(store, "retention probe old", old_ts)
        new = add_event(store, "retention probe new", time.time())
        assert store.get("events_pruned_at") is None

        first = env.runner.cycle()
        assert first["cycle"] == 1
        remaining = event_ids(store)
        assert old not in remaining
        assert new in remaining
        pruned_at = store.get("events_pruned_at")
        assert isinstance(pruned_at, (int, float)) and not isinstance(pruned_at, bool)

        stale = add_event(store, "retention probe stale", old_ts)
        second = env.runner.cycle()
        assert second["cycle"] == 2
        assert stale in event_ids(store)
        assert store.get("events_pruned_at") == pruned_at

        def exploding(*args, **kwargs):
            raise RuntimeError("the prune died")

        monkeypatch.setattr(store, "prune_events_daily", exploding)
        third = env.runner.cycle()
        assert third["cycle"] == 3
        assert "errors" in third
        assert stale in event_ids(store)
    finally:
        store.close()


# ---------------------------------------------------------------- backups


def assert_v1_backup(path):
    """*path* is a readable copy of the v1 database the fixture holds."""
    assert path.is_file(), path
    raw = sqlite3.connect(path)
    raw.row_factory = sqlite3.Row
    try:
        assert raw.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert raw.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0] == 1
        assert {row[0] for row in raw.execute("SELECT id FROM bots")} == OLD_BOTS
        assert {
            row[0] for row in raw.execute("SELECT client_order_id FROM orders")
        } == set(OLD_ORDERS)
        assert count(raw, "fills") == 1
        assert count(raw, "hwm") == 3
        assert [
            (row["level"], row["message"])
            for row in raw.execute("SELECT level, message FROM events ORDER BY rowid")
        ] == OLD_EVENTS
    finally:
        raw.close()


def is_v1_backup(path):
    """True when *path* opens as a v1 copy of the fixture's rows; never raises."""
    try:
        raw = sqlite3.connect(path)
    except sqlite3.Error:
        return False
    try:
        if raw.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            return False
        row = raw.execute("SELECT MAX(version) FROM schema_version").fetchone()
        if row is None or row[0] != 1:
            return False
        return (
            raw.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == len(OLD_ORDERS)
        )
    except sqlite3.Error:
        return False
    finally:
        raw.close()


def stamped_backups(directory):
    """The timestamped copies beside a database, i.e. anything but the plain name."""
    return sorted(directory.glob("engine.pre-v2.*.sqlite"))


def test_backup_is_valid_v1_copy(tmp_path):
    """The copy a migration leaves behind opens as the v1 file it copied."""
    path = copy_fixture(tmp_path)
    store = Store(path)
    try:
        assert store.schema_version() == 2
    finally:
        store.close()

    backup = tmp_path / "engine.pre-v2.sqlite"
    assert_v1_backup(backup)
    assert [entry for entry in tmp_path.iterdir() if entry.name.endswith(".tmp")] == []

    # A name already taken by something unreadable is no reason to carry on with
    # no copy at all: a readable copy of the same v1 data lands beside it.
    damaged_dir = tmp_path / "damaged"
    damaged_dir.mkdir()
    damaged_path = copy_fixture(damaged_dir)
    damaged = damaged_dir / "engine.pre-v2.sqlite"
    damaged.write_bytes(b"not a database")
    store = Store(damaged_path)
    try:
        assert store.schema_version() == 2
    finally:
        store.close()

    assert damaged.read_bytes() == b"not a database"
    made = [copy for copy in stamped_backups(damaged_dir) if is_v1_backup(copy)]
    assert made, sorted(entry.name for entry in damaged_dir.iterdir())


def test_backup_failure_leaves_no_file_and_no_migration(tmp_path):
    """No backup, no migration: a database is never moved on without one."""
    from crow_coinbase import migrations

    path = copy_fixture(tmp_path)
    # The backup is written beside the database, in a directory that is not
    # there, so writing it cannot work whatever it is called.
    missing = tmp_path / "no-such-dir" / "engine.sqlite"

    raw = sqlite3.connect(path, isolation_level=None)
    try:
        with pytest.raises(migrations.MigrationError) as err:
            migrations.migrate(raw, str(missing))
        assert str(err.value) == "backup before v2 failed"
    finally:
        raw.close()

    assert not missing.exists()
    assert not missing.parent.exists()
    files = [entry for entry in tmp_path.rglob("*") if entry.is_file()]
    assert [entry.name for entry in files if entry.name.startswith("engine.pre-v")] == []
    assert [entry.name for entry in files if entry.name.endswith(".tmp")] == []

    raw = sqlite3.connect(path)
    raw.row_factory = sqlite3.Row
    try:
        assert raw.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0] == 1
        assert columns(raw, "events") == ["ts", "level", "message"]
        assert columns(raw, "hwm") == ["owner", "value"]
        assert "mode" not in columns(raw, "bots")
        assert "book" not in columns(raw, "orders")
        assert "book" not in columns(raw, "fills")
        assert not added(raw, "ai_previews")
        assert not added(raw, "nonces")
        assert {row[0] for row in raw.execute("SELECT id FROM bots")} == OLD_BOTS
        assert {
            row[0] for row in raw.execute("SELECT client_order_id FROM orders")
        } == set(OLD_ORDERS)
        assert count(raw, "events") == 3
        assert [
            (row["level"], row["message"])
            for row in raw.execute("SELECT level, message FROM events ORDER BY rowid")
        ] == OLD_EVENTS
    finally:
        raw.close()


def test_existing_backup_not_trusted_blindly(tmp_path):
    """A file already at the backup's name is only kept when it is a real copy."""
    # (a) Zero bytes is not a backup: the migration still happens, the v1 data is
    # copied to a name of its own, and the empty file is left where it was.
    path = copy_fixture(tmp_path)
    empty = tmp_path / "engine.pre-v2.sqlite"
    empty.write_bytes(b"")

    store = Store(path)
    try:
        assert store.schema_version() == 2
        assert {row[0] for row in store.conn().execute("SELECT book FROM orders")} == {
            "dry"
        }
        assert count(store.conn(), "orders") == 3
    finally:
        store.close()

    assert empty.exists()
    assert empty.read_bytes() == b""
    made = stamped_backups(tmp_path)
    assert len(made) == 1, [entry.name for entry in tmp_path.iterdir()]
    assert_v1_backup(made[0])

    # (b) A real v1 copy already under that name is kept exactly as it is, and a
    # fresh copy of the data being migrated is written beside it.
    kept_dir = tmp_path / "kept"
    kept_dir.mkdir()
    kept_path = copy_fixture(kept_dir)
    kept = kept_dir / "engine.pre-v2.sqlite"
    shutil.copyfile(FIXTURE, kept)
    before = kept.read_bytes()

    store = Store(kept_path)
    try:
        assert store.schema_version() == 2
        assert count(store.conn(), "orders") == 3
    finally:
        store.close()

    assert kept.read_bytes() == before
    assert_v1_backup(kept)
    made = stamped_backups(kept_dir)
    assert len(made) == 1, [entry.name for entry in kept_dir.iterdir()]
    assert_v1_backup(made[0])


# The child that opens the shared v1 file.  It waits for the parent's "go" file,
# so both processes reach the migration together, then reports what it saw.
CONCURRENT_CHILD = """
import json, sys, time
from pathlib import Path
from crow_coinbase.store import Store

path, go = Path(sys.argv[1]), Path(sys.argv[2])
deadline = time.time() + 120
while not go.exists():
    if time.time() > deadline:
        raise SystemExit("barrier timed out")
    time.sleep(0.002)
store = Store(path)
try:
    out = {
        "version": store.schema_version(),
        "orders": sorted(
            row[0] for row in store.conn().execute(
                "SELECT client_order_id FROM orders")
        ),
        "events": store.conn().execute("SELECT COUNT(*) FROM events").fetchone()[0],
    }
finally:
    store.close()
print(json.dumps(out))
"""

# How many events the racing copies carry, so both processes are inside the same
# migration for long enough to collide.
BULK_EVENTS = 2000


def test_concurrent_open_one_migrates_other_noops(tmp_path):
    """Two engines opening the same v1 file migrate it once, and both survive."""
    src = Path(__file__).resolve().parent.parent / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(src)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )

    for attempt in range(10):
        run = tmp_path / f"attempt{attempt}"
        run.mkdir()
        path = copy_fixture(run)
        raw = sqlite3.connect(path)
        try:
            raw.executemany(
                "INSERT INTO events(ts, level, message) VALUES(?, ?, ?)",
                [(1.0, "info", f"bulk {index}") for index in range(BULK_EVENTS)],
            )
            raw.commit()
        finally:
            raw.close()

        go = run / "go"
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", CONCURRENT_CHILD, str(path), str(go)],
                cwd=str(run),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        go.write_text("go")

        results = []
        for process in processes:
            out, err = process.communicate(timeout=300)
            assert process.returncode == 0, f"attempt {attempt}: {err}"
            assert "MigrationError" not in err, f"attempt {attempt}: {err}"
            results.append(json.loads(out))

        for result in results:
            assert result["version"] == 2, f"attempt {attempt}: {result}"
            assert result["orders"] == sorted(OLD_ORDERS), f"attempt {attempt}"
            assert result["events"] == len(OLD_EVENTS) + BULK_EVENTS, attempt

        backups = sorted(run.glob("engine.pre-v2*.sqlite"))
        assert backups, f"attempt {attempt}: no copy beside the database"
        assert any(is_v1_backup(backup) for backup in backups), (
            f"attempt {attempt}: {[entry.name for entry in backups]}"
        )


# ---------------------------------------------------------------- checks


# One ai_previews row, with its id, state, cid and book as parameters.
PREVIEW_INSERT = (
    "INSERT INTO ai_previews(id, created_at, expires_at, state, product, side, "
    "size, limit_price, hash, cid, book) "
    "VALUES(?, 1.0, 2.0, ?, 'BTC-USDC', 'BUY', '0.001', '60000', 'h', ?, ?)"
)


def insert_preview(conn, ident, state="pending", cid=None, book="dry"):
    conn.execute(PREVIEW_INSERT, (ident, state, cid, book))


def test_book_and_product_type_checks(tmp_path):
    """A book is 'dry' or 'live' and a product type 'SPOT' or 'EQUITY', or nothing."""
    path = copy_fixture(tmp_path)
    store = Store(path)
    db = store.conn()
    try:
        # The v1 rows came across as dry-book SPOT rows.
        assert {row[0] for row in db.execute("SELECT book FROM orders")} == {"dry"}
        assert {
            row[0] for row in db.execute("SELECT product_type FROM orders")
        } == {"SPOT"}
        assert {row[0] for row in db.execute("SELECT book FROM fills")} == {"dry"}
        assert {row[0] for row in db.execute("SELECT book FROM hwm")} == {"dry"}

        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO orders(client_order_id, owner, book) "
                "VALUES('cb-g1-B-9-000000000009', 'g1', 'paper')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO fills(trade_id, book) VALUES('t-paper', 'paper')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO hwm(book, owner, value) VALUES('paper', 'g1', '9')")
        with pytest.raises(sqlite3.IntegrityError):
            insert_preview(db, "paper-book", book="paper")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO orders(client_order_id, owner, product_type) "
                "VALUES('cb-g1-B-7-000000000007', 'g1', 'spot')"
            )

        assert count(db, "orders") == 3
        assert count(db, "fills") == 1
        assert count(db, "hwm") == 3
        assert count(db, "ai_previews") == 0

        db.execute(
            "INSERT INTO orders(client_order_id, owner, book, product_type) "
            "VALUES('cb-g1-B-8-000000000008', 'g1', 'live', 'EQUITY')"
        )
        row = db.execute(
            "SELECT book, product_type FROM orders "
            "WHERE client_order_id='cb-g1-B-8-000000000008'"
        ).fetchone()
        assert (row["book"], row["product_type"]) == ("live", "EQUITY")

        db.execute("INSERT INTO fills(trade_id, book) VALUES('t-live', 'live')")
        assert db.execute(
            "SELECT book FROM fills WHERE trade_id='t-live'"
        ).fetchone()[0] == "live"

        db.execute("INSERT INTO hwm(book, owner, value) VALUES('live', 'g1', '9')")
        assert store.hwm("g1", book="live") == D("9")

        insert_preview(db, "live-book", book="live")
        assert db.execute(
            "SELECT book FROM ai_previews WHERE id='live-book'"
        ).fetchone()[0] == "live"
    finally:
        store.close()


def test_ai_previews_state_cid_consumed(tmp_path):
    """A preview's state is one of six, its cid is used once, consumed_at exists."""
    store = Store(tmp_path / "s.db")
    db = store.conn()
    try:
        assert "consumed_at" in columns(db, "ai_previews")

        with pytest.raises(sqlite3.IntegrityError):
            insert_preview(db, "bad-state", state="weird")

        insert_preview(db, "with-cid", cid="cid-1")
        with pytest.raises(sqlite3.IntegrityError):
            insert_preview(db, "same-cid", cid="cid-1")

        for index in range(5):
            insert_preview(db, f"no-cid-{index}")

        for state in (
            "pending",
            "approved",
            "placed",
            "expired",
            "rejected",
            "cancelled",
        ):
            insert_preview(db, f"state-{state}", state=state)

        assert count(db, "ai_previews") == 12
        assert {row[0] for row in db.execute("SELECT state FROM ai_previews")} == {
            "pending",
            "approved",
            "placed",
            "expired",
            "rejected",
            "cancelled",
        }
        assert db.execute(
            "SELECT COUNT(*) FROM ai_previews WHERE cid IS NULL"
        ).fetchone()[0] == 11
        assert db.execute(
            "SELECT cid FROM ai_previews WHERE id='with-cid'"
        ).fetchone()[0] == "cid-1"
        assert db.execute(
            "SELECT COUNT(*) FROM ai_previews WHERE consumed_at IS NOT NULL"
        ).fetchone()[0] == 0
    finally:
        store.close()


# ---------------------------------------------------------------- record keeping


def test_prune_daily_negative_elapsed_is_due(tmp_path):
    """A stamp from the future (a clock that moved back) makes the prune due."""
    from crow_coinbase.store import EVENTS_PRUNED_KEY

    now = time.time()
    store = Store(tmp_path / "s.db")
    try:
        old = add_event(store, "daily-old", now - 100 * DAY_S)
        new = add_event(store, "daily-new", now)
        store.put(EVENTS_PRUNED_KEY, now + 30 * DAY_S)

        assert store.prune_events_daily(now=now) == 1
        assert store.get(EVENTS_PRUNED_KEY) == pytest.approx(now)
        assert event_ids(store) == {new}
        assert old not in event_ids(store)
    finally:
        store.close()


def test_events_keep_old_ids(tmp_path):
    """A v1 event keeps its rowid as its id, holes included."""
    from crow_coinbase.store import SCHEMA

    path = tmp_path / "holes.sqlite"
    raw = sqlite3.connect(path)
    try:
        for statement in SCHEMA:
            raw.execute(statement)
        raw.execute("INSERT INTO schema_version(version) VALUES(1)")
        raw.executemany(
            "INSERT INTO events(ts, level, message) VALUES(?, ?, ?)",
            [(1.0, level, message) for level, message in OLD_EVENTS],
        )
        raw.execute("DELETE FROM events WHERE rowid=2")
        raw.commit()
        assert [
            row[0] for row in raw.execute("SELECT rowid FROM events ORDER BY rowid")
        ] == [1, 3]
    finally:
        raw.close()

    store = Store(path)
    try:
        assert store.schema_version() == 2
        assert [
            (row["id"], row["message"])
            for row in store.conn().execute("SELECT id, message FROM events ORDER BY id")
        ] == [(1, OLD_EVENTS[0][1]), (3, OLD_EVENTS[2][1])]
        assert [
            (row[0], row[1])
            for row in store.conn().execute("SELECT rowid, id FROM events ORDER BY id")
        ] == [(1, 1), (3, 3)]

        store.event("info", "after the migration")
        newest = store.conn().execute("SELECT MAX(id) FROM events").fetchone()[0]
        assert newest >= 4
    finally:
        store.close()


def test_v1_fixture_untouched():
    """The P1 fixture is read as bytes and must never be rewritten in place."""
    import hashlib

    digest = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert (
        digest
        == "0acc8aef60c9882f3cbde184a6646884fe3ad096943700c7483e62af08fa70b7"
    )
