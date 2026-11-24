import ast
import inspect
import pathlib
import sqlite3
from datetime import datetime, timezone
from decimal import Decimal as D

import crow_coinbase.exchange as exchange_mod
import crow_coinbase.reconcile as reconcile_mod
import pytest
import requests

from crow_coinbase.exchange import (
    DEFAULT_EQUITY_QUOTE_MAX_AGE_S,
    DryRunExchange,
    LiveExchange,
    PermanentError,
    ProductUnavailable,
    TransientError,
    equity_live_refusal,
    equity_preview_refusal,
    new_client_order_id,
    parse_client_order_id,
    with_retry,
)
from crow_coinbase.store import EQUITY, SPOT

FEE = D("0.005")
XRP = "XRP-USDC"
BTC = "BTC-USDC"
NVDA = "NVDA-USD"
VOO = "VOO-USD"
# A fixed instant inside the regular session -- Wed 2026-07-15 14:00:00 UTC,
# 10:00 in New York -- whose New York close is 20:00:00 UTC the same day.  The
# Saturday instant below shares no session at all.
T = datetime(2026, 7, 15, 14, 0, tzinfo=timezone.utc).timestamp()
CLOSE = datetime(2026, 7, 15, 20, 0, tzinfo=timezone.utc).timestamp()
SATURDAY = datetime(2026, 7, 18, 15, 0, tzinfo=timezone.utc).timestamp()
# The bell of the same New York day (09:30, inside the session) and ten minutes
# before it (09:00, where the previous close's print is stamped).
OPEN_BELL = datetime(2026, 7, 15, 13, 30, tzinfo=timezone.utc).timestamp()
PRE_OPEN = datetime(2026, 7, 15, 13, 0, tzinfo=timezone.utc).timestamp()
# The next New York day's mid-session instant, for an order placed a day later.
NEXT_DAY = datetime(2026, 7, 16, 14, 0, tzinfo=timezone.utc).timestamp()


class Mkt:
    """Fake public market data: a fixed book plus a settable candle list."""

    def __init__(self, bid="0.9644", ask="0.9646"):
        self.bid, self.ask = D(bid), D(ask)
        self.cs = []

    def best_bid_ask(self):
        return self.bid, self.ask

    def candles(self, start, end):
        return self.cs


def new_db():
    return sqlite3.connect(":memory:", isolation_level=None)


def created_at(db, order_id):
    return db.execute(
        "SELECT created_at FROM sim_orders WHERE order_id=?", (order_id,)
    ).fetchone()[0]


def sim():
    db = new_db()
    markets = {XRP: Mkt()}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)
    ex.deposit("USDC", D("1000"), "seed")
    ex.deposit("XRP", D("500"), "seed")
    return ex, markets[XRP], db


def test_sim_post_only_and_funds():
    ex, m, _ = sim()
    assert (
        ex.place_limit("grid-B-1-a", XRP, "BUY", D("10"), D("0.9646"))["reason"]
        == "INVALID_LIMIT_PRICE_POST_ONLY"
    )
    assert (
        ex.place_limit("grid-S+1-a", XRP, "SELL", D("10"), D("0.9644"))["reason"]
        == "INVALID_LIMIT_PRICE_POST_ONLY"
    )
    # 2000 XRP at 0.9 costs ~1809 USDC: more than the seeded 1000 USDC can buy
    assert (
        ex.place_limit("grid-B-1-b", XRP, "BUY", D("2000"), D("0.9"))["reason"]
        == "INSUFFICIENT_FUND"
    )
    r = ex.place_limit("grid-B-1-c", XRP, "BUY", D("10"), D("0.9"))
    assert r["ok"]
    # duplicate client_order_id returns the same order (Coinbase semantics)
    assert (
        ex.place_limit("grid-B-1-c", XRP, "BUY", D("10"), D("0.9"))["order_id"]
        == r["order_id"]
    )
    assert ex.balances()["USDC"] == D("1000") - D("10") * D("0.9") * (1 + FEE)


def test_duplicate_cid_after_market_moved_returns_same_order():
    ex, m, _ = sim()
    placed = ex.place_limit("grid-B-1-dup", XRP, "BUY", D("10"), D("0.9"))
    assert placed["ok"]

    # The market moves above the resting price before the resend.
    m.bid, m.ask = D("0.80"), D("0.85")

    resend = ex.place_limit("grid-B-1-dup", XRP, "BUY", D("10"), D("0.9"))
    assert resend["ok"] is True
    assert resend["order_id"] == placed["order_id"]


def test_sim_fills_only_when_later_candle_trades_through():
    ex, m, db = sim()
    oid = ex.place_limit("grid-B-1-c", XRP, "BUY", D("10"), D("0.9"))["order_id"]
    placed = created_at(db, oid)
    m.cs = [
        {"start": int(placed) - 30, "low": D("0.8"), "high": D("1")}
    ]  # before placement: ignored
    assert ex.advance(placed + 100) == []
    m.cs = [
        {"start": int(placed) + 60, "low": D("0.9"), "high": D("1")}
    ]  # touched, not through
    assert ex.advance(placed + 100) == []
    m.cs = [{"start": int(placed) + 60, "low": D("0.8999"), "high": D("1")}]
    assert ex.advance(placed + 200) == ["grid-B-1-c"]
    o = ex.get_order(oid)
    assert o["status"] == "FILLED" and o["filled_size"] == D("10")
    assert ex.totals()["XRP"] == D("500") + D("10")
    assert ex.totals()["USDC"] == D("1000") - D("9") - D("9") * FEE
    f = ex.fills(oid)
    assert len(f) == 1 and f[0]["commission"] == D("9") * FEE


def test_advance_uses_each_orders_own_product():
    db = new_db()
    markets = {XRP: Mkt("0.9644", "0.9646"), BTC: Mkt("60000", "60010")}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)
    ex.deposit("USDC", D("1000"), "seed")

    xrp_order = ex.place_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))
    btc_order = ex.place_limit("grid-B-1-b", BTC, "BUY", D("0.01"), D("59000"))
    assert xrp_order["ok"] and btc_order["ok"]

    placed_x = created_at(db, xrp_order["order_id"])
    placed_b = created_at(db, btc_order["order_id"])
    start = int(max(placed_x, placed_b)) + 60
    # XRP trading at ~0.85 trades through its own 0.9 buy...
    markets[XRP].cs = [{"start": start, "low": D("0.85"), "high": D("1.0")}]
    # ...while BTC never trades below 59500, so its 59000 buy stays open.
    markets[BTC].cs = [{"start": start, "low": D("59500"), "high": D("60500")}]

    assert ex.advance(start + 120) == ["grid-B-1-x"]
    assert ex.get_order(xrp_order["order_id"])["status"] == "FILLED"
    assert ex.get_order(btc_order["order_id"])["status"] == "OPEN"
    assert [o["client_order_id"] for o in ex.list_open_orders()] == ["grid-B-1-b"]


def test_totals_include_holds():
    ex, m, _ = sim()

    buy = ex.place_limit("grid-B-1-hold", XRP, "BUY", D("10"), D("0.9"))
    assert buy["ok"]
    assert ex.totals()["USDC"] == D("1000")
    assert ex.balances()["USDC"] == D("1000") - D("10") * D("0.9") * (1 + FEE)

    sell = ex.place_limit("grid-S+1-hold", XRP, "SELL", D("4"), D("1.05"))
    assert sell["ok"]
    assert ex.totals()["XRP"] == D("500")
    assert ex.balances()["XRP"] == D("500") - D("4")


def test_list_open_orders_unfiltered_returns_all_products():
    db = new_db()
    markets = {XRP: Mkt(), BTC: Mkt("60000", "60010")}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)
    ex.deposit("USDC", D("1000"), "seed")
    ex.deposit("XRP", D("500"), "seed")

    assert ex.place_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))["ok"]
    assert ex.place_limit("grid-B-1-b", BTC, "BUY", D("0.01"), D("59000"))["ok"]

    everywhere = ex.list_open_orders()
    assert sorted(o["client_order_id"] for o in everywhere) == [
        "grid-B-1-b",
        "grid-B-1-x",
    ]
    assert {o["client_order_id"]: o["product"] for o in everywhere} == {
        "grid-B-1-x": XRP,
        "grid-B-1-b": BTC,
    }

    xrp_only = ex.list_open_orders(XRP)
    assert [o["client_order_id"] for o in xrp_only] == ["grid-B-1-x"]


def test_deposit_seeds_balances():
    db = new_db()
    markets = {XRP: Mkt()}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)

    assert ex.totals().get("USDC", D(0)) == D("0")
    assert (
        ex.place_limit("grid-B-1-broke", XRP, "BUY", D("10"), D("0.9"))["reason"]
        == "INSUFFICIENT_FUND"
    )

    ex.deposit("USDC", D("250"), "seed")
    ex.deposit("USDC", D("50"), "top up")
    assert ex.totals()["USDC"] == D("300")


def test_deposit_rejects_non_positive():
    db = new_db()
    ex = DryRunExchange(lambda: db, lambda p: Mkt(), FEE)

    for bad in (D("0"), D("-5")):
        with pytest.raises(ValueError):
            ex.deposit("USDC", bad, "bad")
    assert ex.totals() == {}


def test_deposit_visible_across_connections_default_isolation(tmp_path):
    path = tmp_path / "sim.db"
    c1 = sqlite3.connect(path)  # default isolation level, not autocommit
    c2 = sqlite3.connect(path)
    markets = {XRP: Mkt()}
    first = DryRunExchange(lambda: c1, lambda p: markets[p], FEE)
    second = DryRunExchange(lambda: c2, lambda p: markets[p], FEE)

    first.deposit("USDC", D("125.5"), "seed")

    assert second.totals()["USDC"] == D("125.5")


def test_tx_inside_callers_transaction_is_rolled_back_with_it():
    db = new_db()
    markets = {XRP: Mkt()}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)
    db.execute("CREATE TABLE marker(x)")

    db.execute("BEGIN")
    db.execute("INSERT INTO marker(x) VALUES('outer')")
    ex.deposit("USDC", D("10"), "t")
    db.execute("ROLLBACK")

    assert db.execute("SELECT * FROM marker").fetchall() == []
    assert ex.totals().get("USDC", D(0)) == D(0)
    assert db.execute("SELECT * FROM sim_deposits").fetchall() == []


def test_failing_deposit_inside_callers_transaction_leaves_it_usable(monkeypatch):
    db = new_db()
    markets = {XRP: Mkt()}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)
    db.execute("CREATE TABLE marker(x)")

    db.execute("BEGIN")
    db.execute("INSERT INTO marker(x) VALUES('first')")
    with pytest.raises(ValueError):
        ex.deposit("USDC", D("-1"), "bad")
    db.execute("INSERT INTO marker(x) VALUES('second')")
    db.execute("COMMIT")

    assert [r[0] for r in db.execute("SELECT x FROM marker ORDER BY rowid")] == [
        "first",
        "second",
    ]

    # A raise from inside the transaction body must leave the caller's rows alone.
    db2 = new_db()
    ex2 = DryRunExchange(lambda: db2, lambda p: markets[p], FEE)
    db2.execute("CREATE TABLE marker(x)")

    def failing_add(dbc, cur, delta):
        dbc.execute(
            "INSERT INTO sim_balances(currency,amount) VALUES(?,?)", (cur, "999")
        )
        raise RuntimeError("boom")

    monkeypatch.setattr(ex2, "_add", failing_add)
    db2.execute("BEGIN")
    db2.execute("INSERT INTO marker(x) VALUES('first')")
    with pytest.raises(RuntimeError):
        ex2.deposit("USDC", D("10"), "bad")

    assert db2.execute("SELECT * FROM sim_deposits").fetchall() == []
    assert ex2.totals().get("USDC", D(0)) == D(0)
    assert [r[0] for r in db2.execute("SELECT x FROM marker")] == ["first"]

    db2.execute("INSERT INTO marker(x) VALUES('second')")
    db2.execute("COMMIT")
    assert [r[0] for r in db2.execute("SELECT x FROM marker ORDER BY rowid")] == [
        "first",
        "second",
    ]


def test_cancel_between_advance_read_and_write_is_not_filled(tmp_path):
    path = tmp_path / "sim.db"
    c1 = sqlite3.connect(path)
    c2 = sqlite3.connect(path)
    state = {}

    class CancelThenTradeThrough(Mkt):
        def candles(self, start, end):
            other.cancel([state["order_id"]])
            return [{"start": state["start"], "low": D("0.8"), "high": D("1")}]

    markets = {XRP: CancelThenTradeThrough()}
    ex_a = DryRunExchange(lambda: c1, lambda p: markets[p], FEE)
    other = DryRunExchange(lambda: c2, lambda p: markets[p], FEE)
    ex_a.deposit("USDC", D("1000"), "seed")
    placed = ex_a.place_limit("grid-B-1-c", XRP, "BUY", D("10"), D("0.9"))
    assert placed["ok"]
    state["order_id"] = placed["order_id"]
    state["start"] = int(created_at(c1, placed["order_id"])) + 60
    before = ex_a.totals()

    assert ex_a.advance(state["start"] + 120) == []
    assert ex_a.get_order(placed["order_id"])["status"] == "CANCELLED"
    assert ex_a.totals() == before


def test_fills_carry_product():
    ex, m, db = sim()
    oid = ex.place_limit("grid-B-1-p", XRP, "BUY", D("10"), D("0.9"))["order_id"]
    placed = created_at(db, oid)
    m.cs = [{"start": int(placed) + 60, "low": D("0.8999"), "high": D("1")}]

    assert ex.advance(placed + 200) == ["grid-B-1-p"]
    assert ex.fills(oid)[0]["product"] == XRP


def test_norm_order_and_fill_carry_product():
    order = exchange_mod._norm_order({"order_id": "o", "product_id": BTC, "side": "BUY"})
    assert order["product"] == BTC

    fill = exchange_mod._norm_fill(
        {
            "product_id": BTC,
            "trade_id": "t",
            "order_id": "o",
            "side": "BUY",
            "size": "1",
            "price": "2",
            "trade_time": "x",
        }
    )
    assert fill["product"] == BTC


def test_dry_find_by_client_id_product_filter():
    db = new_db()
    markets = {XRP: Mkt(), BTC: Mkt("60000", "60010")}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)
    ex.deposit("USDC", D("1000"), "seed")
    placed = ex.place_limit("grid-B-1-f", XRP, "BUY", D("10"), D("0.9"))
    assert placed["ok"]

    assert ex.find_by_client_id("grid-B-1-f", 0)["order_id"] == placed["order_id"]
    assert (
        ex.find_by_client_id("grid-B-1-f", 0, XRP)["order_id"] == placed["order_id"]
    )
    assert ex.find_by_client_id("grid-B-1-f", 0, BTC) is None
    assert ex.find_by_client_id("grid-B-1-missing", 0) is None


def test_advance_continues_after_one_products_candles_error():
    class BrokenMkt(Mkt):
        def candles(self, start, end):
            raise TransientError("candles down")

    db = new_db()
    markets = {XRP: BrokenMkt(), BTC: Mkt("60000", "60010")}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)
    ex.deposit("USDC", D("1000"), "seed")
    xrp = ex.place_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))
    btc = ex.place_limit("grid-B-1-b", BTC, "BUY", D("0.01"), D("59000"))
    assert xrp["ok"] and btc["ok"]

    start = int(max(created_at(db, xrp["order_id"]), created_at(db, btc["order_id"])))
    markets[BTC].cs = [{"start": start + 60, "low": D("58000"), "high": D("60000")}]

    assert ex.advance(start + 120) == ["grid-B-1-b"]
    assert ex.get_order(btc["order_id"])["status"] == "FILLED"
    assert ex.get_order(xrp["order_id"])["status"] == "OPEN"


def test_totals_and_balances_per_currency_after_cross_product_fill():
    db = new_db()
    markets = {XRP: Mkt("0.9644", "0.9646"), BTC: Mkt("60000", "60010")}
    ex = DryRunExchange(lambda: db, lambda p: markets[p], FEE)
    ex.deposit("USDC", D("1000"), "seed")

    btc = ex.place_limit("grid-B-1-b", BTC, "BUY", D("0.01"), D("59000"))
    xrp = ex.place_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))
    assert btc["ok"] and xrp["ok"]

    start = int(max(created_at(db, btc["order_id"]), created_at(db, xrp["order_id"])))
    markets[BTC].cs = [{"start": start + 60, "low": D("58000"), "high": D("60000")}]
    assert ex.advance(start + 120) == ["grid-B-1-b"]

    cost = D("59000") * D("0.01")
    assert ex.totals()["BTC"] == D("0.01")
    assert ex.totals()["USDC"] == D("1000") - cost - cost * FEE
    assert ex.totals().get("XRP", D(0)) == D(0)
    xrp_hold = D("10") * D("0.9") * (1 + FEE)
    assert ex.balances()["USDC"] == ex.totals()["USDC"] - xrp_hold


OLD_SIM_ORDERS = """
CREATE TABLE sim_orders (
  order_id TEXT PRIMARY KEY, client_order_id TEXT UNIQUE, side TEXT, price TEXT,
  size TEXT, status TEXT, created_at REAL, filled_at REAL, fee TEXT DEFAULT '0');
"""


def test_old_schema_dry_db_refused(tmp_path):
    db = sqlite3.connect(tmp_path / "old.db")
    db.executescript(OLD_SIM_ORDERS)

    with pytest.raises(RuntimeError, match="predates schema v1"):
        DryRunExchange(lambda: db, lambda p: Mkt(), FEE)


ALLOWED_SDK_METHODS = {
    "get_api_key_permissions",
    "get_transaction_summary",
    "get_accounts",
    "get_unix_time",
    "list_orders",
    "get_order",
    "get_fills",
    "get_public_product",
    "get_public_product_book",
    "get_public_candles",
    # The authenticated product read: the only read that answers a stock at all,
    # which is what `product_spec` and `product_type` are built on.
    "get_product",
    "limit_order_gtc",
    "create_order",
    "cancel_orders",
}

SDK_CLIENTS = ("client", "pub")


def _enclosing(tree):
    """Node id -> the names of the functions and classes it sits inside.

    Innermost first, so a call written in `LiveExchange.place_equity_limit` maps
    to `("place_equity_limit", "LiveExchange")`.  The SDK rule below has to say
    WHERE an allowed call may sit, not just which method it may name.
    """
    out = {}
    stack = []

    def walk(node):
        out[id(node)] = tuple(reversed(stack))
        push = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        if push:
            stack.append(node.name)
        for child in ast.iter_child_nodes(node):
            walk(child)
        if push:
            stack.pop()

    walk(tree)
    return out


def _self_sdk_ref(node):
    """`self.client` / `self.pub` attribute nodes."""
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and node.attr in SDK_CLIENTS
    )


def _sdk_calls(node):
    """`self.client.<attr>(...)` / `self.pub.<attr>(...)` calls by attribute name."""
    out = {}
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        if isinstance(fn, ast.Attribute) and _self_sdk_ref(fn.value):
            out.setdefault(fn.attr, []).append(sub)
    return out


def sdk_guard_violations(src: str) -> list[str]:
    """Ways *src* reaches around the "only these SDK client calls" rule.

    This helper answers "which method name", not "where".  The tighter rule --
    `create_order` only inside `LiveExchange.place_equity_limit` -- is enforced by
    `scan_source` in tests/test_no_bypass.py, which is where the bypass cases for
    it live.
    """
    tree = ast.parse(src)
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node

    def _is_rest_client_call(call):
        if not isinstance(call, ast.Call):
            return False
        fn = call.func
        return (isinstance(fn, ast.Name) and fn.id == "RESTClient") or (
            isinstance(fn, ast.Attribute) and fn.attr == "RESTClient"
        )

    def _assigned_to_client(call):
        """True when *call* sits in the value expression of `self.client = ...`."""
        child = call
        node = parent.get(child)
        while node is not None:
            if isinstance(node, ast.Assign):
                if len(node.targets) != 1 or not _self_sdk_ref(node.targets[0]):
                    return False
                return child is node.value
            child = node
            node = parent.get(node)
        return False

    violations = []
    for node in ast.walk(tree):
        if _self_sdk_ref(node) and isinstance(node.ctx, ast.Load):
            holder = parent.get(node)
            call = parent.get(holder) if holder is not None else None
            if not (
                isinstance(holder, ast.Attribute)
                and holder.value is node
                and isinstance(call, ast.Call)
                and call.func is holder
                and holder.attr in ALLOWED_SDK_METHODS
            ):
                violations.append(
                    f"line {node.lineno}: self.{node.attr} used outside an "
                    "allowlisted call"
                )
        if _is_rest_client_call(node) and not _assigned_to_client(node):
            violations.append(
                f"line {node.lineno}: RESTClient() not assigned to "
                "self.client/self.pub"
            )
    return violations


def test_exchange_sdk_calls_only_post_only_limit_and_cancel():
    src = pathlib.Path(exchange_mod.__file__).read_text()
    tree = ast.parse(src)
    calls = _sdk_calls(tree)

    assert sdk_guard_violations(src) == []

    # non-vacuous: the write paths are actually used
    assert "limit_order_gtc" in calls
    assert "cancel_orders" in calls
    assert set(calls) <= ALLOWED_SDK_METHODS

    for call in calls["limit_order_gtc"]:
        kw = {k.arg: k.value for k in call.keywords if k.arg}
        assert "post_only" in kw
        node = kw["post_only"]
        assert isinstance(node, ast.Constant) and node.value is True

    # The equity path is ONE create_order call, in one place, and it carries no
    # post_only: post-only for equities is unverified, so it is never sent.
    assert len(calls["create_order"]) == 1
    equity_call = calls["create_order"][0]
    assert _enclosing(tree)[id(equity_call)][:2] == (
        "place_equity_limit",
        "LiveExchange",
    )
    equity_kw = {k.arg: k.value for k in equity_call.keywords if k.arg}
    assert "order_configuration" in equity_kw
    assert "equity_order_metadata" in equity_kw
    assert "post_only" not in equity_kw


def test_sdk_guard_flags_bypasses():
    assert sdk_guard_violations(
        'class X:\n    def f(self):\n        return getattr(self.client, "market_order_buy")\n'
    )
    assert sdk_guard_violations(
        "class X:\n"
        "    def f(self):\n"
        "        c = self.client\n"
        "        return c.market_order_buy()\n"
    )
    assert sdk_guard_violations(
        "from coinbase.rest import RESTClient\n"
        "def f():\n"
        '    return RESTClient().market_order(product_id="A-B")\n'
    )
    assert (
        sdk_guard_violations(
            "class X:\n"
            "    def f(self):\n"
            "        self.client = RESTClient()\n"
            "        return self.client.cancel_orders(order_ids=[])\n"
        )
        == []
    )


def test_with_retry_retries_transient_only():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise requests.exceptions.ConnectionError()
        return "ok"

    assert with_retry(flaky, "t", sleep=lambda s: None) == "ok" and calls["n"] == 3

    def bad():
        r = requests.Response()
        r.status_code = 400
        raise requests.exceptions.HTTPError("400", response=r)

    with pytest.raises(PermanentError):
        with_retry(bad, "t", sleep=lambda s: None)

    def down():
        raise requests.exceptions.Timeout()

    with pytest.raises(TransientError):
        with_retry(down, "t", attempts=3, sleep=lambda s: None)


def test_client_order_id_roundtrip():
    for side, lvl in (("BUY", -3), ("SELL", 0), ("SELL", 2)):
        cid = new_client_order_id("grid-", side, lvl)
        assert cid.startswith("grid-") and parse_client_order_id("grid-", cid) == (
            side,
            lvl,
        )
    assert parse_client_order_id("grid-", "manual-123") is None


def test_live_server_time_reads_epoch_seconds():
    class FakeTime:
        def to_dict(self):
            return {
                "iso": "2026-01-01T00:00:00Z",
                "epoch_seconds": "1767225600",
                "epoch_millis": "1767225600000",
            }

    class FakeClient:
        def get_unix_time(self):
            return FakeTime()

    ex = LiveExchange.__new__(LiveExchange)
    ex.sleep = lambda s: None
    ex.client = FakeClient()
    assert ex.server_time() == 1767225600.0


class Resp:
    def __init__(self, payload):
        self.payload = payload

    def to_dict(self):
        return self.payload


class FakeAccounts:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def get_accounts(self, limit=None, cursor=None):
        self.calls.append({"limit": limit, "cursor": cursor})
        return Resp(self.pages[len(self.calls) - 1])


class FakeOrders:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def list_orders(self, **kwargs):
        self.calls.append(kwargs)
        return Resp(self.pages[len(self.calls) - 1])


def raw_product(product, product_type="SPOT", **overrides):
    """A raw authenticated product, as `client.get_product()` answers it.

    `product_id` and `product_type` are the two fields the engine reads off it;
    the tick sizes and the minimums are what `ProductSpec.from_api` needs in order
    to build a spec at all.
    """
    raw = {
        "product_id": product,
        "price_increment": "0.0001",
        "base_increment": "0.1",
        "quote_increment": "0.01",
        "base_min_size": "1",
        "quote_min_size": "1",
        "product_type": product_type,
    }
    raw.update(overrides)
    return raw


def equity_raw(product=NVDA, **overrides):
    """An EQUITY listing: cents on the price, fractional shares, USD quoted."""
    fields = dict(
        price_increment="0.01",
        base_increment="0.0001",
        quote_increment="0.01",
        base_min_size="0.0001",
        quote_min_size="1",
        fractionable=True,
        fractional_notional_min_size="1",
    )
    fields.update(overrides)
    return raw_product(product, "EQUITY", **fields)


# The raw product each id names, as the authenticated read answers it.
PRODUCTS = {XRP: raw_product(XRP), BTC: raw_product(BTC), NVDA: equity_raw(NVDA)}

# The preview a live equity route needs on record before it may send anything.
VALID_CONFIRMATION = {
    "displayed_order_config": "LIMIT_GFD",
    "equity_trading_session": "EQUITY_TRADING_SESSION_NORMAL",
}


class AuthedProducts:
    """The authenticated product read, and how often each product was read.

    This is what a fake SDK client answers for `get_product(product)`; every
    other call is the wrapped client's own, so a test still asserts on the fake it
    built.  `failures` makes the first reads of each product raise, which is a
    lookup that cannot answer; `products` is the whole raw table when a test is
    about a listing the defaults do not describe.
    """

    def __init__(self, inner=None, *, products=None, failures=0):
        self.inner = inner
        table = PRODUCTS if products is None else products
        self.products = {product: dict(raw) for product, raw in table.items()}
        self.failures = failures
        self.reads = {}
        self.total = 0

    def get_product(self, product_id):
        self.reads[product_id] = self.reads.get(product_id, 0) + 1
        self.total += 1
        if self.reads[product_id] <= self.failures:
            raise ProductUnavailable("no spec for this product")
        raw = self.products.get(product_id)
        if raw is None:
            raise ProductUnavailable(f"{product_id}: no such product")
        return Resp(dict(raw))

    def __getattr__(self, name):
        inner = self.__dict__.get("inner")
        if inner is None:
            raise AttributeError(name)
        return getattr(inner, name)


def live(
    client,
    *,
    confirmation=VALID_CONFIRMATION,
    product_types=None,
    products=None,
    failures=0,
):
    """A LiveExchange built around *client* without its constructor.

    The client is the SDK one, so it answers the authenticated product read the
    write paths and `product_spec` use: *products* replaces the raw listings,
    *product_types* overrides one product's kind, and *failures* makes the first
    reads of each product fail.  How often a product was read is on
    `ex.client.reads`, so a test can tell a cached kind from a second lookup.
    `equity_preview_confirmation` is the recorded preview unless a test asks for a
    missing or mismatched one.
    """
    ex = LiveExchange.__new__(LiveExchange)
    ex.sleep = lambda s: None
    ex.equity_preview_confirmation = confirmation
    table = dict(PRODUCTS if products is None else products)
    table = {product: dict(raw) for product, raw in table.items()}
    for product, kind in (product_types or {}).items():
        raw = dict(table.get(product) or raw_product(product))
        raw["product_type"] = kind
        table[product] = raw
    ex.client = AuthedProducts(client, products=table, failures=failures)
    return ex


def test_live_totals_adds_hold_across_pages():
    fake = FakeAccounts(
        [
            {
                "accounts": [
                    {
                        "currency": "USDC",
                        "available_balance": {"value": "10"},
                        "hold": {"value": "2.5"},
                    },
                    {"currency": "BTC", "available_balance": {"value": "0.5"}},
                ],
                "has_next": True,
                "cursor": "c2",
            },
            {
                "accounts": [
                    {"currency": "ETH", "available_balance": {"value": "2"}},
                ],
                "has_next": False,
            },
        ]
    )

    totals = live(fake).totals()

    assert totals == {"USDC": D("12.5"), "BTC": D("0.5"), "ETH": D("2")}
    assert len(fake.calls) == 2
    assert fake.calls[1]["cursor"] == "c2"


def test_live_list_open_orders_unfiltered_follows_cursor():
    def order(order_id, product):
        return {
            "order_id": order_id,
            "client_order_id": "cid-" + order_id,
            "product_id": product,
            "side": "BUY",
            "status": "OPEN",
            "order_configuration": {
                "limit_limit_gtc": {"limit_price": "0.9", "base_size": "10"}
            },
        }

    fake = FakeOrders(
        [
            {
                "orders": [order("o1", XRP)],
                "has_next": True,
                "cursor": "c2",
            },
            {"orders": [order("o2", BTC)], "has_next": False},
        ]
    )
    ex = live(fake)

    everywhere = ex.list_open_orders()

    assert [o["order_id"] for o in everywhere] == ["o1", "o2"]
    assert all("product_ids" not in c for c in fake.calls)
    assert fake.calls[1]["cursor"] == "c2"

    fake.calls = []
    fake.pages = [{"orders": [order("o1", XRP)], "has_next": False}]
    assert [o["order_id"] for o in ex.list_open_orders(XRP)] == ["o1"]
    assert fake.calls[0]["product_ids"] == [XRP]


def test_live_place_limit_sends_post_only():
    class FakePlace:
        def __init__(self):
            self.calls = []

        def limit_order_gtc(self, **kwargs):
            self.calls.append(kwargs)
            return Resp({"success": True, "success_response": {"order_id": "o1"}})

    fake = FakePlace()
    res = live(fake).place_limit("cid-1", XRP, "BUY", D("10"), D("0.9"))

    sent = fake.calls[0]
    assert sent["post_only"] is True
    assert sent["product_id"] == XRP
    assert sent["client_order_id"] == "cid-1"
    assert res["ok"] and res["order_id"] == "o1"


# ---------------------------------------------------------------- equity path


class EqMkt:
    """A fake equity market: one last price, served as both sides of the book.

    Prices and sizes here are synthetic.  `best_bid_ask` is separate so a test
    can put an ask below a buy limit: an equity order carries no post-only rule,
    so that is accepted where the crypto path would refuse it.
    """

    def __init__(self, last="100", bid=None, ask=None):
        self.last = D(last)
        self.bid = self.last if bid is None else D(bid)
        self.ask = self.last if ask is None else D(ask)

    def equity_quote(self):
        return self.last, self.last

    def best_bid_ask(self):
        return self.bid, self.ask

    def candles(self, start, end):
        return []


class FakeCreateOrder:
    """A fake SDK client: `create_order` records its kwargs, then replays a payload."""

    def __init__(self, payload=None, error=None):
        self.payload = (
            {"success": True, "success_response": {"order_id": "o9"}}
            if payload is None
            else payload
        )
        self.error = error
        self.calls = []

    def create_order(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return Resp(self.payload)


def equity_sim(monkeypatch, *, last="100", bid=None, ask=None, instant=T):
    """A dry-run exchange whose one equity product is NVDA-USD, with a fixed clock."""
    monkeypatch.setattr(exchange_mod.time, "time", lambda: instant)
    db = new_db()
    markets = {NVDA: EqMkt(last, bid=bid, ask=ask), XRP: Mkt()}
    ex = DryRunExchange(
        lambda: db,
        lambda p: markets[p],
        FEE,
        is_equity=lambda p: p == NVDA,
    )
    ex.deposit("USD", D("1000"), "seed")
    ex.deposit("USDC", D("1000"), "seed")
    ex.deposit("XRP", D("500"), "seed")
    return ex, markets, db


def test_place_equity_limit_body():
    fake = FakeCreateOrder()
    cid = "cb-ai-B+0-aaaaaaaaaaaa"

    res = live(fake).place_equity_limit(cid, NVDA, "BUY", D("0.5"), D("120.25"))

    assert fake.calls == [
        {
            "client_order_id": cid,
            "product_id": "NVDA-USD",
            "side": "BUY",
            "order_configuration": {
                "limit_limit_gtc": {"base_size": "0.5", "limit_price": "120.25"}
            },
            "equity_order_metadata": {
                "equity_trading_session": exchange_mod.EQUITY_TRADING_SESSION,
                "displayed_order_config": exchange_mod.EQUITY_DISPLAYED_ORDER_CONFIG,
            },
        }
    ]
    # ...and the constants themselves are the wire's own words.
    assert fake.calls[0]["equity_order_metadata"] == {
        "equity_trading_session": "EQUITY_TRADING_SESSION_NORMAL",
        "displayed_order_config": "LIMIT_GFD",
    }
    # post-only for equities is unverified: the request never carries it.
    assert "post_only" not in repr(fake.calls[0])
    assert res == {"ok": True, "order_id": "o9", "reason": None}


def test_equity_constants():
    """The gate's words are constants, so the check and the request cannot drift."""
    assert exchange_mod.EQUITY_TRADING_SESSION == "EQUITY_TRADING_SESSION_NORMAL"
    assert exchange_mod.EQUITY_DISPLAYED_ORDER_CONFIG == "LIMIT_GFD"
    assert exchange_mod.EQUITY_PREVIEW_UNCONFIRMED == "EQUITY_PREVIEW_UNCONFIRMED"
    assert exchange_mod.EQUITY_PREVIEW_CONFIRMED_KEY == "equity_preview_confirmed"

    assert DEFAULT_EQUITY_QUOTE_MAX_AGE_S == 120
    assert isinstance(DEFAULT_EQUITY_QUOTE_MAX_AGE_S, (int, float))


def test_equity_request_is_built_from_the_constants():
    """The request names the gate's constants, not a second copy of the words."""
    body = inspect.getsource(LiveExchange.place_equity_limit)

    assert "EQUITY_TRADING_SESSION" in body
    assert "EQUITY_DISPLAYED_ORDER_CONFIG" in body


def test_equity_preview_refusal():
    """Only a confirmed config plus session is a confirmation."""
    assert equity_preview_refusal(dict(VALID_CONFIRMATION)) is None

    for bad in (
        None,
        {},
        "LIMIT_GFD",
        ("LIMIT_GFD", "EQUITY_TRADING_SESSION_NORMAL"),
        ["LIMIT_GFD", "EQUITY_TRADING_SESSION_NORMAL"],
        {"displayed_order_config": "LIMIT_GFD"},
        {"equity_trading_session": "EQUITY_TRADING_SESSION_NORMAL"},
        {
            "displayed_order_config": "LIMIT_GTC",
            "equity_trading_session": "EQUITY_TRADING_SESSION_NORMAL",
        },
        {
            "displayed_order_config": "LIMIT_GFD",
            "equity_trading_session": "EQUITY_TRADING_SESSION_EXTENDED",
        },
        {
            "displayed_order_config": None,
            "equity_trading_session": "EQUITY_TRADING_SESSION_NORMAL",
        },
    ):
        reason = equity_preview_refusal(bad)
        assert isinstance(reason, str) and reason


def test_equity_live_refusal():
    """Off is always allowed; on is not allowed without a recorded preview."""
    assert equity_live_refusal(False, None) is None
    assert equity_live_refusal(False, {"nonsense": True}) is None
    assert equity_live_refusal(False, dict(VALID_CONFIRMATION)) is None

    assert equity_live_refusal(True, dict(VALID_CONFIRMATION)) is None

    for bad in (None, {}, {"displayed_order_config": "LIMIT_GFD"}):
        reason = equity_live_refusal(True, bad)
        assert isinstance(reason, str) and reason
        # The live gate is the preview gate: the same refusal, unchanged.
        assert reason == equity_preview_refusal(bad)


def test_live_place_limit_refuses_an_equity_product():
    cid = "cb-ai-B+0-eeeeeeeeeeee"
    args = (cid, NVDA, "BUY", D("0.001"), D("1.00"))

    fake = FakeCreateOrder()
    refused = live(fake).place_limit(*args)
    assert refused == {
        "ok": False,
        "order_id": None,
        "reason": "EQUITY_USE_EQUITY_PATH",
    }
    assert fake.calls == []

    # The kind is read case-insensitively, and it is the kind that decides.
    lower = FakeCreateOrder()
    assert (
        live(lower, product_types={NVDA: "equity"}).place_limit(*args)["reason"]
        == "EQUITY_USE_EQUITY_PATH"
    )
    assert lower.calls == []

    # A crypto product still goes out post-only, as it always did -- over
    # `limit_order_gtc`, not the equity path's `create_order`.
    class FakePlace:
        def __init__(self):
            self.calls = []

        def limit_order_gtc(self, **kwargs):
            self.calls.append(kwargs)
            return Resp({"success": True, "success_response": {"order_id": "o1"}})

    sent = FakePlace()
    placed = live(sent).place_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))
    assert placed["ok"] is True
    assert len(sent.calls) == 1
    assert sent.calls[0]["post_only"] is True
    assert sent.calls[0]["product_id"] == XRP
    assert sent.calls[0]["client_order_id"] == "grid-B-1-x"


class FakeBothPaths:
    """An SDK client that records whichever write path it is asked for."""

    def __init__(self, payload=None):
        self.payload = (
            {"success": True, "success_response": {"order_id": "o1"}}
            if payload is None
            else payload
        )
        self.limit_calls = []
        self.create_calls = []

    def limit_order_gtc(self, **kwargs):
        self.limit_calls.append(kwargs)
        return Resp(self.payload)

    def create_order(self, **kwargs):
        self.create_calls.append(kwargs)
        return Resp(self.payload)


def test_live_place_limit_answers_product_type_unknown():
    """A product read that cannot answer refuses the order instead of sending it."""
    client = FakeBothPaths()
    ex = live(client, failures=1)

    refused = ex.place_limit("cb-ai-B+0-ffffffffffff", XRP, "BUY", D("10"), D("0.9"))

    assert refused == {
        "ok": False,
        "order_id": None,
        "reason": exchange_mod.PRODUCT_TYPE_UNKNOWN,
    }
    assert exchange_mod.PRODUCT_TYPE_UNKNOWN == "PRODUCT_TYPE_UNKNOWN"
    assert client.limit_calls == []
    assert ex.client.reads[XRP] == 1


def test_live_place_equity_limit_answers_product_type_unknown():
    client = FakeBothPaths()
    ex = live(client, failures=1)

    refused = ex.place_equity_limit(
        "cb-ai-B+0-ffffffffffff", NVDA, "BUY", D("0.001"), D("1.00")
    )

    assert refused == {
        "ok": False,
        "order_id": None,
        "reason": exchange_mod.PRODUCT_TYPE_UNKNOWN,
    }
    assert client.create_calls == []
    assert client.limit_calls == []
    assert ex.client.reads[NVDA] == 1


def test_product_type_caches_a_successful_lookup():
    """One product is read once, and the write paths read the cached kind."""
    client = FakeBothPaths()
    ex = live(client)

    assert ex.product_type(NVDA) == "EQUITY"
    assert ex.product_type(NVDA) == "EQUITY"
    assert ex.client.reads[NVDA] == 1

    placed = ex.place_equity_limit(
        "cb-ai-B+0-aaaaaaaaaaaa", NVDA, "BUY", D("0.5"), D("120.25")
    )
    assert placed["ok"] is True
    assert ex.client.reads[NVDA] == 1
    assert len(client.create_calls) == 1

    # Each product is cached on its own.
    assert ex.product_type(XRP) == "SPOT"
    assert ex.product_type(XRP) == "SPOT"
    assert ex.client.reads[XRP] == 1


def test_product_type_does_not_cache_a_failure():
    """A read that could not answer is asked again next time."""
    client = FakeBothPaths()
    ex = live(client, failures=1)
    cid = "cb-ai-B+0-bbbbbbbbbbbb"
    args = (cid, NVDA, "BUY", D("0.5"), D("120.25"))

    assert ex.place_equity_limit(*args)["reason"] == exchange_mod.PRODUCT_TYPE_UNKNOWN
    assert client.create_calls == []

    placed = ex.place_equity_limit(*args)
    assert placed["ok"] is True
    assert len(client.create_calls) == 1
    assert ex.client.reads[NVDA] == 2


def test_product_spec_reads_the_authenticated_raw_product():
    """An equity's spec is the authenticated listing, fractionable shares and all."""
    client = FakeBothPaths()
    ex = live(client)

    spec = ex.product_spec(NVDA)

    assert spec.product_id == NVDA
    assert spec.product_type == "EQUITY"
    assert spec.fractionable is True
    assert spec.price_increment == D("0.01")
    assert spec.base_increment == D("0.0001")
    assert spec.quote_increment == D("0.01")
    assert spec.base_min_size == D("0.0001")
    assert spec.quote_min_size == D("1")
    assert spec.fractional_notional_min_size == D("1")
    assert ex.client.reads[NVDA] == 1

    # A listing can change, so a spec is read again rather than kept: the two
    # reads answer the same spec here, and both happened.
    assert ex.product_spec(NVDA) == spec
    assert ex.client.reads[NVDA] == 2

    # A crypto listing comes off the same read, with its own tick sizes.
    spot = ex.product_spec(XRP)
    assert spot.product_id == XRP
    assert spot.product_type == "SPOT"
    assert spot.base_increment == D("0.1")
    assert ex.client.reads[XRP] == 1


def test_product_spec_refuses_a_different_product():
    """A read that answers another product is not this product's spec."""
    ex = live(FakeBothPaths(), products={NVDA: equity_raw(VOO)})

    with pytest.raises(ProductUnavailable):
        ex.product_spec(NVDA)


def test_product_spec_answers_a_halted_or_delisted_product():
    """There is no tradability gate: a halted or delisted listing still answers."""
    halted = equity_raw(
        NVDA, status="delisted", trading_disabled=True, trading_halted=True
    )
    ex = live(FakeBothPaths(), products={NVDA: halted})

    spec = ex.product_spec(NVDA)

    assert spec.product_id == NVDA
    assert spec.product_type == "EQUITY"
    # The flags are carried, not judged: a halted stock is still a stock, and its
    # kind is what tells the engine which path its orders take.
    assert spec.trading_halted is True


def test_product_type_answers_a_halted_or_delisted_product():
    """The kind comes off the same read, and is not gated on tradability either."""
    halted = equity_raw(
        NVDA, status="delisted", trading_disabled=True, trading_halted=True
    )
    ex = live(FakeBothPaths(), products={NVDA: halted})

    assert ex.product_type(NVDA) == "EQUITY"
    assert ex.product_type(NVDA) == "EQUITY"
    assert ex.client.reads[NVDA] == 1


def test_live_place_equity_limit_refuses_a_crypto_product():
    fake = FakeCreateOrder()

    refused = live(fake).place_equity_limit(
        "grid-B-1-x", XRP, "BUY", D("10"), D("0.9")
    )

    assert refused == {
        "ok": False,
        "order_id": None,
        "reason": "NOT_EQUITY_PRODUCT",
    }
    assert fake.calls == []

    lower = FakeCreateOrder()
    assert (
        live(lower, product_types={XRP: " spot "}).place_equity_limit(
            "grid-B-1-x", XRP, "BUY", D("10"), D("0.9")
        )["reason"]
        == "NOT_EQUITY_PRODUCT"
    )
    assert lower.calls == []


def test_live_place_equity_limit_requires_a_confirmation():
    cid = "cb-ai-B+0-dddddddddddd"
    args = (cid, NVDA, "BUY", D("0.001"), D("1.00"))

    for confirmation in (
        None,
        {},
        {
            "displayed_order_config": "LIMIT_GFD",
            "equity_trading_session": "EQUITY_TRADING_SESSION_EXTENDED",
        },
    ):
        client = FakeCreateOrder()
        refused = live(client, confirmation=confirmation).place_equity_limit(*args)
        assert refused == {
            "ok": False,
            "order_id": None,
            "reason": exchange_mod.EQUITY_PREVIEW_UNCONFIRMED,
        }
        assert client.calls == []  # nothing was sent

    sent = FakeCreateOrder()
    placed = live(sent, confirmation=dict(VALID_CONFIRMATION)).place_equity_limit(
        *args
    )
    assert placed["ok"] is True
    assert len(sent.calls) == 1


def test_place_equity_limit_reject():
    cid = "cb-ai-B+0-bbbbbbbbbbbb"
    args = (cid, NVDA, "BUY", D("0.5"), D("120.25"))

    priced = live(
        FakeCreateOrder(
            {
                "success": False,
                "error_response": {
                    "new_order_failure_reason": "INVALID_LIMIT_PRICE",
                    "message": "bad",
                },
            }
        )
    ).place_equity_limit(*args)
    assert priced["ok"] is False
    assert priced["order_id"] is None
    assert priced["reason"] == "INVALID_LIMIT_PRICE"
    assert priced["message"] == "bad"

    unsupported = live(
        FakeCreateOrder(
            {"success": False, "error_response": {"error": "UNSUPPORTED"}}
        )
    ).place_equity_limit(*args)
    assert unsupported["ok"] is False
    assert unsupported["order_id"] is None
    assert unsupported["reason"] == "UNSUPPORTED"

    unknown = live(
        FakeCreateOrder({"success": False, "error_response": {}})
    ).place_equity_limit(*args)
    assert unknown["ok"] is False
    assert unknown["order_id"] is None
    assert unknown["reason"] == "UNKNOWN"


def test_place_equity_limit_transient():
    def http_error(code):
        response = requests.Response()
        response.status_code = code
        return requests.exceptions.HTTPError(f"HTTP {code}", response=response)

    def refuse(error):
        client = FakeCreateOrder(error=error)
        with pytest.raises((TransientError, PermanentError)) as caught:
            live(client).place_equity_limit(
                "cb-ai-B+0-cccccccccccc", NVDA, "BUY", D("0.5"), D("120.25")
            )
        return caught.value

    assert isinstance(refuse(requests.exceptions.ConnectionError()), TransientError)
    assert isinstance(refuse(http_error(503)), TransientError)
    assert isinstance(refuse(http_error(429)), TransientError)
    assert isinstance(refuse(http_error(400)), PermanentError)


def test_dry_equity_zero_commission(monkeypatch):
    # The ask sits below the buy limit: a post-only rule would refuse this, and
    # an equity order accepts it.
    ex, markets, _ = equity_sim(monkeypatch, last="100", bid="89", ask="90")

    buy = ex.place_equity_limit("cb-ai-B+0-eq", NVDA, "BUY", D("2"), D("100.00"))
    assert buy["ok"] is True
    # the hold is exactly size * price: no commission is reserved
    assert ex.balances()["USD"] == D("800")

    markets[NVDA].last = D("99.99")
    assert ex.advance(T + 60) == ["cb-ai-B+0-eq"]
    assert ex.totals()["USD"] == D("800")
    assert ex.totals()["NVDA"] == D("2")
    fills = ex.fills(buy["order_id"])
    assert len(fills) == 1
    assert fills[0]["commission"] == D("0")
    assert fills[0]["price"] == D("100.00")
    assert fills[0]["size"] == D("2")
    assert ex.get_order(buy["order_id"])["total_fees"] == D("0")

    sell = ex.place_equity_limit("cb-ai-S+0-eq", NVDA, "SELL", D("1"), D("105"))
    assert sell["ok"] is True
    markets[NVDA].last = D("105")
    assert ex.advance(T + 120) == []  # not strictly above: no fill
    markets[NVDA].last = D("105.01")
    assert ex.advance(T + 180) == ["cb-ai-S+0-eq"]
    assert ex.totals()["USD"] == D("905")

    # The same simulator still charges the crypto fee.
    xrp = ex.place_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))
    assert xrp["ok"] is True
    markets[XRP].cs = [{"start": int(T) + 60, "low": D("0.8999"), "high": D("1")}]
    assert ex.advance(T + 240) == ["grid-B-1-x"]
    assert ex.fills(xrp["order_id"])[0]["commission"] == D("9") * FEE


def test_dry_equity_boundary_prices(monkeypatch):
    ex, markets, _ = equity_sim(monkeypatch, last="100")
    placed = ex.place_equity_limit("cb-ai-B+0-b1", NVDA, "BUY", D("1"), D("100"))
    assert placed["ok"] is True

    markets[NVDA].last = D("100")
    assert ex.advance(T + 60) == []
    markets[NVDA].last = D("99.99")
    assert ex.advance(T + 120) == ["cb-ai-B+0-b1"]


def test_dry_equity_expires_at_close_partial(monkeypatch):
    ex, markets, _ = equity_sim(monkeypatch, last="100")

    filled = ex.place_equity_limit("cb-ai-B+0-fill", NVDA, "BUY", D("1"), D("100"))
    resting = ex.place_equity_limit("cb-ai-B+1-rest", NVDA, "BUY", D("1"), D("50"))
    assert filled["ok"] is True and resting["ok"] is True

    markets[NVDA].last = D("99")
    assert ex.advance(T + 60) == ["cb-ai-B+0-fill"]
    assert ex.get_order(filled["order_id"])["status"] == "FILLED"

    # One second before the close the session is still open: the resting order stays.
    markets[NVDA].last = D("60")
    assert ex.advance(CLOSE - 1) == []
    assert ex.get_order(resting["order_id"])["status"] == "OPEN"

    # At the close it expires even though the quote would have crossed it.
    markets[NVDA].last = D("40")
    assert ex.advance(CLOSE) == []
    expired = ex.get_order(resting["order_id"])
    assert expired["status"] == "EXPIRED"
    assert expired["filled_size"] == D("0")
    assert "cb-ai-B+1-rest" not in [
        o["client_order_id"] for o in ex.list_open_orders()
    ]
    assert ex.balances()["USD"] == ex.totals()["USD"]

    # The fill that happened is kept, and it is still exactly one fill.
    still = ex.get_order(filled["order_id"])
    assert still["status"] == "FILLED"
    assert still["filled_size"] == D("1")
    assert len(ex.fills(filled["order_id"])) == 1

    # A Saturday has no session at all, so the next step expires what it placed.
    monkeypatch.setattr(exchange_mod.time, "time", lambda: SATURDAY)
    markets[NVDA].last = D("60")
    weekend = ex.place_equity_limit("cb-ai-B+2-sat", NVDA, "BUY", D("1"), D("10"))
    assert weekend["ok"] is True

    monkeypatch.setattr(exchange_mod.time, "time", lambda: T)
    markets[NVDA].last = D("5")  # would cross if the session were open
    assert ex.advance(SATURDAY + 60) == []
    assert ex.get_order(weekend["order_id"])["status"] == "EXPIRED"


def test_dry_equity_expires_past_day_orders_before_reading_the_quote(monkeypatch):
    """A quote that cannot be read still may not keep yesterday's order alive."""
    ex, markets, _ = equity_sim(monkeypatch, last="100")

    closed = ex.place_equity_limit("cb-ai-B+0-old", NVDA, "BUY", D("1"), D("50"))
    assert closed["ok"] is True

    # The next session: the same product, a different trading day.
    monkeypatch.setattr(exchange_mod.time, "time", lambda: NEXT_DAY)
    today = ex.place_equity_limit("cb-ai-B+0-new", NVDA, "BUY", D("1"), D("50"))
    assert today["ok"] is True

    class BrokenQuote(EqMkt):
        def equity_quote(self):
            raise ProductUnavailable("quote backend down")

    markets[NVDA] = BrokenQuote("100")

    assert ex.advance(NEXT_DAY + 60) == []

    # Yesterday's order expired without a quote, and took no fill with it...
    yesterday = ex.get_order(closed["order_id"])
    assert yesterday["status"] == "EXPIRED"
    assert yesterday["filled_size"] == D("0")

    # ...and today's order is untouched: its own session has not closed.
    still_open = ex.get_order(today["order_id"])
    assert still_open["status"] == "OPEN"
    assert still_open["filled_size"] == D("0")


def test_dry_wrong_path_refused(monkeypatch):
    ex, markets, _ = equity_sim(monkeypatch, last="100")

    refused = ex.place_limit("cb-ai-B+0-eq", NVDA, "BUY", D("1"), D("90"))
    assert refused["ok"] is False
    assert refused["order_id"] is None
    assert refused["reason"] == "EQUITY_USE_EQUITY_PATH"

    not_equity = ex.place_equity_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))
    assert not_equity["ok"] is False
    assert not_equity["order_id"] is None
    assert not_equity["reason"] == "NOT_EQUITY_PRODUCT"

    # With the default `is_equity` nothing is refused by place_limit.
    plain_db = new_db()
    plain = DryRunExchange(lambda: plain_db, lambda p: markets[p], FEE)
    plain.deposit("USD", D("1000"), "seed")
    plain.deposit("USDC", D("1000"), "seed")
    crypto_placed = plain.place_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))
    assert crypto_placed["ok"] is True
    equity_placed = plain.place_limit("cb-ai-B+0-eq", NVDA, "BUY", D("1"), D("90"))
    assert equity_placed["ok"] is True


def dry_sim(*, markets, is_equity=None, is_crypto=None, equity_rows=None):
    """A seeded dry-run exchange over *markets*, with whichever product hooks given."""
    db = new_db()
    ex = DryRunExchange(
        lambda: db,
        lambda product: markets[product],
        FEE,
        is_equity=is_equity,
        is_crypto=is_crypto,
        equity_rows=equity_rows,
    )
    ex.deposit("USD", D("1000"), "seed")
    ex.deposit("USDC", D("1000"), "seed")
    return ex, db


class EquityOnlyMkt:
    """A delisted symbol's market: one quote, and candles that may never be read."""

    def __init__(self, last="100"):
        self.last = D(last)
        self.quotes = 0
        self.candles_calls = 0

    def equity_quote(self):
        self.quotes += 1
        return self.last, self.last

    def candles(self, start, end):
        self.candles_calls += 1
        raise RuntimeError("candles must not be read for an equity")

    def best_bid_ask(self):
        raise RuntimeError("an equity's book is its one print")


def insert_sim_order(db, cid, product, side, price, size, created_at):
    """A resting order written straight onto the simulator's book (no place path)."""
    order_id = f"sim-{cid}"
    db.execute(
        "INSERT INTO sim_orders(order_id,client_order_id,product,side,price,size,"
        "status,created_at,fee) VALUES(?,?,?,?,?,?,'OPEN',?,'0')",
        (order_id, cid, product, side, str(price), str(size), created_at),
    )
    return order_id


def test_dry_owns_equity_rule():
    """The simulator's own rule: the configured list, then the rows, minus crypto."""
    markets = {NVDA: EqMkt("100"), VOO: EqMkt("50"), XRP: Mkt(), BTC: Mkt()}

    configured, _ = dry_sim(markets=markets, is_equity=lambda product: product == NVDA)
    assert configured.owns_equity(NVDA) is True
    assert configured.owns_equity(VOO) is False
    assert configured.owns_equity(XRP) is False

    # A delisted symbol the store still holds EQUITY rows for is still an equity.
    rows, _ = dry_sim(markets=markets, equity_rows=lambda product: product == VOO)
    assert rows.owns_equity(VOO) is True
    assert rows.owns_equity(NVDA) is False

    # The configured list wins over the rows, and a crypto-listed product is never
    # moved to the equity side whatever rows the store carries for it.
    both, _ = dry_sim(
        markets=markets,
        is_equity=lambda product: product == NVDA,
        is_crypto=lambda product: product == XRP,
        equity_rows=lambda product: product in (NVDA, VOO, XRP),
    )
    assert both.owns_equity(NVDA) is True
    assert both.owns_equity(VOO) is True
    assert both.owns_equity(XRP) is False

    # The defaults own nothing and name nothing: a plain simulator is a crypto one.
    plain, _ = dry_sim(markets=markets)
    assert callable(plain.is_crypto)
    assert callable(plain.equity_rows)
    for product in (NVDA, VOO, XRP, BTC):
        assert plain.is_crypto(product) is False
        assert plain.equity_rows(product) is False
        assert plain.owns_equity(product) is False


def test_dry_delisted_symbol_simulated_as_equity(monkeypatch):
    """A delisted symbol with EQUITY rows is stepped as an equity: no candles, no fee."""
    monkeypatch.setattr(exchange_mod.time, "time", lambda: T)
    markets = {NVDA: EquityOnlyMkt("100"), XRP: Mkt()}
    ex, db = dry_sim(
        markets=markets,
        is_equity=lambda product: product == VOO,  # NVDA is off the configured list
        equity_rows=lambda product: product == NVDA,  # ...but its rows are EQUITY rows
    )

    # A resting BUY written straight onto the sim book, inside the day's session.
    bought = insert_sim_order(db, "cb-ai-B+0-delmkt", NVDA, "BUY", "100", "2", T)
    markets[NVDA].last = D("99.99")  # strictly below the limit: it fills
    assert ex.advance(T + 60) == ["cb-ai-B+0-delmkt"]

    filled = ex.get_order(bought)
    assert filled["status"] == "FILLED"
    assert filled["total_fees"] == D("0")
    assert ex.fills(bought)[0]["commission"] == D("0")
    assert ex.totals()["NVDA"] == D("2")
    assert ex.totals()["USD"] == D("800")
    # It filled off the quote, never off a candle series the symbol has none of.
    assert markets[NVDA].quotes == 1
    assert markets[NVDA].candles_calls == 0

    # A second one expires once its session day is over, still without candles.
    resting = insert_sim_order(db, "cb-ai-B+1-delmkt", NVDA, "BUY", "50", "1", T)
    # The hold is size * price, with no commission, exactly as a listed equity's.
    assert ex.balances()["USD"] == D("800") - D("50")
    markets[NVDA].last = D("40")  # would cross it, if the session were still open
    assert ex.advance(CLOSE) == []

    expired = ex.get_order(resting)
    assert expired["status"] == "EXPIRED"
    assert expired["filled_size"] == D("0")
    assert ex.balances()["USD"] == D("800")
    # Nothing was left to fill, so the quote was not read a second time.
    assert markets[NVDA].quotes == 1
    assert markets[NVDA].candles_calls == 0


def test_dry_place_limit_refuses_owned_equity():
    """A new order follows the configured lists; the rows only steer reads."""
    markets = {NVDA: EqMkt("100"), XRP: Mkt()}
    ex, _ = dry_sim(
        markets=markets,
        is_equity=lambda product: product == VOO,
        is_crypto=lambda product: product == XRP,
        equity_rows=lambda product: product in (NVDA, XRP),
    )

    refused = ex.place_limit("cb-ai-B+0-rows", NVDA, "BUY", D("1"), D("90"))
    assert refused == {
        "ok": False,
        "order_id": None,
        "reason": "EQUITY_USE_EQUITY_PATH",
    }

    # The crypto list wins: a coin with a stray EQUITY row is still a coin.
    placed = ex.place_limit("grid-B-1-rows", XRP, "BUY", D("10"), D("0.9"))
    assert placed["ok"] is True
    assert placed["reason"] is None

    # A new equity order follows the configured list, never the store's rows.
    delisted = ex.place_equity_limit("cb-ai-B+0-rows2", NVDA, "BUY", D("1"), D("90"))
    assert delisted == {
        "ok": False,
        "order_id": None,
        "reason": "NOT_EQUITY_PRODUCT",
    }
    assert ex.list_open_orders(NVDA) == []


def test_dry_orphan_typing_via_owns_equity():
    """An untagged orphan on the dry book is typed by the simulator's own rule."""
    markets = {NVDA: EqMkt("100"), XRP: Mkt()}

    # A delisted symbol whose rows are EQUITY rows: its orphan is an EQUITY row.
    rows, _ = dry_sim(markets=markets, equity_rows=lambda product: product == NVDA)
    assert reconcile_mod._product_type_of(rows, NVDA, {}) == EQUITY

    # The same simulator with no rows hook, and the symbol off the list: SPOT.
    plain, _ = dry_sim(markets=markets, is_equity=lambda product: product == VOO)
    assert reconcile_mod._product_type_of(plain, NVDA, {}) == SPOT

    # A crypto-listed product is a coin whatever rows the store holds for it.
    crypto, _ = dry_sim(
        markets=markets,
        is_crypto=lambda product: product == NVDA,
        equity_rows=lambda product: product == NVDA,
    )
    assert reconcile_mod._product_type_of(crypto, NVDA, {}) == SPOT


def market_data(source, *, now=None, max_age=None):
    """A MarketData over a fake public client, with a fixed clock when given."""
    options = {}
    if now is not None:
        options["now"] = lambda: now
    if max_age is not None:
        options["equity_max_age_s"] = max_age
    return exchange_mod.MarketData(NVDA, client=object(), equity_last=source, **options)


def test_equity_quote_parses():
    calls = []

    def source(base):
        calls.append(base)
        return ("123.45", T)

    quoted = market_data(source, now=T + 10)
    assert quoted.equity_quote() == (D("123.45"), D("123.45"))
    price, same = quoted.equity_quote()
    assert isinstance(price, D) and price == same
    assert calls == ["NVDA", "NVDA"]

    decimal_source = market_data(lambda base: (D("123.45"), T), now=T + 10)
    assert decimal_source.equity_quote() == (D("123.45"), D("123.45"))

    unconfigured = exchange_mod.MarketData(NVDA, client=object())
    with pytest.raises(ProductUnavailable):
        unconfigured.equity_quote()


def test_equity_quote_reads_the_wall_clock_when_no_clock_is_given(monkeypatch):
    monkeypatch.setattr(exchange_mod.time, "time", lambda: T + 30)

    quoted = exchange_mod.MarketData(
        NVDA, client=object(), equity_last=lambda base: (D("10"), T)
    )

    assert quoted.equity_quote() == (D("10"), D("10"))


def test_equity_quote_refuses_a_stale_print():
    # Age is measured against the injected clock, and the bound is inclusive.
    at_the_bound = market_data(
        lambda base: (D("10"), T), now=T + DEFAULT_EQUITY_QUOTE_MAX_AGE_S
    )
    assert at_the_bound.equity_quote() == (D("10"), D("10"))

    with pytest.raises(ProductUnavailable):
        market_data(
            lambda base: (D("10"), T), now=T + DEFAULT_EQUITY_QUOTE_MAX_AGE_S + 0.5
        ).equity_quote()

    # The bound is a constructor argument, so a caller can tighten it.
    with pytest.raises(ProductUnavailable):
        market_data(lambda base: (D("10"), T), now=T + 10, max_age=5).equity_quote()
    assert market_data(lambda base: (D("10"), T), now=T + 5, max_age=5).equity_quote() == (
        D("10"),
        D("10"),
    )


def test_equity_quote_refuses_a_future_print():
    # Five seconds ahead of the clock is tolerated; more is not.
    assert market_data(lambda base: (D("10"), T + 5), now=T).equity_quote() == (
        D("10"),
        D("10"),
    )

    with pytest.raises(ProductUnavailable):
        market_data(lambda base: (D("10"), T + 6), now=T).equity_quote()
    with pytest.raises(ProductUnavailable):
        market_data(lambda base: (D("10"), T + 60), now=T).equity_quote()


def test_equity_quote_refuses_a_print_outside_the_session():
    # A previous close stamped ten minutes before the open: fresh by age, and
    # still refused, because it was not printed in the regular session.
    with pytest.raises(ProductUnavailable):
        market_data(lambda base: (D("10"), PRE_OPEN), now=PRE_OPEN + 10).equity_quote()

    # A Saturday print is no session's print either.
    with pytest.raises(ProductUnavailable):
        market_data(lambda base: (D("10"), SATURDAY), now=SATURDAY).equity_quote()

    # Nor is the closing print: the close is exclusive.
    with pytest.raises(ProductUnavailable):
        market_data(lambda base: (D("10"), CLOSE), now=CLOSE).equity_quote()

    # The bell itself is inside the session.
    assert market_data(lambda base: (D("10"), OPEN_BELL), now=OPEN_BELL).equity_quote() == (
        D("10"),
        D("10"),
    )


def test_equity_quote_refuses_a_malformed_source_answer():
    for bad in (
        None,
        "123.45",
        123.45,
        {"price": "1", "timestamp": T},
        ["123.45", T],
        ("123.45",),
        ("123.45", T, "extra"),
        ("abc", T),
        (None, T),
        (D("10"), "yesterday"),
        (D("10"), None),
        (D("10"), float("inf")),
        (D("10"), float("nan")),
    ):
        with pytest.raises(ProductUnavailable):
            market_data(lambda base, value=bad: value, now=T).equity_quote()


def test_equity_quote_refuses_a_bad_price():
    for price in ("abc", "0", "-1", 0, -1, float("inf"), float("nan")):
        with pytest.raises(ProductUnavailable):
            market_data(lambda base, value=price: (value, T), now=T).equity_quote()


def test_equity_quote_refuses_a_source_that_raises():
    def down(base):
        raise RuntimeError("quote backend down")

    with pytest.raises(ProductUnavailable):
        market_data(down, now=T).equity_quote()

    def unavailable(base):
        raise ProductUnavailable("no print for this symbol")

    with pytest.raises(ProductUnavailable):
        market_data(unavailable, now=T).equity_quote()


def test_equity_quote_source_error_text_hidden():
    """A source's own message can carry a token or a URL: only its class is reported."""
    canary = "secret-canary-token"

    def down(base):
        raise RuntimeError(f"quote backend said {canary}")

    with pytest.raises(ProductUnavailable) as failed:
        market_data(down, now=T).equity_quote()

    text = str(failed.value)
    assert "RuntimeError" in text
    assert canary not in text

    # A refusal the source itself raises is already the engine's own words.
    def unavailable(base):
        raise ProductUnavailable(f"{NVDA}: no print is available")

    with pytest.raises(ProductUnavailable) as raised:
        market_data(unavailable, now=T).equity_quote()
    assert str(raised.value) == f"{NVDA}: no print is available"


def test_merge_totals_one_pool_usd_once():
    crypto = {"USD": D("300"), "BTC": D("1"), "NVDA": D("5")}
    equity = {"USD": D("300"), "NVDA": D("2"), "VOO": D("9")}

    merged = exchange_mod.merge_totals(crypto, equity, {"NVDA"}, True)

    assert merged == {"USD": D("300"), "BTC": D("1"), "NVDA": D("2")}
    assert "VOO" not in merged

    # An owned currency the equity account does not hold is absent from the
    # result, however much of it the crypto side reports.
    dropped = exchange_mod.merge_totals(
        {"USD": D("300"), "NVDA": D("5")}, {"USD": D("10")}, {"NVDA"}, True
    )
    assert "NVDA" not in dropped


def test_merge_totals_two_pools_usd_summed():
    crypto = {"USD": D("300"), "BTC": D("1"), "NVDA": D("5")}
    equity = {"USD": D("300"), "NVDA": D("2"), "VOO": D("9")}

    merged = exchange_mod.merge_totals(crypto, equity, {"NVDA"}, False)
    assert merged["USD"] == D("600")
    assert merged["BTC"] == D("1")
    assert merged["NVDA"] == D("2")
    assert "VOO" not in merged

    crypto_without_usd = exchange_mod.merge_totals(
        {"BTC": D("1")}, {"USD": D("300")}, set(), False
    )
    assert crypto_without_usd["USD"] == D("300")
    assert "USD" not in exchange_mod.merge_totals({}, {}, set(), False)


def test_merge_totals_one_key():
    crypto = {"USD": D("300"), "BTC": D("1")}

    merged = exchange_mod.merge_totals(crypto, None, {"NVDA"}, True)

    assert merged == crypto
    assert merged is not crypto
    merged["USD"] = D("0")
    assert crypto["USD"] == D("300")


def test_check_equity_key():
    def key(**perms):
        base = {"can_transfer": False, "can_trade": True, "can_view": True}
        base.update(perms)
        return base

    # A key that can do exactly what the engine does is usable.
    assert exchange_mod.check_equity_key(key()) is None

    transfer = exchange_mod.check_equity_key(key(can_transfer=True))
    assert isinstance(transfer, str) and "transfer" in transfer.lower()

    # The transfer refusal comes first, even with trade and view refused too.
    both = exchange_mod.check_equity_key(
        key(can_transfer=True, can_trade=False, can_view=False)
    )
    assert isinstance(both, str) and "transfer" in both.lower()

    # A permission that is not exactly True is not granted: not the string, not
    # the integer, not a truthy-ish word.
    for not_granted in (False, None, "true", 1, "yes"):
        no_trade = exchange_mod.check_equity_key(key(can_trade=not_granted))
        assert isinstance(no_trade, str) and "trade" in no_trade.lower()

        no_view = exchange_mod.check_equity_key(key(can_view=not_granted))
        assert isinstance(no_view, str) and no_view

    # Trading is checked before viewing: a key that may not trade is refused for
    # that, even when it may not view either.
    both_refused = exchange_mod.check_equity_key(key(can_trade=False, can_view=False))
    assert isinstance(both_refused, str) and "trade" in both_refused.lower()

    # A permission absent from the answer is not a permission granted.
    assert exchange_mod.check_equity_key({"can_trade": True, "can_view": True}) is None
    absent_trade = exchange_mod.check_equity_key(
        {"can_transfer": False, "can_view": True}
    )
    assert isinstance(absent_trade, str) and "trade" in absent_trade.lower()
    absent_view = exchange_mod.check_equity_key(
        {"can_transfer": False, "can_trade": True}
    )
    assert isinstance(absent_view, str) and absent_view


def test_check_equity_key_portfolio():
    def key(**perms):
        base = {
            "can_transfer": False,
            "can_trade": True,
            "can_view": True,
            "portfolio_uuid": "pf-1",
        }
        base.update(perms)
        return base

    # The key's portfolio is what the equity route will trade in.
    assert exchange_mod.check_equity_key(key(), "pf-1") is None

    # A key scoped to another portfolio is refused, and says why.
    mismatch = exchange_mod.check_equity_key(key(), "pf-2")
    assert isinstance(mismatch, str) and "portfolio" in mismatch.lower()

    # A key that names no portfolio cannot be matched against one.
    unnamed = exchange_mod.check_equity_key(key(portfolio_uuid=None), "pf-1")
    assert isinstance(unnamed, str) and "portfolio" in unnamed.lower()
    absent = exchange_mod.check_equity_key(
        {"can_transfer": False, "can_trade": True, "can_view": True}, "pf-1"
    )
    assert isinstance(absent, str) and "portfolio" in absent.lower()

    # No portfolio asked for (or an empty one): the field is not compared.
    assert exchange_mod.check_equity_key(key()) is None
    assert exchange_mod.check_equity_key(key(), None) is None
    assert exchange_mod.check_equity_key(key(), "") is None
    assert exchange_mod.check_equity_key(key(portfolio_uuid="pf-9"), "") is None

    # The permission refusals come before the portfolio one.
    trade_first = exchange_mod.check_equity_key(key(can_trade=False), "pf-2")
    assert isinstance(trade_first, str) and "trade" in trade_first.lower()
    view_first = exchange_mod.check_equity_key(key(can_view=False), "pf-2")
    assert isinstance(view_first, str) and view_first


def test_live_get_order_and_fills_accept_product():
    class FakeReads:
        def get_order(self, order_id):
            return Resp(
                {
                    "order": {
                        "order_id": order_id,
                        "product_id": NVDA,
                        "side": "BUY",
                        "status": "FILLED",
                        "order_configuration": {
                            "limit_limit_gtc": {
                                "limit_price": "100",
                                "base_size": "2",
                            }
                        },
                    }
                }
            )

        def get_fills(self, order_ids=None, limit=None, cursor=None):
            return Resp(
                {
                    "fills": [
                        {
                            "trade_id": "t1",
                            "order_id": order_ids[0],
                            "product_id": NVDA,
                            "side": "BUY",
                            "size": "2",
                            "price": "100",
                            "trade_time": "2026-07-15T14:05:00Z",
                        }
                    ],
                    "cursor": "",
                }
            )

    ex = live(FakeReads())

    assert ex.get_order("o1", NVDA) == ex.get_order("o1")
    assert ex.fills("o1", NVDA) == ex.fills("o1")
