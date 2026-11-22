"""api.py and __main__.py: the HTTP surface and the process wrapper around it.

Nothing here mocks the engine's own parts.  An `Engine` comes from the real
`build_app`: a real `Store` on a temporary file, the real `DryRunExchange` over
that store's connection, the real `OrderGateway`, `Limits`, `SnapshotCache`,
`Ledger` and the real `GridStrategy` / `RebalanceStrategy`.  Only the outside
world is faked, in the shape `test_runner.py` uses: `FakeMarket` answers the book,
the poll range and the candle window the dry-run exchange fills from, and
`spec_for` hands back one `ProductSpec`.

Where a test needs the request surface real, it is real: a `TestClient` over the
app FastAPI built, no monkeypatched route, no stubbed handler.  Where a test needs
to know that a handler waited on the gateway's cycle lock, it holds that lock
itself and fires the request from a worker thread.  Money is `Decimal`
throughout, the clock is injected wherever the app reads one, and nothing opens
a socket or waits on the wall clock: the only waits are short polls against a
deadline, plus the lock probes that ask whether a request has finished yet.
"""

from __future__ import annotations

import ast
import contextlib
import csv
import io
import json
import logging
import math
import os
import threading
import time
from dataclasses import dataclass
from decimal import Decimal as D
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import crow_coinbase.api as api_module
import crow_coinbase.__main__ as main_module
from crow_coinbase import records
from crow_coinbase.__main__ import _run_runner, build_app, main
from crow_coinbase.books import APPROVAL_INVALID
from crow_coinbase.gateway import HALTED, NOT_BOT_OWNERS, PORTFOLIO_OWNER
from crow_coinbase.money import ProductSpec
from crow_coinbase.runner import StartupRefused
from crow_coinbase.store import (
    ACTIVE,
    BOT_ID_RE,
    CANCELLED,
    FILLED,
    OPEN,
    PAUSED,
    PENDING_SUBMIT,
    STOPPED,
)
from crow_coinbase.strategies.base import MarketSnapshot, OrderIntent

# 32+ characters, the shortest token the engine starts with.  Test data only.
TOKEN = "test-token-" + "x" * 32
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

ENV = {
    "CROW_COINBASE_ENGINE_TOKEN": TOKEN,
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": "XRP-USDC,BTC-USDC",
    "CROW_COINBASE_MAX_BOT_CAPITAL_USD": "100",
}

BOT = "b1"
PRODUCT = "XRP-USDC"

SPEC = ProductSpec(
    PRODUCT,
    price_increment=D("0.0001"),
    base_increment=D("0.1"),
    quote_increment=D("0.01"),
    base_min_size=D("1"),
    quote_min_size=D("1"),
)

GRID_PARAMS = {
    "center": "1.0",
    "step_pct": "1.5",
    "levels_below": 3,
    "levels_above": 3,
    "quote_per_buy": "10",
    "rebuy_sizing": "proceeds",
}

REBALANCE_PARAMS = {
    "target_base_pct": 50,
    "band_pts": 7.5,
    "min_trade_quote": 2,
    "reprice_after_s": 600,
}

CREATE_BODY = {
    "id": BOT,
    "product": PRODUCT,
    "strategy": "grid",
    "params": GRID_PARAMS,
    "capital_quote": "60",
    "capital_base": "30",
}


# ---------------------------------------------------------------- the outside world


class FakeMarket:
    """A fixed book, a fixed poll range and a scripted candle list."""

    def __init__(self, bid=D("0.99"), ask=D("1.00")):
        self.bid, self.ask = D(bid), D(ask)
        self.low, self.high = self.bid, self.ask
        self.candle_rows = []

    def best_bid_ask(self):
        return self.bid, self.ask

    def range_since(self, since):
        return self.low, self.high

    def candles(self, start, end):
        return list(self.candle_rows)


def trade_through(market, *, low, high):
    """Append one candle that starts after every order already on the book."""
    market.candle_rows.append(
        {"start": time.time() + 1, "low": D(low), "high": D(high)}
    )


class Books:
    """The market cache handed to `build_app`: one `FakeMarket` per product."""

    def __init__(self):
        self.markets = {}

    def market_for(self, product):
        return self.markets.setdefault(product, FakeMarket())

    def __getitem__(self, product):
        return self.markets[product]


# ---------------------------------------------------------------- the engine


@dataclass
class Harness:
    """One built engine plus the market cache its exchange polls."""

    engine: object
    books: Books


def _open_approval_create_app(**kwargs):
    """`create_app` with the approval rail open (the handlers are what is under test)."""
    kwargs.setdefault("require_privileged", lambda request: None)
    return api_module.create_app(**kwargs)


def make_engine(root, *, now=time.time, env=None):
    """Build the real engine on a temporary data dir, with the outside world faked.

    The privileged routes (`/bots/{id}/mode`, `/switches`, `/halt/clear`) are
    reached through their handlers here, so the app is built with an approval
    that accepts: deny-by-default is covered by `test_books.py`.
    """
    data_dir = Path(root)
    data_dir.mkdir(parents=True, exist_ok=True)
    books = Books()
    real_create_app = main_module.create_app
    main_module.create_app = _open_approval_create_app
    try:
        engine = build_app(
            dict(ENV) if env is None else dict(env),
            data_dir=data_dir,
            market_for=books.market_for,
            spec_for=lambda product: SPEC,
            now=now,
        )
    finally:
        main_module.create_app = real_create_app
    return Harness(engine, books)


@contextlib.contextmanager
def api(engine):
    """A `TestClient` whose every request carries the bearer token."""
    with TestClient(engine.app, raise_server_exceptions=False) as client:
        client.headers.update(HEADERS)
        yield client


@contextlib.contextmanager
def raw_api(engine):
    """A `TestClient` with no default header: the auth tests send their own."""
    with TestClient(engine.app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def harness(tmp_path):
    return make_engine(tmp_path / "data")


@pytest.fixture
def engine(harness):
    return harness.engine


@pytest.fixture
def client(engine):
    with api(engine) as open_client:
        yield open_client


# ---------------------------------------------------------------- helpers


def wait_for(predicate, timeout):
    """Poll *predicate* until it holds or the deadline passes."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def count_rows(engine, table):
    return engine.store.conn().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def fetch(engine, sql):
    return engine.store.conn().execute(sql).fetchall()


def currencies(engine):
    return {row[0] for row in fetch(engine, "SELECT currency FROM sim_balances")}


def bot_row(engine, bot_id=BOT):
    return engine.store.get_bot(bot_id)


def detail_text(response):
    """A refusal message as text, whether the app answered a string or a list."""
    detail = response.json().get("detail")
    return detail if isinstance(detail, str) else json.dumps(detail)


ROUTES = [
    ("GET", "/status"),
    ("GET", "/balances"),
    ("GET", "/bots"),
    ("GET", "/orders"),
    ("GET", "/pnl"),
    ("GET", "/export/fills.csv"),
    ("GET", "/bots/b1/fills"),
    ("POST", "/bots"),
    ("POST", "/bots/b1/pause"),
    ("POST", "/bots/b1/resume"),
    ("POST", "/bots/b1/stop"),
    ("POST", "/bots/b1/recenter"),
    ("POST", "/kill"),
    ("POST", "/halt/clear"),
]

ROUTE_BODIES = {
    "/bots": CREATE_BODY,
    "/bots/b1/recenter": {"center": "1.1"},
}

# The acknowledgement every high-water-mark route demands, spelled once.
ACK = {"acknowledge_rebase": True}


def price_at(engine, bid, ask):
    """Put one fresh, usable snapshot in the cache the way a poll writes it."""
    engine.gateway.snapshots.put(
        MarketSnapshot(PRODUCT, D(bid), D(ask), D(bid), D(ask), time.time())
    )

BAD_HEADERS = [
    None,
    {"Authorization": "Bearer wrong-token"},
    {"Authorization": f"Basic {TOKEN}"},
]


def send(client, method, path, headers):
    """One request; *headers* replaces the client's defaults when given."""
    extra = {} if headers is None else {"headers": headers}
    body = ROUTE_BODIES.get(path)
    if method == "POST" and body is not None:
        return client.request(method, path, json=body, **extra)
    return client.request(method, path, **extra)


# ---------------------------------------------------------------- auth


@pytest.mark.parametrize("method,path", ROUTES)
def test_routes_require_token(engine, method, path):
    with raw_api(engine) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert set(health.json()) == HEALTH_KEYS

        for headers in BAD_HEADERS:
            response = send(client, method, path, headers)
            assert response.status_code == 401, f"{method} {path} without {headers}"
            assert response.json() == {"detail": "unauthorized"}
            assert response.headers.get("www-authenticate") == "Bearer"

    # Nothing was written by any of them.
    assert engine.store.list_bots() == []
    assert engine.store.get("halted") is None
    assert engine.gateway.is_halted() is False


def to_text(value):
    """A header value or token as text, whether it arrived as bytes or as str."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def dotted(node):
    """The dotted spelling of a Name/Attribute/Call chain, else ""."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def token_comparisons(source):
    """Every ==/!= in *source* that has an operand naming the token."""
    offenders = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            continue
        operands = [node.left, *node.comparators]
        if any("token" in dotted(operand) for operand in operands):
            offenders.append(ast.unparse(node))
    return offenders


def test_compare_digest_used(engine, monkeypatch):
    real = api_module.hmac.compare_digest
    seen = []

    def spy(left, right):
        seen.append((left, right))
        return real(left, right)

    monkeypatch.setattr(api_module.hmac, "compare_digest", spy)

    with raw_api(engine) as client:
        good = client.get("/status", headers=HEADERS)
        assert good.status_code == 200
        assert seen, "compare_digest was not called for an authenticated request"
        assert any(
            TOKEN in (to_text(left), to_text(right)) for left, right in seen
        ), "the presented token never reached compare_digest"

        before = len(seen)
        bare = client.get("/status")
        assert bare.status_code == 401
        assert len(seen) > before, "a missing header skipped compare_digest"

    source = Path(api_module.__file__).read_text(encoding="utf-8")
    assert "compare_digest" in source
    offenders = token_comparisons(source)
    assert offenders == [], f"the token is compared with ==/!=: {offenders}"


def dependency_names(dependant):
    """Every dependency callable's `__name__` in *dependant*, however deep."""
    names = set()
    for sub in getattr(dependant, "dependencies", ()) or ():
        call = getattr(sub, "call", None)
        if call is not None:
            names.add(getattr(call, "__name__", ""))
        names |= dependency_names(sub)
    return names


def route_dependency_names(route):
    """The names of the callables a route depends on, both spellings FastAPI uses."""
    names = dependency_names(getattr(route, "dependant", None))
    for dep in getattr(route, "dependencies", ()) or ():
        target = getattr(dep, "dependency", dep)
        names.add(getattr(target, "__name__", ""))
    return names


def test_every_route_except_health_is_guarded_and_docs_404(engine):
    guarded = []
    for route in engine.app.routes:
        path = getattr(route, "path", "")
        if path == "/health":
            continue
        names = route_dependency_names(route)
        assert "_check_token" in names, (
            f"{path} carries no auth dependency: {sorted(names)}"
        )
        guarded.append(path)

    # The walk is not vacuous: the surface really is that wide.
    assert len(guarded) >= 13, guarded
    for path in ("/status", "/bots", "/bots/{bot_id}/stop", "/kill", "/pnl"):
        assert path in guarded, f"{path} is not one of the guarded routes"

    with raw_api(engine) as anonymous:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert anonymous.get(path).status_code == 404, path
            assert anonymous.get(path, headers=HEADERS).status_code == 404, path


# ---------------------------------------------------------------- startup


def test_refuses_start_without_token(tmp_path):
    missing = {k: v for k, v in ENV.items() if k != "CROW_COINBASE_ENGINE_TOKEN"}
    blanks = [
        missing,
        dict(ENV, CROW_COINBASE_ENGINE_TOKEN=""),
        dict(ENV, CROW_COINBASE_ENGINE_TOKEN="   "),
    ]
    for index, env in enumerate(blanks):
        data_dir = tmp_path / f"refused-{index}"
        with pytest.raises(StartupRefused):
            build_app(env, data_dir=data_dir)
        assert not (data_dir / "engine.sqlite").exists()

    engine = make_engine(tmp_path / "pieces").engine
    with pytest.raises(StartupRefused):
        api_module.create_app(
            store=engine.store,
            gateway=engine.gateway,
            runner=engine.runner,
            exchange=engine.exchange,
            strategies=engine.runner.strategies,
            limits=engine.limits,
            spec_for=engine.runner.spec_for,
            price_for=lambda product: D("1"),
            token=None,
            heartbeat_path=engine.runner.heartbeat_path,
        )

    assert (
        main(
            dict(missing, CROW_COINBASE_DATA_DIR=str(tmp_path / "no-token")),
            build=build_app,
        )
        == 3
    )


BAD_TOKENS = [
    ("too-short", "short"),
    ("one-char-short", "x" * 31),
    ("space-inside", "a" * 16 + " " + "b" * 20),
    ("trailing-newline", "x" * 39 + "\n"),
    ("tab-inside", "x" * 20 + "\t" + "y" * 20),
]


@pytest.mark.parametrize("case,token", BAD_TOKENS, ids=[c for c, _ in BAD_TOKENS])
def test_token_rejects_whitespace_and_short(tmp_path, case, token):
    data_dir = tmp_path / case
    with pytest.raises(StartupRefused):
        build_app(dict(ENV, CROW_COINBASE_ENGINE_TOKEN=token), data_dir=data_dir)
    assert not (data_dir / "engine.sqlite").exists()

    # Exactly 32 characters is the shortest token this engine starts with, and
    # it still has to be presented byte for byte.
    accepted = "x" * 32
    engine = build_app(
        dict(ENV, CROW_COINBASE_ENGINE_TOKEN=accepted),
        data_dir=tmp_path / "exact",
    )
    with raw_api(engine) as anonymous:
        good = anonymous.get(
            "/status", headers={"Authorization": f"Bearer {accepted}"}
        )
        assert good.status_code == 200, good.text
        wrong = anonymous.get(
            "/status", headers={"Authorization": f"Bearer {'y' * 32}"}
        )
        assert wrong.status_code == 401
        assert wrong.json() == {"detail": "unauthorized"}


# ---------------------------------------------------------------- POST /bots


def test_create_bot_validation_rejects_bad_id_product_params_fee_guard_and_over_cap(
    engine, client
):
    bad_bodies = [
        dict(CREATE_BODY, id="UPPER"),
        dict(CREATE_BODY, id="has-dash"),
        dict(CREATE_BODY, id=""),
        dict(CREATE_BODY, id="x" * 17),
        dict(CREATE_BODY, id="ai"),
        dict(CREATE_BODY, id="orphan"),
        dict(CREATE_BODY, product="DOGE-USDC"),
        dict(CREATE_BODY, strategy="martingale"),
        dict(CREATE_BODY, params=dict(GRID_PARAMS, step_pct="0.5")),
        dict(
            CREATE_BODY,
            params={k: v for k, v in GRID_PARAMS.items() if k != "center"},
        ),
        dict(CREATE_BODY, params=dict(GRID_PARAMS, levels_below=0)),
        dict(CREATE_BODY, capital_quote="150", capital_base="0"),
        dict(CREATE_BODY, capital_quote="60", capital_base="60"),
        dict(CREATE_BODY, capital_quote="0", capital_base="0"),
        dict(CREATE_BODY, mode="live"),
    ]
    for body in bad_bodies:
        assert client.post("/bots", json=body).status_code == 422, body

    fee = client.post(
        "/bots", json=dict(CREATE_BODY, params=dict(GRID_PARAMS, step_pct="0.5"))
    )
    assert fee.status_code == 422
    assert "step" in detail_text(fee) and "0.5" in detail_text(fee)

    assert engine.store.list_bots() == []
    assert count_rows(engine, "sim_deposits") == 0

    created = client.post("/bots", json=CREATE_BODY)
    assert created.status_code == 201
    body = created.json()
    assert body["id"] == BOT
    assert body["status"] == ACTIVE
    assert body["init_done"] is False
    assert bot_row(engine)["status"] == ACTIVE
    assert bot_row(engine)["init_done"] is False

    balances = client.get("/balances").json()
    assert D(balances["totals"]["USDC"]) == D("60")
    assert D(balances["totals"]["XRP"]) == D("30")
    assert D(balances["unallocated"]["USDC"]) == D("0")
    assert D(balances["unallocated"]["XRP"]) == D("0")
    assert balances["owners"][BOT]["product"] == PRODUCT
    # The live book reports whether it has an exchange at all, and no numbers.
    assert balances["live"] == {"available": False}


def test_bot_id_reuse_refused(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    deposits = count_rows(engine, "sim_deposits")
    assert deposits == 2  # the quote seed and the base seed

    assert client.post("/bots", json=CREATE_BODY).status_code == 409

    engine.store.update_hwm("ghost", D("1"))
    assert client.post("/bots", json=dict(CREATE_BODY, id="ghost")).status_code == 409

    engine.store.put("bench:dry:ghost2", None)
    assert client.post("/bots", json=dict(CREATE_BODY, id="ghost2")).status_code == 409

    # A P1 benchmark record still counts as a history this id belongs to.
    engine.store.put("benchmark:ghost4", None)
    assert client.post("/bots", json=dict(CREATE_BODY, id="ghost4")).status_code == 409

    engine.store.insert_order(
        "cb-ghost3-B-1-000000000001",
        "ghost3",
        "bot",
        PRODUCT,
        "BUY",
        -1,
        D("0.9852"),
        D("10"),
        status=OPEN,
        book="dry",
    )
    assert client.post("/bots", json=dict(CREATE_BODY, id="ghost3")).status_code == 409

    assert [row["id"] for row in engine.store.list_bots()] == [BOT]
    assert count_rows(engine, "sim_deposits") == deposits


def test_portfolio_id_rejected(engine, client):
    response = client.post("/bots", json=dict(CREATE_BODY, id=PORTFOLIO_OWNER))
    assert response.status_code == 422
    assert engine.store.list_bots() == []
    assert count_rows(engine, "sim_deposits") == 0
    assert BOT_ID_RE.fullmatch(PORTFOLIO_OWNER) is None
    assert PORTFOLIO_OWNER in NOT_BOT_OWNERS


def test_seed_dry_called_once_in_creation_tx(tmp_path):
    engine = make_engine(tmp_path / "counting").engine
    with api(engine) as client:
        calls = []
        real_seed = engine.gateway.seed_dry

        def counting_seed(owner, quote, base):
            calls.append(
                (owner, quote, base, engine.store.conn().in_transaction)
            )
            return real_seed(owner, quote, base)

        engine.gateway.seed_dry = counting_seed

        over_cap = dict(CREATE_BODY, capital_quote="150", capital_base="0")
        assert client.post("/bots", json=over_cap).status_code == 422
        assert calls == []

        assert client.post("/bots", json=CREATE_BODY).status_code == 201
        assert calls == [(BOT, D("60"), D("30"), True)]

    # A seed that deposits and then blows up rolls the bot row back with it.
    other = make_engine(tmp_path / "rollback").engine
    with api(other) as client:
        real_seed = other.gateway.seed_dry

        def exploding_seed(owner, quote, base):
            real_seed(owner, quote, base)
            raise RuntimeError("seed exploded")

        other.gateway.seed_dry = exploding_seed
        failed = client.post("/bots", json=CREATE_BODY)
        assert failed.status_code == 500
        assert other.store.list_bots() == []
        assert count_rows(other, "sim_deposits") == 0
        assert (currencies(other) & {"USDC", "XRP"}) == set()

        other.gateway.seed_dry = real_seed
        again = client.post("/bots", json=CREATE_BODY)
        assert again.status_code == 201
        assert [row["id"] for row in other.store.list_bots()] == [BOT]
        assert count_rows(other, "sim_deposits") == 2


def test_create_bot_500_detail_is_generic(engine, client):
    def exploding_seed(owner, quote, base):
        raise RuntimeError("secret-internal-detail /tmp/x.sqlite")

    engine.gateway.seed_dry = exploding_seed
    failed = client.post("/bots", json=CREATE_BODY)
    assert failed.status_code == 500
    assert failed.json()["detail"] == "bot creation failed"
    assert "secret-internal-detail" not in failed.text
    assert "/tmp/x.sqlite" not in failed.text
    assert engine.store.list_bots() == []
    assert count_rows(engine, "sim_deposits") == 0


BAD_BOOKS = [
    ("zero-bid-ask", D("0"), D("0")),
    ("crossed", D("1.10"), D("1.00")),
    ("nan-bid", D("NaN"), D("1.00")),
    ("infinite-ask", D("0.99"), D("Infinity")),
]


@pytest.mark.parametrize("case,bid,ask", BAD_BOOKS, ids=[c for c, _, _ in BAD_BOOKS])
def test_price_for_rejects_bad_book(tmp_path, case, bid, ask):
    books = Books()
    books.markets[PRODUCT] = FakeMarket(bid=bid, ask=ask)
    data_dir = tmp_path / case
    data_dir.mkdir(parents=True, exist_ok=True)
    engine = build_app(
        dict(ENV),
        data_dir=data_dir,
        market_for=books.market_for,
        spec_for=lambda product: SPEC,
    )
    # No poll has happened, so the fallback to the book is the one in play.
    assert engine.gateway.snapshots.get(PRODUCT) is None

    with api(engine) as client:
        response = client.post("/bots", json=CREATE_BODY)
        assert response.status_code == 503, response.text
        assert engine.store.list_bots() == []
        assert count_rows(engine, "sim_deposits") == 0


OVER_BOUND_CASES = [
    ("capital_quote", "-1"),
    ("capital_quote", "NaN"),
    ("capital_quote", "Infinity"),
    ("capital_quote", "1e999999999"),
    ("capital_quote", True),
    ("center", "1e999999999"),
    ("center", "NaN"),
    ("center", "Infinity"),
    ("center", "-1"),
    ("center", "0"),
    ("center", True),
]


@pytest.mark.parametrize(
    "where,value", OVER_BOUND_CASES, ids=[f"{w}={v!r}" for w, v in OVER_BOUND_CASES]
)
def test_amounts_over_bounds_rejected(engine, client, where, value):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.store.set_init_done(BOT)
    params_before = bot_row(engine)["params"]

    if where == "capital_quote":
        body = dict(CREATE_BODY, id="b2", capital_quote=value)
        response = client.post("/bots", json=body)
        assert response.status_code == 422, response.text
        assert [row["id"] for row in engine.store.list_bots()] == [BOT]
        assert count_rows(engine, "sim_deposits") == 2
        assert bot_row(engine)["params"] == params_before
    else:
        response = client.post("/bots/b1/recenter", json={"center": value})
        assert response.status_code == 422, response.text
        assert bot_row(engine)["params"] == params_before
        assert bot_row(engine)["params"]["center"] == "1.0"
        assert bot_row(engine)["init_done"] is True


# ---------------------------------------------------------------- the cycle lock


MUTATORS = ("create", "pause", "resume", "stop", "recenter", "halt-clear", "kill")


@pytest.mark.parametrize("case", MUTATORS)
def test_mutators_take_gateway_lock(engine, client, case):
    if case != "create":
        assert client.post("/bots", json=CREATE_BODY).status_code == 201
    if case == "resume":
        # Resuming re-bases the bot's mark, so its equity has to be priceable.
        price_at(engine, "0.99", "1.00")
        assert client.post("/bots/b1/pause").status_code == 200
        assert bot_row(engine)["status"] == PAUSED
    if case == "recenter":
        engine.store.set_init_done(BOT)
    if case == "halt-clear":
        # Clearing a halt re-bases the portfolio mark, so its equity has to be
        # priceable: a poll's snapshot is what makes it so.
        price_at(engine, "0.99", "1.00")
        engine.gateway.halt("held by the test")
        assert engine.gateway.is_halted() is True

    def fire():
        if case == "create":
            return client.post("/bots", json=CREATE_BODY)
        if case == "pause":
            return client.post("/bots/b1/pause")
        if case == "resume":
            return client.post("/bots/b1/resume", json=ACK)
        if case == "stop":
            return client.post("/bots/b1/stop")
        if case == "recenter":
            return client.post("/bots/b1/recenter", json={"center": "1.1"})
        if case == "halt-clear":
            return client.post("/halt/clear", json=ACK)
        return client.post("/kill")

    done = threading.Event()
    answers = []

    def worker():
        try:
            answers.append(fire())
        except BaseException as error:  # noqa: BLE001 - reported to the test thread
            answers.append(error)
        finally:
            done.set()

    with engine.gateway.lock:
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        if case == "kill":
            # The halt never queues behind the lock; the sweep does.
            assert wait_for(engine.gateway.is_halted, 2.0), "kill did not halt"
            assert not done.is_set(), "kill completed while the lock was held"
            assert bot_row(engine)["status"] == ACTIVE
        else:
            assert not done.wait(0.3), f"{case}: completed while the lock was held"
        # The request is not waiting on the transport: a lock-free route answers.
        assert client.get("/health").status_code in (200, 503)
        if case == "create":
            assert engine.store.list_bots() == []
        elif case == "resume":
            assert bot_row(engine)["status"] == PAUSED
        elif case == "recenter":
            assert bot_row(engine)["params"]["center"] == "1.0"
            assert bot_row(engine)["init_done"] is True
        elif case == "halt-clear":
            assert engine.gateway.is_halted() is True
        elif case != "kill":
            assert bot_row(engine)["status"] == ACTIVE

    thread.join(timeout=10)
    assert not thread.is_alive()
    assert done.is_set()
    answer = answers[0]
    assert not isinstance(answer, BaseException), answer
    assert answer.status_code == (201 if case == "create" else 200)

    if case == "create":
        assert [row["id"] for row in engine.store.list_bots()] == [BOT]
    elif case == "pause":
        assert bot_row(engine)["status"] == PAUSED
    elif case == "resume":
        assert bot_row(engine)["status"] == ACTIVE
    elif case == "stop":
        assert bot_row(engine)["status"] == STOPPED
    elif case == "recenter":
        assert bot_row(engine)["params"]["center"] == "1.1"
        assert bot_row(engine)["init_done"] is False
    elif case == "halt-clear":
        assert engine.gateway.is_halted() is False
    else:
        assert engine.gateway.is_halted() is True
        assert bot_row(engine)["status"] == STOPPED


# ---------------------------------------------------------------- stop and kill


def test_stop_cancels_only_that_bot(engine, client):
    for bot_id in ("b1", "b2"):
        body = dict(CREATE_BODY, id=bot_id, capital_quote="40", capital_base="10")
        assert client.post("/bots", json=body).status_code == 201

    engine.runner.cycle()

    for bot_id in ("b1", "b2"):
        assert engine.store.orders(
            owner=bot_id, statuses=(OPEN,)
        ), f"{bot_id} placed no initial book"
    book = {order["client_order_id"] for order in engine.exchange.list_open_orders()}
    assert any(cid.startswith("cb-b1-") for cid in book)
    assert any(cid.startswith("cb-b2-") for cid in book)

    assert client.post("/bots/b1/stop").status_code == 200
    assert bot_row(engine, "b1")["status"] == STOPPED

    after = {order["client_order_id"] for order in engine.exchange.list_open_orders()}
    assert [cid for cid in after if cid.startswith("cb-b1-")] == []
    assert bot_row(engine, "b2")["status"] == ACTIVE
    b2_rows = engine.store.orders(owner="b2", statuses=(OPEN,))
    assert {row["client_order_id"] for row in b2_rows} == {
        cid for cid in after if cid.startswith("cb-b2-")
    }
    assert b2_rows


def test_kill_then_submit_refused(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()
    assert engine.store.orders(owner=BOT, statuses=(OPEN,))

    killed = client.post("/kill")
    assert killed.status_code == 200
    assert killed.json()["halted"] is True
    assert engine.store.get("halted")
    assert bot_row(engine)["status"] == STOPPED
    assert [
        order["client_order_id"]
        for order in engine.exchange.list_open_orders()
        if str(order["client_order_id"]).startswith("cb-")
    ] == []

    intent = OrderIntent(
        action="place",
        side="BUY",
        size=D("3"),
        limit_price=D("0.98"),
        level=-1,
        cancel_cid=None,
        reason="kill switch probe",
    )
    result = engine.gateway.submit("bot", BOT, intent)
    assert result.ok is False
    assert result.refusal == HALTED

    status = client.get("/status").json()
    assert status["halted"] is True
    assert status["bots"][0]["status"] == STOPPED

    cleared = client.post("/halt/clear", json=ACK)
    assert cleared.status_code == 200
    assert cleared.json()["halted"] is False
    assert client.get("/status").json()["halted"] is False
    assert bot_row(engine)["status"] == STOPPED

    def failing_sweep(scope, owner=None):
        raise RuntimeError("boom")

    engine.gateway.cancel_all = failing_sweep
    broken = client.post("/kill")
    assert broken.status_code == 502
    assert broken.json()["halted"] is True
    assert engine.gateway.is_halted() is True
    assert bot_row(engine)["status"] == STOPPED


def swept_cb_orders(engine):
    return [
        str(order["client_order_id"])
        for order in engine.exchange.list_open_orders()
        if str(order["client_order_id"]).startswith("cb-")
    ]


def test_kill_never_aborts_on_store_failure(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    other = dict(CREATE_BODY, id="b2", capital_quote="40", capital_base="10")
    assert client.post("/bots", json=other).status_code == 201
    engine.runner.cycle()
    book = swept_cb_orders(engine)
    assert any(cid.startswith("cb-b1-") for cid in book)
    assert any(cid.startswith("cb-b2-") for cid in book)

    real_status = engine.store.set_bot_status
    attempts = []

    def store_fails_for_one_bot(bot_id, status):
        attempts.append((bot_id, status))
        if bot_id == BOT:
            raise RuntimeError("the bots table is not writable for b1")
        return real_status(bot_id, status)

    engine.store.set_bot_status = store_fails_for_one_bot
    try:
        killed = client.post("/kill")
    finally:
        engine.store.set_bot_status = real_status

    assert killed.status_code == 502, killed.text
    body = killed.json()
    assert body["halted"] is True
    assert isinstance(body["detail"], str) and body["detail"]

    # One failing write did not end the sweep: every bot was still attempted,
    # and the one whose write went through really is STOPPED.
    assert {bot_id for bot_id, _ in attempts} == {BOT, "b2"}
    assert {status for _, status in attempts} == {STOPPED}
    assert bot_row(engine, "b2")["status"] == STOPPED

    assert engine.gateway.is_halted() is True
    assert swept_cb_orders(engine) == []


def test_kill_halt_failure_still_sweeps_and_stops(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()
    assert [cid for cid in swept_cb_orders(engine) if cid.startswith("cb-b1-")]

    real_halt = engine.gateway.halt

    def failing_halt(reason):
        raise RuntimeError("the halt flag could not be persisted")

    engine.gateway.halt = failing_halt
    try:
        killed = client.post("/kill")
    finally:
        engine.gateway.halt = real_halt

    assert killed.status_code == 502, killed.text
    body = killed.json()
    assert body["halted"] is True
    assert isinstance(body["detail"], str) and body["detail"]

    # The halt failed, so the sweep and the stops have to happen anyway.
    assert bot_row(engine)["status"] == STOPPED
    assert swept_cb_orders(engine) == []


def test_stop_marks_stopped_even_when_cancel_fails(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()
    assert engine.store.orders(owner=BOT, statuses=(OPEN,))

    real_cancel_all = engine.gateway.cancel_all

    def failing_sweep(scope, owner=None):
        raise RuntimeError("the sweep died")

    engine.gateway.cancel_all = failing_sweep
    try:
        stopped = client.post("/bots/b1/stop")
    finally:
        engine.gateway.cancel_all = real_cancel_all

    assert stopped.status_code == 502, stopped.text
    detail = stopped.json().get("detail")
    assert isinstance(detail, str) and detail

    # A stop whose sweep failed still leaves the bot stopped: the reconcile loop
    # sweeps a STOPPED owner's book, so a retry is not needed to get out of it.
    assert bot_row(engine)["status"] == STOPPED

    again = client.post("/bots/b1/stop")
    assert again.status_code == 200
    assert bot_row(engine)["status"] == STOPPED


# ---------------------------------------------------------------- rebasing recovery


def book_rows(engine, bot_id=BOT):
    """This bot's order rows as {cid: (status, opposite)}, for a before/after."""
    return {
        row["client_order_id"]: (row["status"], row["opposite"])
        for row in engine.store.orders(owner=bot_id)
    }


def test_halt_clear_without_the_acknowledgement_writes_nothing(engine, client):
    """No body, or a false field, is a 409 and nothing is written."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()
    engine.gateway.halt("held by the test")
    mark = engine.store.hwm(PORTFOLIO_OWNER)
    assert mark is not None
    rows_before = book_rows(engine)

    refusals = [
        client.post("/halt/clear"),
        client.post("/halt/clear", json={"acknowledge_rebase": False}),
    ]
    for response in refusals:
        assert response.status_code == 409, response.text
        detail = detail_text(response)
        assert "acknowledge_rebase" in detail
        assert "high-water mark" in detail
        assert engine.gateway.is_halted() is True
        assert engine.store.get("halted") is not None
        assert engine.store.hwm(PORTFOLIO_OWNER) == mark
        assert book_rows(engine) == rows_before

    # Only a JSON true acknowledges: the string is refused, not coerced.
    coerced = client.post("/halt/clear", json={"acknowledge_rebase": "true"})
    assert coerced.status_code == 422, coerced.text
    assert engine.gateway.is_halted() is True


def test_halt_clear_with_unknown_equity_resets_the_mark(engine, client):
    """A book that cannot be priced is cleared with its mark reset, not blocked."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()
    engine.gateway.halt("held by the test")
    mark = engine.store.hwm(PORTFOLIO_OWNER)
    assert mark is not None

    # A crossed book is unusable, which is what makes the equity unknown.
    engine.gateway.snapshots.put(
        MarketSnapshot(
            PRODUCT, D("1.02"), D("1.00"), D("1.00"), D("1.02"), time.time()
        )
    )
    assert engine.gateway.portfolio_equity() is None

    response = client.post("/halt/clear", json=ACK)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["halted"] is False
    # The entry is still there and says null: no number was written for a book
    # nothing could price.
    assert body["rebased"] == {f"{PORTFOLIO_OWNER}:dry": None}
    # The mark is reset rather than left at the value the stop fired on, so the
    # next priced cycle ratchets a fresh one.
    assert engine.store.hwm(PORTFOLIO_OWNER) is None
    assert engine.store.get("halted") is None
    assert engine.gateway.is_halted() is False


def test_halt_clear_rebases_and_reinitialises_every_grid(engine, client):
    """With the ack: the mark comes down and every live grid re-inits its book."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    rebalancing = dict(
        CREATE_BODY, id="r1", strategy="rebalance", params=REBALANCE_PARAMS
    )
    assert client.post("/bots", json=rebalancing).status_code == 201
    small = dict(CREATE_BODY, id="b2", capital_quote="20", capital_base="5")
    assert client.post("/bots", json=small).status_code == 201

    engine.runner.cycle()  # every bot gets its first book
    assert engine.store.orders(owner=BOT, statuses=(OPEN,))
    assert client.post("/bots/b2/stop").status_code == 200
    assert bot_row(engine, "b2")["status"] == STOPPED
    engine.runner.cycle()
    r1_rows_before = book_rows(engine, "r1")
    r1_params_before = bot_row(engine, "r1")["params"]

    price_at(engine, "0.99", "1.00")
    mark = engine.store.hwm(PORTFOLIO_OWNER)
    assert mark is not None
    engine.gateway.halt("held by the test")

    price_at(engine, "0.30", "0.31")
    equity = engine.gateway.portfolio_equity()
    assert equity is not None and equity < mark

    cleared = client.post("/halt/clear", json=ACK)
    assert cleared.status_code == 200, cleared.text
    body = cleared.json()
    assert body["halted"] is False
    assert str(equity) in body["rebased"].values()
    # The grid that is not stopped re-initialises; a stopped grid and a
    # rebalancer have no grid to lay.
    assert body["reinitialised"] == [BOT]

    assert engine.store.hwm(PORTFOLIO_OWNER) == equity
    assert engine.store.hwm(PORTFOLIO_OWNER) < mark
    assert engine.store.get("halted") is None
    assert engine.gateway.is_halted() is False

    reinitialised = bot_row(engine)
    assert reinitialised["init_done"] is False
    assert reinitialised["status"] == ACTIVE
    assert reinitialised["params"] == GRID_PARAMS
    assert isinstance(engine.store.get("runner:init_since:b1"), (int, float))
    assert bot_row(engine, "b2")["status"] == STOPPED
    # A rebalancer has no book of its own to lay: nothing about it is re-inited.
    assert bot_row(engine, "r1")["init_done"] is True
    assert bot_row(engine, "r1")["params"] == r1_params_before
    assert r1_rows_before  # there was a rebalancer book for the clear to leave be


def test_halt_clear_reinit_failure_answers_502_and_keeps_the_halt(
    engine, client, monkeypatch
):
    """A grid that cannot re-init holds the halt and the mark where they were."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()
    engine.gateway.halt("held by the test")
    mark = engine.store.hwm(PORTFOLIO_OWNER)
    rows_before = book_rows(engine)

    def failing_reinit(bot_id):
        raise RuntimeError("orders still live after the sweeps")

    monkeypatch.setattr(engine.runner, "reinit_bot", failing_reinit)
    response = client.post("/halt/clear", json=ACK)

    assert response.status_code == 502, response.text
    assert "the halt stays" in detail_text(response)
    assert engine.gateway.is_halted() is True
    assert engine.store.get("halted") is not None
    assert engine.store.hwm(PORTFOLIO_OWNER) == mark
    assert book_rows(engine) == rows_before


def test_resume_without_the_acknowledgement_keeps_the_bot_paused(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    assert client.post("/bots/b1/pause").status_code == 200
    mark = engine.store.hwm(BOT)

    for response in (
        client.post("/bots/b1/resume"),
        client.post("/bots/b1/resume", json={"acknowledge_rebase": False}),
    ):
        assert response.status_code == 409, response.text
        detail = detail_text(response)
        assert "acknowledge_rebase" in detail
        assert "high-water mark" in detail
        assert bot_row(engine)["status"] == PAUSED
        assert engine.store.hwm(BOT) == mark


def test_resume_rebases_the_bot_mark_down_and_activates(engine, client):
    """Resuming writes the mark to the equity it is resumed at, down included."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()
    engine.store.update_hwm(BOT, D("1000"))
    assert client.post("/bots/b1/pause").status_code == 200
    assert bot_row(engine)["status"] == PAUSED

    price_at(engine, "0.30", "0.31")
    equity = engine.gateway.ledger.equity(BOT, {PRODUCT: D("0.305")}, PRODUCT)
    assert equity < D("1000")

    resumed = client.post("/bots/b1/resume", json=ACK)
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["status"] == ACTIVE
    assert bot_row(engine)["status"] == ACTIVE
    assert engine.store.hwm(BOT) == equity


def test_resume_without_a_price_answers_503(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    assert client.post("/bots/b1/pause").status_code == 200
    # A crossed book cannot price the bot, so nothing may be re-based off it.
    engine.gateway.snapshots.put(
        MarketSnapshot(
            PRODUCT, D("1.02"), D("1.00"), D("1.00"), D("1.02"), time.time()
        )
    )
    response = client.post("/bots/b1/resume", json=ACK)
    assert response.status_code == 503, response.text
    assert bot_row(engine)["status"] == PAUSED
    assert engine.store.hwm(BOT) is None


# ---------------------------------------------------------------- the price is not in the tx


def probe_app(engine, price_for):
    """A second app over the same pieces, with a price callable of the test's own."""
    return api_module.create_app(
        store=engine.store,
        gateway=engine.gateway,
        runner=engine.runner,
        exchange=engine.exchange,
        strategies=engine.runner.strategies,
        limits=engine.limits,
        spec_for=engine.runner.spec_for,
        price_for=price_for,
        token=TOKEN,
        heartbeat_path=engine.runner.heartbeat_path,
    )


def test_create_bot_prices_before_the_transaction(tmp_path):
    """The price is a network read: it happens with no write transaction open."""
    engine = make_engine(tmp_path / "priced").engine
    seen = []

    def probing_price_for(product):
        seen.append((product, engine.store.conn().in_transaction))
        return D("0.995")

    with TestClient(probe_app(engine, probing_price_for)) as client:
        client.headers.update(HEADERS)
        created = client.post("/bots", json=CREATE_BODY)
        assert created.status_code == 201, created.text

    assert seen == [(PRODUCT, False)]
    assert [row["id"] for row in engine.store.list_bots()] == [BOT]
    assert count_rows(engine, "sim_deposits") == 2

    failures = []

    def failing_price_for(product):
        failures.append((product, engine.store.conn().in_transaction))
        raise RuntimeError("the book is unavailable")

    with TestClient(probe_app(engine, failing_price_for)) as client:
        client.headers.update(HEADERS)
        refused = client.post("/bots", json=dict(CREATE_BODY, id="b2"))

    assert refused.status_code == 503, refused.text
    assert "cannot price" in detail_text(refused)
    assert failures == [(PRODUCT, False)]
    assert [row["id"] for row in engine.store.list_bots()] == [BOT]
    assert count_rows(engine, "sim_deposits") == 2


# ---------------------------------------------------------------- health


# The `/health` body: the cycle's own three keys, then whether the owner's
# credentials are in place and whether a pin exists at all.
HEALTH_KEYS = {
    "ok",
    "live_enabled",
    "heartbeat_age_s",
    "credentials",
    "pinned",
}
LEAK_WORDS = ("balance", "USDC", "totals", "b1")


def leaked(text):
    return [word for word in LEAK_WORDS if word in text]


def test_health_no_balances_and_503_when_stale(tmp_path):
    clock = [1000.0]
    harness = make_engine(tmp_path / "health", now=lambda: clock[0])
    engine = harness.engine
    heartbeat = Path(engine.runner.heartbeat_path)

    with api(engine) as client:
        assert client.post("/bots", json=CREATE_BODY).status_code == 201

        inside_grace = client.get("/health")
        assert inside_grace.status_code == 200
        assert set(inside_grace.json()) == HEALTH_KEYS
        assert inside_grace.json()["ok"] is True
        assert inside_grace.json()["live_enabled"] is False
        assert inside_grace.json()["heartbeat_age_s"] is None
        # No key has been connected on this engine, so there is nothing to trade
        # the live book with and no pin to keep.
        assert inside_grace.json()["credentials"] == "not_ready"
        assert inside_grace.json()["pinned"] is False
        assert leaked(inside_grace.text) == []

        clock[0] = 1000.0 + 130.0  # past the 120 s startup grace
        silent = client.get("/health")
        assert silent.status_code == 503
        assert set(silent.json()) == HEALTH_KEYS
        assert silent.json()["ok"] is False
        assert leaked(silent.text) == []

        heartbeat.write_text(
            json.dumps(
                {"ts": clock[0], "cycle": 1, "bots_active": 0, "errors": []}
            ),
            encoding="utf-8",
        )
        fresh = client.get("/health")
        assert fresh.status_code == 200
        assert fresh.json()["ok"] is True
        assert fresh.json()["live_enabled"] is False
        assert abs(fresh.json()["heartbeat_age_s"]) < 1
        assert leaked(fresh.text) == []

        clock[0] += 119
        assert client.get("/health").status_code == 200

        clock[0] += 2
        late = client.get("/health")
        assert late.status_code == 503
        assert late.json()["ok"] is False
        assert abs(late.json()["heartbeat_age_s"] - 121) < 1
        assert leaked(late.text) == []

        heartbeat.write_text("{not json", encoding="utf-8")
        garbled = client.get("/health")
        assert garbled.status_code == 503
        assert set(garbled.json()) == HEALTH_KEYS
        assert garbled.json()["ok"] is False

    with raw_api(engine) as anonymous:
        anonymous_health = anonymous.get("/health")
        assert anonymous_health.status_code == 503  # still past the grace
        assert set(anonymous_health.json()) == HEALTH_KEYS


FAR_FUTURE_S = 10**9


def test_health_rejects_non_finite_and_future_heartbeat(tmp_path):
    clock = [1000.0]
    engine = make_engine(tmp_path / "health-stamps", now=lambda: clock[0]).engine
    heartbeat = Path(engine.runner.heartbeat_path)

    def stamp(ts):
        heartbeat.write_text(
            json.dumps({"ts": ts, "cycle": 1, "bots_active": 0, "errors": []}),
            encoding="utf-8",
        )

    with api(engine) as client:

        def stale(label):
            response = client.get("/health")
            assert response.status_code == 503, label
            body = response.json()
            assert set(body) == HEALTH_KEYS, label
            assert body["ok"] is False, label
            assert body["live_enabled"] is False, label
            return body

        undatable = [("infinite", float("inf")), ("nan", float("nan"))]

        # Inside the startup grace: a stamp that cannot be dated is not the same
        # thing as no stamp at all, so the grace does not cover it.
        for label, ts in undatable:
            stamp(ts)
            body = stale(f"inside grace: {label}")
            assert body["heartbeat_age_s"] is None, label
        stamp(clock[0] + FAR_FUTURE_S)
        body = stale("inside grace: far-future")
        assert body["heartbeat_age_s"] is None or body["heartbeat_age_s"] < 0

        # Past the grace, the same stamps are stale for the same reasons.
        clock[0] = 1000.0 + 130.0
        for label, ts in undatable:
            stamp(ts)
            body = stale(f"past grace: {label}")
            assert body["heartbeat_age_s"] is None, label
        stamp(clock[0] + FAR_FUTURE_S)
        body = stale("past grace: far-future")
        assert body["heartbeat_age_s"] is None or body["heartbeat_age_s"] < 0

        # A stamp a few seconds ahead of the clock is still a live engine: the
        # skew only refutes the stamp once it passes a whole poll window.
        stamp(clock[0] + 5)
        skewed = client.get("/health")
        assert skewed.status_code == 200, skewed.text
        assert skewed.json()["ok"] is True
        age = skewed.json()["heartbeat_age_s"]
        assert isinstance(age, (int, float)) and not isinstance(age, bool)
        assert math.isfinite(age)
        assert -6 < age <= 0


# ---------------------------------------------------------------- fills

# The tax column set, written out here so a reordering of records.COLUMNS fails
# this test instead of being followed along with.
TAX_COLUMNS = [
    "timestamp_utc",
    "product",
    "base_currency",
    "quote_currency",
    "side",
    "trade_type",
    "base_size",
    "price",
    "fee",
    "gross_quote",
    "net_quote",
    "trade_id",
    "order_id",
    "client_order_id",
    "mode",
]


def trade_both_ways(engine, harness):
    """Run the grid through one buy and one sell, and return its fill rows."""
    book = harness.books.market_for(PRODUCT)
    engine.runner.cycle()
    trade_through(book, low="0.98", high="1.0")
    engine.runner.cycle()
    trade_through(book, low="1.0", high="1.05")
    engine.runner.cycle()
    return fetch(
        engine,
        "SELECT trade_id, trade_time, side, size, price, commission FROM fills "
        "ORDER BY trade_time, trade_id",
    )


def test_export_one_row_per_fill(engine, client, harness):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    fill_rows = trade_both_ways(engine, harness)
    assert {row["side"] for row in fill_rows} == {"BUY", "SELL"}

    exported = client.get("/export/fills.csv")
    assert exported.status_code == 200
    table = list(csv.reader(io.StringIO(exported.text)))
    assert table[0] == TAX_COLUMNS
    assert table[0] == records.COLUMNS
    assert len(table) - 1 == len(fill_rows)

    column = {name: index for index, name in enumerate(table[0])}
    by_id = {row["trade_id"]: row for row in fill_rows}
    sides: dict[str, list[str]] = {}
    for exported_row in table[1:]:
        db_row = by_id[exported_row[column["trade_id"]]]
        gross = D(db_row["size"]) * D(db_row["price"])
        fee = D(db_row["commission"])
        assert exported_row[column["product"]] == PRODUCT
        assert exported_row[column["base_currency"]] == "XRP"
        assert exported_row[column["quote_currency"]] == "USDC"
        assert exported_row[column["trade_type"]] == "FILL"
        assert D(exported_row[column["gross_quote"]]) == gross
        expected = -(gross + fee) if db_row["side"] == "BUY" else gross - fee
        assert D(exported_row[column["net_quote"]]) == expected
        sides.setdefault(db_row["side"], []).append(exported_row[column["net_quote"]])

    # A buy paid out, a sell was paid: the two net signs never meet.
    assert all(D(value) < 0 for value in sides["BUY"])
    assert all(D(value) > 0 for value in sides["SELL"])

    trade_ids = [row[column["trade_id"]] for row in table[1:]]
    assert len(set(trade_ids)) == len(trade_ids)
    assert sorted(trade_ids) == sorted(row["trade_id"] for row in fill_rows)
    assert {row[column["mode"]] for row in table[1:]} == {"dry"}

    year = fill_rows[0]["trade_time"][:4]
    this_year = list(
        csv.reader(
            io.StringIO(
                client.get("/export/fills.csv", params={"year": year}).text
            )
        )
    )
    assert len(this_year) - 1 == len(fill_rows)

    other_year = list(
        csv.reader(
            io.StringIO(
                client.get("/export/fills.csv", params={"year": "1999"}).text
            )
        )
    )
    assert other_year == [records.COLUMNS]

    assert (
        client.get("/export/fills.csv", params={"year": "abc"}).status_code == 422
    )

    bot_fills = client.get(f"/bots/{BOT}/fills")
    assert bot_fills.status_code == 200
    assert sorted(fill["trade_id"] for fill in bot_fills.json()) == sorted(trade_ids)


def test_export_twice_is_identical(engine, client, harness):
    """Each export is built from scratch: no id from an earlier one is remembered."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    fill_rows = trade_both_ways(engine, harness)
    assert len(fill_rows) >= 2

    first = client.get("/export/fills.csv").text
    second = client.get("/export/fills.csv").text

    assert first == second
    assert len(list(csv.reader(io.StringIO(second)))) - 1 == len(fill_rows)


# ---------------------------------------------------------------- the process wrapper


def test_runner_death_exits_process(monkeypatch):
    exits = []
    monkeypatch.setattr(os, "_exit", lambda code: exits.append(code))

    class Dying:
        def run_forever(self):
            raise RuntimeError("boom")

    _run_runner(Dying())
    assert exits == [1]

    class Returning:
        def run_forever(self):
            return None

    _run_runner(Returning())
    assert exits == [1, 1]

    started = threading.Event()
    names = []

    class BoomOnStart:
        def startup_checks(self):
            return []

        def run_forever(self):
            names.append(threading.current_thread().name)
            started.set()
            raise RuntimeError("boom")

    fake_runner = BoomOnStart()
    app = object()
    served = []

    def serve(*args, **kwargs):
        served.append((args, kwargs))

    code = main(
        dict(ENV),
        build=lambda env: SimpleNamespace(app=app, runner=fake_runner),
        serve=serve,
    )
    assert code == 0
    assert started.wait(10)
    assert wait_for(lambda: len(exits) == 3, 10)
    assert names == ["coinbase-runner"]

    assert len(served) == 1
    args, kwargs = served[0]
    assert args[0] is app
    host = kwargs.get("host", args[1] if len(args) > 1 else None)
    port = kwargs.get("port", args[2] if len(args) > 2 else None)
    assert host == "0.0.0.0"
    assert port == 3062


def test_startup_checks_failure_exits_3(tmp_path):
    served = []
    ran = []

    def serve(*args, **kwargs):
        served.append((args, kwargs))

    class Broken:
        def startup_checks(self):
            return ["bot b1: broken"]

        def run_forever(self):
            ran.append(True)

    code = main(
        dict(ENV),
        build=lambda env: SimpleNamespace(app=object(), runner=Broken()),
        serve=serve,
    )
    assert code == 3
    assert served == []
    assert ran == []

    live_env = dict(
        ENV,
        CROW_COINBASE_LIVE="maybe",
        CROW_COINBASE_DATA_DIR=str(tmp_path / "live"),
    )
    live_served = []

    def live_serve(*args, **kwargs):
        live_served.append((args, kwargs))

    assert main(live_env, build=build_app, serve=live_serve) == 3
    assert live_served == []


def test_main_configures_logging(monkeypatch, tmp_path):
    order = []

    def recorder(**kwargs):
        order.append(("basicConfig", kwargs))

    monkeypatch.setattr(logging, "basicConfig", recorder)

    def refusing_build(env):
        order.append(("build", {}))
        raise StartupRefused("no token")

    assert main({}, build=refusing_build) == 3
    assert [step for step, _ in order] == ["basicConfig", "build"]
    assert order[0][1].get("level") == logging.INFO

    order.clear()
    missing = {k: v for k, v in ENV.items() if k != "CROW_COINBASE_ENGINE_TOKEN"}
    assert (
        main(
            dict(missing, CROW_COINBASE_DATA_DIR=str(tmp_path / "logged")),
            build=build_app,
        )
        == 3
    )
    assert len(order) == 1, order
    assert order[0][0] == "basicConfig"
    assert order[0][1].get("level") == logging.INFO


# ---------------------------------------------------------------- smaller surfaces


def test_pause_resume_and_stop_unknown_bot_404(engine, client):
    assert client.post("/bots/ghost/pause").status_code == 404
    assert client.post("/bots/ghost/stop").status_code == 404
    # The acknowledgement is read before the bot is looked up, so no body is a
    # 409 whatever the id; with it, an unknown id is the 404 it always was.
    assert client.post("/bots/ghost/resume").status_code == 409
    assert client.post("/bots/ghost/resume", json=ACK).status_code == 404

    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    price_at(engine, "0.99", "1.00")

    assert client.post("/bots/b1/resume").status_code == 409
    assert client.post("/bots/b1/resume", json=ACK).status_code == 409
    assert "not PAUSED" in detail_text(client.post("/bots/b1/resume", json=ACK))
    assert bot_row(engine)["status"] == ACTIVE

    assert client.post("/bots/b1/pause").status_code == 200
    assert bot_row(engine)["status"] == PAUSED

    assert client.post("/bots/b1/resume", json=ACK).status_code == 200
    assert bot_row(engine)["status"] == ACTIVE

    assert client.post("/bots/b1/pause").status_code == 200
    assert client.post("/bots/b1/stop").status_code == 200
    assert bot_row(engine)["status"] == STOPPED

    assert client.post("/bots/b1/resume").status_code == 409
    assert client.post("/bots/b1/resume", json=ACK).status_code == 409
    assert client.post("/bots/b1/pause").status_code == 409
    assert bot_row(engine)["status"] == STOPPED


def test_recenter_grid_only(engine, client):
    rebalancing = dict(
        CREATE_BODY, id="r1", strategy="rebalance", params=REBALANCE_PARAMS
    )
    assert client.post("/bots", json=rebalancing).status_code == 201
    assert client.post("/bots/r1/recenter", json={"center": "1.1"}).status_code == 422

    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.store.set_init_done(BOT)
    assert bot_row(engine)["init_done"] is True

    recentered = client.post("/bots/b1/recenter", json={"center": "1.1"})
    assert recentered.status_code == 200
    assert bot_row(engine)["params"]["center"] == "1.1"
    assert bot_row(engine)["init_done"] is False
    assert bot_row(engine)["status"] == ACTIVE

    assert client.post("/bots/b1/recenter", json={"center": "0"}).status_code == 422
    assert client.post("/bots/b1/recenter", json={"center": "-1"}).status_code == 422
    assert bot_row(engine)["params"]["center"] == "1.1"
    assert bot_row(engine)["init_done"] is False


def test_recenter_stopped_bot_409(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.store.set_init_done(BOT)
    assert client.post("/bots/b1/stop").status_code == 200
    assert bot_row(engine)["status"] == STOPPED
    params_before = bot_row(engine)["params"]

    calls = []
    real_recenter = engine.runner.recenter

    def watching_recenter(bot_id, center):
        calls.append((bot_id, center))
        return real_recenter(bot_id, center)

    engine.runner.recenter = watching_recenter
    try:
        response = client.post("/bots/b1/recenter", json={"center": "1.1"})
    finally:
        engine.runner.recenter = real_recenter

    assert response.status_code == 409, response.text
    assert calls == [], "a stopped bot was handed to the runner"
    assert bot_row(engine)["params"] == params_before
    assert bot_row(engine)["params"]["center"] == "1.0"
    assert bot_row(engine)["status"] == STOPPED


def test_pnl_shape(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()

    body = client.get("/pnl").json()
    assert list(body["bots"]) == [BOT]
    entry = body["bots"][BOT]
    assert set(entry) == {"realized", "fees", "equity", "vs_hold", "mode"}
    assert entry["mode"] == "dry"
    # A grid bot with no sell yet keeps a decimal string, not null.
    assert entry["realized"] == "0"
    assert D(entry["fees"]) == D("0")
    assert entry["equity"] is not None
    assert D(entry["equity"]).is_finite()
    assert entry["vs_hold"] is not None
    assert D(entry["vs_hold"]).is_finite()


def test_pnl_realized_null_for_rebalance_but_not_for_grid(engine, client):
    """A rebalancer has no cost basis, so it reports no realized profit."""
    rebalancing = dict(
        CREATE_BODY, id="r1", strategy="rebalance", params=REBALANCE_PARAMS
    )
    assert client.post("/bots", json=rebalancing).status_code == 201
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()

    bots = client.get("/pnl").json()["bots"]
    assert bots["r1"]["realized"] is None
    assert bots[BOT]["realized"] == "0"
    assert isinstance(bots[BOT]["realized"], str)


def test_pnl_stale_snapshot_marks_nothing(engine, client):
    """A book no order could be checked against prices no equity."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()
    healthy = client.get("/pnl").json()["bots"][BOT]
    assert healthy["equity"] is not None
    assert healthy["vs_hold"] is not None

    # The same book, stamped well past the staleness window.
    engine.gateway.snapshots.put(
        MarketSnapshot(
            product=PRODUCT,
            bid=D("0.99"),
            ask=D("1.00"),
            low=D("0.99"),
            high=D("1.00"),
            ts=time.time() - 10_000,
        )
    )

    stale = client.get("/pnl").json()["bots"][BOT]
    assert stale["equity"] is None
    assert stale["vs_hold"] is None
    assert stale["realized"] == "0"


def test_pnl_crossed_snapshot_marks_nothing(engine, client):
    """A crossed book is unusable too: no mark comes off it."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    engine.runner.cycle()

    engine.gateway.snapshots.put(
        MarketSnapshot(
            product=PRODUCT,
            bid=D("1.02"),
            ask=D("1.00"),
            low=D("1.00"),
            high=D("1.02"),
            ts=time.time(),
        )
    )

    entry = client.get("/pnl").json()["bots"][BOT]
    assert entry["equity"] is None
    assert entry["vs_hold"] is None


def test_status_and_bots_shape(engine, client):
    assert client.post("/bots", json=CREATE_BODY).status_code == 201

    status = client.get("/status").json()
    assert status["halted"] is False
    assert status["halt_reason"] is None
    assert status["heartbeat"] is None
    assert status["recent_alerts"] == []
    assert len(status["bots"]) == 1
    entry = status["bots"][0]
    assert entry["id"] == BOT
    assert entry["product"] == PRODUCT
    assert entry["strategy"] == "grid"
    assert entry["status"] == ACTIVE
    assert entry["init_done"] is False

    rows = client.get("/bots").json()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == BOT
    assert row["product"] == PRODUCT
    assert row["strategy"] == "grid"
    assert row["status"] == ACTIVE
    assert row["init_done"] is False
    assert row["params"]["center"] == "1.0"
    assert row["params"]["step_pct"] == "1.5"
    assert row["capital_quote"] == "60"
    assert row["capital_base"] == "30"
    # A new bot is always a dry bot, with no live capital of its own yet.
    assert row["mode"] == "dry"
    assert row["live_capital_quote"] is None
    assert row["live_capital_base"] is None
    assert isinstance(row["created_at"], (int, float))


# ---------------------------------------------------------------- status additions

# The whole `/status` body: the keys it always reported, and the three it gained
# beside them.  Written out here so a dropped or renamed key fails a test rather
# than slipping past it.
STATUS_KEYS = {
    "halted",
    "halted_books",
    "halt_reason",
    "halt_reasons",
    "heartbeat",
    "bots",
    "recent_alerts",
    "live_switches",
    "drawdown",
    "products",
}

# The three keys a book's own drawdown carries.
DRAWDOWN_KEYS = {"equity", "hwm", "pct"}
NULL_DRAWDOWN = {"equity": None, "hwm": None, "pct": None}


def drawdown_of(client):
    """The `/status` drawdown, one entry per book."""
    return client.get("/status").json()["drawdown"]


def test_status_reports_switches_and_ceiling(engine, client, tmp_path):
    """`live_switches` is exactly the switches' own snapshot, ceiling included."""
    fresh = client.get("/status").json()["live_switches"]
    assert fresh == {
        "live_enabled": False,
        "ai_live_enabled": False,
        "ceiling": True,
    }
    assert fresh == engine.gateway.switches.snapshot()

    # Flipped through the route the rest of the surface uses, the report follows.
    assert client.post("/switches", json={"live_enabled": True}).status_code == 200
    assert client.get("/status").json()["live_switches"] == {
        "live_enabled": True,
        "ai_live_enabled": False,
        "ceiling": True,
    }
    assert (
        client.post(
            "/switches", json={"live_enabled": False, "ai_live_enabled": True}
        ).status_code
        == 200
    )
    flipped = client.get("/status").json()["live_switches"]
    assert flipped == {
        "live_enabled": False,
        "ai_live_enabled": True,
        "ceiling": True,
    }
    assert flipped == engine.gateway.switches.snapshot()

    # The ceiling is the environment's and not a switch: an engine started under a
    # ceiling that forbids live reports it, with both switches still off under it.
    forbidden = make_engine(
        tmp_path / "ceiling-off", env=dict(ENV, CROW_COINBASE_LIVE="false")
    ).engine
    with api(forbidden) as ceilingless:
        reported = ceilingless.get("/status").json()["live_switches"]
    assert reported == {
        "live_enabled": False,
        "ai_live_enabled": False,
        "ceiling": False,
    }
    assert reported == forbidden.gateway.switches.snapshot()


def test_status_drawdown_per_book(engine, client):
    """Each book's drawdown comes from its own mark: strings, never floats."""
    funded = dict(CREATE_BODY, capital_quote="85", capital_base="0")
    assert client.post("/bots", json=funded).status_code == 201
    price_at(engine, "0.99", "1.00")
    assert engine.gateway.portfolio_equity("dry") == D("85")

    books = drawdown_of(client)
    assert set(books) == {"dry", "live"}
    for book in ("dry", "live"):
        assert set(books[book]) == DRAWDOWN_KEYS, book
    # The dry book is priced; no mark has been written for it yet, so there is no
    # ratio to report.
    initial = books["dry"]
    assert isinstance(initial["equity"], str)
    assert D(initial["equity"]) == D("85")
    assert initial["hwm"] is None
    assert initial["pct"] is None
    # No bot trades the live book, so it reports no equity at all — and no mark.
    assert books["live"] == NULL_DRAWDOWN

    # A mark above the book's own equity: (100 - 85) / 100 is 15 per cent.
    engine.store.update_hwm(PORTFOLIO_OWNER, D("100"))
    assert engine.store.hwm(PORTFOLIO_OWNER) == D("100")
    marked = drawdown_of(client)["dry"]
    assert isinstance(marked["equity"], str)
    assert D(marked["equity"]) == D("85")
    assert isinstance(marked["hwm"], str)
    assert D(marked["hwm"]) == D("100")
    assert isinstance(marked["pct"], str)
    assert D(marked["pct"]) == D("15")

    # Equity at or above the mark is no drawdown at all.
    engine.store.reset_hwm(PORTFOLIO_OWNER, "dry")
    engine.store.update_hwm(PORTFOLIO_OWNER, D("50"))
    at_mark = drawdown_of(client)["dry"]
    assert D(at_mark["hwm"]) == D("50")
    assert isinstance(at_mark["pct"], str)
    assert D(at_mark["pct"]) == D("0")

    # A book nothing can price reports no equity and no ratio; the mark it holds
    # is still reported as stored.
    engine.gateway.snapshots.put(
        MarketSnapshot(
            PRODUCT, D("1.02"), D("1.00"), D("1.00"), D("1.02"), time.time()
        )
    )
    assert engine.gateway.portfolio_equity("dry") is None
    unpriced = drawdown_of(client)["dry"]
    assert unpriced["equity"] is None
    assert D(unpriced["hwm"]) == D("50")
    assert unpriced["pct"] is None
    assert drawdown_of(client)["live"] == NULL_DRAWDOWN


def test_status_products_listed(engine, client):
    """The crypto products the engine may trade, as the plain strings they are."""
    products = client.get("/status").json()["products"]
    assert products == ["XRP-USDC", "BTC-USDC"]
    assert all(isinstance(product, str) for product in products)
    assert products == list(engine.limits.products)


def test_status_existing_keys_unchanged(engine, client):
    """The three new keys arrived beside every key the body already carried."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201

    status = client.get("/status").json()
    assert set(status) == STATUS_KEYS

    assert status["halted"] is False
    assert status["halted_books"] == {"dry": False, "live": False}
    assert status["halt_reason"] is None
    assert status["halt_reasons"] == {"dry": None, "live": None}
    assert status["heartbeat"] is None
    assert [bot["id"] for bot in status["bots"]] == [BOT]
    assert set(status["bots"][0]) == {
        "id",
        "product",
        "strategy",
        "status",
        "init_done",
    }
    assert status["recent_alerts"] == []


# ---------------------------------------------------------------- GET /orders

# The fields one resting order is reported with, and nothing else: no exchange
# order id, no note, no fill figures.
ORDER_KEYS = {
    "client_order_id",
    "bot",
    "product",
    "side",
    "size",
    "price",
    "status",
    "created_at",
    "book",
}


def place_order(
    store,
    cid,
    *,
    status,
    book,
    created_at,
    side="BUY",
    size="10",
    price="0.9852",
):
    """One order row through the store's own writer, stamped by the test."""
    store.insert_order(
        cid,
        BOT,
        "bot",
        PRODUCT,
        side,
        -1,
        D(price),
        D(size),
        status=status,
        book=book,
    )
    store.update_order(cid, created_at=created_at)


def test_orders_lists_only_resting(engine, client):
    """Only the resting rows are listed, oldest first, one book at a time."""
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    store = engine.store

    # The ids sort in the opposite order to the stamps, so a listing that sorted
    # by id alone would answer these in a different order.
    oldest_dry = "cb-b1-B-1-000000000009"
    resting_live = "cb-b1-S-1-000000000007"
    newest_dry = "cb-b1-B-1-000000000001"
    filled = "cb-b1-B-1-000000000005"
    cancelled = "cb-b1-S-1-000000000003"

    place_order(store, oldest_dry, status=OPEN, book="dry", created_at=1000.0)
    place_order(
        store,
        resting_live,
        status=PENDING_SUBMIT,
        book="live",
        created_at=1500.0,
        side="SELL",
        size="4",
        price="1.0024",
    )
    place_order(store, newest_dry, status=OPEN, book="dry", created_at=2000.0)
    place_order(store, filled, status=FILLED, book="dry", created_at=500.0)
    place_order(store, cancelled, status=CANCELLED, book="dry", created_at=600.0)

    both = client.get("/orders")
    assert both.status_code == 200, both.text
    listed = both.json()
    assert [entry["client_order_id"] for entry in listed] == [
        oldest_dry,
        resting_live,
        newest_dry,
    ]

    entry = listed[0]
    assert set(entry) == ORDER_KEYS
    assert entry["bot"] == BOT
    assert entry["product"] == PRODUCT
    assert entry["side"] == "BUY"
    assert isinstance(entry["size"], str) and entry["size"] == "10"
    assert isinstance(entry["price"], str) and entry["price"] == "0.9852"
    assert entry["status"] == OPEN
    assert entry["book"] == "dry"
    assert isinstance(entry["created_at"], float)
    assert entry["created_at"] == 1000.0

    pending = listed[1]
    assert set(pending) == ORDER_KEYS
    assert pending["bot"] == BOT
    assert pending["side"] == "SELL"
    assert pending["size"] == "4"
    assert pending["price"] == "1.0024"
    assert pending["status"] == PENDING_SUBMIT
    assert pending["book"] == "live"
    assert pending["created_at"] == 1500.0

    # A book filters to its own rows; no book at all is both books.
    dry_only = client.get("/orders", params={"book": "dry"})
    assert dry_only.status_code == 200, dry_only.text
    assert [item["client_order_id"] for item in dry_only.json()] == [
        oldest_dry,
        newest_dry,
    ]
    assert {item["book"] for item in dry_only.json()} == {"dry"}

    live_only = client.get("/orders", params={"book": "live"})
    assert live_only.status_code == 200, live_only.text
    assert [item["client_order_id"] for item in live_only.json()] == [resting_live]
    assert live_only.json()[0]["book"] == "live"

    # A filled or cancelled row is never one of them, whichever book was asked for.
    for response in (both, dry_only, live_only):
        listed_ids = {item["client_order_id"] for item in response.json()}
        assert filled not in listed_ids
        assert cancelled not in listed_ids

    # The route reads the books; it does not settle or sweep anything.
    assert {row["client_order_id"] for row in store.orders()} == {
        oldest_dry,
        resting_live,
        newest_dry,
        filled,
        cancelled,
    }


def test_orders_bad_book_refused(engine, client):
    """A book this engine does not know is the surface's own `422 INVALID`."""
    for value in ("weekly", "both", "futures"):
        response = client.get("/orders", params={"book": value})
        assert response.status_code == 422, f"{value}: {response.text}"
        body = response.json()
        assert body.get("code") == "INVALID", f"{value}: {body}"
        fields = body.get("fields")
        assert isinstance(fields, list) and fields, f"{value}: {body}"
        assert any("book" in str(field) for field in fields), f"{value}: {body}"
        assert value not in response.text, f"{value}: the refusal echoed it"

    assert engine.store.orders() == []


def test_orders_requires_bearer(engine):
    """Without the bearer token the listing is the uniform 401."""
    with raw_api(engine) as anonymous:
        assert anonymous.get("/status").status_code == 401
        for headers in BAD_HEADERS:
            extra = {} if headers is None else {"headers": headers}
            response = anonymous.get("/orders", **extra)
            assert response.status_code == 401, headers
            assert response.json() == {"detail": "unauthorized"}
            assert response.headers.get("www-authenticate") == "Bearer"


def test_orders_and_status_are_not_privileged(engine, client):
    """A MAC-less bearer call is enough: neither read asks the approval rail.

    The app below is built with the surface's own deny-by-default approval, so a
    privileged route really is refused there — which is what makes the two reads
    about their own dependencies rather than about the test's open approval.
    """
    assert client.post("/bots", json=CREATE_BODY).status_code == 201
    place_order(
        engine.store,
        "cb-b1-B-1-000000000002",
        status=OPEN,
        book="dry",
        created_at=1000.0,
    )

    with TestClient(probe_app(engine, lambda product: D("1"))) as closed:
        closed.headers.update(HEADERS)
        refused = closed.post("/switches", json={"live_enabled": True})
        assert refused.status_code == 403, refused.text
        assert refused.json()["detail"] == APPROVAL_INVALID

        status = closed.get("/status")
        assert status.status_code == 200, status.text
        assert set(status.json()) == STATUS_KEYS

        orders = closed.get("/orders")
        assert orders.status_code == 200, orders.text
        assert [entry["client_order_id"] for entry in orders.json()] == [
            "cb-b1-B-1-000000000002"
        ]


# ---------------------------------------------------------------- POST /bots: limits


def seed_bot(engine, bot_id, *, age_s=0.0, stopped=False):
    """One bot row through the store's own writer, stamped *age_s* seconds ago.

    The capital is small and valid for the table's own checks, and no dry seed is
    applied: such a row only fills the surface's limits.  Its `created_at` is
    moved back by hand, because `create_bot` stamps the wall clock and the hourly
    window is measured against it.
    """
    engine.store.create_bot(bot_id, PRODUCT, "grid", GRID_PARAMS, D("1"), D("0"))
    if stopped:
        engine.store.set_bot_status(bot_id, STOPPED)
    engine.store.conn().execute(
        "UPDATE bots SET created_at=? WHERE id=?",
        (time.time() - age_s, bot_id),
    )


def seed_bots(engine, ids, *, age_s=0.0, stopped=()):
    for bot_id in ids:
        seed_bot(engine, bot_id, age_s=age_s, stopped=bot_id in stopped)


def test_create_bot_refused_at_open_bot_limit(engine, client):
    """Twenty bots that are not STOPPED are the open-bot ceiling.

    Their rows are stamped well past the hour, so the rolling create window is
    clear and what refuses the request is the open-bot count alone.  The refusal
    comes before the body is looked at and writes nothing: no bot row and no dry
    seed.  A body this engine would answer 422 for is refused the same way while
    the ceiling holds, and stopping one bot makes room for a create again.
    """
    seed_bots(engine, [f"a{n}" for n in range(1, 21)], age_s=7200.0)
    bots_before = count_rows(engine, "bots")
    assert bots_before == 20
    assert count_rows(engine, "sim_balances") == 0

    refused = client.post("/bots", json=CREATE_BODY)
    assert refused.status_code == 429, refused.text
    detail = detail_text(refused)
    assert detail.startswith("BOT_LIMIT"), detail
    assert "Too many bots are running. Stop one before creating another." in detail

    assert count_rows(engine, "bots") == bots_before
    assert count_rows(engine, "sim_balances") == 0
    assert count_rows(engine, "sim_deposits") == 0
    assert engine.store.get_bot(BOT) is None

    # The ceiling is read before the body is validated: a product this engine
    # does not carry is not the refusal that comes back.
    invalid = client.post("/bots", json=dict(CREATE_BODY, product="DOGE-USDC"))
    assert invalid.status_code == 429, invalid.text
    assert detail_text(invalid).startswith("BOT_LIMIT")
    assert count_rows(engine, "bots") == bots_before

    assert client.post("/bots/a1/stop").status_code == 200
    assert engine.store.get_bot("a1")["status"] == STOPPED

    created = client.post("/bots", json=CREATE_BODY)
    assert created.status_code == 201, created.text
    assert created.json()["id"] == BOT
    assert count_rows(engine, "bots") == bots_before + 1
    assert engine.store.get_bot(BOT)["status"] == ACTIVE


def test_create_bot_refused_at_hourly_create_rate(engine, client):
    """Ten rows created inside the hour refuse an eleventh, stopped or not.

    Nine of the ten are STOPPED, so the open-bot ceiling is nowhere near: what
    refuses is the rolling count of bots created in the last 3600 seconds, and
    it does so before the body is looked at and without writing anything.  Once
    those rows are two hours old the same body is a 201.
    """
    seed_bots(
        engine,
        [f"a{n}" for n in range(1, 11)],
        stopped={f"a{n}" for n in range(1, 10)},
    )
    bots_before = count_rows(engine, "bots")
    assert bots_before == 10
    assert count_rows(engine, "sim_balances") == 0

    refused = client.post("/bots", json=CREATE_BODY)
    assert refused.status_code == 429, refused.text
    detail = detail_text(refused)
    assert detail.startswith("BOT_LIMIT"), detail
    assert "Too many bots were created this hour. Try again later." in detail

    assert count_rows(engine, "bots") == bots_before
    assert count_rows(engine, "sim_balances") == 0
    assert count_rows(engine, "sim_deposits") == 0
    assert engine.store.get_bot(BOT) is None

    invalid = client.post("/bots", json=dict(CREATE_BODY, product="DOGE-USDC"))
    assert invalid.status_code == 429, invalid.text
    assert detail_text(invalid).startswith("BOT_LIMIT")
    assert count_rows(engine, "bots") == bots_before

    # Two hours old is outside the window, and the whole ten are now there.
    engine.store.conn().execute(
        "UPDATE bots SET created_at=?", (time.time() - 7200.0,)
    )

    created = client.post("/bots", json=CREATE_BODY)
    assert created.status_code == 201, created.text
    assert created.json()["id"] == BOT
    assert count_rows(engine, "bots") == bots_before + 1


def test_create_bot_under_limits_unchanged(engine, client):
    """Under both limits a create is the 201 it always was, and its refusals too.

    Two bots are well inside the open-bot ceiling and the hourly window, and the
    validation beside them is untouched: an unknown product is still 422 and a
    reused id still 409, with nothing written by either.
    """
    assert api_module.MAX_OPEN_BOTS == 20
    assert api_module.MAX_BOT_CREATES_PER_HOUR == 10

    first = client.post("/bots", json=CREATE_BODY)
    assert first.status_code == 201, first.text
    second = client.post(
        "/bots",
        json=dict(CREATE_BODY, id="b2", capital_quote="40", capital_base="10"),
    )
    assert second.status_code == 201, second.text
    assert [row["id"] for row in engine.store.list_bots()] == [BOT, "b2"]
    assert engine.store.get_bot("b2")["status"] == ACTIVE
    assert count_rows(engine, "sim_deposits") == 4

    bad = client.post("/bots", json=dict(CREATE_BODY, id="b3", product="DOGE-USDC"))
    assert bad.status_code == 422, bad.text
    duplicate = client.post("/bots", json=CREATE_BODY)
    assert duplicate.status_code == 409, duplicate.text
    assert [row["id"] for row in engine.store.list_bots()] == [BOT, "b2"]
    assert count_rows(engine, "sim_deposits") == 4


# ---------------------------------------------------------------- GET /price

# The whole `/price` body: the product the route answered for, its price as a
# decimal string, and the snapshot's own stamp.  Written out here so a dropped or
# renamed key fails a test rather than slipping past it.
PRICE_KEYS = {"product", "price", "ts"}

# The route's two refusals, word for word: a product off the allow-list, and a
# product nothing can be priced for right now.  Both are plain sentences, and
# neither carries anything the engine was told by whatever could not answer.
UNKNOWN_PRODUCT = "That product is not one this engine trades."
NO_PRICE = "No price is available for that product right now."


def price_dependencies(app):
    """The dependency names of the app's one `GET /price` route.

    The same walk `test_privileged_auth.py` classifies its routes with, read off
    the app itself: a route whose dependencies are the bearer check and nothing
    else is one no approval gate can be asked for.
    """
    routes = [
        route
        for route in app.routes
        if getattr(route, "path", "") == "/price"
        and "GET" in (getattr(route, "methods", ()) or ())
    ]
    assert len(routes) == 1, f"the app carries no one GET /price route: {routes}"
    return route_dependency_names(routes[0])


def counted_engine(tmp_path, name):
    """An engine whose market reads are counted, so a route that prices is caught.

    `market_for` is the book every fallback price would come from, and the
    surface's own `price_for` is the other way to a price: a route that answers
    from anywhere but the snapshot cache has to reach one of them, and each
    records that it was asked here.
    """
    books = Books()
    calls = []
    real_market_for = books.market_for

    def counted_market_for(product):
        calls.append(product)
        return real_market_for(product)

    data_dir = tmp_path / name
    data_dir.mkdir(parents=True, exist_ok=True)
    real_create_app = main_module.create_app
    main_module.create_app = _open_approval_create_app
    try:
        engine = build_app(
            dict(ENV),
            data_dir=data_dir,
            market_for=counted_market_for,
            spec_for=lambda product: SPEC,
        )
    finally:
        main_module.create_app = real_create_app
    return Harness(engine, books), calls


def test_price_returns_snapshot_ts(harness):
    """A fresh snapshot is the answer: its own mid as a string, and its own stamp.

    The market cache beside the engine answers 0.99/1.00, whose mid is 0.995, so
    a price of exactly 1.00 can only have come from the snapshot this test puts
    in the cache the way a cycle writes one.  `ts` is that snapshot's own stamp,
    not the clock the request was read at.
    """
    engine = harness.engine
    stamp = time.time() - 30.0
    engine.gateway.snapshots.put(
        MarketSnapshot(
            PRODUCT, D("0.99"), D("1.01"), D("0.99"), D("1.01"), stamp
        )
    )

    with api(engine) as client:
        response = client.get("/price?product=XRP-USDC")

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == PRICE_KEYS, body
    assert body["product"] == PRODUCT, body
    assert isinstance(body["price"], str), body
    assert D(body["price"]) == D("1.00"), body
    assert D(body["price"]) != D("0.995"), "the book answered instead of the cache"
    assert isinstance(body["ts"], (int, float)) and not isinstance(
        body["ts"], bool
    ), body
    assert math.isfinite(body["ts"]), body
    assert body["ts"] == stamp, "the answer carried the snapshot's stamp"
    assert abs(body["ts"] - time.time()) > 5.0, "the answer carried the engine clock"


def test_price_unknown_product_400(tmp_path):
    """A product off the allow-list, and no product at all, are the same 400.

    The price callable is one that records every product it is asked about and
    then fails: the allow-list is checked first, so neither request reaches a
    price at all — and nothing is written by either.
    """
    engine = make_engine(tmp_path / "unknown-product").engine
    asked = []

    def never_priced(product):
        asked.append(product)
        raise RuntimeError("a product this engine does not trade was priced")

    with TestClient(probe_app(engine, never_priced)) as client:
        client.headers.update(HEADERS)
        for path in ("/price?product=DOGE-USDC", "/price"):
            response = client.get(path)
            assert response.status_code == 400, f"{path}: {response.text}"
            assert response.json() == {"detail": UNKNOWN_PRODUCT}, (
                f"{path}: {response.text}"
            )

    assert asked == [], asked
    assert engine.store.list_bots() == []


def test_price_needs_bearer(engine):
    """Without the bearer token the read is the surface's uniform 401."""
    with raw_api(engine) as anonymous:
        for headers in BAD_HEADERS:
            extra = {} if headers is None else {"headers": headers}
            response = anonymous.get("/price?product=XRP-USDC", **extra)
            assert response.status_code == 401, headers
            assert response.json() == {"detail": "unauthorized"}
            assert response.headers.get("www-authenticate") == "Bearer"

        # With it, the same read is served from the snapshot a poll leaves behind.
        price_at(engine, "0.99", "1.00")
        served = anonymous.get("/price?product=XRP-USDC", headers=HEADERS)
        assert served.status_code == 200, served.text
        assert served.json()["product"] == PRODUCT


def test_price_empty_cache_503_no_exchange_call(tmp_path):
    """An empty cache is a plain 503, and no book or fallback price is asked at all.

    The engine is built over a market cache that records every product it is
    asked about, and the app's own `price_for` fails the test outright if the
    route reaches it.  With no snapshot in the cache the route answers its own
    sentence without either: the fallback price and the public book belong to
    the routes that create a bot, not to this read.
    """
    harness, market_calls = counted_engine(tmp_path, "price-empty-cache")
    engine = harness.engine
    assert engine.gateway.snapshots.get(PRODUCT) is None

    price_calls = []

    def never_priced(product):
        price_calls.append(product)
        raise AssertionError("the price route asked for a price off the cache")

    with TestClient(
        probe_app(engine, never_priced), raise_server_exceptions=False
    ) as client:
        client.headers.update(HEADERS)
        response = client.get("/price?product=XRP-USDC")

    assert response.status_code == 503, response.text
    assert response.json() == {"detail": NO_PRICE}, response.text
    assert "exchange" not in response.text.lower()
    assert price_calls == [], price_calls
    assert market_calls == [], market_calls


def test_price_stale_snapshot_503(harness):
    """A snapshot past the staleness window is no price, over a readable book too.

    The runner's mid applies the gateway's own usability rule, so an old snapshot
    answers None just like a missing one: the read is a 503 rather than the book
    the market cache beside the engine could still quote.
    """
    engine = harness.engine
    stale = time.time() - 10_000
    engine.gateway.snapshots.put(
        MarketSnapshot(
            PRODUCT, D("0.99"), D("1.01"), D("0.99"), D("1.01"), stale
        )
    )
    assert (
        engine.gateway._is_unusable(engine.gateway.snapshots.get(PRODUCT)) is True
    )

    with api(engine) as client:
        response = client.get("/price?product=XRP-USDC")

    assert response.status_code == 503, response.text
    assert response.json() == {"detail": NO_PRICE}, response.text
    assert engine.gateway.snapshots.get(PRODUCT).ts == stale


def test_price_is_not_privileged(tmp_path):
    """The read carries the bearer check alone: no MAC and no approval is enough.

    The app is built over the engine's pieces with the surface's own
    deny-by-default approval, so a privileged route really is refused there.  The
    price read is served by that same app, which is what makes this about the
    route's own dependencies rather than about an approval a test opened.
    """
    engine = make_engine(tmp_path / "price-auth").engine
    price_at(engine, "0.99", "1.01")
    app = probe_app(engine, lambda product: D("0.995"))
    assert price_dependencies(app) == {"_check_token"}

    with TestClient(app) as client:
        client.headers.update(HEADERS)
        refused = client.post("/switches", json={"live_enabled": True})
        assert refused.status_code == 403, refused.text
        assert refused.json()["detail"] == APPROVAL_INVALID

        response = client.get("/price?product=XRP-USDC")
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == PRICE_KEYS, body
        assert D(body["price"]) == D("1.00"), body
        assert D(body["price"]) != D("0.995"), "the route priced off the fallback callable"