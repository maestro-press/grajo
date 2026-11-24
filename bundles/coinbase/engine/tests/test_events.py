"""test_events.py: the engine's event feed, its kinds, and the trailing-hold alert.

Every test here builds the REAL engine through `build_app`: a real `Store` on a
temporary data directory, the real dry-run exchange, the live switches, the
runtime caps, the approval rail, the AI order surface and the runner.  Only the
outside world is faked: `FakeMarket` answers one fixed touch (so nothing opens a
socket) and the live book is a SECOND `DryRunExchange` over a second store file,
handed to `build_app` as its `live_factory`, exactly as the other engine tests
do it.  `LiveBuilder` is the factory the credentials slot builds an adapter with
— one `key_permissions()` dict, and a failure for any other exchange call — so a
key can be pushed, refused and locked out here for real.  `FaultyExchange` wraps
an exchange and raises a text of its own from the one call a step is being driven
through, which is how the events that interpolate an error are reached.

The owner is the real approval rail: a privileged request is signed the way
`Authenticator` checks one (`Signer` hands `auth.compute_mac` the same bytes
`TestClient` sends).  Every secret, key and token here is built at runtime, so
no value in this file is a credential.

What each test pins down:

* `GET /events` reads forward from `after` by id, at most `limit` rows, and
  answers the id the next page starts from; `limit` is clamped to 200, a request
  the surface cannot read is the same `422 INVALID` every other route answers, a
  request with no bearer token is a `401`, and a row is exactly the seven fields
  a reader reads (its `data` the parsed object, `{}` when there is none),
* a cursor past the newest event the engine holds answers no rows, the newest id
  it does hold and `reset: true` — the one answer whose `reset` is not false — so
  a client that lost the table can resync; a cursor exactly at the newest id is
  an ordinary empty page,
* every kind of the vocabulary is written by the thing that makes it — a fill by
  `record_fill`, a refusal by a bot's own refused place and by an AI approval the
  chain refuses, a halt by the kill switch, a watchdog alert by a stale
  heartbeat, the three AI kinds by a preview and an approval and a sweep no
  listing asked for, a credentials event by a disconnect, a live switch by the
  signed switch route and by a bot's own book switch, and the cap kinds by the
  startup heal and by `POST /caps` (names only) — and `EVENT_KINDS` is the
  thirteen names with `info` beside them.  An `alert` is what a reader has to act
  on (an empty grid book, an exchange short of its owners, follow-ups given up
  on, a kill-path sweep that failed, a cycle that never got through) and a
  `bot_paused` is one bot stopped (its own drawdown, its strategy's pause, its
  own cycle failing, a fill whose follow-ups are offered again); a real trading
  halt — a book's drawdown stop and the kill switch — stays `halt`,
* the trailing-hold alert answers once per episode, re-arms at or above zero,
  leaves its state alone while the comparison is unknown, survives a new
  `Benchmark` over the same store, and the runner writes one `trailing_hold`
  event per episode for a bot under its hold, at the number of days the
  environment names (and seven for a value that is not one),
* the episode's mark and the event the runner raises with it are one write: an
  alert the store will not take leaves the episode unalerted, and the next cycle
  offers it again,
* a bot's book switch forgets the trail of the book it leaves, so the book it
  comes back to has to trail for the whole window again instead of alerting on a
  stretch of days it spent somewhere else,
* no secret — the engine's token, the install token, the approval secret, a
  private key, a key name — reaches the events table or the feed.  Every source
  that writes an event is driven on one engine that carries both books (the
  owner's key accepted, refused and locked out; the kill switch; the clear; the
  switches; the caps; a fill and a refusal on each book; the AI's preview,
  approval, refusal and expiry; the runner's alerts; a bot's switch to live; the
  watchdog) and an exchange call is made to fail with a text of its own, so the
  events that interpolate an error are exercised too.  Every row is then read
  with raw SQL and searched, message and payload both, and so is every page of
  the feed.  The static scan beside it covers every call that writes an event —
  `*.event`, `_record` and `_announce` — and fails on an argument that names a
  secret, a token, a private key, a password, an api key or a key name,
* the `X-Crow-Source: mcp` header tags an event an HTTP request writes, exactly
  that one header value does, and nothing else a request or a cycle writes is
  ever tagged.
"""

from __future__ import annotations

import ast
import contextlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from decimal import Decimal as D
from pathlib import Path
from typing import Any, Optional

from fastapi.testclient import TestClient

import crow_coinbase.auth as auth_module
import crow_coinbase.reconcile as reconcile_module
from crow_coinbase.__main__ import build_app
from crow_coinbase.benchmark import Benchmark
from crow_coinbase.exchange import DryRunExchange
from crow_coinbase.gateway import PORTFOLIO_OWNER
from crow_coinbase.limits import CAP_SPECS, RuntimeLimits
from crow_coinbase.money import ProductSpec
from crow_coinbase.router import ExchangeRouter
from crow_coinbase.store import FILLED, OPEN, OPP_PLACED, REJECTED, Store
from crow_coinbase.strategies.base import Decision, MarketSnapshot, OrderIntent
from crow_coinbase.watchdog import Watchdog

SRC = Path(__file__).resolve().parents[1] / "src" / "crow_coinbase"

# ---------------------------------------------------------------- test data
PRODUCT = "XRP-USDC"
BASE = "XRP"
QUOTE = "USDC"
BOT = "b1"

FEE_RATE = D("0.005")
DAY_S = 86400.0

# 32+ characters, no whitespace: a bearer token the engine starts with.
TOKEN = "test-token-" + secrets.token_hex(16)
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# The environment every engine here starts from.  `CROW_COINBASE_LIVE` is spelled
# out because the live ceiling has to be readable.
BASE_ENV = {
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": PRODUCT,
    "CROW_COINBASE_MAX_BOT_CAPITAL_USD": "100",
    "CROW_COINBASE_LIVE": "true",
}

# The environment knobs this file names, so a rename fails here.
TRAIL_DAYS_ENV = "CROW_COINBASE_TRAIL_ALERT_DAYS"
AI_MAX_ORDER_ENV = "CROW_COINBASE_AI_MAX_ORDER_USD"

# The thirteen kinds the vocabulary is made of, and the catch-all beside them.
KINDS = (
    "fill",
    "refusal",
    "halt",
    "watchdog",
    "ai_preview",
    "ai_placed",
    "ai_expired",
    "trailing_hold",
    "credentials",
    "live_switch",
    "caps",
    "alert",
    "bot_paused",
)
KIND_COUNT = 13
CATCH_ALL = "info"

# The refusal codes this file drives.
TOO_SMALL = "TOO_SMALL"
ORDER_TOO_LARGE = "ORDER_TOO_LARGE"
KEY_CAN_TRANSFER = "KEY_CAN_TRANSFER"
# The kind every event is written with when nobody classified it.
INFO_KIND = "info"
# The names an event is written through: the store's own `event`, the API's
# `_record`, the AI surface's `_announce` and its quiet twin
# `_announce_quietly`.
EVENT_CALLS = frozenset({"event", "_record", "_announce", "_announce_quietly"})
# The words an identifier handed to one of those may never carry: a value of a
# key, a secret or a token is never what an event's words or payload is built
# from, so a name that says it is one fails the static scan.
SECRET_WORDS = ("secret", "token", "private", "password", "api_key", "key_name")

# The seven fields one row of the feed carries, and nothing else.
ROW_KEYS = {"id", "ts", "level", "kind", "owner", "message", "data"}

# The largest page the feed answers with, and the one it answers with by default.
MAX_LIMIT = 200
DEFAULT_LIMIT = 50

# The private-key header, as PARTS: the shape is built here, never a literal.
PEM_BEGIN = "-----BEGIN "
PEM_KEY = "PRIVATE KEY-----"
PEM_LABEL = "EC "


# ---------------------------------------------------------------- lazy imports
# A module this build does not carry yet has to fail the test that uses it, not
# the collection of this file.


def store_module():
    """The store module, imported where a test needs it."""
    import crow_coinbase.store as module

    return module


# ---------------------------------------------------------------- outside world


class FakeMarket:
    """A public market with a fixed touch: no client, no request, no candles.

    `failure` is how a poll that cannot read the book is driven: with an
    exception set, both reads raise it instead of answering, so the engine's own
    poll-failure path (`{error}` interpolated into an event) runs for real.
    """

    def __init__(self, bid=D("0.99"), ask=D("1.00")):
        self.bid, self.ask = D(bid), D(ask)
        self.low, self.high = self.bid, self.ask
        self.failure: Optional[BaseException] = None

    def _reading(self) -> None:
        """Raise the failure this market was handed, if it has one."""
        if self.failure is not None:
            raise self.failure

    def best_bid_ask(self):
        self._reading()
        return self.bid, self.ask

    def range_since(self, since):
        self._reading()
        return self.low, self.high

    def candles(self, start, end):
        return []


_MARKETS: dict[str, FakeMarket] = {}


def market_for(product: str) -> FakeMarket:
    """One `FakeMarket` per product, so every book has a price."""
    return _MARKETS.setdefault(product, FakeMarket())


def spec_for(product: str) -> ProductSpec:
    """The product spec every product here trades under."""
    return ProductSpec(
        product,
        price_increment=D("0.0001"),
        base_increment=D("0.1"),
        quote_increment=D("0.01"),
        base_min_size=D("1"),
        quote_min_size=D("1"),
    )


class Clock:
    """A clock the test moves by hand, starting from the wall clock.

    It starts at `time.time()` so a piece built with the injected clock and one
    built with the wall clock agree about "now" until a test moves it.
    """

    def __init__(self, at: Optional[float] = None):
        self.at = time.time() if at is None else float(at)

    def __call__(self) -> float:
        return self.at

    def advance(self, seconds: float) -> float:
        self.at += float(seconds)
        return self.at


# ---------------------------------------------------------------- requests


class Signer:
    """Builds the three approval headers for one request over the bytes it sends."""

    def __init__(self, key, clock) -> None:
        self.key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        self.clock = clock

    def nonce(self) -> str:
        """A fresh nonce: long enough, and unique per request."""
        return "n" + secrets.token_hex(12)

    def headers(self, method: str, path_with_query: str, body: bytes = b"") -> dict:
        stamp = str(int(self.clock()))
        used = self.nonce()
        signature = auth_module.compute_mac(
            self.key, method, path_with_query, stamp, used, body
        )
        headers = {
            "Authorization": HEADERS["Authorization"],
            "X-Crow-Timestamp": stamp,
            "X-Crow-Nonce": used,
            "X-Crow-Signature": signature,
        }
        if body:
            headers["Content-Type"] = "application/json"
        return headers

    def request(self, client, method: str, path_with_query: str, payload: Any = None):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        return client.request(
            method,
            path_with_query,
            content=body,
            headers=self.headers(method, path_with_query, body),
        )

    def post(self, client, path_with_query: str, payload: Any = None):
        return self.request(client, "POST", path_with_query, payload)


def owner_secret() -> str:
    """An approval secret, 32+ characters, built at runtime."""
    return "approve-" + secrets.token_hex(20)


def approve_path(preview_id: str) -> str:
    return f"/ai/previews/{preview_id}/approve"


# ---------------------------------------------------------------- the harness


@dataclass
class Harness:
    """One engine, both its books, and the clock a test moves by hand."""

    engine: Any
    clock: Clock
    root: Path
    data_dir: Path
    install_token: str
    live_store: Optional[Store] = None
    live_sim: Any = None

    @property
    def store(self) -> Store:
        return self.engine.store

    @property
    def gateway(self):
        return self.engine.gateway

    @property
    def runner(self):
        return self.engine.runner

    @property
    def ai(self):
        orders = getattr(self.engine, "ai_orders", None)
        assert orders is not None, "the engine carries no AI order surface"
        return orders

    @contextlib.contextmanager
    def client(self):
        with TestClient(self.engine.app, raise_server_exceptions=False) as client:
            client.headers.update(HEADERS)
            yield client


def build_engine(
    root,
    *,
    env: Optional[dict] = None,
    live: bool = True,
    live_builder: Any = None,
) -> Harness:
    """The real engine over *root*, with both books and a fake market.

    `live_builder` is the factory the credentials slot builds a live adapter with
    — the seam `test_credentials.py` uses, and the one a test that pushes a key
    needs.  It is never asked unless a key is pushed, because the live book's own
    exchange comes from `live_factory` here.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = root / "install_token"
    install_token = "install-" + secrets.token_hex(20)
    token_path.write_text(install_token + "\n", encoding="utf-8")
    clock = Clock()

    live_store = None
    live_sim = None
    if live:
        live_store = Store(root / "live.db")
        live_sim = DryRunExchange(live_store.conn, market_for, FEE_RATE)
        for currency in (QUOTE, BASE):
            live_sim.deposit(currency, D("1000"), "funding")

    configuration = dict(BASE_ENV)
    configuration["CROW_COINBASE_ENGINE_TOKEN"] = TOKEN
    configuration["CROW_COINBASE_INSTALL_TOKEN_FILE"] = str(token_path)
    configuration.update(env or {})

    engine = build_app(
        configuration,
        data_dir=data_dir,
        market_for=market_for,
        spec_for=spec_for,
        now=clock,
        live_factory=(
            (lambda: ExchangeRouter(live_sim, usd_one_pool=True))
            if live
            else (lambda: None)
        ),
        live_builder=live_builder,
    )
    for currency in (QUOTE, BASE):
        engine.exchange.deposit(currency, D("100000"), "test float")

    return Harness(
        engine=engine,
        clock=clock,
        root=root,
        data_dir=data_dir,
        install_token=install_token,
        live_store=live_store,
        live_sim=live_sim,
    )


def close(h: Harness) -> None:
    """Close every store the engine opened, so the next build starts clean."""
    for store in (h.engine.store, h.live_store):
        if store is None:
            continue
        with contextlib.suppress(Exception):
            store.close()


def prime(h: Harness, *, bid="0.99", ask="1.00", ts=None):
    """A usable snapshot, stamped now unless the caller says when."""
    at = time.time() if ts is None else ts
    h.engine.runner.snapshots.put(
        MarketSnapshot(PRODUCT, D(bid), D(ask), D(bid), D(ask), at)
    )
    h.engine.runner.snapshots.set_clock(at, at)


def fund_ai(h: Harness, quote="10000") -> str:
    """Give the AI a dry holding: one settled sell, backdated out of the caps."""
    amount = D(quote)
    cid = f"cb-ai-S0-{secrets.token_hex(6)}"
    h.store.insert_order(
        cid, "ai", "ai", PRODUCT, "SELL", 0, D("1.00"), amount, status=OPEN, book="dry",
        product_type="SPOT",
    )
    h.store.update_order(
        cid,
        status=FILLED,
        filled_size=amount,
        filled_value=amount * D("1.00"),
        fees=D("0"),
    )
    h.store.conn().execute(
        "UPDATE orders SET created_at=? WHERE client_order_id=?",
        (time.time() - 5 * DAY_S, cid),
    )
    return cid


def add_bot(h: Harness, bot_id: str = BOT, *, quote="100", base="0") -> dict:
    """A dry bot, funded the way the engine funds one: capital, then its seed."""
    h.store.create_bot(
        bot_id,
        PRODUCT,
        "grid",
        {"center": "1.0", "step_pct": "1.5", "levels_below": 3, "levels_above": 3},
        D(quote),
        D(base),
    )
    if D(quote) > 0 or D(base) > 0:
        h.gateway.seed_dry(bot_id, D(quote), D(base))
    return h.store.get_bot(bot_id)


def post_preview(client, **overrides):
    """The whole POST /ai/previews body, with the caller's fields over it."""
    body = {"product": PRODUCT, "side": "BUY", "size": "5", "limit_price": "0.98"}
    body.update(overrides)
    return client.post("/ai/previews", json=body)


# ---------------------------------------------------------------- the owner's key
#
# Three pieces from `test_credentials.py`, so the credentials routes run here for
# real: the slot's own key check is stubbed the way that file stubs it (a fake
# adapter answering one `key_permissions()` dict and raising on every other
# call), and the key name and private key are built at runtime.


def permissions(
    *,
    can_view: Any = True,
    can_trade: Any = True,
    can_transfer: Any = False,
    portfolio_type: Any = "CONSUMER",
    portfolio: Optional[str] = None,
) -> dict:
    """One `key_permissions()` answer: the CONSUMER key this engine accepts."""
    return {
        "can_view": can_view,
        "can_trade": can_trade,
        "can_transfer": can_transfer,
        "portfolio_uuid": portfolio or ("pf-" + secrets.token_hex(8)),
        "portfolio_type": portfolio_type,
    }


class FakeLive:
    """The live adapter a pushed key builds: one permissions answer, nothing else."""

    dry_run = False

    def __init__(self, perms: Optional[dict] = None) -> None:
        self.perms = permissions() if perms is None else dict(perms)

    def key_permissions(self) -> dict:
        return dict(self.perms)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        raise AssertionError(f"unexpected exchange call: {name}")


class LiveBuilder:
    """The `live_builder` `build_app` takes: one fake, and the perms it reports.

    `perms` is read on every build, so a test can change what the key is scoped to
    between two pushes — which is how a refused push is driven.
    """

    def __init__(self, perms: Optional[dict] = None) -> None:
        self.calls = 0
        self.perms = permissions() if perms is None else dict(perms)
        self.fake = FakeLive(self.perms)

    def __call__(self, creds) -> FakeLive:
        self.calls += 1
        self.fake.perms = dict(self.perms)
        return self.fake


def key_name_canary() -> str:
    """A Coinbase-shaped key name, built at runtime."""
    return (
        "organizations/"
        + secrets.token_hex(8)
        + "/apiKeys/"
        + secrets.token_hex(8)
    )


def _pem_pair() -> tuple[str, str]:
    """A private-key text the engine's shape check accepts, and the body marker.

    The header and the footer are built from PARTS, so this file never spells a
    private-key header out; the marker is one random base64-ish line of the body,
    which is what a scan looks for — a row that carries the key carries it too,
    whatever escaping the payload applies to the newlines around it.
    """
    marker = secrets.token_hex(64)
    header = PEM_BEGIN + PEM_LABEL + PEM_KEY
    footer = "-----END " + PEM_LABEL + PEM_KEY
    return "\n".join([header, marker, footer]), marker


def credentials_body(
    key_name: str, private_key: str, secret: str, *, repin: Any = None
) -> dict:
    """The whole POST /credentials body a test sends."""
    body: dict[str, Any] = {
        "key_name": key_name,
        "private_key": private_key,
        "approve_secret": secret,
    }
    if repin is not None:
        body["repin"] = repin
    return body


# ---------------------------------------------------------------- a failing exchange


class FaultyExchange:
    """An exchange, wrapped: the calls it is told to fail raise a marked error.

    `failures` maps a method name to the exception that call raises, and it is
    read on every call, so one wrapper serves a whole test: the engine is driven
    with no failure at all and then with exactly the one a step needs.  Every
    other method is the wrapped exchange's own.
    """

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.failures: dict[str, BaseException] = {}

    def _maybe_fail(self, name: str) -> None:
        error = self.failures.get(name)
        if error is not None:
            raise error

    def cancel(self, order_ids):
        self._maybe_fail("cancel")
        return self.inner.cancel(order_ids)

    def server_time(self):
        self._maybe_fail("server_time")
        return self.inner.server_time()

    def list_open_orders(self, product=None):
        self._maybe_fail("list_open_orders")
        return self.inner.list_open_orders(product)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)


class QuietEvents:
    """A store's `event`, refusing ONE kind and writing every other one.

    The kind is compared the way every caller passes it (a keyword), so the rows
    of another kind are still written and a test can see what the engine did
    beside the row that could not land.
    """

    def __init__(self, store: Store, kind: str) -> None:
        self.kind = kind
        self.real = store.event
        self.refused = 0

    def __call__(self, level: str, message: str, **fields: Any) -> None:
        if fields.get("kind", INFO_KIND) == self.kind:
            self.refused += 1
            raise RuntimeError("the events table refused the row")
        return self.real(level, message, **fields)


# ---------------------------------------------------------------- an event's sources


def booked_fill(h: Harness, owner: str = BOT, book: str = "dry") -> str:
    """One order row on *book* and the exchange fill booked against it."""
    cid = f"cb-{owner}-B0-{secrets.token_hex(6)}"
    h.store.insert_order(
        cid, owner, "bot", PRODUCT, "BUY", 0, D("0.98"), D("5"),
        status=FILLED, book=book, product_type="SPOT",
    )
    booked = h.store.record_fill(
        {
            "trade_id": "t-" + secrets.token_hex(6),
            "order_id": "o-" + secrets.token_hex(6),
            "side": "BUY",
            "size": "5",
            "price": "0.98",
            "commission": "0.01",
            "trade_time": "2026-01-01T00:00:00Z",
            "product": PRODUCT,
        },
        cid,
        book=book,
    )
    assert booked is True, cid
    return cid


def too_small_intent() -> OrderIntent:
    """A place intent the chain refuses TOO_SMALL: below the base minimum."""
    return OrderIntent(
        action="place",
        side="BUY",
        size=D("0.1"),
        limit_price=D("0.98"),
        level=0,
        cancel_cid=None,
        reason="test",
    )


def follow_ups(h: Harness, bot_id: str, count: int, note_text: str) -> str:
    """A parent fill marked answered, and *count* refused children over it."""
    parent = f"cb-{bot_id}-B9-{secrets.token_hex(6)}"
    h.store.insert_order(
        parent, bot_id, "bot", PRODUCT, "BUY", 0, D("0.98"), D("5"),
        status=FILLED, book="dry", product_type="SPOT",
    )
    h.store.update_order(
        parent,
        filled_size=D("5"),
        filled_value=D("4.90"),
        fees=D("0"),
        opposite=OPP_PLACED,
    )
    for index in range(count):
        child = f"cb-{bot_id}-S{index + 1}-{secrets.token_hex(6)}"
        h.store.insert_order(
            child, bot_id, "bot", PRODUCT, "SELL", index + 1, D("1.00"), D("1"),
            status=REJECTED, book="dry", product_type="SPOT",
        )
        h.store.update_order(child, consumes_fill=parent, note=note_text)
    return parent


def trailing_engine(
    root, env: Optional[dict] = None, *, live: bool = False
) -> Harness:
    """An engine whose one bot is under its hold, with a clock it can move.

    The bot is PAUSED so nothing of its own moves its equity, and its benchmark
    mix is worth more than it holds, so `vs_hold` is negative.  The gateway reads
    the same clock as the runner: these tests move days, and the snapshot a cycle
    polled has to stay usable on that clock.
    """
    engine = build_engine(root, env=env, live=live)
    engine.gateway.now = engine.clock
    prime(engine)
    add_bot(engine, BOT, quote="100", base="0")
    engine.store.set_bot_status(BOT, "PAUSED")
    engine.runner.benchmark.start(
        BOT, base=D("0"), quote=D("200"), price=D("0.995"), book="dry"
    )
    return engine


# ---------------------------------------------------------------- reading events


def rows(store: Store) -> list[dict]:
    """Every event row, oldest first, as dicts."""
    return [
        dict(row) for row in store.conn().execute("SELECT * FROM events ORDER BY id")
    ]


def events_of(store: Store, kind: str) -> list[dict]:
    """Every event row of one kind, oldest first."""
    return [
        dict(row)
        for row in store.conn().execute(
            "SELECT * FROM events WHERE kind=? ORDER BY id", (kind,)
        )
    ]


def data_of(row: dict) -> dict:
    """One event row's parsed payload."""
    return json.loads(row["data_json"] or "{}")


def feed(client, **params) -> dict:
    """One `GET /events` answer, asserted to be the shape the feed answers with."""
    response = client.get("/events", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def one(store: Store, kind: str) -> dict:
    """The only event row of *kind*, or a failure saying how many there were."""
    found = events_of(store, kind)
    assert len(found) == 1, (kind, [(row["level"], row["message"]) for row in found])
    return found[0]


# ================================================================ the feed


def test_events_paging_after_id(tmp_path):
    """The feed reads forward by id, clamps its page, and refuses a bad request."""
    h = build_engine(tmp_path / "feed", live=False)
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)

    with h.client() as client:
        # Five real flows, so the feed has real events to page over.
        preview = post_preview(client)
        assert preview.status_code == 200, preview.text
        assert preview.json()["state"] == "pending", preview.text

        fill_cid = f"cb-{BOT}-B0-{secrets.token_hex(6)}"
        h.store.insert_order(
            fill_cid,
            BOT,
            "bot",
            PRODUCT,
            "BUY",
            0,
            D("0.98"),
            D("5"),
            status=FILLED,
            book="dry",
            product_type="SPOT",
        )
        trade_id = "t-" + secrets.token_hex(6)
        assert h.store.record_fill(
            {
                "trade_id": trade_id,
                "order_id": "o-" + secrets.token_hex(6),
                "side": "BUY",
                "size": "5",
                "price": "0.98",
                "commission": "0.01",
                "trade_time": "2026-01-01T00:00:00Z",
                "product": PRODUCT,
            },
            fill_cid,
            book="dry",
        )

        switched = signer.post(client, "/switches", {"live_enabled": True})
        assert switched.status_code == 200, switched.text
        capped = signer.post(client, "/caps", {"caps": {AI_MAX_ORDER_ENV: "20"}})
        assert capped.status_code == 200, capped.text
        killed = client.post("/kill")
        assert killed.status_code == 200, killed.text
        cleared = signer.post(client, "/halt/clear", {"acknowledge_rebase": True})
        assert cleared.status_code == 200, cleared.text

        all_ids = [row["id"] for row in rows(h.store)]
        assert len(all_ids) >= 5, all_ids
        assert all_ids == sorted(all_ids)

        # Two at a time, forward from 0: ascending, no overlap, no gap.
        first = feed(client, after=0, limit=2)
        assert [event["id"] for event in first["events"]] == all_ids[:2]
        assert first["last_id"] == all_ids[1]
        # `reset` is always answered, and a cursor the engine holds events for is
        # never a reset.
        assert set(first) == {"events", "last_id", "reset"}, first
        assert first["reset"] is False, first

        seen: list[int] = []
        after = 0
        while True:
            page = feed(client, after=after, limit=2)
            entries = page["events"]
            assert page["reset"] is False, page
            if not entries:
                # After the last id: nothing, and `last_id` is the cursor itself.
                assert page["last_id"] == after, page
                break
            ids = [event["id"] for event in entries]
            assert len(ids) <= 2, ids
            assert ids == sorted(ids), ids
            assert all(identifier > after for identifier in ids), (after, ids)
            assert page["last_id"] == ids[-1], page
            seen.extend(ids)
            after = page["last_id"]
        assert seen == all_ids, (seen, all_ids)
        assert len(set(seen)) == len(seen)

        # Every row carries exactly the seven fields a reader reads.
        for event in first["events"]:
            assert set(event) == ROW_KEYS, event
            assert isinstance(event["data"], dict), event
            assert isinstance(event["id"], int), event
            assert isinstance(event["ts"], (int, float)), event

        # A row written with no payload answers an empty object, and one whose
        # payload cannot be parsed does too.
        h.store.event("info", "plain event")
        plain = rows(h.store)[-1]
        assert data_of(plain) == {}
        h.store.conn().execute(
            "UPDATE events SET data_json=? WHERE id=?", ("not json", plain["id"])
        )
        unparsable = feed(client, after=plain["id"] - 1)
        assert unparsable["events"][0]["id"] == plain["id"], unparsable
        assert unparsable["events"][0]["data"] == {}, unparsable

        # The default page is fifty rows.
        stored_now = len(rows(h.store))
        assert len(feed(client)["events"]) == min(DEFAULT_LIMIT, stored_now)

        # A request the surface cannot read is the same 422 every route answers.
        for params in (
            {"after": "abc"},
            {"after": "-1"},
            {"after": "1.5"},
            {"limit": "abc"},
            {"limit": "-5"},
            {"limit": "2.5"},
        ):
            bad = client.get("/events", params=params)
            assert bad.status_code == 422, (params, bad.text)
            assert bad.json().get("code") == "INVALID", (params, bad.text)

    # No bearer token, no feed.
    with TestClient(h.engine.app, raise_server_exceptions=False) as bare:
        refused = bare.get("/events")
        assert refused.status_code == 401, refused.text
    close(h)

    # Two hundred rows is the most one page holds, whatever it is asked for.
    big = build_engine(tmp_path / "feed-big", live=False)
    for index in range(250):
        big.store.event("info", f"bulk {index}")
    bulk_ids = [row["id"] for row in rows(big.store)]
    assert len(bulk_ids) == 250
    with big.client() as client:
        clamped = feed(client, after=0, limit=500)
        assert len(clamped["events"]) == MAX_LIMIT, len(clamped["events"])
        assert [event["id"] for event in clamped["events"]] == bulk_ids[:MAX_LIMIT]
        assert clamped["last_id"] == bulk_ids[MAX_LIMIT - 1]
        assert clamped["reset"] is False, clamped
        # The clamp is a page size, not a refusal: the rest is on the next page.
        rest = feed(client, after=clamped["last_id"], limit=500)
        assert len(rest["events"]) == len(bulk_ids) - MAX_LIMIT, len(rest["events"])
    close(big)


# ================================================================ a lost cursor


def test_events_cursor_past_the_end(tmp_path):
    """A cursor past the newest event resyncs: no rows, the newest id, and reset.

    A client holds `last_id` across a restart.  If the table behind it was wiped
    (a fresh volume, a restore) that cursor points past everything the engine
    holds, and answering an empty page forever would leave the client reading a
    history that will never arrive.  So a cursor past the newest row answers the
    newest id it does hold and `reset` true — the one answer whose `reset` is not
    false — while a cursor exactly at the newest row is an ordinary empty page.
    An empty table has no newest row at all: `last_id` is 0 and the cursor past it
    is a reset.
    """
    h = build_engine(tmp_path / "cursor", live=False)
    for index in range(3):
        h.store.event("info", f"row {index}")
    newest = max(row["id"] for row in rows(h.store))

    with h.client() as client:
        ahead = feed(client, after=newest + 5)
        assert ahead == {"events": [], "last_id": newest, "reset": True}, ahead

        # A cursor exactly at the newest row is not a reset: the client has read
        # everything there is, and the next page starts where this one ends.
        at_end = feed(client, after=newest)
        assert at_end["events"] == [], at_end
        assert at_end["last_id"] == newest, at_end
        assert at_end["reset"] is False, at_end

        # Nor is the beginning, however many rows are there.
        from_start = feed(client, after=0)
        assert from_start["reset"] is False, from_start
        assert len(from_start["events"]) == 3, from_start
    close(h)

    empty = build_engine(tmp_path / "cursor-empty", live=False)
    assert rows(empty.store) == []
    with empty.client() as client:
        nowhere = feed(client, after=5)
        assert nowhere == {"events": [], "last_id": 0, "reset": True}, nowhere
        assert feed(client, after=0)["reset"] is False, "nothing to reset at 0"
    close(empty)


# ================================================================ the kinds


def test_event_kinds_emitted(tmp_path):
    """Every kind is written by the thing that makes it, with its own owner."""
    vocabulary = store_module()
    assert len(vocabulary.EVENT_KINDS) == KIND_COUNT, vocabulary.EVENT_KINDS
    assert set(vocabulary.EVENT_KINDS) == set(KINDS), vocabulary.EVENT_KINDS
    assert len(set(vocabulary.EVENT_KINDS)) == KIND_COUNT, vocabulary.EVENT_KINDS
    assert CATCH_ALL not in vocabulary.EVENT_KINDS

    seen: set[str] = set()

    def note(h: Harness) -> None:
        """Remember every kind this engine wrote, and check each one is known."""
        written = rows(h.store)
        assert written, "the engine wrote no event at all"
        for row in written:
            assert row["kind"] in KINDS or row["kind"] == CATCH_ALL, row
        seen.update(row["kind"] for row in written)

    # ---- fill: record_fill books one, once
    h = build_engine(tmp_path / "kind-fill", live=False)
    cid = f"cb-{BOT}-B0-{secrets.token_hex(6)}"
    h.store.insert_order(
        cid, BOT, "bot", PRODUCT, "BUY", 0, D("0.98"), D("5"),
        status=FILLED, book="dry", product_type="SPOT",
    )
    trade_id = "t-" + secrets.token_hex(6)
    fill = {
        "trade_id": trade_id,
        "order_id": "o-" + secrets.token_hex(6),
        "side": "BUY",
        "size": "5",
        "price": "0.98",
        "commission": "0.01",
        "trade_time": "2026-01-01T00:00:00Z",
        "product": PRODUCT,
    }
    assert h.store.record_fill(fill, cid, book="dry") is True
    booked = one(h.store, "fill")
    assert booked["level"] == "info", booked
    assert booked["owner"] == BOT, booked
    payload = data_of(booked)
    assert set(payload) == {
        "cid",
        "trade_id",
        "product",
        "side",
        "size",
        "price",
        "book",
    }, payload
    assert payload["cid"] == cid, payload
    assert payload["trade_id"] == trade_id, payload
    assert payload["product"] == PRODUCT, payload
    assert payload["side"] == "BUY", payload
    assert D(payload["size"]) == D("5"), payload
    assert D(payload["price"]) == D("0.98"), payload
    assert payload["book"] == "dry", payload
    # The same trade booked again is not a second event, and not a second row.
    assert h.store.record_fill(fill, cid, book="dry") is False
    assert len(events_of(h.store, "fill")) == 1
    note(h)
    close(h)

    # ---- refusal: a bot's own place the chain refuses
    h = build_engine(tmp_path / "kind-refusal-bot", live=False)
    bot = add_bot(h, BOT)
    prime(h)
    intent = OrderIntent(
        action="place",
        side="BUY",
        size=D("0.1"),
        limit_price=D("0.98"),
        level=0,
        cancel_cid=None,
        reason="test",
    )
    assert h.runner._place(bot, intent, PRODUCT, init=False) == TOO_SMALL
    refused = one(h.store, "refusal")
    assert refused["level"] == "warn", refused
    assert refused["owner"] == BOT, refused
    assert data_of(refused) == {"code": TOO_SMALL}, data_of(refused)
    note(h)
    close(h)

    # ---- refusal: an AI approval the chain refuses
    h = build_engine(tmp_path / "kind-refusal-ai", live=False)
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        preview = post_preview(client).json()
        assert preview["state"] == "pending", preview
        h.engine.limits.set_caps({AI_MAX_ORDER_ENV: "1"})
        refused_approve = signer.post(
            client, approve_path(preview["preview_id"]), {"hash": preview["hash"]}
        )
        assert refused_approve.status_code == 409, refused_approve.text
        assert refused_approve.json().get("code") == ORDER_TOO_LARGE
    ai_refusal = one(h.store, "refusal")
    assert ai_refusal["level"] == "warn", ai_refusal
    assert ai_refusal["owner"] == "ai", ai_refusal
    assert data_of(ai_refusal) == {
        "code": ORDER_TOO_LARGE,
        "preview_id": preview["preview_id"],
    }, data_of(ai_refusal)
    note(h)
    close(h)

    # ---- halt: the kill switch
    h = build_engine(tmp_path / "kind-halt", live=False)
    add_bot(h, BOT)
    with h.client() as client:
        killed = client.post("/kill")
        assert killed.status_code == 200, killed.text
        assert killed.json()["halted"] is True, killed.text
    halted = one(h.store, "halt")
    assert halted["level"] == "ALERT", halted
    assert halted["message"] == "kill switch pressed", halted
    halt_data = data_of(halted)
    assert set(halt_data) == {"cancelled", "stopped"}, halt_data
    assert isinstance(halt_data["cancelled"], int), halt_data
    assert isinstance(halt_data["stopped"], int), halt_data
    note(h)
    close(h)

    # ---- watchdog: a stale heartbeat, alerted once per episode
    h = build_engine(tmp_path / "kind-watchdog", live=False)
    watch = Watchdog(
        h.data_dir,
        h.store,
        lambda: None,
        "leave",
        stale_after_s=300.0,
        now=h.clock,
        env={},
    )
    (h.data_dir / "heartbeat").write_text(
        json.dumps({"ts": h.clock() - 1000.0}), encoding="utf-8"
    )
    h.clock.advance(1000.0)
    assert watch.check() == "stale"
    alerted = one(h.store, "watchdog")
    assert alerted["level"] == "ALERT", alerted
    assert alerted["owner"] is None, alerted
    assert "heartbeat" in alerted["message"], alerted
    # One episode, one alert.
    assert watch.check() == "stale"
    assert len(events_of(h.store, "watchdog")) == 1
    note(h)
    close(h)

    # ---- ai_preview and ai_placed: a preview, then the owner's yes
    h = build_engine(tmp_path / "kind-ai", live=False)
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        preview = post_preview(client).json()
        assert preview["state"] == "pending", preview
        stored_preview = one(h.store, "ai_preview")
        assert stored_preview["level"] == "info", stored_preview
        assert stored_preview["owner"] == "ai", stored_preview
        preview_data = data_of(stored_preview)
        assert set(preview_data) == {
            "preview_id",
            "product",
            "side",
            "size",
            "limit_price",
            "book",
            "notional",
            "expires_at",
        }, preview_data
        assert preview_data["preview_id"] == preview["preview_id"], preview_data
        assert preview_data["product"] == PRODUCT, preview_data
        assert preview_data["side"] == "BUY", preview_data
        assert D(preview_data["size"]) == D("5"), preview_data
        assert D(preview_data["limit_price"]) == D(preview["limit_price"])
        assert preview_data["book"] == "dry", preview_data
        assert D(preview_data["notional"]) == D(str(preview["notional"]))
        assert float(preview_data["expires_at"]) == float(preview["expires_at"])

        accepted = signer.post(
            client, approve_path(preview["preview_id"]), {"hash": preview["hash"]}
        )
        assert accepted.status_code == 200, accepted.text
        cid = accepted.json()["cid"]
    placed = one(h.store, "ai_placed")
    assert placed["level"] == "info", placed
    assert placed["owner"] == "ai", placed
    assert data_of(placed) == {
        "preview_id": preview["preview_id"],
        "cid": cid,
        "book": "dry",
    }, data_of(placed)
    note(h)
    close(h)

    # ---- ai_expired: the cycle's own sweep, with no listing asked for
    h = build_engine(tmp_path / "kind-ai-expired", live=False)
    fund_ai(h)
    prime(h)
    with h.client() as client:
        preview = post_preview(client).json()
        assert preview["state"] == "pending", preview
    h.store.conn().execute(
        "UPDATE ai_previews SET expires_at=? WHERE id=?",
        (time.time() - 5.0, preview["preview_id"]),
    )
    heartbeat = h.runner.cycle()
    assert isinstance(heartbeat, dict), heartbeat
    expired = one(h.store, "ai_expired")
    assert expired["level"] == "info", expired
    assert expired["owner"] == "ai", expired
    assert data_of(expired) == {"preview_id": preview["preview_id"]}, data_of(expired)
    note(h)
    close(h)

    # ---- credentials: the owner disconnects the key
    h = build_engine(tmp_path / "kind-credentials", live=False)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        removed = signer.request(client, "DELETE", "/credentials")
        assert removed.status_code == 200, removed.text
        assert removed.json()["state"] == "missing", removed.text
    credential = one(h.store, "credentials")
    assert credential["level"] == "info", credential
    note(h)
    close(h)

    # ---- live_switch: the signed switch route, and a bot's own book switch
    h = build_engine(tmp_path / "kind-switch")
    add_bot(h, BOT)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        switched = signer.post(client, "/switches", {"live_enabled": True})
        assert switched.status_code == 200, switched.text
        assert switched.json()["live_enabled"] is True, switched.text
        # The same value again changes nothing, so it says nothing.
        again = signer.post(client, "/switches", {"live_enabled": True})
        assert again.status_code == 200, again.text
        route_event = one(h.store, "live_switch")
        assert route_event["level"] == "info", route_event
        assert data_of(route_event) == {
            "switch": "live_enabled",
            "enabled": True,
        }, data_of(route_event)

        h.runner.switch_mode(BOT, "live", "10", "10")
        assert h.store.get_bot(BOT)["mode"] == "live"
    switches = events_of(h.store, "live_switch")
    assert len(switches) == 2, [row["message"] for row in switches]
    bot_switch = switches[-1]
    assert bot_switch["level"] == "info", bot_switch
    assert bot_switch["owner"] == BOT, bot_switch
    assert data_of(bot_switch) == {"bot": BOT, "book": "live"}, data_of(bot_switch)
    note(h)
    close(h)

    # ---- caps: the startup heal, and the body that lowers one
    h = build_engine(tmp_path / "kind-caps", live=False)
    drawdown = next(
        spec for spec in CAP_SPECS if spec.field == "portfolio_drawdown_pct"
    )
    h.store.put("runtime_caps", {drawdown.env: "0"})
    RuntimeLimits(h.engine.limits.ceilings, h.store)
    healed = one(h.store, "caps")
    assert healed["level"] == "warn", healed
    assert drawdown.env in healed["message"], healed
    note(h)
    close(h)

    h = build_engine(tmp_path / "kind-caps-route", live=False)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        lowered = signer.post(client, "/caps", {"caps": {AI_MAX_ORDER_ENV: "20"}})
        assert lowered.status_code == 200, lowered.text
        assert lowered.json()["caps"][AI_MAX_ORDER_ENV] == "20", lowered.text
    changed = one(h.store, "caps")
    assert changed["level"] == "info", changed
    assert changed["message"] == "trading limits changed", changed
    caps_data = data_of(changed)
    assert set(caps_data) == {"names"}, caps_data
    assert caps_data["names"] == [AI_MAX_ORDER_ENV], caps_data
    # Names only: no value of any cap travels with the event.
    assert "20" not in json.dumps(caps_data), caps_data
    note(h)
    close(h)

    # ---- halt: a book's own drawdown, which halts that book and nothing else
    h = build_engine(tmp_path / "kind-book-halt", live=False)
    add_bot(h, BOT, quote="100", base="0")
    prime(h)
    h.store.update_hwm(PORTFOLIO_OWNER, D("1000"), "dry")
    h.runner._check_portfolio_drawdown("dry")
    halted_book = one(h.store, "halt")
    assert halted_book["level"] == "ALERT", halted_book
    assert halted_book["owner"] is None, halted_book
    assert h.gateway.is_halted("dry") is True, halted_book
    assert h.gateway.is_halted("live") is False, halted_book
    note(h)
    close(h)

    # ---- alert: a grid bot whose book is empty
    h = build_engine(tmp_path / "kind-idle", live=False)
    add_bot(h, BOT, quote="100", base="0")
    h.store.set_init_done(BOT)
    h.runner._check_idle_books()
    idle = one(h.store, "alert")
    assert idle["level"] == "ALERT", idle
    assert idle["owner"] is None, idle
    assert BOT in idle["message"], idle
    note(h)
    close(h)

    # ---- alert: an exchange short of what its own book's owners hold
    h = build_engine(tmp_path / "kind-unallocated", live=False)
    add_bot(h, BOT, quote="100", base="50")
    h.runner._check_book_unallocated("dry", {QUOTE: D("0"), BASE: D("0")})
    short = one(h.store, "alert")
    assert short["level"] == "ALERT", short
    assert short["message"].startswith("unallocated negative: "), short
    note(h)
    close(h)

    # ---- alert: the follow-ups of a fill were given up on
    h = build_engine(tmp_path / "kind-follow-ups", live=False)
    add_bot(h, BOT)
    follow_ups(h, BOT, 3, "the exchange refused it")
    h.runner._heal(BOT, h.store.get_bot(BOT), "dry")
    given_up = one(h.store, "alert")
    assert given_up["level"] == "ALERT", given_up
    assert "not offered again" in given_up["message"], given_up
    note(h)
    close(h)

    # ---- bot_paused: every follow-up failed, so the fill is offered again
    h = build_engine(tmp_path / "kind-follow-retry", live=False)
    add_bot(h, BOT)
    follow_ups(h, BOT, 2, "INVALID_LIMIT_PRICE_POST_ONLY")
    h.runner._heal(BOT, h.store.get_bot(BOT), "dry")
    offered = one(h.store, "bot_paused")
    assert offered["level"] == "warn", offered
    assert "offered again" in offered["message"], offered
    note(h)
    close(h)

    # ---- alert: the kill path's sweep could not be made
    h = build_engine(tmp_path / "kind-sweep", live=False)

    class RefusingGateway:
        """The gateway as the kill path's sweep sees it: one call, and it raises."""

        def cancel_all(self, *args: Any, **kwargs: Any):
            raise RuntimeError("the exchange refused the sweep")

    reconcile_module._sweep(h.store, RefusingGateway(), "all", None, "dry")
    unswept = one(h.store, "alert")
    assert unswept["level"] == "error", unswept
    assert "sweep all" in unswept["message"], unswept
    note(h)
    close(h)

    # ---- alert: a cycle the loop could not get through
    h = build_engine(tmp_path / "kind-cycle", live=False)
    real_cycle = h.runner.cycle
    stop = threading.Event()

    def failing_cycle():
        """One cycle that raises, and a loop asked to stop after it."""
        stop.set()
        raise RuntimeError("the cycle failed")

    h.runner.cycle = failing_cycle
    h.runner.run_forever(poll_seconds=0, stop=stop)
    h.runner.cycle = real_cycle
    stuck = one(h.store, "alert")
    assert stuck["level"] == "error", stuck
    assert "cycle" in stuck["message"], stuck
    note(h)
    close(h)

    # ---- bot_paused: one bot's own turn failed inside the cycle
    h = build_engine(tmp_path / "kind-bot-failure", live=False)
    add_bot(h, BOT)
    real_process = h.runner._process_bot

    def failing_process(bot_id: str, *_args: Any, **_kwargs: Any) -> None:
        """A bot's turn that raises, which the cycle records against the bot."""
        raise RuntimeError("the bot failed")

    h.runner._process_bot = failing_process
    failed = h.runner._run_bots()
    h.runner._process_bot = real_process
    assert failed == [BOT], failed
    broke = one(h.store, "bot_paused")
    assert broke["level"] == "error", broke
    assert BOT in broke["message"], broke
    note(h)
    close(h)

    # ---- bot_paused: a bot paused by its own drawdown
    h = build_engine(tmp_path / "kind-drawdown", live=False)
    add_bot(h, BOT, quote="100", base="0")
    prime(h)
    h.store.update_hwm(BOT, D("1000"), "dry")
    h.runner._check_bot_drawdowns()
    stopped = one(h.store, "bot_paused")
    assert stopped["level"] == "ALERT", stopped
    assert stopped["owner"] == BOT, stopped
    assert "drawdown" in stopped["message"], stopped
    assert h.store.get_bot(BOT)["status"] == "PAUSED"
    note(h)
    close(h)

    # ---- bot_paused: a strategy that paused its bot itself
    h = build_engine(tmp_path / "kind-pause", live=False)
    add_bot(h, BOT)
    prime(h)
    h.store.set_init_done(BOT)

    class PausingStrategy:
        """A strategy whose one decision pauses the bot and places nothing."""

        def decide(self, snap: Any, view: Any) -> Decision:
            return Decision(intents=[], pause_reason="the fee is too high")

        def init_intents(self, snap: Any, view: Any) -> Decision:
            return self.decide(snap, view)

    bot = h.store.get_bot(BOT)
    h.runner.strategies[bot["strategy"]] = PausingStrategy()
    h.runner._process_bot(BOT)
    paused = one(h.store, "bot_paused")
    assert paused["level"] == "warn", paused
    assert "the fee is too high" in paused["message"], paused
    note(h)
    close(h)

    # Every kind but the runner's trailing hold was driven above.
    assert set(KINDS) - seen == {"trailing_hold"}, sorted(set(KINDS) - seen)


# ================================================================ trailing hold


def test_trailing_hold_once_per_episode(tmp_path):
    """The alert fires once per episode, re-arms, and the runner raises it."""
    store = Store(tmp_path / "trail.sqlite")
    bench = Benchmark(store)
    owner = "b1"
    key = f"trail:dry:{owner}"
    days = 7
    t0 = 1_700_000_000.0

    # Nothing at all while the comparison is unknown.
    assert bench.trailing(owner, "dry", None, t0, days) is None
    assert store.get(key) is None

    # A negative comparison starts the episode and says nothing yet.
    assert bench.trailing(owner, "dry", D("-1"), t0, days) is None
    assert store.get(key) == {"since": t0, "alerted": False}
    assert bench.trailing(owner, "dry", D("-1"), t0 + 3 * DAY_S, days) is None
    assert bench.trailing(owner, "dry", D("-1"), t0 + 6.9 * DAY_S, days) is None
    assert store.get(key) == {"since": t0, "alerted": False}

    # Seven days in: one alert, carrying the start of the episode.
    alert = bench.trailing(owner, "dry", D("-1"), t0 + 7 * DAY_S, days)
    assert isinstance(alert, dict), alert
    assert set(alert) == {"since", "days_negative"}, alert
    assert float(alert["since"]) == t0, alert
    assert abs(float(alert["days_negative"]) - 7.0) < 0.01, alert
    assert store.get(key) == {"since": t0, "alerted": True}

    # ... and never again in this episode, however long it lasts.
    assert bench.trailing(owner, "dry", D("-1"), t0 + 8 * DAY_S, days) is None
    assert bench.trailing(owner, "dry", D("-1"), t0 + 20 * DAY_S, days) is None
    assert store.get(key) == {"since": t0, "alerted": True}

    # An unknown comparison leaves the state exactly as it was, and writes nothing.
    before = store.conn().execute(
        "SELECT value FROM kv WHERE key=?", (key,)
    ).fetchone()[0]
    assert bench.trailing(owner, "dry", None, t0 + 21 * DAY_S, days) is None
    after = store.conn().execute(
        "SELECT value FROM kv WHERE key=?", (key,)
    ).fetchone()[0]
    assert after == before, (before, after)

    # At or above zero the episode re-arms.
    assert bench.trailing(owner, "dry", D("0"), t0 + 22 * DAY_S, days) is None
    assert store.get(key) == {"since": None, "alerted": False}
    assert bench.trailing(owner, "dry", D("5"), t0 + 23 * DAY_S, days) is None
    assert store.get(key) == {"since": None, "alerted": False}

    # A second episode is a second alert, whenever it starts.
    t1 = t0 + 30 * DAY_S
    assert bench.trailing(owner, "dry", D("-2"), t1, days) is None
    assert store.get(key) == {"since": t1, "alerted": False}
    second = bench.trailing(owner, "dry", D("-2"), t1 + 7 * DAY_S, days)
    assert isinstance(second, dict), second
    assert float(second["since"]) == t1, second

    # The state is in the store, not in the object: a new Benchmark reads it.
    fresh = Benchmark(store)
    assert fresh.trailing(owner, "dry", D("-2"), t1 + 8 * DAY_S, days) is None
    assert store.get(key) == {"since": t1, "alerted": True}
    # Each book has its own episode.
    assert fresh.trailing(owner, "live", D("-2"), t1 + 9 * DAY_S, days) is None
    assert store.get(f"trail:live:{owner}") == {
        "since": t1 + 9 * DAY_S,
        "alerted": False,
    }, store.get(f"trail:live:{owner}")
    store.close()

    # ---- the runner: one event per episode, at the number of days it is told
    def trailing_events(h: Harness) -> list[dict]:
        return events_of(h.store, "trailing_hold")

    h = trailing_engine(tmp_path / "trail-runner")
    assert h.runner.trail_alert_days == 7, h.runner.trail_alert_days
    h.runner.cycle()
    assert trailing_events(h) == [], trailing_events(h)
    h.clock.advance(3 * DAY_S)
    h.runner.cycle()
    assert trailing_events(h) == [], trailing_events(h)
    h.clock.advance(3.9 * DAY_S)
    h.runner.cycle()
    assert trailing_events(h) == [], trailing_events(h)
    h.clock.advance(0.2 * DAY_S)
    h.runner.cycle()
    raised = trailing_events(h)
    assert len(raised) == 1, [row["message"] for row in raised]
    held = raised[0]
    assert held["level"] == "warn", held
    assert held["owner"] == BOT, held
    payload = data_of(held)
    assert set(payload) == {"bot", "book", "days_negative"}, payload
    assert payload["bot"] == BOT, payload
    assert payload["book"] == "dry", payload
    assert float(payload["days_negative"]) >= 7.0, payload
    assert BOT in held["message"], held
    # A later cycle in the same episode says nothing new.
    h.clock.advance(1 * DAY_S)
    h.runner.cycle()
    assert len(trailing_events(h)) == 1, trailing_events(h)
    close(h)

    # The number of days is the environment's, and seven when it is not one.
    short = trailing_engine(tmp_path / "trail-two", env={TRAIL_DAYS_ENV: "2"})
    assert short.runner.trail_alert_days == 2, short.runner.trail_alert_days
    short.runner.cycle()
    assert trailing_events(short) == [], trailing_events(short)
    short.clock.advance(2.05 * DAY_S)
    short.runner.cycle()
    assert len(trailing_events(short)) == 1, trailing_events(short)
    close(short)

    for index, junk in enumerate(("x", "0", "-3")):
        engine = trailing_engine(
            tmp_path / f"trail-junk-{index}", env={TRAIL_DAYS_ENV: junk}
        )
        assert engine.runner.trail_alert_days == 7, (
            junk,
            engine.runner.trail_alert_days,
        )
        engine.runner.cycle()
        engine.clock.advance(3 * DAY_S)
        engine.runner.cycle()
        assert trailing_events(engine) == [], (junk, trailing_events(engine))
        close(engine)


# ================================================================ the alert's write


def test_trailing_hold_alert_is_one_write(tmp_path):
    """An alert the store will not take leaves the episode unalerted, and re-offered.

    The episode's mark and the `trailing_hold` event are one write: a store that
    refuses the event takes the mark back with it, so the next cycle owes the
    alert again rather than recording an episode nothing was ever told about.
    """
    h = trailing_engine(tmp_path / "trail-atomic")
    key = f"trail:dry:{BOT}"
    h.runner.cycle()
    h.clock.advance(7.1 * DAY_S)

    quiet = QuietEvents(h.store, "trailing_hold")
    real = h.store.event
    h.store.event = quiet
    try:
        assert isinstance(h.runner.cycle(), dict)
    finally:
        h.store.event = real

    assert quiet.refused == 1, quiet.refused
    state = h.store.get(key)
    assert isinstance(state, dict), state
    assert state["alerted"] is False, state
    assert events_of(h.store, "trailing_hold") == [], rows(h.store)

    # The next cycle offers it again, and writes exactly one.
    assert isinstance(h.runner.cycle(), dict)
    raised = events_of(h.store, "trailing_hold")
    assert len(raised) == 1, [row["message"] for row in raised]
    assert h.store.get(key)["alerted"] is True, h.store.get(key)
    close(h)


# ================================================================ a book switch


def test_trailing_hold_resets_on_book_switch(tmp_path):
    """A switch forgets the trail of the book it leaves, so an old stretch is not news.

    Six days of trailing on the dry book, then live and back: the dry book's
    episode is gone (`Benchmark.forget` resets the trail beside the baseline), and
    the book the bot trades has to trail for the whole window again.  The live
    book's own record is the other half of the same rule — it was seeded with an
    episode that started a hundred days ago, and the switch to live clears it.
    """
    h = trailing_engine(tmp_path / "trail-switch", live=True)
    dry_key = f"trail:dry:{BOT}"
    live_key = f"trail:live:{BOT}"

    # Six days under the hold on the dry book: an episode, and no alert yet.
    h.runner.cycle()
    started = h.clock()
    assert h.store.get(dry_key) == {"since": started, "alerted": False}, h.store.get(
        dry_key
    )
    h.clock.advance(6 * DAY_S)
    h.runner.cycle()
    assert events_of(h.store, "trailing_hold") == [], rows(h.store)

    # An episode on the live book that started long ago, and was never alerted.
    h.store.put(live_key, {"since": h.clock() - 100 * DAY_S, "alerted": False})

    h.gateway.switches.set("live_enabled", True)
    h.runner.switch_mode(BOT, "live", "10", "10")
    assert h.store.get_bot(BOT)["mode"] == "live"
    # The trail of the book the bot now trades is cleared with its baseline.
    assert h.store.get(live_key) == {"since": None, "alerted": False}, h.store.get(
        live_key
    )

    # The cycle would raise the old live episode at once if it were still there:
    # its mix is worth more than the bot holds, exactly as on the dry book.
    h.runner.benchmark.start(
        BOT, base=D("0"), quote=D("200"), price=D("0.995"), book="live"
    )
    h.runner.cycle()
    assert events_of(h.store, "trailing_hold") == [], rows(h.store)

    # Back to the dry book: the episode of the six days it spent there is gone.
    h.runner.switch_mode(BOT, "dry")
    assert h.store.get_bot(BOT)["mode"] == "dry"
    assert h.store.get(dry_key) == {"since": None, "alerted": False}, h.store.get(
        dry_key
    )
    h.runner.benchmark.start(
        BOT, base=D("0"), quote=D("200"), price=D("0.995"), book="dry"
    )

    # A full window on the dry book, from now: an old stretch would already be a
    # week and more, so a single cycle here would be the alert.
    h.runner.cycle()
    restarted = h.clock()
    assert h.store.get(dry_key) == {"since": restarted, "alerted": False}, h.store.get(
        dry_key
    )
    assert events_of(h.store, "trailing_hold") == [], rows(h.store)
    h.clock.advance(6.9 * DAY_S)
    h.runner.cycle()
    assert events_of(h.store, "trailing_hold") == [], rows(h.store)
    h.clock.advance(0.2 * DAY_S)
    h.runner.cycle()
    raised = events_of(h.store, "trailing_hold")
    assert len(raised) == 1, [row["message"] for row in raised]
    assert data_of(raised[0])["book"] == "dry", data_of(raised[0])
    assert float(data_of(raised[0])["days_negative"]) >= 7.0, data_of(raised[0])
    close(h)


# ================================================================ secrets


def _event_blob(store: Store) -> str:
    """Every value of every event row, as one text to search."""
    lines: list[str] = []
    for row in store.conn().execute("SELECT * FROM events"):
        lines.append(" ".join(str(value) for value in dict(row).values()))
    return "\n".join(lines)


def _identifiers(node: ast.AST) -> list[str]:
    """Every name and attribute name one expression references."""
    names: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.append(sub.id)
        elif isinstance(sub, ast.Attribute):
            names.append(sub.attr)
    return names


def _event_call_name(node: ast.Call) -> Optional[str]:
    """The name an event is written under, or None when this call writes none.

    Three names write an event: the store's own `event`, the API's `_record` and
    the AI surface's `_announce`.  The first is looked for on the attribute it is
    called on (`store.event`, `self._store.event`), the other two by their own
    name, so a call through either wrapper is covered exactly as the store's own.
    """
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr if func.attr == "event" else None
    if isinstance(func, ast.Name) and func.id in EVENT_CALLS:
        return func.id
    return None


def test_events_never_contain_secrets(tmp_path):
    """No secret any request, key or failing exchange carries reaches an event.

    One engine carries both books and every source that writes an event is driven
    on it: the owner's key (accepted, refused and locked out), the kill switch, the
    clear, the switches, the caps, a fill and a refusal on each book, the AI's
    preview, approval, refusal and expiry, the runner's own alerts, a bot's switch
    to live, and the watchdog.  One exchange call is made to fail with a text of
    its own, so the events that interpolate an error run too.  Then every row is
    read with raw SQL and searched, its message and its payload both, and every
    page of the feed is searched as well.
    """
    # A marker that is not a secret: a failing exchange puts it in its exception
    # text, and the test looks for it in the events — which is how it knows the
    # `{error}`-interpolating paths really ran, rather than passing because they
    # never did.
    error_mark = "error-canary-" + secrets.token_hex(8)
    failure = RuntimeError("the exchange failed: " + error_mark)
    builder = LiveBuilder(permissions())
    h = build_engine(tmp_path / "secrets", live=True, live_builder=builder)
    # The gateway reads the same clock as the runner, so the days this test moves
    # are days the snapshots it polls stay usable for.
    h.gateway.now = h.clock
    fund_ai(h)
    add_bot(h, BOT, quote="100", base="50")
    add_bot(h, "b2", quote="0", base="0")
    prime(h)

    secret = owner_secret()
    wrong_secret = "wrong-" + secrets.token_hex(20)
    key_name = key_name_canary()
    private_key, key_marker = _pem_pair()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    install = Signer(h.install_token, h.clock)

    # Every value in this tuple is built at runtime, and none of them may appear
    # in an event: the two tokens the engine holds, the two secrets a push
    # carries, the key name and the private key (the whole text, its header line
    # and the line in its body a payload would carry whatever escaping it uses).
    canaries = (
        TOKEN,
        h.install_token,
        secret,
        wrong_secret,
        key_name,
        private_key,
        key_marker,
        private_key.split("\n")[0],
    )

    with h.client() as client:
        # ---- the owner's key: accepted, refused, and locked out
        accepted = install.post(
            client,
            "/credentials",
            credentials_body(key_name, private_key, secret),
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["state"] == "ok", accepted.text

        # The same key pair, refused by the exchange's own permissions answer.
        builder.perms = permissions(can_transfer=True)
        refused_push = signer.post(
            client,
            "/credentials",
            credentials_body(key_name, private_key, secret),
        )
        assert refused_push.status_code == 422, refused_push.text
        assert refused_push.json().get("code") == KEY_CAN_TRANSFER, refused_push.text
        builder.perms = permissions()

        # The lockout: five wrong secrets, and the sixth answers the lockout.
        wrong = Signer(wrong_secret, h.clock)
        answers = [
            wrong.post(
                client,
                "/credentials",
                credentials_body(key_name, private_key, wrong_secret),
            )
            for _ in range(6)
        ]
        assert answers[0].status_code == 403, answers[0].text
        assert answers[0].json().get("detail") == "SECRET_MISMATCH", answers[0].text
        assert answers[-1].status_code == 429, answers[-1].text

        # ---- the AI, on the dry book: a preview, the owner's yes, and a refusal
        preview = post_preview(client).json()
        assert preview["state"] == "pending", preview
        placed = signer.post(
            client, approve_path(preview["preview_id"]), {"hash": preview["hash"]}
        )
        assert placed.status_code == 200, placed.text

        refused_preview = post_preview(client).json()
        assert refused_preview["state"] == "pending", refused_preview
        h.engine.limits.set_caps({AI_MAX_ORDER_ENV: "1"})
        refused_approve = signer.post(
            client,
            approve_path(refused_preview["preview_id"]),
            {"hash": refused_preview["hash"]},
        )
        assert refused_approve.status_code == 409, refused_approve.text
        h.engine.limits.set_caps({AI_MAX_ORDER_ENV: "25"})

        # A preview nothing answers, retired by the surface's own sweep.
        expiring = post_preview(client).json()
        assert expiring["state"] == "pending", expiring
        h.store.conn().execute(
            "UPDATE ai_previews SET expires_at=? WHERE id=?",
            (time.time() - 5.0, expiring["preview_id"]),
        )
        h.ai.sweep()
        assert events_of(h.store, "ai_expired"), rows(h.store)

    # ---- the dry book's own sources
    booked_fill(h, BOT, "dry")
    assert (
        h.runner._place(h.store.get_bot(BOT), too_small_intent(), PRODUCT, init=False)
        == TOO_SMALL
    )

    # A grid bot whose book is empty, and an exchange short of its owners.
    h.store.set_init_done("b2")
    h.runner._check_idle_books()
    h.runner._check_book_unallocated("dry", {QUOTE: D("0"), BASE: D("0")})

    # A bot paused by its own drawdown.
    h.store.update_hwm(BOT, D("1000"), "dry")
    h.runner._check_bot_drawdowns()
    h.store.set_bot_status(BOT, "ACTIVE")

    # The follow-ups of a fill the exchange kept refusing.
    add_bot(h, "b3", quote="100", base="0")
    follow_ups(h, "b3", 3, "the exchange refused it")
    h.runner._heal("b3", h.store.get_bot("b3"), "dry")

    # ---- the same engine's live book: a switch, a fill, an alert, and a preview
    h.gateway.switches.set("live_enabled", True)
    h.runner.switch_mode(BOT, "live", "10", "10")
    booked_fill(h, BOT, "live")
    h.runner._check_book_unallocated("live", {QUOTE: D("0"), BASE: D("0")})
    h.gateway.switches.set("ai_live_enabled", True)
    with h.client() as client:
        # Larger than the AI's single-order cap, so the chain refuses it on the
        # live book and the refusal is recorded there rather than on the dry one.
        live_preview = post_preview(client, size="50").json()
        assert live_preview["book"] == "live", live_preview
        assert live_preview["state"] == "rejected", live_preview
        assert live_preview["refusal"] == ORDER_TOO_LARGE, live_preview
    h.gateway.switches.set("ai_live_enabled", False)

    # ---- a trailing hold, and the watchdog's stale-heartbeat alert
    # The cycle the hold is measured by starts now and is news a week later, so
    # the clock moves and the book is polled again on it before the second look.
    h.runner.benchmark.start(
        BOT, base=D("0"), quote=D("200"), price=D("0.995"), book="live"
    )
    h.runner._trailing_holds()
    h.clock.advance(8 * DAY_S)
    h.runner._poll_markets()
    h.runner._trailing_holds()
    assert events_of(h.store, "trailing_hold"), rows(h.store)
    watch = Watchdog(
        h.data_dir,
        h.store,
        lambda: None,
        "leave",
        stale_after_s=300.0,
        now=h.clock,
        env={},
    )
    (h.data_dir / "heartbeat").write_text(
        json.dumps({"ts": h.clock() - 1000.0}), encoding="utf-8"
    )
    h.clock.advance(1000.0)
    assert watch.check() == "stale"
    assert events_of(h.store, "watchdog"), rows(h.store)

    # ---- the kill switch, the clear, the switches and the caps
    h.gateway.clear_halt()
    with h.client() as client:
        killed = client.post("/kill")
        assert killed.status_code == 200, killed.text
        cleared = signer.post(client, "/halt/clear", {"acknowledge_rebase": True})
        assert cleared.status_code == 200, cleared.text
        turned = signer.post(
            client, "/switches", {"live_enabled": False, "ai_live_enabled": True}
        )
        assert turned.status_code == 200, turned.text
        capped = signer.post(client, "/caps", {"caps": {AI_MAX_ORDER_ENV: "13"}})
        assert capped.status_code == 200, capped.text

    # ---- the events that interpolate an error
    # A poll that cannot read the book, and a clock the exchange will not report.
    market_for(PRODUCT).failure = failure
    h.runner._poll_markets()
    market_for(PRODUCT).failure = None

    real = h.engine.exchange
    faulty = FaultyExchange(real)
    h.runner.exchange = faulty
    h.gateway.exchange = faulty
    h.gateway.books.dry = faulty
    faulty.failures["server_time"] = failure
    h.runner._poll_markets()

    # A halted book's sweep, which the reconcile loop tries and cannot make.
    cancel_cid = "cb-b1-B7-" + secrets.token_hex(6)
    real.place_limit(cancel_cid, PRODUCT, "BUY", D("1"), D("0.98"))
    h.store.insert_order(
        cancel_cid, BOT, "bot", PRODUCT, "BUY", 0, D("0.98"), D("1"),
        status=OPEN, book="dry", product_type="SPOT",
    )
    faulty.failures["cancel"] = failure
    h.gateway.halt("a sweep that cannot be made", "dry")
    assert isinstance(h.runner.cycle(), dict)
    h.gateway.clear_halt(book="dry")

    # A cycle the loop could not get through, and a bot's own turn that raised.
    faulty.failures.clear()
    stop = threading.Event()
    real_cycle = h.runner.cycle

    def failing_cycle():
        """One cycle that raises, and a loop asked to stop after it."""
        stop.set()
        raise RuntimeError("the cycle failed: " + error_mark)

    h.runner.cycle = failing_cycle
    h.runner.run_forever(poll_seconds=0, stop=stop)
    h.runner.cycle = real_cycle

    real_process = h.runner._process_bot

    def failing_process(bot_id: str, *_args: Any, **_kwargs: Any) -> None:
        """A bot's turn that raises, which the cycle records against the bot."""
        raise RuntimeError("the bot failed: " + error_mark)

    h.runner._process_bot = failing_process
    h.runner._run_bots()
    h.runner._process_bot = real_process

    # ---- every source above really wrote its event
    written = {row["kind"] for row in rows(h.store)}
    assert {
        "credentials",
        "halt",
        "live_switch",
        "caps",
        "fill",
        "refusal",
        "ai_preview",
        "ai_placed",
        "ai_expired",
        "watchdog",
        "trailing_hold",
    } <= written, sorted(written)
    messages = [str(row["message"]) for row in rows(h.store)]
    assert sum(error_mark in message for message in messages) >= 4, messages

    # ---- and none of them carries a secret
    for row in rows(h.store):
        line = " ".join(str(value) for value in row.values())
        payload = str(row["data_json"] or "")
        for value in canaries:
            assert value not in line, (row["kind"], row["id"])
            assert value not in payload, (row["kind"], row["id"])
    blob = _event_blob(h.store)
    for value in canaries:
        assert value not in blob, value

    # The feed carries none of them either, on any page of it.
    with h.client() as client:
        after = 0
        pages = 0
        while True:
            response = client.get(
                "/events", params={"after": after, "limit": MAX_LIMIT}
            )
            assert response.status_code == 200, response.text
            for value in canaries:
                assert value not in response.text, value
            body = response.json()
            if not body["events"]:
                break
            after = body["last_id"]
            pages += 1
            assert pages < 50, pages
    assert pages >= 1, pages
    close(h)

    # ---- no call anywhere in the package hands an event a secret-shaped name
    checked = 0
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _event_call_name(node) is None:
                continue
            checked += 1
            expressions = list(node.args) + [
                keyword.value for keyword in node.keywords
            ]
            for expression in expressions:
                for name in _identifiers(expression):
                    lowered = name.lower()
                    assert not any(
                        word in lowered for word in SECRET_WORDS
                    ), (path.name, node.lineno, name)
    assert checked > 0, checked


# ================================================================ the source tag


def test_mcp_source_tagged(tmp_path):
    """`X-Crow-Source: mcp` tags an event a request writes, and nothing else does."""
    h = build_engine(tmp_path / "source", live=False)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    mcp = {"X-Crow-Source": "mcp"}

    with h.client() as client:
        tagged = client.post("/kill", headers=mcp)
        assert tagged.status_code == 200, tagged.text
        first = events_of(h.store, "halt")[-1]
        assert data_of(first).get("source") == "mcp", data_of(first)
        # The rest of the payload is kept beside the tag.
        assert set(data_of(first)) == {"cancelled", "stopped", "source"}, data_of(first)

        # No header, another case, another value: never tagged.
        for headers in ({}, {"X-Crow-Source": "MCP"}, {"X-Crow-Source": "other"}):
            answered = client.post("/kill", headers=headers)
            assert answered.status_code == 200, answered.text
            latest = events_of(h.store, "halt")[-1]
            assert "source" not in data_of(latest), (headers, data_of(latest))

        # A following untagged request writes an untagged event.
        untagged = signer.post(client, "/caps", {"caps": {AI_MAX_ORDER_ENV: "19"}})
        assert untagged.status_code == 200, untagged.text
        assert "source" not in data_of(events_of(h.store, "caps")[-1])
        assert events_of(h.store, "caps"), rows(h.store)

        # An AI preview made with the header has its own event tagged.  The halt
        # the kills set is cleared first: a preview is only stored when the chain
        # would let the order out.
        h.gateway.clear_halt()
        fund_ai(h)
        prime(h)
        preview = client.post(
            "/ai/previews",
            json={
                "product": PRODUCT,
                "side": "BUY",
                "size": "5",
                "limit_price": "0.98",
            },
            headers=mcp,
        )
        assert preview.status_code == 200, preview.text
        assert preview.json()["state"] == "pending", preview.text
        preview_event = events_of(h.store, "ai_preview")[-1]
        assert data_of(preview_event).get("source") == "mcp", data_of(preview_event)

        # A cycle run right after a tagged request is never tagged: the tag
        # belongs to the request that carried it, not to the process.
        h.store.create_bot("zz", PRODUCT, "no-such-strategy", {}, D("0"), D("0"))
        known = {row["id"] for row in rows(h.store)}
        h.runner.cycle()
        fresh = [row for row in rows(h.store) if row["id"] not in known]
        assert fresh, "the cycle wrote no event"
        for row in fresh:
            assert "source" not in data_of(row), row

        # The read route needs no such header at all.
        read = client.get("/events", params={"limit": MAX_LIMIT})
        assert read.status_code == 200, read.text
        assert read.json()["events"], read.text
    close(h)