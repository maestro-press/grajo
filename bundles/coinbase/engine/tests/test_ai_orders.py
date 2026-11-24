"""test_ai_orders.py: AI order previews, the owner's approval, and the one send.

Every test here builds the REAL engine through `build_app`: a real `Store` on a
temporary data directory, the real dry-run exchange, gateway, runner, runtime
caps and approval rail, and the AI order surface the app mounts from them.  Only
the outside world is faked: `FakeMarket` answers one fixed touch (so nothing
opens a socket) and the live book is a SECOND `DryRunExchange` over a second
store file, wrapped in an `ExchangeRouter` and handed to `build_app` as its
`live_factory`, exactly as the other engine tests do it.

`RecordingDry` wraps a book's exchange: it records every write call, and it can
answer a post-only refusal or die with a `BaseException` on the next place, so
"nothing was sent" and "the process died between the consume and the send" are
assertions about real calls rather than about a stub.

The owner is the real approval rail: a privileged request is signed the way
`Authenticator` checks one (`Signer` hands `auth.compute_mac` the same bytes
`TestClient` sends).  Every secret, key and token here is built at runtime, so
no value in this file is a credential.

What each test pins down:

* a preview runs the whole chain on the book the route decides, answers the
  pending row and the five limits, sends nothing and writes no order; every
  chain refusal comes back as a refused row, and a malformed body stores nothing,
* a size or a price off the product's own increment is refused before a row is
  written, twenty previews may wait at once and sixty may be made in an hour,
* a preview reports the price the user asked beside the hashed maker price an
  approval covers, and a row from before that field answers null,
* a `submit("ai", ...)` without an approved, unexpired, unconsumed preview whose
  hash matches is `APPROVAL_REQUIRED`, writes nothing, and never touches a bot's
  own path; `check()` runs that step too, while `evaluate()` is the chain alone,
* an approval needs the right hash, a preview that has not expired, and a book
  that has not changed since the preview was taken,
* a reject that had already read a preview cannot undo the order the approval
  placed, and an approval whose window closed before it was spent answers
  `EXPIRED` rather than a rejection,
* an approved order never reprices: a book that moved past the stored limit is
  `POST_ONLY_WOULD_CROSS` before anything is written, and an exchange's own
  post-only refusal is one attempt, one row, and no retry,
* two approvals racing — in two threads of one engine, and in two engines over
  one sqlite file — place exactly one order,
* the sweep keeps an answered preview that has an order behind it, retires a
  placed preview whose order the exchange refused, gives up on an approval
  nobody answered, and the two rules that depend on the cycle being held still
  — an approval nobody spent and an order the book lost — run only in the swept
  cycle (`sweep_locked`), never on a preview, a listing, a reject or an
  approve's own sweep,
* a row already finished with a code of its own (`POST_ONLY_WOULD_CROSS`) is
  never overwritten with `ORDER_FAILED`, a preview whose order the book
  cancelled ends `cancelled` with no code at all, and the flood is counted again
  inside the insert's own transaction so a preview past a bound writes no row
  even when the cheap early check is out of the way,
* the cycle asks the AI surface to sweep once per cycle, and a sweep that raises
  costs the cycle nothing but its own warning,
* every cap, the halt and the AI's money are checked again at the approve,
* a crash after the consume and before the send leaves a row reconcile settles,
  and the approval cannot be spent a second time,
* a failed insert leaves the approval unspent, and a consume that cannot spend
  it refuses the order,
* a cancel is the AI's alone (a bot's order is `NOT_OWNER`), known ids only, and
  the preview it placed ends `cancelled`,
* the approve route is the strict gate's (the install token is never a key) while
  preview, list, reject and cancel are the bearer token's,
* `CROW_COINBASE_AI_ORDER_MODE=autonomous` and an unusable TTL refuse the start,
  and the TTL the environment names is the one a preview is given,
* `ai_orders.py` reaches no exchange write method, by the package's own scan.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import secrets
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal as D
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import crow_coinbase.__main__ as main_module
import crow_coinbase.auth as auth_module
from crow_coinbase.__main__ import build_app, main
from crow_coinbase.exchange import DryRunExchange
from crow_coinbase.gateway import GatewayResult
from crow_coinbase.money import ProductSpec
from crow_coinbase.reconcile import reconcile
from crow_coinbase.router import ExchangeRouter
from crow_coinbase.store import (
    CANCELLED,
    FAILED,
    FILLED,
    OPEN,
    PENDING_SUBMIT,
    REJECTED,
    Store,
)
from crow_coinbase.strategies.base import MarketSnapshot, OrderIntent

# The engine harness lives beside this file, so the no-bypass guard can be used.
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

SRC = Path(__file__).resolve().parents[1] / "src" / "crow_coinbase"

# ---------------------------------------------------------------- test data
PRODUCT = "XRP-USDC"
SECOND = "BTC-USDC"
BASE = "XRP"
QUOTE = "USDC"
BOT = "b1"

FEE_RATE = D("0.005")

# 32+ characters, no whitespace: the shortest bearer token the engine starts with.
TOKEN = "test-token-" + secrets.token_hex(16)
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# The environment every engine here starts from.  `CROW_COINBASE_LIVE` is spelled
# out because `main` refuses a ceiling nobody can read.
BASE_ENV = {
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": f"{PRODUCT},{SECOND}",
    "CROW_COINBASE_MAX_BOT_CAPITAL_USD": "100",
    "CROW_COINBASE_LIVE": "true",
}

# The two variables the AI order surface reads, named here so a rename fails.
AI_MODE_ENV = "CROW_COINBASE_AI_ORDER_MODE"
AI_TTL_ENV = "CROW_COINBASE_AI_PREVIEW_TTL_S"
AI_MAX_ORDER = "CROW_COINBASE_AI_MAX_ORDER_USD"
AI_DAILY = "CROW_COINBASE_AI_DAILY_NOTIONAL_USD"
AI_ORDERS_HOUR = "CROW_COINBASE_AI_ORDERS_PER_HOUR"

DEFAULT_TTL_S = 900
DAY_S = 86400.0

# The refusal codes this surface answers with.
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
POST_ONLY_WOULD_CROSS = "POST_ONLY_WOULD_CROSS"
HASH_MISMATCH = "HASH_MISMATCH"
EXPIRED = "EXPIRED"
NOT_PENDING = "NOT_PENDING"
NOT_FOUND = "NOT_FOUND"
BOOK_CHANGED = "BOOK_CHANGED"
NOT_OWNER = "NOT_OWNER"
NOT_CANCELLABLE = "NOT_CANCELLABLE"
LIVE_LOCKED = "LIVE_LOCKED"
INVALID = "INVALID"
TOO_SMALL = "TOO_SMALL"
ORDER_TOO_LARGE = "ORDER_TOO_LARGE"
DAILY_CAP = "DAILY_CAP"
RATE_CAP = "RATE_CAP"
INSUFFICIENT_HOLDING = "INSUFFICIENT_HOLDING"
STALE_MARKET = "STALE_MARKET"
HALTED = "HALTED"
PRODUCT_NOT_ALLOWED = "PRODUCT_NOT_ALLOWED"

# The six states a preview may hold.
PENDING, APPROVED, PLACED, EXPIRED_STATE, REJECTED_STATE, CANCELLED_STATE = (
    "pending",
    "approved",
    "placed",
    "expired",
    "rejected",
    "cancelled",
)
PREVIEW_STATES = (
    PENDING,
    APPROVED,
    PLACED,
    EXPIRED_STATE,
    REJECTED_STATE,
    CANCELLED_STATE,
)

# The five limits a preview reports, and the key each entry carries.
LIMIT_NAMES = (
    "ai_max_order_usd",
    "ai_daily_notional_usd",
    "daily_notional_usd",
    "ai_orders_per_hour",
    "orders_per_hour",
)
LIMIT_KEYS = {"name", "limit", "used_after"}

# The exchange's own word for a post-only order that would have crossed.
EXCHANGE_POST_ONLY = "INVALID_LIMIT_PRICE_POST_ONLY"
# What the engine answers when the price moved past a stored approval.
PRICE_MOVED = "Price moved; ask again"


# ---------------------------------------------------------------- the engine's
# own modules, imported where a test needs them: a module this build does not
# have yet has to fail the test that uses it, not the collection of this file.


def ai_module():
    """The AI orders module, imported where a test needs it."""
    import crow_coinbase.ai_orders as module

    return module


def no_bypass_module():
    """The package's no-bypass scan, imported where a test needs it."""
    import test_no_bypass as module

    return module


# ---------------------------------------------------------------- outside world


class FakeMarket:
    """A public market with a fixed touch: no client, no request, no candles."""

    def __init__(self, bid=D("0.99"), ask=D("1.00")):
        self.bid, self.ask = D(bid), D(ask)
        self.low, self.high = self.bid, self.ask

    def best_bid_ask(self):
        return self.bid, self.ask

    def range_since(self, since):
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
    built with the wall clock agree about "now"; the expiry helpers below move
    both, so a test about expiry never depends on which clock was wired.
    """

    def __init__(self, at: float | None = None):
        self.at = time.time() if at is None else float(at)

    def __call__(self) -> float:
        return self.at

    def advance(self, seconds: float) -> float:
        self.at += float(seconds)
        return self.at


class Crash(BaseException):
    """A send that dies the way a process dies: nothing catches `BaseException`."""


class RecordingDry:
    """An exchange, wrapped: records writes, and can refuse or die on a place.

    `mode` is "ok" (the real placement), "post_only" (the exchange's own
    post-only refusal) or "crash" (a `BaseException` raised instead of a call).
    Every other attribute is the wrapped exchange's, so the gateway, the ledger
    and reconcile see the book they always did.
    """

    def __init__(self, inner):
        object.__setattr__(self, "inner", inner)
        object.__setattr__(self, "place_calls", [])
        object.__setattr__(self, "writes", [])
        object.__setattr__(self, "mode", "ok")

    def place_limit(self, cid, product, side, size, price):
        self.place_calls.append((cid, product, side, D(size), D(price)))
        mode = self.mode
        if mode == "crash":
            raise Crash()
        if mode == "post_only":
            return {"ok": False, "order_id": None, "reason": EXCHANGE_POST_ONLY}
        return self.inner.place_limit(cid, product, side, size, price)

    def deposit(self, currency, amount, note):
        self.writes.append("deposit")
        return self.inner.deposit(currency, amount, note)

    def cancel(self, order_ids):
        self.writes.append("cancel")
        return self.inner.cancel(order_ids)

    def place_equity_limit(self, cid, product, side, size, price):
        self.writes.append("place_equity_limit")
        return self.inner.place_equity_limit(cid, product, side, size, price)

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def clear(self) -> None:
        """Forget every call so a test can assert about the next one alone."""
        self.place_calls.clear()
        self.writes.clear()


# ---------------------------------------------------------------- requests


class Signer:
    """Builds the three approval headers for one request over the bytes it sends."""

    def __init__(self, key, clock) -> None:
        self.key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        self.clock = clock

    def nonce(self) -> str:
        """A fresh nonce: long enough, and unique per request."""
        return "n" + secrets.token_hex(12)

    def headers(self, method: str, path_with_query: str, body: bytes = b"", **kwargs):
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

    def post(self, client, path_with_query: str, payload: Any = None):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        return client.post(
            path_with_query,
            content=body,
            headers=self.headers("POST", path_with_query, body),
        )


def owner_secret() -> str:
    """An approval secret, 32+ characters, built at runtime."""
    return "approve-" + secrets.token_hex(20)


def approve_path(preview_id: str) -> str:
    return f"/ai/previews/{preview_id}/approve"


def reject_path(preview_id: str) -> str:
    return f"/ai/previews/{preview_id}/reject"


def cancel_path(cid: str) -> str:
    return f"/ai/orders/{cid}/cancel"


# ---------------------------------------------------------------- the harness


@dataclass
class Harness:
    """One engine, both its books and the signer over its clock."""

    engine: Any
    clock: Clock
    root: Path
    data_dir: Path
    token_path: Path
    install_token: str
    dry: RecordingDry
    live: RecordingDry | None = None
    live_store: Store | None = None
    live_sim: Any = None

    @property
    def store(self) -> Store:
        return self.engine.store

    @property
    def gateway(self):
        return self.engine.gateway

    @property
    def ai(self):
        """The AI order surface this engine was built with."""
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
    env: dict | None = None,
    live: bool = True,
    clock: Clock | None = None,
) -> Harness:
    """The real engine over *root*, with both books and a fake market.

    `live=False` wires a live side that answers no exchange at all, so the live
    book is locked exactly as it is on an engine no key was pushed to.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = root / "install_token"
    install_token = "install-" + secrets.token_hex(20)
    token_path.write_text(install_token + "\n", encoding="utf-8")
    clock = Clock() if clock is None else clock

    live_store = None
    live_sim = None
    live_rec = None
    if live:
        live_store = Store(root / "live.db")
        live_sim = DryRunExchange(live_store.conn, market_for, FEE_RATE)
        for currency in (QUOTE, BASE, "BTC"):
            live_sim.deposit(currency, D("1000"), "funding")
        live_rec = RecordingDry(ExchangeRouter(live_sim, usd_one_pool=True))

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
        live_factory=(lambda: live_rec) if live else (lambda: None),
    )

    # The simulator every dry order reaches is the wrapped one, so a test can
    # see (and count) the sends; nothing is written here.
    for currency in (QUOTE, BASE):
        engine.exchange.deposit(currency, D("100000"), "test float")
    dry = RecordingDry(engine.exchange)
    engine.gateway.books.dry = dry

    return Harness(
        engine=engine,
        clock=clock,
        root=root,
        data_dir=data_dir,
        token_path=token_path,
        install_token=install_token,
        dry=dry,
        live=live_rec,
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


def prime(h: Harness, *, bid="0.99", ask="1.00", products=(PRODUCT, SECOND), ts=None):
    """A usable snapshot per product, stamped now unless the caller says when."""
    at = time.time() if ts is None else ts
    for product in products:
        h.engine.runner.snapshots.put(
            MarketSnapshot(product, D(bid), D(ask), D(bid), D(ask), at)
        )
    h.engine.runner.snapshots.set_clock(at, at)


def fund_ai(h: Harness, quote="10000") -> str:
    """Give the AI a dry holding: one settled sell, backdated out of the caps.

    The AI has no bot row and no budget of its own, so its dry holding is what
    its own order rows leave it.  The settled sell is dated five days back, so
    it spends none of today's notional and no hour's order count — it is a
    holding, not a trade of today.
    """
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


def add_bot(h: Harness, bot_id: str = BOT, *, quote="100", base="50") -> dict:
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


def buy(*, side="BUY", size="5", price="0.98", approval_id=None, level=0, **overrides):
    """A well-formed place intent: whatever it earns is the chain's answer."""
    fields: dict[str, Any] = dict(
        action="place",
        side=side,
        size=D(size),
        limit_price=D(price),
        level=level,
        cancel_cid=None,
        reason="test",
    )
    if approval_id is not None:
        fields["approval_id"] = approval_id
    fields.update(overrides)
    return OrderIntent(**fields)


def spend(
    h: Harness,
    *,
    price,
    size,
    owner="ai",
    source="ai",
    book="dry",
    status=CANCELLED,
) -> str:
    """One order row that spends a cap without moving a holding (cancelled)."""
    cid = f"cb-{owner}-B0-{secrets.token_hex(6)}"
    h.store.insert_order(
        cid, owner, source, PRODUCT, "BUY", 0, D(price), D(size),
        status=status, book=book, product_type="SPOT",
    )
    return cid


# ---------------------------------------------------------------- preview rows


def insert_preview(
    store: Store,
    *,
    product=PRODUCT,
    side="BUY",
    size="5",
    limit_price="0.98",
    book="dry",
    state=PENDING,
    created_at=None,
    expires_at=None,
    consumed_at=None,
    approved_at=None,
    cid=None,
    refusal=None,
    hash_=None,
    payload=None,
    preview_id=None,
):
    """One `ai_previews` row, written the way the table holds it.

    The hash is the real one for the row's own order unless the caller names
    another, so an approval check that gets past its state, its consumption and
    its expiry is decided by that hash and nothing else.
    """
    now = time.time()
    identifier = uuid.uuid4().hex if preview_id is None else preview_id
    row = {
        "id": identifier,
        "created_at": now if created_at is None else float(created_at),
        "expires_at": (now + DEFAULT_TTL_S) if expires_at is None else float(expires_at),
        "state": state,
        "product": product,
        "side": side,
        "size": str(size),
        "limit_price": str(limit_price),
        "book": book,
        "hash": (
            ai_module().preview_hash(product, side, D(size), D(limit_price), book)
            if hash_ is None
            else hash_
        ),
        "payload_json": json.dumps(payload or {}),
        "refusal": refusal,
        "approved_at": approved_at,
        "consumed_at": consumed_at,
        "cid": cid,
    }
    store.conn().execute(
        f"INSERT INTO ai_previews({','.join(row)}) "
        f"VALUES({','.join('?' * len(row))})",
        tuple(row.values()),
    )
    return identifier


def preview_row(store: Store, preview_id: str) -> dict | None:
    """One preview row as a dict, or None when the sweep took it."""
    row = store.conn().execute(
        "SELECT * FROM ai_previews WHERE id=?", (preview_id,)
    ).fetchone()
    return None if row is None else dict(row)


def premature_time(h: Harness) -> float:
    """A moment in the past for whichever clock the engine's expiry reads."""
    return min(float(h.clock()), time.time()) - 1.0


def expire_row(h: Harness, preview_id: str) -> float:
    """Push one preview's expiry into the past, and move the test clock past it.

    Both clocks are moved: the row's expiry lands before `time.time()` and before
    the injected clock, so an engine reading either one sees an expired preview.
    """
    past = premature_time(h)
    h.store.conn().execute(
        "UPDATE ai_previews SET expires_at=? WHERE id=?", (past, preview_id)
    )
    h.clock.advance(max(2.0, h.clock() - past + 1.0))
    return past


def order_count(store: Store) -> int:
    return int(store.conn().execute("SELECT COUNT(*) FROM orders").fetchone()[0])


def preview_count(store: Store) -> int:
    return int(store.conn().execute("SELECT COUNT(*) FROM ai_previews").fetchone()[0])


def orders_for(store: Store, cid: str) -> list[dict]:
    return [row for row in store.orders() if row["client_order_id"] == cid]


def post_preview(client, **overrides):
    """The whole POST /ai/previews body, with the caller's fields over it."""
    body = {"product": PRODUCT, "side": "BUY", "size": "5", "limit_price": "0.98"}
    body.update(overrides)
    return client.post("/ai/previews", json=body)


def limits_by_name(body: dict) -> dict[str, dict]:
    """The five limit entries of a preview answer, by name."""
    entries = body["limits"]
    assert isinstance(entries, list), body
    found: dict[str, dict] = {}
    for entry in entries:
        assert set(entry) == LIMIT_KEYS, entry
        found[entry["name"]] = entry
    return found


# ================================================================ the preview


def test_preview_runs_full_chain(tmp_path):
    """A preview is the whole chain, read-only, on the book the route decides."""
    h = build_engine(tmp_path / "preview")
    fund_ai(h)
    prime(h)
    before_orders = order_count(h.store)

    with h.client() as client:
        response = post_preview(client)
        assert response.status_code == 200, response.text
        body = response.json()
        preview_id = body["preview_id"]
        assert body["state"] == PENDING
        assert body["book"] == "dry"
        assert body["product"] == PRODUCT
        assert body["side"] == "BUY"
        assert D(body["size"]) == D("5")
        assert D(body["limit_price"]) == D("0.98")
        notional = D(body["size"]) * D(body["limit_price"])
        assert D(str(body["notional"])) == notional
        assert re.fullmatch(r"[0-9a-f]{32}", preview_id), preview_id
        assert re.fullmatch(r"[0-9a-f]{64}", body["hash"]), body["hash"]
        assert body["refusal"] is None, body
        assert body["message"] is None, body
        assert isinstance(body["created_at"], (int, float))
        assert isinstance(body["expires_at"], (int, float))
        assert body["expires_at"] - body["created_at"] == pytest.approx(
            DEFAULT_TTL_S, abs=5
        )

        limits = limits_by_name(body)
        assert set(limits) == set(LIMIT_NAMES), limits
        expected = {
            "ai_max_order_usd": ("25", notional),
            "ai_daily_notional_usd": ("50", notional),
            "daily_notional_usd": ("200", notional),
            "ai_orders_per_hour": (10, 1),
            "orders_per_hour": (30, 1),
        }
        for name, (limit, used) in expected.items():
            assert D(str(limits[name]["limit"])) == D(str(limit)), name
            assert D(str(limits[name]["used_after"])) == D(str(used)), name

        # A preview sends nothing anywhere and writes no order row.
        assert h.dry.place_calls == []
        assert h.dry.writes == []
        if h.live is not None:
            assert h.live.place_calls == []
        assert order_count(h.store) == before_orders

        stored = preview_row(h.store, preview_id)
        assert stored is not None
        assert stored["state"] == PENDING
        assert stored["book"] == "dry"
        assert stored["hash"] == body["hash"]
        payload = json.loads(stored["payload_json"])
        assert D(str(payload["notional"])) == notional
        assert {entry["name"] for entry in payload["limits"]} == set(LIMIT_NAMES)
    close(h)

    # Every chain refusal comes back as a refused row, and nothing is sent.
    def stale(engine):
        prime(engine, ts=time.time() - 10 * DAY_S)

    def halted(engine):
        engine.gateway.halt("test")

    def spent_daily(engine):
        spend(engine, price="48", size="1")

    def spent_hour(engine):
        for _ in range(10):
            spend(engine, price="1", size="0.01")

    def unfunded(engine):
        """Nothing: the AI has no dry money at all, so the order cannot be funded."""

    cases = (
        ("too-small", TOO_SMALL, None, {"size": "0.1"}),
        ("order-too-large", ORDER_TOO_LARGE, None, {"size": "40"}),
        ("daily-cap", DAILY_CAP, spent_daily, {}),
        ("rate-cap", RATE_CAP, spent_hour, {}),
        ("insufficient-holding", INSUFFICIENT_HOLDING, unfunded, {}),
        ("stale-market", STALE_MARKET, stale, {}),
        ("halted", HALTED, halted, {}),
        ("product-not-allowed", PRODUCT_NOT_ALLOWED, None, {"product": "DOGE-USDC"}),
    )
    for label, code, arrange, overrides in cases:
        engine = build_engine(tmp_path / f"refuse-{label}")
        if arrange is not unfunded:
            fund_ai(engine)
        prime(engine)
        if arrange is not None:
            arrange(engine)
        orders_before = order_count(engine.store)
        with engine.client() as client:
            refused = post_preview(client, **overrides)
            assert refused.status_code == 200, (label, refused.text)
            answer = refused.json()
            assert answer["refusal"] == code, (label, answer)
            assert answer["state"] == REJECTED_STATE, (label, answer)
            assert answer["book"] == "dry", (label, answer)
            assert isinstance(answer["message"], str) and answer["message"], label
            stored = preview_row(engine.store, answer["preview_id"])
            assert stored is not None, label
            assert stored["state"] == REJECTED_STATE, (label, stored)
            assert stored["refusal"] == code, (label, stored)
            assert stored["book"] == "dry", (label, stored)
        assert engine.dry.place_calls == [], label
        assert engine.dry.writes == [], label
        assert order_count(engine.store) == orders_before, label
        assert preview_count(engine.store) == 1, label
        close(engine)

    # A body this surface cannot honour is a 422 that stores nothing.
    h = build_engine(tmp_path / "malformed")
    fund_ai(h)
    prime(h)
    with h.client() as client:
        stored_before = preview_count(h.store)
        malformed = (
            ("bad side", {"side": "HOLD"}),
            ("zero size", {"size": "0"}),
            ("not a number", {"size": "abc"}),
            ("negative limit", {"limit_price": "-1"}),
            ("unknown field", {"note": "buy the dip"}),
        )
        for label, overrides in malformed:
            refused = post_preview(client, **overrides)
            assert refused.status_code == 422, (label, refused.text)
            assert preview_count(h.store) == stored_before, label

        # The one preview this surface can honour, for the list to show.
        accepted = post_preview(client)
        assert accepted.status_code == 200, accepted.text
        accepted_body = accepted.json()
        assert accepted_body["state"] == PENDING, accepted_body
        accepted_id = accepted_body["preview_id"]
        assert accepted_body["refusal"] is None, accepted_body
        assert preview_count(h.store) == stored_before + 1

        # GET lists what is there, newest first, and filters by state.
        listed = client.get("/ai/previews")
        assert listed.status_code == 200, listed.text
        items = listed.json()
        assert isinstance(items, list), listed.text
        assert len(items) == 1, items
        assert items[0]["preview_id"] == accepted_id, items
        assert set(items[0]) >= {
            "preview_id",
            "hash",
            "state",
            "book",
            "product",
            "side",
            "size",
            "limit_price",
            "notional",
            "limits",
            "expires_at",
            "created_at",
            "refusal",
            "message",
        }

        pending = client.get("/ai/previews", params={"state": PENDING})
        assert pending.status_code == 200, pending.text
        pending_items = pending.json()
        assert [item["preview_id"] for item in pending_items] == [accepted_id], pending_items
        assert all(item["state"] == PENDING for item in pending_items)
        rejected = client.get("/ai/previews", params={"state": REJECTED_STATE})
        assert rejected.status_code == 200, rejected.text
        rejected_items = rejected.json()
        assert isinstance(rejected_items, list), rejected.text
        assert rejected_items == [], rejected_items
        assert all(item["state"] == REJECTED_STATE for item in rejected_items)
        unknown = client.get("/ai/previews", params={"state": "sideways"})
        assert unknown.status_code == 422, unknown.text
        assert unknown.json().get("code") == INVALID, unknown.text
    close(h)


# ================================================================ the flood


def test_preview_flood_capped(tmp_path):
    """Twenty may wait at once and sixty may be made an hour; the rest is a 429."""
    module = ai_module()
    assert module.MAX_PENDING_PREVIEWS == 20, module.MAX_PENDING_PREVIEWS
    assert module.MAX_PREVIEWS_PER_HOUR == 60, module.MAX_PREVIEWS_PER_HOUR

    h = build_engine(tmp_path / "flood")
    fund_ai(h)
    prime(h)
    # The window a preview flood is measured over is the surface's own clock, so
    # the test moves that one rather than waiting an hour for it.
    clock = Clock()
    h.ai.now = clock

    def waiting() -> int:
        """The previews in state `pending`, as the table holds them."""
        return int(
            h.store.conn()
            .execute(
                "SELECT COUNT(*) FROM ai_previews WHERE state=?", (PENDING,)
            )
            .fetchone()[0]
        )

    def this_hour() -> int:
        """Every preview row made in the last hour, whatever it became."""
        return int(
            h.store.conn()
            .execute(
                "SELECT COUNT(*) FROM ai_previews WHERE created_at > ?",
                (float(clock()) - 3600.0,),
            )
            .fetchone()[0]
        )

    pending_ids: list[str] = []
    with h.client() as client:
        # Twenty is what may wait for an answer at once.
        for _ in range(module.MAX_PENDING_PREVIEWS):
            response = post_preview(client)
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["state"] == PENDING, body
            pending_ids.append(body["preview_id"])
        assert waiting() == module.MAX_PENDING_PREVIEWS
        assert this_hour() == module.MAX_PENDING_PREVIEWS

        before = preview_count(h.store)
        refused = post_preview(client)
        assert refused.status_code == 429, refused.text
        assert refused.json().get("code") == "PREVIEW_LIMIT", refused.text
        message = refused.json().get("message")
        assert isinstance(message, str) and message, refused.text
        # A refused flood writes no row at all.
        assert preview_count(h.store) == before
        assert waiting() == module.MAX_PENDING_PREVIEWS

        # One answered no is one place again.
        assert client.post(reject_path(pending_ids.pop())).status_code == 200
        assert waiting() == module.MAX_PENDING_PREVIEWS - 1
        again = post_preview(client)
        assert again.status_code == 200, again.text
        assert again.json()["state"] == PENDING, again.text
        pending_ids.append(again.json()["preview_id"])
        assert waiting() == module.MAX_PENDING_PREVIEWS

        # An hour is worth sixty, whatever becomes of them.  A rejection here and
        # there keeps the pending cap from being the one that answers, so the
        # only thing left to refuse the sixty-first is the hour itself.
        while this_hour() < module.MAX_PREVIEWS_PER_HOUR:
            if waiting() >= module.MAX_PENDING_PREVIEWS:
                assert client.post(reject_path(pending_ids.pop())).status_code == 200
            made = post_preview(client)
            assert made.status_code == 200, (this_hour(), made.text)
            assert made.json()["state"] == PENDING, made.text
            pending_ids.append(made.json()["preview_id"])
        assert this_hour() == module.MAX_PREVIEWS_PER_HOUR
        while waiting() >= module.MAX_PENDING_PREVIEWS:
            assert client.post(reject_path(pending_ids.pop())).status_code == 200

        before = preview_count(h.store)
        capped = post_preview(client)
        assert capped.status_code == 429, capped.text
        assert capped.json().get("code") == "PREVIEW_LIMIT", capped.text
        assert preview_count(h.store) == before

        # An hour later the window is empty and a preview is taken again.
        clock.advance(3601)
        later = post_preview(client)
        assert later.status_code == 200, later.text
        assert later.json()["state"] == PENDING, later.text
    close(h)


def test_preview_off_increment_refused(tmp_path):
    """A size or a price off the product's own tick writes no row, and is not rounded."""
    h = build_engine(tmp_path / "increment")
    fund_ai(h)
    prime(h)
    spec = spec_for(PRODUCT)
    assert spec.base_increment == D("0.1"), spec
    assert spec.price_increment == D("0.0001"), spec

    with h.client() as client:
        before = preview_count(h.store)

        bad_size = post_preview(client, size="5.05")
        assert bad_size.status_code == 422, bad_size.text
        assert bad_size.json().get("code") == INVALID, bad_size.text
        message = str(bad_size.json().get("message") or "")
        assert "size" in message.lower(), bad_size.text
        assert preview_count(h.store) == before

        bad_price = post_preview(client, limit_price="0.98005")
        assert bad_price.status_code == 422, bad_price.text
        assert bad_price.json().get("code") == INVALID, bad_price.text
        message = str(bad_price.json().get("message") or "")
        assert "price" in message.lower(), bad_price.text
        assert preview_count(h.store) == before

        # The product's own increments, and nothing rounded to them: the values
        # sent are the values the chain measured.
        on_tick_size = D("5") + spec.base_increment
        on_tick_price = spec.price_increment * D("9801")
        on_tick = post_preview(
            client, size=str(on_tick_size), limit_price=str(on_tick_price)
        )
        assert on_tick.status_code == 200, on_tick.text
        body = on_tick.json()
        assert body["state"] == PENDING, body
        assert D(body["size"]) == on_tick_size, body
        stored = preview_row(h.store, body["preview_id"])
        assert stored is not None
        assert D(stored["size"]) == on_tick_size, stored
        assert D(stored["limit_price"]) == on_tick_price, stored
    close(h)


def test_preview_off_tick_equity_price_refused_before_approval(tmp_path):
    """An equity's own price tick is checked before an approval or any row exists."""
    product = "NVDA-USD"
    h = build_engine(
        tmp_path / "equity-increment",
        env={"CROW_COINBASE_EQUITY_PRODUCTS": product},
    )
    plain_spec = spec_for

    def gateway_spec(name):
        """The equity's own tick: cents on the price, and no rounding onto it."""
        if name != product:
            return plain_spec(name)
        return ProductSpec(
            name,
            price_increment=D("0.01"),
            base_increment=D("0.01"),
            quote_increment=D("0.01"),
            base_min_size=D("0.01"),
            quote_min_size=D("1"),
            product_type="EQUITY",
            fractionable=True,
        )

    h.engine.gateway.spec_for = gateway_spec

    with h.client() as client:
        before = preview_count(h.store)

        off_tick = post_preview(
            client, product=product, size="1", limit_price="100.005"
        )
        assert off_tick.status_code == 422, off_tick.text
        assert off_tick.json().get("code") == INVALID, off_tick.text
        message = str(off_tick.json().get("message") or "")
        assert "price" in message.lower(), off_tick.text
        # Nothing was written: no preview row, and no order row for an order the
        # equity's own tick cannot spell.
        assert preview_count(h.store) == before
        assert order_count(h.store) == 0

        # On the product's own tick the increment check says nothing, so the
        # answer is the chain's, whatever that is, and never INVALID.
        on_tick = post_preview(
            client, product=product, size="1", limit_price="100.00"
        )
        assert on_tick.json().get("code") != INVALID, on_tick.text
    close(h)


def test_requested_limit_price_returned(tmp_path):
    """A preview answers the price the user asked beside the hashed one it sends."""
    h = build_engine(tmp_path / "requested")
    fund_ai(h)
    prime(h)
    asked = D("1.50")

    with h.client() as client:
        body = post_preview(client, limit_price=str(asked)).json()
        assert body["state"] == PENDING, body
        chain_price = D(body["limit_price"])
        # The book's maker price is the one the approval covers; the price the
        # user asked is stored beside it and is no part of the hash.
        assert chain_price == D("0.9999"), body
        assert chain_price != asked
        assert body["requested_limit_price"] is not None, body
        assert D(body["requested_limit_price"]) == asked, body
        assert body["hash"] == ai_module().preview_hash(
            PRODUCT, "BUY", D("5"), chain_price, "dry"
        ), body
        assert body["hash"] != ai_module().preview_hash(
            PRODUCT, "BUY", D("5"), asked, "dry"
        ), body

        stored = preview_row(h.store, body["preview_id"])
        payload = json.loads(stored["payload_json"])
        assert D(payload["requested_limit_price"]) == asked, payload

        # A row from before this field existed answers null, and still lists.
        older = insert_preview(h.store, payload={})
        listed = client.get("/ai/previews")
        assert listed.status_code == 200, listed.text
        items = {item["preview_id"]: item for item in listed.json()}
        assert D(items[body["preview_id"]]["requested_limit_price"]) == asked, items
        assert items[older]["requested_limit_price"] is None, items
    close(h)


# ================================================================ the approval
# in the chain


def test_ai_submit_without_approval_refused(tmp_path):
    """Only an approved, unexpired, unconsumed preview of THIS order may place."""
    h = build_engine(tmp_path / "no-approval")
    fund_ai(h)
    prime(h)
    add_bot(h, BOT)
    gateway = h.gateway

    before = order_count(h.store)
    bare = gateway.submit("ai", "ai", buy(), PRODUCT)
    assert bare.ok is False
    assert bare.refusal == APPROVAL_REQUIRED
    assert bare.cid is None
    assert order_count(h.store) == before

    unknown = gateway.submit("ai", "ai", buy(approval_id=uuid.uuid4().hex), PRODUCT)
    assert unknown.ok is False and unknown.refusal == APPROVAL_REQUIRED
    assert order_count(h.store) == before

    # Every other shape of "there is no usable approval for this order".
    now = time.time()
    cases = (
        (
            "expired",
            dict(state=APPROVED, expires_at=premature_time(h)),
            {},
        ),
        ("consumed", dict(state=APPROVED, consumed_at=now), {}),
        ("pending", dict(state=PENDING), {}),
        ("placed", dict(state=PLACED, cid=f"cb-ai-{uuid.uuid4().hex}"), {}),
        ("rejected", dict(state=REJECTED_STATE, refusal="REJECTED"), {}),
        ("another size", dict(state=APPROVED, size="6"), {}),
        ("another limit", dict(state=APPROVED, limit_price="0.97"), {}),
        ("another side", dict(state=APPROVED, side="SELL"), {}),
        ("another product", dict(state=APPROVED, product=SECOND), {}),
        ("another book", dict(state=APPROVED, book="live"), {}),
        ("another hash", dict(state=APPROVED, hash_="0" * 64), {}),
    )
    for label, row_fields, intent_fields in cases:
        preview_id = insert_preview(h.store, **row_fields)
        before = order_count(h.store)
        refused = gateway.submit(
            "ai", "ai", buy(approval_id=preview_id, **intent_fields), PRODUCT
        )
        assert refused.ok is False, label
        assert refused.refusal == APPROVAL_REQUIRED, (label, refused)
        assert refused.cid is None, label
        assert order_count(h.store) == before, label

    # A bot's own path is untouched by any of it.
    assert h.gateway.submit("bot", BOT, buy()).ok is True

    # `evaluate()` answers "would the approval-free chain allow this": it is the
    # measurement a preview reads, and it writes nothing.
    before = order_count(h.store)
    assert gateway.evaluate("ai", "ai", buy(), PRODUCT)[0] is None
    assert order_count(h.store) == before
    # ... and it still refuses what the chain refuses.
    assert gateway.evaluate("ai", "ai", buy(size="0.1"), PRODUCT)[0] == TOO_SMALL
    close(h)


def test_approve_hash_mismatch_refused(tmp_path):
    """A hash that is not the preview's refuses, and leaves the preview pending."""
    h = build_engine(tmp_path / "hash")
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)

    with h.client() as client:
        body = post_preview(client).json()
        preview_id = body["preview_id"]
        wrong = ai_module().preview_hash(PRODUCT, "BUY", D("6"), D("0.98"), "dry")
        assert wrong != body["hash"]
        before = order_count(h.store)

        refused = signer.post(client, approve_path(preview_id), {"hash": wrong})
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == HASH_MISMATCH, refused.text
        stored = preview_row(h.store, preview_id)
        assert stored["state"] == PENDING, stored
        assert stored["consumed_at"] is None, stored
        assert order_count(h.store) == before
        assert h.dry.place_calls == []

        # An approve body with a field this build does not know is a 422.
        extra = signer.post(
            client, approve_path(preview_id), {"hash": body["hash"], "force": True}
        )
        assert extra.status_code == 422, extra.text
        assert preview_row(h.store, preview_id)["state"] == PENDING

        # The right hash places it: one send, one row, the preview's own cid.
        accepted = signer.post(client, approve_path(preview_id), {"hash": body["hash"]})
        assert accepted.status_code == 200, accepted.text
        answer = accepted.json()
        cid = f"cb-ai-{preview_id}"
        assert answer["preview_id"] == preview_id
        assert answer["state"] == PLACED
        assert answer["cid"] == cid
        assert answer["book"] == "dry"
        assert h.dry.place_calls == [(cid, PRODUCT, "BUY", D("5"), D("0.98"))]
        assert len(orders_for(h.store, cid)) == 1
        assert preview_row(h.store, preview_id)["state"] == PLACED
    close(h)


def test_approve_after_expiry_refused(tmp_path):
    """An expired preview refuses, and the sweep is what retires it."""
    h = build_engine(tmp_path / "expiry")
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)

    with h.client() as client:
        body = post_preview(client).json()
        preview_id = body["preview_id"]
        expire_row(h, preview_id)

        refused = signer.post(client, approve_path(preview_id), {"hash": body["hash"]})
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == EXPIRED, refused.text
        assert EXPIRED_STATE == preview_row(h.store, preview_id)["state"]
        assert h.dry.place_calls == []

        # A pending row whose expiry has passed is retired by a sweep (a GET).
        stale = insert_preview(h.store, expires_at=premature_time(h))
        swept = client.get("/ai/previews", params={"state": EXPIRED_STATE})
        assert swept.status_code == 200, swept.text
        assert stale in [item["preview_id"] for item in swept.json()]
        assert preview_row(h.store, stale)["state"] == EXPIRED_STATE

        # A terminal row older than seven days is deleted by the same sweep.
        old = time.time() - 8 * DAY_S
        ancient = insert_preview(
            h.store,
            state=REJECTED_STATE,
            refusal="REJECTED",
            created_at=old,
            expires_at=old,
            approved_at=old,
            consumed_at=old,
        )
        assert preview_row(h.store, ancient) is not None
        client.get("/ai/previews")
        assert preview_row(h.store, ancient) is None
    close(h)


def test_approved_order_never_reprices(tmp_path):
    """An approved order goes out at the previewed price, or not at all."""
    # ---- the book moved: refused before a row or a consumption
    moved = build_engine(tmp_path / "moved")
    fund_ai(moved)
    prime(moved)
    secret = owner_secret()
    moved.engine.auth.set_secret(secret)
    signer = Signer(secret, moved.clock)
    with moved.client() as client:
        body = post_preview(client).json()
        preview_id = body["preview_id"]
        # The ask drops under the stored limit, so the order would cross.
        prime(moved, bid="0.96", ask="0.97")
        before = order_count(moved.store)
        refused = signer.post(client, approve_path(preview_id), {"hash": body["hash"]})
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == POST_ONLY_WOULD_CROSS, refused.text
        assert refused.json().get("message") == PRICE_MOVED, refused.text
        assert moved.dry.place_calls == []
        assert order_count(moved.store) == before
        stored = preview_row(moved.store, preview_id)
        assert stored["state"] == REJECTED_STATE, stored
        assert stored["refusal"] == POST_ONLY_WOULD_CROSS, stored
        assert stored["consumed_at"] is None, stored
        assert orders_for(moved.store, f"cb-ai-{preview_id}") == []
    close(moved)

    # ---- the chain agrees, the exchange refuses post-only: one attempt, no retry
    rejecting = build_engine(tmp_path / "post-only")
    fund_ai(rejecting)
    prime(rejecting)
    rejecting.dry.mode = "post_only"
    secret = owner_secret()
    rejecting.engine.auth.set_secret(secret)
    signer = Signer(secret, rejecting.clock)
    with rejecting.client() as client:
        body = post_preview(client).json()
        preview_id = body["preview_id"]
        cid = f"cb-ai-{preview_id}"
        refused = signer.post(client, approve_path(preview_id), {"hash": body["hash"]})
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == POST_ONLY_WOULD_CROSS, refused.text
        assert refused.json().get("message") == PRICE_MOVED, refused.text
        assert len(rejecting.dry.place_calls) == 1, rejecting.dry.place_calls
        tried = rejecting.dry.place_calls[0]
        assert tried[0] == cid
        assert tried[4] == D("0.98")  # the stored price, never a repriced one
        row = rejecting.store.order(cid)
        assert row["status"] == "REJECTED", row
        stored = preview_row(rejecting.store, preview_id)
        assert stored["state"] == REJECTED_STATE, stored
        assert stored["refusal"] == POST_ONLY_WOULD_CROSS, stored
        assert len(orders_for(rejecting.store, cid)) == 1
    close(rejecting)

    # ---- the happy path: one send, at exactly the stored limit
    happy = build_engine(tmp_path / "happy")
    fund_ai(happy)
    prime(happy)
    secret = owner_secret()
    happy.engine.auth.set_secret(secret)
    signer = Signer(secret, happy.clock)
    with happy.client() as client:
        body = post_preview(client).json()
        preview_id = body["preview_id"]
        cid = f"cb-ai-{preview_id}"
        accepted = signer.post(client, approve_path(preview_id), {"hash": body["hash"]})
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["cid"] == cid
        assert happy.dry.place_calls == [
            (cid, PRODUCT, "BUY", D("5"), D(body["limit_price"]))
        ]
        row = happy.store.order(cid)
        assert row["owner"] == "ai", row
        assert row["source"] == "ai", row
        assert row["book"] == body["book"], row
        assert row["price"] == D(body["limit_price"]), row
        assert row["client_order_id"] == "cb-ai-" + preview_id
        stored = preview_row(happy.store, preview_id)
        assert stored["state"] == PLACED, stored
        assert stored["cid"] == cid, stored
        assert stored["consumed_at"] is not None, stored
        assert len(orders_for(happy.store, cid)) == 1
    close(happy)


def test_book_changed_refused(tmp_path):
    """A preview belongs to its book: a route that moved refuses the approval."""
    h = build_engine(tmp_path / "book")
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)

    with h.client() as client:
        assert h.store.get("ai_live_enabled") is not True
        dry = post_preview(client).json()
        assert dry["book"] == "dry" and dry["state"] == PENDING, dry

        # The AI's live switch goes on, and the live account is ready.
        h.gateway.switches.set("ai_live_enabled", True)
        assert h.gateway.books.live_available() is True
        refused = signer.post(client, approve_path(dry["preview_id"]), {"hash": dry["hash"]})
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == BOOK_CHANGED, refused.text
        stored = preview_row(h.store, dry["preview_id"])
        assert stored["state"] == REJECTED_STATE, stored
        assert stored["refusal"] == BOOK_CHANGED, stored
        assert h.dry.place_calls == []
        assert h.live.place_calls == []

        # Taken live, then the switch goes off: the other direction.
        live = post_preview(client).json()
        assert live["book"] == "live" and live["state"] == PENDING, live
        assert live["hash"] != dry["hash"]
        h.gateway.switches.set("ai_live_enabled", False)
        refused = signer.post(
            client, approve_path(live["preview_id"]), {"hash": live["hash"]}
        )
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == BOOK_CHANGED, refused.text
        assert preview_row(h.store, live["preview_id"])["refusal"] == BOOK_CHANGED
        assert h.dry.place_calls == []
        assert h.live.place_calls == []
    close(h)


def test_ai_live_without_credentials_refused_not_dry(tmp_path):
    """A live route with no account is `LIVE_LOCKED`, never a dry order."""
    locked = build_engine(tmp_path / "locked", live=False)
    prime(locked)
    locked.gateway.switches.set("ai_live_enabled", True)

    with locked.client() as client:
        response = post_preview(client)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["refusal"] == LIVE_LOCKED, body
        assert body["book"] == "live", body
        assert body["state"] == REJECTED_STATE, body
        assert preview_row(locked.store, body["preview_id"])["book"] == "live"
        assert locked.dry.place_calls == []
        assert locked.dry.writes == []
        assert order_count(locked.store) == 0

        # The switch off: the same preview is a dry one.
        locked.gateway.switches.set("ai_live_enabled", False)
        fund_ai(locked)
        dry = post_preview(client).json()
        assert dry["book"] == "dry", dry
        assert dry["state"] == PENDING, dry
        assert dry["refusal"] is None, dry
    close(locked)

    # Credentials ready: the preview is a live one.
    ready = build_engine(tmp_path / "live-ready")
    prime(ready)
    ready.gateway.switches.set("ai_live_enabled", True)
    with ready.client() as client:
        live = post_preview(client).json()
        assert live["book"] == "live", live
        assert live["state"] == PENDING, live
        assert live["refusal"] is None, live
    close(ready)


def test_double_approve_one_order(tmp_path):
    """Two approvals of one preview place one order, in one engine or in two."""
    rounds = 20
    h = build_engine(
        tmp_path / "race", env={AI_ORDERS_HOUR: "100", AI_DAILY: "500"}
    )
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)

    with h.client() as client:
        for index in range(rounds):
            body = post_preview(client).json()
            assert body["state"] == PENDING, (index, body)
            preview_id = body["preview_id"]
            cid = f"cb-ai-{preview_id}"
            barrier = threading.Barrier(2)
            answers: list[Any] = []
            lock = threading.Lock()

            def attempt():
                signer = Signer(secret, h.clock)
                barrier.wait(timeout=20)
                with h.client() as worker:
                    answer = signer.post(
                        worker, approve_path(preview_id), {"hash": body["hash"]}
                    )
                with lock:
                    answers.append(answer)

            threads = [threading.Thread(target=attempt) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
            assert all(not thread.is_alive() for thread in threads), index
            assert len(answers) == 2, index

            statuses = sorted(answer.status_code for answer in answers)
            assert statuses == [200, 409], (index, [a.text for a in answers])
            loser = next(answer for answer in answers if answer.status_code == 409)
            assert loser.json().get("code") == NOT_PENDING, (index, loser.text)
            assert len(orders_for(h.store, cid)) == 1, index
            places = [call for call in h.dry.place_calls if call[0] == cid]
            assert len(places) == 1, (index, places)
    close(h)

    # Two engines over one sqlite file share no gateway lock: the table decides.
    root = tmp_path / "two-engines"
    first = build_engine(root, env={AI_ORDERS_HOUR: "100", AI_DAILY: "500"})
    second = build_engine(root, env={AI_ORDERS_HOUR: "100", AI_DAILY: "500"})
    fund_ai(first)
    prime(first)
    prime(second)
    secrets_by_engine = {id(first): owner_secret(), id(second): owner_secret()}
    first.engine.auth.set_secret(secrets_by_engine[id(first)])
    second.engine.auth.set_secret(secrets_by_engine[id(second)])

    with first.client() as client:
        body = post_preview(client).json()
    assert body["state"] == PENDING, body
    preview_id = body["preview_id"]
    cid = f"cb-ai-{preview_id}"
    barrier = threading.Barrier(2)
    answers = []
    lock = threading.Lock()

    def attempt(engine: Harness):
        signer = Signer(secrets_by_engine[id(engine)], engine.clock)
        barrier.wait(timeout=20)
        with engine.client() as client:
            answer = signer.post(
                client, approve_path(preview_id), {"hash": body["hash"]}
            )
        with lock:
            answers.append(answer)

    threads = [
        threading.Thread(target=attempt, args=(engine,)) for engine in (first, second)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert all(not thread.is_alive() for thread in threads)
    statuses = sorted(answer.status_code for answer in answers)
    assert statuses == [200, 409], [a.text for a in answers]
    loser = next(answer for answer in answers if answer.status_code == 409)
    assert loser.json().get("code") == NOT_PENDING, loser.text
    assert len(orders_for(first.store, cid)) == 1
    places = len([c for c in first.dry.place_calls if c[0] == cid]) + len(
        [c for c in second.dry.place_calls if c[0] == cid]
    )
    assert places == 1, places
    close(first)
    close(second)


def test_caps_rechecked_at_approve(tmp_path):
    """Everything the chain reads is read again at the approve, and refuses there."""
    def approved(client, signer):
        body = post_preview(client).json()
        assert body["state"] == PENDING, body
        return body

    def refusal(client, signer, h, body, code):
        before = order_count(h.store)
        places = list(h.dry.place_calls)
        refused = signer.post(
            client, approve_path(body["preview_id"]), {"hash": body["hash"]}
        )
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == code, refused.text
        stored = preview_row(h.store, body["preview_id"])
        assert stored["state"] == REJECTED_STATE, stored
        assert stored["refusal"] == code, stored
        assert h.dry.place_calls == places
        assert order_count(h.store) == before
        assert orders_for(h.store, f"cb-ai-{body['preview_id']}") == []
        # The approval was spent on the refusal, not left usable.
        again = signer.post(
            client, approve_path(body["preview_id"]), {"hash": body["hash"]}
        )
        assert again.status_code == 409, again.text
        assert again.json().get("code") == NOT_PENDING, again.text

    # ---- the AI's single-order cap
    h = build_engine(tmp_path / "cap-order")
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        body = approved(client, signer)
        h.engine.limits.set_caps({AI_MAX_ORDER: "1"})
        refusal(client, signer, h, body, ORDER_TOO_LARGE)
    close(h)

    # ---- the AI's daily notional
    h = build_engine(tmp_path / "cap-daily")
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        body = approved(client, signer)
        spend(h, price="48", size="1")
        refusal(client, signer, h, body, DAILY_CAP)
    close(h)

    # ---- the AI's orders per hour
    h = build_engine(tmp_path / "cap-hour")
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        body = approved(client, signer)
        for _ in range(10):
            spend(h, price="1", size="0.01")
        refusal(client, signer, h, body, RATE_CAP)
    close(h)

    # ---- the halt
    h = build_engine(tmp_path / "cap-halt")
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        body = approved(client, signer)
        h.gateway.halt("test")
        refusal(client, signer, h, body, HALTED)
    close(h)

    # ---- the AI's own money
    h = build_engine(tmp_path / "cap-funds")
    fund_ai(h, quote="5")
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    with h.client() as client:
        body = approved(client, signer)
        # A resting buy of its own holds almost all of what the AI has.
        spend(h, price="0.99", size="5", status=OPEN)
        refusal(client, signer, h, body, INSUFFICIENT_HOLDING)
    close(h)


def test_crash_between_consume_and_submit_reconciles(tmp_path):
    """A send that dies after the commit leaves a row reconcile settles alone."""
    def crash(root):
        """Take a preview and let the approval die inside its send."""
        h = build_engine(root)
        fund_ai(h)
        prime(h)
        h.dry.mode = "crash"
        with h.client() as client:
            body = post_preview(client).json()
        assert body["state"] == PENDING, body
        with pytest.raises(Crash):
            h.ai.approve(body["preview_id"], body["hash"])
        return h, body

    # ---- the exchange does hold the order: the row takes its id
    h, body = crash(tmp_path / "crash-found")
    preview_id = body["preview_id"]
    cid = f"cb-ai-{preview_id}"
    row = h.store.order(cid)
    assert row is not None, "the send died before the row was written"
    assert row["status"] == PENDING_SUBMIT, row
    assert row["order_id"] is None, row
    stored = preview_row(h.store, preview_id)
    assert stored["state"] == PLACED, stored
    assert stored["cid"] == cid, stored
    close(h)

    found = build_engine(tmp_path / "crash-found")
    prime(found)
    row = found.store.order(cid)
    assert row["status"] == PENDING_SUBMIT and row["order_id"] is None, row

    # The approval cannot be spent a second time: one order, ever.
    with pytest.raises(ai_module().AiRefused) as used:
        found.ai.approve(preview_id, body["hash"])
    assert used.value.code == NOT_PENDING
    assert len(orders_for(found.store, cid)) == 1
    assert found.dry.place_calls == []

    # Reconcile settles it from the exchange, exactly as any other order.
    found.engine.exchange.place_limit(
        cid, row["product"], row["side"], D(row["size"]), D(row["price"])
    )
    reconcile(
        found.store, found.engine.exchange, time.time(), gateway=None, book="dry"
    )
    settled = found.store.order(cid)
    assert settled["order_id"] is not None, settled
    assert len(orders_for(found.store, cid)) == 1
    assert preview_row(found.store, preview_id)["state"] == PLACED
    close(found)

    # ---- the exchange never got it: the row is given up on, not duplicated
    h, body = crash(tmp_path / "crash-gone")
    preview_id = body["preview_id"]
    cid = f"cb-ai-{preview_id}"
    assert h.store.order(cid)["status"] == PENDING_SUBMIT
    close(h)

    gone = build_engine(tmp_path / "crash-gone")
    prime(gone)
    reconcile(
        gone.store,
        gone.engine.exchange,
        time.time() + 400,
        gateway=None,
        book="dry",
    )
    abandoned = gone.store.order(cid)
    assert abandoned["status"] == FAILED, abandoned
    assert abandoned["order_id"] is None, abandoned
    assert len(orders_for(gone.store, cid)) == 1
    with pytest.raises(ai_module().AiRefused) as refused:
        gone.ai.approve(preview_id, body["hash"])
    assert refused.value.code == NOT_PENDING
    assert len(orders_for(gone.store, cid)) == 1
    close(gone)


def test_approval_consumed_with_insert(tmp_path):
    """The approval is spent in the row's own transaction, or not at all."""
    h = build_engine(tmp_path / "insert")
    fund_ai(h)
    prime(h)
    with h.client() as client:
        body = post_preview(client).json()
    preview_id = body["preview_id"]
    cid = f"cb-ai-{preview_id}"

    real_insert = h.store.insert_order
    attempts = []

    def failing_insert(*args, **kwargs):
        attempts.append(args)
        raise RuntimeError("the row could not be written")

    h.store.insert_order = failing_insert
    try:
        with pytest.raises(RuntimeError):
            h.ai.approve(preview_id, body["hash"])
    finally:
        h.store.insert_order = real_insert

    assert len(attempts) == 1
    stored = preview_row(h.store, preview_id)
    assert stored["state"] == APPROVED, stored
    assert stored["consumed_at"] is None, stored
    assert h.store.order(cid) is None
    assert h.dry.place_calls == []

    # The approval is still the owner's to spend: a retry of the ORDER goes out.
    retried = h.gateway.submit("ai", "ai", buy(approval_id=preview_id), PRODUCT)
    assert retried.ok is True, retried
    assert retried.cid == cid, retried
    assert h.dry.place_calls == [(cid, PRODUCT, "BUY", D("5"), D("0.98"))]
    assert len(orders_for(h.store, cid)) == 1
    stored = preview_row(h.store, preview_id)
    assert stored["state"] == PLACED, stored
    assert stored["cid"] == cid, stored
    assert stored["consumed_at"] is not None, stored

    # A consume that cannot spend the approval refuses the order and writes none.
    module = ai_module()
    approved_id = insert_preview(h.store, state=APPROVED)

    def gone(conn, approval_id):
        raise module.ApprovalGone()

    saved = h.gateway.consume_approval
    h.gateway.consume_approval = gone
    try:
        refused = h.gateway.submit("ai", "ai", buy(approval_id=approved_id), PRODUCT)
    finally:
        h.gateway.consume_approval = saved
    assert refused.ok is False, refused
    assert refused.refusal == APPROVAL_REQUIRED, refused
    assert refused.cid is None, refused
    assert h.store.order(f"cb-ai-{approved_id}") is None
    assert orders_for(h.store, f"cb-ai-{approved_id}") == []
    close(h)


# ================================================================ the owner's answer


def test_check_requires_approval_for_ai(tmp_path):
    """`check()` runs the AI's approval step; `evaluate()` is the chain alone."""
    h = build_engine(tmp_path / "check-approval")
    fund_ai(h)
    prime(h)
    add_bot(h, BOT)
    gateway = h.gateway

    # No approval behind it: the read-only question answers that refusal too.
    assert gateway.check("ai", "ai", buy(), PRODUCT) == APPROVAL_REQUIRED
    # `evaluate()` is the measurement a preview is built from, and stays as it
    # was: no approval step, no writes.
    assert gateway.evaluate("ai", "ai", buy(), PRODUCT)[0] is None

    # An approval of exactly this order is what `check()` needs to go on.
    approved_id = insert_preview(h.store, state=APPROVED)
    assert gateway.check("ai", "ai", buy(approval_id=approved_id), PRODUCT) is None
    # An approval of another order is not one, and neither is a spent or an
    # unknown id.
    other_id = insert_preview(h.store, state=APPROVED, size="6")
    assert (
        gateway.check("ai", "ai", buy(approval_id=other_id), PRODUCT)
        == APPROVAL_REQUIRED
    )
    assert (
        gateway.check("ai", "ai", buy(approval_id=uuid.uuid4().hex), PRODUCT)
        == APPROVAL_REQUIRED
    )
    assert (
        gateway.check("ai", "ai", buy(approval_id=""), PRODUCT)
        == APPROVAL_REQUIRED
    )

    # A bot takes no approval, in `check()` as in `submit()`.
    assert gateway.check("bot", BOT, buy()) is None
    assert gateway.evaluate("bot", BOT, buy())[0] is None
    # The rest of the chain still answers as it did.
    assert gateway.evaluate("ai", "ai", buy(size="0.1"), PRODUCT)[0] == TOO_SMALL
    close(h)


def test_approval_gone_after_expiry_maps_to_expired(tmp_path):
    """An approval whose window closed before it was spent answers EXPIRED."""
    h = build_engine(tmp_path / "late-expiry")
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    clock = Clock()
    h.ai.now = clock

    with h.client() as client:
        body = post_preview(client).json()
        assert body["state"] == PENDING, body
        preview_id = body["preview_id"]
        cid = f"cb-ai-{preview_id}"
        before = order_count(h.store)

        real_consume = h.gateway.consume_approval
        moved = []

        def expiring_consume(conn, approval_id):
            """The window closes between the approve's guard and its consume."""
            if not moved:
                moved.append(clock.advance(DEFAULT_TTL_S + 1))
            return real_consume(conn, approval_id)

        h.gateway.consume_approval = expiring_consume
        try:
            refused = signer.post(
                client, approve_path(preview_id), {"hash": body["hash"]}
            )
        finally:
            h.gateway.consume_approval = real_consume

        assert moved, "the approval was never spent"
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == EXPIRED, refused.text
        stored = preview_row(h.store, preview_id)
        assert stored["state"] == EXPIRED_STATE, stored
        assert stored["consumed_at"] is None, stored
        assert stored["cid"] is None, stored
        assert h.store.order(cid) is None
        assert order_count(h.store) == before
        assert h.dry.place_calls == []
    close(h)


def test_reject_cannot_overwrite_placed_preview(tmp_path):
    """A reject cannot undo the order an approval placed, whatever it read first."""
    h = build_engine(tmp_path / "reject-placed")
    fund_ai(h)
    prime(h)

    with h.client() as client:
        # ---- the approval is inside its send, and the row is already spent
        body = post_preview(client).json()
        assert body["state"] == PENDING, body
        preview_id = body["preview_id"]
        cid = f"cb-ai-{preview_id}"
        entered, release = threading.Event(), threading.Event()
        real_place = h.dry.place_limit

        def blocking_place(order_cid, product, side, size, price):
            entered.set()
            assert release.wait(timeout=20), "the send was never released"
            return real_place(order_cid, product, side, size, price)

        h.dry.place_limit = blocking_place
        answers: list[Any] = []

        def place_it():
            answers.append(h.ai.approve(preview_id, body["hash"]))

        thread = threading.Thread(target=place_it)
        thread.start()
        try:
            assert entered.wait(timeout=20), "the approval never reached the send"
            # The approval is spent and the order row exists, so the preview is
            # `placed`: there is nothing left for a reject to answer.
            stored = preview_row(h.store, preview_id)
            assert stored["state"] == PLACED, stored
            assert stored["cid"] == cid, stored
            assert len(orders_for(h.store, cid)) == 1
            late = client.post(reject_path(preview_id))
            assert late.status_code == 409, late.text
            assert late.json().get("code") == NOT_PENDING, late.text
        finally:
            release.set()
            thread.join(timeout=20)
            h.dry.place_limit = real_place
        assert not thread.is_alive()
        assert answers and answers[0]["state"] == PLACED, answers
        assert answers[0]["cid"] == cid, answers
        stored = preview_row(h.store, preview_id)
        assert stored["state"] == PLACED, stored
        assert stored["cid"] == cid, stored
        assert stored["refusal"] is None, stored
        assert len(orders_for(h.store, cid)) == 1
        assert h.store.order(cid)["status"] == OPEN

        # ---- a reject whose read was answered before that consume landed
        race = post_preview(client).json()
        assert race["state"] == PENDING, race
        race_id = race["preview_id"]
        race_cid = f"cb-ai-{race_id}"
        real_row = h.ai._row
        armed = {"on": True}

        def read_then_placed(identifier):
            row = real_row(identifier)
            if armed["on"] and identifier == race_id:
                # The approval finishes while this answer is on its way back: the
                # row is spent and the order written before the reject's own
                # write lands.
                armed["on"] = False
                placed = h.ai.approve(identifier, race["hash"])
                assert placed["state"] == PLACED, placed
                return row
            return row

        h.ai._row = read_then_placed
        try:
            lost = client.post(reject_path(race_id))
        finally:
            h.ai._row = real_row
        assert lost.status_code == 409, lost.text
        assert lost.json().get("code") == NOT_PENDING, lost.text
        stored = preview_row(h.store, race_id)
        assert stored["state"] == PLACED, stored
        assert stored["cid"] == race_cid, stored
        assert len(orders_for(h.store, race_cid)) == 1

        # ---- the plain case: one reject retires a pending preview, the next 409
        plain = post_preview(client).json()
        plain_id = plain["preview_id"]
        once = client.post(reject_path(plain_id))
        assert once.status_code == 200, once.text
        assert once.json()["state"] == REJECTED_STATE, once.text
        again = client.post(reject_path(plain_id))
        assert again.status_code == 409, again.text
        assert again.json().get("code") == NOT_PENDING, again.text
        stored = preview_row(h.store, plain_id)
        assert stored["state"] == REJECTED_STATE, stored
        assert stored["refusal"] == "REJECTED", stored
    close(h)


# ================================================================ housekeeping


def test_sweep_keeps_rows_with_cid(tmp_path):
    """An answered preview with an order behind it is the owner's record: kept."""
    h = build_engine(tmp_path / "retention")
    prime(h)
    old = time.time() - 8 * DAY_S

    placed_id = insert_preview(
        h.store,
        state=PLACED,
        cid=f"cb-ai-{uuid.uuid4().hex}",
        created_at=old,
        expires_at=old,
        approved_at=old,
        consumed_at=old,
    )
    refused_with_cid = insert_preview(
        h.store,
        state=REJECTED_STATE,
        refusal="EXCHANGE_REJECTED",
        cid=f"cb-ai-{uuid.uuid4().hex}",
        created_at=old,
        expires_at=old,
        approved_at=old,
        consumed_at=old,
    )
    refused_without = insert_preview(
        h.store,
        state=REJECTED_STATE,
        refusal="REJECTED",
        created_at=old,
        expires_at=old,
        approved_at=old,
    )
    expired_without = insert_preview(
        h.store,
        state=EXPIRED_STATE,
        created_at=old,
        expires_at=old,
        approved_at=old,
    )

    h.ai.sweep()

    assert preview_row(h.store, placed_id) is not None
    assert preview_row(h.store, refused_with_cid) is not None
    assert preview_row(h.store, refused_without) is None
    assert preview_row(h.store, expired_without) is None
    close(h)


def test_sweep_retires_failed_and_stalled(tmp_path):
    """The sweep follows the order rows, and gives up on an unanswered approval."""
    module = ai_module()
    assert module.APPROVED_STALL_S == 60, module.APPROVED_STALL_S

    h = build_engine(tmp_path / "sweep-states", live=False)
    prime(h)
    now = time.time()

    def placed(status):
        """A placed preview, and the order row the approval wrote for it."""
        identifier = uuid.uuid4().hex
        cid = f"cb-ai-{identifier}"
        insert_preview(
            h.store,
            preview_id=identifier,
            state=PLACED,
            cid=cid,
            approved_at=now - 120,
            consumed_at=now - 120,
        )
        h.store.insert_order(
            cid,
            "ai",
            "ai",
            PRODUCT,
            "BUY",
            0,
            D("0.98"),
            D("5"),
            status=status,
            book="dry",
            product_type="SPOT",
        )
        return identifier

    rejected_id = placed(REJECTED)
    failed_id = placed(FAILED)
    open_id = placed(OPEN)
    stalled_id = insert_preview(h.store, state=APPROVED, approved_at=now - 120)
    fresh_id = insert_preview(h.store, state=APPROVED, approved_at=now - 30)

    # The two rules that follow the rows and the approvals depend on the cycle
    # lock, so this is the call the cycle makes, not the one a read makes.
    h.ai.sweep_locked()

    for identifier, label in ((rejected_id, "rejected"), (failed_id, "failed")):
        stored = preview_row(h.store, identifier)
        assert stored["state"] == REJECTED_STATE, (label, stored)
        assert stored["refusal"] == "ORDER_FAILED", (label, stored)
    assert preview_row(h.store, open_id)["state"] == PLACED
    stalled = preview_row(h.store, stalled_id)
    assert stalled["state"] == REJECTED_STATE, stalled
    assert stalled["refusal"] == "APPROVAL_STALLED", stalled
    assert preview_row(h.store, fresh_id)["state"] == APPROVED
    close(h)

    # The cycle asks the AI surface to sweep, once per cycle, and a sweep that
    # raises costs nothing but its own warning.
    cycle_h = build_engine(tmp_path / "sweep-cycle", live=False)
    prime(cycle_h)
    sweep = getattr(cycle_h.engine.runner, "ai_sweep", None)
    assert getattr(sweep, "__self__", None) is cycle_h.ai, sweep

    calls: list[int] = []
    cycle_h.engine.runner.ai_sweep = lambda: calls.append(1)
    cycle_h.engine.runner.cycle()
    cycle_h.engine.runner.cycle()
    assert len(calls) == 2, calls

    def failing_sweep():
        raise RuntimeError("the sweep failed")

    cycle_h.engine.runner.ai_sweep = failing_sweep
    heartbeat = cycle_h.engine.runner.cycle()
    assert isinstance(heartbeat, dict), heartbeat
    close(cycle_h)


def test_runner_sweeps_ai_previews_and_survives_failure(tmp_path):
    """The cycle sweeps the AI's previews itself, and a failing sweep costs no cycle."""
    h = build_engine(tmp_path / "cycle-sweep", live=False)
    fund_ai(h)
    prime(h)
    runner = h.engine.runner
    sweep = runner.ai_sweep
    assert getattr(sweep, "__self__", None) is h.ai, sweep

    with h.client() as client:
        body = post_preview(client).json()
    assert body["state"] == PENDING, body
    preview_id = body["preview_id"]

    # Past its window, and no listing or approval asked for anything: ONE cycle
    # is what retires it, because the cycle is the housekeeping nobody waits for.
    h.store.conn().execute(
        "UPDATE ai_previews SET expires_at=? WHERE id=?",
        (time.time() - 5.0, preview_id),
    )
    assert preview_row(h.store, preview_id)["state"] == PENDING, preview_row(
        h.store, preview_id
    )
    heartbeat = runner.cycle()
    assert isinstance(heartbeat, dict), heartbeat
    stored = preview_row(h.store, preview_id)
    assert stored is not None, stored
    assert stored["state"] == EXPIRED_STATE, stored

    # Once per cycle, exactly once.
    calls: list[int] = []
    runner.ai_sweep = lambda: calls.append(1)
    runner.cycle()
    runner.cycle()
    assert len(calls) == 2, calls

    # A sweep that raises leaves the cycle's heartbeat standing, and the next
    # cycle offers the sweep again rather than giving up on it.
    raised: list[int] = []

    def failing_sweep():
        raised.append(1)
        raise RuntimeError("the sweep failed")

    runner.ai_sweep = failing_sweep
    heartbeat = runner.cycle()
    assert isinstance(heartbeat, dict), heartbeat
    assert len(raised) == 1, raised

    again: list[int] = []
    runner.ai_sweep = lambda: again.append(1)
    assert isinstance(runner.cycle(), dict)
    assert len(again) == 1, again
    close(h)


def test_stall_rule_only_in_locked_sweep(tmp_path):
    """Only the cycle's own sweep retires a stalled approval or a lost order."""
    h = build_engine(tmp_path / "locked-sweep", live=False)
    fund_ai(h)
    prime(h)
    now = time.time()

    # An approval nobody spent, long past the stall window.
    stalled_id = insert_preview(h.store, state=APPROVED, approved_at=now - 120)
    # A placed preview whose order the book lost.
    failed_id = uuid.uuid4().hex
    failed_cid = f"cb-ai-{failed_id}"
    insert_preview(
        h.store,
        preview_id=failed_id,
        state=PLACED,
        cid=failed_cid,
        approved_at=now - 120,
        consumed_at=now - 120,
    )
    h.store.insert_order(
        failed_cid,
        "ai",
        "ai",
        PRODUCT,
        "BUY",
        0,
        D("0.98"),
        D("5"),
        status=FAILED,
        book="dry",
        product_type="SPOT",
    )

    # None of the unlocked callers retires either row: a preview, a listing, a
    # reject and an approve's own sweep are all housekeeping beside the cycle.
    h.ai.sweep()
    assert preview_row(h.store, stalled_id)["state"] == APPROVED
    assert preview_row(h.store, failed_id)["state"] == PLACED

    with h.client() as client:
        listed = client.get("/ai/previews")
        assert listed.status_code == 200, listed.text
        assert preview_row(h.store, stalled_id)["state"] == APPROVED
        assert preview_row(h.store, failed_id)["state"] == PLACED

        made = post_preview(client)
        assert made.status_code == 200, made.text
        assert made.json()["state"] == PENDING, made.text
        assert preview_row(h.store, stalled_id)["state"] == APPROVED
        assert preview_row(h.store, failed_id)["state"] == PLACED

        another = insert_preview(h.store, state=PENDING)
        rejected = client.post(reject_path(another))
        assert rejected.status_code == 200, rejected.text
        assert preview_row(h.store, stalled_id)["state"] == APPROVED
        assert preview_row(h.store, failed_id)["state"] == PLACED

    # The call the cycle makes is the one that retires them.
    assert h.ai.sweep_locked() >= 0
    stalled = preview_row(h.store, stalled_id)
    assert stalled["state"] == REJECTED_STATE, stalled
    assert stalled["refusal"] == "APPROVAL_STALLED", stalled
    failed = preview_row(h.store, failed_id)
    assert failed["state"] == REJECTED_STATE, failed
    assert failed["refusal"] == "ORDER_FAILED", failed
    close(h)


def test_order_failed_sweep_keeps_post_only_refusal(tmp_path):
    """A row already finished with its own code is never overwritten by ORDER_FAILED."""
    h = build_engine(tmp_path / "sweep-refusal", live=False)
    prime(h)
    now = time.time()

    def placed(state, refusal):
        """A preview finished with a code of its own, over an order the book lost."""
        identifier = uuid.uuid4().hex
        cid = f"cb-ai-{identifier}"
        insert_preview(
            h.store,
            preview_id=identifier,
            state=state,
            refusal=refusal,
            cid=cid,
            approved_at=now - 120,
            consumed_at=now - 120,
        )
        h.store.insert_order(
            cid,
            "ai",
            "ai",
            PRODUCT,
            "BUY",
            0,
            D("0.98"),
            D("5"),
            status=FAILED,
            book="dry",
            product_type="SPOT",
        )
        return identifier

    refused_id = placed(REJECTED_STATE, POST_ONLY_WOULD_CROSS)
    placed_id = placed(PLACED, "EXCHANGE_REJECTED")

    h.ai.sweep_locked()

    refused = preview_row(h.store, refused_id)
    assert refused["state"] == REJECTED_STATE, refused
    assert refused["refusal"] == POST_ONLY_WOULD_CROSS, refused
    kept = preview_row(h.store, placed_id)
    assert kept["state"] == PLACED, kept
    assert kept["refusal"] == "EXCHANGE_REJECTED", kept
    close(h)


def test_flood_count_in_insert_transaction(tmp_path):
    """The insert counts the flood itself, with the cheap early check out of the way."""
    module = ai_module()

    # ---- twenty may wait at once, and the row that would be the twenty-first is
    # never written, whatever the early check was told.
    h = build_engine(tmp_path / "flood-insert-pending", live=False)
    fund_ai(h)
    prime(h)
    h.ai._refuse_a_flood = lambda *args, **kwargs: None
    with h.client() as client:
        for _ in range(module.MAX_PENDING_PREVIEWS):
            made = post_preview(client)
            assert made.status_code == 200, made.text
            assert made.json()["state"] == PENDING, made.text
        before = preview_count(h.store)
        refused = post_preview(client)
        assert refused.status_code == 429, refused.text
        assert refused.json().get("code") == "PREVIEW_LIMIT", refused.text
        assert preview_count(h.store) == before
        assert preview_row(h.store, refused.json().get("preview_id") or "") is None
    close(h)

    # ---- sixty may be made in the hour, whatever became of them.
    h = build_engine(tmp_path / "flood-insert-hour", live=False)
    fund_ai(h)
    prime(h)
    h.ai._refuse_a_flood = lambda *args, **kwargs: None
    with h.client() as client:
        for _ in range(module.MAX_PREVIEWS_PER_HOUR):
            made = post_preview(client)
            assert made.status_code == 200, made.text
            assert made.json()["state"] == PENDING, made.text
            answered = client.post(reject_path(made.json()["preview_id"]))
            assert answered.status_code == 200, answered.text
        before = preview_count(h.store)
        capped = post_preview(client)
        assert capped.status_code == 429, capped.text
        assert capped.json().get("code") == "PREVIEW_LIMIT", capped.text
        assert preview_count(h.store) == before
    close(h)


def test_sweep_maps_cancelled_order_to_cancelled_preview(tmp_path):
    """A placed preview whose order the book cancelled ends `cancelled`, no code."""
    h = build_engine(tmp_path / "sweep-cancelled", live=False)
    prime(h)
    now = time.time()

    def placed(status):
        """A placed preview and the order row it confirmed into."""
        identifier = uuid.uuid4().hex
        cid = f"cb-ai-{identifier}"
        insert_preview(
            h.store,
            preview_id=identifier,
            state=PLACED,
            cid=cid,
            approved_at=now - 120,
            consumed_at=now - 120,
        )
        h.store.insert_order(
            cid,
            "ai",
            "ai",
            PRODUCT,
            "BUY",
            0,
            D("0.98"),
            D("5"),
            status=status,
            book="dry",
            product_type="SPOT",
        )
        return identifier

    cancelled_id = placed(CANCELLED)
    open_id = placed(OPEN)

    # A listing sweeps, and the cancelled order ends its preview as cancelled.
    with h.client() as client:
        listed = client.get("/ai/previews")
        assert listed.status_code == 200, listed.text
    swept = preview_row(h.store, cancelled_id)
    assert swept["state"] == CANCELLED_STATE, swept
    assert swept["refusal"] is None, swept
    assert preview_row(h.store, open_id)["state"] == PLACED, preview_row(
        h.store, open_id
    )

    # The same through a plain sweep, and an order still resting is untouched.
    another = placed(CANCELLED)
    h.ai.sweep()
    mapped = preview_row(h.store, another)
    assert mapped["state"] == CANCELLED_STATE, mapped
    assert mapped["refusal"] is None, mapped
    assert preview_row(h.store, open_id)["state"] == PLACED
    close(h)


# ================================================================ cancelling


def test_cancel_ai_only(tmp_path):
    """The cancel route is the AI's, the bearer token's, and knows its orders."""
    h = build_engine(tmp_path / "cancel")
    fund_ai(h)
    prime(h)
    add_bot(h, BOT)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)

    with h.client() as client:
        body = post_preview(client).json()
        preview_id = body["preview_id"]
        placed = signer.post(client, approve_path(preview_id), {"hash": body["hash"]})
        assert placed.status_code == 200, placed.text
        cid = placed.json()["cid"]

        # The bearer token alone cancels it, and the preview it placed ends so.
        cancelled = client.post(cancel_path(cid))
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json() == {"cid": cid, "cancelled": True}
        assert preview_row(h.store, preview_id)["state"] == CANCELLED_STATE
        assert "cancel" in h.dry.writes

        # A bot's order is not the AI's.
        bot = h.gateway.submit("bot", BOT, buy())
        assert bot.ok is True, bot
        refused = client.post(cancel_path(bot.cid))
        assert refused.status_code == 403, refused.text
        assert refused.json().get("code") == NOT_OWNER, refused.text
        assert h.store.order(bot.cid)["status"] == OPEN

        # An id nobody holds, and one that is already done.
        nowhere = client.post(cancel_path("cb-ai-ffffffffffffffffffffffffffffffff"))
        assert nowhere.status_code == 403, nowhere.text
        assert nowhere.json().get("code") == NOT_OWNER, nowhere.text

        h.store.update_order(cid, status=FILLED)
        late = client.post(cancel_path(cid))
        assert late.status_code == 409, late.text
        assert late.json().get("code") == NOT_CANCELLABLE, late.text
    close(h)


# ================================================================ the gate


def test_approve_needs_privileged_mac(tmp_path):
    """Approving is the strict gate's; every other AI route is the bearer's."""
    h = build_engine(tmp_path / "mac")
    fund_ai(h)
    prime(h)

    with h.client() as client:
        body = post_preview(client).json()
        preview_id = body["preview_id"]

        # The bearer token alone is not an approval.
        bare = client.post(approve_path(preview_id), json={"hash": body["hash"]})
        assert bare.status_code == 403, bare.text
        assert bare.json() == {"detail": "APPROVAL_INVALID"}, bare.text

        # The install token is never a key on the strict gate.
        install = Signer(h.install_token, h.clock)
        refused = install.post(
            client, approve_path(preview_id), {"hash": body["hash"]}
        )
        assert refused.status_code == 403, refused.text
        assert refused.json() == {"detail": "APPROVAL_INVALID"}, refused.text

        # Neither is a secret that is not the owner's.
        wrong = Signer("wrong-" + secrets.token_hex(20), h.clock)
        assert (
            wrong.post(client, approve_path(preview_id), {"hash": body["hash"]}).status_code
            == 403
        )
        assert preview_row(h.store, preview_id)["state"] == PENDING

        # The owner's own secret is, and the approval places the order.
        secret = owner_secret()
        h.engine.auth.set_secret(secret)
        owner = Signer(secret, h.clock)
        accepted = owner.post(client, approve_path(preview_id), {"hash": body["hash"]})
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["state"] == PLACED

        # Preview, list and reject are the bearer token's alone.
        second = post_preview(client)
        assert second.status_code == 200, second.text
        rejected = client.post(reject_path(second.json()["preview_id"]))
        assert rejected.status_code == 200, rejected.text
        stored = preview_row(h.store, second.json()["preview_id"])
        assert stored["state"] == REJECTED_STATE, stored
        assert stored["refusal"] == "REJECTED", stored

        # A preview that has already been placed cannot be rejected.
        placed = post_preview(client)
        assert placed.status_code == 200, placed.text
        third = placed.json()
        assert (
            owner.post(client, approve_path(third["preview_id"]), {"hash": third["hash"]}).status_code
            == 200
        )
        late = client.post(reject_path(third["preview_id"]))
        assert late.status_code == 409, late.text
        assert late.json().get("code") == NOT_PENDING, late.text

        listed = client.get("/ai/previews")
        assert listed.status_code == 200, listed.text
        assert {item["state"] for item in listed.json()} <= set(PREVIEW_STATES)

        # An unknown preview is a 404 on the reject route.
        missing = client.post(reject_path(uuid.uuid4().hex))
        assert missing.status_code == 404, missing.text
        assert missing.json().get("code") == NOT_FOUND, missing.text
    close(h)


# ================================================================ the start


def test_autonomous_refused_at_startup(tmp_path, monkeypatch, caplog):
    """Autonomous mode and an unusable TTL refuse the start; the default starts."""
    caplog.set_level(logging.INFO)
    started: list[Any] = []
    monkeypatch.setattr(
        main_module, "_run_runner", lambda runner: started.append(runner)
    )
    served: list[Any] = []

    def serve(*args, **kwargs):
        served.append((args, kwargs))

    def configuration(name: str, **overrides):
        data_dir = tmp_path / name / "data"
        env = dict(BASE_ENV)
        env["CROW_COINBASE_ENGINE_TOKEN"] = TOKEN
        env["CROW_COINBASE_DATA_DIR"] = str(data_dir)
        env.update(overrides)
        return env, data_dir

    # Autonomous AI orders are not a mode this build may run in.
    env, data_dir = configuration(AI_MODE_ENV, **{AI_MODE_ENV: "autonomous"})
    assert main(env, build=build_app, serve=serve) == 3
    assert (
        "Autonomous AI orders become available after outside-client hiding (P3)"
        in caplog.text
    ), caplog.text
    assert served == []
    assert not data_dir.exists()

    # A mode nobody recognises, and a TTL that is not a usable number of seconds.
    for value in ("yolo", "decline", "autonomous-orders"):
        caplog.clear()
        env, data_dir = configuration(f"mode-{value}", **{AI_MODE_ENV: value})
        served.clear()
        assert main(env, build=build_app, serve=serve) == 3, value
        assert AI_MODE_ENV in caplog.text, (value, caplog.text)
        assert served == []
        assert not data_dir.exists()

    for value in ("0", "abc", "999999", "-5", "60.5"):
        caplog.clear()
        env, data_dir = configuration(f"ttl-{value}", **{AI_TTL_ENV: value})
        served.clear()
        assert main(env, build=build_app, serve=serve) == 3, value
        assert AI_TTL_ENV in caplog.text, (value, caplog.text)
        assert served == []
        assert not data_dir.exists()

    # The default, and "approve" spelled out, start and serve the app.
    for label, mode in (("default", None), ("approve", "approve")):
        env, data_dir = configuration(label)
        if mode is not None:
            env[AI_MODE_ENV] = mode
        served.clear()
        started.clear()
        assert main(env, build=build_app, serve=serve) == 0, label
        assert len(served) == 1, label
        assert len(started) == 1, label
        assert data_dir.exists(), label

    # The TTL the environment names is the one a preview is given.
    short = build_engine(tmp_path / "ttl-engine", env={AI_TTL_ENV: "60"})
    fund_ai(short)
    prime(short)
    with short.client() as client:
        body = post_preview(client).json()
        assert body["state"] == PENDING, body
        assert body["expires_at"] - body["created_at"] == pytest.approx(60, abs=5)
    close(short)


# ================================================================ the announcements
#
# The two events an approval writes AFTER its row has moved — the order it placed
# and the refusal the chain answered with — are a reader's account of an answer the
# caller is already owed.  Neither may cost that answer.


def ai_events(store: Store, kind: str) -> list[dict]:
    """Every event row of one kind, oldest first, read with raw SQL."""
    return [
        dict(row)
        for row in store.conn().execute(
            "SELECT * FROM events WHERE kind=? ORDER BY id", (kind,)
        )
    ]


class QuietEvents:
    """A store's `event`, refusing ONE kind and writing every other one.

    The kind is compared the way every caller passes it (a keyword), so the rows
    of another kind are still written: a test can see what the engine did beside
    the row that could not land.
    """

    def __init__(self, store: Store, kind: str) -> None:
        self.kind = kind
        self.real = store.event
        self.refused = 0

    def __call__(self, level: str, message: str, **fields: Any) -> None:
        if fields.get("kind", "info") == self.kind:
            self.refused += 1
            raise RuntimeError("the events table refused the row")
        return self.real(level, message, **fields)


def test_ai_placed_event_never_costs_the_answer(tmp_path, monkeypatch):
    """An `ai_placed` event the store will not take still answers the order it placed.

    The order is on the book and the preview is `placed` by the time the event is
    written, so the owner is answered the client order id whatever the events
    table does; exactly one order row exists for the approval.
    """
    h = build_engine(tmp_path / "quiet-placed", live=False)
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    quiet = QuietEvents(h.store, "ai_placed")

    with h.client() as client:
        body = post_preview(client).json()
        assert body["state"] == PENDING, body
        preview_id = body["preview_id"]
        cid = f"cb-ai-{preview_id}"
        before = order_count(h.store)
        monkeypatch.setattr(h.store, "event", quiet)
        accepted = signer.post(
            client, approve_path(preview_id), {"hash": body["hash"]}
        )
        assert accepted.status_code == 200, accepted.text
        answer = accepted.json()
        assert answer["state"] == PLACED, answer
        assert answer["cid"] == cid, answer
        assert answer["book"] == "dry", answer

    assert quiet.refused == 1, quiet.refused
    # The approval wrote the one row it was spent on, and nothing twice.
    assert order_count(h.store) == before + 1
    assert len(orders_for(h.store, cid)) == 1
    stored = preview_row(h.store, preview_id)
    assert stored["state"] == PLACED, stored
    assert stored["cid"] == cid, stored
    assert h.dry.place_calls == [(cid, PRODUCT, "BUY", D("5"), D("0.98"))]
    assert ai_events(h.store, "ai_placed") == []
    close(h)


def test_ai_refusal_event_never_costs_the_answer(tmp_path, monkeypatch):
    """A refusal event the store will not take still answers the refusal's code."""
    h = build_engine(tmp_path / "quiet-refused", live=False)
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)
    quiet = QuietEvents(h.store, "refusal")

    with h.client() as client:
        body = post_preview(client).json()
        assert body["state"] == PENDING, body
        preview_id = body["preview_id"]
        cid = f"cb-ai-{preview_id}"
        # The chain refuses the approve: the AI's single-order cap is one dollar.
        h.engine.limits.set_caps({AI_MAX_ORDER: "1"})
        monkeypatch.setattr(h.store, "event", quiet)
        refused = signer.post(
            client, approve_path(preview_id), {"hash": body["hash"]}
        )
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == ORDER_TOO_LARGE, refused.text

    assert quiet.refused == 1, quiet.refused
    stored = preview_row(h.store, preview_id)
    assert stored["state"] == REJECTED_STATE, stored
    assert stored["refusal"] == ORDER_TOO_LARGE, stored
    assert h.store.order(cid) is None
    assert h.dry.place_calls == []
    assert ai_events(h.store, "refusal") == []
    close(h)


def test_ai_refusal_event_only_when_a_row_changed(tmp_path, monkeypatch):
    """A refusal whose retirement changed no row announces nothing."""
    h = build_engine(tmp_path / "quiet-unchanged", live=False)
    fund_ai(h)
    prime(h)
    secret = owner_secret()
    h.engine.auth.set_secret(secret)
    signer = Signer(secret, h.clock)

    with h.client() as client:
        body = post_preview(client).json()
        assert body["state"] == PENDING, body
        preview_id = body["preview_id"]
        cid = f"cb-ai-{preview_id}"
        assert ai_events(h.store, "refusal") == []

        def refused_after_the_row_moved(role, owner, intent, product=None):
            """The chain refuses, and the preview is no longer where a refusal ends it.

            The approve has already moved the row to `approved` and is inside its
            spend; the row ends `cancelled` before the refusal's own retirement
            reads it, so that retirement changes nothing — and nothing is news.
            """
            if intent.approval_id:
                h.store.conn().execute(
                    "UPDATE ai_previews SET state=? WHERE id=?",
                    (CANCELLED_STATE, intent.approval_id),
                )
            return GatewayResult(ok=False, cid=None, refusal=ORDER_TOO_LARGE)

        monkeypatch.setattr(h.gateway, "submit", refused_after_the_row_moved)
        refused = signer.post(
            client, approve_path(preview_id), {"hash": body["hash"]}
        )
        assert refused.status_code == 409, refused.text
        assert refused.json().get("code") == ORDER_TOO_LARGE, refused.text

    assert preview_row(h.store, preview_id)["state"] == CANCELLED_STATE
    assert h.store.order(cid) is None
    assert ai_events(h.store, "refusal") == [], ai_events(h.store, "refusal")
    close(h)


# ================================================================ the module


def test_ai_module_no_bypass():
    """The AI order module reaches the exchange through the gateway and nothing else."""
    guard = no_bypass_module()
    path = SRC / "ai_orders.py"
    assert path.is_file(), f"{path} is missing"

    scanned = {item.relative_to(SRC).as_posix() for item in guard._package_files()}
    assert "ai_orders.py" in scanned, sorted(scanned)

    findings = guard.scan_source("ai_orders.py", path.read_text(encoding="utf-8"))
    assert findings == [], "\n".join(findings)