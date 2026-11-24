"""test_ai_capital_caps.py: the AI's live capital, the runtime caps, and `/caps`.

Every test here builds the REAL engine through `build_app`: a real `Store` on a
temporary data directory, the real dry-run exchange, gateway, runner and approval
rail, so a cap check and a refusal are the engine's own.  The live book is a
SECOND `DryRunExchange` over a second store file, wrapped in an `ExchangeRouter`
and funded with `deposit`, and it is handed to `build_app` as its `live_factory`,
so the live book has an account without a key having to be pushed first.

Only the outside world is faked: `FakeMarket` answers one fixed touch, so nothing
opens a socket, and `FakeLiveBuilder` is the `live_builder` `build_app` takes — it
answers one `FakeLive`, whose `key_permissions()` is a good key's answer and whose
every other call fails the test on the spot.  The bearer token, the install token,
the approval secrets and the key pair are all built at runtime, so no value in
this file is a credential.

`Signer` signs a request the way the rail checks one: it hands `auth.compute_mac`
the same bytes `TestClient` sends, over the same path.

What each test pins down:

* the AI's live orders are limited by its own capital, one pool per quote
  currency shared by every product it trades, and a resting order leaves less of
  it for the next one,
* `unallocated(..., book="live")` reserves the AI capital exactly once, with no
  phantom currency in the result, and leaves the dry book alone,
* a bot's dry-to-live switch cannot take that reserve, whatever the AI's own live
  switch says,
* `POST /caps` is the strict gate's (the bearer token, then the owner's MAC, never
  the install token) and `GET /caps` answers the nine caps, their ceilings and
  each book's usage today,
* on a first start every cap is its ceiling; a cap may not be set above its
  ceiling; an invalid value writes nothing; a mixed body writes nothing at all,
* caps survive a restart, a lowered ceiling clamps the stored caps down and
  persists that, and a raised ceiling never raises them,
* every cap check reads the RUNTIME value: the gateway's order, daily, rate,
  drawdown and holding checks, the runner's portfolio halt, the capital a new bot
  is given, and the AI's own holding,
* no module outside `limits.py` reads a cap's env name, and `Limits.from_env` is
  built only where a plain `Limits` is allowed,
* the fifth wrong approval secret writes ONE `credentials` warning event, the
  refused requests that follow write none, a later lockout writes a second, and
  no event carries a secret or a key,
* `RuntimeLimits` delegates everything that is not a cap, reads the stored value
  on every access, and falls back to the ceiling for a value it cannot use.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal as D
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import crow_coinbase.auth as auth_module
import crow_coinbase.limits as limits_module
from crow_coinbase.__main__ import build_app
from crow_coinbase.books import ModeRefused
from crow_coinbase.exchange import DryRunExchange
from crow_coinbase.gateway import (
    DAILY_CAP,
    DRAWDOWN_STOP,
    INSUFFICIENT_HOLDING,
    ORDER_TOO_LARGE,
    PORTFOLIO_OWNER,
    RATE_CAP,
)
from crow_coinbase.limits import Limits
from crow_coinbase.money import ProductSpec
from crow_coinbase.router import ExchangeRouter
from crow_coinbase.store import CANCELLED, FILLED, OPEN, Store
from crow_coinbase.strategies.base import MarketSnapshot, OrderIntent

# ---------------------------------------------------------------- test data
PRODUCT = "XRP-USDC"
SECOND = "BTC-USDC"
BASE = "XRP"
QUOTE = "USDC"
SECOND_BASE = "BTC"

BOT = "b1"

FEE_RATE = D("0.005")
MID = (D("0.99") + D("1.00")) / 2  # 0.995

# 32+ characters, no whitespace: the shortest bearer token the engine starts with.
TOKEN = "test-token-" + secrets.token_hex(16)

# The injected clock every engine and every signature starts from.
NOW = 1_700_000_000.0

# The nine caps, by the env name they are set with: this file spells them out
# rather than importing them, so a name the engine renames is a failure here.
DAILY = "CROW_COINBASE_DAILY_NOTIONAL_USD"
ORDERS_HOUR = "CROW_COINBASE_ORDERS_PER_HOUR"
DRAWDOWN = "CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT"
BOT_MAX_ORDER = "CROW_COINBASE_BOT_MAX_ORDER_USD"
MAX_BOT_CAPITAL = "CROW_COINBASE_MAX_BOT_CAPITAL_USD"
AI_MAX_ORDER = "CROW_COINBASE_AI_MAX_ORDER_USD"
AI_DAILY = "CROW_COINBASE_AI_DAILY_NOTIONAL_USD"
AI_ORDERS_HOUR = "CROW_COINBASE_AI_ORDERS_PER_HOUR"
AI_CAPITAL = "CROW_COINBASE_AI_CAPITAL_USD"

CAP_ENV_NAMES = (
    DAILY,
    ORDERS_HOUR,
    DRAWDOWN,
    BOT_MAX_ORDER,
    MAX_BOT_CAPITAL,
    AI_MAX_ORDER,
    AI_DAILY,
    AI_ORDERS_HOUR,
    AI_CAPITAL,
)

# The nine env names as the constants `limits.py` exports for them.
CAP_ENV_CONSTANTS = (
    "ENV_DAILY_NOTIONAL_USD",
    "ENV_ORDERS_PER_HOUR",
    "ENV_PORTFOLIO_DRAWDOWN_PCT",
    "ENV_BOT_MAX_ORDER_USD",
    "ENV_MAX_BOT_CAPITAL_USD",
    "ENV_AI_MAX_ORDER_USD",
    "ENV_AI_DAILY_NOTIONAL_USD",
    "ENV_AI_ORDERS_PER_HOUR",
    "ENV_AI_CAPITAL_USD",
)

# The defaults, which are also the ceilings on a first start.
CAP_DEFAULTS = {
    DAILY: "200",
    ORDERS_HOUR: "30",
    DRAWDOWN: "20",
    BOT_MAX_ORDER: "50",
    MAX_BOT_CAPITAL: "100",
    AI_MAX_ORDER: "25",
    AI_DAILY: "50",
    AI_ORDERS_HOUR: "10",
    AI_CAPITAL: "25",
}

# The two caps that are counts: ints in the answers, whole numbers in a body.
COUNT_CAPS = (ORDERS_HOUR, AI_ORDERS_HOUR)

CAP_IDS = {
    DAILY: "daily",
    ORDERS_HOUR: "orders-hour",
    DRAWDOWN: "drawdown",
    BOT_MAX_ORDER: "bot-order",
    MAX_BOT_CAPITAL: "max-bot-capital",
    AI_MAX_ORDER: "ai-order",
    AI_DAILY: "ai-daily",
    AI_ORDERS_HOUR: "ai-orders-hour",
    AI_CAPITAL: "ai-capital",
}

# The one kv key the runtime caps live under.
RUNTIME_CAPS_KEY = "runtime_caps"

# The sentence a lockout is recorded with.
LOCKOUT_MESSAGE = "Too many wrong approval secrets; reconnect blocked for a minute"

SECRET_MISMATCH = "SECRET_MISMATCH"
INVALID = "INVALID"
ABOVE_CEILING = "ABOVE_CEILING"
RATE_LIMITED = "RATE_LIMITED"
LIVE_CAPITAL_SHORT = "LIVE_CAPITAL_SHORT"
AI_CAPITAL_SHORT = "AI_CAPITAL_SHORT"

BASE_ENV = {
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": f"{PRODUCT},{SECOND}",
}

GRID_PARAMS = {
    "center": "1.0",
    "step_pct": "1.5",
    "levels_below": 3,
    "levels_above": 3,
    "quote_per_buy": "10",
    "rebuy_sizing": "proceeds",
}

# The private-key headers, built from parts: this file never spells one out.
PEM_BEGIN = "-----BEGIN "
PEM_END = "-----END "
PEM_EC = "EC "
PEM_SUFFIX = "PRIVATE KEY-----"

SRC = Path(__file__).resolve().parents[1] / "src" / "crow_coinbase"


# ---------------------------------------------------------------- the outside world


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


def permissions(portfolio: str | None = None) -> dict:
    """One `key_permissions()` answer: a CONSUMER key that cannot move money out."""
    return {
        "can_view": True,
        "can_trade": True,
        "can_transfer": False,
        "portfolio_uuid": portfolio if portfolio is not None else uuid.uuid4().hex,
        "portfolio_type": "CONSUMER",
    }


class FakeLive:
    """The live adapter: one permissions answer, and every other call a failure."""

    dry_run = False

    def __init__(self) -> None:
        self.perms = permissions()

    def key_permissions(self) -> dict:
        return dict(self.perms)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        raise AssertionError(f"unexpected exchange call: {name}")


class FakeLiveBuilder:
    """The `live_builder` `build_app` takes: one `FakeLive`, counted.

    The `FakeLive` is built once and answered on every call, never a new one per
    call: `permissions()` names a fresh random portfolio every time it is asked,
    so a builder that answered a new `FakeLive` each time would make the key look
    scoped to a different portfolio on every push — the first connect pins one,
    and the owner's own re-push would be refused `KEY_WRONG_PORTFOLIO` for a
    portfolio the same key never left.  One adapter answered every time is one
    key's answer every time.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.fake = FakeLive()

    def __call__(self, creds) -> FakeLive:
        self.calls += 1
        return self.fake


# ---------------------------------------------------------------- test secrets


def approve_secret() -> str:
    """An approval secret, 32+ bytes long, built at runtime."""
    return "approve-" + secrets.token_hex(20)


def key_name_canary() -> str:
    """A key name in the shape Coinbase answers, built at runtime."""
    return f"organizations/{uuid.uuid4().hex}/apiKeys/{uuid.uuid4().hex}"


def private_key_canary() -> tuple[str, str]:
    """A synthetic PEM EC private key, and a body line a scan can look for."""
    marker = base64.b64encode(secrets.token_bytes(36)).decode("ascii")
    lines = [
        base64.b64encode(secrets.token_bytes(40)).decode("ascii"),
        marker,
        base64.b64encode(secrets.token_bytes(40)).decode("ascii"),
    ]
    header = PEM_BEGIN + PEM_EC + PEM_SUFFIX
    footer = PEM_END + PEM_EC + PEM_SUFFIX
    return "\n".join([header, *lines, footer]), marker


def credentials_body(key_name: str, private_key: str, secret: str) -> dict:
    """The whole POST /credentials body a test sends."""
    return {
        "key_name": key_name,
        "private_key": private_key,
        "approve_secret": secret,
    }


class Signer:
    """Builds the three approval headers for one request, over the bytes it sends."""

    def __init__(self, clock) -> None:
        self.clock = clock

    def nonce(self) -> str:
        """A fresh nonce: the base64url alphabet, long enough to be unique."""
        return "n" + secrets.token_hex(12)

    def headers(
        self,
        key,
        method: str,
        path_with_query: str,
        body: bytes = b"",
        *,
        nonce: str | None = None,
        ts: Any = None,
    ) -> dict:
        material = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        stamp = str(int(self.clock[0] if ts is None else ts))
        used = self.nonce() if nonce is None else str(nonce)
        signature = auth_module.compute_mac(
            material, method, path_with_query, stamp, used, body
        )
        headers = {
            "Authorization": f"Bearer {TOKEN}",
            "X-Crow-Timestamp": stamp,
            "X-Crow-Nonce": used,
            "X-Crow-Signature": signature,
        }
        if body:
            headers["Content-Type"] = "application/json"
        return headers

    def post(
        self,
        client,
        path_with_query: str,
        payload: Any = None,
        *,
        key,
        nonce: str | None = None,
        ts: Any = None,
    ):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = self.headers(
            key, "POST", path_with_query, body, nonce=nonce, ts=ts
        )
        return client.post(path_with_query, content=body, headers=headers)


# ---------------------------------------------------------------- the harness


@dataclass
class Harness:
    """One engine, the live account it was given and the signer over its clock."""

    engine: Any
    clock: list
    data_dir: Path
    token_path: Path
    install_token: str
    live_store: Store
    signer: Signer

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
    def limits(self):
        return self.engine.limits

    @contextlib.contextmanager
    def client(self):
        with TestClient(self.engine.app, raise_server_exceptions=False) as client:
            client.headers.update({"Authorization": f"Bearer {TOKEN}"})
            yield client


def build_engine(
    root,
    *,
    env: dict | None = None,
    live_totals=(("USDC", "1000"), ("XRP", "1000"), ("BTC", "1000")),
    clock: list | None = None,
    live: bool = True,
) -> Harness:
    """The real engine over *root*, with a funded live account and a fake market.

    `live=False` wires a live side that answers no exchange at all, so the live
    book is locked exactly as it is on an engine no key was pushed to.
    """
    root = Path(root)
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = root / "install_token"
    install_token = "install-" + secrets.token_hex(20)
    token_path.write_text(install_token + "\n", encoding="utf-8")

    clock = [NOW] if clock is None else clock

    live_store = Store(root / "live.db")
    live_sim = DryRunExchange(live_store.conn, market_for, FEE_RATE)
    for currency, amount in live_totals:
        live_sim.deposit(currency, D(amount), "funding")
    live_router = ExchangeRouter(live_sim, usd_one_pool=True)

    configuration = dict(BASE_ENV)
    configuration["CROW_COINBASE_ENGINE_TOKEN"] = TOKEN
    configuration["CROW_COINBASE_INSTALL_TOKEN_FILE"] = str(token_path)
    configuration.update(env or {})

    engine = build_app(
        configuration,
        data_dir=data_dir,
        market_for=market_for,
        spec_for=spec_for,
        now=lambda: clock[0],
        live_factory=(lambda: live_router) if live else (lambda: None),
        live_builder=FakeLiveBuilder(),
    )
    return Harness(
        engine=engine,
        clock=clock,
        data_dir=data_dir,
        token_path=token_path,
        install_token=install_token,
        live_store=live_store,
        signer=Signer(clock),
    )


def close(h: Harness) -> None:
    """Close both stores, so the next engine over the same files starts clean."""
    for store in (h.engine.store, h.live_store):
        with contextlib.suppress(Exception):
            store.close()


def add_bot(
    h: Harness,
    bot_id: str = BOT,
    *,
    quote: str = "100",
    base: str = "50",
    product: str = PRODUCT,
) -> dict:
    """A dry bot, funded the way the engine funds one: capital, then its seed."""
    h.store.create_bot(
        bot_id, product, "grid", dict(GRID_PARAMS), D(quote), D(base)
    )
    if D(quote) > 0 or D(base) > 0:
        h.gateway.seed_dry(bot_id, D(quote), D(base))
    return h.store.get_bot(bot_id)


def prime(h: Harness, products=(PRODUCT, SECOND)) -> None:
    """A usable snapshot per product on the wall clock the gateway reads."""
    at = time.time()
    for product in products:
        bid, ask = market_for(product).best_bid_ask()
        h.runner.snapshots.put(
            MarketSnapshot(product, bid, ask, bid, ask, at)
        )
    h.runner.snapshots.set_clock(at, at)


def buy(size="20", price="0.99", **overrides) -> OrderIntent:
    """A well-formed place intent: whatever it earns is the chain's answer."""
    fields = dict(
        action="place",
        side="BUY",
        size=D(size),
        limit_price=D(price),
        level=-1,
        cancel_cid=None,
        reason="test",
    )
    fields.update(overrides)
    return OrderIntent(**fields)


def spend(
    h: Harness,
    *,
    price,
    size,
    book: str = "dry",
    source: str = "bot",
    owner: str = BOT,
    product: str = PRODUCT,
    status: str = CANCELLED,
) -> str:
    """One order row that spends a cap without moving a holding (cancelled).

    A cancelled row counts towards the daily notional and the rolling hour — it
    rested on the book — while its fill sums stay zero, so it spends a budget and
    nothing else.
    """
    cid = f"cb-{owner}-B0-{secrets.token_hex(6)}"
    h.store.insert_order(
        cid,
        owner,
        source,
        product,
        "BUY",
        0,
        D(price),
        D(size),
        status=status,
        book=book,
        product_type="SPOT",
    )
    return cid


def fill(
    h: Harness,
    *,
    owner: str,
    product: str,
    book: str,
    size,
    price,
    fee,
    side: str = "BUY",
) -> str:
    """One settled order row: a buy's cost (and fee) leaves the quote currency."""
    cid = f"cb-{owner}-B0-{secrets.token_hex(6)}"
    h.store.insert_order(
        cid, owner, owner, product, side, 0, D(price), D(size), status=OPEN, book=book,
        product_type="SPOT",
    )
    h.store.update_order(
        cid,
        status=FILLED,
        filled_size=D(size),
        filled_value=D(size) * D(price),
        fees=D(fee),
    )
    return cid


def bot_state(store: Store, bot_id: str) -> dict:
    """The columns a switch writes, so "nothing changed" can be asserted."""
    bot = store.get_bot(bot_id)
    return {
        "mode": bot["mode"],
        "capital_quote": bot["capital_quote"],
        "capital_base": bot["capital_base"],
        "live_capital_quote": bot["live_capital_quote"],
        "live_capital_base": bot["live_capital_base"],
        "status": bot["status"],
        "init_done": bot["init_done"],
    }


def bot_body(bot_id: str, *, quote: str = "40", base: str = "0") -> dict:
    """The whole POST /bots body."""
    return {
        "id": bot_id,
        "product": PRODUCT,
        "strategy": "grid",
        "params": GRID_PARAMS,
        "capital_quote": quote,
        "capital_base": base,
    }


def caps_of(client) -> dict:
    """The `/caps` body, refused loudly when the route is not there or not served."""
    response = client.get("/caps")
    assert response.status_code == 200, response.text
    return response.json()


def cap_number(name: str, value: Any) -> D:
    """A cap value as a Decimal, whatever shape it is reported in."""
    return D(str(value))


def wire(name: str, value: Any):
    """A cap value in the JSON shape a body carries: str for money, int for a count."""
    return int(value) if name in COUNT_CAPS else str(value)


# ---------------------------------------------------------------- the AI's capital


def test_ai_orders_limited_to_ai_capital(tmp_path):
    """The AI's own live orders are funded by its capital, one pool for every product."""
    h = build_engine(
        tmp_path / "ai-capital",
        # The order cap and the daily cap are lifted, so only the capital is in
        # the way of the order measured below.
        env={AI_MAX_ORDER: "100", AI_DAILY: "200"},
    )
    h.store.put("ai_live_enabled", True)
    prime(h)

    gateway = h.gateway
    ledger = gateway.ledger

    assert h.limits.ai_capital_usd == D("25")

    # The measurement is read off `evaluate()`: the approval-free chain, which is
    # what a preview asks.  `check()` runs the AI's approval step as well.
    # 20 * 0.99 * 1.005 = 19.899 of the 25 USDC the AI has.
    assert gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0] is None
    # The same order on the other product fits on its own: there is one pool, not
    # one budget per product.
    assert gateway.evaluate("ai", "ai", buy(size="20"), SECOND)[0] is None

    # 40 * 0.99 * 1.005 = 39.798: more than the AI has.
    assert (
        gateway.evaluate("ai", "ai", buy(size="40"), PRODUCT)[0]
        == INSUFFICIENT_HOLDING
    )

    # A resting buy holds 19.899 of the pool, so only 5.101 is left for the next
    # order, whichever product it is on.
    resting = spend(
        h,
        price="0.99",
        size="20",
        book="live",
        source="ai",
        owner="ai",
        status=OPEN,
    )
    assert h.store.order(resting)["book"] == "live"

    assert (
        gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0]
        == INSUFFICIENT_HOLDING
    )
    assert (
        gateway.evaluate("ai", "ai", buy(size="20"), SECOND)[0]
        == INSUFFICIENT_HOLDING
    )
    # 5 * 0.99 * 1.005 = 4.97475 still fits.
    assert gateway.evaluate("ai", "ai", buy(size="5"), PRODUCT)[0] is None

    # The pool is the quote side of every product the AI trades, and the base
    # side is that product's own.
    for product in (PRODUCT, SECOND):
        held = ledger.holding("ai", product, book="live")
        assert held.quote == D("25")
        assert held.reserved_quote == D("19.899")
        assert held.available_quote == D("5.101")
        assert held.base == D("0")
        assert held.reserved_base == D("0")


def test_ai_capital_reserved_in_unallocated(tmp_path):
    """`unallocated` takes the AI capital once, and the dry book is untouched."""
    h = build_engine(
        tmp_path / "ai-reserve",
        live_totals=(("USDC", "1000"), ("XRP", "200"), ("BTC", "5")),
    )
    ledger = h.gateway.ledger
    totals = {QUOTE: D("1000"), BASE: D("200"), SECOND_BASE: D("5")}

    # No AI order at all: the capital is still reserved for it.
    reserved = ledger.unallocated(totals, book="live")
    assert reserved == {
        QUOTE: D("975"),
        BASE: D("200"),
        SECOND_BASE: D("5"),
    }
    assert set(reserved) == {QUOTE, BASE, SECOND_BASE}

    # A settled AI buy on each of two products: 9.9 + 0.0495 of quote and 10 of
    # base on the first, 1.0 + 0.005 of quote and 1 of base on the second.
    fill(h, owner="ai", product=PRODUCT, book="live", size="10", price="0.99", fee="0.0495")
    fill(h, owner="ai", product=SECOND, book="live", size="1", price="1.00", fee="0.005")

    after = ledger.unallocated(totals, book="live")
    assert after == {
        QUOTE: D("1000") - (D("25") - D("9.9495") - D("1.005")),
        BASE: D("200") - D("10"),
        SECOND_BASE: D("5") - D("1"),
    }
    assert set(after) == {QUOTE, BASE, SECOND_BASE}
    # The capital was taken once, not once per product.
    assert D("1000") - after[QUOTE] == D("25") - D("9.9495") - D("1.005")

    # The dry book never carries the AI's live capital.
    dry_totals = {QUOTE: D("500"), BASE: D("100")}
    dry_before = ledger.unallocated(dry_totals, book="dry")
    assert dry_before == {QUOTE: D("500"), BASE: D("100")}

    fill(h, owner="ai", product=PRODUCT, book="dry", size="10", price="0.99", fee="0.0495")
    dry_after = ledger.unallocated(dry_totals, book="dry")
    assert dry_after == {QUOTE: D("500") + D("9.9495"), BASE: D("100") - D("10")}


def test_bot_switch_cannot_take_ai_capital(tmp_path):
    """The AI's reserve is not a bot's to spend, whatever the AI's switch says."""
    h = build_engine(tmp_path / "switch", live_totals=(("USDC", "100"),))
    add_bot(h, BOT, quote="100", base="50")
    h.store.put("live_enabled", True)
    prime(h)

    totals = h.gateway.books.totals("live")
    assert totals[QUOTE] == D("100")
    # 100 on the account, 25 of it the AI's: 75 is what a switch may take.
    assert h.gateway.ledger.unallocated(totals, book="live")[QUOTE] == D("75")
    # The AI's own live switch is off, and the reserve holds anyway.
    assert h.store.get("ai_live_enabled") is not True

    before = bot_state(h.store, BOT)
    with pytest.raises(ModeRefused) as short:
        h.runner.switch_mode(BOT, "live", "80", "0")
    assert short.value.code == LIVE_CAPITAL_SHORT
    assert short.value.status == 409
    assert bot_state(h.store, BOT) == before
    assert h.store.get_bot(BOT)["mode"] == "dry"
    assert h.gateway.ledger.holding(BOT, PRODUCT, book="live").quote == D("0")

    h.runner.switch_mode(BOT, "live", "75", "0")
    bot = h.store.get_bot(BOT)
    assert bot["mode"] == "live"
    assert bot["live_capital_quote"] == D("75")
    assert bot["live_capital_base"] == D("0")

    # The bot's 75 and the AI's 25 are the whole account, exactly once each.
    assert h.gateway.ledger.unallocated(
        h.gateway.books.totals("live"), book="live"
    )[QUOTE] == D("0")


# ---------------------------------------------------------------- the routes


def test_caps_need_mac(tmp_path):
    """POST /caps is the strict gate's; GET /caps needs only the bearer token."""
    h = build_engine(tmp_path / "caps-mac")
    secret = approve_secret()
    h.engine.auth.set_secret(secret)
    body = {"caps": {BOT_MAX_ORDER: "10"}}

    with h.client() as client:
        before = caps_of(client)

        # The bearer token alone is not an approval.
        bare = client.post("/caps", json=body)
        assert bare.status_code == 403, bare.text
        # A MAC over this request, keyed with anything but the owner's secret.
        wrong = h.signer.post(
            client, "/caps", body, key="wrong-" + secrets.token_hex(20)
        )
        assert wrong.status_code == 403, wrong.text
        # The install token is never a key on this route.
        install = h.signer.post(client, "/caps", body, key=h.install_token)
        assert install.status_code == 403, install.text

        # None of those changed a cap.
        assert caps_of(client) == before

        accepted = h.signer.post(client, "/caps", body, key=secret)
        assert accepted.status_code == 200, accepted.text
        answer = accepted.json()
        assert {"caps", "ceilings"} <= set(answer)
        assert cap_number(BOT_MAX_ORDER, answer["caps"][BOT_MAX_ORDER]) == D("10")
        assert cap_number(
            BOT_MAX_ORDER, answer["ceilings"][BOT_MAX_ORDER]
        ) == D("50")
        assert cap_number(
            BOT_MAX_ORDER, caps_of(client)["caps"][BOT_MAX_ORDER]
        ) == D("10")

        # A body carrying a field this build does not know is refused as a body,
        # and names the field rather than a value it carried.
        extra = h.signer.post(
            client,
            "/caps",
            {"caps": {BOT_MAX_ORDER: "10"}, "ceiling": "1"},
            key=secret,
        )
        assert extra.status_code == 422, extra.text
        assert extra.json().get("code") == INVALID, extra.text
        assert cap_number(
            BOT_MAX_ORDER, caps_of(client)["caps"][BOT_MAX_ORDER]
        ) == D("10")

        # Reading the caps is the bearer token's alone.
        assert client.get("/caps").status_code == 200


def test_get_caps_shape(tmp_path):
    """The nine caps, their ceilings, and each book's usage today."""
    h = build_engine(tmp_path / "caps-shape")

    with h.client() as client:
        body = caps_of(client)

        assert set(body) == {"caps", "ceilings", "used_today"}
        caps, ceilings, used = body["caps"], body["ceilings"], body["used_today"]

        assert set(caps) == set(CAP_ENV_NAMES)
        assert set(ceilings) == set(CAP_ENV_NAMES)

        for name, default in CAP_DEFAULTS.items():
            # A first start sets every cap to its ceiling.
            assert cap_number(name, caps[name]) == D(default), name
            assert cap_number(name, ceilings[name]) == D(default), name
            if name in COUNT_CAPS:
                assert isinstance(caps[name], int), name
                assert not isinstance(caps[name], bool), name
                assert isinstance(ceilings[name], int), name
            else:
                # Money and pct travel as decimal strings.
                assert isinstance(caps[name], str), name
                assert isinstance(ceilings[name], str), name

        assert set(used) == {"dry", "live"}
        usage_keys = {
            "daily_notional_usd",
            "ai_daily_notional_usd",
            "orders_last_hour",
            "ai_orders_last_hour",
        }
        for book, entry in used.items():
            assert set(entry) == usage_keys, book
            assert isinstance(entry["daily_notional_usd"], str), book
            assert isinstance(entry["ai_daily_notional_usd"], str), book
            assert cap_number(book, entry["daily_notional_usd"]) == D("0"), book
            assert cap_number(book, entry["ai_daily_notional_usd"]) == D("0"), book
            for count in ("orders_last_hour", "ai_orders_last_hour"):
                assert isinstance(entry[count], int), (book, count)
                assert not isinstance(entry[count], bool), (book, count)
                assert entry[count] == 0, (book, count)

    # Two dry orders and one AI live order, so each book's usage is its own.
    spend(h, price="1", size="5", book="dry")
    spend(h, price="1", size="5", book="dry")
    spend(h, price="2", size="5", book="live", source="ai", owner="ai")

    with h.client() as client:
        used = caps_of(client)["used_today"]
        assert cap_number("dry", used["dry"]["daily_notional_usd"]) == D("10")
        assert cap_number("dry", used["dry"]["ai_daily_notional_usd"]) == D("0")
        assert used["dry"]["orders_last_hour"] == 2
        assert used["dry"]["ai_orders_last_hour"] == 0

        assert cap_number("live", used["live"]["daily_notional_usd"]) == D("10")
        assert cap_number("live", used["live"]["ai_daily_notional_usd"]) == D("10")
        assert used["live"]["orders_last_hour"] == 1
        assert used["live"]["ai_orders_last_hour"] == 1


@pytest.mark.parametrize(
    "name", CAP_ENV_NAMES, ids=[CAP_IDS[cap] for cap in CAP_ENV_NAMES]
)
def test_caps_cannot_exceed_ceiling(tmp_path, name):
    """No cap may be set above its ceiling, and a refused body writes nothing."""
    h = build_engine(tmp_path / f"caps-ceiling-{CAP_IDS[name]}")
    secret = approve_secret()
    h.engine.auth.set_secret(secret)
    other = next(cap for cap in CAP_ENV_NAMES if cap != name)
    count = name in COUNT_CAPS

    def refusal(response) -> dict:
        assert response.status_code == 422, response.text
        body = response.json()
        assert body.get("code") == INVALID or body.get("code") == ABOVE_CEILING, body
        return body

    with h.client() as client:
        before = caps_of(client)
        ceiling = before["ceilings"][name]

        # One step above the ceiling, in the shape this cap travels in.
        superior = (
            int(ceiling) + 1 if count else str(D(str(ceiling)) + D("1"))
        )
        too_high = h.signer.post(
            client, "/caps", {"caps": {name: superior}}, key=secret
        )
        assert too_high.status_code == 422, too_high.text
        body = too_high.json()
        assert body.get("code") == ABOVE_CEILING, body
        assert name in body.get("message", ""), body
        assert caps_of(client) == before

        # A negative value is not a value at all.
        negative = h.signer.post(
            client, "/caps", {"caps": {name: -1}}, key=secret
        )
        body = refusal(negative)
        assert body.get("code") == INVALID, body
        if "message" in body:
            assert name in body["message"], body
        assert caps_of(client) == before

        # The ceiling itself is allowed.  Zero is allowed for every cap except
        # the drawdown percentage: a 0 stop would halt on any dip below the
        # high-water mark, so it is not a value this cap may hold.
        at_ceiling = h.signer.post(
            client, "/caps", {"caps": {name: wire(name, ceiling)}}, key=secret
        )
        assert at_ceiling.status_code == 200, at_ceiling.text
        assert cap_number(name, at_ceiling.json()["caps"][name]) == cap_number(
            name, ceiling
        )

        if name == DRAWDOWN:
            at_zero = h.signer.post(
                client, "/caps", {"caps": {name: wire(name, 0)}}, key=secret
            )
            assert at_zero.status_code == 422, at_zero.text
            body = at_zero.json()
            assert body.get("code") == INVALID, body
            assert name in body.get("message", ""), body
            assert caps_of(client) == before

            # A positive value below the ceiling is accepted, and is the
            # baseline the remaining refusals have to leave exactly as it is.
            positive = h.signer.post(
                client, "/caps", {"caps": {name: wire(name, 1)}}, key=secret
            )
            assert positive.status_code == 200, positive.text
            at_zero_again = caps_of(client)
            assert cap_number(name, at_zero_again["caps"][name]) == D("1")
        else:
            at_zero = h.signer.post(
                client, "/caps", {"caps": {name: wire(name, 0)}}, key=secret
            )
            assert at_zero.status_code == 200, at_zero.text
            assert cap_number(name, at_zero.json()["caps"][name]) == D("0")
            at_zero_again = caps_of(client)
            assert cap_number(name, at_zero_again["caps"][name]) == D("0")

        # One good value beside one refused one: nothing at all is written.
        mixed = h.signer.post(
            client,
            "/caps",
            {"caps": {other: wire(other, "1"), name: superior}},
            key=secret,
        )
        assert mixed.status_code == 422, mixed.text
        assert mixed.json().get("code") == ABOVE_CEILING, mixed.text
        assert caps_of(client) == at_zero_again

        # A name that is not a cap of this engine.
        unknown = h.signer.post(
            client,
            "/caps",
            {"caps": {"CROW_COINBASE_NOT_A_CAP": wire(name, "1")}},
            key=secret,
        )
        body = refusal(unknown)
        assert "CROW_COINBASE_NOT_A_CAP" in body.get("message", ""), body
        assert caps_of(client) == at_zero_again

        # A value that is not a number, and a boolean.
        for bad in ("not-a-number", True):
            refused = h.signer.post(
                client, "/caps", {"caps": {name: bad}}, key=secret
            )
            body = refusal(refused)
            if "message" in body:
                assert name in body["message"], (bad, body)
            assert caps_of(client) == at_zero_again

        if count:
            # A count is a whole number.
            fractional = h.signer.post(
                client, "/caps", {"caps": {name: 2.5}}, key=secret
            )
            refusal(fractional)
            assert caps_of(client) == at_zero_again


def test_caps_survive_restart(tmp_path):
    """A cap set on one run is the cap on the next, over the same data directory."""
    root = tmp_path / "caps-restart"
    first = build_engine(root)
    secret = approve_secret()
    first.engine.auth.set_secret(secret)

    with first.client() as client:
        lowered = first.signer.post(
            client,
            "/caps",
            {"caps": {BOT_MAX_ORDER: "10", ORDERS_HOUR: 5, AI_CAPITAL: "4"}},
            key=secret,
        )
        assert lowered.status_code == 200, lowered.text
        assert cap_number(
            BOT_MAX_ORDER, caps_of(client)["caps"][BOT_MAX_ORDER]
        ) == D("10")
    close(first)

    second = build_engine(root)
    with second.client() as client:
        caps = caps_of(client)["caps"]
        assert cap_number(BOT_MAX_ORDER, caps[BOT_MAX_ORDER]) == D("10")
        assert cap_number(ORDERS_HOUR, caps[ORDERS_HOUR]) == D("5")
        assert cap_number(AI_CAPITAL, caps[AI_CAPITAL]) == D("4")
        # The caps that were left alone are still their ceilings.
        assert cap_number(DAILY, caps[DAILY]) == D("200")
    close(second)


def test_lowering_ceiling_clamps_caps(tmp_path):
    """A lowered ceiling clamps the stored caps down; raising it never raises them."""
    root = tmp_path / "caps-clamp"
    first = build_engine(root)
    secret = approve_secret()
    first.engine.auth.set_secret(secret)

    with first.client() as client:
        # Below the ceiling the next start will have, so it has to be kept.
        lowered = first.signer.post(
            client, "/caps", {"caps": {BOT_MAX_ORDER: "10"}}, key=secret
        )
        assert lowered.status_code == 200, lowered.text
        assert cap_number(
            BOT_MAX_ORDER, caps_of(client)["caps"][BOT_MAX_ORDER]
        ) == D("10")
    close(first)

    second = build_engine(
        root,
        env={
            DAILY: "50",
            DRAWDOWN: "5",
            ORDERS_HOUR: "4",
            AI_CAPITAL: "10",
            BOT_MAX_ORDER: "20",
        },
    )
    with second.client() as client:
        caps = caps_of(client)["caps"]
        assert cap_number(DAILY, caps[DAILY]) == D("50")
        assert cap_number(DRAWDOWN, caps[DRAWDOWN]) == D("5")
        assert cap_number(ORDERS_HOUR, caps[ORDERS_HOUR]) == D("4")
        assert cap_number(AI_CAPITAL, caps[AI_CAPITAL]) == D("10")
        # Already below the new ceiling, so it is kept rather than moved.
        assert cap_number(BOT_MAX_ORDER, caps[BOT_MAX_ORDER]) == D("10")

    # The clamp is persisted, and as one object of strings under the one key.
    stored = second.store.get(RUNTIME_CAPS_KEY)
    assert isinstance(stored, dict), stored
    assert set(stored) == set(CAP_ENV_NAMES)
    for text in stored.values():
        assert isinstance(text, str), stored
    assert cap_number(DAILY, stored[DAILY]) == D("50")
    assert cap_number(DRAWDOWN, stored[DRAWDOWN]) == D("5")
    assert cap_number(ORDERS_HOUR, stored[ORDERS_HOUR]) == D("4")
    assert cap_number(AI_CAPITAL, stored[AI_CAPITAL]) == D("10")
    assert cap_number(BOT_MAX_ORDER, stored[BOT_MAX_ORDER]) == D("10")
    close(second)

    # The ceilings go back up; the caps stay where they were clamped.
    third = build_engine(root)
    with third.client() as client:
        caps = caps_of(client)["caps"]
        assert cap_number(DAILY, caps[DAILY]) == D("50")
        assert cap_number(AI_CAPITAL, caps[AI_CAPITAL]) == D("10")
        assert cap_number(BOT_MAX_ORDER, caps[BOT_MAX_ORDER]) == D("10")
    close(third)


# ---------------------------------------------------------------- every check


def test_every_cap_check_reads_runtime_caps(tmp_path):
    """Lowering a cap at runtime changes the refusal its own check answers with."""
    # --- the bot's single-order cap --------------------------------------
    h = build_engine(tmp_path / "runtime-bot-order")
    add_bot(h, BOT, quote="100", base="50")
    prime(h)
    assert h.limits.ceilings.bot_max_order_usd == D("50")
    # 40 * 0.99 = 39.6 of notional, inside the 50 the ceiling allows.
    assert h.gateway.check("bot", BOT, buy(size="40")) is None
    h.limits.set_caps({BOT_MAX_ORDER: "30"})
    assert h.limits.ceilings.bot_max_order_usd == D("50")  # the env ceiling stands
    assert h.limits.bot_max_order_usd == D("30")
    assert h.gateway.check("bot", BOT, buy(size="40")) == ORDER_TOO_LARGE
    close(h)

    # --- the AI's single-order cap ---------------------------------------
    h = build_engine(tmp_path / "runtime-ai-order")
    h.store.put("ai_live_enabled", True)
    add_bot(h, BOT, quote="100", base="50")
    prime(h)
    # 20 * 0.99 = 19.8 of notional, and 19.899 of the AI's 25 USDC.
    assert h.gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0] is None
    h.limits.set_caps({AI_MAX_ORDER: "15"})
    assert (
        h.gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0]
        == ORDER_TOO_LARGE
    )
    # The bot's own cap was not touched by the AI's.
    assert h.gateway.check("bot", BOT, buy(size="20")) is None
    close(h)

    # --- the global daily notional ---------------------------------------
    h = build_engine(tmp_path / "runtime-daily")
    add_bot(h, BOT, quote="100", base="0")
    prime(h)
    spend(h, price="80", size="2", book="dry")  # 160 of today's budget
    assert h.gateway.check("bot", BOT, buy(size="40")) is None  # 199.6 of 200
    h.limits.set_caps({DAILY: "100"})
    assert h.gateway.check("bot", BOT, buy(size="40")) == DAILY_CAP
    close(h)

    # --- the AI's daily notional -----------------------------------------
    h = build_engine(tmp_path / "runtime-ai-daily")
    h.store.put("ai_live_enabled", True)
    add_bot(h, BOT, quote="100", base="50")
    prime(h)
    spend(h, price="20", size="1", book="live", source="ai", owner="ai")  # 20 spent
    # 39.8 of 50, on the approval-free chain.
    assert h.gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0] is None
    h.limits.set_caps({AI_DAILY: "30"})
    assert (
        h.gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0] == DAILY_CAP
    )
    # The bot's day is its own book's, and the AI's spend is not in it.
    assert h.gateway.check("bot", BOT, buy(size="20")) is None
    close(h)

    # --- the global orders per hour --------------------------------------
    h = build_engine(tmp_path / "runtime-hour")
    add_bot(h, BOT, quote="100", base="50")
    prime(h)
    for _ in range(5):
        spend(h, price="1", size="1", book="dry")
    assert h.gateway.check("bot", BOT, buy(size="20")) is None
    h.limits.set_caps({ORDERS_HOUR: 5})
    assert h.gateway.check("bot", BOT, buy(size="20")) == RATE_CAP
    close(h)

    # --- the AI's orders per hour ----------------------------------------
    h = build_engine(tmp_path / "runtime-ai-hour")
    h.store.put("ai_live_enabled", True)
    add_bot(h, BOT, quote="100", base="50")
    prime(h)
    for _ in range(3):
        spend(h, price="1", size="1", book="live", source="ai", owner="ai")
    assert h.gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0] is None
    h.limits.set_caps({AI_ORDERS_HOUR: 3})
    assert (
        h.gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0] == RATE_CAP
    )
    # The bot's own hour is the dry book's, and the AI's rows are not in it.
    assert h.gateway.check("bot", BOT, buy(size="20")) is None
    close(h)

    # --- the portfolio drawdown percentage -------------------------------
    h = build_engine(tmp_path / "runtime-drawdown")
    add_bot(h, BOT, quote="100", base="50")
    prime(h)
    equity = D("100") + D("50") * MID
    assert equity == D("149.75")
    h.store.update_hwm(PORTFOLIO_OWNER, D("170"), "dry")
    # 20% of 170 is a floor of 136, below the equity.
    assert h.gateway.check("bot", BOT, buy(size="20")) is None
    h.limits.set_caps({DRAWDOWN: "10"})
    # 10% of 170 is a floor of 153, above it.
    assert h.gateway.check("bot", BOT, buy(size="20")) == DRAWDOWN_STOP

    # The runner's own halt reads the same runtime percentage.
    assert h.gateway.is_halted("dry") is False
    h.limits.set_caps({DRAWDOWN: "20"})
    h.runner._check_portfolio_drawdown("dry")
    assert h.gateway.is_halted("dry") is False
    h.limits.set_caps({DRAWDOWN: "10"})
    h.runner._check_portfolio_drawdown("dry")
    assert h.gateway.is_halted("dry") is True
    alerts = [
        str(row["message"])
        for row in h.store.conn().execute(
            "SELECT message FROM events WHERE level='ALERT'"
        )
    ]
    assert any("10% of high-water mark" in message for message in alerts), alerts
    close(h)

    # --- the capital a bot may be given ----------------------------------
    h = build_engine(tmp_path / "runtime-capital")
    prime(h)
    secret = approve_secret()
    h.engine.auth.set_secret(secret)
    with h.client() as client:
        created = client.post("/bots", json=bot_body("cap1", quote="40"))
        assert created.status_code == 201, created.text

        h.limits.set_caps({MAX_BOT_CAPITAL: "30"})

        over = client.post("/bots", json=bot_body("cap2", quote="40"))
        assert over.status_code == 422, over.text
        assert "30" in str(over.json().get("detail", "")), over.text
        assert h.store.get_bot("cap2") is None

        # The capital route measures the same cap.
        switched = h.signer.post(
            client,
            "/bots/cap1/mode",
            {
                "mode": "live",
                "capital_quote": "40",
                "capital_base": "0",
                "acknowledge_live": True,
            },
            key=secret,
        )
        assert switched.status_code == 422, switched.text
        assert "30" in str(switched.json().get("detail", "")), switched.text
        assert h.store.get_bot("cap1")["mode"] == "dry"
    close(h)

    # --- the AI's capital -------------------------------------------------
    h = build_engine(tmp_path / "runtime-ai-capital")
    h.store.put("ai_live_enabled", True)
    prime(h)
    assert h.gateway.ledger.holding("ai", PRODUCT, book="live").quote == D("25")
    assert h.gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0] is None
    h.limits.set_caps({AI_CAPITAL: "10"})
    assert h.gateway.ledger.holding("ai", PRODUCT, book="live").quote == D("10")
    assert (
        h.gateway.evaluate("ai", "ai", buy(size="20"), PRODUCT)[0]
        == INSUFFICIENT_HOLDING
    )
    close(h)

    # --- the sources ------------------------------------------------------
    # A cap's env name belongs to `limits.py` alone, so no other module can read
    # a cap from the environment (or a docstring name one) instead of the runtime
    # object every check is handed.
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "limits.py":
            continue
        text = path.read_text(encoding="utf-8")
        for env_name in CAP_ENV_NAMES:
            assert env_name not in text, f"{path.name} names the cap {env_name}"
        for constant in CAP_ENV_CONSTANTS:
            assert constant not in text, f"{path.name} reads {constant}"

    # A plain `Limits` may be built where non-cap values are wanted: never in a
    # module that checks a cap.
    allowed = {"limits.py", "__main__.py", "runner.py", "watchdog.py"}
    for path in sorted(SRC.rglob("*.py")):
        if "Limits.from_env(" in path.read_text(encoding="utf-8"):
            assert path.name in allowed, f"{path.name} builds its own Limits"


# ---------------------------------------------------------------- the lockout


def lockout_events(store: Store) -> list[dict]:
    """Every event carrying the lockout's own sentence, oldest first."""
    rows = store.conn().execute(
        "SELECT level, kind, owner, message, data_json FROM events "
        "WHERE message=? ORDER BY id",
        (LOCKOUT_MESSAGE,),
    ).fetchall()
    return [dict(row) for row in rows]


def all_events(store: Store) -> list[dict]:
    rows = store.conn().execute(
        "SELECT level, kind, owner, message, data_json FROM events ORDER BY id"
    ).fetchall()
    return [dict(row) for row in rows]


def test_mismatch_lockout_writes_warning_event(tmp_path):
    """The fifth wrong secret locks the route and records it once."""
    clock = [NOW]
    h = build_engine(tmp_path / "lockout", clock=clock)
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    pinned = approve_secret()
    other = approve_secret()

    def body(secret: str) -> dict:
        return credentials_body(key_name, pem, secret)

    with h.client() as client:
        connected = h.signer.post(
            client, "/credentials", body(pinned), key=h.install_token
        )
        assert connected.status_code == 200, connected.text
        assert lockout_events(h.store) == []

        for index in range(5):
            refused = h.signer.post(client, "/credentials", body(other), key=other)
            assert refused.status_code == 403, refused.text
            assert SECRET_MISMATCH in refused.text, refused.text
            events = lockout_events(h.store)
            if index < 4:
                # Nothing was locked yet, so nothing is recorded yet.
                assert events == [], (index, events)
        events = lockout_events(h.store)
        assert len(events) == 1, events
        assert events[0]["level"] == "warn"
        assert events[0]["kind"] == "credentials"
        assert events[0]["message"] == LOCKOUT_MESSAGE

        # The route is locked out for a minute, and refusing adds nothing.
        for _ in range(3):
            limited = h.signer.post(client, "/credentials", body(other), key=other)
            assert limited.status_code == 429, limited.text
            assert RATE_LIMITED in limited.text, limited.text
        assert len(lockout_events(h.store)) == 1

        # A second lockout, once the first has passed, is a second event.
        clock[0] += 61
        for _ in range(5):
            again = h.signer.post(client, "/credentials", body(other), key=other)
            assert again.status_code == 403, again.text
        assert len(lockout_events(h.store)) == 2

    # The pin never moved, and no event carries a secret or a key.
    assert h.store.get(auth_module.APPROVE_PIN_KEY) == hashlib.sha256(
        pinned.encode("utf-8")
    ).hexdigest()
    for event in all_events(h.store):
        text = " ".join(str(value) for value in event.values())
        for value in (pinned, other, key_name, marker, h.install_token):
            assert value not in text, event
    close(h)


# ---------------------------------------------------------------- limits.py


def test_runtime_limits_unit(tmp_path):
    """`RuntimeLimits` delegates, reads the stored caps on every access, and heals."""
    runtime_class = limits_module.RuntimeLimits
    refused_class = limits_module.CapRefused

    assert limits_module.DEFAULT_AI_CAPITAL_USD == D("25")
    assert limits_module.ENV_AI_CAPITAL_USD == AI_CAPITAL

    # The nine caps are one ordered table the rest of the engine reads.
    rows = [str(row) for row in limits_module.CAP_SPECS]
    assert len(rows) == 9, rows
    order = []
    for row in rows:
        names = [name for name in CAP_ENV_NAMES if name in row]
        assert len(names) == 1, row
        order.append(names[0])
    assert order == list(CAP_ENV_NAMES)

    # The new ceiling parses like the other money caps.
    assert Limits.from_env({}).ai_capital_usd == D("25")
    assert Limits.from_env({AI_CAPITAL: "60"}).ai_capital_usd == D("60")
    assert Limits.from_env({AI_CAPITAL: "0"}).ai_capital_usd == D("0")
    for bad in ("-1", "abc", "NaN", "Infinity"):
        with pytest.raises(ValueError) as error:
            Limits.from_env({AI_CAPITAL: bad})
        assert AI_CAPITAL in str(error.value)

    h = build_engine(
        tmp_path / "runtime-unit",
        env={"CROW_COINBASE_POLL_SECONDS": "30"},
    )
    runtime = h.limits
    assert isinstance(runtime, runtime_class)
    assert isinstance(runtime.ceilings, Limits)

    # Everything that is not a cap is the ceiling's own answer.
    assert runtime.poll_seconds == 30
    assert runtime.products == (PRODUCT, SECOND)
    assert runtime.is_equity(PRODUCT) is False
    assert runtime.tradable(PRODUCT) is True
    assert runtime.tradable("NVDA-USD") is False
    assert runtime.maker_fee_pct == D("0.5")
    assert runtime.watchdog_policy == "leave"

    caps, ceilings = runtime.caps(), runtime.ceiling_values()
    assert set(caps) == set(ceilings) == set(CAP_ENV_NAMES)
    for name, default in CAP_DEFAULTS.items():
        assert cap_number(name, caps[name]) == D(default), name
        assert cap_number(name, ceilings[name]) == D(default), name
    assert cap_number(BOT_MAX_ORDER, ceilings[BOT_MAX_ORDER]) == D("50")

    # Every access reads what is stored now, so a write through the kv is seen.
    stored = {name: str(default) for name, default in CAP_DEFAULTS.items()}
    stored[BOT_MAX_ORDER] = "7"
    stored[ORDERS_HOUR] = "3"
    h.store.put(RUNTIME_CAPS_KEY, stored)
    assert runtime.bot_max_order_usd == D("7")
    assert runtime.orders_per_hour == 3
    assert runtime.ai_capital_usd == D("25")

    stored[BOT_MAX_ORDER] = "9"
    h.store.put(RUNTIME_CAPS_KEY, stored)
    assert runtime.bot_max_order_usd == D("9")

    # A refusal names the cap it refused, and writes nothing at all.
    with pytest.raises(refused_class) as above:
        runtime.set_caps({BOT_MAX_ORDER: "51"})
    assert above.value.code == ABOVE_CEILING
    assert BOT_MAX_ORDER in above.value.message
    assert runtime.bot_max_order_usd == D("9")

    with pytest.raises(refused_class) as unknown:
        runtime.set_caps({"CROW_COINBASE_NOT_A_CAP": "1"})
    assert unknown.value.code == INVALID
    assert "CROW_COINBASE_NOT_A_CAP" in unknown.value.message

    with pytest.raises(refused_class):
        runtime.set_caps({DAILY: "10", ORDERS_HOUR: 99})
    assert runtime.daily_notional_usd == D("200")
    assert runtime.orders_per_hour == 3

    # The ceiling itself is allowed, and so is zero.
    runtime.set_caps({BOT_MAX_ORDER: "50", ORDERS_HOUR: 30, DAILY: "0"})
    assert runtime.bot_max_order_usd == D("50")
    assert runtime.orders_per_hour == 30
    assert runtime.daily_notional_usd == D("0")
    close(h)

    # A stored object this build cannot read becomes the ceilings, and is
    # written back as one usable object.
    h = build_engine(tmp_path / "runtime-unit")
    h.store.conn().execute(
        "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)",
        (RUNTIME_CAPS_KEY, "not json at all"),
    )
    close(h)

    h = build_engine(tmp_path / "runtime-unit")
    for name, default in CAP_DEFAULTS.items():
        assert cap_number(name, h.limits.caps()[name]) == D(default), name
    healed = h.store.get(RUNTIME_CAPS_KEY)
    assert isinstance(healed, dict), healed
    assert set(healed) == set(CAP_ENV_NAMES)
    close(h)

    # One unusable entry becomes its ceiling; the usable ones beside it are kept.
    h = build_engine(tmp_path / "runtime-unit")
    stored = {name: str(default) for name, default in CAP_DEFAULTS.items()}
    stored[BOT_MAX_ORDER] = "10"
    stored[DAILY] = "abc"
    stored[ORDERS_HOUR] = "2.5"
    h.store.put(RUNTIME_CAPS_KEY, stored)
    close(h)

    h = build_engine(tmp_path / "runtime-unit")
    caps = h.limits.caps()
    assert cap_number(BOT_MAX_ORDER, caps[BOT_MAX_ORDER]) == D("10")
    assert cap_number(DAILY, caps[DAILY]) == D("200")
    assert cap_number(ORDERS_HOUR, caps[ORDERS_HOUR]) == D("30")
    close(h)


def cap_events(store: Store) -> list[dict]:
    """Every event the cap healing wrote, oldest first."""
    rows = store.conn().execute(
        "SELECT level, kind, owner, message FROM events WHERE kind='caps' ORDER BY id"
    ).fetchall()
    return [dict(row) for row in rows]


def test_cap_heal_writes_warning(tmp_path):
    """A healed stored cap is reported once, naming the cap and never a value.

    A first start has nothing stored to repair and a clean restart repairs
    nothing, so neither writes an event; neither does an entry missing from an
    otherwise stored object, which is simply a cap that has never been set.  The
    two cases an owner has to hear about are a stored value the cap cannot hold
    and one above a ceiling lowered between two runs: each is healed AND
    recorded, as ONE `caps` warning naming every healed variable and no amount.
    """
    # A first start: every cap is written, nothing is out of range.
    root = tmp_path / "cap-heal"
    first = build_engine(root)
    assert first.limits.caps()
    assert cap_events(first.store) == []
    close(first)

    # A clean restart writes nothing either.
    second = build_engine(root)
    assert cap_events(second.store) == []
    close(second)

    # One unusable stored value: healed to its ceiling, and reported once.
    third = build_engine(root)
    stored = {name: str(value) for name, value in third.limits.caps().items()}
    stored[DAILY] = "abc"
    third.store.put(RUNTIME_CAPS_KEY, stored)
    close(third)

    fourth = build_engine(root)
    events = cap_events(fourth.store)
    assert len(events) == 1, events
    assert events[0]["level"] == "warn", events
    assert events[0]["kind"] == "caps", events
    message = str(events[0]["message"])
    assert DAILY in message, message
    assert "abc" not in message, message
    assert cap_number(DAILY, fourth.limits.caps()[DAILY]) == D("200")
    close(fourth)

    # A stored cap above a ceiling lowered between two runs: one event, naming
    # the cap and carrying no amount of it.
    clamped_root = tmp_path / "cap-heal-clamp"
    first = build_engine(clamped_root)
    first.limits.set_caps({BOT_MAX_ORDER: "40"})
    close(first)

    second = build_engine(clamped_root, env={BOT_MAX_ORDER: "20"})
    events = cap_events(second.store)
    assert len(events) == 1, events
    message = str(events[0]["message"])
    assert BOT_MAX_ORDER in message, message
    assert "40" not in message and "20" not in message, message
    assert cap_number(BOT_MAX_ORDER, second.limits.caps()[BOT_MAX_ORDER]) == D("20")
    close(second)

    # Two caps healed at once are still ONE event, naming both.
    both_root = tmp_path / "cap-heal-both"
    first = build_engine(both_root)
    stored = {name: str(value) for name, value in first.limits.caps().items()}
    stored[DAILY] = "not-a-number"
    stored[ORDERS_HOUR] = "2.5"
    first.store.put(RUNTIME_CAPS_KEY, stored)
    close(first)

    second = build_engine(both_root)
    events = cap_events(second.store)
    assert len(events) == 1, events
    message = str(events[0]["message"])
    assert DAILY in message and ORDERS_HOUR in message, message
    close(second)

    # An entry missing from an otherwise stored object heals in silence.
    missing_root = tmp_path / "cap-heal-missing"
    first = build_engine(missing_root)
    stored = {name: str(value) for name, value in first.limits.caps().items()}
    stored.pop(DAILY)
    first.store.put(RUNTIME_CAPS_KEY, stored)
    close(first)

    second = build_engine(missing_root)
    assert cap_events(second.store) == []
    assert cap_number(DAILY, second.limits.caps()[DAILY]) == D("200")
    close(second)


# ---------------------------------------------------------------- the AI's pool, lowered


def test_lowering_ai_capital_below_spent_keeps_unallocated_true(tmp_path):
    """A capital lowered below what the AI already spent takes no phantom credit.

    The AI's USDC order effects are negative once it has spent, so adding them to a
    capital that was lowered underneath them used to leave a NEGATIVE AI pool in
    `unallocated` — free money for every other owner.  The live pool is the one
    the ledger reserves (capital plus the AI's order effects), clamped at zero for
    the capital-bearing currency, and it is subtracted once: a bot's dry-to-live
    switch can no longer take the $20 the lowered capital invented.  A pool that
    is still positive (capital 25 and 40 here) is exactly what it always was.
    """
    h = build_engine(
        tmp_path / "ai-lower",
        env={AI_CAPITAL: "40"},
        live_totals=(("USDC", "1000"), ("XRP", "200"), ("BTC", "5")),
    )
    ledger = h.gateway.ledger

    # Another owner's money on the live book: one bot whose live budget is 980.
    add_bot(h, BOT, quote="0", base="0")
    h.store.set_bot_book(
        BOT,
        mode="live",
        capital_quote=D("0"),
        capital_base=D("0"),
        live_capital_quote=D("980"),
        live_capital_base=D("0"),
    )
    # The AI spent 20 USDC on a settled live buy: its quote effect is -20, and
    # its base side is 20 XRP of the product's own.
    fill(
        h,
        owner="ai",
        product=PRODUCT,
        book="live",
        size="20",
        price="1.00",
        fee="0",
    )

    totals = h.gateway.books.totals("live")
    assert totals[QUOTE] == D("1000")

    def live_unallocated() -> dict:
        return ledger.unallocated(totals, book="live")

    # A positive pool keeps its reserve exactly once: 25 of capital with 20 spent
    # leaves 5, so 1000 - 980 - 5 is still free.
    assert h.limits.ai_capital_usd == D("40")
    h.limits.set_caps({AI_CAPITAL: "25"})
    assert live_unallocated()[QUOTE] == D("15")
    assert ledger.holding("ai", PRODUCT, book="live").quote == D("5")

    # And a larger positive pool is still taken once: 40 - 20 = 20 reserved.
    h.limits.set_caps({AI_CAPITAL: "40"})
    assert live_unallocated()[QUOTE] == D("0")
    assert ledger.holding("ai", PRODUCT, book="live").quote == D("20")

    # Below the spend the pool is not negative: the AI's USDC contributes 0, so
    # only what the other owner holds is subtracted.  No phantom $20 appears.
    h.limits.set_caps({AI_CAPITAL: "0"})
    assert live_unallocated()[QUOTE] == D("20")
    # The AI's base side is untouched by any of this.
    assert live_unallocated()[BASE] == D("180")
    assert live_unallocated()[SECOND_BASE] == D("5")

    # A dry-to-live switch asking for the truth plus the phantom $20 is refused:
    # 1000 - 980 - 0 leaves 20, not 40.
    h.store.put("live_enabled", True)
    add_bot(h, "b2", quote="40", base="0")
    before = bot_state(h.store, "b2")
    with pytest.raises(ModeRefused) as short:
        h.runner.switch_mode("b2", "live", "40", "0")
    assert short.value.code == LIVE_CAPITAL_SHORT
    assert short.value.status == 409
    assert bot_state(h.store, "b2") == before
    assert h.store.get_bot("b2")["mode"] == "dry"

    # Capital 10 is still below the spend, so the same $20 is all there is.
    h.limits.set_caps({AI_CAPITAL: "10"})
    assert live_unallocated()[QUOTE] == D("20")
    close(h)


# ---------------------------------------------------------------- raising the AI capital


def test_raising_ai_capital_needs_free_live_money(tmp_path):
    """A raise of the AI's capital is refused when the live book has not got it.

    The raise is measured against the live book's USDC unallocated as it stands
    (which already reserves the AI's current capital): the extra is what the
    account has to be able to fund.  A lowering and a body that keeps the value
    are never checked, a mixed body with a refused raise writes nothing, and a
    live book that cannot be read accepts the raise because nothing says it is
    short.  Only the error code, the cap's name and no amount are reported.
    """
    h = build_engine(
        tmp_path / "ai-raise",
        env={AI_CAPITAL: "500"},
        live_totals=(("USDC", "50"),),
    )
    secret = approve_secret()
    h.engine.auth.set_secret(secret)

    def set_ai_capital(client, value):
        return h.signer.post(
            client, "/caps", {"caps": {AI_CAPITAL: value}}, key=secret
        )

    with h.client() as client:
        assert cap_number(AI_CAPITAL, caps_of(client)["caps"][AI_CAPITAL]) == D(
            "500"
        )

        # Lowering never checks, and leaves 25 USDC free for the AI.
        lowered = set_ai_capital(client, "25")
        assert lowered.status_code == 200, lowered.text
        assert cap_number(AI_CAPITAL, lowered.json()["caps"][AI_CAPITAL]) == D(
            "25"
        )

        # +10 fits in the free 25.
        raised = set_ai_capital(client, "35")
        assert raised.status_code == 200, raised.text
        assert cap_number(AI_CAPITAL, raised.json()["caps"][AI_CAPITAL]) == D(
            "35"
        )

        # +100 does not: refused, with nothing written.
        refused = set_ai_capital(client, "135")
        assert refused.status_code == 422, refused.text
        body = refused.json()
        assert body.get("code") == AI_CAPITAL_SHORT, body
        assert AI_CAPITAL in body.get("message", ""), body
        assert cap_number(AI_CAPITAL, caps_of(client)["caps"][AI_CAPITAL]) == D(
            "35"
        )

        # One good cap beside the refused raise: the whole body writes nothing.
        before = caps_of(client)
        mixed = h.signer.post(
            client,
            "/caps",
            {"caps": {AI_CAPITAL: "135", DAILY: "100"}},
            key=secret,
        )
        assert mixed.status_code == 422, mixed.text
        assert mixed.json().get("code") == AI_CAPITAL_SHORT, mixed.text
        assert caps_of(client) == before

        # Lowering, and keeping the value, never check anything.
        assert set_ai_capital(client, "5").status_code == 200
        assert set_ai_capital(client, "5").status_code == 200
    close(h)

    # Totals short of the cap itself: lowering and keeping still write.
    short = build_engine(
        tmp_path / "ai-raise-short",
        env={AI_CAPITAL: "500"},
        live_totals=(("USDC", "20"),),
    )
    short_secret = approve_secret()
    short.engine.auth.set_secret(short_secret)
    with short.client() as client:
        lowered = short.signer.post(
            client, "/caps", {"caps": {AI_CAPITAL: "100"}}, key=short_secret
        )
        assert lowered.status_code == 200, lowered.text
        kept = short.signer.post(
            client, "/caps", {"caps": {AI_CAPITAL: "100"}}, key=short_secret
        )
        assert kept.status_code == 200, kept.text
    close(short)

    # A live book that cannot be read accepts the raise: nothing says it is short.
    locked = build_engine(
        tmp_path / "ai-raise-locked",
        env={AI_CAPITAL: "500"},
        live=False,
    )
    locked_secret = approve_secret()
    locked.engine.auth.set_secret(locked_secret)
    with locked.client() as client:
        assert locked.gateway.books.live_available() is False
        lowered = locked.signer.post(
            client, "/caps", {"caps": {AI_CAPITAL: "100"}}, key=locked_secret
        )
        assert lowered.status_code == 200, lowered.text
        raised = locked.signer.post(
            client, "/caps", {"caps": {AI_CAPITAL: "150"}}, key=locked_secret
        )
        assert raised.status_code == 200, raised.text
        assert cap_number(AI_CAPITAL, raised.json()["caps"][AI_CAPITAL]) == D(
            "150"
        )
    close(locked)


# ---------------------------------------------------------------- the drawdown cap


def test_drawdown_cap_must_be_positive(tmp_path):
    """The drawdown percentage is the one cap that may not be set to zero.

    A 0 stop halts a book on any dip below its high-water mark, so the cap is
    refused as an unusable value by `POST /caps` (and nothing in the body is
    written), the other eight caps still take zero, and a stored 0 is healed to
    the ceiling on the next start.
    """
    h = build_engine(tmp_path / "drawdown-positive")
    secret = approve_secret()
    h.engine.auth.set_secret(secret)

    with h.client() as client:
        before = caps_of(client)

        refused = h.signer.post(
            client, "/caps", {"caps": {DRAWDOWN: "0"}}, key=secret
        )
        assert refused.status_code == 422, refused.text
        body = refused.json()
        assert body.get("code") == INVALID, body
        assert DRAWDOWN in body.get("message", ""), body
        assert caps_of(client) == before

        # The other eight caps keep accepting zero.
        for name in CAP_ENV_NAMES:
            if name == DRAWDOWN:
                continue
            zero = h.signer.post(
                client, "/caps", {"caps": {name: wire(name, 0)}}, key=secret
            )
            assert zero.status_code == 200, (name, zero.text)
            assert cap_number(name, zero.json()["caps"][name]) == D("0"), name

        # One good cap beside the refused zero: nothing at all is written.
        at_zero = caps_of(client)
        mixed = h.signer.post(
            client,
            "/caps",
            {"caps": {DAILY: "10", DRAWDOWN: "0"}},
            key=secret,
        )
        assert mixed.status_code == 422, mixed.text
        assert mixed.json().get("code") == INVALID, mixed.text
        assert caps_of(client) == at_zero
    close(h)

    # A stored zero heals to the ceiling at startup, and is written back healed.
    root = tmp_path / "drawdown-heal"
    first = build_engine(root)
    stored = {name: str(value) for name, value in first.limits.caps().items()}
    stored[DRAWDOWN] = "0"
    first.store.put(RUNTIME_CAPS_KEY, stored)
    close(first)

    second = build_engine(root)
    with second.client() as client:
        healed = caps_of(client)["caps"]
        assert cap_number(DRAWDOWN, healed[DRAWDOWN]) == D("20")
    persisted = second.store.get(RUNTIME_CAPS_KEY)
    assert isinstance(persisted, dict), persisted
    assert cap_number(DRAWDOWN, persisted[DRAWDOWN]) == D("20")
    close(second)


def test_lowering_drawdown_cap_halts_only_that_book(tmp_path):
    """A lowered drawdown cap halts the book it is below, and leaves the other alone.

    Two books are in play: the dry one is 149.75 against a 170 mark (about 12%
    down) and the live one is 100 against a 100 mark (flat).  At 20% neither is
    stopped; lowered to 5% only the dry book is below its floor, so the next
    portfolio check raises that book's halt and the live book is untouched.
    """
    h = build_engine(tmp_path / "drawdown-books", live_totals=(("USDC", "100"),))
    add_bot(h, BOT, quote="100", base="50")
    add_bot(h, "l1", quote="0", base="0")
    h.store.set_bot_book(
        "l1",
        mode="live",
        capital_quote=D("0"),
        capital_base=D("0"),
        live_capital_quote=D("100"),
        live_capital_base=D("0"),
    )
    prime(h)

    dry_equity = D("100") + D("50") * MID
    assert dry_equity == D("149.75")
    assert h.gateway.portfolio_equity("dry") == dry_equity
    assert h.gateway.portfolio_equity("live") == D("100")
    h.store.update_hwm(PORTFOLIO_OWNER, D("170"), "dry")
    h.store.update_hwm(PORTFOLIO_OWNER, D("100"), "live")

    # 20%: the dry floor is 136, below the equity, so neither book is halted.
    h.limits.set_caps({DRAWDOWN: "20"})
    h.runner._check_drawdowns()
    assert h.gateway.is_halted("dry") is False
    assert h.gateway.is_halted("live") is False

    # 5%: the dry floor is 161.5, above the equity; the live floor is 95, below.
    h.limits.set_caps({DRAWDOWN: "5"})
    h.runner._check_drawdowns()
    assert h.gateway.is_halted("dry") is True
    assert h.gateway.is_halted("live") is False
    assert h.gateway.halt_reason("live") is None
    assert "dry" in (h.gateway.halt_reason("dry") or "")

    alerts = [
        str(row["message"])
        for row in h.store.conn().execute(
            "SELECT message FROM events WHERE level='ALERT'"
        )
    ]
    assert len(alerts) == 1, alerts
    assert "dry" in alerts[0], alerts
    close(h)


# ---------------------------------------------------------------- lockout extension


def test_lockout_extends_on_guesses_and_still_admits_owner(tmp_path):
    """Wrong secrets keep the route shut, but only real guesses move the end.

    Five wrong secrets trip the lockout and write ONE event.  A wrong secret every
    30 s then extends the lockout by another minute each time, so it is still shut
    at 3 minutes.  A guess that never passes the cheap pre-check — a stale stamp,
    an already-spent nonce, a request with no signature headers — does not extend
    it, and neither does the pinned secret with a MAC keyed by something else.
    Past the unextended end the route is open again, a second real trip writes a
    second event, and while that lockout stands the owner's own push (the pinned
    secret, signed with it) is served and clears it.  The next wrong secret is a
    fresh 403, not the lockout's 429.  `MismatchLimiter.extend` itself is the
    no-op-or-move-the-end half of the limiter and never adds a count.
    """
    clock = [NOW]
    h = build_engine(tmp_path / "lockout-extends", clock=clock)
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    pinned = approve_secret()
    other = approve_secret()
    digest = hashlib.sha256(pinned.encode("utf-8")).hexdigest()

    def body_with(secret: str) -> dict:
        return credentials_body(key_name, pem, secret)

    def push(client, secret, *, key=None, nonce=None, ts=None):
        return h.signer.post(
            client,
            "/credentials",
            body_with(secret),
            key=secret if key is None else key,
            nonce=nonce,
            ts=ts,
        )

    with h.client() as client:
        pin_nonce = h.signer.nonce()
        pinned_connect = push(client, pinned, key=h.install_token, nonce=pin_nonce)
        assert pinned_connect.status_code == 200, pinned_connect.text
        assert h.store.get(auth_module.APPROVE_PIN_KEY) == digest
        assert lockout_events(h.store) == []

        # Five wrong secrets trip the lockout, recorded once.
        for _ in range(5):
            failure = push(client, other)
            assert failure.status_code == 403, failure.text
            assert SECRET_MISMATCH in failure.text, failure.text
        assert len(lockout_events(h.store)) == 1

        # A guess every 30 s, each with fresh headers and a fresh nonce, passes
        # the pre-check and extends the lockout by its own minute.
        for _ in range(6):
            clock[0] += 30
            extended = push(client, other)
            assert extended.status_code == 429, extended.text
            assert RATE_LIMITED in extended.text, extended.text
        assert len(lockout_events(h.store)) == 1

        # The last extending guess was at NOW+180, so an unextended lockout ends
        # at NOW+240.  At NOW+200 (still inside it) a stale stamp, a replayed
        # nonce, a request missing one of the three headers and the pinned
        # secret with a MAC keyed by something else are all 429 and none of them
        # moves the end: any that did would keep the route shut past NOW+240.
        clock[0] = NOW + 200
        assert push(client, other, ts=int(clock[0]) - 10_000).status_code == 429
        assert push(client, other, nonce=pin_nonce).status_code == 429
        raw = json.dumps(body_with(other)).encode("utf-8")
        headerless = h.signer.headers(other, "POST", "/credentials", raw)
        headerless.pop("X-Crow-Timestamp")
        missing = client.post("/credentials", content=raw, headers=headerless)
        assert missing.status_code == 429, missing.text
        bad_mac = "other-" + secrets.token_hex(20)
        assert push(client, pinned, key=bad_mac).status_code == 429

        # Past the unextended end (NOW+240) the route is open again: a wrong
        # secret is the new run's first 403, not the lockout's 429.
        clock[0] = NOW + 241
        first_of_run = push(client, other)
        assert first_of_run.status_code == 403, first_of_run.text
        assert SECRET_MISMATCH in first_of_run.text, first_of_run.text
        assert len(lockout_events(h.store)) == 1

        # Four more (the fifth of the run) trip a second lockout: one more event.
        for _ in range(4):
            again = push(client, other)
            assert again.status_code == 403, again.text
        assert len(lockout_events(h.store)) == 2

        # While that lockout stands, the owner's own push is served and clears it.
        served = push(client, pinned)
        assert served.status_code == 200, served.text
        assert len(lockout_events(h.store)) == 2

        # The next wrong secret starts a fresh count: 403, not 429.
        after = push(client, other)
        assert after.status_code == 403, after.text
        assert SECRET_MISMATCH in after.text, after.text
        assert len(lockout_events(h.store)) == 2

    # The pin never moved.  No event carries a secret or a key.
    assert h.store.get(auth_module.APPROVE_PIN_KEY) == digest
    for event in lockout_events(h.store):
        text = " ".join(str(value) for value in event.values())
        for value in (pinned, other, key_name, marker, h.install_token):
            assert value not in text, event
    close(h)

    # `extend` is a no-op when nothing is locked, moves the end to now + lockout
    # when something is, and never adds a count.
    unit_clock = [NOW]
    limiter = auth_module.MismatchLimiter(
        lambda: unit_clock[0], limit=2, window_s=60, lockout_s=60
    )
    limiter.extend()
    assert limiter.locked() is False
    unit_clock[0] += 10
    limiter.extend()
    assert limiter.locked() is False
    assert limiter.record() is False
    assert limiter.record() is True
    assert limiter.locked() is True
    unit_clock[0] = NOW + 20
    limiter.extend()
    unit_clock[0] = NOW + 79
    assert limiter.locked() is True
    unit_clock[0] = NOW + 80
    assert limiter.locked() is False
    # The extend added no count: a single further record does not lock again.
    assert limiter.record() is False