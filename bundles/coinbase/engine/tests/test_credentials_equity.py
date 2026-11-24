"""test_credentials_equity.py: the equity account as the credentials slot sees it.

P2b Task 6 gives the credentials slot an `EquityWiring` and two OPTIONAL body
fields (`equity_key_name`, `equity_private_key`), so the one key the owner pushes
can drive both sides of the router and a SECOND key can be pushed for the equity
account.  Everything here is fake past the wiring: a real `Store`, the real
`CredentialSlot`, and a fake `build_live` that answers one fake adapter per key
NAME with its own `key_permissions()` answer.

What each test pins down:

* one key with equities enabled builds the shared adapter (`equity is crypto`) and
  one USD pool, with all four hooks wired (the equity list, the crypto list, the
  store's EQUITY rows, an order id's product); with equities off the router is the
  plain one-adapter router it always was, hooks and all,
* two keys build two adapters — the second one on the equity side — and the USD
  pool is derived from the two ports: false for two portfolios, true for one,
  while a check installs nothing,
* the equity key has to deny the transfer permission in so many words, and every
  other way it can be wrong is the same refusal: nothing kept, no pin written, no
  secret handed to the rail, and a message that carries no key, portfolio or
  exception text,
* a bad FIRST key keeps its own `KEY_*` code and the second adapter is never
  built,
* split pools are refused while the crypto list has a USD-quoted product, and
  allowed when it has only USDC-quoted ones (or when there is one pool),
* the two API bodies carry the two optional fields (still refusing anything else)
  and the check route passes them through to the slot,
* a key push verifies the equity lists through the wiring's status and `clear`
  resets it, a check verifies nothing, and a wiring with no status is unchanged,
* the equity key pair reaches no event, no kv row and no file.

Synthetic values only: the key names, PEM bodies, portfolio ids and error canaries
are built at runtime, and the products are the ones the other engine tests use.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from decimal import Decimal as D
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import crow_coinbase.auth as auth_module
import crow_coinbase.credentials as credentials_module
from crow_coinbase.__main__ import build_app
from crow_coinbase.api import CredentialBody, CredentialCheckBody
from crow_coinbase.auth import APPROVE_PIN_KEY, KEY_KIND_INSTALL_TOKEN
from crow_coinbase.credentials import EPOCH_KEY, PORTFOLIO_KEY, CredentialSlot
from crow_coinbase.limits import Limits
from crow_coinbase.money import ProductSpec
from crow_coinbase.router import ExchangeRouter, usd_one_pool_from_keys
from crow_coinbase.store import EQUITY, OPEN, SPOT, Store

# ---------------------------------------------------------------- test data

NVDA = "NVDA-USD"
VOO = "VOO-USD"
BTC_USD = "BTC-USD"
XRP = "XRP-USDC"

# The portfolio the owner configured for the equity account, and two others the
# fake keys name.  Random hex: no real account, no real id.
EQUITY_PORTFOLIO = uuid.uuid4().hex
PORTFOLIO_A = uuid.uuid4().hex
PORTFOLIO_B = uuid.uuid4().hex

# The engine's clock, so nothing here reads the wall clock.
NOW = 1_700_000_000.0

# The env a slot is wired from: an equity list, a crypto list, and the portfolio
# id the second-key path judges the equity key against.
SLOT_ENV = {
    "CROW_COINBASE_PRODUCTS": f"{BTC_USD},{XRP}",
    "CROW_COINBASE_EQUITY_PRODUCTS": NVDA,
    "CROW_COINBASE_EQUITY_PORTFOLIO_ID": EQUITY_PORTFOLIO,
}
# The same env with no equity list at all: a crypto-only install.
NO_EQUITY_ENV = {"CROW_COINBASE_EQUITY_PRODUCTS": ""}
# The same env with no portfolio id configured.
NO_PORTFOLIO_ENV = {"CROW_COINBASE_EQUITY_PORTFOLIO_ID": ""}

# A bearer token for the API harness, 32+ characters and built at runtime.
TOKEN = "test-token-" + secrets.token_hex(16)

# The env `build_app` is given in the API test: equities on, one USDC-quoted
# crypto product, and the configured equity portfolio.
API_ENV = {
    "CROW_COINBASE_ENGINE_TOKEN": TOKEN,
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": XRP,
    "CROW_COINBASE_EQUITY_PRODUCTS": NVDA,
    "CROW_COINBASE_EQUITY_PORTFOLIO_ID": EQUITY_PORTFOLIO,
}

# A PEM header and footer as PARTS: no private-key header is a literal here, and
# the private key itself is built at runtime.
PEM_BEGIN = "-----BEGIN "
PEM_END = "-----END "
PEM_EC = "EC "
PEM_SUFFIX = "PRIVATE KEY-----"


# ---------------------------------------------------------------- the new names


def wiring_module():
    """The equity wiring module Task 6 adds, or a clear failure while it is absent."""
    try:
        return importlib.import_module("crow_coinbase.equity_wiring")
    except ModuleNotFoundError as error:
        raise AssertionError(
            "crow_coinbase.equity_wiring is missing: the slot has no wiring to be given"
        ) from error


def wiring_from(limits, store, env, status=None):
    """`equity_wiring.wiring_from`, through one place so every test fails alike."""
    wiring = wiring_module()
    if status is None:
        return wiring.wiring_from(limits, store, env)
    return wiring.wiring_from(limits, store, env, status=status)


def equity_key_refused() -> str:
    """The code a refused equity key answers, added by Task 6."""
    code = getattr(credentials_module, "EQUITY_KEY_REFUSED", None)
    assert isinstance(code, str) and code, "EQUITY_KEY_REFUSED is not defined"
    return code


def equity_usd_pools() -> str:
    """The code split USD pools with USD-quoted crypto answer, added by Task 6."""
    code = getattr(credentials_module, "EQUITY_USD_POOLS", None)
    assert isinstance(code, str) and code, "EQUITY_USD_POOLS is not defined"
    return code


# ---------------------------------------------------------------- test secrets


def approve_secret() -> str:
    """An approval secret, long enough to be the pin's key, built at runtime."""
    return "approve-" + secrets.token_hex(20)


def key_name_canary() -> str:
    """A key name in the shape Coinbase answers, built at runtime."""
    return f"organizations/{uuid.uuid4().hex}/apiKeys/{uuid.uuid4().hex}"


def private_key_canary() -> tuple[str, str]:
    """A synthetic PEM EC private key, and the body line a scan looks for.

    The header and the footer are built from parts; the marker is a random base64
    line inside the body, so a test can look for the key's bytes without ever
    naming them literally.
    """
    marker = base64.b64encode(secrets.token_bytes(36)).decode("ascii")
    lines = [
        base64.b64encode(secrets.token_bytes(40)).decode("ascii"),
        marker,
        base64.b64encode(secrets.token_bytes(40)).decode("ascii"),
    ]
    header = PEM_BEGIN + PEM_EC + PEM_SUFFIX
    footer = PEM_END + PEM_EC + PEM_SUFFIX
    return "\n".join([header, *lines, footer]), marker


def permissions(
    portfolio: str | None = PORTFOLIO_A,
    *,
    can_view: Any = True,
    can_trade: Any = True,
    can_transfer: Any = False,
    portfolio_type: Any = "CONSUMER",
) -> dict:
    """One `key_permissions()` answer, scoped to *portfolio* unless it is None."""
    return {
        "can_view": can_view,
        "can_trade": can_trade,
        "can_transfer": can_transfer,
        "portfolio_uuid": portfolio,
        "portfolio_type": portfolio_type,
    }


MISSING = object()


# ---------------------------------------------------------------- the outside world


class FakeLive:
    """One live adapter: one permissions answer, and every other call a failure.

    `dry_run` is False, so it is a live account rather than a simulator.  `error`
    is raised instead of answering permissions, which is how a failing permission
    read is exercised.
    """

    dry_run = False

    def __init__(self, perms=None, error: BaseException | None = None) -> None:
        self.perms = permissions() if perms is None else dict(perms)
        self.error = error
        self.permission_calls = 0

    def key_permissions(self) -> dict:
        self.permission_calls += 1
        if self.error is not None:
            raise self.error
        return dict(self.perms)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        raise AssertionError(f"unexpected exchange call: {name}")


class KeyedLiveBuilder:
    """`build_live(creds)` answering one fake adapter per key NAME.

    Every call is counted and its creds kept, so a test can see that a second key
    was (or was not) built at all; the adapter's permissions answer is the one
    keyed by the name the creds carry.
    """

    def __init__(self, perms=None, errors=None) -> None:
        self.calls = 0
        self.creds: list[dict] = []
        self.fakes: dict[str, FakeLive] = {}
        self.perms = dict(perms or {})
        self.errors = dict(errors or {})

    def __call__(self, creds) -> FakeLive:
        self.calls += 1
        self.creds.append(dict(creds))
        name = creds["api_key"]
        fake = FakeLive(
            perms=self.perms.get(name, permissions()),
            error=self.errors.get(name),
        )
        self.fakes[name] = fake
        return fake


class FakeAuth:
    """The approval rail, reduced to the two calls the slot makes on it."""

    def __init__(self) -> None:
        self.secrets: list[str] = []

    def set_secret(self, secret: str) -> None:
        self.secrets.append(secret)

    def clear_secret(self) -> None:
        self.secrets.clear()


class FakeMarket:
    """A public market with a fixed touch: no client, no request, no candles."""

    def __init__(self, bid=D("0.99"), ask=D("1.00")):
        self.bid, self.ask = D(bid), D(ask)

    def best_bid_ask(self):
        return self.bid, self.ask

    def range_since(self, since):
        return self.bid, self.ask

    def candles(self, start, end):
        return []


_MARKETS: dict[str, FakeMarket] = {}


def market_for(product: str) -> FakeMarket:
    """One `FakeMarket` per product, so the engine has a price without a socket."""
    return _MARKETS.setdefault(product, FakeMarket())


def spec_for(product: str) -> ProductSpec:
    """The kind each product is: an equity for NVDA, a SPOT pair for anything else."""
    if product == NVDA:
        return ProductSpec(
            product,
            price_increment=D("0.01"),
            base_increment=D("0.0001"),
            quote_increment=D("0.01"),
            base_min_size=D("0.0001"),
            quote_min_size=D("1"),
            product_type=EQUITY,
        )
    return ProductSpec(
        product,
        price_increment=D("0.0001"),
        base_increment=D("0.1"),
        quote_increment=D("0.01"),
        base_min_size=D("1"),
        quote_min_size=D("1"),
        product_type=SPOT,
    )


class Signer:
    """Builds the three approval headers for one request, and sends it."""

    def __init__(self, clock) -> None:
        self.clock = clock

    def nonce(self) -> str:
        return "n" + secrets.token_hex(12)

    def headers(self, key, method: str, path_with_query: str, body: bytes = b"") -> dict:
        stamp = str(int(self.clock[0]))
        used = self.nonce()
        signature = auth_module.compute_mac(
            key, method, path_with_query, stamp, used, body
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

    def post(self, client, path_with_query: str, payload=None, *, key):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = self.headers(key, "POST", path_with_query, body)
        return client.post(path_with_query, content=body, headers=headers)


# ---------------------------------------------------------------- the slot harness


@dataclass
class SlotHarness:
    """A real store, the real slot with the real wiring, and a fake live side."""

    store: Store
    slot: CredentialSlot
    builder: KeyedLiveBuilder
    auth: FakeAuth
    wiring: Any
    limits: Limits
    data_dir: Path
    env: dict


def build_slot(root, *, env=None, perms=None, errors=None, status=None) -> SlotHarness:
    """One engine's credentials slot over a real `Store` on *root*.

    `env` is layered over `SLOT_ENV`, so a test names only the value it is about
    (a blank one means the default).  The wiring is the real one, built from the
    same parsed limits, the same store and the same env the engine would use, and
    *status* is the equity status it carries when a test is about the hooks the
    slot makes on it (the default is no status at all).
    """
    root = Path(root)
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    merged = dict(SLOT_ENV)
    merged.update(env or {})
    limits = Limits.from_env(merged)
    store = Store(data_dir / "engine.db")
    wiring = wiring_from(limits, store, merged, status=status)
    builder = KeyedLiveBuilder(perms=perms, errors=errors)
    auth = FakeAuth()
    slot = CredentialSlot(store, auth, builder, now=lambda: NOW, equity=wiring)
    return SlotHarness(
        store=store,
        slot=slot,
        builder=builder,
        auth=auth,
        wiring=wiring,
        limits=limits,
        data_dir=data_dir,
        env=merged,
    )


@dataclass
class ApiHarness:
    """The real app over a temp dir, with a fake live side per key name."""

    engine: Any
    builder: KeyedLiveBuilder
    signer: Signer
    data_dir: Path
    install_token: str

    @contextlib.contextmanager
    def client(self):
        with TestClient(self.engine.app, raise_server_exceptions=False) as client:
            client.headers.update({"Authorization": f"Bearer {TOKEN}"})
            yield client


def build_engine(root, *, builder: KeyedLiveBuilder, env=None) -> ApiHarness:
    """`build_app` with equities on, a fake live side, and an install token file.

    The install token lives beside the data directory rather than in it, and the
    market and product specs are injected, so nothing here opens a socket.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = root / "install_token"
    install_token = "install-" + secrets.token_hex(20)
    token_path.write_text(install_token + "\n", encoding="utf-8")
    merged = dict(API_ENV)
    merged.update(env or {})
    merged["CROW_COINBASE_INSTALL_TOKEN_FILE"] = str(token_path)
    clock = [NOW]
    engine = build_app(
        merged,
        data_dir=data_dir,
        market_for=market_for,
        spec_for=spec_for,
        now=lambda: clock[0],
        live_builder=builder,
    )
    return ApiHarness(
        engine=engine,
        builder=builder,
        signer=Signer(clock),
        data_dir=data_dir,
        install_token=install_token,
    )


# ---------------------------------------------------------------- helpers


def insert_order_row(
    store: Store,
    cid: str,
    product: str,
    *,
    order_id: str | None = None,
    product_type: str = EQUITY,
) -> None:
    """One order row on the dry book: the store's own record of a product's kind."""
    store.insert_order(
        cid,
        "b1",
        "grid",
        product,
        "BUY",
        -1,
        D("1"),
        D("1"),
        status=OPEN,
        order_id=order_id,
        book="dry",
        product_type=product_type,
    )


def assert_nothing_kept(h: SlotHarness) -> None:
    """A refusal keeps nothing: no router, no pin, no epoch, no rail secret."""
    assert h.slot.live_exchange() is None, "a refusal kept a live route"
    assert h.store.get(APPROVE_PIN_KEY) is None, "a refusal wrote the pin"
    assert h.store.get(PORTFOLIO_KEY) is None, "a refusal pinned a portfolio"
    assert h.store.get(EPOCH_KEY) is None, "a refusal wrote an epoch"
    assert h.auth.secrets == [], "a refusal handed the secret to the rail"


def refused_set(
    h: SlotHarness,
    first_key: str,
    first_pem: str,
    *,
    equity_key_name=None,
    equity_private_key=None,
    code: str,
    builds: int | None = None,
):
    """`slot.set` answers *code*, keeps nothing, and builds only what it needed."""
    result = h.slot.set(
        first_key,
        first_pem,
        approve_secret(),
        key_kind=KEY_KIND_INSTALL_TOKEN,
        equity_key_name=equity_key_name,
        equity_private_key=equity_private_key,
    )
    assert result.state == "refused", result
    assert result.code == code, result
    assert result.key_last4 == first_key[-4:], result
    assert_nothing_kept(h)
    if builds is not None:
        assert h.builder.calls == builds, h.builder.creds
    return result


# ---------------------------------------------------------------- one key


def test_wiring_one_key(tmp_path):
    """One key, equities enabled: one shared adapter, one pool, every hook wired.

    No equity fields is the DEFAULT path: the same key funds both sides, so the
    router holds ONE adapter object (and therefore one book and one USD pool) and
    the four hooks are the wiring's own — the equity list, the crypto list, the
    store's EQUITY rows and an order id's product.  With equities off the slot
    builds the plain one-adapter router it always did.
    """
    h = build_slot(tmp_path / "one-key")
    assert h.wiring.enabled is True
    assert h.wiring.equity_bases() == ("NVDA",), h.wiring.equity_bases()
    assert h.wiring.portfolio_id == EQUITY_PORTFOLIO

    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    result = h.slot.set(key_name, pem, approve_secret(), key_kind=KEY_KIND_INSTALL_TOKEN)
    assert result.state == "ok", result
    assert result.code is None, result
    assert h.builder.calls == 1, h.builder.creds

    router = h.slot.live_exchange()
    assert isinstance(router, ExchangeRouter), router
    assert router.equity is router.crypto, "one key is one account on both sides"
    assert router.usd_one_pool is True, router.usd_one_pool

    # The equity list and the crypto list, from the env this wiring was built from.
    assert router.is_equity(NVDA) is True
    assert router.is_equity(XRP) is False
    assert router.is_crypto(BTC_USD) is True
    assert router.is_crypto(NVDA) is False
    assert router.equity_bases == ("NVDA",), router.equity_bases

    # The store's own rows: a product's kind, and an order id's product.
    insert_order_row(h.store, "cb-b1-B+1-000000000001", NVDA, order_id="ex-equity-1")
    insert_order_row(h.store, "cb-b1-S+1-000000000002", VOO, order_id="ex-equity-2")
    insert_order_row(
        h.store,
        "cb-b1-B+1-000000000003",
        XRP,
        order_id="ex-spot-1",
        product_type=SPOT,
    )
    assert router.product_of("ex-equity-1") == NVDA
    assert router.product_of("ex-spot-1") == XRP
    assert router.product_of("no-such-order") is None, router.product_of("no-such-order")
    assert router.equity_rows(VOO) is True
    assert router.owns_equity(VOO) is True
    assert router.equity_rows(XRP) is False
    assert router.owns_equity(XRP) is False

    # Equities NOT enabled: the router is the plain one it always was.
    plain = build_slot(tmp_path / "no-equity", env=NO_EQUITY_ENV)
    assert plain.wiring.enabled is False
    plain_key = key_name_canary()
    plain_pem, _plain_marker = private_key_canary()
    plain_result = plain.slot.set(
        plain_key, plain_pem, approve_secret(), key_kind=KEY_KIND_INSTALL_TOKEN
    )
    assert plain_result.state == "ok", plain_result
    assert plain.builder.calls == 1, plain.builder.creds

    plain_router = plain.slot.live_exchange()
    assert isinstance(plain_router, ExchangeRouter), plain_router
    assert plain_router.equity is None
    assert plain_router.usd_one_pool is True
    assert plain_router.equity_bases == ()
    insert_order_row(plain.store, "cb-b1-B+1-000000000001", NVDA, order_id="ex-equity-1")
    assert plain_router.is_equity(NVDA) is False
    assert plain_router.equity_rows(NVDA) is False
    assert plain_router.product_of("ex-equity-1") is None


class RecordingStatus:
    """The equity status, as a fake that records what the slot asks it.

    `verify` takes the two adapters a key push just installed and `reset` takes
    nothing, which is exactly the shape `CredentialSlot` makes its two calls with.
    """

    def __init__(self):
        self.verifications = []
        self.resets = 0

    def verify(self, crypto, equity):
        self.verifications.append((crypto, equity))

    def reset(self):
        self.resets += 1


def test_slot_verifies_the_lists_when_a_key_is_installed(tmp_path):
    """A key push is when the kinds can be read: the slot verifies, and drops it.

    A wiring that carries a status is verified the moment its key is installed —
    the first point at which the authenticated product reads are possible — and a
    verification that goes wrong does not refuse the key (the status keeps that,
    and stock trading turns off instead).  A check installs nothing and so
    verifies nothing, `clear` resets the status with the router it drops, and a
    wiring with no status at all is the slot it has always been.
    """
    first_key = key_name_canary()
    first_pem, _marker = private_key_canary()
    status = RecordingStatus()
    h = build_slot(tmp_path / "verified", status=status)
    assert h.wiring.status is status

    checked = h.slot.check(first_key, first_pem)
    assert checked.state == "ok", checked
    assert h.slot.live_exchange() is None
    assert status.verifications == [], status.verifications

    result = h.slot.set(
        first_key, first_pem, approve_secret(), key_kind=KEY_KIND_INSTALL_TOKEN
    )
    assert result.state == "ok", result
    router = h.slot.live_exchange()
    assert router is not None
    assert status.verifications == [(router.crypto, router.equity)]

    h.slot.clear()
    assert h.slot.live_exchange() is None
    assert status.resets == 1

    # No status on the wiring: the slot installs the key exactly as before, and
    # has nothing to verify or reset.
    plain = build_slot(tmp_path / "no-status")
    assert plain.wiring.status is None
    plain_key = key_name_canary()
    plain_pem, _plain_marker = private_key_canary()
    installed = plain.slot.set(
        plain_key, plain_pem, approve_secret(), key_kind=KEY_KIND_INSTALL_TOKEN
    )
    assert installed.state == "ok", installed
    assert plain.slot.live_exchange() is not None
    plain.slot.clear()
    assert plain.slot.live_exchange() is None


# ---------------------------------------------------------------- two keys


def test_wiring_two_keys_router(tmp_path):
    """Two keys: the second adapter is the equity side, and the pool is derived.

    The equity key is scoped to the configured portfolio and cannot transfer, so
    it is accepted; the two keys name DIFFERENT portfolios, so their USD is two
    pools and the router says so.  The same two keys on ONE portfolio are one
    pool.  A check with the same arguments installs nothing.
    """
    first_key, equity_key = key_name_canary(), key_name_canary()
    first_pem, _first_marker = private_key_canary()
    equity_pem, _equity_marker = private_key_canary()

    h = build_slot(
        tmp_path / "two-keys",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms={
            first_key: permissions(PORTFOLIO_A),
            equity_key: permissions(EQUITY_PORTFOLIO),
        },
    )
    assert h.wiring.usd_crypto_products() == (), h.wiring.usd_crypto_products()

    result = h.slot.set(
        first_key,
        first_pem,
        approve_secret(),
        key_kind=KEY_KIND_INSTALL_TOKEN,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
    )
    assert result.state == "ok", result
    assert result.code is None, result
    assert h.builder.calls == 2, h.builder.creds
    assert [creds["api_key"] for creds in h.builder.creds] == [first_key, equity_key]

    router = h.slot.live_exchange()
    assert isinstance(router, ExchangeRouter), router
    assert router.crypto is h.builder.fakes[first_key]
    assert router.equity is h.builder.fakes[equity_key]
    assert router.equity is not router.crypto
    assert router.usd_one_pool is False

    # The same two keys on ONE portfolio: one pool, seen twice.
    same_first, same_equity = key_name_canary(), key_name_canary()
    same_first_pem, _same_first_marker = private_key_canary()
    same_equity_pem, _same_equity_marker = private_key_canary()
    same = build_slot(
        tmp_path / "one-pool",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms={
            same_first: permissions(EQUITY_PORTFOLIO),
            same_equity: permissions(EQUITY_PORTFOLIO),
        },
    )
    same_result = same.slot.set(
        same_first,
        same_first_pem,
        approve_secret(),
        key_kind=KEY_KIND_INSTALL_TOKEN,
        equity_key_name=same_equity,
        equity_private_key=same_equity_pem,
    )
    assert same_result.state == "ok", same_result
    same_router = same.slot.live_exchange()
    assert same_router is not None
    assert same_router.usd_one_pool is True
    assert same_router.equity is same.builder.fakes[same_equity]
    assert same_router.crypto is same.builder.fakes[same_first]
    assert same_router.equity is not same_router.crypto

    # A check with the same arguments installs nothing at all.
    check_first, check_equity = key_name_canary(), key_name_canary()
    check_first_pem, _m1 = private_key_canary()
    check_equity_pem, _m2 = private_key_canary()
    probe = build_slot(
        tmp_path / "check-only",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms={
            check_first: permissions(PORTFOLIO_A),
            check_equity: permissions(EQUITY_PORTFOLIO),
        },
    )
    checked = probe.slot.check(
        check_first,
        check_first_pem,
        equity_key_name=check_equity,
        equity_private_key=check_equity_pem,
    )
    assert checked.state == "ok", checked
    assert checked.code is None, checked
    assert probe.builder.calls == 2, probe.builder.creds
    assert probe.slot.live_exchange() is None
    assert probe.store.get(APPROVE_PIN_KEY) is None
    assert probe.store.get(PORTFOLIO_KEY) is None
    assert probe.store.get(EPOCH_KEY) is None


# ---------------------------------------------------------------- the equity key's permissions


def test_startup_refuses_transfer_equity_key(tmp_path):
    """The equity key has to deny the transfer permission in so many words.

    `True`, an absent permission and the string "false" are all a key that may
    move money out — a refusal that writes nothing, keeps no router, hands no
    secret to the rail, and says so in plain words carrying no key text, no
    portfolio and no exception text.
    """
    first_key, equity_key = key_name_canary(), key_name_canary()
    first_pem, first_marker = private_key_canary()
    equity_pem, equity_marker = private_key_canary()

    for label, value in (
        ("true", True),
        ("absent", MISSING),
        ("the string false", "false"),
    ):
        second_perms = permissions(EQUITY_PORTFOLIO)
        if value is MISSING:
            second_perms.pop("can_transfer")
        else:
            second_perms["can_transfer"] = value
        h = build_slot(
            tmp_path / f"transfer-{label.replace(' ', '-')}",
            env={"CROW_COINBASE_PRODUCTS": XRP},
            perms={first_key: permissions(PORTFOLIO_A), equity_key: second_perms},
        )
        result = refused_set(
            h,
            first_key,
            first_pem,
            equity_key_name=equity_key,
            equity_private_key=equity_pem,
            code=equity_key_refused(),
            builds=2,
        )
        assert result.state == "refused", label
        for text in (
            first_key,
            equity_key,
            first_marker,
            equity_marker,
            EQUITY_PORTFOLIO,
            PORTFOLIO_A,
        ):
            assert text not in result.message, (label, result.message)

    # An adapter that will not answer at all is the same refusal, in the same
    # fixed words: the error's own text is nowhere in the answer.
    canary = "error-" + secrets.token_hex(8)
    raising = build_slot(
        tmp_path / "transfer-error",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms={first_key: permissions(PORTFOLIO_A)},
        errors={equity_key: RuntimeError(canary)},
    )
    raised = refused_set(
        raising,
        first_key,
        first_pem,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
        code=equity_key_refused(),
        builds=2,
    )
    assert canary not in raised.message, raised.message
    assert canary not in str(raised), raised
    for text in (first_key, equity_key, EQUITY_PORTFOLIO):
        assert text not in raised.message, raised.message


def test_equity_key_refusals(tmp_path):
    """Every other way an equity key is wrong: one code, and nothing kept.

    A portfolio other than the configured one, no configured portfolio at all, a
    key that cannot trade, one that cannot view, only one of the two fields, the
    fields while equities are off, the first key's name used twice and a malformed
    private key are all `EQUITY_KEY_REFUSED`, and none of them writes or keeps
    anything — nor builds a second adapter where the pair was refused first.
    """
    first_key, equity_key = key_name_canary(), key_name_canary()
    first_pem, first_marker = private_key_canary()
    equity_pem, equity_marker = private_key_canary()

    # The equity key names a portfolio other than the configured one.
    wrong_portfolio = build_slot(
        tmp_path / "wrong-portfolio",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms={first_key: permissions(PORTFOLIO_A), equity_key: permissions(PORTFOLIO_B)},
    )
    refuse = refused_set(
        wrong_portfolio,
        first_key,
        first_pem,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
        code=equity_key_refused(),
        builds=2,
    )
    for text in (first_key, equity_key, first_marker, equity_marker, PORTFOLIO_B):
        assert text not in refuse.message, refuse.message

    # No configured portfolio id at all: the equity key has nothing to be scoped to.
    unscoped = build_slot(
        tmp_path / "no-portfolio",
        env=dict(NO_PORTFOLIO_ENV, **{"CROW_COINBASE_PRODUCTS": XRP}),
        perms={first_key: permissions(PORTFOLIO_A), equity_key: permissions(EQUITY_PORTFOLIO)},
    )
    assert unscoped.wiring.portfolio_id is None
    refused_set(
        unscoped,
        first_key,
        first_pem,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
        code=equity_key_refused(),
    )

    # A key that cannot trade, and one that cannot view its own portfolio.
    for label, second_perms in (
        ("cannot-trade", permissions(EQUITY_PORTFOLIO, can_trade=False)),
        ("cannot-view", permissions(EQUITY_PORTFOLIO, can_view=False)),
    ):
        h = build_slot(
            tmp_path / label,
            env={"CROW_COINBASE_PRODUCTS": XRP},
            perms={first_key: permissions(PORTFOLIO_A), equity_key: second_perms},
        )
        result = refused_set(
            h,
            first_key,
            first_pem,
            equity_key_name=equity_key,
            equity_private_key=equity_pem,
            code=equity_key_refused(),
            builds=2,
        )
        for text in (first_key, equity_key, first_marker, equity_marker, EQUITY_PORTFOLIO):
            assert text not in result.message, (label, result.message)

    # Only one of the two fields: refused, and no second adapter is built.
    for label, fields in (
        ("name-only", {"equity_key_name": equity_key}),
        ("key-only", {"equity_private_key": equity_pem}),
    ):
        h = build_slot(
            tmp_path / label,
            env={"CROW_COINBASE_PRODUCTS": XRP},
            perms={first_key: permissions(PORTFOLIO_A), equity_key: permissions(EQUITY_PORTFOLIO)},
        )
        refused_set(
            h,
            first_key,
            first_pem,
            code=equity_key_refused(),
            builds=1,
            **fields,
        )

    # Equity fields while equities are not enabled.
    disabled = build_slot(
        tmp_path / "disabled",
        env=dict(NO_EQUITY_ENV, **{"CROW_COINBASE_PRODUCTS": XRP}),
        perms={first_key: permissions(PORTFOLIO_A), equity_key: permissions(EQUITY_PORTFOLIO)},
    )
    assert disabled.wiring.enabled is False
    refused_set(
        disabled,
        first_key,
        first_pem,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
        code=equity_key_refused(),
        builds=1,
    )

    # The second key's NAME equal to the first: two fields, one key.
    same_name = build_slot(
        tmp_path / "same-name",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms={first_key: permissions(PORTFOLIO_A)},
    )
    refused_set(
        same_name,
        first_key,
        first_pem,
        equity_key_name=first_key,
        equity_private_key=equity_pem,
        code=equity_key_refused(),
        builds=1,
    )

    # A malformed second private key: refused before any adapter is built.
    malformed = build_slot(
        tmp_path / "malformed",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms={first_key: permissions(PORTFOLIO_A), equity_key: permissions(EQUITY_PORTFOLIO)},
    )
    refused_set(
        malformed,
        first_key,
        first_pem,
        equity_key_name=equity_key,
        equity_private_key="not-a-private-key",
        code=equity_key_refused(),
        builds=1,
    )


def test_bad_first_key_refused_before_the_equity_key(tmp_path):
    """A bad first key keeps its own `KEY_*` code, and the second adapter is never built.

    The second key is judged AFTER the first, so a first key that may move money
    out, cannot trade or cannot see the account is answered with its own code —
    even when the equity fields riding along are a perfectly good pair.
    """
    first_key, equity_key = key_name_canary(), key_name_canary()
    first_pem, _first_marker = private_key_canary()
    equity_pem, _equity_marker = private_key_canary()

    for label, first_perms, expected in (
        (
            "can-transfer",
            permissions(PORTFOLIO_A, can_transfer=True),
            credentials_module.KEY_CAN_TRANSFER,
        ),
        (
            "cannot-trade",
            permissions(PORTFOLIO_A, can_trade=False),
            credentials_module.KEY_CANNOT_TRADE,
        ),
        (
            "cannot-view",
            permissions(PORTFOLIO_A, can_view=False),
            credentials_module.KEY_INVALID,
        ),
    ):
        h = build_slot(
            tmp_path / f"first-{label}",
            env={"CROW_COINBASE_PRODUCTS": XRP},
            perms={first_key: first_perms, equity_key: permissions(EQUITY_PORTFOLIO)},
        )
        result = refused_set(
            h,
            first_key,
            first_pem,
            equity_key_name=equity_key,
            equity_private_key=equity_pem,
            code=expected,
            builds=1,
        )
        assert result.state == "refused", label
        assert list(h.builder.fakes) == [first_key], label
        assert equity_key not in h.builder.fakes, label


# ---------------------------------------------------------------- the USD pools


def test_startup_refuses_usd_crypto_with_split_pools(tmp_path):
    """Two pools are refused while a crypto product is quoted in USD.

    Two keys on two portfolios see two USD pools, and a USD-quoted crypto product
    on a second account would be the same cash counted by neither pool cleanly, so
    it is refused; with only USDC-quoted crypto the split is allowed.  One pool
    (both keys on one portfolio) is always allowed.  An unknown portfolio
    relationship is refused rather than assumed — and because the equity key has
    to be scoped to the configured portfolio, the relationship is only unknown
    when the FIRST key is the one that names none, which is judged first with its
    own code.
    """
    first_key, equity_key = key_name_canary(), key_name_canary()
    first_pem, _first_marker = private_key_canary()
    equity_pem, _equity_marker = private_key_canary()

    split = {
        first_key: permissions(PORTFOLIO_A),
        equity_key: permissions(EQUITY_PORTFOLIO),
    }

    # Two pools and BTC-USD on the crypto list: refused.
    usd_crypto = build_slot(
        tmp_path / "split-usd-crypto",
        env={"CROW_COINBASE_PRODUCTS": f"{BTC_USD},{XRP}"},
        perms=split,
    )
    assert usd_crypto.wiring.usd_crypto_products() == (BTC_USD,)
    refused_set(
        usd_crypto,
        first_key,
        first_pem,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
        code=equity_usd_pools(),
        builds=2,
    )

    # The same two keys with only USDC-quoted crypto: two pools, and allowed.
    usdc_only = build_slot(
        tmp_path / "split-usdc-only",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms=split,
    )
    assert usdc_only.wiring.usd_crypto_products() == ()
    accepted = usdc_only.slot.set(
        first_key,
        first_pem,
        approve_secret(),
        key_kind=KEY_KIND_INSTALL_TOKEN,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
    )
    assert accepted.state == "ok", accepted
    accepted_router = usdc_only.slot.live_exchange()
    assert accepted_router is not None
    assert accepted_router.usd_one_pool is False
    assert accepted_router.equity is usdc_only.builder.fakes[equity_key]

    # Both keys on ONE portfolio, with BTC-USD listed: one pool, allowed.
    one_pool = build_slot(
        tmp_path / "one-pool-usd-crypto",
        env={"CROW_COINBASE_PRODUCTS": f"{BTC_USD},{XRP}"},
        perms={
            first_key: permissions(EQUITY_PORTFOLIO),
            equity_key: permissions(EQUITY_PORTFOLIO),
        },
    )
    assert one_pool.wiring.usd_crypto_products() == (BTC_USD,)
    together = one_pool.slot.set(
        first_key,
        first_pem,
        approve_secret(),
        key_kind=KEY_KIND_INSTALL_TOKEN,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
    )
    assert together.state == "ok", together
    together_router = one_pool.slot.live_exchange()
    assert together_router is not None
    assert together_router.usd_one_pool is True

    # An unknown relationship: with a configured portfolio id the equity key's own
    # portfolio check answers first, so the case is built with the FIRST key naming
    # no portfolio — and that key is judged first, with its own code, before the
    # two keys' USD can be derived at all.
    unknown = build_slot(
        tmp_path / "unknown-relationship",
        env={"CROW_COINBASE_PRODUCTS": BTC_USD},
        perms={first_key: permissions(None), equity_key: permissions(EQUITY_PORTFOLIO)},
    )
    unknown_result = refused_set(
        unknown,
        first_key,
        first_pem,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
        code=credentials_module.KEY_NOT_PORTFOLIO_SCOPED,
        builds=1,
    )
    assert unknown_result.state == "refused"
    # The derivation itself refuses to assume: an unscoped key raises rather than
    # answering "one pool" or "two".
    with pytest.raises(ValueError):
        usd_one_pool_from_keys(permissions(None), permissions(EQUITY_PORTFOLIO))
    with pytest.raises(ValueError):
        usd_one_pool_from_keys(permissions(PORTFOLIO_A), permissions(None))
    assert usd_one_pool_from_keys(permissions(PORTFOLIO_A), permissions(PORTFOLIO_A)) is True
    assert usd_one_pool_from_keys(permissions(PORTFOLIO_A), permissions(PORTFOLIO_B)) is False


# ---------------------------------------------------------------- the API


def test_api_equity_fields_pass_through(tmp_path):
    """Both bodies carry the two optional fields, and the check route passes them on.

    The fields are OPTIONAL (a body without them is still valid), anything this
    build does not know is still forbidden, and a POST to `/credentials/check`
    through the real app reaches `slot.check` — the fake live side sees the second
    build — while the answer carries no key name and no private key of either key.
    """
    first_key, equity_key = key_name_canary(), key_name_canary()
    first_pem, first_marker = private_key_canary()
    equity_pem, equity_marker = private_key_canary()
    secret = approve_secret()

    # The check body: the two fields, optional, and nothing else.
    with_fields = CredentialCheckBody(
        key_name=first_key,
        private_key=first_pem,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
    )
    assert with_fields.equity_key_name == equity_key
    assert with_fields.equity_private_key == equity_pem
    without_fields = CredentialCheckBody(key_name=first_key, private_key=first_pem)
    assert without_fields.equity_key_name is None
    assert without_fields.equity_private_key is None
    with pytest.raises(ValidationError):
        CredentialCheckBody(
            key_name=first_key, private_key=first_pem, surprise="unknown-field"
        )

    # The connect body: the same two fields, same rules.
    connect = CredentialBody(
        key_name=first_key,
        private_key=first_pem,
        approve_secret=secret,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
    )
    assert connect.equity_key_name == equity_key
    assert connect.equity_private_key == equity_pem
    assert connect.repin is False
    with pytest.raises(ValidationError):
        CredentialBody(
            key_name=first_key,
            private_key=first_pem,
            approve_secret=secret,
            surprise="unknown-field",
        )

    # The real app, with equities on and a fake live side per key name.
    builder = KeyedLiveBuilder(
        perms={
            first_key: permissions(PORTFOLIO_A),
            equity_key: permissions(EQUITY_PORTFOLIO),
        }
    )
    h = build_engine(tmp_path / "api", builder=builder)
    with h.client() as client:
        response = h.signer.post(
            client,
            "/credentials/check",
            {
                "key_name": first_key,
                "private_key": first_pem,
                "equity_key_name": equity_key,
                "equity_private_key": equity_pem,
            },
            key=h.install_token,
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {
        "state",
        "code",
        "message",
        "key_last4",
        "portfolio_last4",
    }, body
    assert body["state"] == "ok", body
    assert body["code"] is None, body
    assert body["key_last4"] == first_key[-4:], body

    # Both keys reached the slot: one adapter per key was built.
    assert builder.calls == 2, builder.creds
    assert [creds["api_key"] for creds in builder.creds] == [first_key, equity_key]
    # A check installs nothing.
    assert h.engine.slot.live_exchange() is None
    assert h.engine.store.get(APPROVE_PIN_KEY) is None

    # Nothing of either key pair is echoed back.
    for text in (equity_marker, equity_key, equity_pem, first_marker, first_key, first_pem):
        assert text not in response.text, response.text


# ---------------------------------------------------------------- leaks


def test_equity_secrets_never_leak(tmp_path, caplog):
    """The equity key pair lives in memory only: no event, no kv row, no file.

    The connect succeeds — so the pair really was seen — and then every place the
    engine writes is scanned for both key names and both private keys' marker
    lines, plus the log at DEBUG.  What is kept is the approval secret's hash, the
    pinned portfolio and the epoch, and none of those is a key.
    """
    caplog.set_level(logging.DEBUG)
    first_key, equity_key = key_name_canary(), key_name_canary()
    first_pem, first_marker = private_key_canary()
    equity_pem, equity_marker = private_key_canary()
    secret = approve_secret()

    h = build_slot(
        tmp_path / "leaks",
        env={"CROW_COINBASE_PRODUCTS": XRP},
        perms={
            first_key: permissions(PORTFOLIO_A),
            equity_key: permissions(EQUITY_PORTFOLIO),
        },
    )
    result = h.slot.set(
        first_key,
        first_pem,
        secret,
        key_kind=KEY_KIND_INSTALL_TOKEN,
        equity_key_name=equity_key,
        equity_private_key=equity_pem,
    )
    assert result.state == "ok", result
    router = h.slot.live_exchange()
    assert router is not None
    assert router.equity is h.builder.fakes[equity_key]
    assert router.crypto is h.builder.fakes[first_key]

    events = [
        str(row["message"])
        for row in h.store.conn().execute("SELECT message FROM events").fetchall()
    ]
    kv_rows = [
        (str(row["key"]), str(row["value"]))
        for row in h.store.conn().execute("SELECT key, value FROM kv").fetchall()
    ]
    files = sorted(path for path in Path(tmp_path).rglob("*") if path.is_file())
    assert files, "the store wrote no file at all"
    blob = b"".join(path.read_bytes() for path in files)

    for value in (
        first_key,
        equity_key,
        first_pem,
        equity_pem,
        first_marker,
        equity_marker,
        secret,
    ):
        assert value not in caplog.text, value
        for message in events:
            assert value not in message, (value, message)
        for key, stored in kv_rows:
            assert value not in key, (value, key)
            assert value not in stored, (value, stored)
        assert value.encode() not in blob, value

    # The pin is the secret's hash and nothing else; the portfolio and the epoch
    # are the two other rows a connect writes.
    assert h.store.get(APPROVE_PIN_KEY) == hashlib.sha256(secret.encode("utf-8")).hexdigest()
    assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_A
    assert isinstance(h.store.get(EPOCH_KEY), str)