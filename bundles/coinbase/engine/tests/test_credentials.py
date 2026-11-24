"""test_credentials.py: the owner's API key, its pin, and the epoch that guards it.

Every test here builds the REAL engine through `build_app`: a real `Store` on a
temporary data directory, the real dry-run exchange, gateway, runner and the
real approval rail (`Authenticator`), so the credentials routes are gated the
way the engine gates them — the bearer token first, then a MAC over the exact
bytes the request sends.  Only two things are faked, both outside the engine's
own code:

* `LiveBuilder` is the `live_builder` `build_app` takes.  It counts every call
  and answers one `FakeLive`, whose `key_permissions()` returns a permissions
  dict the test sets and whose every other method raises: an exchange call this
  engine was never supposed to make fails the test on the spot.
  `GatedLiveBuilder` is the same builder with a wait on each call, which is how
  two first connects are held at the same point in their own request.
* `FakeMarket` answers a fixed touch, so the dry book has a price and nothing
  opens a socket.

The install token is a random string written to a file OUTSIDE the data
directory, and it is named to the engine through `CROW_COINBASE_INSTALL_TOKEN_FILE`
— outside, because one test scans every file the engine writes for it.  The
owner's approval secret, the key name and the private key are built at runtime
too: no real credential, and no literal key header, is ever text in this file.

`Signer` is the one place a request is signed: it hands `auth.compute_mac` the
same bytes `TestClient` sends, over the same path, so a request that matches is
one the rail accepts and one that does not is refused.

What each test pins down:

* a restart comes up pinned and locked: no live exchange exists until the
  credentials are pushed again, and the first connect is signed by the install
  token while every later one is signed by the owner's secret,
* a first install MAC'd with anything but the install token is refused and
  writes nothing,
* only the sha256 of the approval secret is stored, a second secret is refused
  as `SECRET_MISMATCH`, the install token stops being a key, and a nonce is
  spent once,
* a wipe reports itself unpinned until a push, and `/health` stays anonymous and
  exchange-free,
* `POST /credentials/check` answers the same `KeyCheck` and installs nothing,
* the portfolio is pinned by the first connect and only `repin` moves it, and two
  first connects racing each other leave exactly one pin — and one secret — behind,
* every permission refusal, and the ordering they are judged in, including the
  portfolio type a good key has to report and the transfer permission it has to
  deny in so many words,
* a body that names the same key twice is refused before anything is installed,
* the captured bytes of a credentials body are read once: one that is not UTF-8,
  that does not parse as JSON, or that is not a JSON object is refused as
  `INVALID` with no field named at all,
* five secrets that are not the pinned one lock the route out for a minute, a
  push carrying the pinned secret with a MAC keyed by it is still served and
  clears that lockout, and a refusal of another kind never counts towards it,
* `/health` answers 503 rather than raising when the pin cannot be read,
* no secret, key name, key body or install token reaches a file, a log line, an
  event or a response, and a validation refusal names fields and nothing else,
* the watchdog alerts and keeps running when live is allowed, and sweeps as it
  always did when it is not,
* a disconnect is refused while a live order is resting, and otherwise drops the
  live route while the pin stays behind,
* forgetting is the owner's alone — the bearer token, the install token and a
  wrong secret are each refused and move nothing — and it is refused while a
  live order rests or a live bot (or the AI's switch) is on; a live bot that is
  STOPPED, which a kill or its own stop leaves behind, has nothing to settle and
  does not refuse it; otherwise it drops
  the pin, the portfolio, the epoch and both switches, so the engine is a first
  install again and the install token makes the next first connect, with a new
  epoch and the old secret retired,
* the three credentials routes exist and refuse a request that carries the
  bearer token alone.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import json
import logging
import re
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal as D
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

import crow_coinbase.auth as auth_module
import crow_coinbase.watchdog as watchdog_module
from crow_coinbase.__main__ import build_app
from crow_coinbase.books import (
    APPROVAL_INVALID,
    LIVE_LOCKED,
    SWITCH_AI_LIVE,
    SWITCH_LIVE,
)
from crow_coinbase.money import ProductSpec
from crow_coinbase.store import OPEN, PAUSED, PENDING_SUBMIT, STOPPED, Store
from crow_coinbase.strategies.base import OrderIntent

# ---------------------------------------------------------------- test data
# 32+ characters, no whitespace: the shortest bearer token the engine starts
# with, built at runtime so no value here is a credential anybody could use.
TOKEN = "test-token-" + secrets.token_hex(16)
BEARER = f"Bearer {TOKEN}"
HEADERS = {"Authorization": BEARER}

# The install token the engine's installer would publish, built at runtime too.
INSTALL_TOKEN = "install-" + secrets.token_hex(20)

# The pinned portfolio the fake key names, and a second one for repinning.
PORTFOLIO_A = uuid.uuid4().hex
PORTFOLIO_B = uuid.uuid4().hex

# A PEM header and footer as PARTS: the private-key shape is a thing these tests
# build at runtime, never a literal in this file.
PEM_BEGIN = "-----BEGIN "
PEM_END = "-----END "
PEM_EC = "EC "
PEM_PKCS8 = ""
PEM_SUFFIX = "PRIVATE KEY-----"

BOT = "b1"
PRODUCT = "XRP-USDC"

# The clock every engine and every signature starts from.
NOW = 1_700_000_000.0

# The key permissions the refusal codes are read from.
KEY_INVALID = "KEY_INVALID"
KEY_CAN_TRANSFER = "KEY_CAN_TRANSFER"
KEY_NOT_PORTFOLIO_SCOPED = "KEY_NOT_PORTFOLIO_SCOPED"
KEY_WRONG_PORTFOLIO = "KEY_WRONG_PORTFOLIO"
KEY_CANNOT_TRADE = "KEY_CANNOT_TRADE"
KEY_DEFAULT_PORTFOLIO = "KEY_DEFAULT_PORTFOLIO"
SECRET_MISMATCH = "SECRET_MISMATCH"
LIVE_ORDERS_OPEN = "LIVE_ORDERS_OPEN"
INVALID = "INVALID"
# The code `POST /credentials` answers once too many secrets were wrong.
RATE_LIMITED = "RATE_LIMITED"

# The two kv keys a connect writes beside the pin, and the pin's own key (the one
# `auth` reads).
PIN_KEY = auth_module.APPROVE_PIN_KEY
PORTFOLIO_KEY = "credentials_portfolio"
EPOCH_KEY = "engine_epoch"

SPEC = ProductSpec(
    PRODUCT,
    price_increment=D("0.0001"),
    base_increment=D("0.1"),
    quote_increment=D("0.01"),
    base_min_size=D("1"),
    quote_min_size=D("1"),
)

ENV = {
    "CROW_COINBASE_ENGINE_TOKEN": TOKEN,
    "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
    "CROW_COINBASE_PRODUCTS": "XRP-USDC,BTC-USDC",
    "CROW_COINBASE_MAX_BOT_CAPITAL_USD": "100",
}

# The sentence a stale alert carries while live trading is allowed: the
# watchdog has no network, so it can only say what it did not do.
NOT_CANCELLED = "Real Coinbase orders were NOT cancelled"


# ---------------------------------------------------------------- the outside world


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
    """One `FakeMarket` per product, so the dry book always has a price."""
    return _MARKETS.setdefault(product, FakeMarket())


class FakeLive:
    """The live adapter: one permissions answer, and every other call a failure.

    `perms` is read on every `key_permissions()` call rather than captured, so a
    test can change what the key is scoped to between two pushes.  `error` is
    raised instead, which is how a failing permissions read is exercised.
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


class LiveBuilder:
    """The `live_builder` `build_app` takes: counts calls, answers one `FakeLive`."""

    def __init__(self, perms=None, error: BaseException | None = None) -> None:
        self.calls = 0
        self.creds: list[dict] = []
        self.fake = FakeLive(perms=perms, error=error)

    def __call__(self, creds) -> FakeLive:
        self.calls += 1
        self.creds.append(dict(creds))
        return self.fake


class GatedLiveBuilder:
    """The `live_builder` two racing connects share, held at a gate on every call.

    Each call waits on its own `threading.Event`, and every wait is bounded, so a
    gate nothing opens is one refused connect rather than a hung test.  That is
    what holds a first connect inside `slot.set` — past its MAC gate, before its
    transaction — while a second request gets past the gate as well.  `release`
    opens the gate for good: the calls already waiting are set and every later
    call answers at once.
    """

    def __init__(self, timeout: float = 20.0) -> None:
        self.calls = 0
        self.timeout = float(timeout)
        self._lock = threading.Lock()
        self._open = False
        self._gates: list[threading.Event] = []

    def __call__(self, creds) -> FakeLive:
        gate = threading.Event()
        with self._lock:
            self.calls += 1
            if self._open:
                return FakeLive(perms=permissions(PORTFOLIO_A))
            self._gates.append(gate)
        gate.wait(timeout=self.timeout)
        return FakeLive(perms=permissions(PORTFOLIO_A))

    def release(self) -> None:
        """Open the gate: the waits already there, and every call after them."""
        with self._lock:
            self._open = True
            gates = list(self._gates)
        for gate in gates:
            gate.set()


def permissions(
    portfolio: str | None = PORTFOLIO_A,
    *,
    can_view: Any = True,
    can_trade: Any = True,
    can_transfer: Any = False,
    portfolio_type: Any = "CONSUMER",
) -> dict:
    """One `key_permissions()` answer, scoped to *portfolio* unless it is None.

    A good key is a CONSUMER portfolio key that cannot transfer, because that is
    the only key the engine accepts: every accept-case fakes this dict, and every
    refusal-case overrides exactly the field it is about.
    """
    return {
        "can_view": can_view,
        "can_trade": can_trade,
        "can_transfer": can_transfer,
        "portfolio_uuid": portfolio,
        "portfolio_type": portfolio_type,
    }


# ---------------------------------------------------------------- test secrets


def approve_secret() -> str:
    """An approval secret, 32+ bytes long, built at runtime."""
    return "approve-" + secrets.token_hex(20)


def key_name_canary() -> str:
    """A key name in the shape Coinbase answers, built at runtime."""
    return f"organizations/{uuid.uuid4().hex}/apiKeys/{uuid.uuid4().hex}"


def private_key_canary() -> tuple[str, str]:
    """A synthetic PEM EC private key, and the body line a scan looks for.

    The header and the footer are built from parts, so this file never spells a
    private-key header; the marker is a random base64 line inside the body, so a
    test can look for the key's bytes without ever naming them literally.
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


def pkcs8_key() -> str:
    """A PKCS8 private key body, in the other header a real key may arrive with."""
    header = PEM_BEGIN + PEM_PKCS8 + PEM_SUFFIX
    footer = PEM_END + PEM_PKCS8 + PEM_SUFFIX
    body = base64.b64encode(secrets.token_bytes(48)).decode("ascii")
    return "\n".join([header, body, footer])


# ---------------------------------------------------------------- requests


class Signer:
    """Builds the three approval headers for one request, and sends it."""

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
        stamp = str(int(self.clock[0] if ts is None else ts))
        used = self.nonce() if nonce is None else str(nonce)
        signature = auth_module.compute_mac(
            key, method, path_with_query, stamp, used, body
        )
        headers = {
            "Authorization": BEARER,
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

    def delete(self, client, path_with_query: str, *, key, nonce: str | None = None):
        headers = self.headers(key, "DELETE", path_with_query, b"", nonce=nonce)
        return client.delete(path_with_query, headers=headers)


def credentials_body(
    key_name: str,
    private_key: str,
    secret: str,
    *,
    repin: Any = None,
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


# ---------------------------------------------------------------- the harness


@dataclass
class Harness:
    """One engine, the builder its live side came from, and the signer over it."""

    engine: Any
    builder: LiveBuilder
    signer: Signer
    clock: list
    data_dir: Path
    token_path: Path
    install_token: str

    @property
    def store(self) -> Store:
        return self.engine.store

    @contextlib.contextmanager
    def client(self, *, bearer: bool = True):
        with TestClient(self.engine.app, raise_server_exceptions=False) as client:
            if bearer:
                client.headers.update(HEADERS)
            yield client


def build_engine(
    root,
    *,
    builder: LiveBuilder | None = None,
    clock: list | None = None,
    install_token: str | None = None,
) -> Harness:
    """The real engine over *root*, with the real rail and an injected live side.

    The install token lives beside the data directory rather than in it, so a
    scan of everything the engine wrote never finds the token it wrote nothing of.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = root / "install_token"
    token = INSTALL_TOKEN if install_token is None else install_token
    token_path.write_text(token + "\n", encoding="utf-8")

    clock = [NOW] if clock is None else clock
    builder = LiveBuilder() if builder is None else builder
    env = dict(ENV, CROW_COINBASE_INSTALL_TOKEN_FILE=str(token_path))
    engine = build_app(
        env,
        data_dir=data_dir,
        market_for=market_for,
        spec_for=lambda product: SPEC,
        now=lambda: clock[0],
        live_builder=builder,
    )
    return Harness(
        engine=engine,
        builder=builder,
        signer=Signer(clock),
        clock=clock,
        data_dir=data_dir,
        token_path=token_path,
        install_token=token,
    )


# ---------------------------------------------------------------- helpers


def health(client) -> dict:
    """The `/health` body, with the two keys this task added spelled out."""
    response = client.get("/health")
    assert response.status_code in (200, 503), response.text
    body = response.json()
    assert "credentials" in body and "pinned" in body, body
    assert body["credentials"] in ("ready", "not_ready"), body
    assert isinstance(body["pinned"], bool), body
    return body


def connected(response) -> dict:
    """The 200 body of a successful POST /credentials."""
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "ok", body
    assert body["pinned"] is True, body
    epoch = body["engine_epoch"]
    assert isinstance(epoch, str) and re.fullmatch(r"[0-9a-f]{32}", epoch), body
    return body


def key_check(response) -> dict:
    """The KeyCheck body, in the shape both credentials routes answer with."""
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {
        "state",
        "code",
        "message",
        "key_last4",
        "portfolio_last4",
    }, body
    assert body["state"] in ("missing", "ok", "refused"), body
    assert isinstance(body["message"], str), body
    return body


def refusal(response, code: str) -> dict:
    """A 403 whose detail is the refusal *code*."""
    assert response.status_code == 403, response.text
    detail = response.json().get("detail")
    assert isinstance(detail, str) and code in detail, response.text
    return response.json()


def key_refusal(response, code: str) -> dict:
    """A 422 that names *code* in its body and carries no value of the request."""
    assert response.status_code == 422, response.text
    body = response.json()
    assert "detail" not in body, body
    assert body.get("code") == code, body
    assert isinstance(body.get("message"), str) and body["message"], body
    return body


def pin_row(store: Store):
    """The kv row for the pin, read directly: an absent row is unpinned."""
    return store.conn().execute(
        "SELECT 1 FROM kv WHERE key=?", (PIN_KEY,)
    ).fetchone()


def kv_row(store: Store, key: str):
    return store.conn().execute("SELECT 1 FROM kv WHERE key=?", (key,)).fetchone()


def assert_unpinned(store: Store) -> None:
    """Nothing a connect writes is there: no pin, no portfolio, no epoch."""
    assert pin_row(store) is None, "a pin was written"
    assert kv_row(store, PORTFOLIO_KEY) is None, "a portfolio was pinned"
    assert kv_row(store, EPOCH_KEY) is None, "an epoch was written"


def make_live_bot(store: Store, switch: bool = True) -> None:
    """A bot on the live book, and the owner's switch that allows its route."""
    if store.get_bot(BOT) is None:
        store.create_bot(BOT, PRODUCT, "grid", {"center": "1.0"}, D("60"), D("30"))
    store.set_bot_book(
        BOT,
        mode="live",
        capital_quote=D("60"),
        capital_base=D("0"),
        live_capital_quote=D("60"),
        live_capital_base=D("0"),
    )
    store.put("live_enabled", switch)


def probe_intent() -> OrderIntent:
    """A well-formed place intent: the route's refusal is what it earns."""
    return OrderIntent(
        action="place",
        side="BUY",
        size=D("10"),
        limit_price=D("0.98"),
        level=-1,
        cancel_cid=None,
        reason="credentials probe",
    )


def live_route(engine) -> str | None:
    """The refusal a live-book order earns now, or None when it may go out."""
    return engine.gateway.check("bot", BOT, probe_intent())


def files_under(directory) -> list[Path]:
    """Every file the engine wrote, the sqlite journal included."""
    return [path for path in sorted(Path(directory).rglob("*")) if path.is_file()]


def data_bytes(directory) -> bytes:
    """Every byte under *directory*, concatenated: what a scan searches."""
    blob = b""
    for path in files_under(directory):
        blob += path.read_bytes()
    return blob


def event_messages(store: Store) -> list[str]:
    rows = store.conn().execute("SELECT message FROM events").fetchall()
    return [str(row["message"]) for row in rows]


def spent_nonces(store: Store) -> set[str]:
    """Every nonce the rail has spent, read straight out of its table.

    The rail writes a nonce only once a request's MAC matched, so a nonce being
    there is the one thing that says a request got past the MAC gate.
    """
    rows = store.conn().execute("SELECT nonce FROM nonces").fetchall()
    return {str(row["nonce"]) for row in rows}


def release_once_past_the_gate(builder, store: Store, nonces, *, seconds=20.0) -> bool:
    """Hold *builder* until every nonce in *nonces* has been spent, then open it.

    Answers whether they were all seen, and releases the builder either way so a
    wait that can never be satisfied is a failed assertion rather than a hung
    test.
    """
    deadline = time.monotonic() + float(seconds)
    seen = False
    while time.monotonic() < deadline:
        if set(nonces) <= spent_nonces(store):
            seen = True
            break
        time.sleep(0.01)
    builder.release()
    return seen


# ---------------------------------------------------------------- a restart


def test_restart_locked_until_credentials(tmp_path):
    """A restart has the pin and no key: the live route stays locked until a push.

    The first connect is MAC'd with the install token, so the engine builds the
    adapter once to read the key's permissions; the restart builds nothing at
    all, because a slot with no credentials in memory has no live exchange to
    hand the book router — and once the push passes, the route is decided again.
    """
    builder = LiveBuilder()
    first = build_engine(tmp_path / "restart", builder=builder)
    make_live_bot(first.store)
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    secret = approve_secret()

    with first.client() as client:
        before = health(client)
        assert before["credentials"] == "not_ready"
        assert before["pinned"] is False

        pushed = first.signer.post(
            client,
            "/credentials",
            credentials_body(key_name, pem, secret),
            key=first.install_token,
        )
        connected(pushed)
        assert health(client)["credentials"] == "ready"
        assert health(client)["pinned"] is True

        # The adapter was built from the pair `LiveExchange` takes, and the live
        # route is decided rather than locked while the slot holds it.
        assert builder.calls == 1
        assert builder.creds[0]["api_key"] == key_name
        assert builder.creds[0]["api_secret"] == pem
        assert live_route(first.engine) != LIVE_LOCKED

    restarted = LiveBuilder()
    second = build_engine(tmp_path / "restart", builder=restarted)
    with second.client() as client:
        after = health(client)
        assert after["credentials"] == "not_ready"
        assert after["pinned"] is True
        assert second.engine.slot.state() == "missing"

        # Live is allowed and pinned, but there is no live exchange: the route is
        # refused LIVE_LOCKED and nothing was built to refuse it with.
        assert live_route(second.engine) == LIVE_LOCKED
        assert restarted.calls == 0

        again = connected(
            second.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=secret,
            )
        )

        # The epoch is the engine's own, not the push's: it is written once.
        assert again["engine_epoch"] == pushed.json()["engine_epoch"]
        assert health(client)["credentials"] == "ready"
        assert restarted.calls == 1
        assert live_route(second.engine) != LIVE_LOCKED

    # The key body never became a stored value on either engine.
    assert marker.encode() not in data_bytes(first.data_dir)


# ---------------------------------------------------------------- the first install


def test_first_install_needs_install_token(tmp_path):
    """Only the install token connects a first time; anything else writes nothing."""
    h = build_engine(tmp_path / "first-install")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()
    body = credentials_body(key_name, pem, secret)

    wrong = "other-" + secrets.token_hex(20)
    assert len(wrong) >= 32, "the wrong key has to be long enough to look real"

    with h.client() as client:
        # Signed with a key of the right length that is not the token.
        refusal(
            h.signer.post(client, "/credentials", body, key=wrong), APPROVAL_INVALID
        )
        # Signed with nothing at all.
        bare = client.post("/credentials", json=body, headers=HEADERS)
        refusal(bare, APPROVAL_INVALID)
        # Signed with a fresh random key.
        refusal(
            h.signer.post(
                client, "/credentials", body, key="key-" + secrets.token_hex(20)
            ),
            APPROVAL_INVALID,
        )

        assert_unpinned(h.store)
        assert h.builder.calls == 0
        assert h.engine.slot.state() == "missing"

        installed = connected(
            h.signer.post(client, "/credentials", body, key=h.install_token)
        )
        assert installed["state"] == "ok"
        assert pin_row(h.store) is not None
        assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_A
        assert h.builder.calls == 1


def test_concurrent_first_pins_one_wins(tmp_path):
    """Two first connects at once: exactly one pins its secret, the other is refused.

    Both requests are signed with the install token and carry a DIFFERENT approval
    secret, and the fake live side holds each build until both requests have spent
    their nonce — which the rail writes only after a MAC matched, so both of them
    got past the MAC gate believing the engine was unpinned.  Only one may write a
    pin: the stored pin is the sha256 of the winner's secret, the portfolio is
    written once, and the rail holds that same secret, so the loser's secret keys
    nothing at all.
    """

    def race_once(root) -> None:
        builder = GatedLiveBuilder()
        h = build_engine(root, builder=builder)
        key_name = key_name_canary()
        pem, _marker = private_key_canary()
        secrets_by_racer = [approve_secret(), approve_secret()]
        nonces = [h.signer.nonce(), h.signer.nonce()]
        answers: dict[int, Any] = {}

        def push(index: int, client) -> None:
            answers[index] = h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secrets_by_racer[index]),
                key=h.install_token,
                nonce=nonces[index],
            )

        with h.client() as first, h.client() as second:
            threads = [
                threading.Thread(target=push, args=(0, first), daemon=True),
                threading.Thread(target=push, args=(1, second), daemon=True),
            ]
            for thread in threads:
                thread.start()
            both_past_the_gate = release_once_past_the_gate(builder, h.store, nonces)
            for thread in threads:
                thread.join(timeout=60)
            assert not any(thread.is_alive() for thread in threads), "a request hung"
            assert both_past_the_gate, "both requests never passed the MAC gate"
            assert set(answers) == {0, 1}, answers

            statuses = {
                index: response.status_code for index, response in answers.items()
            }
            won = [index for index, code in statuses.items() if code == 200]
            lost = [index for index, code in statuses.items() if code != 200]
            assert len(won) == 1, statuses
            assert len(lost) == 1, statuses
            refusal(answers[lost[0]], SECRET_MISMATCH)

            winner_secret = secrets_by_racer[won[0]]
            loser_secret = secrets_by_racer[lost[0]]
            assert winner_secret != loser_secret
            assert h.store.get(PIN_KEY) == hashlib.sha256(
                winner_secret.encode("utf-8")
            ).hexdigest()
            assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_A, "the portfolio was pinned twice"

            # The rail kept the winner's secret: a lease MAC'd with it is served,
            # and one MAC'd with the loser's is refused.
            accepted = h.signer.post(
                first, "/lease", {"holder": "race-probe"}, key=winner_secret
            )
            assert accepted.status_code == 200, accepted.text
            refusal(
                h.signer.post(
                    first, "/lease", {"holder": "race-probe"}, key=loser_secret
                ),
                APPROVAL_INVALID,
            )

    for attempt in range(3):
        race_once(tmp_path / f"race-{attempt}")


def test_slot_set_secret_mismatch_on_pinned_store(tmp_path):
    """A pinned slot refuses a second secret, `repin` included, and writes nothing.

    The check is made inside the store transaction, so the pin as it stands at the
    write is what decides: a secret that is not the pinned one is refused however
    the request was keyed, and so is a request the rail keyed with the install
    token at a moment the store held no pin — the transaction is what knows a pin
    is there now.  Each refusal leaves the pin, the portfolio and the rail's
    in-memory secret exactly as they were.
    """
    builder = LiveBuilder(perms=permissions(PORTFOLIO_A))
    h = build_engine(tmp_path / "slot-mismatch", builder=builder)
    slot = h.engine.slot
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    pinned_secret = approve_secret()
    other_secret = approve_secret()

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, pinned_secret),
                key=h.install_token,
            )
        )

    digest = hashlib.sha256(pinned_secret.encode("utf-8")).hexdigest()
    assert h.store.get(PIN_KEY) == digest
    assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_A

    def refuses(secret: str, *, repin: bool, key_kind: str) -> None:
        """`slot.set` answers SECRET_MISMATCH, however the refusal is reported."""
        try:
            result = slot.set(key_name, pem, secret, repin=repin, key_kind=key_kind)
        except Exception as error:  # noqa: BLE001 - a refusal may be raised, not answered
            detail = getattr(error, "detail", None)
            status = getattr(error, "status_code", None)
            assert SECRET_MISMATCH in f"{detail or ''} {error}", error
            assert status in (None, 403), status
            assert secret not in str(error), "the refusal carried the secret"
        else:
            assert result.state == "refused", result
            assert result.code == SECRET_MISMATCH, result
            assert secret not in (result.message or ""), "the refusal carried the secret"
        assert h.store.get(PIN_KEY) == digest, "a refused set moved the pin"
        assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_A, "a refused set moved the portfolio"
        assert slot.state() == "ok", "a refused set dropped the live route"

    refuses(other_secret, repin=False, key_kind="pinned_secret")

    # A repin moves the portfolio, never the secret: the key below names another
    # portfolio, so a repin that had been honoured would have written it.
    builder.fake.perms = permissions(PORTFOLIO_B)
    refuses(other_secret, repin=True, key_kind="pinned_secret")

    # The install token was this request's key when the rail chose it, and a pin
    # row is there by the time the transaction looks: refused, and the body's
    # secret being the right one makes no difference to that.  The key names the
    # pinned portfolio, so nothing before the transaction has reason to refuse it.
    builder.fake.perms = permissions(PORTFOLIO_A)
    refuses(pinned_secret, repin=False, key_kind="install_token")

    # The rail still holds the pinned secret, and the other one keys nothing.
    with h.client() as client:
        accepted = h.signer.post(
            client, "/lease", {"holder": "slot-probe"}, key=pinned_secret
        )
        assert accepted.status_code == 200, accepted.text
        refusal(
            h.signer.post(client, "/lease", {"holder": "slot-probe"}, key=other_secret),
            APPROVAL_INVALID,
        )


def test_secret_pinned_by_hash(tmp_path):
    """The pin is the secret's sha256; a second secret is refused as SECRET_MISMATCH."""
    h = build_engine(tmp_path / "hash")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    first_secret = approve_secret()

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, first_secret),
                key=h.install_token,
            )
        )

    # The kv holds the sha256 hex of the secret, and the file holds no copy of
    # the secret itself, of the key body, or of the key's name.
    assert h.store.get(PIN_KEY) == hashlib.sha256(
        first_secret.encode("utf-8")
    ).hexdigest()
    blob = data_bytes(h.data_dir)
    assert first_secret.encode() not in blob
    assert marker.encode() not in blob
    assert key_name.encode() not in blob

    restarted_builder = LiveBuilder()
    second = build_engine(tmp_path / "hash", builder=restarted_builder)
    other_secret = approve_secret()
    assert other_secret != first_secret

    def body_with(secret: str) -> dict:
        return credentials_body(key_name, pem, secret)

    with second.client() as client:
        # A different secret, MAC'd with itself: the pin refuses it.
        refusal(
            second.signer.post(
                client, "/credentials", body_with(other_secret), key=other_secret
            ),
            SECRET_MISMATCH,
        )
        # The right secret in the body, but MAC'd with the install token: the pin
        # took the token out of the rail, so the MAC cannot match.
        refusal(
            second.signer.post(
                client, "/credentials", body_with(first_secret), key=second.install_token
            ),
            APPROVAL_INVALID,
        )
        # Nothing above changed the pin, and the builder was never called.
        assert second.store.get(PIN_KEY) == hashlib.sha256(
            first_secret.encode("utf-8")
        ).hexdigest()
        assert restarted_builder.calls == 0

        # The right secret, signed with itself, connects.
        nonce = second.signer.nonce()
        connected(
            second.signer.post(
                client,
                "/credentials",
                body_with(first_secret),
                key=first_secret,
                nonce=nonce,
            )
        )
        # The same signed request again: the nonce is spent.
        refusal(
            second.signer.post(
                client,
                "/credentials",
                body_with(first_secret),
                key=first_secret,
                nonce=nonce,
            ),
            APPROVAL_INVALID,
        )


# ---------------------------------------------------------------- health


def test_wipe_reports_unpinned(tmp_path):
    """`/health` says unpinned until a push, and never touches the exchange."""
    h = build_engine(tmp_path / "wipe")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client(bearer=False) as anonymous:
        fresh = anonymous.get("/health")
        assert fresh.status_code == 200, fresh.text
        body = fresh.json()
        assert body["pinned"] is False
        assert body["credentials"] == "not_ready"
        assert h.builder.calls == 0

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        built = h.builder.calls

    # Still anonymous, and no exchange call came out of reading it.
    with h.client(bearer=False) as anonymous:
        fresh = anonymous.get("/health")
        assert fresh.status_code == 200, fresh.text
        body = fresh.json()
        assert body["pinned"] is True
        assert body["credentials"] == "ready"
        assert h.builder.calls == built


def test_health_survives_store_error(tmp_path, monkeypatch):
    """A pin that cannot be read is a 503 that says pinned, never a raised request.

    `pin_exists` is a read of the store, and a store that cannot be read is the
    one thing `/health` must still answer: the engine cannot say whether it is
    pinned, so it fails closed — `pinned` true, `credentials` not ready, and a
    503 — rather than raising out of an anonymous route.
    """
    h = build_engine(tmp_path / "health-error")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        ready = health(client)
        assert ready["credentials"] == "ready"
        assert ready["pinned"] is True

        def unreadable(*args, **kwargs):
            """The pin read: a store that will not open a connection."""
            raise sqlite3.OperationalError("the pin cannot be read")

        monkeypatch.setattr(h.store, "conn", unreadable)
        response = client.get("/health")
        assert response.status_code == 503, response.text
        body = response.json()
        assert body["ok"] is False, body
        assert body["pinned"] is True, body
        assert body["credentials"] == "not_ready", body
        assert "live_enabled" in body, body
        for value in (secret, key_name, marker, "the pin cannot be read"):
            assert value not in response.text, response.text

    # And the store is read again once it can be: the refusal was not sticky.
    monkeypatch.undo()
    with h.client() as client:
        recovered = health(client)
        assert recovered["pinned"] is True
        assert recovered["credentials"] == "ready"


# ---------------------------------------------------------------- POST /credentials/check


def test_check_endpoint_never_installs(tmp_path):
    """/credentials/check answers a KeyCheck and leaves the engine exactly as it was."""
    h = build_engine(tmp_path / "check")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        good = key_check(
            h.signer.post(
                client,
                "/credentials/check",
                {"key_name": key_name, "private_key": pem},
                key=h.install_token,
            )
        )
        assert good["state"] == "ok"
        assert good["code"] is None
        assert key_name.endswith(str(good["key_last4"]))
        assert PORTFOLIO_A.endswith(str(good["portfolio_last4"]))

        bad = key_check(
            h.signer.post(
                client,
                "/credentials/check",
                {"key_name": "not-a-key-name", "private_key": pem},
                key=h.install_token,
            )
        )
        assert bad["state"] == "refused"
        assert bad["code"] == KEY_INVALID

        # Nothing was installed, and no adapter was kept: the good key built one
        # and it was dropped, while the malformed name was refused before
        # anything was built, so the live book still has no exchange.
        assert_unpinned(h.store)
        assert h.engine.slot.state() == "missing"
        assert h.engine.gateway.books.live_available() is False
        assert h.builder.calls == 1

        # Now connect, and the install token stops being a key for this route too.
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        refusal(
            h.signer.post(
                client,
                "/credentials/check",
                {"key_name": key_name, "private_key": pem},
                key=h.install_token,
            ),
            APPROVAL_INVALID,
        )
        after = key_check(
            h.signer.post(
                client,
                "/credentials/check",
                {"key_name": key_name, "private_key": pem},
                key=secret,
            )
        )
        assert after["state"] == "ok"


# ---------------------------------------------------------------- the portfolio pin


def test_portfolio_pinned_on_first_connect(tmp_path):
    """The first connect pins the key's portfolio, and only `repin` moves it."""
    builder = LiveBuilder(perms=permissions(PORTFOLIO_A))
    h = build_engine(tmp_path / "portfolio", builder=builder)
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        first = connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_A

        # The same key now reports a different portfolio: without `repin` that is
        # a refusal, and the pin stays where it was.
        builder.fake.perms = permissions(PORTFOLIO_B)
        key_refusal(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=secret,
            ),
            KEY_WRONG_PORTFOLIO,
        )
        assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_A

        # With `repin`, signed by the secret the pin knows, the pin moves.
        moved = connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret, repin=True),
                key=secret,
            )
        )
        assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_B
        assert moved["engine_epoch"] == first["engine_epoch"]


def test_repin_refused_on_a_first_connect(tmp_path):
    """`repin` names a portfolio to move to, so an unpinned engine has none to move."""
    h = build_engine(tmp_path / "repin-first")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        response = h.signer.post(
            client,
            "/credentials",
            credentials_body(key_name, pem, secret, repin=True),
            key=h.install_token,
        )
        assert response.status_code == 422, response.text
        assert INVALID in response.text, response.text
        assert_unpinned(h.store)
        assert h.engine.slot.state() == "missing"


# ---------------------------------------------------------------- refusals


def test_evaluate_permissions_priority():
    """The permission refusals, in the order the engine judges them."""
    module = credentials_module()
    KeyCheck = module.KeyCheck
    evaluate = module.evaluate_permissions

    assert [field.name for field in dataclasses.fields(KeyCheck)] == [
        "state",
        "code",
        "message",
        "key_last4",
        "portfolio_last4",
    ]

    everything = evaluate(
        permissions(PORTFOLIO_B, can_view=False, can_trade=False, can_transfer=True),
        PORTFOLIO_A,
    )
    assert isinstance(everything, KeyCheck)
    assert everything.state == "refused"
    assert everything.code == KEY_CAN_TRANSFER

    assert (
        evaluate(permissions(None, can_view=False, can_trade=False), None).code
        == KEY_NOT_PORTFOLIO_SCOPED
    )
    assert (
        evaluate(
            permissions(PORTFOLIO_B, can_view=False, can_trade=False), PORTFOLIO_A
        ).code
        == KEY_WRONG_PORTFOLIO
    )
    assert (
        evaluate(
            permissions(PORTFOLIO_A, can_view=False, can_trade=False), PORTFOLIO_A
        ).code
        == KEY_CANNOT_TRADE
    )
    assert (
        evaluate(permissions(PORTFOLIO_A, can_view=False), PORTFOLIO_A).code
        == KEY_INVALID
    )

    good = evaluate(permissions(PORTFOLIO_A), PORTFOLIO_A)
    assert good.state == "ok"
    assert good.code is None
    assert isinstance(good.message, str)

    # An unpinned engine has no portfolio to compare against.
    assert evaluate(permissions(PORTFOLIO_B), None).state == "ok"

    # A refusal says what is wrong in plain words, and never a key's body.
    for refused in (
        evaluate(permissions(None), None),
        evaluate(permissions(PORTFOLIO_B), PORTFOLIO_A),
    ):
        assert "-----" not in refused.message


def test_default_and_intx_portfolio_refused():
    """Only a CONSUMER portfolio key is accepted: DEFAULT has its own refusal.

    A key on the owner's main portfolio can trade money this engine never budgeted,
    so it is refused with a code and a message of its own; INTX (an institution's),
    UNDEFINED, a wrong case and a missing or unusable value are all a key this
    engine cannot scope, which is a different answer.
    """
    module = credentials_module()
    evaluate = module.evaluate_permissions
    default_code = getattr(module, "KEY_DEFAULT_PORTFOLIO")
    assert default_code == KEY_DEFAULT_PORTFOLIO

    main_portfolio = evaluate(permissions(portfolio_type="DEFAULT"), None)
    assert main_portfolio.state == "refused"
    assert main_portfolio.code == default_code
    assert main_portfolio.message == (
        "This key is for your main Coinbase portfolio. Create a key for the "
        "Crow portfolio instead."
    )

    for label, value in (
        ("INTX", "INTX"),
        ("UNDEFINED", "UNDEFINED"),
        ("lower case", "consumer"),
        ("mixed case", "Consumer"),
        ("a number", 1),
        ("null", None),
    ):
        result = evaluate(permissions(portfolio_type=value), None)
        assert result.state == "refused", label
        assert result.code == KEY_NOT_PORTFOLIO_SCOPED, label

    absent = permissions(PORTFOLIO_A)
    absent.pop("portfolio_type")
    assert evaluate(absent, None).code == KEY_NOT_PORTFOLIO_SCOPED

    good = evaluate(permissions(portfolio_type="CONSUMER"), None)
    assert good.state == "ok"
    assert good.code is None

    # The type is judged against the pinned portfolio too, not only unpinned.
    assert evaluate(permissions(PORTFOLIO_A, portfolio_type="DEFAULT"), PORTFOLIO_A).code == default_code
    assert evaluate(permissions(PORTFOLIO_A), PORTFOLIO_A).state == "ok"


def test_missing_can_transfer_refused():
    """A key has to deny the transfer permission in so many words to be accepted.

    Absent, null, the string `"false"`, a number and a truthy value are all not the
    literal `False` the policy reads as consent, so each is refused — and the
    transfer permission is judged before anything else, so such a key is never
    reported as being about its portfolio instead.
    """
    module = credentials_module()
    evaluate = module.evaluate_permissions

    absent = permissions()
    absent.pop("can_transfer")
    missing = evaluate(absent, None)
    assert missing.state == "refused"
    assert missing.code == KEY_CAN_TRANSFER

    for label, value in (
        ("null", None),
        ("the string false", "false"),
        ("zero", 0),
        ("true", True),
        ("one", 1),
    ):
        result = evaluate(permissions(can_transfer=value), None)
        assert result.state == "refused", label
        assert result.code == KEY_CAN_TRANSFER, label

    accepted = evaluate(permissions(can_transfer=False), None)
    assert accepted.state == "ok"
    assert accepted.code is None

    # Transfer is the first judgement: a key that may move money out is not
    # answered with the portfolio, the trade or the view it also fails.
    everything = evaluate(
        permissions(
            None,
            can_view=False,
            can_trade=False,
            can_transfer=True,
            portfolio_type="DEFAULT",
        ),
        PORTFOLIO_A,
    )
    assert everything.code == KEY_CAN_TRANSFER


def test_valid_key_shape():
    """The shape a key has to have before anything is built or reached."""
    module = credentials_module()
    key_name = key_name_canary()
    pem, _marker = private_key_canary()

    assert module.valid_key_shape(key_name, pem) is True
    assert module.valid_key_shape(key_name, pkcs8_key()) is True
    # The two characters backslash-n a JSON body may carry are newlines.
    assert module.valid_key_shape(key_name, pem.replace("\n", "\\n")) is True

    for bad_name in ("", "organizations/x", key_name + "/extra", "apiKeys/abc"):
        assert module.valid_key_shape(bad_name, pem) is False, bad_name
    for bad_key in ("", "not a key", PEM_BEGIN + PEM_EC + PEM_SUFFIX):
        assert module.valid_key_shape(key_name, bad_key) is False, bad_key


def test_credentials_refusals(tmp_path):
    """Every refusal is a 422 that names its code, writes nothing and keeps live locked."""
    builder = LiveBuilder(perms=permissions(PORTFOLIO_A))
    h = build_engine(tmp_path / "refusals", builder=builder)
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:

        def push(perms=None, error: BaseException | None = None, name=key_name, key=pem):
            builder.fake.perms = permissions() if perms is None else perms
            builder.fake.error = error
            return h.signer.post(
                client,
                "/credentials",
                credentials_body(name, key, secret),
                key=h.install_token,
            )

        cases = [
            ("can_transfer", permissions(can_transfer=True), None, KEY_CAN_TRANSFER),
            ("unscoped", permissions(None), None, KEY_NOT_PORTFOLIO_SCOPED),
            (
                "cannot_trade",
                permissions(can_trade=False),
                None,
                KEY_CANNOT_TRADE,
            ),
            ("cannot_view", permissions(can_view=False), None, KEY_INVALID),
            (
                "permissions_raise",
                permissions(),
                RuntimeError("the exchange refused the permissions read"),
                KEY_INVALID,
            ),
        ]
        for label, perms, error, code in cases:
            built = builder.calls
            response = push(perms=perms, error=error)
            key_refusal(response, code)
            assert code in response.text, label
            # Nothing of the failure's own text reaches the caller.
            assert "refused the permissions read" not in response.text, label
            if code == KEY_INVALID and error is not None:
                assert builder.calls == built + 1, label
            assert_unpinned(h.store)
            assert h.engine.gateway.books.live_available() is False, label

        # A key this build cannot even read is refused before anything is built.
        for label, name, key in (
            ("malformed-name", "organizations/x", pem),
            ("not-a-pem", key_name, "not a private key"),
        ):
            built = builder.calls
            key_refusal(push(name=name, key=key), KEY_INVALID)
            assert builder.calls == built, f"{label} reached the exchange"
            assert_unpinned(h.store)
            assert h.engine.slot.state() == "missing", label

        # The same shape refusal through the check route.
        checked = key_check(
            h.signer.post(
                client,
                "/credentials/check",
                {"key_name": "organizations/x", "private_key": pem},
                key=h.install_token,
            )
        )
        assert checked["state"] == "refused"
        assert checked["code"] == KEY_INVALID

        # A secret shorter than the minimum never reaches the engine at all.
        built = builder.calls
        short = h.signer.post(
            client,
            "/credentials",
            credentials_body(key_name, pem, "s" * 31),
            key=h.install_token,
        )
        assert short.status_code == 422, short.text
        assert short.json().get("code") == INVALID, short.text
        assert short.json().get("fields") == ["approve_secret"], short.text
        assert builder.calls == built
        assert_unpinned(h.store)

        # An ok key still connects after every refusal above.
        assert connected(push(perms=permissions(PORTFOLIO_A))).get("state") == "ok"


def test_duplicate_keys_refused(tmp_path):
    """A body that names the same key twice installs nothing, whatever it says.

    The bytes are signed exactly as sent, so the MAC gate passes and it is the
    duplicate key itself that is refused: a JSON object that names a field twice
    has no single value for it, and a body carrying two approval secrets is not a
    body to pin one from.  The answer names the duplicated field when this build
    has such a field, and names nothing at all when it has not — never a value.
    """
    h = build_engine(tmp_path / "duplicate-keys")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    first_secret = approve_secret()
    second_secret = approve_secret()

    def body_naming_twice(field: str, value: Any, again: Any) -> bytes:
        """One JSON body with `field` present twice, built as raw bytes."""
        pairs = [
            f'"key_name": {json.dumps(key_name)}',
            f'"private_key": {json.dumps(pem)}',
            f'"approve_secret": {json.dumps(first_secret)}',
            f"{json.dumps(field)}: {json.dumps(value)}",
            f"{json.dumps(field)}: {json.dumps(again)}",
        ]
        return ("{" + ", ".join(pairs) + "}").encode("utf-8")

    cases = (
        ("approve_secret", second_secret, first_secret, ["approve_secret"]),
        ("key_name", key_name_canary(), key_name, ["key_name"]),
        ("surprise", "value-a", "value-b", []),
    )

    with h.client() as client:
        for field, value, again, fields in cases:
            raw = body_naming_twice(field, value, again)
            headers = h.signer.headers(h.install_token, "POST", "/credentials", raw)
            response = client.post("/credentials", content=raw, headers=headers)
            assert response.status_code == 422, f"{field}: {response.text}"
            body = response.json()
            assert set(body) == {"code", "fields"}, body
            assert body["code"] == INVALID, body
            assert body["fields"] == fields, body
            for echoed in (key_name, first_secret, second_secret, marker, value):
                assert echoed not in response.text, f"{field}: {response.text}"
            assert_unpinned(h.store)
            assert h.builder.calls == 0, f"{field} built an adapter"
            assert h.engine.slot.state() == "missing", field


# ---------------------------------------------------------------- one parse of the body


def raw_post(h, client, raw: bytes, *, key, nonce=None, ts=None):
    """POST *raw* to `/credentials`, signed over exactly those bytes."""
    headers = h.signer.headers(key, "POST", "/credentials", raw, nonce=nonce, ts=ts)
    return client.post("/credentials", content=raw, headers=headers)


def invalid_fields(response) -> list[str]:
    """A `422 INVALID` refusal: the code, the fields, and nothing else in the body."""
    assert response.status_code == 422, response.text
    body = response.json()
    assert set(body) == {"code", "fields"}, body
    assert body["code"] == INVALID, body
    return body["fields"]


def test_credentials_body_parsed_once(tmp_path):
    """`POST /credentials` reads the captured bytes once and refuses what it cannot read.

    The bytes are signed exactly as sent, so the MAC covers the request that
    arrived and it is the body itself that is refused: bytes that are not UTF-8,
    text that does not parse as JSON — a leading BOM, an empty body, a truncated
    one — a JSON value that is not an object, and a body that names
    `approve_secret` twice.  Each answers the one `422` carrying the code
    `INVALID` and the fields that failed, none at all for a body that never
    became an object; none of them pins anything, builds an adapter, or echoes a
    value of the request.  The same bytes, readable, still connect.
    """
    h = build_engine(tmp_path / "parsed-once")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    secret = approve_secret()
    canary = "value-" + secrets.token_hex(8)

    good = json.dumps(credentials_body(key_name, pem, secret)).encode("utf-8")
    # One string value replaced by bytes that are not UTF-8 at all.
    invalid_utf8 = good.replace(
        secret.encode("utf-8"),
        b"approve-" + b"\xff\xfe" + secrets.token_hex(8).encode("ascii"),
    )
    duplicated = (
        "{"
        + ", ".join(
            [
                f'"key_name": {json.dumps(key_name)}',
                f'"private_key": {json.dumps(pem)}',
                f'"approve_secret": {json.dumps(secret)}',
                f'"approve_secret": {json.dumps(secret + canary)}',
            ]
        )
        + "}"
    ).encode("utf-8")

    cases = [
        ("invalid utf-8", invalid_utf8, []),
        ("a leading BOM", b"\xef\xbb\xbf" + good, []),
        ("a JSON array", json.dumps([key_name, pem, secret]).encode("utf-8"), []),
        ("a JSON string", json.dumps(secret).encode("utf-8"), []),
        ("a JSON number", b"7", []),
        ("JSON null", b"null", []),
        ("an empty body", b"", []),
        ("a truncated body", good[: len(good) // 2], []),
        ("a repeated approve_secret", duplicated, ["approve_secret"]),
    ]

    with h.client() as client:
        for label, raw, fields in cases:
            response = raw_post(h, client, raw, key=h.install_token)
            assert invalid_fields(response) == fields, label
            for value in (key_name, secret, canary, marker, h.install_token):
                assert value not in response.text, label
            assert_unpinned(h.store)
            assert h.builder.calls == 0, label
            assert h.engine.slot.state() == "missing", label

        # The bearer token is still asked for first: the same unreadable bytes
        # with no bearer token are a 401, and pin nothing either.
        headers = h.signer.headers(
            h.install_token, "POST", "/credentials", invalid_utf8
        )
        headers.pop("Authorization")
        with h.client(bearer=False) as bare:
            unauthorized = bare.post(
                "/credentials", content=invalid_utf8, headers=headers
            )
        assert unauthorized.status_code == 401, unauthorized.text
        assert_unpinned(h.store)

        connected(raw_post(h, client, good, key=h.install_token))
        assert h.builder.calls == 1
        assert pin_row(h.store) is not None


def test_credentials_body_read_from_the_one_parse(tmp_path):
    """A body another parser could read is still refused when the gate's parse cannot.

    These are the bytes of one valid JSON object, encoded as UTF-16 with a BOM.
    A JSON parser handed bytes detects that encoding and reads the object; the
    route's own parse is over the decoded text, and these bytes are not UTF-8.
    The request is answered as an unreadable body — no field named, nothing
    pinned, no adapter built — so the object the route acts on is always the one
    the gate read.
    """
    h = build_engine(tmp_path / "one-parse")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    secret = approve_secret()
    raw = json.dumps(credentials_body(key_name, pem, secret)).encode("utf-16")

    with h.client() as client:
        response = raw_post(h, client, raw, key=h.install_token)
        assert invalid_fields(response) == []
        for value in (key_name, secret, marker, h.install_token):
            assert value not in response.text
        assert_unpinned(h.store)
        assert h.builder.calls == 0
        assert h.engine.slot.state() == "missing"


def test_secret_mismatch_rate_limited(tmp_path):
    """Five wrong secrets lock `POST /credentials` out for a minute, and nothing else counts.

    The body secret is the only thing a wrong answer is about, so five of them in a
    minute is enough to stop answering the route for a minute — a request that
    carries the pinned secret in its body but a MAC keyed by something else
    included, since a caller guessing secrets is not one that has to be answered
    quickly.  Refusals of another kind do not count: the clock is the engine's
    own, so the window is a thing this test can pass.
    """
    h = build_engine(tmp_path / "rate-limit")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    pinned_secret = approve_secret()
    other_secret = approve_secret()

    def body_with(secret: str) -> dict:
        return credentials_body(key_name, pem, secret)

    with h.client() as client:
        connected(
            h.signer.post(client, "/credentials", body_with(pinned_secret), key=h.install_token)
        )

        # A refusal that is not a secret mismatch — the right secret in the body,
        # MAC'd with a key that is not it — never counts towards the lockout.
        wrong_mac = "other-" + secrets.token_hex(20)
        for _ in range(5):
            refusal(
                h.signer.post(client, "/credentials", body_with(pinned_secret), key=wrong_mac),
                APPROVAL_INVALID,
            )
        connected(h.signer.post(client, "/credentials", body_with(pinned_secret), key=pinned_secret))

        for _ in range(5):
            refusal(
                h.signer.post(client, "/credentials", body_with(other_secret), key=other_secret),
                SECRET_MISMATCH,
            )

        # The pinned secret in the body, MAC'd with a key that is not it: the
        # lockout answers it, and echoes nothing of the body.
        limited = h.signer.post(
            client, "/credentials", body_with(pinned_secret), key=wrong_mac
        )
        assert limited.status_code == 429, limited.text
        assert RATE_LIMITED in limited.text, limited.text
        for value in (pinned_secret, other_secret, marker, key_name):
            assert value not in limited.text, limited.text

        # Still locked a second before the minute is out, and served after it.
        h.clock[0] += 59
        still_limited = h.signer.post(
            client, "/credentials", body_with(pinned_secret), key=wrong_mac
        )
        assert still_limited.status_code == 429, still_limited.text
        assert RATE_LIMITED in still_limited.text, still_limited.text

        h.clock[0] += 2
        connected(
            h.signer.post(client, "/credentials", body_with(pinned_secret), key=pinned_secret)
        )

        # And the pin never moved while all of that was answered.
        assert h.store.get(PIN_KEY) == hashlib.sha256(pinned_secret.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- the lockout and the pinned secret


def lockout_events(store: Store) -> list[dict]:
    """Every event carrying the lockout's own sentence, oldest first."""
    rows = store.conn().execute(
        "SELECT level, kind, message FROM events WHERE message=? ORDER BY id",
        (auth_module.LOCKOUT_MESSAGE,),
    ).fetchall()
    return [dict(row) for row in rows]


def test_lockout_does_not_block_the_pinned_secret(tmp_path):
    """The lockout shuts a guesser out, not a push that carries and signs the pinned secret.

    Five wrong secrets lock `POST /credentials` for a minute.  While that stands,
    a request whose body secret hashes to the pin and whose MAC matches that
    secret is served as it always was, and the lockout is cleared; every other
    request is still `429` — the pinned secret with a MAC keyed by something
    else, the pinned secret with a stamp outside the window, and a wrong secret.
    Those refusals write no event and do not move the end of the lockout, which
    stays the minute from the fifth wrong secret.  A push served during a
    lockout spends its nonce like any other.
    """
    h = build_engine(tmp_path / "lockout-pinned")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    pinned_secret = approve_secret()
    other_secret = approve_secret()
    digest = hashlib.sha256(pinned_secret.encode("utf-8")).hexdigest()

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
        connected(
            h.signer.post(
                client,
                "/credentials",
                body_with(pinned_secret),
                key=h.install_token,
            )
        )
        assert h.store.get(PIN_KEY) == digest
        assert lockout_events(h.store) == []

        # Five wrong secrets, each keyed by itself: the lockout, and its one event.
        for _ in range(5):
            failure = push(client, other_secret)
            assert failure.status_code == 403, failure.text
            assert SECRET_MISMATCH in failure.text, failure.text
        assert len(lockout_events(h.store)) == 1
        event = lockout_events(h.store)[0]
        assert event["level"] == "warn"
        assert event["kind"] == "credentials"

        # (a) The pinned secret, signed with itself, is served while locked, and
        # the lockout is cleared: the next wrong secret is a 403, not a 429.
        connected(push(client, pinned_secret))
        assert len(lockout_events(h.store)) == 1
        after = push(client, other_secret)
        assert after.status_code == 403, after.text
        assert SECRET_MISMATCH in after.text, after.text

        # (b) Four more wrong secrets lock the route again: the wrong secret
        # above was the first of the five.
        for _ in range(4):
            failure = push(client, other_secret)
            assert failure.status_code == 403, failure.text
        assert len(lockout_events(h.store)) == 2
        locked_at = h.clock[0]

        # Half a minute into the lockout, the pinned secret with a MAC keyed by
        # something else, the pinned secret with a stale stamp, and a wrong
        # secret are all 429 — and none of them writes an event.
        h.clock[0] = locked_at + 30
        bad_mac = "other-" + secrets.token_hex(20)
        for label, response in (
            ("a MAC keyed by something else", push(client, pinned_secret, key=bad_mac)),
            ("a stale stamp", push(client, pinned_secret, ts=int(locked_at) - 10_000)),
            ("a wrong secret", push(client, other_secret)),
        ):
            assert response.status_code == 429, label
            assert RATE_LIMITED in response.text, label
            for value in (pinned_secret, other_secret, marker, key_name):
                assert value not in response.text, label
        assert len(lockout_events(h.store)) == 2
        assert h.store.get(PIN_KEY) == digest

        # The lockout still ends a minute after the fifth wrong secret: nothing
        # above moved it, so the push one second past it is served.
        h.clock[0] = locked_at + 61
        connected(push(client, pinned_secret))

        # (c) A push served during a lockout spends its nonce like any other.
        for _ in range(5):
            failure = push(client, other_secret)
            assert failure.status_code == 403, failure.text
        assert len(lockout_events(h.store)) == 3
        nonce = h.signer.nonce()
        connected(push(client, pinned_secret, nonce=nonce))
        refusal(push(client, pinned_secret, nonce=nonce), APPROVAL_INVALID)
        assert len(lockout_events(h.store)) == 3

    # The pin never moved, and no event carries a secret or a key.
    assert h.store.get(PIN_KEY) == digest
    for event in lockout_events(h.store):
        text = " ".join(str(value) for value in event.values())
        for value in (pinned_secret, other_secret, key_name, marker, h.install_token):
            assert value not in text, event


# ---------------------------------------------------------------- nothing leaks


def test_secrets_never_on_disk_or_in_responses(tmp_path, caplog):
    """No secret reaches a file, a log line, an event or a response body."""
    caplog.set_level(logging.DEBUG)
    h = build_engine(tmp_path / "leaks")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    secret = approve_secret()
    canary = "value-" + secrets.token_hex(8)

    bodies: list[str] = []
    with h.client() as client:
        installed = h.signer.post(
            client,
            "/credentials",
            credentials_body(key_name, pem, secret),
            key=h.install_token,
        )
        bodies.append(installed.text)
        assert installed.status_code == 200, installed.text

        checked = h.signer.post(
            client,
            "/credentials/check",
            {"key_name": key_name, "private_key": pem},
            key=secret,
        )
        bodies.append(checked.text)

        # A body this build cannot read: the fields are named, and no value of it
        # is echoed back.
        malformed = h.signer.post(
            client,
            "/credentials",
            dict(credentials_body(key_name, pem, secret), surprise=canary),
            key=secret,
        )
        bodies.append(malformed.text)
        assert malformed.status_code == 422, malformed.text
        body = malformed.json()
        assert set(body) == {"code", "fields"}, body
        assert body["code"] == INVALID
        assert body["fields"] == ["surprise"], body
        assert canary not in malformed.text

        # A refusal, and the anonymous health body.
        refused = h.signer.post(
            client,
            "/credentials/check",
            {"key_name": key_name, "private_key": pem},
            key=h.install_token,
        )
        bodies.append(refused.text)
        refusal(refused, APPROVAL_INVALID)

    with h.client(bearer=False) as anonymous:
        healthy = anonymous.get("/health")
        bodies.append(healthy.text)
        assert healthy.status_code == 200, healthy.text

    # Nothing in any response body carries a value the request sent.
    for text in bodies:
        for value in (marker, key_name, secret, h.install_token):
            assert value not in text, text

    # Nothing on disk does either: the sqlite file, its journal, and whatever
    # else sits beside them.
    blob = data_bytes(h.data_dir)
    for value in (marker, key_name, secret, h.install_token):
        assert value.encode() not in blob, value

    # Nothing in the log does, at DEBUG.
    logged = caplog.text
    for value in (marker, key_name, secret, h.install_token):
        assert value not in logged, logged

    # Nothing in the events table does.
    for message in event_messages(h.store):
        for value in (marker, key_name, secret, h.install_token):
            assert value not in message, message

    # And the pin really is a hash, not the secret.
    assert h.store.get(PIN_KEY) == hashlib.sha256(secret.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- validation shape


def test_validation_errors_have_no_values(tmp_path):
    """A 422 names the fields that failed and never a value that was sent."""
    h = build_engine(tmp_path / "validation")
    canary = "value-" + secrets.token_hex(8)
    key_name = key_name_canary()
    pem, _marker = private_key_canary()

    with h.client() as client:
        bots = client.post(
            "/bots",
            json={
                "id": BOT,
                "product": PRODUCT,
                "strategy": "grid",
                "params": {"center": "1.0"},
                "capital_quote": "60",
                "capital_base": "30",
                "mystery": canary,
            },
        )
        assert bots.status_code == 422, bots.text
        bots_body = bots.json()
        assert set(bots_body) == {"code", "fields"}, bots_body
        assert bots_body["code"] == INVALID
        assert bots_body["fields"] == ["mystery"], bots_body
        assert canary not in bots.text
        assert "detail" not in bots_body

        credentials = h.signer.post(
            client,
            "/credentials",
            dict(
                credentials_body(key_name, pem, approve_secret()), mystery=canary
            ),
            key=h.install_token,
        )
        assert credentials.status_code == 422, credentials.text
        body = credentials.json()
        assert set(body) == {"code", "fields"}, body
        assert body["code"] == INVALID
        assert body["fields"] == ["mystery"], body
        assert canary not in credentials.text
        assert "detail" not in body

    # Neither refusal wrote anything.
    assert h.store.list_bots() == []
    assert_unpinned(h.store)


# ---------------------------------------------------------------- the routes


def test_credentials_routes_classified(tmp_path):
    """The three routes exist, and the bearer token alone is not an approval."""
    h = build_engine(tmp_path / "routes")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    routes = set()
    for route in h.engine.app.routes:
        for method in getattr(route, "methods", ()) or ():
            routes.add((method, getattr(route, "path", "")))
    for wanted in (
        ("POST", "/credentials"),
        ("POST", "/credentials/check"),
        ("DELETE", "/credentials"),
    ):
        assert wanted in routes, sorted(routes)

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )

        refusal(
            client.post(
                "/credentials",
                json=credentials_body(key_name, pem, secret),
                headers=HEADERS,
            ),
            APPROVAL_INVALID,
        )
        refusal(
            client.post(
                "/credentials/check",
                json={"key_name": key_name, "private_key": pem},
                headers=HEADERS,
            ),
            APPROVAL_INVALID,
        )
        refusal(client.delete("/credentials", headers=HEADERS), APPROVAL_INVALID)


# ---------------------------------------------------------------- disconnecting


def test_disconnect_refused_with_live_orders(tmp_path):
    """A resting live order holds the credentials; with none, the route goes with them."""
    h = build_engine(tmp_path / "disconnect")
    make_live_bot(h.store)
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()
    cid = "cb-b1-B+1-aaaaaaaaaaaa"

    with h.client() as client:
        # No approval at all: the strict gate refuses whatever is asked.
        refusal(client.delete("/credentials", headers=HEADERS), APPROVAL_INVALID)

        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        assert live_route(h.engine) != LIVE_LOCKED

        # A live order written but not yet resolved (a submit in flight) cannot be
        # settled without the key either, so it holds the credentials too.
        pending_cid = "cb-b1-B+1-bbbbbbbbbbbb"
        h.store.insert_order(
            pending_cid,
            BOT,
            "bot",
            PRODUCT,
            "BUY",
            1,
            D("0.98"),
            D("10"),
            status=PENDING_SUBMIT,
            book="live",
            product_type="SPOT",
        )
        pending = h.signer.delete(client, "/credentials", key=secret)
        assert pending.status_code == 409, pending.text
        assert LIVE_ORDERS_OPEN in pending.text
        assert health(client)["credentials"] == "ready"
        assert live_route(h.engine) != LIVE_LOCKED
        h.store.conn().execute(
            "DELETE FROM orders WHERE client_order_id=?", (pending_cid,)
        )

        h.store.insert_order(
            cid,
            BOT,
            "bot",
            PRODUCT,
            "BUY",
            1,
            D("0.98"),
            D("10"),
            status=OPEN,
            book="live",
            product_type="SPOT",
        )

        resting = h.signer.delete(client, "/credentials", key=secret)
        assert resting.status_code == 409, resting.text
        assert LIVE_ORDERS_OPEN in resting.text
        assert health(client)["credentials"] == "ready"
        assert live_route(h.engine) != LIVE_LOCKED

        # The order is done with, so the credentials may go.
        h.store.conn().execute(
            "DELETE FROM orders WHERE client_order_id=?", (cid,)
        )
        removed = h.signer.delete(client, "/credentials", key=secret)
        assert removed.status_code == 200, removed.text
        assert removed.json() == {"state": "missing", "pinned": True}

        # The route is locked again, the pin stays, and the install token is
        # still no key.
        assert health(client)["credentials"] == "not_ready"
        assert health(client)["pinned"] is True
        assert live_route(h.engine) == LIVE_LOCKED
        assert pin_row(h.store) is not None
        refusal(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            ),
            APPROVAL_INVALID,
        )


# ---------------------------------------------------------------- forgetting the pin


# The refusal a forget answers while a bot trades the live book, or while the
# AI's switch allows its own live route.
LIVE_BOTS = "LIVE_BOTS"


def forget(h, client, *, key, body=None):
    """POST /credentials/forget, signed over the bytes it sends (usually none)."""
    return h.signer.post(client, "/credentials/forget", body, key=key)


def switches(store: Store) -> tuple[bool, bool]:
    """Both live switches as `Switches` reads them: the JSON true, or off."""
    return (store.get(SWITCH_LIVE) is True, store.get(SWITCH_AI_LIVE) is True)


def pin_state(store: Store) -> tuple:
    """Everything a connect writes, plus both switches, as one comparable value."""
    return (
        store.get(PIN_KEY),
        store.get(PORTFOLIO_KEY),
        store.get(EPOCH_KEY),
        store.get(SWITCH_LIVE),
        store.get(SWITCH_AI_LIVE),
    )


def last_event_id(store: Store) -> int:
    """The id of the newest event the engine holds, and 0 when it holds none."""
    row = store.conn().execute("SELECT MAX(id) FROM events").fetchone()
    return 0 if row is None or row[0] is None else int(row[0])


def events_after(store: Store, event_id: int) -> list[dict]:
    """Every event newer than *event_id*, oldest first."""
    rows = store.conn().execute(
        "SELECT id, level, kind, message, data_json FROM events WHERE id>? ORDER BY id",
        (event_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def live_bots_refusal(response) -> dict:
    """A 409 whose detail is the live-bots refusal: the code, then plain words."""
    assert response.status_code == 409, response.text
    body = response.json()
    detail = body.get("detail")
    assert isinstance(detail, str), response.text
    assert detail.startswith(f"{LIVE_BOTS}: "), detail
    assert len(detail) > len(LIVE_BOTS) + 2, detail
    assert "practice" in detail.lower(), detail
    return body


def test_forget_requires_owner_mac(tmp_path):
    """Forgetting is the owner's: bearer alone, the install token and a wrong secret fail.

    Each refusal is the approval's own 403, and none of them moves the pin, the
    portfolio, the epoch, either switch or the live route: the engine is exactly
    as the connect left it.  The pinned secret forgets them.
    """
    h = build_engine(tmp_path / "forget-mac")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()
    wrong = "other-" + secrets.token_hex(20)
    assert len(wrong) >= 32, "the wrong key has to be long enough to look real"

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        before = pin_state(h.store)

        def refused(label: str, response) -> None:
            """One refusal, and the engine exactly as the connect left it."""
            refusal(response, APPROVAL_INVALID)
            assert pin_state(h.store) == before, label
            assert pin_row(h.store) is not None, label
            assert h.engine.slot.state() == "ok", label
            assert health(client)["credentials"] == "ready", label

        # The bearer token alone is not an approval.
        refused("bearer alone", client.post("/credentials/forget", headers=HEADERS))
        # The install token is never a key on this route, pinned or not.
        refused("the install token", forget(h, client, key=h.install_token))
        # A secret that is not the pinned one.
        refused("a wrong secret", forget(h, client, key=wrong))

        # The owner's own secret forgets the pin and everything a connect wrote.
        forgotten = forget(h, client, key=secret)
        assert forgotten.status_code == 200, forgotten.text
        assert forgotten.json() == {"state": "missing", "pinned": False}
        assert_unpinned(h.store)
        assert h.engine.slot.state() == "missing"
        assert health(client)["pinned"] is False
        assert health(client)["credentials"] == "not_ready"


def test_forget_refused_live_orders(tmp_path):
    """A live order on the account holds the pin where it is: 409 LIVE_ORDERS_OPEN.

    Both a resting order and one written before its submit went out hold it, and
    neither refusal moves anything: the pin, the portfolio, the epoch, the
    switch that allows live and the live route stay exactly as they were.  With
    the order row gone, the same request forgets the engine.
    """
    h = build_engine(tmp_path / "forget-orders")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        h.store.put(SWITCH_LIVE, True)
        before = pin_state(h.store)
        assert switches(h.store) == (True, False)

        def refused_with_live_orders(label: str) -> None:
            response = forget(h, client, key=secret)
            assert response.status_code == 409, f"{label}: {response.text}"
            detail = response.json().get("detail")
            assert isinstance(detail, str), f"{label}: {response.text}"
            assert detail.startswith(f"{LIVE_ORDERS_OPEN}: "), f"{label}: {detail}"
            assert len(detail) > len(LIVE_ORDERS_OPEN) + 2, f"{label}: {detail}"
            assert pin_state(h.store) == before, label
            assert h.engine.slot.state() == "ok", label
            assert health(client)["credentials"] == "ready", label

        # An order written but not yet resolved cannot be settled without the key
        # either, so it holds the credentials exactly as a resting one does.
        pending_cid = "cb-b1-B+1-cccccccccccc"
        h.store.insert_order(
            pending_cid,
            BOT,
            "bot",
            PRODUCT,
            "BUY",
            1,
            D("0.98"),
            D("10"),
            status=PENDING_SUBMIT,
            book="live",
            product_type="SPOT",
        )
        refused_with_live_orders("a submit in flight")
        h.store.conn().execute(
            "DELETE FROM orders WHERE client_order_id=?", (pending_cid,)
        )

        resting_cid = "cb-b1-B+1-dddddddddddd"
        h.store.insert_order(
            resting_cid,
            BOT,
            "bot",
            PRODUCT,
            "BUY",
            1,
            D("0.98"),
            D("10"),
            status=OPEN,
            book="live",
            product_type="SPOT",
        )
        refused_with_live_orders("a resting order")
        h.store.conn().execute(
            "DELETE FROM orders WHERE client_order_id=?", (resting_cid,)
        )

        # The order is done with, so the same request may forget the pin.
        forgotten = forget(h, client, key=secret)
        assert forgotten.status_code == 200, forgotten.text
        assert forgotten.json() == {"state": "missing", "pinned": False}
        assert_unpinned(h.store)
        assert switches(h.store) == (False, False)


def test_forget_refused_live_bot(tmp_path):
    """A live bot, and the AI's live switch on its own, both refuse a forget.

    The order the route judges is the order the engine has: a live bot trading
    the live book is `409 LIVE_BOTS` and nothing changes, and so is the AI's own
    switch with no bot on the live book at all.  Both leave the pin, the
    portfolio, the epoch, the switches and the live route where they were.
    """
    h = build_engine(tmp_path / "forget-live-bot")
    make_live_bot(h.store)
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        before = pin_state(h.store)
        assert switches(h.store) == (True, False)

        live_bots_refusal(forget(h, client, key=secret))
        assert pin_state(h.store) == before, "a refused forget moved the engine"
        assert h.engine.slot.state() == "ok"
        assert health(client)["credentials"] == "ready"

    # The AI's switch, with no bot on the live book: the same refusal.
    ai = build_engine(tmp_path / "forget-ai-live")
    ai_key_name = key_name_canary()
    ai_pem, _ai_marker = private_key_canary()
    ai_secret = approve_secret()
    ai.store.put(SWITCH_AI_LIVE, True)

    with ai.client() as client:
        connected(
            ai.signer.post(
                client,
                "/credentials",
                credentials_body(ai_key_name, ai_pem, ai_secret),
                key=ai.install_token,
            )
        )
        ai_before = pin_state(ai.store)
        assert switches(ai.store) == (False, True)

        live_bots_refusal(forget(ai, client, key=ai_secret))
        assert pin_state(ai.store) == ai_before, "a refused forget moved the engine"
        assert ai.engine.slot.state() == "ok"
        assert health(client)["credentials"] == "ready"


def test_forget_allowed_after_kill(tmp_path):
    """A kill switch leaves its live bot STOPPED, so the pin may be forgotten.

    A bot a kill stopped is a bot that cannot place, resume or switch books, so
    the key the engine would need to settle anything of its own is not being
    used by it, and the forget is not refused as `LIVE_BOTS`.  The kill's own
    sweep may fail in this harness — its live side is the fake that answers one
    permissions read and nothing else — which changes nothing here: the bot is
    STOPPED either way and no live order row exists to hold the pin.
    """
    h = build_engine(tmp_path / "forget-after-kill")
    make_live_bot(h.store)
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        before = h.store.get_bot(BOT)
        assert before["mode"] == "live"
        assert before["status"] != STOPPED

        killed = client.post("/kill")
        assert killed.status_code in (200, 502), killed.text
        assert killed.json().get("halted") is True, killed.text
        stopped = h.store.get_bot(BOT)
        assert stopped["status"] == STOPPED, stopped
        assert stopped["mode"] == "live", "a kill stops the bot, it does not move its book"

        forgotten = forget(h, client, key=secret)
        assert forgotten.status_code == 200, forgotten.text
        assert forgotten.json() == {"state": "missing", "pinned": False}
        assert_unpinned(h.store)
        assert switches(h.store) == (False, False)
        assert h.engine.slot.state() == "missing"
        assert health(client)["pinned"] is False

        # The bot row is untouched by the forget: it is the kill that stopped it.
        after = h.store.get_bot(BOT)
        assert after["status"] == STOPPED, after
        assert after["mode"] == "live", after


def test_forget_allowed_with_stopped_live_bot(tmp_path):
    """Only a live bot that could still act refuses a forget; a STOPPED one does not.

    A bot left STOPPED on the live book cannot resume or switch books, so it has
    nothing the pin is needed to settle and the forget is answered 200, taking
    the pin, the portfolio, the epoch and both switches with it.  An ACTIVE one,
    and one merely PAUSED — which its owner can resume — are still `409
    LIVE_BOTS`, and neither refusal moves anything.
    """
    h = build_engine(tmp_path / "forget-stopped-live")
    make_live_bot(h.store)
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        before = pin_state(h.store)

        # ACTIVE: the bot trades, so the pin stays.
        live_bots_refusal(forget(h, client, key=secret))
        assert pin_state(h.store) == before, "a refused forget moved the engine"
        assert h.store.get_bot(BOT)["status"] != STOPPED

        # PAUSED: its owner can resume it, so the pin stays too.
        h.store.set_bot_status(BOT, PAUSED)
        live_bots_refusal(forget(h, client, key=secret))
        assert pin_state(h.store) == before, "a refused forget moved the engine"
        assert h.engine.slot.state() == "ok"
        assert health(client)["credentials"] == "ready"

        # STOPPED: nothing can act on it, so the pin may go.
        h.store.set_bot_status(BOT, STOPPED)
        forgotten = forget(h, client, key=secret)
        assert forgotten.status_code == 200, forgotten.text
        assert forgotten.json() == {"state": "missing", "pinned": False}
        assert_unpinned(h.store)
        assert switches(h.store) == (False, False)
        assert h.engine.slot.state() == "missing"
        assert h.store.get_bot(BOT)["mode"] == "live", "the bot's book is not the forget's to move"
        assert h.store.get_bot(BOT)["status"] == STOPPED


def test_forget_clears_switches_and_portfolio(tmp_path, caplog):
    """Forget drops the pin, the portfolio, the epoch and both switches, and says so once.

    The live switch is turned on in the kv, which is where `Switches.set` writes
    it, and it reads JSON false afterwards; the AI's switch is absent before the
    forget and reads JSON false after it, so the route wrote that row rather
    than leaving it to be read as off.  The AI's switch is not turned on here
    because an engine whose AI may trade live is refused `LIVE_BOTS` (the
    live-bot test above), and a refusal writes nothing.  What is left is the engine a first
    install is: `/health` unpinned with no credentials in memory, and one info
    event of kind `credentials` recording the forget without a value of the key
    or the secret in it, in a log line or in a file.
    """
    caplog.set_level(logging.DEBUG)
    h = build_engine(tmp_path / "forget-clears")
    key_name = key_name_canary()
    pem, marker = private_key_canary()
    secret = approve_secret()

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret),
                key=h.install_token,
            )
        )
        h.store.put(SWITCH_LIVE, True)
        assert switches(h.store) == (True, False)
        assert h.store.get(SWITCH_AI_LIVE) is None, "the AI switch row was already there"
        before = last_event_id(h.store)

        # An empty JSON object is the other body this route accepts.
        forgotten = forget(h, client, key=secret, body={})
        assert forgotten.status_code == 200, forgotten.text
        assert forgotten.json() == {"state": "missing", "pinned": False}

        assert_unpinned(h.store)
        assert h.store.get(SWITCH_LIVE) is False, "the live switch is not JSON false"
        assert h.store.get(SWITCH_AI_LIVE) is False, "the AI switch is not JSON false"
        assert switches(h.store) == (False, False)
        assert h.engine.slot.state() == "missing"
        assert h.engine.gateway.books.live_available() is False

        after = health(client)
        assert after["pinned"] is False
        assert after["credentials"] == "not_ready"

        written = events_after(h.store, before)
        assert len(written) == 1, written
        event = written[0]
        assert event["level"] == "info", event
        assert event["kind"] == "credentials", event
        message = str(event["message"])
        assert "forgotten" in message.lower(), event
        for value in (secret, key_name, marker, h.install_token):
            assert value not in message, event
            assert value not in str(event.get("data_json") or ""), event
            assert value not in forgotten.text, value
            assert value not in caplog.text, value

    # Nothing of the key or the secret became a file either.
    blob = data_bytes(h.data_dir)
    for value in (secret, key_name, marker, h.install_token):
        assert value.encode() not in blob, value


def test_first_pin_after_forget_with_install_token(tmp_path):
    """A forget makes the engine a first install again: the token pins, with a new epoch.

    The engine epoch is the answer that tells a client "a different engine" from
    "the same one pushed again", so the epoch a forget leaves is not the one a
    later connect answers with: the forget deleted the row, and the next first
    connect writes a fresh one.
    """
    h = build_engine(tmp_path / "forget-first-pin")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret_a = approve_secret()
    secret_b = approve_secret()
    assert secret_a != secret_b

    with h.client() as client:
        first = connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret_a),
                key=h.install_token,
            )
        )
        assert h.builder.calls == 1
        assert h.store.get(PIN_KEY) == hashlib.sha256(
            secret_a.encode("utf-8")
        ).hexdigest()

        assert forget(h, client, key=secret_a).status_code == 200
        assert_unpinned(h.store)
        assert h.engine.slot.state() == "missing"

        # The install token is a key again, and a NEW approval secret pins.
        repinned = connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret_b),
                key=h.install_token,
            )
        )
        assert repinned["engine_epoch"] != first["engine_epoch"]
        assert h.store.get(EPOCH_KEY) == repinned["engine_epoch"]
        assert h.store.get(PIN_KEY) == hashlib.sha256(
            secret_b.encode("utf-8")
        ).hexdigest()
        assert h.store.get(PORTFOLIO_KEY) == PORTFOLIO_A
        assert h.builder.calls == 2, "the live route was not built again"
        assert health(client)["credentials"] == "ready"

        # And the token is no key for the next push again: the pin is back.
        refusal(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret_b),
                key=h.install_token,
            ),
            APPROVAL_INVALID,
        )
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret_b),
                key=secret_b,
            )
        )


def test_old_secret_refused_after_repin(tmp_path):
    """A forget and a re-pin retire the old secret: the new one is the only key.

    The rail holds the secret the pin was made with, so a privileged call MAC'd
    with the secret a forget dropped is the uniform `403 APPROVAL_INVALID` — a
    switch it names is not written — and the same call keyed with the new secret
    is served.
    """
    h = build_engine(tmp_path / "forget-old-secret")
    key_name = key_name_canary()
    pem, _marker = private_key_canary()
    secret_a = approve_secret()
    secret_b = approve_secret()
    assert secret_a != secret_b

    with h.client() as client:
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret_a),
                key=h.install_token,
            )
        )
        assert forget(h, client, key=secret_a).status_code == 200
        connected(
            h.signer.post(
                client,
                "/credentials",
                credentials_body(key_name, pem, secret_b),
                key=h.install_token,
            )
        )

        # The old secret keys nothing: a switch it names is not written, and a
        # disconnect it signs does not drop the route.
        refusal(
            h.signer.post(
                client, "/switches", {SWITCH_LIVE: True}, key=secret_a
            ),
            APPROVAL_INVALID,
        )
        assert switches(h.store) == (False, False), "a refused call moved a switch"
        refusal(h.signer.delete(client, "/credentials", key=secret_a), APPROVAL_INVALID)
        assert health(client)["credentials"] == "ready"
        assert pin_row(h.store) is not None

        # The new secret is the key the rail holds.
        turned = h.signer.post(
            client, "/switches", {SWITCH_LIVE: True}, key=secret_b
        )
        assert turned.status_code == 200, turned.text
        assert switches(h.store) == (True, False)
        removed = h.signer.delete(client, "/credentials", key=secret_b)
        assert removed.status_code == 200, removed.text
        assert removed.json() == {"state": "missing", "pinned": True}


# ---------------------------------------------------------------- the watchdog


class WatchExchange:
    """What the watchdog's sweep would use: it records every list and cancel."""

    def __init__(self) -> None:
        self.listed = 0
        self.cancelled: list[list] = []

    def list_open_orders(self, product=None):
        self.listed += 1
        return [
            {
                "order_id": "oid-1",
                "client_order_id": "cb-b1-B+1-aaaaaaaaaaaa",
                "product": PRODUCT,
            }
        ]

    def cancel(self, order_ids):
        ids = list(order_ids)
        self.cancelled.append(ids)
        return {order_id: True for order_id in ids}


class WatchFactory:
    """A counting exchange factory: the sweep is what would call it."""

    def __init__(self) -> None:
        self.calls = 0
        self.exchange = WatchExchange()

    def __call__(self):
        self.calls += 1
        return self.exchange


class SteppingClock:
    """`start` for the watchdog's construction, `later` for every pass after it."""

    def __init__(self, start: float, later: float) -> None:
        self.start = float(start)
        self.later = float(later)
        self.reads = 0

    def __call__(self) -> float:
        self.reads += 1
        return self.start if self.reads == 1 else self.later


WATCH_POLL = 10
WATCH_ENV = {
    "CROW_COINBASE_LIVE": "true",
    "CROW_COINBASE_WATCHDOG_POLICY": "cancel",
    "CROW_COINBASE_POLL_SECONDS": str(WATCH_POLL),
}


def run_watchdog(root, *, live_switch: bool):
    """One watchdog run over *root* at a stale heartbeat; answers (code, factory, store)."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    store = Store(root / "engine.sqlite")
    store.put("live_enabled", live_switch)
    (root / "heartbeat").write_text(
        json.dumps({"ts": NOW - 10_000, "cycle": 1, "bots_active": 0, "errors": []}),
        encoding="utf-8",
    )

    factory = WatchFactory()
    clock = SteppingClock(NOW, NOW + watchdog_module.STALE_FACTOR * WATCH_POLL + 1)
    env = dict(WATCH_ENV, CROW_COINBASE_DATA_DIR=str(root))
    code = watchdog_module.main(
        env,
        exchange_factory=factory,
        sleep=lambda seconds: None,
        now=clock,
        max_checks=2,
    )
    return code, factory, Store(root / "engine.sqlite")


def alerts(store: Store) -> list[str]:
    rows = store.conn().execute(
        "SELECT message FROM events WHERE level='ALERT' ORDER BY id"
    ).fetchall()
    return [str(row["message"]) for row in rows]


def test_watchdog_runs_when_live_alert_only(tmp_path):
    """Live trading is allowed, so the watchdog alerts, sweeps nothing and runs on."""
    code, factory, store = run_watchdog(tmp_path / "live", live_switch=True)

    assert code == 0
    assert factory.calls == 0, "the watchdog swept a live account"
    messages = alerts(store)
    assert len(messages) == 1, messages
    assert NOT_CANCELLED in messages[0], messages[0]


def test_watchdog_sweeps_when_live_is_off(tmp_path):
    """With the switch off the watchdog keeps the behaviour it always had."""
    code, factory, store = run_watchdog(tmp_path / "dry", live_switch=False)

    assert code == 0
    assert factory.calls == 1, "the sweep never ran"
    assert factory.exchange.cancelled, "the sweep asked for no cancel"
    messages = alerts(store)
    assert len(messages) == 1, messages
    assert NOT_CANCELLED not in messages[0], messages[0]


# ---------------------------------------------------------------- the module


def credentials_module():
    """The credentials module, imported where a test needs it."""
    import crow_coinbase.credentials as module

    return module