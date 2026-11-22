"""test_privileged_auth.py: the approval MAC, its nonces, the install token and the lease.

Every test here serves the engine's real pieces — `test_books.Engine`, so a real
`Store`, a real dry-run exchange, gateway and runner — through `create_app` with
the engine's own `Authenticator` wired in as `auth`, the way `build_app` wires
it, so a privileged request has to present the bearer token and a MAC over the
exact bytes it sends, and the install token is a key only on the routes that
admit it.  The clock is a `Clock` the test moves by hand, so the timestamp
window, the nonce retention and the lease TTL are driven from it rather than
from the wall clock, and the install token comes from a temporary file whose
value is built at runtime by `synthetic_secret`.

`Signer` is the one place a request is signed: the bytes it hands `compute_mac`
are the bytes `TestClient` sends, and each request gets a fresh nonce unless the
test names one.

What each test pins down:

* the fixture's MAC vectors, so `string_to_sign` and `compute_mac` agree with an
  independent computation of the same string,
* which routes need the bearer token alone and which need the MAC as well, and
  that no mutating route is left unclassified,
* a replayed nonce, a tampered body, path, query string or method, and a
  timestamp outside the window,
* nonces living in the store, so they survive a restart, and the retention
  window,
* which key a request is compared against: the in-memory approval secret, the
  install token file, or nothing at all — a pin in the store takes the install
  token out of the rail for good, and only a secret in memory puts a key back,
* that a pin is a kv ROW and not a value: a row holding JSON null, an object, a
  number or an empty string pins the engine exactly as a hash does, and only an
  absent row leaves the install token a key,
* that the install token signs the lease routes and nothing else: a switch, a
  mode, a cleared halt and a live bot's recenter or resume need the secret,
* that a secret and an install token shorter than 32 bytes are no key at all,
* that every refusal is the same 403 carrying no secret, and that a missing or
  empty token file refuses rather than raises,
* that a spent nonce's row carries the request's own stamp, and that the purge
  records the cutoff it used as the kv `nonce_floor` the rail refuses any older
  stamp against — so a clock that jumps forth and back, far enough for the row
  itself to be pruned, still cannot re-admit a captured request,
* that a stored `nonce_floor` which is not a number is read as 0 instead of
  raised on: it refuses nothing, and the next purge leaves a real cutoff there,
* the lease: one holder at a time, a takeover after its TTL, a monotonic cursor
  that survives a reopen, and a cursor only the live holder may move, and only
  as far as the newest event the engine holds,
* that event retention never deletes past the lease cursor, and never raises on
  a cursor a hand-edited store left behind,
* that `build_app` takes the token path from the environment and reads the pin
  out of the store on every call,
* that an injected one-argument approval still gates every privileged route.
"""

from __future__ import annotations

import contextlib
import hashlib
import itertools
import json
import logging
import secrets
import sys
from dataclasses import dataclass
from decimal import Decimal as D
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from crow_coinbase.__main__ import build_app
from crow_coinbase.api import create_app
from crow_coinbase.books import APPROVAL_INVALID, LIVE_NEEDS_OWNER
from crow_coinbase.store import Store

# The engine harness lives beside this file, in `test_books.py`.
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from test_books import BOT, PRODUCT, SPEC, Engine  # noqa: E402

# 32+ characters, no whitespace: the shortest bearer token the engine starts with.
BEARER_TOKEN = "test-token-" + "z" * 32
BEARER = f"Bearer {BEARER_TOKEN}"
HEADERS = {"Authorization": BEARER}

# The refusal a privileged route answers when the approval says no.
APPROVAL = {"detail": APPROVAL_INVALID}

# Every failure of the approval rail is this one 403 with this one detail; a live
# bot's recenter/resume report it as LIVE_NEEDS_OWNER (api.py's own wrapping).
OWNER_REFUSALS = (APPROVAL_INVALID, LIVE_NEEDS_OWNER)

# The injected clock every test starts from, and the windows the code holds to.
NOW = 1_700_000_000.0
LEASE_TTL_S = 60.0
NONCE_RETENTION_S = 300.0

# The two refusals a cursor can earn besides the approval's 403: the lease is
# not this holder's, and the cursor points past the newest event there is.
LEASE_NOT_HELD = "LEASE_NOT_HELD"
CURSOR_AHEAD = "CURSOR_AHEAD"

# The install token path `Authenticator.from_env` falls back to.
DEFAULT_INSTALL_TOKEN = Path("/run/secrets/install_token")

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mac-vectors.json"

# A route that mutates state and how it is classified, by METHOD and path: the
# privileged ones carry the approval dependency — the strict gate, the lease
# gate, or the credentials push's `require_credentials` — and the bearer-only
# ones carry the bearer check alone (the rest of a live bot's approval happens
# inside the handler).  The method is part of the key because `/credentials` is
# two routes with two different gates: POST carries `require_credentials`, its
# own approval dependency, and DELETE carries the strict approval.
PRIVILEGED_PATHS = frozenset(
    {
        ("POST", "/bots/{bot_id}/mode"),
        ("POST", "/switches"),
        ("POST", "/halt/clear"),
        ("POST", "/lease"),
        ("POST", "/lease/cursor"),
        ("POST", "/caps"),
        ("POST", "/ai/previews/{preview_id}/approve"),
        ("POST", "/credentials"),
        ("POST", "/credentials/check"),
        ("DELETE", "/credentials"),
        ("POST", "/credentials/forget"),
    }
)
BEARER_ONLY_PATHS = frozenset(
    {
        ("POST", "/bots"),
        ("POST", "/bots/{bot_id}/pause"),
        ("POST", "/bots/{bot_id}/resume"),
        ("POST", "/bots/{bot_id}/stop"),
        ("POST", "/bots/{bot_id}/recenter"),
        ("POST", "/kill"),
        ("POST", "/ai/previews"),
        ("POST", "/ai/previews/{preview_id}/reject"),
        ("POST", "/ai/orders/{cid}/cancel"),
    }
)
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# The dependencies an approval gate can be called by: the strict gate the
# privileged routes use, and the second one the lease routes use with the
# install token admitted.  The rest are the spellings an app that wired the rail
# directly would carry.
APPROVAL_DEPENDENCIES = frozenset(
    {"_approval_gate", "require_privileged", "require", "_install_ok_gate"}
)
# A dependency name carrying one of these is an approval too, whatever the gate
# beside it is called.
APPROVAL_NAME_PARTS = ("approval", "privileged", "install_ok", "install-ok", "lease")
# The bearer check `create_app` puts on every route; a mutating route that
# resolves anything besides it carries a gate of its own, whatever that gate is
# named.
BEARER_CHECK = "_check_token"


# ---------------------------------------------------------------- plumbing


def auth_module():
    """The approval module, imported where a test needs it."""
    import crow_coinbase.auth as module

    return module


class Clock:
    """A clock the test moves by hand."""

    def __init__(self, at: float = NOW):
        self.at = float(at)

    def __call__(self) -> float:
        return self.at

    def advance(self, seconds: float) -> float:
        self.at += float(seconds)
        return self.at


def synthetic_secret() -> str:
    """A plain random string, built at runtime: test data, never a real secret."""
    return "runtime-" + secrets.token_hex(16)


def owner_secret() -> bytes:
    """A 32-byte approval secret, built at runtime: test data, never a real one."""
    return secrets.token_hex(16).encode("utf-8")


def pin_value() -> str:
    """A pin as 4b writes it: the sha256 hex of an approval secret, built here."""
    return hashlib.sha256(synthetic_secret().encode("utf-8")).hexdigest()


def pin(store) -> str:
    """Persist a pin in *store*'s kv under the key the rail reads, and answer it."""
    value = pin_value()
    store.put(auth_module().APPROVE_PIN_KEY, value)
    return value


def pinned_over(store):
    """The rail's pin answer for *store*: does its kv hold a pin, asked every call?"""
    module = auth_module()
    return lambda: module.pin_exists(store)


def no_pin() -> bool:
    """The pin answer of a store no test pins."""
    return False


def write_token_file(path: Path, token: str) -> str:
    """Write one install token the way the engine's own installer does."""
    path.write_text(token + "\n", encoding="utf-8")
    return token


def new_token_file(path: Path) -> str:
    return write_token_file(path, synthetic_secret())


def new_auth(store, clock, token_path, pinned):
    """An `Authenticator` over *store*, the clock, the token file and a pin answer.

    `pinned` is required, as it is on the rail itself: this test names where the
    answer comes from — `no_pin` for a store nothing pins, `pinned_over` for the
    kv the engine reads.
    """
    return auth_module().Authenticator(store, clock, token_path, pinned=pinned)


class Signer:
    """Builds the three approval headers for one request over the bytes it sends."""

    def __init__(self, key, clock: Clock):
        self.key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        self.clock = clock
        self._nonces = itertools.count(1)

    def nonce(self) -> str:
        """A fresh nonce: 22 characters of the shape the header allows."""
        return f"n{next(self._nonces):05d}{secrets.token_hex(8)}"

    def headers(
        self,
        method: str,
        path_with_query: str,
        body: bytes = b"",
        *,
        ts: Any = None,
        nonce: Any = None,
        key: Any = None,
        with_bearer: bool = True,
    ) -> dict:
        stamp = str(int(self.clock())) if ts is None else str(ts)
        used = self.nonce() if nonce is None else str(nonce)
        if key is None:
            material = self.key
        elif isinstance(key, str):
            material = key.encode("utf-8")
        else:
            material = bytes(key)
        signature = auth_module().compute_mac(
            material, method, path_with_query, stamp, used, body
        )
        headers = {
            "X-Crow-Timestamp": stamp,
            "X-Crow-Nonce": used,
            "X-Crow-Signature": signature,
        }
        if with_bearer:
            headers["Authorization"] = BEARER
        if body:
            headers["Content-Type"] = "application/json"
        return headers

    def post(self, client, path, payload=None, *, body=None, **kwargs):
        """POST *payload* (or *body*) to *path*, signed as sent."""
        if body is None:
            body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = self.headers("POST", path, body, **kwargs)
        return client.post(path, content=body, headers=headers)


@dataclass
class Harness:
    """One engine, the install token file beside it and an approval rail over it."""

    engine: Any
    clock: Clock
    token_path: Path
    token: str
    rail: Any
    signer: Signer

    def client(self, *, store=None, rail=None, require_privileged=None):
        """A `TestClient` over the app `create_app` builds for this engine.

        With no `require_privileged` the app is built the way `build_app` builds
        it — the rail wired in as `auth` — so the strict gate and the lease gate
        are the rail's own.  An injected callable replaces both.
        """
        return client_over(
            self.engine,
            self.rail if rail is None else rail,
            self.clock,
            store,
            require_privileged=require_privileged,
        )


@contextlib.contextmanager
def harness(root, *, clock=None):
    """Build an engine, an install token file and an approval rail, and close all of it."""
    clock = Clock() if clock is None else clock
    engine = Engine(root)
    token_path = Path(root) / "install_token"
    token = new_token_file(token_path)
    rail = new_auth(engine.store, clock, token_path, pinned=no_pin)
    try:
        yield Harness(
            engine=engine,
            clock=clock,
            token_path=token_path,
            token=token,
            rail=rail,
            signer=Signer(token, clock),
        )
    finally:
        engine.close()


def ai_orders_for(engine):
    """The AI order surface this engine's app is built with.

    `test_books.Engine` wires the gateway by hand, so the surface is built here
    over that store and gateway: what this file classifies is that the five AI
    routes exist and carry the gate their own path needs, while the requests
    that use them live in `test_ai_orders.py`.
    """
    from crow_coinbase.ai_orders import AiOrders

    orders = AiOrders(engine.store, ttl_s=900)
    orders.attach(engine.gateway)
    return orders


def credentials_slot(engine, rail, clock):
    """The owner's credentials slot, built the way `build_app` builds it.

    A slot is what mounts the credentials routes, so the route classification
    below sees them; what this file classifies about them is the gate each path
    carries, while the requests that use them live in `test_credentials.py`.
    The adapter builder is never called: nothing here installs a key.
    """
    from crow_coinbase.credentials import CredentialSlot

    def build_live(creds):
        raise AssertionError("the route classification never builds a live adapter")

    return CredentialSlot(engine.store, rail, build_live, now=clock)


def app_over(
    engine, approval, clock, store=None, *, require_privileged=None, slot=None
):
    """The engine's app, with the approval rail and the clock the test supplies.

    With no `require_privileged` the rail is wired in as `auth`, which is what
    `build_app` does: a privileged route asks the rail for the secret, and the
    two lease routes ask it with the install token admitted.  An injected
    one-argument callable is used exactly as it is given, for both gates.

    A `slot` is wired only where the credentials routes are to exist at all: the
    route classification below passes one, so a mutating credentials route is
    counted like every other route.
    """
    pieces = dict(
        store=engine.store if store is None else store,
        gateway=engine.gateway,
        runner=engine.runner,
        exchange=engine.dry,
        strategies=engine.strategies,
        limits=engine.limits,
        spec_for=lambda product: SPEC,
        price_for=engine.price_for,
        token=BEARER_TOKEN,
        heartbeat_path=Path(engine.root) / "hb.json",
        now=clock,
        switches=engine.switches,
        ai_orders=ai_orders_for(engine),
    )
    if slot is not None:
        pieces["slot"] = slot
    if require_privileged is None:
        return create_app(**pieces, auth=approval)
    return create_app(**pieces, require_privileged=require_privileged)


@contextlib.contextmanager
def client_over(
    engine, approval, clock, store=None, *, require_privileged=None, slot=None
):
    app = app_over(
        engine,
        approval,
        clock,
        store,
        require_privileged=require_privileged,
        slot=slot,
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def tiny_app(rail):
    """A three-route app over one rail: no bearer check, no engine, no lease.

    `/strict` asks the approval the way a privileged route does, `/install-ok`
    asks it with the install token admitted, and `/convenience` goes through the
    named helper for that.  `BodyCaptureMiddleware` is installed, so a signed
    body is captured exactly as `create_app` captures one.
    """
    module = auth_module()
    app = FastAPI()
    app.add_middleware(module.BodyCaptureMiddleware)

    @app.post("/strict")
    def strict(request: Request) -> dict:
        rail.require(request)
        return {"ok": True}

    @app.post("/install-ok")
    def install_ok(request: Request) -> dict:
        rail.require(request, allow_install_token=True)
        return {"ok": True}

    @app.post("/convenience")
    def convenience(request: Request) -> dict:
        rail.require_install_ok(request)
        return {"ok": True}

    return app


def assert_refused(response, label: str = ""):
    """403 with the approval's own detail."""
    assert response.status_code == 403, f"{label}: {response.status_code} {response.text}"
    assert response.json() == APPROVAL, f"{label}: {response.text}"


def assert_owner_refused(response, label: str = ""):
    """403 for a live bot's route, which reports the refusal as LIVE_NEEDS_OWNER."""
    assert response.status_code == 403, f"{label}: {response.status_code} {response.text}"
    detail = response.json()["detail"]
    assert detail in OWNER_REFUSALS, f"{label}: {detail}"


def _dependency_names(dependant) -> set[str]:
    """The names of every dependency a route resolves, nested ones included."""
    names: set[str] = set()
    for child in getattr(dependant, "dependencies", ()):
        call = getattr(child, "call", None)
        names.add(getattr(call, "__name__", type(call).__name__))
        names |= _dependency_names(child)
    return names


def _carries_approval(names: set[str]) -> bool:
    """Whether these dependency names carry a gate beyond the bearer check.

    A name that reads like an approval is one; so is any dependency that is not
    the bearer check itself, so a gate wired as a closure or a partial is still
    seen as the gate it is.
    """
    for name in names:
        if name in APPROVAL_DEPENDENCIES:
            return True
        lowered = name.lower()
        if any(part in lowered for part in APPROVAL_NAME_PARTS):
            return True
    return any(name != BEARER_CHECK for name in names)


def _ids(store) -> list[int]:
    rows = store.conn().execute("SELECT id FROM events ORDER BY id").fetchall()
    return [int(row["id"]) for row in rows]


# ---------------------------------------------------------------- the MAC itself


def test_mac_vectors_fixture():
    """Every vector's string-to-sign, body digest and signature come back as written."""
    module = auth_module()
    data = json.loads(FIXTURES.read_text(encoding="utf-8"))
    key = data["key"]
    vectors = data["vectors"]
    assert vectors, "the fixture carries no vector"

    for vector in vectors:
        name = vector["name"]
        body = vector["body"].encode("utf-8")
        assert hashlib.sha256(body).hexdigest() == vector["body_sha256"], name

        text = module.string_to_sign(
            vector["method"],
            vector["path_with_query"],
            vector["ts"],
            vector["nonce"],
            body,
        )
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        assert text == vector["string_to_sign"], name

        signature = module.compute_mac(
            key,
            vector["method"],
            vector["path_with_query"],
            vector["ts"],
            vector["nonce"],
            body,
        )
        assert signature == vector["signature"], name
        assert signature == signature.lower(), name


# ---------------------------------------------------------------- which route needs what


def test_privileged_routes_need_mac(tmp_path):
    """Each privileged route refuses bearer-only and a wrong MAC, and passes the right one.

    The key here is the approval secret the owner holds in memory: the install
    token signs the two lease routes and nothing else, so a switch, a mode, a
    cleared halt or a live bot's recenter and resume need the secret.
    """
    recenter_body = {"center": "1.1"}
    resume_body = {"acknowledge_rebase": True}

    with harness(tmp_path / "routes") as h:
        engine = h.engine
        engine.set_live(BOT, D("100"), D("100"))
        engine.store.set_bot_status(BOT, "PAUSED")
        secret = owner_secret()
        h.rail.set_secret(secret)
        signer = Signer(secret, h.clock)

        with h.client() as client:
            # A live bot's recenter and resume ask the owner, so a request with no
            # MAC is refused; with the right MAC they get past that check.
            for path, payload in (
                (f"/bots/{BOT}/recenter", recenter_body),
                (f"/bots/{BOT}/resume", resume_body),
            ):
                assert_owner_refused(client.post(path, json=payload, headers=HEADERS), path)
                assert_owner_refused(
                    signer.post(client, path, payload, key="wrong-" + synthetic_secret()),
                    path,
                )
                assert signer.post(client, path, payload).status_code != 403, path

            # The routes wired to the approval gate itself.  The lease routes take
            # the secret too, and the cursor has nothing to point past: no events
            # are older than the cursor, so 0 is the one it can name.
            for path, payload in (
                (f"/bots/{BOT}/mode", {"mode": "dry"}),
                ("/switches", {"live_enabled": True}),
                ("/halt/clear", {"acknowledge_rebase": True}),
                ("/lease", {"holder": "holder-a"}),
                ("/lease/cursor", {"holder": "holder-a", "cursor": 0}),
            ):
                assert_refused(client.post(path, json=payload, headers=HEADERS), path)
                assert_refused(
                    signer.post(client, path, payload, key="wrong-" + synthetic_secret()),
                    path,
                )
                answered = signer.post(client, path, payload)
                assert answered.status_code != 403, f"{path}: {answered.text}"
                if path == "/switches":
                    assert answered.status_code == 200, answered.text
                    assert answered.json()["live_enabled"] is True
                if path == "/lease":
                    assert answered.json()["held"] is True
                if path == "/lease/cursor":
                    assert answered.status_code == 200, answered.text
                    assert answered.json() == {"cursor": 0}

            # The bearer token comes first: a good MAC is a 401 without it.
            for path, payload in (
                (f"/bots/{BOT}/mode", {"mode": "dry"}),
                ("/switches", {"live_enabled": True}),
                ("/lease", {"holder": "holder-b"}),
            ):
                unsigned_bearer = signer.post(client, path, payload, with_bearer=False)
                assert unsigned_bearer.status_code == 401, path

    # The kill switch stays bearer-only.
    with harness(tmp_path / "kill") as k:
        with k.client() as client:
            killed = client.post("/kill", headers=HEADERS)
            assert killed.status_code == 200, killed.text
            assert killed.json()["halted"] is True


def test_injected_approval_is_used_for_both_gates(tmp_path):
    """A one-argument approval injected into `create_app` gates every privileged route.

    The engine's rail is not consulted at all when a caller injects its own
    check: it is used as it was given, for the strict routes and the two lease
    routes alike, so a caller that wired its own approval never ends up with a
    lease route asking a different question.
    """
    asked: list[str] = []

    def injected(request: Request) -> None:
        asked.append(request.url.path)
        raise HTTPException(status_code=403, detail=APPROVAL_INVALID)

    with harness(tmp_path / "injected") as h:
        with h.client(require_privileged=injected) as client:
            assert_refused(
                client.post("/switches", json={"live_enabled": True}, headers=HEADERS),
                "/switches",
            )
            assert_refused(
                client.post("/lease", json={"holder": "holder-a"}, headers=HEADERS),
                "/lease",
            )
            assert_refused(
                client.post(
                    "/lease/cursor",
                    json={"holder": "holder-a", "cursor": 0},
                    headers=HEADERS,
                ),
                "/lease/cursor",
            )
            assert asked == ["/switches", "/lease", "/lease/cursor"], asked
            # The bearer-only routes are not the approval's to refuse.
            assert client.get("/status", headers=HEADERS).status_code == 200


def test_every_mutating_route_is_classified(tmp_path):
    """Every mutating route is in one of the two sets, and carries the matching gate.

    The app under test carries a credentials slot, so the credentials routes are
    among the routes classified here; the requests that use them live in
    `test_credentials.py`.
    """
    assert not (PRIVILEGED_PATHS & BEARER_ONLY_PATHS)

    with harness(tmp_path / "classified") as h:
        app = app_over(
            h.engine,
            h.rail,
            h.clock,
            slot=credentials_slot(h.engine, h.rail, h.clock),
        )
        carries_approval: dict[tuple[str, str], bool] = {}
        for route in app.routes:
            methods = set(getattr(route, "methods", ()) or ()) & MUTATING_METHODS
            if not methods:
                continue
            dependant = getattr(route, "dependant", None)
            names = set() if dependant is None else _dependency_names(dependant)
            for method in sorted(methods):
                carries_approval[(method, route.path)] = _carries_approval(names)

        assert carries_approval, "the app carries no mutating route"
        unclassified = sorted(set(carries_approval) - (PRIVILEGED_PATHS | BEARER_ONLY_PATHS))
        assert not unclassified, f"mutating routes with no classification: {unclassified}"
        missing = sorted((PRIVILEGED_PATHS | BEARER_ONLY_PATHS) - set(carries_approval))
        assert not missing, f"classified routes that are not in the app: {missing}"

        for route in PRIVILEGED_PATHS:
            assert carries_approval[route], f"{route} carries no approval dependency"
        for route in BEARER_ONLY_PATHS:
            assert not carries_approval[route], f"{route} carries the approval dependency"


# ---------------------------------------------------------------- nonces


def test_replay_with_new_nonce_refused(tmp_path):
    """One nonce is spent once, and the signature covers body, path, query and method."""
    with harness(tmp_path / "replay") as h:
        signer = h.signer
        body = json.dumps({"holder": "holder-a"}).encode("utf-8")

        with h.client() as client:
            spent = signer.nonce()
            first = client.post(
                "/lease", content=body, headers=signer.headers("POST", "/lease", body, nonce=spent)
            )
            assert first.status_code == 200, first.text

            replayed = client.post(
                "/lease", content=body, headers=signer.headers("POST", "/lease", body, nonce=spent)
            )
            assert_refused(replayed, "replayed nonce")

            # The same request with a fresh nonce is a different request.
            again = client.post(
                "/lease", content=body, headers=signer.headers("POST", "/lease", body)
            )
            assert again.status_code == 200, again.text

            # A body swapped after signing.
            signed = signer.headers("POST", "/lease", body)
            swapped = json.dumps({"holder": "holder-b"}).encode("utf-8")
            assert_refused(client.post("/lease", content=swapped, headers=signed), "body")

            # A path swapped after signing.
            signed = signer.headers("POST", "/lease", body)
            assert_refused(client.post("/lease/cursor", content=body, headers=signed), "path")

            # A query string added after signing, and one that is signed.
            signed = signer.headers("POST", "/lease", body)
            assert_refused(client.post("/lease?dry=1", content=body, headers=signed), "query")
            signed = signer.headers("POST", "/lease?dry=1", body)
            assert (
                client.post("/lease?dry=1", content=body, headers=signed).status_code == 200
            )

            # A method swapped after signing.
            signed = signer.headers("GET", "/lease", body)
            assert_refused(client.post("/lease", content=body, headers=signed), "method")


def test_stale_ts_refused(tmp_path):
    """A timestamp outside +-60 s, or one that is not digits, is refused."""
    with harness(tmp_path / "stamps") as h:
        clock, signer = h.clock, h.signer
        body = json.dumps({"holder": "holder-a"}).encode("utf-8")
        now = int(clock())

        with h.client() as client:
            for offset in (-61, 61):
                headers = signer.headers("POST", "/lease", body, ts=str(now + offset))
                assert_refused(
                    client.post("/lease", content=body, headers=headers), f"offset {offset}"
                )
            for offset in (-59, 59):
                headers = signer.headers("POST", "/lease", body, ts=str(now + offset))
                answered = client.post("/lease", content=body, headers=headers)
                assert answered.status_code == 200, f"offset {offset}: {answered.text}"
            for stamp in ("1700000000.5", "17e8", "1700000000a", "+1700000000", "-1700000000"):
                headers = signer.headers("POST", "/lease", body, ts=stamp)
                assert_refused(client.post("/lease", content=body, headers=headers), stamp)


def test_nonces_survive_restart(tmp_path):
    """A spent nonce is spent after a reopen too; the retention window prunes old ones."""
    with harness(tmp_path / "nonces") as h:
        engine, clock, signer = h.engine, h.clock, h.signer
        body = json.dumps({"holder": "holder-a"}).encode("utf-8")
        first_nonce = signer.nonce()
        first_headers = signer.headers("POST", "/lease", body, nonce=first_nonce)

        with h.client() as client:
            assert client.post("/lease", content=body, headers=first_headers).status_code == 200

            stored = {
                row["nonce"]
                for row in engine.store.conn().execute("SELECT nonce FROM nonces")
            }
            assert first_nonce in stored

            # A refused request does not spend its nonce, so the same one is usable
            # once the request is signed properly.
            unspent = signer.nonce()
            refused = signer.post(
                client,
                "/lease",
                {"holder": "holder-b"},
                nonce=unspent,
                key="wrong-" + synthetic_secret(),
            )
            assert_refused(refused, "wrong key")
            accepted = signer.post(client, "/lease", {"holder": "holder-b"}, nonce=unspent)
            assert accepted.status_code == 200, accepted.text

        engine.store.close()
        reopened = Store(engine.store.path)
        try:
            rail = new_auth(reopened, clock, h.token_path, pinned=no_pin)
            with h.client(store=reopened, rail=rail) as client:
                replay = client.post("/lease", content=body, headers=first_headers)
                assert_refused(replay, "replay after reopen")

                # Older than the retention window: the next accepted request drops it.
                fresh_nonce = signer.nonce()
                clock.advance(NONCE_RETENTION_S + 1)
                fresh = signer.post(client, "/lease", {"holder": "holder-c"}, nonce=fresh_nonce)
                assert fresh.status_code == 200, fresh.text

                stored = {
                    row["nonce"]
                    for row in reopened.conn().execute("SELECT nonce FROM nonces")
                }
                assert first_nonce not in stored
                assert fresh_nonce in stored
        finally:
            reopened.close()


def test_nonce_row_survives_clock_jump_back(tmp_path):
    """A purge leaves its cutoff behind as a floor, so a clock jump cannot re-admit.

    The captured request is accepted at the clock T.  The clock then leaps 400 s
    forward and a second privileged request is accepted, which purges the nonce
    table: the captured row's own stamps are both past the cutoff, so that row
    goes with the purge — and the cutoff is written to kv as `nonce_floor`, the
    oldest stamp the rail still accepts.  The clock comes back to T, the captured
    request fits the timestamp window again, and the floor is what refuses it.
    The floor only ever moves forward, and a stamp below it is refused however
    fresh the nonce beside it is.
    """
    module = auth_module()
    floor_key = getattr(module, "NONCE_FLOOR_KEY", "nonce_floor")

    with harness(tmp_path / "jump") as h:
        engine, clock, signer = h.engine, h.clock, h.signer
        body = json.dumps({"holder": "holder-a"}).encode("utf-8")
        at = clock()
        stamp = int(at)
        nonce = signer.nonce()
        captured = signer.headers("POST", "/lease", body, nonce=nonce)

        def floor():
            """The stored floor, read the way the kv table holds it."""
            return engine.store.get(floor_key)

        def row_of(spent: str):
            return engine.store.conn().execute(
                "SELECT seen_at, ts FROM nonces WHERE nonce=?", (spent,)
            ).fetchone()

        def numeric(value) -> bool:
            return isinstance(value, (int, float)) and not isinstance(value, bool)

        with h.client() as client:
            first = client.post("/lease", content=body, headers=captured)
            assert first.status_code == 200, first.text

            spent = row_of(nonce)
            assert spent is not None, "the accepted request spent no nonce"
            assert spent["ts"] == stamp
            assert float(spent["seen_at"]) == at
            before = floor()

            # 400 s on, and one more accepted request: its spend is what purges,
            # and the cutoff it uses is the floor it leaves behind.
            clock.advance(400)
            later_ts = int(clock())
            later_nonce = signer.nonce()
            later = signer.post(
                client, "/lease", {"holder": "holder-a"}, nonce=later_nonce
            )
            assert later.status_code == 200, later.text

            after = floor()
            assert numeric(after), f"the purge recorded no numeric floor: {after!r}"
            assert float(after) > at, (
                f"the floor {after!r} does not cover the captured stamp {stamp}"
            )
            if numeric(before):
                assert float(after) >= float(before), (before, after)

            # A spent nonce's row carries the request's own stamp.
            later_row = row_of(later_nonce)
            assert later_row is not None, "the accepted request spent no nonce"
            assert later_row["ts"] == later_ts

            # ... and back to T.  The captured request fits its window again, its
            # row went with the purge, and the floor refuses the replay.
            clock.advance(-400)
            assert clock() == at
            assert row_of(nonce) is None, "the purge kept the captured row"
            assert floor() == after, f"the floor went backwards: {floor()!r}"
            assert_refused(
                client.post("/lease", content=body, headers=captured),
                "replay after the clock came back",
            )
            assert floor() == after, "a refused request moved the floor"

            # A stamp below the floor is refused whatever nonce is beside it, at a
            # clock whose window holds it: one second higher, and it is accepted,
            # so it is the floor refusing and not the window.
            limit = int(after)
            clock.advance(limit - 1 - clock())
            assert_refused(
                client.post(
                    "/lease",
                    content=body,
                    headers=signer.headers("POST", "/lease", body, ts=limit - 1),
                ),
                "a fresh nonce under the floor",
            )
            accepted = client.post(
                "/lease",
                content=body,
                headers=signer.headers("POST", "/lease", body, ts=limit),
            )
            assert accepted.status_code == 200, accepted.text
            assert numeric(floor())
            assert float(floor()) >= float(after), "the floor went backwards"


def test_nonce_floor_bad_value_tolerated(tmp_path):
    """A stored floor that is not a number is read as 0: it refuses nothing.

    The floor is read on every accepted request, and a hand-edited or older file
    can hold anything under that key.  A value that is not a number is no floor
    at all: it is not raised on and it does not refuse a request the timestamp
    window admits, and the next purge leaves a real cutoff in its place.
    """
    module = auth_module()
    floor_key = getattr(module, "NONCE_FLOOR_KEY", "nonce_floor")

    with harness(tmp_path / "floor-value") as h:
        engine, signer = h.engine, h.signer
        conn = engine.store.conn()

        def write_floor(text: str) -> None:
            conn.execute(
                "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)", (floor_key, text)
            )

        for label, text in (
            ("text", json.dumps("abc")),
            ("null", json.dumps(None)),
            ("an object", json.dumps({"floor": 12})),
            ("a list", json.dumps([1, 2, 3])),
        ):
            write_floor(text)
            with h.client() as client:
                accepted = signer.post(client, "/lease", {"holder": "holder-a"})
                assert accepted.status_code == 200, f"{label}: {accepted.text}"

            # The bad value is replaced by the cutoff the purge used, not kept.
            stored = engine.store.get(floor_key)
            assert stored is None or (
                isinstance(stored, (int, float)) and not isinstance(stored, bool)
            ), f"{label}: the floor was left as {stored!r}"


# ---------------------------------------------------------------- the key


def test_key_selection(tmp_path):
    """The in-memory secret wins while it is set; a pinned rail with no secret refuses."""
    with harness(tmp_path / "keys") as h:
        clock, signer, rail = h.clock, h.signer, h.rail
        secret = synthetic_secret().encode("utf-8")

        with h.client() as client:
            first = signer.post(client, "/lease", {"holder": "holder-a"})
            assert first.status_code == 200, first.text

            rail.set_secret(secret)
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-a"}), "install token while set"
            )
            with_secret = signer.post(client, "/lease", {"holder": "holder-a"}, key=secret)
            assert with_secret.status_code == 200, with_secret.text

            rail.clear_secret()
            back_to_token = signer.post(client, "/lease", {"holder": "holder-a"})
            assert back_to_token.status_code == 200, back_to_token.text
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-a"}, key=secret),
                "secret after clear",
            )

        pinned_rail = new_auth(
            h.engine.store, clock, h.token_path, pinned=lambda: True
        )
        with h.client(rail=pinned_rail) as client:
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-a"}),
                "pinned rail with no secret",
            )


def test_install_token_refused_once_pinned(tmp_path):
    """A pin in the store takes the install token out of the rail, for good.

    The pin is read out of the same sqlite file on every call, so a rail and an
    app built after it was written have no key at all until a secret is put in
    memory — and the install token never becomes one again.
    """
    with harness(tmp_path / "pinned") as h:
        engine, clock, signer = h.engine, h.clock, h.signer

        with h.client() as client:
            before = signer.post(client, "/lease", {"holder": "holder-a"})
            assert before.status_code == 200, before.text

        value = pin(engine.store)
        assert auth_module().pin_exists(engine.store) is True

        rail = new_auth(
            engine.store, clock, h.token_path, pinned=pinned_over(engine.store)
        )
        with h.client(rail=rail) as client:
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-b"}), "/lease"
            )
            assert_refused(
                signer.post(
                    client, "/lease/cursor", {"holder": "holder-a", "cursor": 0}
                ),
                "/lease/cursor",
            )
            assert_refused(
                client.post("/switches", json={"live_enabled": True}, headers=HEADERS),
                "/switches",
            )
            # The bearer routes are not the approval's to refuse.
            assert client.get("/status", headers=HEADERS).status_code == 200

            # The secret is the key once it is in memory, and the install token
            # is not one beside it either.
            secret = owner_secret()
            rail.set_secret(secret)
            owner = Signer(secret, clock)
            with_secret = owner.post(client, "/lease", {"holder": "holder-c"})
            assert with_secret.status_code == 200, with_secret.text
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-d"}),
                "install token beside the secret",
            )
            assert engine.store.get(auth_module().APPROVE_PIN_KEY) == value


def test_pin_present_in_any_form_refuses_install_token(tmp_path):
    """A pin is a ROW in kv, not a value: whatever it holds takes the token out.

    `store.get` answers the default for an absent key and for a stored JSON null
    alike, and an empty string, an object or a number are values it happily
    returns — so the rail asks whether the row is there, and the answer is the
    same for all of them: this engine is pinned, a rail and an app built after
    the row was written have no key at all, and the install token is refused.
    With the row gone the token signs a privileged request again, which is what
    makes each case below about the row rather than about the store.
    """
    module = auth_module()
    key = module.APPROVE_PIN_KEY
    cases = (
        ("JSON null", json.dumps(None)),
        ("an object", json.dumps({"pinned": True})),
        ("a number", json.dumps(7)),
        ("an empty string", json.dumps("")),
    )

    with harness(tmp_path / "pin-form") as h:
        engine, clock, signer = h.engine, h.clock, h.signer

        def write_pin_row(text: str) -> None:
            """One pin row, written the way a hand-edited file would hold it."""
            engine.store.conn().execute(
                "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)", (key, text)
            )

        def drop_pin_row() -> None:
            engine.store.conn().execute("DELETE FROM kv WHERE key=?", (key,))

        def fresh_rail():
            """A rail built now, reading the pin out of the store on every call."""
            return new_auth(
                engine.store, clock, h.token_path, pinned=pinned_over(engine.store)
            )

        # No row at all: the install token is a key, and this is the baseline the
        # four cases below have to differ from.
        drop_pin_row()
        assert module.pin_exists(engine.store) is False
        with h.client(rail=fresh_rail()) as client:
            accepted = signer.post(client, "/lease", {"holder": "holder-a"})
            assert accepted.status_code == 200, accepted.text

        for label, text in cases:
            write_pin_row(text)
            assert module.pin_exists(engine.store) is True, label

            with h.client(rail=fresh_rail()) as client:
                assert_refused(
                    signer.post(client, "/lease", {"holder": "holder-a"}), label
                )
                assert_refused(
                    signer.post(
                        client, "/lease/cursor", {"holder": "holder-a", "cursor": 0}
                    ),
                    label,
                )
                assert_refused(
                    client.post(
                        "/switches", json={"live_enabled": True}, headers=HEADERS
                    ),
                    label,
                )
                # The bearer routes are not the approval's to refuse.
                assert client.get("/status", headers=HEADERS).status_code == 200, label

            drop_pin_row()
            assert module.pin_exists(engine.store) is False, label


def test_clear_secret_never_restores_install_token(tmp_path):
    """Clearing the secret beside a pin leaves no key at all, and leaves the pin."""
    with harness(tmp_path / "clear") as h:
        engine, clock, signer = h.engine, h.clock, h.signer
        value = pin(engine.store)
        rail = new_auth(
            engine.store, clock, h.token_path, pinned=pinned_over(engine.store)
        )
        secret = owner_secret()
        owner = Signer(secret, clock)

        with h.client(rail=rail) as client:
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-a"}),
                "install token before the secret",
            )

            rail.set_secret(secret)
            assert owner.post(client, "/lease", {"holder": "holder-a"}).status_code == 200

            rail.clear_secret()
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-a"}),
                "install token after clear_secret",
            )
            assert_refused(
                owner.post(client, "/lease", {"holder": "holder-a"}),
                "secret after clear_secret",
            )
            assert_refused(
                client.post("/switches", json={"live_enabled": True}, headers=HEADERS),
                "/switches after clear_secret",
            )
            # Clearing the secret did not unpin the engine.
            assert auth_module().pin_exists(engine.store) is True
            assert engine.store.get(auth_module().APPROVE_PIN_KEY) == value


def test_short_secret_and_token_are_no_key(tmp_path):
    """A secret or an install token under 32 bytes is refused, never keyed with."""
    with harness(tmp_path / "short") as h:
        clock, signer, rail = h.clock, h.signer, h.rail
        short = secrets.token_hex(16)[:31]

        for value in (short, short.encode("utf-8")):
            with pytest.raises(ValueError) as refused:
                rail.set_secret(value)
            assert short not in str(refused.value)

        exact = secrets.token_hex(16)  # 32 characters: the shortest key there is
        rail.set_secret(exact)
        owner = Signer(exact, clock)

        with h.client() as client:
            assert owner.post(client, "/lease", {"holder": "holder-a"}).status_code == 200

            # With the secret cleared and no pin, the install token is the key
            # again — and a token under 32 bytes is no key at all.
            rail.clear_secret()
            write_token_file(h.token_path, short)
            assert_refused(
                Signer(short, clock).post(client, "/lease", {"holder": "holder-b"}),
                "31-byte install token",
            )
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-b"}),
                "the replaced token file",
            )

            longer = secrets.token_hex(16)  # 32 characters again
            write_token_file(h.token_path, longer)
            accepted = Signer(longer, clock).post(
                client, "/lease", {"holder": "holder-b"}
            )
            assert accepted.status_code == 200, accepted.text


def test_install_token_only_signs_credentials_and_lease(tmp_path):
    """The install token is a key on the lease routes (and 4b's credentials) only.

    A mode, a switch, a cleared halt, a live bot's recenter or resume and anything
    else privileged needs the secret.  On the rail itself the token is a key only
    where the approval is asked with `allow_install_token=True` — the two lease
    routes, and the credentials route 4b adds — never through `require`'s default
    and never through the convenience helper's absence.
    """
    with harness(tmp_path / "token-scope") as h:
        engine, clock, signer = h.engine, h.clock, h.signer
        engine.set_live(BOT, D("100"), D("100"))
        engine.store.set_bot_status(BOT, "PAUSED")

        with h.client() as client:
            for path, payload in (
                (f"/bots/{BOT}/mode", {"mode": "dry"}),
                ("/switches", {"live_enabled": True}),
                ("/halt/clear", {"acknowledge_rebase": True}),
                (f"/bots/{BOT}/recenter", {"center": "1.1"}),
                (f"/bots/{BOT}/resume", {"acknowledge_rebase": True}),
            ):
                refused = signer.post(client, path, payload)
                assert refused.status_code == 403, (
                    f"{path}: {refused.status_code} {refused.text}"
                )

            taken = signer.post(client, "/lease", {"holder": "holder-a"})
            assert taken.status_code == 200, taken.text
            assert taken.json()["held"] is True

            moved = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": 0}
            )
            assert moved.status_code == 200, moved.text
            assert moved.json() == {"cursor": 0}

        # The rail's own three answers, on a bare app: the strict gate refuses the
        # token, the install-token gate takes it, and the named helper is that same
        # gate under its own name.
        rail = new_auth(engine.store, clock, h.token_path, pinned=no_pin)
        with TestClient(tiny_app(rail), raise_server_exceptions=False) as client:
            assert_refused(signer.post(client, "/strict", {}), "strict")
            assert signer.post(client, "/install-ok", {}).status_code == 200
            assert signer.post(client, "/convenience", {}).status_code == 200

            # A secret in memory is the key everywhere, and it takes the token out
            # of even the gate that admits it.
            secret = owner_secret()
            rail.set_secret(secret)
            owner = Signer(secret, clock)
            assert owner.post(client, "/strict", {}).status_code == 200
            assert_refused(signer.post(client, "/strict", {}), "token beside the secret")
            assert_refused(signer.post(client, "/install-ok", {}), "token in memory")


def test_install_token_absent_tolerated(tmp_path):
    """An absent, empty or replaced token file refuses or serves, and never raises."""
    with harness(tmp_path / "absent") as h:
        h.token_path.unlink()
        signer = h.signer

        with h.client() as client:
            absent = signer.post(client, "/lease", {"holder": "holder-a"})
            assert_refused(absent, "absent token file")
            # The bearer routes still serve.
            assert client.get("/status", headers=HEADERS).status_code == 200

            # Written later, with no restart: the next request is checked against it.
            token = new_token_file(h.token_path)
            accepted = signer.post(client, "/lease", {"holder": "holder-a"}, key=token)
            assert accepted.status_code == 200, accepted.text

            # An empty file is no key.
            h.token_path.write_text("", encoding="utf-8")
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-a"}, key=token), "empty file"
            )

            # The file is read again on every call, not remembered from the first.
            replacement = new_token_file(h.token_path)
            assert_refused(
                signer.post(client, "/lease", {"holder": "holder-a"}, key=token),
                "replaced token file",
            )
            replaced = signer.post(client, "/lease", {"holder": "holder-a"}, key=replacement)
            assert replaced.status_code == 200, replaced.text


def test_refusals_are_uniform(tmp_path, caplog):
    """Every way of failing is the same 403, and neither a token nor a signature leaks."""
    caplog.set_level(logging.DEBUG)

    with harness(tmp_path / "uniform") as h:
        signer = h.signer
        body = json.dumps({"holder": "holder-a"}).encode("utf-8")
        good = signer.headers("POST", "/lease", body)
        wrong = signer.headers(
            "POST", "/lease", body, key="wrong-" + synthetic_secret()
        )

        variants = [
            # The bearer token is still presented: it is the approval that is missing.
            ("missing everything", {"Authorization": BEARER}),
            ("no signature", {k: v for k, v in good.items() if k != "X-Crow-Signature"}),
            ("no timestamp", {k: v for k, v in good.items() if k != "X-Crow-Timestamp"}),
            ("no nonce", {k: v for k, v in good.items() if k != "X-Crow-Nonce"}),
            ("non-digit timestamp", signer.headers("POST", "/lease", body, ts="yesterday")),
            ("short nonce", signer.headers("POST", "/lease", body, nonce="short")),
            ("bad signature", wrong),
        ]

        responses = []
        with h.client() as client:
            for label, headers in variants:
                response = client.post("/lease", content=body, headers=headers)
                assert response.status_code == 403, f"{label}: {response.text}"
                responses.append((label, response))

        reference = responses[0][1]
        assert reference.json() == APPROVAL
        for label, response in responses[1:]:
            assert response.json() == reference.json(), label
            assert response.text == reference.text, label

        secrets_to_hide = (
            h.token,
            good["X-Crow-Signature"],
            wrong["X-Crow-Signature"],
        )
        for label, response in responses:
            for needle in secrets_to_hide:
                assert needle not in response.text, label
        for needle in secrets_to_hide:
            assert needle not in caplog.text


# ---------------------------------------------------------------- the lease


def test_lease_single_holder_and_takeover_after_ttl(tmp_path):
    """One holder at a time; a renewal holds it, and another holder takes it after the TTL."""
    with harness(tmp_path / "lease") as h:
        clock, signer = h.clock, h.signer

        with h.client() as client:
            assert signer.post(client, "/lease", {"holder": "holder-a"}).json() == {
                "held": True,
                "cursor": None,
            }
            assert signer.post(client, "/lease", {"holder": "holder-b"}).json() == {
                "held": False,
                "cursor": None,
            }

            # Renewing before the TTL keeps it, and keeps the other holder out.
            clock.advance(30)
            assert signer.post(client, "/lease", {"holder": "holder-a"}).json() == {
                "held": True,
                "cursor": None,
            }
            assert signer.post(client, "/lease", {"holder": "holder-b"}).json() == {
                "held": False,
                "cursor": None,
            }

            # Past the TTL the lease is free again.
            clock.advance(LEASE_TTL_S + 1)
            assert signer.post(client, "/lease", {"holder": "holder-b"}).json() == {
                "held": True,
                "cursor": None,
            }
            assert signer.post(client, "/lease", {"holder": "holder-a"}).json() == {
                "held": False,
                "cursor": None,
            }

            for holder in ("", "with space", "sla/sh", "x" * 129, 7, None):
                assert (
                    signer.post(client, "/lease", {"holder": holder}).status_code == 422
                ), holder
            allowed = signer.post(client, "/lease", {"holder": "h.1:2_ok-x"})
            assert allowed.status_code == 200, allowed.text
            assert allowed.json()["held"] is False


def test_lease_cursor(tmp_path):
    """A cursor needs a live holder, never goes backwards, and survives a reopen."""
    with harness(tmp_path / "cursor") as h:
        clock, signer, engine = h.clock, h.signer, h.engine
        # A cursor points at an event, so there are events to point at.
        _old_events(engine.store, now=clock(), count=12)

        with h.client() as client:
            no_lease = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": 5}
            )
            assert no_lease.status_code == 409, no_lease.text
            assert LEASE_NOT_HELD in no_lease.text

            assert signer.post(client, "/lease", {"holder": "holder-a"}).json() == {
                "held": True,
                "cursor": None,
            }
            assert signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": 5}
            ).json() == {"cursor": 5}
            # A lower value leaves the stored one alone.
            assert signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": 3}
            ).json() == {"cursor": 5}
            assert signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": 9}
            ).json() == {"cursor": 9}

            for bad in (-1, True, 1.5, None):
                assert (
                    signer.post(
                        client, "/lease/cursor", {"holder": "holder-a", "cursor": bad}
                    ).status_code
                    == 422
                ), bad
            assert signer.post(client, "/lease/cursor", body=b"{}").status_code == 422

            # The holder that takes over reads the stored cursor.
            clock.advance(LEASE_TTL_S + 1)
            assert signer.post(client, "/lease", {"holder": "holder-b"}).json() == {
                "held": True,
                "cursor": 9,
            }

        engine.store.close()
        reopened = Store(engine.store.path)
        try:
            rail = new_auth(reopened, clock, h.token_path, pinned=no_pin)
            with h.client(store=reopened, rail=rail) as client:
                clock.advance(LEASE_TTL_S + 1)
                assert signer.post(client, "/lease", {"holder": "holder-c"}).json() == {
                    "held": True,
                    "cursor": 9,
                }
                assert signer.post(
                    client, "/lease/cursor", {"holder": "holder-c", "cursor": 10}
                ).json() == {"cursor": 10}
        finally:
            reopened.close()


def _cursor_refused(response, *, status: int, detail: str, label: str = ""):
    """A cursor refusal: the status the surface answers and the code it names."""
    assert response.status_code == status, f"{label}: {response.status_code} {response.text}"
    assert detail in response.text, f"{label}: {response.text}"


def test_cursor_above_newest_event_refused(tmp_path):
    """A cursor past the newest event is refused, and a refusal writes nothing."""
    with harness(tmp_path / "ahead") as h:
        clock, signer, engine = h.clock, h.signer, h.engine

        # With no event at all there is nothing to point a cursor at.
        engine.store.conn().execute("DELETE FROM events")
        assert _ids(engine.store) == []

        with h.client() as client:
            assert signer.post(client, "/lease", {"holder": "holder-a"}).status_code == 200

            ahead = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": 1}
            )
            _cursor_refused(
                ahead, status=422, detail=CURSOR_AHEAD, label="no events at all"
            )
            assert engine.store.get("lease_cursor") is None

            at_zero = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": 0}
            )
            assert at_zero.status_code == 200, at_zero.text
            assert at_zero.json() == {"cursor": 0}

        # With events, the newest id is a cursor and one past it is not.
        newest = _old_events(engine.store, now=clock())[-1]
        with h.client() as client:
            assert signer.post(client, "/lease", {"holder": "holder-a"}).status_code == 200

            accepted = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": newest}
            )
            assert accepted.status_code == 200, accepted.text
            assert accepted.json() == {"cursor": newest}

            too_far = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": newest + 1}
            )
            _cursor_refused(
                too_far, status=422, detail=CURSOR_AHEAD, label="one past the newest"
            )
            assert engine.store.get("lease_cursor") == newest


def test_cursor_needs_live_holder(tmp_path):
    """Only the holder of the live lease may move the cursor, and a holder is named."""
    with harness(tmp_path / "holder") as h:
        clock, signer, engine = h.clock, h.signer, h.engine
        ids = _old_events(engine.store, now=clock())

        with h.client() as client:
            # No lease at all: there is no holder to move the cursor for.
            none_held = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": ids[0]}
            )
            _cursor_refused(
                none_held, status=409, detail=LEASE_NOT_HELD, label="no lease"
            )

            assert signer.post(client, "/lease", {"holder": "holder-a"}).status_code == 200

            # Someone else's name is not this lease's holder.
            other = signer.post(
                client, "/lease/cursor", {"holder": "holder-b", "cursor": ids[0]}
            )
            _cursor_refused(
                other, status=409, detail=LEASE_NOT_HELD, label="another holder"
            )
            assert engine.store.get("lease_cursor") is None

            right = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": ids[0]}
            )
            assert right.status_code == 200, right.text
            assert right.json() == {"cursor": ids[0]}

            # After a takeover the cursor is the new holder's, and not the old one's.
            clock.advance(LEASE_TTL_S + 1)
            assert signer.post(client, "/lease", {"holder": "holder-b"}).status_code == 200
            moved = signer.post(
                client, "/lease/cursor", {"holder": "holder-b", "cursor": ids[-1]}
            )
            assert moved.status_code == 200, moved.text
            stale = signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": ids[-1]}
            )
            _cursor_refused(
                stale, status=409, detail=LEASE_NOT_HELD, label="the holder it left"
            )

            # The body has to name a holder at all.
            assert (
                signer.post(client, "/lease/cursor", {"cursor": ids[-1]}).status_code
                == 422
            )


def test_lease_needs_mac_once_secret_set(tmp_path):
    """The install token opens the lease until an approval secret is set."""
    with harness(tmp_path / "lease-secret") as h:
        secret = synthetic_secret().encode("utf-8")

        with h.client() as client:
            before = h.signer.post(client, "/lease", {"holder": "holder-a"})
            assert before.status_code == 200, before.text

            h.rail.set_secret(secret)
            assert_refused(
                h.signer.post(client, "/lease", {"holder": "holder-a"}), "install token"
            )
            after = h.signer.post(client, "/lease", {"holder": "holder-a"}, key=secret)
            assert after.status_code == 200, after.text


# ---------------------------------------------------------------- event retention


def _old_events(store, *, now: float, count: int = 5) -> list[int]:
    """*count* events with old stamps, the newest of them carrying *now*."""
    for index in range(count):
        store.event("ALERT", f"event {index}")
    ids = _ids(store)
    store.conn().execute("UPDATE events SET ts=?", (now - 200 * 86400,))
    store.conn().execute("UPDATE events SET ts=? WHERE id=?", (now, ids[-1]))
    return ids


def _surviving(store) -> set[int]:
    return set(_ids(store))


def test_prune_never_passes_notifier_cursor(tmp_path):
    """Retention stops at the lease cursor: nothing above it is deleted, ever."""
    now = NOW

    # With a cursor in the middle, the events below it go and the ones above stay.
    store = Store(tmp_path / "cursor.db")
    try:
        ids = _old_events(store, now=now)
        cursor = ids[2]
        store.put("lease_cursor", cursor)
        deleted = store.prune_events(now)
        assert deleted in (2, 3), deleted
        remaining = _surviving(store)
        assert set(ids[3:]) <= remaining
        assert ids[0] not in remaining and ids[1] not in remaining
        assert ids[-1] in remaining
    finally:
        store.close()

    # With no cursor the old behaviour stands: only the newest event survives.
    store = Store(tmp_path / "no-cursor.db")
    try:
        ids = _old_events(store, now=now)
        assert store.get("lease_cursor") is None
        assert store.prune_events(now) == len(ids) - 1
        assert _surviving(store) == {ids[-1]}
    finally:
        store.close()

    # The daily prune holds to the same cursor.
    store = Store(tmp_path / "daily.db")
    try:
        ids = _old_events(store, now=now)
        store.put("lease_cursor", ids[2])
        deleted = store.prune_events_daily(now)
        assert deleted in (2, 3), deleted
        remaining = _surviving(store)
        assert set(ids[3:]) <= remaining
        assert ids[0] not in remaining and ids[1] not in remaining
        assert ids[-1] in remaining
    finally:
        store.close()

    # A cursor written through the lease route is the same cursor.
    with harness(tmp_path / "route") as h:
        store = h.engine.store
        ids = _old_events(store, now=now)
        with h.client() as client:
            assert h.signer.post(client, "/lease", {"holder": "holder-a"}).status_code == 200
            written = h.signer.post(
                client, "/lease/cursor", {"holder": "holder-a", "cursor": ids[2]}
            )
            assert written.status_code == 200, written.text
            assert written.json() == {"cursor": ids[2]}
        deleted = store.prune_events(now)
        assert deleted in (2, 3), deleted
        remaining = _surviving(store)
        assert set(ids[3:]) <= remaining
        assert ids[0] not in remaining and ids[1] not in remaining
        assert ids[-1] in remaining


def test_prune_survives_bad_cursor(tmp_path):
    """A stored cursor that is not a usable id never raises and never over-deletes.

    The cursor is clamped into the range sqlite can bind: a value past the 64-bit
    integer bound is clamped down to it, so nothing above it can be deleted, and a
    stored non-integer or a negative one behaves as 0, which deletes nothing at
    all rather than everything.  The newest event always survives either way.
    """
    now = NOW
    values = (
        (2**70, 2**63 - 1),
        (-5, 0),
        ("abc", 0),
        (1.5, 0),
        (True, 0),
    )

    for index, (stored, cursor) in enumerate(values):
        for prune in ("prune_events", "prune_events_daily"):
            store = Store(tmp_path / f"bad-{index}-{prune}.db")
            try:
                ids = _old_events(store, now=now)
                store.put("lease_cursor", stored)
                deleted = getattr(store, prune)(now)
                remaining = _surviving(store)
                assert ids[-1] in remaining, (stored, prune)
                above = {event_id for event_id in ids if event_id > cursor}
                assert above <= remaining, (stored, prune)
                if cursor == 0:
                    assert deleted == 0, (stored, prune)
                    assert remaining == set(ids), (stored, prune)
                else:
                    assert deleted == len(ids) - 1, (stored, prune)
            finally:
                store.close()


# ---------------------------------------------------------------- build_app


class Market:
    """A fixed book, for the dry-run exchange `build_app` builds."""

    def __init__(self):
        self.bid, self.ask = D("0.99"), D("1.00")
        self.low, self.high = self.bid, self.ask

    def best_bid_ask(self):
        return self.bid, self.ask

    def range_since(self, since):
        return self.low, self.high

    def candles(self, start, end):
        return []


def build_env() -> dict:
    """The configuration `build_app` needs, with no install token file named."""
    return {
        "CROW_COINBASE_ENGINE_TOKEN": BEARER_TOKEN,
        "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
        "CROW_COINBASE_PRODUCTS": PRODUCT,
    }


def test_build_app_uses_env_token_file(tmp_path):
    """The token path comes from the environment, and an absent file refuses."""
    clock = Clock()
    market = Market()
    token_path = tmp_path / "install_token"
    token = new_token_file(token_path)
    env = dict(build_env())
    env["CROW_COINBASE_INSTALL_TOKEN_FILE"] = str(token_path)

    engine = build_app(
        env,
        data_dir=tmp_path / "data",
        market_for=lambda product: market,
        spec_for=lambda product: SPEC,
        now=clock,
    )
    try:
        with TestClient(engine.app, raise_server_exceptions=False) as client:
            body = json.dumps({"holder": "holder-a"}).encode("utf-8")
            signer = Signer(token, clock)
            accepted = client.post(
                "/lease", content=body, headers=signer.headers("POST", "/lease", body)
            )
            assert accepted.status_code == 200, accepted.text
            assert accepted.json()["held"] is True

        rail = getattr(engine, "auth", None)
        assert rail is not None, "build_app does not keep the approval rail on the engine"
        assert callable(getattr(rail, "require", None))
        assert callable(getattr(rail, "set_secret", None))
    finally:
        engine.store.close()

    if DEFAULT_INSTALL_TOKEN.exists():
        return

    without_env = build_app(
        build_env(),
        data_dir=tmp_path / "data2",
        market_for=lambda product: market,
        spec_for=lambda product: SPEC,
        now=clock,
    )
    try:
        with TestClient(without_env.app, raise_server_exceptions=False) as client:
            body = json.dumps({"holder": "holder-a"}).encode("utf-8")
            signer = Signer(token, clock)
            refused = client.post(
                "/lease", content=body, headers=signer.headers("POST", "/lease", body)
            )
            assert_refused(refused, "no token file named")
    finally:
        without_env.store.close()


def test_build_app_wires_pinned(tmp_path):
    """`build_app` reads the pin out of the store on every call, with no restart.

    The pin is written into the same sqlite file the app was built over: the next
    request is checked against a rail that now knows the engine is pinned, so the
    install token is no key and only a secret in memory is.
    """
    clock = Clock()
    market = Market()
    token_path = tmp_path / "install_token"
    token = new_token_file(token_path)
    env = dict(build_env())
    env["CROW_COINBASE_INSTALL_TOKEN_FILE"] = str(token_path)
    module = auth_module()

    engine = build_app(
        env,
        data_dir=tmp_path / "data",
        market_for=lambda product: market,
        spec_for=lambda product: SPEC,
        now=clock,
    )
    try:
        signer = Signer(token, clock)
        with TestClient(engine.app, raise_server_exceptions=False) as client:
            before = signer.post(client, "/lease", {"holder": "holder-a"})
            assert before.status_code == 200, before.text

            value = pin(engine.store)
            assert module.pin_exists(engine.store) is True

            refused = signer.post(client, "/lease", {"holder": "holder-a"})
            assert_refused(refused, "install token after the pin")

            secret = owner_secret()
            engine.auth.set_secret(secret)
            with_secret = Signer(secret, clock).post(
                client, "/lease", {"holder": "holder-a"}
            )
            assert with_secret.status_code == 200, with_secret.text
            assert engine.store.get(module.APPROVE_PIN_KEY) == value
    finally:
        engine.store.close()