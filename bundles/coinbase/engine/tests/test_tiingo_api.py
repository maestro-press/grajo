"""test_tiingo_api.py: the Tiingo routes, and the engine's own equity quote wiring.

Every test here builds the REAL engine through `build_app` — a real `Store` on a
temporary data directory, the real simulator, gateway, ledger and runner — and
the REAL app through its own `create_app`, so what is measured is the wiring the
engine ships and not a stand-in for it.  Two things are faked, both outside it:

* `FakeOpener` is the `opener` the Tiingo client takes.  It records every request
  it is handed and answers one canned reply, or raises one canned error, so no
  test opens a socket: the bearer token, the URL, the headers and the reply all
  stay in this file.
* `spec_for` is a table of `ProductSpec`s, which is the TRUSTED path the engine
  already offers an embedding: it says what each product is without reading a
  public product endpoint, and it is what keeps a stock's spec out of these tests.

The signatures are real: `Signer` hands `auth.compute_mac` the exact bytes
`TestClient` sends, over the exact path, with the engine's own clock, so a
request is one the engine's `Authenticator` accepts or refuses on its own terms.
The owner's secret is built at runtime and set in the rail's memory; the install
token is a runtime string written to a file outside the data directory and named
to the engine through `CROW_COINBASE_INSTALL_TOKEN_FILE`.

What each test pins down:

* all three routes need the bearer token AND the owner's MAC: a signed request
  with no bearer is a 401, a bearer-only request and a wrongly signed one are the
  one uniform `403 APPROVAL_INVALID`, and the install token is never a key —
  in memory or not,
* a signed `POST /tiingo/check` answers for what the opener earned: `ok` for a
  good answer with exactly one request and nothing stored, and `TOKEN_REJECTED`,
  `RATE_LIMITED`, `UNREACHABLE` and `BAD_ANSWER` for the four ways a request can
  fail — each with its fixed sentence, and `TOKEN_SHAPE` before any request at
  all,
* a signed `POST /tiingo` stores a token with NO request made, a bad shape is
  refused and stores nothing, `DELETE /tiingo` forgets it, and the `/status`
  equity block follows: `connected` with no message, `missing` with the missing
  sentence, and `rejected` once a poll was refused 401,
* a body the routes cannot read is `422 {"code": "INVALID", "fields": [...]}`:
  an extra field, a token that is not text, a body naming `token` twice and one
  naming no token at all — field names, and never a value that was sent,
* a canary token reaches no answer, no event and no log line, in the check, the
  set, the clear and a refused request alike — and it is carried in the request
  header only, never in the URL,
* the default wiring: with no `equity_last` the engine's own market prices an
  equity from Tiingo's print, an injected `equity_last` still wins and the client
  is never asked, and with no token the quote is refused and a dry equity order
  never fills,
* the print time Tiingo reports is what the staleness check measures, per book:
  a 10 s old print prices both books, a 200 s old one prices the practice book
  and is refused by the live one, a print AT the client's ceiling is still a last
  price (accepted for practice, refused for live) and one second past the ceiling
  is refused by the client itself,
* the equity block of an install with no equities, and of an app built with no
  Tiingo client, answers `prices: "missing"`,
* the block's `paused` state: a 429 pause and a used-up allowance are both
  `prices: "paused"` with the paused sentence beside them,
* the client the engine builds is told how many equity products are configured,
  so its cache time scales with them — and a client the caller brought is left
  exactly as it came.
"""

from __future__ import annotations

import contextlib
import email.message
import io
import json
import logging
import secrets
import time
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal as D
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import crow_coinbase.auth as auth_module
import crow_coinbase.exchange as exchange_module
import crow_coinbase.tiingo as tiingo_module
from crow_coinbase.__main__ import build_app
from crow_coinbase.api import INVALID_BODY, create_app
from crow_coinbase.auth import ENV_INSTALL_TOKEN_FILE
from crow_coinbase.books import APPROVAL_INVALID, DRY, LIVE
from crow_coinbase.exchange import ProductUnavailable
from crow_coinbase.money import ProductSpec

# ---------------------------------------------------------------- test data
# A bearer token in the shape the engine starts with, built at runtime.
TOKEN = "test-token-" + secrets.token_hex(16)
BEARER = f"Bearer {TOKEN}"
HEADERS = {"Authorization": BEARER}

# The install token the engine's installer would publish, built at runtime too.
INSTALL_TOKEN = "install-" + secrets.token_hex(20)

# The products: one equity on the equity list, one coin on the crypto one, and
# two more equities for the tests that count them.
NVDA = "NVDA-USD"
BTC = "BTC-USD"
MSFT = "MSFT-USD"
AAPL = "AAPL-USD"
PRODUCTS_ENV = "CROW_COINBASE_PRODUCTS"
EQUITY_PRODUCTS_ENV = "CROW_COINBASE_EQUITY_PRODUCTS"

# 10:00 in New York on a Wednesday, in a year the market calendar covers: inside
# the regular session, so a print stamped here is one the engine may price from.
SESSION = datetime(2026, 7, 15, 14, 0, tzinfo=timezone.utc).timestamp()
# The clock every route test starts from: the session above, and nothing moves it.
NOW = SESSION

# The one price the fakes print, and the notional a resting dry equity order uses.
PRICE = "123.45"

# The refusal codes the check route answers with (the contract's own names).
TOKEN_SHAPE = "TOKEN_SHAPE"
TOKEN_REJECTED = "TOKEN_REJECTED"
RATE_LIMITED = "RATE_LIMITED"
UNREACHABLE = "UNREACHABLE"
BAD_ANSWER = "BAD_ANSWER"

# A sentinel for "this build took no such argument", told apart from `None` (which
# is itself a meaningful value for `equity_last` and for an absent `tiingo`).
MISSING = object()


# ---------------------------------------------------------------- test secrets


def synthetic_token() -> str:
    """A token in the shape Tiingo's own has: one line, printable, no spaces."""
    return "tok" + secrets.token_hex(16)


def canary_token() -> str:
    """The one value no answer, event or log line may ever carry."""
    return "canary" + secrets.token_hex(12)


def owner_secret() -> str:
    """An approval secret long enough to be a key, built at runtime."""
    return "owner-" + secrets.token_hex(20)


# ---------------------------------------------------------------- the outside world


class Reply:
    """One canned answer from the fake opener: a status line, some bytes, headers."""

    def __init__(
        self,
        body: bytes = b"",
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.body = body
        self.status = status
        self.headers = dict(headers or {})


class FakeResponse:
    """What a real `urlopen` answers: a context manager over a readable stream.

    `read(amount)` is answered the way the stream answers it — at most *amount*
    bytes, from where the last read stopped — so a client that bounds the body it
    will read is measured against its own bound rather than against this fake.
    """

    def __init__(self, reply: Reply) -> None:
        self._body = reply.body
        self._at = 0
        self.status = reply.status
        self.headers = email.message.Message()
        for name, value in reply.headers.items():
            self.headers[name] = str(value)

    def read(self, amount: int | None = None) -> bytes:
        limit = len(self._body) if amount is None or amount < 0 else int(amount)
        chunk = self._body[self._at : self._at + limit]
        self._at += len(chunk)
        return chunk

    def getcode(self) -> int:
        return self.status

    def getheader(self, name: str, default: Any = None) -> Any:
        return self.headers.get(name, default)

    def info(self) -> Any:
        return self.headers

    def close(self) -> None:
        self._at = len(self._body)

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.close()
        return False


@dataclass
class Sent:
    """One request the fake opener was handed, read however the caller built it."""

    target: Any
    args: tuple
    kwargs: dict

    @property
    def url(self) -> str:
        """The URL asked for, whether the caller passed one or a `Request`."""
        return str(getattr(self.target, "full_url", self.target))

    @property
    def symbol(self) -> str:
        """The ticker this URL names: its last path segment, upper-cased."""
        path = self.url.split("?", 1)[0].rstrip("/")
        return path.rsplit("/", 1)[-1].upper()

    def header(self, name: str) -> Any:
        """One header the caller asked to send, whatever its case and container."""
        getter = getattr(self.target, "get_header", None)
        if getter is not None:
            found = getter(name)
            if found is not None:
                return found
        for container in (
            getattr(self.target, "headers", None),
            getattr(self.target, "unredirected_hdrs", None),
        ):
            for key, value in dict(container or {}).items():
                if str(key).lower() == name.lower():
                    return value
        return None


class FakeOpener:
    """A `urlopen` stand-in: records every request and answers one canned reply.

    `reply` is a `Reply` (returned), an exception (raised as it is, which is how
    a real opener reports a refused request or an unreachable host), or a
    callable handed the `Sent` request when the answer depends on what was asked.
    """

    def __init__(self, reply: Any = None) -> None:
        self.reply = Reply() if reply is None else reply
        self.calls: list[Sent] = []

    def __call__(self, target: Any, *args: Any, **kwargs: Any) -> FakeResponse:
        sent = Sent(target=target, args=args, kwargs=kwargs)
        self.calls.append(sent)
        reply = self.reply(sent) if callable(self.reply) else self.reply
        if isinstance(reply, BaseException):
            raise reply
        return FakeResponse(reply)


def iso_utc(ts: float) -> str:
    """An ISO 8601 stamp in UTC, the way Tiingo writes one."""
    moment = datetime.fromtimestamp(ts, timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iex_body(symbol: str, price: str, printed_at: float) -> bytes:
    """One IEX answer in the shape the client accepts: a list of one object.

    The print time is the `timestamp` field — the fallback the contract names when
    `lastSaleTimestamp` is absent — so the client's own staleness check measures
    the age this test chose.  The price is a numeric string, which the contract
    accepts beside a JSON number.
    """
    return json.dumps(
        [{"ticker": symbol, "tngoLast": price, "timestamp": iso_utc(printed_at)}]
    ).encode("utf-8")


def iex_reply(symbol: str, price: str, printed_at: float) -> Reply:
    """A 200 carrying one good IEX answer for *symbol*."""
    return Reply(iex_body(symbol, price, printed_at))


def refused(status: int, *, retry_after: int | None = None) -> urllib.error.HTTPError:
    """The `HTTPError` a real opener raises for a refused request."""
    headers = email.message.Message()
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return urllib.error.HTTPError(
        tiingo_module.IEX_URL.format(symbol=tiingo_module.CHECK_SYMBOL),
        status,
        "refused",
        headers,
        io.BytesIO(b""),
    )


def unreachable() -> urllib.error.URLError:
    """The error a real opener raises when the host does not answer."""
    return urllib.error.URLError("no route to the host")


def by_symbol(symbol: str, price: str, printed_at: float) -> Any:
    """A reply that names whatever ticker the request asked for.

    Used where one test asks for two different symbols through one client — the
    check's own fixed ticker and an equity's base symbol — and both answers have
    to be ones the client accepts.
    """

    def answer(sent: Sent) -> Reply:
        return iex_reply(sent.symbol or symbol, price, printed_at)

    return answer


# ---------------------------------------------------------------- specs


def equity_spec(product: str) -> ProductSpec:
    """An equity listing: cents on the price, fractional shares, USD quoted."""
    return ProductSpec(
        product,
        price_increment=D("0.01"),
        base_increment=D("0.0001"),
        quote_increment=D("0.01"),
        base_min_size=D("0.0001"),
        quote_min_size=D("1"),
        product_type="EQUITY",
        fractionable=True,
        fractional_notional_min_size=D("1"),
    )


def crypto_spec(product: str) -> ProductSpec:
    """A crypto listing, in the shape the crypto list's products have."""
    return ProductSpec(
        product,
        price_increment=D("0.0001"),
        base_increment=D("0.1"),
        quote_increment=D("0.01"),
        base_min_size=D("1"),
        quote_min_size=D("1"),
    )


def spec(product: str) -> ProductSpec:
    """The listing of *product*: an equity for the equity product, else SPOT.

    This is the INJECTED `spec_for` of the trusted path: it answers without an
    authenticated read, which is exactly what `trusted=True` means.
    """
    return equity_spec(product) if product == NVDA else crypto_spec(product)


# ---------------------------------------------------------------- the client


def quotes(opener: FakeOpener, *, now: Any = None) -> Any:
    """The client under test: a fake opener, and the clock the test names.

    With no clock it reads the wall clock, which is what the engine's own
    `MarketData` reads — a test that pins `time.time` then pins both halves of the
    staleness check at once.
    """
    clock = (lambda: time.time()) if now is None else now
    return tiingo_module.TiingoQuotes(opener=opener, now=clock)


# ---------------------------------------------------------------- requests


class Signer:
    """Signs one request's exact bytes the way the owner's approval does."""

    def __init__(self, clock: list) -> None:
        self.clock = clock

    def nonce(self) -> str:
        """A fresh nonce: the base64url alphabet, long enough to be unique."""
        return "n" + secrets.token_hex(12)

    def headers(
        self,
        key: Any,
        method: str,
        path: str,
        body: bytes = b"",
        *,
        with_bearer: bool = True,
    ) -> dict:
        stamp = str(int(self.clock[0]))
        used = self.nonce()
        signature = auth_module.compute_mac(key, method, path, stamp, used, body)
        sent = {
            "X-Crow-Timestamp": stamp,
            "X-Crow-Nonce": used,
            "X-Crow-Signature": signature,
        }
        if with_bearer:
            sent["Authorization"] = BEARER
        if body:
            sent["Content-Type"] = "application/json"
        return sent

    def post(
        self,
        client: TestClient,
        path: str,
        payload: Any = None,
        *,
        key: Any,
        body: bytes | None = None,
        with_bearer: bool = True,
    ):
        """POST *payload* (or the raw *body*), signed as sent."""
        if body is None:
            body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = self.headers(key, "POST", path, body, with_bearer=with_bearer)
        return client.post(path, content=body, headers=headers)

    def delete(
        self, client: TestClient, path: str, *, key: Any, with_bearer: bool = True
    ):
        """DELETE *path* with an empty body, signed as sent."""
        headers = self.headers(key, "DELETE", path, b"", with_bearer=with_bearer)
        return client.delete(path, headers=headers)


# ---------------------------------------------------------------- the harness


@dataclass
class Harness:
    """One real engine, the clock it was built with, and the client it was given."""

    engine: Any
    clock: list
    opener: FakeOpener
    tiingo: Any

    @contextlib.contextmanager
    def client(self):
        """A `TestClient` with NO default headers, so a test sends what it names."""
        with TestClient(self.engine.app, raise_server_exceptions=False) as client:
            yield client


def build_engine(
    root: Any,
    *,
    opener: FakeOpener | None = None,
    tiingo: Any = None,
    equity_products: str | None = None,
    equity_last: Any = MISSING,
    clock: list | None = None,
    own_tiingo: bool = False,
) -> Harness:
    """The real engine through `build_app`, with the Tiingo client handed to it.

    `market_for` is never injected, so an equity product's client is the one the
    engine builds itself; `spec_for` is, so no test reads a public product
    endpoint.  The install token lives outside the data directory, and the clock
    is a list every signature and the engine read together.

    With `own_tiingo` nothing is handed to `build_app` at all, so the client in
    the harness is the one the engine built for itself.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    token_path = root / "install_token"
    token_path.write_text(INSTALL_TOKEN + "\n", encoding="utf-8")
    clock = [NOW] if clock is None else clock

    env = {
        "CROW_COINBASE_ENGINE_TOKEN": TOKEN,
        "CROW_COINBASE_MAKER_FEE_PCT": "0.5",
        PRODUCTS_ENV: BTC,
        "CROW_COINBASE_MAX_BOT_CAPITAL_USD": "100",
        ENV_INSTALL_TOKEN_FILE: str(token_path),
    }
    if equity_products is not None:
        env[EQUITY_PRODUCTS_ENV] = equity_products

    opener = FakeOpener() if opener is None else opener
    client = quotes(opener, now=lambda: clock[0]) if tiingo is None else tiingo
    options: dict[str, Any] = dict(
        data_dir=root / "data",
        spec_for=spec,
        now=lambda: clock[0],
    )
    if equity_last is not MISSING:
        options["equity_last"] = equity_last
    handed = {} if own_tiingo else {"tiingo": client}
    engine = build_app(env, **handed, **options)
    return Harness(engine=engine, clock=clock, opener=opener, tiingo=engine.tiingo)


def app_over(engine: Any, *, tiingo: Any = MISSING) -> Any:
    """`create_app` over an engine's own pieces, and nothing this test did not name.

    Every piece is the engine's — the same store, gateway, runner, simulator, rail
    and slot the built app was made over — so the app under test differs from the
    engine's own in the one argument the caller passes.
    """
    options: dict[str, Any] = dict(
        store=engine.store,
        gateway=engine.gateway,
        runner=engine.runner,
        exchange=engine.exchange,
        strategies={},
        limits=engine.limits,
        spec_for=engine.gateway.spec_for,
        price_for=lambda product: D("0"),
        token=TOKEN,
        heartbeat_path=engine.runner.heartbeat_path,
        now=engine.runner.now,
        switches=engine.gateway.switches,
        auth=engine.auth,
        slot=engine.slot,
        ai_orders=engine.ai_orders,
    )
    if tiingo is not MISSING:
        options["tiingo"] = tiingo
    return create_app(**options)


# ---------------------------------------------------------------- reads


def equity_block(client: TestClient) -> dict:
    """The equity block of `/status`, read on the client the test already holds."""
    answer = client.get("/status", headers=HEADERS)
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert "equity" in body, body
    return body["equity"]


def status_equity(engine: Any) -> dict:
    """The equity block of `/status`, read over a client of its own."""
    with TestClient(engine.app, raise_server_exceptions=False) as client:
        return equity_block(client)


def every_event_text(store: Any) -> str:
    """Every event's message and stored payload, as one blob a scan can read."""
    rows = store.conn().execute(
        "SELECT message, data_json FROM events ORDER BY id"
    ).fetchall()
    return "\n".join(f"{row['message']}\n{row['data_json']}" for row in rows)


def assert_approval_refused(answer: Any, label: str = "") -> None:
    """403, with the approval rail's own uniform detail and nothing else."""
    assert answer.status_code == 403, f"{label}: {answer.status_code} {answer.text}"
    assert answer.json() == {"detail": APPROVAL_INVALID}, f"{label}: {answer.text}"


# ================================================================ 1. the two gates


def test_the_tiingo_routes_need_the_bearer_token_and_the_owners_mac(tmp_path):
    """All three routes are privileged: bearer first, then the owner's MAC.

    Measured the way `DELETE /credentials` is measured: a request signed with the
    owner's secret but carrying no bearer is a 401; one carrying the bearer and no
    signature, and one signed with the wrong key, are the rail's one uniform 403;
    the install token is never a key, with a secret in memory or without one; and
    the owner's own key gets past both gates.
    """
    h = build_engine(
        tmp_path / "gates",
        opener=FakeOpener(iex_reply(tiingo_module.CHECK_SYMBOL, "417.25", NOW)),
        equity_products=NVDA,
    )
    owner = owner_secret()
    h.engine.auth.set_secret(owner)
    signer = Signer(h.clock)
    payload = {"token": synthetic_token()}

    def signed(client, method, path, body, *, key, with_bearer=True):
        if method == "DELETE":
            return signer.delete(client, path, key=key, with_bearer=with_bearer)
        return signer.post(
            client, path, body, key=key, with_bearer=with_bearer
        )

    def bearer_only(client, method, path, body):
        if method == "DELETE":
            return client.delete(path, headers=HEADERS)
        return client.post(path, json=body, headers=HEADERS)

    with h.client() as client:
        for method, path in (
            ("POST", "/tiingo/check"),
            ("POST", "/tiingo"),
            ("DELETE", "/tiingo"),
        ):
            label = f"{method} {path}"
            body = None if method == "DELETE" else payload

            # The bearer token comes first: a perfectly signed request without it
            # is a 401, whatever else would be wrong with it.
            tokenless = signed(
                client, method, path, body, key=owner, with_bearer=False
            )
            assert tokenless.status_code == 401, f"{label}: {tokenless.text}"

            # The MAC is the second gate, and its refusal names nothing else.
            assert_approval_refused(
                bearer_only(client, method, path, body), f"{label} unsigned"
            )
            assert_approval_refused(
                signed(client, method, path, body, key="wrong-" + owner_secret()),
                f"{label} wrong key",
            )

            # The install token is never a key here, whoever presented it.
            assert_approval_refused(
                signed(client, method, path, body, key=INSTALL_TOKEN),
                f"{label} install token",
            )

            # The owner's own key gets past both gates and the route answers.
            allowed = signed(client, method, path, body, key=owner)
            assert allowed.status_code == 200, f"{label}: {allowed.text}"

        # And with no secret in memory the install token is still no key: these
        # routes are the strict gate, which never admits it.
        h.engine.auth.clear_secret()
        assert_approval_refused(
            signed(client, "POST", "/tiingo/check", payload, key=INSTALL_TOKEN),
            "install token with no secret",
        )


# ================================================================ 2. the check


def test_a_signed_check_answers_for_what_the_opener_earned(tmp_path):
    """One read of one fixed ticker: `ok` for a good answer, a code for a bad one.

    A good check makes exactly one request, keeps nothing and moves no status: the
    token it was handed is not stored, so the equity block still says the prices
    are missing.  Each way a request can fail earns its own code and its own fixed
    sentence, and a token of the wrong shape is refused before anything is sent.
    """
    owner = owner_secret()
    token = synthetic_token()

    # A good answer: one request, and nothing stored.
    h = build_engine(
        tmp_path / "check-ok",
        opener=FakeOpener(iex_reply(tiingo_module.CHECK_SYMBOL, "417.25", NOW)),
        equity_products=NVDA,
    )
    h.engine.auth.set_secret(owner)
    signer = Signer(h.clock)
    with h.client() as client:
        answered = signer.post(client, "/tiingo/check", {"token": token}, key=owner)
        assert answered.status_code == 200, answered.text
        assert answered.json() == {"state": "ok"}, answered.text
        assert len(h.opener.calls) == 1, h.opener.calls
        assert h.opener.calls[0].symbol == tiingo_module.CHECK_SYMBOL, h.opener.calls
        block = equity_block(client)
        assert block["prices"] == "missing", block
        assert block["prices_message"] == tiingo_module.SENTENCE_MISSING, block

    # Each way the read can fail, on a client of its own.
    cases = (
        (TOKEN_REJECTED, refused(401), tiingo_module.SENTENCE_REJECTED),
        (
            RATE_LIMITED,
            refused(429, retry_after=60),
            tiingo_module.SENTENCE_RATE_LIMITED,
        ),
        (UNREACHABLE, unreachable(), tiingo_module.SENTENCE_UNREACHABLE),
        (
            BAD_ANSWER,
            Reply(b"an answer this client cannot use"),
            tiingo_module.SENTENCE_BAD_ANSWER,
        ),
    )
    for code, reply, sentence in cases:
        refused_engine = build_engine(
            tmp_path / f"check-{code.lower()}",
            opener=FakeOpener(reply),
            equity_products=NVDA,
        )
        refused_engine.engine.auth.set_secret(owner)
        refuse_signer = Signer(refused_engine.clock)
        with refused_engine.client() as client:
            answered = refuse_signer.post(
                client, "/tiingo/check", {"token": token}, key=owner
            )
            assert answered.status_code == 200, (code, answered.text)
            assert answered.json() == {
                "state": "refused",
                "code": code,
                "message": sentence,
            }, (code, answered.text)
            assert len(refused_engine.opener.calls) == 1, (
                code,
                refused_engine.opener.calls,
            )
        block = status_equity(refused_engine.engine)
        assert block["prices"] == "missing", (code, block)

    # A token of the wrong shape is refused before any request is made.
    shaped = build_engine(tmp_path / "check-shape", equity_products=NVDA)
    shaped.engine.auth.set_secret(owner)
    shape_signer = Signer(shaped.clock)
    with shaped.client() as client:
        answered = shape_signer.post(
            client, "/tiingo/check", {"token": "two words"}, key=owner
        )
        assert answered.status_code == 200, answered.text
        assert answered.json() == {
            "state": "refused",
            "code": TOKEN_SHAPE,
            "message": tiingo_module.SENTENCE_TOKEN_SHAPE,
        }, answered.text
        assert shaped.opener.calls == [], shaped.opener.calls


# ================================================================ 3. set and clear


def test_a_signed_set_and_a_signed_clear_move_the_status_block(tmp_path):
    """Storing a token makes no request at all; the block says what is stored.

    `POST /tiingo` keeps the token in memory and asks Tiingo nothing; a bad shape
    is refused and stores nothing; `DELETE /tiingo` forgets it.  The `/status`
    equity block follows all three, with `prices_message` null only while the
    prices are connected — and a token Tiingo refuses turns the block `rejected`
    once a poll has been refused 401.
    """
    h = build_engine(
        tmp_path / "moves",
        opener=FakeOpener(iex_reply(NVDA, "100.00", NOW)),
        equity_products=NVDA,
    )
    owner = owner_secret()
    h.engine.auth.set_secret(owner)
    signer = Signer(h.clock)

    block = status_equity(h.engine)
    assert block["prices"] == "missing", block
    assert block["prices_message"] == tiingo_module.SENTENCE_MISSING, block

    with h.client() as client:
        # A token of the wrong shape: refused, nothing stored, nothing asked.
        shaped = signer.post(client, "/tiingo", {"token": "two words"}, key=owner)
        assert shaped.status_code == 200, shaped.text
        assert shaped.json() == {
            "state": "refused",
            "code": TOKEN_SHAPE,
            "message": tiingo_module.SENTENCE_TOKEN_SHAPE,
        }, shaped.text
        assert h.opener.calls == [], h.opener.calls
        assert equity_block(client)["prices"] == "missing"

        # A good token: connected, with no request made at all.
        token = synthetic_token()
        stored = signer.post(client, "/tiingo", {"token": token}, key=owner)
        assert stored.status_code == 200, stored.text
        assert stored.json()["state"] == "connected", stored.text
        assert token not in stored.text
        assert h.opener.calls == [], h.opener.calls
        block = equity_block(client)
        assert block["prices"] == "connected", block
        assert block["prices_message"] is None, block

        # Removing it forgets it, and the block carries the missing sentence.
        cleared = signer.delete(client, "/tiingo", key=owner)
        assert cleared.status_code == 200, cleared.text
        assert cleared.json()["state"] == "missing", cleared.text
        assert h.opener.calls == [], h.opener.calls
        block = equity_block(client)
        assert block["prices"] == "missing", block
        assert block["prices_message"] == tiingo_module.SENTENCE_MISSING, block

        # A token Tiingo refuses is reported rejected once a poll was refused.
        h.opener.reply = refused(401)
        again = signer.post(client, "/tiingo", {"token": synthetic_token()}, key=owner)
        assert again.json()["state"] == "connected", again.text
        with pytest.raises(ProductUnavailable):
            h.engine.runner.market_for(NVDA).equity_quote()
        block = equity_block(client)
        assert block["prices"] == "rejected", block
        assert block["prices_message"] == tiingo_module.SENTENCE_REJECTED, block

        # A fresh token clears the rejection, with no request made to do it.
        renewed = signer.post(
            client, "/tiingo", {"token": synthetic_token()}, key=owner
        )
        assert renewed.json()["state"] == "connected", renewed.text
        assert equity_block(client)["prices"] == "connected"


# ================================================================ 4. the body


def test_a_body_the_routes_cannot_read_names_fields_and_no_values(tmp_path):
    """Every body the routes refuse is the surface's one `422 INVALID` shape.

    An extra field, a token that is not text, a body naming `token` twice and one
    naming no token at all are each answered with the code and the names of the
    fields that failed — never a value, so the token the body carried appears in
    no answer, and nothing is stored by any of them.
    """
    canary = canary_token()
    h = build_engine(tmp_path / "bodies", equity_products=NVDA)
    owner = owner_secret()
    h.engine.auth.set_secret(owner)
    signer = Signer(h.clock)

    def assert_invalid(answer, label, field):
        assert answer.status_code == 422, (label, answer.status_code, answer.text)
        body = answer.json()
        assert set(body) == {"code", "fields"}, (label, body)
        assert body["code"] == INVALID_BODY, (label, body)
        assert field in body["fields"], (label, body)
        assert all(
            isinstance(name, str) and name and " " not in name
            for name in body["fields"]
        ), (label, body)
        assert canary not in answer.text, (label, answer.text)
        return body

    with h.client() as client:
        # An extra field, on both body-carrying routes.
        for path in ("/tiingo", "/tiingo/check"):
            answer = signer.post(
                client, path, {"token": canary, "extra": canary}, key=owner
            )
            assert_invalid(answer, f"{path} extra field", "extra")

        # A token that is not text at all.
        assert_invalid(
            signer.post(client, "/tiingo", {"token": 12345}, key=owner),
            "a token that is not text",
            "token",
        )

        # No token at all.
        assert_invalid(
            signer.post(client, "/tiingo", {}, key=owner), "no token", "token"
        )

        # A body that names `token` twice has no single value for it.  The bytes
        # are written out here because a dict cannot hold one name twice.
        duplicate_body = (
            b'{"token": "' + canary.encode("utf-8") + b'", "token": "second"}'
        )
        duplicate = signer.post(
            client, "/tiingo", key=owner, body=duplicate_body
        )
        assert_invalid(duplicate, "a duplicated token", "token")

    # Nothing of any of it was stored, and no request was ever made.
    assert h.opener.calls == [], h.opener.calls
    assert status_equity(h.engine)["prices"] == "missing"


# ================================================================ 5. the canary


def test_the_canary_token_reaches_no_answer_event_or_log(tmp_path, caplog):
    """The token is carried in one request header and nowhere else.

    With a canary for the token: the check, the set, the clear, a refused shape, a
    refused approval, the body refusal and a poll's own refusal are all exercised,
    and no answer body, no stored event and no log record carries the value.  The
    two requests the client did make carried it in the `Authorization` header and
    nowhere in the URL.
    """
    caplog.set_level(logging.DEBUG)
    canary = canary_token()
    h = build_engine(
        tmp_path / "canary",
        opener=FakeOpener(by_symbol(NVDA, "100.00", NOW)),
        equity_products=NVDA,
    )
    owner = owner_secret()
    h.engine.auth.set_secret(owner)
    signer = Signer(h.clock)
    answers: list[str] = []

    with h.client() as client:
        checked = signer.post(client, "/tiingo/check", {"token": canary}, key=owner)
        assert checked.json()["state"] == "ok", checked.text
        answers.append(checked.text)

        stored = signer.post(client, "/tiingo", {"token": canary}, key=owner)
        assert stored.json()["state"] == "connected", stored.text
        answers.append(stored.text)

        # A token of the wrong shape, still carrying the canary.
        shaped = signer.post(
            client, "/tiingo/check", {"token": canary + " tail"}, key=owner
        )
        assert shaped.json()["code"] == TOKEN_SHAPE, shaped.text
        answers.append(shaped.text)

        # A refused request: the approval says no.
        denied = signer.post(
            client, "/tiingo/check", {"token": canary}, key="wrong-" + owner_secret()
        )
        assert denied.status_code == 403, denied.text
        answers.append(denied.text)

        # A body the route cannot read, with the canary in it twice.
        unreadable = signer.post(
            client, "/tiingo", {"token": canary, "extra": canary}, key=owner
        )
        assert unreadable.status_code == 422, unreadable.text
        answers.append(unreadable.text)

        # The engine's own poll, refused by Tiingo.
        h.opener.reply = refused(401)
        with pytest.raises(ProductUnavailable):
            h.engine.runner.market_for(NVDA).equity_quote()
        answers.append(json.dumps(equity_block(client)))

        cleared = signer.delete(client, "/tiingo", key=owner)
        assert cleared.json()["state"] == "missing", cleared.text
        answers.append(cleared.text)

    for answer in answers:
        assert canary not in answer, answer
    assert canary not in every_event_text(h.engine.store), every_event_text(
        h.engine.store
    )
    assert canary not in caplog.text, caplog.text

    # It went in the header only: two requests were made, and neither URL names it.
    assert len(h.opener.calls) == 2, h.opener.calls
    for sent in h.opener.calls:
        assert canary not in sent.url, sent.url
        assert sent.header("Authorization") == f"Token {canary}", sent.header(
            "Authorization"
        )


# ================================================================ 6. the default wiring


def test_the_engines_own_market_prices_an_equity_from_tiingo(tmp_path, monkeypatch):
    """With no `equity_last`, the market the engine built asks Tiingo.

    The engine's own `MarketData` for an equity product is given the client's own
    read, and prints its one price on both sides of the quote; an injected
    `equity_last` still wins and the client is never asked; and with no token the
    quote is refused, so a resting dry equity order never fills where a priced one
    does.  The wall clock, the session and the print are all the same instant, so
    the engine's own age and session bounds are facts about this print.
    """
    clock = [SESSION + 10]
    monkeypatch.setattr(exchange_module.time, "time", lambda: clock[0])

    token = synthetic_token()
    h = build_engine(
        tmp_path / "priced",
        opener=FakeOpener(iex_reply("NVDA", PRICE, clock[0])),
        equity_products=NVDA,
        clock=clock,
    )
    h.tiingo.set_token(token)
    assert h.engine.tiingo is h.tiingo, h.engine.tiingo

    market = h.engine.runner.market_for(NVDA)
    assert isinstance(market, exchange_module.MarketData), market
    # The equity product is handed the client's own read, and no other source.
    assert market.equity_last == h.tiingo.last, market.equity_last
    assert market.equity_quote() == (D(PRICE), D(PRICE))
    assert len(h.opener.calls) == 1, h.opener.calls

    # A dry equity order priced from that quote fills; the same order on an
    # engine with no token never does, and never asks anything.
    h.engine.exchange.deposit("USD", D("1000"), "test float")
    placed = h.engine.exchange.place_equity_limit(
        "cb-ai-tiingo-priced", NVDA, "BUY", D("1"), D("200")
    )
    assert placed["ok"] is True, placed
    assert h.engine.exchange.advance(clock[0]) == ["cb-ai-tiingo-priced"]
    assert h.engine.exchange.get_order(placed["order_id"])["status"] == "FILLED"
    assert len(h.opener.calls) == 1, h.opener.calls

    silent = build_engine(
        tmp_path / "unpriced",
        opener=FakeOpener(iex_reply("NVDA", PRICE, clock[0])),
        equity_products=NVDA,
        clock=clock,
    )
    unpriced = silent.engine.runner.market_for(NVDA)
    assert unpriced.equity_last == silent.tiingo.last, unpriced.equity_last
    with pytest.raises(ProductUnavailable):
        unpriced.equity_quote()
    silent.engine.exchange.deposit("USD", D("1000"), "test float")
    resting = silent.engine.exchange.place_equity_limit(
        "cb-ai-tiingo-unpriced", NVDA, "BUY", D("1"), D("200")
    )
    assert resting["ok"] is True, resting
    assert silent.engine.exchange.advance(clock[0]) == []
    row = silent.engine.exchange.get_order(resting["order_id"])
    assert row["status"] != "FILLED", row
    assert row["filled_size"] == D("0"), row
    assert silent.opener.calls == [], silent.opener.calls

    # An injected `equity_last` still wins over the client, which is never asked.
    injected_opener = FakeOpener(iex_reply("NVDA", "999.00", clock[0]))
    pinned = build_engine(
        tmp_path / "injected",
        opener=injected_opener,
        equity_products=NVDA,
        equity_last=lambda symbol: (D("55.00"), clock[0]),
        clock=clock,
    )
    pinned.tiingo.set_token(token)
    assert pinned.engine.runner.market_for(NVDA).equity_quote() == (
        D("55.00"),
        D("55.00"),
    )
    assert injected_opener.calls == [], injected_opener.calls


# ================================================================ 7. the print time


def test_the_print_time_tiingo_reports_is_what_staleness_measures(
    tmp_path, monkeypatch
):
    """The age measured is Tiingo's print time, and the BOOK sets the bound.

    Every answer here differs only in the `timestamp` the client reads, so each
    refusal is about the print's own age and nothing else.  `equity_quote` with
    no book asks the live question, so a 200 s print the client hands over is
    refused by the engine's own strict bound while the practice book prices it.
    At the client's ceiling a print is still a last price (see
    `tests/test_tiingo.py`), so it is one second PAST the ceiling that the client
    itself refuses, whichever book asks.
    """
    clock = [SESSION + 10]
    monkeypatch.setattr(exchange_module.time, "time", lambda: clock[0])
    token = synthetic_token()
    ceiling_s = exchange_module.EQUITY_FRESHNESS_CEILING_S
    live_bound_s = exchange_module.DEFAULT_EQUITY_QUOTE_MAX_AGE_S

    def harness_over(name: str, age_s: float) -> Harness:
        """An engine whose stock is one print *age_s* seconds old, its token set."""
        harness = build_engine(
            tmp_path / name,
            opener=FakeOpener(iex_reply("NVDA", PRICE, clock[0] - age_s)),
            equity_products=NVDA,
            clock=clock,
        )
        harness.tiingo.set_token(token)
        return harness

    def market_of(harness: Harness) -> Any:
        """The stock's own market data on that engine."""
        return harness.engine.runner.market_for(NVDA)

    # A 10 s old print is a price for both books, off that one request.
    fresh = harness_over("fresh", 10.0)
    assert market_of(fresh).equity_quote() == (D(PRICE), D(PRICE))
    assert market_of(fresh).equity_quote(book=DRY) == (D(PRICE), D(PRICE))
    assert len(fresh.opener.calls) == 1, fresh.opener.calls

    # A 200 s old print is inside the client's ceiling and past the live bound: the
    # practice book prices it, and the live book refuses it with the bound it applied.
    two_hundred = harness_over("two-hundred", 200.0)
    assert market_of(two_hundred).equity_quote(book=DRY) == (D(PRICE), D(PRICE))
    with pytest.raises(ProductUnavailable) as refused_live:
        market_of(two_hundred).equity_quote()
    assert str(refused_live.value) == (
        f"{NVDA}: equity quote is 200s old, past the {live_bound_s:.0f}s bound"
    ), refused_live.value

    # A print at the client's ceiling is still a last price: the practice book prices
    # that very second, and the live book is the one that refuses it.
    at_ceiling = harness_over("at-ceiling", ceiling_s)
    price, stamp = market_of(at_ceiling).equity_print(book=DRY)
    assert price == D(PRICE), price
    assert clock[0] - stamp == pytest.approx(ceiling_s), (stamp, clock[0])
    with pytest.raises(ProductUnavailable) as refused_ceiling:
        market_of(at_ceiling).equity_quote()
    assert f"past the {live_bound_s:.0f}s bound" in str(refused_ceiling.value), (
        refused_ceiling.value
    )

    # One second past the ceiling the client itself refuses, before any book's bound is
    # read — and the sentence is remembered, so the second book costs no request.
    too_old = harness_over("too-old", ceiling_s + 1.0)
    for book in (DRY, LIVE):
        with pytest.raises(ProductUnavailable) as refused_quote:
            market_of(too_old).equity_quote(book=book)
        # The client's own refusal is what reached the engine's quote.
        assert "TiingoError" in str(refused_quote.value), refused_quote.value
    assert len(too_old.opener.calls) == 1, too_old.opener.calls


# ================================================================ 8. no equities


def test_a_block_with_no_equities_and_an_app_with_no_tiingo_say_missing(tmp_path):
    """An install with no equities reports `missing` and no message, whatever is stored.

    The block is the fixed `enabled: false` shape there, so a connected token moves
    nothing in it; and an app built with no Tiingo client at all reports
    `prices: "missing"` on an install whose equities ARE configured.
    """
    h = build_engine(tmp_path / "no-equities", equity_products=None)
    h.tiingo.set_token(synthetic_token())
    block = status_equity(h.engine)
    assert block["enabled"] is False, block
    assert block["prices"] == "missing", block
    assert block["prices_message"] is None, block

    configured = build_engine(tmp_path / "no-client", equity_products=NVDA)
    app = app_over(configured.engine)
    with TestClient(app, raise_server_exceptions=False) as client:
        answer = client.get("/status", headers=HEADERS)
        assert answer.status_code == 200, answer.text
        block = answer.json()["equity"]
    assert block["enabled"] is True, block
    assert block["prices"] == "missing", block


# ================================================================ 9. the paused block


def test_the_status_block_reports_paused_while_a_429_pause_is_in_force(tmp_path):
    """A refused 429 leaves the prices `paused`, with the paused sentence.

    The pause is the client's own state, so it is the client's own sentence the
    block carries — no surface invents a second one for it.
    """
    h = build_engine(
        tmp_path / "paused-429",
        opener=FakeOpener(refused(429, retry_after=60)),
        equity_products=NVDA,
    )
    h.tiingo.set_token(synthetic_token())

    with pytest.raises(ProductUnavailable):
        h.engine.runner.market_for(NVDA).equity_quote()
    assert len(h.opener.calls) == 1, h.opener.calls

    block = status_equity(h.engine)
    assert block["enabled"] is True, block
    assert block["prices"] == "paused", block
    assert block["prices_message"] == tiingo_module.SENTENCE_PAUSED, block


def test_the_status_block_reports_paused_when_the_allowance_is_used_up(tmp_path):
    """A client that has spent its hour is `paused`, and the block says so."""
    h = build_engine(
        tmp_path / "paused-allowance",
        opener=FakeOpener(by_symbol(NVDA, PRICE, NOW)),
        equity_products=NVDA,
    )
    h.tiingo.set_token(synthetic_token())

    for index in range(tiingo_module.MAX_PER_HOUR):
        assert h.tiingo.last(f"P{index}") is not None, index
    assert len(h.opener.calls) == tiingo_module.MAX_PER_HOUR, h.opener.calls

    block = status_equity(h.engine)
    assert block["prices"] == "paused", block
    assert block["prices_message"] == tiingo_module.SENTENCE_PAUSED, block


# ================================================================ 10. the built client


def test_build_app_tells_the_client_it_builds_the_equity_product_count(tmp_path):
    """The engine's own client scales its cache time with the equities configured."""
    one = build_engine(tmp_path / "one-equity", equity_products=NVDA, own_tiingo=True)
    assert one.engine.tiingo.cache_ttl() == max(
        tiingo_module.CACHE_TTL_S, tiingo_module.CACHE_PER_PRODUCT_S
    )

    three = build_engine(
        tmp_path / "three-equities",
        equity_products=", ".join((NVDA, MSFT, AAPL)),
        own_tiingo=True,
    )
    assert three.engine.tiingo.cache_ttl() == max(
        tiingo_module.CACHE_TTL_S, 3 * tiingo_module.CACHE_PER_PRODUCT_S
    )

    # A client the caller brought keeps its own count: the engine does not re-aim it.
    pinned = build_engine(
        tmp_path / "pinned-client",
        equity_products=NVDA,
        tiingo=tiingo_module.TiingoQuotes(
            opener=FakeOpener(), now=lambda: NOW, product_count=lambda: 7
        ),
    )
    assert pinned.engine.tiingo.cache_ttl() == max(
        tiingo_module.CACHE_TTL_S, 7 * tiingo_module.CACHE_PER_PRODUCT_S
    )