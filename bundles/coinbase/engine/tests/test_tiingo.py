"""test_tiingo.py: TiingoQuotes answers in a Decimal price and a fixed sentence.

The client reads one ticker at a time from Tiingo's IEX endpoint and holds the
token in memory only.  Everything about it that can go wrong is one of the fixed
sentences in `crow_coinbase.tiingo`: the token is one line of printable ASCII
checked before any request, it travels in the `Authorization` header only, and no
answer, log record or error carries the token or the response body.

No test leaves the machine.  The client takes its opener and its clock as
arguments, so every test hands it:

* `FakeOpener`, an `opener(request, timeout=...)` that records the request it was
  given (URL, headers, timeout) and answers from a script: a body (`bytes`), a
  `bytes`-returning callable given the request, or an exception to raise.
  `FakeResponse` is the context-manager answer with `read(n=None)`.
* `Clock`, a `now()` a test advances by hand, so "a cache time later", "an hour
  later" and "a day later" cost nothing and an answer's own timestamp stays
  fresh.

The one test of the real opener runs two loopback servers on 127.0.0.1, one
answering a 302 to the other: a redirect that is followed is a request this
client must not make.

What each test pins down:

* the token and symbol tables, with the boundary on both sides of each rule,
  and a stored token that is the trimmed text,
* the states and their sentences (`missing`, `rejected`, `paused`, `connected`),
  and a `repr` with no token in it,
* one good answer: the price as a `Decimal`, the print time as epoch seconds, and
  the request's shape (header, URL, User-Agent, timeout, upper-cased symbol),
  with `lastSaleTimestamp` winning over `timestamp` when it is there,
* every refusal as exactly one fixed sentence, with the canary token and the
  body's own text in none of it,
* the cache: a second answer inside the TTL is free, a later one is a request,
  the TTL itself grows with the number of equity products, and a stale or bad
  answer is never cached as a price but remembered as a failure,
* the print's own age: `MAX_AGE_S` is the engine's freshness CEILING, the bound
  a practice (dry) stock order accepts a print under, imported from `exchange`
  rather than restated here; a cached price is dropped once its print reaches it
  — whatever cache time the products earn — so a 429 pause answers the
  rate-limited sentence and never an old price,
* `TiingoPaused`: the rate limit and a used-up allowance are raised as it, while
  a stale print, a bad answer, an unreachable host and a refused token are a
  plain `TiingoError`,
* the hourly and daily ceilings, each refusing without a request and each
  recovering on its own, with the `paused` state they report while used up,
* the 429 pause, a fresh cached price answering inside it while a cache miss
  does not, a `Retry-After` that extends it and one that is capped,
* the failure memory: a symbol that just failed answers with its own sentence
  and no request for `cache_ttl()`, and an outage costs a bounded number of
  requests however often it is polled,
* the generation counter: a refusal, a cache write and a remembered failure
  from a request that started before `set_token` leave no mark on the new token,
* the five-second timeout, the refused redirect (two loopback servers, and the
  second origin is never asked at all), and the `paused` state with its own
  sentence,
* a refused token that keeps refusing until a new one is set, and the failures
  that leave the state alone,
* `check`: one read of the fixed ticker that stores nothing, costs nothing and
  passes on an old print,
* the canary sweep: every failure again, with the canary in the token and in the
  body, and nothing of it in an exception, a log record or the `repr`.
"""

from __future__ import annotations

import email.message
import inspect
import json
import logging
import secrets
import threading
import urllib.error
from datetime import datetime, timezone
from decimal import Decimal as D
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import crow_coinbase.exchange as exchange_module
import crow_coinbase.tiingo as tiingo_module
from crow_coinbase.tiingo import (
    CACHE_PER_PRODUCT_S,
    CACHE_TTL_S,
    CHECK_SYMBOL,
    IEX_URL,
    MAX_AGE_S,
    MAX_BODY_BYTES,
    MAX_PER_DAY,
    MAX_PER_HOUR,
    MAX_TOKEN_CHARS,
    RATE_PAUSE_S,
    SENTENCE_BAD_ANSWER,
    SENTENCE_BUDGET,
    SENTENCE_MISSING,
    SENTENCE_PAUSED,
    SENTENCE_RATE_LIMITED,
    SENTENCE_REJECTED,
    SENTENCE_STALE,
    SENTENCE_SYMBOL,
    SENTENCE_TOKEN_SHAPE,
    SENTENCE_UNREACHABLE,
    TIMEOUT_S,
    USER_AGENT,
    TiingoError,
    TiingoQuotes,
    valid_symbol,
    valid_token,
)

# ---------------------------------------------------------------- test data
# Two synthetic tokens, and a canary that must never be echoed: it is a substring
# of the canary token AND of every body the sweep shows the client.
TOKEN = "tiingo-test-token-0123456789abcdef"
NEW_TOKEN = "tiingo-test-token-fedcba9876543210"
CANARY = "canary-" + secrets.token_hex(8)
CANARY_TOKEN = "tiingo-test-token-" + CANARY

# The epoch these tests call "now"; the answers' own timestamps build from it.
BASE = 1_700_000_000.0

# The ticker the tests ask for, one they do not, and the price they get.
NVDA = "NVDA"
OTHER = "MSFT"
PRICE = 100.5

# The cache time each equity-product count earns: the 90 s floor from one product
# up, then `CACHE_PER_PRODUCT_S` (85 s) more for each further product polled.
CACHE_TTL_BY_COUNT = {1: 90.0, 2: 170.0, 3: 255.0}


# ---------------------------------------------------------------- the fake clock


class Clock:
    """A `now()` a test moves by hand."""

    def __init__(self, at: float = BASE) -> None:
        self.value = float(at)

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += float(seconds)


# ---------------------------------------------------------------- the fake opener


class FakeResponse:
    """The context-manager answer `urlopen` gives, as far as the client reads it."""

    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = bytes(body)

    def read(self, n: int | None = None) -> bytes:
        """The body, or at most its first *n* bytes: what the client bounds."""
        if n is None:
            return self.body
        return self.body[:n]

    def getcode(self) -> int:
        return self.status

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc_info) -> bool:
        return False


class Call:
    """One recorded request: what the client asked for and how."""

    def __init__(self, request, timeout) -> None:
        self.request = request
        self.timeout = timeout
        self.url = getattr(request, "full_url", None)
        self.headers = dict(getattr(request, "headers", {}) or {})
        self.headers.update(getattr(request, "unredirected_hdrs", {}) or {})
        method = getattr(request, "get_method", None)
        self.method = method() if callable(method) else None

    @property
    def authorization(self):
        """The `Authorization` header, as the client wrote it."""
        return self.request.get_header("Authorization")

    def header(self, name: str):
        """One header, whatever case the client spelled its name in."""
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return None

    def __repr__(self) -> str:
        return f"Call(url={self.url!r}, timeout={self.timeout!r})"


class FakeOpener:
    """`opener(request, timeout=...)`: record the request, answer from a script.

    An answer is a `bytes` body, a callable given the request (a body built from
    the fake clock, say), or an exception to raise.  The LAST answer repeats, so
    one answer is enough for a test that never changes its mind, and a test that
    does change its mind appends the next one.
    """

    def __init__(self, *answers) -> None:
        self.script = list(answers)
        self.requests: list[Call] = []

    @property
    def count(self) -> int:
        """How many requests the client made."""
        return len(self.requests)

    def __call__(self, request, timeout=None) -> FakeResponse:
        self.requests.append(Call(request, timeout))
        assert self.script, "the client made a request no test scripted"
        answer = self.script[0] if len(self.script) == 1 else self.script.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            answer = answer(request)
        return FakeResponse(answer)


# ---------------------------------------------------------------- the bodies

# A field a row carries or, in `row`, does not carry at all.
DROP = object()


def iso(at: float, *, suffix: str = "Z") -> str:
    """*at* as an ISO 8601 UTC timestamp, with *suffix* as the zone it names."""
    stamp = datetime.fromtimestamp(float(at), tz=timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + suffix


def row(at: float = BASE, *, ticker: str = NVDA, price=PRICE, **changes) -> dict:
    """One IEX row for *ticker*, printed at *at*, plus the test's own changes.

    `changes` sets a field or, with `DROP`, removes it, so "no timestamp at all"
    and "a `tngoLast` that is not a price" are each one argument.
    """
    fields = {"ticker": ticker, "timestamp": iso(at), "tngoLast": price}
    fields.update(changes)
    for name, value in list(fields.items()):
        if value is DROP:
            del fields[name]
    return fields


def canary_row(at: float = BASE, **changes) -> dict:
    """A row that carries the canary as one of its own fields."""
    return row(at, canary=CANARY, **changes)


def listing(*rows) -> bytes:
    """The JSON list the single-ticker URL answers."""
    return json.dumps(list(rows)).encode("utf-8")


def one(fields: dict) -> bytes:
    """A one-row list: the shape a healthy answer has."""
    return listing(fields)


def bare(fields: dict) -> bytes:
    """One object, not in a list: the other shape a healthy answer has."""
    return json.dumps(fields).encode("utf-8")


def fresh_answers(clock: Clock, *, price=PRICE):
    """An answer for whatever ticker the request names, printed at *clock*.

    The print moves with the clock, so a test that advances it still gets a fresh
    price, and the ticker comes from the URL, so a varied-symbol loop is never a
    cache hit and never a ticker mismatch.
    """

    def answer(request) -> bytes:
        symbol = str(request.full_url).rsplit("/", 1)[-1]
        return one(row(clock(), ticker=symbol, price=price))

    return answer


def http_error(
    code: int,
    *,
    retry_after: str | None = None,
    url: str | None = None,
) -> urllib.error.HTTPError:
    """The error `urlopen` raises for an HTTP failure, with an optional header."""
    headers = email.message.Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(
        IEX_URL.format(symbol=NVDA) if url is None else url,
        code,
        "x",
        headers,
        None,
    )


# ---------------------------------------------------------------- the harness


def quotes(opener=None, clock=None, *, product_count=None) -> TiingoQuotes:
    """A client over *opener* and *clock*, with no token yet.

    `product_count` is the number of equity products the client is told the
    engine trades, which is what its cache time is scaled by; left out, the
    client's own default stands.
    """
    options = {} if product_count is None else {"product_count": product_count}
    return TiingoQuotes(
        opener=FakeOpener() if opener is None else opener,
        now=Clock() if clock is None else clock,
        sleep=None,
        **options,
    )


def connected(*answers, token: str = TOKEN, clock=None):
    """A client with *token* set and *answers* scripted for its opener."""
    at = Clock() if clock is None else clock
    opener = FakeOpener(*answers)
    ops = quotes(opener, at)
    ops.set_token(token)
    return ops, opener, at


def refused(ops, symbol: str = NVDA) -> TiingoError:
    """The `TiingoError` `ops.last(symbol)` raised."""
    with pytest.raises(TiingoError) as raised:
        ops.last(symbol)
    return raised.value


def last(symbol: str = NVDA):
    """The act of asking for *symbol*'s last price."""

    def act(ops):
        return ops.last(symbol)

    return act


def assert_sentence(error: BaseException, sentence: str, name: str = "") -> None:
    """The error is exactly *sentence*, and the canary is in none of its text."""
    assert str(error) == sentence, (name, str(error))
    assert CANARY not in str(error), (name, str(error))
    assert CANARY not in repr(error), (name, repr(error))


def assert_request(call: Call, *, symbol: str = NVDA, token: str = TOKEN) -> None:
    """The one request the client makes: header auth, and no token in the URL."""
    assert call.url == IEX_URL.format(symbol=symbol), call
    assert call.authorization == f"Token {token}", call
    assert call.header("Accept") == "application/json", call
    assert call.header("User-Agent") == USER_AGENT, call
    assert call.timeout == TIMEOUT_S, call
    assert token not in str(call.url), call


# ================================================================ 1. the shapes


def test_valid_token_table():
    """One line of printable ASCII, non-empty, at most MAX_TOKEN_CHARS."""
    for text in (
        TOKEN,
        "a",
        "A1",
        "!",
        "~",
        "x" * MAX_TOKEN_CHARS,
        f" {TOKEN} ",
        f"\n{TOKEN}\n",
    ):
        assert valid_token(text) is True, text
    for text in (
        "",
        " ",
        "   ",
        "tiingo test-token",
        "tiingo\ntest-token",
        "tiingo\ttest-token",
        "tiingo\x7ftest-token",
        "tiingo-test-token-\u00fc",
        "x" * (MAX_TOKEN_CHARS + 1),
        None,
        123,
        b"tiingo-test-token",
    ):
        assert valid_token(text) is False, text


def test_valid_symbol_table():
    """One to ten letters, digits, dots and dashes."""
    for symbol in (NVDA, OTHER, "SPY", "BRK.B", "BF-B", "A", "a", "ABCDEFGHIJ"):
        assert valid_symbol(symbol) is True, symbol
    for symbol in (
        "",
        "A B",
        "../x",
        "NVDA\n",
        "NV DA",
        "NVDA_1",
        "ABCDEFGHIJK",
        None,
        1,
    ):
        assert valid_symbol(symbol) is False, symbol


# ================================================================ 2. the states


def test_no_token_means_missing_and_no_request():
    """A client with no token answers `None` and never reaches the opener."""
    clock = Clock()
    opener = FakeOpener(fresh_answers(clock))
    ops = quotes(opener, clock)

    assert ops.state() == "missing"
    assert ops.message() == SENTENCE_MISSING
    assert ops.last(NVDA) is None
    assert opener.count == 0, "a request was made with no token"

    ops.set_token(TOKEN)
    assert ops.state() == "connected"
    assert ops.message() is None
    assert TOKEN not in repr(ops)

    ops.clear()
    assert ops.state() == "missing"
    assert ops.message() == SENTENCE_MISSING
    assert ops.last(NVDA) is None
    assert opener.count == 0, "a request was made after clear()"
    assert TOKEN not in repr(ops)


# ================================================================ 3. the token


def test_set_token_refuses_a_bad_token_with_the_fixed_sentence():
    """A bad token is one fixed sentence: no token in it and no request made."""
    clock = Clock()
    opener = FakeOpener(fresh_answers(clock))
    ops = quotes(opener, clock)

    with pytest.raises(TiingoError) as raised:
        ops.set_token("tiingo " + CANARY + " token")
    assert_sentence(raised.value, SENTENCE_TOKEN_SHAPE, "set_token")
    assert ops.state() == "missing", "a refused token was stored anyway"

    ops.set_token(TOKEN)
    with pytest.raises(TiingoError) as raised:
        ops.set_token("tiingo " + CANARY + " token")
    assert_sentence(raised.value, SENTENCE_TOKEN_SHAPE, "set_token")
    assert ops.state() == "connected", "a refused token dropped the good one"
    assert opener.count == 0, "set_token reached the opener"


# ================================================================ 4. a good answer


def test_a_good_answer_is_a_decimal_price_and_an_epoch():
    """The answer is `(Decimal, epoch)` and the request has one shape only."""
    ops, opener, _ = connected(one(row(BASE, ticker="nvda")))

    price, at = ops.last("nvda")
    assert isinstance(price, D), price
    assert price == D("100.5"), price
    assert not isinstance(at, bool), at
    assert float(at) == BASE, at

    assert opener.count == 1
    # The symbol is upper-cased in the URL, and the token is nowhere else.
    assert_request(opener.requests[0])


def test_set_token_stores_the_trimmed_text():
    """Surrounding whitespace is trimmed, so the header carries the bare token."""
    ops, opener, _ = connected(one(row(BASE)), token=f"  {TOKEN}\n")

    assert ops.last(NVDA) is not None
    assert_request(opener.requests[0], token=TOKEN)


def test_an_integer_or_a_numeric_string_price_reads_as_a_decimal():
    """An integer price and a numeric string price both read as a Decimal."""
    ops, _, _ = connected(one(row(BASE, price=100)))
    assert ops.last(NVDA)[0] == D("100")

    ops, _, _ = connected(one(row(BASE, price="100.5")))
    assert ops.last(NVDA)[0] == D("100.5")


def test_last_sale_wins_and_falls_back_to_the_refresh_time():
    """`lastSaleTimestamp` is the print time when it parses, `timestamp` otherwise."""
    ops, _, _ = connected(
        one(row(BASE - 100.0, lastSaleTimestamp=iso(BASE - 5.0)))
    )
    assert float(ops.last(NVDA)[1]) == BASE - 5.0

    # A null last sale is no last sale: the refresh time stands.
    ops, _, _ = connected(
        one(row(BASE - 5.0, lastSaleTimestamp=None))
    )
    assert float(ops.last(NVDA)[1]) == BASE - 5.0

    # And so is a last sale that will not parse.
    ops, _, _ = connected(
        one(row(BASE - 5.0, lastSaleTimestamp="yesterday"))
    )
    assert float(ops.last(NVDA)[1]) == BASE - 5.0


def test_a_bare_object_is_an_answer_too():
    """The single-ticker URL answers a list of one, or one object."""
    ops, opener, _ = connected(bare(row(BASE, ticker="nvda")))

    price, at = ops.last("nvda")
    assert price == D("100.5")
    assert float(at) == BASE
    assert opener.count == 1
    assert_request(opener.requests[0])


def test_every_iso_offset_reads_as_the_same_epoch():
    """`Z`, `+00:00` and no offset at all are the same instant, read as UTC."""
    for suffix in ("Z", "+00:00", ""):
        ops, opener, _ = connected(one(row(BASE, timestamp=iso(BASE, suffix=suffix))))
        price, at = ops.last(NVDA)
        assert price == D("100.5"), suffix
        assert float(at) == BASE, suffix
        assert opener.count == 1, suffix


# ================================================================ 5. the refusals


def test_a_stale_print_or_a_print_from_the_future_is_refused():
    """A print older than MAX_AGE_S is too old; one in the future is no answer."""
    # At exactly `MAX_AGE_S` the print is still a last price — the ceiling is 300
    # seconds, and it is an age PAST it that a practice order no longer accepts.
    ops, opener, _ = connected(one(row(BASE - MAX_AGE_S)))
    price, printed_at = ops.last(NVDA)
    assert price == D("100.5"), price
    assert BASE - float(printed_at) == MAX_AGE_S, printed_at
    assert opener.count == 1

    ops, opener, _ = connected(one(canary_row(BASE - MAX_AGE_S - 1.0)))
    assert_sentence(refused(ops), SENTENCE_STALE, "stale")
    assert opener.count == 1

    ops, _, _ = connected(one(canary_row(BASE + 6.0)))
    assert_sentence(refused(ops), SENTENCE_BAD_ANSWER, "future")


def test_a_price_that_is_not_a_price_is_refused():
    """Only a finite number above zero is a price."""
    for name, price in (
        ("missing", DROP),
        ("null", None),
        ("bool", True),
        ("zero", 0),
        ("negative", -1.5),
        ("nan", float("nan")),
        ("text", "abc"),
    ):
        ops, opener, _ = connected(one(canary_row(BASE, price=price)))
        assert_sentence(refused(ops), SENTENCE_BAD_ANSWER, name)
        assert opener.count == 1, name


def test_no_usable_time_is_refused():
    """At least one of the two timestamps has to parse."""
    for name, changes in (
        ("none-at-all", {"timestamp": DROP}),
        ("null", {"timestamp": None}),
        ("text", {"timestamp": "yesterday"}),
        ("both-broken", {"timestamp": "x", "lastSaleTimestamp": "y"}),
    ):
        ops, opener, _ = connected(one(canary_row(BASE, **changes)))
        assert_sentence(refused(ops), SENTENCE_BAD_ANSWER, name)
        assert opener.count == 1, name


def test_a_wrong_ticker_or_a_wrong_shape_is_refused():
    """A ticker that is not the one asked for, and every shape that is no answer."""
    bodies = (
        ("wrong-ticker", one(canary_row(BASE, ticker=OTHER))),
        ("two-rows", listing(row(BASE), canary_row(BASE, ticker=OTHER))),
        ("empty-list", listing()),
        ("not-json", f"<html>{CANARY}</html>".encode("utf-8")),
        ("not-utf8", b"\xff\xfe" + CANARY.encode("ascii")),
        ("oversized", b"[" + b" " * MAX_BODY_BYTES),
        ("a-number", json.dumps(1).encode("utf-8")),
        ("a-string", json.dumps(CANARY).encode("utf-8")),
        ("null", json.dumps(None).encode("utf-8")),
    )
    for name, body in bodies:
        ops, opener, _ = connected(body)
        assert_sentence(refused(ops), SENTENCE_BAD_ANSWER, name)
        assert opener.count == 1, name


def test_a_bad_symbol_is_refused_before_any_request():
    """A symbol that is not a symbol never becomes a URL."""
    clock = Clock()
    for symbol in ("", "A B", "../x", "ABCDEFGHIJK"):
        ops, opener, _ = connected(fresh_answers(clock), clock=clock)
        assert_sentence(refused(ops, symbol), SENTENCE_SYMBOL, symbol)
        assert opener.count == 0, f"a request was made for {symbol!r}"


# ================================================================ 6. the cache


def test_the_cache_answers_without_a_request():
    """Inside the TTL a symbol is free; after it, one request."""
    clock = Clock()
    ops, opener, _ = connected(fresh_answers(clock), clock=clock)
    ttl = ops.cache_ttl()

    first = ops.last(NVDA)
    assert opener.count == 1
    assert isinstance(first[0], D)

    clock.advance(ttl - 1.0)
    second = ops.last("nvda")
    assert second == first
    assert opener.count == 1, "the cache did not answer"

    clock.advance(2.0)
    assert ops.last(NVDA) is not None
    assert opener.count == 2, "the cache outlived its TTL"


def test_a_stale_or_bad_answer_is_a_remembered_failure_not_a_price():
    """A refused answer is no price, and the sentence it earned is remembered.

    Nothing is cached as a price, and the next call inside `cache_ttl()` is the
    same sentence with no request at all; past the window the symbol is asked
    again, and a good answer is a price.
    """
    clock = Clock()
    opener = FakeOpener(one(row(BASE - MAX_AGE_S - 1.0)), fresh_answers(clock))
    ops = quotes(opener, clock)
    ops.set_token(TOKEN)
    ttl = ops.cache_ttl()

    assert_sentence(refused(ops), SENTENCE_STALE, "stale")
    assert_sentence(refused(ops), SENTENCE_STALE, "remembered stale")
    assert opener.count == 1, "a stale answer was cached or asked again"

    clock.advance(ttl + 1.0)
    assert ops.last(NVDA) is not None
    assert opener.count == 2, "the remembered failure outlived its window"

    # The good answer cleared the memory: the next call is a cache hit, not the
    # sentence the failure used to answer with.
    assert ops.last(NVDA) is not None
    assert opener.count == 2, "a success left the failure remembered"

    clock = Clock()
    opener = FakeOpener(f"<html>{CANARY}</html>".encode("utf-8"), fresh_answers(clock))
    ops = quotes(opener, clock)
    ops.set_token(TOKEN)

    assert_sentence(refused(ops), SENTENCE_BAD_ANSWER, "bad")
    assert_sentence(refused(ops), SENTENCE_BAD_ANSWER, "remembered bad")
    assert opener.count == 1, "a bad answer was cached or asked again"

    clock.advance(ops.cache_ttl() + 1.0)
    assert ops.last(NVDA) is not None
    assert opener.count == 2, "the remembered failure outlived its window"
    assert ops.last(NVDA) is not None
    assert opener.count == 2, "a success left the failure remembered"


def test_cache_time_scales_with_the_equity_product_count():
    """`cache_ttl()` is the floor or the products' own share, whichever is longer.

    One product: 90 s.  Two: 170 s.  Three: 255 s — `CACHE_PER_PRODUCT_S` for
    each product polled after the first.  Every one of those stays under the
    ceiling a print may be served at, which is what makes a cached price a price
    the engine can still price a practice order from.
    """
    assert CACHE_TTL_S == 90.0, CACHE_TTL_S
    assert CACHE_PER_PRODUCT_S == 85.0, CACHE_PER_PRODUCT_S

    clock = Clock()
    assert quotes(clock=clock).cache_ttl() == CACHE_TTL_BY_COUNT[1], (
        "the default count is one product"
    )

    for count, expected in CACHE_TTL_BY_COUNT.items():
        ops = quotes(clock=clock, product_count=lambda count=count: count)
        assert ops.cache_ttl() == expected, (count, ops.cache_ttl())

    # Fewer than one product is one product, and further products keep adding.
    for count in (0, -3):
        ops = quotes(clock=clock, product_count=lambda count=count: count)
        assert ops.cache_ttl() == CACHE_TTL_BY_COUNT[1], count

    with_four = CACHE_TTL_BY_COUNT[3] + CACHE_PER_PRODUCT_S
    assert quotes(clock=clock, product_count=lambda: 4).cache_ttl() == with_four, 4

    # A count that is not a whole number of products is one product.
    for answer in ("3", 2.5, None):
        ops = quotes(clock=clock, product_count=lambda answer=answer: answer)
        assert ops.cache_ttl() == CACHE_TTL_BY_COUNT[1], answer

    def raising() -> int:
        raise RuntimeError("no product list")

    assert quotes(clock=clock, product_count=raising).cache_ttl() == (
        CACHE_TTL_BY_COUNT[1]
    ), "a count that raises is one product"


def test_a_longer_cache_time_means_fewer_requests_an_hour():
    """Three products polled every 60 s stay inside the allowance with room."""
    for count in (1, 3):
        clock = Clock()
        sent: list[float] = []

        def answering(request, timeout=None, clock=clock, sent=sent):
            sent.append(clock())
            symbol = str(request.full_url).rsplit("/", 1)[-1]
            return FakeResponse(one(row(clock(), ticker=symbol)))

        ops = quotes(answering, clock, product_count=lambda count=count: count)
        ops.set_token(TOKEN)
        assert ops.cache_ttl() == CACHE_TTL_BY_COUNT[count], (count, ops.cache_ttl())
        symbols = [f"S{index}" for index in range(count)]

        refused_calls: list[tuple[int, str, str]] = []
        for minute in range(60):
            for symbol in symbols:
                try:
                    price = ops.last(symbol)
                except TiingoError as error:
                    refused_calls.append((minute, symbol, str(error)))
                    continue
                assert price is not None, (count, minute, symbol)
            clock.advance(60.0)

        assert refused_calls == [], (count, refused_calls)
        assert len(sent) <= MAX_PER_HOUR, (count, len(sent))
        assert ops.state() == "connected", (count, ops.state())


# ================================================================ 7. the ceilings


def test_at_most_max_per_hour_requests_an_hour():
    """The 46th request inside an hour is refused, and an hour later it is not."""
    clock = Clock()
    ops, opener, _ = connected(fresh_answers(clock), clock=clock)

    # Distinct symbols a second apart: nothing is a cache hit, and the whole run
    # stays inside one rolling hour.
    for index in range(MAX_PER_HOUR):
        assert ops.last(f"S{index}") is not None, index
        clock.advance(1.0)
    assert opener.count == MAX_PER_HOUR, opener.count

    assert_sentence(refused(ops, "OVER"), SENTENCE_BUDGET, "hourly")
    assert opener.count == MAX_PER_HOUR, "a request was made over the allowance"
    assert ops.state() == "paused", "a used-up allowance is the paused state"
    assert ops.message() == SENTENCE_PAUSED, ops.message()

    # An hour after the newest request the window is clear again.
    clock.advance(3600.0 + 1.0)
    assert ops.last("OVER") is not None
    assert opener.count == MAX_PER_HOUR + 1
    assert ops.state() == "connected", ops.state()
    assert ops.message() is None, ops.message()


def test_at_most_max_per_day_requests_a_day():
    """The day's ceiling refuses on its own, and a day later it is over."""
    clock = Clock()
    ops, opener, _ = connected(fresh_answers(clock), clock=clock)

    # 90 s apart is at most 41 requests in any rolling hour (under the hourly
    # ceiling) and 900 requests in 81,000 s (inside the day): only the day can
    # refuse here.
    for index in range(MAX_PER_DAY):
        assert ops.last(f"D{index}") is not None, index
        clock.advance(90.0)
    assert opener.count == MAX_PER_DAY, opener.count

    assert_sentence(refused(ops, "OVER"), SENTENCE_BUDGET, "daily")
    assert opener.count == MAX_PER_DAY, "a request was made over the allowance"
    assert ops.state() == "paused", "a used-up day is the paused state"
    assert ops.message() == SENTENCE_PAUSED, ops.message()

    clock.advance(86400.0 + 1.0)
    assert ops.last("OVER") is not None
    assert opener.count == MAX_PER_DAY + 1
    assert ops.state() == "connected", ops.state()


# ================================================================ 8. the 429


def test_a_429_pauses_every_request_and_a_cached_price_still_answers():
    """A 429 pauses the client; a fresh cached price answers, a miss does not."""
    clock = Clock()
    ops, opener, _ = connected(
        fresh_answers(clock), http_error(429), fresh_answers(clock), clock=clock
    )

    first = ops.last(NVDA)
    assert opener.count == 1

    assert_sentence(refused(ops, OTHER), SENTENCE_RATE_LIMITED, "429")
    assert opener.count == 2
    assert ops.state() == "paused", ops.state()
    assert ops.message() == SENTENCE_PAUSED, ops.message()

    # A price fetched before the pause is still a price during it, and it is free.
    assert ops.last(NVDA) == first
    assert opener.count == 2, "a cached price was asked for during the pause"

    # A symbol with no fresh price is a cache miss, and a miss is the pause.
    assert_sentence(refused(ops, OTHER), SENTENCE_RATE_LIMITED, "a cache miss")
    assert opener.count == 2, "a request was made inside the pause"

    # A cached entry older than the cache time is a miss too, and still the pause.
    clock.advance(ops.cache_ttl() + 1.0)
    assert_sentence(refused(ops, NVDA), SENTENCE_RATE_LIMITED, "an expired cache")
    assert opener.count == 2, "a request was made inside the pause"

    # A full pause later the client asks again.
    clock.advance(RATE_PAUSE_S)
    assert ops.last(OTHER) is not None
    assert opener.count == 3
    assert ops.state() == "connected", ops.state()


def test_a_retry_after_header_extends_the_pause():
    """A Retry-After of 1800 s holds the pause past our own 900 s."""
    clock = Clock()
    ops, opener, _ = connected(
        http_error(429, retry_after="1800"), fresh_answers(clock), clock=clock
    )

    assert_sentence(refused(ops), SENTENCE_RATE_LIMITED, "429")
    clock.advance(RATE_PAUSE_S + 1.0)
    assert_sentence(refused(ops, OTHER), SENTENCE_RATE_LIMITED, "901 s of 1800 s")
    assert opener.count == 1, "a request was made inside the pause"

    clock.advance(900.0)
    assert ops.last(OTHER) is not None
    assert opener.count == 2


def test_a_long_retry_after_is_capped_at_an_hour():
    """A Retry-After of 99,999 s means an hour, no more."""
    clock = Clock()
    ops, opener, _ = connected(
        http_error(429, retry_after="99999"), fresh_answers(clock), clock=clock
    )

    assert_sentence(refused(ops), SENTENCE_RATE_LIMITED, "429")
    clock.advance(3600.0 - 1.0)
    assert_sentence(refused(ops, OTHER), SENTENCE_RATE_LIMITED, "3599 s")
    assert opener.count == 1, "a request was made inside the pause"

    clock.advance(2.0)
    assert ops.last(OTHER) is not None
    assert opener.count == 2


# ================================================================ 9. the state


def test_a_429_pause_is_the_paused_state_with_its_own_sentence():
    """A pause in force reads `paused`, with the sentence that says it resumes."""
    assert SENTENCE_PAUSED == (
        "Stock prices are paused for now; they will resume on their own."
    )

    clock = Clock()
    ops, opener, _ = connected(http_error(429), fresh_answers(clock), clock=clock)
    assert ops.state() == "connected", "a client that has not asked is connected"

    assert_sentence(refused(ops), SENTENCE_RATE_LIMITED, "429")
    assert ops.state() == "paused", ops.state()
    assert ops.message() == SENTENCE_PAUSED, ops.message()

    # It is the pause that makes it paused: a whole pause later it is connected.
    clock.advance(RATE_PAUSE_S)
    assert ops.state() == "connected", ops.state()
    assert ops.message() is None, ops.message()
    assert ops.last(OTHER) is not None
    assert opener.count == 2


def test_a_rejected_token_outranks_a_used_up_allowance():
    """rejected is reported before paused, and a new token keeps the allowance."""
    clock = Clock()
    opener = FakeOpener(
        *([fresh_answers(clock)] * (MAX_PER_HOUR - 1) + [http_error(401)])
    )
    ops = quotes(opener, clock)
    ops.set_token(TOKEN)

    for index in range(MAX_PER_HOUR - 1):
        assert ops.last(f"R{index}") is not None, index
        clock.advance(1.0)
    assert_sentence(refused(ops, "LAST"), SENTENCE_REJECTED, "the last request")
    assert opener.count == MAX_PER_HOUR, opener.count
    assert ops.state() == "rejected", "paused outranked rejected"
    assert ops.message() == SENTENCE_REJECTED, ops.message()

    # The hour is used up all the same, so a new token is connected but paused.
    ops.set_token(NEW_TOKEN)
    assert ops.state() == "paused", ops.state()
    assert ops.message() == SENTENCE_PAUSED, ops.message()
    assert_sentence(refused(ops, "OVER"), SENTENCE_BUDGET, "after a new token")
    assert opener.count == MAX_PER_HOUR, opener.count

    # Disconnect takes the allowance with the token, so the next start is clean.
    ops.clear()
    ops.set_token(TOKEN)
    assert ops.state() == "connected", ops.state()
    assert ops.message() is None, ops.message()


def test_a_refused_token_stays_refused_until_a_new_one_is_set():
    """401 and 403 reject the token; nothing is asked for until it is replaced."""
    for code in (401, 403):
        clock = Clock()
        ops, opener, _ = connected(
            http_error(code), fresh_answers(clock), clock=clock
        )

        assert_sentence(refused(ops), SENTENCE_REJECTED, f"HTTP {code}")
        assert ops.state() == "rejected", code
        assert ops.message() == SENTENCE_REJECTED, code
        assert opener.count == 1, code

        # A rejected token makes no more requests, whatever is asked for.
        assert_sentence(refused(ops, OTHER), SENTENCE_REJECTED, "after rejection")
        assert opener.count == 1, "a rejected token still made a request"

        # A new token clears the mark, and the client asks again.
        ops.set_token(NEW_TOKEN)
        assert ops.state() == "connected", code
        assert ops.message() is None, code
        assert ops.last(OTHER) is not None, code
        assert opener.count == 2, code
        assert_request(opener.requests[1], symbol=OTHER, token=NEW_TOKEN)


def test_a_failed_request_leaves_the_state_alone():
    """A server error, an unreachable host and a timeout are one sentence, no mark."""
    for name, answer in (
        ("server-error", http_error(500)),
        ("unreachable", urllib.error.URLError("no route to host")),
        ("timeout", TimeoutError("timed out")),
    ):
        clock = Clock()
        ops, opener, _ = connected(answer, fresh_answers(clock), clock=clock)

        assert_sentence(refused(ops, OTHER), SENTENCE_UNREACHABLE, name)
        assert ops.state() == "connected", name
        assert ops.message() is None, name
        assert opener.count == 1, name


# ================================================================ 10. the check


def test_check_reads_one_fixed_ticker_and_stores_nothing():
    """A check asks for CHECK_SYMBOL with the token it is given, and keeps nothing."""
    clock = Clock()
    opener = FakeOpener(one(row(clock(), ticker=CHECK_SYMBOL)))
    ops = quotes(opener, clock)

    assert ops.check(TOKEN) is None
    assert opener.count == 1
    assert_request(opener.requests[0], symbol=CHECK_SYMBOL, token=TOKEN)

    # Nothing is stored: the client is exactly as unconnected as it was.
    assert ops.state() == "missing"
    assert ops.message() == SENTENCE_MISSING
    assert ops.last(NVDA) is None
    assert opener.count == 1, "a check stored a token"
    assert TOKEN not in repr(ops)


def test_check_passes_with_an_old_print():
    """A closed market is not a bad token: an old print still passes."""
    clock = Clock()
    opener = FakeOpener(one(row(BASE - 10_000.0, ticker=CHECK_SYMBOL)))
    ops = quotes(opener, clock)

    assert ops.check(TOKEN) is None
    assert opener.count == 1


def test_a_failed_check_is_not_remembered_for_the_symbol_it_read():
    """A check stores nothing, so its own failure is not that ticker's failure."""
    clock = Clock()
    opener = FakeOpener(TimeoutError("timed out"), fresh_answers(clock))
    ops = quotes(opener, clock)
    ops.set_token(TOKEN)

    with pytest.raises(TiingoError) as raised:
        ops.check(TOKEN)
    assert_sentence(raised.value, SENTENCE_UNREACHABLE, "check")

    # The ticker the check reads is a price like any other, and it is asked for.
    assert ops.last(CHECK_SYMBOL) is not None
    assert opener.count == 2, "a failed check was remembered against the ticker"


def test_check_does_not_count_on_the_budget():
    """The whole hourly allowance is still there after a check."""
    clock = Clock()
    opener = FakeOpener(fresh_answers(clock))
    ops = quotes(opener, clock)

    assert ops.check(TOKEN) is None
    assert opener.count == 1

    ops.set_token(TOKEN)
    for index in range(MAX_PER_HOUR):
        assert ops.last(f"S{index}") is not None, index
        clock.advance(1.0)
    assert opener.count == MAX_PER_HOUR + 1, opener.count

    assert_sentence(refused(ops, "OVER"), SENTENCE_BUDGET, "hourly")


def test_check_does_not_touch_the_stored_token():
    """A check that is refused leaves the stored token exactly as it was."""
    clock = Clock()
    ops, opener, _ = connected(http_error(401), fresh_answers(clock), clock=clock)

    with pytest.raises(TiingoError) as raised:
        ops.check(NEW_TOKEN)
    assert_sentence(raised.value, SENTENCE_REJECTED, "check refused")
    assert_request(opener.requests[0], symbol=CHECK_SYMBOL, token=NEW_TOKEN)
    assert ops.state() == "connected"
    assert ops.message() is None

    assert ops.last(NVDA) is not None
    assert_request(opener.requests[1])


def test_check_refuses_a_bad_token_without_a_request():
    """A token that is not one line of ASCII is refused before any read."""
    clock = Clock()
    ops, opener, _ = connected(fresh_answers(clock), clock=clock)

    with pytest.raises(TiingoError) as raised:
        ops.check("tiingo " + CANARY + " token")
    assert_sentence(raised.value, SENTENCE_TOKEN_SHAPE, "check token")
    assert opener.count == 0, "a check reached the opener with a bad token"


def test_check_sentences():
    """Every way a check fails has its own fixed sentence."""
    for name, answer, sentence in (
        ("refused", http_error(401), SENTENCE_REJECTED),
        ("forbidden", http_error(403), SENTENCE_REJECTED),
        ("rate-limited", http_error(429), SENTENCE_RATE_LIMITED),
        ("unreachable", urllib.error.URLError("no route to host"), SENTENCE_UNREACHABLE),
        ("timeout", TimeoutError("timed out"), SENTENCE_UNREACHABLE),
        ("not-json", f"<html>{CANARY}</html>".encode("utf-8"), SENTENCE_BAD_ANSWER),
        ("empty-list", listing(), SENTENCE_BAD_ANSWER),
        ("oversized", b"[" + b" " * MAX_BODY_BYTES, SENTENCE_BAD_ANSWER),
    ):
        clock = Clock()
        ops = quotes(FakeOpener(answer), clock)
        with pytest.raises(TiingoError) as raised:
            ops.check(TOKEN)
        assert_sentence(raised.value, sentence, name)
        assert ops.state() == "missing", name


# ================================================================ 11. the canary


def test_the_canary_is_in_no_failure(caplog):
    """Every failure again, with the canary in the token and in the body."""
    caplog.set_level(logging.DEBUG)

    cases = (
        (
            "token-shape",
            lambda ops: ops.set_token("tiingo " + CANARY + " token"),
            (),
            SENTENCE_TOKEN_SHAPE,
        ),
        (
            "symbol-shape",
            last("../" + CANARY),
            (fresh_answers(Clock()),),
            SENTENCE_SYMBOL,
        ),
        ("stale", last(), (one(canary_row(BASE - MAX_AGE_S - 1.0)),), SENTENCE_STALE),
        ("future", last(), (one(canary_row(BASE + 6.0)),), SENTENCE_BAD_ANSWER),
        ("price-missing", last(), (one(canary_row(price=DROP)),), SENTENCE_BAD_ANSWER),
        ("price-null", last(), (one(canary_row(price=None)),), SENTENCE_BAD_ANSWER),
        ("price-bool", last(), (one(canary_row(price=True)),), SENTENCE_BAD_ANSWER),
        ("price-zero", last(), (one(canary_row(price=0)),), SENTENCE_BAD_ANSWER),
        ("price-negative", last(), (one(canary_row(price=-1)),), SENTENCE_BAD_ANSWER),
        (
            "price-nan",
            last(),
            (one(canary_row(price=float("nan"))),),
            SENTENCE_BAD_ANSWER,
        ),
        ("price-text", last(), (one(canary_row(price="abc")),), SENTENCE_BAD_ANSWER),
        ("no-time", last(), (one(canary_row(timestamp=DROP)),), SENTENCE_BAD_ANSWER),
        (
            "time-text",
            last(),
            (one(canary_row(timestamp="yesterday")),),
            SENTENCE_BAD_ANSWER,
        ),
        (
            "wrong-ticker",
            last(),
            (one(canary_row(ticker=OTHER)),),
            SENTENCE_BAD_ANSWER,
        ),
        (
            "two-rows",
            last(),
            (listing(canary_row(), canary_row(ticker=OTHER)),),
            SENTENCE_BAD_ANSWER,
        ),
        ("empty-list", last(), (listing(),), SENTENCE_BAD_ANSWER),
        (
            "not-json",
            last(),
            (f"<html>{CANARY}</html>".encode("utf-8"),),
            SENTENCE_BAD_ANSWER,
        ),
        ("not-utf8", last(), (b"\xff\xfe",), SENTENCE_BAD_ANSWER),
        (
            "oversized",
            last(),
            (b"[" + b" " * MAX_BODY_BYTES,),
            SENTENCE_BAD_ANSWER,
        ),
        ("refused", last(), (http_error(401),), SENTENCE_REJECTED),
        ("forbidden", last(), (http_error(403),), SENTENCE_REJECTED),
        ("rate-limited", last(), (http_error(429),), SENTENCE_RATE_LIMITED),
        (
            "rate-limited-header",
            last(),
            (http_error(429, retry_after=CANARY),),
            SENTENCE_RATE_LIMITED,
        ),
        ("server-error", last(), (http_error(500),), SENTENCE_UNREACHABLE),
        (
            "unreachable",
            last(),
            (urllib.error.URLError(CANARY),),
            SENTENCE_UNREACHABLE,
        ),
        ("timeout", last(), (TimeoutError(CANARY),), SENTENCE_UNREACHABLE),
        (
            "check-token-shape",
            lambda ops: ops.check("tiingo " + CANARY + " token"),
            (),
            SENTENCE_TOKEN_SHAPE,
        ),
        (
            "check-refused",
            lambda ops: ops.check(CANARY_TOKEN),
            (http_error(401),),
            SENTENCE_REJECTED,
        ),
        (
            "check-rate-limited",
            lambda ops: ops.check(CANARY_TOKEN),
            (http_error(429),),
            SENTENCE_RATE_LIMITED,
        ),
        (
            "check-unreachable",
            lambda ops: ops.check(CANARY_TOKEN),
            (urllib.error.URLError(CANARY),),
            SENTENCE_UNREACHABLE,
        ),
        (
            "check-not-json",
            lambda ops: ops.check(CANARY_TOKEN),
            (f"<html>{CANARY}</html>".encode("utf-8"),),
            SENTENCE_BAD_ANSWER,
        ),
    )

    for name, act, script, sentence in cases:
        caplog.clear()
        clock = Clock()
        ops, opener, _ = connected(*script, token=CANARY_TOKEN, clock=clock)
        with pytest.raises(TiingoError) as raised:
            act(ops)
        assert_sentence(raised.value, sentence, name)
        assert CANARY not in caplog.text, (name, caplog.text)
        assert CANARY not in repr(ops), name
        for call in opener.requests:
            assert CANARY not in str(call.url), name

    # The budget sentence too, with the canary token in every request's header.
    caplog.clear()
    clock = Clock()
    ops, opener, _ = connected(fresh_answers(clock), token=CANARY_TOKEN, clock=clock)
    for index in range(MAX_PER_HOUR):
        assert ops.last(f"S{index}") is not None, index
        clock.advance(1.0)
    with pytest.raises(TiingoError) as raised:
        ops.last("OVER")
    assert_sentence(raised.value, SENTENCE_BUDGET, "budget")
    assert CANARY not in caplog.text, caplog.text
    assert CANARY not in repr(ops), repr(ops)


# ================================================================ 12. a remembered failure


def test_a_failed_request_is_remembered_for_the_cache_time():
    """A symbol that just failed answers its own sentence, with no request.

    The memory is per symbol, it lasts `cache_ttl()` from the failure, and a
    token set afterwards is a different token, so what the old one earned is
    forgotten along with it.
    """
    clock = Clock()
    ops, opener, _ = connected(
        TimeoutError("timed out"), fresh_answers(clock), clock=clock
    )
    ttl = ops.cache_ttl()

    assert_sentence(refused(ops), SENTENCE_UNREACHABLE, "the first failure")
    assert opener.count == 1

    # Inside the window the same symbol is the same sentence, and asks nothing.
    clock.advance(ttl - 1.0)
    assert_sentence(refused(ops), SENTENCE_UNREACHABLE, "remembered")
    assert opener.count == 1, "a remembered failure was asked again"

    # A symbol that never failed is asked for, and answers.
    assert ops.last(OTHER) is not None
    assert opener.count == 2, "one symbol's failure held another back"

    # And the first symbol is still remembered: the failure is per symbol, and
    # answering another one did not clear it.
    assert_sentence(refused(ops), SENTENCE_UNREACHABLE, "still remembered")
    assert opener.count == 2

    # A new token is a new generation, so nothing the old one earned is left.
    ops.set_token(NEW_TOKEN)
    assert ops.last(NVDA) is not None
    assert opener.count == 3
    assert_request(opener.requests[2], token=NEW_TOKEN)


def test_clear_forgets_a_remembered_failure():
    """Disconnect is a clean start: the remembered failure goes with the token."""
    clock = Clock()
    ops, opener, _ = connected(
        TimeoutError("timed out"), fresh_answers(clock), clock=clock
    )

    assert_sentence(refused(ops), SENTENCE_UNREACHABLE, "the first failure")
    ops.clear()
    assert ops.last(NVDA) is None
    assert opener.count == 1, "a request was made with no token"

    ops.set_token(TOKEN)
    assert ops.last(NVDA) is not None
    assert opener.count == 2, "a cleared failure was still remembered"


def test_a_remembered_failure_counts_on_the_allowance():
    """A failed request is a request: failures spend the allowance too."""
    clock = Clock()
    ops, opener, _ = connected(TimeoutError("timed out"), clock=clock)

    for index in range(MAX_PER_HOUR):
        assert_sentence(refused(ops, f"F{index}"), SENTENCE_UNREACHABLE, index)
        clock.advance(1.0)
    assert opener.count == MAX_PER_HOUR, opener.count

    assert_sentence(refused(ops, "OVER"), SENTENCE_BUDGET, "the allowance")
    assert opener.count == MAX_PER_HOUR, "a request was made over the allowance"
    assert ops.state() == "paused", ops.state()


def test_an_outage_is_bounded_by_the_failure_memory():
    """Three symbols, every read a timeout, polled twice a minute for an hour.

    A minute holds a poll and a dry advance, so without a memory every cycle
    spends three requests, each one holding its caller for `TIMEOUT_S`.  Three
    equity products give the client a `cache_ttl()` of their own share, and a
    failure remembered per symbol for that long makes the hour cost one request
    per symbol per window: no minute carries more than one request per symbol,
    the total stays under the count the window allows, and no cycle is spent on
    the allowance instead of the outage.
    """
    clock = Clock()
    sent: list[float] = []

    def timing_out(request, timeout=None):
        sent.append(clock())
        raise TimeoutError("timed out")

    symbols = [f"SYM{index}" for index in range(3)]
    ops = quotes(timing_out, clock, product_count=lambda: len(symbols))
    ops.set_token(TOKEN)
    ttl = ops.cache_ttl()
    assert ttl == CACHE_TTL_BY_COUNT[len(symbols)], ttl

    first_cycle: list[str] = []
    for minute in range(60):
        for call in range(2):
            for symbol in symbols:
                if minute == 0 and call == 0:
                    first_cycle.append(symbol)
                assert_sentence(
                    refused(ops, symbol),
                    SENTENCE_UNREACHABLE,
                    (minute, call, symbol),
                )
        clock.advance(60.0)

    # The first poll tried each symbol exactly once.
    assert first_cycle == symbols, first_cycle
    # One request per symbol per window, and not one more.
    assert len(sent) <= 3 * (3600.0 / ttl + 1), len(sent)
    # No minute anywhere carries more than one request per symbol.
    for at in sent:
        in_a_minute = sum(1 for other in sent if at <= other <= at + 60.0)
        assert in_a_minute <= len(symbols), (at, in_a_minute)
    # An outage is no reason to reject a token that was never refused.
    assert ops.state() == "connected", ops.state()


# ================================================================ 13. the generation counter


def test_a_refusal_from_a_request_of_an_older_token_leaves_no_mark():
    """A 401 that lands after `set_token` is the old request's, not the new token's."""
    clock = Clock()
    calls: list[Call] = []
    box: dict[str, TiingoQuotes] = {}

    def answer(request, timeout=None):
        calls.append(Call(request, timeout))
        if len(calls) == 1:
            # The owner pastes a new token while this request is in flight.
            box["ops"].set_token(NEW_TOKEN)
            raise http_error(401)
        symbol = str(request.full_url).rsplit("/", 1)[-1]
        return FakeResponse(one(row(clock(), ticker=symbol)))

    ops = quotes(answer, clock)
    box["ops"] = ops
    ops.set_token(TOKEN)

    assert_sentence(refused(ops), SENTENCE_REJECTED, "the old token's refusal")
    assert ops.state() == "connected", "the new token was marked rejected"
    assert ops.message() is None, ops.message()

    # The new token is what the next request carries, and it is answered.
    assert ops.last(NVDA) is not None
    assert len(calls) == 2, calls
    assert_request(calls[1], token=NEW_TOKEN)


def test_a_cache_write_or_a_remembered_failure_of_an_older_token_is_dropped():
    """An answer and a failure both belong to the token their request was made with."""
    clock = Clock()

    # A good answer fetched with the old token is this call's, and nothing more.
    good_calls: list[Call] = []
    good_box: dict[str, TiingoQuotes] = {}

    def answering(request, timeout=None):
        good_calls.append(Call(request, timeout))
        if len(good_calls) == 1:
            good_box["ops"].set_token(NEW_TOKEN)
        symbol = str(request.full_url).rsplit("/", 1)[-1]
        return FakeResponse(one(row(clock(), ticker=symbol)))

    ops = quotes(answering, clock)
    good_box["ops"] = ops
    ops.set_token(TOKEN)

    assert ops.last(NVDA)[0] == D(PRICE)
    assert ops.last(NVDA)[0] == D(PRICE)
    assert len(good_calls) == 2, "an answer fetched with the old token was cached"
    assert_request(good_calls[1], token=NEW_TOKEN)

    # A failure fetched with the old token is not remembered against the new one.
    bad_calls: list[Call] = []
    bad_box: dict[str, TiingoQuotes] = {}

    def failing(request, timeout=None):
        bad_calls.append(Call(request, timeout))
        if len(bad_calls) == 1:
            bad_box["ops"].set_token(NEW_TOKEN)
            raise TimeoutError("timed out")
        symbol = str(request.full_url).rsplit("/", 1)[-1]
        return FakeResponse(one(row(clock(), ticker=symbol)))

    ops = quotes(failing, clock)
    bad_box["ops"] = ops
    ops.set_token(TOKEN)

    assert_sentence(refused(ops), SENTENCE_UNREACHABLE, "the old token's failure")
    assert ops.last(NVDA) is not None
    assert len(bad_calls) == 2, "a failure of the old token was remembered"
    assert_request(bad_calls[1], token=NEW_TOKEN)


# ================================================================ 14. the timeout


def test_the_request_times_out_after_five_seconds():
    """TIMEOUT_S is 5, and the price read and the check both use it."""
    assert TIMEOUT_S == 5

    clock = Clock()
    ops, opener, _ = connected(fresh_answers(clock), clock=clock)

    assert ops.last(NVDA) is not None
    assert opener.requests[0].timeout == TIMEOUT_S, opener.requests[0]

    assert ops.check(TOKEN) is None
    assert opener.requests[1].timeout == TIMEOUT_S, opener.requests[1]


# ================================================================ 15. redirects


class Loopback:
    """One loopback HTTP server on a thread: what it was asked, and its answer.

    *answer* is handed the handler, so a server here is either the origin a
    redirect points at or the one that redirects.  Every request is recorded with
    the `Authorization` header it carried, which is what "the second origin was
    never asked" is read from.
    """

    def __init__(self, answer) -> None:
        self.seen: list[tuple[str, str | None]] = []
        seen = self.seen

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen.append((self.path, self.headers.get("Authorization")))
                answer(self)

            def log_message(self, *args) -> None:
                """Silence: a test server writes no access log."""

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "Loopback":
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> bool:
        self.server.shutdown()
        self.server.server_close()
        return False


def answering_with(clock: Clock):
    """The origin's answer: one good IEX row for whatever ticker the path names."""

    def answer(handler) -> None:
        symbol = handler.path.rsplit("/", 1)[-1] or NVDA
        body = one(row(clock(), ticker=symbol))
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    return answer


def redirecting_to(location: str):
    """A 302 to *location*, whose `{symbol}` is the ticker the request named."""

    def answer(handler) -> None:
        symbol = handler.path.rsplit("/", 1)[-1] or NVDA
        handler.send_response(302)
        handler.send_header("Location", location.replace("{symbol}", symbol))
        handler.end_headers()

    return answer


def test_a_redirect_is_refused_and_the_second_origin_is_never_asked(monkeypatch):
    """A 3xx is an unreachable host: no second request, and the token goes nowhere.

    Two loopback servers stand in for two origins.  The first answers every
    request with a 302 to the second, which would answer a perfectly good IEX row
    — and the first case redirects to the same host on another port, so a client
    that followed it certainly would reach it.  This client refuses the status
    instead: both the `last` and the `check` are `SENTENCE_UNREACHABLE`, the second
    server records no request at all and no `Authorization` header, and the token
    reaches the first server's own request only.
    """
    # The real opener resolves proxies from the environment; a loopback test
    # server is reached directly or not at all.
    for name in (
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)

    clock = Clock()
    with Loopback(answering_with(clock)) as origin:
        targets = (
            ("another-origin", f"http://127.0.0.1:{origin.port}/iex/{{symbol}}"),
            ("an-http-url", f"http://localhost:{origin.port}/iex/{{symbol}}"),
        )
        for name, location in targets:
            with Loopback(redirecting_to(location)) as redirector:
                monkeypatch.setattr(
                    tiingo_module,
                    "IEX_URL",
                    f"http://127.0.0.1:{redirector.port}/iex/{{symbol}}",
                )
                ops = tiingo_module.TiingoQuotes(now=clock)
                ops.set_token(TOKEN)

                assert_sentence(refused(ops), SENTENCE_UNREACHABLE, f"last {name}")
                with pytest.raises(TiingoError) as raised:
                    ops.check(TOKEN)
                assert_sentence(raised.value, SENTENCE_UNREACHABLE, f"check {name}")

                # The redirecting server carried the token; the other never spoke.
                assert len(redirector.seen) == 2, (name, redirector.seen)
                for path, authorization in redirector.seen:
                    assert authorization == f"Token {TOKEN}", (name, authorization)
                    assert TOKEN not in path, (name, path)
                assert origin.seen == [], (name, origin.seen)
                assert ops.state() == "connected", name


# ================================================================ 16. the print's age


def test_max_age_is_the_freshness_ceiling_the_engine_imports():
    """`MAX_AGE_S` is the engine's freshness CEILING, imported and not restated.

    A practice (dry) stock order accepts a print up to the ceiling while live
    orders keep the strict bound, so the ceiling is the longest bound in the
    engine's per-book table — and a client that refused a younger print, or
    accepted an older one, would disagree with the engine about the same price.
    One literal per bound, read through `exchange`, and the `MarketData` default
    tightens nothing on its own: the book decides.
    """
    ceiling = getattr(exchange_module, "EQUITY_FRESHNESS_CEILING_S", None)
    assert ceiling is not None, (
        "crow_coinbase.exchange.EQUITY_FRESHNESS_CEILING_S is missing: the "
        "client's MAX_AGE_S is a second literal instead of the engine's ceiling"
    )
    table = getattr(exchange_module, "EQUITY_MAX_AGE_BY_BOOK", None)
    assert isinstance(table, dict) and table, table

    assert MAX_AGE_S == ceiling == max(table.values()), (MAX_AGE_S, ceiling, table)
    assert MAX_AGE_S == 300.0, MAX_AGE_S
    assert exchange_module.DEFAULT_EQUITY_QUOTE_MAX_AGE_S == 120.0, (
        exchange_module.DEFAULT_EQUITY_QUOTE_MAX_AGE_S
    )
    assert table.get("dry") == MAX_AGE_S, table
    assert table.get("live") == exchange_module.DEFAULT_EQUITY_QUOTE_MAX_AGE_S, table

    bound_for = getattr(exchange_module, "equity_max_age_for", None)
    assert callable(bound_for), (
        "crow_coinbase.exchange.equity_max_age_for is missing: the age bound has "
        "to come from the book through the table and from nowhere else"
    )
    assert bound_for("dry") == MAX_AGE_S, bound_for("dry")
    for other in ("live", None, "unknown", 3):
        assert bound_for(other) == exchange_module.DEFAULT_EQUITY_QUOTE_MAX_AGE_S, other

    # The quote bound is the book's, so the constructor's own default is no bound.
    default = inspect.signature(exchange_module.MarketData.__init__).parameters[
        "equity_max_age_s"
    ].default
    assert default is None, default


def test_a_cached_print_reaches_max_age_before_the_cache_time_does():
    """No price lives past a `MAX_AGE_S` print, however much cache time is left.

    Four products earn 340 s of cache time, which is LONGER than the ceiling a
    print may be served at, so what ends this entry is the print's own age and
    not the clock on the fetch: a print 2 s old when it is fetched is a price for
    the next 298 s, and at `MAX_AGE_S` the entry is dropped and the symbol is
    asked for again.
    """
    clock = Clock()
    printed = clock() - 2.0
    opener = FakeOpener(one(row(printed)), fresh_answers(clock))
    ops = quotes(opener, clock, product_count=lambda: 4)
    ops.set_token(TOKEN)
    assert ops.cache_ttl() > MAX_AGE_S, ops.cache_ttl()

    first = ops.last(NVDA)
    assert opener.count == 1
    assert clock() - first[1] == 2.0, first

    # The print is 299 s old: still under the ceiling, and answered for free.
    clock.advance(MAX_AGE_S - 3.0)
    assert ops.last(NVDA) == first
    assert opener.count == 1, "the cache did not answer"

    # One second more is `MAX_AGE_S`: the rule is a print younger than that, so
    # the entry is dropped and a fresh one is asked for.
    clock.advance(1.0)
    fresh = ops.last(NVDA)
    assert opener.count == 2, "a cached print at its max age was served"
    assert clock() - fresh[1] < MAX_AGE_S, fresh
    assert fresh != first, fresh


def test_a_cached_print_too_old_is_not_served_during_a_429_pause():
    """A pause answers from the cache only while the cached print is still young.

    A price fetched before a 429 keeps answering inside the pause — but only
    while its print is younger than `MAX_AGE_S`.  Once it is not, there is no
    price to hand over, and a pause with no price is the rate-limited sentence.
    """
    clock = Clock()
    opener = FakeOpener(
        one(row(clock() - 2.0)), http_error(429), fresh_answers(clock)
    )
    ops = quotes(opener, clock, product_count=lambda: 4)
    ops.set_token(TOKEN)
    assert ops.cache_ttl() > MAX_AGE_S, ops.cache_ttl()

    first = ops.last(NVDA)
    assert_sentence(refused(ops, OTHER), SENTENCE_RATE_LIMITED, "429")
    assert opener.count == 2
    assert ops.state() == "paused", ops.state()

    # Inside the cache time by the fetch, and inside the print's own age: a price.
    clock.advance(MAX_AGE_S - 3.0)
    assert ops.last(NVDA) == first
    assert opener.count == 2, "a cached price was asked for during the pause"

    # One second more and the print is `MAX_AGE_S` old: no price during the pause.
    clock.advance(1.0)
    assert_sentence(refused(ops, NVDA), SENTENCE_RATE_LIMITED, "an old cached print")
    assert opener.count == 2, "a request was made inside the pause"


# ================================================================ 17. the paused error


def tiingo_paused_class() -> type:
    """`tiingo.TiingoPaused`: the error the two paused sentences are raised as."""
    paused = getattr(tiingo_module, "TiingoPaused", None)
    assert paused is not None, (
        "crow_coinbase.tiingo.TiingoPaused is missing: a caller cannot tell a "
        "pause from a fault"
    )
    assert issubclass(paused, TiingoError), paused
    return paused


def test_a_pause_is_the_tiingo_paused_error():
    """Tiingo limiting requests and our own used-up allowance are both pauses."""
    paused_class = tiingo_paused_class()

    clock = Clock()
    ops, opener, _ = connected(http_error(429), fresh_answers(clock), clock=clock)
    with pytest.raises(paused_class) as raised:
        ops.last(NVDA)
    assert_sentence(raised.value, SENTENCE_RATE_LIMITED, "429")
    assert isinstance(raised.value, paused_class)
    assert opener.count == 1

    clock = Clock()
    ops, opener, _ = connected(fresh_answers(clock), clock=clock)
    for index in range(MAX_PER_HOUR):
        assert ops.last(f"S{index}") is not None, index
        clock.advance(1.0)

    with pytest.raises(paused_class) as raised:
        ops.last("OVER")
    assert_sentence(raised.value, SENTENCE_BUDGET, "hourly")
    assert isinstance(raised.value, paused_class)
    assert opener.count == MAX_PER_HOUR, "a request was made over the allowance"

    # Another symbol inside the same pause is the same pause: no price at all.
    with pytest.raises(paused_class) as raised:
        ops.last(OTHER)
    assert_sentence(raised.value, SENTENCE_BUDGET, "hourly, another symbol")


def test_every_other_failure_is_a_plain_tiingo_error():
    """A stale print, a bad answer, an unreachable host and a refusal are faults."""
    paused_class = tiingo_paused_class()

    for name, answer, sentence in (
        ("stale", one(canary_row(BASE - MAX_AGE_S - 1.0)), SENTENCE_STALE),
        ("bad-answer", f"<html>{CANARY}</html>".encode("utf-8"), SENTENCE_BAD_ANSWER),
        ("unreachable", TimeoutError("timed out"), SENTENCE_UNREACHABLE),
        ("rejected", http_error(401), SENTENCE_REJECTED),
        ("server-error", http_error(500), SENTENCE_UNREACHABLE),
    ):
        clock = Clock()
        ops, opener, _ = connected(answer, clock=clock)
        with pytest.raises(TiingoError) as raised:
            ops.last(NVDA)
        assert_sentence(raised.value, sentence, name)
        assert not isinstance(raised.value, paused_class), (name, raised.value)
        assert opener.count == 1, name

    # The two refusals made before any request are faults as well.
    clock = Clock()
    ops, opener, _ = connected(fresh_answers(clock), clock=clock)
    with pytest.raises(TiingoError) as raised:
        ops.last("../" + CANARY)
    assert_sentence(raised.value, SENTENCE_SYMBOL, "symbol")
    assert not isinstance(raised.value, paused_class), raised.value

    with pytest.raises(TiingoError) as raised:
        ops.set_token("tiingo " + CANARY + " token")
    assert_sentence(raised.value, SENTENCE_TOKEN_SHAPE, "token shape")
    assert not isinstance(raised.value, paused_class), raised.value
    assert opener.count == 0, "a refusal reached the opener"
