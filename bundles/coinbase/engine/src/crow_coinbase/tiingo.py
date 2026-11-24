"""tiingo.py: the last price of one stock ticker, held in memory only.

The engine asks this module for one number about an equity it does not trade
live: the latest price Tiingo reports for a ticker, and the time that price was
printed, as `(Decimal, epoch seconds)`.  Everything the engine does with a price
— the staleness bound it already applies, the regular-session check, the dry
fill an equity order rests at — reads that pair and nothing else here.

The token, in plain words.  The owner pastes a Tiingo token into Crow, and it
reaches this process through the engine's own route; the route hands it to
`set_token`.  From there it lives in this object's memory and goes nowhere:

* it is kept in memory only — never written to a file, a database row, a kv row,
  an environment variable, an event, an audit row or a log line,
* it travels in the request's `Authorization` header only — never in the URL, a
  query string, the User-Agent or a command line — and it is added as an
  UNREDIRECTED header, so no handler could carry it to a second origin,
* it never comes back out.  `__repr__` shows the state and not the token, every
  refusal is one of the fixed sentences below, and nothing here quotes a
  response body, a header value or the text of an exception it caught.  A
  sentence is the whole of what a caller may show a person,
* it is checked before any request is built: one line of printable ASCII, no
  spaces, so a token pasted with a line break or with a second word around it is
  refused instead of half-sent.

Every refusal is a plain sentence a person can read, so the surface can put it
straight on a card: the token's shape, a token Tiingo would not take, Tiingo
limiting requests, our own request allowance, an unreachable host, an answer
that cannot be used, a price too old to use, no token at all, a bad symbol, and
the pause that says prices resume on their own.  The two that ARE a pause rather
than a fault — Tiingo limiting requests, and our own allowance used up — are
raised as `TiingoPaused`, so a caller can report them once and quietly; every
other sentence is a plain `TiingoError`.

What the client asks of Tiingo, and what it does with the answer.  One ticker at
a time from the IEX endpoint, one request per call and no retry (the engine polls
again in a minute, so a retry only spends allowance), each one bounded by
`TIMEOUT_S` (five seconds: a request that will not answer must not hold the
engine's caller any longer than that).  Redirects are never followed: the default
opener hands the request to an `HTTPRedirectHandler` whose `redirect_request`
answers `None`, so a 3xx is an `HTTPError` like any other refused status and
becomes `SENTENCE_UNREACHABLE` — no second request is made and the token reaches
no other origin.

A good answer is cached per symbol (upper-cased) for `cache_ttl()`, measured from
the moment it was fetched — and only while its own print is younger than
`MAX_AGE_S`.  That time is not one number: it is `CACHE_TTL_S` or the equity
products' own share, whichever is longer, where the share is
`CACHE_PER_PRODUCT_S` (85 s) times the number of equity products the client is
told the engine trades (`product_count`, a callable because the engine's list can
be re-read).  More symbols polled means a longer wait per symbol and the same
allowance left for all of them; a count that cannot be read, or is not a whole
number of products, is one product.  One product is 90 s (40 requests an hour),
two 170 s (42.4) and three 255 s (42.4), all inside `MAX_PER_HOUR`, and a served
print is therefore at most one cache time plus one fetch's lag old — under the
ceiling a practice order accepts.

The client keeps its own conservative ceilings — `MAX_PER_HOUR` requests in a
rolling hour, `MAX_PER_DAY` in a rolling day — under the free plan's planning
numbers, and every request it sends counts against them, a failed one included.
A 429 pauses every request for `RATE_PAUSE_S` (or longer if Tiingo's own
`Retry-After` asks, up to an hour), and a 401 or 403 marks the token rejected so
no further request is made with it until the owner sets a new one.

The four states a surface reports are `connected`, `missing`, `rejected` and
`paused`: `missing` is no token, `rejected` a token Tiingo refused, and `paused`
a token that is fine but cannot be asked right now — a 429 pause is in force, or
the hour's or the day's allowance is used up.  Each has its own sentence, and
`connected` alone has none.

A price is not the only thing the client remembers.  A failed read — unreachable,
an answer it cannot use, a print too old — is remembered per symbol for
`cache_ttl()` as well, and a call inside that window raises the same sentence
again without a request: an outage polled every minute must not spend the
allowance on one symbol, and a repeated sentence is what the engine's "one
warning per episode" reads.  A success clears that symbol's memory, and so does
a new token or a `clear()`.

A token set while a request is in flight is a new generation (`_generation`, one
more on every `set_token` and every `clear`).  The request records the generation
it started with, and a rejection mark, a rate pause, a cache write and a
remembered failure are applied only if the token has not changed meanwhile — an
answer (or a refusal) fetched with the token the owner just replaced says
nothing about the new one.

The price is `tngoLast`; its time is `lastSaleTimestamp` when that parses and the
`timestamp` field otherwise.  `timestamp` is the moment Tiingo last refreshed its
own data, which is the closest thing to a trade time an unentitled account can
read, so it is what the staleness bound measures.  The bound is the engine's
freshness CEILING (`MAX_AGE_S`, imported from `exchange` and never restated
here): the loosest age any book prices from, which is what a practice (dry) stock
order takes while a live order keeps the engine's strict bound.  A print older
than the ceiling is refused at fetch, and a cached print is dropped once it
reaches it; a print from the future is no answer at all.

`check(token)` is the one read that keeps nothing: a single request for a fixed
liquid ticker with the token it is handed, so a person can find out whether a
token works before it is stored.  It never touches the stored token's state and
never counts against the allowance, and it accepts an old print — a closed market
is not a bad token.

Nothing here reaches the network on its own terms beyond that one opener: the
opener, the clock and the product count are arguments, so a test hands over its
own fakes.  The token is never read from the environment or from a compose file;
there is no code path in this module that could.
"""

from __future__ import annotations

import json
import math
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Optional

# How old a print may be and still be the last price.  This is NOT a number of
# this module's own: it is the engine's freshness ceiling
# (`EQUITY_FRESHNESS_CEILING_S`), the loosest bound any book prices from, imported
# so the client and the engine can never disagree about the age of the same price.
# A practice (dry) stock order accepts a print up to that ceiling; a live order
# keeps the strict bound the engine applies itself.  So the client refuses a print
# older than the ceiling at fetch (SENTENCE_STALE) and drops a cached one once its
# print reaches it — a price the engine would refuse is never handed over,
# whatever cache time the products earned.
from .exchange import EQUITY_FRESHNESS_CEILING_S as MAX_AGE_S

# One ticker's last price, and the ticker is the only thing that goes in the URL.
IEX_URL = "https://api.tiingo.com/iex/{symbol}"

# How long a good answer answers for, and our own ceilings on how often the
# client may ask (conservative numbers under the free plan's, not Tiingo's).
CACHE_TTL_S = 90.0

# How much longer the cache time gets per equity product the engine trades: every
# symbol the engine polls is asked about once per window, so the allowance is
# spread over the products instead of being spent by the first few.  85 s is the
# largest share that keeps a list of products inside `MAX_PER_HOUR`: one product
# 90 s (40 requests an hour), two 170 s (42.4) and three 255 s (42.4).
CACHE_PER_PRODUCT_S = 85.0

MAX_PER_HOUR = 45
MAX_PER_DAY = 900

# How long a 429 keeps every request back, and the longest a Retry-After may ask
# for: no pause is worth more than an hour, because a day's allowance is 900.
RATE_PAUSE_S = 900.0
RETRY_AFTER_CAP_S = 3600.0

# One try, and how long it may take: a request that will not answer must not hold
# the engine's caller longer than this.
TIMEOUT_S = 5

# How far in the future a print may sit before it is no answer at all.  Some
# clock skew between this host and Tiingo is normal; minutes of it are not.
FUTURE_SKEW_S = 5.0

USER_AGENT = "crow-coinbase/0.4"

# The ticker a check reads: liquid, and a symbol Tiingo always answers for.
CHECK_SYMBOL = "SPY"

# The most of a body this client will look at, and the longest token it takes.
MAX_BODY_BYTES = 65536
MAX_TOKEN_CHARS = 256

# The four answers `state()` gives, and the sentences `message()` adds.
STATE_CONNECTED = "connected"
STATE_MISSING = "missing"
STATE_REJECTED = "rejected"
STATE_PAUSED = "paused"

# The fixed sentences.  Every raise in this module hands over exactly one of
# these strings: no token, URL, header, response body or caught exception's text
# is ever part of one.
SENTENCE_TOKEN_SHAPE = (
    "The Tiingo token must be one line of letters and digits."
)
SENTENCE_REJECTED = "Tiingo did not accept the token."
SENTENCE_RATE_LIMITED = (
    "Tiingo is limiting requests right now; stock prices will resume on their own."
)
SENTENCE_BUDGET = (
    "Crow has used its hourly or daily allowance of stock price requests; "
    "prices will resume on their own."
)
SENTENCE_UNREACHABLE = "Tiingo could not be reached."
SENTENCE_BAD_ANSWER = "Tiingo's answer could not be used."
SENTENCE_STALE = "Tiingo's latest price is too old to use."
SENTENCE_MISSING = "Stock prices are not connected."
SENTENCE_SYMBOL = "That is not a stock symbol."
SENTENCE_PAUSED = (
    "Stock prices are paused for now; they will resume on their own."
)

# The failures a symbol is remembered for: a request that reached nobody, an
# answer that cannot be used, and a print too old to be a last price.  A refused
# token and a rate limit have state marks of their own and are not remembered
# per symbol.
_REMEMBERED_FAILURES = frozenset(
    (SENTENCE_UNREACHABLE, SENTENCE_BAD_ANSWER, SENTENCE_STALE)
)

# The characters a ticker may be made of, and how long one may be.
_SYMBOL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"
)
_SYMBOL_MAX_CHARS = 10

# The two windows the allowance is counted over.
_HOUR_S = 3600.0
_DAY_S = 86400.0

# The lowest and highest printable ASCII character a token may be made of, so a
# token is one line with no spaces in it.
_TOKEN_LOW = 33
_TOKEN_HIGH = 126


class TiingoError(Exception):
    """One of the fixed sentences above, and nothing else.

    A token, a URL, a header, an answer's body and the text of an exception this
    module caught all stay out of what a caller (and a log line about it) can
    show, because the only strings ever raised are the `SENTENCE_*` constants.
    """


class TiingoPaused(TiingoError):
    """No price right now because we are PAUSED, not because anything failed.

    The two sentences that are a pause — `SENTENCE_RATE_LIMITED` (Tiingo limiting
    requests) and `SENTENCE_BUDGET` (our own hourly or daily allowance used up) —
    are raised as this class, and every other sentence stays a plain
    `TiingoError`.  Both heal on their own, so a caller that reports faults once
    per episode can tell them apart and say so quietly instead; the sentence a
    person reads is the same either way.
    """


class _HttpRefusal(Exception):
    """An HTTP status the client will not read past: the status and its pause.

    Tiingo refusing a token and Tiingo limiting requests are the two outcomes
    that leave a mark on the client's state, so the status is carried from the
    request to the caller that knows what to mark.  Its own message is a constant
    word, never a URL, a body or an exception's text.
    """

    def __init__(self, status: int, retry_after: Optional[float]) -> None:
        super().__init__("refused")
        self.status = int(status)
        self.retry_after = retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that follows nothing: `redirect_request` answers None.

    A 3xx is then no answer this client accepts, and the opener's own default
    error handler raises `HTTPError` for it, which `_read` reports as
    `SENTENCE_UNREACHABLE`.  Nothing is asked of the origin a redirect names, so
    the token can reach no host but the one in `IEX_URL`.
    """

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: Any,
        headers: Any,
        newurl: Any,
    ) -> None:
        """Refuse to build the follow-up request, so the redirect is an error."""
        return None


# The opener every client uses unless a caller (or a test) hands over its own:
# the standard handlers, with the redirect one replaced by `_NoRedirect`.
_DEFAULT_OPENER = urllib.request.build_opener(_NoRedirect).open


def _one_product() -> int:
    """The default `product_count`: an install with one equity product."""
    return 1


def valid_token(token: Any) -> bool:
    """Whether *token* is one line of printable ASCII, non-empty and short enough.

    The surrounding whitespace a paste brings with it is not part of the token,
    so it is trimmed before the shape is judged; the inside must be printable
    ASCII with no spaces and no control characters, which is what makes it one
    line and what keeps it out of a header line of its own.
    """
    if not isinstance(token, str):
        return False
    text = token.strip()
    if not text or len(text) > MAX_TOKEN_CHARS:
        return False
    return all(_TOKEN_LOW <= ord(char) <= _TOKEN_HIGH for char in text)


def valid_symbol(symbol: Any) -> bool:
    """Whether *symbol* is a ticker a person could have meant: 1 to 10 characters.

    Letters, digits, dots and dashes only, so a symbol never carries a slash, a
    space or a newline into the URL it becomes.
    """
    if not isinstance(symbol, str):
        return False
    if not 1 <= len(symbol) <= _SYMBOL_MAX_CHARS:
        return False
    return all(char in _SYMBOL_CHARS for char in symbol)


def _bad_answer() -> TiingoError:
    """A fresh error carrying the sentence an unusable answer earns."""
    return TiingoError(SENTENCE_BAD_ANSWER)


def _field(row: dict, name: str) -> Any:
    """The value of *name* in *row*, whatever case the field's own name is in."""
    wanted = name.lower()
    for key, value in row.items():
        if isinstance(key, str) and key.lower() == wanted:
            return value
    return None


def _answer_row(body: bytes) -> dict:
    """The one object an IEX answer carries, or the sentence for a body that has none.

    The single-ticker URL is documented as a list of one object and reported as
    one object, so both are answers; anything else — an unreadably long body, a
    body that is not UTF-8, a body that is not JSON, a list of two, a number, a
    string, null — is a `TiingoError` whose sentence names none of it.
    """
    if not isinstance(body, (bytes, bytearray)) or len(body) > MAX_BODY_BYTES:
        raise _bad_answer()
    try:
        text = bytes(body).decode("utf-8")
    except UnicodeDecodeError:
        raise _bad_answer() from None
    try:
        answer = json.loads(text)
    except (ValueError, RecursionError):
        raise _bad_answer() from None
    if isinstance(answer, dict):
        return answer
    if isinstance(answer, list) and len(answer) == 1 and isinstance(answer[0], dict):
        return answer[0]
    raise _bad_answer()


def _decimal(text: str) -> Decimal:
    """*text* as a Decimal, or the sentence for a price that is not one."""
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError):
        raise _bad_answer() from None


def _price(value: Any) -> Decimal:
    """The price in a `tngoLast` field: a finite number above zero, as a Decimal.

    Both a JSON number and a numeric string are prices.  A missing field, null, a
    boolean (which Python would otherwise read as 1), zero, a negative, a nan, an
    infinity, and text that is not a number are each nothing this client can use.
    """
    if isinstance(value, bool) or value is None:
        raise _bad_answer()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise _bad_answer()
        amount = _decimal(text)
    elif isinstance(value, (int, float)):
        amount = _decimal(str(value))
    else:
        raise _bad_answer()
    if not amount.is_finite() or amount <= 0:
        raise _bad_answer()
    return amount


def _epoch(value: Any) -> Optional[float]:
    """An ISO 8601 timestamp as epoch seconds, or None when it does not parse.

    A `Z` suffix and a `+00:00` offset are the same instant, and a timestamp that
    names no zone at all is read as UTC.  Anything that is not a string, or a
    string that is not a timestamp, answers None so the caller can try the next
    field.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    try:
        seconds = stamp.timestamp()
    except (OverflowError, OSError, ValueError):
        return None
    return seconds if math.isfinite(seconds) else None


def _print_time(row: dict) -> float:
    """When the price was printed: the last sale's time, else the refresh time.

    `lastSaleTimestamp` is the moment of the trade itself, when the account is
    entitled to it; the `timestamp` field is the moment Tiingo last refreshed its
    data, which is what a plain account can read.  A null or unparsable last sale
    falls through to the refresh time, and neither parsing is no answer.
    """
    for name in ("lastSaleTimestamp", "timestamp"):
        seconds = _epoch(_field(row, name))
        if seconds is not None:
            return seconds
    raise _bad_answer()


def _retry_after(refused: urllib.error.HTTPError) -> Optional[float]:
    """The whole number of seconds a `Retry-After` header asks for, or None.

    Anything that is not a whole number of seconds — a date, a word, a header
    that is not there — answers None, which leaves our own pause in force.  The
    value is never quoted anywhere; it only becomes a pause length.
    """
    try:
        headers = refused.headers
        value = headers.get("Retry-After") if headers is not None else None
    except (AttributeError, TypeError):
        return None
    if value is None:
        return None
    try:
        return float(int(str(value).strip()))
    except (TypeError, ValueError):
        return None


def _pause_seconds(retry_after: Optional[float]) -> float:
    """How long a 429 holds every request back: our own pause, or the longer ask.

    `RATE_PAUSE_S` is the floor and an hour is the ceiling, so a `Retry-After`
    may extend the pause but never strand the client for longer than a day's
    allowance would anyway.
    """
    if retry_after is None:
        return RATE_PAUSE_S
    return max(RATE_PAUSE_S, min(retry_after, RETRY_AFTER_CAP_S))


class TiingoQuotes:
    """Stock prices from Tiingo, in this process's memory only.

    `opener` is the module's own no-redirect opener in production and a fake in a
    test, and it is called as `opener(request, timeout=TIMEOUT_S)` with a
    `Request` whose only secret is in its unredirected `Authorization` header.
    `now` is the clock every age and every window is measured with.  `sleep` is
    accepted for the shape a retrying client would have and is never used: there
    is no retry here, because the engine's next poll is a minute away.
    `product_count` answers how many equity products the engine trades, which is
    what `cache_ttl()` scales the cache time by.

    One lock guards the token, the cache, the remembered failures, the pause, the
    rejected mark and the request times, so two threads polling two symbols see
    one budget.  The request itself is made outside the lock, so a slow answer
    never holds up a second caller.
    """

    def __init__(
        self,
        *,
        opener: Callable[..., Any] = _DEFAULT_OPENER,
        now: Callable[[], float] = time.time,
        sleep: Optional[Callable[[float], None]] = None,
        product_count: Callable[[], Any] = _one_product,
    ) -> None:
        self._opener = opener
        self._now = now
        self._product_count = product_count
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._rejected = False
        self._pause_until: Optional[float] = None
        self._cache: dict[str, tuple[float, tuple[Decimal, float]]] = {}
        self._failures: dict[str, tuple[float, str]] = {}
        self._sent: list[float] = []
        self._generation = 0

    # ------------------------------------------------------------ the token

    def set_token(self, token: Any) -> None:
        """Keep *token*, trimmed, in memory; refuse anything that is not one line.

        A token of the wrong shape is one fixed sentence and changes nothing, so
        a bad paste never drops the token that was working.  A good one clears a
        rejected mark and any rate pause — it is a different token, so what the
        last one earned does not apply — and empties the cache and the remembered
        failures, whose answers and sentences were earned with the old token.  It
        is also a new generation, so a request already in flight leaves no mark.
        """
        if not valid_token(token):
            raise TiingoError(SENTENCE_TOKEN_SHAPE)
        clean = str(token).strip()
        with self._lock:
            self._generation += 1
            self._token = clean
            self._rejected = False
            self._pause_until = None
            self._cache.clear()
            self._failures.clear()

    def clear(self) -> None:
        """Forget the token and everything measured with it: the engine's Disconnect.

        The cache, the remembered failures, the pause, the rejected mark and the
        request times go too, so a token set after a clear starts from a clean
        allowance.  It is a new generation for the same reason `set_token` is.
        """
        with self._lock:
            self._generation += 1
            self._token = None
            self._rejected = False
            self._pause_until = None
            self._cache.clear()
            self._failures.clear()
            self._sent = []

    def state(self) -> str:
        """`connected`, `missing`, `rejected` or `paused`: what a surface may say.

        `missing` outranks everything — with no token there is nothing to be
        rejected or paused — and `rejected` outranks `paused`, because a token
        Tiingo will not take has to be replaced before any wait matters.  `paused`
        is a token that is fine but cannot be asked right now: a 429 pause is in
        force, or the hour's or the day's allowance is used up.
        """
        with self._lock:
            if self._token is None:
                return STATE_MISSING
            if self._rejected:
                return STATE_REJECTED
            now = float(self._now())
            if self._in_pause(now) or self._over_budget(now):
                return STATE_PAUSED
            return STATE_CONNECTED

    def message(self) -> Optional[str]:
        """The one sentence a surface shows for the state, or None when connected."""
        state = self.state()
        if state == STATE_MISSING:
            return SENTENCE_MISSING
        if state == STATE_REJECTED:
            return SENTENCE_REJECTED
        if state == STATE_PAUSED:
            return SENTENCE_PAUSED
        return None

    # ------------------------------------------------------------ a price

    def last(self, symbol: Any) -> Optional[tuple[Decimal, float]]:
        """The last price of *symbol* and when it was printed, or None with no token.

        With no token the answer is None and no request is made: the engine turns
        that into "no equity quote available", so a dry stock order does not fill.
        With a token, every reason not to ask is a fixed sentence — a symbol that
        is not one, a rejected token, a rate pause, our own allowance — and each
        of them is decided before a request is built.  The two paused sentences
        are raised as `TiingoPaused`; every other sentence is a plain
        `TiingoError`.

        A cached answer is served only while BOTH hold: it was fetched less than
        `cache_ttl()` ago, and its own print is younger than `MAX_AGE_S` — the
        engine's freshness ceiling — at `now()`.  A cached price the engine would
        refuse is no price, so an entry whose print has reached the ceiling is
        dropped here and the call goes on to the allowance check and the request:
        the cache time a list of products earns can be longer than the ceiling,
        and the ceiling is what wins.  A price fetched before a pause still
        answers inside it, by the same rule.

        The symbol's own remembered failure answers in the same window: the last
        read of it failed, so asking again this minute would only spend the
        allowance on the same outage.  A request the client refuses outright
        (401, 403, 429) is never remembered per symbol.

        Otherwise exactly one request goes out, and it counts against the
        allowance whether it answers or not.  A good answer is cached with the
        moment it was fetched and clears the symbol's remembered failure; a
        failure is remembered instead — both only if the token has not changed
        since the request started, because another token's answer is no answer
        about this one.
        """
        with self._lock:
            token = self._token
            if token is None:
                return None
            if not valid_symbol(symbol):
                raise TiingoError(SENTENCE_SYMBOL)
            wanted = str(symbol).upper()
            if self._rejected:
                raise TiingoError(SENTENCE_REJECTED)
            now = float(self._now())
            ttl = self.cache_ttl()
            cached = self._cache.get(wanted)
            if cached is not None:
                fetched_at, answer = cached
                if now - fetched_at < ttl and now - answer[1] < MAX_AGE_S:
                    return answer
                # The fetch's own clock ran out, or the print behind it is at the
                # age no book would price from: either way it is not a price now.
                del self._cache[wanted]
            remembered = self._failures.get(wanted)
            if remembered is not None and now - remembered[0] < ttl:
                raise TiingoError(remembered[1])
            if self._in_pause(now):
                raise TiingoPaused(SENTENCE_RATE_LIMITED)
            if self._over_budget(now):
                raise TiingoPaused(SENTENCE_BUDGET)
            generation = self._generation
            self._sent.append(now)
        try:
            body = self._read(wanted, token)
        except _HttpRefusal as refusal:
            error = self._refusal(refusal, marks=True, generation=generation)
            self._remember(wanted, error, generation)
            raise error from None
        except TiingoError as error:
            self._remember(wanted, error, generation)
            raise
        try:
            price, printed_at = self._answer(body, wanted)
        except TiingoError as error:
            self._remember(wanted, error, generation)
            raise
        with self._lock:
            if generation == self._generation:
                self._cache[wanted] = (float(self._now()), (price, printed_at))
                self._failures.pop(wanted, None)
        return price, printed_at

    def check(self, token: Any) -> None:
        """Ask Tiingo one fixed ticker with *token*, and keep nothing at all.

        This is the "does this token work" read: it never stores the token, never
        touches the stored one's state (a refused check leaves a working token
        working and marks nothing), never counts against the allowance, reads no
        cache, remembers no failure and never reads the clock's windows.  A
        well-formed answer passes however old its print is, because a closed
        market is not a bad token.
        """
        if not valid_token(token):
            raise TiingoError(SENTENCE_TOKEN_SHAPE)
        clean = str(token).strip()
        with self._lock:
            generation = self._generation
        try:
            body = self._read(CHECK_SYMBOL, clean)
        except _HttpRefusal as refusal:
            raise self._refusal(
                refusal, marks=False, generation=generation
            ) from None
        _answer_row(body)

    def cache_ttl(self) -> float:
        """How long a good answer answers for: the floor, or the products' share.

        `CACHE_PER_PRODUCT_S` per equity product the engine trades, never below
        `CACHE_TTL_S`, so an engine polling many symbols asks about each of them
        less often and the hourly allowance covers all of them.  A count that
        raises, or that is not a whole number of products (a string, a fraction,
        `None`), is one product: this is a cache time, not a place to fail.
        """
        count = 1
        try:
            answer = self._product_count()
        except Exception:  # noqa: BLE001 - a count that raises is one product
            answer = None
        if isinstance(answer, int) and not isinstance(answer, bool):
            count = max(1, answer)
        return max(CACHE_TTL_S, count * CACHE_PER_PRODUCT_S)

    # ------------------------------------------------------------ the request

    def _read(self, symbol: str, token: str) -> bytes:
        """One request for *symbol*, and the bounded body it answered.

        The token is in the `Authorization` header and nowhere else, and it is
        added as an UNREDIRECTED header even though no redirect is followed, so
        no handler could put it on a second request.  A status the client refuses
        on comes back as `_HttpRefusal` so the caller that knows the state can
        mark it; every way the host can fail to answer is `SENTENCE_UNREACHABLE`,
        with no retry and no exception text kept.
        """
        request = urllib.request.Request(
            IEX_URL.format(symbol=symbol),
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        request.add_unredirected_header("Authorization", f"Token {token}")
        try:
            with self._opener(request, timeout=TIMEOUT_S) as answer:
                return answer.read(MAX_BODY_BYTES + 1)
        except urllib.error.HTTPError as refused:
            raise _HttpRefusal(refused.code, _retry_after(refused)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise TiingoError(SENTENCE_UNREACHABLE) from None

    def _refusal(
        self, refusal: _HttpRefusal, *, marks: bool, generation: int
    ) -> TiingoError:
        """The sentence a refused request earns, and the mark it leaves when it may.

        A 401 or 403 is the token itself being refused, so with *marks* the token
        is marked rejected and no further request is made with it.  A 429 is
        Tiingo limiting us, so with *marks* every request pauses.  Any other
        status — a redirect included — is a host that could not answer us, which
        leaves the state alone.  Both marks belong to the request's own
        generation: a refusal that lands after the owner set a new token says
        nothing about the new one.
        """
        with self._lock:
            current = generation == self._generation
            if refusal.status in (401, 403):
                if marks and current:
                    self._rejected = True
                return TiingoError(SENTENCE_REJECTED)
            if refusal.status == 429:
                if marks and current:
                    pause = _pause_seconds(refusal.retry_after)
                    self._pause_until = float(self._now()) + pause
                return TiingoPaused(SENTENCE_RATE_LIMITED)
        return TiingoError(SENTENCE_UNREACHABLE)

    def _remember(
        self, symbol: str, error: TiingoError, generation: int
    ) -> None:
        """Remember *symbol*'s failure for `cache_ttl()`, unless it is another token's.

        Only the three failures that are about this symbol are remembered (an
        unreachable host, an unusable answer, a print too old): a refused token
        and a rate limit have marks of their own.  The write is skipped when the
        token changed while the request was in flight, which is the same rule the
        cache follows.
        """
        sentence = str(error)
        if sentence not in _REMEMBERED_FAILURES:
            return
        with self._lock:
            if generation != self._generation:
                return
            self._failures[symbol] = (float(self._now()), sentence)

    def _answer(self, body: bytes, symbol: str) -> tuple[Decimal, float]:
        """The price and print time in *body*, or the sentence for a body that has none.

        The row has to name the ticker that was asked for, carry a price that is a
        price, and carry a print time that parses.  A print more than
        `FUTURE_SKEW_S` ahead of this host's clock is no answer, and one older
        than `MAX_AGE_S` is too old to be a last price.
        """
        row = _answer_row(body)
        ticker = _field(row, "ticker")
        if not isinstance(ticker, str) or ticker.strip().upper() != symbol:
            raise _bad_answer()
        price = _price(_field(row, "tngoLast"))
        printed_at = _print_time(row)
        now = float(self._now())
        if printed_at > now + FUTURE_SKEW_S:
            raise _bad_answer()
        if now - printed_at > MAX_AGE_S:
            raise TiingoError(SENTENCE_STALE)
        return price, printed_at

    # ------------------------------------------------------------ the allowance

    def _in_pause(self, now: float) -> bool:
        """Whether a 429 pause still holds every request back."""
        return self._pause_until is not None and now < self._pause_until

    def _over_budget(self, now: float) -> bool:
        """Whether the rolling hour or the rolling day is used up.

        The request times older than a day are dropped first, so the list is never
        longer than one day's ceiling; the hour is then counted over what is left.
        Every request that was sent counts, a failed one included: what the
        allowance measures is what Tiingo was asked.
        """
        cutoff = now - _DAY_S
        self._sent = [at for at in self._sent if at > cutoff]
        hour_ago = now - _HOUR_S
        in_hour = sum(1 for at in self._sent if at > hour_ago)
        return in_hour >= MAX_PER_HOUR or len(self._sent) >= MAX_PER_DAY

    # ------------------------------------------------------------ the shape

    def __repr__(self) -> str:
        """The state only: a representation that can be logged without a token."""
        return f"TiingoQuotes(state={self.state()!r})"
