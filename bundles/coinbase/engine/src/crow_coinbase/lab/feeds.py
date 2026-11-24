"""The two fetchers the lab's command line hands to the back-fill.

`PublicCandles` reads the public candle endpoint and returns the parsed JSON, the
shape `backfill._candles` reads a "candles" list out of.  `fetch_tiingo_csv`
reads one symbol's daily prices as CSV text.

Both take their opener as an argument, defaulting to `urllib.request.urlopen`,
so a caller can drive every request without a connection.  The Tiingo token goes
in the request header and nowhere else: not in the URL, not in an error message.
Every request names the lab in its user agent rather than leaving urllib's
default there.

A candle request the endpoint may still answer — a 429, any 5xx, a connection
that was refused — is tried again, up to three attempts in total, waiting
between them a back-off that doubles and is never shorter than the endpoint's
own Retry-After.  A later page of a walk waits `page_pause` before it goes out,
so a whole-history back-fill is not one burst of requests.  `sleep` is injected
as well as the opener, so a caller can record the waits instead of living
through them.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

__all__ = ["FeedError", "PublicCandles", "fetch_tiingo_csv"]

CANDLES_URL = (
    "https://api.coinbase.com/api/v3/brokerage/market/products/{product}/candles"
)
TIINGO_URL = "https://api.tiingo.com/tiingo/daily/{symbol}/prices"

DEFAULT_TIMEOUT = 30

# The user agent every request to either feed carries.
USER_AGENT = "crow-lab/0.1"

# A candle request is tried this many times in total before it is a FeedError.
RETRY_ATTEMPTS = 3

# The longest Retry-After the walk waits out, in seconds.
RETRY_AFTER_CAP = 60

# The pause before a later page, so a walk does not arrive as one burst.
PAGE_PAUSE = 0.15

# A ticker is letters, digits, dots and dashes; anything else is refused before
# a URL is built from it.
SYMBOL_EXTRA_CHARS = frozenset(".-")

TOKEN_HEADER = "Authorization"

CANDLE_FEED = "the public candle feed"
PRICE_FEED = "the price feed"

# What a token that is not one line of printable ASCII is refused with.
TOKEN_SENTENCE = (
    "The Tiingo token is not valid: it must be one line of letters and digits."
)
# What a request that could not be built at all is refused with; nothing the
# caller passed is quoted back, so the token never reaches the sentence.
UNBUILDABLE_SENTENCE = (
    "The Tiingo request could not be built; check the symbol and the token."
)
# What a rate-limited price request is refused with: the free plan's limits.
RATE_LIMIT_SENTENCE = (
    "the price feed is rate limited: its free plan allows 50 requests/hour and "
    "1,000/day, so wait before asking again"
)


class FeedError(Exception):
    """A feed request that could not be answered, with a plain sentence."""


# ---------------------------------------------------------------- retries


def _retriable(exc) -> bool:
    """True for an answer a later attempt can change: a 429 or any 5xx."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or exc.code >= 500
    return isinstance(exc, urllib.error.URLError)


def _retry_after(exc) -> int:
    """The Retry-After an answer named, in whole seconds, or 0.

    Only a whole number of seconds is read; an HTTP date is left to the back-off,
    and no wait longer than `RETRY_AFTER_CAP` is taken from the header.
    """
    headers = getattr(exc, "headers", None)
    if headers is None:
        return 0
    raw = headers.get("Retry-After")
    if raw is None:
        return 0
    text = str(raw).strip()
    if not text.isdigit():
        return 0
    return min(int(text), RETRY_AFTER_CAP)


def _pause_seconds(attempt: int, exc=None) -> int:
    """How long to wait after failed attempt number *attempt*, in seconds.

    The back-off doubles with every attempt and is never shorter than the wait
    the endpoint itself asked for.
    """
    asked = 0 if exc is None else _retry_after(exc)
    return max(2 ** (attempt - 1), asked)


# ---------------------------------------------------------------- text of a body


def _text_of(body) -> str:
    """The response body as UTF-8 text."""
    if isinstance(body, bytes):
        return body.decode("utf-8")
    return str(body)


# ---------------------------------------------------------------- candles


class PublicCandles:
    """The public candle endpoint, read through an injected opener.

    `granularity` is the endpoint's own name for the interval ("ONE_DAY",
    "ONE_HOUR"); `start` and `end` are unix seconds, as strings or whole numbers.
    `sleep` takes the pause between pages and between attempts, so a caller can
    pass a recorder in its place.
    """

    def __init__(
        self,
        opener=urllib.request.urlopen,
        sleep=time.sleep,
        page_pause: float = PAGE_PAUSE,
    ):
        self.opener = opener
        self.sleep = sleep
        self.page_pause = page_pause
        self._pages = 0

    def get_public_candles(
        self,
        product_id,
        start,
        end,
        granularity,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> dict:
        """The endpoint's parsed JSON for one product and one window."""
        if self._pages:
            self.sleep(self.page_pause)
        self._pages += 1
        query = urllib.parse.urlencode(
            {
                "start": str(start),
                "end": str(end),
                "granularity": str(granularity),
            }
        )
        product = urllib.parse.quote(str(product_id), safe="")
        request = urllib.request.Request(
            CANDLES_URL.format(product=product) + "?" + query,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        body = self._read(request, timeout)
        try:
            text = _text_of(body)
        except UnicodeDecodeError:
            raise FeedError(f"{CANDLE_FEED} answered with text that is not UTF-8") from None
        try:
            payload = json.loads(text)
        except ValueError:
            raise FeedError(f"{CANDLE_FEED} answered with something that is not JSON") from None
        if not isinstance(payload, dict):
            raise FeedError(f"{CANDLE_FEED} answered with JSON that is not an object")
        return payload

    def _read(self, request, timeout) -> bytes:
        """One request's body, retried while the answer is one a wait can change."""
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                with self.opener(request, timeout=timeout) as response:
                    return response.read()
            except urllib.error.HTTPError as exc:
                if not _retriable(exc) or attempt == RETRY_ATTEMPTS:
                    raise FeedError(
                        f"{CANDLE_FEED} refused the request (HTTP {exc.code})"
                    ) from None
                self.sleep(_pause_seconds(attempt, exc))
            except urllib.error.URLError as exc:
                if attempt == RETRY_ATTEMPTS:
                    raise FeedError(
                        f"{CANDLE_FEED} could not be reached: {exc.reason}"
                    ) from None
                self.sleep(_pause_seconds(attempt))
            except OSError as exc:
                raise FeedError(f"{CANDLE_FEED} could not be reached: {exc}") from None
        raise FeedError(f"{CANDLE_FEED} did not answer")


# ---------------------------------------------------------------- tiingo


def _valid_symbol(symbol) -> bool:
    """True for letters, digits, dots and dashes only."""
    if not isinstance(symbol, str) or not symbol:
        return False
    return all(char.isalnum() or char in SYMBOL_EXTRA_CHARS for char in symbol)


def _valid_token(token) -> bool:
    """True for one line of printable ASCII, the shape a token file holds.

    A token of two lines, or one carrying a control character or a character
    outside ASCII, is refused before any request is built from it.
    """
    if not isinstance(token, str):
        return False
    text = token.strip()
    if not text:
        return False
    return all(32 <= ord(char) <= 126 for char in text)


def _start_text(start_date) -> str:
    """A start date as the YYYY-MM-DD text the query takes."""
    stamp = getattr(start_date, "isoformat", None)
    if callable(stamp):
        return stamp()
    return str(start_date)


def fetch_tiingo_csv(
    symbol,
    token,
    start_date=None,
    *,
    opener=urllib.request.urlopen,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """One symbol's daily prices as CSV text, with the token in the header.

    `start_date` is a `date`, a datetime or YYYY-MM-DD text, and is left out of
    the query when it is None.  A symbol that is not letters, digits, dots and
    dashes is refused before a request is built, and so is a token that is not
    one line of printable ASCII; an error message never carries the token.  The
    token rides an unredirected `Authorization` header, so a redirect answers
    with a request that does not carry it to wherever that redirect points.
    """
    if not _valid_symbol(symbol):
        raise FeedError(
            "a ticker is letters, digits, dots and dashes only: "
            f"{symbol!r}"
        )
    if not _valid_token(token):
        raise FeedError(TOKEN_SENTENCE)
    try:
        query = {"format": "csv"}
        if start_date is not None:
            query["startDate"] = _start_text(start_date)
        request = urllib.request.Request(
            TIINGO_URL.format(symbol=symbol) + "?" + urllib.parse.urlencode(query),
            headers={"Accept": "text/csv", "User-Agent": USER_AGENT},
        )
        request.add_unredirected_header(TOKEN_HEADER, f"Token {token.strip()}")
        with opener(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise FeedError(RATE_LIMIT_SENTENCE) from None
        raise FeedError(f"{PRICE_FEED} refused the request (HTTP {exc.code})") from None
    except urllib.error.URLError as exc:
        raise FeedError(f"{PRICE_FEED} could not be reached: {exc.reason}") from None
    except OSError as exc:
        raise FeedError(f"{PRICE_FEED} could not be reached: {exc}") from None
    except ValueError:
        raise FeedError(UNBUILDABLE_SENTENCE) from None
    try:
        return _text_of(body)
    except UnicodeDecodeError:
        raise FeedError(f"{PRICE_FEED} answered with text that is not UTF-8") from None