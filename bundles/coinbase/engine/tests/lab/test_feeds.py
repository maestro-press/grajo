"""lab/feeds.py: the two stdlib fetchers, driven by injected openers.

Neither case here opens a connection: every URL, header and body is read off a
fake opener that the fetcher is handed, so the tests assert the request the
fetcher builds and the answer it returns.
"""

from __future__ import annotations

from email.message import Message
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from crow_coinbase.lab.feeds import (
    TOKEN_HEADER,
    FeedError,
    PublicCandles,
    fetch_tiingo_csv,
)

TOKEN = "FAKE-TOKEN-123"
PRODUCT = "XRP-USDC"

# The one header every request to either feed carries.
USER_AGENT = "crow-lab/0.1"

# The two sentences the fetchers say instead of explaining themselves.
TOKEN_SENTENCE = (
    "The Tiingo token is not valid: it must be one line of letters and digits."
)
UNBUILDABLE_SENTENCE = (
    "The Tiingo request could not be built; check the symbol and the token."
)

CANDLES_ENDPOINT = "https://api.coinbase.com/api/v3/brokerage/market/products"

# 1704067200 is 2024-01-01 00:00 UTC; one day is 86400 s, so the inclusive end
# of the same UTC day is 1704067200 + 86400 - 1 = 1704153599.
START = "1704067200"
END = "1704153599"

CANDLE_BODY = (
    b'{"candles": [{"start": "1704067200", "open": "1.00", '
    b'"high": "1.01", "low": "0.99", "close": "1.00", "volume": "100"}]}'
)

TIINGO_HEADER = (
    "date,close,high,low,open,volume,adjClose,adjHigh,adjLow,adjOpen,"
    "adjVolume,divCash,splitFactor"
)
TIINGO_BODY = (
    TIINGO_HEADER
    + "\n"
    + "2024-06-10,100,102,97,98,500,100,102,97,98,500,0,1\n"
).encode("utf-8")


# ---------------------------------------------------------------- fake opener


class FakeResponse:
    """The part of an http response the fetchers read."""

    status = 200

    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def getcode(self):
        return 200

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeOpener:
    """An opener that records every request and answers with one body.

    It raises `error` instead of answering when one is set, and it accepts the
    extra positional and keyword arguments `urllib.request.urlopen` takes.
    """

    def __init__(self, body=b"", error=None):
        self.body = body
        self.error = error
        self.requests = []

    def __call__(self, request, *args, **kwargs):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return FakeResponse(self.body)

    @property
    def urls(self):
        return [_url_of(request) for request in self.requests]


class ScriptedOpener:
    """An opener that works through a list of outcomes, one per call.

    Each outcome is either a body to answer with or an exception to raise, and
    the last outcome repeats, so a one-item list answers every call the same
    way.  Nothing here opens a connection.
    """

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def __call__(self, request, *args, **kwargs):
        self.requests.append(request)
        index = min(len(self.requests) - 1, len(self.outcomes) - 1)
        outcome = self.outcomes[index]
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResponse(outcome)

    @property
    def urls(self):
        return [_url_of(request) for request in self.requests]


def _http_error(code, *, retry_after=None):
    """An HTTPError of *code*, carrying Retry-After when one is given."""
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return HTTPError(CANDLES_ENDPOINT, code, "error", headers, None)


def _url_of(request):
    """The URL of an opener argument, whether it is a Request or a string."""
    return getattr(request, "full_url", None) or str(request)


def _query(url):
    """The parsed query string of *url*."""
    return parse_qs(urlsplit(url).query, keep_blank_values=True)


def _headers(request):
    """The request's headers, keyed case-insensitively.

    urllib keeps a header added with `add_unredirected_header` in
    `unredirected_hdrs` rather than in `headers`, so both are gathered here: a
    header a fetcher sets is read the same way whichever call set it, and the
    token test below looks at `unredirected_hdrs` alone to see that the header
    is one a redirect cannot carry.
    """
    items = getattr(request, "header_items", None)
    found = dict(items()) if callable(items) else {}
    found.update(getattr(request, "unredirected_hdrs", None) or {})
    return {name.lower(): value for name, value in found.items()}


def _candles(client):
    """One whole-history candle request, the arguments the tests share."""
    return client.get_public_candles(
        PRODUCT, start=START, end=END, granularity="ONE_DAY"
    )


# ---------------------------------------------------------------- user agent


def test_every_request_carries_the_lab_user_agent():
    candles_opener = FakeOpener(CANDLE_BODY)
    _candles(PublicCandles(opener=candles_opener, sleep=lambda seconds: None))

    assert _headers(candles_opener.requests[0]).get("user-agent") == USER_AGENT

    tiingo_opener = FakeOpener(TIINGO_BODY)
    fetch_tiingo_csv("NVDA", TOKEN, "2016-01-01", opener=tiingo_opener)

    assert _headers(tiingo_opener.requests[0]).get("user-agent") == USER_AGENT


# ---------------------------------------------------------------- page pauses


def test_page_pause_sleeps_only_before_a_later_page():
    sleeps = []
    opener = FakeOpener(CANDLE_BODY)
    client = PublicCandles(opener=opener, sleep=sleeps.append)

    _candles(client)
    # The first page of an instance goes out at once.
    assert sleeps == []

    _candles(client)
    # Every later page waits the pause out first.
    assert sleeps == [0.15]
    assert len(opener.requests) == 2


def test_page_pause_is_the_configured_interval():
    sleeps = []
    client = PublicCandles(
        opener=FakeOpener(CANDLE_BODY), sleep=sleeps.append, page_pause=0.5
    )

    _candles(client)
    _candles(client)
    _candles(client)

    assert sleeps == [0.5, 0.5]


# ---------------------------------------------------------------- retries


def test_a_429_is_retried_after_a_one_second_pause():
    opener = ScriptedOpener([_http_error(429), CANDLE_BODY])
    sleeps = []
    client = PublicCandles(opener=opener, sleep=sleeps.append)

    payload = _candles(client)

    assert payload["candles"]
    assert len(opener.requests) == 2
    assert sleeps == [1]


def test_a_retry_after_header_is_honoured():
    opener = ScriptedOpener([_http_error(429, retry_after=7), CANDLE_BODY])
    sleeps = []
    client = PublicCandles(opener=opener, sleep=sleeps.append)

    payload = _candles(client)

    assert payload["candles"]
    assert len(opener.requests) == 2
    assert sleeps == [7]


def test_a_retry_after_header_is_capped_at_a_minute():
    opener = ScriptedOpener([_http_error(429, retry_after=600), CANDLE_BODY])
    sleeps = []
    client = PublicCandles(opener=opener, sleep=sleeps.append)

    payload = _candles(client)

    assert payload["candles"]
    assert sleeps == [60]


def test_a_server_error_is_retried_three_attempts_in_total():
    opener = ScriptedOpener([_http_error(500)])
    sleeps = []
    client = PublicCandles(opener=opener, sleep=sleeps.append)

    with pytest.raises(FeedError) as caught:
        _candles(client)

    assert len(opener.requests) == 3
    assert sleeps == [1, 2]
    # A plain sentence, not a traceback or a document.
    message = str(caught.value)
    assert message
    assert "\n" not in message


def test_an_unreachable_endpoint_is_retried_three_attempts_in_total():
    opener = ScriptedOpener([URLError("connection refused")])
    sleeps = []
    client = PublicCandles(opener=opener, sleep=sleeps.append)

    with pytest.raises(FeedError) as caught:
        _candles(client)

    assert len(opener.requests) == 3
    assert sleeps == [1, 2]
    assert str(caught.value)


def test_a_404_is_not_retried():
    opener = ScriptedOpener([_http_error(404)])
    sleeps = []
    client = PublicCandles(opener=opener, sleep=sleeps.append)

    with pytest.raises(FeedError):
        _candles(client)

    assert len(opener.requests) == 1
    assert sleeps == []


# ---------------------------------------------------------------- public candles


def test_public_candles_builds_the_url_and_returns_json():
    opener = FakeOpener(CANDLE_BODY)
    client = PublicCandles(opener=opener)

    found = client.get_public_candles(
        PRODUCT, start=START, end=END, granularity="ONE_DAY"
    )

    assert found == {
        "candles": [
            {
                "start": "1704067200",
                "open": "1.00",
                "high": "1.01",
                "low": "0.99",
                "close": "1.00",
                "volume": "100",
            }
        ]
    }

    assert len(opener.urls) == 1
    url = opener.urls[0]
    parts = urlsplit(url)
    assert parts.netloc == "api.coinbase.com"
    assert parts.path.endswith(
        "/api/v3/brokerage/market/products/XRP-USDC/candles"
    )

    query = _query(url)
    assert query["start"] == [START]
    assert query["end"] == [END]
    assert query["granularity"] == ["ONE_DAY"]


def test_public_candles_http_error_is_a_feed_error():
    error = HTTPError(
        "https://api.coinbase.com/api/v3/brokerage/market/products",
        503,
        "unavailable",
        None,
        None,
    )
    # A no-op sleeper keeps the retry back-off out of the test's own wall clock.
    client = PublicCandles(
        opener=FakeOpener(error=error), sleep=lambda seconds: None
    )

    with pytest.raises(FeedError) as caught:
        client.get_public_candles(
            PRODUCT, start=START, end=END, granularity="ONE_DAY"
        )

    message = str(caught.value)
    # A plain sentence, not a traceback or a document.
    assert message
    assert "\n" not in message
    assert message.strip() == message


def test_public_candles_non_json_body_is_a_feed_error():
    client = PublicCandles(opener=FakeOpener(b"<html>not json</html>"))

    with pytest.raises(FeedError) as caught:
        client.get_public_candles(
            PRODUCT, start=START, end=END, granularity="ONE_DAY"
        )

    message = str(caught.value)
    assert message
    assert "\n" not in message


# ---------------------------------------------------------------- tiingo CSV


def test_fetch_tiingo_csv_puts_the_token_in_the_header_only():
    opener = FakeOpener(TIINGO_BODY)

    text = fetch_tiingo_csv("NVDA", TOKEN, "2016-01-01", opener=opener)

    assert text == TIINGO_BODY.decode("utf-8")
    assert len(opener.requests) == 1

    url = opener.urls[0]
    assert urlsplit(url).path == "/tiingo/daily/NVDA/prices"
    query = _query(url)
    assert query["format"] == ["csv"]
    assert query["startDate"] == ["2016-01-01"]

    # The token rides in the request header and nowhere in the URL.
    assert TOKEN not in url
    assert _headers(opener.requests[0]).get("authorization") == f"Token {TOKEN}"


def test_fetch_tiingo_csv_keeps_the_token_off_a_redirect():
    opener = FakeOpener(TIINGO_BODY)

    fetch_tiingo_csv("NVDA", TOKEN, "2016-01-01", opener=opener)

    request = opener.requests[0]
    # The token sits in an unredirected header, so the request a redirect sends
    # on does not carry it to wherever that redirect points: the plain headers
    # hold no part of it, and neither does their text.
    assert request.unredirected_hdrs.get(TOKEN_HEADER) == f"Token {TOKEN}"
    assert TOKEN_HEADER not in request.headers
    assert TOKEN not in " ".join(
        f"{name}: {value}" for name, value in request.headers.items()
    )
    # Everything else stays an ordinary header, read whichever way.
    assert request.headers.get("Accept") == "text/csv"
    assert request.has_header(TOKEN_HEADER) is True
    assert request.get_header(TOKEN_HEADER) == f"Token {TOKEN}"


def test_fetch_tiingo_csv_without_a_start_date():
    opener = FakeOpener(TIINGO_BODY)

    fetch_tiingo_csv("NVDA", TOKEN, opener=opener)

    query = _query(opener.urls[0])
    assert query["format"] == ["csv"]
    assert "startDate" not in query


def test_fetch_tiingo_csv_error_does_not_carry_the_token(monkeypatch):
    # The fetcher takes no sleeper of its own, so the process-wide one is stilled
    # here in case a refused request is retried.
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    opener = FakeOpener(error=URLError("connection refused"))

    with pytest.raises(FeedError) as caught:
        fetch_tiingo_csv("NVDA", TOKEN, "2016-01-01", opener=opener)

    message = str(caught.value)
    assert message
    assert TOKEN not in message


def test_fetch_tiingo_csv_refuses_a_bad_symbol_before_any_request():
    opener = FakeOpener(TIINGO_BODY)

    with pytest.raises((ValueError, FeedError)):
        fetch_tiingo_csv("NV DA/../x", TOKEN, opener=opener)

    assert opener.requests == []


def test_fetch_tiingo_csv_refuses_a_two_line_token_before_any_request():
    opener = FakeOpener(TIINGO_BODY)

    with pytest.raises(FeedError) as caught:
        fetch_tiingo_csv("NVDA", "FAKE-ONE\nFAKE-TWO", "2016-01-01", opener=opener)

    message = str(caught.value)
    assert message == TOKEN_SENTENCE
    # No part of the token is quoted back.
    assert "FAKE-ONE" not in message
    assert "FAKE-TWO" not in message
    assert opener.requests == []


def test_fetch_tiingo_csv_refuses_a_token_that_is_not_ascii():
    opener = FakeOpener(TIINGO_BODY)

    with pytest.raises(FeedError) as caught:
        fetch_tiingo_csv("NVDA", "FAKE-TOK\u00c9N", "2016-01-01", opener=opener)

    assert str(caught.value) == TOKEN_SENTENCE
    assert opener.requests == []


def test_fetch_tiingo_csv_wraps_a_value_error_in_a_plain_sentence():
    opener = ScriptedOpener([ValueError(f"not a header: {TOKEN}")])

    with pytest.raises(FeedError) as caught:
        fetch_tiingo_csv("NVDA", TOKEN, "2016-01-01", opener=opener)

    assert str(caught.value) == UNBUILDABLE_SENTENCE
    assert TOKEN not in str(caught.value)


def test_fetch_tiingo_csv_429_names_the_rate_limits(monkeypatch):
    # The fetcher is given no sleeper, so the process-wide one is stilled here.
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    opener = ScriptedOpener([_http_error(429)])

    with pytest.raises(FeedError) as caught:
        fetch_tiingo_csv("NVDA", TOKEN, "2016-01-01", opener=opener)

    message = str(caught.value)
    assert "50 requests/hour" in message
    assert "1,000/day" in message