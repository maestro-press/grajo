"""test_tiingo_quotes.py: the price a stock order is priced from, end to end.

Two things are measured here, and both are about the SAME number: the freshness
CEILING `exchange.EQUITY_FRESHNESS_CEILING_S` (300 s), the bound a PRACTICE (dry)
stock order accepts a print under.  LIVE stock orders keep the strict
`exchange.DEFAULT_EQUITY_QUOTE_MAX_AGE_S` (120 s).  The bound is the book's own —
the engine reads it from `exchange.equity_max_age_for(book)` and no caller passes
a number — so the Tiingo client must never refuse a print the dry book would
accept: a client that caches a print past the ceiling turns a healthy, affordable
hour of polling into an engine that complains the price it was just handed is too
old.

* `test_an_hour_of_reads_never_uses_a_print_past_the_engine_bound` drives the
  REAL `MarketData` over the REAL quote source the engine's `build_app` builds
  over its Tiingo client — `__main__.tiingo_equity_last`, the thin wrapper that
  turns the client's `last` into the engine's own answer — and reads it the way a
  practice order does: `equity_quote(book="dry")`.  One, two and three equity
  products are each polled twice a minute for an hour against a healthy fake that
  stamps every print two seconds before the clock, exactly as a live feed looks:
  no read may be refused for the print's age, a refused read must be a PAUSE
  (`EquityQuotePaused`, which is what the allowance running out looks like) and
  never a plain unavailable, the oldest print served must be under the ceiling,
  and the hour's requests must stay inside both the client's own `MAX_PER_HOUR`
  and the count that product list's cache time allows.

* `test_a_stock_price_pause_is_one_info_event_per_episode` is the runner's side
  of the same story, over the equity harness of `test_equity_status.py`: the
  runner reads an equity as a PRINT (`equity_print(book="dry")`), so its fakes
  answer that read and record the book they were asked for.  A paused quote
  source is one `info` event per episode and writes no warn at all (a pause is
  not a fault), a good quote clears the episode's mark, a second pause is a
  second event, and a real failure still writes exactly one warn.

No test reaches the network: the Tiingo client takes its opener and its clock as
arguments, the equity harness fakes the public market, and the app is built on a
temporary data directory.  Nothing here prints.
"""

from __future__ import annotations

import inspect
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from decimal import Decimal as D

import crow_coinbase.__main__ as main_module
import crow_coinbase.exchange as exchange_module
from crow_coinbase.exchange import (
    DEFAULT_EQUITY_QUOTE_MAX_AGE_S,
    MarketData,
    ProductUnavailable,
)
from crow_coinbase.tiingo import MAX_PER_HOUR, TiingoQuotes

# The equity harness of test_equity_status.py: the real engine through build_app,
# with only the public market (and the live adapter) faked.
import test_equity_status as equity_harness

# ---------------------------------------------------------------- test data
# A token in the shape Tiingo's own has, built at runtime.
TOKEN = "tiingo-test-token-" + secrets.token_hex(16)

# 10:00 in New York on a Tuesday, in a year the market calendar covers: inside the
# regular session, so a print stamped here is one the engine may price from.
SESSION = datetime(2026, 11, 17, 15, 0, tzinfo=timezone.utc).timestamp()

# How far before the clock the healthy fake stamps its prints, in seconds.
PRINT_LAG_S = 2.0

# The one price the fake prints.
PRICE = D("100.5")

# One hour of polling, with the runner's own two reads a minute: the poll and the
# dry advance.
HOUR_MINUTES = 60
READS_PER_MINUTE = 2

# The most requests an hour of that polling may cost, per equity-product count:
# a symbol is asked again once its cached answer's cache time passes, which is
# 90 s for one product (3600/90 = 40), 170 s for two (2 * 3600/170 = 42.4 -> 43)
# and 255 s for three (3 * 3600/255 = 42.4 -> 43).  Every one of them is under
# the client's own MAX_PER_HOUR (45).
REQUEST_BOUNDS = {1: 40, 2: 43, 3: 43}

# The products the runner test builds a pause episode for.
NVDA = equity_harness.NVDA
PAUSE_EVENT = f"poll {NVDA} paused: stock prices are paused"
PAUSED_KEY = f"equity_quote_paused:{NVDA}"
WARN_KEY = f"equity_quote_warn:{NVDA}"


# ---------------------------------------------------------------- the engine's names


def equity_paused_type() -> type:
    """`exchange.EquityQuotePaused`: the engine's own "prices are paused" refusal."""
    paused = getattr(exchange_module, "EquityQuotePaused", None)
    assert paused is not None, (
        "crow_coinbase.exchange.EquityQuotePaused is missing: a paused quote "
        "source is refused as a plain ProductUnavailable, so the runner cannot "
        "tell a pause from a fault"
    )
    assert issubclass(paused, ProductUnavailable), paused
    return paused


def freshness_ceiling() -> float:
    """`exchange.EQUITY_FRESHNESS_CEILING_S`: the oldest print a practice order takes."""
    ceiling = getattr(exchange_module, "EQUITY_FRESHNESS_CEILING_S", None)
    assert ceiling is not None, (
        "crow_coinbase.exchange.EQUITY_FRESHNESS_CEILING_S is missing: nothing "
        "says how old a print a practice stock order accepts"
    )
    return float(ceiling)


def max_age_for(book) -> float:
    """`exchange.equity_max_age_for(book)`: the bound that book asks for itself."""
    helper = getattr(exchange_module, "equity_max_age_for", None)
    assert callable(helper), (
        "crow_coinbase.exchange.equity_max_age_for is missing: the age bound has "
        "to come from the book, and no caller may pass a number"
    )
    return float(helper(book))


def engine_equity_last(client):
    """The equity quote source `build_app` builds over *client*, as its own helper.

    The engine does not hand its Tiingo client's `last` to a product directly: it
    wraps it, so a pause is the engine's `EquityQuotePaused` and every other
    failure stays what it was.  That wrapper is `__main__.tiingo_equity_last`,
    and this is the caller build_app is.
    """
    helper = getattr(main_module, "tiingo_equity_last", None)
    assert helper is not None, (
        "crow_coinbase.__main__.tiingo_equity_last is missing: the engine's own "
        "equity quote source is the client's `last` unconverted, so a pause "
        "reaches the runner as a generic failure"
    )
    last = helper(client)
    assert callable(last), last
    return last


# ---------------------------------------------------------------- the clock and the feed


class Clock:
    """A `now()` a test moves by hand, in a one-item list for the closures."""

    def __init__(self, at: float) -> None:
        self.at = [float(at)]

    def __call__(self) -> float:
        return self.at[0]

    def advance(self, seconds: float) -> None:
        self.at[0] += float(seconds)


class Answer:
    """The context-manager answer an opener gives, as far as the client reads it."""

    def __init__(self, body: bytes) -> None:
        self.body = bytes(body)

    def read(self, size: int | None = None) -> bytes:
        """The body, or at most its first *size* bytes: what the client bounds."""
        if size is None:
            return self.body
        return self.body[:size]

    def __enter__(self) -> "Answer":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False


def healthy_feed(clock: Clock, sent: list[float]):
    """An opener that records the request and prints `PRINT_LAG_S` before the clock.

    This is what a working feed looks like to the engine: every answer names the
    ticker that was asked for and carries a print two seconds old, so the only
    reason a served price could be past the engine's bound is the client handing
    over a cached print that has since grown old.
    """

    def opener(request, timeout=None):
        sent.append(clock())
        symbol = str(request.full_url).rsplit("/", 1)[-1]
        printed = datetime.fromtimestamp(
            clock() - PRINT_LAG_S, timezone.utc
        ).isoformat()
        body = json.dumps(
            {"ticker": symbol, "tngoLast": str(PRICE), "timestamp": printed}
        ).encode("utf-8")
        return Answer(body)

    return opener


class ObservedLast:
    """The engine's quote source, with the age of every print it hands over.

    `equity_quote` answers a price, not a print time, so what a served quote used
    cannot be read off its answer.  This calls the engine's wrapper and returns
    its answer unchanged; what it adds is the one number a reader of the quote
    cannot compute — how old the print behind it was when it was served.
    """

    def __init__(self, source, now) -> None:
        self.source = source
        self.now = now
        self.ages: list[float] = []

    def __call__(self, symbol: str):
        price, printed_at = self.source(symbol)
        self.ages.append(self.now() - float(printed_at))
        return price, printed_at


# ================================================================ 1. an hour of reads


def test_an_hour_of_reads_never_uses_a_print_past_the_engine_bound():
    """One, two and three equities, polled twice a minute for an hour.

    A practice (dry) stock order accepts a print up to the freshness ceiling, so
    every read here is the read the engine makes for one: `equity_quote(book=
    "dry")`, priced against the dry book's own bound and never against a number a
    caller passed.  Against a feed whose every print is two seconds old, no read
    may raise a `ProductUnavailable` that says the print it was given is too old:
    that text ("...s old, past the ...s bound") is the engine refusing a price
    nobody should have handed it.  A read that is refused at all is refused
    because the client's allowance is spent — a PAUSE, `EquityQuotePaused` —
    never a plain unavailable, and every quote that IS served is a print under
    the ceiling.  The whole hour costs no more requests than the client's own
    `MAX_PER_HOUR`, and no more than the cache time of its product list allows.
    """
    paused_class = equity_paused_type()
    ceiling = freshness_ceiling()
    assert ceiling == 300.0, ceiling
    assert max_age_for("dry") == ceiling, max_age_for("dry")
    assert max_age_for("live") == DEFAULT_EQUITY_QUOTE_MAX_AGE_S, max_age_for("live")
    for other in (None, "unknown", 3):
        assert max_age_for(other) == DEFAULT_EQUITY_QUOTE_MAX_AGE_S, other

    # A `MarketData` the engine builds itself tightens nothing: the book decides.
    default = inspect.signature(MarketData.__init__).parameters[
        "equity_max_age_s"
    ].default
    assert default is None, default

    for count in (1, 2, 3):
        clock = Clock(SESSION)
        sent: list[float] = []
        client = TiingoQuotes(
            opener=healthy_feed(clock, sent),
            now=clock,
            product_count=lambda count=count: count,
        )
        client.set_token(TOKEN)
        observed = ObservedLast(engine_equity_last(client), clock)
        markets = [
            MarketData(
                f"S{index}-USD",
                client=object(),
                equity_last=observed,
                now=clock,
            )
            for index in range(count)
        ]
        reads = 0
        # Every refusal seen this hour: (minute, exception class, its text).
        failures: list[tuple[int, str, str]] = []
        for minute in range(HOUR_MINUTES):
            for market in markets:
                for _ in range(READS_PER_MINUTE):
                    reads += 1
                    try:
                        price, ask = market.equity_quote(book="dry")
                    except ProductUnavailable as error:
                        failures.append((minute, type(error).__name__, str(error)))
                        continue
                    assert isinstance(price, D), (count, minute, price)
                    assert price == ask and price > 0, (count, minute, price, ask)
            clock.advance(60.0)

        assert reads == count * HOUR_MINUTES * READS_PER_MINUTE, (count, reads)

        # No refusal says the print is old, and none is a plain unavailable.
        too_old = [
            failure
            for failure in failures
            if "s old" in failure[2] or "past the" in failure[2]
        ]
        assert too_old == [], (count, too_old[:4])
        unavailable = [
            failure for failure in failures if failure[1] != paused_class.__name__
        ]
        assert unavailable == [], (count, unavailable[:4])

        # And every price that was handed over was a print under the ceiling a
        # practice order accepts.
        assert observed.ages, (count, "no quote was served all hour")
        assert max(observed.ages) < ceiling, (count, max(observed.ages))

        # The hour stayed inside the client's own allowance, and inside the count
        # its cache time for this many products allows.
        assert len(sent) <= REQUEST_BOUNDS[count], (count, len(sent))
        assert len(sent) <= MAX_PER_HOUR, (count, len(sent))


# ================================================================ 2. the runner's event


def events(store) -> list[tuple[str, str]]:
    """Every event in the store, oldest first, as (level, message)."""
    rows = store.conn().execute(
        "SELECT level, message FROM events ORDER BY rowid"
    ).fetchall()
    return [(str(row["level"]), str(row["message"])) for row in rows]


def written_since(store, mark: int) -> list[tuple[str, str]]:
    """Every event written after the store's *mark*-th one: this test's own news."""
    return events(store)[mark:]


def poll_warnings(caplog, product: str = NVDA) -> list[str]:
    """Every warn-or-worse log line the poll of *product* wrote."""
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and product in record.getMessage()
    ]


class DryBookMarket(equity_harness.FakeMarket):
    """One product's public market, read the way the runner reads an equity.

    The runner asks an equity for a PRINT (`equity_print(book=...)`), not for a
    quote pair, so the fake answers the price and the moment it was printed and
    records the book it was asked for; `equity_quote` is the same print on both
    sides, which is what a dry fill reads.  `quote_error` is the harness's own
    switch, so "the source is paused" and "the source answered" are one
    assignment each.
    """

    def __init__(self, product: str, **options) -> None:
        super().__init__(product, **options)
        self.books: list[str] = []

    def _print(self, book) -> tuple:
        self.books.append(book)
        if self.quote_error is not None:
            raise self.quote_error
        return self.price, time.time()

    def equity_print(self, book: str = "live") -> tuple:
        """The equity's print and its stamp, or the failure a test asked for."""
        return self._print(book)

    def equity_quote(self, book: str = "live") -> tuple:
        """A dry fill's read: one print, so both sides are that same price."""
        price, _ = self._print(book)
        return price, price


class DryBookMarkets(equity_harness.Markets):
    """One `DryBookMarket` per product, asked by the engine as its `market_for`."""

    def __call__(self, product: str) -> DryBookMarket:
        return self.by_product.setdefault(product, DryBookMarket(product))


def test_a_stock_price_pause_is_one_info_event_per_episode(tmp_path, caplog):
    """A paused quote source is news ONCE per episode, and it is never a warn.

    The engine's quote source is a quote source: when prices are paused there is
    nothing wrong with the engine, the owner or the product, so the runner says
    so once — one `info` event, no warn, and the failure mark the real-failure
    path keeps stays untouched.  A good quote ends the episode and clears the
    mark, so a later pause is news again; a real failure is still one warn.
    """
    caplog.set_level(logging.DEBUG)
    paused_class = equity_paused_type()

    markets = DryBookMarkets()
    # An injected `spec_for` is trusted, so the equities are available and polled
    # from the first cycle: this test is about the quote, not about the kinds.
    engine = equity_harness.build(
        equity_harness.env_for(),
        tmp_path / "pause",
        markets=markets,
        spec_for=equity_harness.spec,
    )
    equity_harness.pin_session(engine)
    assert engine.runner.startup_checks() == []

    # A working feed first, so "the previous snapshot stands" has something to
    # stand: one quote, no event at all from it.
    engine.runner.cycle()
    assert engine.runner.snapshots.get(NVDA) is not None
    standing = engine.runner.snapshots.get(NVDA).bid
    mark = len(events(engine.store))

    # Three cycles with the source paused: ONE info event, no warn anywhere.
    markets[NVDA].quote_error = paused_class(f"{NVDA}: stock prices are paused")
    for _ in range(3):
        engine.runner.cycle()

    assert written_since(engine.store, mark) == [("info", PAUSE_EVENT)], (
        written_since(engine.store, mark)
    )
    assert engine.store.get(PAUSED_KEY) is not None, "the episode was never marked"
    assert engine.store.get(WARN_KEY) is None, "a pause was marked as a failure"
    assert poll_warnings(caplog) == [], poll_warnings(caplog)
    # The last price the engine had is still the one it prices from.
    assert engine.runner.snapshots.get(NVDA) is not None
    assert engine.runner.snapshots.get(NVDA).bid == standing

    # The source answers again: the episode ends and nothing new is said.
    markets[NVDA].quote_error = None
    engine.runner.cycle()
    assert engine.store.get(PAUSED_KEY) is None, "a good quote left the pause marked"
    assert written_since(engine.store, mark) == [("info", PAUSE_EVENT)], (
        written_since(engine.store, mark)
    )
    assert poll_warnings(caplog) == [], poll_warnings(caplog)

    # Paused again: that is a SECOND episode, and it is news again.
    markets[NVDA].quote_error = paused_class(f"{NVDA}: stock prices are paused")
    engine.runner.cycle()
    assert written_since(engine.store, mark) == [
        ("info", PAUSE_EVENT),
        ("info", PAUSE_EVENT),
    ], written_since(engine.store, mark)
    assert engine.store.get(WARN_KEY) is None, "a pause was marked as a failure"
    assert poll_warnings(caplog) == [], poll_warnings(caplog)

    # A real failure is still exactly one warn per episode, and never the pause's
    # own event.
    markets[NVDA].quote_error = RuntimeError("quote unavailable")
    for _ in range(3):
        engine.runner.cycle()

    assert written_since(engine.store, mark) == [
        ("info", PAUSE_EVENT),
        ("info", PAUSE_EVENT),
        ("warn", f"poll {NVDA} failed: quote unavailable (RuntimeError)"),
    ], written_since(engine.store, mark)
    assert len(poll_warnings(caplog)) == 1, poll_warnings(caplog)

    # Every equity read this test caused was the practice (dry) book's print.
    assert markets[NVDA].books, "the equity was never polled"
    assert set(markets[NVDA].books) == {"dry"}, markets[NVDA].books