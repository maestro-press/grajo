"""Exchange adapters (multi-product).

LiveExchange  - Coinbase Advanced Trade via the official coinbase-advanced-py SDK.
DryRunExchange - same interface, simulated order book for any number of products;
                 fills are driven by live public 1-minute candles per product.
                 Never sends an authenticated write.

Normalized order dict: order_id, client_order_id, product, side, status, price,
                       size, filled_size, filled_value, total_fees
Normalized fill dict:  trade_id, order_id, product, side, size, price, commission,
                       trade_time
"""

from __future__ import annotations

import contextlib
import inspect
import logging
import math
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Optional

import requests

from . import market_hours
from .books import DRY, LIVE
from .money import BUY, SELL, ProductSpec, fee_rate_for_type

log = logging.getLogger("crow_coinbase.exchange")
D = Decimal

# ---------------------------------------------------------------- equity gates
# The two words an equity order's request carries on the wire: the regular
# session only, and a day order.  The request and the live gate read these same
# constants, so what is sent and what was confirmed cannot drift apart.
EQUITY_TRADING_SESSION = "EQUITY_TRADING_SESSION_NORMAL"
EQUITY_DISPLAYED_ORDER_CONFIG = "LIMIT_GFD"
# The refusal when the recorded preview confirmation is missing or mismatched.
EQUITY_PREVIEW_UNCONFIRMED = "EQUITY_PREVIEW_UNCONFIRMED"
# The refusal when the product's own spec could not be read, so its kind is
# unknown: neither write path sends an order whose kind it cannot name.
PRODUCT_TYPE_UNKNOWN = "PRODUCT_TYPE_UNKNOWN"
# The kv key the confirmed preview is stored under before the live switch may
# be turned on.
EQUITY_PREVIEW_CONFIRMED_KEY = "equity_preview_confirmed"

# How old an equity print may be before a quote of it is refused, PER BOOK
# (seconds).  A practice (dry) stock order accepts a print up to five minutes
# old; a live stock order keeps the strict two minutes.  Live stock trading is
# off, so the wide bound prices the simulator alone — and the strict one is what
# a live order would be held to, so the table can only be read, never widened by
# a caller.
EQUITY_MAX_AGE_BY_BOOK = {DRY: 300.0, LIVE: 120.0}

# The strict bound, restated as the answer for a book nobody named: the live
# entry of the table is the same number, and this name is what the rest of the
# engine reads when it asks for a bound without a book.
DEFAULT_EQUITY_QUOTE_MAX_AGE_S = 120.0

# How far ahead of our own clock a print may be stamped before it is refused.
MAX_EQUITY_QUOTE_FUTURE_S = 5.0

# The loosest print any book accepts.  This is the age a price fetched from a
# stock-price feed may be SERVED at: a practice order is the only reader that
# takes one this old, so a feed that hands over anything older is handing over a
# print no order could use.
EQUITY_FRESHNESS_CEILING_S = max(EQUITY_MAX_AGE_BY_BOOK.values())


def equity_max_age_for(book: Any) -> float:
    """The oldest print an order on *book* may be priced from, in seconds.

    The bound is a fact of the book and of nothing else: the practice book answers
    its own wide bound, and everything else — the live book, no book at all, an
    unknown word, a wrongly typed value — answers the strict one, so a misread
    book is never the LOOSER rule.  The table is only ever read here: an unknown
    book is answered, never recorded, and a caller is handed the number rather
    than the table it came from.
    """
    try:
        return EQUITY_MAX_AGE_BY_BOOK.get(book, DEFAULT_EQUITY_QUOTE_MAX_AGE_S)
    except TypeError:  # noqa: BLE001 - a book that cannot be a key is no book
        return DEFAULT_EQUITY_QUOTE_MAX_AGE_S


class TransientError(Exception):
    """Network/timeout/5xx/429: outcome unknown, safe to retry reads."""


class PermanentError(Exception):
    """4xx etc: retrying will not help."""


class ProductUnavailable(Exception):
    pass


class EquityQuotePaused(ProductUnavailable):
    """No stock price right now, and nothing is wrong: prices are paused.

    A stock-price feed that is being rate-limited, or whose own allowance is used
    up, has no price to hand over — but the engine, the owner and the product are
    all fine.  The refusal is its own class so a reader (the runner's poll) can
    say so once and stop calling it a fault; the message is the plain sentence a
    person reads, and it carries no token, URL or feed text.
    """


def classify(exc: Exception) -> Exception:
    if isinstance(exc, (TransientError, PermanentError)):
        return exc
    if isinstance(
        exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)
    ):
        return TransientError(type(exc).__name__)
    if isinstance(exc, requests.exceptions.HTTPError):
        code = getattr(exc.response, "status_code", None)
        if code is None or code == 429 or code >= 500:
            return TransientError(f"HTTP {code}")
        return PermanentError(f"HTTP {code}: {str(exc)[:200]}")
    return exc


def with_retry(
    fn: Callable,
    what: str,
    attempts: int = 5,
    base_delay: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
):
    """Retry *idempotent* calls on transient errors with exponential backoff."""
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            err = classify(e)
            if not isinstance(err, TransientError) or i == attempts - 1:
                raise err from e
            delay = min(base_delay * 2**i, 30)
            log.warning(
                "%s failed (%s); retry %d/%d in %.0fs",
                what,
                err,
                i + 1,
                attempts - 1,
                delay,
            )
            sleep(delay)


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _equity_price(pid: str, raw: object) -> Decimal:
    """An equity print's price as a positive, finite `Decimal`."""
    try:
        price = D(str(raw))
    except (ArithmeticError, ValueError, TypeError) as e:
        raise ProductUnavailable(
            f"{pid}: equity quote {raw!r} is not a number"
        ) from e
    if not price.is_finite() or price <= 0:
        raise ProductUnavailable(
            f"{pid}: equity quote {raw!r} is not a positive price"
        )
    return price


def _equity_stamp(pid: str, raw: object) -> float:
    """An equity print's timestamp in epoch seconds; a finite number or refused."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float, Decimal)):
        raise ProductUnavailable(
            f"{pid}: equity quote timestamp {raw!r} is not a number"
        )
    try:
        stamp = float(raw)
    except (ArithmeticError, ValueError, TypeError) as e:
        raise ProductUnavailable(
            f"{pid}: equity quote timestamp {raw!r} is not a number"
        ) from e
    if not math.isfinite(stamp):
        raise ProductUnavailable(
            f"{pid}: equity quote timestamp {raw!r} is not a finite number"
        )
    return stamp


def _takes_book(reader: Any) -> bool:
    """Whether a market's equity read accepts a `book` argument.

    The engine's own `MarketData` does, and so does a market built over it; a
    caller's own stand-in — or one written before the bound became the book's —
    answers its quote without a book, and is then asked without one.  A callable
    whose signature cannot be read is asked without a book: an `equity_print`
    takes none, and the alternative is guessing at a keyword it may not have.
    """
    try:
        parameters = inspect.signature(reader).parameters
    except (TypeError, ValueError):
        return False
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
        return True
    return "book" in parameters


def equity_print_for(market: Any, book: str = LIVE) -> tuple[Decimal, Optional[float]]:
    """One market's equity print under *book*, and when it was printed.

    A market that answers `equity_print` gives the price and the print's own time,
    which is what a reader keeps apart from the time it read it.  A market with
    only `equity_quote` (a caller's own stand-in) gives the same read with the
    print's time unknown, so the answer's second item is None and nothing is
    claimed about when the price was made.  A market that takes no `book` is asked
    without one: the bound it applies is then its own, and the book named here is
    only what a book-aware source would have used.
    """
    printer = getattr(market, "equity_print", None)
    if callable(printer):
        return printer(book=book) if _takes_book(printer) else printer()
    reader = getattr(market, "equity_quote", None)
    if not callable(reader):
        raise ProductUnavailable("no equity quote source is available")
    price, _ = reader(book=book) if _takes_book(reader) else reader()
    return price, None


def _norm_order(o: dict) -> dict:
    cfg = o.get("order_configuration") or {}
    lim = cfg.get("limit_limit_gtc") or cfg.get("limit_limit_gtd") or {}
    return {
        "order_id": o.get("order_id"),
        "client_order_id": o.get("client_order_id") or "",
        "product": o.get("product_id"),
        "side": o.get("side"),
        "status": o.get("status"),
        "price": D(str(lim.get("limit_price") or o.get("average_filled_price") or "0")),
        "size": D(str(lim.get("base_size") or "0")),
        "filled_size": D(str(o.get("filled_size") or "0")),
        "filled_value": D(str(o.get("filled_value") or "0")),
        "total_fees": D(str(o.get("total_fees") or "0")),
    }


def _norm_fill(f: dict) -> dict:
    size, price = D(str(f["size"])), D(str(f["price"]))
    if f.get("size_in_quote"):
        size = size / price
    return {
        "trade_id": f["trade_id"],
        "order_id": f["order_id"],
        "product": f.get("product_id"),
        "side": f["side"],
        "size": size,
        "price": price,
        "commission": D(str(f.get("commission") or "0")),
        "trade_time": f["trade_time"],
        "trade_type": f.get("trade_type", "FILL"),
    }


def _order_result(r: dict) -> dict:
    """One order response as the adapters' own result dict.

    A success answers `{ok: True, order_id, reason: None}`; a refusal answers
    `{ok: False, order_id: None, reason, message}`, where the reason is the
    exchange's own word for what it refused (`UNKNOWN` when it sent none).  Both
    order writes parse their answer here, so the two paths cannot drift apart in
    the shape a caller sees.
    """
    if r.get("success"):
        sr = r.get("success_response") or {}
        return {
            "ok": True,
            "order_id": sr.get("order_id") or r.get("order_id"),
            "reason": None,
        }
    er = r.get("error_response") or {}
    reason = (
        er.get("new_order_failure_reason")
        or er.get("preview_failure_reason")
        or er.get("error")
        or r.get("failure_reason")
        or "UNKNOWN"
    )
    return {
        "ok": False,
        "order_id": None,
        "reason": str(reason),
        "message": er.get("message"),
    }


def equity_preview_refusal(confirmation: Optional[dict]) -> Optional[str]:
    """Why a recorded equity preview confirmation is not one, or None when it is.

    A confirmation is the owner's own recorded answer to a preview, not a
    reminder that a preview happened: it has to be a mapping that names the
    displayed order configuration AND the trading session this adapter sends.
    Anything else — nothing recorded, a bare string or pair, one field, a stale
    word for either — is refused with a reason, so the caller can say why.
    """
    if not isinstance(confirmation, dict):
        return (
            "no recorded equity preview confirmation: the preview an owner "
            "approved has to be confirmed before an equity order may be sent or "
            "the equity live switch turned on"
        )
    if confirmation.get("displayed_order_config") != EQUITY_DISPLAYED_ORDER_CONFIG:
        return (
            "the recorded equity preview confirmation does not confirm the "
            f"displayed order configuration {EQUITY_DISPLAYED_ORDER_CONFIG}"
        )
    if confirmation.get("equity_trading_session") != EQUITY_TRADING_SESSION:
        return (
            "the recorded equity preview confirmation does not confirm the "
            f"trading session {EQUITY_TRADING_SESSION}"
        )
    return None


def equity_live_refusal(
    equity_live: bool, confirmation: Optional[dict]
) -> Optional[str]:
    """Why the equity live switch may not be on, or None when it may.

    Off is always allowed: a dry equity route needs no preview on record.  On is
    allowed only with the same confirmation an equity order needs, so the switch
    cannot be turned on without one: this returns `equity_preview_refusal`'s own
    answer, unchanged.

    The preview an owner approved for this engine — NVDA-USD, BUY, one limit
    order of 0.001 at $1.00 as a day order — has to confirm both
    `displayed_order_config` (`LIMIT_GFD`) and `equity_trading_session`
    (`EQUITY_TRADING_SESSION_NORMAL`) before that confirmation is stored under
    the kv key `equity_preview_confirmed`.  Until it is, the live switch is
    refused, and so is every equity order.
    """
    if not equity_live:
        return None
    return equity_preview_refusal(confirmation)


class MarketData:
    """Public, unauthenticated market data (used by both live and dry-run).

    A crypto product is quoted from the public book and its candles.  An equity
    product has no such book: its quote comes from `equity_last`, a callable
    given the base symbol ("NVDA" for "NVDA-USD") that answers the last traded
    price and the epoch seconds it was printed at, and both sides of the quote
    are that one price.  How old that print may be is the BOOK's question —
    `equity_max_age_for` — and a bound given to the constructor can only tighten
    it.
    """

    def __init__(
        self,
        product_id: str,
        client=None,
        sleep=time.sleep,
        equity_last: Optional[Callable[[str], object]] = None,
        equity_max_age_s: Optional[float] = None,
        now: Optional[Callable[[], float]] = None,
    ):
        from coinbase.rest import RESTClient

        self.pid = product_id
        self.pub = client or RESTClient(api_key=None, api_secret=None)
        self.sleep = sleep
        self.equity_last = equity_last
        self.equity_max_age_s = (
            None if equity_max_age_s is None else float(equity_max_age_s)
        )
        self.now = now
        self.base_symbol = product_id.split("-", 1)[0]

    def product(self) -> tuple[ProductSpec, dict]:
        try:
            p = with_retry(
                lambda: self.pub.get_public_product(self.pid).to_dict(),
                "get_product",
                sleep=self.sleep,
            )
        except PermanentError as e:
            raise ProductUnavailable(
                f"{self.pid} not found or not accessible via the API ({e}). "
                f"Not switching to another product."
            )
        if p.get("product_id") != self.pid:
            raise ProductUnavailable(f"{self.pid} not returned by API")
        problems = [
            k for k in ("trading_disabled", "cancel_only", "is_disabled") if p.get(k)
        ]
        if p.get("status") != "online":
            problems.append(f"status={p.get('status')}")
        if problems:
            raise ProductUnavailable(f"{self.pid} not tradable: {', '.join(problems)}")
        return ProductSpec.from_api(p), p

    def best_bid_ask(self) -> tuple[Decimal, Decimal]:
        b = with_retry(
            lambda: self.pub.get_public_product_book(self.pid, limit=1).to_dict(),
            "book",
            sleep=self.sleep,
        )["pricebook"]
        return D(b["bids"][0]["price"]), D(b["asks"][0]["price"])

    def equity_print(self, book: str = LIVE) -> tuple[Decimal, float]:
        """An equity product's print for *book*: the price and when it was made.

        `equity_last` answers `(price, timestamp)`, the timestamp in epoch
        seconds.  The print has to be one this engine may price an order on
        *book* from, so it is refused with `ProductUnavailable` when: there is no
        source to ask; the source raises (the refusal names the exception's class
        and never its message, which can carry a URL or a token); the source
        answers anything but a two-item tuple; the price is not a positive finite
        number; the timestamp is not a finite number; the print is older than the
        bound *book* allows; it is stamped more than five seconds ahead of the
        clock; or it was not printed inside the regular session.  The last one is
        what refuses a previous close's print, however fresh it is by age: a
        price nobody is trading at is not a quote.

        The age bound is the book's own (`equity_max_age_for`), and a bound given
        to the constructor can only TIGHTEN it: what is applied is the smaller of
        the two, and the refusal names that applied bound, so a caller can never
        let an older print price an order than the book it is for takes.  A
        source's own `ProductUnavailable` — an `EquityQuotePaused` included — is
        re-raised unchanged: it is already the engine's own words, and a pause
        has to stay a pause for the reader that tells the two apart.
        """
        if self.equity_last is None:
            raise ProductUnavailable(
                f"{self.pid}: no equity quote source is configured"
            )
        try:
            raw = self.equity_last(self.base_symbol)
        except ProductUnavailable:
            raise
        except Exception as e:  # noqa: BLE001 - any source failure is no quote
            # Only the class is reported: a source's own message can carry a URL
            # or a token, and this text reaches an event and a log line.
            raise ProductUnavailable(
                f"{self.pid}: equity quote failed ({type(e).__name__})"
            ) from e
        if raw is None:
            raise ProductUnavailable(f"{self.pid}: no equity quote available")
        if not isinstance(raw, tuple) or len(raw) != 2:
            raise ProductUnavailable(
                f"{self.pid}: equity quote {raw!r} is not a (price, timestamp) pair"
            )
        price_raw, stamped = raw
        last = _equity_price(self.pid, price_raw)
        stamp = _equity_stamp(self.pid, stamped)
        now = float(self.now()) if self.now is not None else time.time()
        if stamp - now > MAX_EQUITY_QUOTE_FUTURE_S:
            raise ProductUnavailable(
                f"{self.pid}: equity quote is stamped {stamp - now:.0f}s ahead of "
                f"the clock"
            )
        bound = equity_max_age_for(book)
        if self.equity_max_age_s is not None:
            bound = min(bound, self.equity_max_age_s)
        if now - stamp > bound:
            raise ProductUnavailable(
                f"{self.pid}: equity quote is {now - stamp:.0f}s old, past the "
                f"{bound:.0f}s bound"
            )
        if not market_hours.is_regular_session(stamp):
            raise ProductUnavailable(
                f"{self.pid}: equity quote was not printed in the regular session"
            )
        return last, stamp

    def equity_quote(self, book: str = LIVE) -> tuple[Decimal, Decimal]:
        """An equity product's last price as `(bid, ask)`; one price, both sides.

        One print, read under *book*'s own age bound (see `equity_print`, which is
        the whole of the check), answered as the same price on both sides: a
        print is not a book, and a crossed one would refuse every order off a
        market that is working exactly as it should.
        """
        last, _ = self.equity_print(book=book)
        return last, last

    def candles(self, start: float, end: float) -> list[dict]:
        """1-minute candles in [start, end], oldest first."""
        start = max(start, end - 300 * 60)  # API returns at most 350 candles
        r = with_retry(
            lambda: self.pub.get_public_candles(
                self.pid,
                start=str(int(start)),
                end=str(int(end)),
                granularity="ONE_MINUTE",
            ).to_dict(),
            "candles",
            sleep=self.sleep,
        )
        out = [
            {"start": int(c["start"]), "low": D(c["low"]), "high": D(c["high"])}
            for c in r.get("candles", [])
        ]
        return sorted(out, key=lambda c: c["start"])

    def range_since(self, since: float) -> tuple[Decimal, Decimal]:
        bid, ask = self.best_bid_ask()
        lo, hi = bid, ask
        for c in self.candles(since - 60, time.time()):
            lo, hi = min(lo, c["low"]), max(hi, c["high"])
        return lo, hi


# ====================================================================== live


class LiveExchange:
    dry_run = False

    def __init__(
        self,
        creds: dict,
        market_for: Optional[Callable[[str], MarketData]] = None,
        sleep=time.sleep,
        equity_preview_confirmation: Optional[dict] = None,
    ):
        from coinbase.rest import RESTClient

        if not creds:
            raise PermanentError(
                "live mode needs COINBASE_KEY_FILE or COINBASE_API_KEY/COINBASE_API_SECRET in .env"
            )
        self.client = RESTClient(timeout=15, verbose=False, **creds)
        self.market_for = market_for or (lambda p: MarketData(p, sleep=sleep))
        self.sleep = sleep
        self.equity_preview_confirmation = equity_preview_confirmation

    # -- product kinds
    def product_spec(self, product: str) -> ProductSpec:
        """The product's own listing, off the AUTHENTICATED product read.

        Only the authenticated read answers a stock at all — the public product
        endpoint answers 404 for an equity — so this is the one spec read an
        equity may be built from.  It is never cached: tick sizes, minimums and
        the listing's own flags can change, and a caller that wants the listing as
        it stands asks again.  There is no tradability gate, because a halted or
        delisted product still answers the kind of product it is; a read that
        answers some other product's listing is refused with
        `ProductUnavailable` rather than taken as this one's spec.
        """
        raw = with_retry(
            lambda: self.client.get_product(product).to_dict(),
            "get_product",
            sleep=self.sleep,
        )
        if raw.get("product_id") != product:
            raise ProductUnavailable(f"{product} not returned by API")
        return ProductSpec.from_api(raw)

    def product_type(self, product: str) -> str:
        """The product's own kind, upper-cased and stripped, off the same read.

        The kind comes from the authenticated product read `product_spec` builds
        its spec from, never from the public market data, which answers nothing at
        all for a stock.  A successful lookup is remembered per product, so a
        write path that reads the kind once (and a caller that asks again) asks
        the exchange once: the cache is this instance's own attribute, made on
        first use, because a `LiveExchange` may be built without its constructor.
        A lookup that cannot answer propagates and is NOT cached: a failure says
        nothing about the product, so the next read asks again rather than
        remembering a kind it never learned.
        """
        try:
            cache = self._product_types
        except AttributeError:
            cache = {}
            self._product_types = cache
        kind = cache.get(product)
        if kind is not None:
            return kind
        raw = with_retry(
            lambda: self.client.get_product(product).to_dict(),
            "get_product",
            sleep=self.sleep,
        )
        kind = str(raw.get("product_type") or "").strip().upper()
        cache[product] = kind
        return kind

    # -- read
    def key_permissions(self) -> dict:
        return with_retry(
            lambda: self.client.get_api_key_permissions().to_dict(),
            "key_permissions",
            sleep=self.sleep,
        )

    def maker_fee_rate(self) -> Optional[Decimal]:
        r = with_retry(
            lambda: self.client.get_transaction_summary(product_type="SPOT").to_dict(),
            "fees",
            sleep=self.sleep,
        )
        rate = (r.get("fee_tier") or {}).get("maker_fee_rate")
        return D(str(rate)) if rate is not None else None

    def balances(self) -> dict[str, Decimal]:
        out, cursor = {}, None
        while True:
            r = with_retry(
                lambda: self.client.get_accounts(limit=250, cursor=cursor).to_dict(),
                "accounts",
                sleep=self.sleep,
            )
            for a in r.get("accounts", []):
                out[a["currency"]] = D(str(a["available_balance"]["value"]))
            if not r.get("has_next"):
                return out
            cursor = r.get("cursor")

    def totals(self) -> dict[str, Decimal]:
        """Per currency: available + held (the hold field may be absent)."""
        out, cursor = {}, None
        while True:
            r = with_retry(
                lambda: self.client.get_accounts(limit=250, cursor=cursor).to_dict(),
                "accounts",
                sleep=self.sleep,
            )
            for a in r.get("accounts", []):
                avail = D(str(a["available_balance"]["value"]))
                hold = D(str((a.get("hold") or {}).get("value") or "0"))
                out[a["currency"]] = avail + hold
            if not r.get("has_next"):
                return out
            cursor = r.get("cursor")

    def server_time(self) -> float:
        r = with_retry(
            lambda: self.client.get_unix_time(),
            "server_time",
            sleep=self.sleep,
        )
        return float(r.to_dict()["epoch_seconds"])

    def list_open_orders(self, product: Optional[str] = None) -> list[dict]:
        out, cursor = [], None
        while True:
            kwargs = {"order_status": ["OPEN"], "limit": 250, "cursor": cursor}
            if product:
                kwargs["product_ids"] = [product]
            r = with_retry(
                lambda k=kwargs: self.client.list_orders(**k).to_dict(),
                "list_open_orders",
                sleep=self.sleep,
            )
            out += [_norm_order(o) for o in r.get("orders", [])]
            if not r.get("has_next"):
                return out
            cursor = r.get("cursor")

    def get_order(self, order_id: str, product: Optional[str] = None) -> dict:
        """One order by id.

        `product` is accepted because a router routes by product and has already
        used it; the exchange's own lookup answers without being told, so nothing
        about the request changes.
        """
        r = with_retry(
            lambda: self.client.get_order(order_id).to_dict(),
            "get_order",
            sleep=self.sleep,
        )
        return _norm_order(r["order"])

    def find_by_client_id(
        self, cid: str, since: float, product: Optional[str] = None
    ) -> Optional[dict]:
        """Look an order up by client_order_id (used before re-sending after a timeout)."""
        cursor = None
        for _ in range(10):
            kwargs = {"start_date": iso(since - 120), "limit": 250, "cursor": cursor}
            if product:
                kwargs["product_ids"] = [product]
            r = with_retry(
                lambda k=kwargs: self.client.list_orders(**k).to_dict(),
                "find_by_client_id",
                sleep=self.sleep,
            )
            for o in r.get("orders", []):
                if o.get("client_order_id") == cid:
                    return _norm_order(o)
            if not r.get("has_next"):
                return None
            cursor = r.get("cursor")
        return None

    def fills(self, order_id: str, product: Optional[str] = None) -> list[dict]:
        """The fills of one order; `product` is accepted and ignored, as in
        `get_order`, because the caller routed the read by product already."""
        out, cursor = [], None
        while True:
            r = with_retry(
                lambda: self.client.get_fills(
                    order_ids=[order_id], limit=100, cursor=cursor
                ).to_dict(),
                "fills",
                sleep=self.sleep,
            )
            out += [_norm_fill(f) for f in r.get("fills", [])]
            if not r.get("cursor"):
                return out
            cursor = r.get("cursor")

    # -- write
    def place_limit(
        self, cid: str, product: str, side: str, size: Decimal, price: Decimal
    ) -> dict:
        """ONE attempt, post-only GTC limit. Returns {ok, order_id, reason}.
        Raises TransientError when the outcome is unknown (caller must look up by cid).

        A crypto product only: an equity product goes through
        `place_equity_limit`, whose request is a different shape.  The kind is
        read off the product's own spec — lazily, and remembered once it has been
        read — so an equity is refused whatever the caller meant to do with it.  A
        spec lookup that cannot answer refuses the order with
        `PRODUCT_TYPE_UNKNOWN`: nothing is sent, nothing is raised, and the failed
        lookup is not remembered.
        """
        kind = None
        try:
            kind = self.product_type(product)
        except Exception as error:  # noqa: BLE001 - no spec means no known kind
            log.warning(
                "place %s: %s is of an unknown kind (%s); not sending",
                cid,
                product,
                type(error).__name__,
            )
        if kind is None:
            return _refused(PRODUCT_TYPE_UNKNOWN)
        if kind == "EQUITY":
            return _refused("EQUITY_USE_EQUITY_PATH")
        try:
            r = self.client.limit_order_gtc(
                client_order_id=cid,
                product_id=product,
                side=side,
                base_size=format(size, "f"),
                limit_price=format(price, "f"),
                post_only=True,
            ).to_dict()
        except Exception as e:  # noqa: BLE001
            raise classify(e) from e
        return _order_result(r)

    def place_equity_limit(
        self, cid: str, product: str, side: str, size: Decimal, price: Decimal
    ) -> dict:
        """ONE attempt at an equity limit order. Returns {ok, order_id, reason}.

        Raises TransientError when the outcome is unknown (the caller must look up
        by client order id).  Two gates run before anything is sent: the
        product's own spec has to say EQUITY (a crypto product is refused here,
        never re-routed), and the preview confirmation on record has to be the
        one `equity_preview_refusal` accepts, so an unconfirmed configuration or
        session never reaches the wire.  A spec lookup that cannot answer refuses
        the order with `PRODUCT_TYPE_UNKNOWN` — nothing sent, nothing raised, and
        the failed lookup not remembered, so the next attempt asks again.

        The request carries the GTC limit configuration and the regular-session
        metadata an equity order needs, named from the module's constants; it
        carries no post-only flag, because post-only on an equity product is not
        a rule this adapter can stand behind.
        """
        kind = None
        try:
            kind = self.product_type(product)
        except Exception as error:  # noqa: BLE001 - no spec means no known kind
            log.warning(
                "place %s: %s is of an unknown kind (%s); not sending",
                cid,
                product,
                type(error).__name__,
            )
        if kind is None:
            return _refused(PRODUCT_TYPE_UNKNOWN)
        if kind != "EQUITY":
            return _refused("NOT_EQUITY_PRODUCT")
        if equity_preview_refusal(self.equity_preview_confirmation) is not None:
            return _refused(EQUITY_PREVIEW_UNCONFIRMED)
        try:
            r = self.client.create_order(
                client_order_id=cid,
                product_id=product,
                side=side,
                order_configuration={
                    "limit_limit_gtc": {
                        "base_size": format(size, "f"),
                        "limit_price": format(price, "f"),
                    }
                },
                equity_order_metadata={
                    "equity_trading_session": EQUITY_TRADING_SESSION,
                    "displayed_order_config": EQUITY_DISPLAYED_ORDER_CONFIG,
                },
            ).to_dict()
        except Exception as e:  # noqa: BLE001
            raise classify(e) from e
        return _order_result(r)

    def cancel(self, order_ids: list[str]) -> dict[str, bool]:
        res = {}
        for i in range(0, len(order_ids), 100):
            chunk = order_ids[i : i + 100]
            r = with_retry(
                lambda: self.client.cancel_orders(order_ids=chunk).to_dict(),
                "cancel",
                sleep=self.sleep,
            )
            for x in r.get("results", []):
                res[x.get("order_id")] = bool(x.get("success")) or x.get(
                    "failure_reason"
                ) in ("DUPLICATE_CANCEL_REQUEST",)
        return res

    def advance(self, now: float) -> None:
        pass


# ====================================================================== dry run

SIM_SCHEMA = """
CREATE TABLE IF NOT EXISTS sim_orders (
  order_id TEXT PRIMARY KEY, client_order_id TEXT UNIQUE, product TEXT, side TEXT,
  price TEXT, size TEXT, status TEXT, created_at REAL, filled_at REAL,
  fee TEXT DEFAULT '0');
CREATE TABLE IF NOT EXISTS sim_balances (currency TEXT PRIMARY KEY, amount TEXT);
CREATE TABLE IF NOT EXISTS sim_deposits (
  id INTEGER PRIMARY KEY AUTOINCREMENT, currency TEXT, amount TEXT, note TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS sim_kv (key TEXT PRIMARY KEY, value TEXT);
"""


class DryRunExchange:
    """Simulates the exchange in the dry-run database. Never sends an authenticated request.

    One simulated account over any number of products: every currency of every product
    lives in the same `sim_balances` table, and an open order holds funds in its own
    product's currencies.

    Fill rule (conservative): a resting buy fills only if a later 1-minute candle traded
    strictly BELOW its price; a sell only if one traded strictly ABOVE. Candles that began
    before the order was placed are ignored.

    An equity product is simulated from the clock and one quote instead of candles.
    `owns_equity` names the products that take that path: `is_equity` is the
    configured equity list, and `equity_rows` a predicate over the store's own
    EQUITY order rows, so a symbol taken off the list still has its resting orders
    simulated as the equity instruments they were.  `is_crypto` names the
    configured crypto products and always wins: a coin is never moved to the
    equity path by a stray store row.  With no hook at all nothing is an equity,
    and every product is simulated as crypto.  An equity order fills when the
    equity quote stands strictly through its limit, and it expires once the
    session of the day it was placed in has closed (or on a day with no session at
    all).  It pays no commission: `fee_rate` is the crypto maker fee and equity
    products pay none of it, neither in the hold a buy reserves nor in the fee a
    fill books.  A NEW order follows the configured lists alone: `place_limit`
    refuses an equity and `place_equity_limit` takes only what `is_equity` names.
    """

    dry_run = True

    def __init__(
        self,
        conn_factory: Callable[[], sqlite3.Connection],
        market_for: Callable[[str], MarketData],
        fee_rate: Decimal,
        is_equity: Optional[Callable[[str], bool]] = None,
        is_crypto: Optional[Callable[[str], bool]] = None,
        equity_rows: Optional[Callable[[str], bool]] = None,
    ):
        self.conn_factory = conn_factory
        self.market_for = market_for
        self.fee_rate = fee_rate
        self.is_equity = is_equity or (lambda product: False)
        self.is_crypto = is_crypto or (lambda product: False)
        self.equity_rows = equity_rows or (lambda product: False)
        db = conn_factory()
        db.row_factory = sqlite3.Row
        db.executescript(SIM_SCHEMA)
        columns = {r["name"] for r in db.execute("PRAGMA table_info(sim_orders)")}
        if "product" not in columns:
            raise RuntimeError(
                "dry-run DB predates schema v1; reset the coinbase-data volume"
            )

    def _db(self) -> sqlite3.Connection:
        """A connection for THIS call only (never cached, so threads never share one)."""
        db = self.conn_factory()
        db.row_factory = sqlite3.Row
        return db

    @contextlib.contextmanager
    def _tx(self):
        """One immediate write transaction, committed on success, rolled back on error.

        Works whether the connection runs in autocommit (`isolation_level=None`) or
        under the default implicit-transaction handling.  When the caller already
        has a transaction open, a savepoint is used instead: the work joins the
        caller's transaction and their commit/rollback decides its fate.
        """
        db = self._db()
        if db.in_transaction:
            db.execute("SAVEPOINT sim")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK TO sim")
                db.execute("RELEASE sim")
                raise
            db.execute("RELEASE sim")
            return
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
        except BaseException:
            db.execute("ROLLBACK")
            raise
        db.execute("COMMIT")

    def owns_equity(self, product: Optional[str]) -> bool:
        """True when *product*'s resting orders are simulated as an equity.

        The rule is the router's own: the configured equity list names it, or the
        caller's `equity_rows` says the store holds EQUITY rows for it — a symbol
        taken off the list still has orders on the book.  A crypto-listed product
        is never one, whatever rows the store carries for it: a stray EQUITY row
        on a coin is history, not a place its orders live.  This steers the fee,
        the hold and the step a resting order takes; a NEW order follows the
        configured lists alone.
        """
        if self.is_equity(product):
            return True
        return bool(self.equity_rows(product)) and not self.is_crypto(product)

    def _fee_rate(self, product: str) -> Decimal:
        """The maker fee this product pays: none for an equity, else the configured rate.

        The rule itself lives in `money.fee_rate_for_type`, so the kind this
        simulator reads here and the fee the ledger reserves are one answer.
        """
        kind = "EQUITY" if self.owns_equity(product) else "SPOT"
        return fee_rate_for_type(kind, self.fee_rate)

    # -- balances (total minus holds of open orders = available)
    def _total(self, db, cur: str) -> Decimal:
        r = db.execute(
            "SELECT amount FROM sim_balances WHERE currency=?", (cur,)
        ).fetchone()
        return D(r[0]) if r else D(0)

    def _add(self, db, cur: str, delta: Decimal) -> None:
        db.execute(
            "INSERT INTO sim_balances(currency,amount) VALUES(?,?)"
            " ON CONFLICT(currency) DO UPDATE SET amount=excluded.amount",
            (cur, str(self._total(db, cur) + delta)),
        )

    def deposit(self, currency: str, amount: Decimal, note: str) -> None:
        amt = D(amount)
        if amt <= 0:
            raise ValueError(f"deposit amount must be positive, got {amount}")
        with self._tx() as db:
            self._add(db, currency, amt)
            db.execute(
                "INSERT INTO sim_deposits(currency,amount,note,ts) VALUES(?,?,?,?)",
                (currency, str(amount), note, time.time()),
            )

    def _holds(self, db) -> dict[str, Decimal]:
        """Currency -> funds held by OPEN orders, summed over every product."""
        holds: dict[str, Decimal] = {}
        for r in db.execute(
            "SELECT product,side,price,size FROM sim_orders WHERE status='OPEN'"
        ):
            base, quote = r["product"].split("-", 1)
            size, price = D(r["size"]), D(r["price"])
            if r["side"] == BUY:
                cur, amt = quote, size * price * (1 + self._fee_rate(r["product"]))
            else:
                cur, amt = base, size
            holds[cur] = holds.get(cur, D(0)) + amt
        return holds

    def _balances(self, db) -> dict[str, Decimal]:
        out = {
            r["currency"]: D(r["amount"])
            for r in db.execute("SELECT currency, amount FROM sim_balances")
        }
        for cur, amt in self._holds(db).items():
            out[cur] = out.get(cur, D(0)) - amt
        return out

    def balances(self) -> dict[str, Decimal]:
        return self._balances(self._db())

    def totals(self) -> dict[str, Decimal]:
        """Every currency in the simulated account, INCLUDING open-order holds."""
        db = self._db()
        return {
            r["currency"]: D(r["amount"])
            for r in db.execute("SELECT currency, amount FROM sim_balances")
        }

    def server_time(self) -> float:
        return time.time()

    def key_permissions(self) -> dict:
        return {}

    def maker_fee_rate(self) -> Optional[Decimal]:
        return None

    # -- orders
    def _row(self, r) -> dict:
        filled = r["status"] == "FILLED"
        size, price = D(r["size"]), D(r["price"])
        return {
            "order_id": r["order_id"],
            "client_order_id": r["client_order_id"],
            "product": r["product"],
            "side": r["side"],
            "status": r["status"],
            "price": price,
            "size": size,
            "filled_size": size if filled else D(0),
            "filled_value": size * price if filled else D(0),
            "total_fees": D(r["fee"]),
        }

    def _find_cid(self, db, cid: str):
        return db.execute(
            "SELECT * FROM sim_orders WHERE client_order_id=?", (cid,)
        ).fetchone()

    def list_open_orders(self, product: Optional[str] = None) -> list[dict]:
        db = self._db()
        if product is None:
            rows = db.execute("SELECT * FROM sim_orders WHERE status='OPEN'")
        else:
            rows = db.execute(
                "SELECT * FROM sim_orders WHERE status='OPEN' AND product=?",
                (product,),
            )
        return [self._row(r) for r in rows]

    def get_order(self, order_id: str, product: Optional[str] = None) -> dict:
        """One simulated order by id.  `product` is accepted and ignored: the
        caller routed the read by product, and the row already knows its own."""
        db = self._db()
        r = db.execute(
            "SELECT * FROM sim_orders WHERE order_id=?", (order_id,)
        ).fetchone()
        if not r:
            raise PermanentError("HTTP 404: order not found")
        return self._row(r)

    def find_by_client_id(
        self, cid: str, since: float, product: Optional[str] = None
    ) -> Optional[dict]:
        r = self._find_cid(self._db(), cid)
        if not r:
            return None
        if product is not None and r["product"] != product:
            return None
        return self._row(r)

    def fills(self, order_id: str, product: Optional[str] = None) -> list[dict]:
        """The fills of one simulated order; `product` is accepted and ignored."""
        db = self._db()
        r = db.execute(
            "SELECT * FROM sim_orders WHERE order_id=? AND status='FILLED'", (order_id,)
        ).fetchone()
        if not r:
            return []
        return [
            {
                "trade_id": "sim-" + r["order_id"],
                "order_id": r["order_id"],
                "product": r["product"],
                "side": r["side"],
                "size": D(r["size"]),
                "price": D(r["price"]),
                "commission": D(r["fee"]),
                "trade_time": iso(r["filled_at"]),
                "trade_type": "FILL",
            }
        ]

    def place_limit(
        self, cid: str, product: str, side: str, size: Decimal, price: Decimal
    ) -> dict:
        """A crypto limit order; an equity product is refused, not simulated here.

        A product `owns_equity` names — one on the configured list, or a delisted
        one the store still holds EQUITY rows for — answers
        `EQUITY_USE_EQUITY_PATH`, while a crypto-listed product is never refused
        here, whatever rows the store carries for it.
        """
        if not self.is_crypto(product) and self.owns_equity(product):
            return _refused("EQUITY_USE_EQUITY_PATH")
        return self._place(cid, product, side, size, price, post_only=True)

    def place_equity_limit(
        self, cid: str, product: str, side: str, size: Decimal, price: Decimal
    ) -> dict:
        """An equity limit order; a crypto product is refused, not simulated here.

        Only the CONFIGURED equity list (`is_equity`) admits an order: the store's
        EQUITY rows steer reads, cancels and the simulation of resting orders, but
        they never make a new order an equity one.

        No post-only check applies: post-only is a crypto rule this simulator does
        not claim to know for an equity product, so a limit at or through the
        quote is accepted and simply fills on the next step.
        """
        if not self.is_equity(product):
            return _refused("NOT_EQUITY_PRODUCT")
        return self._place(cid, product, side, size, price, post_only=False)

    def _place(
        self,
        cid: str,
        product: str,
        side: str,
        size: Decimal,
        price: Decimal,
        post_only: bool,
    ) -> dict:
        """The one placement body both write paths share.

        `post_only` is the only difference between them: a crypto order may not
        cross the book, an equity order carries no such rule.  The hold is
        `size * price` plus this product's own fee rate (none for an equity), and
        the resend/race handling is identical for both.
        """
        # A resend of an already-placed cid returns that order, even if the market
        # has since moved past the price (the re-check inside _tx covers races).
        existing = self._find_cid(self._db(), cid)
        if existing:
            return {"ok": True, "order_id": existing["order_id"], "reason": None}
        base, quote = product.split("-", 1)
        fee_rate = self._fee_rate(product)
        if post_only:
            bid, ask = self.market_for(product).best_bid_ask()
            if (side == BUY and price >= ask) or (side == SELL and price <= bid):
                return _refused("INVALID_LIMIT_PRICE_POST_ONLY")
        with self._tx() as db:
            existing = self._find_cid(db, cid)
            if (
                existing
            ):  # same semantics as Coinbase: duplicate cid returns the existing order
                return {"ok": True, "order_id": existing["order_id"], "reason": None}
            bal = self._balances(db)
            need = size * price * (1 + fee_rate) if side == BUY else size
            have = bal.get(quote if side == BUY else base, D(0))
            if need > have:
                return _refused("INSUFFICIENT_FUND")
            oid = "sim-" + uuid.uuid4().hex[:12]
            db.execute(
                "INSERT INTO sim_orders(order_id,client_order_id,product,side,price,size,status,created_at) "
                "VALUES(?,?,?,?,?,?, 'OPEN', ?)",
                (oid, cid, product, side, str(price), str(size), time.time()),
            )
            return {"ok": True, "order_id": oid, "reason": None}

    def cancel(self, order_ids: list[str]) -> dict[str, bool]:
        out = {}
        with self._tx() as db:
            for oid in order_ids:
                cur = db.execute(
                    "UPDATE sim_orders SET status='CANCELLED' WHERE order_id=? AND status='OPEN'",
                    (oid,),
                )
                out[oid] = cur.rowcount == 1
        return out

    # -- simulation step
    def advance(self, now: float) -> list[str]:
        """Settle resting orders off their own market: fills, and equity expiries.

        Each product is stepped by the path its kind owns: a crypto product from
        its candles, an equity product from its quote and the session clock.  A
        failure reading one product's market is a warning that skips that
        product's orders for this step and leaves the rest of the book alone.
        The returned ids are the orders that filled, in the order they did.
        """
        db = self._db()
        open_rows = [
            dict(r) for r in db.execute("SELECT * FROM sim_orders WHERE status='OPEN'")
        ]
        if not open_rows:
            return []
        by_product: dict[str, list[dict]] = {}
        for r in open_rows:
            by_product.setdefault(r["product"], []).append(r)
        filled = []
        for product, rows in by_product.items():
            if self.owns_equity(product):
                filled += self._advance_equity(product, rows, now)
            else:
                filled += self._advance_crypto(product, rows, now)
        return filled

    def _advance_crypto(self, product: str, rows: list[dict], now: float) -> list[str]:
        """Fill the product's resting orders whose own candles traded through them."""
        base, quote = product.split("-", 1)
        oldest = min(r["created_at"] for r in rows)
        try:
            candles = self.market_for(product).candles(oldest, now)
        except Exception as e:  # noqa: BLE001
            log.warning("candles failed for %s: %s", product, e)
            return []
        fee_rate = self._fee_rate(product)
        filled = []
        for r in rows:
            price, size = D(r["price"]), D(r["size"])
            eligible = [c for c in candles if c["start"] >= r["created_at"]]
            hit = next(
                (
                    c
                    for c in eligible
                    if (
                        c["low"] < price
                        if r["side"] == BUY
                        else c["high"] > price
                    )
                ),
                None,
            )
            if not hit:
                continue
            fee = size * price * fee_rate
            with self._tx() as tdb:
                cur = tdb.execute(
                    "UPDATE sim_orders SET status='FILLED', filled_at=?, fee=?"
                    " WHERE order_id=? AND status='OPEN'",
                    (
                        max(hit["start"] + 60, r["created_at"]),
                        str(fee),
                        r["order_id"],
                    ),
                )
                if cur.rowcount != 1:  # a concurrent cancel won: change nothing
                    continue
                if r["side"] == BUY:
                    self._add(tdb, quote, -(size * price + fee))
                    self._add(tdb, base, size)
                else:
                    self._add(tdb, base, -size)
                    self._add(tdb, quote, size * price - fee)
                filled.append(r["client_order_id"])
        return filled

    def _advance_equity(self, product: str, rows: list[dict], now: float) -> list[str]:
        """Expire first, then fill the product's resting equity orders.

        An order outlives the session of the day it was placed in by nothing: at
        that day's close (or on a day with no session at all) it expires.  The
        expiry is settled for every row BEFORE the quote is asked for, so a quote
        that cannot be read only costs this step its fills — it can never keep an
        order from yesterday alive.  With nothing left to fill the quote is not
        read at all.

        A resting order fills at its own limit price, for its whole size, with no
        commission, once the quote stands strictly through it: below a buy, above
        a sell.

        The quote is the PRACTICE book's print (`equity_print_for(..., DRY)`), so
        the age this fill accepts is the one a dry order's book allows and not the
        strict live bound: the orders here are the simulator's.
        """
        fee_rate = self._fee_rate(product)
        resting: list[dict] = []
        for r in rows:
            close = market_hours.session_close(r["created_at"])
            if close is None or now >= close:
                self._expire(r["order_id"])
                continue
            resting.append(r)
        if not resting:
            return []
        try:
            last, _ = equity_print_for(self.market_for(product), DRY)
        except Exception as e:  # noqa: BLE001
            log.warning("equity quote failed for %s: %s", product, e)
            return []
        filled = []
        for r in resting:
            price = D(r["price"])
            crossed = last < price if r["side"] == BUY else last > price
            if not crossed:
                continue
            if self._fill_equity(r, now, fee_rate):
                filled.append(r["client_order_id"])
        return filled

    def _fill_equity(self, row: dict, now: float, fee_rate: Decimal) -> bool:
        """Mark *row* filled and move its currencies, in one guarded transaction.

        False means the row was no longer OPEN when the write landed: a cancel or
        a settle won the race, so no balance is moved here.
        """
        base, quote = row["product"].split("-", 1)
        price, size = D(row["price"]), D(row["size"])
        fee = size * price * fee_rate
        with self._tx() as tdb:
            cur = tdb.execute(
                "UPDATE sim_orders SET status='FILLED', filled_at=?, fee=?"
                " WHERE order_id=? AND status='OPEN'",
                (now, str(fee), row["order_id"]),
            )
            if cur.rowcount != 1:  # a concurrent cancel won: change nothing
                return False
            if row["side"] == BUY:
                self._add(tdb, quote, -(size * price + fee))
                self._add(tdb, base, size)
            else:
                self._add(tdb, base, -size)
                self._add(tdb, quote, size * price - fee)
        return True

    def _expire(self, order_id: str) -> bool:
        """Mark a resting order EXPIRED; False when a cancel or fill got there first."""
        with self._tx() as db:
            cur = db.execute(
                "UPDATE sim_orders SET status='EXPIRED' WHERE order_id=? AND status='OPEN'",
                (order_id,),
            )
            return cur.rowcount == 1


def _refused(reason: str) -> dict:
    """A placement the adapter refused before touching the book."""
    return {"ok": False, "order_id": None, "reason": reason}


def merge_totals(
    crypto: dict[str, Decimal],
    equity: Optional[dict[str, Decimal]],
    equity_bases,
    usd_one_pool: bool,
) -> dict[str, Decimal]:
    """One totals view over the crypto account and the equity account.

    Every currency of the crypto account is kept, so a crypto holding is never
    dropped by merging.  Each equity base symbol (`NVDA` for `NVDA-USD`) is taken
    from the equity account and overwrites whatever the crypto side reports for
    that name: the shares live in one place, and that place is the equity
    account.  A base the equity account does not hold is left out entirely, so a
    stale crypto-side number cannot stand in for shares that are not there.

    Every other currency only the equity account holds (its sweep balance, a fund
    it holds) is not part of this account and is dropped.

    USD is the one currency the two accounts can share.  With `usd_one_pool` the
    cash is one pool seen twice, so nothing is added and the crypto side's figure
    stands; without it the two accounts are separate pools and their USD sums.

    A missing equity account (a crypto-only install) is the crypto totals alone,
    in a fresh dict the caller may change.
    """
    merged = dict(crypto or {})
    if equity is None:
        return merged
    for base in set(equity_bases or ()):
        if base in equity:
            merged[base] = equity[base]
        else:
            merged.pop(base, None)
    if not usd_one_pool:
        usd = D(str(merged.get("USD", 0))) + D(str((equity or {}).get("USD", 0)))
        if usd:
            merged["USD"] = usd
        else:
            merged.pop("USD", None)
    return merged


def check_equity_key(perms: dict, portfolio_id: Optional[str] = None) -> Optional[str]:
    """Why an equity API key may not be used, or None when it may.

    Four refusals, in this order.  A key that can transfer funds is never used,
    because this engine only ever places and cancels orders and never moves
    funds.  A key that cannot trade cannot be used for what this engine does, and
    one that cannot view its own portfolio cannot be read safely either — for
    both of those the permission has to be exactly `True`: "true", 1 and every
    other truthy value are not the grant the answer means, and a permission
    absent from the answer is not a permission granted.  Finally, when a
    *portfolio_id* is given, the key has to be scoped to exactly that portfolio:
    a key scoped elsewhere, or to none at all, is refused because the shares
    would live somewhere the engine is not accounting for.
    """
    perms = perms or {}
    if perms.get("can_transfer"):
        return "equity API key can transfer funds; the engine never moves funds"
    if perms.get("can_trade") is not True:
        return "equity API key cannot trade"
    if perms.get("can_view") is not True:
        return "equity API key cannot view its own portfolio"
    wanted = str(portfolio_id).strip() if portfolio_id is not None else ""
    if wanted:
        scoped = perms.get("portfolio_uuid")
        if scoped != wanted:
            return (
                f"equity API key is scoped to portfolio {scoped!r}, not to "
                f"{wanted}; the equity route trades one known portfolio"
            )
    return None


def new_client_order_id(prefix: str, side: str, level: int) -> str:
    return f"{prefix}{side[0]}{level:+d}-{uuid.uuid4().hex[:12]}"


def parse_client_order_id(prefix: str, cid: str) -> Optional[tuple[str, int]]:

    m = re.fullmatch(rf"{re.escape(prefix)}([BS])([+-]\d+)-[0-9a-f]+", cid or "")
    if not m:
        return None
    return (BUY if m.group(1) == "B" else SELL), int(m.group(2))
