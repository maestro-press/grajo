"""Engine limits from the environment, and the windows the order caps read.

`Limits` is the parsed configuration: the nineteen values the engine reads at
startup, their defaults and their validation in one table.  Every value is read
from an explicit mapping, never from `os.environ`, so the caller decides what a
process sees.  A missing or blank value means "the default"; an invalid one
raises `ValueError` naming the variable that carried it.  Money stays `Decimal`:
values are parsed with `Decimal(str(...))` and a non-finite number is refused.

Nine of those values are CAPS: a daily notional and a rolling-hour order count
(for every owner and, separately, for the `ai` owner), a portfolio drawdown
percentage, a single-order cap per source, the capital a bot may be given, and
the capital the `ai` owner trades.  `CAP_SPECS` is the one ordered table of
them — the variable each is set with, the field it becomes, whether it is money
or a count, and whether zero is a value it may hold — and everything else in the
engine reads them through it.  The value the environment carries is a CEILING.

`RuntimeLimits` is what the engine reads at run time: it holds the ceiling
`Limits` parsed from the environment, and answers the nine caps from one kv key
(`runtime_caps`), so an owner can lower a cap while the engine runs and can
never raise one above the ceiling the process was started with.  Every other
value — the poll interval, the products, the fee, the watchdog policy, the
equity settings, `is_equity`, `tradable` — is the ceiling object's own, so a
`RuntimeLimits` can be passed wherever a `Limits` is read.

`CapWindow` answers the two questions the order caps ask — how much notional was
already placed today (UTC day) and how many orders were placed in the last
rolling hour — by reading the `orders` table.  It counts the orders the engine
actually placed: a row the exchange rejected, or one that never reached it, does
not spend the budget, while a cancelled one does (it rested on the book).  The
state lives in the table rather than in a counter here, so the caps survive a
restart.  Every read names one book (`books.py`): a day of dry orders spends no
live budget, and a live order is never hidden behind a day of dry ones.

A crypto product is an upper-case BASE-QUOTE pair, each side 2-15 characters of
A-Z0-9, and the quote must be USDC or USD: the caps are denominated in USD, so
any other quote would route notional past them.  An equity product is a
TICKER-USD pair, the ticker 1-6 upper-case letters.  The two lists describe
different instruments, so an equity may not repeat a crypto id nor share its
base asset (a BTC-USD equity would be the same coin as the BTC-USDC pair).
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

from .store import FAILED, PRODUCT_TYPES, REJECTED, Store

D = Decimal
ZERO = D(0)
HUNDRED = D(100)

log = logging.getLogger("crow_coinbase.limits")

# ---------------------------------------------------------------- env names
ENV_POLL_SECONDS = "CROW_COINBASE_POLL_SECONDS"
ENV_MAKER_FEE_PCT = "CROW_COINBASE_MAKER_FEE_PCT"
ENV_PRODUCTS = "CROW_COINBASE_PRODUCTS"
ENV_DAILY_NOTIONAL_USD = "CROW_COINBASE_DAILY_NOTIONAL_USD"
ENV_ORDERS_PER_HOUR = "CROW_COINBASE_ORDERS_PER_HOUR"
ENV_PORTFOLIO_DRAWDOWN_PCT = "CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT"
ENV_BOT_MAX_ORDER_USD = "CROW_COINBASE_BOT_MAX_ORDER_USD"
ENV_MAX_BOT_CAPITAL_USD = "CROW_COINBASE_MAX_BOT_CAPITAL_USD"
ENV_AI_MAX_ORDER_USD = "CROW_COINBASE_AI_MAX_ORDER_USD"
ENV_AI_DAILY_NOTIONAL_USD = "CROW_COINBASE_AI_DAILY_NOTIONAL_USD"
ENV_AI_ORDERS_PER_HOUR = "CROW_COINBASE_AI_ORDERS_PER_HOUR"
ENV_AI_CAPITAL_USD = "CROW_COINBASE_AI_CAPITAL_USD"
ENV_WATCHDOG_POLICY = "CROW_COINBASE_WATCHDOG_POLICY"
ENV_EQUITY_PRODUCTS = "CROW_COINBASE_EQUITY_PRODUCTS"
ENV_EQUITY_MAX_ORDER_USD = "CROW_COINBASE_EQUITY_MAX_ORDER_USD"
ENV_EQUITY_DAILY_NOTIONAL_USD = "CROW_COINBASE_EQUITY_DAILY_NOTIONAL_USD"
ENV_EQUITY_AI_CAPITAL_USD = "CROW_COINBASE_EQUITY_AI_CAPITAL_USD"
ENV_EQUITY_DRAWDOWN_ALERT_PCT = "CROW_COINBASE_EQUITY_DRAWDOWN_ALERT_PCT"
ENV_EQUITY_LIVE = "CROW_COINBASE_EQUITY_LIVE"

# ---------------------------------------------------------------- defaults
DEFAULT_POLL_SECONDS = 60
DEFAULT_MAKER_FEE_PCT = D("0.5")
DEFAULT_PRODUCTS = ("BTC-USDC", "ETH-USDC", "XRP-USDC")
DEFAULT_DAILY_NOTIONAL_USD = D("200")
DEFAULT_ORDERS_PER_HOUR = 30
DEFAULT_PORTFOLIO_DRAWDOWN_PCT = D("20")
DEFAULT_BOT_MAX_ORDER_USD = D("50")
DEFAULT_MAX_BOT_CAPITAL_USD = D("100")
DEFAULT_AI_MAX_ORDER_USD = D("25")
DEFAULT_AI_DAILY_NOTIONAL_USD = D("50")
DEFAULT_AI_ORDERS_PER_HOUR = 10
DEFAULT_AI_CAPITAL_USD = D("25")
DEFAULT_WATCHDOG_POLICY = "leave"
DEFAULT_EQUITY_PRODUCTS: tuple[str, ...] = ()
DEFAULT_EQUITY_MAX_ORDER_USD = D("100")
DEFAULT_EQUITY_DAILY_NOTIONAL_USD = D("200")
DEFAULT_EQUITY_AI_CAPITAL_USD = D("0")
DEFAULT_EQUITY_DRAWDOWN_ALERT_PCT = D("20")
DEFAULT_EQUITY_LIVE = False

# what the watchdog may do with a stale heartbeat: alert only, or cancel too
WATCHDOG_POLICIES = ("leave", "cancel")

# what a boolean env value may say, lower-cased and stripped
TRUE_WORDS = ("true", "1", "yes", "on")
FALSE_WORDS = ("false", "0", "no", "off")

PRODUCT_SPLIT_RE = re.compile(r"^([A-Z0-9]{2,15})-([A-Z0-9]{2,15})$")

# an equity product: a 1-6 letter ticker, always quoted in USD
EQUITY_PRODUCT_RE = re.compile(r"^[A-Z]{1,6}-USD$")

# The quote half of a product must be USD-denominated: the daily cap is a USD
# amount, so a pair quoted in anything else would spend budget it is not
# measured against.
ALLOWED_QUOTES = ("USDC", "USD")


# ---------------------------------------------------------------- value parsing
def _text(env: Mapping[str, str], name: str) -> Optional[str]:
    """The mapping's value for *name* with padding stripped, or None if blank."""
    raw = env.get(name)
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _decimal(name: str, text: str) -> Decimal:
    """A finite Decimal, parsed from its string form (never through float)."""
    try:
        value = D(text)
    except (ArithmeticError, ValueError):
        raise ValueError(f"{name} must be a number, got {text!r}") from None
    if not value.is_finite():
        raise ValueError(f"{name} must be a finite number, got {text!r}")
    return value


def _money(name: str, text: str) -> Decimal:
    """A strictly positive amount of money."""
    value = _decimal(name, text)
    if value <= ZERO:
        raise ValueError(f"{name} must be greater than 0, got {text!r}")
    return value


def _nonneg_money(name: str, text: str) -> Decimal:
    """An amount of money that may be zero — nothing allocated is not an error."""
    value = _decimal(name, text)
    if value < ZERO:
        raise ValueError(f"{name} must be 0 or greater, got {text!r}")
    return value


def _pct(
    name: str,
    text: str,
    low: Decimal,
    high: Decimal,
    *,
    low_inclusive: bool = True,
    high_inclusive: bool = True,
) -> Decimal:
    """A percentage inside the given range; inclusive unless told otherwise."""
    value = _decimal(name, text)
    above_low = value >= low if low_inclusive else value > low
    below_high = value <= high if high_inclusive else value < high
    if not (above_low and below_high):
        bounds = (
            "[" if low_inclusive else "(",
            "]" if high_inclusive else ")",
        )
        raise ValueError(
            f"{name} must be a percentage within "
            f"{bounds[0]}{low}, {high}{bounds[1]}, got {text!r}"
        )
    return value


def _fee_pct(name: str, text: str) -> Decimal:
    """A maker fee percent: 0 is free, 100 is refused."""
    return _pct(name, text, ZERO, HUNDRED, high_inclusive=False)


def _drawdown_pct(name: str, text: str) -> Decimal:
    """A drawdown threshold: some drawdown must be possible to trip it."""
    return _pct(name, text, ZERO, HUNDRED, low_inclusive=False)


def _positive_int(name: str, text: str) -> int:
    """A whole number of at least 1."""
    try:
        value = int(text)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number, got {text!r}") from None
    if value <= 0:
        raise ValueError(f"{name} must be greater than 0, got {text!r}")
    return value


def _products(name: str, text: str) -> tuple[str, ...]:
    """A comma-separated product list, order kept, padding stripped.

    Each entry is an upper-case BASE-QUOTE pair — each side 2-15 characters of
    A-Z0-9 — whose quote is USDC or USD, because the caps are USD amounts and a
    pair quoted in another currency would slip past them.
    """
    parts = [part.strip() for part in text.split(",")]
    if any(not part for part in parts):
        raise ValueError(
            f"{name} must be a comma-separated list of products, got {text!r}"
        )
    quotes = " or ".join(ALLOWED_QUOTES)
    for part in parts:
        match = PRODUCT_SPLIT_RE.match(part)
        if match is None or match.group(2) not in ALLOWED_QUOTES:
            raise ValueError(
                f"{name} has an invalid product {part!r}; expected an upper-case "
                f"BASE-QUOTE pair quoted in {quotes} such as BTC-USDC, with each "
                f"side 2-15 characters of A-Z0-9"
            )
    if len(set(parts)) != len(parts):
        raise ValueError(f"{name} lists the same product more than once: {text!r}")
    return tuple(parts)


def _equity_products(name: str, text: str) -> tuple[str, ...]:
    """A comma-separated equity list, order kept, padding stripped.

    Each entry is an upper-case TICKER-USD pair with a 1-6 letter ticker.
    Equities are quoted in USD, so a USDC-quoted equity is refused.
    """
    parts = [part.strip() for part in text.split(",")]
    if any(not part for part in parts):
        raise ValueError(
            f"{name} must be a comma-separated list of equity products, "
            f"got {text!r}"
        )
    for part in parts:
        if EQUITY_PRODUCT_RE.match(part) is None:
            raise ValueError(
                f"{name} has an invalid equity product {part!r}; expected an "
                f"upper-case TICKER-USD pair such as NVDA-USD, with a ticker of "
                f"1-6 letters — equities are quoted in USD, never USDC"
            )
    if len(set(parts)) != len(parts):
        raise ValueError(
            f"{name} lists the same equity product more than once: {text!r}"
        )
    return tuple(parts)


def _bool(name: str, text: str) -> bool:
    """A boolean, spelled true/false, 1/0, yes/no or on/off in any case."""
    lowered = text.strip().lower()
    if lowered in TRUE_WORDS:
        return True
    if lowered in FALSE_WORDS:
        return False
    raise ValueError(
        f"{name} must be one of {', '.join(TRUE_WORDS + FALSE_WORDS)}, "
        f"got {text!r}"
    )


def _policy(name: str, text: str) -> str:
    """One of the known watchdog policies."""
    if text not in WATCHDOG_POLICIES:
        raise ValueError(
            f"{name} must be one of {', '.join(WATCHDOG_POLICIES)}, got {text!r}"
        )
    return text


def _refuse_shared_instruments(
    products: tuple[str, ...], equity_products: tuple[str, ...]
) -> None:
    """Refuse an equity that is, or shares a base asset with, a crypto product.

    The equity caps are a budget of their own, so an instrument appearing on
    both lists would spend one pool while being measured against the other.  A
    shared base asset is the same instrument too: a BTC-USD equity is the coin
    the BTC-USDC pair trades.
    """
    crypto_ids = set(products)
    crypto_bases = {product.split("-", 1)[0] for product in products}
    for equity in equity_products:
        base = equity.split("-", 1)[0]
        if equity in crypto_ids or base in crypto_bases:
            raise ValueError(
                f"{ENV_EQUITY_PRODUCTS} names {equity}, which collides with a "
                f"crypto product; an equity and a crypto product may share "
                f"neither an id nor a base asset"
            )


def _product_kind(spec: Any) -> str:
    """A product spec's kind, upper-cased and stripped (" spot " is SPOT)."""
    return str(getattr(spec, "product_type", "") or "").strip().upper()


def validate_product_types(
    products: Iterable[str],
    equity_products: Iterable[str],
    spec_for: Callable[[str], Any],
) -> None:
    """Refuse a list that names a product of the wrong kind.

    The env parser can only read the shape of a product id, so an id that is
    well formed but names the other kind of instrument (an equity in the crypto
    list, a coin in the equity list) passes it.  The kind is the exchange's fact,
    read through *spec_for*, so this guard is the one place it is compared: every
    entry of *products* must be SPOT and every entry of *equity_products* must be
    EQUITY, case-insensitively.  The kind is read lazily rather than in
    `build_app`, because a spec needs the network.  Raises `ValueError` naming
    the product it refused; returns None when both lists agree with their kinds.
    """
    for product in products:
        kind = _product_kind(spec_for(product))
        if kind != "SPOT":
            raise ValueError(
                f"{ENV_PRODUCTS} names {product}, which is a {kind or 'untyped'} "
                f"product, not a SPOT one; the crypto list may only name SPOT "
                f"products"
            )
    for product in equity_products:
        kind = _product_kind(spec_for(product))
        if kind != "EQUITY":
            raise ValueError(
                f"{ENV_EQUITY_PRODUCTS} names {product}, which is a "
                f"{kind or 'untyped'} product, not an EQUITY one; the equity "
                f"list may only name EQUITY products"
            )
    return None


# field name, env name, default, parser — one row per value, in the order the
# engine reads them.  `from_env` walks this table and nothing else.
_SPECS: tuple[tuple[str, str, Any, Callable[[str, str], Any]], ...] = (
    ("poll_seconds", ENV_POLL_SECONDS, DEFAULT_POLL_SECONDS, _positive_int),
    ("maker_fee_pct", ENV_MAKER_FEE_PCT, DEFAULT_MAKER_FEE_PCT, _fee_pct),
    ("products", ENV_PRODUCTS, DEFAULT_PRODUCTS, _products),
    ("daily_notional_usd", ENV_DAILY_NOTIONAL_USD, DEFAULT_DAILY_NOTIONAL_USD, _money),
    ("orders_per_hour", ENV_ORDERS_PER_HOUR, DEFAULT_ORDERS_PER_HOUR, _positive_int),
    (
        "portfolio_drawdown_pct",
        ENV_PORTFOLIO_DRAWDOWN_PCT,
        DEFAULT_PORTFOLIO_DRAWDOWN_PCT,
        _drawdown_pct,
    ),
    ("bot_max_order_usd", ENV_BOT_MAX_ORDER_USD, DEFAULT_BOT_MAX_ORDER_USD, _money),
    (
        "max_bot_capital_usd",
        ENV_MAX_BOT_CAPITAL_USD,
        DEFAULT_MAX_BOT_CAPITAL_USD,
        _money,
    ),
    ("ai_max_order_usd", ENV_AI_MAX_ORDER_USD, DEFAULT_AI_MAX_ORDER_USD, _money),
    (
        "ai_daily_notional_usd",
        ENV_AI_DAILY_NOTIONAL_USD,
        DEFAULT_AI_DAILY_NOTIONAL_USD,
        _money,
    ),
    (
        "ai_orders_per_hour",
        ENV_AI_ORDERS_PER_HOUR,
        DEFAULT_AI_ORDERS_PER_HOUR,
        _positive_int,
    ),
    ("ai_capital_usd", ENV_AI_CAPITAL_USD, DEFAULT_AI_CAPITAL_USD, _nonneg_money),
    ("watchdog_policy", ENV_WATCHDOG_POLICY, DEFAULT_WATCHDOG_POLICY, _policy),
    (
        "equity_products",
        ENV_EQUITY_PRODUCTS,
        DEFAULT_EQUITY_PRODUCTS,
        _equity_products,
    ),
    (
        "equity_max_order_usd",
        ENV_EQUITY_MAX_ORDER_USD,
        DEFAULT_EQUITY_MAX_ORDER_USD,
        _money,
    ),
    (
        "equity_daily_notional_usd",
        ENV_EQUITY_DAILY_NOTIONAL_USD,
        DEFAULT_EQUITY_DAILY_NOTIONAL_USD,
        _money,
    ),
    (
        "equity_ai_capital_usd",
        ENV_EQUITY_AI_CAPITAL_USD,
        DEFAULT_EQUITY_AI_CAPITAL_USD,
        _nonneg_money,
    ),
    (
        "equity_drawdown_alert_pct",
        ENV_EQUITY_DRAWDOWN_ALERT_PCT,
        DEFAULT_EQUITY_DRAWDOWN_ALERT_PCT,
        _drawdown_pct,
    ),
    ("equity_live", ENV_EQUITY_LIVE, DEFAULT_EQUITY_LIVE, _bool),
)


@dataclass(frozen=True)
class Limits:
    """The engine's configured bounds. Frozen: parsed once, then read-only."""

    poll_seconds: int = DEFAULT_POLL_SECONDS
    maker_fee_pct: Decimal = DEFAULT_MAKER_FEE_PCT
    products: tuple[str, ...] = DEFAULT_PRODUCTS
    daily_notional_usd: Decimal = DEFAULT_DAILY_NOTIONAL_USD
    orders_per_hour: int = DEFAULT_ORDERS_PER_HOUR
    portfolio_drawdown_pct: Decimal = DEFAULT_PORTFOLIO_DRAWDOWN_PCT
    bot_max_order_usd: Decimal = DEFAULT_BOT_MAX_ORDER_USD
    max_bot_capital_usd: Decimal = DEFAULT_MAX_BOT_CAPITAL_USD
    ai_max_order_usd: Decimal = DEFAULT_AI_MAX_ORDER_USD
    ai_daily_notional_usd: Decimal = DEFAULT_AI_DAILY_NOTIONAL_USD
    ai_orders_per_hour: int = DEFAULT_AI_ORDERS_PER_HOUR
    ai_capital_usd: Decimal = DEFAULT_AI_CAPITAL_USD
    watchdog_policy: str = DEFAULT_WATCHDOG_POLICY
    equity_products: tuple[str, ...] = DEFAULT_EQUITY_PRODUCTS
    equity_max_order_usd: Decimal = DEFAULT_EQUITY_MAX_ORDER_USD
    equity_daily_notional_usd: Decimal = DEFAULT_EQUITY_DAILY_NOTIONAL_USD
    equity_ai_capital_usd: Decimal = DEFAULT_EQUITY_AI_CAPITAL_USD
    equity_drawdown_alert_pct: Decimal = DEFAULT_EQUITY_DRAWDOWN_ALERT_PCT
    equity_live: bool = DEFAULT_EQUITY_LIVE

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Limits":
        """Parse *env* into Limits. Only *env* is read; blank means the default."""
        values: dict[str, Any] = {}
        for field_name, name, default, parse in _SPECS:
            text = _text(env, name)
            values[field_name] = default if text is None else parse(name, text)
        _refuse_shared_instruments(values["products"], values["equity_products"])
        return cls(**values)

    def is_equity(self, product: str) -> bool:
        """True when *product* is one of the configured equity products."""
        return product in self.equity_products

    def tradable(self, product: str) -> bool:
        """True when *product* is on either list — crypto or equity."""
        return product in self.products or self.is_equity(product)


# ---------------------------------------------------------------- the caps
# The nine caps, in the order the engine reads them: the variable each is set
# with, the field it becomes on `Limits`/`RuntimeLimits`, its kind, and whether
# it is a cap zero may be set to.  Every other module reads a cap through this
# table, through the fields it names, so a variable's name lives here alone and
# nothing can read one from the environment instead of the runtime object every
# check is handed.
CAP_KIND_MONEY = "money"
CAP_KIND_COUNT = "count"


@dataclass(frozen=True)
class CapSpec:
    """One cap: its variable, the field it is read as, and whether it is a count.

    `positive` marks the one cap whose value of zero is not a value at all: the
    portfolio drawdown percentage, where 0 would halt a book on any dip below its
    high-water mark rather than at a threshold.  Every other cap takes 0 — a cap
    of zero is a legitimate way to stop spending that budget — so the rule is
    stated per cap here rather than assumed from the kind.
    """

    env: str
    field: str
    kind: str
    positive: bool = False


CAP_SPECS: tuple[CapSpec, ...] = (
    CapSpec(ENV_DAILY_NOTIONAL_USD, "daily_notional_usd", CAP_KIND_MONEY),
    CapSpec(ENV_ORDERS_PER_HOUR, "orders_per_hour", CAP_KIND_COUNT),
    CapSpec(
        ENV_PORTFOLIO_DRAWDOWN_PCT,
        "portfolio_drawdown_pct",
        CAP_KIND_MONEY,
        positive=True,
    ),
    CapSpec(ENV_BOT_MAX_ORDER_USD, "bot_max_order_usd", CAP_KIND_MONEY),
    CapSpec(ENV_MAX_BOT_CAPITAL_USD, "max_bot_capital_usd", CAP_KIND_MONEY),
    CapSpec(ENV_AI_MAX_ORDER_USD, "ai_max_order_usd", CAP_KIND_MONEY),
    CapSpec(ENV_AI_DAILY_NOTIONAL_USD, "ai_daily_notional_usd", CAP_KIND_MONEY),
    CapSpec(ENV_AI_ORDERS_PER_HOUR, "ai_orders_per_hour", CAP_KIND_COUNT),
    CapSpec(ENV_AI_CAPITAL_USD, "ai_capital_usd", CAP_KIND_MONEY),
)

_CAP_BY_ENV = {spec.env: spec for spec in CAP_SPECS}
_CAP_BY_FIELD = {spec.field: spec for spec in CAP_SPECS}

# The one kv key the caps in force live under: a JSON object of variable ->
# value-as-text, so every cap survives a restart in the shape it was set in.
RUNTIME_CAPS_KEY = "runtime_caps"

# The two codes a refused cap answers with: the value cannot be used at all, or
# it is above the ceiling this process was started with.
CAP_INVALID = "INVALID"
CAP_ABOVE_CEILING = "ABOVE_CEILING"


def cap_value(spec: CapSpec, raw: Any) -> Optional[Any]:
    """One cap's value from *raw*, or None when raw cannot be used as one.

    A boolean is refused rather than read as 1/0, an amount that is not a finite
    number is refused (every comparison against `NaN` answers false, so it would
    slip past every cap), a negative one is refused, and a count has to be whole.
    A cap whose `positive` is set refuses zero as well: it is a threshold at which
    something other than nothing happens, so a zero would be a value nobody meant
    to set.  Money and percentages come back `Decimal` and counts `int`.
    """
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        value = D(str(raw))
    except (ArithmeticError, ValueError, TypeError):
        return None
    if not value.is_finite() or value < ZERO:
        return None
    if spec.positive and value == ZERO:
        return None
    if spec.kind == CAP_KIND_COUNT:
        if value != value.to_integral_value():
            return None
        return int(value)
    return value


class CapRefused(Exception):
    """A cap this engine will not store: its code, and a plain reason for it.

    `message` names the cap's own variable and nothing else — never a value of
    the request's, and never another field's — so a caller can report it as it
    is.  The exception's own text starts with the code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class RuntimeLimits:
    """The ceiling `Limits`, and the caps as they stand right now.

    Built over the parsed `Limits` (the ceilings) and the `Store` the engine
    runs on.  The nine caps live in one kv key and are read on every access, so
    a value set through `set_caps` is the value the next order check reads: none
    of them is cached and the engine is never rebuilt to take a new one.

    Every value that is not a cap — the poll interval, the products, the maker
    fee, the watchdog policy, the equity settings, `is_equity`, `tradable` — is
    answered by the ceiling object, so this can be passed anywhere a `Limits` is
    read.

    A missing, unreadable or unusable stored value is the ceiling, and a stored
    value above its ceiling is clamped down to it: a ceiling lowered between two
    runs always wins, and one raised again never raises a cap that was set below
    it.  So the first start sets every cap to its ceiling, and the object that
    results is written back as one value.
    """

    def __init__(self, ceilings: Limits, store: Store) -> None:
        self._ceilings = ceilings
        self._store = store
        self._heal()

    # ------------------------------------------------ the ceilings
    @property
    def ceilings(self) -> Limits:
        """The configuration parsed from the environment: the most a cap may be."""
        return self._ceilings

    def ceiling_values(self) -> dict[str, Any]:
        """Every cap's ceiling, by the variable it is set with."""
        return {spec.env: getattr(self._ceilings, spec.field) for spec in CAP_SPECS}

    # ------------------------------------------------ the caps in force
    def caps(self) -> dict[str, Any]:
        """Every cap as it stands now, by the variable it is set with."""
        return {spec.env: self._value(spec) for spec in CAP_SPECS}

    def set_caps(self, updates: Mapping[str, Any]) -> dict[str, Any]:
        """Store these caps, or refuse them all and write nothing at all.

        Every entry is checked before anything is written: a variable this engine
        holds no cap for, a value that cannot be used, and a value above its
        ceiling each refuse the whole body with `CapRefused`, so a body carrying
        one good cap beside a refused one changes nothing.  Zero and the ceiling
        are both values a cap may hold — except for a cap whose `positive` is set
        (the portfolio drawdown percentage), where zero is refused as a value
        this engine will not store.
        """
        if not isinstance(updates, Mapping):
            raise CapRefused(
                CAP_INVALID, f"{RUNTIME_CAPS_KEY} must name caps and their values"
            )
        wanted: dict[str, Any] = {}
        for env, raw in updates.items():
            spec = _CAP_BY_ENV.get(env)
            if spec is None:
                raise CapRefused(CAP_INVALID, f"{env} is not a cap of this engine")
            value = cap_value(spec, raw)
            if value is None:
                if spec.positive:
                    wanted_kind = "a number greater than 0"
                elif spec.kind == CAP_KIND_COUNT:
                    wanted_kind = "a non-negative whole number"
                else:
                    wanted_kind = "a non-negative number"
                raise CapRefused(CAP_INVALID, f"{env} must be {wanted_kind}")
            ceiling = getattr(self._ceilings, spec.field)
            if value > ceiling:
                raise CapRefused(
                    CAP_ABOVE_CEILING, f"{env} is above its ceiling"
                )
            wanted[env] = value
        current = self.caps()
        current.update(wanted)
        self._write(current)
        return current

    # ------------------------------------------------ reading one cap
    def __getattr__(self, name: str) -> Any:
        """The cap named, read from the store now, or the ceiling's own answer.

        Nothing is cached: every access to one of the nine cap fields is a read
        of the kv object, so a value written by another request (or by a person
        editing the file) is what the next check sees.  A stored value that
        cannot be used, and one above the ceiling, answer the ceiling.

        A name starting with an underscore is this object's own business and is
        never delegated: the ceiling holds no such value, and asking it would
        turn a missing attribute into a second lookup.
        """
        if name.startswith("_"):
            raise AttributeError(name)
        spec = _CAP_BY_FIELD.get(name)
        if spec is not None:
            return self._value(spec)
        return getattr(self.ceilings, name)

    def _value(self, spec: CapSpec) -> Any:
        """One cap as it stands: what is stored, and never more than its ceiling."""
        ceiling = getattr(self._ceilings, spec.field)
        value = cap_value(spec, self._stored().get(spec.env))
        if value is None or value > ceiling:
            return ceiling
        return value

    def _stored(self) -> dict:
        """The stored caps object as a mapping, or an empty one when unreadable.

        A key that was never written, a value that is not a JSON object, and a
        file whose value cannot be parsed at all are all "no caps stored": the
        ceilings then stand, which is the only answer that cannot raise the caps
        above what the process was started with.
        """
        try:
            stored = self._store.get(RUNTIME_CAPS_KEY)
        except Exception:  # noqa: BLE001 - an unreadable kv is "no caps stored"
            log.warning("runtime caps unreadable; the ceilings stand")
            return {}
        return stored if isinstance(stored, dict) else {}

    def _write(self, values: Mapping[str, Any]) -> None:
        """Store every cap as its text, in the one object, in one write."""
        self._store.put(
            RUNTIME_CAPS_KEY,
            {env: str(value) for env, value in values.items()},
        )

    def _heal(self) -> None:
        """Bring the stored caps in line with the ceilings, and write the result.

        A cap with nothing usable stored becomes its ceiling, one stored above a
        (possibly lowered) ceiling is clamped down to it, and one stored below it
        is kept exactly as it is.  A stored value the cap cannot hold — a 0 for a
        cap whose `positive` is set, a count that is not whole, an amount that is
        not a number — is nothing usable stored, so it heals to the ceiling.  The
        result is one value under one key, and it is only written when it differs
        from what is there.

        Healing a cap that WAS stored is something the owner has to hear about,
        because what they set is not what the engine will trade on: those caps are
        reported once, as one warning naming every variable that was moved and no
        amount of any of them.  A first start has nothing stored to repair, an
        entry missing from an otherwise stored object is simply a cap nobody has
        set, and a clean restart repairs nothing — none of those writes an event.
        """
        stored = self._stored()
        healed: dict[str, Any] = {}
        repaired: list[str] = []
        for spec in CAP_SPECS:
            ceiling = getattr(self._ceilings, spec.field)
            value = cap_value(spec, stored.get(spec.env))
            if value is None or value > ceiling:
                if spec.env in stored:
                    repaired.append(spec.env)
                value = ceiling
            healed[spec.env] = value
        texts = {env: str(value) for env, value in healed.items()}
        if texts != stored:
            self._store.put(RUNTIME_CAPS_KEY, texts)
        if repaired:
            self._store.event(
                "warn",
                "Saved trading limits were out of range and were reset: "
                + ", ".join(repaired),
                kind="caps",
            )


# ---------------------------------------------------------------- cap windows
HOUR_SECONDS = 3600.0

# An order the exchange refused, or one that never reached it, spent nothing.
EXCLUDED_STATUSES = (REJECTED, FAILED)


class CapWindow:
    """The two order caps, read from the `orders` table on every call.

    It holds no counters: the rows are the state, so a restart (or a second
    process) sees exactly the same budget.  `now` is injected so a caller can
    move the clock.

    What a row spends: a CANCELLED order counts.  It was accepted and rested on
    the book, and counting it blocks cap-gaming by placing then cancelling.  An
    order that partially filled and was then cancelled counts its FULL submitted
    size (`price * size`), not just the filled part.  Only REJECTED (a post-only
    refusal) and FAILED (never reached the exchange) are excluded.  A row whose
    status is NULL counts too.
    """

    def __init__(self, store: Store, now: Callable[[], float]):
        self.store = store
        self.now = now

    # ------------------------------------------------ public API
    def daily_notional(
        self,
        source: Optional[str] = None,
        *,
        products: Optional[Iterable[str]] = None,
        exclude_products: Optional[Iterable[str]] = None,
        product_type: Optional[str] = None,
        book: str = "dry",
    ) -> Decimal:
        """Notional placed since this UTC day's midnight, on one book.

        Only the lower bound is applied, so a row dated after the clock counts
        too: a future-dated row can never buy budget (fail closed).  `price` and
        `size` are TEXT, so the sum is taken in Decimal, never in float.  A
        source of None counts every row, and only rows of *book* are counted at
        all: the dry and the live book each have their own day.

        `products` keeps only those rows and `exclude_products` drops them; both
        are filters, so an empty collection given for `products` matches nothing
        (an empty `exclude_products` excludes nothing).  That is how an equity
        budget is read apart from the crypto one: the caps are separate pools.

        `product_type` is that same separation by kind, exactly `SPOT` or
        `EQUITY`, and it binds as one parameter beside the product filters: the
        crypto budget reads SPOT rows and the equity budget EQUITY ones.  Any
        other value is refused with `ValueError` rather than matching nothing,
        so a misspelt kind can never quietly read an empty budget.
        """
        if product_type is not None and product_type not in PRODUCT_TYPES:
            raise ValueError(
                f"unknown product type: {product_type!r}; a budget is read as "
                f"one of {', '.join(PRODUCT_TYPES)}"
            )
        start = self._utc_day_start()
        rows = self._fetch(
            "price, size",
            "created_at >= ?",
            (start,),
            source,
            products=products,
            exclude_products=exclude_products,
            product_type=product_type,
            book=book,
        )
        priced = (D(row["price"] or "0") * D(row["size"] or "0") for row in rows)
        return sum(priced, D(0))

    def orders_last_hour(
        self, source: Optional[str] = None, *, book: str = "dry"
    ) -> int:
        """How many orders of one book were placed in the rolling hour before `now()`.

        The window is relative to the clock, not to the clock hour: anything
        strictly newer than `now() - 3600` counts, and only rows of *book* count.
        """
        cutoff = self.now() - HOUR_SECONDS
        rows = self._fetch(
            "COUNT(*) AS placed",
            "created_at > ?",
            (cutoff,),
            source,
            book=book,
        )
        row = rows.fetchone()
        return int(row["placed"]) if row is not None else 0

    # ------------------------------------------------ internals
    def _utc_day_start(self) -> float:
        """The epoch seconds of this UTC day's midnight, and nothing beyond it."""
        day = datetime.fromtimestamp(self.now(), timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        return day.timestamp()

    def _fetch(
        self,
        columns: str,
        where: str,
        args: tuple,
        source: Optional[str],
        *,
        products: Optional[Iterable[str]] = None,
        exclude_products: Optional[Iterable[str]] = None,
        product_type: Optional[str] = None,
        book: str = "dry",
    ) -> sqlite3.Cursor:
        """Run one read over the counted rows; every value is a bound parameter.

        `COALESCE(status, '')` makes a row with a NULL status count: an unknown
        status must never look like an excluded one (fail closed).  The book is a
        bound parameter too, so a read counts one book's rows and never both.

        The product filters bind one parameter per product name; the only SQL
        text that varies is the number of placeholders, never a value.  An empty
        `products` collection adds `AND 1 = 0`, because a filter given nothing to
        match must match nothing rather than turn itself off.

        A `product_type` adds `AND product_type = ?` with the kind bound as one
        parameter, so a crypto budget and an equity budget are read apart from
        the one table.
        """
        marks = ",".join("?" * len(EXCLUDED_STATUSES))
        sql = (
            f"SELECT {columns} FROM orders "
            f"WHERE {where} AND COALESCE(status, '') NOT IN ({marks}) "
            f"AND book = ?"
        )
        params: list[Any] = list(args) + list(EXCLUDED_STATUSES) + [book]
        if source is not None:
            sql += " AND source = ?"
            params.append(source)
        if products is not None:
            wanted = list(products)
            if wanted:
                sql += f" AND product IN ({','.join('?' * len(wanted))})"
                params.extend(wanted)
            else:
                sql += " AND 1 = 0"
        if exclude_products is not None:
            unwanted = list(exclude_products)
            if unwanted:
                sql += f" AND product NOT IN ({','.join('?' * len(unwanted))})"
                params.extend(unwanted)
        if product_type is not None:
            sql += " AND product_type = ?"
            params.append(product_type)
        return self.store.conn().execute(sql, params)