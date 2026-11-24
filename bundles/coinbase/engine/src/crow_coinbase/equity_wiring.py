"""The equity half of an account, as the pieces that need it see it.

One `EquityWiring` carries the four facts a router needs to tell the two kinds of
product apart, and the two product lists read as they stand right now:

    is_equity      the configured equity products (a NEW order follows this list)
    is_crypto      the configured crypto products (this list always wins)
    equity_rows    whether the store holds an EQUITY order row for a product, so
                   a symbol taken off the equity list still reaches the account
                   that holds its orders
    product_of     an exchange order id's product, for a read routed by id alone

The lists are callables, not tuples, because the limits they come from are read
at run time: an owner who adds an equity does not rebuild the process, and a
router built once sees the new list on its next call.  `enabled` is what every
caller asks before it builds anything equity-shaped — with no equity products
configured there is no equity half at all, and the router stays the plain
crypto-only one it has always been.

`portfolio_id` is the portfolio the equity account is known to trade in
(`CROW_COINBASE_EQUITY_PORTFOLIO_ID`).  It is an id, not a secret, and it is the
only value the equity key's own path reads: no key, secret or token comes from
the environment.  A blank or absent value is `None`, which is what makes the
second key's path refuse rather than judge a key against no portfolio at all.

Nothing here reads a store or a limit of its own: `wiring_from` takes both and
binds the four hooks to them, so this module knows only the router's shape.

`EquityStatus` is the fifth fact the equity half carries: whether the stock
products' KINDS are confirmed.  Coinbase answers a stock on its public product
endpoint with 404, so the only read that says what a stock is happens on an
authenticated one — after a key push.  Until one has answered, stock trading is
off (with a reason a cycle can ring once), and a key whose reads disagree or fail
leaves it off without refusing the key.  The status also holds the specs those
reads gave, so the engine prices a stock from the authenticated listing and never
from a public read it cannot have.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .books import LIVE
from .exchange import (
    EQUITY_PREVIEW_CONFIRMED_KEY,
    ProductSpec,
    check_equity_key,
    equity_preview_refusal,
)
from .gateway import EQUITY_UNAVAILABLE, LIVE_DISABLED
from .limits import validate_product_types
from .router import ExchangeRouter

# The environment variable naming the portfolio the equity account trades in.  It
# carries an id, never a credential.
ENV_EQUITY_PORTFOLIO_ID = "CROW_COINBASE_EQUITY_PORTFOLIO_ID"

# The quote half a crypto product has to carry to be paid for in the same dollars
# an equity account holds.
QUOTE_USD = "USD"

# The fixed refusals `equity_key_refusal` answers with.  Each is plain words and
# none of them is, or carries, a value out of the permissions it judged.
EQUITY_KEY_UNSCOPED = "unscoped"
EQUITY_KEY_TRANSFER = "transfer"
EQUITY_KEY_PERMISSIONS = "permissions"


def _quote_of(product: str) -> str:
    """The quote half of a product id ("USD" for "BTC-USD"), or "" without one."""
    _base, separator, quote = str(product).partition("-")
    return quote if separator else ""


def _base_of(product: str) -> str:
    """The base half of a product id ("NVDA" for "NVDA-USD")."""
    base, _separator, _quote = str(product).partition("-")
    return base


def _portfolio_from_env(env) -> Optional[str]:
    """The configured equity portfolio, stripped, or None when nothing is set."""
    value = env.get(ENV_EQUITY_PORTFOLIO_ID) if env is not None else None
    return str(value or "").strip() or None


@dataclass(frozen=True)
class _Kind:
    """A product's kind alone, for a read that answered no spec.

    `limits.validate_product_types` reads `product_type` off whatever it is
    given, and a crypto product's kind is the only thing `verify` reads about it,
    so that kind is handed over in this shape rather than as a spec nobody read.
    """

    product_type: Any


class EquityStatus:
    """Whether the stock products' kinds are confirmed, and what that allows.

    Coinbase's public product endpoint answers a stock with 404, so the only read
    that says what a stock is happens on an authenticated one, after a key push.
    This object sits between that read and everything else: it keeps the
    authenticated spec of every equity product (`spec_for`, the spec the engine
    prices and checks a stock order with), and it says — in fixed words, never in
    an exchange's own message — why stock trading is off, if it is.

    Three reasons, in the order a start and a key push can earn them:

        EQUITY_KINDS_UNVERIFIED  no key has given specs yet
        EQUITY_KIND_MISMATCH     an authenticated read says a listed product is
                                 the other kind of instrument
        EQUITY_KIND_READ_FAILED  an authenticated read failed

    `verify` takes the two adapters a freshly installed key gives (`crypto` and
    `equity`, the same object on a one-key install) and reads them: every equity
    product's `product_spec` and every crypto product's `product_type`, then the
    engine's own `limits.validate_product_types` over what those reads answered.
    All of it agreeing is what turns stock trading on; a disagreement, or a read
    that could not answer, turns it off and drops the specs, so a stock is never
    priced from a spec a later read contradicted.  It NEVER raises: a key push is
    still the owner's key whatever its reads said, and a read's own text — which
    can carry a URL or a token — is reported nowhere.  `reset` forgets everything
    a verification kept, which is what clearing the key means.

    `trusted=True` is a caller that injected specs of its own (a test, an
    embedding): there is nothing left to confirm, so `reason` is None and both
    `verify` and `reset` change nothing.

    `refusal(book)` is the refusal an order on *book* earns right now:
    `EQUITY_UNAVAILABLE` while the kinds are unconfirmed, on either book, because
    a stock whose kind nobody confirmed may not be traded on either one, and
    `LIVE_DISABLED` on the live book while `equity_live` is on but no confirmed
    order preview is on record (`live_reason`).  A cancel is never asked: taking
    an order off the book is always allowed.
    """

    REASON_UNVERIFIED = "EQUITY_KINDS_UNVERIFIED"  # no key has given specs yet
    REASON_MISMATCH = "EQUITY_KIND_MISMATCH"  # a listed product is the wrong kind
    REASON_READ_FAILED = "EQUITY_KIND_READ_FAILED"  # an authenticated read failed
    LIVE_UNCONFIRMED = "EQUITY_LIVE_UNCONFIRMED"  # the live switch has no preview

    def __init__(self, store: Any, limits: Any, *, trusted: bool = False) -> None:
        self._store = store
        self._limits = limits
        self._trusted = bool(trusted)
        self._specs: dict[str, ProductSpec] = {}
        self._reason: Optional[str] = self.REASON_UNVERIFIED

    def spec_for(self, product: Any) -> Optional[ProductSpec]:
        """The authenticated spec kept for an equity product, else None.

        Only a successful verification keeps one, and only for a product its own
        equity read answered: a crypto product has no equity spec, and a spec a
        later read contradicted is dropped with the reason it was dropped for.
        """
        return self._specs.get(product)

    def verify(self, crypto: Any, equity: Any) -> None:
        """Read both adapters' product kinds and turn stock trading on or off.

        Every equity product's authenticated spec and every crypto product's
        authenticated kind are read, and the engine's own kind check is asked over
        them, so a list that names the other kind of instrument is caught here
        rather than at the first order.  All of it agreeing verifies the status and
        keeps the specs; a `ValueError` from the check is a mismatch, and any other
        failure is a failed read.  Neither raises, and neither reports the words a
        read failed with: only the fixed reason is kept.
        """
        if self._trusted:
            return
        products = tuple(self._limits.products)
        equity_products = tuple(self._limits.equity_products)
        try:
            specs = {
                product: equity.product_spec(product) for product in equity_products
            }
            kinds = {product: crypto.product_type(product) for product in products}
            validate_product_types(
                products,
                equity_products,
                lambda product: specs.get(product) or _Kind(kinds.get(product)),
            )
        except ValueError:
            self._fail(self.REASON_MISMATCH)
            return
        except Exception:  # noqa: BLE001 - a failed read is no confirmation
            self._fail(self.REASON_READ_FAILED)
            return
        self._specs = specs
        self._reason = None

    def reset(self) -> None:
        """Forget a verification: stock trading is off until a key confirms again."""
        if self._trusted:
            return
        self._fail(self.REASON_UNVERIFIED)

    def reason(self) -> Optional[str]:
        """None when the stock products are confirmed (or the caller's own), else why."""
        return None if self._trusted else self._reason

    def live_reason(self) -> Optional[str]:
        """`EQUITY_LIVE_UNCONFIRMED` while the live switch has no confirmed preview.

        Off is always allowed: the reason is only ever about a live equity route,
        and it is answered from the confirmation on record, so writing one turns
        the live route on without anything being rebuilt.
        """
        if not self._limits.equity_live:
            return None
        confirmation = self._store.get(EQUITY_PREVIEW_CONFIRMED_KEY)
        if equity_preview_refusal(confirmation) is None:
            return None
        return self.LIVE_UNCONFIRMED

    def refusal(self, book: str) -> Optional[str]:
        """The refusal an order on *book* earns now, or None when it may go out."""
        if self.reason() is not None:
            return EQUITY_UNAVAILABLE
        if book == LIVE and self.live_reason() is not None:
            return LIVE_DISABLED
        return None

    def _fail(self, reason: str) -> None:
        """Record why stock trading is off, and drop every spec held for it."""
        self._reason = reason
        self._specs = {}


@dataclass(frozen=True)
class EquityWiring:
    """The equity half of an account: its four product hooks, its two lists, its status.

    `equity_products` and `crypto_products` are asked on every use, so they read
    the limits in force rather than a copy taken when this was built.  The four
    hooks are always handed to a router together (`router`), because a router
    given one of them and not the others would answer half the question.
    `status` is the kind report a key push verifies and the gateway refuses an
    equity order by (see `EquityStatus`); a wiring with none carries no such
    report, which is what a caller that wired nothing has.
    """

    is_equity: Callable[[str], bool]
    is_crypto: Callable[[str], bool]
    equity_rows: Callable[[str], bool]
    product_of: Callable[[str], Optional[str]]
    equity_products: Callable[[], tuple]
    crypto_products: Callable[[], tuple]
    portfolio_id: Optional[str] = None
    status: Optional[EquityStatus] = None

    @property
    def enabled(self) -> bool:
        """Whether any equity product is configured right now."""
        return bool(self.equity_products())

    def equity_bases(self) -> tuple:
        """The base symbols of the configured equities, sorted and unique.

        These are the currency names the equity account's shares are held under
        (`"NVDA"` for `"NVDA-USD"`), which is what merging the two accounts'
        totals needs in order to take the shares from the equity side.
        """
        return tuple(
            sorted({_base_of(product) for product in self.equity_products()})
        )

    def usd_crypto_products(self) -> tuple:
        """The crypto products paid for in USD rather than USDC.

        A USD-quoted crypto product spends the same dollars an equity account
        holds, so two separate USD pools would count one balance twice; a
        USDC-quoted one spends a currency of its own and does not.
        """
        return tuple(
            product
            for product in self.crypto_products()
            if _quote_of(product) == QUOTE_USD
        )

    def router(self, crypto, equity=None, *, usd_one_pool: bool) -> ExchangeRouter:
        """The router over *crypto*, and over *equity* when there is an equity half.

        With no equity products configured the answer is the plain router the
        crypto-only install has always had, whatever *equity* is: equities are not
        enabled, so there is nothing to route to them.  Otherwise *equity* is used
        when one is given and the crypto adapter itself when it is not — one
        adapter on both sides is one account, which is the default one-key
        install — and all four hooks, the equity bases and *usd_one_pool* are
        passed together.
        """
        if not self.enabled:
            return ExchangeRouter(crypto, usd_one_pool=True)
        return ExchangeRouter(
            crypto,
            crypto if equity is None else equity,
            is_equity=self.is_equity,
            is_crypto=self.is_crypto,
            product_of=self.product_of,
            equity_rows=self.equity_rows,
            usd_one_pool=usd_one_pool,
            equity_bases=self.equity_bases(),
        )


def wiring_from(
    limits: Any, store: Any, env, status: Optional[EquityStatus] = None
) -> EquityWiring:
    """The wiring for one engine, over its limits and its store, from *env*.

    The product hooks are the objects themselves — the limits' own `is_equity`,
    a membership test over the limits' crypto list, and the store's own queries —
    and the two lists are read through the limits on every call, so a list changed
    at run time is the list the next order uses.  Only `portfolio_id` is read
    from *env*.

    *status* is the kind report the same engine verifies on a key push and refuses
    an equity order by; with none the wiring carries none, and nothing downstream
    has a report to read.  It is built by the caller and not here, because only
    the caller knows whether the specs it prices from are its own (`trusted`).
    """
    return EquityWiring(
        is_equity=limits.is_equity,
        is_crypto=lambda product: product in limits.products,
        equity_rows=store.has_equity_rows,
        product_of=store.product_of_order,
        equity_products=lambda: tuple(limits.equity_products),
        crypto_products=lambda: tuple(limits.products),
        portfolio_id=_portfolio_from_env(env),
        status=status,
    )


def equity_key_refusal(perms, portfolio_id: Optional[str]) -> Optional[str]:
    """Why a second key may not be the equity account's, or None when it may.

    Three refusals, in this order.  A blank portfolio id is `unscoped`: the equity
    account is traded in one known portfolio, so a key judged against no portfolio
    at all cannot be accepted.  A permissions answer that is not a mapping, or one
    whose `can_transfer` is not literally `False`, is `transfer` — the engine only
    ever places and cancels orders and never moves funds, and an absent permission
    is not a denial.  Everything else the key's own permissions say (trading,
    viewing, the portfolio it is scoped to) is `permissions`, which is
    `exchange.check_equity_key`'s own answer.  The refusals are fixed words, so no
    key name, portfolio id or exchange error can reach a caller through them.
    """
    if not str(portfolio_id or "").strip():
        return EQUITY_KEY_UNSCOPED
    if not isinstance(perms, dict) or perms.get("can_transfer") is not False:
        return EQUITY_KEY_TRANSFER
    if check_equity_key(perms, portfolio_id) is not None:
        return EQUITY_KEY_PERMISSIONS
    return None