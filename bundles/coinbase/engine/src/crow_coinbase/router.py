"""One exchange surface over a crypto adapter and an equity adapter.

Every product the engine touches belongs to exactly one adapter, and the product
alone decides which: `is_equity(product)` names the equity products, and every
other product is the crypto adapter's.  The router never asks an adapter whether
it happens to know a product, and it never tries one and falls back to the
other.  A fallback would turn one account's refusal — a closed market, a rejected
order, a key that cannot trade — into an order somewhere else, on a different
account, at whatever size or price that account would take; it would also hide
the refusal the caller needs to see, and it would make the account an order lands
on depend on which request happened to fail first.  So the wrong path is refused
instead of retried: an equity product offered to `place_limit` answers
`EQUITY_USE_EQUITY_PATH`, whether or not an equity adapter is configured, and a
crypto product offered to `place_equity_limit` answers `NOT_EQUITY_PRODUCT`, in
both cases without reaching either adapter.  An equity product offered to
`place_equity_limit` when there is no equity account answers `NO_EQUITY_ACCOUNT`
rather than being passed to the crypto adapter's own equity method.

Reads that name an order but not its product are routed through
`product_of(order_id)`.  When that answers nothing and an equity adapter is
present, the router cannot tell which account holds the order, and it raises
`ValueError` rather than asking both: an order id is not a product, and a guess
would report one account's state as another order's.  A cancel is the one place
both adapters are asked about the same id, and only because cancelling is safe to
do twice: an unknown id goes to both, and the answers are ORed, so a cancel is
reported as done when either account says so.

With no equity adapter the router is a pass-through: every call is the crypto
adapter's own, arguments unchanged, so a crypto-only install keeps the surface it
had.  The same holds for the calls only one account can answer — `deposit`, the
maker fee, the server clock and `dry_run` are the crypto adapter's, because the
equity side has nothing of its own to offer for them.  `key_permissions` is the
exception: with an equity adapter it answers both keys (`{"crypto": ...,
"equity": ...}`), because the startup checks have to be able to tell the two keys
apart, while a one-key install keeps the crypto key's own answer unchanged.

`list_open_orders(None)` is both books: the crypto orders first, then the equity
ones, and a failing list call from either adapter propagates rather than being
read as an empty book.  `totals` and `balances` are one view over both accounts,
merged by `exchange.merge_totals` (see it for how the shared and the
equity-owned currencies are treated).  That merged view is for reporting only:
the two funding checks that must see one account each never read it.  A crypto
portfolio drawdown stop reads `crypto_totals()`, the crypto adapter's own totals,
and an equity BUY's funding check reads `equity_usd()`, the equity adapter's own
USD — never `totals()`, which would let one account's cash fund the other's
orders.  `advance` steps the crypto simulator and then the equity one, once each,
even when the two names are the same object.

`usd_one_pool` is a fact the caller states, never one this module guesses: two
keys on two portfolios see two separate USD pools, and summing a shared pool
would count the same cash twice.  So it is a required keyword; a router that
dropped it would silently assume one.  `usd_one_pool_from_keys` derives it from
the two keys' own `portfolio_uuid` answers, and refuses an unknown relationship
rather than defaulting.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Callable, Optional

from .exchange import merge_totals

D = Decimal

EQUITY_USE_EQUITY_PATH = "EQUITY_USE_EQUITY_PATH"
NOT_EQUITY_PRODUCT = "NOT_EQUITY_PRODUCT"
NO_EQUITY_ACCOUNT = "NO_EQUITY_ACCOUNT"


def _refused(reason: str) -> dict:
    """A placement the router refused before reaching an adapter."""
    return {"ok": False, "order_id": None, "reason": reason}


def _portfolio_uuid(perms) -> Optional[str]:
    """The portfolio a key's permissions name, or None when it names none.

    Only a non-blank string is a portfolio: an absent key, a null and a blank one
    all mean the answer does not say, which is a different thing from "the same
    portfolio".
    """
    if not isinstance(perms, dict):
        return None
    value = perms.get("portfolio_uuid")
    if not isinstance(value, str):
        return None
    return value.strip() or None


def usd_one_pool_from_keys(crypto_perms: dict, equity_perms: dict) -> bool:
    """Whether two keys' portfolios make one USD pool or two.

    True when both keys name the same portfolio (the one pool seen twice), False
    when they name different ones (two pools that sum).  An unknown relationship
    raises `ValueError`: with either key unscoped — absent, null or blank — the
    engine cannot say whether USD would be counted once or twice, and equities
    are not enabled on a relationship nobody knows.
    """
    crypto_portfolio = _portfolio_uuid(crypto_perms)
    equity_portfolio = _portfolio_uuid(equity_perms)
    if crypto_portfolio is None or equity_portfolio is None:
        raise ValueError(
            "the two API keys do not both name a portfolio, so whether their "
            "USD is one pool or two is unknown; equities are not enabled on an "
            "unknown portfolio relationship"
        )
    return crypto_portfolio == equity_portfolio


class ExchangeRouter:
    """Route each call to the adapter that owns the product, or refuse it.

    `equity` is optional: with none, every call is the crypto adapter's and the
    crypto-only install is unchanged.  `is_equity` says which products belong to
    the equity adapter (with none, none do).  `product_of` answers an order id's
    product where only the id is known; with none, an id is never resolvable.
    `usd_one_pool` and `equity_bases` are the two facts `merge_totals` needs: one
    shared USD pool or two separate ones, and which currency names are equity
    shares rather than crypto holdings.

    `usd_one_pool` is a required keyword: whether the two keys see one pool or
    two is a fact about the accounts, so a router built without it would be
    guessing about the money.  One adapter on both sides is one account, so its
    USD cannot be two pools — that pairing raises `ValueError` unless
    `usd_one_pool` is True, and stores True.  A crypto and an equity adapter that
    disagree about `dry_run` never become a router either: its `dry_run` answer
    would be a lie about one of them.
    """

    def __init__(
        self,
        crypto,
        equity=None,
        *,
        is_equity: Optional[Callable[[str], bool]] = None,
        product_of: Optional[Callable[[str], Optional[str]]] = None,
        usd_one_pool: bool,
        equity_bases=(),
    ):
        if equity is not None and crypto.dry_run != equity.dry_run:
            raise ValueError(
                "the crypto and equity adapters disagree about dry_run "
                f"({crypto.dry_run!r} vs {equity.dry_run!r}); one router cannot "
                "simulate one account and place on the other"
            )
        if equity is not None and equity is crypto and not usd_one_pool:
            raise ValueError(
                "one adapter on both sides is one account: its USD is one pool, "
                "and counting it as two would sum the same cash twice"
            )
        self.crypto = crypto
        self.equity = equity
        self.is_equity = is_equity or (lambda product: False)
        self.product_of = product_of or (lambda order_id: None)
        self.usd_one_pool = True if equity is crypto else bool(usd_one_pool)
        self.equity_bases = tuple(equity_bases or ())

    # -- routing
    def _adapter(self, product: Optional[str]):
        """The adapter that owns *product*; without an equity one, the crypto side."""
        if self.equity is not None and product is not None and self.is_equity(product):
            return self.equity
        return self.crypto

    def _resolve(self, order_id: str, product: Optional[str]) -> Optional[str]:
        """The product an id-only read routes by; `ValueError` when it is unknown."""
        if product is not None:
            return product
        found = self.product_of(order_id)
        if found is None and self.equity is not None:
            raise ValueError(
                f"order {order_id} has no known product, so this read cannot be "
                "routed between the crypto and the equity account"
            )
        return found

    # -- writes
    def place_limit(self, cid, product, side, size, price):
        """A crypto limit order; an equity product is refused, never re-routed.

        The product is refused because of what it is, not because of whether an
        equity adapter happens to be configured: an equity order has to take the
        equity path, or not go out at all.
        """
        if self.is_equity(product):
            return _refused(EQUITY_USE_EQUITY_PATH)
        return self.crypto.place_limit(cid, product, side, size, price)

    def place_equity_limit(self, cid, product, side, size, price):
        """An equity limit order; a crypto product is refused, never re-routed.

        A crypto product is refused first, equity account or not, and an equity
        product with no equity account is refused `NO_EQUITY_ACCOUNT` rather than
        handed to the crypto adapter.  Only a real equity account is ever asked
        to place one.
        """
        if not self.is_equity(product):
            return _refused(NOT_EQUITY_PRODUCT)
        if self.equity is None:
            return _refused(NO_EQUITY_ACCOUNT)
        return self.equity.place_equity_limit(cid, product, side, size, price)

    def cancel(self, order_ids):
        """Cancel each id on the account that owns it; an unknown id goes to both."""
        if self.equity is None:
            return self.crypto.cancel(order_ids)
        crypto_ids: list[str] = []
        equity_ids: list[str] = []
        for order_id in order_ids:
            product = self.product_of(order_id)
            if product is None:
                crypto_ids.append(order_id)
                equity_ids.append(order_id)
            elif self.is_equity(product):
                equity_ids.append(order_id)
            else:
                crypto_ids.append(order_id)
        out: dict[str, bool] = {}
        if crypto_ids:
            for order_id, ok in (self.crypto.cancel(crypto_ids) or {}).items():
                out[order_id] = bool(ok)
        if equity_ids:
            for order_id, ok in (self.equity.cancel(equity_ids) or {}).items():
                out[order_id] = out.get(order_id, False) or bool(ok)
        return out

    def deposit(self, currency, amount, note):
        return self.crypto.deposit(currency, amount, note)

    # -- reads
    def find_by_client_id(self, cid, since, product=None):
        """Find an order by client id; with an equity adapter the product is required."""
        if self.equity is not None and product is None:
            raise ValueError(
                f"client order id {cid} cannot be routed without its product"
            )
        return self._adapter(product).find_by_client_id(cid, since, product)

    def get_order(self, order_id, product=None):
        resolved = self._resolve(order_id, product)
        return self._adapter(resolved).get_order(order_id, resolved)

    def fills(self, order_id, product=None):
        resolved = self._resolve(order_id, product)
        return self._adapter(resolved).fills(order_id, resolved)

    def list_open_orders(self, product=None):
        """One product's book, or both books with no product named."""
        if self.equity is None:
            return self.crypto.list_open_orders(product)
        if product is None:
            orders = list(self.crypto.list_open_orders(None))
            orders.extend(self.equity.list_open_orders(None))
            return orders
        return self._adapter(product).list_open_orders(product)

    def totals(self):
        """The merged view over both accounts, for reporting and marking."""
        if self.equity is None:
            return self.crypto.totals()
        return merge_totals(
            self.crypto.totals(),
            self.equity.totals(),
            self.equity_bases,
            self.usd_one_pool,
        )

    def balances(self):
        """The merged available-balance view over both accounts."""
        if self.equity is None:
            return self.crypto.balances()
        return merge_totals(
            self.crypto.balances(),
            self.equity.balances(),
            self.equity_bases,
            self.usd_one_pool,
        )

    def crypto_totals(self):
        """The crypto account's OWN totals, never merged with the equity one.

        This is the read the crypto portfolio drawdown stop uses: `totals()`
        merges the two accounts, so a drawdown measured on it would move when the
        equity account did, and with two pools it would sum two separate pools of
        cash.  The equity account is not consulted at all here.
        """
        return self.crypto.totals()

    def equity_usd(self):
        """The equity account's OWN USD, or None when there is no equity account.

        This is the read an equity BUY's funding check uses: the shares and the
        cash that funds them live on the equity account, so its own `balances()`
        USD is what may be spent and `totals()` — which merges the crypto side in
        — may not be read instead.  Nothing from the crypto account is added.  A
        missing USD balance is zero: that account holds no dollars to spend.
        """
        if self.equity is None:
            return None
        usd = self.equity.balances().get("USD", D(0))
        return D(str(usd))

    def key_permissions(self):
        """One key's permissions, or both keys' under their own names.

        With an equity adapter the answer is `{"crypto": ..., "equity": ...}`, so
        a startup check can refuse one key without the other; one adapter on both
        sides is still reported under both names.
        """
        crypto_perms = self.crypto.key_permissions()
        if self.equity is None:
            return crypto_perms
        return {"crypto": crypto_perms, "equity": self.equity.key_permissions()}

    def maker_fee_rate(self):
        return self.crypto.maker_fee_rate()

    def server_time(self):
        return self.crypto.server_time()

    @property
    def dry_run(self) -> bool:
        return self.crypto.dry_run

    # -- simulation step
    def advance(self, now):
        """Step both simulators once; the same object on both sides is stepped once."""
        filled = list(self.crypto.advance(now) or [])
        if self.equity is not None and self.equity is not self.crypto:
            filled.extend(self.equity.advance(now) or [])
        return filled