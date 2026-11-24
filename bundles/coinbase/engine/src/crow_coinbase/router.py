"""One exchange surface over a crypto adapter and an equity adapter.

Every product the engine touches belongs to exactly one adapter.  A NEW order is
decided by the configured lists alone: `is_equity(product)` names the configured
equity products, `is_crypto(product)` the crypto ones, and every other product is
the crypto adapter's.  A read or a cancel is decided by `owns_equity(product)`
instead, which follows the store's own EQUITY order rows (`equity_rows`) as well
as the configured list, so a symbol taken off the equity list still reaches the
account that holds its orders.  The crypto list always wins over those rows: a
product `is_crypto` names is never an equity, whatever EQUITY rows the store
carries for it, so a stray row cannot move a coin to the equity account.  The
router never asks an adapter whether it happens to know a product, and it never
tries one and falls back to the other.  A fallback would turn one account's
refusal — a closed market, a rejected order, a key that cannot trade — into an
order somewhere else, on a different account, at whatever size or price that
account would take; it would also hide the refusal the caller needs to see, and
it would make the account an order lands on depend on which request happened to
fail first.  So the wrong path is refused instead of retried: a product
`owns_equity` names offered to `place_limit` answers `EQUITY_USE_EQUITY_PATH` (a
crypto-listed product is never refused), whether or not an equity adapter is
configured, and a product off the equity list offered to `place_equity_limit`
answers `NOT_EQUITY_PRODUCT`, in both cases without reaching either adapter.  An
equity product offered to `place_equity_limit` when there is no equity account
answers `NO_EQUITY_ACCOUNT` rather than being passed to the crypto adapter's own
equity method.  The configured lists, and only they, decide what a new order is:
the store's rows steer reads and cancels, never a new order.

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
read as an empty book.  Each snapshot of that merged answer is a COPY carrying
`"account": "crypto"` or `"account": "equity"`, so a caller reading the whole
book can tell which account listed it; the adapter's own record is never
mutated.  A one-key router is a pure pass-through and tags nothing.

One adapter on both sides is ONE account and so one book: there is nothing to
merge, so it is listed exactly once and each snapshot is tagged by what
`owns_equity` says about its own product — `"equity"` when the product's orders
live on the equity side, `"crypto"` otherwise.  That keeps an order from being
listed twice, once under each account, when the two accounts are the same one.
An adapter that answers `product_type(product)` itself — a live one, which reads
the kind off the product's own spec — is asked instead, because it knows a kind
the router's hooks cannot: `is_crypto` still wins, then a kind of `EQUITY`
(case-insensitively) is the equity account and any other kind the crypto one, and
a lookup that raises or answers an empty kind is the equity account as well: a
product the crypto list does not name and whose kind nothing could read is never
adopted as a coin, because the wrong account means the wrong fee, the wrong pool
and the wrong mark.  A router with no routing hook at all (`is_equity`,
`is_crypto` and `equity_rows` all unset) has nothing to tag by, so its one list
is returned untagged exactly as the adapter answered it — unless that adapter
reports kinds, in which case those are what the tag comes from.
`totals` and `balances` are one view over both accounts, merged by
`exchange.merge_totals` (see it for how the shared and the
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

A product that was taken off the equity list but still has EQUITY order rows in
the store is routed to the equity account: the caller injects `equity_rows`, a
predicate over the store's own rows, and `owns_equity` asks it beside
`is_equity` — minus every product `is_crypto` names.  That way cancel, get_order,
fills, list_open_orders, the kill path's sweep and reconcile still reach the one
account that holds the order — the crypto account would refuse it, or worse,
look like the order was never there.  Those rows are history, not a decision
about what to trade: they never make a new order an equity (`place_equity_limit`
follows the configured list) and never move a crypto-listed product to the equity
account.  The router itself never reads a store: the predicate is the caller's.
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


def _tagged(snapshots, account: str) -> list:
    """Copies of *snapshots*, each saying which *account* listed it.

    A snapshot is a mapping, so the tag is written onto a copy: the adapter's own
    object is left exactly as the exchange answered it.  Anything handed back that
    is not a mapping is passed on untouched rather than refused here, because
    this is a reporting tag, not a validation of the adapter's answer.
    """
    tagged = []
    for snap in snapshots or ():
        copied = dict(snap) if isinstance(snap, dict) else snap
        if isinstance(copied, dict):
            copied["account"] = account
        tagged.append(copied)
    return tagged


def _tagged_by_product(snapshots, owns_equity: Callable[[str], bool]) -> list:
    """Copies of *snapshots*, each saying which account owns its own product.

    One adapter on both sides reports one book, so there is no second list to
    merge and no account to read off the call: a snapshot's account is what
    `owns_equity` says about the product it names, which is the same answer the
    routed reads use.  A snapshot that names no product is tagged `"crypto"`:
    nothing names it an equity.  As in `_tagged`, the tag is written onto a copy
    and a snapshot that is not a mapping is passed on untouched.
    """
    tagged = []
    for snap in snapshots or ():
        copied = dict(snap) if isinstance(snap, dict) else snap
        if isinstance(copied, dict):
            product = copied.get("product")
            owned = product is not None and owns_equity(product)
            copied["account"] = "equity" if owned else "crypto"
        tagged.append(copied)
    return tagged


def _account_of_product(
    product,
    is_crypto: Callable[[str], bool],
    product_type: Callable[[str], object],
) -> str:
    """Which account an adapter's own product kind says *product* belongs to.

    The crypto list is asked first and wins: a coin is the crypto account's
    whatever the adapter's spec says about it.  Otherwise the adapter's own kind
    is the answer — `EQUITY`, case-insensitively and unpadded, is the equity
    account and any other non-empty kind the crypto one — because a kind read off
    the product's spec is a fact about the instrument that neither the configured
    lists nor the store's rows can supply.  A lookup that raises, and an empty
    kind, are the equity account too: a product the crypto list does not name and
    whose kind nothing can name is never adopted as the crypto account's, because
    adopting what may be a stock as a coin would put it in the wrong fee, the
    wrong pool and the wrong mark.  A snapshot that names no product has no such
    question and is the crypto account's.
    """
    if product is None:
        return "crypto"
    if is_crypto(product):
        return "crypto"
    try:
        kind = product_type(product)
    except Exception:  # noqa: BLE001 - no kind is no evidence of a coin
        kind = ""
    text = str(kind or "").strip().upper()
    if text:
        return "equity" if text == "EQUITY" else "crypto"
    return "equity"


def _tagged_by_kind(
    snapshots,
    is_crypto: Callable[[str], bool],
    product_type: Callable[[str], object],
) -> list:
    """Copies of *snapshots*, each tagged by the adapter's own product kind.

    One adapter on both sides reports one book, and an adapter that reports kinds
    knows what each of its products is: its answer tags the snapshot, with the
    crypto list first and the cautious equity answer for a kind nobody could read
    (see `_account_of_product`).  As in `_tagged`, the tag is written onto a copy
    and a snapshot that is not a mapping is passed on untouched.
    """
    tagged = []
    for snap in snapshots or ():
        copied = dict(snap) if isinstance(snap, dict) else snap
        if isinstance(copied, dict):
            copied["account"] = _account_of_product(
                copied.get("product"), is_crypto, product_type
            )
        tagged.append(copied)
    return tagged


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
    the equity adapter (with none, none do) and `is_crypto` which belong to the
    crypto one (with none, none are crypto-listed); those two lists, and only
    they, decide what a new order is.  `equity_rows` says which products the
    store holds EQUITY order rows for, and `owns_equity` combines it with the two
    lists for the reads and cancels: a symbol taken off the equity list keeps its
    resting orders on the equity account, while a crypto-listed product is never
    moved there.  `product_of` answers an order id's product where only the id is
    known; with none, an id is never resolvable.
    `usd_one_pool` and `equity_bases` are the two facts `merge_totals` needs: one
    shared USD pool or two separate ones, and which currency names are equity
    shares rather than crypto holdings.

    `usd_one_pool` is a required keyword: whether the two keys see one pool or
    two is a fact about the accounts, so a router built without it would be
    guessing about the money.  One adapter on both sides is one account, so its
    USD cannot be two pools — that pairing raises `ValueError` unless
    `usd_one_pool` is True, and stores True — and it is also one book, so its
    orders are listed once and tagged by the adapter's own product kind where it
    reports one, and by `owns_equity` of their own product otherwise.  A crypto and
    an equity adapter that disagree about `dry_run` never become a
    router either: its `dry_run` answer would be a lie about one of them.
    """

    def __init__(
        self,
        crypto,
        equity=None,
        *,
        is_equity: Optional[Callable[[str], bool]] = None,
        is_crypto: Optional[Callable[[str], bool]] = None,
        product_of: Optional[Callable[[str], Optional[str]]] = None,
        usd_one_pool: bool,
        equity_bases=(),
        equity_rows: Optional[Callable[[str], bool]] = None,
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
        # Whether the caller gave the router anything to tell the two accounts'
        # products apart by: with no hook at all a shared adapter's one book is
        # listed untagged rather than tagged with a guess.
        self.routes_by_hook = (
            is_equity is not None
            or is_crypto is not None
            or equity_rows is not None
        )
        self.is_equity = is_equity or (lambda product: False)
        self.is_crypto = is_crypto or (lambda product: False)
        self.equity_rows = equity_rows or (lambda product: False)
        self.product_of = product_of or (lambda order_id: None)
        self.usd_one_pool = True if equity is crypto else bool(usd_one_pool)
        self.equity_bases = tuple(equity_bases or ())

    # -- routing
    def owns_equity(self, product: Optional[str]) -> bool:
        """True when *product*'s ORDERS live on the equity account.

        Either the configured list names it an equity, or the caller's
        `equity_rows` says the store holds EQUITY order rows for it: a symbol
        taken off the equity list still has its resting orders, its fills and its
        adoption records on the equity account, and every routed read or cancel
        about it has to reach that account.

        A crypto-listed product is never one, whatever rows the store holds for
        it: a stray EQUITY row on a coin is history, not a place its orders live,
        and acting on it would send a crypto cancel to the wrong account.  This
        answers reads and cancels only; a new order follows the configured lists.
        """
        if self.is_equity(product):
            return True
        return bool(self.equity_rows(product)) and not self.is_crypto(product)

    def _adapter(self, product: Optional[str]):
        """The adapter that owns *product*; without an equity one, the crypto side."""
        if (
            self.equity is not None
            and product is not None
            and self.owns_equity(product)
        ):
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
        equity adapter happens to be configured: an equity order — one on the
        equity list, or a delisted one the store still holds as an EQUITY row —
        has to take the equity path, or not go out at all.  A product the crypto
        list names is never refused here, even when the store carries a stray
        EQUITY row for it: the coin is the crypto account's, and a new order on it
        is a crypto order.
        """
        if not self.is_crypto(product) and self.owns_equity(product):
            return _refused(EQUITY_USE_EQUITY_PATH)
        return self.crypto.place_limit(cid, product, side, size, price)

    def place_equity_limit(self, cid, product, side, size, price):
        """An equity limit order; a product off the equity list is refused.

        A product off the equity list is refused first, equity account or not,
        and an equity product with no equity account is refused
        `NO_EQUITY_ACCOUNT` rather than handed to the crypto adapter.  Only a real
        equity account is ever asked to place one.

        A NEW order follows the CONFIGURED list and nothing else: the store's
        EQUITY rows are history, so a symbol taken off the list takes neither
        path — the crypto one would be a different instrument and the equity one
        is no longer what the owner asked for.
        """
        if not self.is_equity(product):
            return _refused(NOT_EQUITY_PRODUCT)
        if self.equity is None:
            return _refused(NO_EQUITY_ACCOUNT)
        return self.equity.place_equity_limit(cid, product, side, size, price)

    def cancel(self, order_ids):
        """Cancel each id on the account that owns it; an unknown id goes to both.

        The account is decided the same way every routed call decides it
        (`owns_equity`), so an order on a symbol that has since left the equity
        list is still cancelled on the equity account that holds it, while a
        crypto-listed product's order is cancelled on the crypto account.
        """
        if self.equity is None:
            return self.crypto.cancel(order_ids)
        crypto_ids: list[str] = []
        equity_ids: list[str] = []
        for order_id in order_ids:
            product = self.product_of(order_id)
            if product is None:
                crypto_ids.append(order_id)
                equity_ids.append(order_id)
            elif self.owns_equity(product):
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
        """One product's book, or both books with no product named.

        With an equity adapter, the merged book is copies of both adapters'
        snapshots — crypto first — each tagged with the `"account"` it came from,
        so a caller reading the whole book can tell which one listed it without
        asking about the product again.  The tag goes on a copy, so an adapter's
        own record still reads exactly what the account said.  A one-key router is
        a pure pass-through: the crypto adapter's own answer, arguments unchanged
        and untagged, and the same for a single product asked of either account.

        One adapter on both sides is one account and one book, so it is listed
        ONCE rather than asked twice for the same orders: each snapshot is then
        tagged by the adapter's own `product_type` when it answers one — a kind
        nobody could read is the equity account, never a coin (see
        `_account_of_product`) — and by `owns_equity` otherwise, `"equity"` when
        that product's orders live on the equity side and `"crypto"` when they do
        not, which is the same answer a routed read uses.
        A router given no routing hook at all has nothing to tag by, so its single
        list comes back untagged — unless the adapter reports product kinds, in
        which case those are what the tag comes from.
        """
        if self.equity is None:
            return self.crypto.list_open_orders(product)
        if product is None:
            if self.equity is self.crypto:
                listed = self.crypto.list_open_orders(None)
                product_type = getattr(self.crypto, "product_type", None)
                if callable(product_type):
                    return _tagged_by_kind(listed, self.is_crypto, product_type)
                if not self.routes_by_hook:
                    return listed
                return _tagged_by_product(listed, self.owns_equity)
            orders = _tagged(self.crypto.list_open_orders(None), "crypto")
            orders.extend(_tagged(self.equity.list_open_orders(None), "equity"))
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