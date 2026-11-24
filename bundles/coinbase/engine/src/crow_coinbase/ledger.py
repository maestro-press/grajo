"""One owner's holdings and equity, derived from its capital plus its order rows.

A resting order moves nothing between an owner's *total* holdings: it only holds
funds, so `reserved_*` rises and `available_*` falls.  Totals come from filled
parts alone (proceeds for a sell, cost and fees for a buy).

Every figure is read one book at a time (`books.py`): a book's holdings for an
owner are that book's capital (the bot row's dry or live budget) plus the effect
of that book's order rows, counted only from the moment that book started for the
owner (`store.book_epoch`).  The two books never mix: a dry holding can never
pick up a live row or a live budget, and `unallocated` subtracts one book's
holdings from that book's totals alone.

The `ai` owner has no bot row and no budget of its own in the store: its live
capital is the one the engine hands this ledger as a callable, in USDC
(`AI_CAPITAL_CURRENCY`), and it is read on every call so a cap lowered at run
time is the capital the next check sees.  On the live book the AI's quote side is
ONE pool per quote currency, shared by every product it trades in that currency:
the capital plus the effect of all its live orders there.  Its base side stays
per product.  So a resting AI buy leaves less of the pool for its next order,
whatever product that order is on, and `unallocated` reserves the pool once —
not once per product — against the live book's totals, whether or not the AI's
live switch is on.  A bot switching to the live book therefore cannot spend it.
The dry book is untouched: the AI's live capital is a live figure only, and an
AI dry order moves the dry book exactly as any other owner's does.

The pool can be spent, not merely small: a capital lowered at run time below what
the AI has already spent leaves its order effects alone and bigger than the
capital, so the pool's quote side for the capital-bearing currency is read as
`max(0, capital + effects)` — money that is gone is gone, and it must never be
subtracted as a NEGATIVE holding, which would hand the same amount to every
other owner as free money.  A currency the AI holds with no capital of its own
is not floored that way: an AI that sold into it keeps what it holds there.

Its EQUITIES are one pool of their own, per book: every slot that IS an equity
shares ONE quote pool, `equity_capital` (read through its own callable on every
call) plus the quote effect of all the AI's equity slots on that book, floored at
zero the same way.  So a resting equity buy leaves less of the pool for the next
equity order whatever symbol that is, and `unallocated` reserves that pool ONCE,
under USD, instead of once per product.  An equity buy reserves `size * price`
with no fee, because an equity pays no maker fee (see `money.fee_rate_for_type`).

A slot is an equity because of its own order rows, not because of the configured
list: a row written `product_type` EQUITY keeps its symbol in the pool even after
the engine stops listing it, so its spend still draws on the capital and the
shares it bought are still marked as equities.  The configured rule only adds to
that — a slot whose product the rule calls an equity is one even before it has a
row.  `equity_pool_used` reads the same way, one level up: the slot is decided
first (any EQUITY row of it, or the configured rule), and then EVERY row of an
equity slot counts, whatever kind the row itself was written with — a SPOT row on
a symbol the pool holds is spend from the same pool, so a live buy counts at its
whole size, a finished buy at what it actually paid, and a sell at what it
brought back.  The answer is never floored, so a pool that sold for more than it
bought reads negative.  A ledger told no equity settings at all still reads its
EQUITY rows.  The AI's live USDC pool is separate and ignores equity slots
entirely, so an equity order never touches the crypto money.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Optional

from .books import BOOKS, DRY, LIVE
from .money import BUY
from .store import EQUITY, LIVE_STATUSES, Store

D = Decimal

# The owner the AI trades as: it has no bot row, so nothing but this ledger and
# the gateway's route know what it holds.
AI_OWNER = "ai"

# The currency the AI's live capital is held in, and the only one it is given.
AI_CAPITAL_CURRENCY = "USDC"

# The currency the AI's equity pool is held in: every equity product is quoted in
# USD, so the pool's capital and its products share one currency.
EQUITY_CAPITAL_CURRENCY = "USD"


@dataclass(frozen=True)
class Holding:
    """One owner's totals for one product, in that product's quote and base currency.

    `quote` and `base` are totals: reservations are NOT subtracted from them.
    `equity` says whether the slot belongs to the AI's equity pool: it is true
    when one of the slot's own order rows is an EQUITY row, or when the
    configured rule calls the slot's product an equity.  It defaults to False,
    so a holding built from the four totals alone is a crypto one.
    """

    quote: Decimal
    base: Decimal
    reserved_quote: Decimal
    reserved_base: Decimal
    equity: bool = False

    @property
    def available_quote(self) -> Decimal:
        """Quote currency still free to spend."""
        return self.quote - self.reserved_quote

    @property
    def available_base(self) -> Decimal:
        """Base currency not already committed to a resting sell."""
        return self.base - self.reserved_base


EMPTY = Holding(D(0), D(0), D(0), D(0))


def _nothing_is_equity(product: str) -> bool:
    """The default equity rule: no product is an equity at all."""
    return False


def _stamp(value: Any) -> float:
    """A stored timestamp as a float; an absent or unusable one is zero."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class Ledger:
    """Reads a `Store`; holds no state of its own beyond the fee rate.

    `ai_capital` answers the `ai` owner's live capital, read on every call; with
    none the AI trades on what its own filled orders leave it, which is what an
    engine that gives it no capital means.  It is a callable rather than an
    amount so a cap changed at run time is the capital the next read sees.

    `equity_ai_capital` is the same figure for the AI's equity pool, and
    `is_equity` says which products are equities.  Both are optional and both
    default to nothing: a ledger told neither has no equity capital and nothing
    is an equity, which is exactly the crypto-only engine.  A capital that cannot
    be read, or one that is not a finite, non-negative number, counts as 0.
    """

    def __init__(
        self,
        store: Store,
        *,
        fee_rate: Decimal,
        ai_capital: Optional[Callable[[], Decimal]] = None,
        equity_ai_capital: Optional[Callable[[], Decimal]] = None,
        is_equity: Optional[Callable[[str], bool]] = None,
    ):
        self.store = store
        self.fee_rate = D(fee_rate)
        self._ai_capital = ai_capital
        self._equity_ai_capital = equity_ai_capital
        self._is_equity = is_equity if is_equity is not None else _nothing_is_equity

    # ------------------------------------------------ which book
    def _book_for(self, owner: Optional[str], book: Optional[str]) -> str:
        """The book a read is about: the one named, else the owner's current one.

        A caller that names no book means "the book this owner trades": a bot
        row's `mode`, and "dry" for an owner without one (the `ai` owner, an
        orphan, a bot that is gone).  A named book has to be one this engine
        knows, so a typo cannot silently read a third, empty book.
        """
        if book is None:
            bot = self.store.get_bot(owner) if owner is not None else None
            return bot["mode"] if bot is not None else DRY
        if book not in BOOKS:
            raise ValueError(f"unknown book: {book!r}")
        return book

    def _capital(self, bot: dict, book: str) -> tuple[D, D]:
        """A bot's capital budget on *book*: its dry pair, or its live pair (NULL is 0)."""
        if book == DRY:
            return D(bot["capital_quote"]), D(bot["capital_base"])
        quote = bot["live_capital_quote"]
        base = bot["live_capital_base"]
        return (
            D(0) if quote is None else D(quote),
            D(0) if base is None else D(base),
        )

    def _ai_capital_now(self) -> D:
        """The AI's live capital right now, and 0 when none can be used.

        A value that is not a finite, non-negative number is refused here rather
        than carried on: `NaN` compares false against every bound, so an
        unreadable capital would slip past the unallocated check, and a negative
        one would hand money to whoever reads the pool.
        """
        if self._ai_capital is None:
            return D(0)
        try:
            value = D(self._ai_capital())
        except (ArithmeticError, TypeError, ValueError):
            return D(0)
        if not value.is_finite() or value < 0:
            return D(0)
        return value

    def _equity_capital_now(self) -> D:
        """The AI's equity capital right now, and 0 when none can be used.

        Read on every call, like `_ai_capital_now` and for the same reason: a cap
        lowered at run time is the capital the next read sees.  A value that is
        not a finite, non-negative number — and a callable that raises — counts as
        0 rather than being carried on into a comparison it would slip past.
        """
        if self._equity_ai_capital is None:
            return D(0)
        try:
            value = D(self._equity_ai_capital())
        except (ArithmeticError, TypeError, ValueError):
            return D(0)
        if not value.is_finite() or value < 0:
            return D(0)
        return value

    def _is_equity_product(self, product: str) -> bool:
        """True when the configured rule says *product* is an equity."""
        return bool(self._is_equity(product))

    def _slot_is_equity(self, held: Holding, product: str) -> bool:
        """True when a slot is part of the AI's equity pool.

        A slot's own EQUITY rows decide it (`held.equity`), and the configured
        rule can only add to that: a product taken off the equity list whose
        rows are still EQUITY rows stays an equity, and so does a product the
        rule names before it has any row.  A caller that has no slot to hand
        passes `EMPTY`, which carries the rule's answer alone.
        """
        return held.equity or self._is_equity_product(product)

    # ------------------------------------------------ per (owner, product) totals
    def _holdings(
        self, owner: Optional[str] = None, book: str = DRY
    ) -> dict[tuple[str, str], Holding]:
        """(owner, product) pairs — all of them, or just *owner*'s — with capital.

        Only *book*'s capital and only *book*'s order rows are read, and a row
        written before its owner's epoch on that book is not part of it: it
        belongs to a period the owner has already left.

        A slot's `equity` flag is decided here, beside the totals it belongs to:
        it is true when any of the slot's rows is an EQUITY row, so a symbol that
        was taken off the equity list keeps its place in the equity pool for as
        long as the store says its orders were equities.
        """
        acc: dict[tuple[str, str], list[Decimal]] = {}
        equity_slots: set[tuple[str, str]] = set()

        def slot(own: str, product: str) -> list[Decimal]:
            return acc.setdefault((own, product), [D(0), D(0), D(0), D(0)])

        # A bot's capital is counted once, on its own product, even when it has
        # orders in other products.  Filtered in SQL: only the owner's own rows
        # (bots and orders) are read when an owner is given.
        if owner is None:
            bots = self.store.list_bots()
        else:
            bot = self.store.get_bot(owner)
            bots = [bot] if bot is not None else []
        for bot in bots:
            row = slot(bot["id"], bot["product"])
            quote, base = self._capital(bot, book)
            row[0] += quote
            row[1] += base

        # The epoch is read once per owner, on demand: a row older than it is the
        # history of a book this owner is no longer on, not part of today's.
        epochs: dict[str, float] = {}

        def epoch_of(own: str) -> float:
            if own not in epochs:
                epochs[own] = self.store.book_epoch(book, own)
            return epochs[own]

        # Owners with no bot row (orphan, ai, a removed bot) start from zero.
        for o in self.store.orders(owner=owner, book=book):
            if _stamp(o["created_at"]) < epoch_of(o["owner"]):
                continue
            key = (o["owner"], o["product"])
            row = slot(*key)
            if o["product_type"] == EQUITY:
                equity_slots.add(key)
            filled_size, filled_value, fees = (
                o["filled_size"],
                o["filled_value"],
                o["fees"],
            )
            live = o["status"] in LIVE_STATUSES
            remaining = (o["size"] - filled_size) if live else D(0)
            if o["side"] == BUY:
                row[0] -= filled_value + fees
                row[1] += filled_size
                if live:  # the fee is included in the reservation for crypto
                    if o["product_type"] == EQUITY:
                        # An equity pays no maker fee, so the hold is the cost.
                        row[2] += remaining * o["price"]
                    else:
                        row[2] += remaining * o["price"] * (1 + self.fee_rate)
            else:
                row[0] += filled_value - fees
                row[1] -= filled_size
                if live:
                    row[3] += remaining

        return {
            key: Holding(
                *values,
                equity=key in equity_slots or self._is_equity_product(key[1]),
            )
            for key, values in acc.items()
        }

    def _product_for(self, owner: str, product: Optional[str]) -> str:
        """The product to report on: explicit, else the owner's bot product."""
        if product is not None:
            return product
        bot = self.store.get_bot(owner)
        if bot is None:
            raise ValueError(f"owner {owner!r} has no bot row; pass a product")
        return bot["product"]

    # ------------------------------------------------ the AI's live pool
    def _ai_live_pool(
        self, slots: Optional[dict[tuple[str, str], Holding]] = None
    ) -> dict[str, tuple[D, D]]:
        """The AI's live quote side, one pool per quote currency.

        The pool of a currency is what the AI has in it on the live book: its
        capital in that currency (USDC, and only USDC) plus the effect of every
        live AI order on a product quoted in it — spent on buys, proceeds on
        sells, and what its resting orders reserve.  Its base side is not pooled
        here: a base asset belongs to the one product that trades it.

        The capital-bearing currency's quote side is floored at zero: a capital
        lowered below what the AI has already spent leaves the effects bigger
        than the capital, and money that is gone cannot be owed back to the
        account — a negative pool would be a NEGATIVE holding, which every other
        owner would then be handed as free money.  A currency with no capital of
        its own is left exactly as its orders make it, so an AI that sold into
        one keeps the positive pool it holds.

        `slots` is the AI's per-product holding set, already read when the caller
        has it; a pool entry exists for a currency the AI has capital or an order
        in, so nothing invents a currency beside the real ones.  An equity slot is
        not part of this pool at all: the equities' money is `_equity_pool`'s, and
        an equity order must never draw on (or reserve) the crypto side.
        """
        if slots is None:
            slots = self._holdings(AI_OWNER, LIVE)
        pool: dict[str, list[D]] = {}
        for (_owner, product), held in slots.items():
            if self._slot_is_equity(held, product):
                continue
            quote = product.split("-", 1)[1]
            entry = pool.setdefault(quote, [D(0), D(0)])
            entry[0] += held.quote
            entry[1] += held.reserved_quote
        capital = self._ai_capital_now()
        if capital > 0:
            entry = pool.setdefault(AI_CAPITAL_CURRENCY, [D(0), D(0)])
            entry[0] += capital
        return {
            currency: (
                D(0)
                if currency == AI_CAPITAL_CURRENCY and values[0] < 0
                else values[0],
                values[1],
            )
            for currency, values in pool.items()
        }

    # ------------------------------------------------ the AI's equity pool
    def _equity_pool(
        self, slots: dict[tuple[str, str], Holding]
    ) -> dict[str, tuple[D, D]]:
        """The AI's equity quote side: ONE pool per quote currency, per book.

        The pool of a currency is the equity capital (added once, in
        `EQUITY_CAPITAL_CURRENCY`) plus the quote effect of every equity slot of
        the ones given — spent on buys, proceeds on sells, and what its resting
        orders reserve.  Every equity product the AI trades draws on the same
        pool, whatever symbol it is, so the pool is never counted once per
        product.  Its base side stays per product and is not pooled here.

        The capital-bearing currency's quote side is floored at zero for the same
        reason as the USDC pool: money already spent cannot be owed back to the
        account, and a negative pool would be a NEGATIVE holding handed to every
        other owner.  No entry is invented for a currency the AI has neither
        capital nor an equity in, so a crypto-only ledger's `unallocated` gains
        no currency of its own.
        """
        pool: dict[str, list[D]] = {}
        for (_owner, product), held in slots.items():
            if not self._slot_is_equity(held, product):
                continue
            quote = product.split("-", 1)[1]
            entry = pool.setdefault(quote, [D(0), D(0)])
            entry[0] += held.quote
            entry[1] += held.reserved_quote
        capital = self._equity_capital_now()
        if capital > 0:
            entry = pool.setdefault(EQUITY_CAPITAL_CURRENCY, [D(0), D(0)])
            entry[0] += capital
        return {
            currency: (D(0) if values[0] < 0 else values[0], values[1])
            for currency, values in pool.items()
        }

    def equity_pool_used(self, book: str = DRY) -> D:
        """What the AI's equity pool has spent on one book, in USD.

        The SLOT decides, not the row: a slot (the AI, a product) belongs to the
        pool exactly when `_slot_is_equity` says so — any of its rows on that book
        is an EQUITY row, or the configured rule names its product — and then
        every one of its rows counts, whatever `product_type` the row itself was
        written with.  Reading it row by row is what keeps this figure and
        `holding`/`equity_products` on one answer: a SPOT row on a symbol the pool
        holds is spend from the same pool, and leaving it out would report a
        slot's money in two places at once.  The epoch filter is `_holdings`'s own,
        so a row from a period the owner has already left is not read here either.

        A resting buy holds its WHOLE submitted size (`size * price`, the pool
        committed at placement), a finished buy counts what it actually paid
        (`filled_value` plus its fees), and a sell — resting or finished — takes
        back what it brought in (`filled_value` less its fees).  An AI slot that
        is not an equity is not part of the pool at all.

        The answer is never floored: a pool that sold for more than it bought
        reads negative here, and the gateway is where a negative is refused.  The
        equity capital is not part of it either — the caller adds that — so this
        is the spend alone.
        """
        resolved = self._book_for(None, book)
        epoch = self.store.book_epoch(resolved, AI_OWNER)
        rows = [
            row
            for row in self.store.orders(owner=AI_OWNER, book=resolved)
            if _stamp(row["created_at"]) >= epoch
        ]
        equity_slots = {
            row["product"] for row in rows if row["product_type"] == EQUITY
        }
        total = D(0)
        for row in rows:
            if not (
                row["product"] in equity_slots
                or self._is_equity_product(row["product"])
            ):
                continue
            if row["side"] == BUY:
                if row["status"] in LIVE_STATUSES or row["status"] is None:
                    total += row["size"] * row["price"]
                else:
                    total += row["filled_value"] + row["fees"]
            else:
                total -= row["filled_value"] - row["fees"]
        return total

    def equity_products(self, book: str = DRY) -> list[str]:
        """Every product the AI's equity pool holds a slot in on one book.

        The answer is sorted and carries each product once, and a slot belongs
        here exactly when `_slot_is_equity` says so: its own rows are EQUITY rows
        or the configured rule names its product.  That is what a caller needs to
        mark a book whose symbol was taken off the equity list while the shares
        the AI bought are still there — the configured list alone would leave
        them unpriced.  Only *book*'s slots are read.
        """
        resolved = self._book_for(None, book)
        slots = self._holdings(AI_OWNER, resolved)
        return sorted(
            {
                product
                for (_owner, product), held in slots.items()
                if self._slot_is_equity(held, product)
            }
        )

    # ------------------------------------------------ public API
    def holding(
        self, owner: str, product: Optional[str] = None, *, book: Optional[str] = None
    ) -> Holding:
        """The owner's holdings on *product* (default: its bot's own product).

        `book` names the book ("dry" or "live"); with none, the owner's current
        book is read — its bot row's `mode`, and "dry" for an owner with no bot
        row.

        The `ai` owner on the live book reports the POOL of its product's quote
        currency, not a figure of its own: every AI order in that currency draws
        on the one pool, so the quote a product shows is what all of them have
        left together.  Its base side is that product's own, exactly as for any
        other owner.  The pool's quote side never reads below zero (see
        `_ai_live_pool`), so an AI whose capital was lowered under what it has
        already spent has nothing left to spend rather than a negative balance —
        and an order for more than that is `INSUFFICIENT_HOLDING` at the gateway,
        exactly as any other holding that cannot fund it.
        """
        prod = self._product_for(owner, product)
        resolved = self._book_for(owner, book)
        slots = self._holdings(owner, resolved)
        held = slots.get((owner, prod), EMPTY)
        if owner != AI_OWNER:
            return held
        if self._slot_is_equity(held, prod):
            quote, reserved_quote = self._equity_pool(slots).get(
                prod.split("-", 1)[1], (D(0), D(0))
            )
            return Holding(
                quote, held.base, reserved_quote, held.reserved_base, equity=True
            )
        if resolved != LIVE:
            return held
        quote, reserved_quote = self._ai_live_pool(slots).get(
            prod.split("-", 1)[1], (D(0), D(0))
        )
        return Holding(
            quote, held.base, reserved_quote, held.reserved_base, held.equity
        )

    def equity(
        self,
        owner: str,
        prices: dict[str, Decimal],
        product: Optional[str] = None,
        *,
        book: Optional[str] = None,
    ) -> Decimal:
        """Mark-to-market value: quote plus base at the product's price.

        Same book rule as `holding`: the named book, else the owner's current one.
        """
        prod = self._product_for(owner, product)
        resolved = self._book_for(owner, book)
        h = self.holding(owner, prod, book=resolved)
        return h.quote + h.base * D(prices[prod])

    def unallocated(
        self, totals: dict[str, Decimal], *, book: str = DRY
    ) -> dict[str, Decimal]:
        """Per currency: the exchange total minus what every owner holds.

        *totals* have to be that book's own totals: only *book*'s capital and
        only *book*'s order rows are subtracted, so a dry bot's holdings can
        never make the live book look short (or the other way round).  Negative
        values are returned as they are (the exchange is short).  Every currency
        seen in *totals* or in any owner's holdings appears in the result.

        On the live book the AI's quote side is reserved here as its POOL, once
        per quote currency (`_ai_live_pool`): its capital in the currency it is
        held in plus the effect of its own live orders there.  That is neither the
        raw sum of its per-product quote — which counts its capital once per
        product — nor the capital alone beside those effects, which would reserve
        money the AI has already spent twice over and, once the capital dropped
        below the spend, subtract a NEGATIVE figure and hand the difference to
        every other owner.  The reserve holds whether or not the AI's live switch
        is on, so what a bot's dry-to-live switch may take never includes the AI's
        money.  The dry book carries no such figure.

        The AI's EQUITIES are reserved the same way and on BOTH books, as the one
        equity pool (`_equity_pool`): their quote side is not summed per product
        at all — that would count the equity capital once per symbol — but added
        ONCE under its own currency.  Their base side is still per product, so
        shares the AI holds are subtracted from their own currency exactly as any
        other owner's are.  The crypto-side USDC pool ignores equity slots, so an
        equity order never touches the crypto money (or the other way round).
        """
        resolved = self._book_for(None, book)
        holdings = self._holdings(None, resolved)
        ai_slots = {key: held for key, held in holdings.items() if key[0] == AI_OWNER}
        pool: Optional[dict[str, tuple[D, D]]] = None
        if resolved == LIVE:
            pool = self._ai_live_pool(ai_slots)
        equity_pool = self._equity_pool(ai_slots)
        held: dict[str, Decimal] = {}
        for (owner, product), h in holdings.items():
            base, quote = product.split("-", 1)
            if owner == AI_OWNER and self._slot_is_equity(h, product):
                held[base] = held.get(base, D(0)) + h.base
                continue
            if pool is None or owner != AI_OWNER:
                held[quote] = held.get(quote, D(0)) + h.quote
            held[base] = held.get(base, D(0)) + h.base
        if pool is not None:
            for currency, (quote, _reserved) in pool.items():
                held[currency] = held.get(currency, D(0)) + quote
        for currency, (quote, _reserved) in equity_pool.items():
            held[currency] = held.get(currency, D(0)) + quote
        return {
            cur: D(totals.get(cur, D(0))) - held.get(cur, D(0))
            for cur in set(totals) | set(held)
        }