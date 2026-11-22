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
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Optional

from .books import BOOKS, DRY, LIVE
from .money import BUY
from .store import LIVE_STATUSES, Store

D = Decimal

# The owner the AI trades as: it has no bot row, so nothing but this ledger and
# the gateway's route know what it holds.
AI_OWNER = "ai"

# The currency the AI's live capital is held in, and the only one it is given.
AI_CAPITAL_CURRENCY = "USDC"


@dataclass(frozen=True)
class Holding:
    """One owner's totals for one product, in that product's quote and base currency.

    `quote` and `base` are totals: reservations are NOT subtracted from them.
    """

    quote: Decimal
    base: Decimal
    reserved_quote: Decimal
    reserved_base: Decimal

    @property
    def available_quote(self) -> Decimal:
        """Quote currency still free to spend."""
        return self.quote - self.reserved_quote

    @property
    def available_base(self) -> Decimal:
        """Base currency not already committed to a resting sell."""
        return self.base - self.reserved_base


EMPTY = Holding(D(0), D(0), D(0), D(0))


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
    """

    def __init__(
        self,
        store: Store,
        *,
        fee_rate: Decimal,
        ai_capital: Optional[Callable[[], Decimal]] = None,
    ):
        self.store = store
        self.fee_rate = D(fee_rate)
        self._ai_capital = ai_capital

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

    # ------------------------------------------------ per (owner, product) totals
    def _holdings(
        self, owner: Optional[str] = None, book: str = DRY
    ) -> dict[tuple[str, str], Holding]:
        """(owner, product) pairs — all of them, or just *owner*'s — with capital.

        Only *book*'s capital and only *book*'s order rows are read, and a row
        written before its owner's epoch on that book is not part of it: it
        belongs to a period the owner has already left.
        """
        acc: dict[tuple[str, str], list[Decimal]] = {}

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
            row = slot(o["owner"], o["product"])
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
                if live:  # the fee is included in the reservation
                    row[2] += remaining * o["price"] * (1 + self.fee_rate)
            else:
                row[0] += filled_value - fees
                row[1] -= filled_size
                if live:
                    row[3] += remaining

        return {key: Holding(*values) for key, values in acc.items()}

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
        in, so nothing invents a currency beside the real ones.
        """
        if slots is None:
            slots = self._holdings(AI_OWNER, LIVE)
        pool: dict[str, list[D]] = {}
        for (_owner, product), held in slots.items():
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
        if owner != AI_OWNER or resolved != LIVE:
            return held
        quote, reserved_quote = self._ai_live_pool(slots).get(
            prod.split("-", 1)[1], (D(0), D(0))
        )
        return Holding(quote, held.base, reserved_quote, held.reserved_base)

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
        """
        resolved = self._book_for(None, book)
        holdings = self._holdings(None, resolved)
        pool: Optional[dict[str, tuple[D, D]]] = None
        if resolved == LIVE:
            pool = self._ai_live_pool(
                {key: held for key, held in holdings.items() if key[0] == AI_OWNER}
            )
        held: dict[str, Decimal] = {}
        for (owner, product), h in holdings.items():
            base, quote = product.split("-", 1)
            if pool is None or owner != AI_OWNER:
                held[quote] = held.get(quote, D(0)) + h.quote
            held[base] = held.get(base, D(0)) + h.base
        if pool is not None:
            for currency, (quote, _reserved) in pool.items():
                held[currency] = held.get(currency, D(0)) + quote
        return {
            cur: D(totals.get(cur, D(0))) - held.get(cur, D(0))
            for cur in set(totals) | set(held)
        }