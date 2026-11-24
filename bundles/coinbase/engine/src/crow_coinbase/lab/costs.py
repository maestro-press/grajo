"""Cost model, FIFO tax-lot book and tax due for the research lab.

Money and prices are `Decimal` throughout; datetimes are timezone-aware UTC and
a naive datetime is refused with ValueError.  Nothing in this module reaches an
exchange: an order here is a description of a desired trade, and a fill is
arithmetic.

Tax rules modelled
------------------
* Every sale is a taxable event against the FIFO lot book; the buy fee joins
  the basis of the lot it bought and the sell fee is spread over the pieces the
  sale produced, pro rata by quantity.
* A piece is long-term when the sale date is strictly after the first calendar
  anniversary of the acquisition date.  Acquired 2023-01-01: sold 2024-01-01 is
  short-term, sold 2024-01-02 is long-term.  Acquired 2024-01-01: sold
  2025-01-01 is short-term even though 366 days pass, sold 2025-01-02 is
  long-term.  A lot acquired on 29 February has its next year's anniversary on
  28 February, so a sale that day is still short-term and one from 1 March on is
  long-term.
* Short-term results are summed per calendar year and so are long-term results.
  A loss carried in from an earlier year reduces the same class of gain, a loss
  on one side is then netted against a gain on the other, and the two rates are
  applied to what is left.  A loss left over after that netting keeps the
  character it was realized with and carries forward on its own side.
* The $3,000 limit on netting a net capital loss against ordinary income is NOT
  modelled: a loss year pays nothing and the whole loss carries forward.
* A crypto pair (a "-" in the symbol) never has a wash sale.  For a single-name
  instrument a loss that is replaced within 30 days either side of the sale is a
  wash sale: the disallowed amount shrinks the recognised loss and is added to
  the replacement lot's basis.  Holding-period tacking is not modelled.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, localcontext
from typing import Optional

from .store import ASSET_CLASSES, CRYPTO_CLASS, STOCK_CLASS

D = Decimal

__all__ = [
    "CostModel",
    "Increments",
    "Lots",
    "Order",
    "RealizedGain",
    "WashSaleFlag",
    "liquidation_tax",
    "tax_due",
]

# A purchase on either side of a loss sale, within this many days, replaces it.
WASH_WINDOW = timedelta(days=30)

# `holdings()` is a running sum rounded to the working precision, so the open
# lots can add up to slightly more than it reports (or slightly less).  A sale
# within this much of the open lots is a sale of the whole book.
DUST = D("1E-20")

MARKET = "market"
LIMIT = "limit"
BUY = "BUY"
SELL = "SELL"


# ---------------------------------------------------------------- value helpers


def _decimal(value: object, name: str) -> D:
    """A Decimal from a Decimal, str or int.  A float is refused."""
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(
            f"{name} must be a Decimal, not {type(value).__name__}: {value!r}"
        )
    try:
        return D(str(value))
    except Exception as exc:  # noqa: BLE001 - re-raised with the field name
        raise ValueError(f"{name} is not a decimal value: {value!r}") from exc


def _positive(value: object, name: str) -> D:
    out = _decimal(value, name)
    if out <= 0:
        raise ValueError(f"{name} must be positive: {value!r}")
    return out


def _at_least_zero(value: object, name: str) -> D:
    out = _decimal(value, name)
    if out < 0:
        raise ValueError(f"{name} must not be negative: {value!r}")
    return out


def _tax_rate(value: object, name: str) -> D:
    if value is None:
        raise ValueError(f"{name} is required (no assumed bracket): {value!r}")
    out = _decimal(value, name)
    if out < 0 or out > 1:
        raise ValueError(f"{name} must be within [0, 1]: {value!r}")
    return out


def _utc(moment: object, name: str) -> datetime:
    """*moment* refused unless it is a timezone-aware datetime, as UTC."""
    if not isinstance(moment, datetime):
        raise ValueError(f"{name} must be a datetime, got {type(moment).__name__}")
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"{name} must be timezone-aware: {moment!r}")
    return moment.astimezone(timezone.utc)


# ---------------------------------------------------------------- orders


@dataclass(frozen=True)
class Order:
    """One desired trade: a market order in size or in notional, or a resting one.

    A market order carries exactly one of `qty` and `notional`; a limit order
    carries `qty` and `limit_price` and no notional.  Sizes and prices are
    positive Decimals.
    """

    side: str
    qty: Optional[D] = None
    notional: Optional[D] = None
    kind: str = MARKET
    limit_price: Optional[D] = None

    def __post_init__(self) -> None:
        if self.side not in (BUY, SELL):
            raise ValueError(f"side must be {BUY!r} or {SELL!r}: {self.side!r}")
        if self.kind not in (MARKET, LIMIT):
            raise ValueError(
                f"kind must be {MARKET!r} or {LIMIT!r}: {self.kind!r}"
            )
        if self.kind == MARKET:
            if self.limit_price is not None:
                raise ValueError("a market order carries no limit_price")
            if (self.qty is None) == (self.notional is None):
                raise ValueError(
                    "a market order carries exactly one of qty and notional"
                )
            if self.qty is not None:
                object.__setattr__(self, "qty", _positive(self.qty, "qty"))
            else:
                object.__setattr__(
                    self, "notional", _positive(self.notional, "notional")
                )
            return
        if self.notional is not None:
            raise ValueError("a limit order carries no notional")
        if self.qty is None:
            raise ValueError("a limit order carries qty")
        if self.limit_price is None:
            raise ValueError("a limit order carries limit_price")
        object.__setattr__(self, "qty", _positive(self.qty, "qty"))
        object.__setattr__(
            self, "limit_price", _positive(self.limit_price, "limit_price")
        )


@dataclass(frozen=True)
class Increments:
    """The product's order size step and price step."""

    base: D
    quote: D

    def __post_init__(self) -> None:
        object.__setattr__(self, "base", _positive(self.base, "base"))
        object.__setattr__(self, "quote", _positive(self.quote, "quote"))


# ---------------------------------------------------------------- cost model


@dataclass(frozen=True)
class CostModel:
    """Fees, slippage and the tax rates that apply to one asset.

    The two tax rates are keyword-only and have no default: a run states them
    rather than inheriting an assumed bracket.
    """

    asset: str
    taker: D
    maker: D
    slippage: D
    st_tax_rate: D = field(kw_only=True)
    lt_tax_rate: D = field(kw_only=True)
    increments: Optional[Increments] = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if not isinstance(self.asset, str) or not self.asset:
            raise ValueError(f"asset must be a non-empty string: {self.asset!r}")
        object.__setattr__(self, "taker", _at_least_zero(self.taker, "taker"))
        object.__setattr__(self, "maker", _at_least_zero(self.maker, "maker"))
        object.__setattr__(
            self, "slippage", _at_least_zero(self.slippage, "slippage")
        )
        object.__setattr__(
            self, "st_tax_rate", _tax_rate(self.st_tax_rate, "st_tax_rate")
        )
        object.__setattr__(
            self, "lt_tax_rate", _tax_rate(self.lt_tax_rate, "lt_tax_rate")
        )
        if self.increments is not None and not isinstance(self.increments, Increments):
            raise ValueError(
                f"increments must be an Increments, got "
                f"{type(self.increments).__name__}"
            )

    @property
    def asset_class(self) -> str:
        """`crypto` for a pair symbol (it carries a "-"), else `stock`."""
        return CRYPTO_CLASS if "-" in self.asset else STOCK_CLASS

    @classmethod
    def for_crypto(
        cls,
        asset: str,
        *,
        st_tax_rate: D,
        lt_tax_rate: D,
        slippage: D,
        taker: D = D("0.009"),
        maker: D = D("0.005"),
        increments: Optional[Increments] = None,
    ) -> "CostModel":
        return cls(
            asset,
            taker,
            maker,
            slippage,
            st_tax_rate=st_tax_rate,
            lt_tax_rate=lt_tax_rate,
            increments=increments,
        )

    @classmethod
    def for_stock(
        cls,
        asset: str,
        *,
        st_tax_rate: D,
        lt_tax_rate: D,
        slippage: D = D("0.0005"),
        increments: Optional[Increments] = None,
    ) -> "CostModel":
        return cls(
            asset,
            D("0"),
            D("0"),
            slippage,
            st_tax_rate=st_tax_rate,
            lt_tax_rate=lt_tax_rate,
            increments=increments,
        )


# ---------------------------------------------------------------- lot book


@dataclass
class RealizedGain:
    """One closed piece of a lot, as the sale produced it.

    Mutable: a wash-sale match later raises `gain` by the disallowed amount (so
    the recognised loss shrinks) and adds the same amount to `disallowed`.
    """

    qty: D
    gain: D
    long_term: bool
    ts_sold: datetime
    ts_acquired: datetime
    disallowed: D = D("0")

    def __post_init__(self) -> None:
        self.qty = _positive(self.qty, "qty")
        self.gain = _decimal(self.gain, "gain")
        self.disallowed = _at_least_zero(self.disallowed, "disallowed")
        self.long_term = bool(self.long_term)
        self.ts_sold = _utc(self.ts_sold, "ts_sold")
        self.ts_acquired = _utc(self.ts_acquired, "ts_acquired")


@dataclass(frozen=True)
class WashSaleFlag:
    """A loss sale that a replacement purchase disallowed part of."""

    ts: datetime
    qty: D
    disallowed_loss: D

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", _utc(self.ts, "ts"))
        object.__setattr__(self, "qty", _positive(self.qty, "qty"))
        object.__setattr__(
            self,
            "disallowed_loss",
            _at_least_zero(self.disallowed_loss, "disallowed_loss"),
        )


@dataclass
class _Lot:
    """One acquisition still held: quantity left, and the basis of that quantity."""

    ts: datetime
    qty: D
    price: D
    basis_total: D
    matched: D = D("0")


@dataclass
class _LossSlot:
    """A loss piece still open for a replacement purchase."""

    piece: RealizedGain
    unmatched: D


def _anniversary(acquired: date) -> date:
    """The first calendar anniversary of an acquisition date."""
    year = acquired.year + 1
    try:
        return date(year, acquired.month, acquired.day)
    except ValueError:
        # 29 February has no counterpart in the next year, so the anniversary
        # that year is 28 February; long-term applies from 1 March on.
        return date(year, 2, 28)


class Lots:
    """A FIFO lot book for one asset class, with the tax result of every sale.

    `realized` holds the pieces of every sale, oldest first, and the list a sale
    returns holds the very same objects in the same order.
    """

    def __init__(self, asset_class: str):
        if asset_class not in ASSET_CLASSES:
            raise ValueError(
                f"invalid asset class {asset_class!r}; expected one of "
                f"{list(ASSET_CLASSES)}"
            )
        self.asset_class = asset_class
        self.lots: list[_Lot] = []
        self.realized: list[RealizedGain] = []
        self._losses: list[_LossSlot] = []
        self._flags: list[WashSaleFlag] = []

    # ------------------------------------------------------------ reads
    def holdings(self) -> D:
        """Total quantity still held."""
        total = D("0")
        for lot in self.lots:
            total += lot.qty
        return total

    def wash_sale_flags(self) -> list[WashSaleFlag]:
        """Every wash-sale match on the book, oldest first."""
        self.settle()
        return list(self._flags)

    def copy(self) -> "Lots":
        """An independent deep copy of the book, history included."""
        return copy.deepcopy(self)

    def open_copy(self) -> "Lots":
        """A book holding copies of the open lots only, and nothing else.

        The rule's view of the book: the lots still held, copied one by one, so
        reading or writing the copy leaves the run alone.  `realized`, the loss
        slots and the wash-sale flags are empty, because the rule sees what is
        held and not what has already been sold.
        """
        view = Lots(self.asset_class)
        view.lots = [replace(lot) for lot in self.lots]
        return view

    # ------------------------------------------------------------ writes
    def buy(
        self, ts: datetime, qty: D, price: D, fee: D = D("0")
    ) -> None:
        """Open a new lot; its basis is qty*price plus the fee."""
        moment = _utc(ts, "ts")
        units = _positive(qty, "qty")
        unit_price = _positive(price, "price")
        paid = _at_least_zero(fee, "fee")
        self.settle()
        lot = _Lot(
            ts=moment,
            qty=units,
            price=unit_price,
            basis_total=units * unit_price + paid,
        )
        self.lots.append(lot)
        if self.asset_class == STOCK_CLASS:
            self._match_later_purchases(lot)

    def sell(
        self, ts: datetime, qty: D, price: D, fee: D = D("0")
    ) -> list[RealizedGain]:
        """Close `qty` oldest lots first at `price`; returns the pieces.

        Selling more than the book holds raises ValueError.  The fee is spread
        over the pieces pro rata by quantity, and the pieces are the same
        objects kept in `realized`.

        The book is compared against the open lots added without rounding, so a
        sale of exactly `holdings()` still closes every lot: the difference the
        rounded total leaves behind is dust, and the sale stops when the lots
        run out with no more than `DUST` of the asked quantity unfilled.
        """
        moment = _utc(ts, "ts")
        units = _positive(qty, "qty")
        unit_price = _positive(price, "price")
        paid = _at_least_zero(fee, "fee")
        held = self.holdings()
        # Refuse an oversized sale before any lot is touched.  The sum of the
        # lot quantities is taken at a precision wide enough to keep it exact,
        # because the running sum behind `holdings()` drops the digits that
        # separate a whole-book sale from one unit too many.
        with localcontext() as ctx:
            ctx.prec = max(
                ctx.prec,
                sum(len(lot.qty.as_tuple().digits) for lot in self.lots) + 2,
            )
            open_qty = sum((lot.qty for lot in self.lots), D("0"))
            if units - open_qty > DUST:
                raise ValueError(f"cannot sell {units}: the book holds {held}")
        self.settle()
        pieces: list[RealizedGain] = []
        remaining = units
        while remaining > 0 and self.lots:
            lot = self.lots[0]
            take = lot.qty if lot.qty <= remaining else remaining
            if take == lot.qty:
                basis = lot.basis_total
            else:
                basis = lot.basis_total * take / lot.qty
            fee_share = paid * take / units
            piece = RealizedGain(
                qty=take,
                gain=take * unit_price - fee_share - basis,
                long_term=moment.date() > _anniversary(lot.ts.date()),
                ts_sold=moment,
                ts_acquired=lot.ts,
            )
            self.realized.append(piece)
            pieces.append(piece)
            remaining -= take
            if take == lot.qty:
                self.lots.pop(0)
            else:
                lot.qty = lot.qty - take
                lot.basis_total = lot.basis_total - basis
        if self.asset_class == STOCK_CLASS:
            for piece in pieces:
                if piece.gain < 0:
                    self._losses.append(
                        _LossSlot(piece=piece, unmatched=piece.qty)
                    )
        return pieces

    def settle(self) -> None:
        """Match open loss pieces against replacement lots already held.

        A sale records each loss piece and then leaves it alone, so the pieces
        `sell()` returned keep the gain they were created with.  The match
        against lots that were *already* held when the loss was sold (bought
        within the 30 days before that sale) is applied here: on the next buy,
        the next sell, a `wash_sale_flags()` read, or the simulator's tax step.
        Crypto has no wash-sale rule, so this does nothing for a crypto book.
        """
        if self.asset_class != STOCK_CLASS:
            return
        for slot in self._losses:
            if slot.unmatched <= 0:
                continue
            sale_day = slot.piece.ts_sold.date()
            window_start = sale_day - WASH_WINDOW
            for lot in self.lots:
                if slot.unmatched <= 0:
                    break
                available = lot.qty - lot.matched
                if available <= 0:
                    continue
                lot_day = lot.ts.date()
                if lot_day < window_start or lot_day > sale_day:
                    continue
                matched = (
                    slot.unmatched if slot.unmatched <= available else available
                )
                self._match(slot, lot, matched)

    # ------------------------------------------------------------ wash matching
    def _match_later_purchases(self, lot: _Lot) -> None:
        """Case (a): a purchase made within 30 days after a loss sale."""
        buy_day = lot.ts.date()
        for slot in self._losses:
            if slot.unmatched <= 0:
                continue
            sale_day = slot.piece.ts_sold.date()
            if buy_day <= sale_day or buy_day > sale_day + WASH_WINDOW:
                continue
            available = lot.qty - lot.matched
            if available <= 0:
                continue
            matched = slot.unmatched if slot.unmatched <= available else available
            self._match(slot, lot, matched)

    def _match(self, slot: _LossSlot, lot: _Lot, matched: D) -> None:
        """Disallow `matched` units of a loss and carry that basis into the lot."""
        piece = slot.piece
        # The piece's gain was raised by whatever has been disallowed already,
        # so the original loss per unit is (disallowed - gain) / qty.
        per_unit = (piece.disallowed - piece.gain) / piece.qty
        if per_unit <= 0:
            slot.unmatched = D("0")
            return
        disallowed = per_unit * matched
        piece.gain = piece.gain + disallowed
        piece.disallowed = piece.disallowed + disallowed
        lot.basis_total = lot.basis_total + disallowed
        lot.matched = lot.matched + matched
        slot.unmatched = slot.unmatched - matched
        later = piece.ts_sold if piece.ts_sold > lot.ts else lot.ts
        self._flags.append(
            WashSaleFlag(ts=later, qty=matched, disallowed_loss=disallowed)
        )


# ---------------------------------------------------------------- tax


def tax_due(realized: list[RealizedGain], costs: "CostModel") -> dict[int, D]:
    """Tax owed per calendar year of the sale, in year order.

    Short-term and long-term results are summed per year, an earlier year's loss
    carries forward against the same class, and a remaining loss on one side is
    netted against a gain on the other before the rates apply.  A year appears
    only when it has realized pieces.

    A loss still left after that netting keeps its own character: it reduces
    only the same class of gain in a later year and carries forward on that
    side, so a long-term loss is never spent against a short-term gain twice
    over.  The $3,000 offset against ordinary income is not modelled.
    """
    by_year: dict[int, list[D]] = {}
    for piece in realized:
        year = _utc(piece.ts_sold, "ts_sold").year
        bucket = by_year.setdefault(year, [D("0"), D("0")])
        if piece.long_term:
            bucket[1] += piece.gain
        else:
            bucket[0] += piece.gain

    st_carry = D("0")
    lt_carry = D("0")
    due: dict[int, D] = {}
    for year in sorted(by_year):
        short_gains, long_gains = by_year[year]
        st = short_gains - st_carry
        lt = long_gains - lt_carry
        # A loss on one side is netted against a gain on the other, but what is
        # left of the loss stays on the side it was realized on.
        if st < 0 and lt > 0:
            offset = min(-st, lt)
            lt -= offset
            st += offset
        elif lt < 0 and st > 0:
            offset = min(-lt, st)
            st -= offset
            lt += offset
        taxable_st = st if st > 0 else D("0")
        taxable_lt = lt if lt > 0 else D("0")
        due[year] = taxable_st * costs.st_tax_rate + taxable_lt * costs.lt_tax_rate
        st_carry = -st if st < 0 else D("0")
        lt_carry = -lt if lt < 0 else D("0")
    return due


def liquidation_tax(
    lots: Lots,
    realized: list[RealizedGain],
    paid_so_far: D,
    mark_price: D,
    ts: datetime,
    costs: "CostModel",
) -> D:
    """Tax the whole book would owe if it were closed at `mark_price` at `ts`.

    The book is sold on a copy, with no fee and no slippage, and the tax is
    computed over the pieces on file plus the hypothetical ones.  The result is
    that total minus what has already been paid, so it may be negative when a
    correction (a wash-sale match, say) turns an earlier payment into a refund.
    The book and the realized list handed in are left as they were.
    """
    moment = _utc(ts, "ts")
    mark = _decimal(mark_price, "mark_price")
    paid = _decimal(paid_so_far, "paid_so_far")
    book = lots.copy()
    book.settle()
    held = book.holdings()
    pieces: list[RealizedGain] = []
    if held > 0:
        if mark <= 0:
            raise ValueError(f"mark_price must be positive: {mark_price!r}")
        pieces = book.sell(moment, held, mark)
    total = sum(tax_due(list(realized) + pieces, costs).values(), D("0"))
    return total - paid