"""The strategy contract: what a strategy sees, and what it may answer.

Only frozen dataclasses and one Protocol live here, so the loop, the gateway and
every strategy share the same shapes without importing one another.  Money and
size are `Decimal`; `ts`, `print_ts` and `now` are the only floats (epoch
seconds).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Literal, Optional, Protocol

from ..ledger import Holding
from ..money import ProductSpec


@dataclass(frozen=True)
class MarketSnapshot:
    """One product's top of book and the low/high of the poll window that read it.

    `ts` is when the read happened.  `print_ts` is when the PRICE was made, for a
    market that knows the difference: an equity print carries its own time, and a
    reader has to be able to tell a fresh read of an old price from a fresh price
    (a stock order's age bound is about the print, not about the read).  It is the
    last field, defaulting to None, so every snapshot that has no print of its own
    — a crypto book, or one built before this existed — is unchanged and is judged
    by `ts` alone.
    """

    product: str
    bid: Decimal
    ask: Decimal
    low: Decimal
    high: Decimal
    ts: float
    print_ts: Optional[float] = None


@dataclass(frozen=True)
class OrderIntent:
    """One order to place, or one order to cancel.

    A place intent carries `side`, `size` and `limit_price` (`level` is the grid
    level it belongs to).  A cancel intent carries `cancel_cid` only.
    `consumes_fill` marks the fill this re-place answers, so the loop can retire
    it exactly once.  `approval_id` names the owner's approved preview an `ai`
    order goes out under (`ai_orders.py`); a bot never sets it.
    """

    action: Literal["place", "cancel"]
    side: Optional[Literal["BUY", "SELL"]]
    size: Optional[Decimal]
    limit_price: Optional[Decimal]
    level: Optional[int]
    cancel_cid: Optional[str]
    reason: str
    consumes_fill: Optional[str] = None
    approval_id: Optional[str] = None


@dataclass(frozen=True)
class BotView:
    """Everything one bot's strategy may read when it decides."""

    bot_id: str
    product: str
    params: dict
    state: dict
    holding: Holding
    open_orders: list[dict]
    pending_fills: list[dict]
    fee_rate: Decimal
    spec: ProductSpec
    now: float


@dataclass(frozen=True)
class Decision:
    """A strategy's answer for one tick: intents to send, plus state to keep."""

    intents: list[OrderIntent]
    pause_reason: Optional[str] = None
    state_update: Optional[dict] = None
    skipped_fills: list[str] = field(default_factory=list)


class Strategy(Protocol):
    """A grid-like strategy: validate its params once, then decide per tick.

    `fee_guard` returns a refusal reason when the configured step cannot pay the
    maker fee twice with a margin, and None when it can.
    """

    name: str

    def validate(self, params: dict) -> None: ...

    def fee_guard(self, params: dict, maker_fee_pct: Decimal) -> Optional[str]: ...

    def init_intents(self, snap: MarketSnapshot, view: BotView) -> Decision: ...

    def decide(self, snap: MarketSnapshot, view: BotView) -> Decision: ...