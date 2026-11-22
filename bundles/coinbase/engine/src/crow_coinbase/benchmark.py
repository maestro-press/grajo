"""benchmark.py: the hold-the-starting-mix shadow value.

The benchmark answers one question: what would this owner's equity be if the
starting mix of base and quote had simply been held, with every resting order
forgotten?  The starting mix is a kv record on the store (`store.get` /
`store.put` only, JSON, so the Decimals go in as strings), keyed per owner and
per book: `bench:<book>:<owner>`.  Each book has its own shadow, so a bot that
switched books starts a fresh mix on the one it moved to instead of carrying the
other book's history into it.

`start` is a no-op once the owner has a mix on that book, so a restart of the
engine can never reset the shadow to the current, already-traded holding.  The
one record a book still reads is the P1 one: a `benchmark:<owner>` key written
before books existed is the dry book's baseline (a P1 engine only ever traded the
simulator) and only the dry book's — the live book has its own baseline or none.
`forget` writes the record away (None, which keeps the key, so a bot id is still
known to have been used), which is how a switch makes the next `start` take a
fresh mix — and it re-arms that book's trailing-hold episode in the same write, so
the days a bot spent on one book never count against the one it moves to.

`trailing` is the other thing the shadow is read for: an episode of the owner
trailing its own starting mix.  Its state is a kv record of its own per
(`book`, owner) — when the episode started and whether it has been alerted — so
one episode raises one alert however many cycles pass through it, and the state
is in the store rather than in this object.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Optional

from .books import BOOKS, DRY

D = Decimal

# The per-book key: `bench:<book>:<owner>`.
KEY_PREFIX = "bench:"
# The P1 key, `benchmark:<owner>`, kept readable as the dry book's baseline.
LEGACY_PREFIX = "benchmark:"
# The per-book key a trailing-hold episode lives under: `trail:<book>:<owner>`.  It
# holds `{"since": <epoch or null>, "alerted": bool}`, so the alert it raises
# survives a new `Benchmark` over the same store (and a restart) and re-arms only
# once the comparison is no longer negative.
TRAIL_PREFIX = "trail:"
# Seconds in a day: the episode's age is measured in days, on the same clock.
DAY_SECONDS = 86400.0


def _dec(value, field: str = "value") -> D:
    """`Decimal(str(value))`, with a `ValueError` instead of a decimal error.

    Params and rows arrive from JSON, so a number may be a str, int, float or
    Decimal; anything unparseable is a `ValueError`.
    """
    try:
        return D(str(value))
    except (ArithmeticError, ValueError, TypeError):
        raise ValueError(f"{field} must be a number, got {value!r}") from None


def _mix_value(value, field: str) -> D:
    """A finite, non-negative amount of the starting mix (zero is allowed)."""
    out = _dec(value, field)
    if not out.is_finite():
        raise ValueError(f"{field} must be a finite number, got {value!r}")
    if out < 0:
        raise ValueError(f"{field} must be >= 0, got {value!r}")
    return out


def _book_name(book: str) -> str:
    """One of the two books, or a `ValueError` for anything else."""
    if book not in BOOKS:
        raise ValueError(f"unknown book: {book!r}")
    return book


class Benchmark:
    """One frozen starting mix per (owner, book), valued at a given price."""

    def __init__(self, store: Any):
        self.store = store

    # ------------------------------------------------ keys
    @staticmethod
    def _key(owner: str, book: str) -> str:
        return f"{KEY_PREFIX}{book}:{owner}"

    @staticmethod
    def _legacy_key(owner: str) -> str:
        return f"{LEGACY_PREFIX}{owner}"

    @staticmethod
    def _trail_key(owner: str, book: str) -> str:
        return f"{TRAIL_PREFIX}{book}:{owner}"

    def _mix(self, owner: str, book: str) -> dict:
        """The owner's stored starting mix on *book*, or `KeyError` when unstarted.

        The dry book also reads the P1 record: a `benchmark:<owner>` key is what a
        P1 engine left, and that engine only ever traded the simulator, so it is
        the dry book's baseline.  The live book never reads it.
        """
        record = self.store.get(self._key(owner, book))
        if record is None and book == DRY:
            record = self.store.get(self._legacy_key(owner))
        if record is None:
            raise KeyError(owner)
        return record

    # ------------------------------------------------ public API
    def start(
        self, owner: str, base: Any, quote: Any, price: Any, book: str = DRY
    ) -> None:
        """Record the mix once; a later call for the same owner and book changes nothing.

        Every value is read and checked before anything is written, so a refused
        start leaves the owner unstarted.  A record already on the book — its own,
        or for the dry book the P1 `benchmark:<owner>` one — is the baseline, so
        the start writes nothing at all.
        """
        mode = _book_name(book)
        mix_base = _mix_value(base, "base")
        mix_quote = _mix_value(quote, "quote")
        mix_price = _mix_value(price, "price")

        key = self._key(owner, mode)
        if self.store.get(key) is not None:
            return
        if mode == DRY and self.store.get(self._legacy_key(owner)) is not None:
            return
        self.store.put(
            key,
            {
                "base": str(mix_base),
                "quote": str(mix_quote),
                "price": str(mix_price),
            },
        )

    def value(self, owner: str, price: Any, book: str = DRY) -> D:
        """What the starting mix of *book* is worth at *price*."""
        mix = self._mix(owner, _book_name(book))
        return _dec(mix["base"], "base") * _dec(price, "price") + _dec(
            mix["quote"], "quote"
        )

    def vs_hold(
        self, owner: str, equity: Any, price: Any, book: str = DRY
    ) -> D:
        """The owner's equity minus the hold-the-mix shadow (positive is ahead)."""
        return _dec(equity, "equity") - self.value(owner, price, book)

    def forget(self, owner: str, book: str) -> None:
        """Drop the baseline of one book so a later start takes a fresh mix.

        The record is written as None rather than deleted: the key's presence is
        also how the engine knows the owner has been seen before, so the id is not
        handed out again.  Forgetting the dry book forgets the P1 record with it,
        since that is where the dry book's baseline may come from.

        The book's trailing-hold episode goes in the same step: the days a bot
        spent trailing its mix are the days it spent on THAT book, so a bot that
        leaves it has not been behind for a stretch it traded somewhere else.  The
        trail record is written to the empty state `trailing` re-arms with —
        `{"since": None, "alerted": False}` — so the book it comes back to has to
        trail for the whole window again.  Both writes are one transaction, so a
        baseline and an episode never disagree about which book they belong to.
        """
        mode = _book_name(book)
        with self.store.tx():
            self.store.put(self._key(owner, mode), None)
            if mode == DRY:
                self.store.put(self._legacy_key(owner), None)
            self.store.put(
                self._trail_key(owner, mode), {"since": None, "alerted": False}
            )

    # ------------------------------------------------ the trailing hold
    def trailing(
        self,
        owner: str,
        book: str,
        vs_hold: Any,
        now: Any,
        days: int,
    ) -> Optional[dict]:
        """One alert per episode of the owner trailing the mix it started with.

        The episode's state is in the store, under `trail:<book>:<owner>`:
        `{"since": <epoch or null>, "alerted": bool}`.  *vs_hold* is the
        comparison against the shadow (`vs_hold`, a `Decimal`) or None when it
        cannot be measured, and `now`/`days` say how long a negative comparison
        has to last before it is news.

        The episode is measured on the clock the caller passes in, and on nothing
        else: `now` minus the moment the episode started is the number of days
        the caller is told about.  So engine downtime counts toward those days,
        and so does a stretch in which no usable price was read — an episode that
        began before the engine stopped is still that old when it comes back, and
        a book nothing could price neither starts nor ends one while it is
        unpriceable.  The window is elapsed wall-clock time, not a count of
        cycles that found a price.

        An unknown comparison (`None`) leaves the state exactly as it is and
        answers None, so a book nothing can price neither starts nor ends an
        episode.  A comparison at or above zero re-arms the state (`since` null,
        not alerted) and answers None: ONE non-negative sample is enough, and it
        resets the episode rather than pausing it, so the next negative sample
        starts a new one from its own moment.  A negative one starts the episode
        at the first moment it was seen, and once it has lasted *days* days it
        answers `{"since": <the start>, "days_negative": <days elapsed>}` exactly
        once: the state is then marked alerted and later calls in the same
        episode answer None, however long the episode lasts.  State is written
        only when it changes, so a steady episode writes nothing between the two
        ends.
        """
        mode = _book_name(book)
        if vs_hold is None:
            return None
        value = _dec(vs_hold, "vs_hold")
        key = self._trail_key(owner, mode)
        state = self.store.get(key)
        if not isinstance(state, dict):
            state = {}
        since = state.get("since")
        if isinstance(since, bool) or not isinstance(since, (int, float)):
            since = None
        else:
            since = float(since)
        alerted = bool(state.get("alerted"))
        if value >= 0:
            if since is not None or alerted:
                self.store.put(key, {"since": None, "alerted": False})
            return None
        at = float(now)
        if since is None:
            self.store.put(key, {"since": at, "alerted": False})
            return None
        elapsed = at - since
        if elapsed >= int(days) * DAY_SECONDS and not alerted:
            self.store.put(key, {"since": since, "alerted": True})
            return {"since": since, "days_negative": elapsed / DAY_SECONDS}
        return None