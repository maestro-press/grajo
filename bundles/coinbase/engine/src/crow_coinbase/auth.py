"""auth.py: the owner's approval rail — a MAC over the request, its nonces, and the lease.

A privileged route (a mode switch, the live switches, clearing a halt, a live
bot's recenter or resume, and the lease) needs more than the engine's bearer
token: it needs a MAC the owner signed over the exact request it sent.  This
module computes that MAC, checks it, spends its nonce once, and refuses
everything else with one answer — `403` carrying `APPROVAL_INVALID`, whatever
went wrong and whichever check failed first.

The three headers a signed request carries:

* `X-Crow-Timestamp` — integer epoch seconds, ASCII digits only, within
  `MAC_WINDOW_S` of the engine's own clock either way.
* `X-Crow-Nonce` — 16 to 128 characters of `[A-Za-z0-9_-]`, used once.  It is
  written to the `nonces` table as part of accepting the request, so a nonce
  spent before a restart is still spent after it.  That table is bounded: an
  accepted request purges the rows old enough to be past their own timestamps,
  and the cutoff it used is written to the kv table as `nonce_floor` — the
  oldest stamp this engine still accepts.  A request whose stamp is below that
  floor is refused, so a clock that jumps forward (pruning as it goes) and then
  back cannot re-admit a captured request whose row the purge took.
* `X-Crow-Signature` — lowercase hex of `HMAC_SHA256(key, string_to_sign)`.

The signed text is five lines joined by `"\\n"`:

    METHOD
    path_with_query
    ts
    nonce
    sha256hex(body bytes)

`METHOD` is uppercase, `path_with_query` is the request target as it was sent
(the raw path, plus `"?"` and the raw query string when there is one), `ts` and
`nonce` are the header texts, and the last line is the hex SHA-256 of the raw
body bytes.  The MAC therefore covers the method, the path, the query, the
stamp, the nonce and the body: a body, a path, a query or a method swapped after
signing is a different request and fails the check.

The body is not read by the approval itself — `require` is a plain sync
dependency that gets the request — so `BodyCaptureMiddleware`, which
`create_app` installs, reads the whole body when a request carries an
`X-Crow-Signature` header, caps it at `MAX_BODY_BYTES`, and hands the same bytes
on to FastAPI through a wrapped `receive`.  The bytes it read are left on
`scope["state"]["raw_body"]`; an approval with no captured body refuses.

The key is one of three things, decided on every call and never cached:

* the in-memory approval secret when one is set (`set_secret`), which is the
  only key a privileged route takes, and which has to be at least `MIN_KEY_BYTES`
  long to be a key at all,
* nothing at all when a pin exists (`pin_exists` asks whether the pin's kv ROW
  is there, on every call, which is what `pinned()` answers): a pinned engine
  with no secret in memory has NO key, and refuses every request — the lease's
  included,
* otherwise the install token, read on demand from `token_path` (absent,
  unreadable, empty, all-whitespace or under `MIN_KEY_BYTES` is no key, and
  refuses) — and only for a route that admits it.

The install token is therefore not a second key beside the owner's: a pin takes
it out of the rail for good, and `clear_secret` cannot hand it back, because with
a pin in the store the next request simply has no key.  `clear_secret` never
deletes the pin.

Which routes admit the install token is the surface's decision, and it is three
callers of this module.  `require(request)` is the strict gate — a mode switch,
the live switches, clearing a halt, a live bot's recenter or resume, and
disconnecting the owner's credentials — where the install token is never a key.
`require(request, allow_install_token=True)`, spelled `require_install_ok`, is
the gate for the two lease routes and for the credentials check route, where it
is.  `require_credentials` is the third: the gate of the one route that installs
a key, whose MAC is keyed by the approval secret the request's own BODY carries
once a pin exists — compared against the pin's sha256 first, so a body carrying
another secret is `SECRET_MISMATCH` rather than a MAC failure — and by the
install token while there is no pin yet.  It answers which of those two kinds of
key the request was checked against (`KEY_KIND_PINNED_SECRET` or
`KEY_KIND_INSTALL_TOKEN`), because that route's own transaction decides again
whether a pin exists at the moment it writes: the answer is the kind of key the
approval believed in, not a promise that the store still agrees.

That `SECRET_MISMATCH` is answered BEFORE the timestamp, the nonce and the MAC
are checked: the body's secret is at least `MIN_KEY_BYTES` random characters, so
an answer that says "not the pinned secret" tells a caller nothing it could have
computed, and it has to arrive before any of the checks a caller can forge.
Because it is answered before the MAC, a run of them is cheap to produce, so
`MismatchLimiter` counts them in process memory and the route answers
`429 RATE_LIMITED` for a minute once `MISMATCH_LIMIT` of them arrived inside
`MISMATCH_WINDOW_S`; only `SECRET_MISMATCH` counts — a served request and every
other refusal leave the count where it was.  The answer that locks the route
also writes ONE `credentials` warning event, so the owner is told the reconnect
is blocked instead of discovering it; the refusals that follow write nothing and
a later lockout writes its own.  No event carries a secret, a key, a header or a
signature.

A lockout therefore shuts a guesser out, not the owner.  While one stands the
request is evaluated in three steps, and none of them writes an event:

1. a cheap pre-check that spends nothing and reads no pin — the three headers
   present and usable, the stamp inside the window and at or above the nonce
   floor, and the nonce not already spent.  A request that cannot pass it is the
   lockout's `429 RATE_LIMITED`, and it moves nothing: a guess with a stale
   stamp, a replayed nonce or no signature is not evidence of more guessing.
2. the pin.  An engine with no pin at all, and a body secret whose sha256 is not
   the stored pin, are both that same `429`; the wrong secret also `extend`s the
   lockout a further `MISMATCH_LOCKOUT_S` — no new count, no new event — because
   the caller is still guessing at the one thing it can guess at.
3. for a body secret that IS the pin, the full check with that secret as the key
   (headers, window, floor, MAC and a nonce spent once).  A MAC that does not
   match is the same `429` and moves nothing; a valid one is SERVED, and
   `MismatchLimiter.clear` forgets the count and the lockout so the next wrong
   secret starts a fresh one.

Nothing here counts a `SECRET_MISMATCH`, writes an event or touches the pin
while the lockout stands: a lockout is recorded ONCE, where it trips, and a
later one writes its own.

The refusal is one answer — `403 APPROVAL_INVALID` — whatever failed: every
header is read and the `hmac.compare_digest` comparison always runs, even when a
header is missing or malformed, against an empty expected value, so a refusal
never says which check failed in its detail, its log or its exception text.
Total refusal time is NOT uniform, though: a request refused before a key exists
or before its headers are usable never computes a MAC, so it is answered sooner
than one that was compared and failed the comparison.  Nothing here writes a
key, a signature or a nonce into a log, a response, an event or an error.

The lease is the other thing a client of this surface holds: `Lease.acquire`
takes, renews or reports a single holder with a TTL, and `Lease.set_cursor`
advances a monotonic cursor that event retention reads (`Store.prune_events`
never deletes past it) — for the live lease's own holder only, and never past the
newest event this engine holds.  Both live in the store's `kv` table, so both
survive a restart.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException, Request

from .books import APPROVAL_INVALID
from .store import LEASE_CURSOR_KEY, Store

log = logging.getLogger("crow_coinbase.auth")

# ---------------------------------------------------------------- headers
# The three headers a signed request carries.  The names are the ones the owner
# signs with; the lookups below are done on the lowercased spellings, which is
# what a request's headers answer a lookup with.
STAMP_HEADER = "X-Crow-Timestamp"
NONCE_HEADER = "X-Crow-Nonce"
SIGNATURE_HEADER = "X-Crow-Signature"
STAMP_LOOKUP = STAMP_HEADER.lower()
NONCE_LOOKUP = NONCE_HEADER.lower()
SIGNATURE_LOOKUP = SIGNATURE_HEADER.lower()
SIGNATURE_SCOPE_NAME = SIGNATURE_LOOKUP.encode("latin-1")

# ---------------------------------------------------------------- the MAC
# How far a request's stamp may be from this engine's clock, either way.
MAC_WINDOW_S = 60.0
# An epoch-seconds stamp: ASCII digits, and short enough that no absurd number is
# parsed on the refusal path.
STAMP_RE = re.compile(r"[0-9]{1,18}")
# A nonce: the base64url alphabet, long enough to be unique and short enough to
# be a header.
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")

# ---------------------------------------------------------------- the key
# The environment variable that names the install token file, and the path the
# engine's own installer publishes it at when nothing names another one.
ENV_INSTALL_TOKEN_FILE = "CROW_COINBASE_INSTALL_TOKEN_FILE"
DEFAULT_INSTALL_TOKEN_PATH = "/run/secrets/install_token"

# The kv key a pinned approval secret lives under: the sha256 hex of the secret,
# written when the owner pins one.  Only its presence is read here, and the value
# is never read as a key.
APPROVE_PIN_KEY = "approve_secret_sha256"

# The refusal a credentials request earns when its body carries a secret that is
# not the pinned one.  It says nothing about the request beyond that: the MAC
# failure beside it is the uniform `APPROVAL_INVALID`, and this one is only the
# hash mismatch, which the owner has to be told apart from a bad signature.
SECRET_MISMATCH = "SECRET_MISMATCH"

# The two kinds of key `require_credentials` checks a request against, and the
# answer it gives back: the owner's pinned secret (the one thing a pinned engine
# accepts) or the installer's token (a key only while no pin exists).
KEY_KIND_PINNED_SECRET = "pinned_secret"
KEY_KIND_INSTALL_TOKEN = "install_token"

# The refusal a route answers when too many wrong approval secrets arrived in one
# window.  It is the route's answer rather than a secret's: nothing about the
# request is read to produce it.
RATE_LIMITED = "RATE_LIMITED"
# How many `SECRET_MISMATCH` answers one window holds, how long that window is,
# and how long the route then refuses for.  Counted in process memory and never
# persisted: a limit that exists to slow a guesser rather than to record one is
# not something a restart has to remember.
MISMATCH_LIMIT = 5
MISMATCH_WINDOW_S = 60.0
MISMATCH_LOCKOUT_S = 60.0

# The one sentence a lockout is recorded with, and the kind of event it is: it
# says what happened and nothing about the request that caused it — no header, no
# secret and no signature — so it can be shown to the owner as it stands.
LOCKOUT_MESSAGE = (
    "Too many wrong approval secrets; reconnect blocked for a minute"
)
LOCKOUT_EVENT_KIND = "credentials"

# The kv key the nonce purge writes its cutoff to: the oldest stamp this engine
# still accepts, and one that only ever moves forward.  A request whose stamp is
# below it is refused however fresh its nonce is, which is what keeps a purge
# from re-admitting a captured request when the clock jumps back.
NONCE_FLOOR_KEY = "nonce_floor"

# The fewest bytes an approval secret, or an install token, may have.  A shorter
# one is not a weak key, it is no key at all: `set_secret` refuses it and a token
# file that short keys nothing.
MIN_KEY_BYTES = 32

# ---------------------------------------------------------------- the body
# The largest body this rail will read to check a signature.  A body over it is
# left unset, which refuses: an approval that cannot see the whole body cannot
# vouch for it.
MAX_BODY_BYTES = 1024 * 1024

# ---------------------------------------------------------------- nonces
# How long a spent nonce is remembered.  A stamp is only good for
# `MAC_WINDOW_S`, so a nonce older than the retention cannot be presented inside
# the window again.
NONCE_RETENTION_S = 300.0
# The margin added to the window when a spent nonce's row is judged old.  A row
# is dropped only once BOTH its own `seen_at` and the request's `ts` are past the
# bound, so a clock that jumps forward and back cannot re-admit a captured
# request whose stamp is still inside the window.
NONCE_MARGIN_S = 60.0

# ---------------------------------------------------------------- the lease
# The kv key the one lease lives under, and the key `store.prune_events` reads as
# its floor (imported from `store` so the two can never disagree).
LEASE_KEY = "lease"
LEASE_CURSOR = LEASE_CURSOR_KEY
# How long one acquisition holds the lease before another holder may take it.
LEASE_TTL_S = 60.0
# The holder a lease may be taken or renewed for: printable, bounded, and free of
# the characters that would make two holders read as one.
HOLDER_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
LEASE_NOT_HELD = "LEASE_NOT_HELD"
# A cursor may not point past the newest event this engine holds: a reader cannot
# have read an event that does not exist, and a cursor ahead of the events would
# stop retention from ever deleting one.
CURSOR_AHEAD = "CURSOR_AHEAD"

BODY_STATE_KEY = "raw_body"


# ---------------------------------------------------------------- the MAC itself


def _key_bytes(value: Any) -> Optional[bytes]:
    """A value presented as a key, as bytes; None when it is not text at all."""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


def _body_bytes(body: Any) -> bytes:
    """The bytes a body is signed over: bytes as they are, text as its UTF-8."""
    if isinstance(body, str):
        return body.encode("utf-8")
    if body is None:
        return b""
    return bytes(body)


def string_to_sign(
    method: Any,
    path_with_query: Any,
    ts: Any,
    nonce: Any,
    body: Any,
) -> str:
    """The exact text the MAC is computed over, five lines and no trailing one."""
    digest = hashlib.sha256(_body_bytes(body)).hexdigest()
    return "\n".join(
        [
            str(method).upper(),
            "" if path_with_query is None else str(path_with_query),
            "" if ts is None else str(ts),
            "" if nonce is None else str(nonce),
            digest,
        ]
    )


def compute_mac(
    key: Any,
    method: Any,
    path_with_query: Any,
    ts: Any,
    nonce: Any,
    body: Any,
) -> str:
    """The lowercase hex HMAC-SHA256 of `string_to_sign`, keyed by *key*.

    The key is taken as bytes when it already is bytes and as its UTF-8 encoding
    when it is text, so a caller that has a token as a string cannot key the MAC
    with a different secret than one that has it as bytes.
    """
    material = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    message = string_to_sign(method, path_with_query, ts, nonce, body)
    return hmac.new(material, message.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- request bits


def _path_with_query(scope: Mapping[str, Any]) -> str:
    """The request target as it was sent: raw path, then `?` and the raw query.

    `raw_path` is what the client sent, before any decoding, so two requests that
    differ only in their percent-encoding are two different signed requests.  A
    raw path that is not ASCII, or absent, falls back to the scope's decoded path
    rather than to nothing, so a refusal is a mismatch and not a crash.
    """
    raw = scope.get("raw_path")
    path = ""
    if isinstance(raw, (bytes, bytearray)):
        try:
            path = bytes(raw).decode("ascii")
        except UnicodeDecodeError:
            path = ""
    if not path:
        path = str(scope.get("path") or "")
    query = scope.get("query_string") or b""
    if isinstance(query, (bytes, bytearray)) and query:
        return path + "?" + bytes(query).decode("latin-1")
    return path


def _raw_body(request: Request) -> Optional[bytes]:
    """The body `BodyCaptureMiddleware` read for this request, or None for none."""
    try:
        body = request.state.raw_body
    except AttributeError:
        return None
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return None


def _in_window(stamp: str, now: float) -> bool:
    """Whether *stamp* is a whole number of seconds within the window of *now*."""
    if STAMP_RE.fullmatch(stamp) is None:
        return False
    try:
        at = int(stamp)
    except ValueError:
        return False
    return abs(float(at) - now) <= MAC_WINDOW_S


def _nonce_floor(db: Any) -> float:
    """The stored nonce floor as a number, or 0.0 when nothing usable is stored.

    Read on every accepted request and inside the purge's own transaction.  A key
    that is absent, a value that is not JSON, and a JSON value that is not a
    number (null, an object, a list, a string, a boolean, a number too large to
    be a float) are all no floor at all: 0 refuses nothing, so a hand-edited or
    older file makes the floor quiet rather than raising on the request path.
    """
    row = db.execute(
        "SELECT value FROM kv WHERE key=?", (NONCE_FLOOR_KEY,)
    ).fetchone()
    if row is None:
        return 0.0
    try:
        value = json.loads(row["value"])
    except (TypeError, ValueError):
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    try:
        return float(value)
    except (OverflowError, ValueError):
        return 0.0


def _above_floor(stamp: str, floor: float) -> bool:
    """Whether *stamp* is at or above the floor the last purge recorded."""
    if STAMP_RE.fullmatch(stamp) is None:
        return False
    try:
        return int(stamp) >= floor
    except ValueError:
        return False


def _refused() -> HTTPException:
    """The one refusal this module raises: 403, and nothing about the request."""
    return HTTPException(status_code=403, detail=APPROVAL_INVALID)


def _limited() -> HTTPException:
    """The lockout's refusal: 429, and nothing about the request."""
    return HTTPException(status_code=429, detail=RATE_LIMITED)


def _presented(request: Request) -> tuple[str, str, str]:
    """The three approval headers as they were sent: stamp, nonce, signature.

    One place spells out which header holds what — an absent one is an empty
    string — so the check that verifies a request and the cheaper one that only
    decides whether a request is worth verifying can never read different things
    out of the same request.
    """
    headers = request.headers
    return (
        headers.get(STAMP_LOOKUP) or "",
        headers.get(NONCE_LOOKUP) or "",
        headers.get(SIGNATURE_LOOKUP) or "",
    )


# ---------------------------------------------------------------- body capture


def _carries_signature(scope: Mapping[str, Any]) -> bool:
    """Whether this request presented an `X-Crow-Signature` header with a value."""
    for name, value in scope.get("headers") or ():
        if not value:
            continue
        if bytes(name).lower() == SIGNATURE_SCOPE_NAME:
            return True
    return False


class _Replayed:
    """A `receive` that answers the messages already read, then the real one.

    The captured messages are handed on in the order they arrived and the
    original channel answers whatever comes after them, so a body larger than the
    capture cap is still delivered whole and a disconnect is still seen.
    """

    def __init__(self, receive: Any, held: list) -> None:
        self._receive = receive
        self._held = list(held)

    async def __call__(self) -> Any:
        if self._held:
            return self._held.pop(0)
        return await self._receive()


async def _read_body(receive: Any) -> tuple[list, Optional[bytes]]:
    """Read the request body, up to `MAX_BODY_BYTES`, and answer what was read.

    The messages read are answered as a list so they can be replayed downstream.
    A body over the cap, and a client that went away mid-body, both answer None:
    the caller leaves the body unset and the approval refuses.
    """
    held: list = []
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        held.append(message)
        if message.get("type") != "http.request":
            return held, None
        chunk = message.get("body", b"") or b""
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            return held, None
        chunks.append(bytes(chunk))
        if not message.get("more_body", False):
            return held, b"".join(chunks)


class BodyCaptureMiddleware:
    """Reads a signed request's body once, so the approval can sign over it.

    A request that carries no `X-Crow-Signature` header is passed straight
    through: nothing is buffered for it.  A signed one has its body read here,
    left on `scope["state"]["raw_body"]` and replayed to the app unchanged, so
    the bytes the MAC covers are the bytes the handler parses.

    The state dict is a fresh copy for every request, so one request's captured
    body is never read as another's: a request whose body was not captured finds
    no body at all, which refuses.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        state = dict(scope.get("state") or {})
        state.pop(BODY_STATE_KEY, None)
        scope["state"] = state
        if not _carries_signature(scope):
            await self.app(scope, receive, send)
            return
        held, body = await _read_body(receive)
        if body is not None:
            state[BODY_STATE_KEY] = body
        await self.app(scope, _Replayed(receive, held), send)


# ---------------------------------------------------------------- the pin


def pin_exists(store: Store) -> bool:
    """Whether a pin ROW was written for this engine, whatever it holds.

    Asked on every approval and never cached, so a pin written by a later request
    is seen by a rail — and by an app — that was built before it.  The row is
    read directly rather than through `Store.get`, which answers its default for
    an absent key and for a stored JSON null alike: a row holding null, an
    object, a number or an empty string pins the engine exactly as a hash does,
    and only an absent row leaves the install token a key.  The value is never
    read as a key.  A store that cannot be read raises, and the approval turns
    that into its one refusal.
    """
    row = store.conn().execute(
        "SELECT 1 FROM kv WHERE key=?", (APPROVE_PIN_KEY,)
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------- wrong secrets


class MismatchLimiter:
    """The in-process count of wrong approval secrets, and the lockout it earns.

    `record` counts one `SECRET_MISMATCH` answer at the engine's clock `now`, and
    the `MISMATCH_LIMIT`th one inside `MISMATCH_WINDOW_S` locks the route until
    `MISMATCH_LOCKOUT_S` after it; `locked` is the question the route asks before
    it reads anything, and it forgets the whole count once the lockout has
    passed, so the next window starts empty.

    `extend` is the other way the end of a lockout moves, and the only one that
    adds no count: while the route is locked, a caller that keeps presenting the
    wrong secret pushes the end a further `MISMATCH_LOCKOUT_S` from now, so a run
    of guesses keeps it shut for as long as the run lasts.  A route that is not
    locked is left exactly as it was — an extend never starts a lockout.

    Only the caller's own `record` calls count: a served request and a refusal of
    another kind never reach this class, so nothing but a wrong secret can lock
    the route.  Nothing here is persisted and nothing here is a value: the count
    is timestamps and the lockout is one of them, never a secret.  The lock is
    taken so two threads answering at once cannot both read a stale count.

    `clear` is the other side of `record`: a request the lockout would have
    refused but that was served anyway — the owner's own push, carrying and
    signing the pinned secret — forgets the count and the lockout together, so
    the next wrong secret is the first of a new run instead of inheriting the one
    that tripped the lockout.
    """

    def __init__(
        self,
        now: Callable[[], float],
        *,
        limit: int = MISMATCH_LIMIT,
        window_s: float = MISMATCH_WINDOW_S,
        lockout_s: float = MISMATCH_LOCKOUT_S,
    ) -> None:
        self._now = now
        self._limit = int(limit)
        self._window = float(window_s)
        self._lockout = float(lockout_s)
        self._lock = threading.Lock()
        self._seen: list[float] = []
        self._until: Optional[float] = None

    def locked(self) -> bool:
        """Whether the route is locked out right now."""
        at = float(self._now())
        with self._lock:
            if self._until is None:
                return False
            if at < self._until:
                return True
            self._forget()
            return False

    def record(self) -> bool:
        """Count one wrong secret, and lock the route on the last one a window holds.

        A stamp older than the window no longer counts, and the lockout is set
        from the moment of the answer that reached the limit rather than from the
        first of the run, so a caller that keeps guessing keeps the route shut.

        Answers True exactly when THIS call is the one that locked the route, so
        a caller can record the lockout once and not once per refused request
        that follows it.  A call that arrives while the route is already locked
        counts nothing and answers False.
        """
        at = float(self._now())
        with self._lock:
            if self._until is not None:
                if at < self._until:
                    return False
                self._forget()
            self._seen = [
                stamp for stamp in self._seen if at - stamp <= self._window
            ]
            self._seen.append(at)
            if len(self._seen) >= self._limit:
                self._until = at + self._lockout
                return True
            return False

    def extend(self) -> None:
        """Move the end of a standing lockout a further `lockout_s` from now.

        The answer to a caller that is still guessing while the route is shut: a
        wrong approval secret is the one thing a guesser can keep producing, so
        the minute it earns is counted from its own arrival rather than from the
        fifth wrong one that tripped the lockout.  It adds NO count and writes
        nothing — a count belongs to `record`, and the event a lockout is
        recorded with is written once, where it trips.

        A route that is not locked is left exactly as it was, and its expired
        lockout with it: there is no end to move, and this is not how one starts.
        """
        at = float(self._now())
        with self._lock:
            if self._until is None:
                return
            if at >= self._until:
                self._forget()
                return
            self._until = at + self._lockout

    def clear(self) -> None:
        """Forget every count and the lockout: a served request opens the route.

        Called when a request was served while the lockout stood, which only the
        owner's own push (the pinned secret in the body, a MAC keyed by it) can
        be.  Both the count and the end of the lockout go, so the next wrong
        secret starts the window over rather than inheriting a run that has
        already been answered with a lockout.  Nothing here is persisted, and a
        route that is not locked is left exactly as it was.
        """
        with self._lock:
            self._forget()

    def _forget(self) -> None:
        """Forget every count and the lockout; called with the lock held."""
        self._seen = []
        self._until = None


# ---------------------------------------------------------------- the approval


class Authenticator:
    """The approval a privileged route needs: a MAC, a nonce, and one answer.

    `store` is where a spent nonce is written, `now` is the engine's clock (a
    callable answering epoch seconds), and `token_path` the install token file.
    `pinned` is required and answers whether a secret was pinned for this engine;
    it is asked on EVERY call, so a pin written after this rail was built is seen
    without rebuilding anything.  When it says yes and no secret is in memory
    there is no key, and every request is refused — the install token included.
    """

    def __init__(
        self,
        store: Store,
        now: Callable[[], float],
        token_path: Path | str,
        pinned: Callable[[], bool],
    ) -> None:
        self._store = store
        self._now = now
        self._token_path = token_path
        self._pinned = pinned
        self._secret: Optional[bytes] = None
        # The count of wrong approval secrets on the credentials route: in this
        # rail's own memory, read from the engine's clock like everything else.
        self._mismatches = MismatchLimiter(now)

    @classmethod
    def from_env(
        cls,
        store: Store,
        env: Mapping[str, str],
        now: Callable[[], float],
        pinned: Callable[[], bool],
    ) -> "Authenticator":
        """The rail over *store*, with the token path *env* names (or the default).

        `pinned` is required here too: it is the only place the rail can learn
        whether this engine has a pin, and a rail built without the answer would
        keep using the install token after one.
        """
        named = env.get(ENV_INSTALL_TOKEN_FILE)
        path = named if named else DEFAULT_INSTALL_TOKEN_PATH
        return cls(store, now, path, pinned=pinned)

    # ------------------------------------------------ the in-memory secret
    def set_secret(self, secret: Any) -> None:
        """Hold an approval secret in memory; from now on it is the only key.

        The value has to be text or bytes and at least `MIN_KEY_BYTES` long: a
        blank or short secret is a key nobody meant to set, so it is refused as a
        `ValueError` that carries no part of the value.
        """
        if isinstance(secret, str):
            material = secret.encode("utf-8")
        elif isinstance(secret, (bytes, bytearray)):
            material = bytes(secret)
        else:
            raise ValueError("an approval secret must be bytes or text")
        if len(material) < MIN_KEY_BYTES:
            raise ValueError(
                f"an approval secret must be at least {MIN_KEY_BYTES} bytes"
            )
        self._secret = material

    def clear_secret(self) -> None:
        """Forget the in-memory secret, and nothing else.

        The pin, if there is one, stays where it is: with a pin in the store the
        next request has no key at all, so clearing a secret never makes the
        install token a key again.
        """
        self._secret = None

    # ------------------------------------------------ the key
    def _install_token(self) -> Optional[bytes]:
        """The install token as bytes, or None when the file gives no key.

        Read on every call and never remembered: an absent, unreadable, empty,
        all-whitespace or too-short file is no key (and refuses), and a token
        written or replaced after the engine started is the one the next request
        is checked against.
        """
        try:
            text = Path(self._token_path).read_text(encoding="utf-8")
        except (OSError, ValueError):
            return None
        material = text.strip().encode("utf-8")
        if len(material) < MIN_KEY_BYTES:
            return None
        return material

    def _key(self, allow_install_token: bool) -> Optional[bytes]:
        """The key this request is checked against, or None when there is none.

        A secret in memory is the key whenever it is set.  With no secret, a pin
        means NO key whatever the request asked for, so a pinned engine refuses
        everything until a secret is in memory again.  Only a store with no pin,
        and only a route that admits it, falls through to the install token.
        """
        secret = self._secret
        if secret:
            return secret
        if self._pinned():
            return None
        if not allow_install_token:
            return None
        return self._install_token()

    # ------------------------------------------------ the check
    def require(self, request: Request, allow_install_token: bool = False) -> None:
        """Pass the request, or refuse it as `403 APPROVAL_INVALID`.

        With the default the install token is not a key: only a secret in memory
        is, so a request against a pinned engine with no secret is refused
        whatever it presents.  `allow_install_token=True` is the same check with
        the install token admitted for this one route; `require_install_ok` is
        that call under its own name.

        Nothing else is ever raised: every failure inside the check — an absent
        file, a header that is not text this engine can read, a body nothing
        captured, a store that will not take the nonce — is this one refusal.
        """
        try:
            self._check(request, allow_install_token)
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001 - every failure of the check is a refusal
            raise _refused() from None

    def require_install_ok(self, request: Request) -> None:
        """The install-token gate: the check with the install token admitted.

        The two lease routes and the credentials check route ask through this;
        every other privileged route asks `require`, which never takes the token.
        """
        self.require(request, allow_install_token=True)

    def require_credentials(self, request: Request, body_secret: Any) -> str:
        """Pass a `POST /credentials` request, or refuse it with the code it earns.

        That one route has its own key.  With a pin in the store the MAC has to be
        keyed by the approval secret the request's BODY carries, and that secret
        has to be the pinned one — compared as the sha256 hex of its UTF-8 bytes
        against the stored value — or the answer is `403 SECRET_MISMATCH` and
        nothing else is looked at.  That comparison comes FIRST, before the
        timestamp window, the nonce, the floor and the MAC: the body's secret is
        at least `MIN_KEY_BYTES` random characters, so the answer says nothing a
        caller could have computed, and it has to be settled before any check a
        caller can forge.  With no pin at all the install token is the key,
        exactly as it is on the lease routes, so a first connect presents it and
        the body's secret is only what the pin will be made of.

        Answers the kind of key the request was checked against —
        `KEY_KIND_PINNED_SECRET` or `KEY_KIND_INSTALL_TOKEN` — so the route can
        hand that answer to the store's own transaction, which decides again
        whether a pin exists by the time it writes.

        Everything else is the check every privileged route gets: the three
        headers, the timestamp window, the nonce, the nonce floor, and the MAC
        over the raw body the middleware captured.  Every failure of that is the
        one `403 APPROVAL_INVALID`, and nothing here writes a key, a signature or
        a secret anywhere.

        A `SECRET_MISMATCH` is also what a run of wrong secrets earns the route
        itself: once `MISMATCH_LIMIT` of them arrived inside `MISMATCH_WINDOW_S`,
        the route answers `429 RATE_LIMITED` for `MISMATCH_LOCKOUT_S` — because
        that comparison is cheap enough to guess at and the answer is the same for
        any secret that is not the pinned one.

        That lockout shuts a guesser out and not the owner.  While it stands the
        request is answered in three steps, and none of them writes an event:

        1. the cheap pre-check (`_usable_headers`): the three headers present and
           usable, the stamp inside the window and at or above the nonce floor,
           and the nonce not already spent.  It reads no pin and spends nothing,
           so a guess that cannot pass it — a stale stamp, a replayed nonce, no
           signature at all — answers the lockout's `429` and moves nothing.
        2. the pin: an engine with no pin at all, and a body secret whose sha256
           is not the stored pin, are both that same `429`; the wrong secret also
           `extend`s the lockout a further `MISMATCH_LOCKOUT_S`, because the
           caller is still guessing at the only thing it can guess at.
        3. for a body secret that IS the pin, the full check `_verify` with that
           secret as the key (headers, window, floor, MAC, a nonce spent once).
           A MAC that does not match is the same `429` and moves nothing; a valid
           one is served as it always was and clears the lockout.

        None of those counts a `SECRET_MISMATCH`, writes an event, or changes the
        pin.  The answer that locks the route also writes ONE warning event, so
        the owner is told the reconnect is blocked rather than left to discover
        it; the refusals that follow it write nothing, and a later lockout writes
        its own.  A store that cannot take the event changes nothing about the
        answer: the `403 SECRET_MISMATCH` is raised either way.
        """
        if self._mismatches.locked():
            return self._while_locked(request, body_secret)
        try:
            return self._check_credentials(request, body_secret)
        except HTTPException as error:
            # Only this one refusal counts towards the lockout: the route's own
            # successes and every other refusal leave the count where it was.
            if error.status_code == 403 and error.detail == SECRET_MISMATCH:
                if self._mismatches.record():
                    self._record_lockout()
            raise
        except Exception:  # noqa: BLE001 - every failure of the check is a refusal
            raise _refused() from None

    def _while_locked(self, request: Request, body_secret: Any) -> str:
        """Answer one request while the credentials route is locked out.

        The three steps `require_credentials` documents, in the order they have to
        run: the cheap pre-check first, so a request that cannot be signed at all
        is refused without the pin being read and without extending anything; the
        pin next, where a wrong secret is the one answer that says the caller is
        still guessing and so pushes the end of the lockout out; and the full
        check last, for a body secret that IS the pin, where a bad MAC is the same
        refusal as any other and a valid one is served.

        Answers the key kind of a served request (`KEY_KIND_PINNED_SECRET`) and
        raises `429 RATE_LIMITED` for every other one.  Any failure on the way —
        a store that cannot be read, a body nothing captured — is that same
        `429`, which says nothing about which part of the request failed; nothing
        of the request reaches the answer, and nothing here writes an event.
        """
        try:
            if not self._usable_headers(request):
                raise _limited()
            if not self._pinned():
                raise _limited()
            material = _key_bytes(body_secret)
            if material is None or not self._matches_pin(material):
                self._mismatches.extend()
                raise _limited()
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001 - the lockout answers whatever failed
            raise _limited() from None
        try:
            self._verify(request, material)
        except Exception:  # noqa: BLE001 - a lockout answers a bad MAC too
            # The full check's own refusal is `403 APPROVAL_INVALID`, which is
            # what a caller outside a lockout gets; inside one, every failure of
            # it is the lockout's `429` so the answer never says whether the
            # secret was right.  Nothing is extended by it.
            raise _limited() from None
        self._mismatches.clear()
        return KEY_KIND_PINNED_SECRET

    def _usable_headers(self, request: Request) -> bool:
        """Whether a request's stamp, nonce and signature are usable as they are.

        The half of `_verify` that needs no key: the three headers have to be
        there, the stamp a whole number of seconds inside `MAC_WINDOW_S` of the
        engine's clock and at or above the nonce floor, the nonce of the shape a
        nonce has, and the body the one the middleware captured.  Nothing is
        spent and nothing is written — the nonce table is only READ — so a caller
        can ask this before it decides whether to look at a pin at all.
        """
        stamp, nonce, presented = _presented(request)
        if not presented or not stamp or not nonce:
            return False
        if _raw_body(request) is None:
            return False
        if NONCE_RE.fullmatch(nonce) is None:
            return False
        if not _in_window(stamp, float(self._now())):
            return False
        if not _above_floor(stamp, self._floor()):
            return False
        return not self._spent(nonce)

    def _spent(self, nonce: str) -> bool:
        """Whether this nonce is already in the table, read without writing.

        A row exists only once a request whose MAC matched spent it, so a row is
        a nonce already used.  A question rather than a claim: nothing is
        inserted for a nonce that is not there, which is what makes it safe to ask
        before anything of the request has been judged.
        """
        row = self._store.conn().execute(
            "SELECT 1 FROM nonces WHERE nonce=?", (nonce,)
        ).fetchone()
        return row is not None

    def _record_lockout(self) -> None:
        """Record the lockout once: one warning event, and no value of anything.

        Best effort on purpose: the refusal it belongs to is the answer, so a
        store that cannot take the event is logged without its exception text
        (which could carry a row's value) and the caller still refuses.
        """
        try:
            self._store.event(
                "warn", LOCKOUT_MESSAGE, kind=LOCKOUT_EVENT_KIND
            )
        except Exception:  # noqa: BLE001 - the refusal stands either way
            log.warning("credentials lockout could not be recorded")

    def _matches_pin(self, material: Optional[bytes]) -> bool:
        """Whether these bytes ARE the pinned secret: sha256 hex, compare_digest.

        The pin's value is a hash of the secret and never the secret, so the two
        are compared as the hex texts the store holds and this computes, in
        constant time.  A pin row holding anything that is not text matches
        nothing, and `None` (a body with no secret this module can read) is the
        sha256 of no bytes, which matches nothing either.
        """
        stored = self._store.get(APPROVE_PIN_KEY)
        expected = stored.encode("utf-8") if isinstance(stored, str) else b""
        presented = hashlib.sha256(material or b"").hexdigest().encode("utf-8")
        return hmac.compare_digest(presented, expected)

    def _check_credentials(self, request: Request, body_secret: Any) -> str:
        """The credentials gate's own key: the body's secret, or the install token.

        Answers which kind of key the request was checked against, so the caller
        can pass it on: `KEY_KIND_PINNED_SECRET` once a pin decided the key, and
        `KEY_KIND_INSTALL_TOKEN` when the install token did.
        """
        material = _key_bytes(body_secret)
        if self._pinned():
            if not self._matches_pin(material):
                raise HTTPException(status_code=403, detail=SECRET_MISMATCH)
            if material is None:
                raise _refused()
            self._verify(request, material)
            return KEY_KIND_PINNED_SECRET
        self._verify(request, self._install_token())
        return KEY_KIND_INSTALL_TOKEN

    def _floor(self) -> float:
        """The oldest stamp this engine still accepts, from the kv table.

        Written by the purge in `_spend`, and only ever forward.  A key that is
        absent, and a value that is not a number, are no floor at all (0), so a
        hand-edited file refuses nothing instead of raising here.
        """
        return _nonce_floor(self._store.conn())

    def _check(self, request: Request, allow_install_token: bool) -> None:
        """The whole check, in the order the surface documents it.

        The key is the one `_key` answers for this route; the rest of the check
        is `_verify`, which is the same one the credentials route runs with the
        key its own body named.
        """
        self._verify(request, self._key(allow_install_token))

    def _verify(self, request: Request, key: Optional[bytes]) -> None:
        """The shared check over one key: headers, window, floor, MAC, then nonce.

        `key` is the one key this request is checked against, or None when this
        engine has none — a refusal whatever the request carries.  The headers
        are read whatever they hold, the expected MAC is computed only when every
        part of the request is usable, and the comparison runs either way —
        against an empty value when the request was never usable.  The nonce is
        spent only after the MAC matched, so a refused request leaves both the
        nonce and the floor exactly as they were.
        """
        stamp, nonce, presented = _presented(request)
        body = _raw_body(request)
        now = float(self._now())
        floor = self._floor()
        usable = (
            key is not None
            and body is not None
            and bool(presented)
            and bool(stamp)
            and bool(nonce)
            and _in_window(stamp, now)
            and _above_floor(stamp, floor)
            and NONCE_RE.fullmatch(nonce) is not None
        )
        expected = b""
        if usable and key is not None:
            expected = compute_mac(
                key,
                request.scope.get("method") or "",
                _path_with_query(request.scope),
                stamp,
                nonce,
                body,
            ).encode("ascii")
        matched = hmac.compare_digest(expected, presented.encode("utf-8", "replace"))
        if not (usable and matched):
            raise _refused()
        self._spend(nonce, stamp)

    def _spend(self, nonce: str, stamp: str) -> None:
        """Remember *nonce*, and the request's own stamp, once.

        The insert is what makes a nonce single-use: a second presentation of the
        same text is a primary-key conflict, and a conflict is the same 403 as
        every other refusal.  The row carries the request's `ts` beside the
        moment it was seen, so a clock that jumps forward (pruning as it goes)
        and then back cannot re-admit a captured request whose stamp still fits
        the window.

        The delete keeps the table bounded, and drops a row only once BOTH of its
        stamps are old: `seen_at` and `ts` each below `now - retention`, where the
        retention is the larger of `NONCE_RETENTION_S` and
        `MAC_WINDOW_S + NONCE_MARGIN_S`.  One old stamp is not enough — the row
        exists to refuse a replay, and a replay is possible for as long as its own
        `ts` fits the window.

        The cutoff that delete used is written to the kv table as `nonce_floor` in
        the SAME transaction, and only forward: the floor is the newest cutoff any
        purge has used, so a row the purge took can never be replayed off a clock
        that jumped back.  A failure of any statement here refuses the request it
        was part of.
        """
        at = float(self._now())
        cutoff = at - max(NONCE_RETENTION_S, MAC_WINDOW_S + NONCE_MARGIN_S)
        try:
            with self._store.tx() as db:
                db.execute(
                    "INSERT INTO nonces(nonce, seen_at, ts) VALUES(?, ?, ?)",
                    (nonce, at, int(stamp)),
                )
                db.execute(
                    "DELETE FROM nonces WHERE seen_at < ? AND ts < ?",
                    (cutoff, cutoff),
                )
                floor = max(_nonce_floor(db), cutoff)
                db.execute(
                    "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)",
                    (NONCE_FLOOR_KEY, json.dumps(floor)),
                )
        except Exception:  # noqa: BLE001 - a nonce that cannot be spent is a refusal
            raise _refused() from None


# ---------------------------------------------------------------- the lease


def _lease_record(row: Any) -> Optional[dict]:
    """A stored lease as a dict, or None when the row is absent or unreadable."""
    if row is None:
        return None
    try:
        value = json.loads(row["value"])
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _lease_live(lease: Optional[dict], at: float) -> bool:
    """Whether *lease* is held at *at*: it exists, and its TTL has not passed."""
    if not isinstance(lease, dict):
        return False
    expires = lease.get("expires_at")
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        return False
    return float(expires) > at


def _stored_cursor(db: Any) -> Optional[int]:
    """The lease cursor in the kv table, or None when no integer is stored."""
    row = db.execute(
        "SELECT value FROM kv WHERE key=?", (LEASE_CURSOR,)
    ).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(row["value"])
    except (TypeError, ValueError):
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


class Lease:
    """The one holder of this engine's lease, and the cursor it advances.

    `acquire` takes the lease, renews it for the same holder, or answers that
    another holder has it — all in one transaction, so two acquirers racing each
    other cannot both be told yes.  `set_cursor` is the holder's alone, refuses a
    cursor past the newest event, and only ever moves the cursor forward; a lower
    value leaves the stored one, and the stored one is what it answers.
    """

    def __init__(
        self,
        store: Store,
        now: Callable[[], float],
        ttl: float = LEASE_TTL_S,
    ) -> None:
        self._store = store
        self._now = now
        self._ttl = float(ttl)

    def acquire(self, holder: str) -> dict:
        """Take the lease for *holder*, renew it, or answer that it is held.

        A lease that is absent or past its TTL is free, and so is one already held
        by this holder (that is a renewal).  One held by anyone else is not taken:
        the holder is answered false and keeps the lease until its TTL passes.
        The cursor comes back either way, so a new holder reads where the last
        one got to.
        """
        at = float(self._now())
        with self._store.tx() as db:
            row = db.execute(
                "SELECT value FROM kv WHERE key=?", (LEASE_KEY,)
            ).fetchone()
            current = _lease_record(row)
            if _lease_live(current, at) and current.get("holder") != holder:
                return {"held": False, "cursor": _stored_cursor(db)}
            record = {"holder": holder, "expires_at": at + self._ttl}
            db.execute(
                "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)",
                (LEASE_KEY, json.dumps(record)),
            )
            return {"held": True, "cursor": _stored_cursor(db)}

    def set_cursor(self, holder: str, cursor: int) -> int:
        """Advance *holder*'s cursor to at least *cursor* and answer the stored one.

        The cursor belongs to the lease's live holder: with no unexpired lease, or
        with one held by another holder, this is a `409 LEASE_NOT_HELD` and
        nothing is written.  A cursor past the newest event this engine holds —
        `COALESCE(MAX(id),0)`, read inside the same transaction — is a `422
        CURSOR_AHEAD`: that reader could not have read it, and a cursor past the
        events would stop retention from ever deleting one.  A value below the
        stored one is not an error and not a write — the cursor never goes
        backwards, so a reader that already passed that point is never asked to
        read an event again.
        """
        at = float(self._now())
        with self._store.tx() as db:
            row = db.execute(
                "SELECT value FROM kv WHERE key=?", (LEASE_KEY,)
            ).fetchone()
            lease = _lease_record(row)
            if not _lease_live(lease, at):
                raise HTTPException(
                    status_code=409,
                    detail=f"{LEASE_NOT_HELD}: the lease is not held",
                )
            if lease.get("holder") != holder:
                raise HTTPException(
                    status_code=409,
                    detail=f"{LEASE_NOT_HELD}: another holder holds the lease",
                )
            wanted = int(cursor)
            newest = db.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()
            if wanted > int(newest[0]):
                raise HTTPException(
                    status_code=422,
                    detail=f"{CURSOR_AHEAD}: the cursor is past the newest event",
                )
            stored = _stored_cursor(db)
            value = wanted if stored is None else max(stored, wanted)
            db.execute(
                "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)",
                (LEASE_CURSOR, json.dumps(int(value))),
            )
            return int(value)