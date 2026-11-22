"""api.py: the engine's HTTP surface — health, status, bots, orders, fills, kill.

Every route but `GET /health` needs the engine's bearer token.  The header is
compared with `hmac.compare_digest` — looked up on the `hmac` module at call
time — and the comparison runs even when the header is missing or carries
another scheme, against an empty value, so one refusal takes the same time
whatever was sent.  A mismatch is a 401 that says nothing more.  `/health` is
the one anonymous route and it carries five keys and nothing else: whether the
heartbeat is fresh, that live trading is off, how old the heartbeat is, whether
the owner's credentials are in memory (`credentials`, "ready" or "not_ready"),
and whether a pin exists at all (`pinned`).  It reads the heartbeat file, the
pin's row and the credentials slot — no balance, no exchange, and no bot — and
it never raises: a store that cannot answer whether this engine is pinned is
answered `503` with `pinned` true and `credentials` "not_ready", because an
engine that cannot say whether it has a pin has to read as one that does.

A body this surface cannot read is a 422 that names the FIELDS that failed and
nothing else: the app's own `RequestValidationError` handler answers
`{"code": "INVALID", "fields": [...]}`, with each field's location joined by
dots and the leading `body` dropped, so no value the request sent is ever echoed
back in a refusal.  `POST /credentials` adds two refusals of its own to that
shape: a body naming the same key twice has no single value for it, so such a
body is the same `422`, naming the duplicated fields and never a value, and a
body that does not decode as UTF-8, does not parse as JSON, or does not parse
into an object is that `422` naming no field at all.  That route parses its
captured bytes ONCE, in its own dependency, with a hook that records a repeated
name, and builds the model from what that one parse answered; FastAPI never
parses the body a second time, so the object the route acts on is always the one
the MAC was computed over.

Every route reads or writes one of the engine's two books (`books.py`).  A bot
trades the book its own row's `mode` names, a fill row carries the book it was
booked on, and a response reports the figures of the book it is about rather
than a total of the two: the positions, equity, realized profit and benchmark of
a bot are its current book's, and the dry figures stay the simulator's.

A new bot is always a dry bot, and its capital arrives exactly once, from its own
creation, through `gateway.seed_dry` inside the same transaction that writes the
bot row.  The one route that moves a bot from one book to the other is
`POST /bots/{bot_id}/mode`, which goes through `Runner.switch_mode` and never
touches an exchange itself, and a live-mode bot also has to be approved by its
owner before it is recentered or resumed.

Several routes are privileged: the mode switch, the live switches, clearing a
halt — it re-initialises live grids and re-bases the marks a drawdown is
measured against, which is the same weight of decision as switching a bot's book
— and forgetting the owner's credentials, plus, inside their own handlers, a live
bot's recenter and resume.  The check they need is a callable `create_app` takes
(`require_privileged`), and the module's own default refuses every request, so
the surface is deny-by-default
until an approval is wired in.  The engine wires `auth.Authenticator.require`
there: a privileged request presents the bearer token AND a MAC over the request
it sends, in three headers — `X-Crow-Timestamp`
(integer epoch seconds within a minute of the engine's clock), `X-Crow-Nonce`
(16 to 128 characters of `[A-Za-z0-9_-]`, used once and remembered in the store
so it stays spent across a restart) and `X-Crow-Signature` (lowercase hex
HMAC-SHA256 over the method, the path with its query string, the stamp, the
nonce and the body's SHA-256).  A request is refused as a 403 that names nothing
but `APPROVAL_INVALID`, whatever was wrong with it; the bearer token is still
checked first, so an unauthenticated request is a 401, a refused approval a 403,
and a malformed body a 422.  The body the MAC covers is read by
`auth.BodyCaptureMiddleware`, which `create_app` installs for every request that
carries a signature header and replays the same bytes to the handler.

That strict gate never takes the install token, because the install token is a
key on only a few routes: the two lease routes below, and `POST
/credentials/check`.  Those carry a second dependency (`_install_ok_gate`) that
asks the same approval with `allow_install_token=True` —
`auth.Authenticator.require_install_ok` when the engine's own rail is wired in —
so a mode switch, a switch, a cleared halt, a live bot's recenter or resume, a
credentials disconnect and a credentials forget need the owner's secret while a
lease does not.  An injected `require_privileged` is used for both gates exactly
as it is given.

The two cap routes are this surface's own bounds: `GET /caps` — the bearer token
alone, since it moves nothing — reports the caps in force, the ceilings above
them and each book's use today, and `POST /caps` — the strict gate — lowers one
or more of them.  The environment is the ceiling: a cap may be set to zero or to
its ceiling and never above it, a partial body changes only what it names, and a
refusal is a `422` carrying the code and a plain reason that names the cap and
nothing else.  Nothing is written when any entry of the body is refused.  Zero is
a value of every cap but the portfolio drawdown percentage, which is a threshold
that zero would make mean "halt on any dip": that one cap refuses it as
unusable, and a stored zero is healed to its ceiling at startup.  A body that
RAISES the `ai` capital is measured against the live book as it stands before
anything is written — the extra against the live USDC the account still has
unallocated, which already reserves that capital — and refused `422
AI_CAPITAL_SHORT` when the book cannot fund it; a lowering, a value kept as it
is, and a raise on a live book that cannot be read are never checked.

The owner's credentials are four routes, mounted only when the surface is given
a `credentials.CredentialSlot` (an engine built without one has no live key to
install and offers no such route at all): `POST /credentials/check` judges a key
pair and installs nothing behind the install-token gate, `POST /credentials`
installs one behind its OWN MAC — `auth.Authenticator.require_credentials`, which
keys the signature with the approval secret the request's body carries once a pin
exists and with the install token while there is none — `DELETE
/credentials` drops the live route behind the strict gate, and `POST
/credentials/forget` drops the pin itself behind that same strict gate, so the
engine reads as a first install again.  A key refusal is a
422 carrying the refusal code and its plain message; a body carrying a secret
that is not the pinned one is `403 SECRET_MISMATCH` — answered before the
stamp, the nonce and the MAC are looked at, and asked again inside the store's
own transaction, because the rail's answer was decided against the pin as it
stood when the request arrived — a signature that does not match is the uniform
`403 APPROVAL_INVALID`, a body that names one field twice is the same `422
INVALID` the rest of the surface answers (naming the duplicated fields, never a
value), a body this build cannot read is that `422` naming no field at all, and
five wrong secrets inside a minute are `429 RATE_LIMITED` for the minute that
follows — a lockout that shuts a guesser out and not the owner, since a push
carrying the pinned secret in its body and signing those bytes with it is still
served, and clears it.  A disconnect while a live order is resting is `409
LIVE_ORDERS_OPEN`, and a forget is refused the same way — and `409 LIVE_BOTS`
while a live bot that could still act trades the live book or the AI's live
switch is on (a STOPPED bot, which the kill switch or its own stop leaves in live
mode, is not one: it cannot place, resume or switch books) — because an engine
unpinned under one of them has no key to settle what it has open.

The lease is the other thing this surface offers the owner's client, and both of
its routes are privileged in the same way: `POST /lease` takes, renews or
declines one holder's lease and answers the cursor that holder reads events
from, and `POST /lease/cursor` names the holder and advances that holder's
cursor, monotonically, while the lease is held — refusing a cursor past the
newest event the engine holds.  Event retention never deletes past the cursor.

Every mutation runs under `gateway.lock` — the lock a cycle holds — because a
request and a running cycle must never build a book at the same time.  A pause
is the one of them that lets the lock go between its passes: it holds it for
each cancel-and-reconcile pass (the pass that finds the book clear does the whole
of the pause's write inside that same section) and never for the wait between two
passes, so a pause can never make a kill switch wait.  That window is why a pause
names its bot in the runner's pausing set for as long as it runs: the resume,
recenter and mode routes answer `409 PAUSE_IN_PROGRESS` instead of moving a bot
whose sweep is still going, and a second pause of that bot is refused the same
way rather than sweeping it twice.  The reason a pause wrote
(`bot:paused_reason:<id>`) is reported only while the bot's own row says PAUSED,
and a stop or the kill switch takes it away with the status, so a note left on a
bot that is not paused never reads as an owner's pause.  The kill switch is the
other exception to the order and not to the lock: it halts first, without the
lock, so a kill never queues behind a cycle, and only then takes the lock to
sweep both books and stop the bots.  Clearing a halt is an
acknowledgement rather than a reset: each in-play book's portfolio high-water
mark is written down to that book's own equity and every grid bot re-initialises
its book, so the drawdown the stop fired on cannot fire again on the next cycle.
A book nothing can price has its mark reset instead of blocking the clear, and
the next priced cycle ratchets a fresh one.

`GET /status` reports three things beside the keys it has always carried: the
owner's two live switches and the ceiling above them, exactly as `Switches`'
snapshot answers them; one drawdown entry per book — that book's own portfolio
equity, the mark it is measured against, and the percentage between the two,
floored at zero and null wherever either number is unknown (a book no bot trades
has no equity, and a mark nobody wrote is no mark); and the products this engine
may trade.  `GET /orders?book=` is the order rows' own read side: the resting
orders (`PENDING_SUBMIT` and `OPEN`) of both books or of the one the query names,
oldest first, each named by the client order id the engine minted for it and
carrying no exchange order id, no note and no fill figures.  A `book` that is
neither of the two names nor absent is the surface's usual `422 INVALID`, naming
the field and echoing nothing that was sent.

`GET /price?product=<id>` is the surface's one quote, and it is the bearer
token's alone: it moves nothing and settles nothing, so it is not privileged.  It
answers the mid of the product's cached market snapshot — the snapshot cache is
the only place it reads, and it never calls `price_for` or any exchange path —
as a decimal string, beside `ts`, that snapshot's own stamp.  A product this
engine does not trade, and no product at all, is a `400` that says so and nothing
else; a cache that cannot price the product (no snapshot, or one the engine's own
usability rule refuses) is a `503` carrying a plain sentence.

The event feed is the surface's read side of that history: `GET /events?after=<id>`
answers the events after the id it was given, oldest first, at most a page of them,
with the id the next page starts from and `reset` beside it — true for the one
answer whose cursor is past the newest event the engine holds (a table that was
wiped), which tells the client to start again from the id it is given.  It writes
no event of its own, so a reader only ever sees what the engine did; the rows the
surface's own routes write carry their kind (`halt`, `live_switch`, `caps`,
`credentials`) and the ids and names of things, never a value of a key or a
secret.  A request that carries `X-Crow-Source: mcp` has the events it writes
tagged `"source": "mcp"` by the store (`EventSourceMiddleware`, which sets that
tag for the length of one request and no longer), so a reader can tell the
agent's actions from the owner's.

Handlers are plain functions, so FastAPI runs them on worker threads; the store
hands every thread its own sqlite connection, so a handler can read while the
runner's thread writes.  Money is `Decimal` inside and a string in JSON.
"""

from __future__ import annotations

import csv
import hmac
import json
import logging
import math
import re
import tempfile
import time
from collections.abc import Callable, Mapping
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from . import records
from .ai_orders import AiOrders, AiRefused
from .auth import (
    APPROVE_PIN_KEY,
    HOLDER_RE,
    MIN_KEY_BYTES,
    SECRET_MISMATCH,
    Authenticator,
    BodyCaptureMiddleware,
    Lease,
    pin_exists,
)
from .benchmark import KEY_PREFIX, LEGACY_PREFIX, Benchmark
from .books import (
    APPROVAL_INVALID,
    BOOKS,
    DRY,
    LIVE,
    LIVE_DISABLED,
    LIVE_NEEDS_OWNER,
    SWITCH_AI_LIVE,
    SWITCH_LIVE,
    ModeRefused,
    Switches,
)
from .credentials import (
    EPOCH_KEY,
    LIVE_ORDERS_OPEN,
    MESSAGE_FORGOTTEN,
    MESSAGE_REMOVED,
    PORTFOLIO_KEY,
    CredentialSlot,
    KeyCheck,
)
from .gateway import NOT_BOT_OWNERS, PORTFOLIO_OWNER, OrderGateway
from .ledger import AI_CAPITAL_CURRENCY
from .limits import (
    CAP_KIND_COUNT,
    CAP_SPECS,
    CapRefused,
    CapWindow,
    Limits,
    cap_value,
)
from .money import ProductSpec
from .runner import (
    PAUSED_REASON_PREFIX,
    PauseChanged,
    Runner,
    StartupRefused,
    realized_pnl,
)
from .store import (
    ACTIVE,
    BOT_ID_RE,
    EVENT_SOURCE,
    EVENT_SOURCE_MCP,
    LIVE_STATUSES,
    PAUSED,
    STOPPED,
    Store,
)
from .strategies.base import Strategy

D = Decimal
log = logging.getLogger("crow_coinbase.api")

# ---------------------------------------------------------------- constants
# The one environment variable this module names: its absence refuses a start.
ENV_TOKEN = "CROW_COINBASE_ENGINE_TOKEN"
MISSING_TOKEN = "CROW_COINBASE_ENGINE_TOKEN is missing or blank"
WHITESPACE_TOKEN = "CROW_COINBASE_ENGINE_TOKEN must not contain whitespace"
SHORT_TOKEN = "CROW_COINBASE_ENGINE_TOKEN is shorter than 32 characters"
# The shortest token this engine serves with.  A token is compared byte for
# byte, so it is never trimmed: whitespace in the configured value is a mistake
# to refuse, not one to repair into a different secret.
MIN_TOKEN_CHARS = 32

# The largest exponent an amount may carry: 1e16 and up is a typo or an attack,
# and it is refused before it reaches any arithmetic.
MAX_AMOUNT_EXPONENT = 15

# What a failed POST /bots says: the exception text goes to the log, not out.
CREATE_FAILED = "bot creation failed"

# What POST /bots/{bot_id}/pause answers when its sweep could not clear the bot's
# book.  The sentence is fixed: the exchange's own words (and the exception text)
# are logged and never quoted, and it says what to do, because a bot left PAUSED
# by a failed sweep takes the same request again to retry the cancel.
PAUSE_INCOMPLETE = (
    "PAUSE_INCOMPLETE: some of this bot's orders may still be waiting on "
    "Coinbase; press Pause again to retry"
)

# What POST /bots/{bot_id}/pause answers when the bot it names was only just
# asked to pause and is still PAUSED: the first press is still the one being
# answered, so a second is not a second sweep.  A pause of an ACTIVE bot is never
# debounced, and neither is one of a bot whose last pause attempt is older than
# `PAUSE_DEBOUNCE_S`.
PAUSE_TOO_SOON = (
    "PAUSE_TOO_SOON: this bot was only just asked to pause; wait a few seconds "
    "and press Pause again"
)
PAUSE_DEBOUNCE_S = 10.0

# What POST /bots/{bot_id}/pause answers when the bot it names was changed while
# its book was being swept: a stop or a kill marked it STOPPED meanwhile, or its
# mode, params or grid epoch moved.  Nothing of the pause was written then, so
# this is a conflict to look at, not a failed sweep.
PAUSE_CHANGED = (
    "PAUSE_CHANGED: this bot was changed while it was being paused; check it and "
    "press Pause again if it is still needed"
)

# What the routes that move a bot (resume, recenter, a book switch) answer while
# a pause of it is still in flight, and what a second pause of that bot answers:
# the pause waits between its passes, and a move — or another sweep — made in
# that window would be written over by the pause's own final write.
PAUSE_IN_PROGRESS = (
    "PAUSE_IN_PROGRESS: this bot is being paused; wait a few seconds and try again"
)

# The kv key holding a bot's pause-failure episode: set when the alert is
# written and cleared by the next pause that completes, so two failed presses
# inside one episode say it once and a later failure is news again.
PAUSE_ALERT_PREFIX = "api:pause_alert:"
PAUSE_FAILED = (
    "bot paused but its waiting orders may still be on the exchange"
)

# How many bots may exist at once and how many may be created in a rolling hour.
# A bot whose status is not STOPPED counts against the first — a paused bot can
# still be resumed and is still one the engine carries — and every row counts
# against the second whatever its status.  Both are refused `429 BOT_LIMIT`
# before the body is looked at, so nothing is written by a create that arrives
# over either ceiling: no bot row and no dry seed.
MAX_OPEN_BOTS = 20
MAX_BOT_CREATES_PER_HOUR = 10

AUTH_SCHEME = "Bearer"
BEARER_PREFIX = f"{AUTH_SCHEME} "
UNAUTHORIZED = "unauthorized"

# A heartbeat older than this many poll windows means the engine is not cycling.
HEALTH_WINDOWS = 2
# The startup grace: this many poll windows may pass with no heartbeat at all.
DEFAULT_GRACE_WINDOWS = 2

# The event level and how many of them `/status` reports.
ALERT_LEVEL = "ALERT"
ALERT_LIMIT = 10

# The event feed's page: the size it answers with when asked for nothing, and the
# most one page ever holds.  A `limit` past the maximum is clamped down to it —
# the clamp is a page size, not a refusal — while a value this surface cannot read
# as a count is the same `422 INVALID` every other route answers.
EVENTS_DEFAULT_LIMIT = 50
EVENTS_MAX_LIMIT = 200
EVENTS_MIN_LIMIT = 1

# The header an MCP client carries, and the one value of it the store tags an
# event with.  The comparison is exact and case-sensitive: any other value, and
# no header at all, leaves the request's events untagged.
SOURCE_HEADER = "x-crow-source"
SOURCE_MCP_BYTES = EVENT_SOURCE_MCP.encode("ascii")

# What POST /bots/{bot_id}/mode answers when a live switch was not acknowledged.
LIVE_ACK = "live needs acknowledge_live: true"
# What POST /switches answers when no field of its body names a switch.
NO_SWITCH = "send live_enabled and/or ai_live_enabled"
# What POST /switches answers while the ceiling forbids live, whatever is asked.
CEILING_OFF = (
    f"{LIVE_DISABLED}: the live ceiling (CROW_COINBASE_LIVE) is off, so no "
    "switch can turn live trading on"
)
# What POST /lease answers when its holder is not a holder this engine can tell
# apart from another one: bounded, and free of whitespace and separators a
# different holder could be built out of.
HOLDER_INVALID = "holder must be 1-128 characters of [A-Za-z0-9._:-]"
# What POST /lease/cursor answers for a cursor that is not a count.
CURSOR_INVALID = "cursor must be a non-negative integer"
# What a body this surface cannot read answers with: the fields that failed, and
# never a value that was sent.
INVALID_BODY = "INVALID"
# What POST /credentials answers for `repin` on an engine with no pin: there is no
# pinned portfolio for a repin to move away from.
REPIN_NEEDS_PIN = (
    "repin names the portfolio to move to, and this engine has no pinned "
    "portfolio yet: connect the key once without it"
)
# What DELETE /credentials answers while a live order is still resting.
LIVE_ORDERS_OPEN_MESSAGE = (
    "a live order is still resting on the account; cancel it before removing "
    "the credentials"
)
# What POST /credentials/forget answers while a bot trades the live book, or while
# the AI's own live switch is on: an engine that is unpinned under a live bot has
# no key to settle what that bot has open, so the bots go back to practice first.
LIVE_BOTS = "LIVE_BOTS"
LIVE_BOTS_MESSAGE = "Switch live bots back to practice mode first."
# What GET /price answers for a product this engine does not trade (a missing one
# included), and what it answers when the cache holds no snapshot it may quote
# — none at all, or one the engine's own usability rule refuses.  Both are plain
# sentences that name nothing else.
PRICE_UNKNOWN_PRODUCT = "That product is not one this engine trades."
PRICE_UNAVAILABLE = "No price is available for that product right now."

# The `Limits` FIELD the AI's live capital is kept under: the one cap whose raise
# is measured against the live book before it is written.  It is named by its
# field and never by its environment variable, which `limits.py` owns alone, and
# the variable a refusal names is read off the cap's own spec there.
AI_CAPITAL_FIELD = "ai_capital_usd"
# What POST /caps answers when the raise it was asked for is more than the live
# book has free: the cap it named, and no amount of anything.
AI_CAPITAL_SHORT = "AI_CAPITAL_SHORT"

YEAR_RE = re.compile(r"^\d{4}$")
CSV_NAME = "fills.csv"
CSV_PREFIX = "fills-"
CSV_SUFFIX = ".csv"
ALL_YEARS = "all"

# The strategy that funds a target mix instead of buying a position: it keeps no
# cost basis, so it has no realized profit to report.
REBALANCE = "rebalance"


# ---------------------------------------------------------------- tokens


def token_or_refuse(token: Optional[str]) -> str:
    """The configured API token, or `StartupRefused` when it may not be served.

    Shared by `create_app` and the process wrapper: a blank token is not a
    running engine with unauthenticated routes, it is an engine that refuses to
    start.  Called before anything is opened or written.  The value is taken as
    it was configured — whitespace anywhere in it, or a token short enough to
    guess, is refused rather than trimmed into a different secret.
    """
    text = "" if token is None else str(token)
    if not text:
        raise StartupRefused(MISSING_TOKEN)
    if any(character.isspace() for character in text):
        raise StartupRefused(WHITESPACE_TOKEN)
    if len(text) < MIN_TOKEN_CHARS:
        raise StartupRefused(SHORT_TOKEN)
    return text


def _presented_token(authorization: Optional[str]) -> bytes:
    """The bytes a request presented as its bearer token; empty when it named none.

    A missing header and a header of another scheme both answer an empty value,
    so the comparison below always runs and always runs on bytes.
    """
    if not authorization:
        return b""
    header = str(authorization)
    if not header.startswith(BEARER_PREFIX):
        return b""
    return header[len(BEARER_PREFIX) :].strip().encode("utf-8")


# ---------------------------------------------------------------- refusals


def _invalid(detail: str) -> HTTPException:
    """422: the request cannot be honoured as sent."""
    return HTTPException(status_code=422, detail=detail)


def _unknown(detail: str) -> HTTPException:
    """404: no such bot."""
    return HTTPException(status_code=404, detail=detail)


def _conflict(detail: str) -> HTTPException:
    """409: a state the request does not fit."""
    return HTTPException(status_code=409, detail=detail)


def _unavailable(detail: str) -> HTTPException:
    """503: something the surface needs cannot be reached right now."""
    return HTTPException(status_code=503, detail=detail)


def _bad_gateway(detail: str) -> HTTPException:
    """502: the exchange (or the layer in front of it) failed the call."""
    return HTTPException(status_code=502, detail=detail)


# ---------------------------------------------------------------- request bodies


def _no_boolean(value: Any, where: str) -> Any:
    """A JSON number as it arrived, or a refusal when it is `true`/`false`.

    Pydantic would read a boolean as a number for a union field that admits
    `int`, turning `true` into a capital of 1; the check is on the raw body
    value, before that happens.
    """
    if isinstance(value, bool):
        raise ValueError(f"{where} must be a number, not a boolean")
    return value


class BotCreate(BaseModel):
    """The whole POST /bots body.

    `extra="forbid"` is load-bearing: a new bot is always a dry bot, so a body
    carrying a `mode` (or any other field this build does not know) is refused
    rather than quietly ignored.  Moving a bot onto the live book is the mode
    route's job, with its own checks and its own approval.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    product: str
    strategy: str
    params: dict[str, Any]
    capital_quote: str | int | float
    capital_base: str | int | float

    @field_validator("capital_quote", "capital_base", mode="before")
    @classmethod
    def _not_a_boolean(cls, value: Any, info: ValidationInfo) -> Any:
        return _no_boolean(value, str(info.field_name))


class Recenter(BaseModel):
    """The whole POST /bots/{id}/recenter body: one new center, nothing else."""

    model_config = ConfigDict(extra="forbid")

    center: str | int | float

    @field_validator("center", mode="before")
    @classmethod
    def _not_a_boolean(cls, value: Any, info: ValidationInfo) -> Any:
        return _no_boolean(value, str(info.field_name))


# What a route that re-bases a high-water mark says when it was not acknowledged:
# the write it makes and the body that authorises it.
HALT_CLEAR_ACK = (
    "clearing the halt re-bases the portfolio high-water mark to the current "
    'equity; send {"acknowledge_rebase": true} to acknowledge that and clear it'
)
RESUME_ACK = (
    "resuming re-bases the bot's high-water mark to its current equity; send "
    '{"acknowledge_rebase": true} to acknowledge that and resume it'
)


class Acknowledge(BaseModel):
    """The whole body of a route that re-bases a high-water mark: one explicit yes.

    `extra="forbid"` and the validator keep the acknowledgement literal: only a
    JSON `true` clears a halt or resumes a bot, never the string `"true"` and
    never a field this build does not know.
    """

    model_config = ConfigDict(extra="forbid")

    acknowledge_rebase: bool

    @field_validator("acknowledge_rebase", mode="before")
    @classmethod
    def _only_a_boolean(cls, value: Any) -> Any:
        if not isinstance(value, bool):
            raise ValueError("acknowledge_rebase must be true or false")
        return value


class SwitchMode(BaseModel):
    """The whole POST /bots/{id}/mode body: the book to move to, and its budget.

    `extra="forbid"` keeps a field this build does not know from riding along.
    The two capital amounts are the live book's budget and only a switch TO the
    live book takes them; they are read as numbers (never as booleans, which
    Pydantic would otherwise accept as 1 and 0), and the runner validates them
    with the rest of the switch.

    `acknowledge_live` is taken exactly as it arrived rather than coerced: only a
    JSON `true` authorises a live switch, and every other value — absent, false,
    the string `"true"`, a number — is refused with the message below.
    """

    model_config = ConfigDict(extra="forbid")

    mode: Literal["dry", "live"]
    capital_quote: Optional[str | int | float] = None
    capital_base: Optional[str | int | float] = None
    acknowledge_live: Any = None

    @field_validator("capital_quote", "capital_base", mode="before")
    @classmethod
    def _not_a_boolean(cls, value: Any, info: ValidationInfo) -> Any:
        return _no_boolean(value, str(info.field_name))


class SwitchesBody(BaseModel):
    """The whole POST /switches body: one or both of the owner's live switches.

    At least one field has to be present, and each present one has to be a JSON
    boolean: Pydantic would read `"yes"` or `1` as true for a `bool` field, and a
    switch nobody spelled out is refused rather than guessed at.
    """

    model_config = ConfigDict(extra="forbid")

    live_enabled: Optional[bool] = None
    ai_live_enabled: Optional[bool] = None

    @field_validator("live_enabled", "ai_live_enabled", mode="before")
    @classmethod
    def _only_a_boolean(cls, value: Any, info: ValidationInfo) -> Any:
        if value is None:
            return value
        if not isinstance(value, bool):
            raise ValueError(f"{info.field_name} must be true or false")
        return value

    @model_validator(mode="after")
    def _names_a_switch(self) -> "SwitchesBody":
        if self.live_enabled is None and self.ai_live_enabled is None:
            raise ValueError(NO_SWITCH)
        return self


def _acknowledged(body: Optional[Acknowledge]) -> bool:
    """True only for a body that says so: no body is not an acknowledgement."""
    return body is not None and body.acknowledge_rebase is True


class CapsBody(BaseModel):
    """The whole POST /caps body: the caps to set, by the variable that sets them.

    `extra="forbid"` keeps a field this build does not know from riding along, so
    a body carrying anything beside `caps` is refused as a body.  The values
    themselves are taken as they arrived — a string, a number, a boolean, null —
    because the cap check refuses each of those in its own words rather than a
    model quietly coercing one into a number nobody sent.
    """

    model_config = ConfigDict(extra="forbid")

    caps: dict[str, Any]


class LeaseBody(BaseModel):
    """The whole POST /lease body: which holder wants the lease, and nothing else.

    The holder is a `str` and stays one: an integer, a list or a null is refused
    rather than coerced into a holder name nobody sent.  Its shape (length and
    alphabet) is checked by the route, so the refusal names the field and says
    nothing about which holder holds the lease.
    """

    model_config = ConfigDict(extra="forbid")

    holder: str


class LeaseCursor(BaseModel):
    """The whole POST /lease/cursor body: which holder moves the cursor, and where to.

    `extra="forbid"` keeps a field this build does not know from riding along.
    The holder is a `str` and stays one — its shape is checked by the route, which
    refuses one the lease cannot belong to — and the cursor has to be a JSON
    integer: a boolean (which Pydantic would read as 1 or 0), a fractional
    number, a digit string and a negative value are all refused rather than read
    into the cursor a retention window is measured against.
    """

    model_config = ConfigDict(extra="forbid")

    holder: str
    cursor: int

    @field_validator("cursor", mode="before")
    @classmethod
    def _only_an_integer(cls, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(CURSOR_INVALID)
        return value

    @field_validator("cursor")
    @classmethod
    def _not_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError(CURSOR_INVALID)
        return value


# ---------------------------------------------------------------- the AI's orders


class AiPreviewBody(BaseModel):
    """The whole POST /ai/previews body: one proposed order, and nothing else.

    `extra="forbid"` keeps a field this build does not know from riding along, so
    a body carrying anything beside the four it names is refused as a body rather
    than quietly dropped.  The side is one of the two literals the engine trades,
    and the amounts travel as text: `AiOrders.preview` parses them itself, so a
    size or a price it cannot read is refused in the surface's own words and
    stores nothing.
    """

    model_config = ConfigDict(extra="forbid")

    product: str
    side: Literal["BUY", "SELL"]
    size: str
    limit_price: str


class AiApproveBody(BaseModel):
    """The whole POST /ai/previews/{id}/approve body: the hash the owner was shown.

    `extra="forbid"` for the same reason: the approval is one hash and nothing
    else, so a body that carries a `force` or any other field this build does not
    know is refused as a body.
    """

    model_config = ConfigDict(extra="forbid")

    hash: str


# ---------------------------------------------------------------- credentials bodies


class CredentialCheckBody(BaseModel):
    """The whole POST /credentials/check body: a key pair to look at, nothing else.

    `extra="forbid"` keeps a field this build does not know from riding along,
    and both parts stay text: nothing here is coerced into a key the caller did
    not send.
    """

    model_config = ConfigDict(extra="forbid")

    key_name: str
    private_key: str


class CredentialBody(BaseModel):
    """The whole POST /credentials body: the key, and the secret that pins it.

    `approve_secret` has to be at least `MIN_KEY_BYTES` characters long, because a
    shorter one is not a weak approval key but no key at all; a shorter secret is
    refused HERE, before the route or the engine sees it.  `repin` is taken
    exactly as it arrived rather than coerced: only a JSON `true` moves a pinned
    portfolio, and every other value — absent, false, the string `"true"`, a
    number — is refused as a field this build cannot read.
    """

    model_config = ConfigDict(extra="forbid")

    key_name: str
    private_key: str
    approve_secret: str = Field(min_length=MIN_KEY_BYTES)
    repin: bool = False

    @field_validator("repin", mode="before")
    @classmethod
    def _only_a_boolean(cls, value: Any) -> Any:
        if not isinstance(value, bool):
            raise ValueError("repin must be true or false")
        return value


class DuplicatedBodyFields(Exception):
    """A body that names one field twice, answered as the surface's `422 INVALID`.

    Raised by the `POST /credentials` dependency from the ONE parse of the
    captured bytes, before that parse's object is read into a model: a model
    keeps only the last value a name was given, and an approval made on one of
    two secrets says nothing about the other.  The exception carries field NAMES
    and nothing else, so the answer to it can carry nothing a request sent.
    """

    def __init__(self, fields: list[str]) -> None:
        super().__init__(INVALID_BODY)
        self.fields = list(fields)


# ---------------------------------------------------------------- approval


def require_privileged(request: Request) -> None:
    """The approval a privileged route needs, and the default that denies it.

    Nothing is approved here: every request is refused with `APPROVAL_INVALID`,
    and the refusal says nothing about a request it never looked at.  The engine
    wires `auth.Authenticator.require` in over this, and `create_app` takes the
    callable, so a test (or another build) supplies its own check instead.
    """
    raise HTTPException(status_code=403, detail=APPROVAL_INVALID)


# The refusal above, under its own name: `create_app` compares by identity to tell
# the module's deny-by-default apart from an approval a caller injected, so an
# injected one is never quietly replaced by anything.
DENY_ALL = require_privileged


# ---------------------------------------------------------------- money parsing


def _amount(value: Any, field: str) -> D:
    """A non-negative finite `Decimal` from a JSON string or number.

    A number goes through `Decimal(str(value))`, never `Decimal(float)`, so no
    binary rounding is introduced on the way in.  A boolean is refused instead
    of being read as 1/0, NaN and infinity are refused here because every later
    comparison would answer false for them, and an amount whose leading digit
    sits past `MAX_AMOUNT_EXPONENT` is refused rather than carried into the cap
    and the ledger.
    """
    if isinstance(value, bool):
        raise _invalid(f"{field} must be a number, not a boolean")
    try:
        amount = D(str(value))
    except (ArithmeticError, ValueError, TypeError):
        raise _invalid(f"{field} must be a number") from None
    if not amount.is_finite():
        raise _invalid(f"{field} must be a finite number")
    if amount < 0:
        raise _invalid(f"{field} must be >= 0")
    if amount.adjusted() > MAX_AMOUNT_EXPONENT:
        raise _invalid(f"{field} is out of range")
    return amount


def _positive(value: Any, field: str) -> D:
    """A strictly positive finite `Decimal` (a grid center, for instance)."""
    amount = _amount(value, field)
    if amount <= 0:
        raise _invalid(f"{field} must be > 0")
    return amount


# ---------------------------------------------------------------- rows as JSON


def _text(value: Any) -> str:
    """A stored value as the string this surface reports it as."""
    return "" if value is None else str(value)


def _optional_text(value: Any) -> Optional[str]:
    """A stored value as a string, or null when the column holds no amount."""
    return None if value is None else str(value)


def _bot_json(bot: Mapping[str, Any]) -> dict:
    """One bot row, money as strings and `init_done` as the boolean it means.

    The book a bot trades is reported with it, and so is the capital budget of
    each book: the dry pair always has an amount, while the live pair is null
    until the bot has been given a live budget (and null again once it is back
    on dry).
    """
    return {
        "id": bot["id"],
        "product": bot["product"],
        "strategy": bot["strategy"],
        "params": bot["params"],
        "status": bot["status"],
        "init_done": bool(bot["init_done"]),
        "mode": bot["mode"],
        "capital_quote": _text(bot["capital_quote"]),
        "capital_base": _text(bot["capital_base"]),
        "live_capital_quote": _optional_text(bot["live_capital_quote"]),
        "live_capital_base": _optional_text(bot["live_capital_base"]),
        "created_at": bot["created_at"],
    }


def _bot_brief(bot: Mapping[str, Any]) -> dict:
    """The five fields `/status` reports per bot."""
    return {
        "id": bot["id"],
        "product": bot["product"],
        "strategy": bot["strategy"],
        "status": bot["status"],
        "init_done": bool(bot["init_done"]),
    }


def _pause_reason(store: Store, bot_id: str) -> Optional[str]:
    """The note this bot's last pause wrote, or None when there is no note.

    The reason is kv (`bot:paused_reason:<id>`), written by whoever paused the bot
    — an owner's pause ("owner"), a drawdown stop ("drawdown"), the strategy's
    own reason — cleared by a resume and by a stop or a kill.  Anything stored
    that is not a word is answered as no reason at all: this is a note for the
    owner, never a value echoed out of the store.  It is the note as stored, and
    the status it belongs to is not read here: `_paused_bot_json` reports it only
    for a bot whose status is PAUSED.
    """
    value = store.get(f"{PAUSED_REASON_PREFIX}{bot_id}")
    return value if isinstance(value, str) and value else None


def _paused_bot_json(bot: Mapping[str, Any], store: Store) -> dict:
    """`_bot_json` plus `paused_reason`, for the answers that report a pause.

    Kept beside `_bot_json` rather than inside it so the routes that have no
    reason to report one (a create, a stop, a recenter) answer exactly as they
    always did; the bot list and the pause and resume answers carry it.

    The reason is answered ONLY while the row says PAUSED: a note a restart or an
    edited store left behind for a bot that is not paused is nobody's answer, so
    it reads as null rather than as an owner's pause.
    """
    reason = _pause_reason(store, bot["id"]) if bot["status"] == PAUSED else None
    return {**_bot_json(bot), "paused_reason": reason}


def _holding_json(product: str, holding: Any) -> dict:
    """One owner's holding on its product, every amount a string."""
    return {
        "product": product,
        "quote": _text(holding.quote),
        "base": _text(holding.base),
        "reserved_quote": _text(holding.reserved_quote),
        "reserved_base": _text(holding.reserved_base),
    }


def _drawdown_json(
    gateway: OrderGateway, store: Store, book: str, in_play: bool
) -> dict:
    """One book's drawdown, every amount a string and every unknown one null.

    `equity` is the book's own portfolio valuation, and only a book at least one
    bot trades has one: a book nobody trades holds no portfolio, so nothing is
    priced for it and its entry says null rather than a zero that would read as a
    100 per cent drawdown.  `hwm` is the mark that book holds as stored, whether
    or not it can be priced now.  `pct` is how far equity sits below the mark —
    floored at zero, because equity at or above the mark is no drawdown at all —
    and is null unless both numbers are there and the mark is positive, the same
    condition the stop itself measures against.  All three are computed with
    `Decimal` and reported as the strings they are.
    """
    equity = gateway.portfolio_equity(book) if in_play else None
    hwm = store.hwm(PORTFOLIO_OWNER, book)
    pct: Optional[D] = None
    if equity is not None and hwm is not None and hwm > 0:
        pct = max(D(0), (hwm - equity) / hwm * D(100))
    return {
        "equity": _optional_text(equity),
        "hwm": _optional_text(hwm),
        "pct": _optional_text(pct),
    }


def _order_json(row: Any) -> dict:
    """One resting order row in the shape `GET /orders` reports it.

    `bot` is the owner that placed it, both amounts are decimal strings, the
    status and the book are the stored names, and `created_at` is the float the
    row was stamped with.  The exchange's own order id and the row's note stay
    inside the engine: an order is named here by the client order id the engine
    minted for it.
    """
    return {
        "client_order_id": _text(row["client_order_id"]),
        "bot": _text(row["owner"]),
        "product": _text(row["product"]),
        "side": _text(row["side"]),
        "size": _text(row["size"]),
        "price": _text(row["price"]),
        "status": _text(row["status"]),
        "created_at": (
            None if row["created_at"] is None else float(row["created_at"])
        ),
        "book": _text(row["book"]),
    }


def _fill_json(row: Any) -> dict:
    """One fills-table row in the shape the surface reports it."""
    return {
        "trade_id": _text(row["trade_id"]),
        "order_id": _text(row["order_id"]),
        "client_order_id": _text(row["client_order_id"]),
        "product": _text(row["product"]),
        "side": _text(row["side"]),
        "size": _text(row["size"]),
        "price": _text(row["price"]),
        "commission": _text(row["commission"]),
        "trade_time": _text(row["trade_time"]),
        "trade_type": _text(row["trade_type"]),
        "book": _text(row["book"]),
    }


# ---------------------------------------------------------------- the store


def _require_bot(store: Store, bot_id: str) -> dict:
    """The bot row, or a 404 for an id this engine does not know."""
    bot = store.get_bot(bot_id)
    if bot is None:
        raise _unknown(f"no bot {bot_id!r}")
    return bot


def _benchmark_keys(bot_id: str) -> list[str]:
    """Every kv key a benchmark record of *bot_id* can live under.

    A baseline is keyed per book (`bench:<book>:<id>`) and the P1 key
    (`benchmark:<id>`) is still the dry book's own, so an id used before is found
    through any of them — including a record holding null, which is what
    forgetting a benchmark leaves behind.
    """
    return [f"{KEY_PREFIX}{book}:{bot_id}" for book in BOOKS] + [
        f"{LEGACY_PREFIX}{bot_id}"
    ]


def _ever_existed(store: Store, bot_id: str) -> bool:
    """True when this id has ever been used, however little of it is left.

    An id is never reused: a bot row, an order or fill row, a high-water mark,
    or a benchmark record on either book (or the P1 key, even one holding null)
    all mean the name belongs to a history this engine still reports on.
    """
    db = store.conn()
    checks = [
        ("SELECT 1 FROM bots WHERE id=? LIMIT 1", (bot_id,)),
        ("SELECT 1 FROM orders WHERE owner=? LIMIT 1", (bot_id,)),
        ("SELECT 1 FROM fills WHERE owner=? LIMIT 1", (bot_id,)),
        ("SELECT 1 FROM hwm WHERE owner=? LIMIT 1", (bot_id,)),
    ]
    checks.extend(
        ("SELECT 1 FROM kv WHERE key=? LIMIT 1", (key,))
        for key in _benchmark_keys(bot_id)
    )
    for sql, args in checks:
        if db.execute(sql, args).fetchone() is not None:
            return True
    return False


def _alert_rows(store: Store) -> list[dict]:
    """The most recent ALERT events, newest first, each as {ts, message}."""
    rows = store.conn().execute(
        "SELECT ts, message FROM events WHERE level=? "
        "ORDER BY ts DESC, rowid DESC LIMIT ?",
        (ALERT_LEVEL, ALERT_LIMIT),
    ).fetchall()
    return [{"ts": row["ts"], "message": row["message"]} for row in rows]


def _fee_total(store: Store, bot_id: str, book: str) -> D:
    """What this owner has paid in commission on *book* in its current period.

    Only fills from the period this book has been running count: a fill booked
    before the book's epoch belongs to a period the owner has already left (a
    switch, a re-init), so adding it would report the fees of every period the
    book ever had.  The stamp compared is the order row's own `created_at`,
    reached through the fill's client order id, because that is the same stamp
    `realized_pnl` filters its sells by; a fill with no order row (an orphan) is
    dated by its own `recorded_at`, the moment it was booked, and one with
    neither counts only when the book has no epoch at all.  The tax export and a
    bot's own fill list do NOT filter: they carry every fill of every book.
    """
    epoch = store.book_epoch(book, bot_id)
    total = D(0)
    rows = store.conn().execute(
        "SELECT f.commission FROM fills AS f "
        "LEFT JOIN orders AS o ON o.client_order_id = f.client_order_id "
        "WHERE f.owner=? AND f.book=? "
        "AND COALESCE(o.created_at, f.recorded_at, 0) >= ?",
        (bot_id, book, epoch),
    )
    for row in rows:
        total += D(row["commission"] or "0")
    return total


def _fill_rows(store: Store, year: Optional[str]) -> list[Any]:
    """Every fill row, oldest first, optionally only one calendar year's."""
    sql = "SELECT * FROM fills"
    args: tuple = ()
    if year is not None:
        sql += " WHERE trade_time LIKE ?"
        args = (f"{year}%",)
    sql += " ORDER BY trade_time, trade_id"
    return list(store.conn().execute(sql, args).fetchall())


# ---------------------------------------------------------------- csv


def _record_fill(row: Any) -> dict:
    """The parts of a fill row `records.append_fill` reads."""
    return {
        "size": row["size"],
        "price": row["price"],
        "commission": row["commission"],
        "side": row["side"],
        "trade_time": row["trade_time"],
        "trade_id": row["trade_id"],
        "order_id": row["order_id"],
        "trade_type": row["trade_type"],
    }


def _write_header(path: Path) -> None:
    """A file with the column header and no row: an empty export is still a table."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        csv.writer(handle).writerow(records.COLUMNS)


def _fills_csv(rows: list[Any]) -> str:
    """The fills as CSV text, written by the one formatter that owns the columns.

    Each row goes through `records.append_fill` into a scratch file, so the web
    export and the on-disk trades file can never disagree about a column's
    formatting.  An empty selection still answers the header line.  The scratch
    file is fresh on every call, so no trade id remembered from an earlier export
    can suppress a row of this one, and its ids are dropped once it is read.
    """
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / CSV_NAME
        for row in rows:
            records.append_fill(
                path,
                _text(row["product"]),
                _record_fill(row),
                _text(row["client_order_id"]),
                _text(row["book"]),
            )
        if not path.exists():
            _write_header(path)
        text = path.read_text(encoding="utf-8")
    records.forget(path)
    return text


# ---------------------------------------------------------------- the heartbeat


def _read_json_file(path: Path | str) -> Any:
    """A JSON file's contents, or None when it is absent, unreadable or garbled."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _heartbeat_age(path: Path | str, at: float) -> Optional[float]:
    """How old the heartbeat's stamp is at *at*, or None when there is no stamp.

    No file, an unreadable one, one that is not JSON, and one whose `ts` is not
    a number are all "no stamp": the caller decides what a missing heartbeat
    means, and a garbled file must never read as a fresh one.  A `ts` that is a
    number but not finite comes back as a non-finite age — a stamp this clock
    cannot date, which is not the same thing as an absent one.
    """
    payload = _read_json_file(path)
    if not isinstance(payload, dict):
        return None
    stamp = payload.get("ts")
    if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
        return None
    try:
        stamp_at = float(stamp)
    except (OverflowError, ValueError):
        return float("nan")
    if not math.isfinite(stamp_at):
        return float("nan")
    return float(at) - stamp_at


def _health_body(
    ok: bool,
    age: Optional[float],
    credentials: str,
    pinned: bool,
) -> dict:
    """The whole `/health` body: five keys, and never a balance or a bot."""
    return {
        "ok": bool(ok),
        "live_enabled": False,
        "heartbeat_age_s": age,
        "credentials": credentials,
        "pinned": bool(pinned),
    }


def _credentials_state(slot: Optional[CredentialSlot]) -> str:
    """Whether the owner's key is in memory right now: "ready" or "not_ready".

    A surface built without a slot has nowhere to hold a key, so it is never
    ready — and asking is a read of one in-memory field, never an exchange call.
    """
    return "ready" if slot is not None and slot.state() == "ok" else "not_ready"


def _pinned_state(store: Store, slot: Optional[CredentialSlot]) -> bool:
    """Whether a pin ROW exists for this engine, whatever it holds.

    A surface built without a slot answers the same question straight from the
    store, so the two ways of building an engine cannot disagree about it.
    """
    return bool(slot.pinned()) if slot is not None else pin_exists(store)


# ---------------------------------------------------------------- bot creation


def _check_new_bot(
    store: Store,
    limits: Limits,
    strategies: Mapping[str, Strategy],
    spec_for: Callable[[str], ProductSpec],
    body: BotCreate,
) -> tuple[D, D]:
    """Every refusal a new bot can earn before its capital is priced.

    Nothing is written here and nothing is fetched from the exchange: the caller
    runs this before it opens the transaction that writes the row and its one
    seed, and prices the capital afterwards with `_check_bot_capital`, so a
    refusal anywhere leaves the store exactly as it was.  Returns the parsed
    `(capital_quote, capital_base)`.
    """
    bot_id = body.id
    if not BOT_ID_RE.fullmatch(bot_id):
        raise _invalid(f"bot id {bot_id!r} must be 1-16 lowercase letters or digits")
    if bot_id in NOT_BOT_OWNERS:
        raise _invalid(f"bot id {bot_id!r} is reserved")
    if _ever_existed(store, bot_id):
        raise _conflict(f"bot id {bot_id!r} was used before; ids are never reused")
    if body.product not in limits.products:
        raise _invalid(f"product {body.product!r} is not in the allow-list")
    strategy = strategies.get(body.strategy)
    if strategy is None:
        raise _invalid(f"unknown strategy {body.strategy!r}")
    try:
        spec = spec_for(body.product)
    except Exception as error:  # noqa: BLE001 - any failure means no spec
        raise _invalid(f"no product spec for {body.product}: {error}") from None
    try:
        strategy.validate(body.params, spec)
        why = strategy.fee_guard(body.params, limits.maker_fee_pct)
    except ValueError as error:
        raise _invalid(str(error)) from None
    if why:
        raise _invalid(str(why))

    quote = _amount(body.capital_quote, "capital_quote")
    base = _amount(body.capital_base, "capital_base")
    if quote + base <= 0:
        raise _invalid("capital must be more than zero: both amounts are zero")
    return quote, base


def _check_bot_capital(
    limits: Limits,
    product: str,
    quote: D,
    base: D,
    price_for: Callable[[str], D],
) -> None:
    """Refuse capital over the cap, measured in quote terms.

    A base amount is valued at the product's price, which is a read of the
    exchange (or of the last poll's snapshot): it happens here, before the caller
    opens the transaction that writes the bot, so a slow or failing price never
    holds a write lock.  A price the exchange cannot give is a 503, the same
    answer as when the product cannot be priced at all.
    """
    value = quote
    if base > 0:
        try:
            price = price_for(product)
        except Exception as error:  # noqa: BLE001 - the price is the exchange's
            raise _unavailable(f"cannot price {product}: {error}") from None
        value += base * D(price)
    if value > limits.max_bot_capital_usd:
        raise _invalid(
            f"capital {value} is over the {limits.max_bot_capital_usd} USD cap"
        )


# ---------------------------------------------------------------- the caps


def _cap_json(spec: Any, value: Any) -> Any:
    """One cap in the shape a body carries it: text for money, a number for a count.

    Money and percentages travel as decimal strings so no reader has to guess at
    a float's precision, and a count travels as an integer: it is a number of
    orders, and `True` is never one of them.
    """
    return int(value) if spec.kind == CAP_KIND_COUNT else str(value)


def _caps_json(limits: Limits) -> dict:
    """Every cap this engine holds, as it stands, by the variable that sets it."""
    return {
        spec.env: _cap_json(spec, getattr(limits, spec.field))
        for spec in CAP_SPECS
    }


def _ceilings_json(limits: Limits) -> dict:
    """Every cap's ceiling, in the same shape `_caps_json` reports a cap.

    The ceilings are the values this process was started with, so a cap lowered
    afterwards reads below its ceiling here.  A plain `Limits` is both: with no
    runtime object over it, a cap is its own ceiling.
    """
    ceilings = getattr(limits, "ceilings", limits)
    return {
        spec.env: _cap_json(spec, getattr(ceilings, spec.field))
        for spec in CAP_SPECS
    }


def _book_usage(caps: CapWindow, book: str) -> dict:
    """One book's spend today and in the rolling hour, every owner and the AI's.

    The figure of each book is that book's own rows: a day of dry orders spends
    no live budget.  Money is a decimal string and a count is an integer, exactly
    as a cap is reported.
    """
    return {
        "daily_notional_usd": str(caps.daily_notional(None, book=book)),
        "ai_daily_notional_usd": str(caps.daily_notional("ai", book=book)),
        "orders_last_hour": int(caps.orders_last_hour(None, book=book)),
        "ai_orders_last_hour": int(caps.orders_last_hour("ai", book=book)),
    }


# ---------------------------------------------------------------- the AI's capital


def _ai_capital_spec() -> Optional[Any]:
    """The one cap that is the AI's live capital, or None when this build has none.

    Found by the FIELD it is read as (`AI_CAPITAL_FIELD`), so this module never
    spells the variable that sets it: a cap's environment variable lives in
    `limits.py` alone, and every refusal here names the one the spec carries.
    """
    for spec in CAP_SPECS:
        if spec.field == AI_CAPITAL_FIELD:
            return spec
    return None


def _ai_capital_short(gateway: Any, limits: Limits, wanted: Any) -> Optional[str]:
    """Why a raise of the AI's capital cannot be written, or None when it can.

    A raise is the one cap change that would hand out money that is not there, so
    the EXTRA it asks for is measured against what the live book still has free:
    the live USDC unallocated as it stands, which already reserves the capital in
    force, so the question is exactly whether the account can fund the new figure
    on top of what the AI has already spent.

    Only a raise is measured.  A body that lowers the value, keeps it as it is or
    does not name this cap is never checked; a value this engine cannot store
    anyway (unusable, or above its ceiling) is left to `set_caps`, which refuses
    the whole body in its own words; and a live book that cannot be read at all —
    `LiveLocked`, a failing totals call, an unreadable ledger — accepts the raise,
    because nothing then says the book is short.

    Answers a message that names the cap and no amount of anything, which the
    route reports as `422 AI_CAPITAL_SHORT`; nothing is written here.
    """
    spec = _ai_capital_spec()
    if spec is None or not isinstance(wanted, Mapping) or spec.env not in wanted:
        return None
    value = cap_value(spec, wanted[spec.env])
    if value is None:
        return None
    ceilings = getattr(limits, "ceilings", limits)
    if value > getattr(ceilings, spec.field):
        return None
    try:
        extra = value - getattr(limits, spec.field)
    except (ArithmeticError, TypeError, ValueError):
        return None
    if extra <= D(0):
        return None
    try:
        totals = gateway.books.totals(LIVE)
        free = gateway.ledger.unallocated(totals, book=LIVE).get(
            AI_CAPITAL_CURRENCY, D(0)
        )
    except Exception:  # noqa: BLE001 - a book that cannot be read says nothing
        return None
    if extra > D(free):
        return (
            f"{spec.env} cannot be raised: the live book has less unallocated "
            f"than this raise adds"
        )
    return None


# ---------------------------------------------------------------- the event feed


def _event_data(raw: Any) -> dict:
    """One event's payload as an object: `{}` when there is none, or it cannot be read.

    The column is JSON this surface writes itself, so a row it cannot parse was
    written by something else (or edited by hand): a reader is answered an empty
    payload rather than an error, and never a value that is not an object.
    """
    try:
        parsed = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _event_json(row: Any) -> dict:
    """One event row in the shape the feed reports it: seven fields, and no more."""
    stamp = row["ts"]
    return {
        "id": int(row["id"]),
        "ts": float(stamp) if isinstance(stamp, (int, float)) else 0.0,
        "level": _text(row["level"]),
        "kind": _text(row["kind"]),
        "owner": _optional_text(row["owner"]),
        "message": _text(row["message"]),
        "data": _event_data(row["data_json"]),
    }


def _events_page(store: Store, after: int, limit: int) -> dict:
    """One page of the feed: the rows after *after*, oldest first, at most *limit*.

    Read-only: it writes nothing, moves no cursor and needs no approval, so a
    client can read forward from the id it last saw.  `last_id` is the id of the
    last row this page carried, or *after* when it carried none, which is exactly
    the cursor to ask for next.

    `reset` is always answered, and is true for one case alone: a cursor past the
    newest event this engine holds.  The table behind a client's cursor can be
    gone (a wiped volume, a restore), and an empty page for ever would leave it
    reading a history that will never arrive — so that one answer carries the
    newest id the engine does hold (0 when the table is empty) as `last_id` and
    `reset` true, which is the client's signal to start again from there.  Every
    other answer, including a cursor exactly at the newest row, is `reset` false.
    """
    start = int(after)
    size = max(EVENTS_MIN_LIMIT, min(int(limit), EVENTS_MAX_LIMIT))
    conn = store.conn()
    rows = conn.execute(
        "SELECT id, ts, level, kind, owner, message, data_json FROM events "
        "WHERE id > ? ORDER BY id ASC LIMIT ?",
        (start, size),
    ).fetchall()
    events = [_event_json(row) for row in rows]
    if events:
        return {"events": events, "last_id": events[-1]["id"], "reset": False}
    newest_row = conn.execute("SELECT MAX(id) FROM events").fetchone()
    newest = 0 if newest_row is None else int(newest_row[0] or 0)
    if start > newest:
        return {"events": [], "last_id": newest, "reset": True}
    return {"events": [], "last_id": start, "reset": False}


def _record(
    store: Store,
    level: str,
    message: str,
    *,
    kind: str,
    owner: Optional[str] = None,
    data: Optional[dict] = None,
) -> None:
    """Write one event, and never let the record of a request fail the request.

    Every event this module writes is a reader's account of what the request did,
    already done by the time it is written: a store that will not take it is
    logged (without a value of anything) and the answer the request earned stands.
    No message or payload handed here carries a key, a secret, a token or a key
    name — only codes and the names of things.
    """
    try:
        store.event(level, message, kind=kind, owner=owner, data=data)
    except Exception:  # noqa: BLE001 - the request's answer outranks its record
        log.warning("event %s could not be recorded", kind)


# ---------------------------------------------------------------- pause episodes


def _pause_alert(store: Store, bot_id: str, book: str) -> None:
    """Alert that a pause could not clear this bot's book, once per episode.

    A pause that fails leaves the bot PAUSED with orders still resting, and the
    retry is the same request again: the owner needs to be told once that the
    cancel did not go through, not once per press.  The kv key
    `api:pause_alert:<bot>` is the episode's own record — written with the alert,
    cleared by the next pause that finishes — so it is read first and written
    after, and a store that will not take either is only logged: the answer the
    request earned (the 502) stands whatever happened to its record.
    """
    key = f"{PAUSE_ALERT_PREFIX}{bot_id}"
    try:
        if store.get(key) is not None:
            return
        _record(
            store,
            "warn",
            PAUSE_FAILED,
            kind="alert",
            owner=bot_id,
            data={"bot": bot_id, "book": book},
        )
        store.put(key, True)
    except Exception:  # noqa: BLE001 - the failure it reports is the request's
        log.warning("bot %s: pause alert could not be recorded", bot_id)


def _pause_alert_clear(store: Store, bot_id: str) -> None:
    """End a pause-failure episode, so a later failure is news again."""
    key = f"{PAUSE_ALERT_PREFIX}{bot_id}"
    try:
        if store.get(key) is not None:
            store.put(key, None)
    except Exception:  # noqa: BLE001 - the pause itself went through
        log.warning("bot %s: pause alert could not be cleared", bot_id)


def _pause_reason_clear(store: Store, bot_id: str) -> None:
    """Forget why a bot was paused: a bot that was stopped is not paused for one.

    Called by the stop route and by the kill path, the two ways a bot stops being
    paused by going away altogether.  A write the store will not take is only
    logged and never fails the stop: the bot is stopped either way, the rest of
    the kill's bots are still stopped, and `_paused_bot_json` reports a reason
    only for a PAUSED row, so a note left behind reads as nothing.
    """
    try:
        store.put(f"{PAUSED_REASON_PREFIX}{bot_id}", None)
    except Exception:  # noqa: BLE001 - the stop it belongs to already happened
        log.warning("bot %s: pause reason could not be cleared", bot_id)


# ---------------------------------------------------------------- the source tag


def _presented_source(scope: Any) -> Optional[str]:
    """The source tag one request carries, or None when it carries none.

    The header's value is compared byte for byte, so `mcp` is the one spelling
    that tags anything: `MCP`, `other` and an empty value are all untagged.
    """
    for name, value in scope.get("headers") or ():
        if bytes(name).decode("latin-1").lower() != SOURCE_HEADER:
            continue
        return EVENT_SOURCE_MCP if bytes(value) == SOURCE_MCP_BYTES else None
    return None


class EventSourceMiddleware:
    """Tags the events an HTTP request writes with the source header it carried.

    A PURE ASGI middleware — a class with `__call__(scope, receive, send)`, not a
    `BaseHTTPMiddleware` — because the tag lives in a context variable and has to
    be set in the very context the request's handler runs in: the body-capturing
    middleware beside it reads bytes, and wrapping that in a task of its own would
    be a copy of the context this tag would never reach.

    The variable is set before the request is handled and reset in a `finally`, so
    nothing it set outlives the request that carried it.  No other thread of the
    engine sets it at all, so an event the cycle or the watchdog writes is never
    tagged, whatever request is in flight at the time.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        token = EVENT_SOURCE.set(_presented_source(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            EVENT_SOURCE.reset(token)


# ---------------------------------------------------------------- the app


def create_app(
    *,
    store: Store,
    gateway: OrderGateway,
    runner: Runner,
    exchange: Any,
    strategies: Mapping[str, Strategy],
    limits: Limits,
    spec_for: Callable[[str], ProductSpec],
    price_for: Callable[[str], D],
    token: Optional[str],
    heartbeat_path: Path | str,
    now: Callable[[], float] = time.time,
    startup_grace_s: Optional[float] = None,
    switches: Optional[Switches] = None,
    require_privileged: Callable[[Request], None] = require_privileged,
    auth: Optional[Authenticator] = None,
    slot: Optional[CredentialSlot] = None,
    ai_orders: Optional[AiOrders] = None,
) -> FastAPI:
    """Build the app over already-built pieces: nothing here opens a file or a socket.

    The token is checked FIRST, before the app object exists: a blank one is a
    refused start, never a set of unauthenticated routes.  `now` is the clock
    the health route reads, `heartbeat_path` the file a cycle writes, and
    `price_for` the mid a bot's base capital is valued at in quote terms —
    `GET /price` does not use it, reading the cache through `runner` instead.

    `limits` is what every cap this surface reports is read from — the runtime
    object in the real engine, which reads the caps in force out of the store,
    and a plain `Limits` where a caller supplies one, whose caps are then its own
    values and whose ceilings are the same numbers.  The two cap routes report it
    and lower it; every order check the gateway runs reads the same object.

    `switches` is the owner's two live switches (both off over this store when
    the caller wires none) and `require_privileged` the approval a privileged
    route needs — a callable taking the request, whose default here refuses every
    request with `APPROVAL_INVALID`.  An injected approval is used exactly as it
    is given, for the strict gate and the install-token gate alike; when none is
    injected and `auth` is, the strict gate runs `auth.require` and the
    install-token gate runs `auth.require_install_ok`, so the engine's own rail
    is in place without this module knowing how it is built.  Nothing being wired
    leaves the deny-by-default refusal, so a privileged route is never open by
    omission.

    The install-token gate belongs to the two lease routes and to
    `POST /credentials/check`: the install token signs those, while a mode switch,
    a live switch, a cleared halt, a live bot's recenter or resume, a credentials
    disconnect and a credentials forget are the strict gate's, which never takes
    it.

    `slot` is the owner's credentials, and the four credentials routes exist only
    when it is given: `POST /credentials/check` judges a key pair, `POST
    /credentials` installs one behind its own MAC (the body's approval secret) and
    behind a gate that refuses a body naming one field twice, `DELETE
    /credentials` drops the live route, and `POST /credentials/forget` drops the
    pin, the pinned portfolio, the engine epoch and both live switches, so the
    engine reads as a first install again.  An engine built without a slot — a
    surface over a store no key can be installed on — therefore carries no such
    route at all rather than a route that cannot answer, and `/health` reports
    `credentials: "not_ready"` for it and reads the pin from the store.

    `auth.BodyCaptureMiddleware` is installed for every request; it reads the
    body only of a request that carries a signature header, and replays those
    bytes downstream.  A body this surface cannot read is answered by the app's
    own `RequestValidationError` handler: `422 {"code": "INVALID", "fields":
    [...]}`, naming the fields and never a value that was sent; a body that names
    one field twice reaches `DuplicatedBodyFields`, which answers the same shape.

    `ai_orders` is the AI's preview and approval surface (`ai_orders.py`), and the
    five AI routes exist only when it is given: `POST /ai/previews` measures a
    proposed order and stores the answer, `GET /ai/previews` lists what is there,
    `POST /ai/previews/{id}/approve` spends one preview behind the STRICT gate
    (the install token is never a key there), `POST /ai/previews/{id}/reject`
    retires one, and `POST /ai/orders/{cid}/cancel` cancels an AI order's own
    order.  A refusal of that surface is answered with its own code, its plain
    sentence and its status.
    """
    secret = token_or_refuse(token).encode("utf-8")
    created_at = now()
    window = HEALTH_WINDOWS * limits.poll_seconds
    grace = (
        DEFAULT_GRACE_WINDOWS * limits.poll_seconds
        if startup_grace_s is None
        else startup_grace_s
    )
    live_switches = switches if switches is not None else Switches(store, {})
    strict = require_privileged
    install_ok = require_privileged
    if require_privileged is DENY_ALL and auth is not None:
        # The engine's own rail over this store: the strict gate asks it for the
        # owner's secret, and the lease gate asks that same rail with the install
        # token admitted.  An injected approval replaces both with itself.
        strict = auth.require
        install_ok = auth.require_install_ok
    lease = Lease(store, now)
    # The per-bot pause debounce, in memory and inside this app: bot id -> the
    # moment (`now()`) this bot was last asked to pause.  Only a bot that is
    # ALREADY paused is debounced against it, so a resume followed by a pause is
    # never held back, and nothing is written outside this app's own lifetime.
    last_pause: dict[str, float] = {}

    def _check_token(authorization: Optional[str] = Header(default=None)) -> None:
        """The bearer-token gate: uniform on the presented bytes, silent when it passes."""
        presented = _presented_token(authorization)
        if hmac.compare_digest(presented, secret):
            return
        raise HTTPException(
            status_code=401,
            detail=UNAUTHORIZED,
            headers={"WWW-Authenticate": AUTH_SCHEME},
        )

    def _approval_gate(request: Request) -> None:
        """The privileged routes' dependency: the strict approval, unmodified."""
        strict(request)

    def _install_ok_gate(request: Request) -> None:
        """The lease routes' dependency: the approval that admits the install token."""
        install_ok(request)

    def _live_needs_owner(bot: Mapping[str, Any], request: Request) -> None:
        """Ask the owner's approval for a bot on the live book; a dry bot needs none.

        A refusal is reported as `LIVE_NEEDS_OWNER` rather than as the approval
        rail's own code: the caller of a live bot's route is being told that this
        bot needs its owner, which is the fact the route acts on.
        """
        if bot["mode"] != LIVE:
            return
        try:
            strict(request)
        except HTTPException:
            raise HTTPException(
                status_code=403, detail=LIVE_NEEDS_OWNER
            ) from None

    guard = [Depends(_check_token)]
    # The privileged routes check the token FIRST and the approval second, so an
    # unauthenticated request is a 401 whatever else is wrong with it.  The lease
    # routes carry the same pair, with the gate that admits the install token.
    privileged = [Depends(_check_token), Depends(_approval_gate)]
    lease_gate = [Depends(_check_token), Depends(_install_ok_gate)]
    app = FastAPI(
        title="crow-coinbase engine",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    # Installed for every request: it reads the body of a signed one, and passes
    # every other request straight through.
    app.add_middleware(BodyCaptureMiddleware)
    # Installed for every request too: it sets the event-source tag a request's
    # header names for the length of that request, and resets it afterwards.
    app.add_middleware(EventSourceMiddleware)

    # ------------------------------------------------ a body this build cannot read
    @app.exception_handler(RequestValidationError)
    async def _unreadable_body(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        """Answer every validation failure the same way: the fields, and no values.

        The default answer carries the rejected input, which for a credentials
        request would be the private key and the approval secret.  So the shape is
        this module's own: the code `INVALID` and the names of the fields that
        failed, each located the way FastAPI locates it with the leading `body`
        dropped, and nothing else at all.
        """
        return JSONResponse(
            status_code=422,
            content={"code": INVALID_BODY, "fields": _invalid_fields(error)},
        )

    @app.exception_handler(DuplicatedBodyFields)
    async def _duplicated_body(
        request: Request, error: DuplicatedBodyFields
    ) -> JSONResponse:
        """Answer a body that names a field twice: the same shape, no values.

        `POST /credentials` refuses such a body before it is read into a model,
        so the refusal arrives here rather than through the validation handler
        above.  It is the same `422` those answer with: the code `INVALID` and
        the names of the fields that were named twice.
        """
        return JSONResponse(
            status_code=422,
            content={"code": INVALID_BODY, "fields": list(error.fields)},
        )

    # ------------------------------------------------ health (anonymous)
    def _health_answer() -> JSONResponse:
        """The `/health` answer, from the heartbeat, the pin and the slot.

        Everything the answer reads is read here, so a failure anywhere in it —
        the heartbeat file, the pin's row, the slot — is the one place the route
        below has to catch.
        """
        at = now()
        credentials = _credentials_state(slot)
        pinned = _pinned_state(store, slot)
        age = _heartbeat_age(heartbeat_path, at)
        if age is None:
            # No heartbeat yet: fine while the engine is still starting up,
            # refused once the startup grace has passed without one.
            ok = at - created_at <= grace
            return JSONResponse(
                status_code=200 if ok else 503,
                content=_health_body(ok, None, credentials, pinned),
            )
        if not math.isfinite(age):
            # A stamp that cannot be dated is stale, and the grace does not
            # cover it: only an absent stamp is what the grace is for.
            return JSONResponse(
                status_code=503,
                content=_health_body(False, None, credentials, pinned),
            )
        # A stamp too far ahead of this clock refutes it in the same way an old
        # one does, so both ends are a whole poll window.
        ok = -limits.poll_seconds <= age <= window
        return JSONResponse(
            status_code=200 if ok else 503,
            content=_health_body(ok, age, credentials, pinned),
        )

    @app.get("/health")
    def health() -> JSONResponse:
        """Is a cycle still getting through? Five keys, and no bot or balance.

        It reads the heartbeat file, the pin's row and the slot, and nothing that
        reaches the exchange.  It never raises: a store that cannot say whether
        this engine is pinned, or anything else the answer reads, is answered
        `503` with `pinned` true and `credentials` "not_ready" — an engine that
        cannot tell whether it has a pin has to read as one that does, and an
        anonymous route must answer rather than fail.  The refusal is not
        sticky: the next request reads the store again.
        """
        try:
            return _health_answer()
        except Exception:  # noqa: BLE001 - the anonymous route always answers
            # The reason is not logged with its text: it could carry a value of
            # the store, and nothing of it belongs in a log line or a response.
            log.warning("health: the engine's state could not be read")
            return JSONResponse(
                status_code=503,
                content=_health_body(False, None, "not_ready", True),
            )

    # ------------------------------------------------ status
    @app.get("/status", dependencies=guard)
    def status() -> dict:
        """The halt flags, the heartbeat, the bots, the marks and the switches.

        `halted` stays one boolean for a reader that only knows that shape: it is
        the global halt OR any book's.  `halted_books` and `halt_reasons` say
        which book, and why, while `halt_reason` remains the global flag's own
        reason (the kill switch's), so a kill still reads differently from one
        book's drawdown.

        The keys beside those are reads and write nothing: `live_switches` is the
        switches' own snapshot (both flags and the environment's ceiling),
        `drawdown` is one entry per book with that book's equity, mark and the
        percentage between them, and `products` is the allow-list as the plain
        strings it holds.
        """
        halted_books = gateway.halted_books()
        bots = store.list_bots()
        modes = {bot["mode"] for bot in bots}
        return {
            "halted": gateway.is_halted() or any(halted_books.values()),
            "halted_books": halted_books,
            "halt_reason": gateway.halt_reason(),
            "halt_reasons": {book: gateway.halt_reason(book) for book in BOOKS},
            "heartbeat": _read_json_file(heartbeat_path),
            "bots": [_bot_brief(bot) for bot in bots],
            "recent_alerts": _alert_rows(store),
            "live_switches": live_switches.snapshot(),
            "drawdown": {
                book: _drawdown_json(gateway, store, book, book in modes)
                for book in BOOKS
            },
            "products": list(limits.products),
        }

    # ------------------------------------------------ the event feed
    @app.get("/events", dependencies=guard)
    def events(
        after: int = Query(default=0, ge=0),
        limit: int = Query(default=EVENTS_DEFAULT_LIMIT, ge=EVENTS_MIN_LIMIT),
    ) -> dict:
        """The events after *after*, oldest first, at most *limit* of them.

        Reading is the bearer token's alone (it moves nothing), and it is
        read-only: the feed writes no event of its own, so a reader can only ever
        see what the engine did.  `last_id` is the id to ask for next; a page that
        carried nothing answers the cursor it was given, except for a cursor past
        the newest event the engine holds — that page answers the newest id and
        `reset` true, so a client whose table was wiped can resync.
        """
        return _events_page(store, after, limit)

    # ------------------------------------------------ the resting orders
    @app.get("/orders", dependencies=guard)
    def list_orders(
        book: Optional[Literal["dry", "live"]] = Query(default=None),
    ) -> list[dict]:
        """Every resting order, oldest first, on both books or the one named.

        Reading is the bearer token's alone — it moves nothing and settles
        nothing — so this is not a privileged route.  The rows are the engine's
        own order records, and only the ones still resting: `PENDING_SUBMIT` and
        `OPEN`, so a filled, cancelled, rejected or failed order is never one of
        them.  `book` filters to that book's rows, and no `book` at all reads
        both.  A `book` this engine has no book for is the surface's usual `422
        INVALID`, naming the query field and echoing nothing that was sent.
        """
        return [
            _order_json(row)
            for row in store.orders(statuses=LIVE_STATUSES, book=book)
        ]

    # ------------------------------------------------ the price
    @app.get("/price", dependencies=guard)
    def price(product: str = Query(default="")) -> dict:
        """One product's mid from the snapshot cache alone, and that snapshot's stamp.

        Read-only, so the bearer token alone is the gate and no approval is
        needed: nothing here places, settles or writes anything.  The product has
        to be one this engine trades — its allow-list — and a product it does not
        trade, or none at all, is a `400` in the surface's own plain words.

        The figure is the engine's CACHE and nothing else: `Runner._mid` applies
        the gateway's own usability rule to the product's latest polled snapshot
        and answers None for a missing, stale, crossed or future one.  This route
        never calls `price_for` and never reaches an exchange or a market path,
        so a cache that cannot price the product is a `503` carrying a plain
        sentence rather than a figure read from somewhere else.  `ts` is the
        snapshot's own stamp, not the engine's clock as the answer was read.
        """
        if product not in limits.products:
            raise HTTPException(status_code=400, detail=PRICE_UNKNOWN_PRODUCT)
        snap = runner.snapshots.get(product)
        mid = runner._mid(product)
        if mid is None or snap is None:
            raise _unavailable(PRICE_UNAVAILABLE)
        return {"product": product, "price": _text(mid), "ts": snap.ts}

    # ------------------------------------------------ balances
    @app.get("/balances", dependencies=guard)
    def balances() -> dict:
        """The simulated account, each owner's holding, and what is unallocated.

        `totals` and `unallocated` are the simulator's, and an owner's holding is
        read on the book that owner trades now, so a live bot's holdings are not
        counted against the dry account (or the other way round).  The live book
        reports whether an account can be reached at all and no figures: its
        money is not this route's to report.
        """
        totals = exchange.totals()
        owners = {
            bot["id"]: _holding_json(
                bot["product"],
                gateway.ledger.holding(
                    bot["id"], bot["product"], book=bot["mode"]
                ),
            )
            for bot in store.list_bots()
        }
        return {
            "totals": {cur: _text(value) for cur, value in totals.items()},
            "owners": owners,
            "unallocated": {
                cur: _text(value)
                for cur, value in gateway.ledger.unallocated(
                    totals, book=DRY
                ).items()
            },
            "live": {"available": bool(gateway.books.live_available())},
        }

    # ------------------------------------------------ the caps
    @app.get("/caps", dependencies=guard)
    def read_caps() -> dict:
        """The caps in force, the ceilings above them, and each book's use today.

        Every cap this engine holds is reported, by the variable that sets it:
        money and percentages as decimal strings, counts as integers.  `ceilings`
        is what the process was started with, so a cap lowered since then reads
        below its ceiling here, and `used_today` is each book's own spend — the
        daily notional and the rolling-hour order count, for every owner and for
        the AI's orders alone — read from that book's rows as they stand.

        Reading is the bearer token's alone: it moves nothing, so it needs no
        approval, while setting a cap does.
        """
        return {
            "caps": _caps_json(limits),
            "ceilings": _ceilings_json(limits),
            "used_today": {
                book: _book_usage(gateway.caps, book) for book in BOOKS
            },
        }

    @app.post("/caps", dependencies=privileged)
    def set_caps(body: CapsBody) -> Response:
        """Lower one or more caps, or refuse the whole body and write nothing.

        A privileged route, behind the strict approval: it moves the bounds every
        order is measured against, so the install token is never a key here.  The
        body is a partial update — only the caps it names change — and a refusal
        is a `422` carrying the code and a plain reason that names the cap, never
        a value.  A cap may be set to zero or to its ceiling, and never above it:
        the environment is the ceiling and this route cannot raise it.

        One cap has a floor of its own: the portfolio drawdown percentage is a
        threshold, so zero is refused as an unusable value rather than stored.

        A raise of the AI's live capital is measured against the live book before
        anything is written (`_ai_capital_short`): the extra the body asks for has
        to fit in the live USDC the account still has unallocated, or the whole
        body is refused `422 AI_CAPITAL_SHORT`.  A lowering, a value kept as it
        is, and a raise on a live book that cannot be read are never checked.

        Nothing is written unless every entry of the body is acceptable, so a
        body carrying one good cap beside a refused one changes nothing at all.
        """
        setter = getattr(limits, "set_caps", None)
        if setter is None:
            raise _unavailable(
                "this engine holds no runtime caps; its caps are its environment"
            )
        with gateway.lock:
            short = _ai_capital_short(gateway, limits, body.caps)
            if short is not None:
                return JSONResponse(
                    status_code=422,
                    content={"code": AI_CAPITAL_SHORT, "message": short},
                )
            try:
                setter(body.caps)
            except CapRefused as error:
                return JSONResponse(
                    status_code=422,
                    content={"code": error.code, "message": error.message},
                )
            # Names only: which caps the body set, and no amount of any of them.
            _record(
                store,
                "info",
                "trading limits changed",
                kind="caps",
                data={"names": sorted(str(name) for name in body.caps)},
            )
        return JSONResponse(
            status_code=200,
            content={"caps": _caps_json(limits), "ceilings": _ceilings_json(limits)},
        )

    # ------------------------------------------------ bots
    @app.get("/bots", dependencies=guard)
    def list_bots() -> list[dict]:
        """Every bot row, oldest first, each with why it was paused.

        `paused_reason` is null for every bot whose status is not PAUSED — a bot
        that is running, and a bot that was stopped or swept by the kill switch —
        and a short word for one that is ("owner", "drawdown", the strategy's own
        reason), so a panel can tell an owner's pause from the drawdown stop it
        should look at.
        """
        return [_paused_bot_json(bot, store) for bot in store.list_bots()]

    @app.post("/bots", status_code=201, dependencies=guard)
    def create_bot(body: BotCreate) -> dict:
        """Create one dry-run bot and fund it, once, in the same transaction.

        The whole body runs under the cycle lock.  The check that reads the
        exchange for a price runs before the transaction, so a network call never
        holds a write lock; inside the one immediate transaction that follows,
        the bot row and the simulated money that funds it are written together: a
        failure after the funding rolls both back, so an id is never left
        half-created and a seed is never applied twice.

        Two ceilings are read first, inside the lock and before the body is
        looked at: too many bots that are not STOPPED (`MAX_OPEN_BOTS`), or too
        many rows created in the rolling hour just gone
        (`MAX_BOT_CREATES_PER_HOUR`, any status).  Either one is a `429
        BOT_LIMIT` that writes nothing at all — no bot row and no dry seed — so a
        request over a ceiling is refused the same way whatever its body carries,
        and a body the surface would answer 422 or 409 for is still answered that
        way once there is room.
        """
        with gateway.lock:
            db = store.conn()
            open_bots = db.execute(
                "SELECT COUNT(*) FROM bots WHERE status != ?", (STOPPED,)
            ).fetchone()[0]
            if open_bots >= MAX_OPEN_BOTS:
                raise HTTPException(
                    status_code=429,
                    detail=(
                        "BOT_LIMIT: Too many bots are running. "
                        "Stop one before creating another."
                    ),
                )
            # The rolling hour: a count, not a rate of change, so a row created
            # at the edge of the window stops counting as the window moves on.
            recent = db.execute(
                "SELECT COUNT(*) FROM bots WHERE created_at > ?",
                (time.time() - 3600,),
            ).fetchone()[0]
            if recent >= MAX_BOT_CREATES_PER_HOUR:
                raise HTTPException(
                    status_code=429,
                    detail=(
                        "BOT_LIMIT: Too many bots were created this hour. "
                        "Try again later."
                    ),
                )
            try:
                quote, base = _check_new_bot(
                    store, limits, strategies, spec_for, body
                )
                _check_bot_capital(limits, body.product, quote, base, price_for)
                with store.tx():
                    row = store.create_bot(
                        body.id,
                        body.product,
                        body.strategy,
                        body.params,
                        quote,
                        base,
                    )
                    gateway.seed_dry(body.id, quote, base)
            except HTTPException:
                raise
            except Exception as error:  # noqa: BLE001 - reported, never swallowed
                log.exception("bot %s: creation failed: %s", body.id, error)
                raise HTTPException(status_code=500, detail=CREATE_FAILED) from None
        return _bot_json(row)

    # ------------------------------------------------ the books and their switches
    @app.post("/bots/{bot_id}/mode", dependencies=privileged)
    def switch_bot_mode(bot_id: str, body: SwitchMode) -> dict:
        """Move one bot between the dry book and the live one, or refuse and write nothing.

        A switch to the live book is the engine's only money-moving request, so it
        is privileged and it takes an explicit acknowledgement: without a JSON
        `true` in `acknowledge_live` the request answers 409 and the runner is not
        called at all.  The capital it names is the live book's budget, priced in
        quote terms against the same cap a new bot's capital is, before the switch
        runs; the runner then checks it against what the real account still has
        unallocated, and every refusal it raises is reported with its own code and
        status.  Nothing is written until every check has passed.  A bot a pause is
        still sweeping is `409 PAUSE_IN_PROGRESS` rather than moved: the pause lets
        the lock go between its passes, and a switch in that window would be
        written over by the pause's own final transaction.
        """
        if body.mode == LIVE and body.acknowledge_live is not True:
            raise _conflict(LIVE_ACK)
        with gateway.lock:
            bot = _require_bot(store, bot_id)
            if runner.is_pausing(bot_id):
                raise _conflict(PAUSE_IN_PROGRESS)
            if body.mode == LIVE and bot["mode"] == DRY:
                quote = _amount(body.capital_quote, "capital_quote")
                base = _amount(body.capital_base, "capital_base")
                _check_bot_capital(limits, bot["product"], quote, base, price_for)
            try:
                runner.switch_mode(
                    bot_id, body.mode, body.capital_quote, body.capital_base
                )
            except ModeRefused as error:
                raise HTTPException(
                    status_code=error.status,
                    detail=f"{error.code}: {error.message}",
                ) from None
            except ValueError as error:
                raise _invalid(str(error)) from None
            return _bot_json(_require_bot(store, bot_id))

    @app.post("/switches", dependencies=privileged)
    def set_switches(body: SwitchesBody) -> dict:
        """Turn the owner's live switches on or off, within the environment's ceiling.

        Turning a switch ON while `CROW_COINBASE_LIVE` forbids live answers 409 and
        writes nothing; turning one OFF is always allowed, because a switch that
        cannot be lowered is not a switch.  Lowering one touches no resting order:
        the orders already on a book stay there until a bot is paused, stopped or
        switched.
        """
        wanted = {
            name: value
            for name, value in (
                (SWITCH_LIVE, body.live_enabled),
                (SWITCH_AI_LIVE, body.ai_live_enabled),
            )
            if value is not None
        }
        with gateway.lock:
            if not live_switches.ceiling and any(wanted.values()):
                raise _conflict(CEILING_OFF)
            before = live_switches.snapshot()
            for name, value in wanted.items():
                live_switches.set(name, value)
            after = live_switches.snapshot()
            # One event per switch whose value ACTUALLY moved: writing the value
            # a switch already held changed nothing, so it says nothing either.
            for name, value in wanted.items():
                if before.get(name) == after.get(name):
                    continue
                label = (
                    "live trading switch"
                    if name == SWITCH_LIVE
                    else "AI live switch"
                )
                _record(
                    store,
                    "info",
                    f"{label} turned {'on' if value else 'off'}",
                    kind="live_switch",
                    data={"switch": name, "enabled": bool(value)},
                )
            return after

    # ------------------------------------------------ the lease
    @app.post("/lease", dependencies=lease_gate)
    def take_lease(body: LeaseBody) -> dict:
        """Take the lease for this holder, renew it, or answer that another holds it.

        A privileged route: the bearer token and a MAC both have to be presented,
        and this is one of the routes whose MAC may be keyed by the install token
        as well as by the owner's secret.  The answer carries whether the holder
        got the lease and the cursor the previous holder reached, so a client that
        takes over reads on from where events were last read rather than from the
        beginning.
        """
        if HOLDER_RE.fullmatch(body.holder) is None:
            raise _invalid(HOLDER_INVALID)
        return lease.acquire(body.holder)

    @app.post("/lease/cursor", dependencies=lease_gate)
    def advance_lease_cursor(body: LeaseCursor) -> dict:
        """Advance the named holder's cursor and report where it now stands.

        Only the holder of the live lease may move it: another holder's name, or
        no lease at all, is a 409 and nothing is written.  The cursor it names has
        to be one this engine holds an event for — `COALESCE(MAX(id),0)` — so a
        cursor past the newest event is a 422 rather than a promise retention
        could never keep.  It only ever moves forward: a lower value is answered
        with the stored one.  The cursor is the floor event retention keeps
        (`Store.prune_events`), so no event past it is deleted while it is stored.
        """
        if HOLDER_RE.fullmatch(body.holder) is None:
            raise _invalid(HOLDER_INVALID)
        return {"cursor": lease.set_cursor(body.holder, body.cursor)}

    # ------------------------------------------------ the owner's credentials
    def _credential_mac(request: Request, body_secret: str) -> str:
        """The MAC this one route needs: the body's own approval secret.

        `POST /credentials` is not one of the two gates above, because its key is
        the secret the request's body carries rather than one this engine already
        holds.  With no approval rail wired in there is nothing that could vouch
        for such a request, so it is refused exactly as an approval would be.

        Answers the kind of key the rail used (the owner's pinned secret, or the
        install token while there is no pin), which the route passes to the
        slot: that transaction decides again, from the pin as it stands when it
        writes, whether this request may pin anything.
        """
        if auth is None:
            raise HTTPException(status_code=403, detail=APPROVAL_INVALID)
        return auth.require_credentials(request, body_secret)

    if slot is not None:

        @app.post("/credentials/check", dependencies=lease_gate)
        def check_credentials(body: CredentialCheckBody) -> dict:
            """Judge one key pair and install nothing, whatever the answer is.

            The adapter is built to read the key's permissions and then dropped,
            so this route can never leave a live route behind: an engine that has
            not been connected still has no live exchange when the request
            returns.  A key that is refused answers 200 with `state: "refused"`,
            its code and its plain message — the request itself succeeded, and the
            key is what was judged.  The install token signs this one while no pin
            exists; after a pin only the owner's secret does.
            """
            return _key_check_json(
                slot.check(body.key_name, body.private_key)
            )

        @app.post(
            "/credentials",
            dependencies=[Depends(_check_token)],
        )
        def set_credentials(
            request: Request,
            body: CredentialBody = Depends(_credentials_body),
        ) -> Response:
            """Connect the owner's key: check it, pin it, and keep it in memory only.

            The body arrives from this route's own dependency, which decodes the
            bytes the middleware captured, parses them once with a hook that
            records a repeated name, and builds this model from that one result:
            nothing parses the body a second time, so a body that names one field
            twice — an object saying two values for `approve_secret` has no
            single value to approve — and a body this build cannot read are
            refused there, in the same `422` shape the rest of the surface
            answers, naming fields and never a value.

            The MAC over these exact bytes is checked next, keyed by the secret
            the body itself carries: with a pin in the store it has to be the
            pinned secret (`SECRET_MISMATCH` otherwise, answered before the
            stamp, the nonce and the MAC are read), and with no pin the install
            token is the key, so only the installer can make the first connect.
            The kind of key that answered is passed on, because a pin can be
            written between that answer and the write below.

            `repin` is refused on an unpinned engine — there is no pinned
            portfolio for it to move away from — and never reaches the slot.

            Past that, one `slot.set` under the cycle lock checks the key, and on
            an acceptable one writes the pin, the portfolio and the engine epoch
            in one transaction and keeps the live route.  That transaction
            re-checks the pin, so a connect that lost a race for the first pin is
            `403 SECRET_MISMATCH` and writes nothing; a refused key answers 422
            with its code and its plain message and leaves everything exactly as
            it was: nothing pinned, nothing kept, the live book still locked.
            """
            key_kind = _credential_mac(request, body.approve_secret)
            if body.repin and not slot.pinned():
                return _surface_refusal(REPIN_NEEDS_PIN)
            with gateway.lock:
                result = slot.set(
                    body.key_name,
                    body.private_key,
                    body.approve_secret,
                    repin=body.repin,
                    key_kind=key_kind,
                )
                if result.code == SECRET_MISMATCH:
                    # The pin the approval was decided against is not the pin the
                    # transaction found: the same code the rail answers with, and
                    # nothing was written or kept.
                    raise HTTPException(status_code=403, detail=SECRET_MISMATCH)
                if result.state != "ok":
                    _record(
                        store,
                        "warn",
                        "credentials refused",
                        kind="credentials",
                        data={"code": result.code} if result.code else {},
                    )
                    return _key_refusal(result)
                epoch = slot.engine_epoch()
            _record(store, "info", "credentials stored", kind="credentials")
            return JSONResponse(
                status_code=200,
                content={
                    "state": "ok",
                    "pinned": True,
                    "engine_epoch": epoch,
                    "key_last4": result.key_last4,
                    "portfolio_last4": result.portfolio_last4,
                },
            )

        @app.delete("/credentials", dependencies=privileged)
        def delete_credentials() -> Response:
            """Drop the live route and the in-memory secret, and leave the pin.

            A privileged route signed by the owner's secret: the install token is
            never a key here, because removing the way in is an owner's decision.
            A live order still resting on the account holds the credentials where
            they are (`409 LIVE_ORDERS_OPEN`), since without the key nothing could
            cancel it; otherwise the slot forgets the route and the rail forgets
            the secret, and the engine is exactly as it was before the first
            connect — pinned, and with no live exchange until a push.  One info
            event records the removal, and no value of the key in it.
            """
            with gateway.lock:
                if slot.live_orders_resting():
                    return JSONResponse(
                        status_code=409,
                        content={
                            "detail": f"{LIVE_ORDERS_OPEN}: {LIVE_ORDERS_OPEN_MESSAGE}"
                        },
                    )
                slot.clear()
                _record(store, "info", MESSAGE_REMOVED, kind="credentials")
                return JSONResponse(
                    status_code=200,
                    content={"state": "missing", "pinned": slot.pinned()},
                )

        @app.post("/credentials/forget", dependencies=privileged)
        def forget_credentials() -> Response:
            """Unpin the engine: drop the pin, the portfolio, the epoch and both switches.

            A privileged route signed by the owner's secret, and the one route
            that takes the pin away: the install token is never a key here, so a
            disconnect cannot be turned into a first install by whoever can read
            the token file.  A disconnect (`DELETE /credentials`) leaves the pin
            where it is, which is what makes the install token no key for the
            next push; this route is how an owner who no longer has the sealed
            approval secret starts over.

            Nothing is written while the engine is trading live: a live order
            still resting on the account is `409 LIVE_ORDERS_OPEN` (without the
            key nothing could cancel it), and a live bot that could still act —
            or the AI switch that allows its own live route — is `409 LIVE_BOTS`.
            A bot left STOPPED on the live book is not one of them: the kill
            switch and a bot's own stop leave it there, and a STOPPED bot cannot
            place, resume or switch books, so there is nothing the pin would
            settle for it.  Both refusals are read before anything is touched, so
            a refusal leaves the pin, the portfolio, the epoch, both switches and
            the live route exactly as they were.

            Past those checks, one transaction deletes the pin's kv row, the
            pinned portfolio and the engine epoch, and writes both live switches
            off with the JSON false `Switches.set` writes, so the engine reads as
            a first install: unpinned, every switch off, and a fresh epoch the
            next connect writes.  The slot then drops the live route and the
            in-memory secret, and one info event records the forget.  Nothing of
            the key, the secret or an exception's text is written anywhere.
            """
            with gateway.lock:
                if slot.live_orders_resting():
                    return JSONResponse(
                        status_code=409,
                        content={
                            "detail": f"{LIVE_ORDERS_OPEN}: {LIVE_ORDERS_OPEN_MESSAGE}"
                        },
                    )
                if live_switches.ai_live_enabled() or any(
                    bot["mode"] == LIVE and bot["status"] != STOPPED
                    for bot in store.list_bots()
                ):
                    return JSONResponse(
                        status_code=409,
                        content={"detail": f"{LIVE_BOTS}: {LIVE_BOTS_MESSAGE}"},
                    )
                with store.tx() as db:
                    for name in (APPROVE_PIN_KEY, PORTFOLIO_KEY, EPOCH_KEY):
                        db.execute("DELETE FROM kv WHERE key=?", (name,))
                    # The switches go off the way `Switches.set` writes them: the
                    # JSON false, so `Switches` reads them off and not merely
                    # absent.
                    store.put(SWITCH_LIVE, False)
                    store.put(SWITCH_AI_LIVE, False)
                slot.clear()
                _record(store, "info", MESSAGE_FORGOTTEN, kind="credentials")
                return JSONResponse(
                    status_code=200,
                    content={"state": "missing", "pinned": slot.pinned()},
                )

    @app.post("/bots/{bot_id}/pause", dependencies=guard)
    def pause_bot(bot_id: str) -> Response:
        """ACTIVE or PAUSED -> PAUSED, with this bot's whole book taken off the market.

        A pause has to take a bot out of the market, not only out of the cycle:
        the runner skips a PAUSED bot, so an order left resting would go on
        filling with nothing to answer it.  So the runner handles all of it
        (`Runner.pause_bot`): the status is written first — the bot places nothing
        from the moment this answers, whatever the sweep does — then the bot's own
        book (`bot["mode"]`, dry or live) is swept and reconciled until none of
        ITS rows is live, every fill still waiting for an opposite order is
        retired, and one transaction writes the params the bot already had back
        with a NEW grid epoch and `init_done` cleared.

        The new epoch is what makes a resume lay the WHOLE grid again: without it
        the resumed grid counts the replaced grid's filled rows as today's levels
        and lays only a fraction of its orders.  No other owner's order is
        touched, and the book the bot left is not visited.

        This route does NOT wrap the runner call in `gateway.lock`: the runner
        takes the lock for each cancel-and-reconcile pass and lets it go for the
        wait between passes, so a pause never makes a kill switch wait.  Only the
        checks below are made under it, briefly.

        A STOPPED bot is a conflict: a stop or the kill switch closed its book and
        nothing here re-opens one.  A bot whose pause is still sweeping is refused
        `409 PAUSE_IN_PROGRESS` and walks away without sweeping anything: the
        first press is still the one being answered, and a second sweep would race
        it for the same rows.  A bot that is ALREADY paused and is not being swept
        is swept again rather than refused, because that is how a pause whose
        sweep could not finish is retried — but a press inside `PAUSE_DEBOUNCE_S`
        of this bot's last pause attempt is `429 PAUSE_TOO_SOON` and sweeps
        nothing.  A pause of an ACTIVE bot is never debounced.  Only a pause that
        is not refused stamps `last_pause`, so a refusal neither debounces the
        retry that follows it nor claims the sweep it never made.

        Cancelling is the kill path, and the kill path works while a book is
        halted, so a halt is never a reason to leave a bot's orders behind: the
        sweep takes them off whatever the halt says about placing anything new.  A
        halt raised while the pause is waiting only ends the WAITING: a pass that
        still leaves a live row with the book halted answers 502 at once, instead
        of sweeping until the settle's own retries run out.

        A bot whose row changes while the pause is sweeping — a stop or a kill
        that marked it STOPPED, or a move of its mode, its params or its grid
        epoch — is `409 PAUSE_CHANGED`: nothing of the pause was written, so the
        answer neither writes over what changed the row nor claims orders may
        still be resting on a book the change already swept.

        A sweep that cannot complete — an exchange error, a book still live after
        the settle's own retries, a book halted with rows still live, or a live
        book with no exchange to settle from — answers 502 with the fixed
        `PAUSE_INCOMPLETE` sentence and nothing of the failure: the reason is
        logged server side, never reported.  The bot stays PAUSED in that case, so
        pressing Pause again re-runs the cancel, and the first failure of such an
        episode writes one `alert` (the kv key `api:pause_alert:<bot>` holds the
        episode open) so two failed presses say it once.

        A pause that did something writes one `bot_paused` info event naming the
        bot, its book and `reason: "owner"`; one that found an already-paused bot
        with a clean book writes no event at all.  Either way the answer carries
        `paused_reason`, the same word GET /bots reports.  For as long as the
        sweep runs, the bot is named in the runner's pausing set, so the resume,
        recenter and mode routes answer `409 PAUSE_IN_PROGRESS` rather than move a
        bot that is being swept.  Pause stays the bearer token's alone: no
        approval is asked, and the kill switch is unchanged.
        """
        with gateway.lock:
            bot = _require_bot(store, bot_id)
            if bot["status"] == STOPPED:
                raise _conflict(f"bot {bot_id} is {bot['status']}, not {ACTIVE}")
            if runner.is_pausing(bot_id):
                raise _conflict(PAUSE_IN_PROGRESS)
            book = bot["mode"]
            at = now()
            if bot["status"] == PAUSED:
                last = last_pause.get(bot_id)
                if last is not None and 0.0 <= at - last < PAUSE_DEBOUNCE_S:
                    raise HTTPException(status_code=429, detail=PAUSE_TOO_SOON)
            # Stamped before the sweep, so a pause that FAILS is still the pause
            # this bot was just asked for (and the retry is a few seconds away).
            last_pause[bot_id] = at
        try:
            cleared, prior_status = runner.pause_bot(bot_id)
        except PauseChanged:
            # The bot was changed under the sweep (a stop, a kill, a move): that
            # is its own answer, and nothing of the pause was written.
            log.warning("bot %s: pause ended, the bot changed", bot_id)
            raise _conflict(PAUSE_CHANGED) from None
        except Exception as error:  # noqa: BLE001 - the status stands
            log.error(
                "bot %s: pause could not sweep the %s book: %s",
                bot_id,
                book,
                error,
            )
            _pause_alert(store, bot_id, book)
            return JSONResponse(
                status_code=502, content={"detail": PAUSE_INCOMPLETE}
            )
        # The sweep completed, so the episode (if there was one) is over: the next
        # failure is news again.  What the pause found is only the log's business;
        # the answer below is the bot row as it now stands.
        _pause_alert_clear(store, bot_id)
        log.info(
            "bot %s: paused (%s live row(s) cleared, was %s)",
            bot_id,
            cleared,
            prior_status,
        )
        return _paused_bot_json(_require_bot(store, bot_id), store)

    @app.post("/bots/{bot_id}/resume", dependencies=guard)
    def resume_bot(
        bot_id: str, request: Request, body: Optional[Acknowledge] = None
    ) -> dict:
        """PAUSED -> ACTIVE, re-basing the bot's own high-water mark first.

        A bot paused by its own drawdown stop is resumed against a mark written
        down to its equity as of now, so the same drawdown does not pause it again
        on the next cycle; that is why the request carries an acknowledgement.
        The acknowledgement is checked first, then the bot: one on the live book
        also needs its owner's approval (a refusal is `LIVE_NEEDS_OWNER`), because
        resuming it puts real money back to work.  Then the status: a STOPPED bot
        is not resumed here, it is a conflict.  A book that cannot be priced
        answers 503 and leaves the bot paused, since no mark can be written off it.

        A bot a pause is still sweeping is `409 PAUSE_IN_PROGRESS`: the pause
        waits between its own passes, and a resume in that window would be written
        over by the pause's final transaction.  A resume that goes through clears
        the pause's own note (`bot:paused_reason:<id>`), so the bot no longer reads
        as paused for a reason, and it answers `paused_reason` as null.
        """
        if not _acknowledged(body):
            raise _conflict(RESUME_ACK)
        with gateway.lock:
            bot = _require_bot(store, bot_id)
            if runner.is_pausing(bot_id):
                raise _conflict(PAUSE_IN_PROGRESS)
            _live_needs_owner(bot, request)
            if bot["status"] != PAUSED:
                raise _conflict(f"bot {bot_id} is {bot['status']}, not {PAUSED}")
            product = bot["product"]
            book = bot["mode"]
            mid = runner._mid(product)
            if mid is None:
                raise _unavailable(
                    f"cannot price {product} for {bot_id}: its equity is unknown, "
                    "so the bot stays paused"
                )
            runner.rebase_hwm(
                bot_id,
                runner.ledger.equity(bot_id, {product: mid}, product, book=book),
                book,
            )
            store.set_bot_status(bot_id, ACTIVE)
            bot["status"] = ACTIVE
            # The reason a pause wrote belongs to the pause that is now over.
            store.put(f"{PAUSED_REASON_PREFIX}{bot_id}", None)
            return _paused_bot_json(bot, store)

    @app.post("/bots/{bot_id}/stop", dependencies=guard)
    def stop_bot(bot_id: str) -> Response:
        """Sweep this bot's book off the exchange, then mark it STOPPED.

        The status is written whether or not the sweep went through: reconcile
        sweeps a STOPPED owner's book again, so a bot left stopped is exactly a
        bot whose leftover orders get retried, while a bot left ACTIVE would go
        on placing.  A failing sweep answers 502, with the status already
        written.  A bot that is already stopped is answered, not swept.

        A stopped bot is not paused for a reason, so the pause's own note
        (`bot:paused_reason:<id>`) goes with the status — on the stopped path and
        on the already-stopped one alike — and a clear the store will not take is
        only logged, because the stop itself already happened.
        """
        with gateway.lock:
            bot = _require_bot(store, bot_id)
            if bot["status"] == STOPPED:
                _pause_reason_clear(store, bot_id)
                return _bot_json(bot)
            failure: Optional[BaseException] = None
            try:
                gateway.cancel_all(scope="owner", owner=bot_id)
            except Exception as error:  # noqa: BLE001 - the bot stops regardless
                failure = error
                log.error("bot %s: stop could not sweep the book: %s", bot_id, error)
            store.set_bot_status(bot_id, STOPPED)
            bot["status"] = STOPPED
            _pause_reason_clear(store, bot_id)
            if failure is not None:
                return JSONResponse(
                    status_code=502,
                    content={
                        "detail": f"could not cancel {bot_id}'s orders: {failure}"
                    },
                )
            return _bot_json(bot)

    @app.post("/bots/{bot_id}/recenter", dependencies=guard)
    def recenter_bot(bot_id: str, request: Request, body: Recenter) -> dict:
        """Move a grid bot's center, then let the next cycle lay the new book.

        Only a strategy with a `recenter` (the grid) can be moved: a rebalancer
        has no center to move, so it is refused rather than silently ignored.  A
        recenter tears the bot's book down and lays a new one, which for a bot on
        the live book is a real-money decision: it needs its owner's approval
        first, and a refusal is `LIVE_NEEDS_OWNER`.  A bot a pause is still
        sweeping is `409 PAUSE_IN_PROGRESS`: the pause waits between its passes,
        and a recenter in that window would race the pause's own final write.
        """
        with gateway.lock:
            bot = _require_bot(store, bot_id)
            if runner.is_pausing(bot_id):
                raise _conflict(PAUSE_IN_PROGRESS)
            _live_needs_owner(bot, request)
            if bot["status"] == STOPPED:
                raise _conflict(f"bot {bot_id} is {STOPPED}; it cannot be recentered")
            strategy = strategies.get(bot["strategy"])
            if strategy is None or not hasattr(strategy, "recenter"):
                raise _invalid(
                    f"strategy {bot['strategy']!r} cannot be recentered"
                )
            center = _positive(body.center, "center")
            try:
                runner.recenter(bot_id, center)
            except ValueError as error:
                raise _invalid(str(error)) from None
            except RuntimeError as error:
                raise _conflict(str(error)) from None
            except Exception as error:  # noqa: BLE001 - the exchange failed the sweep
                log.warning("bot %s: recenter failed: %s", bot_id, error)
                raise _bad_gateway(f"could not recenter {bot_id}: {error}") from None
            return _bot_json(_require_bot(store, bot_id))

    # ------------------------------------------------ the kill switch
    @app.post("/kill", dependencies=guard)
    def kill() -> Response:
        """Halt first and without the lock, then sweep the book and stop every bot.

        The halt takes no lock by design, so a kill never queues behind a cycle
        that is holding it.  No step of it may stop the ones after it: a halt
        that cannot be persisted, a sweep that fails and a bot whose status
        cannot be written are each remembered and logged, and the sweep and the
        stops happen anyway.  Any remembered failure answers 502 with the
        reasons and `halted` still true: the flag is what refuses every later
        order, and what could be done was done.
        """
        failures: list[str] = []
        cancelled = 0
        stopped: list[str] = []
        try:
            gateway.halt("kill switch")
        except Exception as error:  # noqa: BLE001 - the sweep runs whatever happened
            failures.append(f"the halt flag could not be persisted: {error}")
            log.exception("kill: the halt failed")
        with gateway.lock:
            try:
                cancelled = gateway.cancel_all(scope="all")
            except Exception as error:  # noqa: BLE001 - the bots stop regardless
                failures.append(f"the sweep failed: {error}")
                log.error("kill: the sweep failed: %s", error)
            stopped = _stop_every_bot(store, failures)
        # The kill is announced whatever else failed: the halt is already in
        # force, and what was cancelled and stopped is what a reader needs.
        try:
            swept = int(cancelled or 0)
        except (TypeError, ValueError):
            swept = 0
        _record(
            store,
            ALERT_LEVEL,
            "kill switch pressed",
            kind="halt",
            data={"cancelled": swept, "stopped": len(stopped)},
        )
        if failures:
            return JSONResponse(
                status_code=502,
                content={"detail": "; ".join(failures), "halted": True},
            )
        return JSONResponse(
            status_code=200,
            content={"halted": True, "cancelled": cancelled, "stopped": stopped},
        )

    @app.post("/halt/clear", dependencies=privileged)
    def clear_halt(body: Optional[Acknowledge] = None) -> dict:
        """Clear every halt, re-basing each in-play book's mark and re-initialising grids.

        Clearing is an acknowledgement, not a reset: each book at least one bot
        trades has its portfolio high-water mark written down to that book's own
        equity, so the drawdown the stop fired on cannot halt the engine again on
        the next cycle.  Every book is priced BEFORE anything is written.  A book
        that still cannot be priced does not hold the clear: it is cleared with
        its portfolio mark RESET, so the next priced cycle ratchets a fresh one,
        and its `rebased` entry is null rather than a number.  Then every grid bot
        that is not STOPPED re-initialises its book, so the engine resumes with a
        live book rather than the one the halt left resting; if one of them cannot,
        nothing is re-based or cleared and the halt stays.  A bot stopped by a kill
        is not restarted by this.  A route that re-initialises live grids and moves
        the marks a stop is measured against is a privileged one, so it needs the
        same approval a mode switch does.
        """
        if not _acknowledged(body):
            raise _conflict(HALT_CLEAR_ACK)
        with gateway.lock:
            modes = {bot["mode"] for bot in store.list_bots()}
            in_play = [book for book in BOOKS if book in modes]
            priced: dict[str, Optional[D]] = {
                book: gateway.portfolio_equity(book) for book in in_play
            }
            reinitialised: list[str] = []
            for bot in store.list_bots():
                if bot["status"] == STOPPED:
                    continue
                strategy = strategies.get(bot["strategy"])
                if strategy is None or not hasattr(strategy, "recenter"):
                    continue
                try:
                    runner.reinit_bot(bot["id"])
                except Exception as error:  # noqa: BLE001 - the halt stays
                    log.warning(
                        "bot %s: re-init on clear failed: %s", bot["id"], error
                    )
                    raise _bad_gateway(
                        f"could not re-init {bot['id']}: {error}; the halt stays"
                    ) from None
                reinitialised.append(bot["id"])
            # A re-init moves no money: it sweeps resting orders and retires
            # pending fills, neither of which changes an owner's equity, so the
            # marks priced above are the equity each book holds now.
            for book, equity in priced.items():
                if equity is None:
                    # No number can be written for a book nothing can price, so
                    # the mark the stop fired on goes: the next priced cycle
                    # ratchets a fresh one.
                    store.reset_hwm(PORTFOLIO_OWNER, book)
                    continue
                runner.rebase_hwm(PORTFOLIO_OWNER, equity, book)
            gateway.clear_halt()
            _record(store, "info", "halt cleared", kind="halt")
        return {
            "halted": False,
            "rebased": {
                f"{PORTFOLIO_OWNER}:{book}": (
                    None if equity is None else _text(equity)
                )
                for book, equity in priced.items()
            },
            "reinitialised": reinitialised,
        }

    # ------------------------------------------------ fills
    @app.get("/bots/{bot_id}/fills", dependencies=guard)
    def bot_fills(bot_id: str) -> list[dict]:
        """Every fill booked against this bot, oldest trade first."""
        _require_bot(store, bot_id)
        rows = store.conn().execute(
            "SELECT * FROM fills WHERE owner=? ORDER BY trade_time, trade_id",
            (bot_id,),
        ).fetchall()
        return [_fill_json(row) for row in rows]

    @app.get("/export/fills.csv", dependencies=guard)
    def export_fills(year: Optional[str] = None) -> Response:
        """The authoritative tax export: one row per booked fill, all or one year's.

        Built from the database, so it carries every fill the engine booked; the
        `trades.csv` beside the database is a convenience copy that can in
        principle lag behind it.
        """
        stamp = ALL_YEARS
        if year is not None:
            if not YEAR_RE.fullmatch(year):
                raise _invalid("year must be four digits, e.g. 2025")
            stamp = year
        rows = _fill_rows(store, year)
        return Response(
            content=_fills_csv(rows),
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{CSV_PREFIX}{stamp}{CSV_SUFFIX}"'
                )
            },
        )

    # ------------------------------------------------ profit and loss
    @app.get("/pnl", dependencies=guard)
    def pnl() -> dict:
        """Realized profit, fees, marked equity and the hold-the-mix shadow, per bot.

        Every figure is the bot's CURRENT book's: its realized profit comes from
        that book's sell rows, its fees from that book's fills, its equity from
        that book's capital and rows, and its benchmark from that book's own
        baseline.  So a bot that switched books reports the book it trades now and
        never the history of the one it left — and, on that book, only the period
        it has been running (`store.book_epoch`), so a bot that left the dry book
        and came back reports the profit and fees of the period it came back for
        rather than adding the one before it.  The per-bot fill list and the tax
        export stay unfiltered: they carry every fill of every book.

        A bot's equity is marked at the mid of a snapshot the gateway can price an
        order from (`runner._mid`), so a missing, stale or crossed book leaves its
        equity and its comparison against the benchmark null rather than marked
        off a book nothing could be checked against; the same is true of a bot
        whose benchmark was never started.  `realized` is null for a strategy that
        keeps no cost basis (a rebalancer funds a target mix instead of buying a
        position), and a decimal string otherwise.
        """
        benchmark = Benchmark(store)
        entries: dict[str, dict] = {}
        for bot in store.list_bots():
            bot_id = bot["id"]
            product = bot["product"]
            book = bot["mode"]
            equity: Optional[D] = None
            vs_hold: Optional[D] = None
            mid = runner._mid(product)
            if mid is not None:
                equity = gateway.ledger.equity(
                    bot_id, {product: mid}, product, book=book
                )
                try:
                    vs_hold = benchmark.vs_hold(bot_id, equity, mid, book=book)
                except KeyError:
                    vs_hold = None
            gained = (
                None
                if bot["strategy"] == REBALANCE
                else _text(realized_pnl(store, bot_id, book=book).get(bot_id, D(0)))
            )
            entries[bot_id] = {
                "mode": book,
                "realized": gained,
                "fees": _text(_fee_total(store, bot_id, book)),
                "equity": None if equity is None else _text(equity),
                "vs_hold": None if vs_hold is None else _text(vs_hold),
            }
        return {"bots": entries}

    # ------------------------------------------------ the AI's orders
    if ai_orders is not None:

        @app.exception_handler(AiRefused)
        async def _ai_refused(request: Request, error: AiRefused) -> JSONResponse:
            """Answer a refused AI order request: its code, its sentence, its status.

            Every refusal that surface raises answers the same shape, so a panel
            reads one code and one plain sentence whatever went wrong, and no
            value of the request comes back with it.
            """
            return JSONResponse(
                status_code=error.status,
                content={"code": error.code, "message": error.message},
            )

        @app.post("/ai/previews", dependencies=guard)
        def create_ai_preview(body: AiPreviewBody) -> dict:
            """Measure one proposed AI order against the chain and store the answer.

            The bearer token's route: it writes a preview row and nothing else —
            no order, no exchange call.  A chain refusal answers 200 with the
            row's state `rejected` and the code, which is the request succeeding
            at measuring an order; a body the surface cannot read is the 422 the
            rest of the app answers, and a preview asked for while too many are
            waiting or too many have been asked for this hour is `429
            PREVIEW_LIMIT` with nothing written.
            """
            return ai_orders.preview(
                body.product, body.side, body.size, body.limit_price
            )

        @app.get("/ai/previews", dependencies=guard)
        def list_ai_previews(state: Optional[str] = None) -> list[dict]:
            """The newest previews, optionally only one state's.

            Reading is the bearer token's alone (it moves nothing).  A state this
            engine does not know answers 422 `INVALID` rather than an empty
            list.
            """
            wanted = None if state is None or not str(state).strip() else str(state)
            return ai_orders.list(wanted)

        @app.post("/ai/previews/{preview_id}/approve", dependencies=privileged)
        def approve_ai_preview(request: Request, body: AiApproveBody) -> dict:
            """Spend one preview on the owner's yes: re-check everything, then place.

            A privileged route behind the STRICT gate — the owner's approval
            secret, never the install token — because it is what turns a proposal
            into an order.  The approve runs under the gateway's cycle lock, and
            the row's own conditional transition is what decides which of two
            approvals places the one order.  The preview id is read from the
            path.
            """
            identifier = request.path_params.get("preview_id")
            return ai_orders.approve(identifier, body.hash)

        @app.post("/ai/previews/{preview_id}/reject", dependencies=guard)
        def reject_ai_preview(request: Request) -> dict:
            """Retire one preview the owner said no to; nothing is sent.

            The bearer token's route: turning a proposal down moves no money, so
            it needs no approval — and a preview that is not waiting for an
            answer is a 409.
            """
            return ai_orders.reject(request.path_params.get("preview_id"))

        @app.post("/ai/orders/{cid}/cancel", dependencies=guard)
        def cancel_ai_order(cid: str) -> dict:
            """Cancel one of the AI's own orders, through the gateway.

            The bearer token's route, because stopping is never blocked.  An
            order that is not the AI's is a 403 `NOT_OWNER`; one that cannot be
            cancelled now is a 409; and the preview the order placed becomes
            `cancelled`.
            """
            return ai_orders.cancel_order(cid)

    return app


# ---------------------------------------------------------------- answers as JSON


def _invalid_fields(error: RequestValidationError) -> list[str]:
    """The fields a validation failure names, and none of the values it carried.

    Each location is joined by dots (`approve_secret`, `params.step_pct`) with the
    leading `body` dropped, and a failure that is about the body as a whole (a
    body that is not JSON at all) names no field at all rather than a position.
    Order is the order FastAPI reported, and each name appears once.
    """
    fields: list[str] = []
    for problem in error.errors():
        loc = tuple(problem.get("loc") or ())
        if loc and loc[0] == "body":
            loc = loc[1:]
        name = ".".join(str(part) for part in loc)
        if name and name not in fields:
            fields.append(name)
    return fields


def _unreadable_body() -> RequestValidationError:
    """The refusal for a body this build cannot read: `422 INVALID`, no field.

    A body that does not decode as UTF-8, does not parse as JSON, or does not
    parse into an object never became a field of anything, so it names none.  It
    is raised as the validation failure the surface's own handler answers, which
    is what keeps that one `422` shape in a single place: the code `INVALID` and
    the fields it names — here, none at all.
    """
    return RequestValidationError([])


def _credentials_body(request: Request) -> CredentialBody:
    """The `POST /credentials` body, from ONE parse of the bytes the MAC covers.

    FastAPI would parse the body itself, from the raw bytes, and its parser and
    this route's own reading of them could disagree: the same bytes can be one
    object to a parser that sniffs an encoding and unreadable to a strict UTF-8
    decode, and a body that names a field twice has two values only until a
    model keeps the last of them.  So the bytes `BodyCaptureMiddleware` captured
    are decoded here — strictly, as UTF-8, with no encoding sniffed — parsed as
    JSON from the decoded TEXT (a leading BOM is then a parse failure and not an
    encoding hint), and read into the model from that single result.  The route
    takes the model from this dependency, so nothing parses the body again.

    Bytes this build cannot read — not UTF-8, not JSON, or not a JSON object once
    parsed — are the `422 INVALID` naming no field.  A body that names one field
    twice is the `422 INVALID` naming the duplicated fields this build has a
    field for, and naming nothing when it has none: it is refused rather than
    answered with one of its two values.  A body the model refuses is the same
    `422` every other route's validation failure earns — the field names and no
    values.  None of those ever reaches the handler.

    A request whose body was not captured (no `X-Crow-Signature` header, or a
    body over the capture cap) is refused `403 APPROVAL_INVALID`: the approval
    cannot vouch for bytes it never saw, so it is the approval's refusal rather
    than a body this route read.  Nothing of a body is reported by any of these.
    """
    raw = getattr(request.state, "raw_body", None)
    if not isinstance(raw, (bytes, bytearray)):
        raise HTTPException(status_code=403, detail=APPROVAL_INVALID)
    known = tuple(CredentialBody.model_fields)
    repeated: list[str] = []
    seen_twice = False

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict:
        """One JSON object: note every name it gives twice, then read it as usual."""
        nonlocal seen_twice
        names = [name for name, _value in pairs]
        for name in names:
            if names.count(name) < 2:
                continue
            seen_twice = True
            if name in known and name not in repeated:
                repeated.append(name)
        return dict(pairs)

    try:
        text = bytes(raw).decode("utf-8")
        parsed = json.loads(text, object_pairs_hook=pairs_hook)
    except (UnicodeDecodeError, ValueError):
        raise _unreadable_body() from None
    if not isinstance(parsed, dict):
        raise _unreadable_body()
    if seen_twice:
        raise DuplicatedBodyFields(repeated)
    try:
        return CredentialBody.model_validate(parsed)
    except ValidationError as error:
        raise RequestValidationError(error.errors()) from None


def _key_check_json(check: KeyCheck) -> dict:
    """One `KeyCheck` as the surface reports it: five fields, no key material."""
    return {
        "state": check.state,
        "code": check.code,
        "message": check.message,
        "key_last4": check.key_last4,
        "portfolio_last4": check.portfolio_last4,
    }


def _key_refusal(check: KeyCheck) -> JSONResponse:
    """A key refusal: the code and its plain message, and no value of the request."""
    return JSONResponse(
        status_code=422,
        content={"code": check.code, "message": check.message},
    )


def _surface_refusal(message: str) -> JSONResponse:
    """A 422 this surface raised itself: the code, a plain reason, no values."""
    return JSONResponse(
        status_code=422, content={"code": INVALID_BODY, "message": message}
    )


def _stop_every_bot(store: Store, failures: list[str]) -> list[str]:
    """Mark every bot STOPPED and answer their ids in the order they are stored.

    One bot whose status cannot be written is logged into *failures* and the
    rest are still stopped: a kill that left half the bots able to place would
    be worse than one that reports the write it could not make.

    Each bot that is stopped also loses the note its last pause wrote
    (`bot:paused_reason:<id>`), since a bot a kill swept is not paused for a
    reason.  That clear is the bot's own attempt: one the store will not take is
    only logged, so it never keeps this bot from counting as stopped or the next
    one from being stopped.
    """
    stopped: list[str] = []
    for bot in store.list_bots():
        try:
            store.set_bot_status(bot["id"], STOPPED)
        except Exception as error:  # noqa: BLE001 - the next bot is still stopped
            failures.append(f"bot {bot['id']} could not be stopped: {error}")
            log.error("kill: could not stop bot %s: %s", bot["id"], error)
            continue
        _pause_reason_clear(store, bot["id"])
        stopped.append(bot["id"])
    return stopped