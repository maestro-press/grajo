"""credentials.py: the owner's API key, its pin, and the epoch that guards it.

The engine trades the live book with a Coinbase key the owner pastes in once: a
key NAME (`organizations/{org}/apiKeys/{id}`, no secret in it) and an EC private
key in PEM form.  This module holds the whole of what the engine does with that
pair, and the rule it is built to is that the pair lives in PROCESS MEMORY only:

* nothing here writes the key name, the private key or the approval secret to a
  file, a kv row, an event, a log line or an HTTP body.  The one thing persisted
  about the secret is its sha256 hex, which is the pin (`auth.APPROVE_PIN_KEY`),
  and the pin is written by `CredentialSlot.set` in the same transaction as the
  portfolio and the epoch,
* every message this module produces is plain words about what is wrong, never a
  value the request sent, and never the text of an exception an SDK raised.

`KeyCheck` is one answer about one key: `state` ("missing", "ok" or "refused"),
the `code` of a refusal, a `message` a person can read, and the last four
characters of the key name and of the portfolio — enough to tell two keys apart
in a UI, and not enough to be either.

`evaluate_permissions` is the whole policy, and it is pure: a key that does not
deny the transfer permission in so many words is refused first (it can move money
out, so nothing else it may do matters), then a key that names no portfolio, then
one whose portfolio is not a CONSUMER one (the owner's main portfolio is refused
with a code of its own), then one scoped to a portfolio this engine did not pin,
then one that cannot trade, then one that cannot even see the account.
Everything it reads is a permission the exchange reported; the order is what
makes the answer stable whatever a key is set to.

`valid_key_shape` is what runs before anything is built or reached: a key name in
the shape Coinbase answers, and a private key that really is one — a PEM pair of
the two headers a key may arrive with (a SEC1 "EC" one or a PKCS8 one), built
here from parts so this file holds no private-key header as a literal.  `\\n` may
arrive as the two characters backslash-n out of a JSON body, so it is normalised
before the shape is judged and before the key is handed to an adapter.

`CredentialSlot` is the one place a key becomes a live route.  It builds the
adapter through an injected `build_live(creds)` — the real `LiveExchange` in
production, a fake in a test — asks it for its permissions, and on an acceptable
key keeps exactly one thing: an `ExchangeRouter` over that adapter, with the two
accounts' USD one pool because there is one key.  Nothing else retains the key,
and the router is what `BookRouter` asks for on every access, so a restart has no
live route at all until the owner pushes the key again: the live book answers
`LIVE_LOCKED` in the meantime — the pin that is still in the store is what
makes the install token no key for that push.  `clear` drops the router and the
in-memory secret and leaves the pin where it is; unpinning is the surface's own
`POST /credentials/forget`, which deletes the pin, the pinned portfolio and the
engine epoch and writes both live switches off in one transaction, and this
module neither performs that write nor decides who may call it.

`set` is the only writer: it checks the key, and only then writes the pin (first
connect only), the pinned portfolio (replaced only by a `repin`), and the engine
epoch (generated once, kept on every later push) in ONE transaction, keeps the
router, and hands the approval secret to the rail.  The epoch is the answer the
surface reports on every connect, so a client can tell "the same engine, pushed
again" from "a different engine".  The key check happens BEFORE that
transaction — it builds a live adapter and asks the exchange — so the
transaction is short, and it re-checks the pin itself: the approval rail decides
which kind of key a request presented from the pin as it stood when the request
arrived, and two first connects can both be decided against an unpinned store.
Only one of them may pin, so the transaction refuses `SECRET_MISMATCH` when the
pin row is there and the request was keyed with the install token, and refuses
it when the body's secret is not the pinned one — `repin` included, because a
repin moves the portfolio and never the secret.  The rail's in-memory secret is
set only after the transaction commits, and it is set only for a secret whose
own hash is the pin the transaction left behind.

Refusal codes are strings equal to their names, so a code travels in JSON
unchanged: `KEY_INVALID`, `KEY_CAN_TRANSFER`, `KEY_NOT_PORTFOLIO_SCOPED`,
`KEY_DEFAULT_PORTFOLIO`, `KEY_WRONG_PORTFOLIO`, `KEY_CANNOT_TRADE`,
`LIVE_ORDERS_OPEN` — and `SECRET_MISMATCH` for the pin refusal, which the
approval rail raises on this route and which the transaction below answers with
the same code (defined there, where it is answered, and re-exported here with
the rest).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, replace
from typing import Any, Callable, Optional

from .auth import (
    APPROVE_PIN_KEY,
    KEY_KIND_INSTALL_TOKEN,
    KEY_KIND_PINNED_SECRET,
    SECRET_MISMATCH,
    pin_exists,
)
from .books import LIVE, LIVE_LOCKED
from .router import ExchangeRouter
from .store import LIVE_STATUSES, Store

# ---------------------------------------------------------------- refusal codes
KEY_INVALID = "KEY_INVALID"  # unreadable key, unreadable permissions, cannot see
KEY_CAN_TRANSFER = "KEY_CAN_TRANSFER"  # the key can move money out
KEY_NOT_PORTFOLIO_SCOPED = "KEY_NOT_PORTFOLIO_SCOPED"  # not a portfolio to scope to
KEY_DEFAULT_PORTFOLIO = "KEY_DEFAULT_PORTFOLIO"  # the owner's main portfolio
KEY_WRONG_PORTFOLIO = "KEY_WRONG_PORTFOLIO"  # another portfolio than the pinned one
KEY_CANNOT_TRADE = "KEY_CANNOT_TRADE"  # the key has no trade permission
LIVE_ORDERS_OPEN = "LIVE_ORDERS_OPEN"  # live orders are resting: not now
# `SECRET_MISMATCH` is imported above: the rail raises it, this module reports it.

# ---------------------------------------------------------------- portfolio types
# The only portfolio type this engine trades: a user-created, consumer portfolio
# of its own, which is what the pinned portfolio is.
#
# UNVERIFIED: that a user-created portfolio reports CONSUMER; confirmed at
# go-live Test connection.
PORTFOLIO_TYPE = "CONSUMER"
# The owner's main Coinbase portfolio.  A key scoped to it could trade money this
# engine never budgeted, so it is refused with a code and a message of its own.
DEFAULT_PORTFOLIO_TYPE = "DEFAULT"

# ---------------------------------------------------------------- the kv keys
# The portfolio the first connect pinned.  A later key scoped to another one is
# refused unless the owner asks for `repin`, which is the only way it moves.
PORTFOLIO_KEY = "credentials_portfolio"
# The epoch of this engine's credentials, generated on the first connect and kept
# afterwards.  Reported on every connect, and never used as a secret.
EPOCH_KEY = "engine_epoch"

# ---------------------------------------------------------------- the key's shape
# A Coinbase key name, in the shape the exchange answers: no secret in it, and
# nothing in it this engine has to parse.
KEY_NAME_RE = re.compile(r"organizations/[A-Za-z0-9-]+/apiKeys/[A-Za-z0-9-]+")
# The two characters a JSON body may carry where a newline belongs.
BACKSLASH_N = "\\n"

# The private-key headers, built from parts rather than written out: this file
# must never hold a private-key header as a literal.  A key arrives as SEC1 (the
# "EC" label and a space) or as PKCS8 (no label of its own), and both are private
# keys.
_PEM_BEGIN = "-----BEGIN "
_PEM_END = "-----END "
_PEM_KEY = "PRIVATE KEY-----"
_PEM_LABELS = ("EC ", "")
PEM_PAIRS = tuple(
    (_PEM_BEGIN + label + _PEM_KEY, _PEM_END + label + _PEM_KEY)
    for label in _PEM_LABELS
)

# ---------------------------------------------------------------- the messages
# Every one of these is plain words, and none of them carries a value the request
# sent, a key's body, a portfolio id or an exception's text.
MESSAGE_OK = "This key can trade one portfolio and cannot move money out."
MESSAGE_SHAPE = "That is not a Coinbase key name and private key this engine can read."
MESSAGE_UNREADABLE = (
    "The exchange could not read this key; check the key name and the private key."
)
MESSAGE_TRANSFER = (
    "This key can move money out; make a key with View and Trade only."
)
MESSAGE_UNSCOPED = (
    "This key is not scoped to a portfolio; make a portfolio-scoped key."
)
MESSAGE_DEFAULT_PORTFOLIO = (
    "This key is for your main Coinbase portfolio. Create a key for the Crow "
    "portfolio instead."
)
MESSAGE_WRONG_PORTFOLIO = (
    "This key is scoped to a different portfolio than the one this engine trades."
)
MESSAGE_CANNOT_TRADE = "This key cannot trade; give it Trade permission."
MESSAGE_CANNOT_VIEW = "This key cannot see the account; give it View permission."
MESSAGE_SECRET_MISMATCH = "That approval secret is not the one this engine pinned."
MESSAGE_REMOVED = "credentials removed"
# The record of an owner's forget, which unpins the engine rather than disconnecting
# it: no key, no secret and no portfolio in the sentence.
MESSAGE_FORGOTTEN = "Credentials forgotten"

# The book a resting order has to be on for a disconnect to be refused: the live
# one, because its orders cannot be settled without the account this key opens.
RESTING_STATUSES = LIVE_STATUSES

# The refusal the live book answers while the slot holds nothing.  Named here so a
# reader of this module can see that "no live exchange yet" is `books.LIVE_LOCKED`
# rather than a second code of this module's own.
NO_LIVE_EXCHANGE = LIVE_LOCKED


# ---------------------------------------------------------------- one answer


@dataclass(frozen=True)
class KeyCheck:
    """One answer about one key: its state, a refusal code, and how it looks.

    `state` is "missing" (nothing was asked), "ok" or "refused".  `code` is one of
    the refusal codes above for a refusal and None otherwise.  `message` is plain
    words for a person, and `key_last4` / `portfolio_last4` are the last four
    characters of the key name and of the portfolio the key names — enough to
    tell two keys apart in a UI and not enough to be either.
    """

    state: str
    code: Optional[str]
    message: str
    key_last4: Optional[str]
    portfolio_last4: Optional[str]


def _last4(value: Any) -> Optional[str]:
    """The last four characters of a name, or None when there is no name."""
    if not isinstance(value, str) or not value:
        return None
    return value[-4:]


def _portfolio_of(perms: Any) -> Optional[str]:
    """The portfolio a permissions answer names, or None when it names none.

    Only a non-blank string is a portfolio: an absent key, a null and a blank one
    all mean the answer does not say, which is a different thing from naming one.
    """
    if not isinstance(perms, dict):
        return None
    value = perms.get("portfolio_uuid")
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _refused(code: str, message: str, key_name: Any, perms: Any = None) -> KeyCheck:
    """One refusal, carrying only the code, the message and two name suffixes."""
    return KeyCheck(
        state="refused",
        code=code,
        message=message,
        key_last4=_last4(key_name),
        portfolio_last4=_last4(_portfolio_of(perms)),
    )


def evaluate_permissions(perms: Any, pinned_portfolio: Optional[str]) -> KeyCheck:
    """Judge one key's permissions against the portfolio this engine pinned.

    Pure, and judged in ONE fixed order, which is what makes the answer stable
    whatever a key is set to:

    1. `can_transfer` has to be the literal `False`.  Absent, null, a number,
       the string "false" and a truthy value are all a key that may move money
       out, and are refused `KEY_CAN_TRANSFER` before anything else is looked
       at — nothing else such a key may do matters.
    2. The key has to name a portfolio (`portfolio_uuid`), or it is
       `KEY_NOT_PORTFOLIO_SCOPED`: there is nothing for the engine to scope its
       trading to.
    3. That portfolio's `portfolio_type` has to be the string `"CONSUMER"`.  The
       owner's main portfolio (`"DEFAULT"`) is `KEY_DEFAULT_PORTFOLIO`, with a
       message of its own, and every other value — `"INTX"`, `"UNDEFINED"`, a
       value in another case, a number, a null, a missing field — is
       `KEY_NOT_PORTFOLIO_SCOPED`, because a key whose portfolio is not a
       consumer one is not scoped where this engine can use it.
    4. A key scoped to a portfolio other than the pinned one is
       `KEY_WRONG_PORTFOLIO`.  A `pinned_portfolio` of None is an engine with
       nothing pinned yet: the first connect is what pins one, so there is
       nothing to compare against.
    5. `can_trade` has to be the literal `True`, or `KEY_CANNOT_TRADE`.
    6. `can_view` has to be the literal `True`, or `KEY_INVALID`: a key that
       cannot even see the account is not a key this engine can use.

    Only a literal `True` is a permission, and only a literal `False` is a
    denied one: an answer that says `1`, `"true"` or nothing at all is refused
    rather than read as consent.

    UNVERIFIED: that a user-created portfolio reports CONSUMER; confirmed at
    go-live Test connection.
    """
    if not isinstance(perms, dict) or perms.get("can_transfer") is not False:
        return _refused(KEY_CAN_TRANSFER, MESSAGE_TRANSFER, None, perms)
    portfolio = _portfolio_of(perms)
    if portfolio is None:
        return _refused(KEY_NOT_PORTFOLIO_SCOPED, MESSAGE_UNSCOPED, None, perms)
    portfolio_type = perms.get("portfolio_type")
    if isinstance(portfolio_type, str) and portfolio_type == DEFAULT_PORTFOLIO_TYPE:
        return _refused(
            KEY_DEFAULT_PORTFOLIO, MESSAGE_DEFAULT_PORTFOLIO, None, perms
        )
    if not (isinstance(portfolio_type, str) and portfolio_type == PORTFOLIO_TYPE):
        return _refused(KEY_NOT_PORTFOLIO_SCOPED, MESSAGE_UNSCOPED, None, perms)
    if pinned_portfolio and portfolio != pinned_portfolio:
        return _refused(KEY_WRONG_PORTFOLIO, MESSAGE_WRONG_PORTFOLIO, None, perms)
    if perms.get("can_trade") is not True:
        return _refused(KEY_CANNOT_TRADE, MESSAGE_CANNOT_TRADE, None, perms)
    if perms.get("can_view") is not True:
        return _refused(KEY_INVALID, MESSAGE_CANNOT_VIEW, None, perms)
    return KeyCheck(
        state="ok",
        code=None,
        message=MESSAGE_OK,
        key_last4=None,
        portfolio_last4=_last4(portfolio),
    )


# ---------------------------------------------------------------- the key's shape


def normalised_key(private_key: Any) -> Optional[str]:
    """A private key with its line breaks as newlines, or None when it is not text.

    A JSON body may carry the two characters backslash-n where a newline belongs,
    so they are turned into newlines before the shape is judged and before the
    key is handed to an adapter.  Anything that is not text has no shape at all.
    """
    if not isinstance(private_key, str):
        return None
    text = private_key.replace(BACKSLASH_N, "\n").strip()
    return text or None


def _pem_body(text: str, begin: str, end: str) -> Optional[str]:
    """The body between one header and its footer, or None when they do not pair."""
    if not text.startswith(begin) or not text.endswith(end):
        return None
    body = text[len(begin) : len(text) - len(end)]
    return body.strip() or None


def valid_key_shape(key_name: Any, private_key: Any) -> bool:
    """Whether this pair has the shape of a Coinbase key before anything is built.

    The name has to be one Coinbase answers (`organizations/{org}/apiKeys/{id}`),
    and the private key a PEM pair — one of the two private-key headers and its
    footer — with a non-empty body between them.  Nothing here reaches the
    exchange, reads a file or keeps anything: a pair that fails this is refused
    `KEY_INVALID` without an adapter ever being built.
    """
    if not isinstance(key_name, str) or KEY_NAME_RE.fullmatch(key_name) is None:
        return False
    text = normalised_key(private_key)
    if text is None:
        return False
    return any(
        _pem_body(text, begin, end) is not None for begin, end in PEM_PAIRS
    )


# ---------------------------------------------------------------- the slot


class CredentialSlot:
    """The owner's key, in memory only: the live route, the pin, and the epoch.

    `store` is the system of record, `auth` the approval rail the secret is handed
    to, and `build_live(creds)` builds the adapter one key pair names — the real
    `LiveExchange` in production, where `__main__.build_app` supplies it, and a
    fake in a test.  `now` is the engine's clock, the one a stamp would be taken
    from, so nothing here reads the wall clock of its own.

    What the slot keeps between calls is ONE thing: the `ExchangeRouter` over the
    adapter an accepted key built.  It keeps no key, no key name and no secret of
    its own — the secret is the rail's (`set_secret`), and the pin is the store's.
    """

    def __init__(
        self,
        store: Store,
        auth: Any,
        build_live: Callable[[dict], Any],
        *,
        now: Callable[[], float],
    ) -> None:
        self._store = store
        self._auth = auth
        self._build_live = build_live
        self._now = now
        self._exchange: Optional[ExchangeRouter] = None

    # ------------------------------------------------ state
    def state(self) -> str:
        """Whether a live route is held right now: "ok" or "missing"."""
        return "ok" if self._exchange is not None else "missing"

    def live_exchange(self) -> Optional[ExchangeRouter]:
        """The live route, or None when no key is held — the factory `BookRouter` asks.

        Asked on every access, so a key pushed later is picked up without the
        engine being rebuilt, and an engine that restarted holds nothing until it
        is pushed again: the live book refuses `LIVE_LOCKED` in the meantime
        rather than reaching an account nothing opened.
        """
        return self._exchange

    def pinned(self) -> bool:
        """Whether a pin ROW exists for this engine, whatever it holds."""
        return pin_exists(self._store)

    def engine_epoch(self) -> Optional[str]:
        """This engine's credentials epoch, as it was persisted; None when never pinned."""
        value = self._store.get(EPOCH_KEY)
        return value if isinstance(value, str) and value else None

    def live_orders_resting(self) -> bool:
        """Whether any live-book order row is still open or unfilled.

        Read from the order rows rather than from the exchange: an order resting
        on the real account cannot be settled without the key being removed, so a
        disconnect while one is there is refused instead of leaving a live order
        nobody can cancel.  `RESTING_STATUSES` is every live status there is, so
        an order written before its submit went out — resolved later by its
        client order id — holds the credentials exactly as a resting one does:
        an outcome nobody knows yet cannot be settled without the key either.
        """
        return bool(
            self._store.orders(statuses=RESTING_STATUSES, book=LIVE)
        )

    # ------------------------------------------------ checking
    def check(
        self, key_name: str, private_key: str, *, repin: bool = False
    ) -> KeyCheck:
        """Judge one key pair and keep nothing, whatever it answers.

        The shape is judged first, then the adapter is built and asked for its
        permissions, then `evaluate_permissions` judges them against the pinned
        portfolio — or, with `repin`, against nothing, which is how a key that
        names another portfolio is allowed to move the pin.  An exchange or a
        network that fails answers the same fixed refusal `KEY_INVALID`, never
        the exception's own text.
        """
        result, _router, _portfolio = self._evaluate(
            key_name, private_key, repin=repin
        )
        return result

    def _evaluate(
        self, key_name: Any, private_key: Any, *, repin: bool
    ) -> tuple[KeyCheck, Optional[ExchangeRouter], Optional[str]]:
        """The one check `check` and `set` share: the answer, its router, its portfolio.

        The router is answered only for a key that passed, so a refusal never
        leaves one behind; `set` is the only caller that keeps it.
        """
        last4 = _last4(key_name)
        if not valid_key_shape(key_name, private_key):
            return (
                _refused(KEY_INVALID, MESSAGE_SHAPE, key_name),
                None,
                None,
            )
        key = normalised_key(private_key)
        try:
            live = self._build_live({"api_key": key_name, "api_secret": key})
            router = ExchangeRouter(live, usd_one_pool=True)
            perms = router.key_permissions()
        except Exception:  # noqa: BLE001 - any failure is one refusal, in plain words
            return (
                KeyCheck(
                    state="refused",
                    code=KEY_INVALID,
                    message=MESSAGE_UNREADABLE,
                    key_last4=last4,
                    portfolio_last4=None,
                ),
                None,
                None,
            )
        pinned = None if repin else self._stored_portfolio()
        result = evaluate_permissions(perms, pinned)
        if result.state != "ok":
            return replace(result, key_last4=last4), None, None
        return (
            replace(result, key_last4=last4),
            router,
            _portfolio_of(perms),
        )

    def _stored_portfolio(self) -> Optional[str]:
        """The portfolio this engine pinned, or None when nothing is pinned yet."""
        value = self._store.get(PORTFOLIO_KEY)
        return value if isinstance(value, str) and value else None

    # ------------------------------------------------ installing
    def set(
        self,
        key_name: str,
        private_key: str,
        approve_secret: str,
        *,
        repin: bool = False,
        key_kind: str = KEY_KIND_PINNED_SECRET,
    ) -> KeyCheck:
        """Check the key, and only on an acceptable one pin it and keep it.

        `key_kind` is the kind of key the approval rail says this request
        presented — `KEY_KIND_PINNED_SECRET` for the owner's own secret, whose
        sha256 has to be the pin, or `KEY_KIND_INSTALL_TOKEN` for the installer's
        token, which is a key only while no pin exists.  The rail decides that
        from the pin as it stood when the request was approved, so the decision
        is made AGAIN inside the transaction below: two first connects can both
        be approved against an unpinned store, and only one of them may pin.  It
        defaults to the owner's secret, so a caller that does not say which kind
        of key it had is held to the pin and can never make the first one.

        One transaction writes everything a connect persists: the pin (its kv row
        only when there is no pin row at all, because the first connect is what
        pins a secret), the portfolio the key names (replaced only by `repin`),
        and the engine epoch (generated once and kept on every later push).  Then
        the router is kept in memory and the approval secret is handed to the
        rail, which is the only holder of anything a later request can be keyed
        with — and only once the transaction committed, and only for a secret
        whose own sha256 is the pin it left behind.

        A refusal writes nothing, keeps nothing and leaves the rail exactly as it
        was: `repin` moves the portfolio and never the secret, so a request
        carrying another approval secret is `SECRET_MISMATCH` here whatever it
        asked for, and so is one the rail keyed with the install token when a pin
        row is there by the time this transaction looks.  A pin row holding
        anything but the sha256 hex — a hand-edited value, a null — matches no
        secret either, so the engine stays pinned and the refusal stays closed.
        The key check itself — the adapter built and asked for its permissions —
        happens BEFORE the transaction, and the transaction is what re-checks the
        pin; the secret's length is the request model's business, so a secret too
        short to be a key never reaches this method.
        """
        result, router, portfolio = self._evaluate(
            key_name, private_key, repin=repin
        )
        if result.state != "ok" or router is None:
            return result
        digest = _secret_digest(approve_secret)
        if digest is None:
            return _secret_refusal(result.key_last4, result.portfolio_last4)
        refused = False
        kept: Optional[str] = None
        with self._store.tx() as db:
            pin_row = db.execute(
                "SELECT value FROM kv WHERE key=?", (APPROVE_PIN_KEY,)
            ).fetchone()
            if pin_row is None:
                # No pin row at all: only the install token may make the first
                # one.  A request the rail keyed with an owner's secret is a
                # store that lost its pin, not a connect.
                if key_kind == KEY_KIND_INSTALL_TOKEN:
                    kept = digest.decode("ascii")
                    db.execute(
                        "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)",
                        (APPROVE_PIN_KEY, json.dumps(kept)),
                    )
                else:
                    refused = True
            else:
                stored = _row_text(pin_row)
                if (
                    key_kind != KEY_KIND_PINNED_SECRET
                    or stored is None
                    or not hmac.compare_digest(digest, stored.encode("utf-8"))
                ):
                    refused = True
                else:
                    kept = stored
            if not refused:
                pinned = _kv_text(db, PORTFOLIO_KEY)
                if portfolio is not None and (repin or not pinned):
                    db.execute(
                        "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)",
                        (PORTFOLIO_KEY, json.dumps(portfolio)),
                    )
                if _kv_text(db, EPOCH_KEY) is None:
                    db.execute(
                        "INSERT OR REPLACE INTO kv(key,value) VALUES(?,?)",
                        (EPOCH_KEY, json.dumps(_new_epoch())),
                    )
        if (
            refused
            or kept is None
            or not hmac.compare_digest(digest, kept.encode("utf-8"))
        ):
            return _secret_refusal(result.key_last4, result.portfolio_last4)
        self._exchange = router
        self._auth.set_secret(approve_secret)
        return result

    def clear(self) -> None:
        """Drop the live route and the in-memory secret; the pin stays where it is.

        Clearing is not unpinning: the pin is what makes the install token no key,
        so the next connect has to present the owner's secret in its body, and the
        install token never becomes a way back in.
        """
        self._exchange = None
        self._auth.clear_secret()


def _row_text(row: Any) -> Optional[str]:
    """A kv row's value as the text it holds, or None when it holds none.

    A row holding a JSON null, an object, a number or an empty string is no
    digest: a pin written in any of those forms matches no secret, which is what
    keeps a hand-edited pin closed rather than open.
    """
    if row is None:
        return None
    try:
        value = json.loads(row["value"])
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, str) and value else None


def _kv_text(db: Any, key: str) -> Optional[str]:
    """A kv value as the text it holds, read inside a caller's transaction."""
    return _row_text(
        db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    )


def _secret_digest(secret: Any) -> Optional[bytes]:
    """The sha256 hex of an approval secret as bytes, or None when it is not text."""
    if isinstance(secret, str):
        return hashlib.sha256(secret.encode("utf-8")).hexdigest().encode("ascii")
    if isinstance(secret, (bytes, bytearray)):
        return hashlib.sha256(bytes(secret)).hexdigest().encode("ascii")
    return None


def _secret_refusal(
    key_last4: Optional[str] = None, portfolio_last4: Optional[str] = None
) -> KeyCheck:
    """The refusal a request whose secret is not the pinned one earns.

    The same shape and code the approval rail answers with, and nothing of the
    request in it: no secret, no key, no exception text.
    """
    return KeyCheck(
        state="refused",
        code=SECRET_MISMATCH,
        message=MESSAGE_SECRET_MISMATCH,
        key_last4=key_last4,
        portfolio_last4=portfolio_last4,
    )


def _new_epoch() -> str:
    """A fresh engine epoch: 16 random bytes as hex, and never a key."""
    return secrets.token_hex(16)