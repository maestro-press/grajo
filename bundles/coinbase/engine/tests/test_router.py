"""router.py: one exchange surface over a crypto adapter and an equity adapter.

Routing is BY PRODUCT, never by trying one adapter and falling back to the
other: an equity product is answered by the equity adapter or refused, and the
crypto adapter is never consulted about it.  With no equity adapter every call
is the crypto adapter's own, arguments unchanged, so a crypto-only install keeps
the surface it had.

`Fake` is a canned adapter: every call it receives is appended to one shared log
as `(adapter name, method, positional args)`, so a test can see exactly which
adapter was asked and with what.  Products and prices here are synthetic.

`usd_one_pool` is a required keyword: whether the two keys see one USD pool or
two is a fact the caller states, and a router built without it would silently
assume one.  Two calls answer the funding checks that must not read the merged
view — `crypto_totals()` (the crypto account's own totals, for the portfolio
drawdown stop) and `equity_usd()` (the equity account's own USD, for an equity
buy's funding) — while `totals()`/`balances()` stay the merged view.
"""

from __future__ import annotations

from decimal import Decimal as D

import pytest

from crow_coinbase.exchange import TransientError
from crow_coinbase.router import (
    EQUITY_USE_EQUITY_PATH,
    NO_EQUITY_ACCOUNT,
    NOT_EQUITY_PRODUCT,
    ExchangeRouter,
    usd_one_pool_from_keys,
)

XRP = "XRP-USDC"
BTC = "BTC-USDC"
NVDA = "NVDA-USD"


class Fake:
    """A canned adapter that records `(name, method, args)` into a shared log."""

    def __init__(
        self,
        name,
        log,
        *,
        totals=None,
        balances=None,
        open_orders=None,
        cancel_result=None,
        advance_returns=None,
        fills_result=None,
        key_permissions=None,
        maker_fee_rate=None,
        server_time=0.0,
        dry_run=True,
    ):
        self.name = name
        self.log = log
        self._totals = dict(totals or {})
        self._balances = dict(balances or {})
        self._open = list(open_orders or [])
        self.cancel_result = cancel_result
        self.advance_returns = advance_returns
        self._fills = list(fills_result or [])
        self._permissions = dict(key_permissions or {})
        self._maker_fee = maker_fee_rate
        self._server_time = server_time
        self.dry_run = dry_run

    def _record(self, method, *args):
        self.log.append((self.name, method, args))

    # -- writes
    def place_limit(self, cid, product, side, size, price):
        self._record("place_limit", cid, product, side, size, price)
        return {"ok": True, "order_id": f"{self.name}-{cid}", "reason": None}

    def place_equity_limit(self, cid, product, side, size, price):
        self._record("place_equity_limit", cid, product, side, size, price)
        return {"ok": True, "order_id": f"{self.name}-{cid}", "reason": None}

    def cancel(self, order_ids):
        self._record("cancel", order_ids)
        if self.cancel_result is None:
            return {order_id: True for order_id in order_ids}
        return {
            order_id: bool(self.cancel_result.get(order_id, False))
            for order_id in order_ids
        }

    def deposit(self, currency, amount, note):
        self._record("deposit", currency, amount, note)
        return f"{self.name}-deposit"

    # -- reads
    def find_by_client_id(self, cid, since, product=None):
        self._record("find_by_client_id", cid, since, product)
        return {
            "order_id": f"{self.name}-{cid}",
            "client_order_id": cid,
            "product": product,
        }

    def get_order(self, order_id, product=None):
        self._record("get_order", order_id, product)
        return {"order_id": order_id, "product": product}

    def fills(self, order_id, product=None):
        self._record("fills", order_id, product)
        return [dict(fill) for fill in self._fills]

    def list_open_orders(self, product=None):
        self._record("list_open_orders", product)
        return [dict(order) for order in self._open]

    def totals(self):
        self._record("totals")
        return dict(self._totals)

    def balances(self):
        self._record("balances")
        return dict(self._balances)

    def key_permissions(self):
        self._record("key_permissions")
        return dict(self._permissions)

    def maker_fee_rate(self):
        self._record("maker_fee_rate")
        return self._maker_fee

    def server_time(self):
        self._record("server_time")
        return self._server_time

    def advance(self, now):
        self._record("advance", now)
        return self.advance_returns


def make_router(crypto_kwargs=None, equity_kwargs=None, **router_kwargs):
    """A router over two recording fakes, plus the log the two share."""
    log = []
    crypto = Fake("crypto", log, **(crypto_kwargs or {}))
    equity = Fake("equity", log, **(equity_kwargs or {}))
    options = {
        "is_equity": lambda product: product == NVDA,
        "product_of": {"o1": XRP, "o2": NVDA, "o3": BTC}.get,
        "usd_one_pool": True,
        "equity_bases": ("NVDA",),
    }
    options.update(router_kwargs)
    return ExchangeRouter(crypto, equity, **options), crypto, equity, log


def calls(log):
    """The log as `(adapter name, method)` pairs, in call order."""
    return [(name, method) for name, method, _ in log]


def test_router_place_routes():
    router, _crypto, _equity, log = make_router()

    placed = router.place_limit("cb-ai-B+0-1", XRP, "BUY", D("10"), D("0.9"))
    assert placed["ok"] is True
    assert calls(log) == [("crypto", "place_limit")]
    assert log[0][2] == ("cb-ai-B+0-1", XRP, "BUY", D("10"), D("0.9"))

    log.clear()
    refused = router.place_limit("cb-ai-B+0-2", NVDA, "BUY", D("1"), D("100"))
    assert refused["ok"] is False
    assert refused["order_id"] is None
    assert refused["reason"] == EQUITY_USE_EQUITY_PATH
    assert log == []

    equity_placed = router.place_equity_limit(
        "cb-ai-B+0-3", NVDA, "BUY", D("1"), D("100")
    )
    assert equity_placed["ok"] is True
    assert calls(log) == [("equity", "place_equity_limit")]

    log.clear()
    not_equity = router.place_equity_limit("grid-B-1-x", XRP, "BUY", D("10"), D("0.9"))
    assert not_equity["ok"] is False
    assert not_equity["order_id"] is None
    assert not_equity["reason"] == NOT_EQUITY_PRODUCT
    assert log == []


def test_router_place_limit_refuses_equity_without_an_equity_adapter():
    # An equity product is refused because of what it is, not because of whether
    # an equity adapter happens to be configured.
    log = []
    crypto = Fake("crypto", log)
    router = ExchangeRouter(
        crypto, is_equity=lambda product: product == NVDA, usd_one_pool=True
    )

    refused = router.place_limit("cb-ai-B+0-1", NVDA, "BUY", D("1"), D("100"))

    assert refused == {
        "ok": False,
        "order_id": None,
        "reason": EQUITY_USE_EQUITY_PATH,
    }
    assert log == []


def test_router_place_equity_limit_without_an_equity_adapter():
    log = []
    crypto = Fake("crypto", log)
    router = ExchangeRouter(
        crypto, is_equity=lambda product: product == NVDA, usd_one_pool=True
    )

    # The product belongs on the equity path, but there is no equity account.
    no_account = router.place_equity_limit(
        "cb-ai-B+0-1", NVDA, "BUY", D("1"), D("100")
    )
    assert no_account == {
        "ok": False,
        "order_id": None,
        "reason": NO_EQUITY_ACCOUNT,
    }

    # A crypto product is refused on its own terms, equity account or not.
    not_equity = router.place_equity_limit(
        "grid-B-1-x", XRP, "BUY", D("10"), D("0.9")
    )
    assert not_equity == {
        "ok": False,
        "order_id": None,
        "reason": NOT_EQUITY_PRODUCT,
    }

    # Neither refusal reached the crypto adapter's own equity method.
    assert log == []


def test_router_refusals_never_reach_an_adapter():
    router, _crypto, _equity, log = make_router()

    assert (
        router.place_limit("c1", NVDA, "BUY", D("1"), D("1"))["reason"]
        == EQUITY_USE_EQUITY_PATH
    )
    assert (
        router.place_equity_limit("c2", XRP, "BUY", D("10"), D("0.9"))["reason"]
        == NOT_EQUITY_PRODUCT
    )
    assert log == []


def test_router_list_all_concatenates():
    router, _crypto, _equity, log = make_router(
        crypto_kwargs={"open_orders": [{"order_id": "c1"}]},
        equity_kwargs={"open_orders": [{"order_id": "e1"}]},
    )

    everything = router.list_open_orders()

    # crypto first, then the equity account
    assert [order["order_id"] for order in everything] == ["c1", "e1"]
    assert calls(log) == [("crypto", "list_open_orders"), ("equity", "list_open_orders")]

    log.clear()
    equity_only = router.list_open_orders(NVDA)
    assert [order["order_id"] for order in equity_only] == ["e1"]
    assert calls(log) == [("equity", "list_open_orders")]
    assert log[0][2] == (NVDA,)

    log.clear()
    assert router.list_open_orders(XRP) == [{"order_id": "c1"}]
    assert calls(log) == [("crypto", "list_open_orders")]


def test_router_cancel_routes_by_row_product():
    router, _crypto, _equity, log = make_router()

    merged = router.cancel(["o1", "o2", "o3"])

    sent = {}
    for name, method, args in log:
        assert method == "cancel"
        sent[name] = list(args[0])
    assert sent == {"crypto": ["o1", "o3"], "equity": ["o2"]}
    assert merged == {"o1": True, "o2": True, "o3": True}


def test_router_cancel_unknown_id_both_ored():
    router, crypto, equity, log = make_router(
        crypto_kwargs={"cancel_result": {"x": False}},
        equity_kwargs={"cancel_result": {"x": True}},
        product_of=lambda order_id: None,
    )

    assert router.cancel(["x"]) == {"x": True}
    assert sorted(name for name, _, _ in log) == ["crypto", "equity"]

    log.clear()
    crypto.cancel_result = {"y": False}
    equity.cancel_result = {"y": False}
    assert router.cancel(["y"]) == {"y": False}
    assert sorted(name for name, _, _ in log) == ["crypto", "equity"]


def test_router_get_order_routes_by_product():
    router, _crypto, _equity, log = make_router()

    assert router.get_order("o2", NVDA)["order_id"] == "o2"
    assert calls(log) == [("equity", "get_order")]
    assert log[0][2] == ("o2", NVDA)

    log.clear()
    assert router.get_order("o2")["order_id"] == "o2"  # product_of answers
    assert calls(log) == [("equity", "get_order")]

    log.clear()
    assert router.get_order("o1")["order_id"] == "o1"
    assert calls(log) == [("crypto", "get_order")]

    log.clear()
    with pytest.raises(ValueError):
        router.get_order("o-nobody-knows")
    assert log == []  # never guessed


def test_router_fills_routes_by_product():
    # The crypto adapter would answer [] for anything; it must not be asked.
    router, _crypto, _equity, log = make_router(
        crypto_kwargs={"fills_result": []},
        equity_kwargs={
            "fills_result": [{"trade_id": "t-eq", "order_id": "o2", "product": NVDA}]
        },
    )

    assert [fill["trade_id"] for fill in router.fills("o2", NVDA)] == ["t-eq"]
    assert calls(log) == [("equity", "fills")]

    log.clear()
    assert [fill["trade_id"] for fill in router.fills("o2")] == ["t-eq"]
    assert calls(log) == [("equity", "fills")]

    log.clear()
    assert router.fills("o1") == []
    assert calls(log) == [("crypto", "fills")]


class FailingList(Fake):
    """An adapter whose `list_open_orders` raises, whatever it holds."""

    def list_open_orders(self, product=None):
        self._record("list_open_orders", product)
        raise TransientError(f"{self.name}: 503 service unavailable")


def test_router_list_all_raises_on_one_failure():
    log = []
    router = ExchangeRouter(
        Fake("crypto", log, open_orders=[{"order_id": "c1"}]),
        FailingList("equity", log),
        is_equity=lambda product: product == NVDA,
        usd_one_pool=True,
    )
    with pytest.raises(TransientError):
        router.list_open_orders()

    log = []
    router = ExchangeRouter(
        FailingList("crypto", log),
        Fake("equity", log, open_orders=[{"order_id": "e1"}]),
        is_equity=lambda product: product == NVDA,
        usd_one_pool=True,
    )
    with pytest.raises(TransientError):
        router.list_open_orders()


def test_router_one_key_passthrough():
    log = []
    crypto = Fake(
        "crypto",
        log,
        totals={"USD": D("300")},
        balances={"USD": D("300")},
        open_orders=[{"order_id": "c1"}],
        key_permissions={"can_trade": True},
    )
    router = ExchangeRouter(
        crypto, is_equity=lambda product: product == NVDA, usd_one_pool=True
    )

    assert router.place_limit("cid", XRP, "BUY", D("1"), D("2"))["ok"] is True
    assert router.cancel(["o1"]) == {"o1": True}
    assert router.totals() == {"USD": D("300")}
    assert router.balances() == {"USD": D("300")}
    assert router.crypto_totals() == {"USD": D("300")}
    assert router.equity_usd() is None
    assert router.key_permissions() == {"can_trade": True}
    assert router.list_open_orders() == [{"order_id": "c1"}]
    assert router.get_order("o1", NVDA)["order_id"] == "o1"
    assert router.fills("o1", XRP) == []
    assert router.find_by_client_id("cid", 0.0, XRP)["client_order_id"] == "cid"

    assert {name for name, _, _ in log} == {"crypto"}
    args_by_method = {method: args for _, method, args in log}
    assert args_by_method["get_order"] == ("o1", NVDA)
    assert args_by_method["fills"] == ("o1", XRP)
    assert args_by_method["cancel"] == (["o1"],)


def test_router_totals_merge():
    crypto_kwargs = {
        "totals": {"USD": D("300"), "BTC": D("1"), "NVDA": D("5")},
        "balances": {"USD": D("300"), "BTC": D("1"), "NVDA": D("5")},
    }
    equity_kwargs = {
        "totals": {"USD": D("300"), "NVDA": D("2"), "VOO": D("9")},
        "balances": {"USD": D("300"), "NVDA": D("2"), "VOO": D("9")},
    }

    one_pool, _crypto, _equity, _log = make_router(
        crypto_kwargs, equity_kwargs, usd_one_pool=True
    )
    assert one_pool.totals() == {"USD": D("300"), "BTC": D("1"), "NVDA": D("2")}
    assert one_pool.balances() == {"USD": D("300"), "BTC": D("1"), "NVDA": D("2")}

    two_pools, _crypto, _equity, _log = make_router(
        crypto_kwargs, equity_kwargs, usd_one_pool=False
    )
    assert two_pools.totals() == {"USD": D("600"), "BTC": D("1"), "NVDA": D("2")}


def test_router_usd_one_pool_is_required():
    # No default: whether the two keys see one USD pool or two is a fact about
    # the accounts, so the caller states it or the router is never built.
    log = []
    crypto = Fake("crypto", log)

    with pytest.raises(TypeError):
        ExchangeRouter(crypto)
    with pytest.raises(TypeError):
        ExchangeRouter(crypto, Fake("equity", log), is_equity=lambda p: p == NVDA)
    assert log == []


def test_router_same_object_refuses_two_usd_pools():
    # One adapter on both sides is one account, so its USD cannot be two pools:
    # summing it would count the same cash twice.
    log = []
    same = Fake("crypto", log)

    with pytest.raises(ValueError):
        ExchangeRouter(same, same, is_equity=lambda p: False, usd_one_pool=False)


def test_router_same_object_stores_one_usd_pool():
    log = []
    same = Fake("crypto", log, totals={"USD": D("300"), "NVDA": D("2")})

    router = ExchangeRouter(same, same, is_equity=lambda p: False, usd_one_pool=True)

    assert router.usd_one_pool is True
    assert router.totals() == {"USD": D("300"), "NVDA": D("2")}


def test_usd_one_pool_from_keys_same_portfolio():
    assert (
        usd_one_pool_from_keys({"portfolio_uuid": "pf-1"}, {"portfolio_uuid": "pf-1"})
        is True
    )


def test_usd_one_pool_from_keys_different_portfolios():
    assert (
        usd_one_pool_from_keys({"portfolio_uuid": "pf-1"}, {"portfolio_uuid": "pf-2"})
        is False
    )


def test_usd_one_pool_from_keys_unknown_relationship():
    # An unknown relationship is not a guess: equities are not enabled on it.
    for crypto_perms, equity_perms in (
        ({}, {"portfolio_uuid": "pf-1"}),
        ({"portfolio_uuid": "pf-1"}, {}),
        ({}, {}),
        ({"portfolio_uuid": "pf-1"}, {"portfolio_uuid": None}),
        ({"portfolio_uuid": None}, {"portfolio_uuid": "pf-1"}),
        ({"portfolio_uuid": "pf-1"}, {"portfolio_uuid": ""}),
        ({"portfolio_uuid": ""}, {"portfolio_uuid": ""}),
    ):
        with pytest.raises(ValueError):
            usd_one_pool_from_keys(crypto_perms, equity_perms)


def test_router_crypto_totals_ignores_the_equity_account():
    crypto_kwargs = {"totals": {"USD": D("300"), "BTC": D("1")}}
    equity_kwargs = {"totals": {"USD": D("300"), "NVDA": D("2")}}
    router, _crypto, _equity, log = make_router(
        crypto_kwargs, equity_kwargs, usd_one_pool=False
    )

    log.clear()
    assert router.crypto_totals() == {"USD": D("300"), "BTC": D("1")}
    assert calls(log) == [("crypto", "totals")]

    # The merged view really does sum the two accounts here, which is exactly
    # why the portfolio drawdown stop may not read it.
    log.clear()
    assert router.totals() == {"USD": D("600"), "BTC": D("1"), "NVDA": D("2")}
    assert calls(log) == [("crypto", "totals"), ("equity", "totals")]

    # One key has nothing to merge, and the call is still the crypto account's.
    log.clear()
    solo = ExchangeRouter(
        Fake("crypto", log, totals={"USD": D("300")}), usd_one_pool=True
    )
    assert solo.crypto_totals() == {"USD": D("300")}
    assert calls(log) == [("crypto", "totals")]


def test_router_equity_usd_reads_the_equity_account():
    router, _crypto, _equity, log = make_router(
        crypto_kwargs={"balances": {"USD": D("300"), "BTC": D("1")}},
        equity_kwargs={"balances": {"USD": D("42.5"), "NVDA": D("2")}},
        usd_one_pool=False,
    )

    log.clear()
    assert router.equity_usd() == D("42.5")
    assert isinstance(router.equity_usd(), D)
    assert calls(log) == [("equity", "balances"), ("equity", "balances")]

    # The crypto account's USD is a different pool and is never added in.
    log.clear()
    assert router.balances()["USD"] == D("342.5")
    assert calls(log) == [("crypto", "balances"), ("equity", "balances")]

    # An equity account holding no USD funds nothing.
    empty, _crypto, _equity, _log = make_router(
        crypto_kwargs={"balances": {"USD": D("300")}},
        equity_kwargs={"balances": {"NVDA": D("2")}},
    )
    assert empty.equity_usd() == D("0")


def test_router_equity_usd_without_an_equity_adapter_is_none():
    log = []
    router = ExchangeRouter(
        Fake("crypto", log, balances={"USD": D("300")}), usd_one_pool=True
    )

    assert router.equity_usd() is None
    assert log == []  # there is no equity account to ask


def test_router_key_permissions_names_both_keys():
    router, _crypto, _equity, log = make_router(
        crypto_kwargs={
            "key_permissions": {"can_trade": True, "portfolio_uuid": "pf-crypto"}
        },
        equity_kwargs={
            "key_permissions": {"can_trade": True, "portfolio_uuid": "pf-equity"}
        },
    )

    assert router.key_permissions() == {
        "crypto": {"can_trade": True, "portfolio_uuid": "pf-crypto"},
        "equity": {"can_trade": True, "portfolio_uuid": "pf-equity"},
    }
    assert sorted(calls(log)) == [
        ("crypto", "key_permissions"),
        ("equity", "key_permissions"),
    ]


def test_router_key_permissions_same_object_keeps_both_keys():
    log = []
    same = Fake("crypto", log, key_permissions={"can_trade": True})
    router = ExchangeRouter(same, same, is_equity=lambda p: False, usd_one_pool=True)

    perms = router.key_permissions()

    # One key on both sides is still reported under both names.
    assert set(perms) == {"crypto", "equity"}
    assert perms["crypto"] == {"can_trade": True}
    assert perms["equity"] == perms["crypto"]


def test_router_key_permissions_one_key_unchanged():
    log = []
    crypto = Fake("crypto", log, key_permissions={"can_trade": True})

    assert ExchangeRouter(crypto, usd_one_pool=True).key_permissions() == {
        "can_trade": True
    }


def test_router_refuses_mismatched_dry_run():
    # A router that simulates one account and places on the other would answer
    # `dry_run` with a lie, so a mismatched pair never becomes a router.
    log = []
    crypto = Fake("crypto", log, dry_run=True)
    equity = Fake("equity", log, dry_run=False)

    with pytest.raises(ValueError):
        ExchangeRouter(
            crypto, equity, is_equity=lambda p: p == NVDA, usd_one_pool=True
        )
    assert log == []

    # A matching pair is fine, and the answer is the crypto adapter's.
    equity.dry_run = True
    simulated = ExchangeRouter(
        crypto, equity, is_equity=lambda p: p == NVDA, usd_one_pool=True
    )
    assert simulated.dry_run is True

    crypto.dry_run = False
    equity.dry_run = False
    placed = ExchangeRouter(
        crypto, equity, is_equity=lambda p: p == NVDA, usd_one_pool=True
    )
    assert placed.dry_run is False

    # One adapter alone has no counterpart to disagree with.
    assert ExchangeRouter(crypto, usd_one_pool=True).dry_run is False


def test_router_find_by_client_id_requires_product_with_equity():
    router, _crypto, _equity, log = make_router()

    with pytest.raises(ValueError):
        router.find_by_client_id("cid", 0.0)
    assert log == []

    found = router.find_by_client_id("cid", 0.0, NVDA)
    assert found["client_order_id"] == "cid"
    assert calls(log) == [("equity", "find_by_client_id")]
    assert log[0][2] == ("cid", 0.0, NVDA)


def test_router_advance_both_once():
    router, _crypto, _equity, log = make_router(
        crypto_kwargs={"advance_returns": ["a"]},
        equity_kwargs={"advance_returns": ["b"]},
    )
    assert router.advance(123.0) == ["a", "b"]
    assert log == [
        ("crypto", "advance", (123.0,)),
        ("equity", "advance", (123.0,)),
    ]

    # The same object on both sides is stepped once, not twice.
    log.clear()
    same = Fake("crypto", log, advance_returns=["a"])
    ExchangeRouter(
        same, same, is_equity=lambda product: False, usd_one_pool=True
    ).advance(1.0)
    assert calls(log) == [("crypto", "advance")]

    # A step that answers nothing counts as empty.
    log.clear()
    quiet = ExchangeRouter(
        Fake("crypto", log, advance_returns=None),
        Fake("equity", log, advance_returns=None),
        is_equity=lambda product: product == NVDA,
        usd_one_pool=True,
    )
    assert quiet.advance(2.0) == []


def test_router_passthrough_misc():
    router, _crypto, _equity, log = make_router(
        crypto_kwargs={
            "maker_fee_rate": D("0.001"),
            "server_time": 1767225600.0,
            "dry_run": True,
        },
        equity_kwargs={
            "maker_fee_rate": D("0.5"),
            "server_time": 1.0,
            "dry_run": True,
        },
    )

    # The maker fee, the clock and the simulation switch are the crypto
    # account's: the equity side has no answer of its own for them.
    assert router.maker_fee_rate() == D("0.001")
    assert router.server_time() == 1767225600.0
    assert router.deposit("USD", D("10"), "seed") == "crypto-deposit"
    assert router.dry_run is True
    assert {name for name, _, _ in log} == {"crypto"}