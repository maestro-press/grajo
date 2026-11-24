"""limits.py: env-configured limits and the rolling/daily cap windows."""

import dataclasses
import time
from datetime import datetime, timezone
from decimal import Decimal as D

import pytest

from crow_coinbase.limits import (
    CapWindow,
    Limits,
    validate_product_types,
)
from crow_coinbase.store import (
    CANCELLED,
    FAILED,
    FILLED,
    OPEN,
    PENDING_SUBMIT,
    REJECTED,
    Store,
)

PRODUCT = "XRP-USDC"

POLL = "CROW_COINBASE_POLL_SECONDS"
FEE = "CROW_COINBASE_MAKER_FEE_PCT"
PRODUCTS = "CROW_COINBASE_PRODUCTS"
DAILY = "CROW_COINBASE_DAILY_NOTIONAL_USD"
ORDERS_HOUR = "CROW_COINBASE_ORDERS_PER_HOUR"
DRAWDOWN = "CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT"
BOT_MAX_ORDER = "CROW_COINBASE_BOT_MAX_ORDER_USD"
MAX_BOT_CAPITAL = "CROW_COINBASE_MAX_BOT_CAPITAL_USD"
AI_MAX_ORDER = "CROW_COINBASE_AI_MAX_ORDER_USD"
AI_DAILY = "CROW_COINBASE_AI_DAILY_NOTIONAL_USD"
AI_ORDERS_HOUR = "CROW_COINBASE_AI_ORDERS_PER_HOUR"
AI_CAPITAL = "CROW_COINBASE_AI_CAPITAL_USD"
WATCHDOG = "CROW_COINBASE_WATCHDOG_POLICY"
EQUITY_PRODUCTS = "CROW_COINBASE_EQUITY_PRODUCTS"
EQUITY_MAX_ORDER = "CROW_COINBASE_EQUITY_MAX_ORDER_USD"
EQUITY_DAILY = "CROW_COINBASE_EQUITY_DAILY_NOTIONAL_USD"
EQUITY_AI_CAPITAL = "CROW_COINBASE_EQUITY_AI_CAPITAL_USD"
EQUITY_DRAWDOWN_ALERT = "CROW_COINBASE_EQUITY_DRAWDOWN_ALERT_PCT"
EQUITY_LIVE = "CROW_COINBASE_EQUITY_LIVE"

ENV_NAMES = (
    POLL,
    FEE,
    PRODUCTS,
    DAILY,
    ORDERS_HOUR,
    DRAWDOWN,
    BOT_MAX_ORDER,
    MAX_BOT_CAPITAL,
    AI_MAX_ORDER,
    AI_DAILY,
    AI_ORDERS_HOUR,
    AI_CAPITAL,
    WATCHDOG,
    EQUITY_PRODUCTS,
    EQUITY_MAX_ORDER,
    EQUITY_DAILY,
    EQUITY_AI_CAPITAL,
    EQUITY_DRAWDOWN_ALERT,
    EQUITY_LIVE,
)


@pytest.fixture
def store(tmp_path):
    """A fresh store with the one bot every order row needs."""
    s = Store(tmp_path / "s.db")
    s.create_bot("b1", PRODUCT, "grid", {}, D("100"), D("50"))
    yield s
    s.close()


@pytest.fixture
def chicago_tz(monkeypatch):
    """Run the test under TZ America/Chicago, then restore the process timezone."""
    monkeypatch.setenv("TZ", "America/Chicago")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def utc(y, mo, d, h=0, mi=0, s=0, us=0):
    """Epoch seconds for a UTC wall clock reading; the tests never use the real one."""
    return datetime(y, mo, d, h, mi, s, us, tzinfo=timezone.utc).timestamp()


def cid_of(owner, n):
    """A client order id in the engine's `cb-<owner>-...` form (hex tail)."""
    return f"cb-{owner}-B0-{n:012x}"


def window_at(store, now):
    """A CapWindow plus the one-cell clock it reads, so a test can move time."""
    clock = [now]
    return CapWindow(store, lambda: clock[0]), clock


def add(
    store,
    n,
    created_at,
    *,
    price,
    size,
    side="BUY",
    status=OPEN,
    source="bot",
    owner="b1",
    product=PRODUCT,
    product_type="SPOT",
    book="dry",
):
    """Insert one order row and pin its created_at to *created_at*.

    insert_order stamps the wall clock, so the timestamp is overwritten
    afterwards; the connection is autocommit, so the row is durable at once.  A
    row is SPOT unless the test names the other kind it means.
    """
    cid = cid_of(owner, n)
    store.insert_order(
        cid,
        owner,
        source,
        product,
        side,
        level=0,
        price=price,
        size=size,
        status=status,
        book=book,
        product_type=product_type,
    )
    store.conn().execute(
        "UPDATE orders SET created_at=? WHERE client_order_id=?", (created_at, cid)
    )
    return cid


def test_defaults_from_env():
    limits = Limits.from_env({})

    assert limits.poll_seconds == 60
    assert isinstance(limits.poll_seconds, int)

    assert limits.maker_fee_pct == D("0.5")
    assert isinstance(limits.maker_fee_pct, D)

    assert limits.products == ("BTC-USDC", "ETH-USDC", "XRP-USDC")
    assert isinstance(limits.products, tuple)
    assert len(limits.products) == 3

    assert limits.daily_notional_usd == D("200")
    assert isinstance(limits.daily_notional_usd, D)

    assert limits.orders_per_hour == 30
    assert isinstance(limits.orders_per_hour, int)

    assert limits.portfolio_drawdown_pct == D("20")
    assert isinstance(limits.portfolio_drawdown_pct, D)

    assert limits.bot_max_order_usd == D("50")
    assert isinstance(limits.bot_max_order_usd, D)

    assert limits.max_bot_capital_usd == D("100")
    assert isinstance(limits.max_bot_capital_usd, D)

    assert limits.ai_max_order_usd == D("25")
    assert isinstance(limits.ai_max_order_usd, D)

    assert limits.ai_daily_notional_usd == D("50")
    assert isinstance(limits.ai_daily_notional_usd, D)

    assert limits.ai_orders_per_hour == 10
    assert isinstance(limits.ai_orders_per_hour, int)

    assert limits.ai_capital_usd == D("25")
    assert isinstance(limits.ai_capital_usd, D)

    assert limits.watchdog_policy == "leave"
    assert isinstance(limits.watchdog_policy, str)

    # A missing key and an empty / whitespace-only value both mean "the default".
    assert Limits.from_env({name: "" for name in ENV_NAMES}) == limits
    assert Limits.from_env({name: "   " for name in ENV_NAMES}) == limits
    assert Limits.from_env({name: "\t \n" for name in ENV_NAMES}) == limits

    # Frozen: the parsed limits are not editable after they are read.
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.poll_seconds = 5


def test_env_overrides_parse():
    limits = Limits.from_env(
        {
            POLL: "30",
            FEE: "0.25",
            PRODUCTS: " XRP-USDC , BTC-USDC ",
            DAILY: "150",
            ORDERS_HOUR: "45",
            DRAWDOWN: "35",
            BOT_MAX_ORDER: "20",
            MAX_BOT_CAPITAL: "10",
            AI_MAX_ORDER: "5",
            AI_DAILY: "12",
            AI_ORDERS_HOUR: "4",
            AI_CAPITAL: "15",
            WATCHDOG: "cancel",
        }
    )

    assert limits.poll_seconds == 30
    assert isinstance(limits.poll_seconds, int)

    assert limits.maker_fee_pct == D("0.25")
    assert isinstance(limits.maker_fee_pct, D)
    assert not isinstance(limits.maker_fee_pct, float)

    assert limits.products == ("XRP-USDC", "BTC-USDC")  # order kept, padding stripped
    assert isinstance(limits.products, tuple)

    assert limits.daily_notional_usd == D("150")
    assert isinstance(limits.daily_notional_usd, D)

    assert limits.orders_per_hour == 45
    assert isinstance(limits.orders_per_hour, int)

    assert limits.portfolio_drawdown_pct == D("35")
    assert isinstance(limits.portfolio_drawdown_pct, D)

    assert limits.bot_max_order_usd == D("20")
    assert isinstance(limits.bot_max_order_usd, D)

    assert limits.max_bot_capital_usd == D("10")
    assert isinstance(limits.max_bot_capital_usd, D)

    assert limits.ai_max_order_usd == D("5")
    assert isinstance(limits.ai_max_order_usd, D)

    assert limits.ai_daily_notional_usd == D("12")
    assert isinstance(limits.ai_daily_notional_usd, D)

    assert limits.ai_orders_per_hour == 4
    assert isinstance(limits.ai_orders_per_hour, int)

    assert limits.ai_capital_usd == D("15")
    assert isinstance(limits.ai_capital_usd, D)

    assert limits.watchdog_policy == "cancel"

    # One product is a one-element tuple, not a string.
    single = Limits.from_env({PRODUCTS: "ETH-USDC"})
    assert single.products == ("ETH-USDC",)
    assert isinstance(single.products, tuple)

    # An override mapping differs from the all-defaults one.
    assert limits != Limits.from_env({})


def test_from_env_reads_only_the_mapping_given(monkeypatch):
    monkeypatch.setenv(POLL, "5")
    monkeypatch.setenv(FEE, "9.5")
    monkeypatch.setenv(WATCHDOG, "cancel")

    # os.environ says one thing, the mapping says nothing: the defaults stand.
    assert Limits.from_env({}).poll_seconds == 60
    assert Limits.from_env({}).maker_fee_pct == D("0.5")
    assert Limits.from_env({}).watchdog_policy == "leave"

    # And the mapping it is given is the one that decides.
    assert Limits.from_env({POLL: "7"}).poll_seconds == 7
    assert Limits.from_env({WATCHDOG: "cancel"}).watchdog_policy == "cancel"


BAD_VALUES = (
    (POLL, "0"),
    (POLL, "-5"),
    (POLL, "abc"),
    (POLL, "1.5"),
    (FEE, "-0.1"),
    (FEE, "100"),
    (FEE, "x"),
    (FEE, "NaN"),
    (FEE, "Infinity"),
    (PRODUCTS, ","),
    (PRODUCTS, "xrp-usdc"),
    (PRODUCTS, "XRPUSDC"),
    (PRODUCTS, "BTC-USDC,BTC-USDC"),
    (PRODUCTS, "ETH-BTC"),
    (PRODUCTS, "BTC-EUR"),
    (DAILY, "0"),
    (DAILY, "-1"),
    (DAILY, "Infinity"),
    (ORDERS_HOUR, "0"),
    (ORDERS_HOUR, "2.5"),
    (DRAWDOWN, "0"),
    (DRAWDOWN, "101"),
    (BOT_MAX_ORDER, "0"),
    (BOT_MAX_ORDER, "NaN"),
    (MAX_BOT_CAPITAL, "-3"),
    (AI_MAX_ORDER, "abc"),
    (AI_DAILY, "0"),
    (AI_ORDERS_HOUR, "0"),
    (AI_CAPITAL, "-1"),
    (AI_CAPITAL, "abc"),
    (AI_CAPITAL, "Infinity"),
    (WATCHDOG, "kill"),
)


@pytest.mark.parametrize("name,bad", BAD_VALUES)
def test_invalid_env_values_name_the_variable(name, bad):
    with pytest.raises(ValueError) as err:
        Limits.from_env({name: bad})

    assert name in str(err.value)

    # The edges of the same ranges are valid, not errors.
    assert Limits.from_env({DRAWDOWN: "100"}).portfolio_drawdown_pct == D("100")
    assert Limits.from_env({FEE: "0"}).maker_fee_pct == D("0")


def test_usd_quoted_products_are_valid():
    limits = Limits.from_env({PRODUCTS: "BTC-USD,ETH-USDC"})

    assert limits.products == ("BTC-USD", "ETH-USDC")


def test_equity_defaults():
    limits = Limits.from_env({})

    # No equity products are configured until the operator names some.
    assert limits.equity_products == ()
    assert isinstance(limits.equity_products, tuple)

    assert limits.equity_max_order_usd == D("100")
    assert isinstance(limits.equity_max_order_usd, D)

    assert limits.equity_daily_notional_usd == D("200")
    assert isinstance(limits.equity_daily_notional_usd, D)

    assert limits.equity_ai_capital_usd == D("0")
    assert isinstance(limits.equity_ai_capital_usd, D)

    assert limits.equity_drawdown_alert_pct == D("20")
    assert isinstance(limits.equity_drawdown_alert_pct, D)

    # No equity orders leave the box unless these are turned on deliberately.
    assert limits.equity_live is False
    assert isinstance(limits.equity_live, bool)

    # The bare instance is the all-defaults one, the same as an empty mapping.
    assert Limits() == limits
    assert Limits.from_env({name: "" for name in ENV_NAMES}) == limits


def test_equity_products_parse():
    limits = Limits.from_env({EQUITY_PRODUCTS: "NVDA-USD,VOO-USD,AMD-USD"})

    assert limits.equity_products == ("NVDA-USD", "VOO-USD", "AMD-USD")
    assert isinstance(limits.equity_products, tuple)
    assert "AMD-USD" in limits.equity_products

    # Padding around each entry is stripped, the order is kept.
    padded = Limits.from_env({EQUITY_PRODUCTS: " NVDA-USD , VOO-USD "})
    assert padded.equity_products == ("NVDA-USD", "VOO-USD")

    # One entry is a one-element tuple, not a string.
    single = Limits.from_env({EQUITY_PRODUCTS: "NVDA-USD"})
    assert single.equity_products == ("NVDA-USD",)
    assert isinstance(single.equity_products, tuple)

    # Each of these is refused, and the message names the variable.
    for text in (
        "NVDA-USDC",  # an equity product is quoted in USD
        "nvda-usd",  # lower-case
        "BRK.B-USD",  # a ticker carries no punctuation
        "NVDA-USD,NVDA-USD",  # listed twice
        "TOOLONGX-USD",  # 7 characters: too long for a ticker
    ):
        with pytest.raises(ValueError) as err:
            Limits.from_env({EQUITY_PRODUCTS: text})
        assert EQUITY_PRODUCTS in str(err.value)

    # The crypto and equity lists may not describe the same instrument, whether
    # the id matches outright or only collides on the base asset.
    for env in (
        {PRODUCTS: "NVDA-USD,BTC-USDC", EQUITY_PRODUCTS: "NVDA-USD"},
        {PRODUCTS: "BTC-USDC", EQUITY_PRODUCTS: "BTC-USD"},
        {EQUITY_PRODUCTS: "XRP-USD"},  # XRP-USDC is in the crypto defaults
    ):
        with pytest.raises(ValueError) as err:
            Limits.from_env(env)
        assert EQUITY_PRODUCTS in str(err.value)


class FakeSpec:
    """A product spec stub: the one field the type guard reads is the kind."""

    def __init__(self, product_type):
        self.product_type = product_type


def spec_for_types(table):
    """A `spec_for` answering from a product id -> product_type table."""

    def spec_for(product):
        return FakeSpec(table[product])

    return spec_for


def test_validate_product_types_accepts_a_matching_pair():
    spec_for = spec_for_types({"XRP-USDC": "SPOT", "NVDA-USD": "EQUITY"})

    assert validate_product_types(("XRP-USDC",), ("NVDA-USD",), spec_for) is None

    # Two empty lists are a valid configuration: nothing listed, nothing wrong.
    assert validate_product_types((), (), spec_for) is None


def test_validate_product_types_refuses_an_equity_in_the_crypto_list():
    # NVDA-USD is a well-formed pair, so the env parser accepts it; what makes it
    # wrong is the product's kind, and the type guard is what reads the kind.
    limits = Limits.from_env({PRODUCTS: "NVDA-USD"})
    assert limits.products == ("NVDA-USD",)

    spec_for = spec_for_types({"NVDA-USD": "EQUITY", "XRP-USDC": "SPOT"})
    with pytest.raises(ValueError) as err:
        validate_product_types(limits.products, limits.equity_products, spec_for)
    assert "NVDA-USD" in str(err.value)

    # Beside a crypto product too: the equity entry is the one refused.
    with pytest.raises(ValueError) as err:
        validate_product_types(("XRP-USDC", "NVDA-USD"), (), spec_for)
    assert "NVDA-USD" in str(err.value)


def test_validate_product_types_refuses_a_spot_in_the_equity_list():
    spec_for = spec_for_types({"NVDA-USD": "EQUITY", "XRP-USDC": "SPOT"})

    with pytest.raises(ValueError) as err:
        validate_product_types((), ("NVDA-USD", "XRP-USDC"), spec_for)
    assert "XRP-USDC" in str(err.value)

    # The equity list alone is enough; no crypto list is needed to catch it.
    with pytest.raises(ValueError) as err:
        validate_product_types((), ("XRP-USDC",), spec_for)
    assert "XRP-USDC" in str(err.value)


def test_validate_product_types_reads_the_kind_case_insensitively():
    # Padding and case in the kind do not matter: " spot " is still SPOT.
    padded = spec_for_types({"XRP-USDC": " spot ", "nvda-usd": "Equity"})
    assert validate_product_types(("XRP-USDC",), ("nvda-usd",), padded) is None

    wrong_crypto = spec_for_types({"XRP-USDC": "equity"})
    with pytest.raises(ValueError) as err:
        validate_product_types(("XRP-USDC",), (), wrong_crypto)
    assert "XRP-USDC" in str(err.value)

    wrong_equity = spec_for_types({"NVDA-USD": " Spos "})
    with pytest.raises(ValueError) as err:
        validate_product_types((), ("NVDA-USD",), wrong_equity)
    assert "NVDA-USD" in str(err.value)


def test_equity_money_fields():
    limits = Limits.from_env(
        {
            EQUITY_MAX_ORDER: "150",
            EQUITY_DAILY: "250",
            EQUITY_AI_CAPITAL: "75.5",
            EQUITY_DRAWDOWN_ALERT: "10",
        }
    )

    assert limits.equity_max_order_usd == D("150")
    assert isinstance(limits.equity_max_order_usd, D)
    assert not isinstance(limits.equity_max_order_usd, float)

    assert limits.equity_daily_notional_usd == D("250")
    assert isinstance(limits.equity_daily_notional_usd, D)

    assert limits.equity_ai_capital_usd == D("75.5")
    assert isinstance(limits.equity_ai_capital_usd, D)

    assert limits.equity_drawdown_alert_pct == D("10")
    assert isinstance(limits.equity_drawdown_alert_pct, D)

    # Zero equity capital is valid: the AI simply has nothing to spend.
    broke = Limits.from_env({EQUITY_AI_CAPITAL: "0"})
    assert broke.equity_ai_capital_usd == D("0")
    assert isinstance(broke.equity_ai_capital_usd, D)

    # A 100% drawdown alert is the top of the range and is accepted.
    top = Limits.from_env({EQUITY_DRAWDOWN_ALERT: "100"})
    assert top.equity_drawdown_alert_pct == D("100")
    assert isinstance(top.equity_drawdown_alert_pct, D)

    # Each bad value is refused, and the message names the variable.
    for name, text in (
        (EQUITY_MAX_ORDER, "0"),
        (EQUITY_MAX_ORDER, "-1"),
        (EQUITY_MAX_ORDER, "NaN"),
        (EQUITY_DAILY, "0"),
        (EQUITY_AI_CAPITAL, "-1"),
        (EQUITY_AI_CAPITAL, "Infinity"),
        (EQUITY_AI_CAPITAL, "abc"),
        (EQUITY_DRAWDOWN_ALERT, "0"),
        (EQUITY_DRAWDOWN_ALERT, "101"),
    ):
        with pytest.raises(ValueError) as err:
            Limits.from_env({name: text})
        assert name in str(err.value)


def test_equity_live_bool():
    for text in (
        "true",
        "TRUE",
        "True",
        " true ",
        "\ttrue\n",
        "1",
        "yes",
        "YEs",
        "on",
        "ON ",
        " On ",
    ):
        assert Limits.from_env({EQUITY_LIVE: text}).equity_live is True

    for text in (
        "false",
        "FALSE",
        "False",
        " false ",
        "\tfalse\n",
        "0",
        "no",
        "nO",
        "off",
        "OFF ",
        " Off ",
    ):
        assert Limits.from_env({EQUITY_LIVE: text}).equity_live is False

    # Blank means the default, which is off.
    assert Limits.from_env({EQUITY_LIVE: ""}).equity_live is False
    assert Limits.from_env({EQUITY_LIVE: "   "}).equity_live is False

    for text in ("maybe", "2"):
        with pytest.raises(ValueError) as err:
            Limits.from_env({EQUITY_LIVE: text})
        assert EQUITY_LIVE in str(err.value)


def test_is_equity_tradable():
    limits = Limits.from_env({PRODUCTS: "BTC-USDC", EQUITY_PRODUCTS: "NVDA-USD"})

    assert limits.is_equity("NVDA-USD") is True
    assert limits.is_equity("BTC-USDC") is False

    # Tradable is the union of the two lists, and nothing else.
    assert limits.tradable("NVDA-USD") is True
    assert limits.tradable("BTC-USDC") is True
    assert limits.tradable("VOO-USD") is False
    assert limits.tradable("ETH-USDC") is False


def test_daily_resets_at_utc_midnight(store, chicago_tz):
    add(store, 1, utc(2026, 3, 10, 23, 59, 59), price=D("2"), size=D("10"))  # 20
    add(store, 2, utc(2026, 3, 11, 0, 0, 1), price=D("3"), size=D("10"))  # 30

    late, _ = window_at(store, utc(2026, 3, 10, 23, 59, 59, us=500000))
    # A row dated after the clock counts: the window has no upper bound, so a
    # future-dated row can never buy budget (fail closed).
    assert late.daily_notional(None) == D("50")

    new_day, _ = window_at(store, utc(2026, 3, 11, 0, 0, 2))
    assert new_day.daily_notional(None) == D("30")
    assert isinstance(new_day.daily_notional(None), D)

    # Exactly midnight belongs to the new day (the lower bound is inclusive).
    add(store, 3, utc(2026, 3, 11, 0, 0, 0), price=D("1"), size=D("5"))  # 5
    same_window, _ = window_at(store, utc(2026, 3, 11, 0, 0, 2))
    assert same_window.daily_notional(None) == D("35")
    assert same_window.orders_last_hour(None) == 3


def test_daily_window_is_utc_not_local_day(store, chicago_tz):
    # America/Chicago is UTC-5 here, so 03:00 UTC on 03-10 is 22:00 on 03-09
    # local: the row and the clock below sit on different local days but the
    # same UTC day.
    add(store, 1, utc(2026, 3, 10, 3, 0, 0), price=D("2"), size=D("7"))  # 14

    midday, _ = window_at(store, utc(2026, 3, 10, 12, 0, 0))  # 07:00 local, 03-10
    assert midday.daily_notional(None) == D("14")

    # 23:00 UTC on 03-10 is 18:00 local on the 10th — the same local day as the
    # clock below, which has already rolled over to the UTC day of the 11th.
    add(store, 2, utc(2026, 3, 10, 23, 0, 0), price=D("3"), size=D("5"))  # 15

    next_utc_day, _ = window_at(store, utc(2026, 3, 11, 2, 0, 0))  # 21:00 local 03-10
    assert next_utc_day.daily_notional(None) == D("0")

    # A row inside the new UTC day is what counts, whatever the local day says.
    add(store, 3, utc(2026, 3, 11, 1, 0, 0), price=D("11"), size=D("2"))  # 22
    assert next_utc_day.daily_notional(None) == D("22")


def test_rolling_hour_crosses_clock_hour(store, tmp_path):
    base = utc(2026, 3, 10, 10, 50, 0)
    for i in range(30):  # 10:50:00 ... 10:59:40, one every 20 s
        add(store, i + 1, base + 20 * i, price=D("1"), size=D("1"))
    add(store, 40, utc(2026, 3, 10, 11, 4, 59), price=D("1"), size=D("1"))

    # 11:05 is a new clock hour, but nothing has rolled out of the window yet.
    at_1105, _ = window_at(store, utc(2026, 3, 10, 11, 5, 0))
    assert at_1105.orders_last_hour(None) == 31

    # 11:50:30 cuts at 10:50:30: the 10:50:00 and 10:50:20 rows are gone,
    # the other 28 spread rows plus the 11:04:59 one remain.
    later, _ = window_at(store, utc(2026, 3, 10, 11, 50, 30))
    assert later.orders_last_hour(None) == 29

    # The edges of the rolling hour: strictly newer than now() - 3600.
    boundary_path = tmp_path / "boundary.db"
    edge = Store(boundary_path)
    try:
        edge.create_bot("b1", PRODUCT, "grid", {}, D("100"), D("50"))
        now = utc(2026, 3, 10, 12, 0, 0)
        add(edge, 1, now - 3600, price=D("1"), size=D("1"))  # exactly 3600 s old
        add(edge, 2, now - 3599, price=D("1"), size=D("1"))  # one second inside
        edge_window, _ = window_at(edge, now)
        assert edge_window.orders_last_hour(None) == 1
    finally:
        edge.close()


def test_post_only_rejections_not_counted(store):
    t = utc(2026, 3, 10, 12, 0, 0)
    add(store, 1, t, price=D("2"), size=D("1"), status=REJECTED)
    add(store, 2, t, price=D("3"), size=D("1"), status=FAILED)

    window, _ = window_at(store, t)
    assert window.daily_notional(None) == D("0")
    assert window.orders_last_hour(None) == 0

    add(store, 3, t, price=D("4"), size=D("1"), status=OPEN)
    add(store, 4, t, price=D("5"), size=D("1"), status=FILLED)
    add(store, 5, t, price=D("6"), size=D("1"), status=CANCELLED)

    assert window.daily_notional(None) == D("15")
    assert window.orders_last_hour(None) == 3

    # The cancelled row keeps counting even after a rejection lands beside it.
    add(store, 6, t, price=D("100"), size=D("1"), status=REJECTED)
    assert window.daily_notional(None) == D("15")
    assert window.orders_last_hour(None) == 3


def test_null_status_row_counts(store):
    t = utc(2026, 3, 10, 12, 0, 0)
    cid = add(store, 1, t, price=D("2"), size=D("9"))  # 18

    store.conn().execute(
        "UPDATE orders SET status=NULL WHERE client_order_id=?", (cid,)
    )

    window, _ = window_at(store, t)
    assert window.daily_notional(None) == D("18")
    assert window.orders_last_hour(None) == 1


def test_orders_created_at_index_exists(store):
    names = {row[1] for row in store.conn().execute("PRAGMA index_list(orders)")}

    assert "orders_created_at" in names


def test_pending_submit_counted(store):
    t = utc(2026, 3, 10, 12, 0, 0)
    add(store, 1, t, price=D("1.5"), size=D("4"), status=PENDING_SUBMIT)

    window, _ = window_at(store, t)
    assert window.daily_notional(None) == D("6")
    assert window.daily_notional(None) != D("0")
    assert window.orders_last_hour(None) == 1


def test_buy_and_sell_both_count_at_stored_price(store):
    t = utc(2026, 3, 10, 12, 0, 0)
    buy = add(store, 1, t, side="BUY", price=D("1.25"), size=D("8"))
    sell = add(store, 2, t, side="SELL", price=D("0.5"), size=D("3"))

    window, _ = window_at(store, t)
    assert window.daily_notional(None) == D("11.5")  # 1.25*8 + 0.5*3
    assert isinstance(window.daily_notional(None), D)
    assert window.orders_last_hour(None) == 2

    # The stored price is the final submitted one, so a reprice moves the notional.
    store.update_order(buy, price=D("1.5"))
    assert window.daily_notional(None) == D("13.5")  # 1.5*8 + 0.5*3
    assert window.orders_last_hour(None) == 2

    store.update_order(sell, price=D("1"))
    assert window.daily_notional(None) == D("15")  # 1.5*8 + 1*3


def test_source_filtering_separates_bot_from_ai(store):
    t = utc(2026, 3, 10, 12, 0, 0)
    add(store, 1, t, price=D("2"), size=D("5"), source="bot")  # 10
    add(store, 2, t, side="SELL", price=D("1"), size=D("5"), source="bot")  # 5
    add(store, 3, t, price=D("3"), size=D("2"), source="ai", owner="ai")  # 6

    window, _ = window_at(store, t)

    assert window.daily_notional("bot") == D("15")
    assert window.daily_notional("ai") == D("6")
    assert window.daily_notional(None) == D("21")

    assert window.orders_last_hour("bot") == 2
    assert window.orders_last_hour("ai") == 1
    assert window.orders_last_hour(None) == 3

    # A source nobody used is an empty read, still typed.
    assert window.daily_notional("nobody") == D("0")
    assert isinstance(window.daily_notional("nobody"), D)
    assert window.orders_last_hour("nobody") == 0
    assert isinstance(window.orders_last_hour("nobody"), int)


def test_daily_notional_filters(store):
    t = utc(2026, 3, 10, 12, 0, 0)
    add(store, 1, t, price=D("2"), size=D("10"), product="XRP-USDC")  # 20
    add(store, 2, t, price=D("5"), size=D("4"), product="NVDA-USD")  # 20
    add(store, 3, t, price=D("10"), size=D("1"), product="NVDA-USD")  # 10

    window, _ = window_at(store, t)

    # No filter is the unchanged read: every product's notional.
    total = window.daily_notional(None)
    assert total == D("50")
    assert isinstance(total, D)

    equities = window.daily_notional(None, products=("NVDA-USD",))
    assert equities == D("30")
    assert isinstance(equities, D)

    # Any collection of products works, tuple or not.
    assert window.daily_notional(None, products=["XRP-USDC"]) == D("20")
    assert isinstance(window.daily_notional(None, products=["XRP-USDC"]), D)

    # Excluding takes the other side: the equity spend leaves the crypto budget.
    assert window.daily_notional(None, exclude_products={"NVDA-USD"}) == D("20")
    nothing_left = window.daily_notional(
        None, exclude_products={"NVDA-USD", "XRP-USDC"}
    )
    assert nothing_left == D("0")
    assert isinstance(nothing_left, D)

    # An empty collection matches nothing: it is a filter, not "no filter".
    empty = window.daily_notional(None, products=())
    assert empty == D("0")
    assert isinstance(empty, D)

    # The source filter still applies beside the product ones.
    add(
        store,
        4,
        t,
        price=D("7"),
        size=D("1"),
        product="NVDA-USD",
        source="ai",
        owner="ai",
    )  # 7

    assert window.daily_notional("ai", products=("NVDA-USD",)) == D("7")
    assert window.daily_notional("ai") == D("7")
    assert window.daily_notional(None) == D("57")
    assert window.daily_notional(None, products=("NVDA-USD",)) == D("37")
    assert window.daily_notional("bot", products=["NVDA-USD"]) == D("30")
    assert window.daily_notional("bot", exclude_products=["NVDA-USD"]) == D("20")


def test_caps_survive_restart(tmp_path):
    path = tmp_path / "caps.db"
    t = utc(2026, 3, 10, 12, 0, 0)

    first = Store(path)
    try:
        first.create_bot("b1", PRODUCT, "grid", {}, D("100"), D("50"))
        add(first, 1, t, price=D("2"), size=D("3"))  # 6, inside the hour
        add(first, 2, t - 1800, price=D("1.5"), size=D("2"), status=FILLED)  # 3
        add(first, 3, t - 7200, price=D("9"), size=D("9"), status=OPEN)  # day, no hour

        before, _ = window_at(first, t)
        assert before.daily_notional(None) == D("90")  # 6 + 3 + 81
        assert before.orders_last_hour(None) == 2
    finally:
        first.close()

    second = Store(path)
    try:
        after, _ = window_at(second, t)
        assert after.daily_notional(None) == before.daily_notional(None)
        assert after.daily_notional(None) == D("90")
        assert after.orders_last_hour(None) == before.orders_last_hour(None)
        assert after.orders_last_hour(None) == 2
    finally:
        second.close()


def test_empty_table_is_zero(store):
    window, _ = window_at(store, utc(2026, 3, 10, 12, 0, 0))

    assert window.daily_notional(None) == D("0")
    assert window.daily_notional(None) == 0
    assert isinstance(window.daily_notional(None), D)

    assert window.daily_notional("bot") == D("0")
    assert isinstance(window.daily_notional("bot"), D)

    assert window.orders_last_hour(None) == 0
    assert isinstance(window.orders_last_hour(None), int)
    assert not isinstance(window.orders_last_hour(None), D)

    assert window.orders_last_hour("ai") == 0
    assert isinstance(window.orders_last_hour("ai"), int)


# ---------------------------------------------------------------- product type


def test_daily_notional_filters_by_product_type(store):
    """A SPOT budget and an EQUITY budget are read apart, from one table."""
    t = utc(2026, 3, 10, 12, 0, 0)
    add(store, 1, t, price=D("2"), size=D("10"))  # 20, SPOT by default
    add(
        store,
        2,
        t,
        price=D("5"),
        size=D("4"),
        product="NVDA-USD",
        product_type="EQUITY",
        source="ai",
    )  # 20, EQUITY
    add(
        store,
        3,
        t,
        price=D("10"),
        size=D("1"),
        product="VOO-USD",
        product_type="EQUITY",
        source="ai",
    )  # 10, EQUITY

    window, _ = window_at(store, t)

    # No filter is still every row, exactly as before.
    assert window.daily_notional(None) == D("50")

    assert window.daily_notional(None, product_type="SPOT") == D("20")
    assert window.daily_notional(None, product_type="EQUITY") == D("30")
    assert isinstance(window.daily_notional(None, product_type="EQUITY"), D)

    # The source filter still applies beside the kind: the SPOT row is the
    # bot's, the two EQUITY rows are the ai's.
    assert window.daily_notional("bot", product_type="SPOT") == D("20")
    assert window.daily_notional("ai", product_type="SPOT") == D("0")
    assert window.daily_notional("ai", product_type="EQUITY") == D("30")
    assert window.daily_notional("bot", product_type="EQUITY") == D("0")

    # ... and so do the product filters.
    assert window.daily_notional(
        None, product_type="EQUITY", products=("NVDA-USD",)
    ) == D("20")
    assert window.daily_notional(
        None, product_type="SPOT", products=("NVDA-USD",)
    ) == D("0")
    assert window.daily_notional(
        None, product_type="EQUITY", exclude_products=("VOO-USD",)
    ) == D("20")


def test_daily_notional_filters_one_book_with_a_product_type(store):
    t = utc(2026, 3, 10, 12, 0, 0)
    add(store, 1, t, price=D("2"), size=D("10"))  # dry SPOT, 20
    add(store, 2, t, price=D("3"), size=D("5"), book="live")  # live SPOT, 15
    add(
        store,
        3,
        t,
        price=D("7"),
        size=D("1"),
        product="NVDA-USD",
        product_type="EQUITY",
        book="live",
    )  # live EQUITY, 7

    window, _ = window_at(store, t)

    assert window.daily_notional(None, book="dry", product_type="SPOT") == D("20")
    assert window.daily_notional(None, book="dry", product_type="EQUITY") == D("0")
    assert window.daily_notional(None, book="live", product_type="SPOT") == D("15")
    assert window.daily_notional(None, book="live", product_type="EQUITY") == D("7")


@pytest.mark.parametrize("bad", ["equity", "X", "Spot", "spoT", "SPOT "])
def test_daily_notional_refuses_an_unknown_product_type(store, bad):
    t = utc(2026, 3, 10, 12, 0, 0)
    add(store, 1, t, price=D("2"), size=D("10"))

    window, _ = window_at(store, t)

    with pytest.raises(ValueError):
        window.daily_notional(None, product_type=bad)