"""Statistics that read a project's trials as a search, not a single finding.

A trial is one recorded run: an asset, an interval, a rule and its parameters.
Read alone its excess Sharpe is just a number; read next to the rest of the
project's trials it is one of many looks at overlapping data.  This module turns
that collection into the numbers a reader needs before trusting one row:

* `pbo_cscv` cuts the period into equal blocks, ranks the configs on half of
  them and reads where the winner lands on the other half, so its answer is how
  often the in-sample best is a poor out-of-sample pick.
* `expected_max_sharpe` is the Sharpe a search of N configs reaches on luck
  alone, and `deflated_sharpe` reports how much of an observed Sharpe survives
  that bar, allowing for the sample's skew and kurtosis.
* `newey_west_t` gives a mean a standard error that tolerates correlation
  between neighbouring periods, `newey_west_long_run_variance` reports that
  variance itself, and `min_detectable_edge` is the smallest mean excess return
  a sample of a given size and spread can resolve at all.
* `trial_stats` reads the multiple-comparisons count the other functions here
  take as `n_trials` straight off the store, with the spread of the trial
  Sharpes beside it.

Every statistic here is a float: these are statistics about returns, not money,
and the money a run settles in stays `Decimal` in `sim` and `metrics`.

The second half of the module produces the numbers instead of reading them.  It
walks a rule forward over contiguous windows of one data segment, joins the test
slices into a single out-of-sample run, runs the benchmarks over the very same
bars, records each config as a trial, and turns the result into a verdict.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import statistics
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal as D
from statistics import NormalDist
from typing import Iterable, Optional

from .costs import BUY, CostModel, Order
from .gridsim import simulate_grid
from .metrics import (
    after_tax_return,
    buy_and_hold,
    fifty_fifty,
    max_drawdown,
    period_returns,
    sharpe,
)
from .sim import STOCK_MAX_GAP, PastBars, SimResult, simulate
from .store import Bar, Event, LabStore, TrialRow

__all__ = [
    "DSR_MIN",
    "NW_T_MIN",
    "PBO_MAX",
    "PBOResult",
    "InsufficientData",
    "OOSResult",
    "TrialStats",
    "Verdict",
    "WindowChoice",
    "bars_hash",
    "data_segments",
    "deflated_sharpe",
    "default_nw_lags",
    "evaluate_edge_rule",
    "expected_max_sharpe",
    "min_detectable_edge",
    "newey_west_long_run_variance",
    "newey_west_t",
    "pbo_cscv",
    "skew_kurtosis",
    "trial_stats",
    "verdict_from_numbers",
    "walk_forward_oos",
]

# A pooled variance at or below this is no spread at all: returns that never
# move have a Sharpe of 0 rather than an unbounded one.
ZERO_VARIANCE = 1e-18
# Two ratios closer than this are the same value for ranking purposes.
TIE = 1e-12
# Euler-Mascheroni, the constant in the expected maximum of N draws.
EULER = 0.5772156649015329


# ---------------------------------------------------------------- value helpers


def _number(value: object, name: str) -> float:
    """A finite float from an int or a float, else ValueError."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number, not {type(value).__name__}")
    out = float(value)
    if not math.isfinite(out):
        raise ValueError(f"{name} must be finite: {value!r}")
    return out


def _floats(values: Iterable[object], name: str) -> list[float]:
    """A series of finite floats; a value that is not one raises ValueError."""
    return [
        _number(value, f"{name}[{index}]")
        for index, value in enumerate(values)
    ]


def _whole(value: object, name: str, minimum: Optional[int] = None) -> int:
    """A whole number from an int or an integral float, else ValueError."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a whole number: {value!r}")
    if isinstance(value, int):
        out = value
    elif isinstance(value, float) and value.is_integer():
        out = int(value)
    else:
        raise ValueError(f"{name} must be a whole number: {value!r}")
    if minimum is not None and out < minimum:
        raise ValueError(f"{name} must be at least {minimum}: {value!r}")
    return out


def _quantile(probability: float) -> float:
    """The standard normal quantile, the argument kept inside (0, 1)."""
    return NormalDist().inv_cdf(min(1.0 - 1e-15, max(1e-15, probability)))


def _matrix(returns_matrix: Iterable[Iterable[object]]) -> list[list[float]]:
    """The rows as finite floats, refusing a ragged matrix or a non-number."""
    rows: list[list[float]] = []
    width: Optional[int] = None
    for index, row in enumerate(returns_matrix):
        try:
            raw = list(row)
        except TypeError as exc:
            raise ValueError(
                f"returns_matrix row {index} is not a sequence of values"
            ) from exc
        values = _floats(raw, f"returns_matrix[{index}]")
        if width is None:
            width = len(values)
        elif len(values) != width:
            raise ValueError(
                f"returns_matrix row {index} carries {len(values)} values, "
                f"not the {width} of the first row"
            )
        rows.append(values)
    return rows


# ---------------------------------------------------------------- PBO / CSCV


@dataclass(frozen=True)
class PBOResult:
    """The share of block splits whose in-sample winner fails out of sample.

    `pbo` is the counted share of the `n_combos` splits: a split counts when the
    config chosen on the in-sample half lands at or below the middle of the
    out-of-sample order.  `n_groups` is the block count, `n_configs` the column
    count, and `warnings` names anything that makes the share thin to read
    (currently a config count below 10).
    """

    pbo: float
    n_combos: int
    n_groups: int
    n_configs: int
    warnings: tuple[str, ...]


def _block_stats(
    rows: list[list[float]], n_configs: int
) -> tuple[float, list[float], list[float]]:
    """One block's row count, per-config sums and per-config sums of squares."""
    sums = [math.fsum(row[config] for row in rows) for config in range(n_configs)]
    squares = [
        math.fsum(row[config] * row[config] for row in rows)
        for config in range(n_configs)
    ]
    return float(len(rows)), sums, squares


def _pooled_sharpe(n_obs: int, total: float, squares: float) -> float:
    """Mean over the sample standard deviation of the pooled rows.

    A variance at or below `ZERO_VARIANCE` is read as no spread, so the Sharpe
    is 0.0 rather than a division by nothing.
    """
    mean = total / n_obs
    variance = (squares - n_obs * mean * mean) / (n_obs - 1)
    if variance <= ZERO_VARIANCE:
        return 0.0
    return mean / math.sqrt(variance)


def _half_sharpes(
    blocks: list[tuple[float, list[float], list[float]]],
    indices: tuple[int, ...],
    n_configs: int,
) -> list[float]:
    """Per-config Sharpe over the rows of the named blocks, pooled in order."""
    n_obs = 0
    sums = [0.0] * n_configs
    squares = [0.0] * n_configs
    for index in indices:
        count, block_sums, block_squares = blocks[index]
        n_obs += int(count)
        for config in range(n_configs):
            sums[config] += block_sums[config]
            squares[config] += block_squares[config]
    return [
        _pooled_sharpe(n_obs, sums[config], squares[config])
        for config in range(n_configs)
    ]


def pbo_cscv(
    returns_matrix: list[list[float]], n_groups: int = 16
) -> Optional[PBOResult]:
    """The share of block splits whose in-sample winner fails out of sample.

    The matrix has one row per period (oldest first) and one column per config.
    The period is cut into `n_groups` equal blocks of `len(rows) // n_groups`
    rows, dropping the oldest rows that do not fill a block, and every way of
    taking half of the blocks as the in-sample half is walked (the rest of the
    blocks are the out-of-sample half).  On each split the config with the
    highest in-sample Sharpe is the winner; the winner's out-of-sample Sharpe is
    put in order among the other configs' out-of-sample Sharpes, and the split
    counts when the winner lands at or below the middle of that order — half the
    configs or worse.  `pbo` is the counted share of the C(n_groups,
    n_groups / 2) splits, so 0 says the in-sample best was always a top-half pick
    out of sample and 1 says it was always at or below half.

    Each block's count, sum and sum of squares are taken once and pooled per
    split, so a half's Sharpe is the mean over the sample standard deviation
    (n - 1) of the pooled rows.  A pooled variance at or below 1e-18 is read as
    no spread and gives a Sharpe of 0.0.  Two Sharpes closer than 1e-12 are the
    same value: the winner is the lowest-index config within that distance of
    the best, and the rank separates configs strictly below the winner from the
    ones level with it.

    None (nothing to compute) when `n_groups` is odd or below 4, when there are
    fewer than 4 configs, or when a block would hold fewer than two rows.  A
    ragged matrix, or a value that is not a finite number, raises ValueError.
    `warnings` names a config count below 10, where there are too few candidates
    for the ranking to say much.
    """
    groups = _whole(n_groups, "n_groups")
    matrix = _matrix(returns_matrix)
    n_rows = len(matrix)
    n_configs = len(matrix[0]) if matrix else 0
    if groups % 2 or groups < 4 or n_configs < 4 or n_rows < 2 * groups:
        return None

    size = n_rows // groups
    # The oldest rows that do not fill a whole block are left out of the walk.
    trimmed = matrix[n_rows - groups * size :]
    blocks = [
        _block_stats(trimmed[start : start + size], n_configs)
        for start in range(0, groups * size, size)
    ]

    half = groups // 2
    n_combos = math.comb(groups, half)
    overfit = 0
    for chosen in itertools.combinations(range(groups), half):
        picked = set(chosen)
        rest = tuple(index for index in range(groups) if index not in picked)
        in_sample = _half_sharpes(blocks, chosen, n_configs)
        out_sample = _half_sharpes(blocks, rest, n_configs)

        best = max(in_sample)
        winner = next(
            config
            for config, value in enumerate(in_sample)
            if value >= best - TIE
        )
        target = out_sample[winner]
        lower = sum(1 for value in out_sample if value < target - TIE)
        level = sum(1 for value in out_sample if abs(value - target) <= TIE)
        # rank = lower + (level + 1) / 2, and ln(rank / (N + 1 - rank)) <= 0
        # exactly when 2 * rank <= N + 1, so the sign stays in integers.
        if 2 * lower + level + 1 <= n_configs + 1:
            overfit += 1

    warnings: tuple[str, ...] = ()
    if n_configs < 10:
        warnings = (
            f"too few configs for a reliable PBO (N={n_configs}, want N well "
            f"above 10)",
        )
    return PBOResult(
        pbo=overfit / n_combos,
        n_combos=n_combos,
        n_groups=groups,
        n_configs=n_configs,
        warnings=warnings,
    )


# ---------------------------------------------------------------- deflated Sharpe


def expected_max_sharpe(
    n_trials: int, var_trials_sr: float
) -> Optional[float]:
    """The Sharpe a search of `n_trials` configs reaches on luck alone.

    SR0 = sqrt(V) * ((1 - g) * Z^-1(1 - 1/N) + g * Z^-1(1 - 1/(N e))), with V the
    variance of the trial Sharpes, N the trial count, g the Euler-Mascheroni
    constant and Z the standard normal.  None when there are fewer than two
    trials, since there is no maximum across one draw, and 0.0 when the trial
    Sharpes have no spread at all.  A negative variance raises ValueError; so
    does a trial count that is not a whole number.
    """
    count = _whole(n_trials, "n_trials")
    variance = _number(var_trials_sr, "var_trials_sr")
    if variance < 0:
        raise ValueError(
            f"var_trials_sr must not be negative: {var_trials_sr!r}"
        )
    if count < 2:
        return None
    trials = float(count)
    high = _quantile(1.0 - 1.0 / trials)
    extreme = _quantile(1.0 - 1.0 / (trials * math.e))
    return math.sqrt(variance) * (
        (1.0 - EULER) * high + EULER * extreme
    )


def deflated_sharpe(
    sr: float,
    n_obs: int,
    skew: float,
    kurt: float,
    n_trials: int,
    var_trials_sr: float,
) -> Optional[float]:
    """How much of a per-period Sharpe survives the bar a search of N sets.

    The observed Sharpe is measured against `expected_max_sharpe` in units of
    its own standard error, and the standard normal distribution function of
    that distance is returned: a value near 1 says the Sharpe clears the bar a
    search of this many configs would reach on luck, a value near 0 says it does
    not.  `sr` is per period, not annualized.  `skew` and `kurt` are the sample's
    skewness and plain (non-excess) kurtosis, 3 for a normal sample; they widen
    or narrow the standard error through
    `1 - skew * sr + ((kurt - 1) / 4) * sr**2`.

    None when there are fewer than two observations, when there are fewer than
    two trials, or when that factor is not positive (the standard error is then
    not a real number).  The result is not clamped into any range.
    """
    observed = _number(sr, "sr")
    observations = _whole(n_obs, "n_obs")
    skewness = _number(skew, "skew")
    tail = _number(kurt, "kurt")
    if observations < 2:
        return None
    bar = expected_max_sharpe(n_trials, var_trials_sr)
    if bar is None:
        return None
    factor = (
        1.0
        - skewness * observed
        + ((tail - 1.0) / 4.0) * observed * observed
    )
    if factor <= 0:
        return None
    distance = (observed - bar) * math.sqrt(observations - 1) / math.sqrt(factor)
    return NormalDist().cdf(distance)


# ---------------------------------------------------------------- moments


def skew_kurtosis(returns: list[float]) -> Optional[tuple[float, float]]:
    """The sample's skewness and plain kurtosis, from moments about the mean.

    The second, third and fourth moments are population moments: the mean of the
    squared, cubed and fourth-powered deviations from the mean.  Skewness is the
    third over the second to the power 3/2, and kurtosis is the fourth over the
    second squared, so a normal sample sits near 0 and 3.

    None when there are fewer than two values, or when the second moment is at
    or below 1e-18 so there is no spread to divide by.  A value that is not a
    finite number raises ValueError.
    """
    values = _floats(returns, "returns")
    n_obs = len(values)
    if n_obs < 2:
        return None
    mean = math.fsum(values) / n_obs
    deviations = [value - mean for value in values]
    second = math.fsum(gap * gap for gap in deviations) / n_obs
    if second <= ZERO_VARIANCE:
        return None
    third = math.fsum(gap**3 for gap in deviations) / n_obs
    fourth = math.fsum(gap**4 for gap in deviations) / n_obs
    return third / second**1.5, fourth / (second * second)


# ---------------------------------------------------------------- Newey-West


def default_nw_lags(n_obs: int) -> int:
    """The NW94 pilot n, used as a fixed lag: floor(4 * (n_obs / 100) ** (2/9)).

    More observations buy more lags, slowly: 100 observations give 4, 500 give
    5, 1000 give 6, and a short sample gives 1 or 0.  A count below 1 raises
    ValueError.
    """
    observations = _whole(n_obs, "n_obs", minimum=1)
    return int(math.floor(4.0 * (observations / 100.0) ** (2.0 / 9.0)))


def newey_west_long_run_variance(
    values: list[float], lags: Optional[int] = None
) -> Optional[float]:
    """The Newey-West long-run variance of a series, S.

    With T observations, xbar the mean and h_t = x_t - xbar, the autocovariances
    are `Omega_j = sum over t > j of h_t * h_{t-j} / T`, and the long-run
    variance is `S = Omega_0 + sum from j = 1 to m of (1 - j / (m + 1)) * 2 *
    Omega_j`, so later lags are weighted down linearly.

    `m` is `lags` when given, else `default_nw_lags(T)`.  None when there are
    fewer than three observations, when `m` is at least T, or when `S` is at or
    below 1e-18 (the series has no variation to standardise against).  A
    negative lag count, a lag count that is not a whole number, or a value that
    is not a finite number raises ValueError.
    """
    series = _floats(values, "values")
    n_obs = len(series)
    if lags is None:
        window = default_nw_lags(n_obs) if n_obs >= 1 else 0
    else:
        window = _whole(lags, "lags", minimum=0)
    if n_obs < 3 or window >= n_obs:
        return None

    mean = math.fsum(series) / n_obs
    deviations = [value - mean for value in series]
    total = math.fsum(gap * gap for gap in deviations) / n_obs
    for lag in range(1, window + 1):
        weight = 1.0 - lag / (window + 1.0)
        covariance = (
            math.fsum(
                deviations[index] * deviations[index - lag]
                for index in range(lag, n_obs)
            )
            / n_obs
        )
        total += weight * 2.0 * covariance
    if total <= ZERO_VARIANCE:
        return None
    return total


def newey_west_t(
    excess_returns: list[float], lags: Optional[int] = None
) -> Optional[float]:
    """A mean's ratio to a standard error that tolerates serial correlation.

    The long-run variance `S` is the one `newey_west_long_run_variance`
    reports: `Omega_0` plus `sum from j = 1 to m of (1 - j / (m + 1)) * 2 *
    Omega_j`, with `Omega_j = sum over t > j of h_t * h_{t-j} / T`, xbar the
    mean, h_t = x_t - xbar, and later lags weighted down linearly.  The result
    is `xbar / sqrt(S / T)`, the ratio of the mean to its own standard error.

    `m` is `lags` when given, else `default_nw_lags(T)`.  None when there are
    fewer than three observations, when `m` is at least T, or when `S` is at or
    below 1e-18 (the series has no variation to standardise against).  A
    negative lag count, a lag count that is not a whole number, or a value that
    is not a finite number raises ValueError.
    """
    values = _floats(excess_returns, "excess_returns")
    n_obs = len(values)
    total = newey_west_long_run_variance(values, lags)
    if total is None:
        return None
    mean = math.fsum(values) / n_obs
    return mean / math.sqrt(total / n_obs)


# ---------------------------------------------------------------- minimum detectable edge


def min_detectable_edge(
    n_obs: int,
    sd: float,
    alpha: float = 0.05,
    power: float = 0.8,
    *,
    t_crit: Optional[float] = None,
) -> float:
    """The smallest mean excess return a sample of this size can resolve.

    The two-sided critical value at `alpha` and the quantile at `power` are
    added and scaled by the per-period standard deviation over the square root
    of the observation count: `(Z^-1(1 - alpha / 2) + Z^-1(power)) * sd /
    sqrt(n_obs)`.  A mean below the result sits too close to zero to be told
    apart from it at that confidence and power.

    With `t_crit`, that value takes the place of the two-sided critical value
    and `alpha` plays no part: the result is `(t_crit + Z^-1(power)) * sd /
    sqrt(n_obs)`, the mean excess a sample needs for its Newey-West t to clear
    the bar `t_crit` at that power.  The `sd` is then expected to be the
    long-run sd, the square root of the Newey-West S.

    A count below 1, a negative standard deviation, a `t_crit` that is not a
    number above 0, or an `alpha` or `power` outside (0, 1) raises ValueError; a
    standard deviation of 0 gives 0.0.
    """
    observations = _whole(n_obs, "n_obs", minimum=1)
    spread = _number(sd, "sd")
    if spread < 0:
        raise ValueError(f"sd must not be negative: {sd!r}")
    significance = _number(alpha, "alpha")
    if not 0.0 < significance < 1.0:
        raise ValueError(f"alpha must be inside (0, 1): {alpha!r}")
    reach = _number(power, "power")
    if not 0.0 < reach < 1.0:
        raise ValueError(f"power must be inside (0, 1): {power!r}")
    if t_crit is None:
        critical = _quantile(1.0 - significance / 2.0) + _quantile(reach)
    else:
        bar = _number(t_crit, "t_crit")
        if bar <= 0.0:
            raise ValueError(f"t_crit must be greater than 0: {t_crit!r}")
        critical = bar + _quantile(reach)
    return critical * spread / math.sqrt(observations)


# ---------------------------------------------------------------- trial counting


@dataclass(frozen=True)
class TrialStats:
    """How many configs a project has spent on an asset's class, and spread.

    `n_trials` is the multiple-comparisons count, `n_with_sharpe` how many of
    those configs carry an excess Sharpe, `var_trials_sr` the sample variance
    of those values (None when fewer than two carry one) and `scope` a sentence
    naming exactly which rows were counted.
    """

    n_trials: int
    var_trials_sr: Optional[float]
    n_with_sharpe: int
    scope: str


def _sharpe_values(rows: list[TrialRow]) -> list[float]:
    """The excess Sharpes the rows carry, in row order, leaving the gaps out."""
    return [row.excess_sharpe for row in rows if row.excess_sharpe is not None]


def _latest_trials(rows: list[TrialRow]) -> list[TrialRow]:
    """One row per trial: the last one recorded for its own key.

    A trial's key is its asset, its rule and its canonical params, and the rows
    arrive in id order, so a later row overwrites the one before it under the
    same key.  A re-run on updated data lands on the same key and replaces the
    Sharpe read for it, while a different walk setting is a different key
    because the settings are stored beside the rule's own params.
    """
    latest: dict[tuple[str, str, str], TrialRow] = {}
    for row in rows:
        key = (
            row.asset,
            row.rule_id,
            json.dumps(row.params, sort_keys=True, separators=(",", ":")),
        )
        latest[key] = row
    return list(latest.values())


# All the stocks of a project are counted together, the way its crypto pairs
# are: a search over several names is one search, so the looks spent across them
# add up rather than each name standing as a test of its own.
def trial_stats(
    store: LabStore, project_id: str, interval: str, asset: str
) -> TrialStats:
    """The trials a project has spent on one asset's class at one interval.

    A symbol carrying a "-" is a crypto pair.  Both classes are read the same
    way: a crypto read counts every crypto asset in the project at that
    interval and a stock read every stock asset, and every rule counts, because
    a search across several names is one search.  Another project's runs never
    count.

    A trial is one (asset, rule, params) key, so only the newest row of each key
    is read: a re-run of a config on updated data replaces that config's Sharpe
    rather than adding a trial, and a different walk setting is a different key
    because `evaluate_edge_rule` stores the settings with the params.  A latest
    row recorded without an excess Sharpe still counts as a trial, since the
    search spent a look on it, but it carries no value for the variance.  The
    variance is the sample variance (n - 1) of the values that are there, and
    None when fewer than two trials carry one.  `scope` spells out which rows
    the count covers.
    """
    if not isinstance(asset, str) or not asset:
        raise ValueError(f"asset must be a non-empty string: {asset!r}")
    crypto = "-" in asset
    rows = store.trials(project_id, interval, "crypto" if crypto else "stock")
    latest = _latest_trials(rows)
    sharpes = _sharpe_values(latest)
    if crypto:
        scope = (
            f"N counts configs across all crypto assets in project "
            f"{project_id!r} at interval {interval!r}"
        )
    else:
        scope = (
            f"N counts configs across all stock assets in project "
            f"{project_id!r} at interval {interval!r}"
        )
    return TrialStats(
        n_trials=len(latest),
        var_trials_sr=statistics.variance(sharpes) if len(sharpes) >= 2 else None,
        n_with_sharpe=len(sharpes),
        scope=scope,
    )


# ================================================================ procedure half
#
# Everything above reads numbers; everything below produces them.  A rule module
# is any object carrying RULE_ID, HYPOTHESIS, GRID, ASSETS, an
# INITIAL_BASE_FRACTION, a `make(params)` that builds its decide callable and,
# for the grid simulator, an `initial_grid(params, history)` whose `history`
# is a read-only window over the segment running up to and including the
# slice's own first bar, the bar whose close the ladder is built from.  The walk
# forward runs a rule over contiguous windows of one data segment, joins the
# test slices into one continuous out-of-sample run and reports the benchmarks
# over the very same bars; the verdict reads those numbers against fixed bars.

# An out-of-sample winner that the block splits do not call a lucky pick, a
# Sharpe that survives the search that produced it, and a mean that sits clearly
# above zero once serial correlation is allowed for.
PBO_MAX = 0.05
DSR_MIN = 0.95
NW_T_MIN = 3.0

# The simulators a walk forward can drive, by name.
SIMULATORS = ("market", "grid")

# The longest step between two crypto daily bars that is still one continuous run.
CRYPTO_MAX_GAP = timedelta(days=1)


class InsufficientData(ValueError):
    """No stretch of bars is long enough to hold one train and test window."""


# ---------------------------------------------------------------- procedure helpers


def _money(value: object, name: str) -> D:
    """A Decimal from a Decimal, str or int; a float is refused."""
    if isinstance(value, D):
        return value
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(
            f"{name} must be a Decimal, not {type(value).__name__}: {value!r}"
        )
    try:
        return D(str(value))
    except Exception as exc:  # noqa: BLE001 - re-raised with the field name
        raise ValueError(f"{name} is not a decimal value: {value!r}") from exc


def _jsonable(value: object) -> object:
    """The same value as plain JSON types: Decimals as text, datetimes as ISO text."""
    if isinstance(value, D):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value


def _start_orders(rule_module, start_cash: D) -> tuple:
    """The orders that put the rule's first share of the cash into the asset once.

    `INITIAL_BASE_FRACTION` is the share of the starting cash the rule holds at
    its first open, so a run always starts in cash and buys in at bar 0's open
    as a taker.  A fraction of 0 orders nothing.
    """
    raw = getattr(rule_module, "INITIAL_BASE_FRACTION", D("0"))
    fraction = _money(raw, "INITIAL_BASE_FRACTION")
    if fraction < 0 or fraction > 1:
        raise ValueError(
            f"INITIAL_BASE_FRACTION must sit within [0, 1]: {raw!r}"
        )
    if fraction <= 0:
        return ()
    return (Order(BUY, notional=start_cash * fraction),)


def _visible(decide, seg: list, slice_start: int):
    """The decide a run over `seg[slice_start:...]` is handed, with a longer lookback.

    The run itself is given only its own slice of the segment, so the context it
    builds holds that slice's bars.  The wrapper swaps in a window over the whole
    segment that still stops at the bar the run has reached, which lets a rule
    read the warm-up bars before its slice and never a later bar.
    """

    def bounded(ctx):
        return decide(
            replace(ctx, bars=PastBars(seg, slice_start + len(ctx.bars)))
        )

    return bounded


def _window_delegate(deciders: list, oos_start: int, test: int):
    """The decide a joined out-of-sample run is handed for a list of deciders.

    The run's context counts bars from the start of its own slice, so the
    position is a segment index once the offset is known: window k owns
    out-of-sample bars `k * test .. k * test + test - 1`, i.e. the positions
    from `oos_start + k * test`.  A position before the first test slice or past
    the last one is clamped onto the nearest window.  The rule's own run and a
    null schedule's run are therefore answered with the same window selection
    and differ only in the deciders.
    """

    def delegate(ctx):
        position = len(ctx.bars) - 1
        which = (position - oos_start) // test
        if which < 0:
            which = 0
        elif which >= len(deciders):
            which = len(deciders) - 1
        return deciders[which](ctx)

    return delegate


def _simulate_slice(
    seg: list,
    events: list,
    decide,
    slice_start: int,
    slice_len: int,
    sim: str,
    grid_params: Optional[dict],
    start_cash: D,
    costs: CostModel,
    initial_orders: tuple,
    contribution=None,
):
    """One run over `seg[slice_start:slice_start + slice_len]` from cash.

    *contribution* is the rule's own funding schedule, handed to the market
    simulator as it stands and ignored by the grid simulator, which does not
    carry one.
    """
    rows = seg[slice_start : slice_start + slice_len]
    if sim == "market":
        return simulate(
            rows,
            events,
            decide,
            start_cash,
            D("0"),
            costs,
            initial_orders=initial_orders,
            contribution=contribution,
        )
    return simulate_grid(
        rows,
        events,
        decide,
        grid_params,
        start_cash,
        D("0"),
        costs,
        initial_orders=initial_orders,
    )


# ---------------------------------------------------------------- data helpers


def bars_hash(bars: list[Bar]) -> str:
    """A sha256 over a canonical text of every bar's fields.

    The text carries the symbol, the interval, the open stamp, the four prices
    and the volume of each bar in the order given, with prices in their plain
    fixed-point form.  The same bars therefore always hash the same, and a change
    to any field of any bar hashes differently.
    """
    lines: list[str] = []
    for index, bar in enumerate(bars):
        if not isinstance(bar, Bar):
            raise ValueError(
                f"bars[{index}] is not a Bar: {type(bar).__name__}"
            )
        lines.append(
            "|".join(
                (
                    bar.symbol,
                    bar.interval,
                    bar.ts.isoformat(),
                    format(bar.open, "f"),
                    format(bar.high, "f"),
                    format(bar.low, "f"),
                    format(bar.close, "f"),
                    format(bar.volume, "f"),
                )
            )
        )
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def data_segments(bars: list[Bar], costs: CostModel) -> list[tuple[int, int]]:
    """The contiguous stretches of an ascending bar list, as half-open ranges.

    A break falls between two bars whose stamps are further apart than the data
    may skip: more than one day for a crypto pair, more than the weekend a stock
    calendar may close over for a single name.  An empty list has no segments.
    """
    rows = list(bars)
    if not rows:
        return []
    limit = (
        CRYPTO_MAX_GAP
        if costs.asset_class == "crypto"
        else STOCK_MAX_GAP
    )
    segments: list[tuple[int, int]] = []
    start = 0
    for index in range(1, len(rows)):
        if rows[index].ts - rows[index - 1].ts > limit:
            segments.append((start, index))
            start = index
    segments.append((start, len(rows)))
    return segments


# ---------------------------------------------------------------- walk forward


@dataclass(frozen=True)
class WindowChoice:
    """One window and the config it selected on its train slice.

    The four slice bounds are indices into the segment in use, with the end
    exclusive.  `config_index` is the winner's position in the rule's GRID,
    `params` its config, and `train_sharpe` the per-period Sharpe that won the
    selection (for a rule with a null schedule, the Sharpe of the winner's excess
    over its own null schedule on that slice; a curve with no spread ranks as
    0.0).
    """

    index: int
    train_start: int
    train_end: int
    test_start: int
    test_end: int
    config_index: int
    params: dict
    train_sharpe: Optional[float]


@dataclass
class OOSResult:
    """Everything one walk forward produced.

    `segment_start` is the index in the bars handed in of the first bar of the
    data segment the walk forward read, before the oldest bars that fill no
    window are dropped, and `segment_start_ts` is the stamp of the first bar
    actually used.  `oos` is the single joined out-of-sample run, `benchmarks`
    the 50/50 and buy-and-hold runs over exactly the same bars (and, for a rule
    with a null schedule, the `no_veto` run beside them).  `pass_benchmark`
    names the benchmark the rule is judged against, "fifty_fifty" for a rule
    with no null schedule and "no_veto" for one that has it, and `oos_excess`
    is the rule's period returns minus that benchmark's.  `pbo_matrix` is one
    row per period of the segment and one column per config, and
    `config_excess_sharpes` each config's Sharpe over its excess against the
    pass benchmark across the whole segment: the 50/50 run, or for a rule with a
    null schedule that config's own schedule with the veto switched off.
    `notes` names anything the numbers leave unsaid, such as earlier bars a data
    gap puts out of reach or the oldest bars that fill no window.
    """

    segment_start: int
    segment_start_ts: datetime
    windows: list
    oos: SimResult
    benchmarks: dict
    oos_excess: list
    pbo_matrix: list
    config_excess_sharpes: list
    notes: list
    pass_benchmark: str = "fifty_fifty"


def walk_forward_oos(
    rule_module,
    bars: list[Bar],
    events: list[Event],
    costs: CostModel,
    train_len: int,
    test_len: int,
    step: int,
    sim: str,
    *,
    start_cash: D = D("10000"),
) -> OOSResult:
    """Select a config on each train slice and run it over the next test slice.

    The bar list is split into contiguous segments at every data gap, and the
    last segment long enough for one train slice plus one test slice is the one
    used; nothing straddles a gap.  With `train`, `test` and a stride equal to
    `test`, the segment gives `K = (len - train) // test` windows: window k trains
    on `seg[k * test : k * test + train]` and tests on the `test` bars after it.
    The windows are anchored at the segment's newest bar, so the oldest bars that
    do not fill a window are not used and the last bar of the segment is the last
    bar of the last test slice.

    Each config is run over the train slice from cash, with the rule's initial
    buy, and the config with the highest per-period Sharpe of that run is chosen
    (a curve with no spread counts as 0.0, and the lowest index wins a tie).
    A rule carrying a null schedule is chosen on an excess instead: each config's
    run is measured against the same config's null schedule over the same train
    slice, from the same initial orders, costs and events and through the same
    visibility wrapper, and the config whose excess carries the highest
    per-period Sharpe wins.  A config that only repeats its own benchmark
    therefore earns nothing on the selection.
    For the grid simulator a run's ladder comes from `initial_grid` handed the
    segment up to and including that slice's first bar, so a rule can read that
    bar's close and every earlier one and never a later bar.

    The test slices are then joined into ONE continuous run in which every
    window's own decide answers for its own bars, so cash, the holding, the tax
    lots and the loss carry-forward cross window boundaries while only the
    delegate changes.  The joined run's ladder is built the same way, once, and
    is not rebuilt at a boundary.

    The 50/50 and buy-and-hold benchmarks run over exactly the joined test bars,
    and every config is also run once over the whole segment so the block-split
    matrix and each config's excess Sharpe against the pass benchmark can be
    reported.

    A rule module carrying a callable `null_params(params)` has a null schedule:
    the same config with whatever makes its own answer special switched off.
    Such a rule is judged against that schedule rather than against a half in
    cash, because the counterfactual it has to beat is its own buy plan without
    the switch.  The null schedule's deciders are `make(null_params(params))` of
    each window's chosen config, the joined run is repeated over them with the
    same starting cash, the same initial orders and the same costs, and that run
    is `benchmarks["no_veto"]`; `pass_benchmark` is then "no_veto", `oos_excess`
    is read against it, and each config's own excess Sharpe is taken against a
    whole-segment run of its own null schedule.  The train-slice selection reads
    an excess the same way, on the train slice alone, so the config that decides
    a window is the one whose own excess over its null schedule did best there.
    The 50/50 benchmark is still
    run and reported beside it.  A rule without `null_params` keeps the 50/50 as
    its pass benchmark and its absolute train-slice Sharpe as the selection.

    A rule carrying a `FUNDING` schedule is a funded rule: every run of it and of
    its null schedule is handed that fixed weekly contribution, and their
    returns are read net of the money contributed, so the contribution is not
    mistaken for a gain.  The 50/50 and buy-and-hold benchmarks are funded by
    the same schedule over the same bars, each deposit spent at the open after
    it lands, so the context a funded rule is read beside is a funded
    comparison too.  A funded rule may start from no cash, but not from more
    than one weekly amount.  The grid simulator does not carry a contribution,
    so a funded rule asked for there is refused.

    The simulator pays a deposit on the first bar of a slice even when that bar
    falls in the middle of a week, while the rule reads the bars before its
    slice as well and so does not count that bar as a week start.  A train or
    test slice that starts mid-week therefore leaves one deposit idle in cash,
    the same one in the rule's run and in its no-veto benchmark, so the two are
    still read against each other over the same schedule.

    Events are passed to every run unchanged.  A shape the procedure cannot run
    (an unknown simulator, a stride other than the test length, slices shorter
    than two bars, an empty grid, a grid run without `initial_grid`, a grid run
    of a rule with a null schedule or with a `FUNDING` schedule, a starting cash
    that is not positive for an unfunded rule, a starting cash below 0 or above
    one weekly amount for a funded rule) raises ValueError; data too short for
    one window raises InsufficientData.
    """
    if sim not in SIMULATORS:
        raise ValueError(f"sim must be one of {list(SIMULATORS)}, not {sim!r}")
    train = _whole(train_len, "train_len", minimum=2)
    test = _whole(test_len, "test_len", minimum=2)
    stride = _whole(step, "step")
    if stride != test:
        raise ValueError(
            f"step must equal test_len ({test}), not {stride}: the test slices "
            f"have to be contiguous so the joined out-of-sample run is one "
            f"continuous simulation"
        )
    funding = getattr(rule_module, "FUNDING", None)
    amount: Optional[D] = None
    if funding is not None:
        raw_amount = (
            funding.get("amount") if isinstance(funding, dict) else None
        )
        if raw_amount is None:
            raise ValueError(
                f"FUNDING must carry a weekly 'amount': {funding!r}"
            )
        amount = _money(raw_amount, "FUNDING['amount']")
    grid = list(getattr(rule_module, "GRID", ()) or ())
    if not grid:
        raise ValueError(
            "GRID is empty: a walk forward needs at least one config to choose "
            "between"
        )
    if sim == "grid" and not callable(getattr(rule_module, "initial_grid", None)):
        raise ValueError(
            f"sim 'grid' needs the rule's initial_grid, which rule "
            f"{getattr(rule_module, 'RULE_ID', '?')!r} does not carry"
        )
    null_of = getattr(rule_module, "null_params", None)
    if not callable(null_of):
        null_of = None
    if null_of is not None and sim == "grid":
        raise ValueError(
            f"sim 'grid' cannot run the null schedule of rule "
            f"{getattr(rule_module, 'RULE_ID', '?')!r}: null_params builds a "
            f"market schedule, so the same schedule with the switch off cannot "
            f"be run as this rule's pass benchmark"
        )
    if funding is not None and sim == "grid":
        raise ValueError(
            f"sim 'grid' cannot run rule "
            f"{getattr(rule_module, 'RULE_ID', '?')!r}: its FUNDING {funding!r} "
            f"spends a fixed weekly contribution, and the grid simulator does "
            f"not carry one"
        )
    # A rule run from cash needs a positive start; a funded rule may start from
    # nothing at all, but not from more than one weekly amount of idle cash.
    cash = _money(start_cash, "start_cash")
    if funding is None:
        if cash <= 0:
            raise ValueError(f"start_cash must be positive: {start_cash!r}")
    else:
        if cash < 0:
            raise ValueError(
                f"start_cash must not be negative: {start_cash!r}"
            )
        if cash > amount:
            raise ValueError(
                f"a funded rule starts with at most one weekly amount "
                f"({amount}) of cash: {cash}"
            )

    rows = list(bars)
    segments = data_segments(rows, costs)
    needed = train + test
    chosen: Optional[tuple[int, int]] = None
    for start, end in reversed(segments):
        if end - start >= needed:
            chosen = (start, end)
            break
    if chosen is None:
        longest = max((end - start for start, end in segments), default=0)
        raise InsufficientData(
            f"no stretch of bars holds the {needed} bars a {train}-bar train and "
            f"{test}-bar test window needs; the longest holds {longest}"
        )
    segment_start, segment_end = chosen
    seg = rows[segment_start:segment_end]
    notes: list[str] = []
    if segment_start > 0:
        notes.append(
            f"bars before {seg[0].ts.isoformat()} are not used: a data gap "
            f"separates them"
        )

    initial = _start_orders(rule_module, cash)
    count = (len(seg) - train) // test
    # The windows are anchored at the newest bar: the bars a whole number of
    # windows does not reach are the oldest ones, so they are dropped and the
    # segment's last bar stays the last bar of the last test slice.
    used = train + count * test
    dropped = len(seg) - used
    if dropped > 0:
        seg = seg[dropped:]
        notes.append(
            f"the {dropped} oldest bars of the segment fill no window and are "
            f"not used"
        )
    windows: list[WindowChoice] = []
    for index in range(count):
        train_start = index * test
        train_end = train_start + train
        test_start = train + index * test
        test_end = test_start + test
        best_index = 0
        best_value: Optional[float] = None
        for config_index, params in enumerate(grid):
            grid_params = (
                rule_module.initial_grid(
                    params, PastBars(seg, train_start + 1)
                )
                if sim == "grid"
                else None
            )
            run = _simulate_slice(
                seg,
                events,
                _visible(rule_module.make(params), seg, train_start),
                train_start,
                train,
                sim,
                grid_params,
                cash,
                costs,
                initial,
                funding,
            )
            train_returns = period_returns(run.curve, run.contributions)
            if null_of is not None:
                # The same config's null schedule over the very same train
                # slice, from the same initial orders and costs, so only the
                # switch itself separates the two runs.
                null_run = _simulate_slice(
                    seg,
                    events,
                    _visible(
                        rule_module.make(null_of(params)), seg, train_start
                    ),
                    train_start,
                    train,
                    sim,
                    grid_params,
                    cash,
                    costs,
                    initial,
                    funding,
                )
                train_returns = [
                    left - right
                    for left, right in zip(
                        train_returns,
                        period_returns(
                            null_run.curve, null_run.contributions
                        ),
                    )
                ]
            ratio = sharpe(train_returns)
            value = 0.0 if ratio is None else ratio
            if best_value is None or value > best_value:
                best_index, best_value = config_index, value
        windows.append(
            WindowChoice(
                index=index,
                train_start=train_start,
                train_end=train_end,
                test_start=test_start,
                test_end=test_end,
                config_index=best_index,
                params=grid[best_index],
                train_sharpe=best_value,
            )
        )

    oos_start = train
    oos_len = count * test
    oos_rows = seg[oos_start : oos_start + oos_len]
    deciders = [rule_module.make(choice.params) for choice in windows]

    def joined_run(chosen: list):
        """The joined run, answered window by window by `chosen`."""
        oos_decide = _visible(
            _window_delegate(chosen, oos_start, test), seg, oos_start
        )
        if sim == "market":
            return simulate(
                oos_rows,
                events,
                oos_decide,
                cash,
                D("0"),
                costs,
                initial_orders=initial,
                contribution=funding,
            )
        oos_grid = rule_module.initial_grid(
            windows[0].params, PastBars(seg, oos_start + 1)
        )
        return simulate_grid(
            oos_rows,
            events,
            oos_decide,
            oos_grid,
            cash,
            D("0"),
            costs,
            initial_orders=initial,
        )

    oos_run = joined_run(deciders)

    benchmarks = {
        "fifty_fifty": fifty_fifty(
            oos_rows, events, cash, costs, contribution=funding
        ),
        "buy_and_hold": buy_and_hold(
            oos_rows, events, cash, costs, contribution=funding
        ),
    }
    if null_of is not None:
        # The same joined run over the same bars, with each window's own config
        # built from its null params, so only the veto itself is switched off.
        null_deciders = [
            rule_module.make(null_of(choice.params)) for choice in windows
        ]
        benchmarks["no_veto"] = joined_run(null_deciders)
    pass_benchmark = "no_veto" if null_of is not None else "fifty_fifty"

    rule_returns = period_returns(oos_run.curve, oos_run.contributions)
    pass_run = benchmarks[pass_benchmark]
    bench_returns = period_returns(
        pass_run.curve, getattr(pass_run, "contributions", None)
    )
    oos_excess = [
        left - right for left, right in zip(rule_returns, bench_returns)
    ]

    columns: list[list[float]] = []
    null_columns: list[list[float]] = []
    for params in grid:
        grid_params = (
            rule_module.initial_grid(params, PastBars(seg, 1))
            if sim == "grid"
            else None
        )
        run = _simulate_slice(
            seg,
            events,
            _visible(rule_module.make(params), seg, 0),
            0,
            len(seg),
            sim,
            grid_params,
            cash,
            costs,
            initial,
            funding,
        )
        columns.append(period_returns(run.curve, run.contributions))
        if null_of is not None:
            null_run = _simulate_slice(
                seg,
                events,
                _visible(rule_module.make(null_of(params)), seg, 0),
                0,
                len(seg),
                sim,
                grid_params,
                cash,
                costs,
                initial,
                funding,
            )
            null_columns.append(
                period_returns(null_run.curve, null_run.contributions)
            )
    periods = len(seg) - 1
    pbo_matrix = [
        [column[row] for column in columns] for row in range(periods)
    ]
    if null_of is not None:
        config_excess_sharpes = [
            sharpe(
                [left - right for left, right in zip(column, null_column)]
            )
            for column, null_column in zip(columns, null_columns)
        ]
    else:
        bench_run = fifty_fifty(
            seg, events, cash, costs, contribution=funding
        )
        bench_full = period_returns(bench_run.curve, bench_run.contributions)
        config_excess_sharpes = [
            sharpe([left - right for left, right in zip(column, bench_full)])
            for column in columns
        ]

    return OOSResult(
        segment_start=segment_start,
        segment_start_ts=seg[0].ts,
        windows=windows,
        oos=oos_run,
        benchmarks=benchmarks,
        oos_excess=oos_excess,
        pbo_matrix=pbo_matrix,
        config_excess_sharpes=config_excess_sharpes,
        notes=notes,
        pass_benchmark=pass_benchmark,
    )


# ---------------------------------------------------------------- verdict


@dataclass(frozen=True)
class Verdict:
    """A rule's verdict: its status, the reasons for it and the numbers behind it.

    `status` is "pass", "fail" or "not_enough_data".  `reasons` opens with the
    line that says why a "not_enough_data" verdict is not a pass, then carries
    one line for every condition that failed or could not be computed, then one
    `note:` line per note and one `warning:` line per PBO warning, then the
    trial counting scope sentence and, when the data supports one, the smallest
    edge it could detect.  `numbers` holds the same values in JSON-friendly
    types.
    """

    status: str
    reasons: list[str]
    numbers: dict


def verdict_from_numbers(
    *,
    rule_return,
    bench_return,
    rule_drawdown,
    bench_drawdown,
    pbo,
    dsr,
    nw_t,
    mde,
    scope,
    pbo_warnings=(),
    extra=None,
    mean_excess=None,
    notes=(),
    bench_label: str = "50/50 benchmark",
    funded: bool = False,
) -> Verdict:
    """Weigh one rule's out-of-sample numbers against the pass bars.

    Five conditions decide the status, each on its own, and each is tracked
    under its own name: the rule's after-tax return must be strictly above the
    pass benchmark's, its drawdown no deeper than that benchmark's, its
    block-split overfit share at or below `PBO_MAX`, its deflated Sharpe at or
    above `DSR_MIN`, and the Newey-West t of its mean excess return strictly
    above `NW_T_MIN`.  `bench_label` is how the two benchmark lines name that
    benchmark, the 50/50 run by default.  A condition whose input is None is not
    computable; one that is computed and misses adds a line saying what it was
    and the bar it missed, and passing conditions add nothing.

    `funded` says the rule was funded by a weekly contribution, so its return is
    the gain on the money paid in rather than the growth of a starting balance:
    the return line is worded that way and the numbers carry the flag.  A rule
    read from its starting cash alone keeps the wording it has always had.

    Two shapes of thin sample are not called a failure.  When `nw_t` is at or
    below `NW_T_MIN`, `mde` is given and the mean excess return per period
    `mean_excess` sits inside it — `abs(mean_excess) < mde` — the sample could
    not have resolved an edge of that size, so the status is
    "not_enough_data" whatever else missed.  When the only condition that
    missed is the block-split share, the status is "not_enough_data" too, and
    the verdict opens with a line naming that share and saying the in-sample
    winner is often a poor pick out of sample, so the data cannot rank the
    configs.

    Otherwise the status is "fail" when any condition failed, else
    "not_enough_data" when any could not be computed, else "pass".  A
    "not_enough_data" verdict opens with a line saying so before the condition
    lines, then one `note:` line per item of `notes` and one `warning:` line
    per item of `pbo_warnings`.  Every verdict closes with the trial counting
    scope sentence and, when `mde` is given, the smallest mean excess return per
    period the sample could detect at 80% power against the Newey-West t bar.
    `extra` is merged into the numbers, which come back with Decimals as text
    and everything else as a plain number, string or list.
    """
    outcome: list[tuple[str, Optional[bool], str]] = []

    if rule_return is None or bench_return is None:
        outcome.append(("return", None, "return: not computable"))
    elif rule_return > bench_return:
        outcome.append(("return", True, ""))
    elif funded:
        outcome.append(
            (
                "return",
                False,
                f"return: the rule's gain on money contributed is "
                f"{rule_return}, which is not above the {bench_label}'s "
                f"{bench_return}, so it does not beat the pass benchmark on "
                f"gain",
            )
        )
    else:
        outcome.append(
            (
                "return",
                False,
                f"return: the rule ends at {rule_return}, which is not above "
                f"the {bench_label}'s {bench_return}, so it does not beat the "
                f"pass benchmark on return",
            )
        )

    if rule_drawdown is None or bench_drawdown is None:
        outcome.append(("drawdown", None, "drawdown: not computable"))
    elif rule_drawdown <= bench_drawdown:
        outcome.append(("drawdown", True, ""))
    else:
        outcome.append(
            (
                "drawdown",
                False,
                f"drawdown: the rule falls {rule_drawdown} from its peak, "
                f"deeper than the {bench_label}'s {bench_drawdown}",
            )
        )

    if pbo is None:
        outcome.append(("pbo", None, "pbo: not computable"))
    elif pbo <= PBO_MAX:
        outcome.append(("pbo", True, ""))
    else:
        outcome.append(
            (
                "pbo",
                False,
                f"pbo: the in-sample winner lands at or below the middle out of "
                f"sample in {pbo} of the block splits, above the limit of "
                f"{PBO_MAX}",
            )
        )

    if dsr is None:
        outcome.append(("dsr", None, "dsr: not computable"))
    elif dsr >= DSR_MIN:
        outcome.append(("dsr", True, ""))
    else:
        outcome.append(
            (
                "dsr",
                False,
                f"dsr: the deflated Sharpe is {dsr}, below the minimum of "
                f"{DSR_MIN}",
            )
        )

    if nw_t is None:
        outcome.append(("nw_t", None, "nw_t: not computable"))
    elif nw_t > NW_T_MIN:
        outcome.append(("nw_t", True, ""))
    else:
        outcome.append(
            (
                "nw_t",
                False,
                f"nw_t: the Newey-West t of the mean excess return is {nw_t}, "
                f"which is not above {NW_T_MIN}",
            )
        )

    failed = [name for name, passed, _ in outcome if passed is False]
    missing = any(passed is None for _, passed, _ in outcome)
    underpowered = (
        nw_t is not None
        and nw_t <= NW_T_MIN
        and mde is not None
        and mean_excess is not None
        and abs(mean_excess) < mde
    )
    lines = [text for _, passed, text in outcome if passed is not True]
    opening: Optional[str] = None
    if underpowered:
        status = "not_enough_data"
        opening = (
            f"not enough data to tell: the mean excess return per period "
            f"({mean_excess}) is smaller than the smallest edge this sample "
            f"could detect ({mde}), so it cannot be told apart from zero"
        )
    elif failed == ["pbo"]:
        status = "not_enough_data"
        opening = (
            f"selection unstable (PBO = {pbo}): the in-sample winner is often "
            f"a poor pick out of sample, so this data cannot rank the configs"
        )
    elif failed:
        status = "fail"
    elif missing:
        status = "not_enough_data"
        opening = (
            "not enough data to tell: some of the numbers this verdict needs "
            "could not be computed from this data"
        )
    else:
        status = "pass"

    reasons: list[str] = []
    if opening is not None:
        reasons.append(opening)
    reasons.extend(lines)
    reasons.extend(f"note: {text}" for text in notes)
    reasons.extend(f"warning: {text}" for text in pbo_warnings)
    reasons.append(f"scope: {scope}")
    if mde is not None:
        reasons.append(
            f"mde: smallest mean excess return per period this data could "
            f"detect (80% power, Newey-West t bar {NW_T_MIN}): {mde}"
        )

    numbers: dict = {
        "rule_return": rule_return,
        "bench_return": bench_return,
        "rule_drawdown": rule_drawdown,
        "bench_drawdown": bench_drawdown,
        "pbo": pbo,
        "dsr": dsr,
        "nw_t": nw_t,
        "mde": mde,
        "mean_excess": mean_excess,
        "pbo_warnings": list(pbo_warnings),
        "funded": bool(funded),
    }
    if extra:
        numbers.update(extra)
    return Verdict(status=status, reasons=reasons, numbers=_jsonable(numbers))


# ---------------------------------------------------------------- evaluate


def _absent_numbers(sim: str) -> dict:
    """The verdict's numbers with every statistic missing, for a run that cannot start."""
    return {
        "rule_return": None,
        "bench_return": None,
        "rule_drawdown": None,
        "bench_drawdown": None,
        "pbo": None,
        "dsr": None,
        "nw_t": None,
        "mde": None,
        "pbo_warnings": [],
        "n_obs": None,
        "sd": None,
        "long_run_sd": None,
        "mean_excess": None,
        "n_windows": 0,
        "n_trials": None,
        "var_trials_sr": None,
        "buy_and_hold_return": None,
        "pass_benchmark": None,
        "fifty_fifty_return": None,
        "sim": sim,
        "segment_start_ts": None,
    }


def evaluate_edge_rule(
    store: LabStore,
    project_id: str,
    rule_module,
    bars: list[Bar],
    events: list[Event],
    costs: CostModel,
    *,
    train_len: int,
    test_len: int,
    step: int,
    sim: str,
    n_groups: int = 16,
    start_cash: D = D("10000"),
) -> Verdict:
    """Walk a registered rule forward, record its configs as trials and weigh it.

    The rule has to be registered under the project and to declare the cost
    model's asset class in its ASSETS, and there has to be at least one bar.
    The grid the module carries has to be the one the current registered
    version holds: the pre-registered grid is the design of record, so a module
    whose GRID has moved is refused before a trial is recorded, and changing
    the design is a new rule version.  Every config that carries a `floor_pct`
    is then held above the round trip: a floor at or below
    `2 * (maker + slippage)` leaves no edge behind the two fills it has to
    clear, so such a config raises ValueError before any run.

    The walk forward runs first.  Data too short for a window produces a
    "not_enough_data" verdict with every statistic missing rather than an error,
    because a short sample is an answer in itself.  Otherwise each config of the
    grid is recorded as one trial, with the walk settings stored beside the
    rule's own params so another train or test length is a trial of its own, and
    so are another starting cash and another funding; a re-run of a config on
    updated data replaces that config's Sharpe and adds no trial.  The trial
    count is then read back, and the numbers are weighed: the
    after-tax return of the run and of the pass benchmark, their drawdowns,
    the block-split overfit share, the deflated Sharpe against the project's
    trial count and Sharpe spread, the Newey-West t of the mean excess return,
    and the smallest edge the sample could detect.

    The pass benchmark is the one the walk forward names: a rule with a null
    schedule is judged against the same schedule with its switch off, and every
    other rule against the 50/50 run.  The 50/50 after-tax return is reported
    either way, and for a rule judged against its null schedule it is context
    only, which a note on the verdict says in so many words.  The buy-and-hold
    return is reported for context too and is not one of the conditions.

    The smallest edge is read off the Newey-West long-run sd of the mean excess
    return, not the plain per-period sd: it is the smallest mean excess whose
    Newey-West t would clear `NW_T_MIN` at 80% power.

    A funded rule (one carrying a `FUNDING` schedule) is reported as funded: its
    return line is read as the gain on the money contributed, and the verdict
    also carries the dollar excess of its after-tax equity over the pass
    benchmark's, the number of weekly deposits the out-of-sample run took, and
    that excess per deposit, with a note saying the per-period excess is diluted
    by the growing balance.  A rule read from its starting cash alone reports
    none of those.
    """
    rule_id = getattr(rule_module, "RULE_ID", None)
    if store.get_rule(project_id, rule_id) is None:
        raise ValueError(
            f"rule {rule_id!r} is not registered in project {project_id!r}"
        )
    if not store.grid_matches_registered(
        project_id, rule_id, getattr(rule_module, "GRID", ())
    ):
        raise ValueError(
            f"rule {rule_id!r} in project {project_id!r} has a different grid "
            f"than the one pre-registered; the registered grid stands, so run "
            f"is refused. Register a new rule version to change the design "
            f"(python -m crow_coinbase.lab register --rule {rule_id} "
            f"--new-version); trials from the old grid keep counting."
        )
    assets = tuple(getattr(rule_module, "ASSETS", ()))
    if costs.asset_class not in assets:
        raise ValueError(
            f"the {costs.asset_class} asset class of {costs.asset!r} is not in "
            f"this rule's ASSETS {assets}, so these costs do not belong to "
            f"this rule"
        )
    rows = list(bars)
    if not rows:
        raise ValueError("evaluate_edge_rule needs at least one bar")
    interval = rows[0].interval

    # A grid floor at or below the round trip cannot leave an edge behind the
    # two fills it has to clear, so the rule is refused before it runs.
    round_trip = 2 * (costs.maker + costs.slippage)
    for params in getattr(rule_module, "GRID", ()) or ():
        raw = params.get("floor_pct") if isinstance(params, dict) else None
        if raw is None:
            continue
        try:
            floor = D(str(raw))
        except Exception as exc:  # noqa: BLE001 - re-raised with the field name
            raise ValueError(
                f"config {params!r} carries a floor_pct that is not a decimal "
                f"value: {raw!r}"
            ) from exc
        if floor <= round_trip:
            raise ValueError(
                f"config {params!r} carries floor_pct {raw!r}, which is not "
                f"above the round-trip cost of {round_trip} (2 * (maker "
                f"{costs.maker} + slippage {costs.slippage})): a floor that "
                f"does not clear the round trip leaves no edge behind it"
            )

    try:
        result = walk_forward_oos(
            rule_module,
            rows,
            events,
            costs,
            train_len,
            test_len,
            step,
            sim,
            start_cash=start_cash,
        )
    except InsufficientData as exc:
        stats = trial_stats(store, project_id, interval, costs.asset)
        return Verdict(
            status="not_enough_data",
            reasons=[
                f"not enough data to tell: {exc}",
                f"scope: {stats.scope}",
            ],
            numbers=_absent_numbers(sim),
        )

    grid = list(getattr(rule_module, "GRID", ()) or ())
    funding = getattr(rule_module, "FUNDING", None)
    funded = funding is not None
    ends = dict(data_segments(rows, costs))
    segment = rows[result.segment_start : ends[result.segment_start]]
    data_hash = bars_hash(segment)
    # The walk settings ride beside the config's own params, under a reserved
    # key, so the same config walked with other settings is a trial of its own
    # and a re-run on updated data is the same trial again.  Only a funded rule
    # carries its start cash and its funding in that key, because for it another
    # start cash is another run of it.  An unfunded rule's key is the four walk
    # settings and nothing else: its start cash must not enter the key, or a
    # re-run from another start cash lands on new keys and adds trials instead of
    # replacing the ones already on file.
    walk_settings: dict[str, object] = {
        "train_len": train_len,
        "test_len": test_len,
        "n_groups": n_groups,
        "sim": sim,
    }
    if funded:
        walk_settings["start_cash"] = str(_money(start_cash, "start_cash"))
        walk_settings["funding"] = {
            "amount": str(_money(funding["amount"], "FUNDING['amount']")),
            "every": funding.get("every"),
        }
    for index, params in enumerate(grid):
        value = (
            result.config_excess_sharpes[index]
            if index < len(result.config_excess_sharpes)
            else None
        )
        store.record_run(
            project_id,
            costs.asset,
            interval,
            rule_id,
            {**params, "_walk": dict(walk_settings)},
            data_hash,
            value,
            {"excess_sharpe": value},
        )
    stats = trial_stats(store, project_id, interval, costs.asset)

    oos = result.oos
    benchmark = result.benchmarks[result.pass_benchmark]
    rule_return = after_tax_return(oos, start_cash)
    bench_return = after_tax_return(benchmark, start_cash)
    rule_drawdown = max_drawdown(
        oos.curve, getattr(oos, "contributions", None) or None
    )
    bench_drawdown = max_drawdown(
        benchmark.curve, getattr(benchmark, "contributions", None) or None
    )
    hold_return = after_tax_return(result.benchmarks["buy_and_hold"], start_cash)
    fifty_return = after_tax_return(
        result.benchmarks["fifty_fifty"], start_cash
    )

    notes = list(result.notes)
    bench_label = "50/50 benchmark"
    if result.pass_benchmark == "no_veto":
        bench_label = "same schedule with no veto"
        notes.append(
            f"the 50/50 benchmark ends at {fifty_return}; shown for context "
            f"only, this rule is judged against the same schedule with no veto"
        )

    excess_dollars = None
    n_deposits = 0
    per_deposit = None
    if funded:
        excess_dollars = (
            oos.final_equity_after_liquidation_tax
            - benchmark.final_equity_after_liquidation_tax
        )
        n_deposits = len(oos.contributions)
        per_deposit = excess_dollars / n_deposits if n_deposits else None
        if per_deposit is not None:
            notes.append(
                f"excess dollars per weekly deposit is {per_deposit}; the "
                f"per-period excess is diluted by the growing balance, so "
                f"mean_excess understates the dollar edge"
            )

    overfit = pbo_cscv(result.pbo_matrix, n_groups)
    pbo = None if overfit is None else overfit.pbo
    pbo_warnings = () if overfit is None else overfit.warnings

    excess = list(result.oos_excess)
    n_obs = len(excess)
    sd = statistics.stdev(excess) if n_obs >= 2 else None
    mean_excess = math.fsum(excess) / n_obs if n_obs else None
    long_run = newey_west_long_run_variance(excess)
    long_run_sd = math.sqrt(long_run) if long_run is not None else None
    ratio = sharpe(excess)
    moments = skew_kurtosis(excess)
    dsr = None
    if (
        ratio is not None
        and moments is not None
        and stats.var_trials_sr is not None
    ):
        dsr = deflated_sharpe(
            ratio,
            n_obs,
            moments[0],
            moments[1],
            stats.n_trials,
            stats.var_trials_sr,
        )
    nw_t = newey_west_t(excess)
    mde = None
    if n_obs >= 2 and long_run_sd is not None and long_run_sd > 0:
        mde = min_detectable_edge(n_obs, long_run_sd, t_crit=NW_T_MIN)

    extra = {
        "n_obs": n_obs,
        "sd": sd,
        "long_run_sd": long_run_sd,
        "mean_excess": mean_excess,
        "n_windows": len(result.windows),
        "n_trials": stats.n_trials,
        "var_trials_sr": stats.var_trials_sr,
        "buy_and_hold_return": hold_return,
        "pass_benchmark": result.pass_benchmark,
        "fifty_fifty_return": fifty_return,
        "sim": sim,
        "segment_start_ts": result.segment_start_ts,
    }
    if funded:
        extra["excess_dollars"] = excess_dollars
        extra["n_deposits"] = n_deposits
        extra["excess_dollars_per_deposit"] = per_deposit

    return verdict_from_numbers(
        rule_return=rule_return,
        bench_return=bench_return,
        rule_drawdown=rule_drawdown,
        bench_drawdown=bench_drawdown,
        pbo=pbo,
        dsr=dsr,
        nw_t=nw_t,
        mde=mde,
        scope=stats.scope,
        pbo_warnings=pbo_warnings,
        mean_excess=mean_excess,
        notes=notes,
        bench_label=bench_label,
        funded=funded,
        extra=extra,
    )
