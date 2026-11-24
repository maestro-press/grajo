"""lab/validate.py: PBO, deflated Sharpe, Newey-West t and trial counting."""

import math
import random
import statistics
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D
from types import SimpleNamespace

import pytest

from crow_coinbase.lab import metrics
from crow_coinbase.lab.costs import SELL, CostModel, Order
from crow_coinbase.lab.gridsim import GridResult
from crow_coinbase.lab.sim import Gates
from crow_coinbase.lab.store import Bar
from crow_coinbase.lab.store import LabStore
from crow_coinbase.lab.validate import (
    PBOResult,
    TrialStats,
    deflated_sharpe,
    default_nw_lags,
    expected_max_sharpe,
    min_detectable_edge,
    newey_west_t,
    pbo_cscv,
    skew_kurtosis,
    trial_stats,
)

from crow_coinbase.lab.validate import (
    InsufficientData,
    bars_hash,
    data_segments,
    evaluate_edge_rule,
    verdict_from_numbers,
    walk_forward_oos,
)


PROJECT = "p"
OTHER_PROJECT = "q"
DATA_HASH = "h1"


# ---------------------------------------------------------------- helpers


def matrix_from_columns(columns):
    """A returns matrix of periods by configs, built from per-config lists."""
    return [[column[row] for column in columns] for row in range(len(columns[0]))]


def plain_matrix(n_configs, n_rows=8):
    """A boring matrix (values in -0.01, 0, 0.01) of n_rows periods by n_configs."""
    return [
        [0.01 * ((row + config) % 3) - 0.01 for config in range(n_configs)]
        for row in range(n_rows)
    ]


@pytest.fixture
def store(tmp_path):
    s = LabStore(tmp_path / "lab.db")
    yield s
    s.close()


# ---------------------------------------------------------------- PBO / CSCV

# One column per config, one entry per period (oldest first).  Periods 2b and
# 2b+1 make up block b, so config 0 is strong in blocks 0 and 1 and weak in
# blocks 2 and 3, config 1 the other way round, and configs 2 and 3 carry the
# same pattern in every block.
PBO_COLUMNS = [
    [0.06, 0.04, 0.06, 0.04, -0.04, -0.06, -0.04, -0.06],
    [-0.04, -0.06, -0.04, -0.06, 0.06, 0.04, 0.06, 0.04],
    [0.02, 0.0] * 4,
    [0.01, -0.01] * 4,
]


def test_pbo_hand_example():
    # Sharpe of a two-value block [a, b] is (a+b)/2 / sqrt(((a-(a+b)/2)^2 * 2)/1).
    # IS {0,1} pools blocks 0 and 1: config 0 = [.06,.04,.06,.04] has mean .05 and
    # sample sd sqrt(.0004/3) = .011547, Sharpe 4.3301 (the best of the four);
    # config 1 = -4.3301, config 2 = [.02,0,.02,0] Sharpe .8660, config 3 = 0.
    # Its OOS half (blocks 2 and 3) is config 0 = [-.04,-.06,-.04,-.06], Sharpe
    # -4.3301, the worst out of sample, so that combination counts.
    # IS {2,3} is the mirror image: config 1 best in sample, worst out of sample.
    # IS {0,2}, {0,3}, {1,2}, {1,3} each pool one good and one bad block, so
    # configs 0, 1 and 3 have mean 0 (Sharpe 0) and config 2 keeps Sharpe
    # .8660 = .01 / .011547: config 2 is best in sample AND best out of sample.
    # 6 combinations of 4 blocks taken 2 at a time (C(4,2)); 2 of them count.
    matrix = matrix_from_columns(PBO_COLUMNS)
    result = pbo_cscv(matrix, n_groups=4)

    assert isinstance(result, PBOResult)
    assert result.pbo == pytest.approx(2 / 6)
    assert result.n_combos == 6
    assert result.n_groups == 4
    assert result.n_configs == 4
    assert len(result.warnings) == 1
    assert "too few configs" in result.warnings[0]


def test_pbo_tie_counts_as_overfit():
    # Four identical config columns: every config ties on both halves, so the
    # in-sample winner is the lowest index (config 0) and it is level with all
    # four configs out of sample.  A tie for the middle rank is rank
    # (N + 1) / 2 = 2.5 of N = 4, so omega = 2.5 / 5 = 0.5, logit(0.5) = 0, and
    # the worst half counts.  In the counted form
    # 2 * lower + level + 1 = 0 + 4 + 1 = 5 <= N + 1 = 5, so every split counts:
    # C(4, 2) = 6 splits, all of them overfit, pbo = 6 / 6 = 1.0.
    col = [0.01, -0.01, 0.02, 0.0, 0.01, -0.02, 0.03, -0.01]
    result = pbo_cscv(matrix_from_columns([col] * 4), n_groups=4)

    assert result is not None
    assert result.pbo == 1.0
    assert result.n_combos == 6


def test_pbo_drops_oldest_remainder_rows():
    # 9 periods with 4 blocks: block size 9 // 4 = 2, so the oldest row is
    # dropped and rows 1..8 are exactly the 8-period matrix above.
    columns = [
        [9.0] + PBO_COLUMNS[0],
        [-9.0] + PBO_COLUMNS[1],
        [0.5] + PBO_COLUMNS[2],
        [0.0] + PBO_COLUMNS[3],
    ]
    matrix = matrix_from_columns(columns)
    assert len(matrix) == 9

    result = pbo_cscv(matrix, n_groups=4)
    assert result.pbo == pytest.approx(2 / 6)
    assert result.n_combos == 6
    assert len(result.warnings) == 1
    assert "too few configs" in result.warnings[0]


def test_pbo_planted_edge_low():
    # One config with a .02 mean on a .01 scale: its block Sharpe sits around
    # 2.0 while a noise config's sits around 0 with a spread of 1/sqrt(10) =
    # .316, so it is the in-sample best and the out-of-sample best everywhere.
    rng = random.Random(7)
    n_configs, n_rows = 10, 160
    columns = [[0.02 + rng.gauss(0.0, 0.01) for _ in range(n_rows)]]
    for _ in range(n_configs - 1):
        columns.append([rng.gauss(0.0, 0.01) for _ in range(n_rows)])

    result = pbo_cscv(matrix_from_columns(columns), n_groups=16)
    assert result is not None
    assert result.pbo == 0.0
    assert result.n_combos == 12870  # C(16, 8) = 12870
    assert result.n_groups == 16
    assert result.n_configs == 10
    assert result.warnings == ()


def test_pbo_noise_near_half():
    # Ten configs drawn from the same distribution: nothing to prefer, so the
    # in-sample winner is a coin toss out of sample and the share of splits it
    # fails sits near half.  One noise dataset is only a noisy estimate of that
    # share, because its 12870 splits are all built from the same 16 blocks and
    # so are not independent draws; the estimate taken here is the mean of the
    # share over 30 independent noise datasets, which is near half.
    n_configs, n_rows = 10, 160
    shares = []
    for seed in range(100, 130):
        rng = random.Random(seed)
        columns = [
            [rng.gauss(0.0, 0.01) for _ in range(n_rows)]
            for _ in range(n_configs)
        ]
        result = pbo_cscv(matrix_from_columns(columns), n_groups=16)
        assert result is not None
        assert result.n_combos == 12870  # C(16, 8) = 12870
        shares.append(result.pbo)

    assert len(shares) == 30
    assert 0.4 <= statistics.mean(shares) <= 0.6


def test_pbo_too_few_configs_none():
    # Below 4 configs there is nothing to rank against.
    assert pbo_cscv(plain_matrix(3), n_groups=4) is None
    # An odd block count cannot be split into halves.
    assert pbo_cscv(plain_matrix(5, 10), n_groups=5) is None
    # Fewer than 4 blocks.
    assert pbo_cscv(plain_matrix(5), n_groups=2) is None
    # 8 blocks of at least 2 rows need 16 periods.
    assert pbo_cscv(plain_matrix(5, 15), n_groups=8) is None

    # Rows of different lengths are not a matrix.
    ragged = plain_matrix(5)
    ragged[7] = ragged[7][:4]
    with pytest.raises(ValueError):
        pbo_cscv(ragged, n_groups=4)

    # 4 <= N < 10 gets one warning; N = 10 does not.
    for n_configs in range(4, 10):
        thin = pbo_cscv(plain_matrix(n_configs), n_groups=4)
        assert thin is not None
        assert len(thin.warnings) == 1
        assert "too few configs" in thin.warnings[0]
    ample = pbo_cscv(plain_matrix(10), n_groups=4)
    assert ample is not None
    assert ample.warnings == ()


# ---------------------------------------------------------------- deflated Sharpe

# A per-period Sharpe of 2.5 annualized over 250 periods, 1250 observations and
# a trials-Sharpe variance of 0.5 over 250 periods.
SR = 2.5 / math.sqrt(250)  # 0.15811388300841897
N_OBS = 1250
VAR_TRIALS_SR = 0.5 / 250  # 0.002


def test_dsr_paper_example():
    # sqrt(0.002) = 0.0447213595, 1 - euler = 0.4227843351, euler = 0.5772156649.
    # N = 100: z(.99) = 2.3263478740, z(1 - 1/(100e)) = 2.6802
    #   SR0 = 0.0447213595 * (0.4227843351*2.3263478740 + 0.5772156649*2.6802)
    #       = 0.0447213595 * 2.5305865 = 0.11317
    #   sqrt(n_obs - 1) = sqrt(1249) = 35.3411941
    #   1 - (-3)*0.1581139 + ((10-1)/4)*0.025 = 1.5305917, sqrt = 1.2371708
    #   arg = (0.1581139 - 0.1131713) * 35.3411941 / 1.2371708 = 1.28384
    #   Phi(1.28384) = 0.90040
    sr0 = expected_max_sharpe(100, VAR_TRIALS_SR)
    assert sr0 == pytest.approx(0.1132, abs=5e-5)
    dsr = deflated_sharpe(SR, N_OBS, -3.0, 10.0, 100, VAR_TRIALS_SR)
    assert dsr == pytest.approx(0.9004, abs=5e-4)

    # N = 46: z(1 - 1/46) = 2.01909, z(1 - 1/(46e)) = 2.40904
    #   SR0 = 0.0447213595 * (0.4227843351*2.01909 + 0.5772156649*2.40904)
    #       = 0.0447213595 * 2.2441738 = 0.100362
    #   arg = (0.1581139 - 0.1003625) * 35.3411941 / 1.2371708 = 1.64975
    #   Phi(1.64975) = 0.95050
    sr0 = expected_max_sharpe(46, VAR_TRIALS_SR)
    assert sr0 == pytest.approx(0.1004, abs=2e-4)
    dsr = deflated_sharpe(SR, N_OBS, -3.0, 10.0, 46, VAR_TRIALS_SR)
    assert dsr == pytest.approx(0.9505, abs=5e-4)

    # N = 88 with skew 0 and normal kurtosis 3:
    #   z(1 - 1/88) = 2.27800, z(1 - 1/(88e)) = 2.63713
    #   SR0 = 0.0447213595 * (0.4227843351*2.27800 + 0.5772156649*2.63713)
    #       = 0.0447213595 * 2.4852960 = 0.111146
    #   1 - 0*0.1581139 + ((3-1)/4)*0.025 = 1.0125, sqrt = 1.0062306
    #   arg = (0.1581139 - 0.1111458) * 35.3411941 / 1.0062306 = 1.64963
    #   Phi(1.64963) = 0.95048
    sr0 = expected_max_sharpe(88, VAR_TRIALS_SR)
    assert sr0 == pytest.approx(0.1111, abs=2e-4)
    dsr = deflated_sharpe(SR, N_OBS, 0.0, 3.0, 88, VAR_TRIALS_SR)
    assert dsr == pytest.approx(0.9505, abs=5e-4)


def test_dsr_tight_values():
    # sqrt(0.002) = 0.0447213595, z(.99) = 2.3263478740 and
    # z(1 - 1/(100e)) = 2.6802, so the bar is 0.0447213595 * 2.5305969 =
    # 0.1131720019.  sqrt(n_obs - 1) = sqrt(1249) = 35.3411941 and the
    # standard-error factor is sqrt(1 - (-3)*0.1581139 + ((10-1)/4)*0.025) =
    # sqrt(1.5305917) = 1.2371708, so the argument is
    # (0.1581139 - 0.1131720) * 35.3411941 / 1.2371708 = 1.2838 and
    # Phi(1.2838) = 0.9003968.
    # A sqrt(T) in place of sqrt(T - 1) in that argument moves it by about
    # 0.04% (0.0005 here) and the deflated Sharpe by about 9e-5, more than
    # abs=1e-6 allows.
    assert expected_max_sharpe(100, VAR_TRIALS_SR) == pytest.approx(
        0.11317200186510788, abs=1e-8
    )
    assert deflated_sharpe(
        SR, N_OBS, -3.0, 10.0, 100, VAR_TRIALS_SR
    ) == pytest.approx(0.9003968344495117, abs=1e-6)

    # N = 46: z(1 - 1/46) = 2.01909 and z(1 - 1/(46e)) = 2.40904, so the bar is
    # 0.0447213595 * 2.2441738 = 0.1003623706; the argument is
    # (0.1581139 - 0.1003624) * 35.3411941 / 1.2371708 = 1.6498 and
    # Phi(1.6498) = 0.9505017.
    assert expected_max_sharpe(46, VAR_TRIALS_SR) == pytest.approx(
        0.10036237061762683, abs=1e-8
    )
    assert deflated_sharpe(
        SR, N_OBS, -3.0, 10.0, 46, VAR_TRIALS_SR
    ) == pytest.approx(0.9505017068756567, abs=1e-6)

    # N = 88 with skew 0 and normal kurtosis 3: z(1 - 1/88) = 2.27800 and
    # z(1 - 1/(88e)) = 2.63713, so the bar is
    # 0.0447213595 * 2.4852960 = 0.1111457618; the factor is
    # sqrt(1 + ((3-1)/4)*0.025) = sqrt(1.0125) = 1.0062306, so the argument is
    # (0.1581139 - 0.1111458) * 35.3411941 / 1.0062306 = 1.6496 and
    # Phi(1.6496) = 0.9504908.
    assert expected_max_sharpe(88, VAR_TRIALS_SR) == pytest.approx(
        0.11114576178355964, abs=1e-8
    )
    assert deflated_sharpe(
        SR, N_OBS, 0.0, 3.0, 88, VAR_TRIALS_SR
    ) == pytest.approx(0.9504908166761022, abs=1e-6)


def test_dsr_more_trials_lower():
    # A higher bar for the number of trials tried pushes SR0 up, so the same
    # Sharpe deflates further: N = 10 gives a larger value than N = 100.
    ten = deflated_sharpe(SR, N_OBS, -3.0, 10.0, 10, VAR_TRIALS_SR)
    hundred = deflated_sharpe(SR, N_OBS, -3.0, 10.0, 100, VAR_TRIALS_SR)
    assert ten > hundred

    # Ten trials with skew 0 and kurtosis 3:
    #   z(.9) = 1.2815515655, z(1 - 1/(10e)) = 1.78925
    #   SR0 = 0.0447213595 * (0.4227843351*1.2815515655 + 0.5772156649*1.78925)
    #       = 0.0447213595 * 1.5746053 = 0.0704185
    #   1 - 0*0.1581139 + ((3-1)/4)*0.025 = 1.0125, sqrt = 1.0062306
    #   arg = (0.1581139 - 0.0704185) * 35.3411941 / 1.0062306 = 3.08007
    #   Phi(3.08007) = 0.99897
    assert deflated_sharpe(
        SR, N_OBS, 0.0, 3.0, 10, VAR_TRIALS_SR
    ) == pytest.approx(0.9990, abs=5e-4)


def test_dsr_degenerate_none():
    assert expected_max_sharpe(1, VAR_TRIALS_SR) is None
    assert expected_max_sharpe(0, VAR_TRIALS_SR) is None
    assert deflated_sharpe(SR, N_OBS, 0.0, 3.0, 1, VAR_TRIALS_SR) is None
    assert deflated_sharpe(SR, 1, -3.0, 10.0, 100, VAR_TRIALS_SR) is None

    # 1 - skew*sr + ((kurt - 1)/4)*sr^2 = 1 - 100*10 + (2/4)*100 = -949, negative.
    assert deflated_sharpe(10.0, N_OBS, 100.0, 3.0, 100, VAR_TRIALS_SR) is None

    with pytest.raises(ValueError):
        expected_max_sharpe(100, -1.0)

    # A trials variance of 0 is allowed: SR0 is 0 and the result is a number.
    zero_sr0 = expected_max_sharpe(5, 0.0)
    assert isinstance(zero_sr0, float)
    assert zero_sr0 == 0.0
    assert isinstance(deflated_sharpe(SR, N_OBS, 0.0, 3.0, 5, 0.0), float)


# ---------------------------------------------------------------- moments


def test_skew_kurtosis():
    # [0, 0, 0, 4]: mean 1, deviations -1,-1,-1,3
    #   m2 = (1+1+1+9)/4 = 3, m3 = (-1-1-1+27)/4 = 6, m4 = (1+1+1+81)/4 = 21
    #   skew = 6 / 3**1.5 = 6 / 5.196152422706632 = 1.1547005383792515
    #   kurt = 21 / 9 = 2.3333333333333335
    assert skew_kurtosis([0.0, 0.0, 0.0, 4.0]) == pytest.approx(
        (1.1547005383792515, 2.3333333333333335)
    )

    # [-1, 0, 0, 1]: mean 0, m2 = m4 = 0.5, m3 = 0
    #   skew = 0 / 0.5**1.5 = 0.0, kurt = 0.5 / 0.25 = 2.0
    assert skew_kurtosis([-1.0, 0.0, 0.0, 1.0]) == pytest.approx((0.0, 2.0))

    # Three identical values have no second moment to divide by, and one value
    # cannot make one either.
    assert skew_kurtosis([1.0, 1.0, 1.0]) is None
    assert skew_kurtosis([1.0]) is None


# ---------------------------------------------------------------- Newey-West


def test_newey_west_hand_values():
    # x = [2, 0, 2, 0]: mean 1, h = [1, -1, 1, -1], T = 4
    #   Omega_0 = (1+1+1+1)/4 = 1
    #   Omega_1 = (-1*1 + 1*-1 + -1*1)/4 = -3/4 = -0.75
    #   Omega_2 = (1*1 + -1*-1)/4 = 2/4 = 0.5
    x = [2.0, 0.0, 2.0, 0.0]

    # lags 0: S = 1, se = sqrt(1/4) = 0.5, t = 1 / 0.5 = 2.0
    assert newey_west_t(x, lags=0) == pytest.approx(2.0)
    # lags 1: S = 1 + (1 - 1/2)*2*(-0.75) = 0.25, se = 0.25, t = 4.0
    assert newey_west_t(x, lags=1) == pytest.approx(4.0)
    # lags 2: S = 1 + (2/3)*2*(-0.75) + (1/3)*2*0.5 = 1/3,
    #   se = sqrt(1/12) = 0.28867513459481287, t = 3.4641016151377544
    assert newey_west_t(x, lags=2) == pytest.approx(3.4641016151377544)

    # floor(4 * (4/100)**(2/9)) = floor(1.9561) = 1, so no lags means lags 1.
    assert default_nw_lags(4) == 1
    assert newey_west_t(x) == pytest.approx(4.0)

    # floor(4 * (100/100)**(2/9)) = 4
    # floor(4 * 5**(2/9)) = floor(5.7200) = 5
    # floor(4 * 10**(2/9)) = floor(6.6720) = 6
    assert default_nw_lags(100) == 4
    assert default_nw_lags(500) == 5
    assert default_nw_lags(1000) == 6


def test_newey_west_long_run_variance_hand_values():
    from crow_coinbase.lab.validate import newey_west_long_run_variance

    # x = [2, 0, 2, 0]: mean 1, h = [1, -1, 1, -1], T = 4
    #   Omega_0 = (1+1+1+1)/4 = 1
    #   Omega_1 = (-1*1 + 1*-1 + -1*1)/4 = -3/4
    #   Omega_2 = (1*1 + -1*-1)/4 = 2/4 = 0.5
    x = [2.0, 0.0, 2.0, 0.0]

    # lags 0: S = Omega_0 = 1
    assert newey_west_long_run_variance(x, lags=0) == pytest.approx(1.0)
    # lags 1: S = 1 + (1 - 1/2)*2*(-0.75) = 1 - 0.75 = 0.25
    assert newey_west_long_run_variance(x, lags=1) == pytest.approx(0.25)
    # lags 2: S = 1 + (2/3)*2*(-0.75) + (1/3)*2*0.5 = 1 - 1 + 1/3 = 1/3
    assert newey_west_long_run_variance(x, lags=2) == pytest.approx(
        0.3333333333333333, rel=1e-12
    )
    # floor(4 * (4/100)**(2/9)) = 1, so the default lag is 1: S = 0.25
    assert newey_west_long_run_variance(x) == pytest.approx(0.25)

    # the t of the same series is the mean over sqrt(S / T):
    # 1 / sqrt((1/3)/4) = 1 / sqrt(1/12) = sqrt(12) = 3.4641016151377544
    assert newey_west_t(x, lags=2) == pytest.approx(3.4641016151377544)

    # every deviation from the mean is 0, so S is 0
    assert newey_west_long_run_variance([0.01, 0.01, 0.01, 0.01]) is None
    # fewer than 3 observations
    assert newey_west_long_run_variance([0.01, -0.01]) is None
    # as many lags as observations
    assert newey_west_long_run_variance(x, lags=4) is None

    with pytest.raises(ValueError):
        newey_west_long_run_variance(x, lags=-1)


def test_newey_west_autocorrelated_lower_t():
    # An AR(1) series with coefficient 0.5 and a mean of 0.15 added: the
    # positive autocorrelation makes the naive t too large, while the
    # HAC-corrected one stays positive.
    rng = random.Random(5)
    previous = 0.0
    series = []
    for _ in range(1000):
        previous = 0.5 * previous + rng.gauss(0.0, 1.0)
        series.append(previous + 0.15)

    naive = statistics.mean(series) / (
        statistics.stdev(series) / math.sqrt(len(series))
    )
    adjusted = newey_west_t(series)

    assert adjusted is not None
    assert adjusted > 0.0
    assert naive > adjusted


def test_newey_west_degenerate_none():
    # Every deviation from the mean is 0, so S is 0.
    assert newey_west_t([0.01, 0.01, 0.01, 0.01]) is None
    # Fewer than 3 observations.
    assert newey_west_t([0.01, -0.01]) is None
    # As many lags as observations.
    assert newey_west_t([0.01, -0.01, 0.02, 0.0], lags=4) is None

    with pytest.raises(ValueError):
        newey_west_t([0.01, -0.01, 0.02, 0.0], lags=-1)


# ---------------------------------------------------------------- minimum detectable edge


def test_min_detectable_edge():
    # (1.959963984540054 + 0.8416212335729143) * 0.02 / sqrt(100)
    #   = 2.801585218112968 * 0.002 = 0.005603170436225936
    assert min_detectable_edge(100, 0.02) == pytest.approx(
        0.005603170436225936, rel=1e-6
    )
    # sqrt(400) = 20 instead of 10: the same numerator over twice the divisor
    #   = 2.801585218112968 * 0.001 = 0.002801585218112968
    assert min_detectable_edge(400, 0.02) == pytest.approx(
        0.002801585218112968, rel=1e-6
    )

    for bad in (
        (0, 0.02),
        (100, -1.0),
        (100, 0.02, 0.0),
        (100, 0.02, 1.0),
        (100, 0.02, 0.05, 0.0),
        (100, 0.02, 0.05, 1.0),
    ):
        with pytest.raises(ValueError):
            min_detectable_edge(*bad)


def test_min_detectable_edge_t_bar():
    from crow_coinbase.lab.validate import min_detectable_edge

    # With a t bar given, the critical value is t_crit + z(power) instead of
    # z(1 - alpha/2) + z(power): z(0.8) = 0.8416212335729143, so the critical
    # value here is 3.0 + 0.8416212335729143 = 3.8416212335729143.
    #   (3.8416212335729143) * 0.02 / sqrt(100) = 3.8416212335729143 * 0.002
    #   = 0.007683242467145829
    assert min_detectable_edge(100, 0.02, t_crit=3.0) == pytest.approx(
        0.007683242467145829, rel=1e-9
    )
    # sqrt(400) = 20 instead of 10: 3.8416212335729143 * 0.001
    assert min_detectable_edge(400, 0.02, t_crit=3.0) == pytest.approx(
        0.0038416212335729143, rel=1e-9
    )

    # alpha plays no part once the t bar is given: 0.5 instead of 0.05 leaves
    # the same 3.0 + 0.8416212335729143 = 3.8416212335729143
    assert min_detectable_edge(
        100, 0.02, 0.5, 0.8, t_crit=3.0
    ) == pytest.approx(0.007683242467145829, rel=1e-9)

    # the t bar itself has to be positive
    with pytest.raises(ValueError):
        min_detectable_edge(100, 0.02, t_crit=0.0)
    with pytest.raises(ValueError):
        min_detectable_edge(100, 0.02, t_crit=-1.0)

    # with no t bar the two-sided reading is unchanged:
    # (1.959963984540054 + 0.8416212335729143) * 0.02 / sqrt(100)
    #   = 2.801585218112968 * 0.002 = 0.005603170436225936
    assert min_detectable_edge(100, 0.02) == pytest.approx(
        0.005603170436225936, rel=1e-9
    )


# ---------------------------------------------------------------- trial counting


@pytest.fixture
def trials_store(store):
    """Project "p" over two crypto pairs and two stocks, plus project "q"."""
    rows = (
        (PROJECT, "ETH-USDC", "1d", "band", {"k": 1}, 0.1),
        (PROJECT, "ETH-USDC", "1d", "band", {"k": 2}, 0.2),
        (PROJECT, "XRP-USDC", "1d", "band", {"k": 1}, 0.3),
        (PROJECT, "XRP-USDC", "1d", "band", {"k": 2}, 0.4),
        (PROJECT, "ETH-USDC", "1d", "regime", {"n": 5}, 0.5),
        (PROJECT, "ETH-USDC", "1h", "band", {"k": 1}, 0.9),
        (PROJECT, "NVDA", "1d", "veto", {"d": 3}, 0.6),
        (PROJECT, "NVDA", "1d", "veto", {"d": 5}, 0.7),
        (PROJECT, "AMD", "1d", "veto", {"d": 3}, 0.8),
        (OTHER_PROJECT, "ETH-USDC", "1d", "band", {"k": 1}, 0.99),
    )
    for project, asset, interval, rule_id, params, sharpe in rows:
        store.record_run(
            project, asset, interval, rule_id, params, DATA_HASH, sharpe, {}
        )
    return store


def test_trials_keyed_by_interval(trials_store):
    # The 1d crypto read counts 5 rows: four band configs and one regime config.
    daily = trial_stats(trials_store, PROJECT, "1d", "XRP-USDC")
    assert isinstance(daily, TrialStats)
    assert daily.n_trials == 5
    assert daily.n_with_sharpe == 5

    # The 1h read sees only the 1h row, so one trial and no variance from it.
    hourly = trial_stats(trials_store, PROJECT, "1h", "XRP-USDC")
    assert hourly.n_trials == 1
    assert hourly.n_with_sharpe == 1
    assert hourly.var_trials_sr is None
    assert "1h" in hourly.scope

    # Another project's 1d row stays out of this project's count.
    distant = trial_stats(trials_store, OTHER_PROJECT, "1d", "ETH-USDC")
    assert distant.n_trials == 1


def test_trials_counted_across_crypto_assets(trials_store):
    # Whichever crypto pair is asked about, the count covers the whole class:
    # values .1 .2 .3 .4 .5, mean .3, squared deviations .04 .01 0 .01 .04,
    # sum .1 over 4 degrees of freedom -> .025.
    for asset in ("ADA-USDC", "XRP-USDC", "ETH-USDC"):
        stats = trial_stats(trials_store, PROJECT, "1d", asset)
        assert stats.n_trials == 5
        assert stats.n_with_sharpe == 5
        assert stats.var_trials_sr == pytest.approx(0.025)
        assert "crypto" in stats.scope


def test_trials_counted_across_rules(trials_store):
    # Rule "band" contributes four rows and rule "regime" one, all crypto at 1d.
    crypto = trial_stats(trials_store, PROJECT, "1d", "XRP-USDC")
    assert crypto.n_trials == 5

    # A stock read pools every stock asset in the project at that interval, the
    # way the crypto read pools every pair: NVDA's veto d=3 (.6) and d=5 (.7)
    # and AMD's veto d=3 (.8) are one search.  Values .6 .7 .8, mean .7,
    # squared deviations .01 0 .01, sum .02 over 2 degrees of freedom -> .01.
    nvda = trial_stats(trials_store, PROJECT, "1d", "NVDA")
    assert nvda.n_trials == 3
    assert nvda.n_with_sharpe == 3
    assert nvda.var_trials_sr == pytest.approx(0.01)
    assert "all stock assets" in nvda.scope

    # Another stock at the same interval adds to that count instead of standing
    # beside it: AMD's read is the same three trials.
    amd = trial_stats(trials_store, PROJECT, "1d", "AMD")
    assert amd.n_trials == 3
    assert amd.n_with_sharpe == 3
    assert amd.var_trials_sr == pytest.approx(0.01)
    assert "all stock assets" in amd.scope

    # A trial with no Sharpe counts as a trial but not as a Sharpe: the crypto
    # count grows to 6, the Sharpe count stays 5 and the variance is unchanged.
    trials_store.record_run(
        PROJECT, "ETH-USDC", "1d", "regime", {"n": 9}, DATA_HASH, None, {}
    )
    after = trial_stats(trials_store, PROJECT, "1d", "ADA-USDC")
    assert after.n_trials == 6
    assert after.n_with_sharpe == 5
    assert after.var_trials_sr == pytest.approx(0.025)


def test_trials_pooled_across_stocks_doubles_n(store):
    # Two configs on NVDA, each its own key (asset, rule, params): 2 trials.
    store.record_run(PROJECT, "NVDA", "1d", "veto", {"d": 1}, "h1", 0.1, {})
    store.record_run(PROJECT, "NVDA", "1d", "veto", {"d": 2}, "h1", 0.3, {})

    # The pool is the project's stocks, so AMD's read answers 2 as well even
    # though AMD has contributed nothing yet.
    for asset in ("NVDA", "AMD"):
        alone = trial_stats(store, PROJECT, "1d", asset)
        assert alone.n_trials == 2
        assert alone.n_with_sharpe == 2
        assert "all stock assets" in alone.scope

    # The same two configs on AMD are two more keys, because a key carries the
    # asset, so the pool holds 2 + 2 = 4 trials whichever stock is asked about.
    store.record_run(PROJECT, "AMD", "1d", "veto", {"d": 1}, "h1", 0.2, {})
    store.record_run(PROJECT, "AMD", "1d", "veto", {"d": 2}, "h1", 0.4, {})
    for asset in ("NVDA", "AMD"):
        pooled = trial_stats(store, PROJECT, "1d", asset)
        assert pooled.n_trials == 4
        assert pooled.n_with_sharpe == 4
        # values .1 .3 .2 .4, mean .25, squared deviations .0225 .0025 .0025
        # .0225, sum .05 over 3 degrees of freedom -> .016666666666666666
        assert pooled.var_trials_sr == pytest.approx(0.05 / 3)


def test_trials_rerun_on_new_data_is_one_trial(store):
    # One key (NVDA, "veto", {"d": 1}) run first on data hash "h1" and then on
    # "h2": two rows, one trial, and the later row's Sharpe is the one read.
    store.record_run(PROJECT, "NVDA", "1d", "veto", {"d": 1}, "h1", 0.1, {})
    store.record_run(PROJECT, "NVDA", "1d", "veto", {"d": 1}, "h2", 0.5, {})
    store.record_run(PROJECT, "NVDA", "1d", "veto", {"d": 2}, "h1", 0.3, {})

    stats = trial_stats(store, PROJECT, "1d", "NVDA")
    assert stats.n_trials == 2
    assert stats.n_with_sharpe == 2
    # the latest rows carry .5 and .3 (not .1), mean .4, squared deviations .01
    # and .01, sum .02 over 1 degree of freedom -> .02
    assert stats.var_trials_sr == pytest.approx(0.02)

    # A key whose latest row carries no Sharpe is still a trial, and the older
    # value is superseded rather than counted: {"d": 3} ran at .9 on "h1" and
    # again with no Sharpe on "h2", so the count is 3 while only .5 and .3
    # carry a Sharpe.
    store.record_run(PROJECT, "NVDA", "1d", "veto", {"d": 3}, "h1", 0.9, {})
    store.record_run(PROJECT, "NVDA", "1d", "veto", {"d": 3}, "h2", None, {})
    later = trial_stats(store, PROJECT, "1d", "NVDA")
    assert later.n_trials == 3
    assert later.n_with_sharpe == 2
    assert later.var_trials_sr == pytest.approx(0.02)


# ================================================================ procedure half
#
# A rule module is anything carrying RULE_ID, HYPOTHESIS, GRID, ASSETS, an
# INITIAL_BASE_FRACTION, a `make(params)` that builds its decide callable and,
# for the grid simulator, an `initial_grid(params, history)`.  The stand-ins
# below are `types.SimpleNamespace` objects, the same shape a rule file has.

UTC = timezone.utc

STOCK0 = CostModel.for_stock(
    "NVDA", st_tax_rate=D("0.30"), lt_tax_rate=D("0.15"), slippage=D("0")
)


def crypto_zero(asset):
    """A crypto model with no taker fee, no maker fee and no slippage."""
    return CostModel(
        asset,
        taker=D("0"),
        maker=D("0"),
        slippage=D("0"),
        st_tax_rate=D("0.30"),
        lt_tax_rate=D("0.15"),
    )


CRYPTO0 = crypto_zero("XRP-USDC")


def utc(year, month, day, hour=0, minute=0):
    """A timezone-aware UTC datetime at that clock reading."""
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def day_bars(symbol, closes, start=utc(2024, 1, 1)):
    """One daily bar per calendar day from *start*, opening at the prior close.

    The first bar opens at its own close.  high is one above the higher of open
    and close, low one below the lower, and every bar trades one unit.
    """
    rows = []
    previous = None
    for offset, close in enumerate(closes):
        price = D(close)
        opening = price if previous is None else previous
        rows.append(
            Bar(
                symbol=symbol,
                interval="1d",
                ts=start + timedelta(days=offset),
                open=opening,
                high=(price if price > opening else opening) + D("1"),
                low=(price if price < opening else opening) - D("1"),
                close=price,
                volume=D("1"),
            )
        )
        previous = price
    return rows


def never_trades(ctx):
    """A decide that asks for nothing at any bar."""
    return None


def exit_rule(params):
    """A decide that sells the whole holding once, after the named bar.

    It answers at the bar whose index in the visible history is `params["exit"]`
    and the market sale fills at the next bar's open, so the rule never trades
    at the bar it reacted to.
    """

    def decide(ctx):
        if len(ctx.bars) - 1 == params["exit"]:
            return [Order(SELL, qty=ctx.base)]
        return None

    return decide


def fake_rule(
    grid,
    make,
    fraction=D("1"),
    assets=("crypto", "stock"),
    initial_grid=None,
):
    """A rule module stand-in carrying the attributes the procedure reads."""
    rule = SimpleNamespace(
        RULE_ID="fake",
        HYPOTHESIS="h",
        GRID=grid,
        ASSETS=assets,
        INITIAL_BASE_FRACTION=fraction,
        make=make,
    )
    if initial_grid is not None:
        rule.initial_grid = initial_grid
    return rule


def holding_rule(grid, fraction=D("1"), assets=("crypto", "stock")):
    """A fake rule whose decide never answers, so the run buys in and holds."""
    return fake_rule(grid, lambda params: never_trades, fraction, assets)


def sell_after_defer(params):
    """A decide that sells the whole holding at bar exit + defer.

    The decision is taken at that bar and the market sale fills at the next
    bar's open, which is that bar's own close, so a longer defer holds the book
    through one more close before the sale.
    """
    at = int(params["exit"]) + int(params["defer"])

    def decide(ctx):
        if len(ctx.bars) - 1 == at:
            return [Order(SELL, qty=ctx.base)]
        return None

    return decide


def no_defer(params):
    """The same schedule with the defer switched off: its own null schedule."""
    return {**params, "defer": 0}


# ---------------------------------------------------------------- walk forward


def test_oos_state_carried_across_windows():
    # 70 rising daily closes: bar i closes at 100 + i, so bar 20 opens at 119.
    bars = day_bars("NVDA", [D(100 + i) for i in range(70)])
    rule = holding_rule([{"k": 1}, {"k": 2}])

    result = walk_forward_oos(rule, bars, [], STOCK0, 20, 10, 10, "market")

    # (70 - 20) // 10 = 5 windows, each trained on 20 bars and tested on the
    # next 10 of one segment that starts at bar 0.
    assert len(result.windows) == 5
    assert result.segment_start == 0
    assert [choice.test_start for choice in result.windows] == [
        20,
        30,
        40,
        50,
        60,
    ]

    # One run over the 50 out-of-sample bars, entered once at bar 20's open and
    # never traded again: a 50-point curve and a single lot on the book.
    assert len(result.oos.curve) == 50
    assert len(result.oos.trades) == 1
    opening = result.oos.trades[0]
    assert opening.ts == bars[20].ts
    assert opening.side == "BUY"
    assert opening.maker is False
    # the whole 10000 of cash at the 119 open: 10000 / 119 units
    assert opening.qty == D("10000") / D("119")
    # cash, base, lots and carry-forward never reset at a window boundary, so
    # the single purchase is still the whole holding at the end
    assert result.oos.final_base == opening.qty


def test_oos_benchmarks_same_segments():
    bars = day_bars("NVDA", [D(100 + i) for i in range(70)])
    rule = holding_rule([{"k": 1}, {"k": 2}])

    result = walk_forward_oos(rule, bars, [], STOCK0, 20, 10, 10, "market")
    stamps = [bar.ts for bar in bars[20:70]]

    assert [ts for ts, _ in result.oos.curve] == stamps
    assert set(result.benchmarks) == {"fifty_fifty", "buy_and_hold"}
    for name in ("fifty_fifty", "buy_and_hold"):
        benchmark = result.benchmarks[name]
        assert [ts for ts, _ in benchmark.curve] == stamps
        assert benchmark.trades[0].ts == bars[20].ts
        assert benchmark.trades[0].side == "BUY"
        assert benchmark.trades[0].maker is False

    # 50 out-of-sample bars carry 49 period returns
    assert len(result.oos_excess) == 49


def test_oos_window_decider_matches_its_own_bars():
    # 70 rising daily closes, one segment, a 20-bar train and a 10-bar test:
    # (70 - 20) // 10 = 5 windows, so the out-of-sample run covers the 50 bars
    # at segment indices 20..69.
    bars = day_bars("NVDA", [D(100 + i) for i in range(70)])
    calls = []
    tags = []

    def tagged_make(params):
        tag = len(tags)
        tags.append(tag)

        def decide(ctx):
            calls.append((tag, len(ctx.bars)))
            return None

        return decide

    rule = SimpleNamespace(
        RULE_ID="tagged",
        HYPOTHESIS="h",
        GRID=[{"k": 1}, {"k": 2}],
        ASSETS=("stock",),
        INITIAL_BASE_FRACTION=D("1"),
        make=tagged_make,
    )

    result = walk_forward_oos(rule, bars, [], STOCK0, 20, 10, 10, "market")
    assert len(result.windows) == 5

    # 5 windows * 2 configs = 10 deciders built for the train slices (tags
    # 0..9), then one decider per window for the joined out-of-sample run (tags
    # 10..14).  The 2 deciders built after that (tags 15 and 16) serve the runs
    # over the whole segment, so only tags 10..14 are read here.
    assert len(tags) >= 15

    seen = {}
    for tag, length in calls:
        if 10 <= tag < 15:
            seen.setdefault(tag, []).append(length)

    for k in range(5):
        # Window k owns out-of-sample bars k * 10 .. k * 10 + 9, which are
        # segment indices 20 + 10k .. 29 + 10k, and the lookback stops at the
        # bar the run has reached, so those asks carry lengths 21 + 10k ..
        # 30 + 10k: window 0 gets 21..30, window 1 31..40, window 2 41..50,
        # window 3 51..60 and window 4 61..70.
        lengths = seen.get(10 + k, [])
        assert len(lengths) == 10
        assert sorted(lengths) == list(range(21 + 10 * k, 31 + 10 * k))

    # Every out-of-sample bar is answered by exactly one window and none by a
    # decider outside its own 10-bar range: lengths 21..70 appear once each.
    owned = [length for tag, length in calls if 10 <= tag < 15]
    assert sorted(owned) == list(range(21, 71))


def test_oos_windows_anchored_at_segment_end():
    # 75 daily closes: bar i closes at 100 + i, so bar 5 closes at 105 and the
    # last bar (74) at 174.  A 20-bar train and a 10-bar test give
    # (75 - 20) // 10 = 5 windows, which use 20 + 5 * 10 = 70 bars and leave 5
    # unused.
    bars = day_bars("NVDA", [D(100 + i) for i in range(75)])
    rule = holding_rule([{"k": 1}, {"k": 2}])

    result = walk_forward_oos(rule, bars, [], STOCK0, 20, 10, 10, "market")

    # The 70 used bars are the newest ones, so the 5 oldest are the ones left
    # out: the segment used starts at bar 5 and its own indices 0..69 run from
    # there to the last input bar.
    assert result.segment_start_ts == bars[5].ts
    assert result.windows[0].train_start == 0
    assert len(result.windows) == 5
    assert result.windows[-1].test_end == 70
    assert any("5 oldest bars" in note for note in result.notes)

    # The joined out-of-sample run covers segment indices 20..69, i.e. input
    # bars 25..74, so it ends on the last input bar.
    assert result.oos.curve[-1][0] == bars[74].ts

    # A buy-and-hold spends the whole 10000 at the first out-of-sample open,
    # which is bar 25's open, i.e. bar 24's close of 124 = 100 + 24.  STOCK0
    # charges no taker fee, no slippage and no size step, so the run holds
    # 10000 / 124 units and the last bar closes at 174 = 100 + 74:
    #   10000 / 124 * 174 = 1740000 / 124 = 14032.2580645161290322580645161...
    expected = 14032.258064516129  # 1740000 / 124
    benchmark = result.benchmarks["buy_and_hold"]
    assert benchmark.curve[-1][0] == bars[74].ts
    assert float(benchmark.curve[-1][1]) == pytest.approx(expected, rel=1e-12)

    # The rule holds the same single position from the same open, so its own
    # out-of-sample curve ends at the same 10000 / 124 * 174.
    assert float(result.oos.curve[-1][1]) == pytest.approx(expected, rel=1e-12)


def test_walk_forward_frozen_config_no_leak():
    # 500 for the first four bars, then down 2 a bar: bar 4 closes at 498 and bar
    # 59 at 500 - 2 * 56 = 388, so every price stays above 0.  A position held
    # through it loses each bar; one sold at bar 3's open (500) sits in cash.
    falling = [D(500)] * 4 + [D(500 - 2 * (i - 3)) for i in range(4, 60)]
    rule = fake_rule([{"exit": 99}, {"exit": 2}], exit_rule)

    first = walk_forward_oos(
        rule, day_bars("NVDA", falling), [], STOCK0, 20, 10, 10, "market"
    )

    # Over the 20 train bars config 0 holds and its Sharpe is negative; config 1
    # sells at bar 3's open, its equity is 10000 for every bar after, so its
    # Sharpe is undefined and counts as 0.0, which is the higher of the two.
    assert first.windows[0].config_index == 1
    assert first.windows[0].params == {"exit": 2}
    assert first.windows[0].train_sharpe in (0.0, None)

    # The same bars with window 0's test slice (bars 20..29) replaced: the
    # choice and its train Sharpe do not move, so the test slice does not reach
    # the selection.
    altered = falling[:20] + [D(500 + 7 * i) for i in range(20, 30)] + falling[30:]
    assert len(altered) == 60
    second = walk_forward_oos(
        rule, day_bars("NVDA", altered), [], STOCK0, 20, 10, 10, "market"
    )
    assert second.windows[0].config_index == first.windows[0].config_index
    assert second.windows[0].train_sharpe == first.windows[0].train_sharpe
    assert second.windows[0].params == {"exit": 2}

    # A train slice that rises instead: holding earns a positive Sharpe, which
    # the flat exit config cannot match.
    third = walk_forward_oos(
        rule,
        day_bars("NVDA", [D(100 + i) for i in range(60)]),
        [],
        STOCK0,
        20,
        10,
        10,
        "market",
    )
    assert third.windows[0].config_index == 0
    assert third.windows[0].params == {"exit": 99}
    assert third.windows[0].train_sharpe > 0.0


def test_window_does_not_straddle_gap():
    rising = [D(100 + i) for i in range(40)]
    first = day_bars("XRP-USDC", rising)
    # The second stretch starts 43 days after the first: day 39 to day 43 is a
    # four-day step, longer than the one day a crypto daily bar may skip.
    across = day_bars("XRP-USDC", rising, start=utc(2024, 1, 1) + timedelta(days=43))
    bars = first + across

    assert data_segments(bars, CRYPTO0) == [(0, 40), (40, 80)]
    assert data_segments([], CRYPTO0) == []

    rule = holding_rule([{"k": 1}, {"k": 2}])
    result = walk_forward_oos(rule, bars, [], CRYPTO0, 10, 5, 5, "market")

    # 40 bars hold 10 + 5 and the second stretch is the last segment that does.
    assert result.segment_start == 40
    assert result.segment_start_ts == bars[40].ts
    assert all(ts >= bars[40].ts for ts, _ in result.oos.curve)
    # the bars before the gap are named as left out
    assert any(
        "not used" in note or "gap" in note for note in result.notes
    )

    # A second stretch of 12 bars cannot hold a 10 + 5 window, so the first
    # segment is the one used; nothing earlier is left out, so no note says so.
    short = day_bars(
        "XRP-USDC", rising[:12], start=utc(2024, 1, 1) + timedelta(days=43)
    )
    assert data_segments(first + short, CRYPTO0) == [(0, 40), (40, 52)]
    fallback = walk_forward_oos(rule, first + short, [], CRYPTO0, 10, 5, 5, "market")
    assert fallback.segment_start == 0
    assert fallback.segment_start_ts == bars[0].ts

    # Neither segment holds 15 bars: there is no window to run at all.
    tiny_first = day_bars("XRP-USDC", rising[:12])
    tiny_second = day_bars(
        "XRP-USDC", rising[:12], start=utc(2024, 1, 1) + timedelta(days=14)
    )
    assert data_segments(tiny_first + tiny_second, CRYPTO0) == [(0, 12), (12, 24)]
    with pytest.raises(InsufficientData):
        walk_forward_oos(
            rule, tiny_first + tiny_second, [], CRYPTO0, 10, 5, 5, "market"
        )

    # A stock may skip a weekend: three days between bars is not a break, while
    # five days (a holiday beside it) is.
    friday = day_bars("NVDA", rising[:5])
    monday = day_bars("NVDA", rising[:5], start=utc(2024, 1, 1) + timedelta(days=7))
    assert data_segments(friday + monday, STOCK0) == [(0, 10)]
    next_week = day_bars(
        "NVDA", rising[:5], start=utc(2024, 1, 1) + timedelta(days=9)
    )
    assert data_segments(friday + next_week, STOCK0) == [(0, 5), (5, 10)]

    # A crypto daily bar may not skip a day at all.
    crypto_daily = day_bars("XRP-USDC", rising[:6])
    assert data_segments(crypto_daily, CRYPTO0) == [(0, 6)]
    crypto_skip = day_bars(
        "XRP-USDC", rising[:3], start=utc(2024, 1, 1) + timedelta(days=4)
    )
    assert data_segments(crypto_daily[:3] + crypto_skip, CRYPTO0) == [(0, 3), (3, 6)]


def test_pbo_matrix_full_sample_runs():
    # 100 * 1.1 ** i exactly: 100, 110, 121, 133.1, 146.41, 161.051, ...
    closes = [D(100) * D("1.1") ** i for i in range(8)]
    bars = day_bars("NVDA", closes)
    rule = fake_rule([{"exit": 99}, {"exit": 2}], exit_rule)

    result = walk_forward_oos(rule, bars, [], STOCK0, 4, 2, 2, "market")

    matrix = result.pbo_matrix
    # 8 bars give 7 periods and the grid gives one column per config
    assert len(matrix) == 7
    assert all(len(row) == 2 for row in matrix)

    # Column 0 holds: 10000 of cash buys 100 units at the 100 open, and the
    # close rises 10% a bar, so each period is 110/100 - 1 = 0.1, 121/110 - 1,
    # and so on to 194.871710 / 177.156100 - 1 = 0.1.
    assert [row[0] for row in matrix] == pytest.approx([0.1] * 7, abs=1e-9)

    # Column 1 sells the 100 units at bar 3's open, which is bar 2's close 121:
    # equity runs 10000, 11000, 12100 and then 12100 in cash for the last bars,
    # so the steps are 0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0.
    assert [row[1] for row in matrix] == pytest.approx(
        [0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0], abs=1e-9
    )

    assert len(result.config_excess_sharpes) == 2


def test_oos_excess_is_rule_minus_fifty_fifty():
    closes = [D(100) * D("1.1") ** i for i in range(8)]
    bars = day_bars("NVDA", closes)
    rule = fake_rule([{"exit": 99}, {"exit": 2}], exit_rule)

    result = walk_forward_oos(rule, bars, [], STOCK0, 4, 2, 2, "market")

    rule_returns = metrics.period_returns(result.oos.curve)
    bench_returns = metrics.period_returns(result.benchmarks["fifty_fifty"].curve)

    # 4 out-of-sample bars carry 3 returns each, so 3 excess returns
    assert len(result.oos_excess) == len(rule_returns) == len(bench_returns) == 3
    for index, excess in enumerate(result.oos_excess):
        assert excess == pytest.approx(
            rule_returns[index] - bench_returns[index], abs=1e-12
        )


def test_grid_mode_runs_continuous():
    # 0.9% taker, 0.5% maker, 0.1% slippage, with no size or price step.
    crypto = CostModel(
        "XRP-USDC",
        taker=D("0.009"),
        maker=D("0.005"),
        slippage=D("0.001"),
        st_tax_rate=D("0.30"),
        lt_tax_rate=D("0.15"),
    )
    # 103, 97, 103, ... with each bar opening at the previous close, so a 2% rung
    # around the centre is traded through again and again.
    bars = day_bars("XRP-USDC", [D(100 + 3 * ((-1) ** i)) for i in range(80)])

    def decide_gates(ctx):
        return Gates()

    seen = []

    def ladder(params, history):
        # The grid is built at the slice's first bar from that bar's close, so
        # the lookback always carries that bar and every earlier one.
        seen.append((len(history), history[-1].ts))
        return {
            "center": history[-1].close,
            "step_pct": D("0.02"),
            "levels_below": 2,
            "levels_above": 2,
            "quote_per_buy": D("200"),
        }

    rule = fake_rule(
        [{"g": 1}, {"g": 2}],
        lambda params: decide_gates,
        fraction=D("0.5"),
        assets=("crypto",),
        initial_grid=ladder,
    )

    result = walk_forward_oos(rule, bars, [], crypto, 30, 10, 10, "grid")

    # Every ladder build's lookback, counted.  (80 - 30) // 10 = 5 windows whose
    # train slices start at bars 0, 10, 20, 30 and 40; the lookback runs through
    # the slice's first bar, so those builds see 0 + 1, 10 + 1, 20 + 1, 30 + 1
    # and 40 + 1 bars, once per config (2 configs).  The joined out-of-sample run
    # is built from bar 30, the train length, so it sees 31 bars, once.  Each
    # full-sample run is built from bar 0, so it sees 1 bar, once per config.
    # 1: 2 + 2 = 4, 11: 2, 21: 2, 31: 2 + 1 = 3, 41: 2, and 4 + 2 + 2 + 3 + 2
    # = 13 builds in all.
    lengths = [length for length, _ in seen]
    assert len(seen) == 13  # 5 windows * 2 configs + 1 out of sample + 2 full
    assert sorted(lengths) == [1, 1, 1, 1, 11, 11, 21, 21, 31, 31, 31, 41, 41]
    for length, ts in seen:
        assert ts == bars[length - 1].ts

    # (80 - 30) // 10 = 5 windows over one continuous ladder run
    assert len(result.windows) == 5
    assert isinstance(result.oos, GridResult)
    assert any(trade.maker for trade in result.oos.trades)
    assert set(result.benchmarks) == {"fifty_fifty", "buy_and_hold"}
    assert len(result.oos.curve) == 50


def test_walk_forward_validates_args():
    bars = day_bars("NVDA", [D(100 + i) for i in range(40)])
    rule = holding_rule([{"k": 1}, {"k": 2}])

    # test slices have to be contiguous, so the step is the test length
    with pytest.raises(ValueError):
        walk_forward_oos(rule, bars, [], STOCK0, 20, 10, 5, "market")

    with pytest.raises(ValueError):
        walk_forward_oos(rule, bars, [], STOCK0, 20, 10, 10, "bogus")

    # the grid simulator needs the ladder the rule builds from its history
    with pytest.raises(ValueError):
        walk_forward_oos(rule, bars, [], STOCK0, 20, 10, 10, "grid")

    # a train slice of one bar carries no return to rank configs by
    with pytest.raises(ValueError):
        walk_forward_oos(rule, bars, [], STOCK0, 1, 10, 10, "market")

    with pytest.raises(ValueError):
        walk_forward_oos(holding_rule([]), bars, [], STOCK0, 20, 10, 10, "market")


def test_bars_hash_stable():
    bars = day_bars("NVDA", [D(100 + i) for i in range(6)])

    assert bars_hash(bars) == bars_hash(list(bars))

    # a different close on bar 3: 123 instead of 103, which also moves bar 4's
    # open and both bars' high and low
    moved = [D(100 + i) if i != 3 else D("123") for i in range(6)]
    assert bars_hash(bars) != bars_hash(day_bars("NVDA", moved))

    # the same prices under another symbol are other bars
    assert bars_hash(bars) != bars_hash(day_bars("AMD", [D(100 + i) for i in range(6)]))


# ---------------------------------------------------------------- verdict

CONDITION_CODES = ("return:", "drawdown:", "pbo:", "dsr:", "nw_t:")


def verdict_numbers(**overrides):
    """Every condition passing, with any of them overridden by name."""
    values = dict(
        rule_return=D("0.08"),
        bench_return=D("0.05"),
        rule_drawdown=D("0.10"),
        bench_drawdown=D("0.20"),
        pbo=0.05,
        dsr=0.95,
        nw_t=3.5,
        mde=None,
        scope="S",
    )
    values.update(overrides)
    return values


def test_verdict_lists_all_failures():
    verdict = verdict_from_numbers(
        rule_return=D("0.01"),
        bench_return=D("0.05"),
        rule_drawdown=D("0.30"),
        bench_drawdown=D("0.20"),
        pbo=0.5,
        dsr=0.2,
        nw_t=1.0,
        mde=0.004,
        scope="S",
    )

    assert verdict.status == "fail"

    # every failing condition is named, in the return, drawdown, pbo, dsr, nw_t
    # order
    condition_lines = [
        reason for reason in verdict.reasons if reason.startswith(CONDITION_CODES)
    ]
    assert len(condition_lines) == 5
    assert [line.split(":")[0] + ":" for line in condition_lines] == list(
        CONDITION_CODES
    )

    assert any(reason.startswith("scope: S") for reason in verdict.reasons)
    assert any(reason.startswith("mde:") for reason in verdict.reasons)
    assert not any("no edge" in reason for reason in verdict.reasons)


def test_verdict_pass_and_edges():
    passed = verdict_from_numbers(**verdict_numbers())
    assert passed.status == "pass"
    # a passing condition adds no line: the scope sentence is the whole list
    assert passed.reasons == ["scope: S"]

    # pbo 0.05 against PBO_MAX 0.05 and dsr 0.95 against DSR_MIN 0.95 are the
    # same values as their bars, and the edges pass
    with_mde = verdict_from_numbers(**verdict_numbers(mde=0.004))
    assert with_mde.status == "pass"
    assert len(with_mde.reasons) == 2
    assert with_mde.reasons[0] == "scope: S"
    assert with_mde.reasons[1].startswith("mde:")

    # nw_t above NW_T_MIN 3.0 is required, so 3.0 itself fails
    slow = verdict_from_numbers(**verdict_numbers(nw_t=3.0))
    assert slow.status == "fail"
    assert any(reason.startswith("nw_t:") for reason in slow.reasons)

    # a drawdown equal to the benchmark's is no deeper than it
    level = verdict_from_numbers(**verdict_numbers(rule_drawdown=D("0.20")))
    assert level.status == "pass"

    # a return equal to the benchmark's is not above it
    level_return = verdict_from_numbers(**verdict_numbers(rule_return=D("0.05")))
    assert level_return.status == "fail"
    assert any(
        reason.startswith("return:") for reason in level_return.reasons
    )


def test_verdict_not_enough_data_with_mde():
    verdict = verdict_from_numbers(**verdict_numbers(pbo=None, dsr=None, mde=0.004))

    assert verdict.status == "not_enough_data"
    assert "not enough data to tell" in verdict.reasons[0]
    assert "pbo: not computable" in verdict.reasons
    assert "dsr: not computable" in verdict.reasons
    assert any(
        reason.startswith("mde:") and "0.004" in reason
        for reason in verdict.reasons
    )
    assert not any("no edge" in reason for reason in verdict.reasons)

    # a computed failure outranks the missing numbers, and both are still listed
    mixed = verdict_from_numbers(**verdict_numbers(pbo=None, rule_return=D("0.01")))
    assert mixed.status == "fail"
    assert any(reason.startswith("return:") for reason in mixed.reasons)
    assert "pbo: not computable" in mixed.reasons


def test_verdict_underpowered_is_not_enough_data():
    # The mean excess of 0.0005 sits below the smallest edge 0.002 this sample
    # could detect, so the sample cannot tell the rule apart from the benchmark:
    # a return of 0.04 against 0.05, a dsr of 0.4 and a nw_t of 1.2 are not
    # evidence of a failure, they are a sample too thin to answer.
    verdict = verdict_from_numbers(
        **verdict_numbers(
            nw_t=1.2,
            mde=0.002,
            mean_excess=0.0005,
            rule_return=D("0.04"),
            dsr=0.4,
        )
    )

    assert verdict.status == "not_enough_data"
    opening = verdict.reasons[0]
    assert opening.startswith("not enough data to tell")
    lowered = opening.lower()
    assert "mean excess" in lowered
    assert "detect" in lowered

    # the conditions that missed are still listed after the opening line
    assert any(reason.startswith("return:") for reason in verdict.reasons)
    assert any(reason.startswith("dsr:") for reason in verdict.reasons)
    assert any(reason.startswith("nw_t:") for reason in verdict.reasons)

    mde_lines = [
        reason for reason in verdict.reasons if reason.startswith("mde:")
    ]
    assert len(mde_lines) == 1
    assert "0.002" in mde_lines[0]

    # no line announces a failed verdict
    assert not any(reason.startswith("fail") for reason in verdict.reasons)


def test_verdict_powered_failure_still_fails():
    # The same t of 1.2, but a mean excess of -0.005 is well past the smallest
    # edge 0.002 the sample could detect: an edge this size was there to be
    # seen, and the rule's mean sits on the wrong side of zero instead.
    verdict = verdict_from_numbers(
        **verdict_numbers(nw_t=1.2, mde=0.002, mean_excess=-0.005)
    )

    assert verdict.status == "fail"
    assert any(reason.startswith("nw_t:") for reason in verdict.reasons)
    assert not verdict.reasons[0].startswith("not enough data to tell")


def test_verdict_only_pbo_missed_is_not_enough_data():
    # Every condition passes except the block splits: 0.5 of them put the
    # in-sample winner at or below the middle out of sample.  One miss from a
    # ranking is not a failure to report, and the opening line names the ranking
    # number rather than calling the data merely thin.
    only_pbo = verdict_from_numbers(
        **verdict_numbers(pbo=0.5, mde=0.002, mean_excess=0.01)
    )
    assert only_pbo.status == "not_enough_data"
    opening = only_pbo.reasons[0]
    assert opening.startswith("selection unstable (PBO = ")
    assert opening == (
        "selection unstable (PBO = 0.5): the in-sample winner is often a poor "
        "pick out of sample, so this data cannot rank the configs"
    )
    assert "only condition" not in opening
    assert any(reason.startswith("pbo:") for reason in only_pbo.reasons)
    assert any(reason.startswith("mde:") for reason in only_pbo.reasons)

    # a second miss beside it is a failure
    two_misses = verdict_from_numbers(**verdict_numbers(pbo=0.5, dsr=0.4))
    assert two_misses.status == "fail"
    assert any(reason.startswith("pbo:") for reason in two_misses.reasons)
    assert any(reason.startswith("dsr:") for reason in two_misses.reasons)

    # a condition that could not be computed is no second miss, so the pbo miss
    # on its own still leaves the sample unable to rank the configs
    missing_t = verdict_from_numbers(**verdict_numbers(pbo=0.5, nw_t=None))
    assert missing_t.status == "not_enough_data"
    assert missing_t.reasons[0].startswith("selection unstable (PBO = ")
    assert missing_t.reasons[0].startswith("selection unstable (PBO = 0.5)")
    assert "nw_t: not computable" in missing_t.reasons


def test_verdict_notes_and_warnings_in_reasons():
    note = "the 5 oldest bars of the segment fill no window and are not used"
    warning = "too few configs for a reliable PBO (N=4)"
    verdict = verdict_from_numbers(
        **verdict_numbers(), notes=[note], pbo_warnings=[warning]
    )

    assert verdict.status == "pass"
    note_line = f"note: {note}"
    warning_line = f"warning: {warning}"
    assert verdict.reasons.count(note_line) == 1
    assert verdict.reasons.count(warning_line) == 1

    # both ride with the reasons, ahead of the trial counting scope sentence
    scope = verdict.reasons.index("scope: S")
    assert verdict.reasons.index(note_line) < scope
    assert verdict.reasons.index(warning_line) < scope
    assert verdict.numbers["pbo_warnings"] == [warning]


# ---------------------------------------------------------------- evaluate


def test_evaluate_requires_registration_and_asset_class(store):
    bars = day_bars("NVDA", [D(100 + i) for i in range(40)])
    rule = fake_rule(
        [{"k": 1}, {"k": 2}], lambda params: never_trades, assets=("stock",)
    )

    with pytest.raises(ValueError, match="not registered"):
        evaluate_edge_rule(
            store, PROJECT, rule, bars, [], STOCK0, train_len=10, test_len=5,
            step=5, sim="market",
        )

    store.register_rule(PROJECT, "fake", "h", rule.GRID)

    # registered for stocks, run against a crypto pair's costs
    with pytest.raises(ValueError, match="asset class"):
        evaluate_edge_rule(
            store, PROJECT, rule, bars, [], CRYPTO0, train_len=10, test_len=5,
            step=5, sim="market",
        )


def test_evaluate_edge_rule_refuses_changed_grid(store):
    # Four configs registered as the design of record, then one of them moved.
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)

    # The same rule module with its last config's value changed: the registered
    # grid stands, so the run is refused before a trial is recorded.
    changed = SimpleNamespace(
        **{**vars(rule), "GRID": [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 9}]}
    )
    bars = day_bars("NVDA", [D(100 + i) for i in range(60)])

    with pytest.raises(ValueError, match="different grid") as err:
        evaluate_edge_rule(
            store, PROJECT, changed, bars, [], STOCK0,
            train_len=30, test_len=10, step=10, sim="market",
        )

    assert "new rule version" in str(err.value)
    assert store.trials(PROJECT, "1d", "stock") == []


def test_evaluate_edge_rule_same_grid_runs(store):
    # The very grid that was registered runs, and each of its four configs is
    # recorded as one trial.
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)

    bars = day_bars("NVDA", [D(100 + i) for i in range(60)])
    verdict = evaluate_edge_rule(
        store, PROJECT, rule, bars, [], STOCK0,
        train_len=30, test_len=10, step=10, sim="market",
    )

    assert verdict.status in ("pass", "fail", "not_enough_data")
    assert len(store.trials(PROJECT, "1d", "stock")) == 4
    assert verdict.numbers["n_trials"] == 4


def test_evaluate_not_enough_data_gives_mde(store):
    # four configs, never traded: 4 trials, one curve per config
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)

    # A steady rise, so the rule that holds beats the half-in-cash benchmark on
    # return, keeps a drawdown of 0 for both (closes never fall), and its excess
    # returns are a smooth positive run: nw_t and the deflated Sharpe clear any
    # bar here.  The one number the data cannot give is the PBO: 59 periods
    # cannot fill 32 blocks of two rows, so n_groups=32 leaves it uncomputable.
    bars = day_bars("NVDA", [D(100 + i) for i in range(60)])
    verdict = evaluate_edge_rule(
        store,
        PROJECT,
        rule,
        bars,
        [],
        STOCK0,
        train_len=30,
        test_len=10,
        step=10,
        sim="market",
        n_groups=32,
    )

    assert verdict.status == "not_enough_data"
    assert "not enough data to tell" in verdict.reasons[0]
    assert any(reason.startswith("pbo:") for reason in verdict.reasons)
    assert "pbo: not computable" in verdict.reasons
    assert any(reason.startswith("mde:") for reason in verdict.reasons)

    # (60 - 30) // 10 = 3 windows, 30 out-of-sample bars, 29 period returns
    assert verdict.numbers["n_obs"] == 29
    assert verdict.numbers["n_windows"] == 3
    assert verdict.numbers["n_trials"] == 4
    assert verdict.numbers["pbo"] is None
    assert verdict.numbers["mde"] is not None
    assert verdict.numbers["mde"] > 0

    # 20 bars cannot hold a 30 + 10 window: no simulation, no edge to report
    short = day_bars("NVDA", [D(100 + i) for i in range(20)])
    too_short = evaluate_edge_rule(
        store, PROJECT, rule, short, [], STOCK0, train_len=30, test_len=10,
        step=10, sim="market",
    )
    assert too_short.status == "not_enough_data"
    assert "not enough data to tell" in too_short.reasons[0]
    assert too_short.numbers["mde"] is None


def test_evaluate_reasons_carry_walk_notes_and_pbo_warning(store):
    # Four configs and four blocks make the PBO computable, and four configs are
    # few enough for its warning.  65 bars with a 30-bar train and a 10-bar test
    # give (65 - 30) // 10 = 3 windows over 30 + 3 * 10 = 60 bars, so the 5
    # oldest bars fill no window.
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)

    bars = day_bars(
        "NVDA", [D(100 + i + 3 * ((-1) ** (i // 3))) for i in range(65)]
    )
    verdict = evaluate_edge_rule(
        store, PROJECT, rule, bars, [], STOCK0,
        train_len=30, test_len=10, step=10, sim="market", n_groups=4,
    )

    assert verdict.numbers["pbo"] is not None
    assert any("oldest bars" in reason for reason in verdict.reasons)
    assert any(
        reason.startswith("warning: too few configs")
        for reason in verdict.reasons
    )


def test_evaluate_mde_uses_long_run_sd(store):
    # The same walk as above, over a series that moves: the smallest edge a
    # sample can detect is read off the Newey-West long-run sd, not the plain
    # per-period sd.
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)

    bars = day_bars(
        "NVDA", [D(100 + i + 3 * ((-1) ** (i // 3))) for i in range(65)]
    )
    verdict = evaluate_edge_rule(
        store, PROJECT, rule, bars, [], STOCK0,
        train_len=30, test_len=10, step=10, sim="market", n_groups=4,
    )
    numbers = verdict.numbers

    # 3 windows of a 10-bar test slice carry 30 out-of-sample bars, so 29
    # period returns
    n_obs = numbers["n_obs"]
    assert n_obs == 29
    assert numbers["sd"] is not None
    assert numbers["mean_excess"] is not None
    long_run_sd = numbers["long_run_sd"]
    assert long_run_sd is not None
    assert numbers["mde"] is not None

    # (3.0 + z(0.8)) * long_run_sd / sqrt(n_obs), z(0.8) = 0.8416212335729143
    assert numbers["mde"] == pytest.approx(
        (3.0 + 0.8416212335729143) * long_run_sd / math.sqrt(n_obs), rel=1e-9
    )

    # the i.i.d. reading of the same sample is another number:
    # (1.959963984540054 + 0.8416212335729143) * sd / sqrt(n_obs)
    iid = (
        (1.959963984540054 + 0.8416212335729143)
        * numbers["sd"]
        / math.sqrt(n_obs)
    )
    assert numbers["mde"] != pytest.approx(iid, rel=1e-6)


def test_evaluate_refuses_floor_not_above_round_trip_cost(store):
    # 0.4% maker fee and 0.1% slippage each way: 2 * (0.004 + 0.001) = 0.01 is
    # the round trip a floor has to clear to leave any edge behind it.
    costs = CostModel(
        "XRP-USDC",
        taker=D("0.009"),
        maker=D("0.004"),
        slippage=D("0.001"),
        st_tax_rate=D("0.30"),
        lt_tax_rate=D("0.15"),
    )
    # 20 bars hold no 30 + 10 window, so a refusal here is the floor guard's
    # and not the walk forward's.
    bars = day_bars("XRP-USDC", [D(100 + i) for i in range(20)])

    def registered(grid, rule_id):
        rule = fake_rule(
            grid, lambda params: never_trades, assets=("crypto",)
        )
        rule.RULE_ID = rule_id
        store.register_rule(PROJECT, rule_id, "h", grid)
        return rule

    def refused(grid, rule_id):
        rule = registered(grid, rule_id)
        with pytest.raises(ValueError, match="floor_pct"):
            evaluate_edge_rule(
                store, PROJECT, rule, bars, [], costs,
                train_len=30, test_len=10, step=10, sim="market",
            )

    # a floor of exactly 0.01 is the round trip, which is not above it
    refused(
        [{"floor_pct": 0.01, "k": k} for k in range(4)], "floor_equal"
    )
    # one config below the round trip refuses the whole rule
    refused(
        [
            {"floor_pct": 0.02, "k": 1},
            {"floor_pct": 0.02, "k": 2},
            {"floor_pct": 0.01, "k": 3},
            {"floor_pct": 0.02, "k": 4},
        ],
        "floor_one_low",
    )

    # a floor above the round trip is allowed, and the walk then answers that
    # the bars are too short instead of raising
    allowed_grid = [{"floor_pct": 0.011, "k": k} for k in range(4)]
    allowed = registered(allowed_grid, "floor_above")
    allowed_verdict = evaluate_edge_rule(
        store, PROJECT, allowed, bars, [], costs,
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert allowed_verdict.status == "not_enough_data"
    assert "not enough data to tell" in allowed_verdict.reasons[0]

    # a rule that declares no floor at all is not held to the round trip
    plain_grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    plain = registered(plain_grid, "floor_none")
    plain_verdict = evaluate_edge_rule(
        store, PROJECT, plain, bars, [], costs,
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert plain_verdict.status == "not_enough_data"
    assert "not enough data to tell" in plain_verdict.reasons[0]


def test_evaluate_trials_counted_across_assets(store):
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("crypto",))
    store.register_rule(PROJECT, "fake", "h", grid)

    eth = day_bars("ETH-USDC", [D(100 + i) for i in range(60)])
    xrp = day_bars("XRP-USDC", [D(50 + i) for i in range(60)])

    first = evaluate_edge_rule(
        store, PROJECT, rule, eth, [], crypto_zero("ETH-USDC"),
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert first.numbers["n_trials"] == 4

    # a crypto count spans every pair in the project at that interval
    second = evaluate_edge_rule(
        store, PROJECT, rule, xrp, [], crypto_zero("XRP-USDC"),
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert second.numbers["n_trials"] == 8
    assert any("crypto" in reason for reason in second.reasons)

    # the same rule over the same bars is the trial already on file, so the
    # count stays where it was
    again = evaluate_edge_rule(
        store, PROJECT, rule, eth, [], crypto_zero("ETH-USDC"),
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert again.numbers["n_trials"] == 8


def test_evaluate_trials_distinct_across_reruns_and_settings(store):
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)
    G = len(rule.GRID)  # 4 configs, so one walk records 4 trials

    bars = day_bars("NVDA", [D(100 + i) for i in range(60)])
    first = evaluate_edge_rule(
        store, PROJECT, rule, bars, [], STOCK0,
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert first.numbers["n_trials"] == G

    # A few more days of bars is a new data hash over the same segment, so each
    # config's row is a re-run of the trial already on file: still 4 trials.
    longer = day_bars("NVDA", [D(100 + i) for i in range(63)])
    rerun = evaluate_edge_rule(
        store, PROJECT, rule, longer, [], STOCK0,
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert rerun.numbers["n_trials"] == G

    # The walk settings are part of a trial's key, so a different train length
    # is a different trial for every config: 4 + 4 = 8.
    other_settings = evaluate_edge_rule(
        store, PROJECT, rule, longer, [], STOCK0,
        train_len=20, test_len=10, step=10, sim="market",
    )
    assert other_settings.numbers["n_trials"] == 2 * G


def test_evaluate_trials_pooled_across_two_stocks(store):
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)
    G = len(rule.GRID)  # 4 configs, so one walk records 4 trials

    amd_costs = CostModel.for_stock(
        "AMD", st_tax_rate=D("0.30"), lt_tax_rate=D("0.15"), slippage=D("0")
    )

    nvda = day_bars("NVDA", [D(100 + i) for i in range(60)])
    first = evaluate_edge_rule(
        store, PROJECT, rule, nvda, [], STOCK0,
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert first.numbers["n_trials"] == G

    # The same rule and the same settings on AMD: the stock read pools both
    # names, so the second verdict counts 4 + 4 trials and its scope says so.
    amd = day_bars("AMD", [D(50 + i) for i in range(60)])
    second = evaluate_edge_rule(
        store, PROJECT, rule, amd, [], amd_costs,
        train_len=30, test_len=10, step=10, sim="market",
    )
    assert second.numbers["n_trials"] == 2 * G
    assert any("all stock assets" in reason for reason in second.reasons)


# ---------------------------------------------------------------- the null schedule
#
# R5 (the earnings veto) is a rule with a null schedule: its own configs with the
# window shut (`null_params`).  Its out-of-sample run is weighed against that
# schedule, and the 50/50 benchmark is context beside it.


R5_CLOSES = [D(100 + 2 * (index % 2)) for index in range(80)]


def test_walk_forward_r5_benchmark_is_no_veto_schedule():
    from crow_coinbase.lab.rules import event_veto
    from crow_coinbase.lab.store import Event

    # 80 daily closes zigzagging 100, 102, 100, 102, ... so a buy that waits one
    # bar pays two points away from the price it would have paid: bar 51 opens
    # at day 50's close of 100 and bar 52 at day 51's close of 102.
    bars = day_bars("NVDA", R5_CLOSES)

    # 2024-01-01 is a Monday, so the week starts are every seventh bar from
    # bar 0 and bar 49 is Monday 19 February 2024, a market holiday.  A release
    # after Wednesday 21 February's close reacts on Thursday 22 February: from
    # Monday 19 February the next session is Tuesday 20, and Wednesday 21 and
    # Thursday 22 are the two sessions after it, so a window of 2, 3 or 5
    # sessions holds the bar-49 buy back while veto_days 1 and the null schedule
    # let it through.
    earnings = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 2, 21, 20),
        announced_at=utc(2024, 1, 1),
        session="post",
    )

    result = walk_forward_oos(
        event_veto,
        bars,
        [earnings],
        STOCK0,
        30,
        10,
        10,
        "market",
        start_cash=D("50"),
    )

    assert result.pass_benchmark == "no_veto"
    assert set(result.benchmarks) == {"fifty_fifty", "buy_and_hold", "no_veto"}

    # the null schedule runs over exactly the joined out-of-sample bars
    null_run = result.benchmarks["no_veto"]
    assert [ts for ts, _ in null_run.curve] == [ts for ts, _ in result.oos.curve]

    # (80 - 30) // 10 = 5 windows of a 10-bar test slice, so 50 out-of-sample
    # bars and 49 period returns, and the excess is read against the null run;
    # both runs are funded, so each return is read net of its own contributions
    rule_returns = metrics.period_returns(
        result.oos.curve, result.oos.contributions
    )
    null_returns = metrics.period_returns(
        null_run.curve, null_run.contributions
    )
    assert len(result.oos_excess) == len(rule_returns) == len(null_returns) == 49
    for index, excess in enumerate(result.oos_excess):
        assert excess == rule_returns[index] - null_returns[index]

    # With no event at all the window never opens, so the rule's own schedule
    # and the null schedule are one and the same run: the curves match step for
    # step, every excess return is zero, and each config's own excess against
    # its null schedule has no spread to divide by.
    quiet = walk_forward_oos(
        event_veto,
        bars,
        [],
        STOCK0,
        30,
        10,
        10,
        "market",
        start_cash=D("50"),
    )
    assert quiet.pass_benchmark == "no_veto"
    assert quiet.benchmarks["no_veto"].curve == quiet.oos.curve
    assert quiet.oos_excess == [0.0] * 49
    assert quiet.config_excess_sharpes == [None] * len(event_veto.GRID)


def test_walk_forward_funded_rule_counts_contributions():
    from crow_coinbase.lab.rules import event_veto
    from crow_coinbase.lab.store import Event

    # 60 daily bars from Monday 1 January 2024: flat at 100 through bar 49 and
    # 110 from bar 50 on.  Each bar opens at the previous close, so bar 50 opens
    # at 100 and bar 51 at 110.  30 train bars and (60 - 30) // 10 = 3 windows of
    # a 10-bar test slice put the out-of-sample run on bars 30..59.
    bars = day_bars("NVDA", [D(100)] * 50 + [D(110)] * 10)

    # A 20:00 release on Tuesday 20 February 2024 (bar 50) reacts on Wednesday
    # 21 February (bar 51).  From Monday 19 February (bar 49) one session is left
    # before the reaction, so a one-session window holds that week's buy back and
    # the amount is due again on the Tuesday, when the window is shut.
    earnings = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 2, 20, 20),
        announced_at=utc(2024, 1, 2),
        session="post",
    )

    result = walk_forward_oos(
        event_veto,
        bars,
        [earnings],
        STOCK0,
        30,
        10,
        10,
        "market",
        start_cash=D("50"),
    )

    # (60 - 30) // 10 = 3 windows of a 10-bar test slice
    assert len(result.windows) == 3

    # 50 lands on each week start of the out-of-sample slice: bar 30 is the
    # slice's own first bar (a Wednesday, mid-week) and bars 35 (Monday
    # 5 February), 42, 49 and 56 are the four week starts inside it, so
    # 5 * 50 = 250 is contributed to every run over those bars.
    assert result.oos.total_contributed == D("250")
    assert len(result.oos.contributions) == 5
    assert result.benchmarks["no_veto"].total_contributed == D("250")
    assert result.benchmarks["fifty_fifty"].total_contributed == D("250")
    assert result.benchmarks["buy_and_hold"].total_contributed == D("250")

    # the veto moves one weekly buy, so the two runs mark different equity
    assert result.oos.curve != result.benchmarks["no_veto"].curve
    assert result.pass_benchmark == "no_veto"

    # The one period the two runs disagree on, from the marks by hand.  The run
    # started with 50 and bought 0.5 units a week at 100, so by bar 49 it holds
    # 1.0 unit with 150 of cash beside it and the bar-49 close marks
    # 150 + 1.0 * 100 = 250, whether the week's buy has been sent or held back.
    #   * the null schedule sends that buy and it fills at bar 50's open of 100,
    #     so at bar 50's close it holds 1.5 units and 100 of cash:
    #     100 + 1.5 * 110 = 265, a return of 265 / 250 - 1 = 0.06
    #   * the veto run keeps the week's buy back, so at bar 50's close it still
    #     holds 1.0 unit and 150 of cash: 150 + 1.0 * 110 = 260, a return of
    #     260 / 250 - 1 = 0.04.  A buy filled at 110 does not move the mark, so
    #     whether the owing week is spent there or later leaves the marks as they
    #     are.
    # Nothing lands at bar 50, so neither step subtracts a contribution and the
    # excess there is 0.04 - 0.06 = -0.02.  Bar 50 is out-of-sample index 20
    # (50 - 30) and the step into it is read at index 19.  From there the price
    # is flat at 110, and the one contribution left (bar 56's) lifts both marks
    # by the same 50 the step subtracts, so every other step is level.
    assert result.oos_excess[19] == pytest.approx(-0.02, abs=1e-9)
    assert result.oos_excess[:19] == pytest.approx([0.0] * 19, abs=1e-12)
    assert result.oos_excess[20:] == pytest.approx([0.0] * 9, abs=1e-12)


def test_walk_forward_grid_sim_refuses_funded_rule():
    def ladder(params, history):
        return {
            "center": history[-1].close,
            "step_pct": D("0.02"),
            "levels_below": 2,
            "levels_above": 2,
            "quote_per_buy": D("200"),
        }

    rule = fake_rule(
        [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}],
        lambda params: never_trades,
        assets=("crypto",),
        initial_grid=ladder,
    )
    rule.SIMULATOR = "grid"
    rule.FUNDING = {"amount": D("50"), "every": "week"}

    # 45 daily bars hold a 20-bar train and a 10-bar test slice
    bars = day_bars("XRP-USDC", [D(100 + index) for index in range(45)])

    # a grid search cannot spend a fixed weekly contribution
    with pytest.raises(ValueError, match="FUNDING"):
        walk_forward_oos(rule, bars, [], CRYPTO0, 20, 10, 10, "grid")


def test_walk_forward_null_schedule_selects_on_excess_not_absolute():
    # Closes over the segment: five bars flat at 100, a jump to 110, a fall to
    # 104.5, then flat.  The initial buy takes 10000 / 100 = 100 units at bar
    # 0's open, with no fee and no tax.  A run that sells at bar s is marked at
    # the closes up to s and then holds the cash the fill left, so its period
    # returns are the hold returns up to s and zero after: the sale fills at bar
    # s + 1's open, which is bar s's own close.
    #
    # The hold returns are h = [0, 0, 0, 0, 0.1, -0.05, 0, 0, 0], since
    # 110 / 100 - 1 = 0.1 and 104.5 / 110 - 1 = -0.05 and every other step is
    # flat.
    #
    # Config 0 sells at bar 5, so its returns are [0,0,0,0,0.1,0,0,0,0]:
    #   mean 0.1 / 9 = 1/90, deviations 8/90 once and -1/90 eight times, sum of
    #   squares (64 + 8)/8100 = 8/900, sample variance (8/900)/8 = 1/900,
    #   sd 1/30, Sharpe (1/90) / (1/30) = 1/3 = 0.3333.
    # Config 1 sells at bar 4 + 2 = 6, so its returns are
    # [0,0,0,0,0.1,-0.05,0,0,0]:
    #   mean 0.05/9 = 1/180, deviations 17/180, -10/180 and -1/180 seven times,
    #   sum of squares (289 + 100 + 7)/32400 = 11/900, sample variance
    #   (11/900)/8 = 11/7200, sd 0.0390867, Sharpe 0.0055556 / 0.0390867 =
    #   0.1421.
    # Read alone, config 0 is therefore the better run.
    #
    # Against its own null schedule the order turns round.  Config 0 defers
    # nothing, so its null schedule is itself: nine zero excess returns, no
    # spread, an excess Sharpe of 0.0.  Config 1's null sells at bar 4, which
    # fills at bar 5's open of 100 and leaves 10000 in cash for every later bar,
    # so its null run is nine zeros too and its excess over it is
    # [0,0,0,0,0.1,-0.05,0,0,0] again, Sharpe 0.1421 > 0.
    closes = [D(100)] * 5 + [D("110"), D("104.5")] + [D("104.5")] * 7
    bars = day_bars("XRP-USDC", closes)
    grid = [{"exit": 5, "defer": 0}, {"exit": 4, "defer": 2}]

    null_schedule = fake_rule(grid, sell_after_defer, assets=("crypto",))
    null_schedule.null_params = no_defer
    picked = walk_forward_oos(
        null_schedule, bars, [], CRYPTO0, 10, 2, 2, "market"
    )
    # windows 0 trains on bars 0..9, and there the excess picks config 1
    assert picked.windows[0].config_index == 1
    assert picked.windows[0].params == {"exit": 4, "defer": 2}

    # The same two configs with the same decide in a rule carrying no null
    # schedule: nothing to measure an excess against, so the absolute Sharpe
    # decides and picks config 0.
    absolute_only = fake_rule(grid, sell_after_defer, assets=("crypto",))
    assert not hasattr(absolute_only, "null_params")
    absolute = walk_forward_oos(
        absolute_only, bars, [], CRYPTO0, 10, 2, 2, "market"
    )
    assert absolute.windows[0].config_index == 0
    assert absolute.windows[0].params == {"exit": 5, "defer": 0}


def test_walk_forward_other_rule_keeps_fifty_fifty_benchmark():
    bars = day_bars("NVDA", [D(100 + index) for index in range(70)])
    rule = holding_rule([{"k": 1}, {"k": 2}])

    result = walk_forward_oos(rule, bars, [], STOCK0, 20, 10, 10, "market")

    # a rule module with no null_params has no null schedule to run
    assert not hasattr(rule, "null_params")
    assert result.pass_benchmark == "fifty_fifty"
    assert "no_veto" not in result.benchmarks

    # 50 out-of-sample bars carry 49 period returns, and the excess is read
    # against the 50/50 benchmark as before
    rule_returns = metrics.period_returns(result.oos.curve)
    bench_returns = metrics.period_returns(result.benchmarks["fifty_fifty"].curve)
    assert len(result.oos_excess) == 49
    for index, excess in enumerate(result.oos_excess):
        assert excess == rule_returns[index] - bench_returns[index]


def test_walk_forward_null_schedule_needs_market_sim():
    bars = day_bars("XRP-USDC", [D(100 + index) for index in range(45)])

    def ladder(params, history):
        return {
            "center": history[-1].close,
            "step_pct": D("0.02"),
            "levels_below": 2,
            "levels_above": 2,
            "quote_per_buy": D("200"),
        }

    # a rule with a null schedule, carrying the ladder the grid simulator needs,
    # so the refusal is the null schedule's and not one of the shape checks
    rule = fake_rule(
        [{"k": 1}, {"k": 2}],
        lambda params: never_trades,
        assets=("crypto",),
        initial_grid=ladder,
    )
    rule.null_params = lambda params: {**params, "veto_days": 0}

    with pytest.raises(ValueError, match="null_params"):
        walk_forward_oos(rule, bars, [], CRYPTO0, 20, 10, 10, "grid")


def test_evaluate_r5_reports_fifty_fifty_as_context(store):
    from crow_coinbase.lab.rules import event_veto

    # 80 zigzag daily bars, one segment, 5 windows of a 30-bar train and a
    # 10-bar test, so the PBO matrix has 79 periods and 4 configs and 4 blocks
    # of 19 rows each
    bars = day_bars("NVDA", R5_CLOSES)
    store.register_rule(
        PROJECT, event_veto.RULE_ID, event_veto.HYPOTHESIS, event_veto.GRID
    )

    verdict = evaluate_edge_rule(
        store,
        PROJECT,
        event_veto,
        bars,
        [],
        STOCK0,
        train_len=30,
        test_len=10,
        step=10,
        sim="market",
        n_groups=4,
        start_cash=D("50"),
    )
    numbers = verdict.numbers

    assert numbers["pass_benchmark"] == "no_veto"
    # no event, so the veto never fires and the rule's own schedule is the null
    # schedule: the two runs are the same run, so the return cannot be above it
    assert numbers["bench_return"] == numbers["rule_return"]
    assert isinstance(numbers["fifty_fifty_return"], str)

    return_lines = [
        reason for reason in verdict.reasons if reason.startswith("return:")
    ]
    assert len(return_lines) == 1
    assert "same schedule with no veto" in return_lines[0]

    context_lines = [
        reason for reason in verdict.reasons if "context only" in reason
    ]
    assert context_lines
    assert any("50/50" in reason for reason in context_lines)
    assert any(
        numbers["fifty_fifty_return"] in reason for reason in context_lines
    )

    # every other rule keeps the 50/50 pass benchmark and says nothing about
    # context
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    plain = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)
    plain_verdict = evaluate_edge_rule(
        store,
        PROJECT,
        plain,
        bars,
        [],
        STOCK0,
        train_len=30,
        test_len=10,
        step=10,
        sim="market",
        n_groups=4,
    )
    assert plain_verdict.numbers["pass_benchmark"] == "fifty_fifty"
    assert not any("context only" in reason for reason in plain_verdict.reasons)


# ================================================================ funded runs
#
# A rule carrying a FUNDING schedule is funded by a fixed weekly contribution:
# it may start from no cash at all, it may not start with more than one weekly
# amount, and the verdict reads its numbers net of the money put in.


def test_walk_forward_funded_rule_may_start_from_no_cash():
    from crow_coinbase.lab.rules import event_veto

    # 60 daily bars from Monday 1 January 2024, rising one point a bar: 30 train
    # bars leave (60 - 30) // 10 = 3 windows of a 10-bar test slice.
    bars = day_bars("NVDA", [D(100 + index) for index in range(60)])

    result = walk_forward_oos(
        event_veto, bars, [], STOCK0, 30, 10, 10, "market", start_cash=D("0")
    )

    # The out-of-sample run covers bars 30..59, and 50 lands on each week start
    # there: bar 30 is the slice's own first bar and bars 35 (Monday 5 February),
    # 42, 49 and 56 are the four week starts inside it, so 5 * 50 = 250.
    assert len(result.oos.contributions) == 5
    assert result.oos.total_contributed == D("250")
    assert len(result.oos.curve) == 30
    assert all(equity > 0 for _, equity in result.oos.curve)
    assert len(result.oos_excess) == 29
    assert result.pass_benchmark == "no_veto"

    # one weekly amount of cash is still a starting cash the rule may take
    at_the_top = walk_forward_oos(
        event_veto, bars, [], STOCK0, 30, 10, 10, "market", start_cash=D("50")
    )
    assert at_the_top.oos.total_contributed == D("250")

    # more than one weekly amount would sit idle beside the schedule
    with pytest.raises(ValueError, match="weekly amount"):
        walk_forward_oos(
            event_veto, bars, [], STOCK0, 30, 10, 10, "market", start_cash=D("51")
        )

    # a rule that carries no funding still has to start with cash of its own
    plain = holding_rule([{"k": 1}, {"k": 2}])
    with pytest.raises(ValueError):
        walk_forward_oos(
            plain, bars, [], STOCK0, 30, 10, 10, "market", start_cash=D("0")
        )


def test_evaluate_funded_verdict_reports_the_excess_per_deposit(store):
    from crow_coinbase.lab.rules import event_veto
    from crow_coinbase.lab.store import Event

    # Flat at 100 through bar 49 and 110 from bar 50 on, with the release that
    # holds the Monday 19 February buy back until the window is shut.
    bars = day_bars("NVDA", [D(100)] * 50 + [D(110)] * 10)
    earnings = Event(
        symbol="NVDA",
        kind="earnings",
        at=utc(2024, 2, 20, 20),
        announced_at=utc(2024, 1, 2),
        session="post",
    )
    store.register_rule(
        PROJECT, event_veto.RULE_ID, event_veto.HYPOTHESIS, event_veto.GRID
    )

    verdict = evaluate_edge_rule(
        store,
        PROJECT,
        event_veto,
        bars,
        [earnings],
        STOCK0,
        train_len=30,
        test_len=10,
        step=10,
        sim="market",
        n_groups=4,
        start_cash=D("0"),
    )
    numbers = verdict.numbers

    assert numbers["funded"] is True

    # The out-of-sample run covers bars 30..59: bar 30 (the slice's own first
    # bar, mid-week) and the four week starts at bars 35, 42, 49 and 56 carry one
    # contribution each, so five of them.
    assert numbers["n_deposits"] == 5
    assert isinstance(numbers["excess_dollars"], str)
    assert isinstance(numbers["excess_dollars_per_deposit"], str)

    excess = D(numbers["excess_dollars"])
    per = D(numbers["excess_dollars_per_deposit"])
    # read off the two strings the verdict printed: excess_dollars / 5
    assert float(per) == pytest.approx(float(excess) / 5, rel=1e-12)
    # the vetoed buy misses the rise from 100 to 110, so the rule ends behind
    assert excess != D("0")

    assert any(
        "per weekly deposit" in reason and "diluted" in reason
        for reason in verdict.reasons
    )

    # an unfunded rule reports none of that
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    plain = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)
    plain_verdict = evaluate_edge_rule(
        store,
        PROJECT,
        plain,
        bars,
        [],
        STOCK0,
        train_len=30,
        test_len=10,
        step=10,
        sim="market",
        n_groups=4,
    )
    for key in ("excess_dollars", "n_deposits", "excess_dollars_per_deposit"):
        assert key not in plain_verdict.numbers
    assert not any(
        "per weekly deposit" in reason for reason in plain_verdict.reasons
    )


def test_verdict_funded_return_line_names_the_gain_on_money_contributed():
    funded = verdict_from_numbers(
        **verdict_numbers(rule_return=D("0.01")), funded=True
    )
    assert funded.status == "fail"
    funded_line = next(
        reason for reason in funded.reasons if reason.startswith("return:")
    )
    assert "gain on money contributed" in funded_line
    assert "ends at" not in funded_line
    assert funded.numbers["funded"] is True

    # the unfunded sentence is the one it has always been
    plain = verdict_from_numbers(**verdict_numbers(rule_return=D("0.01")))
    plain_line = next(
        reason for reason in plain.reasons if reason.startswith("return:")
    )
    assert "ends at" in plain_line
    assert "gain on money contributed" not in plain_line
    assert plain.numbers["funded"] is False


def test_evaluate_records_the_start_cash_and_funding_in_the_trial_key(store):
    from crow_coinbase.lab.rules import event_veto

    bars = day_bars("NVDA", [D(100)] * 50 + [D(110)] * 10)
    store.register_rule(
        PROJECT, event_veto.RULE_ID, event_veto.HYPOTHESIS, event_veto.GRID
    )
    configs = len(event_veto.GRID)  # 4 configs, so one walk records 4 trials

    def walked(start_cash):
        return evaluate_edge_rule(
            store,
            PROJECT,
            event_veto,
            bars,
            [],
            STOCK0,
            train_len=30,
            test_len=10,
            step=10,
            sim="market",
            n_groups=4,
            start_cash=start_cash,
        )

    def walks(rule_id="event_veto"):
        return [
            row.params["_walk"]
            for row in store.trials(PROJECT, "1d", "stock")
            if row.rule_id == rule_id
        ]

    first = walked(D("0"))
    assert first.numbers["n_trials"] == configs
    recorded = walks()
    assert len(recorded) == configs
    for walk in recorded:
        assert walk["start_cash"] == "0"
        assert walk["funding"] == {"amount": "50", "every": "week"}
        assert walk["train_len"] == 30
        assert walk["test_len"] == 10
        assert walk["n_groups"] == 4
        assert walk["sim"] == "market"

    # another start cash is another trial per config: 4 + 4 = 8
    second = walked(D("50"))
    assert second.numbers["n_trials"] == 2 * configs
    assert sorted(walk["start_cash"] for walk in walks()) == [
        "0",
        "0",
        "0",
        "0",
        "50",
        "50",
        "50",
        "50",
    ]

    # the same settings again replace the same trial instead of adding one
    again = walked(D("0"))
    assert again.numbers["n_trials"] == 2 * configs

    # An unfunded rule records neither a funding nor a start cash: its walk
    # settings are the four the walk forward is asked with, so walking it from
    # another start cash is the trial already on file.
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    plain = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)
    evaluate_edge_rule(
        store,
        PROJECT,
        plain,
        bars,
        [],
        STOCK0,
        train_len=30,
        test_len=10,
        step=10,
        sim="market",
        n_groups=4,
    )
    unfunded = walks("fake")
    assert len(unfunded) == 4
    for walk in unfunded:
        assert walk == {
            "train_len": 30,
            "test_len": 10,
            "n_groups": 4,
            "sim": "market",
        }
        assert "start_cash" not in walk
        assert "funding" not in walk


def test_unfunded_rerun_replaces_its_trial_rows(store):
    grid = [{"k": 1}, {"k": 2}, {"k": 3}, {"k": 4}]
    rule = fake_rule(grid, lambda params: never_trades, assets=("stock",))
    store.register_rule(PROJECT, "fake", "h", grid)

    bars = day_bars("NVDA", [D(100 + index) for index in range(60)])

    def walked(start_cash):
        return evaluate_edge_rule(
            store,
            PROJECT,
            rule,
            bars,
            [],
            STOCK0,
            train_len=30,
            test_len=10,
            step=10,
            sim="market",
            start_cash=start_cash,
        )

    def rows():
        return [
            row
            for row in store.trials(PROJECT, "1d", "stock")
            if row.rule_id == "fake"
        ]

    # one walk records one trial row per config of the grid
    first = walked(D("5000"))
    assert first.numbers["n_trials"] == 4
    assert len(rows()) == 4

    # the same settings again land on the same four keys, so no row is added
    again = walked(D("5000"))
    assert again.numbers["n_trials"] == 4
    assert len(rows()) == 4

    # An unfunded trial's key carries no start cash, so the same rule walked
    # from another start cash is the same four trials: 4 rows, not 8, and the
    # multiple-comparisons count the deflated Sharpe is read against is still 4.
    other_cash = walked(D("10000"))
    assert other_cash.numbers["n_trials"] == 4
    assert len(rows()) == 4
