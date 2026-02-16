"""Tests for bootstrap confidence intervals and statistical tests."""

import pytest
from eval.statistics import (
    bootstrap_ci,
    paired_bootstrap_test,
    compute_all_cis,
    BootstrapCI,
)


class TestBootstrapCI:
    def test_perfect_metric(self):
        """All 1.0 values should give CI = [1.0, 1.0]."""
        ci = bootstrap_ci([1.0] * 20)
        assert ci.mean == 1.0
        assert ci.ci_lower == 1.0
        assert ci.ci_upper == 1.0
        assert ci.std == 0.0

    def test_zero_metric(self):
        """All 0.0 values should give CI = [0.0, 0.0]."""
        ci = bootstrap_ci([0.0] * 20)
        assert ci.mean == 0.0
        assert ci.ci_lower == 0.0
        assert ci.ci_upper == 0.0

    def test_mixed_values(self):
        """Mixed values should give a reasonable CI."""
        values = [1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0]
        ci = bootstrap_ci(values)
        assert ci.mean == 0.8
        assert 0.4 <= ci.ci_lower <= 0.8
        assert 0.8 <= ci.ci_upper <= 1.0
        assert ci.n_samples == 10

    def test_empty_values(self):
        """Empty list should return zero CI."""
        ci = bootstrap_ci([])
        assert ci.mean == 0.0
        assert ci.n_samples == 0

    def test_single_value(self):
        """Single value should give degenerate CI."""
        ci = bootstrap_ci([0.75])
        assert ci.mean == 0.75
        assert ci.ci_lower == 0.75
        assert ci.ci_upper == 0.75

    def test_ci_contains_mean(self):
        """The CI should contain the observed mean."""
        values = [0.9, 0.8, 1.0, 0.7, 0.95, 0.85, 0.9, 0.88]
        ci = bootstrap_ci(values)
        assert ci.ci_lower <= ci.mean <= ci.ci_upper

    def test_wider_ci_with_more_variance(self):
        """Higher variance data should produce wider CIs."""
        low_var = [0.9, 0.91, 0.89, 0.9, 0.9, 0.91, 0.89, 0.9]
        high_var = [1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0]
        ci_low = bootstrap_ci(low_var)
        ci_high = bootstrap_ci(high_var)
        width_low = ci_low.ci_upper - ci_low.ci_lower
        width_high = ci_high.ci_upper - ci_high.ci_lower
        assert width_high > width_low

    def test_format_table(self):
        """Table format should produce readable string."""
        ci = BootstrapCI(
            mean=0.9167, ci_lower=0.8333, ci_upper=1.0,
            std=0.05, n_samples=12, n_bootstrap=10000,
            confidence_level=0.95,
        )
        formatted = ci.format_table(as_percentage=True)
        assert "91.7%" in formatted
        assert "83.3%" in formatted
        assert "100.0%" in formatted

    def test_to_dict(self):
        """to_dict should produce serializable output."""
        ci = bootstrap_ci([1.0, 0.0, 1.0, 1.0])
        d = ci.to_dict()
        assert "mean" in d
        assert "ci_lower" in d
        assert "ci_upper" in d
        assert d["n_samples"] == 4

    def test_reproducibility(self):
        """Same seed should give same results."""
        values = [0.8, 0.9, 1.0, 0.7, 0.85]
        ci1 = bootstrap_ci(values, seed=42)
        ci2 = bootstrap_ci(values, seed=42)
        assert ci1.ci_lower == ci2.ci_lower
        assert ci1.ci_upper == ci2.ci_upper


class TestPairedBootstrapTest:
    def test_clearly_better_system(self):
        """System A clearly better than B should be significant."""
        a = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
        b = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        result = paired_bootstrap_test(a, b)
        assert result.delta_mean == 1.0
        assert result.significant is True
        assert result.p_value < 0.01

    def test_identical_systems(self):
        """Identical systems should not be significant."""
        a = [0.8, 0.9, 0.7, 0.85, 0.95]
        result = paired_bootstrap_test(a, a)
        assert result.delta_mean == 0.0
        assert result.significant is False

    def test_empty_paired(self):
        """Empty paired test should return non-significant."""
        result = paired_bootstrap_test([], [])
        assert result.significant is False
        assert result.p_value == 1.0

    def test_mismatched_lengths(self):
        """Mismatched lengths should raise."""
        with pytest.raises(AssertionError):
            paired_bootstrap_test([1.0, 0.0], [1.0])

    def test_to_dict(self):
        """to_dict should produce serializable output."""
        result = paired_bootstrap_test([1.0, 0.0], [0.0, 0.0])
        d = result.to_dict()
        assert "delta_mean" in d
        assert "p_value" in d
        assert "significant" in d


class TestComputeAllCIs:
    def test_multiple_metrics(self):
        """Should compute CIs for all named metrics."""
        metrics = {
            "tdr": [1.0, 1.0, 1.0, 0.9],
            "fbr": [0.0, 0.0, 0.0, 0.0],
            "rouge_l": [0.8, 0.7, 0.9, 0.85],
        }
        cis = compute_all_cis(metrics)
        assert len(cis) == 3
        assert "tdr" in cis
        assert "fbr" in cis
        assert "rouge_l" in cis
        assert cis["tdr"].mean == pytest.approx(0.975)
        assert cis["fbr"].mean == 0.0
