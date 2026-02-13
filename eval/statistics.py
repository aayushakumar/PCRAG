"""
Bootstrap confidence intervals and statistical tests for PCRAG evaluation.

Provides publication-grade statistical analysis:
  - Bootstrap confidence intervals for any metric (TDR, FBR, Token F1, etc.)
  - Paired bootstrap test for comparing configurations
  - Formatted output for LaTeX/Markdown tables
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass


@dataclass
class BootstrapCI:
    """Bootstrap confidence interval result."""
    mean: float
    ci_lower: float
    ci_upper: float
    std: float
    n_samples: int
    n_bootstrap: int
    confidence_level: float

    def __str__(self) -> str:
        pct = int(self.confidence_level * 100)
        return (
            f"{self.mean:.4f} "
            f"({pct}% CI: [{self.ci_lower:.4f}, {self.ci_upper:.4f}], "
            f"n={self.n_samples})"
        )

    def to_dict(self) -> dict:
        return {
            "mean": round(self.mean, 4),
            "ci_lower": round(self.ci_lower, 4),
            "ci_upper": round(self.ci_upper, 4),
            "std": round(self.std, 4),
            "n_samples": self.n_samples,
            "n_bootstrap": self.n_bootstrap,
            "confidence_level": self.confidence_level,
        }

    def format_table(self, as_percentage: bool = True) -> str:
        """Format for publication table: 'mean [lower, upper]'."""
        if as_percentage:
            return (
                f"{self.mean:.1%} "
                f"[{self.ci_lower:.1%}, {self.ci_upper:.1%}]"
            )
        return (
            f"{self.mean:.3f} "
            f"[{self.ci_lower:.3f}, {self.ci_upper:.3f}]"
        )


def bootstrap_ci(
    values: list[float],
    n_bootstrap: int = 10000,
    confidence_level: float = 0.95,
    seed: int = 42,
    statistic: str = "mean",
) -> BootstrapCI:
    """
    Compute bootstrap confidence interval for the mean of *values*.

    Args:
        values: Observed metric values (one per sample).
        n_bootstrap: Number of bootstrap resamples. 10000 is standard
                     for publication-grade CIs (Efron & Tibshirani 1993).
        confidence_level: Confidence level (0.95 = 95% CI).
        seed: Random seed for reproducibility.
        statistic: Aggregation ('mean' or 'proportion').

    Returns:
        BootstrapCI with mean, lower, upper, std.
    """
    n = len(values)
    if n == 0:
        return BootstrapCI(
            mean=0.0, ci_lower=0.0, ci_upper=0.0,
            std=0.0, n_samples=0,
            n_bootstrap=n_bootstrap,
            confidence_level=confidence_level,
        )

    rng = random.Random(seed)

    # Observed statistic
    observed_mean = sum(values) / n

    # Bootstrap resampling
    bootstrap_means: list[float] = []
    for _ in range(n_bootstrap):
        resample = [rng.choice(values) for _ in range(n)]
        bootstrap_means.append(sum(resample) / len(resample))

    # Sort for percentile method
    bootstrap_means.sort()

    # Percentile confidence interval
    alpha = 1.0 - confidence_level
    lower_idx = max(0, int(math.floor(alpha / 2 * n_bootstrap)) - 1)
    upper_idx = min(n_bootstrap - 1, int(math.ceil((1 - alpha / 2) * n_bootstrap)) - 1)

    ci_lower = bootstrap_means[lower_idx]
    ci_upper = bootstrap_means[upper_idx]

    # Standard deviation of bootstrap distribution
    bm_mean = sum(bootstrap_means) / len(bootstrap_means)
    variance = sum((x - bm_mean) ** 2 for x in bootstrap_means) / len(bootstrap_means)
    std = math.sqrt(variance)

    return BootstrapCI(
        mean=observed_mean,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        std=std,
        n_samples=n,
        n_bootstrap=n_bootstrap,
        confidence_level=confidence_level,
    )


@dataclass
class PairedBootstrapResult:
    """Result of paired bootstrap significance test."""
    delta_mean: float       # mean(system_a - system_b)
    ci_lower: float
    ci_upper: float
    p_value: float          # Proportion of resamples where delta <= 0
    significant: bool       # True if CI excludes 0
    n_samples: int
    n_bootstrap: int

    def __str__(self) -> str:
        sig = "significant" if self.significant else "not significant"
        return (
            f"Δ={self.delta_mean:.4f} "
            f"(95% CI: [{self.ci_lower:.4f}, {self.ci_upper:.4f}], "
            f"p={self.p_value:.4f}, {sig})"
        )

    def to_dict(self) -> dict:
        return {
            "delta_mean": round(self.delta_mean, 4),
            "ci_lower": round(self.ci_lower, 4),
            "ci_upper": round(self.ci_upper, 4),
            "p_value": round(self.p_value, 4),
            "significant": self.significant,
            "n_samples": self.n_samples,
            "n_bootstrap": self.n_bootstrap,
        }


def paired_bootstrap_test(
    values_a: list[float],
    values_b: list[float],
    n_bootstrap: int = 10000,
    confidence_level: float = 0.95,
    seed: int = 42,
) -> PairedBootstrapResult:
    """
    Paired bootstrap test: is system A significantly better than system B?

    Tests H0: mean(A) <= mean(B) vs H1: mean(A) > mean(B).

    Args:
        values_a: Per-sample scores for system A (must be same length as B).
        values_b: Per-sample scores for system B.
        n_bootstrap: Number of bootstrap iterations.
        confidence_level: For the confidence interval on the delta.
        seed: Random seed.

    Returns:
        PairedBootstrapResult with delta, CI, p-value.
    """
    n = len(values_a)
    assert len(values_b) == n, f"Paired samples must be equal length: {n} vs {len(values_b)}"

    if n == 0:
        return PairedBootstrapResult(
            delta_mean=0.0, ci_lower=0.0, ci_upper=0.0,
            p_value=1.0, significant=False,
            n_samples=0, n_bootstrap=n_bootstrap,
        )

    rng = random.Random(seed)

    # Paired differences
    deltas = [a - b for a, b in zip(values_a, values_b)]
    observed_delta = sum(deltas) / n

    # Bootstrap
    bootstrap_deltas: list[float] = []
    for _ in range(n_bootstrap):
        indices = [rng.randrange(n) for _ in range(n)]
        resample = [deltas[i] for i in indices]
        bootstrap_deltas.append(sum(resample) / len(resample))

    bootstrap_deltas.sort()

    # CI
    alpha = 1.0 - confidence_level
    lower_idx = max(0, int(math.floor(alpha / 2 * n_bootstrap)) - 1)
    upper_idx = min(n_bootstrap - 1, int(math.ceil((1 - alpha / 2) * n_bootstrap)) - 1)

    ci_lower = bootstrap_deltas[lower_idx]
    ci_upper = bootstrap_deltas[upper_idx]

    # p-value: proportion of bootstrap deltas <= 0
    p_value = sum(1 for d in bootstrap_deltas if d <= 0) / n_bootstrap

    significant = ci_lower > 0 or ci_upper < 0  # CI excludes zero

    return PairedBootstrapResult(
        delta_mean=observed_delta,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        p_value=p_value,
        significant=significant,
        n_samples=n,
        n_bootstrap=n_bootstrap,
    )


def compute_all_cis(
    metric_values: dict[str, list[float]],
    n_bootstrap: int = 10000,
    confidence_level: float = 0.95,
) -> dict[str, BootstrapCI]:
    """
    Compute bootstrap CIs for a dictionary of named metrics.

    Args:
        metric_values: {metric_name: [per_sample_values]}

    Returns:
        {metric_name: BootstrapCI}
    """
    return {
        name: bootstrap_ci(values, n_bootstrap, confidence_level)
        for name, values in metric_values.items()
    }
