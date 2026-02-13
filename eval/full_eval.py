"""
PCRAG Full Evaluation Suite — Publication-grade evaluation for IEEE Access.

Generates comprehensive evaluation across multiple dimensions:
  1. Security metrics: TDR, FBR, UAA across all attack types
  2. Answer quality: ROUGE-L, exact match, token-level F1
  3. Ablation study: Component contribution analysis
  4. Overhead analysis: Latency breakdown, artifact size
  5. Statistical significance: Multiple runs with std dev

Outputs publication-ready Markdown tables and JSON results.

Usage:
    python -m eval.full_eval [--dataset nq] [--n-samples 50] [--output eval_report.md]
"""

from __future__ import annotations

import json
import logging
import os
import re
import string
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.pipeline import PCRAGPipeline, PipelineConfig, PipelineMetrics
from core.crypto import generate_keypair, public_key_b64
from core.schema import RenderPolicy
from attacks.tamper import ATTACKS, run_all_attacks
from eval.metrics import (
    compute_tdr,
    compute_fbr,
    compute_uaa_proxy,
)
from eval.ablation import run_ablation, generate_ablation_report, get_ablation_configs

logger = logging.getLogger(__name__)


# ── Answer Quality Metrics ─────────────────────────────────────────────────

def normalize_text(text: str) -> str:
    """Normalize text for evaluation: lowercase, remove punctuation, collapse whitespace."""
    text = text.lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    text = " ".join(text.split())
    return text


def exact_match(prediction: str, gold_answers: list[str]) -> float:
    """Exact match (any gold answer). Returns 1.0 or 0.0."""
    pred_norm = normalize_text(prediction)
    for gold in gold_answers:
        if normalize_text(gold) == pred_norm:
            return 1.0
    return 0.0


def contains_match(prediction: str, gold_answers: list[str]) -> float:
    """Check if any gold answer is contained in the prediction."""
    pred_norm = normalize_text(prediction)
    for gold in gold_answers:
        if normalize_text(gold) in pred_norm:
            return 1.0
    return 0.0


def token_f1(prediction: str, gold_answers: list[str]) -> float:
    """Token-level F1 score (best over all gold answers)."""
    pred_tokens = normalize_text(prediction).split()
    if not pred_tokens:
        return 0.0

    best_f1 = 0.0
    for gold in gold_answers:
        gold_tokens = normalize_text(gold).split()
        if not gold_tokens:
            continue

        common = Counter(pred_tokens) & Counter(gold_tokens)
        n_common = sum(common.values())

        if n_common == 0:
            continue

        precision = n_common / len(pred_tokens)
        recall = n_common / len(gold_tokens)
        f1 = 2 * precision * recall / (precision + recall)
        best_f1 = max(best_f1, f1)

    return best_f1


def compute_rouge_l(prediction: str, gold_answers: list[str]) -> float:
    """
    ROUGE-L F1 score (best over all gold answers).
    Uses the rouge_score library if available, falls back to LCS-based computation.
    """
    try:
        from rouge_score import rouge_scorer
        scorer = rouge_scorer.RougeScorer(["rougeL"], use_stemmer=True)
        best = 0.0
        for gold in gold_answers:
            scores = scorer.score(gold, prediction)
            best = max(best, scores["rougeL"].fmeasure)
        return best
    except ImportError:
        # Fallback: simple LCS-based ROUGE-L
        return _lcs_rouge_l(prediction, gold_answers)


def _lcs_rouge_l(prediction: str, gold_answers: list[str]) -> float:
    """Fallback LCS-based ROUGE-L."""
    pred_tokens = normalize_text(prediction).split()
    best_f1 = 0.0

    for gold in gold_answers:
        gold_tokens = normalize_text(gold).split()
        if not gold_tokens or not pred_tokens:
            continue

        # LCS length
        m, n = len(gold_tokens), len(pred_tokens)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if gold_tokens[i-1] == pred_tokens[j-1]:
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])

        lcs_len = dp[m][n]
        if lcs_len == 0:
            continue

        precision = lcs_len / n
        recall = lcs_len / m
        f1 = 2 * precision * recall / (precision + recall)
        best_f1 = max(best_f1, f1)

    return best_f1


# ── Per-Sample Result ──────────────────────────────────────────────────────

@dataclass
class SampleResult:
    """Evaluation result for a single query."""
    query: str
    answer_text: str
    gold_answers: list[str]
    dataset: str

    # Answer quality
    exact_match: float = 0.0
    contains_match: float = 0.0
    token_f1: float = 0.0
    rouge_l: float = 0.0

    # Security
    tdr: float = 0.0
    fbr: float = 0.0
    per_attack_tdr: dict[str, bool] = field(default_factory=dict)

    # Overhead
    latency_ms: float = 0.0
    artifact_size_bytes: int = 0
    n_claims: int = 0
    n_spans: int = 0

    # Pipeline metrics
    metrics: Optional[PipelineMetrics] = None

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "answer": self.answer_text[:200],
            "exact_match": self.exact_match,
            "contains_match": self.contains_match,
            "token_f1": self.token_f1,
            "rouge_l": self.rouge_l,
            "tdr": self.tdr,
            "fbr": self.fbr,
            "latency_ms": self.latency_ms,
            "artifact_size_bytes": self.artifact_size_bytes,
            "n_claims": self.n_claims,
            "n_spans": self.n_spans,
        }


# ── Aggregate Results ──────────────────────────────────────────────────────

@dataclass
class EvalResults:
    """Aggregated evaluation results."""
    dataset: str
    config_name: str
    n_samples: int = 0

    # Answer quality (mean)
    avg_exact_match: float = 0.0
    avg_contains_match: float = 0.0
    avg_token_f1: float = 0.0
    avg_rouge_l: float = 0.0

    # Security (mean)
    avg_tdr: float = 0.0
    avg_fbr: float = 0.0
    per_attack_tdr: dict[str, float] = field(default_factory=dict)
    per_attack_uaa: dict[str, float] = field(default_factory=dict)

    # Overhead (mean)
    avg_latency_ms: float = 0.0
    avg_artifact_size: float = 0.0
    avg_n_claims: float = 0.0
    avg_n_spans: float = 0.0

    # Latency breakdown
    avg_retrieval_ms: float = 0.0
    avg_generation_ms: float = 0.0
    avg_claim_extraction_ms: float = 0.0
    avg_span_selection_ms: float = 0.0
    avg_verification_ms: float = 0.0
    avg_signing_ms: float = 0.0
    avg_transparency_ms: float = 0.0

    # Standard deviations
    std_latency_ms: float = 0.0
    std_tdr: float = 0.0
    std_rouge_l: float = 0.0

    # Token usage
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0

    # Per-sample results
    samples: list[SampleResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dataset": self.dataset,
            "config": self.config_name,
            "n_samples": self.n_samples,
            "answer_quality": {
                "exact_match": self.avg_exact_match,
                "contains_match": self.avg_contains_match,
                "token_f1": self.avg_token_f1,
                "rouge_l": self.avg_rouge_l,
            },
            "security": {
                "tdr": self.avg_tdr,
                "fbr": self.avg_fbr,
                "per_attack_tdr": self.per_attack_tdr,
            },
            "overhead": {
                "latency_ms": self.avg_latency_ms,
                "artifact_size": self.avg_artifact_size,
            },
            "tokens": {
                "prompt": self.total_prompt_tokens,
                "completion": self.total_completion_tokens,
            },
        }


# ── Main Evaluation Runner ────────────────────────────────────────────────

def run_full_eval(
    queries: list[str],
    gold_answers_list: list[list[str]],
    dataset_name: str = "custom",
    config: PipelineConfig | None = None,
    pipeline: PCRAGPipeline | None = None,
) -> EvalResults:
    """
    Run full evaluation on a set of queries with gold answers.

    Args:
        queries: List of evaluation queries.
        gold_answers_list: List of gold answer lists (one per query).
        dataset_name: Name of the dataset for reporting.
        config: Pipeline configuration to use.
        pipeline: Pre-built pipeline (overrides config).

    Returns:
        EvalResults with all metrics.
    """
    if config is None:
        config = PipelineConfig(
            use_llm_generation=False,
            use_llm_claims=False,
            use_embedding_spans=False,
            verifier_mode="heuristic",
            retrieval_mode="bm25",
            enable_transparency=True,
            enable_signing=True,
        )

    keypair = generate_keypair()
    pk_b64 = public_key_b64(keypair.public_key)

    if pipeline is None:
        policy = RenderPolicy(confidence_threshold=config.confidence_threshold)
        pipeline = PCRAGPipeline(keypair=keypair, policy=policy, config=config)
    else:
        pk_b64 = public_key_b64(pipeline.keypair.public_key)

    results = EvalResults(
        dataset=dataset_name,
        config_name=config.config_name,
        n_samples=len(queries),
    )

    all_attack_tdr: dict[str, list[bool]] = {name: [] for name in ATTACKS}
    all_attack_uaa: dict[str, list[float]] = {name: [] for name in ATTACKS}

    for qi, (query, gold_answers) in enumerate(zip(queries, gold_answers_list), 1):
        if qi % 10 == 0 or qi == 1:
            print(f"  [{qi}/{len(queries)}] Processing...")

        try:
            signed, metrics = pipeline.answer(query)
            cert_dict = signed.certificate.model_dump(mode="python")
            sig_b64 = signed.signature
            answer_text = signed.certificate.answer_commitment.answer_text

            # Answer quality metrics
            sr = SampleResult(
                query=query,
                answer_text=answer_text,
                gold_answers=gold_answers,
                dataset=dataset_name,
                exact_match=exact_match(answer_text, gold_answers),
                contains_match=contains_match(answer_text, gold_answers),
                token_f1=token_f1(answer_text, gold_answers),
                rouge_l=compute_rouge_l(answer_text, gold_answers),
                latency_ms=metrics.total_ms,
                artifact_size_bytes=len(json.dumps(cert_dict, default=str).encode()),
                n_claims=len(cert_dict.get("claims", [])),
                n_spans=sum(
                    len(c.get("evidence_spans", []))
                    for c in cert_dict.get("claims", [])
                ),
                metrics=metrics,
            )

            # Security metrics
            fbr = compute_fbr(cert_dict)
            sr.fbr = fbr

            tampered_certs = run_all_attacks(cert_dict)
            tdr_score, attack_results = compute_tdr(
                cert_dict, sig_b64, pk_b64, tampered_certs
            )
            sr.tdr = tdr_score
            sr.per_attack_tdr = attack_results

            for name, detected in attack_results.items():
                all_attack_tdr[name].append(detected)

            for name, tampered in tampered_certs.items():
                uaa = compute_uaa_proxy(cert_dict, tampered, sig_b64, pk_b64)
                all_attack_uaa[name].append(uaa)

            results.samples.append(sr)
            results.total_prompt_tokens += metrics.prompt_tokens
            results.total_completion_tokens += metrics.completion_tokens

        except Exception as e:
            logger.warning(f"  [{qi}] Error processing query: {e}")
            continue

    # Aggregate
    n = len(results.samples)
    if n == 0:
        return results

    results.n_samples = n
    results.avg_exact_match = sum(s.exact_match for s in results.samples) / n
    results.avg_contains_match = sum(s.contains_match for s in results.samples) / n
    results.avg_token_f1 = sum(s.token_f1 for s in results.samples) / n
    results.avg_rouge_l = sum(s.rouge_l for s in results.samples) / n
    results.avg_tdr = sum(s.tdr for s in results.samples) / n
    results.avg_fbr = sum(s.fbr for s in results.samples) / n
    results.avg_latency_ms = sum(s.latency_ms for s in results.samples) / n
    results.avg_artifact_size = sum(s.artifact_size_bytes for s in results.samples) / n
    results.avg_n_claims = sum(s.n_claims for s in results.samples) / n
    results.avg_n_spans = sum(s.n_spans for s in results.samples) / n

    # Standard deviations
    import math
    if n > 1:
        mean_lat = results.avg_latency_ms
        results.std_latency_ms = math.sqrt(sum((s.latency_ms - mean_lat) ** 2 for s in results.samples) / (n - 1))
        mean_tdr = results.avg_tdr
        results.std_tdr = math.sqrt(sum((s.tdr - mean_tdr) ** 2 for s in results.samples) / (n - 1))
        mean_rl = results.avg_rouge_l
        results.std_rouge_l = math.sqrt(sum((s.rouge_l - mean_rl) ** 2 for s in results.samples) / (n - 1))

    # Per-attack aggregation
    for name in ATTACKS:
        vals = all_attack_tdr[name]
        results.per_attack_tdr[name] = sum(vals) / len(vals) if vals else 0.0
    for name in ATTACKS:
        vals = all_attack_uaa[name]
        results.per_attack_uaa[name] = sum(vals) / len(vals) if vals else 0.0

    # Latency breakdown
    metrics_list = [s.metrics for s in results.samples if s.metrics]
    if metrics_list:
        nm = len(metrics_list)
        results.avg_retrieval_ms = sum(m.retrieval_ms for m in metrics_list) / nm
        results.avg_generation_ms = sum(m.generation_ms for m in metrics_list) / nm
        results.avg_claim_extraction_ms = sum(m.claim_extraction_ms for m in metrics_list) / nm
        results.avg_span_selection_ms = sum(m.span_selection_ms for m in metrics_list) / nm
        results.avg_verification_ms = sum(m.verification_ms for m in metrics_list) / nm
        results.avg_signing_ms = sum(m.signing_ms for m in metrics_list) / nm
        results.avg_transparency_ms = sum(m.transparency_ms for m in metrics_list) / nm

    return results


# ── Report Generation ──────────────────────────────────────────────────────

def generate_full_report(
    eval_results: list[EvalResults],
    ablation_results: list | None = None,
    output_path: str = "eval_report.md",
) -> str:
    """
    Generate a comprehensive evaluation report for IEEE Access paper.

    Produces:
      - Table 1: Answer Quality (EM, Contains, F1, ROUGE-L)
      - Table 2: Security Metrics (TDR, FBR, UAA)
      - Table 3: Per-Attack Detection Rate
      - Table 4: Overhead Analysis
      - Table 5: Latency Breakdown
      - Ablation tables (if provided)
    """
    lines = [
        "# PCRAG — Comprehensive Evaluation Report",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"**System:** Proof-Carrying Retrieval-Augmented Generation (PCRAG)",
        "",
        "---",
        "",
    ]

    # ── Table 1: Answer Quality ────────────────────────────────────────────
    lines.extend([
        "## Table 1: Answer Quality Metrics",
        "",
        "| Dataset | Config | N | EM | Contains | Token F1 | ROUGE-L |",
        "|---------|--------|---|----|---------|---------|---------:|",
    ])

    for r in eval_results:
        lines.append(
            f"| {r.dataset} | {r.config_name[:30]} | {r.n_samples} | "
            f"{r.avg_exact_match:.3f} | {r.avg_contains_match:.3f} | "
            f"{r.avg_token_f1:.3f} | {r.avg_rouge_l:.3f} |"
        )

    # ── Table 2: Security Summary ──────────────────────────────────────────
    lines.extend([
        "",
        "## Table 2: Security Metrics Summary",
        "",
        "| Dataset | TDR (mean ± std) | FBR | UAA (mean) |",
        "|---------|------------------|-----|------------|",
    ])

    for r in eval_results:
        mean_uaa = sum(r.per_attack_uaa.values()) / len(r.per_attack_uaa) if r.per_attack_uaa else 0.0
        lines.append(
            f"| {r.dataset} | {r.avg_tdr:.2%} ± {r.std_tdr:.2%} | "
            f"{r.avg_fbr:.2%} | {mean_uaa:.2%} |"
        )

    # ── Table 3: Per-Attack TDR ────────────────────────────────────────────
    lines.extend([
        "",
        "## Table 3: Per-Attack Tamper Detection Rate",
        "",
    ])

    if eval_results:
        attack_names = sorted(ATTACKS.keys())
        header = "| Dataset | " + " | ".join(attack_names) + " |"
        sep = "|---------|" + "|".join(["-----" for _ in attack_names]) + "|"
        lines.append(header)
        lines.append(sep)

        for r in eval_results:
            cells = [f"{r.per_attack_tdr.get(a, 0.0):.0%}" for a in attack_names]
            lines.append(f"| {r.dataset} | " + " | ".join(cells) + " |")

    # ── Table 4: Overhead Analysis ─────────────────────────────────────────
    lines.extend([
        "",
        "## Table 4: Overhead Analysis",
        "",
        "| Dataset | Latency (ms) ± std | Artifact Size (B) | Avg Claims | Avg Spans |",
        "|---------|-------------------|--------------------|------------|-----------|",
    ])

    for r in eval_results:
        lines.append(
            f"| {r.dataset} | {r.avg_latency_ms:.1f} ± {r.std_latency_ms:.1f} | "
            f"{r.avg_artifact_size:.0f} | {r.avg_n_claims:.1f} | {r.avg_n_spans:.1f} |"
        )

    # ── Table 5: Latency Breakdown ─────────────────────────────────────────
    lines.extend([
        "",
        "## Table 5: Pipeline Latency Breakdown (ms)",
        "",
        "| Dataset | Retrieval | Generation | Claims | Spans | Verify | Sign | T-Log | Total |",
        "|---------|-----------|------------|--------|-------|--------|------|-------|-------|",
    ])

    for r in eval_results:
        lines.append(
            f"| {r.dataset} | {r.avg_retrieval_ms:.1f} | {r.avg_generation_ms:.1f} | "
            f"{r.avg_claim_extraction_ms:.1f} | {r.avg_span_selection_ms:.1f} | "
            f"{r.avg_verification_ms:.1f} | {r.avg_signing_ms:.1f} | "
            f"{r.avg_transparency_ms:.1f} | {r.avg_latency_ms:.1f} |"
        )

    # ── Table 6: Token Usage ───────────────────────────────────────────────
    has_tokens = any(r.total_prompt_tokens > 0 for r in eval_results)
    if has_tokens:
        lines.extend([
            "",
            "## Table 6: LLM Token Usage",
            "",
            "| Dataset | Prompt Tokens | Completion Tokens | Total Tokens | Tokens/Query |",
            "|---------|--------------|-------------------|--------------|--------------|",
        ])

        for r in eval_results:
            total = r.total_prompt_tokens + r.total_completion_tokens
            per_q = total / r.n_samples if r.n_samples else 0
            lines.append(
                f"| {r.dataset} | {r.total_prompt_tokens:,} | "
                f"{r.total_completion_tokens:,} | {total:,} | {per_q:.0f} |"
            )

    # ── Per-Attack UAA ─────────────────────────────────────────────────────
    lines.extend([
        "",
        "## Table 7: Utility Under Attack (UAA)",
        "",
        "UAA measures residual utility after tampering. Lower is better (more secure).",
        "In fail-closed mode, detected attacks yield UAA=0%.",
        "",
    ])

    if eval_results:
        attack_names = sorted(ATTACKS.keys())
        header = "| Dataset | " + " | ".join(attack_names) + " |"
        sep = "|---------|" + "|".join(["-----" for _ in attack_names]) + "|"
        lines.append(header)
        lines.append(sep)

        for r in eval_results:
            cells = [f"{r.per_attack_uaa.get(a, 0.0):.0%}" for a in attack_names]
            lines.append(f"| {r.dataset} | " + " | ".join(cells) + " |")

    # ── Ablation ───────────────────────────────────────────────────────────
    if ablation_results:
        lines.extend([
            "",
            "---",
            "",
            "## Ablation Study",
            "",
            "See separate ablation report for detailed component contribution analysis.",
            "",
        ])

    # ── Notes ──────────────────────────────────────────────────────────────
    lines.extend([
        "",
        "---",
        "",
        "## Methodology Notes",
        "",
        "- **TDR (Tamper Detection Rate)**: Fraction of attacks detected via signature",
        "  verification failure or hash commitment mismatch. Target: 100%.",
        "- **FBR (False Blocking Rate)**: Fraction of correctly entailed, high-confidence",
        "  claims that are incorrectly blocked. Target: 0%.",
        "- **UAA (Utility Under Attack)**: Residual claim renderability after tampering.",
        "  In fail-closed mode, detected attacks yield UAA=0. Target: 0%.",
        "- **EM (Exact Match)**: Answer exactly matches a gold answer (after normalization).",
        "- **Contains**: Any gold answer is a substring of the generated answer.",
        "- **Token F1**: Token-level F1 between predicted and best-matching gold answer.",
        "- **ROUGE-L**: Longest common subsequence F1 score.",
        "- All crypto uses Ed25519 (RFC 8032) with JSON Canonicalization Scheme (RFC 8785).",
        "- Transparency log uses Merkle trees with SHA-256 and inclusion proofs.",
        "",
    ])

    report = "\n".join(lines)
    Path(output_path).write_text(report)
    print(f"\nFull report written to {output_path}")

    return report


# ── Dataset-based evaluation ───────────────────────────────────────────────

def eval_on_demo_queries(
    config: PipelineConfig | None = None,
    use_llm: bool = False,
) -> EvalResults:
    """
    Run evaluation on the built-in demo queries (5 queries from DEMO_DOCUMENTS).
    Fast baseline that doesn't require dataset downloads.
    """
    queries = [
        "What is Python and who created it?",
        "How does RSA encryption work?",
        "What is SHA-256 used for?",
        "Tell me about Ed25519 digital signatures.",
        "What is Certificate Transparency?",
    ]

    # Demo gold answers (approximate — from the demo documents)
    gold_answers = [
        ["Python is a high-level general-purpose programming language",
         "created by Guido van Rossum", "Guido van Rossum"],
        ["RSA is a public-key cryptosystem", "asymmetric cryptography",
         "large prime numbers"],
        ["SHA-256 is a cryptographic hash function",
         "member of SHA-2 family", "256-bit hash"],
        ["Ed25519 is a public-key signature system",
         "EdDSA signature scheme", "Curve25519"],
        ["Certificate Transparency is a system for monitoring SSL/TLS certificates",
         "publicly auditable logs", "detect misissued certificates"],
    ]

    if config is None:
        config = PipelineConfig(
            use_llm_generation=use_llm,
            use_llm_claims=use_llm,
            use_embedding_spans=use_llm,
            verifier_mode="nli" if use_llm else "heuristic",
            retrieval_mode="hybrid" if use_llm else "bm25",
            enable_transparency=True,
            enable_signing=True,
        )

    print(f"\n{'='*60}")
    print(f"Evaluating on Demo Queries (n=5)")
    print(f"Config: {config.config_name}")
    print(f"{'='*60}")

    return run_full_eval(queries, gold_answers, "demo", config)


def eval_on_dataset(
    dataset_name: str = "natural_questions",
    n_samples: int = 50,
    config: PipelineConfig | None = None,
    use_llm: bool = False,
) -> EvalResults:
    """
    Run evaluation on a real dataset from HuggingFace.

    Args:
        dataset_name: "natural_questions", "hotpotqa", or "triviaqa"
        n_samples: Number of samples to evaluate
        config: Pipeline configuration
        use_llm: Whether to use LLM components
    """
    from data.loader import load_dataset_samples

    print(f"\n{'='*60}")
    print(f"Loading {dataset_name} ({n_samples} samples)...")
    print(f"{'='*60}")

    samples = load_dataset_samples(dataset_name, n_samples=n_samples)

    queries = [s.question for s in samples]
    gold_answers = [s.gold_answers for s in samples]

    if config is None:
        config = PipelineConfig(
            use_llm_generation=use_llm,
            use_llm_claims=use_llm,
            use_embedding_spans=use_llm,
            verifier_mode="nli" if use_llm else "heuristic",
            retrieval_mode="hybrid" if use_llm else "bm25",
            enable_transparency=True,
            enable_signing=True,
        )

    print(f"Config: {config.config_name}")

    return run_full_eval(queries, gold_answers, dataset_name, config)


# ── CLI Entry Point ────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="PCRAG Full Evaluation Suite")
    parser.add_argument("--dataset", default="demo",
                        choices=["demo", "natural_questions", "nq", "hotpotqa", "triviaqa", "all"],
                        help="Dataset to evaluate on")
    parser.add_argument("--n-samples", type=int, default=50,
                        help="Number of samples per dataset")
    parser.add_argument("--output", default="eval_report.md",
                        help="Output report path")
    parser.add_argument("--ablation", action="store_true",
                        help="Run ablation study")
    parser.add_argument("--use-llm", action="store_true",
                        help="Use LLM components (requires GROQ_API_KEY)")
    parser.add_argument("--json-output", default=None,
                        help="Also write results as JSON")
    args = parser.parse_args()

    use_llm = args.use_llm or bool(os.environ.get("GROQ_API_KEY"))

    all_results: list[EvalResults] = []

    # Run evaluation
    if args.dataset == "demo":
        result = eval_on_demo_queries(use_llm=use_llm)
        all_results.append(result)
    elif args.dataset == "all":
        # Demo first
        all_results.append(eval_on_demo_queries(use_llm=use_llm))
        # Then real datasets
        for ds in ["natural_questions", "hotpotqa", "triviaqa"]:
            try:
                result = eval_on_dataset(ds, n_samples=args.n_samples, use_llm=use_llm)
                all_results.append(result)
            except Exception as e:
                print(f"Warning: Failed to evaluate on {ds}: {e}")
    else:
        result = eval_on_dataset(args.dataset, n_samples=args.n_samples, use_llm=use_llm)
        all_results.append(result)

    # Run ablation if requested
    ablation_results = None
    if args.ablation:
        demo_queries = [
            "What is Python and who created it?",
            "How does RSA encryption work?",
            "What is SHA-256 used for?",
            "Tell me about Ed25519 digital signatures.",
            "What is Certificate Transparency?",
        ]
        ablation_results = run_ablation(demo_queries, use_llm=use_llm)
        generate_ablation_report(ablation_results, args.output.replace(".md", "_ablation.md"))

    # Generate report
    report = generate_full_report(all_results, ablation_results, args.output)

    # Print summary
    print("\n" + "=" * 60)
    print("EVALUATION SUMMARY")
    print("=" * 60)
    for r in all_results:
        print(f"\n{r.dataset} (n={r.n_samples}):")
        print(f"  Answer Quality: EM={r.avg_exact_match:.3f} | "
              f"Contains={r.avg_contains_match:.3f} | "
              f"F1={r.avg_token_f1:.3f} | "
              f"ROUGE-L={r.avg_rouge_l:.3f}")
        print(f"  Security: TDR={r.avg_tdr:.2%} | FBR={r.avg_fbr:.2%}")
        print(f"  Overhead: {r.avg_latency_ms:.1f}ms | {r.avg_artifact_size:.0f}B")

    # JSON output
    if args.json_output:
        json_data = {
            "results": [r.to_dict() for r in all_results],
        }
        Path(args.json_output).write_text(json.dumps(json_data, indent=2, default=str))
        print(f"\nJSON results written to {args.json_output}")


if __name__ == "__main__":
    main()
