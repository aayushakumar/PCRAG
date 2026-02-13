"""
PCRAG Evaluation Runner — generates a markdown report with TDR, FBR, UAA, overhead.

Usage:
    python -m eval.run_eval [--output report.md]
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from core.crypto import generate_keypair, public_key_b64
from core.pipeline import PCRAGPipeline, PipelineConfig
from core.schema import RenderPolicy
from attacks.tamper import ATTACKS, run_all_attacks
from eval.metrics import (
    compute_tdr,
    compute_fbr,
    compute_uaa_proxy,
    measure_overhead,
    verify_certificate_integrity,
)


EVAL_QUERIES = [
    "What is Python and who created it?",
    "How does RSA encryption work?",
    "What is SHA-256 used for?",
    "Tell me about Ed25519 digital signatures.",
    "What is Certificate Transparency?",
]


def run_evaluation(output_path: str = "eval_report.md") -> None:
    """Run the full evaluation suite and generate a markdown report."""

    print("=== PCRAG Evaluation Suite ===\n")

    # Setup
    keypair = generate_keypair()
    pk_b64 = public_key_b64(keypair.public_key)
    policy = RenderPolicy(confidence_threshold=0.5)
    pipeline = PCRAGPipeline(keypair=keypair, policy=policy,
                              config=PipelineConfig(
                                  use_llm_generation=False,
                                  use_llm_claims=False,
                                  use_embedding_spans=False,
                                  verifier_mode="heuristic",
                                  retrieval_mode="bm25",
                                  enable_transparency=True,
                              ))

    all_tdr_results: dict[str, list[bool]] = {name: [] for name in ATTACKS}
    all_fbr: list[float] = []
    all_uaa: dict[str, list[float]] = {name: [] for name in ATTACKS}
    all_latencies: list[float] = []
    all_sizes: list[int] = []

    for qi, query in enumerate(EVAL_QUERIES, 1):
        print(f"[{qi}/{len(EVAL_QUERIES)}] Query: {query}")

        # Generate certificate
        start = time.perf_counter()
        signed, run_metrics = pipeline.answer(query, policy=policy)
        latency_ms = (time.perf_counter() - start) * 1000
        all_latencies.append(latency_ms)

        cert_dict = signed.certificate.model_dump(mode="python")
        sig_b64 = signed.signature

        # Artifact size
        artifact_json = json.dumps(cert_dict, default=str)
        all_sizes.append(len(artifact_json.encode("utf-8")))

        # FBR on legitimate certificate
        fbr = compute_fbr(cert_dict)
        all_fbr.append(fbr)

        # Run all attacks
        tampered_certs = run_all_attacks(cert_dict)

        # TDR
        tdr, attack_results = compute_tdr(cert_dict, sig_b64, pk_b64, tampered_certs)
        for name, detected in attack_results.items():
            all_tdr_results[name].append(detected)

        # UAA per attack
        for name, tampered in tampered_certs.items():
            uaa = compute_uaa_proxy(cert_dict, tampered, sig_b64, pk_b64)
            all_uaa[name].append(uaa)

        print(f"  Latency: {latency_ms:.1f}ms | TDR: {tdr:.2%} | FBR: {fbr:.2%}")

    # ---------------------------------------------------------------------------
    # Aggregate metrics
    # ---------------------------------------------------------------------------
    avg_latency = sum(all_latencies) / len(all_latencies) if all_latencies else 0
    avg_size = sum(all_sizes) / len(all_sizes) if all_sizes else 0
    avg_fbr = sum(all_fbr) / len(all_fbr) if all_fbr else 0

    # Per-attack TDR
    per_attack_tdr: dict[str, float] = {}
    for name, results in all_tdr_results.items():
        per_attack_tdr[name] = sum(results) / len(results) if results else 0.0

    overall_tdr = sum(per_attack_tdr.values()) / len(per_attack_tdr) if per_attack_tdr else 0.0

    # Per-attack UAA
    per_attack_uaa: dict[str, float] = {}
    for name, scores in all_uaa.items():
        per_attack_uaa[name] = sum(scores) / len(scores) if scores else 0.0

    # ---------------------------------------------------------------------------
    # Generate markdown report
    # ---------------------------------------------------------------------------
    lines = [
        "# PCRAG Evaluation Report",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"**Queries evaluated:** {len(EVAL_QUERIES)}",
        f"**Attacks tested:** {len(ATTACKS)}",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Tamper Detection Rate (TDR)** | {overall_tdr:.2%} |",
        f"| **False Blocking Rate (FBR)** | {avg_fbr:.2%} |",
        f"| **Avg Pipeline Latency** | {avg_latency:.1f} ms |",
        f"| **Avg Artifact Size** | {avg_size:.0f} bytes |",
        "",
        "---",
        "",
        "## Tamper Detection Rate by Attack",
        "",
        "| Attack | TDR | Detected/Total |",
        "|--------|-----|----------------|",
    ]

    for name in sorted(per_attack_tdr):
        rate = per_attack_tdr[name]
        results = all_tdr_results[name]
        detected = sum(results)
        total = len(results)
        lines.append(f"| {name} | {rate:.2%} | {detected}/{total} |")

    lines.extend([
        "",
        "---",
        "",
        "## Utility Under Attack (UAA proxy)",
        "",
        "UAA measures what fraction of originally renderable claims remain renderable",
        "after tampering (before fail-closed enforcement). Lower is better for security.",
        "",
        "| Attack | UAA (mean) |",
        "|--------|------------|",
    ])

    for name in sorted(per_attack_uaa):
        lines.append(f"| {name} | {per_attack_uaa[name]:.2%} |")

    lines.extend([
        "",
        "---",
        "",
        "## Overhead",
        "",
        "| Query | Latency (ms) | Artifact Size (bytes) |",
        "|-------|--------------|-----------------------|",
    ])

    for i, query in enumerate(EVAL_QUERIES):
        lines.append(f"| {query[:50]} | {all_latencies[i]:.1f} | {all_sizes[i]} |")

    lines.extend([
        "",
        "---",
        "",
        "## False Blocking Rate (per query)",
        "",
        "| Query | FBR |",
        "|-------|-----|",
    ])

    for i, query in enumerate(EVAL_QUERIES):
        lines.append(f"| {query[:50]} | {all_fbr[i]:.2%} |")

    lines.extend([
        "",
        "---",
        "",
        "## Notes",
        "",
        "- TDR is computed by checking if signature verification OR hash commitment",
        "  verification fails when a tampered certificate is verified against the",
        "  original signature.",
        "- FBR is 0% when all correctly entailed+high-confidence claims are rendered.",
        "- UAA proxy: fraction of originally rendered claims that remain rendered in",
        "  tampered cert (ignoring fail-closed). In practice, fail-closed would block ALL",
        "  claims if signature fails.",
        "- All crypto uses Ed25519 (RFC 8032) with JCS canonicalization (RFC 8785).",
        "",
    ])

    report = "\n".join(lines)

    # Write report
    Path(output_path).write_text(report)
    print(f"\n=== Report written to {output_path} ===")
    print(report)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="eval_report.md")
    args = parser.parse_args()
    run_evaluation(args.output)
