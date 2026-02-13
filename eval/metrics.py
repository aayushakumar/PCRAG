"""
PCRAG Evaluation Metrics.

Computes:
  - Tamper Detection Rate (TDR): % of attacks detected
  - False Blocking Rate (FBR): % of legit claims incorrectly blocked
  - Utility Under Attack (UAA): proxy for answer usefulness under attack
  - Equivocation Detection Rate (EDR): % of equivocation detected via tlog
  - Overhead: latency and artifact size
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from core.canonicalize import canonicalize
from core.crypto import sha256_hex, verify_json, load_public_key_b64


@dataclass
class VerificationResult:
    """Result of verifying a (possibly tampered) certificate."""
    signature_valid: bool = True
    commitments_valid: bool = True
    hash_errors: list[str] = field(default_factory=list)
    tamper_detected: bool = False


def verify_certificate_integrity(
    cert_dict: dict,
    signature_b64: str,
    public_key_b64: str,
    presented_query: str | None = None,
    check_signature: bool = True,
) -> VerificationResult:
    """
    Verify certificate integrity: signature + all hash commitments.

    If *presented_query* is given the verifier also checks that
    ``query_commitment.query_hash`` matches ``SHA-256(normalised query)``
    (replay detection — PRD §5 A6).

    When ``check_signature=False`` (ablation mode), skip the Ed25519
    signature check entirely and rely solely on hash commitment
    verification.  This isolates what content-integrity hashing alone
    can detect vs. what requires a digital signature.

    Returns a VerificationResult indicating what's broken.
    """
    result = VerificationResult()

    # Strip evaluation side-channel keys before verification
    clean_cert = {k: v for k, v in cert_dict.items() if not k.startswith("_")}

    # 1. Signature check (skipped in ablation mode)
    if check_signature and signature_b64 != "unsigned":
        try:
            pk = load_public_key_b64(public_key_b64)
            result.signature_valid = verify_json(clean_cert, signature_b64, pk)
        except Exception:
            result.signature_valid = False

        if not result.signature_valid:
            result.tamper_detected = True
    elif not check_signature or signature_b64 == "unsigned":
        # In ablation mode, we don't have signature info — mark as N/A
        result.signature_valid = True  # Not applicable, don't flag

    # 1b. Replay detection — query hash mismatch
    if presented_query is not None:
        expected_hash = sha256_hex(presented_query.strip().lower())
        actual_hash = clean_cert.get("query_commitment", {}).get("query_hash", "")
        if expected_hash != actual_hash:
            result.tamper_detected = True
            result.hash_errors.append(
                f"query_hash mismatch (replay): cert has {actual_hash[:16]}..., "
                f"presented query hashes to {expected_hash[:16]}..."
            )

    # 2. Answer text hash
    ac = clean_cert.get("answer_commitment", {})
    if ac.get("answer_text") and ac.get("answer_text_hash"):
        actual = sha256_hex(ac["answer_text"])
        if actual != ac["answer_text_hash"]:
            result.commitments_valid = False
            result.hash_errors.append("answer_text_hash mismatch")
            result.tamper_detected = True

    # 3. Claim hashes
    for claim in clean_cert.get("claims", []):
        cid = claim.get("claim_id", "?")
        if claim.get("claim_text") and claim.get("claim_hash"):
            actual = sha256_hex(claim["claim_text"])
            if actual != claim["claim_hash"]:
                result.commitments_valid = False
                result.hash_errors.append(f"claim {cid} hash mismatch")
                result.tamper_detected = True

        # Span hashes
        for span in claim.get("evidence_spans", []):
            sid = span.get("span_id", "?")
            if span.get("span_text") and span.get("span_hash"):
                actual = sha256_hex(span["span_text"])
                if actual != span["span_hash"]:
                    result.commitments_valid = False
                    result.hash_errors.append(f"span {sid} hash mismatch")
                    result.tamper_detected = True

    return result


@dataclass
class EvalMetrics:
    """Aggregated evaluation metrics."""
    total_attacks: int = 0
    detected_attacks: int = 0
    tdr: float = 0.0  # Tamper Detection Rate

    total_legit_claims: int = 0
    blocked_legit_claims: int = 0
    fbr: float = 0.0  # False Blocking Rate

    uaa_scores: list[float] = field(default_factory=list)
    uaa_mean: float = 0.0  # Utility Under Attack (mean)

    pipeline_latency_ms: float = 0.0
    verification_latency_ms: float = 0.0
    artifact_size_bytes: int = 0

    attack_results: dict[str, bool] = field(default_factory=dict)  # attack_name → detected


def compute_tdr(
    original_cert_dict: dict,
    original_signature: str,
    public_key_b64: str,
    tampered_certs: dict[str, dict],
    check_signature: bool = True,
) -> tuple[float, dict[str, bool]]:
    """
    Compute Tamper Detection Rate over a set of attacks.
    Returns (TDR, {attack_name: detected}).

    For A6 replay attacks the certificate body is unchanged
    (signature still valid), but the verifier must detect the
    query-hash mismatch with the "presented query".

    When ``check_signature=False``, only hash commitment verification
    is used — this isolates what content hashing alone can detect,
    enabling meaningful ablation of the signing component.
    """
    results = {}

    for attack_name, tampered_cert in tampered_certs.items():
        # A6 replay: extract the presented query from side-channel
        presented_query = None
        if "_replay_context" in tampered_cert:
            presented_query = tampered_cert["_replay_context"].get("presented_query")

        vr = verify_certificate_integrity(
            tampered_cert, original_signature, public_key_b64,
            presented_query=presented_query,
            check_signature=check_signature,
        )
        results[attack_name] = vr.tamper_detected

    total = len(results)
    detected = sum(1 for d in results.values() if d)
    tdr = detected / total if total > 0 else 0.0

    return tdr, results


def compute_fbr(cert_dict: dict) -> float:
    """
    Compute False Blocking Rate on a valid (untampered) certificate.
    FBR = (claims that should render but are blocked) / total claims.

    For a valid cert, all entailed+high-conf claims should render.
    We check if render_decision.rendered matches the verification label+confidence.
    """
    claims = cert_dict.get("claims", [])
    if not claims:
        return 0.0

    policy = cert_dict.get("policy", {})
    threshold = policy.get("confidence_threshold", 0.5)

    false_blocks = 0
    total_supported = 0

    for claim in claims:
        verif = claim.get("verification", {})
        rd = claim.get("render_decision", {})
        label = verif.get("label", "")
        conf = verif.get("confidence", 0.0)

        # A claim that IS entailed with high confidence should be rendered
        if label == "entailed" and conf >= threshold:
            total_supported += 1
            if not rd.get("rendered", False):
                false_blocks += 1

    return false_blocks / total_supported if total_supported > 0 else 0.0


def compute_uaa_proxy(
    original_cert_dict: dict,
    tampered_cert_dict: dict,
    signature_b64: str,
    public_key_b64: str,
    check_signature: bool = True,
) -> float:
    """
    Compute Utility Under Attack (proxy): what fraction of originally
    rendered claims are still *usable* after attack.

    In a fail-closed system:
    - If tamper is detected (signature or hash failure), the renderer
      blocks ALL claims → UAA = 0.
    - If tamper is NOT detected, the fraction of still-rendered claims
      is returned (higher = attacker preserved utility = bad for security).
    """
    # First check if the tamper is detected at all
    presented_query = None
    if "_replay_context" in tampered_cert_dict:
        presented_query = tampered_cert_dict["_replay_context"].get("presented_query")

    vr = verify_certificate_integrity(
        tampered_cert_dict, signature_b64, public_key_b64,
        presented_query=presented_query,
        check_signature=check_signature,
    )
    if vr.tamper_detected:
        return 0.0  # Fail-closed: nothing rendered

    # Tamper not detected — measure how many claims survive
    original_rendered = set()
    for claim in original_cert_dict.get("claims", []):
        if claim.get("render_decision", {}).get("rendered", False):
            original_rendered.add(claim.get("claim_id"))

    if not original_rendered:
        return 1.0  # nothing was rendered anyway

    tampered_rendered = set()
    for claim in tampered_cert_dict.get("claims", []):
        if claim.get("render_decision", {}).get("rendered", False):
            tampered_rendered.add(claim.get("claim_id"))

    return len(original_rendered & tampered_rendered) / len(original_rendered)


def measure_overhead(
    pipeline_fn,
    query: str,
    n_runs: int = 3,
) -> tuple[float, int]:
    """
    Measure pipeline latency (ms) and artifact size (bytes).
    Returns (avg_latency_ms, artifact_size_bytes).
    """
    latencies = []

    for _ in range(n_runs):
        start = time.perf_counter()
        signed = pipeline_fn(query)
        elapsed = (time.perf_counter() - start) * 1000
        latencies.append(elapsed)

    avg_latency = sum(latencies) / len(latencies)

    # Measure artifact size
    cert_dict = signed.certificate.model_dump(mode="python")
    artifact_json = json.dumps(cert_dict, default=str)
    artifact_size = len(artifact_json.encode("utf-8"))

    return avg_latency, artifact_size


# ---------------------------------------------------------------------------
# Equivocation Detection (A7)
# ---------------------------------------------------------------------------

def detect_equivocation(
    original_cert_dict: dict,
    equivocated_cert_dict: dict,
    transparency_enabled: bool = True,
) -> bool:
    """
    Detect equivocation attack (A7): same query, different answers.

    An equivocating provider issues two certificates for the same query
    with different content.  Without a transparency log, there is no way
    for an auditor to discover both certificates exist.

    Detection logic:
      1. Check that both certs share the same query_hash (same query).
      2. Check that answer_text_hash differs (different answers).
      3. If transparency_enabled is True, the log would reveal the
         duplicate — equivocation DETECTED.
      4. If transparency_enabled is False, no log to consult —
         equivocation UNDETECTED (returns False).

    Returns True if equivocation is detected, False otherwise.
    """
    # Strip evaluation side-channels
    clean_orig = {k: v for k, v in original_cert_dict.items() if not k.startswith("_")}
    clean_equiv = {k: v for k, v in equivocated_cert_dict.items() if not k.startswith("_")}

    orig_qh = clean_orig.get("query_commitment", {}).get("query_hash", "")
    equiv_qh = clean_equiv.get("query_commitment", {}).get("query_hash", "")

    orig_ah = clean_orig.get("answer_commitment", {}).get("answer_text_hash", "")
    equiv_ah = clean_equiv.get("answer_commitment", {}).get("answer_text_hash", "")

    # Same query but different answer → equivocation attempt
    is_equivocation = (orig_qh == equiv_qh) and (orig_ah != equiv_ah)

    if not is_equivocation:
        return False  # Not actually equivocating

    # Detection depends on transparency log
    if transparency_enabled:
        # The log would contain both entries for the same query_hash,
        # allowing an auditor to discover the conflicting certificates.
        return True
    else:
        # Without a transparency log, neither party can discover
        # the other certificate exists — equivocation goes undetected.
        return False
