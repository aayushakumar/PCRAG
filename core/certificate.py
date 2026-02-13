"""
Certificate builder — assembles an AnswerCertificate from pipeline outputs,
applies render policy, signs the certificate, and returns a SignedCertificate.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonicalize import canonicalize
from .crypto import KeyPair, sha256_hex, sign_json
from .schema import (
    AnswerCertificate,
    AnswerCommitment,
    BlockReasonCode,
    ClaimRecord,
    Issuer,
    QueryCommitment,
    RenderDecision,
    RenderPolicy,
    RetrievalCommitment,
    RetrievedItemCommitment,
    SignedCertificate,
    SpanRecord,
    Verification,
    VerificationLabel,
)


def _make_render_decision(
    verification: Verification,
    spans: list[SpanRecord],
    policy: RenderPolicy,
) -> RenderDecision:
    """Apply fail-closed policy to determine render decision for a claim."""
    if not spans:
        return RenderDecision(rendered=False, reason_code=BlockReasonCode.NO_SPAN)
    if verification.label == VerificationLabel.CONTRADICTED:
        return RenderDecision(rendered=False, reason_code=BlockReasonCode.CONTRADICTED)
    if verification.label == VerificationLabel.NOT_SUPPORTED:
        return RenderDecision(rendered=False, reason_code=BlockReasonCode.NOT_SUPPORTED)
    if policy.require_entailed and verification.label != VerificationLabel.ENTAILED:
        return RenderDecision(rendered=False, reason_code=BlockReasonCode.NOT_SUPPORTED)
    if verification.confidence < policy.confidence_threshold:
        return RenderDecision(rendered=False, reason_code=BlockReasonCode.LOW_CONF)
    return RenderDecision(rendered=True)


def build_claim_record(
    claim_text: str,
    spans: list[SpanRecord],
    verification: Verification,
    policy: RenderPolicy,
) -> ClaimRecord:
    """Build a single ClaimRecord with hash commitment and render decision."""
    claim_hash = sha256_hex(claim_text)

    # Compute verifier_inputs_hash = SHA-256(claim_text || span_texts)
    inputs_blob = claim_text + "".join(s.span_text for s in spans)
    verification.verifier_inputs_hash = sha256_hex(inputs_blob)

    render_decision = _make_render_decision(verification, spans, policy)

    return ClaimRecord(
        claim_id=uuid.uuid4().hex[:12],
        claim_text=claim_text,
        claim_hash=claim_hash,
        evidence_spans=spans,
        verification=verification,
        render_decision=render_decision,
    )


def build_span_record(
    doc_id: str,
    span_text: str,
    start_offset: int = 0,
    end_offset: int = 0,
    alignment_score: float = 0.0,
    chunk_id: str = "",
) -> SpanRecord:
    """Build a SpanRecord with hash commitment."""
    return SpanRecord(
        span_id=uuid.uuid4().hex[:12],
        doc_id=doc_id,
        chunk_id=chunk_id,
        start_offset=start_offset,
        end_offset=end_offset,
        span_text=span_text,
        span_hash=sha256_hex(span_text),
        alignment_score=alignment_score,
    )


def build_certificate(
    query: str,
    answer_text: str,
    claims: list[ClaimRecord],
    retrieval_commitment: RetrievalCommitment,
    keypair: KeyPair,
    policy: RenderPolicy | None = None,
    session_nonce: str | None = None,
    sign: bool = True,
) -> SignedCertificate:
    """
    Build and optionally sign an AnswerCertificate.

    Steps:
      1. Compute hash commitments for query & answer.
      2. Assemble the AnswerCertificate.
      3. Canonicalize via JCS (RFC 8785).
      4. Sign with Ed25519 (if sign=True).
      5. Return SignedCertificate.

    When ``sign=False`` (ablation mode), hash commitments are computed
    normally but the signature is set to ``"unsigned"``.  This isolates
    the detection power of hash commitments from digital signatures.
    """
    if policy is None:
        policy = RenderPolicy()

    cert = AnswerCertificate(
        issuer=Issuer(
            issuer_id="pcrag-server",
            public_key_id=keypair.kid,
        ),
        query_commitment=QueryCommitment(
            query_hash=sha256_hex(query.strip().lower()),
            session_nonce=session_nonce or uuid.uuid4().hex,
        ),
        retrieval_commitment=retrieval_commitment,
        answer_commitment=AnswerCommitment(
            answer_text_hash=sha256_hex(answer_text),
            answer_text=answer_text,
        ),
        claims=claims,
        policy=policy,
    )

    if sign:
        # Sign the certificate (JCS canonical form)
        cert_dict = cert.model_dump(mode="python")
        signature_b64 = sign_json(cert_dict, keypair.private_key)
    else:
        signature_b64 = "unsigned"

    return SignedCertificate(certificate=cert, signature=signature_b64)
