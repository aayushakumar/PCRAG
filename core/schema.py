"""
PCRAG Certificate Schema — Pydantic v2 models.

Implements the certificate format defined in PRD §7:
  AnswerCertificate → ClaimRecord → SpanRecord → RetrievedItemCommitment

All hash fields use SHA-256 hex digests.
All timestamps are ISO-8601 strings.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VerificationLabel(str, Enum):
    ENTAILED = "entailed"
    CONTRADICTED = "contradicted"
    NOT_SUPPORTED = "not_supported"


class BlockReasonCode(str, Enum):
    LOW_CONF = "LOW_CONF"
    NO_SPAN = "NO_SPAN"
    CONTRADICTED = "CONTRADICTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    HASH_MISMATCH = "HASH_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class Issuer(BaseModel):
    issuer_id: str
    public_key_id: str  # kid — key identifier


class QueryCommitment(BaseModel):
    query_hash: str  # SHA-256 hex of normalised query
    session_nonce: str = Field(default_factory=lambda: uuid.uuid4().hex)


class RetrievedItemCommitment(BaseModel):
    doc_id: str
    source_uri: str = ""
    content_hash: str  # SHA-256 of canonical chunk text
    metadata_hash: str = ""  # SHA-256 of metadata JSON
    snapshot_time: str = ""
    content_excerpt: str = ""  # for offline verification


class RetrievalCommitment(BaseModel):
    retriever_id: str = "pcrag-bm25-v1"
    retriever_version: str = "0.1.0"
    retrieval_time: str = ""
    retrieved_items: list[RetrievedItemCommitment] = Field(default_factory=list)


class AnswerCommitment(BaseModel):
    answer_text_hash: str
    answer_text: str = ""  # included for self-contained verification


class SpanRecord(BaseModel):
    span_id: str
    doc_id: str
    chunk_id: str = ""
    start_offset: int = 0
    end_offset: int = 0
    span_text: str  # included for offline/drift-proof verification
    span_hash: str  # SHA-256 of span_text
    alignment_score: float = 0.0


class Verification(BaseModel):
    label: VerificationLabel
    confidence: float = Field(ge=0.0, le=1.0)
    verifier_id: str = "pcrag-nli-v1"
    verifier_version: str = "0.1.0"
    verifier_digest: str = ""
    verifier_inputs_hash: str = ""  # SHA-256(claim_text + span_texts)


class RenderDecision(BaseModel):
    rendered: bool
    reason_code: Optional[BlockReasonCode] = None


class ClaimRecord(BaseModel):
    claim_id: str
    claim_text: str
    claim_hash: str  # SHA-256 of claim_text
    evidence_spans: list[SpanRecord] = Field(default_factory=list)
    verification: Verification
    render_decision: RenderDecision


class RenderPolicy(BaseModel):
    mode: str = "fail_closed"
    confidence_threshold: float = 0.5
    require_entailed: bool = True


class TransparencyRecord(BaseModel):
    """Optional CT-style transparency log entry."""
    log_id: str = ""
    leaf_hash: str = ""
    inclusion_proof: list[str] = Field(default_factory=list)
    signed_tree_head: str = ""


# ---------------------------------------------------------------------------
# Top-level certificate
# ---------------------------------------------------------------------------

class AnswerCertificate(BaseModel):
    schema_version: str = "pcrag/1.0"
    certificate_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    issued_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    issuer: Issuer
    query_commitment: QueryCommitment
    retrieval_commitment: RetrievalCommitment = Field(
        default_factory=RetrievalCommitment
    )
    answer_commitment: AnswerCommitment
    claims: list[ClaimRecord] = Field(default_factory=list)
    policy: RenderPolicy = Field(default_factory=RenderPolicy)
    transparency: Optional[TransparencyRecord] = None


class SignedCertificate(BaseModel):
    """Certificate + detached Ed25519 signature (base64)."""
    certificate: AnswerCertificate
    signature: str  # base64-encoded Ed25519 signature over JCS bytes
