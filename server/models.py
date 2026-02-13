"""Request/response models for the PCRAG API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from core.schema import RenderPolicy, SignedCertificate


# ---------------------------------------------------------------------------
# POST /pcrag/answer
# ---------------------------------------------------------------------------

class AnswerRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    policy: Optional[RenderPolicy] = None
    top_k: int = Field(default=5, ge=1, le=20)


class AnswerResponse(BaseModel):
    answer_text: str
    certificate: dict  # raw certificate dict (for JSON response)
    signature: str
    public_key: str  # base64 public key for verification


# ---------------------------------------------------------------------------
# POST /pcrag/verify
# ---------------------------------------------------------------------------

class VerifyRequest(BaseModel):
    certificate: dict
    signature: str = Field(..., min_length=1)
    public_key: str = Field(..., min_length=1)  # base64 Ed25519 public key
    query: Optional[str] = Field(default=None, max_length=2000)  # For replay detection


class BlockedClaim(BaseModel):
    claim_id: str
    reason: str


class VerifyResponse(BaseModel):
    valid_signature: bool
    valid_commitments: bool
    renderable_claims: list[str]
    blocked_claims: list[BlockedClaim]
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# GET /pcrag/evidence-bundle/{certificate_id}
# ---------------------------------------------------------------------------

class EvidenceBundleResponse(BaseModel):
    certificate_id: str
    spans: list[dict]
    documents: list[dict]
