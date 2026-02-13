"""
PCRAG FastAPI server.

Endpoints:
  POST /pcrag/answer          — run pipeline, return signed certificate
  POST /pcrag/verify          — verify a certificate + signature
  GET  /pcrag/evidence-bundle/{certificate_id}  — get evidence bundle
"""

from __future__ import annotations

import base64
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from core.canonicalize import canonicalize
from core.crypto import (
    generate_keypair,
    load_public_key_b64,
    public_key_b64,
    sha256_hex,
    verify_json,
)
from core.pipeline import PCRAGPipeline, PipelineConfig
from core.schema import AnswerCertificate, RenderPolicy

from .models import (
    AnswerRequest,
    AnswerResponse,
    BlockedClaim,
    EvidenceBundleResponse,
    VerifyRequest,
    VerifyResponse,
)

app = FastAPI(
    title="PCRAG — Proof-Carrying RAG",
    description="RAG with cryptographic evidence certificates",
    version="0.1.0",
)

# CORS for React renderer
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global state (single pipeline instance for MVP)
# ---------------------------------------------------------------------------
_pipeline: PCRAGPipeline | None = None
_certificate_store: dict[str, dict] = {}  # certificate_id → signed cert dict


def get_pipeline() -> PCRAGPipeline:
    global _pipeline
    if _pipeline is None:
        import os
        has_llm = bool(os.environ.get("GROQ_API_KEY"))
        config = PipelineConfig(
            use_llm_generation=has_llm,
            use_llm_claims=has_llm,
            use_embedding_spans=has_llm,   # embeddings don't need API key but keep parity
            verifier_mode="nli" if has_llm else "heuristic",
            retrieval_mode="hybrid" if has_llm else "bm25",
            enable_transparency=True,
            enable_signing=True,
        )
        _pipeline = PCRAGPipeline(config=config)
    return _pipeline


# ---------------------------------------------------------------------------
# POST /pcrag/answer
# ---------------------------------------------------------------------------

@app.post("/pcrag/answer", response_model=AnswerResponse)
async def answer(req: AnswerRequest):
    """Run the PCRAG pipeline and return a signed certificate."""
    pipeline = get_pipeline()

    policy = req.policy or pipeline.policy
    signed, metrics = pipeline.answer(req.query, top_k=req.top_k, policy=policy)

    # Convert certificate to dict for JSON response
    cert_dict = signed.certificate.model_dump(mode="python")

    # Store for evidence-bundle endpoint
    cert_id = signed.certificate.certificate_id
    _certificate_store[cert_id] = {
        "certificate": cert_dict,
        "signature": signed.signature,
    }

    return AnswerResponse(
        answer_text=signed.certificate.answer_commitment.answer_text,
        certificate=cert_dict,
        signature=signed.signature,
        public_key=public_key_b64(pipeline.keypair.public_key),
    )


# ---------------------------------------------------------------------------
# POST /pcrag/verify
# ---------------------------------------------------------------------------

@app.post("/pcrag/verify", response_model=VerifyResponse)
async def verify(req: VerifyRequest):
    """Verify a certificate signature and internal hash commitments."""
    errors: list[str] = []
    renderable: list[str] = []
    blocked: list[BlockedClaim] = []

    # 1. Verify Ed25519 signature
    try:
        pk = load_public_key_b64(req.public_key)
        sig_valid = verify_json(req.certificate, req.signature, pk)
    except Exception as e:
        sig_valid = False
        errors.append(f"Signature verification error: {e}")

    if not sig_valid:
        errors.append("Ed25519 signature is INVALID")

    # 2. Grab the certificate dict for inspection
    cert = req.certificate

    # 2a. Replay detection — if query provided, check query_hash
    if req.query is not None:
        expected_qhash = sha256_hex(req.query.strip().lower())
        actual_qhash = cert.get("query_commitment", {}).get("query_hash", "")
        if expected_qhash != actual_qhash:
            errors.append(
                f"Replay detected: query_hash mismatch "
                f"(cert={actual_qhash[:16]}..., query={expected_qhash[:16]}...)"
            )

    # 3. Verify internal hash commitments
    commitments_valid = True

    # 2a. Answer text hash
    answer_text = cert.get("answer_commitment", {}).get("answer_text", "")
    expected_hash = cert.get("answer_commitment", {}).get("answer_text_hash", "")
    if answer_text and expected_hash:
        actual = sha256_hex(answer_text)
        if actual != expected_hash:
            commitments_valid = False
            errors.append(f"Answer text hash mismatch: expected {expected_hash}, got {actual}")

    # 2b. Claim hashes + span hashes
    policy = cert.get("policy", {})
    conf_threshold = policy.get("confidence_threshold", 0.5)

    for claim in cert.get("claims", []):
        cid = claim.get("claim_id", "?")
        claim_text = claim.get("claim_text", "")
        claim_hash = claim.get("claim_hash", "")

        # Check claim hash
        if claim_text and claim_hash:
            actual = sha256_hex(claim_text)
            if actual != claim_hash:
                commitments_valid = False
                errors.append(f"Claim {cid} hash mismatch")
                blocked.append(BlockedClaim(claim_id=cid, reason="HASH_MISMATCH"))
                continue

        # Check span hashes
        span_ok = True
        for span in claim.get("evidence_spans", []):
            s_text = span.get("span_text", "")
            s_hash = span.get("span_hash", "")
            if s_text and s_hash:
                actual = sha256_hex(s_text)
                if actual != s_hash:
                    commitments_valid = False
                    span_ok = False
                    errors.append(f"Span {span.get('span_id', '?')} hash mismatch in claim {cid}")

        if not span_ok:
            blocked.append(BlockedClaim(claim_id=cid, reason="HASH_MISMATCH"))
            continue

        # Check render decision
        rd = claim.get("render_decision", {})
        verif = claim.get("verification", {})
        label = verif.get("label", "")
        conf = verif.get("confidence", 0.0)

        if rd.get("rendered") and label == "entailed" and conf >= conf_threshold:
            renderable.append(cid)
        else:
            reason = rd.get("reason_code", "NOT_SUPPORTED")
            blocked.append(BlockedClaim(claim_id=cid, reason=reason))

    return VerifyResponse(
        valid_signature=sig_valid,
        valid_commitments=commitments_valid,
        renderable_claims=renderable,
        blocked_claims=blocked,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# GET /pcrag/evidence-bundle/{certificate_id}
# ---------------------------------------------------------------------------

@app.get("/pcrag/evidence-bundle/{certificate_id}", response_model=EvidenceBundleResponse)
async def evidence_bundle(certificate_id: str):
    """Return evidence spans and source docs for a certificate."""
    stored = _certificate_store.get(certificate_id)
    if not stored:
        raise HTTPException(status_code=404, detail="Certificate not found")

    cert = stored["certificate"]
    spans = []
    docs = []
    seen_docs = set()

    for claim in cert.get("claims", []):
        for span in claim.get("evidence_spans", []):
            spans.append({
                "span_id": span["span_id"],
                "claim_id": claim["claim_id"],
                "doc_id": span["doc_id"],
                "span_text": span["span_text"],
                "span_hash": span["span_hash"],
            })
            doc_id = span["doc_id"]
            if doc_id not in seen_docs:
                seen_docs.add(doc_id)
                # Find doc info in retrieval commitment
                for item in cert.get("retrieval_commitment", {}).get("retrieved_items", []):
                    if item["doc_id"] == doc_id:
                        docs.append(item)
                        break

    return EvidenceBundleResponse(
        certificate_id=certificate_id,
        spans=spans,
        documents=docs,
    )


# ---------------------------------------------------------------------------
# GET /pcrag/transparency/sth — get signed tree head
# ---------------------------------------------------------------------------

@app.get("/pcrag/transparency/sth")
async def get_sth():
    """Return the current Signed Tree Head from the transparency log."""
    pipeline = get_pipeline()
    if pipeline.transparency_log is None:
        raise HTTPException(status_code=404, detail="Transparency log not enabled")
    sth = pipeline.transparency_log.get_signed_tree_head()
    return sth.to_dict()


# ---------------------------------------------------------------------------
# GET /pcrag/transparency/proof/{leaf_index} — inclusion proof
# ---------------------------------------------------------------------------

@app.get("/pcrag/transparency/proof/{leaf_index}")
async def get_inclusion_proof(leaf_index: int):
    """Return an inclusion proof for a given leaf index."""
    pipeline = get_pipeline()
    if pipeline.transparency_log is None:
        raise HTTPException(status_code=404, detail="Transparency log not enabled")
    try:
        proof = pipeline.transparency_log.get_inclusion_proof(leaf_index)
        return proof.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------------------------------------------------------------------
# Serve React renderer static files (if built)
# ---------------------------------------------------------------------------

_renderer_dist = Path(__file__).parent.parent / "renderer_web" / "dist"
if _renderer_dist.exists():
    app.mount("/", StaticFiles(directory=str(_renderer_dist), html=True), name="renderer")
