"""
End-to-end PCRAG pipeline.

Orchestrates: retrieve → generate (LLM) → extract claims (LLM) →
              select spans (embeddings) → verify (NLI) → build certificate → sign.

Supports configurable component selection for ablation studies:
  - LLM vs. heuristic answer generation
  - LLM vs. regex claim decomposition
  - Embedding vs. Jaccard span selection
  - NLI vs. heuristic verification
  - BM25 vs. dense vs. hybrid retrieval
  - With/without transparency log
  - With/without signing
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .certificate import build_certificate, build_claim_record, build_span_record
from .claims import extract_claims
from .crypto import KeyPair, sha256_hex
from .retriever import SimpleRetriever, Document, get_demo_retriever
from .schema import (
    RenderPolicy,
    RetrievalCommitment,
    RetrievedItemCommitment,
    SignedCertificate,
    TransparencyRecord,
)
from .spans import DocumentChunk, select_evidence_spans
from .transparency import MerkleLog
from .verifier_nli import HeuristicVerifier, make_verification

logger = logging.getLogger(__name__)


# ── Pipeline configuration ──────────────────────────────────────────────────

@dataclass
class PipelineConfig:
    """
    Configuration for the PCRAG pipeline.

    Controls which components are used, enabling ablation studies.
    """
    # LLM settings
    use_llm_generation: bool = True     # True = Groq LLM; False = heuristic concat
    use_llm_claims: bool = True         # True = LLM decomposition; False = regex
    llm_model: str = "llama-3.3-70b-versatile"

    # Retrieval settings
    retrieval_mode: str = "hybrid"      # "bm25", "dense", or "hybrid"

    # Span selection
    use_embedding_spans: bool = True    # True = semantic; False = Jaccard

    # Verification
    verifier_mode: str = "nli"          # "nli" or "heuristic"

    # Transparency
    enable_transparency: bool = True

    # Signing
    enable_signing: bool = True         # False = ablation without signing

    # Policy
    confidence_threshold: float = 0.5

    @property
    def config_name(self) -> str:
        """Human-readable config name for reporting."""
        parts = []
        parts.append(f"gen={'llm' if self.use_llm_generation else 'heur'}")
        parts.append(f"claims={'llm' if self.use_llm_claims else 'regex'}")
        parts.append(f"ret={self.retrieval_mode}")
        parts.append(f"spans={'emb' if self.use_embedding_spans else 'jacc'}")
        parts.append(f"ver={self.verifier_mode}")
        parts.append(f"sign={'on' if self.enable_signing else 'off'}")
        parts.append(f"tlog={'on' if self.enable_transparency else 'off'}")
        return " | ".join(parts)


# ── Pipeline latency tracking ──────────────────────────────────────────────

@dataclass
class PipelineMetrics:
    """Latency breakdown for a single pipeline run."""
    retrieval_ms: float = 0.0
    generation_ms: float = 0.0
    claim_extraction_ms: float = 0.0
    span_selection_ms: float = 0.0
    verification_ms: float = 0.0
    certificate_build_ms: float = 0.0
    signing_ms: float = 0.0
    transparency_ms: float = 0.0
    total_ms: float = 0.0

    # LLM usage tracking
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ── Main pipeline ───────────────────────────────────────────────────────────

class PCRAGPipeline:
    """
    The main PCRAG pipeline — production-grade with full component stack.

    Components:
      - Retriever: Hybrid BM25 + dense (sentence-transformers)
      - Generator: Groq LLM (Llama-3.3-70B)
      - Claim extractor: LLM-based atomic decomposition
      - Span selector: Embedding-based semantic alignment
      - Verifier: DeBERTa NLI model
      - Certificate: JCS + Ed25519
      - Transparency: Merkle log with inclusion proofs
    """

    def __init__(
        self,
        retriever: SimpleRetriever | None = None,
        verifier=None,
        keypair: KeyPair | None = None,
        policy: RenderPolicy | None = None,
        config: PipelineConfig | None = None,
        enable_transparency: bool = True,
    ):
        from .crypto import generate_keypair

        self.config = config or PipelineConfig(
            enable_transparency=enable_transparency,
        )
        self.retriever = retriever or get_demo_retriever()
        self.keypair = keypair or generate_keypair()
        self.policy = policy or RenderPolicy(
            confidence_threshold=self.config.confidence_threshold,
        )

        # Set up verifier
        if verifier is not None:
            self.verifier = verifier
        elif self.config.verifier_mode == "nli":
            from .verifier_nli import get_verifier
            self.verifier = get_verifier("nli")
        else:
            self.verifier = HeuristicVerifier()

        # Set up LLM client (lazy — only created when needed)
        self._llm_client = None

        # Set up embedding model (lazy)
        self._embedding_model = None

        # Transparency log
        self.transparency_log: MerkleLog | None = None
        if self.config.enable_transparency:
            self.transparency_log = MerkleLog(self.keypair)

    @property
    def llm_client(self):
        if self._llm_client is None and (
            self.config.use_llm_generation or self.config.use_llm_claims
        ):
            from .llm import LLMClient
            self._llm_client = LLMClient()
        return self._llm_client

    @property
    def embedding_model(self):
        if self._embedding_model is None and self.config.use_embedding_spans:
            from .embeddings import get_embedding_model
            self._embedding_model = get_embedding_model()
        return self._embedding_model

    def answer(
        self,
        query: str,
        top_k: int = 5,
        policy: RenderPolicy | None = None,
    ) -> tuple[SignedCertificate, PipelineMetrics]:
        """
        Run the full pipeline.

        Returns:
            Tuple of (SignedCertificate, PipelineMetrics).
        """
        t_total = time.perf_counter()
        policy = policy or self.policy
        metrics = PipelineMetrics()

        # 1. Retrieve
        t0 = time.perf_counter()
        chunks = self.retriever.retrieve(query, top_k=top_k)
        metrics.retrieval_ms = (time.perf_counter() - t0) * 1000

        # 2. Generate answer
        t0 = time.perf_counter()
        if self.config.use_llm_generation and self.llm_client:
            evidence_texts = [c.text for c in chunks]
            llm_resp = self.llm_client.generate_answer(query, evidence_texts)
            answer_text = llm_resp.text
            metrics.prompt_tokens += llm_resp.prompt_tokens
            metrics.completion_tokens += llm_resp.completion_tokens
        else:
            answer_text = self._generate_answer_heuristic(query, chunks)
        metrics.generation_ms = (time.perf_counter() - t0) * 1000

        # 3. Extract claims
        t0 = time.perf_counter()
        claim_texts = extract_claims(
            answer_text,
            use_llm=self.config.use_llm_claims,
            llm_client=self.llm_client,
        )
        metrics.claim_extraction_ms = (time.perf_counter() - t0) * 1000

        # 4–5. For each claim: select spans + verify
        t0_spans = time.perf_counter()
        t_verify_total = 0.0
        claim_records = []

        for claim_text in claim_texts:
            # Select evidence spans
            span_results = select_evidence_spans(
                claim_text, chunks,
                max_spans=3,
                use_embeddings=self.config.use_embedding_spans,
                embedding_model=self.embedding_model,
            )

            # Build SpanRecords
            span_records = [
                build_span_record(
                    doc_id=chunk.doc_id,
                    span_text=span_text,
                    start_offset=start,
                    end_offset=end,
                    alignment_score=score,
                    chunk_id=chunk.chunk_id,
                )
                for chunk, span_text, score, start, end in span_results
            ]

            # Verify claim against evidence
            t_v = time.perf_counter()
            evidence_texts = [s.span_text for s in span_records]
            verification = make_verification(
                claim_text, evidence_texts, self.verifier
            )
            t_verify_total += time.perf_counter() - t_v

            # Build ClaimRecord with render decision
            claim_record = build_claim_record(
                claim_text, span_records, verification, policy
            )
            claim_records.append(claim_record)

        metrics.span_selection_ms = (time.perf_counter() - t0_spans) * 1000 - t_verify_total * 1000
        metrics.verification_ms = t_verify_total * 1000

        # 6. Build retrieval commitment
        t0 = time.perf_counter()
        retrieval_time = datetime.now(timezone.utc).isoformat()
        retrieval_commitment = RetrievalCommitment(
            retrieval_time=retrieval_time,
            retrieved_items=[
                RetrievedItemCommitment(
                    doc_id=c.doc_id,
                    source_uri=c.source_uri,
                    content_hash=sha256_hex(c.text),
                    metadata_hash=sha256_hex(
                        json.dumps(c.metadata or {}, sort_keys=True)
                    ),
                    snapshot_time=retrieval_time,
                    content_excerpt=c.text[:200],
                )
                for c in chunks
            ],
        )

        # 7. Build & sign certificate
        signed_cert = build_certificate(
            query=query,
            answer_text=answer_text,
            claims=claim_records,
            retrieval_commitment=retrieval_commitment,
            keypair=self.keypair,
            policy=policy,
            sign=self.config.enable_signing,
        )
        metrics.certificate_build_ms = (time.perf_counter() - t0) * 1000

        # 8. Record in transparency log (if enabled)
        if self.transparency_log is not None:
            t0 = time.perf_counter()
            cert = signed_cert.certificate
            leaf_idx = self.transparency_log.append_certificate(
                signature=signed_cert.signature,
                certificate_id=cert.certificate_id,
                issued_at=cert.issued_at,
            )
            proof = self.transparency_log.get_inclusion_proof(leaf_idx)
            sth = self.transparency_log.get_signed_tree_head()
            cert.transparency = TransparencyRecord(
                log_id="pcrag-merkle-log-v1",
                leaf_hash=self.transparency_log._leaves[leaf_idx],
                inclusion_proof=proof.hashes,
                signed_tree_head=json.dumps(sth.to_dict()),
            )
            # Re-sign after adding transparency record
            from .crypto import sign_json
            cert_dict = cert.model_dump(mode="python")
            signed_cert.signature = sign_json(cert_dict, self.keypair.private_key)
            metrics.transparency_ms = (time.perf_counter() - t0) * 1000

        metrics.total_ms = (time.perf_counter() - t_total) * 1000

        return signed_cert, metrics

    def _generate_answer_heuristic(
        self, query: str, chunks: list[DocumentChunk]
    ) -> str:
        """
        Heuristic answer generation: compile relevant sentences from chunks.
        Used as fallback when LLM is not available, or for ablation baseline.
        """
        if not chunks:
            return "No relevant information found."

        sentences = []
        for chunk in chunks[:3]:
            chunk_sentences = re.split(r'(?<=[.!?])\s+', chunk.text)
            sentences.extend(chunk_sentences[:3])

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for s in sentences:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return " ".join(unique[:6])
