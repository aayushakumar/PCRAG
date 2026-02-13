"""
Evidence span selection — find the best matching spans in retrieved documents
for each extracted claim.

Two modes:
  1. Embedding-based (sentence-transformers) — semantic similarity, used in prod.
  2. Jaccard word-overlap — fast fallback for tests / ablation baseline.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DocumentChunk:
    """A retrieved document chunk."""
    doc_id: str
    chunk_id: str
    text: str
    source_uri: str = ""
    metadata: dict | None = None


def _tokenize(text: str) -> set[str]:
    """Simple whitespace + lowercase tokenizer."""
    return set(re.findall(r'\b\w+\b', text.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _sentence_split(text: str) -> list[str]:
    """Split text into sentences."""
    sentences = re.split(r'(?<=[.!?])\s+', text)
    return [s.strip() for s in sentences if s.strip()]


def select_evidence_spans_jaccard(
    claim: str,
    chunks: list[DocumentChunk],
    max_spans: int = 3,
    min_score: float = 0.05,
) -> list[tuple[DocumentChunk, str, float, int, int]]:
    """
    Select evidence spans using Jaccard word overlap (heuristic baseline).

    Returns list of (chunk, span_text, score, start_offset, end_offset).
    """
    claim_tokens = _tokenize(claim)
    if not claim_tokens:
        return []

    candidates: list[tuple[DocumentChunk, str, float, int, int]] = []

    for chunk in chunks:
        sentences = _sentence_split(chunk.text)
        offset = 0
        for sent in sentences:
            start = chunk.text.find(sent, offset)
            if start == -1:
                start = offset
            end = start + len(sent)
            offset = end

            sent_tokens = _tokenize(sent)
            score = _jaccard(claim_tokens, sent_tokens)

            if score >= min_score:
                candidates.append((chunk, sent, score, start, end))

    candidates.sort(key=lambda x: x[2], reverse=True)
    return candidates[:max_spans]


def select_evidence_spans_embedding(
    claim: str,
    chunks: list[DocumentChunk],
    max_spans: int = 3,
    min_score: float = 0.25,
    embedding_model=None,
) -> list[tuple[DocumentChunk, str, float, int, int]]:
    """
    Select evidence spans using semantic embedding similarity.

    Uses sentence-transformers (all-MiniLM-L6-v2) for cosine similarity
    between claim and candidate evidence sentences.

    Returns list of (chunk, span_text, score, start_offset, end_offset).
    """
    if embedding_model is None:
        from .embeddings import get_embedding_model
        embedding_model = get_embedding_model()

    # Collect all candidate sentences with metadata
    candidates_meta: list[tuple[DocumentChunk, str, int, int]] = []
    candidate_texts: list[str] = []

    for chunk in chunks:
        sentences = _sentence_split(chunk.text)
        offset = 0
        for sent in sentences:
            start = chunk.text.find(sent, offset)
            if start == -1:
                start = offset
            end = start + len(sent)
            offset = end
            candidates_meta.append((chunk, sent, start, end))
            candidate_texts.append(sent)

    if not candidate_texts:
        return []

    # Compute semantic similarity
    sim_matrix = embedding_model.similarity([claim], candidate_texts)
    scores = sim_matrix[0]  # shape: (num_candidates,)

    # Rank by similarity and filter
    ranked = sorted(
        range(len(scores)),
        key=lambda i: float(scores[i]),
        reverse=True,
    )

    results = []
    for idx in ranked:
        score = float(scores[idx])
        if score < min_score:
            break
        chunk, sent, start, end = candidates_meta[idx]
        results.append((chunk, sent, score, start, end))
        if len(results) >= max_spans:
            break

    return results


def select_evidence_spans(
    claim: str,
    chunks: list[DocumentChunk],
    max_spans: int = 3,
    min_score: float = 0.05,
    use_embeddings: bool = False,
    embedding_model=None,
) -> list[tuple[DocumentChunk, str, float, int, int]]:
    """
    Select the best evidence spans for a claim from retrieved chunks.

    Args:
        claim: The claim text to find evidence for.
        chunks: List of retrieved document chunks.
        max_spans: Maximum number of spans to return.
        min_score: Minimum similarity score threshold.
        use_embeddings: If True, use embedding similarity; else Jaccard.
        embedding_model: Optional pre-loaded EmbeddingModel.

    Returns:
        List of (chunk, span_text, score, start_offset, end_offset).
    """
    if use_embeddings:
        return select_evidence_spans_embedding(
            claim, chunks, max_spans,
            min_score=max(min_score, 0.25),  # higher threshold for embeddings
            embedding_model=embedding_model,
        )
    return select_evidence_spans_jaccard(
        claim, chunks, max_spans, min_score
    )
