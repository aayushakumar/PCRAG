"""
Document retriever for PCRAG.

Supports three retrieval modes:
  1. BM25 (lexical) — fast, no model needed
  2. Dense (embedding-based) — semantic similarity
  3. Hybrid (BM25 + Dense fusion) — best quality, used in production

Hybrid retrieval uses Reciprocal Rank Fusion (RRF) to combine BM25 and
dense retrieval scores, following best practices from modern RAG systems.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import numpy as np
from rank_bm25 import BM25Okapi

from .spans import DocumentChunk

logger = logging.getLogger(__name__)


@dataclass
class Document:
    """A source document in the knowledge base."""
    doc_id: str
    title: str
    text: str
    source_uri: str = ""
    metadata: dict = field(default_factory=dict)


class SimpleRetriever:
    """
    Hybrid document retriever with BM25 + dense retrieval.

    Supports three modes controlled by `retrieval_mode`:
      - "bm25": Lexical retrieval only (BM25Okapi)
      - "dense": Semantic retrieval only (sentence-transformers)
      - "hybrid": Reciprocal Rank Fusion of BM25 + dense (default)
    """

    def __init__(
        self,
        documents: list[Document] | None = None,
        retrieval_mode: str = "hybrid",
        embedding_model=None,
    ):
        self._documents: list[Document] = []
        self._chunks: list[DocumentChunk] = []
        self._bm25: BM25Okapi | None = None
        self._chunk_embeddings: np.ndarray | None = None
        self._embedding_model = embedding_model
        self.retrieval_mode = retrieval_mode
        if documents:
            self.index(documents)

    def _chunk_document(self, doc: Document, chunk_size: int = 500) -> list[DocumentChunk]:
        """Split document into sentence-aware chunks."""
        sentences = re.split(r'(?<=[.!?])\s+', doc.text)
        chunks: list[DocumentChunk] = []
        current: list[str] = []
        current_len = 0

        for sent in sentences:
            if current_len + len(sent) > chunk_size and current:
                chunk_text = " ".join(current)
                chunks.append(DocumentChunk(
                    doc_id=doc.doc_id,
                    chunk_id=f"{doc.doc_id}_c{len(chunks)}",
                    text=chunk_text,
                    source_uri=doc.source_uri,
                    metadata=doc.metadata,
                ))
                current = []
                current_len = 0
            current.append(sent)
            current_len += len(sent)

        if current:
            chunk_text = " ".join(current)
            chunks.append(DocumentChunk(
                doc_id=doc.doc_id,
                chunk_id=f"{doc.doc_id}_c{len(chunks)}",
                text=chunk_text,
                source_uri=doc.source_uri,
                metadata=doc.metadata,
            ))

        return chunks

    def index(self, documents: list[Document]) -> None:
        """Index documents for retrieval."""
        self._documents = documents
        self._chunks = []
        for doc in documents:
            self._chunks.extend(self._chunk_document(doc))

        # Build BM25 index
        tokenized = [re.findall(r'\b\w+\b', c.text.lower()) for c in self._chunks]
        if tokenized:
            self._bm25 = BM25Okapi(tokenized)

        # Build dense index if needed
        if self.retrieval_mode in ("dense", "hybrid") and self._chunks:
            self._build_dense_index()

    def _build_dense_index(self) -> None:
        """Build the dense embedding index for all chunks."""
        if self._embedding_model is None:
            from .embeddings import get_embedding_model
            self._embedding_model = get_embedding_model()

        chunk_texts = [c.text for c in self._chunks]
        self._chunk_embeddings = self._embedding_model.encode(chunk_texts)
        logger.info(f"Built dense index with {len(chunk_texts)} chunks")

    def retrieve(self, query: str, top_k: int = 5) -> list[DocumentChunk]:
        """Retrieve top-k chunks for a query using the configured mode."""
        if not self._chunks:
            return []

        if self.retrieval_mode == "bm25":
            return self._retrieve_bm25(query, top_k)
        elif self.retrieval_mode == "dense":
            return self._retrieve_dense(query, top_k)
        else:  # hybrid
            return self._retrieve_hybrid(query, top_k)

    def _retrieve_bm25(self, query: str, top_k: int) -> list[DocumentChunk]:
        """BM25 lexical retrieval."""
        if not self._bm25:
            return []

        query_tokens = re.findall(r'\b\w+\b', query.lower())
        scores = self._bm25.get_scores(query_tokens)

        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        results = []
        for idx in ranked[:top_k]:
            if scores[idx] > 0:
                results.append(self._chunks[idx])

        return results

    def _retrieve_dense(self, query: str, top_k: int) -> list[DocumentChunk]:
        """Dense embedding-based retrieval."""
        if self._chunk_embeddings is None or len(self._chunk_embeddings) == 0:
            return []

        if self._embedding_model is None:
            from .embeddings import get_embedding_model
            self._embedding_model = get_embedding_model()

        query_emb = self._embedding_model.encode([query])
        scores = (query_emb @ self._chunk_embeddings.T)[0]

        ranked = sorted(range(len(scores)), key=lambda i: float(scores[i]), reverse=True)
        results = []
        for idx in ranked[:top_k]:
            if float(scores[idx]) > 0:
                results.append(self._chunks[idx])

        return results

    def _retrieve_hybrid(self, query: str, top_k: int) -> list[DocumentChunk]:
        """
        Hybrid retrieval using Reciprocal Rank Fusion (RRF).

        Combines BM25 and dense retrieval rankings using:
          RRF_score(d) = 1/(k + rank_bm25(d)) + 1/(k + rank_dense(d))
        where k=60 (standard RRF constant).
        """
        k = 60  # RRF constant

        # Get BM25 ranking
        bm25_results = self._retrieve_bm25(query, top_k=top_k * 2)
        bm25_ranks = {id(chunk): rank for rank, chunk in enumerate(bm25_results)}

        # Get dense ranking
        dense_results = self._retrieve_dense(query, top_k=top_k * 2)
        dense_ranks = {id(chunk): rank for rank, chunk in enumerate(dense_results)}

        # Compute RRF scores for all unique chunks
        all_chunks = {}
        for chunk in bm25_results + dense_results:
            cid = id(chunk)
            if cid not in all_chunks:
                all_chunks[cid] = chunk

        rrf_scores = {}
        for cid, chunk in all_chunks.items():
            score = 0.0
            if cid in bm25_ranks:
                score += 1.0 / (k + bm25_ranks[cid])
            if cid in dense_ranks:
                score += 1.0 / (k + dense_ranks[cid])
            rrf_scores[cid] = score

        # Sort by RRF score
        ranked = sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True)
        return [all_chunks[cid] for cid in ranked[:top_k]]


# ---------------------------------------------------------------------------
# Built-in demo corpus
# ---------------------------------------------------------------------------

DEMO_DOCUMENTS = [
    Document(
        doc_id="wiki_python",
        title="Python (programming language)",
        text=(
            "Python is a high-level, general-purpose programming language. "
            "Its design philosophy emphasizes code readability with the use of significant indentation. "
            "Python is dynamically typed and garbage-collected. "
            "It supports multiple programming paradigms, including structured, object-oriented and functional programming. "
            "It was created by Guido van Rossum and first released in 1991. "
            "Python consistently ranks as one of the most popular programming languages."
        ),
        source_uri="https://en.wikipedia.org/wiki/Python_(programming_language)",
    ),
    Document(
        doc_id="wiki_rsa",
        title="RSA (cryptosystem)",
        text=(
            "RSA is a public-key cryptosystem, one of the oldest widely used for secure data transmission. "
            "The acronym RSA comes from the surnames of Ron Rivest, Adi Shamir and Leonard Adleman. "
            "A user of RSA creates and publishes a public key based on two large prime numbers, along with an auxiliary value. "
            "The prime numbers are kept secret. Messages can be encrypted by anyone, via the public key, "
            "but can only be decoded by someone who knows the prime factors. "
            "The security of RSA relies on the practical difficulty of factoring the product of two large prime numbers."
        ),
        source_uri="https://en.wikipedia.org/wiki/RSA_(cryptosystem)",
    ),
    Document(
        doc_id="wiki_sha256",
        title="SHA-2",
        text=(
            "SHA-2 is a set of cryptographic hash functions designed by the United States National Security Agency (NSA). "
            "SHA-256 is one of the hash functions in the SHA-2 family, generating a 256-bit (32-byte) hash value. "
            "It is widely used in security applications and protocols, including TLS, SSL, PGP, SSH, and Bitcoin. "
            "SHA-256 is a one-way function: it is practically infeasible to reverse the process and recover the original data. "
            "A small change in the input produces an entirely different hash output, known as the avalanche effect."
        ),
        source_uri="https://en.wikipedia.org/wiki/SHA-2",
    ),
    Document(
        doc_id="wiki_ed25519",
        title="EdDSA - Ed25519",
        text=(
            "Ed25519 is a public-key signature system based on the Edwards-curve Digital Signature Algorithm (EdDSA). "
            "It uses SHA-512 and Curve25519. "
            "Ed25519 is designed to be faster than existing digital signature schemes without sacrificing security. "
            "It was developed by Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang. "
            "Ed25519 produces 64-byte signatures and uses 32-byte public keys. "
            "It is deterministic: signing the same message with the same key always produces the same signature."
        ),
        source_uri="https://en.wikipedia.org/wiki/EdDSA",
    ),
    Document(
        doc_id="wiki_ct",
        title="Certificate Transparency",
        text=(
            "Certificate Transparency (CT) is an Internet security standard for monitoring and auditing digital certificates. "
            "It creates an open framework of logs, monitors, and auditors that lets any domain owner or CA determine "
            "whether certificates have been mistakenly or maliciously issued. "
            "CT uses Merkle trees to provide an append-only log of certificates. "
            "Browsers can require CT compliance and refuse to accept certificates not logged in CT. "
            "This is defined in RFC 6962 and its successor RFC 9162."
        ),
        source_uri="https://en.wikipedia.org/wiki/Certificate_Transparency",
    ),
]


def get_demo_retriever() -> SimpleRetriever:
    """Return a retriever loaded with the demo corpus."""
    retriever = SimpleRetriever()
    retriever.index(DEMO_DOCUMENTS)
    return retriever
