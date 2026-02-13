"""
Embedding module for PCRAG.

Provides sentence-level embeddings using sentence-transformers for:
  1. Semantic retrieval (hybrid BM25 + dense)
  2. Evidence span alignment (claim ↔ span similarity)

Uses all-MiniLM-L6-v2 by default (fast, 384-dim, good quality).
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "all-MiniLM-L6-v2"


class EmbeddingModel:
    """
    Sentence embedding model wrapper.

    Lazily loads the model on first use to avoid import-time overhead.
    Thread-safe via the underlying sentence-transformers implementation.
    """

    def __init__(self, model_name: str = DEFAULT_MODEL):
        self.model_name = model_name
        self._model = None

    def _load(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading embedding model: {self.model_name}")
            self._model = SentenceTransformer(self.model_name)
        return self._model

    def encode(
        self,
        texts: list[str],
        batch_size: int = 64,
        normalize: bool = True,
    ) -> np.ndarray:
        """
        Encode texts into dense vectors.

        Args:
            texts: List of strings to encode.
            batch_size: Batch size for encoding.
            normalize: Whether to L2-normalize embeddings.

        Returns:
            np.ndarray of shape (len(texts), embedding_dim)
        """
        if not texts:
            return np.array([])

        model = self._load()
        embeddings = model.encode(
            texts,
            batch_size=batch_size,
            normalize_embeddings=normalize,
            show_progress_bar=False,
        )
        return np.array(embeddings)

    def similarity(
        self,
        query_texts: list[str],
        candidate_texts: list[str],
    ) -> np.ndarray:
        """
        Compute cosine similarity between query and candidate texts.

        Args:
            query_texts: List of query strings.
            candidate_texts: List of candidate strings.

        Returns:
            np.ndarray of shape (len(query_texts), len(candidate_texts))
        """
        if not query_texts or not candidate_texts:
            return np.array([[]])

        q_embs = self.encode(query_texts)
        c_embs = self.encode(candidate_texts)

        # Cosine similarity (embeddings are already L2-normalized)
        return q_embs @ c_embs.T

    @property
    def embedding_dim(self) -> int:
        """Return the dimensionality of embeddings."""
        model = self._load()
        return model.get_sentence_embedding_dimension()


# ── Module-level singleton ──────────────────────────────────────────────────

_default_model: EmbeddingModel | None = None


def get_embedding_model(model_name: str = DEFAULT_MODEL) -> EmbeddingModel:
    """Get or create the default embedding model (singleton)."""
    global _default_model
    if _default_model is None or _default_model.model_name != model_name:
        _default_model = EmbeddingModel(model_name)
    return _default_model
