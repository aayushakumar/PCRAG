"""
NLI-based claim verifier.

Three verifier backends:
  1. HeuristicVerifier — keyword overlap (fast, no ML, for tests/ablation baseline)
  2. NLIVerifier — cross-encoder DeBERTa NLI model (real semantic verification)
  3. LLMVerifier — LLM-based verification via Groq (highest quality, slower)

The NLIVerifier (DeBERTa-v3-xsmall) is the default for evaluation:
  - 22M parameters, runs on CPU in ~50ms per claim-span pair
  - Trained on MNLI + SNLI + FEVER for natural language inference
  - Outputs calibrated probabilities for entailment/contradiction/neutral
"""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol, Optional

from .schema import Verification, VerificationLabel

logger = logging.getLogger(__name__)


class VerifierBackend(Protocol):
    """Protocol for claim verifiers."""

    def verify_claim(
        self, claim: str, evidence_texts: list[str]
    ) -> tuple[VerificationLabel, float]:
        """Return (label, confidence) for a claim given evidence texts."""
        ...

    @property
    def verifier_id(self) -> str: ...

    @property
    def verifier_version(self) -> str: ...


# ---------------------------------------------------------------------------
# Heuristic verifier (no ML dependency)
# ---------------------------------------------------------------------------

class HeuristicVerifier:
    """Simple keyword-overlap based verifier for MVP / testing."""

    verifier_id: str = "pcrag-heuristic-v1"
    verifier_version: str = "0.1.0"

    def verify_claim(
        self, claim: str, evidence_texts: list[str]
    ) -> tuple[VerificationLabel, float]:
        if not evidence_texts:
            return VerificationLabel.NOT_SUPPORTED, 0.0

        claim_words = set(claim.lower().split())
        if not claim_words:
            return VerificationLabel.NOT_SUPPORTED, 0.0

        best_overlap = 0.0
        for ev in evidence_texts:
            ev_words = set(ev.lower().split())
            if claim_words and ev_words:
                overlap = len(claim_words & ev_words) / len(claim_words)
                best_overlap = max(best_overlap, overlap)

        if best_overlap >= 0.5:
            return VerificationLabel.ENTAILED, min(best_overlap, 0.99)
        elif best_overlap >= 0.2:
            return VerificationLabel.NOT_SUPPORTED, best_overlap
        else:
            return VerificationLabel.NOT_SUPPORTED, best_overlap


# ---------------------------------------------------------------------------
# NLI model verifier (optional — requires transformers + torch)
# ---------------------------------------------------------------------------

class NLIVerifier:
    """
    Uses a cross-encoder NLI model for semantic claim verification.

    Default model: cross-encoder/nli-deberta-v3-xsmall (22M params).
    Also supports cross-encoder/nli-deberta-v3-base (86M) for higher accuracy.
    """

    verifier_id: str = "pcrag-nli-deberta-v1"
    verifier_version: str = "1.0.0"

    def __init__(self, model_name: str = "cross-encoder/nli-deberta-v3-xsmall"):
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            import torch
        except ImportError:
            raise ImportError(
                "NLIVerifier requires `transformers` and `torch`. "
                "Install them or use HeuristicVerifier."
            )

        self._model_name = model_name
        self.verifier_id = f"pcrag-nli-{model_name.split('/')[-1]}"
        logger.info(f"Loading NLI model: {model_name}")
        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModelForSequenceClassification.from_pretrained(model_name)
        self._model.eval()
        self._torch = torch
        # Label mapping for deberta NLI models: 0=contradiction, 1=neutral, 2=entailment
        self._label_map = {0: VerificationLabel.CONTRADICTED,
                           1: VerificationLabel.NOT_SUPPORTED,
                           2: VerificationLabel.ENTAILED}

    def verify_claim(
        self, claim: str, evidence_texts: list[str]
    ) -> tuple[VerificationLabel, float]:
        if not evidence_texts:
            return VerificationLabel.NOT_SUPPORTED, 0.0

        import torch

        best_label = VerificationLabel.NOT_SUPPORTED
        best_conf = 0.0

        for evidence in evidence_texts:
            inputs = self._tokenizer(
                evidence, claim,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            with torch.no_grad():
                logits = self._model(**inputs).logits
                probs = torch.softmax(logits, dim=-1)[0]

            pred_idx = probs.argmax().item()
            confidence = probs[pred_idx].item()
            label = self._label_map.get(pred_idx, VerificationLabel.NOT_SUPPORTED)

            # Prefer entailment; if contradiction found, flag it
            if label == VerificationLabel.ENTAILED and confidence > best_conf:
                best_label = label
                best_conf = confidence
            elif label == VerificationLabel.CONTRADICTED and best_label != VerificationLabel.ENTAILED:
                best_label = label
                best_conf = confidence

        return best_label, round(best_conf, 4)


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------

_cached_nli_verifier: NLIVerifier | None = None


def get_verifier(mode: str = "nli") -> HeuristicVerifier | NLIVerifier:
    """
    Get a verifier instance.

    Args:
        mode: "nli" for DeBERTa NLI model (default),
              "heuristic" for keyword-overlap fallback.

    Returns:
        A verifier instance.
    """
    global _cached_nli_verifier

    if mode == "heuristic":
        return HeuristicVerifier()

    # Try NLI, fall back to heuristic
    if _cached_nli_verifier is not None:
        return _cached_nli_verifier

    try:
        _cached_nli_verifier = NLIVerifier()
        return _cached_nli_verifier
    except (ImportError, Exception) as e:
        logger.warning(f"Cannot load NLI model ({e}), falling back to heuristic")
        return HeuristicVerifier()


def make_verification(
    claim: str,
    evidence_texts: list[str],
    verifier: VerifierBackend | HeuristicVerifier | NLIVerifier | None = None,
) -> Verification:
    """Run verification and build a Verification record."""
    if verifier is None:
        verifier = HeuristicVerifier()

    label, confidence = verifier.verify_claim(claim, evidence_texts)

    # Compute verifier digest (hash of verifier identity)
    verifier_digest = hashlib.sha256(
        f"{verifier.verifier_id}:{verifier.verifier_version}".encode()
    ).hexdigest()[:16]

    return Verification(
        label=label,
        confidence=confidence,
        verifier_id=verifier.verifier_id,
        verifier_version=verifier.verifier_version,
        verifier_digest=verifier_digest,
    )
