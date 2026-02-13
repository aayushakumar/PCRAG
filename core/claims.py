"""
Claim extraction — split an answer into atomic factual claims.

Two modes:
  1. LLM-based decomposition (Groq Llama-3.3-70B) — used in production/eval.
  2. Heuristic sentence splitting — fast fallback for tests / no-API scenarios.

The LLM decomposer produces higher-quality atomic claims because it can:
  - Split compound sentences into independent assertions
  - Resolve pronouns for self-contained claims
  - Filter out meta-statements and hedging language
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


def extract_claims_heuristic(answer_text: str) -> list[str]:
    """
    Split answer text into claim sentences using heuristics.

    Fast fallback when no LLM is available. Used in unit tests and
    as a baseline for ablation studies comparing LLM vs. rule-based
    decomposition.
    """
    if not answer_text or not answer_text.strip():
        return []

    text = answer_text.strip()

    # Split on sentence boundaries
    sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z])', text)

    # Also split on newlines that look like list items
    expanded: list[str] = []
    for sent in sentences:
        parts = re.split(r'\n+', sent)
        for part in parts:
            part = part.strip()
            # Remove leading bullet markers
            part = re.sub(r'^[-•*]\s+', '', part)
            part = re.sub(r'^\d+[.)]\s+', '', part)
            if part and len(part) > 5:  # skip tiny fragments
                expanded.append(part)

    return expanded


def extract_claims_llm(
    answer_text: str,
    llm_client: Optional[object] = None,
) -> list[str]:
    """
    Decompose answer text into atomic factual claims using an LLM.

    Uses Groq Llama-3.3-70B for high-quality claim decomposition.
    Falls back to heuristic if the LLM call fails.

    Args:
        answer_text: The answer text to decompose.
        llm_client: An LLMClient instance (or None to create one).

    Returns:
        List of atomic claim strings.
    """
    if not answer_text or not answer_text.strip():
        return []

    try:
        if llm_client is None:
            from .llm import LLMClient
            llm_client = LLMClient()

        claims = llm_client.decompose_claims(answer_text)

        if claims:
            logger.info(f"LLM decomposed answer into {len(claims)} claims")
            return claims
        else:
            logger.warning("LLM returned no claims, falling back to heuristic")
            return extract_claims_heuristic(answer_text)
    except Exception as e:
        logger.warning(f"LLM claim decomposition failed ({e}), using heuristic")
        return extract_claims_heuristic(answer_text)


def extract_claims(
    answer_text: str,
    use_llm: bool = False,
    llm_client: Optional[object] = None,
) -> list[str]:
    """
    Extract atomic claims from answer text.

    Args:
        answer_text: The answer text to process.
        use_llm: If True, use LLM-based decomposition (requires GROQ_API_KEY).
        llm_client: Optional pre-configured LLMClient instance.

    Returns:
        List of atomic claim strings.
    """
    if use_llm:
        return extract_claims_llm(answer_text, llm_client)
    return extract_claims_heuristic(answer_text)
