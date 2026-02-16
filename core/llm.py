"""
LLM client abstraction for PCRAG.

Supports Groq (primary) for fast inference with Llama-3.3-70B.
Designed for two tasks:
  1. Answer generation from retrieved evidence
  2. Atomic claim decomposition

Environment variable: GROQ_API_KEY
"""

from __future__ import annotations

import json
import os
import time
import logging
from dataclasses import dataclass

from groq import Groq

logger = logging.getLogger(__name__)

# ── Default models ──────────────────────────────────────────────────────────

DEFAULT_GENERATION_MODEL = "llama-3.3-70b-versatile"
DEFAULT_DECOMPOSITION_MODEL = "llama-3.3-70b-versatile"

# ── Prompts ─────────────────────────────────────────────────────────────────

ANSWER_SYSTEM_PROMPT = """\
You are a precise, factual question-answering assistant. You MUST answer \
based ONLY on the provided evidence passages. Do not add information beyond \
what is stated in the evidence.

Rules:
1. Synthesize information from the evidence passages into a coherent answer.
2. Each factual statement must be directly supported by at least one passage.
3. If the evidence is insufficient, say so explicitly.
4. Be concise but comprehensive. Aim for 3-8 sentences.
5. Do not hallucinate or infer beyond what the evidence states."""

ANSWER_USER_TEMPLATE = """\
Question: {query}

Evidence passages:
{evidence}

Provide a factual answer based strictly on the evidence above."""

CLAIM_DECOMPOSITION_SYSTEM_PROMPT = """\
You are a claim decomposition engine. Your task is to split a text into \
independent, atomic factual claims. Each claim should be a single, \
self-contained statement that can be independently verified.

Rules:
1. Each claim must be ONE factual assertion.
2. Claims must be self-contained (no pronouns referring to other claims).
3. Preserve the original meaning exactly — do not rephrase or add information.
4. Output ONLY a JSON array of strings, nothing else.
5. If a sentence contains multiple facts, split them.
6. Omit opinions, hedging language, and meta-statements about the answer itself.
7. Do NOT include empty strings or duplicate claims."""

CLAIM_DECOMPOSITION_USER_TEMPLATE = """\
Decompose the following text into atomic factual claims.
Output ONLY a JSON array of strings.

Text: {text}"""


# ── Client ──────────────────────────────────────────────────────────────────

@dataclass
class LLMResponse:
    """Response from an LLM call."""
    text: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float


class LLMClient:
    """
    LLM client using Groq API.

    Usage:
        client = LLMClient()  # reads GROQ_API_KEY from env
        response = client.generate_answer("What is RSA?", evidence_texts)
        claims = client.decompose_claims("RSA is a public-key cryptosystem...")
    """

    def __init__(
        self,
        api_key: str | None = None,
        generation_model: str = DEFAULT_GENERATION_MODEL,
        decomposition_model: str = DEFAULT_DECOMPOSITION_MODEL,
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "GROQ_API_KEY must be set in environment or passed to LLMClient"
            )
        self._client = Groq(api_key=self.api_key)
        self.generation_model = generation_model
        self.decomposition_model = decomposition_model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def _call(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        max_retries: int = 3,
    ) -> LLMResponse:
        """Make a single LLM API call with retry logic for rate limits."""
        import re as _re

        for attempt in range(max_retries):
            try:
                t0 = time.perf_counter()
                response = self._client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temperature or self.temperature,
                    max_tokens=max_tokens or self.max_tokens,
                )
                latency = (time.perf_counter() - t0) * 1000

                text = response.choices[0].message.content or ""
                usage = response.usage
                return LLMResponse(
                    text=text.strip(),
                    model=model,
                    prompt_tokens=usage.prompt_tokens if usage else 0,
                    completion_tokens=usage.completion_tokens if usage else 0,
                    latency_ms=latency,
                )
            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "rate_limit" in error_str:
                    # Extract retry delay from error message
                    wait_match = _re.search(r'try again in (\d+)m([\d.]+)s', error_str)
                    if wait_match:
                        wait_secs = int(wait_match.group(1)) * 60 + float(wait_match.group(2))
                    else:
                        wait_secs = min(30 * (2 ** attempt), 120)

                    if attempt < max_retries - 1:
                        logger.warning(
                            f"Rate limited (attempt {attempt+1}/{max_retries}), "
                            f"waiting {wait_secs:.0f}s..."
                        )
                        time.sleep(min(wait_secs, 120))  # Cap at 2 minutes
                    else:
                        raise
                else:
                    raise

        raise RuntimeError("Max retries exceeded")

    def generate_answer(
        self,
        query: str,
        evidence_texts: list[str],
        model: str | None = None,
    ) -> LLMResponse:
        """
        Generate a grounded answer from retrieved evidence passages.

        Args:
            query: The user's question.
            evidence_texts: List of evidence passage texts.
            model: Override the default generation model.

        Returns:
            LLMResponse with the generated answer.
        """
        evidence_block = "\n\n".join(
            f"[Passage {i+1}]: {text}" for i, text in enumerate(evidence_texts)
        )
        user_prompt = ANSWER_USER_TEMPLATE.format(
            query=query, evidence=evidence_block
        )
        return self._call(
            system_prompt=ANSWER_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            model=model or self.generation_model,
        )

    def decompose_claims(
        self,
        text: str,
        model: str | None = None,
    ) -> list[str]:
        """
        Decompose text into atomic factual claims using an LLM.

        Args:
            text: The text to decompose.
            model: Override the default decomposition model.

        Returns:
            List of atomic claim strings.
        """
        user_prompt = CLAIM_DECOMPOSITION_USER_TEMPLATE.format(text=text)
        response = self._call(
            system_prompt=CLAIM_DECOMPOSITION_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            model=model or self.decomposition_model,
            temperature=0.0,  # deterministic for claim decomposition
        )

        # Parse JSON array from response
        return self._parse_claims_json(response.text)

    @staticmethod
    def _parse_claims_json(text: str) -> list[str]:
        """Robustly parse a JSON array of strings from LLM output."""
        # Try direct JSON parse first
        try:
            result = json.loads(text)
            if isinstance(result, list):
                return [str(c).strip() for c in result if str(c).strip()]
        except json.JSONDecodeError:
            pass

        # Try to find JSON array in the text (LLM may wrap in markdown)
        import re
        match = re.search(r'\[.*?\]', text, re.DOTALL)
        if match:
            try:
                result = json.loads(match.group())
                if isinstance(result, list):
                    return [str(c).strip() for c in result if str(c).strip()]
            except json.JSONDecodeError:
                pass

        # Fallback: split by newlines and clean
        lines = text.strip().split('\n')
        claims = []
        for line in lines:
            line = line.strip()
            line = re.sub(r'^[\d]+[.)]\s*', '', line)  # remove numbering
            line = re.sub(r'^[-•*]\s*', '', line)  # remove bullets
            line = line.strip('"\'')
            if line and len(line) > 10:
                claims.append(line)

        return claims
