"""
Dataset loader for PCRAG evaluation.

Loads and prepares standard QA benchmarks for evaluating the PCRAG pipeline:
  1. Natural Questions (NQ) — Google's benchmark of real search queries
  2. HotpotQA — Multi-hop reasoning QA
  3. TriviaQA — Large-scale QA with evidence documents

Each loader returns a list of EvalSample instances suitable for the PCRAG pipeline.

We use the HuggingFace `datasets` library for loading.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class EvalSample:
    """A single evaluation sample for PCRAG."""
    question: str
    gold_answers: list[str]  # acceptable answers (for ROUGE/BERTScore)
    evidence_documents: list[dict]  # list of {"doc_id", "title", "text"}
    dataset: str  # source dataset name
    sample_id: str = ""  # unique identifier

    def __post_init__(self):
        if not self.sample_id:
            self.sample_id = hashlib.sha256(
                self.question.encode()
            ).hexdigest()[:12]


def load_natural_questions(
    n_samples: int = 200,
    split: str = "validation",
    seed: int = 42,
    cache_dir: str | None = None,
) -> list[EvalSample]:
    """
    Load Natural Questions dataset.

    Uses the simplified version (nq_open) which has short answers.
    The evidence comes from the Wikipedia context provided with each question.

    Args:
        n_samples: Number of samples to load.
        split: Dataset split ("train" or "validation").
        seed: Random seed for sampling.
        cache_dir: Optional cache directory for the dataset.

    Returns:
        List of EvalSample instances.
    """
    from datasets import load_dataset

    logger.info(f"Loading Natural Questions ({split}, n={n_samples})...")

    ds = load_dataset(
        "nq_open",
        split=split,
        cache_dir=cache_dir,
        trust_remote_code=True,
    )

    # Sample subset
    rng = random.Random(seed)
    indices = list(range(len(ds)))
    rng.shuffle(indices)
    indices = indices[:n_samples]

    samples = []
    for idx in indices:
        row = ds[idx]
        question = row["question"]
        answers = row["answer"]  # list of answer strings

        # NQ open doesn't include contexts — we'll use the pipeline's own retriever
        # but we track the gold answers for evaluation
        samples.append(EvalSample(
            question=question,
            gold_answers=answers if isinstance(answers, list) else [answers],
            evidence_documents=[],  # pipeline will retrieve its own
            dataset="natural_questions",
        ))

    logger.info(f"Loaded {len(samples)} Natural Questions samples")
    return samples


def load_hotpotqa(
    n_samples: int = 200,
    split: str = "validation",
    seed: int = 42,
    difficulty: str = "hard",
    cache_dir: str | None = None,
) -> list[EvalSample]:
    """
    Load HotpotQA dataset.

    HotpotQA provides supporting facts (multi-hop evidence), making it
    excellent for evaluating claim-evidence alignment.

    Args:
        n_samples: Number of samples to load.
        split: Dataset split.
        seed: Random seed for sampling.
        difficulty: "hard" or "medium" or "easy".
        cache_dir: Optional cache directory.

    Returns:
        List of EvalSample instances.
    """
    from datasets import load_dataset

    logger.info(f"Loading HotpotQA ({split}, n={n_samples})...")

    ds = load_dataset(
        "hotpot_qa",
        "distractor",
        split=split,
        cache_dir=cache_dir,
        trust_remote_code=True,
    )

    # Filter by difficulty if specified
    if difficulty:
        ds = ds.filter(lambda x: x.get("level", "") == difficulty)

    # Sample subset
    rng = random.Random(seed)
    indices = list(range(len(ds)))
    rng.shuffle(indices)
    indices = indices[:n_samples]

    samples = []
    for idx in indices:
        row = ds[idx]
        question = row["question"]
        answer = row["answer"]

        # Build evidence documents from context
        contexts = row.get("context", {})
        titles = contexts.get("title", [])
        sentences_list = contexts.get("sentences", [])

        evidence_docs = []
        for i, (title, sentences) in enumerate(zip(titles, sentences_list)):
            text = " ".join(sentences) if isinstance(sentences, list) else str(sentences)
            evidence_docs.append({
                "doc_id": f"hotpot_{idx}_{i}",
                "title": title,
                "text": text,
                "source_uri": f"hotpotqa://doc/{idx}/{i}",
            })

        samples.append(EvalSample(
            question=question,
            gold_answers=[answer],
            evidence_documents=evidence_docs,
            dataset="hotpotqa",
        ))

    logger.info(f"Loaded {len(samples)} HotpotQA samples")
    return samples


def load_triviaqa(
    n_samples: int = 200,
    split: str = "validation",
    seed: int = 42,
    cache_dir: str | None = None,
) -> list[EvalSample]:
    """
    Load TriviaQA dataset.

    TriviaQA has questions with evidence documents and multiple valid answers.

    Args:
        n_samples: Number of samples to load.
        split: Dataset split.
        seed: Random seed for sampling.
        cache_dir: Optional cache directory.

    Returns:
        List of EvalSample instances.
    """
    from datasets import load_dataset

    logger.info(f"Loading TriviaQA ({split}, n={n_samples})...")

    ds = load_dataset(
        "trivia_qa",
        "rc.nocontext",
        split=split,
        cache_dir=cache_dir,
        trust_remote_code=True,
    )

    # Sample subset
    rng = random.Random(seed)
    indices = list(range(len(ds)))
    rng.shuffle(indices)
    indices = indices[:n_samples]

    samples = []
    for idx in indices:
        row = ds[idx]
        question = row["question"]
        answer_info = row.get("answer", {})

        # Get all valid answers
        aliases = answer_info.get("aliases", [])
        normalized = answer_info.get("normalized_aliases", [])
        value = answer_info.get("value", "")

        gold = list(set(aliases + normalized + ([value] if value else [])))
        if not gold:
            continue

        samples.append(EvalSample(
            question=question,
            gold_answers=gold,
            evidence_documents=[],  # pipeline retrieves its own
            dataset="triviaqa",
        ))

    logger.info(f"Loaded {len(samples)} TriviaQA samples")
    return samples


def load_dataset_samples(
    dataset_name: str = "natural_questions",
    n_samples: int = 200,
    **kwargs,
) -> list[EvalSample]:
    """
    Load evaluation samples from a named dataset.

    Args:
        dataset_name: One of "natural_questions", "hotpotqa", "triviaqa".
        n_samples: Number of samples to load.
        **kwargs: Additional arguments passed to the loader.

    Returns:
        List of EvalSample instances.
    """
    loaders = {
        "natural_questions": load_natural_questions,
        "nq": load_natural_questions,
        "hotpotqa": load_hotpotqa,
        "hotpot": load_hotpotqa,
        "triviaqa": load_triviaqa,
        "trivia": load_triviaqa,
    }

    loader = loaders.get(dataset_name.lower())
    if loader is None:
        raise ValueError(
            f"Unknown dataset: {dataset_name}. "
            f"Choose from: {list(loaders.keys())}"
        )

    return loader(n_samples=n_samples, **kwargs)
