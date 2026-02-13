"""Tests for evidence span selection."""

import pytest

from core.spans import DocumentChunk, select_evidence_spans, _jaccard, _tokenize


class TestTokenize:
    def test_basic(self):
        tokens = _tokenize("Hello World")
        assert tokens == {"hello", "world"}

    def test_punctuation(self):
        tokens = _tokenize("Hello, world! How are you?")
        assert "hello" in tokens
        assert "world" in tokens

    def test_empty(self):
        assert _tokenize("") == set()


class TestJaccard:
    def test_identical_sets(self):
        s = {"a", "b", "c"}
        assert _jaccard(s, s) == 1.0

    def test_disjoint_sets(self):
        assert _jaccard({"a", "b"}, {"c", "d"}) == 0.0

    def test_partial_overlap(self):
        a = {"a", "b", "c"}
        b = {"b", "c", "d"}
        # intersection={b,c}=2, union={a,b,c,d}=4 → 0.5
        assert _jaccard(a, b) == 0.5

    def test_empty_sets(self):
        assert _jaccard(set(), set()) == 0.0
        assert _jaccard({"a"}, set()) == 0.0


class TestSelectEvidenceSpans:
    @pytest.fixture
    def chunks(self):
        return [
            DocumentChunk(
                doc_id="doc1",
                chunk_id="doc1_c0",
                text="Python is a high-level programming language. It was created by Guido van Rossum.",
            ),
            DocumentChunk(
                doc_id="doc2",
                chunk_id="doc2_c0",
                text="RSA is a public-key cryptosystem. It uses prime numbers.",
            ),
        ]

    def test_returns_relevant_spans(self, chunks):
        results = select_evidence_spans("Python is a programming language", chunks)
        assert len(results) > 0
        # Best match should be from doc1
        best_chunk, best_text, best_score, start, end = results[0]
        assert best_chunk.doc_id == "doc1"
        assert best_score > 0

    def test_max_spans_limit(self, chunks):
        results = select_evidence_spans("Python programming language", chunks, max_spans=1)
        assert len(results) <= 1

    def test_min_score_filter(self, chunks):
        results = select_evidence_spans("quantum computing lasers", chunks, min_score=0.5)
        # Should return nothing with high threshold for unrelated query
        assert len(results) == 0

    def test_empty_chunks(self):
        results = select_evidence_spans("test query", [])
        assert results == []

    def test_empty_claim(self, chunks):
        results = select_evidence_spans("", chunks)
        assert results == []

    def test_span_offsets(self, chunks):
        results = select_evidence_spans("Python is a programming language", chunks)
        for chunk, text, score, start, end in results:
            assert start >= 0
            assert end > start
            assert end <= len(chunk.text) + 1  # Allow slight offset variance
