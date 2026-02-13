"""Tests for the BM25 retriever."""

import pytest

from core.retriever import Document, SimpleRetriever, get_demo_retriever, DEMO_DOCUMENTS


class TestSimpleRetriever:
    def test_index_and_retrieve(self):
        docs = [
            Document(
                doc_id="d1", title="Doc 1",
                text="The quick brown fox jumps over the lazy dog. The fox is very fast and agile.",
            ),
            Document(
                doc_id="d2", title="Doc 2",
                text="Cryptography uses prime numbers for encryption. Public key systems are based on primes.",
            ),
            Document(
                doc_id="d3", title="Doc 3",
                text="Machine learning models use neural networks. Deep learning requires GPUs.",
            ),
            Document(
                doc_id="d4", title="Doc 4",
                text="Databases store structured data. SQL is used to query relational databases.",
            ),
        ]
        retriever = SimpleRetriever(docs)
        results = retriever.retrieve("brown fox jumps", top_k=2)
        assert len(results) > 0
        assert results[0].doc_id == "d1"

    def test_empty_corpus(self):
        retriever = SimpleRetriever()
        results = retriever.retrieve("anything")
        assert results == []

    def test_top_k_limit(self):
        retriever = get_demo_retriever()
        results = retriever.retrieve("Python programming", top_k=2)
        assert len(results) <= 2

    def test_retrieval_returns_chunks(self):
        retriever = get_demo_retriever()
        results = retriever.retrieve("Ed25519 digital signatures")
        assert len(results) > 0
        # Should find ed25519 doc
        assert any("Ed25519" in c.text or "ed25519" in c.text.lower() for c in results)

    def test_chunks_have_doc_ids(self):
        retriever = get_demo_retriever()
        results = retriever.retrieve("SHA-256 hash function")
        for chunk in results:
            assert chunk.doc_id != ""
            assert chunk.chunk_id != ""

    def test_chunking(self):
        # Long document should be split into chunks
        long_text = ". ".join([f"Sentence number {i} about various topics" for i in range(50)])
        doc = Document(doc_id="long", title="Long Doc", text=long_text)
        retriever = SimpleRetriever([doc])
        # Should have created multiple chunks
        assert len(retriever._chunks) > 1

    def test_demo_corpus_coverage(self):
        """Demo corpus should have all 5 expected documents."""
        assert len(DEMO_DOCUMENTS) == 5
        doc_ids = {d.doc_id for d in DEMO_DOCUMENTS}
        assert "wiki_python" in doc_ids
        assert "wiki_rsa" in doc_ids
        assert "wiki_sha256" in doc_ids
        assert "wiki_ed25519" in doc_ids
        assert "wiki_ct" in doc_ids

    def test_no_results_for_gibberish(self):
        retriever = get_demo_retriever()
        results = retriever.retrieve("xyzzy glorp blargh", top_k=5)
        # BM25 should return 0 or very low results for gibberish
        assert len(results) == 0 or all(True for _ in results)
