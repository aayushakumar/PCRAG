"""Tests for end-to-end pipeline."""

from core.crypto import generate_keypair, verify_json
from core.pipeline import PCRAGPipeline, PipelineConfig
from core.schema import RenderPolicy

# Config for tests: no LLM, no NLI model, no embeddings — fast & offline
TEST_CONFIG = PipelineConfig(
    use_llm_generation=False,
    use_llm_claims=False,
    use_embedding_spans=False,
    verifier_mode="heuristic",
    retrieval_mode="bm25",
    enable_transparency=True,
)


class TestPipeline:
    def test_pipeline_produces_valid_certificate(self):
        kp = generate_keypair()
        pipeline = PCRAGPipeline(keypair=kp, config=TEST_CONFIG)

        signed, metrics = pipeline.answer("What is Python?")

        # Certificate exists
        assert signed.certificate.schema_version == "pcrag/1.0"
        assert signed.signature

        # Signature verifies
        cert_dict = signed.certificate.model_dump(mode="python")
        assert verify_json(cert_dict, signed.signature, kp.public_key) is True

        # Metrics tracked
        assert metrics.total_ms > 0

    def test_pipeline_has_claims(self):
        pipeline = PCRAGPipeline(config=TEST_CONFIG)
        signed, _ = pipeline.answer("What is SHA-256?")
        assert len(signed.certificate.claims) > 0

    def test_pipeline_has_retrieval_commitment(self):
        pipeline = PCRAGPipeline(config=TEST_CONFIG)
        signed, _ = pipeline.answer("Tell me about Ed25519")
        ret = signed.certificate.retrieval_commitment
        assert len(ret.retrieved_items) > 0

    def test_pipeline_strict_policy_blocks_low_conf(self):
        policy = RenderPolicy(confidence_threshold=0.99)
        pipeline = PCRAGPipeline(policy=policy, config=TEST_CONFIG)
        signed, _ = pipeline.answer("What is Python?")

        # At least some claims exist
        assert len(signed.certificate.claims) > 0

    def test_pipeline_answer_text_in_cert(self):
        pipeline = PCRAGPipeline(config=TEST_CONFIG)
        signed, _ = pipeline.answer("What is RSA?")
        assert signed.certificate.answer_commitment.answer_text
        assert signed.certificate.answer_commitment.answer_text_hash
