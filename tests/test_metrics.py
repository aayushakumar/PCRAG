"""Tests for evaluation metrics."""

import pytest

from core.crypto import generate_keypair, public_key_b64, sign_json, sha256_hex
from core.pipeline import PCRAGPipeline, PipelineConfig
from attacks.tamper import a1_citation_swap, a2_span_substitution, a6_replay, run_all_attacks
from eval.metrics import (
    verify_certificate_integrity,
    compute_tdr,
    compute_fbr,
    compute_uaa_proxy,
    measure_overhead,
    VerificationResult,
)

TEST_CONFIG = PipelineConfig(
    use_llm_generation=False, use_llm_claims=False,
    use_embedding_spans=False, verifier_mode="heuristic",
    retrieval_mode="bm25", enable_transparency=False,
)


@pytest.fixture
def valid_cert():
    """Generate a valid signed certificate."""
    kp = generate_keypair()
    pipeline = PCRAGPipeline(keypair=kp, config=TEST_CONFIG)
    signed, _ = pipeline.answer("What is Python?")
    cert_dict = signed.certificate.model_dump(mode="python")
    sig_b64 = signed.signature
    pk_b64 = public_key_b64(kp.public_key)
    return cert_dict, sig_b64, pk_b64, kp, pipeline


class TestVerifyCertificateIntegrity:
    def test_valid_cert_passes(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        result = verify_certificate_integrity(cert_dict, sig, pk_b64)
        assert result.signature_valid is True
        assert result.commitments_valid is True
        assert result.tamper_detected is False

    def test_tampered_claim_detected(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        cert_dict["claims"][0]["claim_text"] = "TAMPERED!"
        result = verify_certificate_integrity(cert_dict, sig, pk_b64)
        assert result.tamper_detected is True

    def test_replay_detection(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        # Same cert with different presented query → replay detected
        result = verify_certificate_integrity(
            cert_dict, sig, pk_b64,
            presented_query="completely different question"
        )
        assert result.tamper_detected is True

    def test_replay_same_query_passes(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        # Same query → should pass (not a replay)
        result = verify_certificate_integrity(
            cert_dict, sig, pk_b64,
            presented_query="what is python?"  # matches original
        )
        assert result.tamper_detected is False

    def test_strips_evaluation_keys(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        cert_dict["_replay_context"] = {"presented_query": "test"}
        # Should strip _ keys before verification, so sig should still be valid
        result = verify_certificate_integrity(cert_dict, sig, pk_b64)
        assert result.signature_valid is True


class TestComputeTDR:
    def test_all_attacks_detected(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        tampered = run_all_attacks(cert_dict)
        tdr, results = compute_tdr(cert_dict, sig, pk_b64, tampered)
        assert tdr == 1.0
        assert all(results.values())

    def test_no_attacks(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        tdr, results = compute_tdr(cert_dict, sig, pk_b64, {})
        assert tdr == 0.0


class TestComputeFBR:
    def test_valid_cert_zero_fbr(self, valid_cert):
        cert_dict, _, _, _, _ = valid_cert
        fbr = compute_fbr(cert_dict)
        assert fbr == 0.0

    def test_empty_claims(self):
        assert compute_fbr({"claims": []}) == 0.0


class TestComputeUAA:
    def test_detected_attack_uaa_zero(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        tampered = a1_citation_swap(cert_dict)
        uaa = compute_uaa_proxy(cert_dict, tampered, sig, pk_b64)
        assert uaa == 0.0  # Detected → fail-closed → 0

    def test_replay_uaa_zero(self, valid_cert):
        cert_dict, sig, pk_b64, _, _ = valid_cert
        tampered = a6_replay(cert_dict, new_query="different query")
        uaa = compute_uaa_proxy(cert_dict, tampered, sig, pk_b64)
        assert uaa == 0.0  # Replay detected


class TestMeasureOverhead:
    def test_returns_latency_and_size(self, valid_cert):
        _, _, _, _, pipeline = valid_cert
        latency, size = measure_overhead(
            lambda q: pipeline.answer(q)[0],
            "What is Python?",
            n_runs=1,
        )
        assert latency > 0
        assert size > 0
