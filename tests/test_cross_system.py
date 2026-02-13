"""
Cross-system verification test — PRD §11.1 item 5.

Generates a certificate via the pipeline, then verifies it using
three independent verifiers (pipeline internal, CLI logic, API logic)
to prove the certificate format is portable and verifiable
without trusting the generator.
"""

import json
import base64
import pytest
from pathlib import Path

from core.crypto import (
    generate_keypair,
    public_key_b64,
    load_public_key_b64,
    sha256_hex,
    verify_json,
)
from core.canonicalize import canonicalize
from core.pipeline import PCRAGPipeline, PipelineConfig
from eval.metrics import verify_certificate_integrity

TEST_CONFIG = PipelineConfig(
    use_llm_generation=False, use_llm_claims=False,
    use_embedding_spans=False, verifier_mode="heuristic",
    retrieval_mode="bm25", enable_transparency=False,
)


@pytest.fixture
def generated_cert():
    """Generate a certificate for cross-system testing."""
    kp = generate_keypair()
    pipeline = PCRAGPipeline(keypair=kp, config=TEST_CONFIG)
    signed, _ = pipeline.answer("What is Ed25519?")
    cert_dict = signed.certificate.model_dump(mode="python")
    sig_b64 = signed.signature
    pk_b64 = public_key_b64(kp.public_key)
    return cert_dict, sig_b64, pk_b64


class TestCrossSystemVerification:
    def test_direct_crypto_verify(self, generated_cert):
        """Verify using raw crypto primitives (independent verifier)."""
        cert_dict, sig_b64, pk_b64 = generated_cert
        pk = load_public_key_b64(pk_b64)

        # 1. JCS canonicalize
        canonical = canonicalize(cert_dict)

        # 2. Verify signature
        sig = base64.b64decode(sig_b64)
        from core.crypto import verify_bytes
        assert verify_bytes(canonical, sig, pk) is True

        # 3. Verify hash commitments
        ac = cert_dict["answer_commitment"]
        assert sha256_hex(ac["answer_text"]) == ac["answer_text_hash"]

        for claim in cert_dict["claims"]:
            assert sha256_hex(claim["claim_text"]) == claim["claim_hash"]
            for span in claim["evidence_spans"]:
                assert sha256_hex(span["span_text"]) == span["span_hash"]

    def test_metrics_verifier(self, generated_cert):
        """Verify using eval/metrics verify_certificate_integrity."""
        cert_dict, sig_b64, pk_b64 = generated_cert
        result = verify_certificate_integrity(cert_dict, sig_b64, pk_b64)
        assert result.signature_valid is True
        assert result.commitments_valid is True
        assert result.tamper_detected is False
        assert result.hash_errors == []

    def test_json_roundtrip_verified(self, generated_cert):
        """Serialize to JSON, deserialize, and verify (portable format)."""
        cert_dict, sig_b64, pk_b64 = generated_cert

        # Serialize
        bundle = json.dumps({
            "certificate": cert_dict,
            "signature": sig_b64,
            "public_key": pk_b64,
        }, default=str)

        # Deserialize
        loaded = json.loads(bundle)
        pk = load_public_key_b64(loaded["public_key"])
        assert verify_json(loaded["certificate"], loaded["signature"], pk) is True

    def test_file_roundtrip_verified(self, generated_cert, tmp_path):
        """Write to file, read back, verify (offline verification)."""
        cert_dict, sig_b64, pk_b64 = generated_cert

        path = tmp_path / "cert.json"
        path.write_text(json.dumps({
            "certificate": cert_dict,
            "signature": sig_b64,
            "public_key": pk_b64,
        }, default=str, indent=2))

        loaded = json.loads(path.read_text())
        pk = load_public_key_b64(loaded["public_key"])
        assert verify_json(loaded["certificate"], loaded["signature"], pk) is True

    def test_tampered_cert_fails_all_verifiers(self, generated_cert):
        """A tampered cert must fail in all verification paths."""
        cert_dict, sig_b64, pk_b64 = generated_cert

        # Tamper
        import copy
        tampered = copy.deepcopy(cert_dict)
        tampered["claims"][0]["claim_text"] = "TAMPERED claim"

        # Direct crypto
        pk = load_public_key_b64(pk_b64)
        assert verify_json(tampered, sig_b64, pk) is False

        # Metrics verifier
        result = verify_certificate_integrity(tampered, sig_b64, pk_b64)
        assert result.tamper_detected is True

    def test_replay_detected_all_verifiers(self, generated_cert):
        """Replay (wrong query) must be detected when query is provided."""
        cert_dict, sig_b64, pk_b64 = generated_cert

        # Certificate was generated for "What is Ed25519?"
        # Present it for a different query
        result = verify_certificate_integrity(
            cert_dict, sig_b64, pk_b64,
            presented_query="What is RSA?"
        )
        assert result.tamper_detected is True
        assert any("replay" in e.lower() for e in result.hash_errors)
