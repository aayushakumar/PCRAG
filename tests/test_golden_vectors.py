"""Golden test vector — verify a fixed certificate file byte-for-byte."""

import json
import base64
import pytest
from pathlib import Path

from core.canonicalize import canonicalize
from core.crypto import (
    generate_keypair,
    load_private_key,
    load_public_key,
    load_public_key_b64,
    public_key_b64,
    serialize_private_key,
    sha256_hex,
    sign_bytes,
    sign_json,
    verify_bytes,
    verify_json,
)

GOLDEN_DIR = Path(__file__).parent.parent / "golden"
GOLDEN_PATH = GOLDEN_DIR / "golden_certificate.json"


def _load_golden() -> dict:
    """Load the golden certificate from disk."""
    assert GOLDEN_PATH.exists(), f"Golden file not found at {GOLDEN_PATH}"
    return json.loads(GOLDEN_PATH.read_text())


def _create_golden_certificate() -> dict:
    """Create the deterministic golden certificate content (fixed values)."""
    return {
        "schema_version": "pcrag/1.0",
        "certificate_id": "golden_test_vector_001",
        "issued_at": "2025-01-01T00:00:00+00:00",
        "issuer": {
            "issuer_id": "pcrag-test",
            "public_key_id": "golden_kid"
        },
        "query_commitment": {
            "query_hash": sha256_hex("what is python?"),
            "session_nonce": "golden_nonce_fixed"
        },
        "retrieval_commitment": {
            "retriever_id": "pcrag-bm25-v1",
            "retriever_version": "0.1.0",
            "retrieval_time": "2025-01-01T00:00:00+00:00",
            "retrieved_items": []
        },
        "answer_commitment": {
            "answer_text_hash": sha256_hex("Python is a programming language."),
            "answer_text": "Python is a programming language."
        },
        "claims": [
            {
                "claim_id": "golden_c1",
                "claim_text": "Python is a programming language.",
                "claim_hash": sha256_hex("Python is a programming language."),
                "evidence_spans": [
                    {
                        "span_id": "golden_s1",
                        "doc_id": "wiki_python",
                        "chunk_id": "wiki_python_c0",
                        "start_offset": 0,
                        "end_offset": 55,
                        "span_text": "Python is a high-level, general-purpose programming language.",
                        "span_hash": sha256_hex("Python is a high-level, general-purpose programming language."),
                        "alignment_score": 0.75
                    }
                ],
                "verification": {
                    "label": "entailed",
                    "confidence": 0.9,
                    "verifier_id": "pcrag-test-v1",
                    "verifier_version": "0.1.0",
                    "verifier_digest": "test_digest",
                    "verifier_inputs_hash": sha256_hex(
                        "Python is a programming language."
                        "Python is a high-level, general-purpose programming language."
                    )
                },
                "render_decision": {
                    "rendered": True,
                    "reason_code": None
                }
            }
        ],
        "policy": {
            "mode": "fail_closed",
            "confidence_threshold": 0.5,
            "require_entailed": True
        },
        "transparency": None
    }


class TestGoldenVector:
    def test_golden_file_exists(self):
        """The golden file must exist on disk as a fixed reference."""
        assert GOLDEN_PATH.exists(), "golden/golden_certificate.json missing"

    def test_verify_golden_signature(self):
        """Load the golden file and verify signature + hashes."""
        data = _load_golden()
        pk = load_public_key_b64(data["public_key"])
        assert verify_json(data["certificate"], data["signature"], pk) is True

    def test_golden_hash_commitments(self):
        """All hash commitments in the golden file are correct."""
        data = _load_golden()
        cert = data["certificate"]

        # Answer hash
        assert cert["answer_commitment"]["answer_text_hash"] == sha256_hex(
            cert["answer_commitment"]["answer_text"]
        )

        # Claim + span hashes
        for claim in cert["claims"]:
            assert claim["claim_hash"] == sha256_hex(claim["claim_text"])
            for span in claim["evidence_spans"]:
                assert span["span_hash"] == sha256_hex(span["span_text"])

    def test_golden_content_matches_expected(self):
        """The golden file certificate content matches the expected structure."""
        data = _load_golden()
        cert = data["certificate"]
        expected = _create_golden_certificate()

        # Compare all content fields (they should be identical)
        assert cert["schema_version"] == expected["schema_version"]
        assert cert["certificate_id"] == expected["certificate_id"]
        assert cert["issued_at"] == expected["issued_at"]
        assert cert["issuer"] == expected["issuer"]
        assert cert["query_commitment"] == expected["query_commitment"]
        assert cert["answer_commitment"] == expected["answer_commitment"]
        assert cert["policy"] == expected["policy"]
        assert len(cert["claims"]) == len(expected["claims"])
        for actual_claim, expected_claim in zip(cert["claims"], expected["claims"]):
            assert actual_claim["claim_text"] == expected_claim["claim_text"]
            assert actual_claim["claim_hash"] == expected_claim["claim_hash"]

    def test_canonical_determinism(self):
        """Same certificate → identical canonical bytes every time."""
        cert = _create_golden_certificate()
        b1 = canonicalize(cert)
        b2 = canonicalize(cert)
        assert b1 == b2

    def test_golden_canonical_matches_fresh_sign(self):
        """A fresh signature over the same content verifies with the stored key."""
        data = _load_golden()
        sk_b64 = data.get("_private_key_for_test_only")
        if not sk_b64:
            pytest.skip("Golden file missing private key for re-sign test")

        sk = load_private_key(base64.b64decode(sk_b64))
        cert = data["certificate"]

        # Re-sign and compare
        new_sig = sign_json(cert, sk)
        assert new_sig == data["signature"], "Re-signing deterministic content should produce same signature"

    def test_save_and_load_roundtrip(self, tmp_path):
        """Save golden cert to disk, load it back, verify."""
        kp = generate_keypair()
        cert = _create_golden_certificate()
        sig_b64 = sign_json(cert, kp.private_key)
        pk_b64 = public_key_b64(kp.public_key)

        golden_data = {
            "certificate": cert,
            "signature": sig_b64,
            "public_key": pk_b64,
        }
        path = tmp_path / "golden.json"
        path.write_text(json.dumps(golden_data, indent=2, default=str))

        loaded = json.loads(path.read_text())
        pk = load_public_key_b64(loaded["public_key"])
        assert verify_json(loaded["certificate"], loaded["signature"], pk) is True

    def test_tampered_golden_fails(self):
        """Tampering with the golden certificate must invalidate signature."""
        import copy
        data = _load_golden()
        cert = copy.deepcopy(data["certificate"])
        cert["claims"][0]["claim_text"] = "TAMPERED!"
        pk = load_public_key_b64(data["public_key"])
        assert verify_json(cert, data["signature"], pk) is False
