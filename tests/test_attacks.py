"""Tests for tamper attack harness — verify that attacks are detected."""

import pytest

from attacks.tamper import (
    a1_citation_swap,
    a2_span_substitution,
    a3_claim_edit,
    a4_reorder_drop,
    a5_ui_tamper,
    a6_replay,
    a7_equivocation,
    run_all_attacks,
)
from core.crypto import generate_keypair, sha256_hex, public_key_b64
from core.pipeline import PCRAGPipeline, PipelineConfig
from eval.metrics import verify_certificate_integrity, detect_equivocation

TEST_CONFIG = PipelineConfig(
    use_llm_generation=False, use_llm_claims=False,
    use_embedding_spans=False, verifier_mode="heuristic",
    retrieval_mode="bm25", enable_transparency=False,
)


@pytest.fixture
def signed_cert():
    """Produce a valid signed certificate for testing."""
    kp = generate_keypair()
    pipeline = PCRAGPipeline(keypair=kp, config=TEST_CONFIG)
    signed, _ = pipeline.answer("What is Python and who created it?")
    cert_dict = signed.certificate.model_dump(mode="python")
    return cert_dict, signed.signature, public_key_b64(kp.public_key), kp


class TestA1CitationSwap:
    def test_signature_fails(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a1_citation_swap(cert_dict)
        # Signature must fail because cert contents changed
        result = verify_certificate_integrity(tampered, sig, pk_b64)
        assert result.tamper_detected is True

    def test_doc_ids_changed(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a1_citation_swap(cert_dict)
        # Should differ (unless only 1 doc, in which case we fake it)
        assert tampered != cert_dict


class TestA2SpanSubstitution:
    def test_hash_mismatch_detected(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        for mode in ["insert", "paraphrase", "numbers"]:
            tampered = a2_span_substitution(cert_dict, mode=mode)
            result = verify_certificate_integrity(tampered, sig, pk_b64)
            assert result.tamper_detected is True, f"Failed for mode={mode}"

    def test_span_text_changed(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a2_span_substitution(cert_dict, mode="insert")
        for tc, oc in zip(
            tampered.get("claims", []),
            cert_dict.get("claims", []),
        ):
            for ts, os_ in zip(
                tc.get("evidence_spans", []),
                oc.get("evidence_spans", []),
            ):
                if os_.get("span_text"):
                    assert ts["span_text"] != os_["span_text"]


class TestA3ClaimEdit:
    def test_hash_mismatch_detected(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        for mode in ["negate", "quantifier"]:
            tampered = a3_claim_edit(cert_dict, mode=mode)
            result = verify_certificate_integrity(tampered, sig, pk_b64)
            assert result.tamper_detected is True, f"Failed for mode={mode}"


class TestA4ReorderDrop:
    def test_drop_detected(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a4_reorder_drop(cert_dict, action="drop")
        result = verify_certificate_integrity(tampered, sig, pk_b64)
        assert result.tamper_detected is True

    def test_drop_all_detected(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a4_reorder_drop(cert_dict, action="drop_all")
        result = verify_certificate_integrity(tampered, sig, pk_b64)
        assert result.tamper_detected is True


class TestA5UITamper:
    def test_signature_fails(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a5_ui_tamper(cert_dict)
        result = verify_certificate_integrity(tampered, sig, pk_b64)
        assert result.tamper_detected is True


class TestA6Replay:
    def test_replay_has_context(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a6_replay(cert_dict, new_query="totally different question")
        assert "_replay_context" in tampered
        assert tampered["_replay_context"]["presented_query"] == "totally different question"

    def test_replay_query_hash_mismatch(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a6_replay(cert_dict, new_query="new query about something else")
        # The cert's query_hash should NOT match the new query
        expected_hash = sha256_hex("new query about something else")
        actual_hash = tampered.get("query_commitment", {}).get("query_hash", "")
        assert actual_hash != expected_hash

    def test_replay_detected_by_verifier(self, signed_cert):
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a6_replay(cert_dict, new_query="different query")
        result = verify_certificate_integrity(
            tampered, sig, pk_b64,
            presented_query="different query",
        )
        assert result.tamper_detected is True

    def test_replay_cert_body_unchanged(self, signed_cert):
        """The cert body should NOT be modified by A6 (signature remains valid)."""
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a6_replay(cert_dict, new_query="different query")
        # Strip evaluation side-channel keys and verify signature is still valid
        clean = {k: v for k, v in tampered.items() if not k.startswith("_")}
        result = verify_certificate_integrity(clean, sig, pk_b64)
        assert result.signature_valid is True

    def test_replay_detected_with_different_query(self, signed_cert):
        """Replay must be detected when verifier knows the presented query."""
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a6_replay(cert_dict, new_query="totally different question")
        # Signature is still valid (cert body unchanged), but query hash mismatches
        result = verify_certificate_integrity(
            tampered, sig, pk_b64,
            presented_query="totally different question",
        )
        assert result.tamper_detected is True

    def test_replay_body_unchanged_strict(self, signed_cert):
        """A6 must NOT modify the certificate body (only side-channel)."""
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered = a6_replay(cert_dict, new_query="something new")
        # Strip side-channel key and compare
        clean = {k: v for k, v in tampered.items() if not k.startswith("_")}
        assert clean == cert_dict


class TestAllAttacks:
    def test_all_attacks_detected(self, signed_cert):
        """Every attack in the registry must be detected."""
        cert_dict, sig, pk_b64, kp = signed_cert
        tampered_certs = run_all_attacks(cert_dict)

        for name, tampered in tampered_certs.items():
            # A6 replay: cert body is unchanged, detection is via query mismatch
            presented_query = None
            if "_replay_context" in tampered:
                presented_query = tampered["_replay_context"].get("presented_query")

            result = verify_certificate_integrity(
                tampered, sig, pk_b64,
                presented_query=presented_query,
            )
            # A4_reorder_spans might not be detected by hash check alone
            # (span hashes still match individually), but signature will fail
            # because the array order changed in the signed payload.
            assert result.tamper_detected is True, (
                f"Attack {name} was NOT detected! "
                f"sig_valid={result.signature_valid}, "
                f"commits_valid={result.commitments_valid}"
            )


class TestA7Equivocation:
    """Tests for equivocation attack (A7) — same query, different answers."""

    def test_equivocation_produces_different_answer(self, signed_cert):
        """A7 must produce a certificate with a different answer."""
        cert_dict, sig, pk_b64, kp = signed_cert
        equivocated = a7_equivocation(cert_dict)

        orig_answer = cert_dict["answer_commitment"]["answer_text"]
        equiv_answer = equivocated["answer_commitment"]["answer_text"]
        assert orig_answer != equiv_answer

    def test_equivocation_same_query_hash(self, signed_cert):
        """A7 must preserve the same query_hash (same query)."""
        cert_dict, sig, pk_b64, kp = signed_cert
        equivocated = a7_equivocation(cert_dict)

        orig_qh = cert_dict["query_commitment"]["query_hash"]
        equiv_qh = equivocated["query_commitment"]["query_hash"]
        assert orig_qh == equiv_qh

    def test_equivocation_has_consistent_internal_hashes(self, signed_cert):
        """A7 cert must have internally consistent hashes (recomputed)."""
        cert_dict, sig, pk_b64, kp = signed_cert
        equivocated = a7_equivocation(cert_dict)

        # Answer hash must match the new answer
        ac = equivocated["answer_commitment"]
        assert sha256_hex(ac["answer_text"]) == ac["answer_text_hash"]

        # Claim hashes must match the new claim texts
        for claim in equivocated.get("claims", []):
            if claim.get("claim_text") and claim.get("claim_hash"):
                assert sha256_hex(claim["claim_text"]) == claim["claim_hash"]

    def test_equivocation_detected_with_transparency(self, signed_cert):
        """A7 must be detected when transparency log is enabled."""
        cert_dict, sig, pk_b64, kp = signed_cert
        equivocated = a7_equivocation(cert_dict)

        detected = detect_equivocation(
            cert_dict, equivocated, transparency_enabled=True
        )
        assert detected is True

    def test_equivocation_undetected_without_transparency(self, signed_cert):
        """A7 must NOT be detected when transparency log is disabled."""
        cert_dict, sig, pk_b64, kp = signed_cert
        equivocated = a7_equivocation(cert_dict)

        detected = detect_equivocation(
            cert_dict, equivocated, transparency_enabled=False
        )
        assert detected is False

    def test_equivocation_context_metadata(self, signed_cert):
        """A7 must include _equivocation_context for evaluation."""
        cert_dict, sig, pk_b64, kp = signed_cert
        equivocated = a7_equivocation(cert_dict)

        assert "_equivocation_context" in equivocated
        ctx = equivocated["_equivocation_context"]
        assert ctx["detection_requires"] == "transparency_log"
        assert ctx["same_query_hash"] == cert_dict["query_commitment"]["query_hash"]
        assert ctx["original_answer_hash"] != ctx["equivocated_answer_hash"]
