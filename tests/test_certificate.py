"""Tests for certificate building, render decisions, and signing."""

import pytest
from core.certificate import (
    build_certificate,
    build_claim_record,
    build_span_record,
    _make_render_decision,
)
from core.crypto import generate_keypair, sha256_hex, verify_json
from core.schema import (
    RenderPolicy,
    RetrievalCommitment,
    SpanRecord,
    Verification,
    VerificationLabel,
    BlockReasonCode,
)


class TestSpanRecord:
    def test_build_span_record(self):
        span = build_span_record(
            doc_id="d1",
            span_text="The sky is blue.",
            start_offset=0,
            end_offset=16,
        )
        assert span.doc_id == "d1"
        assert span.span_text == "The sky is blue."
        assert span.span_hash == sha256_hex("The sky is blue.")
        assert span.span_id  # auto-generated


class TestRenderDecision:
    def test_entailed_high_conf_renders(self):
        policy = RenderPolicy(confidence_threshold=0.5)
        verif = Verification(label=VerificationLabel.ENTAILED, confidence=0.8)
        spans = [build_span_record("d1", "evidence")]
        rd = _make_render_decision(verif, spans, policy)
        assert rd.rendered is True
        assert rd.reason_code is None

    def test_contradicted_blocks(self):
        policy = RenderPolicy()
        verif = Verification(label=VerificationLabel.CONTRADICTED, confidence=0.9)
        spans = [build_span_record("d1", "evidence")]
        rd = _make_render_decision(verif, spans, policy)
        assert rd.rendered is False
        assert rd.reason_code == BlockReasonCode.CONTRADICTED

    def test_not_supported_blocks(self):
        policy = RenderPolicy()
        verif = Verification(label=VerificationLabel.NOT_SUPPORTED, confidence=0.3)
        spans = [build_span_record("d1", "evidence")]
        rd = _make_render_decision(verif, spans, policy)
        assert rd.rendered is False
        assert rd.reason_code == BlockReasonCode.NOT_SUPPORTED

    def test_low_confidence_blocks(self):
        policy = RenderPolicy(confidence_threshold=0.8)
        verif = Verification(label=VerificationLabel.ENTAILED, confidence=0.5)
        spans = [build_span_record("d1", "evidence")]
        rd = _make_render_decision(verif, spans, policy)
        assert rd.rendered is False
        assert rd.reason_code == BlockReasonCode.LOW_CONF

    def test_no_spans_blocks(self):
        policy = RenderPolicy()
        verif = Verification(label=VerificationLabel.ENTAILED, confidence=0.9)
        rd = _make_render_decision(verif, [], policy)
        assert rd.rendered is False
        assert rd.reason_code == BlockReasonCode.NO_SPAN


class TestBuildCertificate:
    def test_build_and_sign(self):
        kp = generate_keypair()
        policy = RenderPolicy()

        span = build_span_record("d1", "Python was created by Guido van Rossum.")
        verif = Verification(label=VerificationLabel.ENTAILED, confidence=0.9)
        claim = build_claim_record(
            "Python was created by Guido van Rossum.",
            [span],
            verif,
            policy,
        )

        signed = build_certificate(
            query="Who created Python?",
            answer_text="Python was created by Guido van Rossum.",
            claims=[claim],
            retrieval_commitment=RetrievalCommitment(),
            keypair=kp,
            policy=policy,
        )

        assert signed.certificate.schema_version == "pcrag/1.0"
        assert signed.signature  # non-empty

        # Verify signature
        cert_dict = signed.certificate.model_dump(mode="python")
        assert verify_json(cert_dict, signed.signature, kp.public_key) is True

    def test_hash_commitments_match(self):
        kp = generate_keypair()
        claim_text = "Ed25519 produces 64-byte signatures."
        span_text = "Ed25519 produces 64-byte signatures and uses 32-byte public keys."

        span = build_span_record("d1", span_text)
        verif = Verification(label=VerificationLabel.ENTAILED, confidence=0.85)
        claim = build_claim_record(claim_text, [span], verif, RenderPolicy())

        assert claim.claim_hash == sha256_hex(claim_text)
        assert claim.evidence_spans[0].span_hash == sha256_hex(span_text)

    def test_answer_hash_matches(self):
        kp = generate_keypair()
        answer = "Test answer text."

        signed = build_certificate(
            query="test",
            answer_text=answer,
            claims=[],
            retrieval_commitment=RetrievalCommitment(),
            keypair=kp,
        )

        assert signed.certificate.answer_commitment.answer_text_hash == sha256_hex(answer)
