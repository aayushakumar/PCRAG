"""Tests for PCRAG certificate schema validation."""

import pytest
from pydantic import ValidationError

from core.schema import (
    AnswerCertificate,
    AnswerCommitment,
    ClaimRecord,
    Issuer,
    QueryCommitment,
    RenderDecision,
    RenderPolicy,
    SignedCertificate,
    SpanRecord,
    Verification,
    VerificationLabel,
    BlockReasonCode,
)


class TestSchemaValidation:
    def test_verification_label_enum(self):
        assert VerificationLabel.ENTAILED == "entailed"
        assert VerificationLabel.CONTRADICTED == "contradicted"
        assert VerificationLabel.NOT_SUPPORTED == "not_supported"

    def test_span_record_valid(self):
        span = SpanRecord(
            span_id="s1",
            doc_id="d1",
            span_text="test span",
            span_hash="abc123",
        )
        assert span.span_text == "test span"
        assert span.start_offset == 0

    def test_verification_confidence_bounds(self):
        # Valid
        Verification(label=VerificationLabel.ENTAILED, confidence=0.95)
        Verification(label=VerificationLabel.ENTAILED, confidence=0.0)
        Verification(label=VerificationLabel.ENTAILED, confidence=1.0)

        # Invalid
        with pytest.raises(ValidationError):
            Verification(label=VerificationLabel.ENTAILED, confidence=1.5)
        with pytest.raises(ValidationError):
            Verification(label=VerificationLabel.ENTAILED, confidence=-0.1)

    def test_claim_record_valid(self):
        cr = ClaimRecord(
            claim_id="c1",
            claim_text="Python was created by Guido.",
            claim_hash="abc",
            evidence_spans=[],
            verification=Verification(
                label=VerificationLabel.ENTAILED,
                confidence=0.9,
            ),
            render_decision=RenderDecision(rendered=True),
        )
        assert cr.claim_id == "c1"

    def test_answer_certificate_defaults(self):
        cert = AnswerCertificate(
            issuer=Issuer(issuer_id="test", public_key_id="kid1"),
            query_commitment=QueryCommitment(query_hash="abc123"),
            answer_commitment=AnswerCommitment(
                answer_text_hash="def456",
                answer_text="Test answer",
            ),
        )
        assert cert.schema_version == "pcrag/1.0"
        assert cert.certificate_id  # auto-generated
        assert cert.issued_at  # auto-generated
        assert cert.claims == []

    def test_answer_certificate_missing_required_fails(self):
        with pytest.raises(ValidationError):
            AnswerCertificate(
                issuer=Issuer(issuer_id="test", public_key_id="kid1"),
                # Missing query_commitment and answer_commitment
            )

    def test_render_policy_defaults(self):
        p = RenderPolicy()
        assert p.mode == "fail_closed"
        assert p.confidence_threshold == 0.5
        assert p.require_entailed is True

    def test_signed_certificate(self):
        cert = AnswerCertificate(
            issuer=Issuer(issuer_id="test", public_key_id="kid1"),
            query_commitment=QueryCommitment(query_hash="abc"),
            answer_commitment=AnswerCommitment(answer_text_hash="def"),
        )
        sc = SignedCertificate(certificate=cert, signature="base64sig")
        assert sc.signature == "base64sig"

    def test_model_dump_roundtrip(self):
        """Ensure model_dump → model_validate round-trips."""
        cert = AnswerCertificate(
            issuer=Issuer(issuer_id="test", public_key_id="kid1"),
            query_commitment=QueryCommitment(query_hash="abc"),
            answer_commitment=AnswerCommitment(
                answer_text_hash="def",
                answer_text="Hello",
            ),
            claims=[
                ClaimRecord(
                    claim_id="c1",
                    claim_text="Test",
                    claim_hash="hash",
                    evidence_spans=[],
                    verification=Verification(
                        label=VerificationLabel.ENTAILED,
                        confidence=0.9,
                    ),
                    render_decision=RenderDecision(rendered=True),
                ),
            ],
        )
        data = cert.model_dump()
        restored = AnswerCertificate.model_validate(data)
        assert restored.issuer.issuer_id == "test"
        assert len(restored.claims) == 1
        assert restored.claims[0].claim_text == "Test"
