"""Tests for the CLI verifier."""

import json
import pytest
from pathlib import Path
from click.testing import CliRunner

from core.crypto import generate_keypair, public_key_b64, sign_json
from core.pipeline import PCRAGPipeline, PipelineConfig
from verifier_cli.cli import main

TEST_CONFIG = PipelineConfig(
    use_llm_generation=False, use_llm_claims=False,
    use_embedding_spans=False, verifier_mode="heuristic",
    retrieval_mode="bm25", enable_transparency=False,
)


@pytest.fixture
def valid_cert_file(tmp_path):
    """Create a valid signed certificate file."""
    kp = generate_keypair()
    pipeline = PCRAGPipeline(keypair=kp, config=TEST_CONFIG)
    signed, _ = pipeline.answer("What is Python?")

    cert_dict = signed.certificate.model_dump(mode="python")
    data = {
        "certificate": cert_dict,
        "signature": signed.signature,
    }

    cert_path = tmp_path / "cert.json"
    cert_path.write_text(json.dumps(data, indent=2, default=str))

    return cert_path, public_key_b64(kp.public_key)


@pytest.fixture
def tampered_cert_file(tmp_path):
    """Create a tampered certificate file."""
    kp = generate_keypair()
    pipeline = PCRAGPipeline(keypair=kp, config=TEST_CONFIG)
    signed, _ = pipeline.answer("What is Python?")

    cert_dict = signed.certificate.model_dump(mode="python")
    # Tamper: edit claim text
    if cert_dict.get("claims"):
        cert_dict["claims"][0]["claim_text"] = "TAMPERED CLAIM TEXT"

    data = {
        "certificate": cert_dict,
        "signature": signed.signature,
    }

    cert_path = tmp_path / "tampered.json"
    cert_path.write_text(json.dumps(data, indent=2, default=str))

    return cert_path, public_key_b64(kp.public_key)


class TestCLIVerifier:
    def test_verify_valid_cert(self, valid_cert_file):
        cert_path, pk_b64 = valid_cert_file
        runner = CliRunner()
        result = runner.invoke(main, ["verify", str(cert_path), "--public-key", pk_b64])
        assert result.exit_code == 0
        assert "VERIFIED SUCCESSFULLY" in result.output or "VALID" in result.output

    def test_verify_tampered_cert_fails(self, tampered_cert_file):
        cert_path, pk_b64 = tampered_cert_file
        runner = CliRunner()
        result = runner.invoke(main, ["verify", str(cert_path), "--public-key", pk_b64])
        # Should exit non-zero (fail-closed)
        assert result.exit_code != 0

    def test_inspect_valid_cert(self, valid_cert_file):
        cert_path, pk_b64 = valid_cert_file
        runner = CliRunner()
        result = runner.invoke(main, ["inspect", str(cert_path)])
        assert result.exit_code == 0
        assert "pcrag/1.0" in result.output
