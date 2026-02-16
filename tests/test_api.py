"""Tests for the FastAPI API endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport

from server.app import app


@pytest.fixture(autouse=True)
def reset_pipeline():
    """Reset the global pipeline for each test."""
    import server.app as sa
    sa._pipeline = None
    sa._certificate_store = {}


@pytest.mark.asyncio
async def test_answer_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/pcrag/answer", json={"query": "What is Python?"})
        assert resp.status_code == 200
        data = resp.json()
        assert "answer_text" in data
        assert "certificate" in data
        assert "signature" in data
        assert "public_key" in data


@pytest.mark.asyncio
async def test_answer_then_verify():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Generate
        resp = await client.post("/pcrag/answer", json={"query": "What is SHA-256?"})
        assert resp.status_code == 200
        answer_data = resp.json()

        # Verify
        verify_req = {
            "certificate": answer_data["certificate"],
            "signature": answer_data["signature"],
            "public_key": answer_data["public_key"],
        }
        resp = await client.post("/pcrag/verify", json=verify_req)
        assert resp.status_code == 200
        verify_data = resp.json()
        assert verify_data["valid_signature"] is True
        assert verify_data["valid_commitments"] is True


@pytest.mark.asyncio
async def test_verify_tampered_fails():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Generate
        resp = await client.post("/pcrag/answer", json={"query": "What is Ed25519?"})
        answer_data = resp.json()

        # Tamper with claim text
        cert = answer_data["certificate"]
        if cert.get("claims"):
            cert["claims"][0]["claim_text"] = "TAMPERED!"

        verify_req = {
            "certificate": cert,
            "signature": answer_data["signature"],
            "public_key": answer_data["public_key"],
        }
        resp = await client.post("/pcrag/verify", json=verify_req)
        verify_data = resp.json()
        # Should detect tampering
        assert verify_data["valid_signature"] is False or verify_data["valid_commitments"] is False


@pytest.mark.asyncio
async def test_evidence_bundle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Generate
        resp = await client.post("/pcrag/answer", json={"query": "What is RSA?"})
        answer_data = resp.json()
        cert_id = answer_data["certificate"]["certificate_id"]

        # Get evidence bundle
        resp = await client.get(f"/pcrag/evidence-bundle/{cert_id}")
        assert resp.status_code == 200
        bundle = resp.json()
        assert bundle["certificate_id"] == cert_id


@pytest.mark.asyncio
async def test_evidence_bundle_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/pcrag/evidence-bundle/nonexistent")
        assert resp.status_code == 404
