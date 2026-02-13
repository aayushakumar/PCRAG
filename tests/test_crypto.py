"""Tests for Ed25519 signing/verification and SHA-256 hashing."""

import base64
import pytest
from hypothesis import given, strategies as st

from core.crypto import (
    generate_keypair,
    load_public_key_b64,
    public_key_b64,
    sha256_hex,
    sign_bytes,
    sign_json,
    verify_bytes,
    verify_json,
)


class TestSHA256:
    def test_known_hash(self):
        # SHA-256 of empty string
        assert sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_deterministic(self):
        assert sha256_hex("hello") == sha256_hex("hello")

    def test_different_inputs(self):
        assert sha256_hex("hello") != sha256_hex("world")

    def test_bytes_input(self):
        assert sha256_hex(b"hello") == sha256_hex("hello")


class TestEd25519:
    def test_generate_keypair(self):
        kp = generate_keypair()
        assert kp.private_key is not None
        assert kp.public_key is not None
        assert len(kp.kid) == 16  # hex truncated

    def test_sign_verify_roundtrip(self):
        kp = generate_keypair()
        msg = b"test message"
        sig = sign_bytes(msg, kp.private_key)
        assert len(sig) == 64  # Ed25519 signatures are 64 bytes
        assert verify_bytes(msg, sig, kp.public_key) is True

    def test_wrong_key_fails(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        msg = b"test message"
        sig = sign_bytes(msg, kp1.private_key)
        assert verify_bytes(msg, sig, kp2.public_key) is False

    def test_tampered_message_fails(self):
        kp = generate_keypair()
        msg = b"original"
        sig = sign_bytes(msg, kp.private_key)
        assert verify_bytes(b"tampered", sig, kp.public_key) is False

    def test_tampered_signature_fails(self):
        kp = generate_keypair()
        msg = b"test"
        sig = sign_bytes(msg, kp.private_key)
        tampered_sig = bytearray(sig)
        tampered_sig[0] ^= 0xFF
        assert verify_bytes(msg, bytes(tampered_sig), kp.public_key) is False

    def test_sign_verify_json(self):
        kp = generate_keypair()
        obj = {"claim": "hello", "value": 42}
        sig = sign_json(obj, kp.private_key)
        assert verify_json(obj, sig, kp.public_key) is True

    def test_json_key_order_invariant(self):
        """Signing with different key order should produce same signature
        because JCS canonicalizes first."""
        kp = generate_keypair()
        obj1 = {"b": 2, "a": 1}
        obj2 = {"a": 1, "b": 2}
        sig1 = sign_json(obj1, kp.private_key)
        sig2 = sign_json(obj2, kp.private_key)
        assert sig1 == sig2  # deterministic signature

    def test_public_key_serialization(self):
        kp = generate_keypair()
        b64 = public_key_b64(kp.public_key)
        pk_loaded = load_public_key_b64(b64)
        # Verify round-trip
        msg = b"test"
        sig = sign_bytes(msg, kp.private_key)
        assert verify_bytes(msg, sig, pk_loaded) is True


class TestPropertyBased:
    @given(st.binary(min_size=0, max_size=1000))
    def test_sign_verify_any_bytes(self, data):
        kp = generate_keypair()
        sig = sign_bytes(data, kp.private_key)
        assert verify_bytes(data, sig, kp.public_key) is True

    @given(st.text(min_size=1, max_size=200))
    def test_sha256_deterministic(self, text):
        assert sha256_hex(text) == sha256_hex(text)

    @given(st.text(min_size=1, max_size=200))
    def test_sha256_hex_length(self, text):
        h = sha256_hex(text)
        assert len(h) == 64  # 256 bits = 64 hex chars
