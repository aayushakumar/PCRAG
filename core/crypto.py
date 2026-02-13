"""
Cryptographic primitives for PCRAG.

- SHA-256 hashing (hash commitments)
- Ed25519 key generation, signing, and verification (RFC 8032)

All operations are deterministic and use the `cryptography` library.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .canonicalize import canonicalize


# ---------------------------------------------------------------------------
# SHA-256 utilities
# ---------------------------------------------------------------------------

def sha256_hex(data: str | bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Ed25519 key management
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    kid: str  # key identifier (hex of public key hash)


def generate_keypair() -> KeyPair:
    """Generate a fresh Ed25519 key pair."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = hashlib.sha256(pk_bytes).hexdigest()[:16]
    return KeyPair(private_key=sk, public_key=pk, kid=kid)


def public_key_bytes(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_b64(pk: Ed25519PublicKey) -> str:
    return base64.b64encode(public_key_bytes(pk)).decode()


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def load_public_key_b64(b64: str) -> Ed25519PublicKey:
    return load_public_key(base64.b64decode(b64))


def serialize_private_key(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def load_private_key(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


# ---------------------------------------------------------------------------
# Signing & verification
# ---------------------------------------------------------------------------

def sign_bytes(data: bytes, sk: Ed25519PrivateKey) -> bytes:
    """Sign raw bytes with Ed25519. Returns 64-byte signature."""
    return sk.sign(data)


def verify_bytes(data: bytes, signature: bytes, pk: Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        pk.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def sign_json(obj: dict, sk: Ed25519PrivateKey) -> str:
    """Canonicalize a JSON-compatible dict via JCS, sign it, return base64 sig."""
    canonical = canonicalize(obj)
    sig = sign_bytes(canonical, sk)
    return base64.b64encode(sig).decode()


def verify_json(obj: dict, signature_b64: str, pk: Ed25519PublicKey) -> bool:
    """Verify that base64 signature matches JCS-canonical form of obj."""
    canonical = canonicalize(obj)
    sig = base64.b64decode(signature_b64)
    return verify_bytes(canonical, sig, pk)
