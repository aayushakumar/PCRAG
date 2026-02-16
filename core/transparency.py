"""
Transparency Log — Certificate Transparency-style append-only Merkle log.

Implements PRD §9: append-only public record of issued certificates with
verifiable inclusion proofs and signed tree heads.

Design (RFC 6962 / trillian-inspired):
  - Leaf = SHA-256(certificate_signature || certificate_id || issued_at)
  - Binary Merkle tree over leaves
  - Inclusion proof: path of sibling hashes from leaf to root
  - Signed Tree Head (STH): root hash + tree size + signature
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from .crypto import KeyPair, sign_bytes, verify_bytes

import base64


# ---------------------------------------------------------------------------
# Merkle tree primitives
# ---------------------------------------------------------------------------

def _hash_leaf(data: bytes) -> str:
    """Hash a leaf: H(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).hexdigest()


def _hash_node(left: str, right: str) -> str:
    """Hash an internal node: H(0x01 || left || right)."""
    payload = b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SignedTreeHead:
    """Signed Tree Head (STH) — commitment to the log state."""
    tree_size: int
    root_hash: str
    timestamp: str
    signature: str  # base64 Ed25519 signature over (tree_size || root_hash || timestamp)

    def to_dict(self) -> dict:
        return {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }


@dataclass
class InclusionProof:
    """Proof that a leaf is included in the Merkle tree."""
    leaf_index: int
    tree_size: int
    hashes: list[str]  # sibling hashes from leaf to root

    def to_dict(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "hashes": self.hashes,
        }


# ---------------------------------------------------------------------------
# Merkle log
# ---------------------------------------------------------------------------

class MerkleLog:
    """
    In-memory append-only Merkle log.

    Supports:
      - append(leaf_data) → leaf_index
      - get_inclusion_proof(leaf_index) → InclusionProof
      - get_signed_tree_head() → SignedTreeHead
      - verify_inclusion(proof, leaf_hash, root_hash) → bool (static)
    """

    def __init__(self, keypair: KeyPair):
        self._leaves: list[str] = []  # leaf hashes
        self._keypair = keypair

    @property
    def size(self) -> int:
        return len(self._leaves)

    def append(self, leaf_data: bytes) -> int:
        """Append a leaf to the log. Returns the leaf index."""
        leaf_hash = _hash_leaf(leaf_data)
        self._leaves.append(leaf_hash)
        return len(self._leaves) - 1

    def append_certificate(
        self, signature: str, certificate_id: str, issued_at: str
    ) -> int:
        """
        Append a certificate to the log.
        Leaf = SHA-256(signature || certificate_id || issued_at).
        Returns the leaf index.
        """
        leaf_data = f"{signature}|{certificate_id}|{issued_at}".encode("utf-8")
        return self.append(leaf_data)

    def root_hash(self) -> str:
        """Compute the current Merkle root hash."""
        if not self._leaves:
            return hashlib.sha256(b"").hexdigest()
        return self._compute_root(self._leaves)

    def _compute_root(self, hashes: list[str]) -> str:
        """Compute Merkle root from a list of leaf hashes."""
        if len(hashes) == 0:
            return hashlib.sha256(b"").hexdigest()
        if len(hashes) == 1:
            return hashes[0]

        # Pad to next power of 2
        level = list(hashes)

        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    next_level.append(_hash_node(level[i], level[i + 1]))
                else:
                    # Odd number: promote the last hash
                    next_level.append(level[i])
            level = next_level

        return level[0]

    def get_inclusion_proof(self, leaf_index: int) -> InclusionProof:
        """
        Generate a Merkle inclusion proof for a given leaf index.
        Returns the list of sibling hashes needed to recompute root.

        Each entry in the proof is either:
          - a sibling hash (when the node is paired), or
          - omitted (when the node is promoted due to odd level size).

        We encode promotions by storing an empty string "" in the proof
        so the verifier knows to skip combining at that level.
        """
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise ValueError(f"Leaf index {leaf_index} out of range [0, {len(self._leaves)})")

        proof_hashes: list[str] = []
        level = list(self._leaves)
        idx = leaf_index

        while len(level) > 1:
            next_level = []

            # Check if our node is paired or promoted
            if idx < len(level) - 1 or len(level) % 2 == 0:
                # Node has a sibling
                if idx % 2 == 0:
                    proof_hashes.append(level[idx + 1])
                else:
                    proof_hashes.append(level[idx - 1])
            else:
                # Node is the last unpaired element — promoted
                proof_hashes.append("")  # sentinel for "no sibling"

            # Build next level
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    next_level.append(_hash_node(level[i], level[i + 1]))
                else:
                    next_level.append(level[i])

            idx = idx // 2
            level = next_level

        return InclusionProof(
            leaf_index=leaf_index,
            tree_size=len(self._leaves),
            hashes=proof_hashes,
        )

    def get_signed_tree_head(self) -> SignedTreeHead:
        """Get the current Signed Tree Head (STH)."""
        root = self.root_hash()
        ts = datetime.now(timezone.utc).isoformat()
        # Sign: tree_size || root_hash || timestamp
        msg = f"{len(self._leaves)}|{root}|{ts}".encode("utf-8")
        sig = sign_bytes(msg, self._keypair.private_key)
        sig_b64 = base64.b64encode(sig).decode()

        return SignedTreeHead(
            tree_size=len(self._leaves),
            root_hash=root,
            timestamp=ts,
            signature=sig_b64,
        )

    @staticmethod
    def verify_inclusion(
        proof: InclusionProof,
        leaf_data: bytes,
        expected_root: str,
    ) -> bool:
        """
        Verify that leaf_data is included in the tree with the given root.
        Recomputes the root from the leaf and proof hashes.

        Empty strings ("") in the proof indicate promotions (no sibling).
        """
        current = _hash_leaf(leaf_data)
        idx = proof.leaf_index

        for sibling_hash in proof.hashes:
            if sibling_hash == "":
                # Promoted — just advance the index
                idx = idx // 2
                continue
            if idx % 2 == 0:
                current = _hash_node(current, sibling_hash)
            else:
                current = _hash_node(sibling_hash, current)
            idx = idx // 2

        return current == expected_root

    @staticmethod
    def verify_sth(
        sth: SignedTreeHead,
        public_key,
    ) -> bool:
        """Verify the STH signature."""
        msg = f"{sth.tree_size}|{sth.root_hash}|{sth.timestamp}".encode("utf-8")
        sig = base64.b64decode(sth.signature)
        return verify_bytes(msg, sig, public_key)
