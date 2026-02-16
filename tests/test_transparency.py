"""Tests for the Merkle transparency log."""

import pytest

from core.crypto import generate_keypair
from core.transparency import MerkleLog, _hash_leaf, _hash_node


@pytest.fixture
def log():
    kp = generate_keypair()
    return MerkleLog(kp), kp


class TestMerkleLogBasic:
    def test_empty_log(self, log):
        ml, _ = log
        assert ml.size == 0
        # Empty root is hash of empty string
        root = ml.root_hash()
        assert len(root) == 64  # SHA-256 hex

    def test_append_single(self, log):
        ml, _ = log
        idx = ml.append(b"leaf_0")
        assert idx == 0
        assert ml.size == 1

    def test_append_multiple(self, log):
        ml, _ = log
        for i in range(5):
            idx = ml.append(f"leaf_{i}".encode())
            assert idx == i
        assert ml.size == 5

    def test_root_changes_on_append(self, log):
        ml, _ = log
        root0 = ml.root_hash()
        ml.append(b"leaf_0")
        root1 = ml.root_hash()
        ml.append(b"leaf_1")
        root2 = ml.root_hash()
        assert root0 != root1
        assert root1 != root2

    def test_deterministic_root(self, log):
        ml, kp = log
        ml.append(b"a")
        ml.append(b"b")
        root1 = ml.root_hash()

        ml2 = MerkleLog(kp)
        ml2.append(b"a")
        ml2.append(b"b")
        root2 = ml2.root_hash()
        assert root1 == root2


class TestInclusionProof:
    def test_single_leaf_proof(self, log):
        ml, _ = log
        ml.append(b"only_leaf")
        proof = ml.get_inclusion_proof(0)
        assert proof.leaf_index == 0
        assert proof.tree_size == 1

        root = ml.root_hash()
        assert MerkleLog.verify_inclusion(proof, b"only_leaf", root)

    def test_two_leaf_proof(self, log):
        ml, _ = log
        ml.append(b"leaf_0")
        ml.append(b"leaf_1")
        root = ml.root_hash()

        for i in range(2):
            proof = ml.get_inclusion_proof(i)
            data = f"leaf_{i}".encode()
            assert MerkleLog.verify_inclusion(proof, data, root)

    def test_many_leaves_proof(self, log):
        ml, _ = log
        n = 10
        for i in range(n):
            ml.append(f"leaf_{i}".encode())
        root = ml.root_hash()

        for i in range(n):
            proof = ml.get_inclusion_proof(i)
            assert MerkleLog.verify_inclusion(proof, f"leaf_{i}".encode(), root)

    def test_proof_fails_for_wrong_data(self, log):
        ml, _ = log
        ml.append(b"real_leaf")
        ml.append(b"another_leaf")
        root = ml.root_hash()

        proof = ml.get_inclusion_proof(0)
        assert not MerkleLog.verify_inclusion(proof, b"fake_leaf", root)

    def test_proof_fails_for_wrong_root(self, log):
        ml, _ = log
        ml.append(b"leaf_0")
        proof = ml.get_inclusion_proof(0)
        assert not MerkleLog.verify_inclusion(proof, b"leaf_0", "0" * 64)

    def test_out_of_range_raises(self, log):
        ml, _ = log
        ml.append(b"leaf")
        with pytest.raises(ValueError):
            ml.get_inclusion_proof(5)
        with pytest.raises(ValueError):
            ml.get_inclusion_proof(-1)


class TestSignedTreeHead:
    def test_sth_signature_valid(self, log):
        ml, kp = log
        ml.append(b"leaf_0")
        sth = ml.get_signed_tree_head()
        assert sth.tree_size == 1
        assert len(sth.root_hash) == 64
        assert MerkleLog.verify_sth(sth, kp.public_key)

    def test_sth_changes_after_append(self, log):
        ml, kp = log
        ml.append(b"leaf_0")
        sth1 = ml.get_signed_tree_head()

        ml.append(b"leaf_1")
        sth2 = ml.get_signed_tree_head()

        assert sth1.root_hash != sth2.root_hash
        assert sth2.tree_size == 2

    def test_sth_to_dict(self, log):
        ml, _ = log
        ml.append(b"data")
        sth = ml.get_signed_tree_head()
        d = sth.to_dict()
        assert "tree_size" in d
        assert "root_hash" in d
        assert "timestamp" in d
        assert "signature" in d


class TestAppendCertificate:
    def test_append_certificate(self, log):
        ml, _ = log
        idx = ml.append_certificate(
            signature="sig_b64",
            certificate_id="cert_001",
            issued_at="2025-01-01T00:00:00Z",
        )
        assert idx == 0
        assert ml.size == 1

    def test_certificate_inclusion(self, log):
        ml, _ = log
        idx = ml.append_certificate(
            signature="sig_b64",
            certificate_id="cert_001",
            issued_at="2025-01-01T00:00:00Z",
        )
        root = ml.root_hash()
        proof = ml.get_inclusion_proof(idx)

        # Reconstruct leaf data the same way
        leaf_data = "sig_b64|cert_001|2025-01-01T00:00:00Z".encode("utf-8")
        assert MerkleLog.verify_inclusion(proof, leaf_data, root)


class TestHashPrimitives:
    def test_leaf_hash_prefix(self):
        h = _hash_leaf(b"data")
        # Should be SHA-256 of 0x00 || data
        import hashlib
        expected = hashlib.sha256(b"\x00data").hexdigest()
        assert h == expected

    def test_node_hash_prefix(self):
        h = _hash_node("aa" * 32, "bb" * 32)
        import hashlib
        expected = hashlib.sha256(
            b"\x01" + bytes.fromhex("aa" * 32) + bytes.fromhex("bb" * 32)
        ).hexdigest()
        assert h == expected
