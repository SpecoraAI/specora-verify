"""Tests for verification receipt generation.

These tests verify:
1. Receipt generation for valid signatures
2. Receipt generation for invalid signatures
3. Receipt generation for hash-only verification
4. Receipt determinism (except verified_at)
5. Structured error codes
6. Key fingerprint and derived ID in receipts
"""

from __future__ import annotations

import base64
import json
import pytest

# Skip tests if cryptography is not available
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from specora_verify.canonical import canonical_json_bytes
from specora_verify.fingerprint import (
    KEY_ID_PREFIX,
    compute_key_fingerprint,
    compute_key_fingerprint_and_id,
    derive_key_id,
    derived_key_id_from_public_key,
    fingerprint_from_public_key,
)
from specora_verify.hash import sha256_hex
from specora_verify.receipt import (
    generate_artifact_receipt,
    generate_bundle_receipt,
)


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def sample_artifact():
    """Sample artifact for signing."""
    return {
        "id": "test-artifact-001",
        "timestamp": "2026-03-01T12:00:00Z",
        "data": {"value": 42},
    }


@pytest.fixture
def signed_artifact(keypair, sample_artifact):
    """Return artifact with signature and public key data."""
    private_key, public_key = keypair

    # Compute hash
    canonical_bytes = canonical_json_bytes(sample_artifact)
    artifact_hash = sha256_hex(canonical_bytes)

    # Sign
    signature_bytes = private_key.sign(artifact_hash.encode("utf-8"))
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    # Get public key as base64
    raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

    return {
        "artifact": sample_artifact,
        "signature_b64": signature_b64,
        "public_key_b64": public_key_b64,
        "public_key": public_key,
        "artifact_hash": artifact_hash,
    }


class TestKeyFingerprint:
    """Test key fingerprint computation."""

    def test_fingerprint_is_64_hex_chars(self, keypair):
        """Fingerprint should be 64 lowercase hex characters."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        fingerprint = compute_key_fingerprint(raw_bytes)

        assert len(fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in fingerprint)

    def test_fingerprint_is_deterministic(self, keypair):
        """Same key should produce same fingerprint."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        fp1 = compute_key_fingerprint(raw_bytes)
        fp2 = compute_key_fingerprint(raw_bytes)

        assert fp1 == fp2

    def test_fingerprint_from_public_key(self, keypair):
        """fingerprint_from_public_key should work with Ed25519PublicKey."""
        _, public_key = keypair
        fingerprint = fingerprint_from_public_key(public_key)

        assert len(fingerprint) == 64

    def test_derived_key_id_format(self, keypair):
        """Derived key ID should have correct format."""
        _, public_key = keypair
        key_id = derived_key_id_from_public_key(public_key)

        assert key_id.startswith(KEY_ID_PREFIX)
        assert len(key_id) == len(KEY_ID_PREFIX) + 16

    def test_derive_key_id_from_fingerprint(self):
        """derive_key_id should take first 16 chars."""
        fingerprint = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
        key_id = derive_key_id(fingerprint)

        assert key_id == "spk-a1b2c3d4e5f6g7h8"

    def test_compute_both_fingerprint_and_id(self, keypair):
        """compute_key_fingerprint_and_id should return both values."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        fingerprint, key_id = compute_key_fingerprint_and_id(raw_bytes)

        assert len(fingerprint) == 64
        assert key_id.startswith(KEY_ID_PREFIX)
        assert key_id == f"{KEY_ID_PREFIX}{fingerprint[:16]}"


class TestReceiptGeneration:
    """Test verification receipt generation."""

    def test_receipt_on_valid_signature(self, signed_artifact):
        """Receipt should show PASS for valid signature."""
        receipt = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        assert receipt.verification.result == "PASS"
        assert receipt.verification.signature.valid is True
        assert len(receipt.verification.errors) == 0

    def test_receipt_on_invalid_signature(self, keypair, sample_artifact):
        """Receipt should show FAIL for invalid signature."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        # Wrong signature
        wrong_sig = base64.b64encode(b"x" * 64).decode("ascii")

        receipt = generate_artifact_receipt(
            artifact=sample_artifact,
            signature_b64=wrong_sig,
            public_key_data=public_key_b64,
        )

        assert receipt.verification.result == "FAIL"
        assert receipt.verification.signature.valid is False
        assert len(receipt.verification.errors) > 0

    def test_receipt_hash_only_without_flag(self, sample_artifact):
        """Receipt should FAIL for hash-only without --allow-hash-only."""
        receipt = generate_artifact_receipt(
            artifact=sample_artifact,
            signature_b64=None,
            public_key_data=None,
            allow_hash_only=False,
        )

        assert receipt.verification.result == "FAIL"
        assert any("SIGNATURE_MISSING" in e["code"] for e in receipt.verification.errors)

    def test_receipt_hash_only_with_flag(self, sample_artifact):
        """Receipt should PASS for hash-only with --allow-hash-only."""
        receipt = generate_artifact_receipt(
            artifact=sample_artifact,
            signature_b64=None,
            public_key_data=None,
            allow_hash_only=True,
        )

        assert receipt.verification.result == "PASS"
        assert receipt.verification.signature is None

    def test_receipt_contains_hash(self, signed_artifact):
        """Receipt should contain computed hash."""
        receipt = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        assert receipt.verification.hash is not None
        assert receipt.verification.hash.sha256 == signed_artifact["artifact_hash"]

    def test_receipt_contains_key_fingerprint(self, signed_artifact):
        """Receipt should contain key fingerprint and derived ID."""
        receipt = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        assert receipt.verification.public_key is not None
        assert receipt.verification.public_key.fingerprint_sha256 is not None
        assert receipt.verification.public_key.derived_key_id is not None
        assert receipt.verification.public_key.derived_key_id.startswith(KEY_ID_PREFIX)

    def test_receipt_contains_tool_info(self, signed_artifact):
        """Receipt should contain tool version info."""
        receipt = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        assert receipt.tool.name == "specora-verify"
        assert receipt.tool.version is not None
        assert receipt.tool.python is not None
        assert receipt.tool.crypto_backend is not None

    def test_receipt_contains_canonicalization_policy(self, signed_artifact):
        """Receipt should contain canonicalization policy."""
        receipt = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        policy = receipt.verification.canonicalization
        assert policy["sort_keys"] is True
        assert policy["separators"] == [",", ":"]
        assert policy["ensure_ascii"] is True
        assert policy["encoding"] == "utf-8"

    def test_receipt_contains_verified_at(self, signed_artifact):
        """Receipt should contain verification timestamp."""
        receipt = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        assert receipt.verified_at is not None
        assert receipt.verified_at.endswith("Z")


class TestReceiptDeterminism:
    """Test receipt determinism (except verified_at)."""

    def test_receipt_deterministic_except_timestamp(self, signed_artifact):
        """Receipts should be identical except for verified_at."""
        receipt1 = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )
        receipt2 = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        # Convert to dict and remove timestamp
        d1 = receipt1.to_dict()
        d2 = receipt2.to_dict()

        del d1["verified_at"]
        del d2["verified_at"]

        assert d1 == d2


class TestReceiptSerialization:
    """Test receipt serialization."""

    def test_receipt_to_json(self, signed_artifact):
        """Receipt should serialize to valid JSON."""
        receipt = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        json_str = receipt.to_json()
        parsed = json.loads(json_str)

        assert parsed["verification"]["result"] == "PASS"
        assert "tool" in parsed
        assert "verified_at" in parsed

    def test_receipt_to_dict(self, signed_artifact):
        """Receipt should convert to dict correctly."""
        receipt = generate_artifact_receipt(
            artifact=signed_artifact["artifact"],
            signature_b64=signed_artifact["signature_b64"],
            public_key_data=signed_artifact["public_key_b64"],
        )

        d = receipt.to_dict()

        assert isinstance(d, dict)
        assert "tool" in d
        assert "verification" in d
        assert "verified_at" in d


class TestBundleReceipt:
    """Test bundle manifest receipt generation."""

    def test_bundle_receipt_basic(self):
        """Bundle receipt should work for basic manifest."""
        manifest = {
            "schema_version": "1.0.0",
            "artifacts": [
                {"name": "file1.json", "sha256": "a" * 64},
            ],
        }

        receipt = generate_bundle_receipt(manifest=manifest)

        assert receipt.verification.type == "bundle"
        assert receipt.verification.hash is not None
        assert receipt.verification.result == "PASS"

    def test_bundle_receipt_with_signing_block(self, keypair):
        """Bundle receipt should verify signing block if present."""
        private_key, public_key = keypair

        # Create manifest without signing block first
        manifest_content = {
            "schema_version": "1.0.0",
            "artifacts": [],
        }

        # Compute hash
        manifest_hash = sha256_hex(canonical_json_bytes(manifest_content))

        # Sign
        signature_bytes = private_key.sign(manifest_hash.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        # Add signing block
        manifest_content["signing"] = {
            "manifest_sha256": manifest_hash,
            "signature_b64": signature_b64,
            "key_id": "test-key",
        }

        # Get public key
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        receipt = generate_bundle_receipt(
            manifest=manifest_content,
            public_key_data=public_key_b64,
        )

        assert receipt.verification.result == "PASS"
        assert receipt.verification.signature.valid is True


class TestStructuredErrors:
    """Test structured error codes in receipts."""

    def test_signature_invalid_error_code(self, keypair, sample_artifact):
        """Invalid signature should produce SIGNATURE_INVALID error."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        receipt = generate_artifact_receipt(
            artifact=sample_artifact,
            signature_b64=base64.b64encode(b"x" * 64).decode("ascii"),
            public_key_data=public_key_b64,
        )

        assert any(e["code"] == "SIGNATURE_INVALID" for e in receipt.verification.errors)

    def test_signature_missing_error_code(self, sample_artifact):
        """Missing signature should produce SIGNATURE_MISSING error."""
        receipt = generate_artifact_receipt(
            artifact=sample_artifact,
            signature_b64=None,
            public_key_data=None,
            allow_hash_only=False,
        )

        assert any(e["code"] == "SIGNATURE_MISSING" for e in receipt.verification.errors)
