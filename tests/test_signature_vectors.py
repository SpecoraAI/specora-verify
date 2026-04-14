"""Tests for Ed25519 signature verification using golden vectors.

These tests verify that the signature verification implementation matches
the server-side signing process by using published golden test vectors.

The golden vectors are stored at:
    vectors/signature/

This ensures the verifier produces identical results to the server signing
code path (governance_signing_service.py).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Skip all tests if cryptography is not available
pytest.importorskip("cryptography")

from specora_verify.canonical import canonical_json_bytes
from specora_verify.fingerprint import compute_key_fingerprint, derive_key_id
from specora_verify.hash import sha256_hex
from specora_verify.signature import get_key_info, verify_signature

# Golden vectors directory (relative to repo root)
VECTORS_ROOT = Path(__file__).parent.parent / "vectors" / "signature"


def _load_vector(vector_name: str) -> dict:
    """Load all files for a signature test vector."""
    vector_dir = VECTORS_ROOT / vector_name

    if not vector_dir.exists():
        pytest.skip(f"Vector directory not found: {vector_dir}")

    return {
        "artifact": json.loads((vector_dir / "artifact.json").read_text()),
        "canonical": (vector_dir / "artifact.canonical.json").read_bytes(),
        "hash": (vector_dir / "artifact.sha256.txt").read_text().strip(),
        "signature": (vector_dir / "signature.b64").read_text().strip(),
        "pubkey_pem": (vector_dir / "pubkey.pem").read_text(),
        "pubkey_b64": (vector_dir / "pubkey.b64").read_text().strip(),
        "metadata": json.loads((vector_dir / "metadata.json").read_text()),
    }


class TestSignatureGoldenVectors:
    """Tests using golden signature test vectors."""

    def test_signed_artifact_001_canonical_matches(self):
        """Canonical JSON bytes match golden vector."""
        vector = _load_vector("signed-artifact-001")

        computed = canonical_json_bytes(vector["artifact"])

        assert computed == vector["canonical"], (
            f"Canonical bytes mismatch.\n"
            f"Computed: {computed!r}\n"
            f"Expected: {vector['canonical']!r}"
        )

    def test_signed_artifact_001_hash_matches(self):
        """SHA-256 hash matches golden vector."""
        vector = _load_vector("signed-artifact-001")

        computed = sha256_hex(canonical_json_bytes(vector["artifact"]))

        assert computed == vector["hash"], (
            f"Hash mismatch.\n"
            f"Computed: {computed}\n"
            f"Expected: {vector['hash']}"
        )

    def test_signed_artifact_001_signature_verifies(self):
        """Signature verification passes with golden vector."""
        vector = _load_vector("signed-artifact-001")

        result = verify_signature(
            manifest_hash=vector["hash"],
            signature_b64=vector["signature"],
            public_key=vector["pubkey_pem"],
        )

        assert result.valid is True, f"Signature verification failed: {result.errors}"
        assert len(result.errors) == 0

    def test_signed_artifact_001_key_fingerprint_matches(self):
        """Key fingerprint matches golden vector metadata."""
        vector = _load_vector("signed-artifact-001")

        result = verify_signature(
            manifest_hash=vector["hash"],
            signature_b64=vector["signature"],
            public_key=vector["pubkey_pem"],
        )

        assert result.key_fingerprint == vector["metadata"]["key_fingerprint_sha256"], (
            f"Fingerprint mismatch.\n"
            f"Computed: {result.key_fingerprint}\n"
            f"Expected: {vector['metadata']['key_fingerprint_sha256']}"
        )

    def test_signed_artifact_001_derived_key_id_matches(self):
        """Derived key_id matches golden vector metadata."""
        vector = _load_vector("signed-artifact-001")

        result = verify_signature(
            manifest_hash=vector["hash"],
            signature_b64=vector["signature"],
            public_key=vector["pubkey_pem"],
        )

        derived = derive_key_id(result.key_fingerprint)

        assert derived == vector["metadata"]["derived_key_id"], (
            f"Derived key_id mismatch.\n"
            f"Computed: {derived}\n"
            f"Expected: {vector['metadata']['derived_key_id']}"
        )

    def test_signed_artifact_001_base64_key_verifies(self):
        """Signature also verifies with base64 key format."""
        vector = _load_vector("signed-artifact-001")

        result = verify_signature(
            manifest_hash=vector["hash"],
            signature_b64=vector["signature"],
            public_key=vector["pubkey_b64"],
            key_format="base64",
        )

        assert result.valid is True, f"Verification with b64 key failed: {result.errors}"

    def test_signed_artifact_001_fingerprint_consistent_across_formats(self):
        """Key fingerprint is consistent across PEM and base64 key formats."""
        vector = _load_vector("signed-artifact-001")

        info_pem = get_key_info(vector["pubkey_pem"])
        info_b64 = get_key_info(vector["pubkey_b64"])

        assert info_pem.fingerprint == info_b64.fingerprint
        assert info_pem.fingerprint == vector["metadata"]["key_fingerprint_sha256"]

    def test_signed_artifact_001_tamper_detection(self):
        """Tampering with artifact is detected."""
        vector = _load_vector("signed-artifact-001")

        # Tamper with the artifact
        tampered = vector["artifact"].copy()
        tampered["all_policies_passed"] = False

        tampered_hash = sha256_hex(canonical_json_bytes(tampered))

        result = verify_signature(
            manifest_hash=tampered_hash,
            signature_b64=vector["signature"],
            public_key=vector["pubkey_pem"],
        )

        assert result.valid is False, "Tampered artifact should fail verification"
        assert "invalid signature" in result.errors[0].lower()


class TestSignatureSemantics:
    """Tests for signature semantics matching server implementation."""

    def test_signature_covers_utf8_hash_string(self):
        """Signature is over UTF-8 encoded hash string, not binary hash."""
        vector = _load_vector("signed-artifact-001")

        # The metadata confirms the signature covers manifest_hash_utf8
        assert vector["metadata"]["signature_covers"] == "manifest_hash_utf8"

        # Verify the hash we use for verification is the hex string
        computed_hash = sha256_hex(canonical_json_bytes(vector["artifact"]))
        assert len(computed_hash) == 64
        assert all(c in "0123456789abcdef" for c in computed_hash)

        # Verification should pass
        result = verify_signature(
            manifest_hash=computed_hash,
            signature_b64=vector["signature"],
            public_key=vector["pubkey_pem"],
        )
        assert result.valid is True
