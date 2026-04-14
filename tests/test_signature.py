"""Tests for Ed25519 signature verification.

These tests verify:
1. Valid signature verification passes
2. Invalid signature verification fails
3. Tampered artifact detection
4. Key loading from various formats
5. Key info extraction
6. Deterministic verification
"""

from __future__ import annotations

import base64
import pytest

# Skip all tests if cryptography is not available
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from specora_verify.canonical import canonical_json_bytes
from specora_verify.hash import sha256_hex
from specora_verify.signature import (
    get_key_info,
    is_crypto_available,
    load_public_key,
    verify_signature,
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
        "data": {
            "value": 42,
            "nested": {"key": "value"},
        },
    }


class TestCryptoAvailability:
    """Test cryptography library detection."""

    def test_crypto_is_available(self):
        """Cryptography should be available in test environment."""
        assert is_crypto_available() is True


class TestKeyLoading:
    """Test public key loading from various formats."""

    def test_load_pem_key(self, keypair):
        """Load Ed25519 public key from PEM format."""
        _, public_key = keypair
        pem_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        pem_str = pem_bytes.decode("utf-8")

        loaded = load_public_key(pem_str, key_format="pem")
        assert loaded is not None

    def test_load_base64_key(self, keypair):
        """Load Ed25519 public key from base64-encoded raw bytes."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        b64_str = base64.b64encode(raw_bytes).decode("ascii")

        loaded = load_public_key(b64_str, key_format="base64")
        assert loaded is not None

    def test_load_raw_key(self, keypair):
        """Load Ed25519 public key from raw 32 bytes."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        loaded = load_public_key(raw_bytes, key_format="raw")
        assert loaded is not None

    def test_auto_detect_pem(self, keypair):
        """Auto-detect PEM format."""
        _, public_key = keypair
        pem_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        loaded = load_public_key(pem_bytes, key_format="auto")
        assert loaded is not None

    def test_auto_detect_base64(self, keypair):
        """Auto-detect base64 format."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        b64_str = base64.b64encode(raw_bytes).decode("ascii")

        loaded = load_public_key(b64_str, key_format="auto")
        assert loaded is not None

    def test_invalid_base64_rejected(self):
        """Invalid base64 encoding is rejected."""
        from specora_verify.errors import VerificationError

        with pytest.raises(VerificationError):
            load_public_key("not-valid-base64!!!", key_format="base64")

    def test_wrong_key_size_rejected(self):
        """Non-32-byte key data is rejected."""
        from specora_verify.errors import VerificationError

        # 16 bytes instead of 32
        short_key = base64.b64encode(b"x" * 16).decode("ascii")
        with pytest.raises(VerificationError):
            load_public_key(short_key, key_format="base64")


class TestKeyInfo:
    """Test key info extraction."""

    def test_key_info_pem(self, keypair):
        """Extract info from PEM key."""
        _, public_key = keypair
        pem_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        pem_str = pem_bytes.decode("utf-8")

        info = get_key_info(pem_str)

        assert info.valid is True
        assert info.algorithm == "Ed25519"
        assert info.key_size_bits == 256
        assert info.curve == "edwards25519"
        assert info.format == "pem"
        assert len(info.fingerprint) == 64  # SHA-256 hex

    def test_key_info_base64(self, keypair):
        """Extract info from base64 key."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        b64_str = base64.b64encode(raw_bytes).decode("ascii")

        info = get_key_info(b64_str)

        assert info.valid is True
        assert info.algorithm == "Ed25519"
        assert info.format == "base64"

    def test_key_info_invalid_key(self):
        """Invalid key returns error info."""
        info = get_key_info("not-a-valid-key")

        assert info.valid is False
        assert info.error is not None


class TestSignatureVerification:
    """Test Ed25519 signature verification."""

    def test_valid_signature(self, keypair, sample_artifact):
        """Valid signature verifies successfully."""
        private_key, public_key = keypair

        # Compute hash (matching server-side process)
        canonical_bytes = canonical_json_bytes(sample_artifact)
        artifact_hash = sha256_hex(canonical_bytes)

        # Sign the hash (UTF-8 encoded hex string, not binary)
        signature_bytes = private_key.sign(artifact_hash.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        # Get public key as base64
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        # Verify
        result = verify_signature(
            manifest_hash=artifact_hash,
            signature_b64=signature_b64,
            public_key=public_key_b64,
        )

        assert result.valid is True
        assert result.manifest_hash == artifact_hash
        assert len(result.errors) == 0

    def test_invalid_signature_rejected(self, keypair, sample_artifact):
        """Invalid signature is rejected."""
        private_key, public_key = keypair

        # Compute hash
        canonical_bytes = canonical_json_bytes(sample_artifact)
        artifact_hash = sha256_hex(canonical_bytes)

        # Create a different signature (sign different data)
        wrong_signature = private_key.sign(b"different data")
        wrong_sig_b64 = base64.b64encode(wrong_signature).decode("ascii")

        # Get public key
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        # Verify should fail
        result = verify_signature(
            manifest_hash=artifact_hash,
            signature_b64=wrong_sig_b64,
            public_key=public_key_b64,
        )

        assert result.valid is False
        assert len(result.errors) > 0
        assert "invalid signature" in result.errors[0].lower()

    def test_tampered_artifact_detected(self, keypair, sample_artifact):
        """Tampering with artifact after signing is detected."""
        private_key, public_key = keypair

        # Sign original artifact
        canonical_bytes = canonical_json_bytes(sample_artifact)
        artifact_hash = sha256_hex(canonical_bytes)
        signature_bytes = private_key.sign(artifact_hash.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        # Tamper with artifact
        tampered_artifact = sample_artifact.copy()
        tampered_artifact["data"]["value"] = 999
        tampered_hash = sha256_hex(canonical_json_bytes(tampered_artifact))

        # Get public key
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        # Verify with tampered hash should fail
        result = verify_signature(
            manifest_hash=tampered_hash,
            signature_b64=signature_b64,
            public_key=public_key_b64,
        )

        assert result.valid is False

    def test_wrong_key_rejected(self, sample_artifact):
        """Signature verified with wrong key is rejected."""
        # Generate two different keypairs
        private_key1 = Ed25519PrivateKey.generate()
        private_key2 = Ed25519PrivateKey.generate()
        public_key2 = private_key2.public_key()

        # Sign with key 1
        canonical_bytes = canonical_json_bytes(sample_artifact)
        artifact_hash = sha256_hex(canonical_bytes)
        signature_bytes = private_key1.sign(artifact_hash.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        # Verify with key 2 (different key)
        raw_bytes = public_key2.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        result = verify_signature(
            manifest_hash=artifact_hash,
            signature_b64=signature_b64,
            public_key=public_key_b64,
        )

        assert result.valid is False

    def test_invalid_hash_format_rejected(self, keypair):
        """Invalid hash format is rejected."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        # Too short
        result = verify_signature(
            manifest_hash="abc123",
            signature_b64="AAAA",
            public_key=public_key_b64,
        )
        assert result.valid is False
        assert "64 chars" in result.errors[0]

        # Invalid characters
        result = verify_signature(
            manifest_hash="G" * 64,  # G is not valid hex
            signature_b64="AAAA",
            public_key=public_key_b64,
        )
        assert result.valid is False
        assert "lowercase hexadecimal" in result.errors[0]

    def test_invalid_signature_encoding_rejected(self, keypair):
        """Invalid signature base64 is rejected."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        result = verify_signature(
            manifest_hash="a" * 64,
            signature_b64="not-valid-base64!!!",
            public_key=public_key_b64,
        )

        assert result.valid is False
        assert "base64" in result.errors[0].lower()

    def test_wrong_signature_length_rejected(self, keypair):
        """Signature with wrong length is rejected."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        # 32 bytes instead of 64
        short_sig = base64.b64encode(b"x" * 32).decode("ascii")

        result = verify_signature(
            manifest_hash="a" * 64,
            signature_b64=short_sig,
            public_key=public_key_b64,
        )

        assert result.valid is False
        assert "64 bytes" in result.errors[0]


class TestDeterminism:
    """Test verification determinism."""

    def test_verification_is_deterministic(self, keypair, sample_artifact):
        """Same inputs produce same verification result."""
        private_key, public_key = keypair

        # Sign
        canonical_bytes = canonical_json_bytes(sample_artifact)
        artifact_hash = sha256_hex(canonical_bytes)
        signature_bytes = private_key.sign(artifact_hash.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        # Get public key
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        # Verify multiple times
        results = [
            verify_signature(
                manifest_hash=artifact_hash,
                signature_b64=signature_b64,
                public_key=public_key_b64,
            )
            for _ in range(5)
        ]

        # All results should be identical
        assert all(r.valid == results[0].valid for r in results)
        assert all(r.key_fingerprint == results[0].key_fingerprint for r in results)

    def test_fingerprint_is_deterministic(self, keypair):
        """Key fingerprint is deterministic."""
        _, public_key = keypair

        # Get key in different formats
        pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        b64 = base64.b64encode(raw).decode("ascii")

        # Get info from each format
        info_pem = get_key_info(pem)
        info_b64 = get_key_info(b64)
        info_raw = get_key_info(raw)

        # Fingerprints should all match
        assert info_pem.fingerprint == info_b64.fingerprint == info_raw.fingerprint


class TestResultSerialization:
    """Test result serialization."""

    def test_signature_result_to_dict(self, keypair, sample_artifact):
        """SignatureVerificationResult serializes correctly."""
        private_key, public_key = keypair

        canonical_bytes = canonical_json_bytes(sample_artifact)
        artifact_hash = sha256_hex(canonical_bytes)
        signature_bytes = private_key.sign(artifact_hash.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        public_key_b64 = base64.b64encode(raw_bytes).decode("ascii")

        result = verify_signature(
            manifest_hash=artifact_hash,
            signature_b64=signature_b64,
            public_key=public_key_b64,
        )

        d = result.to_dict()

        assert "valid" in d
        assert "manifest_hash" in d
        assert "signature_b64" in d
        assert "key_fingerprint" in d
        assert "algorithm" in d
        assert "errors" in d

    def test_key_info_to_dict(self, keypair):
        """KeyInfo serializes correctly."""
        _, public_key = keypair
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        b64 = base64.b64encode(raw_bytes).decode("ascii")

        info = get_key_info(b64)
        d = info.to_dict()

        assert "algorithm" in d
        assert "key_size_bits" in d
        assert "fingerprint" in d
        assert "format" in d
        assert "curve" in d
        assert "valid" in d
