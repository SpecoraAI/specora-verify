"""Ed25519 signature verification for Specora manifests.

This module provides Ed25519 (RFC 8032) signature verification matching
the Specora platform signing implementation.

IMPORTANT: This module requires the 'cryptography' package. Install with:
    pip install specora-verify[crypto]

The verification process:
1. Decode base64 signature to bytes (64 bytes expected)
2. Load Ed25519 public key from PEM, raw bytes, or base64
3. Verify signature over the manifest hash bytes (UTF-8 encoded hex string)

This matches the server-side signing in:
    Specora Wire Spec v1.0 Annex B (Signing) - https://spec.specora.ai/v1.0
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from specora_verify.errors import VerificationError

# Error codes for signature verification
ERR_CRYPTO_MISSING = "CRYPTO_MISSING"
ERR_KEY_LOAD = "KEY_LOAD_FAILED"
ERR_SIG_INVALID = "SIGNATURE_INVALID"
ERR_SIG_FORMAT = "SIGNATURE_FORMAT"
ERR_HASH_FORMAT = "HASH_FORMAT"

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Flag to track if cryptography is available
_CRYPTO_AVAILABLE = False
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    _CRYPTO_AVAILABLE = True
except ImportError:
    pass


def is_crypto_available() -> bool:
    """Check if cryptography library is available for signature verification."""
    return _CRYPTO_AVAILABLE


def require_crypto() -> None:
    """Raise error if cryptography is not available."""
    if not _CRYPTO_AVAILABLE:
        raise VerificationError(
            ERR_CRYPTO_MISSING,
            "Signature verification requires the 'cryptography' package. "
            "Install with: pip install specora-verify[crypto]",
        )


@dataclass
class KeyInfo:
    """Information about a public key."""

    algorithm: str
    key_size_bits: int
    fingerprint: str  # SHA-256 of raw public key bytes, hex encoded
    format: str  # pem, raw, base64
    curve: str | None = None
    valid: bool = True
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "key_size_bits": self.key_size_bits,
            "fingerprint": self.fingerprint,
            "format": self.format,
            "curve": self.curve,
            "valid": self.valid,
            "error": self.error,
        }


@dataclass
class SignatureVerificationResult:
    """Result of signature verification."""

    valid: bool
    manifest_hash: str | None = None
    signature_b64: str | None = None
    key_fingerprint: str | None = None
    algorithm: str = "ed25519"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "manifest_hash": self.manifest_hash,
            "signature_b64": self.signature_b64,
            "key_fingerprint": self.key_fingerprint,
            "algorithm": self.algorithm,
            "errors": self.errors,
        }


def _compute_key_fingerprint(public_key_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint of raw public key bytes."""
    import hashlib

    return hashlib.sha256(public_key_bytes).hexdigest()


def load_public_key(
    key_data: str | bytes,
    key_format: str = "auto",
) -> Ed25519PublicKey:
    """Load Ed25519 public key from various formats.

    Supported formats:
    - pem: PEM-encoded public key (-----BEGIN PUBLIC KEY-----)
    - base64: Base64-encoded raw 32-byte Ed25519 public key
    - raw: Raw 32-byte Ed25519 public key bytes
    - auto: Detect format automatically

    Args:
        key_data: Key data as string (PEM/base64) or bytes (raw/base64)
        key_format: Format hint ("pem", "base64", "raw", "auto")

    Returns:
        Ed25519PublicKey instance

    Raises:
        VerificationError: If key cannot be loaded or is invalid
    """
    require_crypto()

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    # Normalize to bytes if string
    if isinstance(key_data, str):
        key_bytes = key_data.encode("utf-8")
    else:
        key_bytes = key_data

    # Auto-detect format
    if key_format == "auto":
        if key_bytes.startswith(b"-----BEGIN"):
            key_format = "pem"
        elif len(key_bytes) == 32:
            key_format = "raw"
        else:
            # Try base64
            key_format = "base64"

    try:
        if key_format == "pem":
            loaded_key = load_pem_public_key(key_bytes)
            if not isinstance(loaded_key, Ed25519PublicKey):
                raise VerificationError(
                    ERR_KEY_LOAD,
                    f"Expected Ed25519 public key, got {type(loaded_key).__name__}",
                )
            return loaded_key

        elif key_format == "base64":
            try:
                raw_bytes = base64.b64decode(key_bytes)
            except Exception as e:
                raise VerificationError(ERR_KEY_LOAD, f"Invalid base64 encoding: {e}") from e

            if len(raw_bytes) != 32:
                raise VerificationError(
                    ERR_KEY_LOAD,
                    f"Ed25519 public key must be 32 bytes, got {len(raw_bytes)}",
                )
            return Ed25519PublicKey.from_public_bytes(raw_bytes)

        elif key_format == "raw":
            if len(key_bytes) != 32:
                raise VerificationError(
                    ERR_KEY_LOAD,
                    f"Ed25519 public key must be 32 bytes, got {len(key_bytes)}",
                )
            return Ed25519PublicKey.from_public_bytes(key_bytes)

        else:
            raise VerificationError(ERR_KEY_LOAD, f"Unknown key format: {key_format}")

    except VerificationError:
        raise
    except Exception as e:
        raise VerificationError(ERR_KEY_LOAD, f"Failed to load public key: {e}") from e


def get_key_info(key_data: str | bytes, key_format: str = "auto") -> KeyInfo:
    """Get information about a public key.

    Args:
        key_data: Key data (PEM, base64, or raw bytes)
        key_format: Format hint

    Returns:
        KeyInfo with key metadata
    """
    require_crypto()

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    try:
        public_key = load_public_key(key_data, key_format)

        # Get raw bytes for fingerprint
        raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        fingerprint = _compute_key_fingerprint(raw_bytes)

        # Detect original format
        if isinstance(key_data, str) and key_data.startswith("-----BEGIN"):
            detected_format = "pem"
        elif isinstance(key_data, bytes) and len(key_data) == 32:
            detected_format = "raw"
        else:
            detected_format = "base64"

        return KeyInfo(
            algorithm="Ed25519",
            key_size_bits=256,
            fingerprint=fingerprint,
            format=detected_format,
            curve="edwards25519",
            valid=True,
        )

    except Exception as e:
        return KeyInfo(
            algorithm="unknown",
            key_size_bits=0,
            fingerprint="",
            format=key_format,
            valid=False,
            error=str(e),
        )


def verify_signature(
    manifest_hash: str,
    signature_b64: str,
    public_key: Ed25519PublicKey | str | bytes,
    key_format: str = "auto",
) -> SignatureVerificationResult:
    """Verify Ed25519 signature over manifest hash.

    The signature is verified over the UTF-8 encoded manifest hash string,
    NOT the binary hash bytes. This matches the server-side signing:

        signature = private_key.sign(manifest_hash.encode("utf-8"))

    Args:
        manifest_hash: SHA-256 hex string (64 chars) that was signed
        signature_b64: Base64-encoded Ed25519 signature (64 bytes decoded)
        public_key: Ed25519PublicKey instance or key data to load
        key_format: Format hint if public_key is data to load

    Returns:
        SignatureVerificationResult with verification details
    """
    require_crypto()

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    result = SignatureVerificationResult(
        valid=False,
        manifest_hash=manifest_hash,
        signature_b64=signature_b64,
    )

    # Validate manifest hash format
    if not manifest_hash or len(manifest_hash) != 64:
        result.errors.append(
            f"Invalid manifest hash length: expected 64 chars, got {len(manifest_hash) if manifest_hash else 0}"
        )
        return result

    if not all(c in "0123456789abcdef" for c in manifest_hash):
        result.errors.append("Manifest hash must be lowercase hexadecimal")
        return result

    # Load public key if not already loaded
    try:
        if isinstance(public_key, (str, bytes)):
            pub_key = load_public_key(public_key, key_format)
        else:
            pub_key = public_key

        # Compute fingerprint
        raw_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        result.key_fingerprint = _compute_key_fingerprint(raw_bytes)

    except VerificationError as e:
        result.errors.append(str(e))
        return result

    # Decode signature
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception as e:
        result.errors.append(f"Invalid base64 signature: {e}")
        return result

    if len(signature_bytes) != 64:
        result.errors.append(
            f"Invalid signature length: expected 64 bytes, got {len(signature_bytes)}"
        )
        return result

    # Verify signature
    # CRITICAL: Sign/verify over UTF-8 encoded hex string, not binary hash
    message_bytes = manifest_hash.encode("utf-8")

    try:
        pub_key.verify(signature_bytes, message_bytes)
        result.valid = True
    except InvalidSignature:
        result.errors.append("Signature verification failed: invalid signature")
    except Exception as e:
        result.errors.append(f"Signature verification error: {e}")

    return result


def verify_artifact_signature(
    artifact_hash: str,
    signature_b64: str,
    public_key_data: str | bytes,
    key_format: str = "auto",
) -> SignatureVerificationResult:
    """Verify signature over an artifact hash.

    Convenience wrapper for verify_signature that accepts raw key data.

    Args:
        artifact_hash: SHA-256 hex hash of the artifact
        signature_b64: Base64-encoded Ed25519 signature
        public_key_data: Public key (PEM, base64, or raw bytes)
        key_format: Key format hint

    Returns:
        SignatureVerificationResult
    """
    return verify_signature(
        manifest_hash=artifact_hash,
        signature_b64=signature_b64,
        public_key=public_key_data,
        key_format=key_format,
    )
