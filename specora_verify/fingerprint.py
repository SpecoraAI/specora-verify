"""Key fingerprint and derived key_id utilities.

This module provides deterministic key fingerprint computation and
derived key_id generation following a stable, documented rule.

Key Fingerprint:
    SHA-256 hash of the raw 32-byte Ed25519 public key bytes.
    Output: 64-character lowercase hexadecimal string.

Derived Key ID:
    First 16 characters of the key fingerprint, prefixed with "spk-".
    Example: spk-a1b2c3d4e5f6g7h8

This provides a human-readable, collision-resistant identifier for keys.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# Prefix for derived key IDs
KEY_ID_PREFIX = "spk-"

# Length of fingerprint portion in derived key ID (16 hex chars = 64 bits)
KEY_ID_FINGERPRINT_LENGTH = 16


def compute_key_fingerprint(public_key_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint of raw public key bytes.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key

    Returns:
        64-character lowercase hexadecimal fingerprint

    Example:
        >>> compute_key_fingerprint(b'\\x00' * 32)
        '66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925'
    """
    return hashlib.sha256(public_key_bytes).hexdigest()


def derive_key_id(fingerprint: str) -> str:
    """Derive a human-readable key ID from a fingerprint.

    The derived key ID is:
        "spk-" + first 16 characters of fingerprint

    This provides:
        - 64 bits of collision resistance (sufficient for key identification)
        - Human-readable format
        - Stable, predictable derivation

    Args:
        fingerprint: 64-character SHA-256 hex fingerprint

    Returns:
        Derived key ID (e.g., "spk-a1b2c3d4e5f6g7h8")

    Example:
        >>> derive_key_id("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
        'spk-a1b2c3d4e5f6g7h8'
    """
    return f"{KEY_ID_PREFIX}{fingerprint[:KEY_ID_FINGERPRINT_LENGTH]}"


def compute_key_fingerprint_and_id(public_key_bytes: bytes) -> tuple[str, str]:
    """Compute both fingerprint and derived key ID.

    Convenience function that returns both values.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key

    Returns:
        Tuple of (fingerprint, derived_key_id)
    """
    fingerprint = compute_key_fingerprint(public_key_bytes)
    derived_id = derive_key_id(fingerprint)
    return fingerprint, derived_id


def fingerprint_from_public_key(public_key: Ed25519PublicKey) -> str:
    """Compute fingerprint from Ed25519PublicKey object.

    Requires cryptography library.

    Args:
        public_key: Ed25519PublicKey instance

    Returns:
        64-character lowercase hexadecimal fingerprint
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return compute_key_fingerprint(raw_bytes)


def derived_key_id_from_public_key(public_key: Ed25519PublicKey) -> str:
    """Derive key ID from Ed25519PublicKey object.

    Requires cryptography library.

    Args:
        public_key: Ed25519PublicKey instance

    Returns:
        Derived key ID (e.g., "spk-a1b2c3d4e5f6g7h8")
    """
    fingerprint = fingerprint_from_public_key(public_key)
    return derive_key_id(fingerprint)
