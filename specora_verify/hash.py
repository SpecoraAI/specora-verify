"""SHA-256 hash computation for manifest verification.

This module provides hash computation functions that produce
64-character lowercase hex strings matching the Specora platform.
"""

from __future__ import annotations

import hashlib
from typing import Any

from specora_verify.canonical import canonical_json_bytes


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return lowercase hex string.

    Args:
        data: Bytes to hash

    Returns:
        64-character lowercase hex string

    Example:
        >>> sha256_hex(b'test')
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    """
    return hashlib.sha256(data).hexdigest()


def compute_manifest_hash(payload: dict[str, Any]) -> str:
    """Compute SHA-256 hash of canonical JSON representation.

    This is the standard hash computation for manifest verification:
    1. Serialize payload to canonical JSON bytes
    2. Compute SHA-256 of the bytes
    3. Return lowercase hex digest

    Args:
        payload: Manifest dictionary to hash

    Returns:
        64-character lowercase hex hash

    Example:
        >>> compute_manifest_hash({"id": "test", "value": 123})
        # Returns SHA-256 of '{"id":"test","value":123}'
    """
    return sha256_hex(canonical_json_bytes(payload))
