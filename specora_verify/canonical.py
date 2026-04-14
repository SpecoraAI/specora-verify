"""Canonical JSON serialization for manifest verification.

This module provides the canonical JSON serialization algorithm that MUST
produce byte-identical output to the internal Specora implementation.

The canonical format is documented in:
    Specora Wire Spec v1.0 §4 (Canonical JSON) - https://spec.specora.ai/v1.0

CRITICAL: Any changes to this algorithm require a schema version bump.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize dict to canonical JSON bytes for hashing.

    This is the authoritative serialization format matching:
    - Specora Wire Spec v1.0 Annex A (Canonical JSON reference impl)

    Canonical format:
    - sort_keys=True (deterministic key ordering, lexicographic)
    - separators=(",", ":") (compact, no whitespace)
    - ensure_ascii=True (portable encoding, non-ASCII escaped as \\uXXXX)
    - UTF-8 byte encoding
    - No trailing newlines

    Args:
        payload: Dictionary to serialize

    Returns:
        UTF-8 encoded bytes of canonical JSON

    Example:
        >>> canonical_json_bytes({"b": 2, "a": 1})
        b'{"a":1,"b":2}'
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def canonical_json_str(payload: dict[str, Any]) -> str:
    """Serialize dict to canonical JSON string.

    Use canonical_json_bytes() for hashing. This function is provided
    for cases where a string is needed (e.g., display, comparison).

    Args:
        payload: Dictionary to serialize

    Returns:
        Canonical JSON as string
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
