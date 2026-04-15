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


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize a JSON value to canonical bytes for hashing.

    Accepts any JSON-serializable value (object, array, string, number,
    boolean, null) per Specora Wire Spec v1.0 §4, which defines canonical
    form over the full JSON value type — not just top-level objects.

    Canonical format (Wire Spec v1.0 §4.1):
    - sort_keys=True (deterministic key ordering, lexicographic)
    - separators=(",", ":") (compact, no whitespace)
    - ensure_ascii=True (non-ASCII escaped as \\uXXXX for byte-identical
      output across encoders)
    - allow_nan=False (NaN / ±Infinity rejected)
    - UTF-8 byte encoding, no trailing newlines

    Args:
        payload: Any JSON value (dict, list, str, int, float, bool, None).

    Returns:
        UTF-8 encoded bytes of canonical JSON.

    Example:
        >>> canonical_json_bytes({"b": 2, "a": 1})
        b'{"a":1,"b":2}'
        >>> canonical_json_bytes([3, 1, 2])
        b'[3,1,2]'
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_str(payload: Any) -> str:
    """Serialize a JSON value to canonical string form.

    Use canonical_json_bytes() for hashing. This function is provided
    for cases where a string is needed (e.g., display, comparison).

    Args:
        payload: Any JSON-serializable value.

    Returns:
        Canonical JSON as string.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
