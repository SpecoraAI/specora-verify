"""Tests for canonical JSON serialization.

These tests verify the canonical JSON algorithm produces deterministic,
spec-compliant output.
"""

from __future__ import annotations

import pytest

from specora_verify.canonical import canonical_json_bytes, canonical_json_str


class TestCanonicalJsonBytes:
    """Tests for canonical_json_bytes()."""

    def test_sorts_keys(self) -> None:
        """Keys must be sorted lexicographically."""
        payload = {"z": 1, "a": 2, "m": 3}
        result = canonical_json_bytes(payload)
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_nested_key_sorting(self) -> None:
        """Nested object keys must also be sorted."""
        payload = {"outer": {"z": 1, "a": 2}}
        result = canonical_json_bytes(payload)
        assert result == b'{"outer":{"a":2,"z":1}}'

    def test_compact_separators(self) -> None:
        """No whitespace in output."""
        payload = {"key": "value", "list": [1, 2, 3]}
        result = canonical_json_bytes(payload)
        assert b" " not in result
        assert b"\n" not in result
        assert b"\t" not in result

    def test_ascii_encoding(self) -> None:
        """Non-ASCII characters must be escaped."""
        payload = {"emoji": "\u2764"}  # Red heart
        result = canonical_json_bytes(payload)
        assert result == b'{"emoji":"\\u2764"}'

    def test_utf8_byte_encoding(self) -> None:
        """Output must be UTF-8 bytes."""
        payload = {"test": "value"}
        result = canonical_json_bytes(payload)
        assert isinstance(result, bytes)
        assert result.decode("utf-8") == '{"test":"value"}'

    def test_no_trailing_newline(self) -> None:
        """Output must not have trailing newline."""
        payload = {"key": "value"}
        result = canonical_json_bytes(payload)
        assert not result.endswith(b"\n")

    def test_integer_representation(self) -> None:
        """Integers must be represented without quotes."""
        payload = {"count": 42}
        result = canonical_json_bytes(payload)
        assert result == b'{"count":42}'

    def test_boolean_representation(self) -> None:
        """Booleans must be lowercase true/false."""
        payload = {"active": True, "deleted": False}
        result = canonical_json_bytes(payload)
        assert b"true" in result
        assert b"false" in result
        assert b"True" not in result
        assert b"False" not in result

    def test_null_representation(self) -> None:
        """None must be represented as null."""
        payload = {"value": None}
        result = canonical_json_bytes(payload)
        assert result == b'{"value":null}'

    def test_empty_object(self) -> None:
        """Empty object must serialize correctly."""
        result = canonical_json_bytes({})
        assert result == b"{}"

    def test_empty_array(self) -> None:
        """Empty array must serialize correctly."""
        payload = {"items": []}
        result = canonical_json_bytes(payload)
        assert result == b'{"items":[]}'

    def test_determinism(self) -> None:
        """Same input must always produce same output."""
        payload = {"b": 2, "a": 1, "c": 3}
        result1 = canonical_json_bytes(payload)
        result2 = canonical_json_bytes(payload)
        result3 = canonical_json_bytes(payload)
        assert result1 == result2 == result3


class TestCanonicalJsonStr:
    """Tests for canonical_json_str()."""

    def test_returns_string(self) -> None:
        """Output must be a string."""
        result = canonical_json_str({"key": "value"})
        assert isinstance(result, str)

    def test_matches_bytes_decode(self) -> None:
        """String output must match bytes decoded as UTF-8."""
        payload = {"test": "value", "num": 123}
        str_result = canonical_json_str(payload)
        bytes_result = canonical_json_bytes(payload).decode("utf-8")
        assert str_result == bytes_result


class TestEdgeCases:
    """Edge case tests."""

    def test_unicode_in_keys(self) -> None:
        """Unicode in keys must be handled correctly."""
        payload = {"caf\u00e9": "coffee"}
        result = canonical_json_bytes(payload)
        # Key must be ASCII-escaped
        assert b"\\u00e9" in result

    def test_special_characters_in_strings(self) -> None:
        """Special characters must be properly escaped."""
        payload = {"text": 'line1\nline2\ttab"quote'}
        result = canonical_json_bytes(payload)
        assert b"\\n" in result
        assert b"\\t" in result
        assert b'\\"' in result

    def test_large_integer(self) -> None:
        """Large integers within safe range must work."""
        payload = {"big": 9007199254740991}  # Max safe integer
        result = canonical_json_bytes(payload)
        assert b"9007199254740991" in result

    def test_negative_integer(self) -> None:
        """Negative integers must work."""
        payload = {"negative": -42}
        result = canonical_json_bytes(payload)
        assert result == b'{"negative":-42}'

    def test_deeply_nested(self) -> None:
        """Deeply nested structures must work."""
        payload = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        result = canonical_json_bytes(payload)
        assert result == b'{"a":{"b":{"c":{"d":{"e":1}}}}}'


class TestWireSpecV1ValueTypes:
    """Wire Spec v1.0 §4 defines canonical form over any JSON value, not
    just top-level objects. These tests lock the widened contract."""

    def test_top_level_array(self) -> None:
        assert canonical_json_bytes([3, 1, 2]) == b"[3,1,2]"

    def test_top_level_string(self) -> None:
        assert canonical_json_bytes("hello") == b'"hello"'

    def test_top_level_integer(self) -> None:
        assert canonical_json_bytes(42) == b"42"

    def test_top_level_null(self) -> None:
        assert canonical_json_bytes(None) == b"null"

    def test_array_of_objects_inner_keys_sorted(self) -> None:
        payload = [{"z": 1, "a": 2}, {"y": 3, "b": 4}]
        assert canonical_json_bytes(payload) == b'[{"a":2,"z":1},{"b":4,"y":3}]'

    def test_nan_rejected(self) -> None:
        import math

        with pytest.raises(ValueError):
            canonical_json_bytes({"x": math.nan})

    def test_infinity_rejected(self) -> None:
        import math

        with pytest.raises(ValueError):
            canonical_json_bytes({"x": math.inf})
