"""Tests for anchor payload validation."""

from __future__ import annotations

import pytest

from specora_verify.validators.anchor import validate_anchor_payload


@pytest.fixture
def sample_anchor_payload() -> dict:
    """Create a valid anchor payload for testing."""
    return {
        "payload_schema_version": "1.0.0",
        "root_hash": "a4d31481f3caafb2cc89bdf11f422eb1cf658603672d2fb4ab21dcba67d3e6ba",
        "root_type": "daily",
        "period_start": "2026-03-01T00:00:00Z",
        "period_end": "2026-03-01T23:59:59Z",
        "leaf_count": 4250,
        "first_seq": 100001,
        "last_seq": 104250,
        "manifest_hash": "4e4cd3656219d8d8b52e75c94f20ce03f2ee592e71d8d6f49c17facfdbf960af",
        "manifest_spec_id": "proof-manifest",
        "manifest_schema_version": "1.0.0",
        "hash_algorithm": "sha256",
        "hash_algorithm_version": "1",
        "ledger_hash_algorithm": "sha256",
        "ledger_hash_algorithm_version": "1",
        "org_id": "c16922ef-95de-4d43-ac62-a279fac7e14f",
    }


class TestAnchorPayloadValidation:
    """Tests for validate_anchor_payload function."""

    def test_valid_anchor_payload(self, sample_anchor_payload: dict) -> None:
        """Valid anchor payload must pass validation."""
        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid
        assert result.schema_version == "1.0.0"
        assert result.root_type == "daily"
        assert result.manifest_hash == "4e4cd3656219d8d8b52e75c94f20ce03f2ee592e71d8d6f49c17facfdbf960af"
        assert result.computed_hash is not None
        assert len(result.computed_hash) == 64

    def test_missing_required_field(self, sample_anchor_payload: dict) -> None:
        """Missing required field must fail validation."""
        del sample_anchor_payload["root_hash"]

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("root_hash" in e for e in result.errors)

    def test_missing_manifest_hash(self, sample_anchor_payload: dict) -> None:
        """Missing manifest_hash must fail validation."""
        del sample_anchor_payload["manifest_hash"]

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("manifest_hash" in e for e in result.errors)

    def test_invalid_root_hash_format(self, sample_anchor_payload: dict) -> None:
        """Invalid root_hash format must fail validation."""
        sample_anchor_payload["root_hash"] = "not-a-valid-hash"

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("root_hash" in e and "hex" in e.lower() for e in result.errors)

    def test_invalid_timestamp_format(self, sample_anchor_payload: dict) -> None:
        """Invalid timestamp format must fail validation."""
        sample_anchor_payload["period_start"] = "2026-03-01"

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("period_start" in e for e in result.errors)

    def test_expected_hash_match(self, sample_anchor_payload: dict) -> None:
        """Expected hash matching computed hash must pass."""
        result = validate_anchor_payload(sample_anchor_payload)
        expected = result.computed_hash

        result2 = validate_anchor_payload(sample_anchor_payload, expected_hash=expected)

        assert result2.valid
        assert result2.computed_hash == expected

    def test_expected_hash_mismatch(self, sample_anchor_payload: dict) -> None:
        """Expected hash not matching must fail."""
        wrong_hash = "0" * 64

        result = validate_anchor_payload(sample_anchor_payload, expected_hash=wrong_hash)

        assert not result.valid
        assert any("mismatch" in e.lower() for e in result.errors)


class TestNullableSequenceFields:
    """Tests for nullable first_seq/last_seq fields."""

    def test_null_first_seq_valid(self, sample_anchor_payload: dict) -> None:
        """null first_seq must be valid."""
        sample_anchor_payload["first_seq"] = None
        sample_anchor_payload["last_seq"] = None

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_integer_first_seq_valid(self, sample_anchor_payload: dict) -> None:
        """Integer first_seq must be valid."""
        sample_anchor_payload["first_seq"] = 0
        sample_anchor_payload["last_seq"] = 100

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_string_first_seq_invalid(self, sample_anchor_payload: dict) -> None:
        """String first_seq must be invalid."""
        sample_anchor_payload["first_seq"] = "100"

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("first_seq" in e and "integer" in e.lower() for e in result.errors)

    def test_float_first_seq_invalid(self, sample_anchor_payload: dict) -> None:
        """Float first_seq must be invalid."""
        sample_anchor_payload["first_seq"] = 100.5

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("float" in e.lower() for e in result.errors)

    def test_negative_first_seq_invalid(self, sample_anchor_payload: dict) -> None:
        """Negative first_seq must be invalid."""
        sample_anchor_payload["first_seq"] = -1

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("first_seq" in e and "non-negative" in e.lower() for e in result.errors)


class TestRootTypeValidation:
    """Tests for root_type enum validation."""

    def test_daily_root_type_valid(self, sample_anchor_payload: dict) -> None:
        """daily root_type must be valid."""
        sample_anchor_payload["root_type"] = "daily"

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_hourly_root_type_valid(self, sample_anchor_payload: dict) -> None:
        """hourly root_type must be valid."""
        sample_anchor_payload["root_type"] = "hourly"

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_monthly_root_type_valid(self, sample_anchor_payload: dict) -> None:
        """monthly root_type must be valid."""
        sample_anchor_payload["root_type"] = "monthly"

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_invalid_root_type(self, sample_anchor_payload: dict) -> None:
        """Invalid root_type must fail validation."""
        sample_anchor_payload["root_type"] = "weekly"

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("root_type" in e for e in result.errors)


class TestOptionalOrgId:
    """Tests for optional org_id field."""

    def test_with_org_id_valid(self, sample_anchor_payload: dict) -> None:
        """Payload with org_id must be valid."""
        assert "org_id" in sample_anchor_payload

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_without_org_id_valid(self, sample_anchor_payload: dict) -> None:
        """Payload without org_id must be valid (optional field)."""
        del sample_anchor_payload["org_id"]

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_invalid_org_id_format(self, sample_anchor_payload: dict) -> None:
        """Invalid org_id format must fail validation."""
        sample_anchor_payload["org_id"] = "not-a-uuid"

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("org_id" in e for e in result.errors)


class TestLeafCountValidation:
    """Tests for leaf_count validation."""

    def test_positive_leaf_count_valid(self, sample_anchor_payload: dict) -> None:
        """Positive leaf_count must be valid."""
        sample_anchor_payload["leaf_count"] = 100

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_zero_leaf_count_valid(self, sample_anchor_payload: dict) -> None:
        """Zero leaf_count must be valid."""
        sample_anchor_payload["leaf_count"] = 0

        result = validate_anchor_payload(sample_anchor_payload)

        assert result.valid

    def test_string_leaf_count_invalid(self, sample_anchor_payload: dict) -> None:
        """String leaf_count must be invalid."""
        sample_anchor_payload["leaf_count"] = "100"

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("leaf_count" in e and "integer" in e.lower() for e in result.errors)

    def test_negative_leaf_count_invalid(self, sample_anchor_payload: dict) -> None:
        """Negative leaf_count must be invalid."""
        sample_anchor_payload["leaf_count"] = -1

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("leaf_count" in e and "non-negative" in e.lower() for e in result.errors)


class TestFloatProhibition:
    """Tests for float prohibition in anchor payloads."""

    def test_float_leaf_count_invalid(self, sample_anchor_payload: dict) -> None:
        """Float leaf_count must be invalid."""
        sample_anchor_payload["leaf_count"] = 100.0

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("float" in e.lower() for e in result.errors)

    def test_float_first_seq_invalid(self, sample_anchor_payload: dict) -> None:
        """Float first_seq must be invalid."""
        sample_anchor_payload["first_seq"] = 100.0

        result = validate_anchor_payload(sample_anchor_payload)

        assert not result.valid
        assert any("float" in e.lower() for e in result.errors)
