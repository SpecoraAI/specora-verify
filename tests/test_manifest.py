"""Tests for manifest validation."""

from __future__ import annotations

import pytest

from specora_verify.validators.manifest import validate_manifest


class TestProofManifestValidation:
    """Tests for proof-manifest validation."""

    def test_valid_proof_manifest(self, sample_proof_manifest: dict) -> None:
        """Valid proof manifest must pass validation."""
        result = validate_manifest(sample_proof_manifest)

        assert result.valid
        assert result.spec_id == "proof-manifest"
        assert result.schema_version == "1.0.0"
        assert result.computed_hash is not None
        assert len(result.computed_hash) == 64

    def test_missing_required_field(self, sample_proof_manifest: dict) -> None:
        """Missing required field must fail validation."""
        del sample_proof_manifest["root_hash"]
        # Must specify spec_id since root_hash is a detection field
        result = validate_manifest(sample_proof_manifest, spec_id="proof-manifest")

        assert not result.valid
        assert "root_hash" in result.missing_fields
        assert any("root_hash" in e for e in result.errors)

    def test_invalid_uuid_format(self, sample_proof_manifest: dict) -> None:
        """Invalid UUID format must fail validation."""
        sample_proof_manifest["id"] = "not-a-uuid"
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("uuid" in e.lower() for e in result.type_errors)

    def test_uppercase_uuid_fails(self, sample_proof_manifest: dict) -> None:
        """Uppercase UUID must fail (must be lowercase)."""
        sample_proof_manifest["id"] = "E3E817D2-0A81-4EBC-81B8-6A3F12B7A9F1"
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("lowercase" in e.lower() for e in result.type_errors)

    def test_invalid_timestamp_format(self, sample_proof_manifest: dict) -> None:
        """Timestamp without Z suffix must fail."""
        sample_proof_manifest["created_at"] = "2026-03-02T01:15:30+00:00"
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("iso8601" in e.lower() or "z" in e.lower() for e in result.type_errors)

    def test_invalid_root_type(self, sample_proof_manifest: dict) -> None:
        """Invalid root_type enum value must fail."""
        sample_proof_manifest["root_type"] = "invalid"
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("root_type" in e for e in result.type_errors)

    def test_invalid_root_hash_length(self, sample_proof_manifest: dict) -> None:
        """Root hash with wrong length must fail."""
        sample_proof_manifest["root_hash"] = "abc123"  # Too short
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("64" in e or "hex" in e.lower() for e in result.type_errors)

    def test_float_leaf_count_fails(self, sample_proof_manifest: dict) -> None:
        """Float value for leaf_count must fail."""
        sample_proof_manifest["leaf_count"] = 42.5
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("float" in e.lower() or "integer" in e.lower() for e in result.errors)

    def test_negative_leaf_count_fails(self, sample_proof_manifest: dict) -> None:
        """Negative leaf_count must fail."""
        sample_proof_manifest["leaf_count"] = -1
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("non-negative" in e.lower() for e in result.type_errors)

    def test_string_leaf_count_fails(self, sample_proof_manifest: dict) -> None:
        """String value for leaf_count must fail (must be integer)."""
        sample_proof_manifest["leaf_count"] = "4250"
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("integer" in e.lower() for e in result.type_errors)

    def test_boolean_not_integer(self, sample_proof_manifest: dict) -> None:
        """Boolean cannot substitute for integer."""
        sample_proof_manifest["leaf_count"] = True
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("integer" in e.lower() for e in result.type_errors)


class TestLeadingZeroIntegers:
    """Test leading-zero integer handling.

    Note: Leading-zero integers (e.g., 0100) are invalid JSON syntax.
    The JSON parser rejects them before our validator runs.
    This test documents that behavior.
    """

    def test_leading_zero_int_is_invalid_json(self) -> None:
        """Leading-zero integers are rejected at JSON parse time."""
        import json

        invalid_json = '{"leaf_count": 0100}'

        with pytest.raises(json.JSONDecodeError):
            json.loads(invalid_json)


class TestAttestationManifestValidation:
    """Tests for attestation-manifest validation."""

    def test_valid_attestation_manifest(self, sample_attestation_manifest: dict) -> None:
        """Valid attestation manifest must pass validation."""
        result = validate_manifest(sample_attestation_manifest)

        assert result.valid
        assert result.spec_id == "attestation-manifest"
        assert result.schema_version == "1.0.0"
        assert result.computed_hash is not None

    def test_invalid_snapshot_type(self, sample_attestation_manifest: dict) -> None:
        """Invalid snapshot_type enum value must fail."""
        sample_attestation_manifest["snapshot_type"] = "invalid"
        result = validate_manifest(sample_attestation_manifest)

        assert not result.valid
        assert any("snapshot_type" in e for e in result.type_errors)


class TestHashVerification:
    """Tests for hash verification."""

    def test_hash_match(self, sample_proof_manifest: dict) -> None:
        """Matching expected hash must pass."""
        # First compute the actual hash
        initial_result = validate_manifest(sample_proof_manifest)
        computed_hash = initial_result.computed_hash

        # Now verify with expected hash
        result = validate_manifest(sample_proof_manifest, expected_hash=computed_hash)

        assert result.valid
        assert result.computed_hash == result.expected_hash

    def test_hash_mismatch(self, sample_proof_manifest: dict) -> None:
        """Mismatched expected hash must fail."""
        wrong_hash = "0" * 64
        result = validate_manifest(sample_proof_manifest, expected_hash=wrong_hash)

        assert not result.valid
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_computed_hash_is_deterministic(self, sample_proof_manifest: dict) -> None:
        """Same input must always produce same hash."""
        result1 = validate_manifest(sample_proof_manifest)
        result2 = validate_manifest(sample_proof_manifest)
        result3 = validate_manifest(sample_proof_manifest)

        assert result1.computed_hash == result2.computed_hash == result3.computed_hash


class TestSpecIdOverride:
    """Tests for spec_id and schema_version override."""

    def test_explicit_spec_id(self, sample_proof_manifest: dict) -> None:
        """Explicit spec_id must override detection."""
        result = validate_manifest(
            sample_proof_manifest,
            spec_id="proof-manifest",
            schema_version="1.0.0",
        )

        assert result.valid
        assert result.spec_id == "proof-manifest"
        assert result.schema_version == "1.0.0"

    def test_unknown_spec_id_fails(self, sample_proof_manifest: dict) -> None:
        """Unknown spec_id must fail."""
        result = validate_manifest(
            sample_proof_manifest,
            spec_id="unknown-manifest",
            schema_version="1.0.0",
        )

        assert not result.valid
        assert any("unknown" in e.lower() for e in result.errors)

    def test_unknown_version_fails(self, sample_proof_manifest: dict) -> None:
        """Unknown schema version must fail."""
        result = validate_manifest(
            sample_proof_manifest,
            spec_id="proof-manifest",
            schema_version="99.0.0",
        )

        assert not result.valid
        assert any("unknown" in e.lower() for e in result.errors)


class TestFloatProhibition:
    """Tests for float prohibition in manifests."""

    def test_float_in_nested_object_fails(self, sample_proof_manifest: dict) -> None:
        """Float in nested object must fail."""
        sample_proof_manifest["metadata"] = {"ratio": 0.5}
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("float" in e.lower() for e in result.errors)

    def test_float_in_array_fails(self, sample_proof_manifest: dict) -> None:
        """Float in array must fail."""
        sample_proof_manifest["values"] = [1, 2, 3.14, 4]
        result = validate_manifest(sample_proof_manifest)

        assert not result.valid
        assert any("float" in e.lower() for e in result.errors)
