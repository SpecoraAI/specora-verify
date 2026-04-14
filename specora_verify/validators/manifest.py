"""Manifest validation logic.

Validates manifest structure, types, and optionally compares computed
hash against an expected value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from specora_verify.contracts.registry import (
    HEX_HASH_PATTERN,
    TIMESTAMP_PATTERN,
    UUID_PATTERN,
    detect_spec_id,
    get_contract,
)
from specora_verify.hash import compute_manifest_hash


@dataclass
class ManifestValidationResult:
    """Result of manifest validation."""

    valid: bool
    spec_id: str | None = None
    schema_version: str | None = None
    computed_hash: str | None = None
    expected_hash: str | None = None
    missing_fields: list[str] = field(default_factory=list)
    type_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "valid": self.valid,
            "spec_id": self.spec_id,
            "schema_version": self.schema_version,
            "computed_hash": self.computed_hash,
            "expected_hash": self.expected_hash,
            "missing_fields": self.missing_fields,
            "type_errors": self.type_errors,
            "errors": self.errors,
        }


def _validate_field_type(
    field_name: str,
    value: Any,
    expected_type: str,
) -> str | None:
    """Validate a single field's type and format.

    Returns error message if invalid, None if valid.
    """
    if expected_type.startswith("enum:"):
        allowed = expected_type[5:].split("|")
        if not isinstance(value, str) or value not in allowed:
            return f"'{field_name}' must be one of {allowed}, got '{value}'"
        return None

    if expected_type == "uuid":
        if not isinstance(value, str):
            return f"'{field_name}' must be a string (UUID), got {type(value).__name__}"
        if not UUID_PATTERN.match(value):
            return f"'{field_name}' must be lowercase hyphenated UUID, got '{value}'"
        return None

    if expected_type == "hex64":
        if not isinstance(value, str):
            return f"'{field_name}' must be a string (hex), got {type(value).__name__}"
        if not HEX_HASH_PATTERN.match(value):
            return f"'{field_name}' must be 64-char lowercase hex, got '{value}'"
        return None

    if expected_type == "iso8601_utc":
        if not isinstance(value, str):
            return f"'{field_name}' must be a string (timestamp), got {type(value).__name__}"
        if not TIMESTAMP_PATTERN.match(value):
            return f"'{field_name}' must be ISO8601 UTC with Z suffix (YYYY-MM-DDTHH:MM:SSZ), got '{value}'"
        return None

    if expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return f"'{field_name}' must be an integer, got {type(value).__name__}"
        if value < 0:
            return f"'{field_name}' must be non-negative, got {value}"
        return None

    if expected_type == "integer_or_null":
        if value is None:
            return None  # null is valid
        if not isinstance(value, int) or isinstance(value, bool):
            return f"'{field_name}' must be an integer or null, got {type(value).__name__}"
        if value < 0:
            return f"'{field_name}' must be non-negative, got {value}"
        return None

    if expected_type == "string":
        if not isinstance(value, str):
            return f"'{field_name}' must be a string, got {type(value).__name__}"
        return None

    return None


def _check_no_floats(data: dict[str, Any], path: str = "") -> list[str]:
    """Recursively check for float values (prohibited in manifests).

    Returns list of field paths containing floats.
    """
    errors = []
    for key, value in data.items():
        field_path = f"{path}.{key}" if path else key
        if isinstance(value, float):
            errors.append(f"'{field_path}' contains float value {value} (floats prohibited)")
        elif isinstance(value, dict):
            errors.extend(_check_no_floats(value, field_path))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, float):
                    errors.append(
                        f"'{field_path}[{i}]' contains float value {item} (floats prohibited)"
                    )
                elif isinstance(item, dict):
                    errors.extend(_check_no_floats(item, f"{field_path}[{i}]"))
    return errors


def validate_manifest(
    payload: dict[str, Any],
    *,
    expected_hash: str | None = None,
    spec_id: str | None = None,
    schema_version: str | None = None,
) -> ManifestValidationResult:
    """Validate manifest structure, types, and optionally hash.

    Args:
        payload: Manifest dictionary to validate
        expected_hash: Optional expected SHA-256 hash to verify against
        spec_id: Override spec_id detection (e.g., "proof-manifest")
        schema_version: Override schema version (e.g., "1.0.0")

    Returns:
        ManifestValidationResult with validation details
    """
    result = ManifestValidationResult(valid=True)
    result.expected_hash = expected_hash

    # Detect or use provided spec_id
    detected_spec_id = spec_id or detect_spec_id(payload)
    if not detected_spec_id:
        result.valid = False
        result.errors.append(
            "Cannot detect manifest type. Provide --spec-id or ensure "
            "manifest has distinguishing fields (payload_schema_version+manifest_hash "
            "for anchor-payload, root_type/root_hash/leaf_count "
            "for proof-manifest, snapshot_type for attestation-manifest)"
        )
        return result

    result.spec_id = detected_spec_id
    result.schema_version = schema_version or "1.0.0"

    # Get contract
    try:
        contract = get_contract(result.spec_id, result.schema_version)
    except KeyError:
        result.valid = False
        result.errors.append(
            f"Unknown manifest contract: {result.spec_id} v{result.schema_version}"
        )
        return result

    # Validate required fields
    missing = contract.validate_required_fields(payload)
    if missing:
        result.valid = False
        result.missing_fields = missing
        result.errors.append(f"Missing required fields: {', '.join(missing)}")

    # Check for floats (prohibited)
    float_errors = _check_no_floats(payload)
    if float_errors:
        result.valid = False
        result.type_errors.extend(float_errors)
        result.errors.extend(float_errors)

    # Validate field types
    validators = contract.get_field_validators()
    for field_name, (expected_type, _pattern) in validators.items():
        if field_name in payload:
            error = _validate_field_type(field_name, payload[field_name], expected_type)
            if error:
                result.valid = False
                result.type_errors.append(error)
                result.errors.append(error)

    # Compute hash
    result.computed_hash = compute_manifest_hash(payload)

    # Compare with expected hash if provided
    if expected_hash:
        if result.computed_hash != expected_hash:
            result.valid = False
            result.errors.append(
                f"Hash mismatch: computed {result.computed_hash}, expected {expected_hash}"
            )

    return result
