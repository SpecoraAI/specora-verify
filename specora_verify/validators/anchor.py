"""Anchor payload validation and vector verification.

Validates anchor payload structure, types, and verifies golden vectors
for anchor-payload specifications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.hash import sha256_hex
from specora_verify.validators.manifest import validate_manifest

# Default anchor vectors directory (relative to repo root)
DEFAULT_ANCHOR_VECTORS_DIR = Path(__file__).parent.parent / "vectors" / "anchor"


@dataclass
class AnchorValidationResult:
    """Result of anchor payload validation."""

    valid: bool
    schema_version: str | None = None
    computed_hash: str | None = None
    expected_hash: str | None = None
    root_type: str | None = None
    manifest_hash: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "valid": self.valid,
            "schema_version": self.schema_version,
            "computed_hash": self.computed_hash,
            "expected_hash": self.expected_hash,
            "root_type": self.root_type,
            "manifest_hash": self.manifest_hash,
            "errors": self.errors,
        }


@dataclass
class AnchorVectorResult:
    """Result for a single anchor vector verification."""

    spec_id: str
    version: str
    bytes_match: bool
    hash_match: bool
    computed_hash: str
    expected_hash: str
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.bytes_match and self.hash_match

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_id": self.spec_id,
            "version": self.version,
            "valid": self.valid,
            "bytes_match": self.bytes_match,
            "hash_match": self.hash_match,
            "computed_hash": self.computed_hash,
            "expected_hash": self.expected_hash,
            "errors": self.errors,
        }


@dataclass
class AnchorVectorVerificationResult:
    """Result of anchor golden vector verification."""

    valid: bool
    vectors_dir: str
    total: int
    passed: int
    failed: int
    results: list[AnchorVectorResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "vectors_dir": self.vectors_dir,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
        }


def validate_anchor_payload(
    payload: dict[str, Any],
    *,
    expected_hash: str | None = None,
) -> AnchorValidationResult:
    """Validate anchor payload structure, types, and optionally hash.

    Args:
        payload: Anchor payload dictionary to validate
        expected_hash: Optional expected SHA-256 hash to verify against

    Returns:
        AnchorValidationResult with validation details
    """
    # Use manifest validation with forced spec_id
    manifest_result = validate_manifest(
        payload,
        expected_hash=expected_hash,
        spec_id="anchor-payload",
        schema_version="1.0.0",
    )

    # Extract anchor-specific fields
    return AnchorValidationResult(
        valid=manifest_result.valid,
        schema_version=payload.get("payload_schema_version"),
        computed_hash=manifest_result.computed_hash,
        expected_hash=manifest_result.expected_hash,
        root_type=payload.get("root_type"),
        manifest_hash=payload.get("manifest_hash"),
        errors=manifest_result.errors,
    )


def _load_anchor_vector_files(
    vectors_dir: Path,
    spec_id: str,
    version: str,
) -> tuple[dict[str, Any] | None, bytes | None, str | None, list[str]]:
    """Load the three vector files for an anchor spec.

    Returns:
        (payload, canonical_bytes, expected_hash, errors)
    """
    import json

    errors: list[str] = []

    # File paths
    json_file = vectors_dir / f"{spec_id}-{version}.json"
    canonical_file = vectors_dir / f"{spec_id}-{version}.canonical.json"
    sha256_file = vectors_dir / f"{spec_id}-{version}.sha256.txt"

    # Load JSON payload
    payload = None
    if json_file.exists():
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse {json_file.name}: {e}")
    else:
        errors.append(f"Vector file not found: {json_file.name}")

    # Load expected canonical bytes
    canonical_bytes = None
    if canonical_file.exists():
        canonical_bytes = canonical_file.read_bytes()
    else:
        errors.append(f"Canonical file not found: {canonical_file.name}")

    # Load expected hash
    expected_hash = None
    if sha256_file.exists():
        expected_hash = sha256_file.read_text(encoding="utf-8").strip()
    else:
        errors.append(f"Hash file not found: {sha256_file.name}")

    return payload, canonical_bytes, expected_hash, errors


def verify_single_anchor_vector(
    vectors_dir: Path,
    spec_id: str,
    version: str,
) -> AnchorVectorResult:
    """Verify a single anchor golden vector.

    Args:
        vectors_dir: Path to anchor vectors directory
        spec_id: Spec ID (e.g., "anchor-payload")
        version: Schema version (e.g., "1.0.0")

    Returns:
        AnchorVectorResult with verification details
    """
    payload, expected_bytes, expected_hash, load_errors = _load_anchor_vector_files(
        vectors_dir, spec_id, version
    )

    if load_errors or payload is None or expected_bytes is None or expected_hash is None:
        return AnchorVectorResult(
            spec_id=spec_id,
            version=version,
            bytes_match=False,
            hash_match=False,
            computed_hash="",
            expected_hash=expected_hash or "",
            errors=load_errors,
        )

    # Compute canonical bytes and hash
    computed_bytes = canonical_json_bytes(payload)
    computed_hash = sha256_hex(computed_bytes)

    # Compare
    bytes_match = computed_bytes == expected_bytes
    hash_match = computed_hash == expected_hash

    errors: list[str] = []
    if not bytes_match:
        errors.append(
            f"Canonical bytes mismatch for {spec_id} v{version}. "
            f"Computed {len(computed_bytes)} bytes, expected {len(expected_bytes)} bytes."
        )
    if not hash_match:
        errors.append(
            f"Hash mismatch for {spec_id} v{version}. "
            f"Computed {computed_hash}, expected {expected_hash}."
        )

    return AnchorVectorResult(
        spec_id=spec_id,
        version=version,
        bytes_match=bytes_match,
        hash_match=hash_match,
        computed_hash=computed_hash,
        expected_hash=expected_hash,
        errors=errors,
    )


def verify_anchor_vectors(
    vectors_dir: Path | str | None = None,
) -> AnchorVectorVerificationResult:
    """Verify all anchor golden vectors in the vectors directory.

    Args:
        vectors_dir: Path to anchor vectors directory (default: bundled vectors)

    Returns:
        AnchorVectorVerificationResult with all verification details
    """
    if vectors_dir is None:
        vectors_dir = DEFAULT_ANCHOR_VECTORS_DIR
    elif isinstance(vectors_dir, str):
        vectors_dir = Path(vectors_dir)

    result = AnchorVectorVerificationResult(
        valid=True,
        vectors_dir=str(vectors_dir),
        total=0,
        passed=0,
        failed=0,
    )

    if not vectors_dir.exists():
        result.valid = False
        result.errors.append(f"Anchor vectors directory not found: {vectors_dir}")
        return result

    # Known anchor vectors to verify
    known_vectors = [
        ("anchor-payload", "1.0.0"),
    ]

    for spec_id, version in known_vectors:
        vector_result = verify_single_anchor_vector(vectors_dir, spec_id, version)
        result.results.append(vector_result)
        result.total += 1

        if vector_result.valid:
            result.passed += 1
        else:
            result.failed += 1
            result.valid = False
            result.errors.extend(vector_result.errors)

    return result
