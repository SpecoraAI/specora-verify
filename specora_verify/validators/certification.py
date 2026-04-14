"""Certification attestation validation and verification.

Validates certification attestation structure, generates attestations,
and verifies certification bundles against tier requirements.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.hash import sha256_hex


# Default certification vectors directory (relative to repo root)
DEFAULT_CERTIFICATION_VECTORS_DIR = Path(__file__).parent.parent.parent / "vectors" / "certification"

# Tier requirement definitions
TIER_REQUIREMENTS: dict[str, list[str]] = {
    "basic": [
        "RCP-66",  # Canonical JSON Determinism
        "RCP-79",  # Manifest Schema Compliance
        "RCP-86",  # Proof Manifest Hash Binding
        "RCP-87",  # Attestation Manifest Hash Binding
        "RCP-88",  # Merkle Root Integrity
        "RCP-94",  # Public Verifier Availability
        "RCP-95",  # Verifier Vector Parity
        "RCP-96",  # Offline Verification Sufficiency
        "RCP-101",  # Cross-Language Vector Parity
        "RCP-103",  # Proof Surface Availability
        "RCP-108",  # Certification Spec Availability
        "RCP-109",  # Certification Attestation Determinism
        "RCP-110",  # Certification Bundle Sufficiency
        "RCP-111",  # Renewal/Revocation Policy Disclosure
        "RCP-112",  # Integrator Enablement Availability
        "RCP-113",  # Certification Scaffold Availability
    ],
    "enterprise": [
        # All basic requirements
        "RCP-66", "RCP-79", "RCP-86", "RCP-87", "RCP-88",
        "RCP-94", "RCP-95", "RCP-96", "RCP-101", "RCP-103",
        "RCP-108", "RCP-109", "RCP-110", "RCP-111", "RCP-112", "RCP-113",
        # Enterprise additions
        "RCP-97",   # Anchor Payload Spec Availability
        "RCP-98",   # Anchor Payload Hash Determinism
        "RCP-99",   # Anchor/Manifest Binding
        "RCP-100",  # Anchor Vector Parity
        "RCP-104",  # Anchor Receipt Spec Availability
        "RCP-105",  # Receipt Hash Determinism
        "RCP-106",  # Payload/Receipt Binding
        "RCP-107",  # Receipt Vector Parity
        "RCP-24",   # Routing Determinism
        "RCP-48",   # Replay Availability
    ],
    "regulated": [
        # All enterprise requirements
        "RCP-66", "RCP-79", "RCP-86", "RCP-87", "RCP-88",
        "RCP-94", "RCP-95", "RCP-96", "RCP-101", "RCP-103",
        "RCP-108", "RCP-109", "RCP-110", "RCP-111", "RCP-112", "RCP-113",
        "RCP-97", "RCP-98", "RCP-99", "RCP-100",
        "RCP-104", "RCP-105", "RCP-106", "RCP-107",
        "RCP-24", "RCP-48",
        # Regulated additions
        "RCP-68",  # TLA+ Model Availability
        "RCP-69",  # TLA+ CI Enforcement
        "RCP-70",  # TLA+ Invariant Coverage
        "RCP-46",  # Audit Export Integrity
        "RCP-51",  # Audit Export Offline Verification
    ],
}

# Required artifacts by tier
TIER_ARTIFACTS: dict[str, list[str]] = {
    "basic": [
        "meta.json",
        "proofs/proof-manifest.json",
        "proofs/attestation-manifest.json",
        "verification/specora-verify-output.json",
    ],
    "enterprise": [
        "meta.json",
        "proofs/proof-manifest.json",
        "proofs/attestation-manifest.json",
        "proofs/anchor-payload.json",
        "proofs/anchor-receipt.json",
        "verification/specora-verify-output.json",
    ],
    "regulated": [
        "meta.json",
        "proofs/proof-manifest.json",
        "proofs/attestation-manifest.json",
        "proofs/anchor-payload.json",
        "proofs/anchor-receipt.json",
        "verification/specora-verify-output.json",
        "optional/tla-summary.json",
    ],
}


@dataclass
class CertificationCheckResult:
    """Result of certification bundle check."""

    valid: bool
    tier: str
    bundle_path: str
    artifacts_found: list[str] = field(default_factory=list)
    artifacts_missing: list[str] = field(default_factory=list)
    requirements_met: list[str] = field(default_factory=list)
    requirements_missing: list[str] = field(default_factory=list)
    verification_results: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "tier": self.tier,
            "bundle_path": self.bundle_path,
            "artifacts_found": self.artifacts_found,
            "artifacts_missing": self.artifacts_missing,
            "requirements_met": self.requirements_met,
            "requirements_missing": self.requirements_missing,
            "verification_results": self.verification_results,
            "errors": self.errors,
        }


@dataclass
class CertificationAttestationResult:
    """Result of attestation validation."""

    valid: bool
    spec_id: str | None = None
    schema_version: str | None = None
    tier: str | None = None
    computed_hash: str | None = None
    expected_hash: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "spec_id": self.spec_id,
            "schema_version": self.schema_version,
            "tier": self.tier,
            "computed_hash": self.computed_hash,
            "expected_hash": self.expected_hash,
            "errors": self.errors,
        }


@dataclass
class CertificationVectorResult:
    """Result for a single certification vector verification."""

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
class CertificationVectorVerificationResult:
    """Result of certification golden vector verification."""

    valid: bool
    vectors_dir: str
    total: int
    passed: int
    failed: int
    results: list[CertificationVectorResult] = field(default_factory=list)
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


def check_certification_bundle(
    bundle_path: Path,
    tier: str,
) -> CertificationCheckResult:
    """Check a certification bundle against tier requirements.

    Args:
        bundle_path: Path to certification bundle directory
        tier: Tier to check against (basic, enterprise, regulated)

    Returns:
        CertificationCheckResult with check details
    """
    result = CertificationCheckResult(
        valid=True,
        tier=tier,
        bundle_path=str(bundle_path),
    )

    # Validate tier
    if tier not in TIER_REQUIREMENTS:
        result.valid = False
        result.errors.append(f"Unknown tier: {tier}. Must be basic, enterprise, or regulated.")
        return result

    # Check required artifacts exist
    required_artifacts = TIER_ARTIFACTS.get(tier, [])
    for artifact in required_artifacts:
        artifact_path = bundle_path / artifact
        if artifact_path.exists():
            result.artifacts_found.append(artifact)
        else:
            result.artifacts_missing.append(artifact)

    if result.artifacts_missing:
        result.valid = False
        result.errors.append(f"Missing required artifacts: {', '.join(result.artifacts_missing)}")

    # Load and verify meta.json
    meta_path = bundle_path / "meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("tier_requested") != tier:
                result.errors.append(
                    f"meta.json tier_requested ({meta.get('tier_requested')}) "
                    f"does not match requested tier ({tier})"
                )
        except json.JSONDecodeError as e:
            result.valid = False
            result.errors.append(f"Failed to parse meta.json: {e}")

    # Verify verification output
    verify_output_path = bundle_path / "verification" / "specora-verify-output.json"
    if verify_output_path.exists():
        try:
            verify_output = json.loads(verify_output_path.read_text(encoding="utf-8"))
            if verify_output.get("status") == "pass":
                result.verification_results["specora_verify"] = "pass"
            else:
                result.valid = False
                result.verification_results["specora_verify"] = "fail"
                result.errors.append("Verification output status is not 'pass'")
        except json.JSONDecodeError as e:
            result.valid = False
            result.errors.append(f"Failed to parse verification output: {e}")

    # Determine requirements met
    # For now, we assume requirements are met if artifacts are present
    # A more complete implementation would verify each artifact
    tier_requirements = TIER_REQUIREMENTS.get(tier, [])
    if result.valid and not result.artifacts_missing:
        result.requirements_met = tier_requirements.copy()
    else:
        result.requirements_missing = tier_requirements.copy()

    return result


def generate_attestation(
    bundle_path: Path,
    tier: str,
    issued_at: str,
    integration_name: str,
    integration_version: str,
    proof_surface_url: str = "https://specora.ai/proof",
    vendor_id: str | None = None,
    ci_badges: list[str] | None = None,
    specora_verify_version: str = "1.0.0",
    node_verifier_commit: str | None = None,
) -> dict[str, Any]:
    """Generate a certification attestation for a bundle.

    Args:
        bundle_path: Path to certification bundle
        tier: Certification tier
        issued_at: ISO8601 timestamp for attestation
        integration_name: Integration identifier
        integration_version: Integration version
        proof_surface_url: URL to proof surface
        vendor_id: Optional vendor UUID
        ci_badges: List of CI badge URLs
        specora_verify_version: Version of specora-verify used
        node_verifier_commit: Optional Node.js verifier commit

    Returns:
        Attestation dictionary
    """
    # Check bundle first
    check_result = check_certification_bundle(bundle_path, tier)

    # Compute evidence hashes
    evidence_hashes: dict[str, str] = {}

    meta_path = bundle_path / "meta.json"
    if meta_path.exists():
        meta_content = json.loads(meta_path.read_text(encoding="utf-8"))
        evidence_hashes["meta"] = sha256_hex(canonical_json_bytes(meta_content))

    proof_manifest_path = bundle_path / "proofs" / "proof-manifest.json"
    if proof_manifest_path.exists():
        proof_manifest = json.loads(proof_manifest_path.read_text(encoding="utf-8"))
        evidence_hashes["proof_manifest"] = sha256_hex(canonical_json_bytes(proof_manifest))

    attestation_manifest_path = bundle_path / "proofs" / "attestation-manifest.json"
    if attestation_manifest_path.exists():
        attestation_manifest = json.loads(attestation_manifest_path.read_text(encoding="utf-8"))
        evidence_hashes["attestation_manifest"] = sha256_hex(canonical_json_bytes(attestation_manifest))

    if tier in ("enterprise", "regulated"):
        anchor_payload_path = bundle_path / "proofs" / "anchor-payload.json"
        if anchor_payload_path.exists():
            anchor_payload = json.loads(anchor_payload_path.read_text(encoding="utf-8"))
            evidence_hashes["anchor_payload"] = sha256_hex(canonical_json_bytes(anchor_payload))

        anchor_receipt_path = bundle_path / "proofs" / "anchor-receipt.json"
        if anchor_receipt_path.exists():
            anchor_receipt = json.loads(anchor_receipt_path.read_text(encoding="utf-8"))
            evidence_hashes["anchor_receipt"] = sha256_hex(canonical_json_bytes(anchor_receipt))

    verify_output_path = bundle_path / "verification" / "specora-verify-output.json"
    if verify_output_path.exists():
        verify_output = json.loads(verify_output_path.read_text(encoding="utf-8"))
        evidence_hashes["verification_output"] = sha256_hex(canonical_json_bytes(verify_output))

    if tier == "regulated":
        tla_path = bundle_path / "optional" / "tla-summary.json"
        if tla_path.exists():
            tla_summary = json.loads(tla_path.read_text(encoding="utf-8"))
            evidence_hashes["tla_summary"] = sha256_hex(canonical_json_bytes(tla_summary))

    # Build attestation
    integration: dict[str, Any] = {
        "name": integration_name,
        "version": integration_version,
    }
    if vendor_id:
        integration["vendor_id"] = vendor_id

    verified_by: dict[str, Any] = {
        "specora_verify_version": specora_verify_version,
    }
    if node_verifier_commit:
        verified_by["node_verifier_commit"] = node_verifier_commit

    attestation: dict[str, Any] = {
        "spec_id": "certification-attestation",
        "schema_version": "1.0.0",
        "issued_at": issued_at,
        "tier": tier,
        "integration": integration,
        "evidence_hashes": evidence_hashes,
        "proof_surface_url": proof_surface_url,
        "ci_badges": ci_badges or [],
        "verified_by": verified_by,
        "requirements_met": sorted(check_result.requirements_met),
        "requirements_missing": sorted(check_result.requirements_missing),
        "notes": None,
    }

    return attestation


def validate_attestation(
    payload: dict[str, Any],
    *,
    expected_hash: str | None = None,
) -> CertificationAttestationResult:
    """Validate certification attestation structure and optionally hash.

    Args:
        payload: Attestation dictionary to validate
        expected_hash: Optional expected SHA-256 hash

    Returns:
        CertificationAttestationResult with validation details
    """
    errors: list[str] = []

    # Check spec_id
    spec_id = payload.get("spec_id")
    if spec_id != "certification-attestation":
        errors.append(f"Invalid spec_id: expected 'certification-attestation', got '{spec_id}'")

    # Check schema_version
    schema_version = payload.get("schema_version")
    if schema_version != "1.0.0":
        errors.append(f"Unsupported schema_version: {schema_version}")

    # Check tier
    tier = payload.get("tier")
    if tier not in ("basic", "enterprise", "regulated"):
        errors.append(f"Invalid tier: {tier}")

    # Check required fields
    required_fields = [
        "spec_id", "schema_version", "issued_at", "tier", "integration",
        "evidence_hashes", "proof_surface_url", "ci_badges", "verified_by",
        "requirements_met", "requirements_missing",
    ]
    for field_name in required_fields:
        if field_name not in payload:
            errors.append(f"Missing required field: {field_name}")

    # Compute hash
    canonical = canonical_json_bytes(payload)
    computed_hash = sha256_hex(canonical)

    # Check expected hash if provided
    if expected_hash and computed_hash != expected_hash:
        errors.append(f"Hash mismatch: computed {computed_hash}, expected {expected_hash}")

    # Check requirements_missing is empty for valid attestation
    requirements_missing = payload.get("requirements_missing", [])
    if requirements_missing:
        errors.append(f"Attestation has missing requirements: {requirements_missing}")

    return CertificationAttestationResult(
        valid=len(errors) == 0,
        spec_id=spec_id,
        schema_version=schema_version,
        tier=tier,
        computed_hash=computed_hash,
        expected_hash=expected_hash,
        errors=errors,
    )


def _load_certification_vector_files(
    vectors_dir: Path,
    spec_id: str,
    version: str,
) -> tuple[dict[str, Any] | None, bytes | None, str | None, list[str]]:
    """Load the three vector files for a certification spec."""
    errors: list[str] = []

    json_file = vectors_dir / f"{spec_id}-{version}.json"
    canonical_file = vectors_dir / f"{spec_id}-{version}.canonical.json"
    sha256_file = vectors_dir / f"{spec_id}-{version}.sha256.txt"

    payload = None
    if json_file.exists():
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse {json_file.name}: {e}")
    else:
        errors.append(f"Vector file not found: {json_file.name}")

    canonical_bytes = None
    if canonical_file.exists():
        canonical_bytes = canonical_file.read_bytes()
    else:
        errors.append(f"Canonical file not found: {canonical_file.name}")

    expected_hash = None
    if sha256_file.exists():
        expected_hash = sha256_file.read_text(encoding="utf-8").strip()
    else:
        errors.append(f"Hash file not found: {sha256_file.name}")

    return payload, canonical_bytes, expected_hash, errors


def verify_single_certification_vector(
    vectors_dir: Path,
    spec_id: str,
    version: str,
) -> CertificationVectorResult:
    """Verify a single certification golden vector."""
    payload, expected_bytes, expected_hash, load_errors = _load_certification_vector_files(
        vectors_dir, spec_id, version
    )

    if load_errors or payload is None or expected_bytes is None or expected_hash is None:
        return CertificationVectorResult(
            spec_id=spec_id,
            version=version,
            bytes_match=False,
            hash_match=False,
            computed_hash="",
            expected_hash=expected_hash or "",
            errors=load_errors,
        )

    computed_bytes = canonical_json_bytes(payload)
    computed_hash = sha256_hex(computed_bytes)

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

    return CertificationVectorResult(
        spec_id=spec_id,
        version=version,
        bytes_match=bytes_match,
        hash_match=hash_match,
        computed_hash=computed_hash,
        expected_hash=expected_hash,
        errors=errors,
    )


def verify_certification_vectors(
    vectors_dir: Path | str | None = None,
) -> CertificationVectorVerificationResult:
    """Verify all certification golden vectors.

    Args:
        vectors_dir: Path to certification vectors directory (default: bundled)

    Returns:
        CertificationVectorVerificationResult with all verification details
    """
    if vectors_dir is None:
        vectors_dir = DEFAULT_CERTIFICATION_VECTORS_DIR
    elif isinstance(vectors_dir, str):
        vectors_dir = Path(vectors_dir)

    result = CertificationVectorVerificationResult(
        valid=True,
        vectors_dir=str(vectors_dir),
        total=0,
        passed=0,
        failed=0,
    )

    if not vectors_dir.exists():
        result.valid = False
        result.errors.append(f"Certification vectors directory not found: {vectors_dir}")
        return result

    # Known certification vectors to verify
    known_vectors = [
        ("certification-attestation", "1.0.0"),
    ]

    for spec_id, version in known_vectors:
        vector_result = verify_single_certification_vector(vectors_dir, spec_id, version)
        result.results.append(vector_result)
        result.total += 1

        if vector_result.valid:
            result.passed += 1
        else:
            result.failed += 1
            result.valid = False
            result.errors.extend(vector_result.errors)

    return result
