"""Specora Trust Protocol Certification Validation.

Validates STP certification bundles and attestations for the three-tier
certification program: Compatible, Governed, Enterprise.

Tier Requirements:
    Compatible: Core STP messages (agent.identity, execution.authorize, execution.record)
    Governed: + execution.attest + policy discovery + webhook + Ed25519 verification
    Enterprise: + evidence export + SIEM streaming + human approval + hierarchical scoping
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.hash import sha256_hex
from specora_verify.stp_contracts import STP_PROTOCOL_VERSION

# =============================================================================
# Default vectors directory
# =============================================================================

DEFAULT_STP_CERTIFICATION_VECTORS_DIR = (
    Path(__file__).parent.parent.parent / "vectors" / "stp-certification"
)


# =============================================================================
# Tier Definitions
# =============================================================================

STP_CERTIFICATION_TIERS = ["compatible", "governed", "enterprise"]

# Tier requirement IDs
STP_TIER_REQUIREMENTS: dict[str, list[str]] = {
    "compatible": [
        # Core STP Implementation
        "STP-REQ-101",  # Implements agent.identity message
        "STP-REQ-102",  # Implements execution.authorize message
        "STP-REQ-103",  # Implements execution.record message
        "STP-REQ-104",  # Uses STPRuntimeType enum values correctly
        "STP-REQ-105",  # Uses STPActionType enum values correctly
        "STP-REQ-106",  # Protocol version 1.0.0
        "STP-REQ-107",  # Handles block decisions correctly
        "STP-REQ-108",  # Handles restrict decisions correctly
        "STP-REQ-109",  # Handles require_approval decisions correctly
        "STP-REQ-110",  # Includes valid timestamps (ISO8601)
    ],
    "governed": [
        # All compatible requirements
        "STP-REQ-101",
        "STP-REQ-102",
        "STP-REQ-103",
        "STP-REQ-104",
        "STP-REQ-105",
        "STP-REQ-106",
        "STP-REQ-107",
        "STP-REQ-108",
        "STP-REQ-109",
        "STP-REQ-110",
        # Governed additions
        "STP-REQ-201",  # Implements execution.attest message
        "STP-REQ-202",  # Policy discovery support (GET /api/v1/stp/policies)
        "STP-REQ-203",  # Webhook integration (decision callbacks)
        "STP-REQ-204",  # Ed25519 signature verification for attestation bundles
        "STP-REQ-205",  # Attestation bundle root hash determinism
        "STP-REQ-206",  # Capability contract validation
    ],
    "enterprise": [
        # All governed requirements
        "STP-REQ-101",
        "STP-REQ-102",
        "STP-REQ-103",
        "STP-REQ-104",
        "STP-REQ-105",
        "STP-REQ-106",
        "STP-REQ-107",
        "STP-REQ-108",
        "STP-REQ-109",
        "STP-REQ-110",
        "STP-REQ-201",
        "STP-REQ-202",
        "STP-REQ-203",
        "STP-REQ-204",
        "STP-REQ-205",
        "STP-REQ-206",
        # Enterprise additions
        "STP-REQ-301",  # Evidence export to Evidence Ledger (CTRL-640)
        "STP-REQ-302",  # SIEM streaming integration
        "STP-REQ-303",  # Human approval workflows (approval_token support)
        "STP-REQ-304",  # Hierarchical policy scoping (org > team > project)
        "STP-REQ-305",  # Non-LLM action support (PLATFORM-460)
        "STP-REQ-306",  # Multi-backend routing support (STPBackendType)
    ],
}

# Required artifacts by tier
STP_TIER_ARTIFACTS: dict[str, list[str]] = {
    "compatible": [
        "meta.json",
        "samples/agent-identity-request.json",
        "samples/agent-identity-response.json",
        "samples/execution-authorize-request.json",
        "samples/execution-authorize-response.json",
        "samples/execution-record-request.json",
        "samples/execution-record-response.json",
        "verification/specora-verify-output.json",
    ],
    "governed": [
        "meta.json",
        "samples/agent-identity-request.json",
        "samples/agent-identity-response.json",
        "samples/execution-authorize-request.json",
        "samples/execution-authorize-response.json",
        "samples/execution-record-request.json",
        "samples/execution-record-response.json",
        "samples/execution-attest-request.json",
        "samples/execution-attest-response.json",
        "samples/attestation-bundle.json",
        "proofs/attestation-signature.json",
        "verification/specora-verify-output.json",
    ],
    "enterprise": [
        "meta.json",
        "samples/agent-identity-request.json",
        "samples/agent-identity-response.json",
        "samples/execution-authorize-request.json",
        "samples/execution-authorize-response.json",
        "samples/execution-record-request.json",
        "samples/execution-record-response.json",
        "samples/execution-attest-request.json",
        "samples/execution-attest-response.json",
        "samples/attestation-bundle.json",
        "proofs/attestation-signature.json",
        "proofs/evidence-ledger-receipt.json",
        "verification/specora-verify-output.json",
        "optional/siem-integration-test.json",
    ],
}


# =============================================================================
# Result Dataclasses
# =============================================================================


@dataclass
class STPCertificationCheckResult:
    """Result of STP certification bundle check."""

    valid: bool
    tier: str
    bundle_path: str
    adapter_name: str = ""
    adapter_version: str = ""
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
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "artifacts_found": self.artifacts_found,
            "artifacts_missing": self.artifacts_missing,
            "requirements_met": self.requirements_met,
            "requirements_missing": self.requirements_missing,
            "verification_results": self.verification_results,
            "errors": self.errors,
        }


@dataclass
class STPCertificationAttestationResult:
    """Result of STP attestation validation."""

    valid: bool
    spec_id: str | None = None
    schema_version: str | None = None
    tier: str | None = None
    adapter_name: str | None = None
    adapter_version: str | None = None
    computed_hash: str | None = None
    expected_hash: str | None = None
    signature_valid: bool | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "spec_id": self.spec_id,
            "schema_version": self.schema_version,
            "tier": self.tier,
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "computed_hash": self.computed_hash,
            "expected_hash": self.expected_hash,
            "signature_valid": self.signature_valid,
            "errors": self.errors,
        }


@dataclass
class STPCertificationVectorResult:
    """Result for a single STP certification vector verification."""

    spec_id: str
    version: str
    tier: str
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
            "tier": self.tier,
            "valid": self.valid,
            "bytes_match": self.bytes_match,
            "hash_match": self.hash_match,
            "computed_hash": self.computed_hash,
            "expected_hash": self.expected_hash,
            "errors": self.errors,
        }


@dataclass
class STPCertificationVectorVerificationResult:
    """Result of STP certification golden vector verification."""

    valid: bool
    vectors_dir: str
    total: int
    passed: int
    failed: int
    results: list[STPCertificationVectorResult] = field(default_factory=list)
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


# =============================================================================
# Scaffold Generation
# =============================================================================


def generate_stp_certification_scaffold(
    output_dir: Path,
    tier: str,
    adapter_name: str,
    adapter_version: str = "1.0.0",
    vendor_name: str = "",
    force: bool = False,
) -> STPCertificationCheckResult:
    """Generate STP certification bundle scaffold.

    Args:
        output_dir: Directory to create scaffold in
        tier: Certification tier (compatible, governed, enterprise)
        adapter_name: Name of the adapter being certified
        adapter_version: Version of the adapter
        vendor_name: Vendor/organization name
        force: Overwrite existing directory

    Returns:
        STPCertificationCheckResult with generation details
    """
    import shutil
    from datetime import datetime

    result = STPCertificationCheckResult(
        valid=True,
        tier=tier,
        bundle_path=str(output_dir),
        adapter_name=adapter_name,
        adapter_version=adapter_version,
    )

    # Validate tier
    if tier not in STP_CERTIFICATION_TIERS:
        result.valid = False
        result.errors.append(
            f"Unknown tier: {tier}. Must be one of: {', '.join(STP_CERTIFICATION_TIERS)}"
        )
        return result

    # Check output directory
    if output_dir.exists():
        if not force:
            result.valid = False
            result.errors.append(
                f"Output directory already exists: {output_dir}. Use --force to overwrite."
            )
            return result
        shutil.rmtree(output_dir)

    # Create directory structure
    try:
        output_dir.mkdir(parents=True)
        (output_dir / "samples").mkdir()
        (output_dir / "proofs").mkdir()
        (output_dir / "verification").mkdir()
        if tier == "enterprise":
            (output_dir / "optional").mkdir()
    except OSError as e:
        result.valid = False
        result.errors.append(f"Failed to create directories: {e}")
        return result

    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Generate meta.json
    meta = {
        "spec_id": "stp-certification-bundle",
        "schema_version": "1.0.0",
        "tier_requested": tier,
        "adapter_name": adapter_name,
        "adapter_version": adapter_version,
        "vendor_name": vendor_name,
        "protocol_version": STP_PROTOCOL_VERSION,
        "created_at": timestamp,
        "requirements": STP_TIER_REQUIREMENTS.get(tier, []),
    }
    meta_path = output_dir / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    result.artifacts_found.append("meta.json")

    # Generate sample request/response pairs
    samples = _generate_sample_messages(tier, adapter_name, timestamp)
    for filename, content in samples.items():
        sample_path = output_dir / "samples" / filename
        sample_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
        result.artifacts_found.append(f"samples/{filename}")

    # Generate placeholder verification output
    verification: dict[str, Any] = {
        "status": "pending",
        "tier": tier,
        "adapter_name": adapter_name,
        "verified_at": None,
        "requirements_checked": [],
    }
    verify_path = output_dir / "verification" / "specora-verify-output.json"
    verify_path.write_text(json.dumps(verification, indent=2), encoding="utf-8")
    result.artifacts_found.append("verification/specora-verify-output.json")

    # Generate tier-specific artifacts
    if tier in ("governed", "enterprise"):
        # Placeholder attestation signature
        sig_placeholder = {
            "algorithm": "Ed25519",
            "public_key_id": "placeholder",
            "signature_b64": "",
            "signed_at": None,
        }
        sig_path = output_dir / "proofs" / "attestation-signature.json"
        sig_path.write_text(json.dumps(sig_placeholder, indent=2), encoding="utf-8")
        result.artifacts_found.append("proofs/attestation-signature.json")

    if tier == "enterprise":
        # Placeholder evidence receipt
        evidence_placeholder = {
            "ledger_position": None,
            "artifact_sha256": "",
            "chain_hash": "",
        }
        evidence_path = output_dir / "proofs" / "evidence-ledger-receipt.json"
        evidence_path.write_text(json.dumps(evidence_placeholder, indent=2), encoding="utf-8")
        result.artifacts_found.append("proofs/evidence-ledger-receipt.json")

        # Placeholder SIEM test
        siem_placeholder = {
            "test_status": "pending",
            "events_sent": 0,
            "provider": None,
        }
        siem_path = output_dir / "optional" / "siem-integration-test.json"
        siem_path.write_text(json.dumps(siem_placeholder, indent=2), encoding="utf-8")
        result.artifacts_found.append("optional/siem-integration-test.json")

    # Generate README
    readme = _generate_certification_readme(tier, adapter_name)
    readme_path = output_dir / "README.md"
    readme_path.write_text(readme, encoding="utf-8")

    # Determine missing requirements (all pending until verification)
    result.requirements_missing = STP_TIER_REQUIREMENTS.get(tier, []).copy()

    return result


def _generate_sample_messages(
    tier: str,
    adapter_name: str,
    timestamp: str,
) -> dict[str, dict[str, Any]]:
    """Generate sample STP messages for certification bundle."""
    samples: dict[str, dict[str, Any]] = {}

    # agent.identity request/response
    samples["agent-identity-request.json"] = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "agent.identity",
        "timestamp": timestamp,
        "payload": {
            "agent_name": f"{adapter_name}-sample-agent",
            "agent_version": "1.0.0",
            "runtime": "custom",
            "capabilities_requested": ["read_code", "write_code"],
            "owner_context": {
                "org_id": "00000000-0000-0000-0000-000000000000",
            },
        },
    }
    samples["agent-identity-response.json"] = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "agent.identity.response",
        "timestamp": timestamp,
        "result": {
            "agent_identity_id": "00000000-0000-0000-0000-000000000001",
            "capabilities_granted": ["read_code", "write_code"],
            "trust_tier": 2,
            "session_token": "sample-session-token",
        },
    }

    # execution.authorize request/response
    samples["execution-authorize-request.json"] = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "execution.authorize",
        "timestamp": timestamp,
        "payload": {
            "agent_identity_id": "00000000-0000-0000-0000-000000000001",
            "action_type": "code_edit",
            "tools_requested": ["filesystem"],
            "scope": {
                "paths": ["/src/**/*.py"],
            },
            "mode": "enforce",
        },
    }
    samples["execution-authorize-response.json"] = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "execution.authorize.response",
        "timestamp": timestamp,
        "result": {
            "authorization_id": "00000000-0000-0000-0000-000000000002",
            "decision": "allow",
            "tools_granted": ["filesystem"],
            "expires_at": "2099-12-31T23:59:59Z",
            "policy_hash": "0" * 64,
        },
    }

    # execution.record request/response
    samples["execution-record-request.json"] = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "execution.record",
        "timestamp": timestamp,
        "payload": {
            "authorization_id": "00000000-0000-0000-0000-000000000002",
            "status": "success",
            "output_hash": "0" * 64,
            "duration_ms": 1000,
            "actions_taken": [
                {"tool": "filesystem", "operation": "write", "target": "/src/main.py"},
            ],
        },
    }
    samples["execution-record-response.json"] = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "execution.record.response",
        "timestamp": timestamp,
        "result": {
            "record_id": "00000000-0000-0000-0000-000000000003",
            "chain_position": 1,
            "record_hash": "0" * 64,
        },
    }

    # Governed/Enterprise: execution.attest
    if tier in ("governed", "enterprise"):
        samples["execution-attest-request.json"] = {
            "protocol_version": STP_PROTOCOL_VERSION,
            "message_type": "execution.attest",
            "timestamp": timestamp,
            "payload": {
                "agent_identity_id": "00000000-0000-0000-0000-000000000001",
                "execution_ids": ["00000000-0000-0000-0000-000000000003"],
                "attestation_type": "execution_bundle",
            },
        }
        samples["execution-attest-response.json"] = {
            "protocol_version": STP_PROTOCOL_VERSION,
            "message_type": "execution.attest.response",
            "timestamp": timestamp,
            "result": {
                "attestation_bundle_id": "00000000-0000-0000-0000-000000000004",
                "bundle_root_hash": "0" * 64,
                "signature_b64": "",
                "public_key_id": "placeholder",
            },
        }
        samples["attestation-bundle.json"] = {
            "attestation_bundle": {
                "bundle_id": "00000000-0000-0000-0000-000000000004",
                "bundle_root_hash": "0" * 64,
                "created_at": timestamp,
                "executions": [
                    {
                        "record_id": "00000000-0000-0000-0000-000000000003",
                        "record_hash": "0" * 64,
                        "chain_position": 1,
                    }
                ],
            },
        }

    return samples


def _generate_certification_readme(tier: str, adapter_name: str) -> str:
    """Generate README for certification bundle."""
    requirements = STP_TIER_REQUIREMENTS.get(tier, [])
    req_list = "\n".join([f"- `{req}`" for req in requirements])

    return f"""# STP Certification Bundle: {adapter_name}

**Tier:** {tier.upper()}
**Protocol Version:** {STP_PROTOCOL_VERSION}

## Requirements

{req_list}

## Verification

Run verification with specora-verify:

```bash
specora-verify stp certify check --tier {tier} --bundle .
```

## Generating Attestation

After all checks pass:

```bash
specora-verify stp certify attest --tier {tier} --bundle . --out attestation.json
```

## Documentation

- [STP Certification Guide](https://docs.specora.ai/protocol/stp-certification)
- [STP Adapter Development](https://docs.specora.ai/protocol/stp-adapters)
"""


# =============================================================================
# Bundle Verification
# =============================================================================


def check_stp_certification_bundle(
    bundle_path: Path,
    tier: str,
) -> STPCertificationCheckResult:
    """Check an STP certification bundle against tier requirements.

    Args:
        bundle_path: Path to certification bundle directory
        tier: Tier to check against (compatible, governed, enterprise)

    Returns:
        STPCertificationCheckResult with check details
    """
    result = STPCertificationCheckResult(
        valid=True,
        tier=tier,
        bundle_path=str(bundle_path),
    )

    # Validate tier
    if tier not in STP_TIER_REQUIREMENTS:
        result.valid = False
        result.errors.append(
            f"Unknown tier: {tier}. Must be one of: {', '.join(STP_CERTIFICATION_TIERS)}"
        )
        return result

    # Check required artifacts exist
    required_artifacts = STP_TIER_ARTIFACTS.get(tier, [])
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
            result.adapter_name = meta.get("adapter_name", "")
            result.adapter_version = meta.get("adapter_version", "")

            if meta.get("tier_requested") != tier:
                result.errors.append(
                    f"meta.json tier_requested ({meta.get('tier_requested')}) "
                    f"does not match requested tier ({tier})"
                )

            # Check protocol version
            if meta.get("protocol_version") != STP_PROTOCOL_VERSION:
                result.errors.append(
                    f"Protocol version mismatch: expected {STP_PROTOCOL_VERSION}, "
                    f"got {meta.get('protocol_version')}"
                )
        except json.JSONDecodeError as e:
            result.valid = False
            result.errors.append(f"Failed to parse meta.json: {e}")

    # Verify sample messages
    samples_dir = bundle_path / "samples"
    if samples_dir.exists():
        result.verification_results["samples"] = _verify_sample_messages(samples_dir, tier)
        if not result.verification_results["samples"].get("valid", False):
            result.valid = False

    # Verify verification output
    verify_output_path = bundle_path / "verification" / "specora-verify-output.json"
    if verify_output_path.exists():
        try:
            verify_output = json.loads(verify_output_path.read_text(encoding="utf-8"))
            if verify_output.get("status") == "pass":
                result.verification_results["specora_verify"] = "pass"
            else:
                result.verification_results["specora_verify"] = verify_output.get(
                    "status", "unknown"
                )
                if verify_output.get("status") != "pending":
                    result.valid = False
                    result.errors.append("Verification output status is not 'pass'")
        except json.JSONDecodeError as e:
            result.valid = False
            result.errors.append(f"Failed to parse verification output: {e}")

    # Verify attestation signature for governed/enterprise
    if tier in ("governed", "enterprise"):
        sig_path = bundle_path / "proofs" / "attestation-signature.json"
        if sig_path.exists():
            try:
                sig_data = json.loads(sig_path.read_text(encoding="utf-8"))
                if sig_data.get("signature_b64"):
                    result.verification_results["attestation_signature"] = "present"
                else:
                    result.verification_results["attestation_signature"] = "placeholder"
            except json.JSONDecodeError as e:
                result.errors.append(f"Failed to parse attestation signature: {e}")

    # Determine requirements met
    tier_requirements = STP_TIER_REQUIREMENTS.get(tier, [])
    if result.valid and not result.artifacts_missing:
        # Check each requirement
        for req in tier_requirements:
            if _check_requirement(bundle_path, req, tier):
                result.requirements_met.append(req)
            else:
                result.requirements_missing.append(req)
    else:
        result.requirements_missing = tier_requirements.copy()

    # Final validity check
    if result.requirements_missing:
        result.valid = False

    return result


def _verify_sample_messages(
    samples_dir: Path,
    tier: str,
) -> dict[str, Any]:
    """Verify sample STP messages in a certification bundle."""
    from specora_verify.validators.stp import validate_stp_message

    results: dict[str, Any] = {"valid": True, "messages": []}

    expected_files = [
        "agent-identity-request.json",
        "agent-identity-response.json",
        "execution-authorize-request.json",
        "execution-authorize-response.json",
        "execution-record-request.json",
        "execution-record-response.json",
    ]

    if tier in ("governed", "enterprise"):
        expected_files.extend(
            [
                "execution-attest-request.json",
                "execution-attest-response.json",
                "attestation-bundle.json",
            ]
        )

    for filename in expected_files:
        filepath = samples_dir / filename
        if not filepath.exists():
            results["messages"].append(
                {
                    "file": filename,
                    "valid": False,
                    "error": "File not found",
                }
            )
            results["valid"] = False
            continue

        try:
            payload = json.loads(filepath.read_text(encoding="utf-8"))
            verify_result = validate_stp_message(payload)
            results["messages"].append(
                {
                    "file": filename,
                    "valid": verify_result.valid,
                    "message_type": verify_result.message_type,
                    "errors": verify_result.errors,
                }
            )
            if not verify_result.valid:
                results["valid"] = False
        except json.JSONDecodeError as e:
            results["messages"].append(
                {
                    "file": filename,
                    "valid": False,
                    "error": str(e),
                }
            )
            results["valid"] = False

    return results


def _check_requirement(
    bundle_path: Path,
    requirement: str,
    tier: str,
) -> bool:
    """Check if a specific requirement is met.

    This is a simplified check - full verification would involve
    actually testing the adapter implementation.
    """
    # For now, requirements are considered met if artifacts are present
    # and verification output shows pass
    verify_path = bundle_path / "verification" / "specora-verify-output.json"
    if verify_path.exists():
        try:
            verify_output = json.loads(verify_path.read_text(encoding="utf-8"))
            checked = verify_output.get("requirements_checked", [])
            return requirement in checked
        except json.JSONDecodeError:
            return False
    return False


# =============================================================================
# Attestation Generation and Validation
# =============================================================================


def generate_stp_certification_attestation(
    bundle_path: Path,
    tier: str,
    issued_at: str,
    issuer_key_id: str = "specora-root-key",
    proof_surface_url: str = "https://specora.ai/proof",
) -> dict[str, Any]:
    """Generate an STP certification attestation for a bundle.

    Args:
        bundle_path: Path to certification bundle
        tier: Certification tier
        issued_at: ISO8601 timestamp for attestation
        issuer_key_id: ID of the signing key
        proof_surface_url: URL to proof surface

    Returns:
        Attestation dictionary
    """
    # Check bundle first
    check_result = check_stp_certification_bundle(bundle_path, tier)

    # Compute evidence hashes
    evidence_hashes: dict[str, str] = {}

    meta_path = bundle_path / "meta.json"
    if meta_path.exists():
        meta_content = json.loads(meta_path.read_text(encoding="utf-8"))
        evidence_hashes["meta"] = sha256_hex(canonical_json_bytes(meta_content))

    # Hash all sample files
    samples_dir = bundle_path / "samples"
    if samples_dir.exists():
        for sample_file in sorted(samples_dir.glob("*.json")):
            content = json.loads(sample_file.read_text(encoding="utf-8"))
            evidence_hashes[f"sample_{sample_file.stem}"] = sha256_hex(
                canonical_json_bytes(content)
            )

    # Compute bundle root hash
    bundle_content = {
        "tier": tier,
        "adapter_name": check_result.adapter_name,
        "adapter_version": check_result.adapter_version,
        "evidence_hashes": evidence_hashes,
    }
    bundle_root_hash = sha256_hex(canonical_json_bytes(bundle_content))

    # Build attestation
    attestation: dict[str, Any] = {
        "spec_id": "stp-certification-attestation",
        "schema_version": "1.0.0",
        "protocol_version": STP_PROTOCOL_VERSION,
        "issued_at": issued_at,
        "tier": tier,
        "adapter": {
            "name": check_result.adapter_name,
            "version": check_result.adapter_version,
        },
        "bundle_root_hash": bundle_root_hash,
        "evidence_hashes": evidence_hashes,
        "proof_surface_url": proof_surface_url,
        "issuer_key_id": issuer_key_id,
        "requirements_met": sorted(check_result.requirements_met),
        "requirements_missing": sorted(check_result.requirements_missing),
    }

    return attestation


def validate_stp_certification_attestation(
    payload: dict[str, Any],
    *,
    expected_hash: str | None = None,
) -> STPCertificationAttestationResult:
    """Validate STP certification attestation structure and optionally hash.

    Args:
        payload: Attestation dictionary to validate
        expected_hash: Optional expected SHA-256 hash

    Returns:
        STPCertificationAttestationResult with validation details
    """
    errors: list[str] = []

    # Check spec_id
    spec_id = payload.get("spec_id")
    if spec_id != "stp-certification-attestation":
        errors.append(f"Invalid spec_id: expected 'stp-certification-attestation', got '{spec_id}'")

    # Check schema_version
    schema_version = payload.get("schema_version")
    if schema_version != "1.0.0":
        errors.append(f"Unsupported schema_version: {schema_version}")

    # Check tier
    tier = payload.get("tier")
    if tier not in STP_CERTIFICATION_TIERS:
        errors.append(f"Invalid tier: {tier}")

    # Check required fields
    required_fields = [
        "spec_id",
        "schema_version",
        "protocol_version",
        "issued_at",
        "tier",
        "adapter",
        "bundle_root_hash",
        "evidence_hashes",
        "proof_surface_url",
        "issuer_key_id",
        "requirements_met",
        "requirements_missing",
    ]
    for field_name in required_fields:
        if field_name not in payload:
            errors.append(f"Missing required field: {field_name}")

    # Extract adapter info
    adapter = payload.get("adapter", {})
    adapter_name = adapter.get("name")
    adapter_version = adapter.get("version")

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

    return STPCertificationAttestationResult(
        valid=len(errors) == 0,
        spec_id=spec_id,
        schema_version=schema_version,
        tier=tier,
        adapter_name=adapter_name,
        adapter_version=adapter_version,
        computed_hash=computed_hash,
        expected_hash=expected_hash,
        errors=errors,
    )


# =============================================================================
# Vector Verification
# =============================================================================


def _load_stp_certification_vector_files(
    vectors_dir: Path,
    spec_id: str,
    version: str,
    tier: str,
) -> tuple[dict[str, Any] | None, bytes | None, str | None, list[str]]:
    """Load the three vector files for an STP certification spec."""
    errors: list[str] = []

    tier_dir = vectors_dir / tier
    json_file = tier_dir / f"{spec_id}-{version}.json"
    canonical_file = tier_dir / f"{spec_id}-{version}.canonical.json"
    sha256_file = tier_dir / f"{spec_id}-{version}.sha256.txt"

    payload = None
    if json_file.exists():
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse {json_file.name}: {e}")
    else:
        errors.append(f"Vector file not found: {tier}/{json_file.name}")

    canonical_bytes = None
    if canonical_file.exists():
        canonical_bytes = canonical_file.read_bytes()
    else:
        errors.append(f"Canonical file not found: {tier}/{canonical_file.name}")

    expected_hash = None
    if sha256_file.exists():
        expected_hash = sha256_file.read_text(encoding="utf-8").strip()
    else:
        errors.append(f"Hash file not found: {tier}/{sha256_file.name}")

    return payload, canonical_bytes, expected_hash, errors


def verify_single_stp_certification_vector(
    vectors_dir: Path,
    spec_id: str,
    version: str,
    tier: str,
) -> STPCertificationVectorResult:
    """Verify a single STP certification golden vector."""
    payload, expected_bytes, expected_hash, load_errors = _load_stp_certification_vector_files(
        vectors_dir, spec_id, version, tier
    )

    if load_errors or payload is None or expected_bytes is None or expected_hash is None:
        return STPCertificationVectorResult(
            spec_id=spec_id,
            version=version,
            tier=tier,
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
            f"Canonical bytes mismatch for {spec_id} v{version} ({tier}). "
            f"Computed {len(computed_bytes)} bytes, expected {len(expected_bytes)} bytes."
        )
    if not hash_match:
        errors.append(
            f"Hash mismatch for {spec_id} v{version} ({tier}). "
            f"Computed {computed_hash}, expected {expected_hash}."
        )

    return STPCertificationVectorResult(
        spec_id=spec_id,
        version=version,
        tier=tier,
        bytes_match=bytes_match,
        hash_match=hash_match,
        computed_hash=computed_hash,
        expected_hash=expected_hash,
        errors=errors,
    )


def verify_stp_certification_vectors(
    vectors_dir: Path | str | None = None,
) -> STPCertificationVectorVerificationResult:
    """Verify all STP certification golden vectors.

    Args:
        vectors_dir: Path to STP certification vectors directory (default: bundled)

    Returns:
        STPCertificationVectorVerificationResult with all verification details
    """
    if vectors_dir is None:
        vectors_dir = DEFAULT_STP_CERTIFICATION_VECTORS_DIR
    elif isinstance(vectors_dir, str):
        vectors_dir = Path(vectors_dir)

    result = STPCertificationVectorVerificationResult(
        valid=True,
        vectors_dir=str(vectors_dir),
        total=0,
        passed=0,
        failed=0,
    )

    if not vectors_dir.exists():
        result.valid = False
        result.errors.append(f"STP certification vectors directory not found: {vectors_dir}")
        return result

    # Known certification vectors to verify by tier
    # Known certification vectors to verify
    # Additional vectors can be added as the certification program expands
    known_vectors = [
        ("stp-certification-attestation", "1.0.0", "compatible"),
    ]

    for spec_id, version, tier in known_vectors:
        vector_result = verify_single_stp_certification_vector(vectors_dir, spec_id, version, tier)
        result.results.append(vector_result)
        result.total += 1

        if vector_result.valid:
            result.passed += 1
        else:
            result.failed += 1
            result.valid = False
            result.errors.extend(vector_result.errors)

    return result
