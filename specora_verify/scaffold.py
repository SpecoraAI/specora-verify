"""Certification bundle scaffold generator.

Generates a structurally valid certification bundle for a given tier
without requiring repository cloning.

Safety constraints:
- Does NOT auto-attest
- Does NOT embed fake proofs
- Does NOT bypass tier checks
- Does NOT silently overwrite existing bundle without --force
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from specora_verify import __version__
from specora_verify.contracts.registry import (
    ATTESTATION_MANIFEST_V1,
    PROOF_MANIFEST_V1,
)

# Templates directory (embedded in package)
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Certification attestation version (see Specora Wire Spec v1.0 Annex C)
CERTIFICATION_ATTESTATION_VERSION = "1.0.0"


@dataclass
class ScaffoldResult:
    """Result of scaffold generation."""

    success: bool
    output_dir: str
    tier: str
    name: str
    version: str
    files_created: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output_dir": self.output_dir,
            "tier": self.tier,
            "name": self.name,
            "version": self.version,
            "files_created": self.files_created,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def _validate_tier(tier: str) -> list[str]:
    """Validate tier value."""
    if tier not in ("basic", "enterprise", "regulated"):
        return [f"Invalid tier: {tier}. Must be basic, enterprise, or regulated."]
    return []


def _validate_name(name: str) -> list[str]:
    """Validate platform name."""
    errors = []
    if not name:
        errors.append("Platform name is required.")
    elif not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", name):
        errors.append(
            f"Invalid platform name: {name}. "
            "Must start with alphanumeric and contain only alphanumeric, dots, underscores, hyphens."
        )
    return errors


def _validate_version(version: str) -> list[str]:
    """Validate platform version."""
    errors = []
    if not version:
        errors.append("Platform version is required.")
    elif not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+", version):
        # Allow semver with optional pre-release/build metadata
        errors.append(
            f"Invalid version: {version}. "
            "Must follow semver format (e.g., 1.0.0, 2.4.1-beta, 1.0.0+build)."
        )
    return errors


def _generate_uuid() -> str:
    """Generate a lowercase UUID string."""
    return str(uuid.uuid4())


def _iso_timestamp() -> str:
    """Generate ISO8601 UTC timestamp with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _create_meta_json(
    tier: str,
    name: str,
    version: str,
    timestamp: str,
    vendor_id: str | None = None,
) -> dict[str, Any]:
    """Create meta.json content."""
    integration: dict[str, Any] = {
        "name": name,
        "version": version,
    }
    if vendor_id:
        integration["vendor_id"] = vendor_id

    return {
        "bundle_version": "1.0.0",
        "tier_requested": tier,
        "integration": integration,
        "created_at": timestamp,
        "generator": {
            "tool": "specora-verify",
            "command": "certify scaffold",
            "version": __version__,
            "generated_at": timestamp,
        },
        "spec_versions": {
            "proof-manifest": PROOF_MANIFEST_V1.schema_version,
            "attestation-manifest": ATTESTATION_MANIFEST_V1.schema_version,
            "certification-attestation": CERTIFICATION_ATTESTATION_VERSION,
        },
        "artifacts_included": _get_tier_artifacts(tier),
    }


def _get_tier_artifacts(tier: str) -> list[str]:
    """Get list of artifacts for a tier."""
    artifacts = [
        "proofs/proof-manifest.json",
        "proofs/attestation-manifest.json",
        "verification/specora-verify-output.json",
    ]

    if tier in ("enterprise", "regulated"):
        artifacts.extend([
            "proofs/anchor-payload.json",
            "proofs/anchor-receipt.json",
        ])

    if tier == "regulated":
        artifacts.append("optional/tla-summary.json")

    return artifacts


def _create_proof_manifest_template(
    manifest_id: str,
    org_id: str,
    timestamp: str,
) -> dict[str, Any]:
    """Create proof-manifest.json template."""
    return {
        "spec_id": "proof-manifest",
        "schema_version": "1.0.0",
        "id": manifest_id,
        "org_id": org_id,
        "root_type": "merkle_sha256",
        "root_hash": "REPLACE_WITH_YOUR_MERKLE_ROOT_HASH",
        "leaf_count": 0,
        "period_start": timestamp,
        "period_end": timestamp,
        "created_at": timestamp,
    }


def _create_attestation_manifest_template(
    manifest_id: str,
    org_id: str,
    timestamp: str,
) -> dict[str, Any]:
    """Create attestation-manifest.json template."""
    return {
        "spec_id": "attestation-manifest",
        "schema_version": "1.0.0",
        "id": manifest_id,
        "org_id": org_id,
        "snapshot_type": "governance_attestation",
        "period_start": timestamp,
        "period_end": timestamp,
        "created_at": timestamp,
    }


def _create_anchor_payload_template(timestamp: str) -> dict[str, Any]:
    """Create anchor-payload.json template for Enterprise/Regulated tiers."""
    return {
        "spec_id": "anchor-payload",
        "schema_version": "1.0.0",
        "manifest_hash": "REPLACE_WITH_MANIFEST_HASH",
        "anchor_backend": "specora",
        "submitted_at": timestamp,
    }


def _create_anchor_receipt_template(timestamp: str) -> dict[str, Any]:
    """Create anchor-receipt.json template for Enterprise/Regulated tiers."""
    return {
        "spec_id": "anchor-receipt",
        "schema_version": "1.0.0",
        "payload_hash": "REPLACE_WITH_PAYLOAD_HASH",
        "backend": "specora",
        "backend_id": "REPLACE_WITH_BACKEND_REFERENCE",
        "anchored_at": timestamp,
    }


def _create_tla_summary_template() -> dict[str, Any]:
    """Create tla-summary.json template for Regulated tier."""
    return {
        "model": "manifest_contract",
        "status": "pending",
        "states_explored": 0,
        "invariants_checked": 0,
        "invariants_passed": 0,
        "ci_run_url": "REPLACE_WITH_CI_RUN_URL",
    }


def _create_verification_output() -> dict[str, Any]:
    """Create verification output placeholder."""
    return {
        "status": "pending",
        "message": "Run 'specora-verify vectors verify' to generate actual verification output.",
        "generated_by": "specora-verify scaffold",
    }


def _create_badges_json() -> dict[str, Any]:
    """Create CI badges reference."""
    return {
        "verifier_cli": "https://github.com/YOUR-ORG/YOUR-REPO/actions/workflows/specora-governance.yml/badge.svg"
    }


def _generate_instructions(
    tier: str,
    name: str,
    version: str,
    output_dir: str,
    timestamp: str,
) -> str:
    """Generate INSTRUCTIONS.md content."""
    instructions = f"""# Certification Bundle Instructions

Generated: {timestamp}
Tier: {tier}
Integration: {name} v{version}
Generator: specora-verify certify scaffold v{__version__}

## Next Steps

### 1. Update Manifest Files

Edit `proofs/proof-manifest.json` and `proofs/attestation-manifest.json` with your actual data:
- Replace placeholder UUIDs with real values
- Update `root_hash` with your Merkle root
- Set correct `period_start`/`period_end`

### 2. Update CI Badge URL

Edit `ci/badges.json` with your actual GitHub Actions badge URL.

### 3. Run Verification

```bash
# Verify golden vectors first
specora-verify vectors verify

# Check your bundle
specora-verify certify check --tier {tier} --bundle {output_dir}
```

### 4. Generate Attestation

```bash
specora-verify certify attest \\
    --tier {tier} \\
    --bundle {output_dir} \\
    --integration-name {name} \\
    --integration-version {version} \\
    --issued-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
    --out attestation.json
```

### 5. Set Up CI

Copy `ci/specora-governance.yml` to `.github/workflows/` in your repository.

## Artifact Checklist

- [ ] `proofs/proof-manifest.json` - Updated with real data
- [ ] `proofs/attestation-manifest.json` - Updated with real data
- [ ] `verification/specora-verify-output.json` - Run `specora-verify vectors verify --format json > verification/specora-verify-output.json`
- [ ] `ci/badges.json` - Updated with real badge URL
- [ ] `policy/baseline-policy.json` - Review and adjust policies
"""

    if tier in ("enterprise", "regulated"):
        instructions += """
### Enterprise Tier Additional

- [ ] `proofs/anchor-payload.json` - Updated with manifest binding
- [ ] `proofs/anchor-receipt.json` - Updated with payload binding
"""

    if tier == "regulated":
        instructions += """
### Regulated Tier Additional

- [ ] `optional/tla-summary.json` - Generated from TLA+ CI
"""

    instructions += f"""
## Documentation

- Certification Program: https://specora.ai/proof/certification
- Integrator Guide: https://specora.ai/proof/integrators
- Troubleshooting: https://specora.ai/proof/integrators/troubleshooting

## Support

- Documentation: https://specora.ai/proof
- Security inquiries: security@specora.ai
"""

    return instructions


def generate_scaffold(
    output_dir: Path | str,
    tier: str,
    name: str,
    version: str,
    vendor_id: str | None = None,
    force: bool = False,
) -> ScaffoldResult:
    """Generate a certification bundle scaffold.

    Args:
        output_dir: Output directory for the bundle
        tier: Certification tier (basic, enterprise, regulated)
        name: Platform name
        version: Platform version (semver)
        vendor_id: Optional vendor UUID
        force: Overwrite existing directory if True

    Returns:
        ScaffoldResult with generation details
    """
    if isinstance(output_dir, str):
        output_dir = Path(output_dir)

    result = ScaffoldResult(
        success=True,
        output_dir=str(output_dir),
        tier=tier,
        name=name,
        version=version,
    )

    # Validate inputs
    errors = []
    errors.extend(_validate_tier(tier))
    errors.extend(_validate_name(name))
    errors.extend(_validate_version(version))

    if errors:
        result.success = False
        result.errors = errors
        return result

    # Check if output directory exists
    if output_dir.exists() and not force:
        result.success = False
        result.errors.append(
            f"Output directory already exists: {output_dir}. "
            "Use --force to overwrite."
        )
        return result

    # Generate timestamp
    timestamp = _iso_timestamp()

    # Generate UUIDs for templates
    manifest_id = _generate_uuid()
    org_id = _generate_uuid()

    try:
        # Create directory structure
        dirs = [
            output_dir,
            output_dir / "proofs",
            output_dir / "verification",
            output_dir / "ci",
            output_dir / "policy",
        ]

        if tier in ("enterprise", "regulated"):
            dirs.append(output_dir / "optional")

        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

        # Create meta.json
        meta_path = output_dir / "meta.json"
        meta_content = _create_meta_json(tier, name, version, timestamp, vendor_id)
        meta_path.write_text(json.dumps(meta_content, indent=2), encoding="utf-8")
        result.files_created.append("meta.json")

        # Create proof-manifest.json
        proof_manifest_path = output_dir / "proofs" / "proof-manifest.json"
        proof_manifest = _create_proof_manifest_template(manifest_id, org_id, timestamp)
        proof_manifest_path.write_text(json.dumps(proof_manifest, indent=2), encoding="utf-8")
        result.files_created.append("proofs/proof-manifest.json")

        # Create attestation-manifest.json
        attestation_manifest_path = output_dir / "proofs" / "attestation-manifest.json"
        attestation_manifest = _create_attestation_manifest_template(manifest_id, org_id, timestamp)
        attestation_manifest_path.write_text(json.dumps(attestation_manifest, indent=2), encoding="utf-8")
        result.files_created.append("proofs/attestation-manifest.json")

        # Create verification output placeholder
        verify_output_path = output_dir / "verification" / "specora-verify-output.json"
        verify_output = _create_verification_output()
        verify_output_path.write_text(json.dumps(verify_output, indent=2), encoding="utf-8")
        result.files_created.append("verification/specora-verify-output.json")
        result.warnings.append(
            "verification/specora-verify-output.json is a placeholder. "
            "Run 'specora-verify vectors verify --format json' to generate actual output."
        )

        # Create CI badges
        badges_path = output_dir / "ci" / "badges.json"
        badges_content = _create_badges_json()
        badges_path.write_text(json.dumps(badges_content, indent=2), encoding="utf-8")
        result.files_created.append("ci/badges.json")

        # Copy CI workflow template
        ci_workflow_src = TEMPLATES_DIR / "ci-workflow.yml"
        ci_workflow_dst = output_dir / "ci" / "specora-governance.yml"
        if ci_workflow_src.exists():
            # Update tier in template
            ci_content = ci_workflow_src.read_text(encoding="utf-8")
            ci_content = ci_content.replace(
                "CERTIFICATION_TIER: basic",
                f"CERTIFICATION_TIER: {tier}",
            )
            ci_workflow_dst.write_text(ci_content, encoding="utf-8")
            result.files_created.append("ci/specora-governance.yml")

        # Copy baseline policy template
        policy_src = TEMPLATES_DIR / "baseline-policy.json"
        policy_dst = output_dir / "policy" / "baseline-policy.json"
        if policy_src.exists():
            # Update tier in template
            policy_content = json.loads(policy_src.read_text(encoding="utf-8"))
            policy_content["tier"] = tier

            # Adjust policy for higher tiers
            if tier in ("enterprise", "regulated"):
                policy_content["governance"]["anchor_enabled"] = True

            if tier == "regulated":
                policy_content["governance"]["audit_export_enabled"] = True

            policy_dst.write_text(json.dumps(policy_content, indent=2), encoding="utf-8")
            result.files_created.append("policy/baseline-policy.json")

        # Enterprise/Regulated artifacts
        if tier in ("enterprise", "regulated"):
            # Anchor payload
            anchor_payload_path = output_dir / "proofs" / "anchor-payload.json"
            anchor_payload = _create_anchor_payload_template(timestamp)
            anchor_payload_path.write_text(json.dumps(anchor_payload, indent=2), encoding="utf-8")
            result.files_created.append("proofs/anchor-payload.json")

            # Anchor receipt
            anchor_receipt_path = output_dir / "proofs" / "anchor-receipt.json"
            anchor_receipt = _create_anchor_receipt_template(timestamp)
            anchor_receipt_path.write_text(json.dumps(anchor_receipt, indent=2), encoding="utf-8")
            result.files_created.append("proofs/anchor-receipt.json")

        # Regulated artifacts
        if tier == "regulated":
            # TLA+ summary
            tla_summary_path = output_dir / "optional" / "tla-summary.json"
            tla_summary = _create_tla_summary_template()
            tla_summary_path.write_text(json.dumps(tla_summary, indent=2), encoding="utf-8")
            result.files_created.append("optional/tla-summary.json")

        # Create instructions
        instructions_path = output_dir / "INSTRUCTIONS.md"
        instructions_content = _generate_instructions(
            tier, name, version, str(output_dir), timestamp
        )
        instructions_path.write_text(instructions_content, encoding="utf-8")
        result.files_created.append("INSTRUCTIONS.md")

        # Add warnings about placeholder values
        result.warnings.append(
            "Replace placeholder values in proof manifests with your actual data."
        )
        result.warnings.append(
            "Update ci/badges.json with your actual CI badge URL."
        )

    except OSError as e:
        result.success = False
        result.errors.append(f"Failed to create scaffold: {e}")

    return result
