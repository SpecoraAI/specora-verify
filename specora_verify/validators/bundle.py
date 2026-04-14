"""Bundle (ZIP) verification.

Verifies the integrity of Specora proof bundles exported from the platform.
A bundle is a ZIP file containing:
- manifest.json: Bundle manifest with artifact hashes
- Various NDJSON and JSON files referenced in the manifest
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from specora_verify.hash import compute_manifest_hash, sha256_hex


@dataclass
class ArtifactVerification:
    """Result of verifying a single artifact in the bundle."""

    name: str
    declared_hash: str
    computed_hash: str
    size_bytes: int
    valid: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "declared_hash": self.declared_hash,
            "computed_hash": self.computed_hash,
            "size_bytes": self.size_bytes,
            "valid": self.valid,
            "error": self.error,
        }


@dataclass
class BundleVerificationResult:
    """Result of bundle verification."""

    valid: bool
    bundle_path: str
    manifest_valid: bool = False
    manifest_hash: str | None = None
    schema_version: str | None = None
    artifacts_verified: int = 0
    artifacts_failed: int = 0
    artifacts: list[ArtifactVerification] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "bundle_path": self.bundle_path,
            "manifest_valid": self.manifest_valid,
            "manifest_hash": self.manifest_hash,
            "schema_version": self.schema_version,
            "artifacts_verified": self.artifacts_verified,
            "artifacts_failed": self.artifacts_failed,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "errors": self.errors,
        }


def _verify_artifact(
    zf: zipfile.ZipFile,
    artifact: dict[str, Any],
) -> ArtifactVerification:
    """Verify a single artifact in the bundle.

    Args:
        zf: Open ZipFile object
        artifact: Artifact entry from manifest (name, sha256, size_bytes, etc.)

    Returns:
        ArtifactVerification with results
    """
    name = artifact.get("name", "")
    declared_hash = artifact.get("sha256", "")
    declared_size = artifact.get("size_bytes", 0)

    try:
        with zf.open(name) as f:
            content = f.read()
    except KeyError:
        return ArtifactVerification(
            name=name,
            declared_hash=declared_hash,
            computed_hash="",
            size_bytes=0,
            valid=False,
            error=f"File not found in bundle: {name}",
        )

    computed_hash = sha256_hex(content)
    actual_size = len(content)

    errors: list[str] = []
    if computed_hash != declared_hash:
        errors.append(
            f"Hash mismatch: computed {computed_hash}, declared {declared_hash}"
        )
    if declared_size and actual_size != declared_size:
        errors.append(
            f"Size mismatch: actual {actual_size}, declared {declared_size}"
        )

    return ArtifactVerification(
        name=name,
        declared_hash=declared_hash,
        computed_hash=computed_hash,
        size_bytes=actual_size,
        valid=len(errors) == 0,
        error="; ".join(errors) if errors else None,
    )


def verify_bundle(bundle_path: Path | str) -> BundleVerificationResult:
    """Verify a Specora proof bundle ZIP.

    Verification steps:
    1. Open ZIP and verify structure
    2. Parse manifest.json
    3. Verify each artifact's SHA-256 hash matches manifest
    4. Compute manifest hash

    Args:
        bundle_path: Path to bundle ZIP file

    Returns:
        BundleVerificationResult with all verification details
    """
    if isinstance(bundle_path, str):
        bundle_path = Path(bundle_path)

    result = BundleVerificationResult(
        valid=True,
        bundle_path=str(bundle_path),
    )

    # Check file exists
    if not bundle_path.exists():
        result.valid = False
        result.errors.append(f"Bundle file not found: {bundle_path}")
        return result

    # Open ZIP
    try:
        zf = zipfile.ZipFile(bundle_path, "r")
    except zipfile.BadZipFile as e:
        result.valid = False
        result.errors.append(f"Invalid ZIP file: {e}")
        return result

    with zf:
        # Check for manifest.json
        if "manifest.json" not in zf.namelist():
            result.valid = False
            result.errors.append("manifest.json not found in bundle")
            return result

        # Parse manifest
        try:
            manifest_bytes = zf.read("manifest.json")
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except json.JSONDecodeError as e:
            result.valid = False
            result.errors.append(f"Failed to parse manifest.json: {e}")
            return result

        # Extract manifest metadata
        result.schema_version = manifest.get("schema_version")
        result.manifest_valid = True
        result.manifest_hash = compute_manifest_hash(manifest)

        # Verify artifacts
        artifacts = manifest.get("artifacts", [])
        for artifact in artifacts:
            artifact_result = _verify_artifact(zf, artifact)
            result.artifacts.append(artifact_result)

            if artifact_result.valid:
                result.artifacts_verified += 1
            else:
                result.artifacts_failed += 1
                result.valid = False
                if artifact_result.error:
                    result.errors.append(
                        f"Artifact '{artifact_result.name}': {artifact_result.error}"
                    )

    return result
