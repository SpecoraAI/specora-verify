"""Tests for certification bundle scaffold generation.

RCP-113: Certification Scaffold Availability
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path

import pytest

from specora_verify.scaffold import generate_scaffold


class TestScaffoldGeneration:
    """Test scaffold generation."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        d = tempfile.mkdtemp()
        yield Path(d)
        shutil.rmtree(d, ignore_errors=True)

    def test_basic_tier_creates_correct_structure(self, temp_dir):
        """Test that Basic tier creates the expected directory structure."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
        )

        assert result.success is True
        assert result.tier == "basic"
        assert result.name == "test-platform"
        assert result.version == "1.0.0"

        # Check directory structure
        assert (output / "proofs").is_dir()
        assert (output / "verification").is_dir()
        assert (output / "ci").is_dir()
        assert (output / "policy").is_dir()

        # Check required files
        assert (output / "meta.json").exists()
        assert (output / "proofs" / "proof-manifest.json").exists()
        assert (output / "proofs" / "attestation-manifest.json").exists()
        assert (output / "verification" / "specora-verify-output.json").exists()
        assert (output / "ci" / "badges.json").exists()
        assert (output / "ci" / "specora-governance.yml").exists()
        assert (output / "policy" / "baseline-policy.json").exists()
        assert (output / "INSTRUCTIONS.md").exists()

    def test_enterprise_tier_creates_additional_artifacts(self, temp_dir):
        """Test that Enterprise tier creates anchor artifacts."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="enterprise",
            name="test-platform",
            version="2.0.0",
        )

        assert result.success is True
        assert result.tier == "enterprise"

        # Check enterprise-specific artifacts
        assert (output / "proofs" / "anchor-payload.json").exists()
        assert (output / "proofs" / "anchor-receipt.json").exists()
        assert (output / "optional").is_dir()

    def test_regulated_tier_creates_tla_summary(self, temp_dir):
        """Test that Regulated tier creates TLA+ summary."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="regulated",
            name="test-platform",
            version="3.0.0",
        )

        assert result.success is True
        assert result.tier == "regulated"

        # Check regulated-specific artifacts
        assert (output / "optional" / "tla-summary.json").exists()

    def test_meta_json_contains_correct_fields(self, temp_dir):
        """Test that meta.json has correct generator metadata."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="my-platform",
            version="1.2.3",
        )

        assert result.success is True

        meta = json.loads((output / "meta.json").read_text())

        assert meta["bundle_version"] == "1.0.0"
        assert meta["tier_requested"] == "basic"
        assert meta["integration"]["name"] == "my-platform"
        assert meta["integration"]["version"] == "1.2.3"
        assert "generator" in meta
        assert meta["generator"]["tool"] == "specora-verify"
        assert meta["generator"]["command"] == "certify scaffold"
        assert "generated_at" in meta["generator"]
        assert "spec_versions" in meta

    def test_meta_json_timestamp_is_valid_iso8601(self, temp_dir):
        """Test that timestamps are valid ISO8601 with Z suffix."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
        )

        assert result.success is True

        meta = json.loads((output / "meta.json").read_text())

        # Check timestamp format
        timestamp = meta["generator"]["generated_at"]
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", timestamp)

    def test_invalid_tier_returns_error(self, temp_dir):
        """Test that invalid tier returns error."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="invalid",
            name="test-platform",
            version="1.0.0",
        )

        assert result.success is False
        assert any("Invalid tier" in e for e in result.errors)

    def test_invalid_name_returns_error(self, temp_dir):
        """Test that invalid platform name returns error."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="",
            version="1.0.0",
        )

        assert result.success is False
        assert any("name is required" in e.lower() for e in result.errors)

    def test_invalid_version_returns_error(self, temp_dir):
        """Test that invalid version returns error."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="invalid",
        )

        assert result.success is False
        assert any("Invalid version" in e for e in result.errors)

    def test_existing_directory_without_force_returns_error(self, temp_dir):
        """Test that existing directory without --force returns error."""
        output = temp_dir / "bundle"
        output.mkdir()

        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
            force=False,
        )

        assert result.success is False
        assert any("already exists" in e for e in result.errors)

    def test_existing_directory_with_force_succeeds(self, temp_dir):
        """Test that existing directory with --force succeeds."""
        output = temp_dir / "bundle"
        output.mkdir()

        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
            force=True,
        )

        assert result.success is True

    def test_vendor_id_is_embedded_in_meta(self, temp_dir):
        """Test that vendor_id is embedded in meta.json when provided."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
            vendor_id="c16922ef-95de-4d43-ac62-a279fac7e14f",
        )

        assert result.success is True

        meta = json.loads((output / "meta.json").read_text())
        assert meta["integration"]["vendor_id"] == "c16922ef-95de-4d43-ac62-a279fac7e14f"

    def test_policy_tier_matches_requested_tier(self, temp_dir):
        """Test that baseline policy has correct tier."""
        for tier in ["basic", "enterprise", "regulated"]:
            output = temp_dir / f"bundle-{tier}"
            result = generate_scaffold(
                output_dir=output,
                tier=tier,
                name="test-platform",
                version="1.0.0",
            )

            assert result.success is True

            policy = json.loads((output / "policy" / "baseline-policy.json").read_text())
            assert policy["tier"] == tier

    def test_ci_workflow_tier_matches_requested_tier(self, temp_dir):
        """Test that CI workflow has correct tier."""
        for tier in ["basic", "enterprise", "regulated"]:
            output = temp_dir / f"bundle-{tier}"
            result = generate_scaffold(
                output_dir=output,
                tier=tier,
                name="test-platform",
                version="1.0.0",
            )

            assert result.success is True

            ci_content = (output / "ci" / "specora-governance.yml").read_text()
            assert f"CERTIFICATION_TIER: {tier}" in ci_content

    def test_semver_with_prerelease_is_valid(self, temp_dir):
        """Test that semver with pre-release suffix is valid."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0-beta.1",
        )

        assert result.success is True
        assert result.version == "1.0.0-beta.1"

    def test_semver_with_build_metadata_is_valid(self, temp_dir):
        """Test that semver with build metadata is valid."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0+build.123",
        )

        assert result.success is True
        assert result.version == "1.0.0+build.123"

    def test_files_created_list_is_populated(self, temp_dir):
        """Test that files_created list is populated correctly."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
        )

        assert result.success is True
        assert "meta.json" in result.files_created
        assert "proofs/proof-manifest.json" in result.files_created
        assert "proofs/attestation-manifest.json" in result.files_created
        assert "INSTRUCTIONS.md" in result.files_created

    def test_warnings_include_placeholder_note(self, temp_dir):
        """Test that warnings mention placeholder values."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
        )

        assert result.success is True
        assert len(result.warnings) > 0
        assert any("placeholder" in w.lower() for w in result.warnings)


class TestScaffoldIdempotency:
    """Test scaffold idempotency behavior."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        d = tempfile.mkdtemp()
        yield Path(d)
        shutil.rmtree(d, ignore_errors=True)

    def test_scaffold_with_force_is_idempotent(self, temp_dir):
        """Test that scaffold with --force produces same structure twice."""
        output = temp_dir / "bundle"

        # First generation
        result1 = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
        )
        assert result1.success is True

        # Second generation with force
        result2 = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
            force=True,
        )
        assert result2.success is True

        # Both should have same files
        assert set(result1.files_created) == set(result2.files_created)


class TestScaffoldSafetyConstraints:
    """Test scaffold safety constraints."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        d = tempfile.mkdtemp()
        yield Path(d)
        shutil.rmtree(d, ignore_errors=True)

    def test_scaffold_does_not_create_attestation(self, temp_dir):
        """Test that scaffold does NOT create attestation (safety)."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
        )

        assert result.success is True

        # Should NOT have attestation.json
        assert not (output / "attestation.json").exists()
        assert "attestation.json" not in result.files_created

    def test_scaffold_uses_placeholder_hashes(self, temp_dir):
        """Test that scaffold uses placeholder hashes, not real ones."""
        output = temp_dir / "bundle"
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="test-platform",
            version="1.0.0",
        )

        assert result.success is True

        proof_manifest = json.loads((output / "proofs" / "proof-manifest.json").read_text())
        assert proof_manifest["root_hash"] == "REPLACE_WITH_YOUR_MERKLE_ROOT_HASH"

    def test_name_validation_blocks_injection(self, temp_dir):
        """Test that name validation blocks path injection."""
        output = temp_dir / "bundle"

        # Try path injection
        result = generate_scaffold(
            output_dir=output,
            tier="basic",
            name="../../../etc/passwd",
            version="1.0.0",
        )

        assert result.success is False
