"""Tests for bundle verification."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from specora_verify.hash import sha256_hex
from specora_verify.validators.bundle import verify_bundle


@pytest.fixture
def valid_bundle(tmp_path: Path) -> Path:
    """Create a valid test bundle."""
    bundle_path = tmp_path / "test_bundle.zip"

    # Create artifacts
    ledger_content = b'{"id":"1","data":"test"}\n{"id":"2","data":"test2"}\n'
    ledger_hash = sha256_hex(ledger_content)

    manifest = {
        "schema_version": "1.1.0",
        "bundle_created_at": "2026-03-01T00:00:00Z",
        "artifacts": [
            {
                "name": "ledger/ledger_rows.ndjson",
                "sha256": ledger_hash,
                "size_bytes": len(ledger_content),
                "record_count": 2,
            }
        ],
    }

    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("ledger/ledger_rows.ndjson", ledger_content)

    return bundle_path


class TestBundleVerification:
    """Tests for bundle verification."""

    def test_valid_bundle_passes(self, valid_bundle: Path) -> None:
        """Valid bundle must pass verification."""
        result = verify_bundle(valid_bundle)

        assert result.valid
        assert result.manifest_valid
        assert result.schema_version == "1.1.0"
        assert result.artifacts_verified == 1
        assert result.artifacts_failed == 0

    def test_missing_file_fails(self, tmp_path: Path) -> None:
        """Missing bundle file must fail."""
        nonexistent = tmp_path / "nonexistent.zip"
        result = verify_bundle(nonexistent)

        assert not result.valid
        assert "not found" in result.errors[0].lower()

    def test_invalid_zip_fails(self, tmp_path: Path) -> None:
        """Invalid ZIP file must fail."""
        invalid_zip = tmp_path / "invalid.zip"
        invalid_zip.write_bytes(b"not a zip file")

        result = verify_bundle(invalid_zip)

        assert not result.valid
        assert any("zip" in e.lower() for e in result.errors)

    def test_missing_manifest_fails(self, tmp_path: Path) -> None:
        """Bundle without manifest.json must fail."""
        bundle_path = tmp_path / "no_manifest.zip"

        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("data.json", '{"test": true}')

        result = verify_bundle(bundle_path)

        assert not result.valid
        assert any("manifest" in e.lower() for e in result.errors)

    def test_tampered_artifact_fails(self, tmp_path: Path) -> None:
        """Bundle with tampered artifact must fail."""
        bundle_path = tmp_path / "tampered.zip"

        # Create manifest with hash of original content
        original_content = b'{"id":"1","data":"original"}\n'
        original_hash = sha256_hex(original_content)

        manifest = {
            "schema_version": "1.1.0",
            "artifacts": [
                {
                    "name": "data.ndjson",
                    "sha256": original_hash,
                    "size_bytes": len(original_content),
                }
            ],
        }

        # But write different content
        tampered_content = b'{"id":"1","data":"TAMPERED"}\n'

        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("data.ndjson", tampered_content)

        result = verify_bundle(bundle_path)

        assert not result.valid
        assert result.artifacts_failed == 1
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_missing_artifact_fails(self, tmp_path: Path) -> None:
        """Bundle with missing artifact must fail."""
        bundle_path = tmp_path / "missing_artifact.zip"

        manifest = {
            "schema_version": "1.1.0",
            "artifacts": [
                {
                    "name": "missing_file.ndjson",
                    "sha256": "a" * 64,
                    "size_bytes": 100,
                }
            ],
        }

        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))

        result = verify_bundle(bundle_path)

        assert not result.valid
        assert result.artifacts_failed == 1
        assert any("not found" in e.lower() for e in result.errors)

    def test_size_mismatch_fails(self, tmp_path: Path) -> None:
        """Bundle with size mismatch must fail."""
        bundle_path = tmp_path / "size_mismatch.zip"

        content = b"short"
        content_hash = sha256_hex(content)

        manifest = {
            "schema_version": "1.1.0",
            "artifacts": [
                {
                    "name": "data.txt",
                    "sha256": content_hash,
                    "size_bytes": 9999,  # Wrong size
                }
            ],
        }

        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("data.txt", content)

        result = verify_bundle(bundle_path)

        assert not result.valid
        assert any("size" in e.lower() for e in result.errors)


class TestBundleManifestHash:
    """Tests for bundle manifest hash computation."""

    def test_manifest_hash_computed(self, valid_bundle: Path) -> None:
        """Manifest hash must be computed."""
        result = verify_bundle(valid_bundle)

        assert result.manifest_hash is not None
        assert len(result.manifest_hash) == 64

    def test_manifest_hash_is_deterministic(self, valid_bundle: Path) -> None:
        """Same bundle must produce same manifest hash."""
        result1 = verify_bundle(valid_bundle)
        result2 = verify_bundle(valid_bundle)

        assert result1.manifest_hash == result2.manifest_hash


class TestMultipleArtifacts:
    """Tests for bundles with multiple artifacts."""

    def test_multiple_valid_artifacts(self, tmp_path: Path) -> None:
        """Bundle with multiple valid artifacts must pass."""
        bundle_path = tmp_path / "multi.zip"

        content1 = b"content one"
        content2 = b"content two"
        content3 = b"content three"

        manifest = {
            "schema_version": "1.1.0",
            "artifacts": [
                {"name": "file1.txt", "sha256": sha256_hex(content1), "size_bytes": len(content1)},
                {"name": "file2.txt", "sha256": sha256_hex(content2), "size_bytes": len(content2)},
                {"name": "file3.txt", "sha256": sha256_hex(content3), "size_bytes": len(content3)},
            ],
        }

        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("file1.txt", content1)
            zf.writestr("file2.txt", content2)
            zf.writestr("file3.txt", content3)

        result = verify_bundle(bundle_path)

        assert result.valid
        assert result.artifacts_verified == 3
        assert result.artifacts_failed == 0

    def test_partial_failure(self, tmp_path: Path) -> None:
        """Bundle with one tampered artifact must report partial failure."""
        bundle_path = tmp_path / "partial.zip"

        content1 = b"valid content"
        content2 = b"will be tampered"

        manifest = {
            "schema_version": "1.1.0",
            "artifacts": [
                {"name": "valid.txt", "sha256": sha256_hex(content1), "size_bytes": len(content1)},
                {"name": "tampered.txt", "sha256": sha256_hex(content2), "size_bytes": len(content2)},
            ],
        }

        with zipfile.ZipFile(bundle_path, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("valid.txt", content1)
            zf.writestr("tampered.txt", b"TAMPERED!")

        result = verify_bundle(bundle_path)

        assert not result.valid
        assert result.artifacts_verified == 1
        assert result.artifacts_failed == 1
