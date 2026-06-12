"""CLI integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from specora_verify.cli import main
from specora_verify.errors import EXIT_ERROR, EXIT_FAIL, EXIT_PASS

# Path to golden vectors
VECTORS_DIR = Path(__file__).parent.parent / "specora_verify" / "vectors" / "manifest"


class TestCLIVectorsVerify:
    """Tests for 'specora-verify vectors verify' command."""

    def test_vectors_verify_pass(self) -> None:
        """vectors verify must pass with valid vectors directory."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        with pytest.raises(SystemExit) as exc_info:
            main(["vectors", "verify", "--vectors-dir", str(VECTORS_DIR)])

        assert exc_info.value.code == EXIT_PASS

    def test_vectors_verify_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """vectors verify --format json must produce valid JSON."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        with pytest.raises(SystemExit):
            main(["--format", "json", "vectors", "verify", "--vectors-dir", str(VECTORS_DIR)])

        captured = capsys.readouterr()
        result = json.loads(captured.out)

        assert "valid" in result
        assert "total" in result
        assert "passed" in result


class TestCLIManifestHash:
    """Tests for 'specora-verify manifest hash' command."""

    def test_manifest_hash_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """manifest hash must output SHA-256 hash."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        manifest_file = VECTORS_DIR / "proof-manifest-1.0.0.json"
        if not manifest_file.exists():
            pytest.skip(f"Manifest file not found: {manifest_file}")

        with pytest.raises(SystemExit) as exc_info:
            main(["manifest", "hash", str(manifest_file)])

        assert exc_info.value.code == EXIT_PASS

        captured = capsys.readouterr()
        hash_output = captured.out.strip()

        # Must be 64-char hex
        assert len(hash_output) == 64
        assert all(c in "0123456789abcdef" for c in hash_output)

    def test_manifest_hash_matches_golden(self, capsys: pytest.CaptureFixture[str]) -> None:
        """manifest hash must match golden vector hash."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        manifest_file = VECTORS_DIR / "proof-manifest-1.0.0.json"
        sha256_file = VECTORS_DIR / "proof-manifest-1.0.0.sha256.txt"

        if not manifest_file.exists() or not sha256_file.exists():
            pytest.skip("Vector files not found")

        expected_hash = sha256_file.read_text().strip()

        with pytest.raises(SystemExit):
            main(["manifest", "hash", str(manifest_file)])

        captured = capsys.readouterr()
        actual_hash = captured.out.strip()

        assert actual_hash == expected_hash

    def test_manifest_hash_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """manifest hash --format json must output JSON."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        manifest_file = VECTORS_DIR / "proof-manifest-1.0.0.json"
        if not manifest_file.exists():
            pytest.skip(f"Manifest file not found: {manifest_file}")

        with pytest.raises(SystemExit):
            main(["--format", "json", "manifest", "hash", str(manifest_file)])

        captured = capsys.readouterr()
        result = json.loads(captured.out)

        assert "hash" in result
        assert "algorithm" in result
        assert result["algorithm"] == "sha256"

    def test_manifest_hash_file_not_found(self) -> None:
        """manifest hash with missing file must return ERROR."""
        with pytest.raises(SystemExit) as exc_info:
            main(["manifest", "hash", "/nonexistent/file.json"])

        assert exc_info.value.code == EXIT_ERROR


class TestCLIManifestVerify:
    """Tests for 'specora-verify manifest verify' command."""

    def test_manifest_verify_pass(self) -> None:
        """manifest verify must pass for valid manifest."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        manifest_file = VECTORS_DIR / "proof-manifest-1.0.0.json"
        if not manifest_file.exists():
            pytest.skip(f"Manifest file not found: {manifest_file}")

        with pytest.raises(SystemExit) as exc_info:
            main(["manifest", "verify", str(manifest_file)])

        assert exc_info.value.code == EXIT_PASS

    def test_manifest_verify_with_expected_hash(self) -> None:
        """manifest verify --expected-hash must verify hash."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        manifest_file = VECTORS_DIR / "proof-manifest-1.0.0.json"
        sha256_file = VECTORS_DIR / "proof-manifest-1.0.0.sha256.txt"

        if not manifest_file.exists() or not sha256_file.exists():
            pytest.skip("Vector files not found")

        expected_hash = sha256_file.read_text().strip()

        with pytest.raises(SystemExit) as exc_info:
            main(["manifest", "verify", str(manifest_file), "--expected-hash", expected_hash])

        assert exc_info.value.code == EXIT_PASS

    def test_manifest_verify_wrong_hash_fails(self) -> None:
        """manifest verify with wrong expected hash must fail."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        manifest_file = VECTORS_DIR / "proof-manifest-1.0.0.json"
        if not manifest_file.exists():
            pytest.skip(f"Manifest file not found: {manifest_file}")

        wrong_hash = "0" * 64

        with pytest.raises(SystemExit) as exc_info:
            main(["manifest", "verify", str(manifest_file), "--expected-hash", wrong_hash])

        assert exc_info.value.code == EXIT_FAIL

    def test_manifest_verify_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """manifest verify --format json must output JSON."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        manifest_file = VECTORS_DIR / "proof-manifest-1.0.0.json"
        if not manifest_file.exists():
            pytest.skip(f"Manifest file not found: {manifest_file}")

        with pytest.raises(SystemExit):
            main(["--format", "json", "manifest", "verify", str(manifest_file)])

        captured = capsys.readouterr()
        result = json.loads(captured.out)

        assert "valid" in result
        assert "spec_id" in result
        assert "computed_hash" in result


class TestCLIBundleVerify:
    """Tests for 'specora-verify bundle verify' command."""

    def test_bundle_verify_file_not_found(self) -> None:
        """bundle verify with missing file must return ERROR."""
        with pytest.raises(SystemExit) as exc_info:
            main(["bundle", "verify", "/nonexistent/bundle.zip"])

        assert exc_info.value.code == EXIT_ERROR


class TestCLIExitCodes:
    """Tests for CLI exit code contract (RCP-96)."""

    def test_exit_pass_is_zero(self) -> None:
        """EXIT_PASS must be 0."""
        assert EXIT_PASS == 0

    def test_exit_fail_is_two(self) -> None:
        """EXIT_FAIL must be 2."""
        assert EXIT_FAIL == 2

    def test_exit_error_is_three(self) -> None:
        """EXIT_ERROR must be 3."""
        assert EXIT_ERROR == 3


class TestCLIHelp:
    """Tests for CLI help output."""

    def test_main_help(self) -> None:
        """--help must not raise unhandled exception."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0

    def test_vectors_help(self) -> None:
        """vectors --help must work."""
        with pytest.raises(SystemExit) as exc_info:
            main(["vectors", "--help"])

        assert exc_info.value.code == 0

    def test_manifest_help(self) -> None:
        """manifest --help must work."""
        with pytest.raises(SystemExit) as exc_info:
            main(["manifest", "--help"])

        assert exc_info.value.code == 0

    def test_bundle_help(self) -> None:
        """bundle --help must work."""
        with pytest.raises(SystemExit) as exc_info:
            main(["bundle", "--help"])

        assert exc_info.value.code == 0


class TestCLIVersion:
    """Tests for version output."""

    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        """--version must output version string."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])

        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "specora-verify" in captured.out
        # Assert against the package version so this does not break on bumps.
        from specora_verify import __version__

        assert __version__ in captured.out
