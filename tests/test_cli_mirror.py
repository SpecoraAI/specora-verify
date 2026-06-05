"""Tests for mirror CLI commands (PR-ENT-540).

Tests for `specora-verify mirror verify-latest` and related commands.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Path to mirror test fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "mirror"


def run_cli(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    """Run specora-verify CLI command."""
    cmd = [sys.executable, "-m", "specora_verify", *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
        input=input_text,
    )


class TestMirrorVerifyLatestOffline:
    """Tests for `specora-verify mirror verify-latest --offline`."""

    def test_pass_github_s3_match(self) -> None:
        """PASS when GitHub and S3 anchors match."""
        result = run_cli(
            "mirror",
            "verify-latest",
            "--offline",
            "--local-github",
            str(FIXTURES_DIR / "valid-github.json"),
            "--local-s3",
            str(FIXTURES_DIR / "valid-s3.json"),
            "--quorum",
            "2",
        )

        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
        assert "PASS" in result.stdout or '"status": "pass"' in result.stdout

    def test_pass_github_dns_match(self) -> None:
        """PASS when GitHub and DNS anchors match (32-char prefix)."""
        result = run_cli(
            "mirror",
            "verify-latest",
            "--offline",
            "--local-github",
            str(FIXTURES_DIR / "valid-github.json"),
            "--local-dns",
            str(FIXTURES_DIR / "valid-dns.txt"),
            "--quorum",
            "2",
        )

        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
        assert "PASS" in result.stdout

    def test_fail_hash_mismatch(self) -> None:
        """FAIL when hash mismatch detected."""
        result = run_cli(
            "mirror",
            "verify-latest",
            "--offline",
            "--local-github",
            str(FIXTURES_DIR / "valid-github.json"),
            "--local-s3",
            str(FIXTURES_DIR / "mismatch-s3.json"),
            "--quorum",
            "2",
        )

        # Exit code 2 = FAIL
        assert result.returncode == 2, (
            f"Expected exit 2, got {result.returncode}\nstdout: {result.stdout}"
        )
        assert "FAIL" in result.stdout or "mismatch" in result.stdout.lower()

    def test_error_quorum_failure(self) -> None:
        """ERROR when quorum cannot be reached."""
        result = run_cli(
            "mirror",
            "verify-latest",
            "--offline",
            "--local-github",
            str(FIXTURES_DIR / "valid-github.json"),
            "--quorum",
            "2",
        )

        # Exit code 3 = ERROR
        assert result.returncode == 3, (
            f"Expected exit 3, got {result.returncode}\nstdout: {result.stdout}"
        )

    def test_error_no_sources(self) -> None:
        """ERROR when no sources specified."""
        result = run_cli(
            "mirror",
            "verify-latest",
            "--offline",
        )

        assert result.returncode == 3
        assert "no source" in result.stderr.lower() or "no source" in result.stdout.lower()


class TestMirrorVerifyLatestOutput:
    """Tests for mirror verify-latest output formatting."""

    def test_text_output_format(self) -> None:
        """Text output includes expected fields."""
        result = run_cli(
            "--format",
            "text",
            "mirror",
            "verify-latest",
            "--offline",
            "--local-github",
            str(FIXTURES_DIR / "valid-github.json"),
            "--local-s3",
            str(FIXTURES_DIR / "valid-s3.json"),
            "--quorum",
            "2",
        )

        assert result.returncode == 0
        assert "SPECORA MIRROR VERIFICATION" in result.stdout
        assert "Quorum Required" in result.stdout
        assert "Quorum Achieved" in result.stdout
        assert "Sources Checked" in result.stdout

    def test_json_output_format(self) -> None:
        """JSON output is valid and contains expected fields."""
        result = run_cli(
            "--format",
            "json",
            "mirror",
            "verify-latest",
            "--offline",
            "--local-github",
            str(FIXTURES_DIR / "valid-github.json"),
            "--local-s3",
            str(FIXTURES_DIR / "valid-s3.json"),
            "--quorum",
            "2",
        )

        assert result.returncode == 0

        # Parse JSON output
        data = json.loads(result.stdout)

        assert data["status"] == "pass"
        assert data["valid"] is True
        assert data["quorum_required"] == 2
        assert data["quorum_achieved"] == 2
        assert "sources" in data
        assert "github_release" in data["sources"]
        assert "s3_versioned" in data["sources"]


class TestMirrorVerifyLatestReceipt:
    """Tests for --emit-receipt functionality."""

    def test_emit_receipt_creates_file(self) -> None:
        """--emit-receipt creates valid JSON receipt."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            receipt_path = Path(f.name)

        try:
            result = run_cli(
                "mirror",
                "verify-latest",
                "--offline",
                "--local-github",
                str(FIXTURES_DIR / "valid-github.json"),
                "--local-s3",
                str(FIXTURES_DIR / "valid-s3.json"),
                "--quorum",
                "2",
                "--emit-receipt",
                str(receipt_path),
            )

            assert result.returncode == 0

            # Verify receipt was created
            assert receipt_path.exists()

            # Parse receipt
            receipt_data = json.loads(receipt_path.read_text())

            assert receipt_data["schema_version"] == "1.0.0"
            assert "verifier_version" in receipt_data
            assert "verification_timestamp" in receipt_data
            assert receipt_data["result"]["status"] == "pass"
            assert receipt_data["result"]["valid"] is True

        finally:
            receipt_path.unlink(missing_ok=True)


class TestMirrorCIMode:
    """Tests for CI mode exit code mapping."""

    def test_ci_mode_maps_warn_to_fail(self) -> None:
        """--ci maps WARN (1) to FAIL (2)."""
        # Create scenario where we get WARN (quorum met, some unreachable)
        # This is tricky to test in offline mode since we can't simulate unreachable
        # For now, just verify CI flag is accepted
        result = run_cli(
            "--ci",
            "mirror",
            "verify-latest",
            "--offline",
            "--local-github",
            str(FIXTURES_DIR / "valid-github.json"),
            "--local-s3",
            str(FIXTURES_DIR / "valid-s3.json"),
            "--quorum",
            "2",
        )

        # PASS should remain 0 even in CI mode
        assert result.returncode == 0


class TestMirrorVerifyAnchors:
    """Tests for `specora-verify mirror verify-anchors`."""

    def test_offline_requires_local_dirs(self) -> None:
        """Offline mode requires local directory arguments."""
        result = run_cli(
            "mirror",
            "verify-anchors",
            "--since",
            "2026-03-01",
            "--offline",
        )

        assert result.returncode == 3
        assert "local" in result.stderr.lower() or "local" in result.stdout.lower()

    def test_online_not_supported(self) -> None:
        """Online mode returns error (not yet supported)."""
        result = run_cli(
            "mirror",
            "verify-anchors",
            "--since",
            "2026-03-01",
            "--github-repo",
            "specora/anchors",
        )

        assert result.returncode == 3
        assert "online" in result.stderr.lower() or "rate" in result.stderr.lower()

    def test_offline_chain_pass(self) -> None:
        """Offline verification of valid chain should PASS."""
        chain_dir = FIXTURES_DIR / "chain"
        result = run_cli(
            "mirror",
            "verify-anchors",
            "--since",
            "2026-01-01",
            "--offline",
            "--local-github-dir",
            str(chain_dir),
            "--quorum",
            "1",
        )

        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
        assert "PASS" in result.stdout or '"status": "pass"' in result.stdout

    def test_offline_json_output(self) -> None:
        """JSON output should be valid."""
        chain_dir = FIXTURES_DIR / "chain"
        result = run_cli(
            "--format",
            "json",
            "mirror",
            "verify-anchors",
            "--since",
            "2026-01-01",
            "--offline",
            "--local-github-dir",
            str(chain_dir),
            "--quorum",
            "1",
        )

        assert result.returncode == 0

        # Parse JSON output
        data = json.loads(result.stdout)
        assert data["status"] == "pass"
        assert data["total_anchors"] == 3
        assert data["chain_linkage_valid"] is True
