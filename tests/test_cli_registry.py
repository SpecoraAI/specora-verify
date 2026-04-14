"""CLI tests for registry commands (PR-ENT-560)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "registry"
CHAIN_DIR = FIXTURES_DIR / "chain"


def run_cli(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Run the CLI with given arguments."""
    cmd = [sys.executable, "-m", "specora_verify"] + list(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check,
    )


class TestRegistryVerify:
    """Tests for registry verify command."""

    def test_verify_valid_snapshot(self):
        """Valid snapshot returns exit 0."""
        result = run_cli(
            "registry",
            "verify",
            str(FIXTURES_DIR / "snapshot-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout
        assert "Hash Valid:" in result.stdout
        assert "YES" in result.stdout

    def test_verify_snapshot_json_output(self):
        """JSON output format works."""
        result = run_cli(
            "--format",
            "json",
            "registry",
            "verify",
            str(FIXTURES_DIR / "snapshot-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["valid"] is True
        assert output["hash_valid"] is True
        assert output["is_genesis"] is True

    def test_verify_tampered_snapshot_fails(self):
        """Tampered snapshot fails (INV-REG-005)."""
        result = run_cli(
            "registry",
            "verify",
            str(FIXTURES_DIR / "snapshot-tampered.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 2  # FAIL
        assert "FAIL" in result.stdout
        assert "INV-REG-005" in result.stdout

    def test_verify_file_not_found(self):
        """Non-existent file returns error."""
        result = run_cli(
            "registry",
            "verify",
            "/nonexistent/snapshot.json",
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3  # ERROR
        assert "not found" in result.stderr.lower() or "not found" in result.stdout.lower()

    def test_verify_emit_receipt(self, tmp_path: Path):
        """Receipt emitted when requested."""
        receipt_path = tmp_path / "receipt.json"
        result = run_cli(
            "registry",
            "verify",
            str(FIXTURES_DIR / "snapshot-valid.json"),
            "--dangerously-skip-signature",
            "--emit-receipt",
            str(receipt_path),
        )
        assert result.returncode == 0
        assert receipt_path.exists()

        receipt = json.loads(receipt_path.read_text())
        assert receipt["schema_version"] == "1.0.0"
        assert "result" in receipt


class TestRegistryVerifyChain:
    """Tests for registry verify-chain command."""

    def test_verify_chain_valid(self):
        """Valid chain returns exit 0."""
        result = run_cli(
            "registry",
            "verify-chain",
            str(CHAIN_DIR),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout
        assert "Chain Length:" in result.stdout
        assert "Chain Valid:" in result.stdout
        assert "YES" in result.stdout

    def test_verify_chain_json_output(self):
        """JSON output format works."""
        result = run_cli(
            "--format",
            "json",
            "registry",
            "verify-chain",
            str(CHAIN_DIR),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["chain_valid"] is True
        assert output["chain_length"] == 3
        assert output["latest_version"] == 3

    def test_verify_chain_with_violation(self, tmp_path: Path):
        """Chain with revocation violation fails (INV-REG-003)."""
        # Create chain with violation
        chain_dir = tmp_path / "chain"
        chain_dir.mkdir()
        for name in ["snapshot-v0001.json", "snapshot-v0002.json", "snapshot-v0003.json"]:
            src = CHAIN_DIR / name
            (chain_dir / name).write_text(src.read_text())
        # Add violation snapshot
        (chain_dir / "snapshot-v0004.json").write_text(
            (FIXTURES_DIR / "snapshot-revocation-violation.json").read_text()
        )

        result = run_cli(
            "registry",
            "verify-chain",
            str(chain_dir),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 2  # FAIL
        assert "INV-REG-003" in result.stdout
        assert "Revocation" in result.stdout

    def test_verify_chain_empty_dir(self, tmp_path: Path):
        """Empty directory returns error."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = run_cli(
            "registry",
            "verify-chain",
            str(empty_dir),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3  # ERROR
        assert "No valid" in result.stderr or "No valid" in result.stdout

    def test_verify_chain_emit_receipt(self, tmp_path: Path):
        """Receipt emitted when requested."""
        receipt_path = tmp_path / "receipt.json"
        result = run_cli(
            "registry",
            "verify-chain",
            str(CHAIN_DIR),
            "--dangerously-skip-signature",
            "--emit-receipt",
            str(receipt_path),
        )
        assert result.returncode == 0
        assert receipt_path.exists()

        receipt = json.loads(receipt_path.read_text())
        assert receipt["schema_version"] == "1.0.0"
        assert receipt["result"]["chain_valid"] is True


class TestRegistryInfo:
    """Tests for registry info command."""

    def test_registry_info_valid(self):
        """Display snapshot info."""
        result = run_cli(
            "registry",
            "info",
            str(FIXTURES_DIR / "snapshot-valid.json"),
        )
        assert result.returncode == 0
        assert "SPECORA REGISTRY SNAPSHOT" in result.stdout
        assert "Version:" in result.stdout
        assert "Witnesses:" in result.stdout
        assert "witness-org-alpha" in result.stdout

    def test_registry_info_json_output(self):
        """JSON output format works."""
        result = run_cli(
            "--format",
            "json",
            "registry",
            "info",
            str(FIXTURES_DIR / "snapshot-valid.json"),
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["registry_version"] == 1
        assert len(output["witnesses"]) == 2

    def test_registry_info_file_not_found(self):
        """Non-existent file returns error."""
        result = run_cli(
            "registry",
            "info",
            "/nonexistent/snapshot.json",
        )
        assert result.returncode == 3  # ERROR


class TestRegistryExitCodes:
    """Tests for registry command exit codes."""

    def test_exit_code_pass(self):
        """PASS status returns exit 0."""
        result = run_cli(
            "registry",
            "verify",
            str(FIXTURES_DIR / "snapshot-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0

    def test_exit_code_fail_tampered(self):
        """FAIL status (tampered) returns exit 2."""
        result = run_cli(
            "registry",
            "verify",
            str(FIXTURES_DIR / "snapshot-tampered.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 2

    def test_exit_code_error_file_not_found(self):
        """ERROR status (file not found) returns exit 3."""
        result = run_cli(
            "registry",
            "verify",
            "/nonexistent/file.json",
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3


class TestSkipSignatureCIBlocking:
    """Tests for --dangerously-skip-signature blocking in CI mode."""

    def test_skip_signature_blocked_in_ci_mode_verify(self):
        """--dangerously-skip-signature + --ci returns error."""
        result = run_cli(
            "--ci",
            "registry",
            "verify",
            str(FIXTURES_DIR / "snapshot-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3  # ERROR
        assert "SKIP_SIGNATURE_IN_CI" in result.stderr or "cannot be used with --ci" in result.stderr

    def test_skip_signature_blocked_in_ci_mode_verify_chain(self):
        """--dangerously-skip-signature + --ci returns error for verify-chain."""
        result = run_cli(
            "--ci",
            "registry",
            "verify-chain",
            str(CHAIN_DIR),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3  # ERROR
        assert "SKIP_SIGNATURE_IN_CI" in result.stderr or "cannot be used with --ci" in result.stderr

    def test_skip_signature_allowed_without_ci_mode(self):
        """--dangerously-skip-signature works without --ci."""
        result = run_cli(
            "registry",
            "verify",
            str(FIXTURES_DIR / "snapshot-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0  # PASS
