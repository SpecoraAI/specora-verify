"""CLI tests for witness commands (PR-ENT-550)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "witness"


def run_cli(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Run the CLI with given arguments."""
    cmd = [sys.executable, "-m", "specora_verify"] + list(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check,
    )


class TestWitnessVerify:
    """Tests for witness verify command."""

    def test_verify_valid_statement(self):
        """Valid statement returns exit 0."""
        result = run_cli(
            "witness",
            "verify",
            str(FIXTURES_DIR / "statement-valid.json"),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout
        assert "witness-org-alpha" in result.stdout

    def test_verify_statement_json_output(self):
        """JSON output format works."""
        result = run_cli(
            "--format",
            "json",
            "witness",
            "verify",
            str(FIXTURES_DIR / "statement-valid.json"),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["valid"] is True
        assert output["witness_org_id"] == "witness-org-alpha"

    def test_verify_revoked_witness_fails(self):
        """Statement from revoked witness fails."""
        result = run_cli(
            "witness",
            "verify",
            str(FIXTURES_DIR / "statement-revoked-witness.json"),
            "--registry",
            str(FIXTURES_DIR / "registry-revoked.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 2  # FAIL
        assert "INV-ANCHOR-016" in result.stdout

    def test_verify_missing_registry(self):
        """Missing registry still validates structure."""
        result = run_cli(
            "witness",
            "verify",
            str(FIXTURES_DIR / "statement-valid.json"),
            "--dangerously-skip-signature",
        )
        # Without registry, we can only validate structure
        assert result.returncode == 0

    def test_verify_file_not_found(self):
        """Non-existent file returns error."""
        result = run_cli(
            "witness",
            "verify",
            "/nonexistent/statement.json",
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3  # ERROR
        assert "not found" in result.stderr.lower() or "not found" in result.stdout.lower()


class TestWitnessVerifyNetwork:
    """Tests for witness verify-network command."""

    def test_verify_network_quorum_met(self, tmp_path: Path):
        """Quorum met with agreeing witnesses returns exit 0 (PASS)."""
        # Create temp dir with only agreeing statements (no mismatch)
        statements_dir = tmp_path / "statements"
        statements_dir.mkdir()
        for name in ["witness-alpha.json", "witness-beta.json", "witness-gamma.json"]:
            src = FIXTURES_DIR / "statements" / name
            if src.exists():
                (statements_dir / name).write_text(src.read_text())

        result = run_cli(
            "witness",
            "verify-network",
            "--statements-dir",
            str(statements_dir),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--min-witnesses",
            "2",
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0  # PASS - all agree
        assert "Quorum Achieved:" in result.stdout
        assert "PASS" in result.stdout

    def test_verify_network_hash_mismatch_fails(self):
        """Hash mismatch returns exit 2 (FAIL) - tamper signal."""
        result = run_cli(
            "witness",
            "verify-network",
            "--statements-dir",
            str(FIXTURES_DIR / "statements"),  # Includes mismatch.json
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--min-witnesses",
            "2",
            "--dangerously-skip-signature",
        )
        # Hash mismatch is a tamper signal - FAIL regardless of quorum
        assert result.returncode == 2  # FAIL
        assert "INV-ANCHOR-014" in result.stdout
        assert "FAIL" in result.stdout

    def test_verify_network_quorum_not_met(self, tmp_path: Path):
        """Quorum not met returns exit 2 (FAIL)."""
        # Create temp dir with only agreeing statements (no mismatch)
        statements_dir = tmp_path / "statements"
        statements_dir.mkdir()
        for name in ["witness-alpha.json", "witness-beta.json"]:
            src = FIXTURES_DIR / "statements" / name
            if src.exists():
                (statements_dir / name).write_text(src.read_text())

        result = run_cli(
            "witness",
            "verify-network",
            "--statements-dir",
            str(statements_dir),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--min-witnesses",
            "10",  # Impossible quorum
            "--dangerously-skip-signature",
        )
        assert result.returncode == 2  # FAIL
        assert "INV-ANCHOR-015" in result.stdout

    def test_verify_network_json_output(self, tmp_path: Path):
        """JSON output format works."""
        # Create temp dir with only agreeing statements
        statements_dir = tmp_path / "statements"
        statements_dir.mkdir()
        for name in ["witness-alpha.json", "witness-beta.json"]:
            src = FIXTURES_DIR / "statements" / name
            if src.exists():
                (statements_dir / name).write_text(src.read_text())

        result = run_cli(
            "--format",
            "json",
            "witness",
            "verify-network",
            "--statements-dir",
            str(statements_dir),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--min-witnesses",
            "2",
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["quorum_required"] == 2
        assert output["quorum_achieved"] == 2

    def test_verify_network_emit_receipt(self, tmp_path: Path):
        """Receipt emitted when requested."""
        # Create temp dir with only agreeing statements
        statements_dir = tmp_path / "statements"
        statements_dir.mkdir()
        for name in ["witness-alpha.json", "witness-beta.json"]:
            src = FIXTURES_DIR / "statements" / name
            if src.exists():
                (statements_dir / name).write_text(src.read_text())

        receipt_path = tmp_path / "receipt.json"
        result = run_cli(
            "witness",
            "verify-network",
            "--statements-dir",
            str(statements_dir),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--min-witnesses",
            "2",
            "--dangerously-skip-signature",
            "--emit-receipt",
            str(receipt_path),
        )
        assert result.returncode == 0
        assert receipt_path.exists()

        receipt = json.loads(receipt_path.read_text())
        assert receipt["schema_version"] == "1.0.0"
        assert "result" in receipt

    def test_verify_network_empty_dir(self, tmp_path: Path):
        """Empty directory returns error."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = run_cli(
            "witness",
            "verify-network",
            "--statements-dir",
            str(empty_dir),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--min-witnesses",
            "2",
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3  # ERROR
        assert "No valid witness statements" in result.stderr or "No valid" in result.stdout


class TestWitnessRegistryInfo:
    """Tests for witness registry-info command."""

    def test_registry_info_valid(self):
        """Display registry info."""
        result = run_cli(
            "witness",
            "registry-info",
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
        )
        assert result.returncode == 0
        assert "SPECORA WITNESS REGISTRY" in result.stdout
        assert "witness-org-alpha" in result.stdout
        assert "Total Witnesses:" in result.stdout

    def test_registry_info_json_output(self):
        """JSON output format works."""
        result = run_cli(
            "--format",
            "json",
            "witness",
            "registry-info",
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["registry_version"] == 1
        assert len(output["witnesses"]) == 3

    def test_registry_info_file_not_found(self):
        """Non-existent file returns error."""
        result = run_cli(
            "witness",
            "registry-info",
            "--registry",
            "/nonexistent/registry.json",
        )
        assert result.returncode == 3  # ERROR


class TestWitnessExitCodes:
    """Tests for witness command exit codes."""

    def test_exit_code_pass(self):
        """PASS status returns exit 0."""
        result = run_cli(
            "witness",
            "verify",
            str(FIXTURES_DIR / "statement-valid.json"),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0

    def test_exit_code_fail_revoked(self):
        """FAIL status (revoked) returns exit 2."""
        result = run_cli(
            "witness",
            "verify",
            str(FIXTURES_DIR / "statement-revoked-witness.json"),
            "--registry",
            str(FIXTURES_DIR / "registry-revoked.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 2

    def test_exit_code_error_file_not_found(self):
        """ERROR status (file not found) returns exit 3."""
        result = run_cli(
            "witness",
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
            "witness",
            "verify",
            str(FIXTURES_DIR / "statement-valid.json"),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3  # ERROR
        assert "SKIP_SIGNATURE_IN_CI" in result.stderr or "cannot be used with --ci" in result.stderr

    def test_skip_signature_blocked_in_ci_mode_verify_network(self, tmp_path: Path):
        """--dangerously-skip-signature + --ci returns error for verify-network."""
        statements_dir = tmp_path / "statements"
        statements_dir.mkdir()
        for name in ["witness-alpha.json", "witness-beta.json"]:
            src = FIXTURES_DIR / "statements" / name
            if src.exists():
                (statements_dir / name).write_text(src.read_text())

        result = run_cli(
            "--ci",
            "witness",
            "verify-network",
            "--statements-dir",
            str(statements_dir),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--min-witnesses",
            "2",
            "--dangerously-skip-signature",
        )
        assert result.returncode == 3  # ERROR
        assert "SKIP_SIGNATURE_IN_CI" in result.stderr or "cannot be used with --ci" in result.stderr

    def test_skip_signature_allowed_without_ci_mode(self):
        """--dangerously-skip-signature works without --ci."""
        result = run_cli(
            "witness",
            "verify",
            str(FIXTURES_DIR / "statement-valid.json"),
            "--registry",
            str(FIXTURES_DIR / "registry-valid.json"),
            "--dangerously-skip-signature",
        )
        assert result.returncode == 0  # PASS
