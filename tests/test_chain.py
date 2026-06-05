"""Tests for transparency chain verification (PR-ENT-520-ANCHOR-01).

Tests the offline chain verification module and CLI command.
"""

import hashlib
import json

import pytest

from specora_verify.canonical import canonical_json_bytes
from specora_verify.validators.chain import (
    CHAIN_SCHEMA_VERSION,
    GENESIS_PREVIOUS_HASH,
    ChainVerificationResult,
    load_chain_file,
    verify_chain,
    verify_chain_file,
)


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash as hex string."""
    return hashlib.sha256(data).hexdigest()


def build_canonical_payload(
    *,
    index: int,
    artifact_type: str,
    artifact_sha256: str,
    previous_entry_hash: str,
    public_key_id: str,
    created_at: str,
) -> dict:
    """Build canonical payload for entry hash computation."""
    return {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "index": int(index),
        "artifact_type": artifact_type,
        "artifact_sha256": artifact_sha256,
        "previous_entry_hash": previous_entry_hash,
        "public_key_id": public_key_id,
        "created_at": created_at,
    }


def compute_entry_hash(entry: dict) -> str:
    """Compute entry hash from entry dict."""
    payload = build_canonical_payload(
        index=entry["index"],
        artifact_type=entry["artifact_type"],
        artifact_sha256=entry["artifact_sha256"],
        previous_entry_hash=entry["previous_entry_hash"],
        public_key_id=entry["public_key_id"],
        created_at=entry["created_at"],
    )
    return compute_sha256(canonical_json_bytes(payload))


def build_valid_chain(count: int = 3) -> list[dict]:
    """Build a valid chain with `count` entries."""
    entries = []
    previous_hash = GENESIS_PREVIOUS_HASH

    for i in range(count):
        entry = {
            "index": i,
            "artifact_type": ["attestation", "bundle", "erk", "scorecard"][i % 4],
            "artifact_sha256": chr(ord("a") + i) * 64,
            "previous_entry_hash": previous_hash,
            "public_key_id": "spk-test12345678",
            "created_at": f"2026-03-01T12:{i:02d}:00Z",
            "signature_b64": "c2lnbmF0dXJl",  # Placeholder
        }
        entry["entry_hash"] = compute_entry_hash(entry)
        entries.append(entry)
        previous_hash = entry["entry_hash"]

    return entries


class TestGenesisMarker:
    """Tests for genesis entry marker (INV-ANCHOR-005)."""

    def test_genesis_previous_hash_constant(self):
        """Genesis marker is 64 zeros."""
        assert GENESIS_PREVIOUS_HASH == "0" * 64
        assert len(GENESIS_PREVIOUS_HASH) == 64


class TestChainVerification:
    """Tests for verify_chain function."""

    def test_empty_chain(self):
        """Empty chain is valid but noted."""
        result = verify_chain([])

        assert result.valid is True
        assert result.total_entries == 0
        assert "empty" in result.errors[0].lower()

    def test_valid_single_entry(self):
        """Single genesis entry is valid."""
        entries = build_valid_chain(1)
        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is True
        assert result.total_entries == 1
        assert result.verified_count == 1

    def test_valid_multi_entry_chain(self):
        """Multi-entry chain with correct linking is valid."""
        entries = build_valid_chain(5)
        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is True
        assert result.total_entries == 5
        assert result.verified_count == 5
        assert result.start_index == 0
        assert result.end_index == 4

    def test_invalid_genesis_previous_hash(self):
        """Genesis entry with wrong previous_hash fails."""
        entries = build_valid_chain(1)
        entries[0]["previous_entry_hash"] = "f" * 64  # Wrong!
        entries[0]["entry_hash"] = compute_entry_hash(entries[0])

        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is False
        assert any("genesis" in e.lower() for e in result.errors)

    def test_broken_chain_link(self):
        """Entry with wrong previous_entry_hash fails."""
        entries = build_valid_chain(3)
        # Break the link between entry 1 and 2
        entries[2]["previous_entry_hash"] = "f" * 64  # Wrong!
        entries[2]["entry_hash"] = compute_entry_hash(entries[2])

        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is False
        assert any("previous_entry_hash mismatch" in e for e in result.errors)

    def test_tampered_entry_hash(self):
        """Entry with tampered entry_hash fails."""
        entries = build_valid_chain(3)
        # Tamper with entry 1's hash without updating the chain
        entries[1]["entry_hash"] = "f" * 64  # Tampered!

        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is False
        assert any("entry_hash mismatch" in e for e in result.errors)

    def test_index_gap_detection(self):
        """Missing index in sequence fails."""
        entries = build_valid_chain(3)
        # Remove entry at index 1 (create gap)
        entries = [entries[0], entries[2]]

        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is False
        assert any("expected index" in e.lower() for e in result.errors)

    def test_out_of_order_entries_sorted(self):
        """Out-of-order entries are sorted before verification."""
        entries = build_valid_chain(3)
        # Shuffle entries
        shuffled = [entries[2], entries[0], entries[1]]

        result = verify_chain(shuffled, verify_signatures=False)

        assert result.valid is True

    def test_missing_required_field(self):
        """Entry missing required field fails."""
        entries = build_valid_chain(1)
        del entries[0]["artifact_type"]

        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is False
        assert any("missing required field" in e for e in result.errors)

    def test_invalid_hash_length(self):
        """Entry with invalid hash length fails."""
        entries = build_valid_chain(1)
        entries[0]["entry_hash"] = "abc"  # Too short

        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is False
        assert any("64 hex chars" in e for e in result.errors)

    def test_invalid_artifact_type(self):
        """Entry with invalid artifact_type fails."""
        entries = build_valid_chain(1)
        entries[0]["artifact_type"] = "invalid"
        entries[0]["entry_hash"] = compute_entry_hash(entries[0])

        result = verify_chain(entries, verify_signatures=False)

        assert result.valid is False
        assert any("invalid artifact_type" in e for e in result.errors)


class TestChainFileLoading:
    """Tests for load_chain_file function."""

    def test_load_json_array(self, tmp_path):
        """Load chain from JSON array file."""
        entries = build_valid_chain(3)
        file_path = tmp_path / "chain.json"
        file_path.write_text(json.dumps(entries))

        loaded = load_chain_file(file_path)

        assert len(loaded) == 3
        assert loaded[0]["index"] == 0

    def test_load_ndjson(self, tmp_path):
        """Load chain from NDJSON file."""
        entries = build_valid_chain(3)
        file_path = tmp_path / "chain.ndjson"
        file_path.write_text("\n".join(json.dumps(e) for e in entries))

        loaded = load_chain_file(file_path)

        assert len(loaded) == 3
        assert loaded[0]["index"] == 0

    def test_file_not_found(self, tmp_path):
        """Missing file raises VerificationError."""
        from specora_verify.errors import VerificationError

        with pytest.raises(VerificationError) as exc_info:
            load_chain_file(tmp_path / "nonexistent.json")

        assert "not found" in str(exc_info.value).lower()

    def test_invalid_json(self, tmp_path):
        """Invalid JSON raises VerificationError."""
        from specora_verify.errors import VerificationError

        file_path = tmp_path / "invalid.json"
        file_path.write_text("{not valid json}")

        with pytest.raises(VerificationError) as exc_info:
            load_chain_file(file_path)

        assert "parse" in str(exc_info.value).lower()


class TestVerifyChainFile:
    """Tests for verify_chain_file function."""

    def test_verify_valid_chain_file(self, tmp_path):
        """Verify valid chain file succeeds."""
        entries = build_valid_chain(3)
        file_path = tmp_path / "chain.json"
        file_path.write_text(json.dumps(entries))

        result = verify_chain_file(file_path, verify_signatures=False)

        assert result.valid is True
        assert result.total_entries == 3

    def test_verify_invalid_chain_file(self, tmp_path):
        """Verify invalid chain file fails."""
        entries = build_valid_chain(3)
        entries[1]["entry_hash"] = "f" * 64  # Tampered
        file_path = tmp_path / "chain.json"
        file_path.write_text(json.dumps(entries))

        result = verify_chain_file(file_path, verify_signatures=False)

        assert result.valid is False

    def test_verify_missing_file(self, tmp_path):
        """Verify missing file returns error result."""
        result = verify_chain_file(tmp_path / "nonexistent.json")

        assert result.valid is False
        assert any("not found" in e.lower() for e in result.errors)


class TestChainVerificationResult:
    """Tests for ChainVerificationResult data class."""

    def test_to_dict(self):
        """Result to_dict includes all fields."""
        result = ChainVerificationResult(
            valid=True,
            total_entries=3,
            verified_count=3,
            start_index=0,
            end_index=2,
            first_entry_hash="a" * 64,
            last_entry_hash="b" * 64,
            errors=[],
        )

        data = result.to_dict()

        assert data["valid"] is True
        assert data["total_entries"] == 3
        assert data["verified_count"] == 3
        assert data["start_index"] == 0
        assert data["end_index"] == 2
        assert data["first_entry_hash"] == "a" * 64
        assert data["last_entry_hash"] == "b" * 64

    def test_to_dict_with_errors(self):
        """Result with errors includes error list."""
        result = ChainVerificationResult(
            valid=False,
            total_entries=3,
            verified_count=1,
            errors=["Error 1", "Error 2"],
        )

        data = result.to_dict()

        assert data["valid"] is False
        assert len(data["errors"]) == 2


class TestCLIIntegration:
    """Integration tests for verify-log CLI command."""

    def test_cli_verify_valid_chain(self, tmp_path):
        """CLI verify-log with valid chain returns PASS."""
        import argparse

        from specora_verify.cli import cmd_verify_log

        entries = build_valid_chain(3)
        file_path = tmp_path / "chain.json"
        file_path.write_text(json.dumps(entries))

        args = argparse.Namespace(
            log=file_path,
            public_key=None,
            skip_signatures=True,
            format="text",
        )

        exit_code = cmd_verify_log(args)

        assert exit_code == 0  # EXIT_PASS

    def test_cli_verify_invalid_chain(self, tmp_path):
        """CLI verify-log with invalid chain returns FAIL."""
        import argparse

        from specora_verify.cli import cmd_verify_log

        entries = build_valid_chain(3)
        entries[1]["entry_hash"] = "f" * 64  # Tampered
        file_path = tmp_path / "chain.json"
        file_path.write_text(json.dumps(entries))

        args = argparse.Namespace(
            log=file_path,
            public_key=None,
            skip_signatures=True,
            format="text",
        )

        exit_code = cmd_verify_log(args)

        assert exit_code == 2  # EXIT_FAIL

    def test_cli_verify_missing_file(self, tmp_path):
        """CLI verify-log with missing file returns ERROR."""
        import argparse

        from specora_verify.cli import cmd_verify_log

        args = argparse.Namespace(
            log=tmp_path / "nonexistent.json",
            public_key=None,
            skip_signatures=True,
            format="text",
        )

        exit_code = cmd_verify_log(args)

        assert exit_code == 3  # EXIT_ERROR


class TestOutputFormatting:
    """Tests for chain result output formatting."""

    def test_format_chain_result_text(self):
        """Text format includes key information."""
        from specora_verify.output import format_chain_result

        result = ChainVerificationResult(
            valid=True,
            total_entries=3,
            verified_count=3,
            start_index=0,
            end_index=2,
            first_entry_hash="a" * 64,
            last_entry_hash="b" * 64,
        )

        output = format_chain_result(result, output_format="text", file_path="chain.json")

        assert "TRANSPARENCY CHAIN" in output
        assert "chain.json" in output
        assert "Total Entries:" in output
        assert "PASS" in output

    def test_format_chain_result_json(self):
        """JSON format is valid JSON with all fields."""
        from specora_verify.output import format_chain_result

        result = ChainVerificationResult(
            valid=True,
            total_entries=3,
            verified_count=3,
            start_index=0,
            end_index=2,
        )

        output = format_chain_result(result, output_format="json", file_path="chain.json")
        data = json.loads(output)

        assert data["valid"] is True
        assert data["total_entries"] == 3
        assert data["file"] == "chain.json"

    def test_format_chain_result_with_errors(self):
        """Error output includes error messages."""
        from specora_verify.output import format_chain_result

        result = ChainVerificationResult(
            valid=False,
            total_entries=3,
            verified_count=1,
            errors=["Entry 1: hash mismatch", "Entry 2: link broken"],
        )

        output = format_chain_result(result, output_format="text", file_path="chain.json")

        assert "FAIL" in output
        assert "Errors:" in output
        assert "hash mismatch" in output
