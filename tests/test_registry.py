"""Unit tests for registry snapshot validation (PR-ENT-560)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from specora_verify.validators.registry import (
    ChainVerificationResult,
    GENESIS_HASH,
    RegistryKey,
    RegistrySnapshot,
    RegistryVerificationStatus,
    RegistryWitness,
    SnapshotVerificationResult,
    compute_registry_hash,
    create_registry_receipt,
    derive_registry_key_id,
    derive_witness_key_id,
    enforce_revocation_monotonicity,
    get_exit_code,
    load_registry_snapshot,
    parse_registry_snapshot,
    validate_registry_snapshot,
    verify_registry_chain,
)
from specora_verify.fetchers.registry import (
    SnapshotFetchResult,
    load_local_registry_snapshot,
    load_local_registry_chain,
    load_registry_snapshots_sorted,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "registry"
CHAIN_DIR = FIXTURES_DIR / "chain"


# =============================================================================
# Key ID Derivation Tests
# =============================================================================


class TestKeyIdDerivation:
    """Tests for key ID derivation functions."""

    def test_derive_registry_key_id_32_zero_bytes(self):
        """Zero bytes produce expected rpk- key ID."""
        key_bytes = b"\x10" * 32
        key_id = derive_registry_key_id(key_bytes)
        assert key_id.startswith("rpk-")
        assert len(key_id) == 20  # rpk- + 16 hex chars
        assert key_id == "rpk-baa501b37267c06d"

    def test_derive_witness_key_id_deterministic(self):
        """Same input produces same output."""
        key_bytes = b"\x00" * 32
        key_id_1 = derive_witness_key_id(key_bytes)
        key_id_2 = derive_witness_key_id(key_bytes)
        assert key_id_1 == key_id_2
        assert key_id_1 == "wpk-66687aadf862bd77"

    def test_derive_key_id_different_keys(self):
        """Different keys produce different IDs."""
        key1 = derive_registry_key_id(b"\x00" * 32)
        key2 = derive_registry_key_id(b"\x01" * 32)
        assert key1 != key2


# =============================================================================
# Snapshot Parsing Tests
# =============================================================================


class TestSnapshotParsing:
    """Tests for registry snapshot parsing."""

    def test_load_valid_snapshot(self):
        """Valid snapshot loads correctly."""
        snapshot = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        assert snapshot.spec_id == "witness-registry-snapshot"
        assert snapshot.schema_version == "1.0.0"
        assert snapshot.registry_version == 1
        assert snapshot.is_genesis()
        assert len(snapshot.witnesses) == 2

    def test_parse_snapshot_missing_field(self):
        """Missing required field raises error."""
        data = {"spec_id": "witness-registry-snapshot"}
        with pytest.raises(Exception) as exc_info:
            parse_registry_snapshot(data)
        assert "Missing required fields" in str(exc_info.value)

    def test_parse_snapshot_invalid_spec_id(self):
        """Invalid spec_id raises error."""
        data = json.loads((FIXTURES_DIR / "snapshot-valid.json").read_text())
        data["spec_id"] = "wrong-spec"
        with pytest.raises(Exception) as exc_info:
            parse_registry_snapshot(data)
        assert "spec_id" in str(exc_info.value)

    def test_parse_snapshot_invalid_version(self):
        """Invalid registry_version raises error."""
        data = json.loads((FIXTURES_DIR / "snapshot-valid.json").read_text())
        data["registry_version"] = 0
        with pytest.raises(Exception) as exc_info:
            parse_registry_snapshot(data)
        assert "registry_version" in str(exc_info.value)

    def test_parse_snapshot_file_not_found(self):
        """Non-existent file raises error."""
        with pytest.raises(Exception) as exc_info:
            load_registry_snapshot("/nonexistent/snapshot.json")
        assert "not found" in str(exc_info.value).lower()

    def test_snapshot_is_genesis(self):
        """Genesis snapshot correctly identified."""
        snapshot = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        assert snapshot.is_genesis()
        assert snapshot.previous_registry_hash == GENESIS_HASH

    def test_snapshot_get_witness(self):
        """Witness lookup by org_id works."""
        snapshot = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        witness = snapshot.get_witness("witness-org-alpha")
        assert witness is not None
        assert witness.org_name == "Witness Organization Alpha"

        missing = snapshot.get_witness("unknown-org")
        assert missing is None

    def test_snapshot_get_key(self):
        """Key lookup by key_id works."""
        snapshot = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        result = snapshot.get_key("wpk-66687aadf862bd77")
        assert result is not None
        witness, key = result
        assert witness.witness_org_id == "witness-org-alpha"
        assert key.status == "active"


# =============================================================================
# Hash Computation Tests (INV-REG-005)
# =============================================================================


class TestHashComputation:
    """Tests for registry hash computation."""

    def test_compute_hash_deterministic(self):
        """Same input produces same hash."""
        data = json.loads((FIXTURES_DIR / "snapshot-valid.json").read_text())
        hash1 = compute_registry_hash(data)
        hash2 = compute_registry_hash(data)
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_compute_hash_excludes_hash_and_signature(self):
        """Hash computation excludes registry_hash and registry_signature."""
        data = json.loads((FIXTURES_DIR / "snapshot-valid.json").read_text())
        hash1 = compute_registry_hash(data)

        # Changing the hash/signature fields should not change computed hash
        data["registry_hash"] = "x" * 64
        data["registry_signature"] = "different"
        hash2 = compute_registry_hash(data)
        assert hash1 == hash2

    def test_compute_hash_changes_on_content_change(self):
        """Content change produces different hash."""
        data = json.loads((FIXTURES_DIR / "snapshot-valid.json").read_text())
        hash1 = compute_registry_hash(data)

        data["registry_version"] = 999
        hash2 = compute_registry_hash(data)
        assert hash1 != hash2


# =============================================================================
# Snapshot Validation Tests (INV-REG-001, INV-REG-004, INV-REG-005)
# =============================================================================


class TestSnapshotValidation:
    """Tests for snapshot validation."""

    def test_validate_valid_snapshot_skip_signature(self):
        """Valid snapshot passes validation (skip signature)."""
        snapshot = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        result = validate_registry_snapshot(snapshot, skip_signature=True)
        assert result.valid
        assert result.hash_valid
        assert result.is_genesis

    def test_validate_tampered_snapshot_fails(self):
        """Tampered snapshot fails hash validation (INV-REG-005)."""
        data = json.loads((FIXTURES_DIR / "snapshot-tampered.json").read_text())
        result = validate_registry_snapshot(data, skip_signature=True)
        assert not result.valid
        assert not result.hash_valid
        assert any("INV-REG-005" in e for e in result.errors)

    def test_validate_key_id_mismatch_fails(self):
        """Key ID mismatch fails validation (INV-REG-004)."""
        data = json.loads((FIXTURES_DIR / "snapshot-valid.json").read_text())
        # Corrupt a key ID
        data["witnesses"][0]["keys"][0]["public_key_id"] = "wpk-0000000000000000"
        with pytest.raises(Exception) as exc_info:
            parse_registry_snapshot(data)
        assert "INV-REG-004" in str(exc_info.value)


# =============================================================================
# Revocation Monotonicity Tests (INV-REG-003)
# =============================================================================


class TestRevocationMonotonicity:
    """Tests for revocation monotonicity enforcement."""

    def test_revocation_monotonicity_valid(self):
        """Valid chain with revocation passes."""
        v2 = load_registry_snapshot(CHAIN_DIR / "snapshot-v0002.json")
        v3 = load_registry_snapshot(CHAIN_DIR / "snapshot-v0003.json")
        violations = enforce_revocation_monotonicity(v2, v3)
        assert len(violations) == 0

    def test_revocation_monotonicity_violation_witness(self):
        """Revoked witness cannot become active (INV-REG-003)."""
        v3 = load_registry_snapshot(CHAIN_DIR / "snapshot-v0003.json")
        v4_violation = load_registry_snapshot(FIXTURES_DIR / "snapshot-revocation-violation.json")
        violations = enforce_revocation_monotonicity(v3, v4_violation)
        assert len(violations) > 0
        assert any("INV-REG-003" in v for v in violations)
        assert any("witness-org-beta" in v for v in violations)

    def test_revocation_monotonicity_genesis_no_check(self):
        """Genesis snapshot has no previous to check."""
        genesis = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        violations = enforce_revocation_monotonicity(None, genesis)
        assert len(violations) == 0


# =============================================================================
# Chain Verification Tests (INV-REG-002)
# =============================================================================


class TestChainVerification:
    """Tests for registry chain verification."""

    def test_verify_valid_chain(self):
        """Valid chain passes verification."""
        snapshots = [
            load_registry_snapshot(CHAIN_DIR / "snapshot-v0001.json"),
            load_registry_snapshot(CHAIN_DIR / "snapshot-v0002.json"),
            load_registry_snapshot(CHAIN_DIR / "snapshot-v0003.json"),
        ]
        result = verify_registry_chain(snapshots, skip_signature=True)
        assert result.valid
        assert result.chain_valid
        assert result.chain_length == 3
        assert result.latest_version == 3
        assert result.status == RegistryVerificationStatus.PASS

    def test_verify_broken_chain(self):
        """Broken chain fails verification (INV-REG-002)."""
        # Load valid genesis and broken chain snapshot
        genesis = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        broken = json.loads((FIXTURES_DIR / "snapshot-broken-chain.json").read_text())

        # Need to manually create a snapshot with wrong previous hash
        broken_snapshot = parse_registry_snapshot(broken)

        result = verify_registry_chain([genesis, broken_snapshot], skip_signature=True)
        assert not result.valid
        assert not result.chain_valid
        assert result.status == RegistryVerificationStatus.FAIL
        assert any("INV-REG-002" in e for e in result.errors)

    def test_verify_chain_with_revocation_violation(self):
        """Chain with revocation violation fails (INV-REG-003)."""
        snapshots = [
            load_registry_snapshot(CHAIN_DIR / "snapshot-v0001.json"),
            load_registry_snapshot(CHAIN_DIR / "snapshot-v0002.json"),
            load_registry_snapshot(CHAIN_DIR / "snapshot-v0003.json"),
            load_registry_snapshot(FIXTURES_DIR / "snapshot-revocation-violation.json"),
        ]
        result = verify_registry_chain(snapshots, skip_signature=True)
        assert not result.valid
        assert result.status == RegistryVerificationStatus.FAIL
        assert len(result.revocation_violations) > 0
        assert any("INV-REG-003" in v for v in result.revocation_violations)

    def test_verify_empty_chain(self):
        """Empty chain returns error."""
        result = verify_registry_chain([], skip_signature=True)
        assert not result.valid
        assert result.status == RegistryVerificationStatus.ERROR
        assert "No snapshots" in result.errors[0]

    def test_verify_non_genesis_first_fails(self):
        """First snapshot must be genesis (INV-REG-002)."""
        # Use v2 as first (has non-zero previous_registry_hash)
        v2 = load_registry_snapshot(CHAIN_DIR / "snapshot-v0002.json")
        result = verify_registry_chain([v2], skip_signature=True)
        assert not result.valid
        assert any("genesis" in e.lower() for e in result.errors)


# =============================================================================
# Receipt Generation Tests
# =============================================================================


class TestReceiptGeneration:
    """Tests for verification receipt generation."""

    def test_create_receipt_snapshot(self):
        """Receipt created for snapshot verification."""
        snapshot = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        result = validate_registry_snapshot(snapshot, skip_signature=True)
        receipt = create_registry_receipt(result, verifier_version="1.0.0")

        assert receipt.schema_version == "1.0.0"
        assert receipt.verifier_version == "1.0.0"
        assert receipt.verification_timestamp  # Non-empty
        assert receipt.result is result

    def test_receipt_to_json(self):
        """Receipt serializes to JSON."""
        snapshot = load_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        result = validate_registry_snapshot(snapshot, skip_signature=True)
        receipt = create_registry_receipt(result)

        json_str = receipt.to_json()
        parsed = json.loads(json_str)
        assert parsed["schema_version"] == "1.0.0"
        assert "result" in parsed


# =============================================================================
# Exit Code Tests
# =============================================================================


class TestExitCodes:
    """Tests for exit code mapping."""

    def test_pass_exit_code_0(self):
        """PASS status returns exit 0."""
        assert get_exit_code(RegistryVerificationStatus.PASS) == 0

    def test_warn_exit_code_1(self):
        """WARN status returns exit 1."""
        assert get_exit_code(RegistryVerificationStatus.WARN) == 1

    def test_fail_exit_code_2(self):
        """FAIL status returns exit 2."""
        assert get_exit_code(RegistryVerificationStatus.FAIL) == 2

    def test_error_exit_code_3(self):
        """ERROR status returns exit 3."""
        assert get_exit_code(RegistryVerificationStatus.ERROR) == 3


# =============================================================================
# Fetcher Tests
# =============================================================================


class TestRegistryFetcher:
    """Tests for registry snapshot fetchers."""

    def test_load_local_snapshot(self):
        """Load snapshot from local file."""
        result = load_local_registry_snapshot(FIXTURES_DIR / "snapshot-valid.json")
        assert result.success
        assert result.registry_version == 1
        assert result.snapshot is not None

    def test_load_local_snapshot_not_found(self):
        """Non-existent file returns error."""
        result = load_local_registry_snapshot("/nonexistent/file.json")
        assert not result.success
        assert "not found" in result.error.lower()

    def test_load_local_chain(self):
        """Load snapshot chain from directory."""
        results = load_local_registry_chain(CHAIN_DIR)
        assert len(results) == 3
        assert all(r.success for r in results)

    def test_load_local_chain_not_found(self):
        """Non-existent directory returns error."""
        results = load_local_registry_chain("/nonexistent/dir")
        assert len(results) == 1
        assert not results[0].success

    def test_load_snapshots_sorted(self):
        """Snapshots loaded and sorted by version."""
        snapshots, errors = load_registry_snapshots_sorted(CHAIN_DIR)
        assert len(snapshots) == 3
        assert len(errors) == 0
        assert snapshots[0].registry_version == 1
        assert snapshots[1].registry_version == 2
        assert snapshots[2].registry_version == 3


# =============================================================================
# Data Class Tests
# =============================================================================


class TestDataClasses:
    """Tests for data class methods."""

    def test_registry_key_to_dict(self):
        """RegistryKey serializes correctly."""
        key = RegistryKey(
            public_key_id="wpk-abc123",
            public_key="base64key",
            status="active",
            created_at="2026-01-01T00:00:00Z",
        )
        d = key.to_dict()
        assert d["public_key_id"] == "wpk-abc123"
        assert d["status"] == "active"

    def test_registry_witness_to_dict(self):
        """RegistryWitness serializes correctly."""
        witness = RegistryWitness(
            witness_org_id="org-test",
            org_name="Test Org",
            trust_level="external",
            status="active",
            registered_at="2026-01-01T00:00:00Z",
            keys=[],
        )
        d = witness.to_dict()
        assert d["witness_org_id"] == "org-test"
        assert d["keys"] == []

    def test_snapshot_result_to_dict(self):
        """SnapshotVerificationResult serializes correctly."""
        result = SnapshotVerificationResult(
            valid=True,
            registry_version=1,
            hash_valid=True,
        )
        d = result.to_dict()
        assert d["valid"] is True
        assert d["registry_version"] == 1

    def test_chain_result_valid_property(self):
        """ChainVerificationResult.valid property works."""
        result_pass = ChainVerificationResult(status=RegistryVerificationStatus.PASS)
        assert result_pass.valid

        result_warn = ChainVerificationResult(status=RegistryVerificationStatus.WARN)
        assert result_warn.valid

        result_fail = ChainVerificationResult(status=RegistryVerificationStatus.FAIL)
        assert not result_fail.valid
