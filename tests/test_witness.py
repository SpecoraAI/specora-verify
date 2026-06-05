"""Tests for witness statement validation (PR-ENT-550)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from specora_verify.errors import VerificationError
from specora_verify.fetchers.witness import (
    load_local_witness_statement,
    load_local_witness_statements_dir,
)
from specora_verify.validators.witness import (
    WitnessEntry,
    WitnessQuorumResult,
    WitnessRegistry,
    WitnessStatementResult,
    WitnessStatus,
    WitnessVerificationStatus,
    create_witness_receipt,
    derive_witness_key_id,
    load_witness_registry,
    parse_witness_registry,
    validate_witness_statement,
    verify_witness_quorum,
    witness_status_to_exit_code,
)

# =============================================================================
# Fixtures
# =============================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "witness"


@pytest.fixture
def valid_registry() -> WitnessRegistry:
    """Load valid witness registry fixture."""
    return load_witness_registry(FIXTURES_DIR / "registry-valid.json")


@pytest.fixture
def revoked_registry() -> WitnessRegistry:
    """Load registry with revoked witness."""
    return load_witness_registry(FIXTURES_DIR / "registry-revoked.json")


@pytest.fixture
def valid_statement() -> dict:
    """Load valid witness statement fixture."""
    path = FIXTURES_DIR / "statement-valid.json"
    return json.loads(path.read_text())


@pytest.fixture
def revoked_statement() -> dict:
    """Load statement from revoked witness."""
    path = FIXTURES_DIR / "statement-revoked-witness.json"
    return json.loads(path.read_text())


# =============================================================================
# Key ID Derivation Tests
# =============================================================================


class TestKeyIdDerivation:
    """Tests for witness key ID derivation."""

    def test_derive_key_id_32_zero_bytes(self):
        """Key ID derived from 32 zero bytes."""
        key_bytes = b"\x00" * 32
        key_id = derive_witness_key_id(key_bytes)
        assert key_id == "wpk-66687aadf862bd77"
        assert key_id.startswith("wpk-")
        assert len(key_id) == 20  # wpk- + 16 hex chars

    def test_derive_key_id_deterministic(self):
        """Key ID derivation is deterministic."""
        key_bytes = b"\x01" * 32
        key_id_1 = derive_witness_key_id(key_bytes)
        key_id_2 = derive_witness_key_id(key_bytes)
        assert key_id_1 == key_id_2

    def test_derive_key_id_different_keys(self):
        """Different keys produce different IDs."""
        key_id_1 = derive_witness_key_id(b"\x00" * 32)
        key_id_2 = derive_witness_key_id(b"\x01" * 32)
        assert key_id_1 != key_id_2


# =============================================================================
# Registry Loading Tests
# =============================================================================


class TestRegistryLoading:
    """Tests for witness registry loading and parsing."""

    def test_load_valid_registry(self, valid_registry: WitnessRegistry):
        """Load valid registry file."""
        assert valid_registry.registry_version == 1
        assert valid_registry.registry_authority == "Specora Witness Authority"
        assert len(valid_registry.witnesses) == 3

    def test_registry_lookup_by_org_id(self, valid_registry: WitnessRegistry):
        """Look up witness by organization ID."""
        entry = valid_registry.lookup(witness_org_id="witness-org-alpha")
        assert entry is not None
        assert entry.witness_org_id == "witness-org-alpha"
        assert entry.status == WitnessStatus.ACTIVE

    def test_registry_lookup_by_key_id(self, valid_registry: WitnessRegistry):
        """Look up witness by public key ID."""
        entry = valid_registry.lookup(public_key_id="wpk-66687aadf862bd77")
        assert entry is not None
        assert entry.witness_org_id == "witness-org-alpha"

    def test_registry_lookup_not_found(self, valid_registry: WitnessRegistry):
        """Lookup returns None for unknown witness."""
        entry = valid_registry.lookup(witness_org_id="unknown-org")
        assert entry is None

    def test_registry_get_active_witnesses(self, valid_registry: WitnessRegistry):
        """Get all active witnesses."""
        active = valid_registry.get_active_witnesses()
        assert len(active) == 3
        assert all(w.status == WitnessStatus.ACTIVE for w in active)

    def test_registry_file_not_found(self):
        """Load non-existent registry raises error."""
        with pytest.raises(VerificationError) as exc_info:
            load_witness_registry("/nonexistent/registry.json")
        assert "not found" in str(exc_info.value)

    def test_registry_invalid_json(self, tmp_path: Path):
        """Load invalid JSON raises error."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json")
        with pytest.raises(VerificationError) as exc_info:
            load_witness_registry(bad_file)
        assert "parse" in str(exc_info.value).lower()


class TestRegistrySchemaValidation:
    """Tests for registry schema validation."""

    def test_missing_registry_version(self):
        """Missing registry_version raises error."""
        data = {
            "generated_at": "2026-03-01T00:00:00Z",
            "registry_authority": "Test",
            "witnesses": [],
        }
        with pytest.raises(VerificationError) as exc_info:
            parse_witness_registry(data)
        assert "registry_version" in str(exc_info.value)

    def test_missing_generated_at(self):
        """Missing generated_at raises error."""
        data = {
            "registry_version": 1,
            "registry_authority": "Test",
            "witnesses": [],
        }
        with pytest.raises(VerificationError) as exc_info:
            parse_witness_registry(data)
        assert "generated_at" in str(exc_info.value)

    def test_invalid_timestamp_format(self):
        """Invalid timestamp format raises error."""
        data = {
            "registry_version": 1,
            "generated_at": "2026-03-01",  # Missing time
            "registry_authority": "Test",
            "witnesses": [],
        }
        with pytest.raises(VerificationError) as exc_info:
            parse_witness_registry(data)
        assert "generated_at" in str(exc_info.value)

    def test_duplicate_org_id(self):
        """Duplicate witness_org_id raises error."""
        data = {
            "registry_version": 1,
            "generated_at": "2026-03-01T00:00:00Z",
            "registry_authority": "Test",
            "witnesses": [
                {
                    "witness_org_id": "duplicate-org",
                    "org_name": "First",
                    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "public_key_id": "wpk-66687aadf862bd77",
                    "trust_level": "external",
                    "status": "active",
                    "registered_at": "2026-02-01T00:00:00Z",
                },
                {
                    "witness_org_id": "duplicate-org",
                    "org_name": "Second",
                    "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                    "public_key_id": "wpk-72cd6e8422c407fb",
                    "trust_level": "external",
                    "status": "active",
                    "registered_at": "2026-02-01T00:00:00Z",
                },
            ],
        }
        with pytest.raises(VerificationError) as exc_info:
            parse_witness_registry(data)
        assert "duplicate" in str(exc_info.value).lower()

    def test_key_id_mismatch(self):
        """Key ID not matching derived value raises error."""
        data = {
            "registry_version": 1,
            "generated_at": "2026-03-01T00:00:00Z",
            "registry_authority": "Test",
            "witnesses": [
                {
                    "witness_org_id": "test-org",
                    "org_name": "Test",
                    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "public_key_id": "wpk-0000000000000000",  # Wrong!
                    "trust_level": "external",
                    "status": "active",
                    "registered_at": "2026-02-01T00:00:00Z",
                },
            ],
        }
        with pytest.raises(VerificationError) as exc_info:
            parse_witness_registry(data)
        assert "mismatch" in str(exc_info.value).lower()

    def test_invalid_status(self):
        """Invalid witness status raises error."""
        data = {
            "registry_version": 1,
            "generated_at": "2026-03-01T00:00:00Z",
            "registry_authority": "Test",
            "witnesses": [
                {
                    "witness_org_id": "test-org",
                    "org_name": "Test",
                    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "public_key_id": "wpk-66687aadf862bd77",
                    "trust_level": "external",
                    "status": "invalid_status",
                    "registered_at": "2026-02-01T00:00:00Z",
                },
            ],
        }
        with pytest.raises(VerificationError) as exc_info:
            parse_witness_registry(data)
        assert "status" in str(exc_info.value).lower()


# =============================================================================
# Statement Validation Tests
# =============================================================================


class TestStatementValidation:
    """Tests for witness statement validation."""

    def test_validate_statement_valid_structure(
        self, valid_statement: dict, valid_registry: WitnessRegistry
    ):
        """Valid statement passes structural validation."""
        result = validate_witness_statement(
            valid_statement,
            registry=valid_registry,
            skip_signature=True,
        )
        assert result.valid
        assert result.witness_org_id == "witness-org-alpha"
        assert result.anchor_hash == valid_statement["anchor_hash"]
        assert result.anchor_index == 1842
        assert len(result.errors) == 0

    def test_validate_statement_missing_fields(self, valid_registry: WitnessRegistry):
        """Missing required fields detected."""
        statement = {
            "spec_id": "witness-statement",
            "schema_version": "1.0.0",
            # Missing most fields
        }
        result = validate_witness_statement(
            statement,
            registry=valid_registry,
            skip_signature=True,
        )
        assert not result.valid
        assert len(result.errors) > 0
        assert "Missing required fields" in result.errors[0]

    def test_validate_statement_invalid_spec_id(
        self, valid_statement: dict, valid_registry: WitnessRegistry
    ):
        """Invalid spec_id detected."""
        statement = {**valid_statement, "spec_id": "wrong-spec"}
        result = validate_witness_statement(
            statement,
            registry=valid_registry,
            skip_signature=True,
        )
        assert not result.valid
        assert any("spec_id" in e for e in result.errors)

    def test_validate_statement_invalid_anchor_hash(
        self, valid_statement: dict, valid_registry: WitnessRegistry
    ):
        """Invalid anchor_hash format detected."""
        statement = {**valid_statement, "anchor_hash": "not-a-valid-hash"}
        result = validate_witness_statement(
            statement,
            registry=valid_registry,
            skip_signature=True,
        )
        assert not result.valid
        assert any("anchor_hash" in e for e in result.errors)

    def test_validate_statement_invalid_timestamp(
        self, valid_statement: dict, valid_registry: WitnessRegistry
    ):
        """Invalid timestamp format detected."""
        statement = {**valid_statement, "timestamp": "invalid-timestamp"}
        result = validate_witness_statement(
            statement,
            registry=valid_registry,
            skip_signature=True,
        )
        assert not result.valid
        assert any("timestamp" in e for e in result.errors)

    def test_validate_statement_invalid_key_id_format(
        self, valid_statement: dict, valid_registry: WitnessRegistry
    ):
        """Invalid key ID format detected."""
        statement = {**valid_statement, "witness_public_key_id": "bad-key-id"}
        result = validate_witness_statement(
            statement,
            registry=valid_registry,
            skip_signature=True,
        )
        assert not result.valid
        assert any("witness_public_key_id" in e for e in result.errors)


class TestStatementAnchorHashMatching:
    """Tests for anchor hash matching (INV-ANCHOR-014)."""

    def test_anchor_hash_matches_expected(
        self, valid_statement: dict, valid_registry: WitnessRegistry
    ):
        """Matching anchor hash passes."""
        expected_hash = valid_statement["anchor_hash"]
        result = validate_witness_statement(
            valid_statement,
            registry=valid_registry,
            expected_anchor_hash=expected_hash,
            skip_signature=True,
        )
        assert result.valid
        assert len(result.errors) == 0

    def test_anchor_hash_mismatch_detected(
        self, valid_statement: dict, valid_registry: WitnessRegistry
    ):
        """Mismatched anchor hash fails (INV-ANCHOR-014)."""
        expected_hash = "a" * 64  # Different from statement
        result = validate_witness_statement(
            valid_statement,
            registry=valid_registry,
            expected_anchor_hash=expected_hash,
            skip_signature=True,
        )
        assert not result.valid
        assert any("INV-ANCHOR-014" in e for e in result.errors)


class TestStatementRevokedWitness:
    """Tests for revoked witness handling (INV-ANCHOR-016)."""

    def test_revoked_witness_fails(
        self, revoked_statement: dict, revoked_registry: WitnessRegistry
    ):
        """Statement from revoked witness fails (INV-ANCHOR-016)."""
        result = validate_witness_statement(
            revoked_statement,
            registry=revoked_registry,
            skip_signature=True,
        )
        assert not result.valid
        assert any("INV-ANCHOR-016" in e for e in result.errors)
        assert result.witness_status == WitnessStatus.REVOKED

    def test_witness_not_in_registry(self, valid_statement: dict, valid_registry: WitnessRegistry):
        """Statement from unknown witness fails."""
        statement = {
            **valid_statement,
            "witness_org_id": "unknown-org",
            "witness_public_key_id": "wpk-0000000000000000",
        }
        result = validate_witness_statement(
            statement,
            registry=valid_registry,
            skip_signature=True,
        )
        assert not result.valid
        assert any("not found" in e.lower() for e in result.errors)


# =============================================================================
# Quorum Verification Tests
# =============================================================================


class TestQuorumVerification:
    """Tests for witness quorum verification."""

    def test_quorum_all_agree_pass(self, valid_registry: WitnessRegistry):
        """All witnesses agree - PASS."""
        statements = []
        for path in sorted((FIXTURES_DIR / "statements").glob("witness-*.json")):
            if "mismatch" not in path.name:
                statements.append(json.loads(path.read_text()))

        result = verify_witness_quorum(
            statements=statements,
            registry=valid_registry,
            quorum_required=2,
            skip_signature=True,
        )
        assert result.valid
        assert result.status == WitnessVerificationStatus.PASS
        assert result.quorum_achieved >= 2
        assert not result.hash_mismatch_detected

    def test_quorum_partial_agree_pass(self, valid_registry: WitnessRegistry):
        """Quorum met with some invalid - PASS."""
        # Use only alpha and beta (both valid)
        statements = [
            json.loads((FIXTURES_DIR / "statements" / "witness-alpha.json").read_text()),
            json.loads((FIXTURES_DIR / "statements" / "witness-beta.json").read_text()),
        ]
        result = verify_witness_quorum(
            statements=statements,
            registry=valid_registry,
            quorum_required=2,
            skip_signature=True,
        )
        assert result.valid
        assert result.quorum_achieved == 2

    def test_quorum_not_met_fail(self, valid_registry: WitnessRegistry):
        """Quorum not met - FAIL (INV-ANCHOR-015)."""
        # Only one statement
        statements = [
            json.loads((FIXTURES_DIR / "statements" / "witness-alpha.json").read_text()),
        ]
        result = verify_witness_quorum(
            statements=statements,
            registry=valid_registry,
            quorum_required=2,
            skip_signature=True,
        )
        assert not result.valid
        assert result.status == WitnessVerificationStatus.FAIL
        assert any("INV-ANCHOR-015" in e for e in result.errors)

    def test_quorum_hash_mismatch_detected(self, valid_registry: WitnessRegistry):
        """Hash mismatch detected across witnesses - FAIL (tamper signal)."""
        # Include mismatched statement
        statements = [
            json.loads((FIXTURES_DIR / "statements" / "witness-alpha.json").read_text()),
            json.loads((FIXTURES_DIR / "statements" / "witness-beta.json").read_text()),
            json.loads((FIXTURES_DIR / "statements" / "witness-mismatch.json").read_text()),
        ]
        result = verify_witness_quorum(
            statements=statements,
            registry=valid_registry,
            quorum_required=2,
            skip_signature=True,
        )
        # Hash mismatch is a tamper signal - FAIL regardless of quorum
        assert not result.valid
        assert result.status == WitnessVerificationStatus.FAIL
        assert result.hash_mismatch_detected
        assert len(result.mismatched_witnesses) > 0
        assert any("INV-ANCHOR-014" in e for e in result.errors)

    def test_quorum_empty_statements_error(self, valid_registry: WitnessRegistry):
        """Empty statements list - ERROR."""
        result = verify_witness_quorum(
            statements=[],
            registry=valid_registry,
            quorum_required=2,
            skip_signature=True,
        )
        assert not result.valid
        assert result.status == WitnessVerificationStatus.ERROR
        assert any("No witness statements" in e for e in result.errors)

    def test_quorum_same_org_duplicates_not_inflate(self, valid_registry: WitnessRegistry):
        """Duplicate statements from same org don't inflate quorum."""
        # Load alpha statement multiple times
        alpha_statement = json.loads(
            (FIXTURES_DIR / "statements" / "witness-alpha.json").read_text()
        )
        # Submit 3 copies of the same org's statement
        statements = [alpha_statement, alpha_statement, alpha_statement]

        result = verify_witness_quorum(
            statements=statements,
            registry=valid_registry,
            quorum_required=2,  # Require 2 distinct orgs
            skip_signature=True,
        )
        # Should FAIL because only 1 distinct org, not 3
        assert not result.valid
        assert result.status == WitnessVerificationStatus.FAIL
        assert result.quorum_achieved == 1  # Only 1 distinct org
        assert any("INV-ANCHOR-015" in e for e in result.errors)

    def test_quorum_requires_distinct_orgs(self, valid_registry: WitnessRegistry):
        """Quorum counts distinct organizations, not statement count."""
        # Load alpha and beta statements
        alpha_statement = json.loads(
            (FIXTURES_DIR / "statements" / "witness-alpha.json").read_text()
        )
        beta_statement = json.loads((FIXTURES_DIR / "statements" / "witness-beta.json").read_text())
        # Submit alpha twice and beta once = 3 statements, but 2 distinct orgs
        statements = [alpha_statement, alpha_statement, beta_statement]

        result = verify_witness_quorum(
            statements=statements,
            registry=valid_registry,
            quorum_required=2,
            skip_signature=True,
        )
        # Should PASS because 2 distinct orgs meet quorum
        assert result.valid
        assert result.quorum_achieved == 2  # 2 distinct orgs
        assert result.witnesses_checked == 2  # Deduped to 2


# =============================================================================
# Receipt Generation Tests
# =============================================================================


class TestReceiptGeneration:
    """Tests for witness verification receipt generation."""

    def test_create_receipt(self, valid_registry: WitnessRegistry):
        """Create verification receipt."""
        statements = [
            json.loads((FIXTURES_DIR / "statements" / "witness-alpha.json").read_text()),
            json.loads((FIXTURES_DIR / "statements" / "witness-beta.json").read_text()),
        ]
        quorum_result = verify_witness_quorum(
            statements=statements,
            registry=valid_registry,
            quorum_required=2,
            skip_signature=True,
        )
        receipt = create_witness_receipt(
            result=quorum_result,
            registry=valid_registry,
            verifier_version="1.0.0",
        )
        assert receipt.schema_version == "1.0.0"
        assert receipt.verifier_version == "1.0.0"
        assert receipt.verification_timestamp is not None
        assert receipt.witness_result is not None
        assert receipt.registry_fingerprint is not None

    def test_receipt_to_json(self, valid_registry: WitnessRegistry):
        """Receipt converts to JSON."""
        statements = [
            json.loads((FIXTURES_DIR / "statements" / "witness-alpha.json").read_text()),
        ]
        quorum_result = verify_witness_quorum(
            statements=statements,
            registry=valid_registry,
            quorum_required=1,
            skip_signature=True,
        )
        receipt = create_witness_receipt(
            result=quorum_result,
            registry=valid_registry,
        )
        json_str = receipt.to_json()
        parsed = json.loads(json_str)
        assert parsed["schema_version"] == "1.0.0"
        assert "result" in parsed


# =============================================================================
# Exit Code Mapping Tests
# =============================================================================


class TestExitCodeMapping:
    """Tests for exit code mapping."""

    def test_pass_exit_code_0(self):
        """PASS maps to exit code 0."""
        assert witness_status_to_exit_code(WitnessVerificationStatus.PASS) == 0

    def test_warn_exit_code_1(self):
        """WARN maps to exit code 1."""
        assert witness_status_to_exit_code(WitnessVerificationStatus.WARN) == 1

    def test_fail_exit_code_2(self):
        """FAIL maps to exit code 2."""
        assert witness_status_to_exit_code(WitnessVerificationStatus.FAIL) == 2

    def test_error_exit_code_3(self):
        """ERROR maps to exit code 3."""
        assert witness_status_to_exit_code(WitnessVerificationStatus.ERROR) == 3


# =============================================================================
# Fetcher Tests
# =============================================================================


class TestWitnessFetcher:
    """Tests for witness statement fetcher."""

    def test_load_local_statement(self):
        """Load statement from local file."""
        result = load_local_witness_statement(FIXTURES_DIR / "statement-valid.json")
        assert result.success
        assert result.statement is not None
        assert result.witness_org_id == "witness-org-alpha"
        assert result.fetch_latency_ms >= 0

    def test_load_local_statement_not_found(self, tmp_path: Path):
        """Load non-existent file returns error."""
        result = load_local_witness_statement(tmp_path / "nonexistent.json")
        assert not result.success
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_load_local_statements_dir(self):
        """Load all statements from directory."""
        results = load_local_witness_statements_dir(FIXTURES_DIR / "statements")
        assert len(results) >= 3
        assert all(r.success for r in results if "mismatch" not in str(r.source_path))

    def test_load_local_statements_dir_not_found(self, tmp_path: Path):
        """Load from non-existent directory returns error."""
        results = load_local_witness_statements_dir(tmp_path / "nonexistent")
        assert len(results) == 1
        assert not results[0].success
        assert "not found" in results[0].error.lower()


# =============================================================================
# Data Class Tests
# =============================================================================


class TestDataClasses:
    """Tests for dataclass methods."""

    def test_witness_entry_to_dict(self):
        """WitnessEntry converts to dict."""
        entry = WitnessEntry(
            witness_org_id="test-org",
            org_name="Test Org",
            public_key="base64key",
            public_key_id="wpk-0123456789abcdef",
            trust_level="external",
            status=WitnessStatus.ACTIVE,
            registered_at="2026-01-01T00:00:00Z",
        )
        d = entry.to_dict()
        assert d["witness_org_id"] == "test-org"
        assert d["status"] == "active"

    def test_witness_registry_to_dict(self, valid_registry: WitnessRegistry):
        """WitnessRegistry converts to dict."""
        d = valid_registry.to_dict()
        assert d["registry_version"] == 1
        assert len(d["witnesses"]) == 3

    def test_statement_result_to_dict(self):
        """WitnessStatementResult converts to dict."""
        result = WitnessStatementResult(
            valid=True,
            witness_org_id="test-org",
            verification_result="pass",
            anchor_hash="a" * 64,
            anchor_index=42,
            signature_valid=True,
            witness_status=WitnessStatus.ACTIVE,
        )
        d = result.to_dict()
        assert d["valid"]
        assert d["witness_status"] == "active"

    def test_quorum_result_valid_property(self):
        """WitnessQuorumResult.valid property works."""
        pass_result = WitnessQuorumResult(
            status=WitnessVerificationStatus.PASS,
            quorum_required=2,
            quorum_achieved=2,
            witnesses_checked=2,
            witnesses_valid=2,
        )
        assert pass_result.valid

        warn_result = WitnessQuorumResult(
            status=WitnessVerificationStatus.WARN,
            quorum_required=2,
            quorum_achieved=2,
            witnesses_checked=3,
            witnesses_valid=2,
        )
        assert warn_result.valid

        fail_result = WitnessQuorumResult(
            status=WitnessVerificationStatus.FAIL,
            quorum_required=2,
            quorum_achieved=1,
            witnesses_checked=2,
            witnesses_valid=1,
        )
        assert not fail_result.valid
