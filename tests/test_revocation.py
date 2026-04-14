"""Tests for offline key revocation list support.

These tests verify:
1. Revocation list parsing and validation
2. Key trust checking for active/retired/revoked/unknown keys
3. Behavior with --require-trusted-key flag
4. Malformed revocation list handling
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from specora_verify.errors import VerificationError
from specora_verify.revocation import (
    KEY_STATUS_ACTIVE,
    KEY_STATUS_RETIRED,
    KEY_STATUS_REVOKED,
    KEY_STATUS_UNKNOWN,
    KeyEntry,
    RevocationList,
    check_key_trust,
    load_revocation_list,
    parse_revocation_list,
)


@pytest.fixture
def sample_revocation_list_data() -> dict:
    """Sample valid revocation list data."""
    return {
        "version": 1,
        "generated_at": "2026-03-01T00:00:00Z",
        "authority": "Specora Key Authority",
        "keys": [
            {
                "derived_key_id": "spk-e1c8139bffc31826",
                "fingerprint_sha256": "e1c8139bffc31826d0bad3384200ed2be209b29cced8af4221368019e59a3ae0",
                "status": "active",
                "status_reason": "current production key",
                "effective_at": "2026-01-01T00:00:00Z",
            },
            {
                "derived_key_id": "spk-a1b2c3d4e5f6a7b8",
                "fingerprint_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "status": "retired",
                "status_reason": "rotation",
                "effective_at": "2025-12-01T00:00:00Z",
            },
            {
                "derived_key_id": "spk-deadbeef12345678",
                "fingerprint_sha256": "deadbeef12345678abcdef0123456789abcdef0123456789abcdef0123456789",
                "status": "revoked",
                "status_reason": "compromise",
                "effective_at": "2025-11-15T00:00:00Z",
            },
        ],
    }


@pytest.fixture
def revocation_list(sample_revocation_list_data: dict) -> RevocationList:
    """Parsed revocation list."""
    return parse_revocation_list(sample_revocation_list_data)


class TestRevocationListParsing:
    """Tests for revocation list parsing."""

    def test_parse_valid_list(self, sample_revocation_list_data: dict):
        """Valid revocation list parses successfully."""
        result = parse_revocation_list(sample_revocation_list_data)

        assert result.version == 1
        assert result.generated_at == "2026-03-01T00:00:00Z"
        assert result.authority == "Specora Key Authority"
        assert len(result.keys) == 3

    def test_parse_key_entries(self, revocation_list: RevocationList):
        """Key entries are parsed correctly."""
        active_key = revocation_list.keys[0]
        assert active_key.derived_key_id == "spk-e1c8139bffc31826"
        assert active_key.status == "active"
        assert active_key.status_reason == "current production key"

    def test_missing_version_fails(self, sample_revocation_list_data: dict):
        """Missing version field raises error."""
        del sample_revocation_list_data["version"]

        with pytest.raises(VerificationError) as exc:
            parse_revocation_list(sample_revocation_list_data)

        assert "version" in str(exc.value)

    def test_missing_generated_at_fails(self, sample_revocation_list_data: dict):
        """Missing generated_at field raises error."""
        del sample_revocation_list_data["generated_at"]

        with pytest.raises(VerificationError) as exc:
            parse_revocation_list(sample_revocation_list_data)

        assert "generated_at" in str(exc.value)

    def test_invalid_timestamp_format_fails(self, sample_revocation_list_data: dict):
        """Invalid timestamp format raises error."""
        sample_revocation_list_data["generated_at"] = "2026-03-01"

        with pytest.raises(VerificationError) as exc:
            parse_revocation_list(sample_revocation_list_data)

        assert "generated_at" in str(exc.value)

    def test_invalid_key_id_format_fails(self, sample_revocation_list_data: dict):
        """Invalid key ID format raises error."""
        sample_revocation_list_data["keys"][0]["derived_key_id"] = "invalid-key-id"

        with pytest.raises(VerificationError) as exc:
            parse_revocation_list(sample_revocation_list_data)

        assert "derived_key_id" in str(exc.value)

    def test_invalid_fingerprint_format_fails(self, sample_revocation_list_data: dict):
        """Invalid fingerprint format raises error."""
        sample_revocation_list_data["keys"][0]["fingerprint_sha256"] = "short"

        with pytest.raises(VerificationError) as exc:
            parse_revocation_list(sample_revocation_list_data)

        assert "fingerprint_sha256" in str(exc.value)

    def test_key_id_fingerprint_mismatch_fails(self, sample_revocation_list_data: dict):
        """Key ID not matching fingerprint raises error."""
        # Change fingerprint but not key_id
        sample_revocation_list_data["keys"][0]["fingerprint_sha256"] = (
            "0000000000000000" + "0" * 48
        )

        with pytest.raises(VerificationError) as exc:
            parse_revocation_list(sample_revocation_list_data)

        assert "mismatch" in str(exc.value).lower()

    def test_invalid_status_fails(self, sample_revocation_list_data: dict):
        """Invalid status value raises error."""
        sample_revocation_list_data["keys"][0]["status"] = "invalid"

        with pytest.raises(VerificationError) as exc:
            parse_revocation_list(sample_revocation_list_data)

        assert "status" in str(exc.value)


class TestRevocationListLookup:
    """Tests for key lookup in revocation list."""

    def test_lookup_by_key_id(self, revocation_list: RevocationList):
        """Lookup by derived key ID works."""
        entry = revocation_list.lookup(key_id="spk-e1c8139bffc31826")

        assert entry is not None
        assert entry.status == "active"

    def test_lookup_by_fingerprint(self, revocation_list: RevocationList):
        """Lookup by fingerprint works."""
        entry = revocation_list.lookup(
            fingerprint="e1c8139bffc31826d0bad3384200ed2be209b29cced8af4221368019e59a3ae0"
        )

        assert entry is not None
        assert entry.status == "active"

    def test_lookup_unknown_key(self, revocation_list: RevocationList):
        """Lookup of unknown key returns None."""
        entry = revocation_list.lookup(key_id="spk-0000000000000000")

        assert entry is None

    def test_get_status_active(self, revocation_list: RevocationList):
        """Get status returns active for active key."""
        status = revocation_list.get_status(key_id="spk-e1c8139bffc31826")

        assert status == KEY_STATUS_ACTIVE

    def test_get_status_retired(self, revocation_list: RevocationList):
        """Get status returns retired for retired key."""
        status = revocation_list.get_status(key_id="spk-a1b2c3d4e5f6a7b8")

        assert status == KEY_STATUS_RETIRED

    def test_get_status_revoked(self, revocation_list: RevocationList):
        """Get status returns revoked for revoked key."""
        status = revocation_list.get_status(key_id="spk-deadbeef12345678")

        assert status == KEY_STATUS_REVOKED

    def test_get_status_unknown(self, revocation_list: RevocationList):
        """Get status returns unknown for unknown key."""
        status = revocation_list.get_status(key_id="spk-0000000000000000")

        assert status == KEY_STATUS_UNKNOWN


class TestKeyTrustCheck:
    """Tests for key trust checking."""

    def test_no_revocation_list_trusted(self):
        """Without revocation list, key is trusted with warning."""
        result = check_key_trust(
            revocation_list=None,
            key_id="spk-any",
        )

        assert result.trusted is True
        assert result.warning is not None
        assert result.revocation_list_provided is False

    def test_active_key_trusted(self, revocation_list: RevocationList):
        """Active key is fully trusted."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-e1c8139bffc31826",
        )

        assert result.trusted is True
        assert result.key_status == KEY_STATUS_ACTIVE
        assert result.warning is None
        assert result.error is None

    def test_retired_key_trusted_with_warning(self, revocation_list: RevocationList):
        """Retired key is trusted but with warning."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-a1b2c3d4e5f6a7b8",
        )

        assert result.trusted is True
        assert result.key_status == KEY_STATUS_RETIRED
        assert result.warning is not None
        assert "retired" in result.warning.lower()

    def test_retired_key_fails_with_require_trusted(self, revocation_list: RevocationList):
        """Retired key fails with --require-trusted-key."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-a1b2c3d4e5f6a7b8",
            require_trusted_key=True,
        )

        assert result.trusted is False
        assert result.key_status == KEY_STATUS_RETIRED
        assert result.error is not None

    def test_revoked_key_not_trusted(self, revocation_list: RevocationList):
        """Revoked key is not trusted."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-deadbeef12345678",
        )

        assert result.trusted is False
        assert result.key_status == KEY_STATUS_REVOKED
        assert result.error is not None
        assert "revoked" in result.error.lower()

    def test_revoked_key_not_trusted_regardless_of_flag(self, revocation_list: RevocationList):
        """Revoked key is not trusted even without require_trusted_key."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-deadbeef12345678",
            require_trusted_key=False,
        )

        assert result.trusted is False

    def test_unknown_key_trusted_with_warning(self, revocation_list: RevocationList):
        """Unknown key is trusted but with warning."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-0000000000000000",
        )

        assert result.trusted is True
        assert result.key_status == KEY_STATUS_UNKNOWN
        assert result.warning is not None

    def test_unknown_key_fails_with_require_trusted(self, revocation_list: RevocationList):
        """Unknown key fails with --require-trusted-key."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-0000000000000000",
            require_trusted_key=True,
        )

        assert result.trusted is False
        assert result.key_status == KEY_STATUS_UNKNOWN
        assert result.error is not None


class TestRevocationListLoading:
    """Tests for loading revocation list from file."""

    def test_load_valid_file(self, sample_revocation_list_data: dict):
        """Valid file loads successfully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(sample_revocation_list_data, f)
            f.flush()

            result = load_revocation_list(Path(f.name))

            assert result.version == 1
            assert len(result.keys) == 3

    def test_load_missing_file_fails(self):
        """Missing file raises error."""
        with pytest.raises(VerificationError) as exc:
            load_revocation_list(Path("/nonexistent/revocation-list.json"))

        assert "not found" in str(exc.value).lower()

    def test_load_invalid_json_fails(self):
        """Invalid JSON raises error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json")
            f.flush()

            with pytest.raises(VerificationError) as exc:
                load_revocation_list(Path(f.name))

            assert "parse" in str(exc.value).lower()


class TestTrustResultSerialization:
    """Tests for trust result serialization."""

    def test_trust_result_to_dict(self, revocation_list: RevocationList):
        """Trust result serializes to dict correctly."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-e1c8139bffc31826",
        )

        d = result.to_dict()

        assert "revocation_list_provided" in d
        assert "key_status" in d
        assert "require_trusted_key" in d
        assert "trusted" in d

    def test_trust_result_includes_warning(self, revocation_list: RevocationList):
        """Trust result includes warning when present."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-a1b2c3d4e5f6a7b8",  # retired key
        )

        d = result.to_dict()

        assert "warning" in d

    def test_trust_result_includes_error(self, revocation_list: RevocationList):
        """Trust result includes error when present."""
        result = check_key_trust(
            revocation_list=revocation_list,
            key_id="spk-deadbeef12345678",  # revoked key
        )

        d = result.to_dict()

        assert "error" in d
