"""Tests for the AID-920 Wire Spec v1.1 bundle validator.

Pairs with ``specora_verify/wire_spec.py``. Round-trips the four
``vectors/canonical-bundle/with-agent-identity/`` vectors and exercises
the tampering / forward-compat / no-issuer-key edge cases.

CSEA-SUPPRESS-2026-05-08-002 — investor-demo lane, archive 2026-06-05.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from specora_verify.wire_spec import (
    BundleV1_1ValidationResult,
    has_any_agent_identity,
    validate_bundle_v1_1,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
V11_VECTORS_DIR = REPO_ROOT / "vectors" / "canonical-bundle" / "with-agent-identity"
V10_VECTORS_DIR = REPO_ROOT / "vectors" / "canonical-bundle"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def issuer_pubkey_hex() -> str:
    return _load(V11_VECTORS_DIR / "ISSUER.json")["issuer_public_key_hex"]


@pytest.fixture(scope="module")
def evaluate_at() -> datetime:
    """Fixed evaluation time so vectors are stable as wall-clock advances."""
    return datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


class TestForwardCompat:
    """v1.0 bundles must validate clean under v1.1 (additive guarantee)."""

    @pytest.mark.parametrize(
        "filename",
        [
            "canonical-bundle-anthropic-1.0.0.canonical.json",
            "canonical-bundle-cloudtrail-1.0.0.canonical.json",
        ],
    )
    def test_v1_0_bundle_validates_under_v1_1(self, filename, issuer_pubkey_hex, evaluate_at):
        bundle = _load(V10_VECTORS_DIR / filename)
        result = validate_bundle_v1_1(
            bundle,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert isinstance(result, BundleV1_1ValidationResult)
        assert result.valid, result.reasons
        assert all(v.status == "absent" for v in result.record_verdicts), (
            "v1.0 bundles must produce only 'absent' verdicts under v1.1"
        )
        assert not has_any_agent_identity(bundle)


class TestV1_1Vectors:
    def test_single_record_with_identity(self, issuer_pubkey_hex, evaluate_at):
        bundle = _load(V11_VECTORS_DIR / "canonical-bundle-with-identity-1.0.0.canonical.json")
        assert has_any_agent_identity(bundle)
        result = validate_bundle_v1_1(
            bundle,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert result.valid, result.reasons
        assert [v.status for v in result.record_verdicts] == ["valid"]

    def test_multi_record_all_with_identity(self, issuer_pubkey_hex, evaluate_at):
        bundle = _load(V11_VECTORS_DIR / "canonical-bundle-mixed-identity-1.0.0.canonical.json")
        result = validate_bundle_v1_1(
            bundle,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert result.valid
        assert [v.status for v in result.record_verdicts] == [
            "valid",
            "valid",
        ]

    def test_partial_identity_bundle(self, issuer_pubkey_hex, evaluate_at):
        """Mixed bundle: one record with identity, one without — both legal."""
        bundle = _load(V11_VECTORS_DIR / "canonical-bundle-partial-identity-1.0.0.canonical.json")
        result = validate_bundle_v1_1(
            bundle,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert result.valid
        statuses = [v.status for v in result.record_verdicts]
        assert "valid" in statuses
        assert "absent" in statuses

    def test_empty_bundle(self, issuer_pubkey_hex, evaluate_at):
        bundle = _load(
            V11_VECTORS_DIR / "canonical-bundle-empty-with-identity-allowed-1.0.0.canonical.json"
        )
        result = validate_bundle_v1_1(
            bundle,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert result.valid
        assert result.record_count == 0


class TestTampering:
    """Tampering with agent_identity flips the bundle to FAIL."""

    def test_tampered_subject_fails_bundle(self, issuer_pubkey_hex, evaluate_at):
        bundle = _load(V11_VECTORS_DIR / "canonical-bundle-with-identity-1.0.0.canonical.json")
        bundle["records"][0]["agent_identity"]["subject"]["agent_id"] = "evil-impersonator"
        result = validate_bundle_v1_1(
            bundle,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert not result.valid
        assert result.record_verdicts[0].status == "invalid"
        assert result.record_verdicts[0].reason == "signature does not verify"

    def test_one_invalid_record_fails_whole_bundle(self, issuer_pubkey_hex, evaluate_at):
        bundle = _load(V11_VECTORS_DIR / "canonical-bundle-mixed-identity-1.0.0.canonical.json")
        # Tamper only the second record.
        bundle["records"][1]["agent_identity"]["public_key"] = "ee" * 32
        result = validate_bundle_v1_1(
            bundle,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert not result.valid
        # The first record still verifies; the second fails.
        assert result.record_verdicts[0].status == "valid"
        assert result.record_verdicts[1].status == "invalid"


class TestMissingIssuerKey:
    """When agent_identity is present but no issuer pubkey is supplied."""

    def test_no_issuer_pubkey_returns_invalid(self, evaluate_at):
        bundle = _load(V11_VECTORS_DIR / "canonical-bundle-with-identity-1.0.0.canonical.json")
        result = validate_bundle_v1_1(bundle, issuer_public_key_hex=None, now=evaluate_at)
        assert not result.valid
        assert result.record_verdicts[0].reason == "issuer pubkey not supplied"


class TestVectorMetadata:
    """All v1.1 vectors must carry the for-demo-only marker on the issuer."""

    def test_issuer_marker_present(self):
        issuer = _load(V11_VECTORS_DIR / "ISSUER.json")
        assert issuer["_metadata"]["marker"] == "for-demo-only-not-production"
        assert issuer["_metadata"]["subject"]["organizational_unit"] == (
            "for-demo-only-not-production"
        )
