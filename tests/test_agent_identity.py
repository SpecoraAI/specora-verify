"""Tests for the AID-910 demo-lane agent identity validator.

Pairs with ``specora_verify/agent_identity.py``. Round-trips the three
golden vectors under ``vectors/agent-identity/`` and exercises the
tampering / format / expiry edge cases.

CSEA-SUPPRESS-2026-05-08-002 — investor-demo lane, archive 2026-06-05.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from specora_verify.agent_identity import (
    CERT_FORMAT_VERSION,
    AgentIdentityValidationResult,
    public_key_fingerprint,
    validate_agent_identity_certificate,
)

VECTORS_DIR = Path(__file__).resolve().parents[1] / "vectors" / "agent-identity"


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


@pytest.fixture(scope="module")
def issuer_pubkey_hex() -> str:
    return _load("ISSUER.json")["issuer_public_key_hex"]


@pytest.fixture(scope="module")
def evaluate_at() -> datetime:
    """Fixed evaluation time so vectors are stable as wall-clock advances."""
    return datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)


class TestValidVector:
    def test_valid_cert_passes(self, issuer_pubkey_hex, evaluate_at):
        vec = _load("valid.json")
        result = validate_agent_identity_certificate(
            vec["certificate"],
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert isinstance(result, AgentIdentityValidationResult)
        assert result.valid, result.reason
        assert result.subject is not None
        assert result.subject["agent_id"] == "acme-demo-agent"
        assert result.issuer_key_fingerprint == public_key_fingerprint(
            issuer_pubkey_hex
        )

    def test_valid_cert_format_marker(self):
        vec = _load("valid.json")
        assert vec["certificate"]["format"] == CERT_FORMAT_VERSION
        assert vec["certificate"]["issuer"]["organizational_unit"] == (
            "for-demo-only-not-production"
        )


class TestExpiredVector:
    def test_expired_cert_fails(self, issuer_pubkey_hex, evaluate_at):
        vec = _load("expired.json")
        result = validate_agent_identity_certificate(
            vec["certificate"],
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert not result.valid
        assert result.reason == "certificate expired"


class TestRevokedVector:
    """Demo lane represents revocation as a side-channel marker.

    The cert itself remains cryptographically valid (so a stale signed
    bundle does not become unverifiable). The relying party gates on
    the revocation marker out-of-band — same pattern as Web PKI's CRL.
    """

    def test_cert_validates_cryptographically(
        self, issuer_pubkey_hex, evaluate_at
    ):
        vec = _load("revoked.json")
        result = validate_agent_identity_certificate(
            vec["certificate"],
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert result.valid, (
            "the demo-lane revoked vector packages an inert revocation "
            "marker beside a still-cryptographically-valid cert; "
            "relying parties consult the marker separately"
        )

    def test_revocation_marker_present(self):
        vec = _load("revoked.json")
        assert "revocation" in vec
        assert vec["revocation"]["reason"] == "synthetic-demo-revocation"


class TestTampering:
    def test_tampered_subject_fails(self, issuer_pubkey_hex, evaluate_at):
        vec = _load("valid.json")
        cert = dict(vec["certificate"])
        cert["subject"] = {
            **cert["subject"],
            "agent_id": "evil-impersonator",
        }
        result = validate_agent_identity_certificate(
            cert, issuer_public_key_hex=issuer_pubkey_hex, now=evaluate_at
        )
        assert not result.valid
        assert result.reason == "signature does not verify"

    def test_wrong_issuer_key_fails(self, evaluate_at):
        vec = _load("valid.json")
        # Use a syntactically-valid but wrong issuer pubkey.
        wrong_pubkey = "ff" * 32
        result = validate_agent_identity_certificate(
            vec["certificate"],
            issuer_public_key_hex=wrong_pubkey,
            now=evaluate_at,
        )
        assert not result.valid
        assert result.reason == "issuer key fingerprint mismatch"

    def test_unknown_format_fails(self, issuer_pubkey_hex, evaluate_at):
        vec = _load("valid.json")
        cert = dict(vec["certificate"])
        cert["format"] = "specora-aid-cert-v999"
        result = validate_agent_identity_certificate(
            cert, issuer_public_key_hex=issuer_pubkey_hex, now=evaluate_at
        )
        assert not result.valid
        assert result.reason == "unsupported certificate format"


class TestVectorMetadata:
    """All vectors must carry the demo-lane marker."""

    @pytest.mark.parametrize(
        "name", ["valid.json", "expired.json", "revoked.json", "ISSUER.json"]
    )
    def test_marker_present(self, name):
        vec = _load(name)
        assert vec["_metadata"]["marker"] == "for-demo-only-not-production"
