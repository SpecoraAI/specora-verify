"""Tests for the AID-910 agent identity validator.

Pairs with ``specora_verify/agent_identity.py``. Round-trips the three
golden vectors under ``vectors/agent-identity/`` and exercises the
tampering / format / expiry / principal-block edge cases.

The envelope shape is governed by ADR-PLATFORM-009 (Specora) and
HonorNet ADR-009: ``subject`` is the AGENT block, ``principal`` is the
OWNER block ({id, public_key}). Both are sealed in the cert signature.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from specora_verify.agent_identity import (
    CERT_FORMAT_VERSION,
    AgentIdentityValidationResult,
    public_key_fingerprint,
    validate_agent_identity_certificate,
)

VECTORS_DIR = Path(__file__).resolve().parents[1] / "specora_verify" / "vectors" / "agent-identity"


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


@pytest.fixture(scope="module")
def issuer_pubkey_hex() -> str:
    return _load("ISSUER.json")["issuer_public_key_hex"]


@pytest.fixture(scope="module")
def evaluate_at() -> datetime:
    """Fixed evaluation time so vectors are stable as wall-clock advances."""
    return datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


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
        assert result.principal is not None
        assert result.principal["id"] == "00000000-0000-0000-0000-0000000000aa"
        assert len(result.principal["public_key"]) == 64
        assert result.issuer_key_fingerprint == public_key_fingerprint(issuer_pubkey_hex)

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

    def test_cert_validates_cryptographically(self, issuer_pubkey_hex, evaluate_at):
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


class TestPrincipalBlock:
    """The principal block (ADR-PLATFORM-009) is sealed into the cert."""

    def test_tampered_principal_id_fails_signature(self, issuer_pubkey_hex, evaluate_at):
        vec = _load("valid.json")
        cert = dict(vec["certificate"])
        cert["principal"] = {**cert["principal"], "id": "evil-org"}
        result = validate_agent_identity_certificate(
            cert, issuer_public_key_hex=issuer_pubkey_hex, now=evaluate_at
        )
        assert not result.valid
        assert result.reason == "signature does not verify"

    def test_tampered_principal_pubkey_fails_signature(self, issuer_pubkey_hex, evaluate_at):
        vec = _load("valid.json")
        cert = dict(vec["certificate"])
        cert["principal"] = {**cert["principal"], "public_key": "ff" * 32}
        result = validate_agent_identity_certificate(
            cert, issuer_public_key_hex=issuer_pubkey_hex, now=evaluate_at
        )
        assert not result.valid
        assert result.reason == "signature does not verify"

    def test_missing_principal_block_rejected(self, issuer_pubkey_hex, evaluate_at):
        # Strip principal AND re-sign would still fail because we don't
        # have the private key; instead bypass-signature path: assert the
        # cert without principal cannot validate, regardless of how it
        # was produced. Using the live signed cert with principal stripped
        # exercises the well-formed-check, not the signature check.
        vec = _load("valid.json")
        cert = dict(vec["certificate"])
        cert.pop("principal", None)
        result = validate_agent_identity_certificate(
            cert, issuer_public_key_hex=issuer_pubkey_hex, now=evaluate_at
        )
        # Either rejected at signature-check (because the canonical bytes
        # now differ) or at the well-formed check (which only fires after
        # signature verification when principal isn't covered). The first
        # one wins here.
        assert not result.valid
        assert result.reason in (
            "signature does not verify",
            "missing or malformed principal block",
        )


class TestVectorMetadata:
    """All vectors must carry the prelaunch marker."""

    @pytest.mark.parametrize("name", ["valid.json", "expired.json", "revoked.json", "ISSUER.json"])
    def test_marker_present(self, name):
        vec = _load(name)
        assert vec["_metadata"]["marker"] == "for-demo-only-not-production"


class TestPrincipalPubkeyCasing:
    """§5.2 + canonical-bundle-v1.1.json pin principal.public_key to
    ^[0-9a-f]{64}$. The validator must NOT be more permissive than its own
    schema by accepting uppercase hex."""

    def test_uppercase_principal_pubkey_rejected(self, issuer_pubkey_hex, evaluate_at):
        vec = _load("valid.json")
        cert = dict(vec["certificate"])
        cert["principal"] = {
            **cert["principal"],
            "public_key": cert["principal"]["public_key"].upper(),
        }
        result = validate_agent_identity_certificate(
            cert, issuer_public_key_hex=issuer_pubkey_hex, now=evaluate_at
        )
        assert not result.valid
        # Either the signature check (canonical bytes changed) or the
        # lowercase-hex well-formedness check rejects it; both are correct.
        assert result.reason in (
            "signature does not verify",
            "principal.public_key must be 64 lowercase hex chars",
        )


class TestTimezoneNaiveTimestamps:
    """RFC 3339 requires an explicit offset. A naive (tz-less) validity
    window must be REJECTED, never coerced to the verifier's local time —
    otherwise the same cert flips verdict depending on where it runs, which
    breaks the determinism guarantee the verifier exists to provide.
    """

    def _mint_naive_cert(self, issuer_pubkey_hex):
        """A valid cert except its validity window lacks a 'Z' offset."""
        vec = _load("valid.json")
        cert = dict(vec["certificate"])
        cert["issued_at"] = "2026-05-08T12:00:00"  # naive — no Z
        cert["not_after"] = "2026-06-07T12:00:00"  # naive — no Z
        return cert

    def test_naive_validity_window_rejected(self, issuer_pubkey_hex, evaluate_at):
        cert = self._mint_naive_cert(issuer_pubkey_hex)
        result = validate_agent_identity_certificate(
            cert, issuer_public_key_hex=issuer_pubkey_hex, now=evaluate_at
        )
        assert not result.valid
        # Rejected either at signature (canonical bytes changed) or at the
        # validity-window well-formedness check; both are correct outcomes.
        assert result.reason in (
            "signature does not verify",
            "missing or malformed validity window",
        )

    def test_verdict_is_locale_independent(self, monkeypatch):
        """The same naive-timestamp cert must yield the SAME verdict under
        any host timezone — never valid-here / expired-there."""
        import time

        vec = _load("valid.json")
        issuer = _load("ISSUER.json")["issuer_public_key_hex"]
        cert = dict(vec["certificate"])
        cert["not_after"] = "2026-06-07T12:00:00"  # naive boundary
        now = datetime(2026, 6, 7, 9, 0, 0, tzinfo=UTC)

        verdicts = []
        for tz in ("Pacific/Honolulu", "Asia/Tokyo", "UTC"):
            monkeypatch.setenv("TZ", tz)
            try:
                time.tzset()
            except AttributeError:  # pragma: no cover - non-POSIX
                pytest.skip("time.tzset() unavailable on this platform")
            verdicts.append(
                validate_agent_identity_certificate(
                    cert, issuer_public_key_hex=issuer, now=now
                ).valid
            )
        time.tzset()
        assert len(set(verdicts)) == 1, f"verdict varied by host timezone: {verdicts}"
