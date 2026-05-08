"""AID-940 — Anthropic reader agent_identity pass-through tests.

Closes the second half of the Phase 1 CSEA Stage 4 pairing: AID-910
verifier validator now pairs with a real reader that lifts identity
claims from upstream Anthropic Compliance API records.

Two pass-through paths exercised:

1. **Direct embedding** — record["agent_identity"] (SDK-direct path,
   used by agents that include the cert envelope in the upstream
   request body via the SDK's :func:`sign_action` helper).
2. **Header propagation** — record["request_metadata"]
   ["x-specora-agent-identity"] (header-style path, used by agents
   that prefer to keep the request body untouched).

Doctrine assertions:

* The reader NEVER fabricates an identity claim. Records without an
  embedded claim produce bundle records without an agent_identity
  field — the verifier's :func:`validate_bundle_v1_1` then surfaces
  status="absent" for those records.
* Tampering with the embedded claim flips
  :func:`validate_bundle_v1_1` to FAIL on that record.

CSEA-SUPPRESS-2026-05-08-002 / archive 2026-06-05.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from specora_verify.readers.anthropic import AnthropicReader
from specora_verify.wire_spec import validate_bundle_v1_1

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "anthropic"


@pytest.fixture
def issuer_pubkey_hex() -> str:
    payload = json.loads(
        (FIXTURE_DIR / "with-identity.ISSUER.json").read_text()
    )
    return payload["issuer_public_key_hex"]


@pytest.fixture
def evaluate_at() -> datetime:
    return datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)


class TestDirectEmbedding:
    def test_reader_lifts_direct_agent_identity(
        self, issuer_pubkey_hex, evaluate_at
    ):
        result = AnthropicReader().read(
            FIXTURE_DIR / "with-identity-direct.jsonl",
            key_id="spk-test-0001",
        )
        records = result.bundle_payload["records"]
        assert len(records) == 3

        # First two records carry agent_identity; third does not.
        assert "agent_identity" in records[0]
        assert "agent_identity" in records[1]
        assert "agent_identity" not in records[2]

        # The verifier-side validator accepts every present claim.
        verdict = validate_bundle_v1_1(
            result.bundle_payload,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert verdict.valid, verdict.reasons
        statuses = [v.status for v in verdict.record_verdicts]
        assert statuses == ["valid", "valid", "absent"]

    def test_reader_preserves_subject_bytes(
        self, issuer_pubkey_hex, evaluate_at
    ):
        """Reader must not touch the embedded envelope at all.

        If the reader normalizes/re-canonicalizes the cert, the
        signature breaks. Round-trip the bytes verbatim.
        """
        result = AnthropicReader().read(
            FIXTURE_DIR / "with-identity-direct.jsonl",
            key_id="spk-test-0001",
        )
        cert = result.bundle_payload["records"][0]["agent_identity"]
        assert cert["subject"]["agent_id"] == "acme-anthropic-agent-1"
        assert cert["format"] == "specora-aid-cert-v1-demo"
        # Validation is the strongest "preserved bytes" assertion.
        verdict = validate_bundle_v1_1(
            result.bundle_payload,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert verdict.valid


class TestHeaderPropagation:
    def test_reader_lifts_header_agent_identity(
        self, issuer_pubkey_hex, evaluate_at
    ):
        result = AnthropicReader().read(
            FIXTURE_DIR / "with-identity-header.jsonl",
            key_id="spk-test-0001",
        )
        records = result.bundle_payload["records"]
        assert len(records) == 2
        assert "agent_identity" in records[0]
        assert "agent_identity" not in records[1]

        verdict = validate_bundle_v1_1(
            result.bundle_payload,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert verdict.valid


class TestNoFabrication:
    """Doctrine: the reader NEVER fabricates an identity claim.

    Existing v1.0 fixtures (no agent_identity anywhere) must continue
    to produce bundles with no agent_identity field on any record.
    """

    def test_minimal_v1_0_fixture_has_no_identity_lifted(self):
        result = AnthropicReader().read(
            FIXTURE_DIR / "minimal-valid.jsonl",
            key_id="spk-test-0001",
        )
        for record in result.bundle_payload["records"]:
            assert "agent_identity" not in record


class TestTamperingFlipsBundle:
    def test_tampering_with_lifted_cert_flips_bundle(
        self, issuer_pubkey_hex, evaluate_at
    ):
        result = AnthropicReader().read(
            FIXTURE_DIR / "with-identity-direct.jsonl",
            key_id="spk-test-0001",
        )
        # Tamper after read — simulates a bad actor between reader
        # and verifier.
        result.bundle_payload["records"][0]["agent_identity"][
            "subject"
        ]["agent_id"] = "evil-impersonator"
        verdict = validate_bundle_v1_1(
            result.bundle_payload,
            issuer_public_key_hex=issuer_pubkey_hex,
            now=evaluate_at,
        )
        assert not verdict.valid
        assert verdict.record_verdicts[0].status == "invalid"
        assert (
            verdict.record_verdicts[0].reason == "signature does not verify"
        )
