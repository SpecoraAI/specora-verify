"""Wire Spec v1.1 bundle-level validator.

Apache 2.0. Pairs with ``docs/wire-spec-v1.1.md`` and the JSON Schema at
``docs/schemas/canonical-bundle-v1.1.json``. v1.0 bundles continue to
validate against the v1.0 schema unchanged (tested by
``tests/test_wire_spec_schemas.py``).

What v1.1 adds
==============

A single OPTIONAL field on each ``records[]`` entry:

* ``agent_identity`` — a Specora cert envelope of format
  ``specora-aid-cert-v1``. The envelope carries a ``principal`` block
  attesting the OWNER public key (ADR-PLATFORM-009 / HonorNet ADR-009)
  in addition to the AGENT identity. Pairs with the AID-910 issuer in
  the platform repo and the AID-910 reference validator in
  ``specora_verify.agent_identity``. When absent, this validator ignores
  the field. When present, it round-trips the envelope through the
  AID-910 validator and propagates the verdict.

Tampering with the ``agent_identity`` field on a record flips the
bundle to ``FAIL`` (per the analyst-pre-brief Slide 5 invariant).

Doctrine guardrails preserved
=============================

* **Out-of-band always**: this validator never contacts Specora, never
  contacts the issuer, never contacts the relying party. Issuer pubkey
  is supplied to :func:`validate_bundle_v1_1` out-of-band.
* **v1.0 forward-compat**: a v1.0 bundle (no ``agent_identity`` on any
  record) validates clean under v1.1.
* **Adoption is opt-in**: every record may or may not carry the field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from specora_verify.agent_identity import (
    AgentIdentityValidationResult,
    validate_agent_identity_certificate,
)


WIRE_SPEC_VERSION_V1_0 = "1.0"
WIRE_SPEC_VERSION_V1_1 = "1.1"


@dataclass
class RecordIdentityVerdict:
    """Per-record agent-identity outcome.

    ``record_index`` is the position of the record in
    ``bundle["records"]`` (0-based). ``status`` is one of:

    * ``"absent"`` — the record carries no ``agent_identity`` field
      (the v1.0 path; not a failure).
    * ``"valid"`` — the field is present and the AID-910 validator
      returned ``valid=True``.
    * ``"invalid"`` — present but rejected by the AID-910 validator.
      ``reason`` carries the AID-910 reason string.
    """

    record_index: int
    status: str
    reason: str | None = None


@dataclass
class BundleV1_1ValidationResult:
    """Whole-bundle validation outcome.

    ``valid=True`` requires every record's identity verdict to be
    either ``absent`` or ``valid``. A single ``invalid`` flips the
    whole bundle to ``valid=False``.
    """

    valid: bool
    record_count: int
    record_verdicts: list[RecordIdentityVerdict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def has_any_agent_identity(bundle: dict[str, Any]) -> bool:
    """Return True if any record in the bundle carries ``agent_identity``.

    Convenience accessor for callers that want to know whether a bundle
    is exercising the v1.1 surface or is a pure v1.0 payload.
    """
    if not isinstance(bundle, dict):
        return False
    records = bundle.get("records")
    if not isinstance(records, list):
        return False
    return any(
        isinstance(r, dict) and "agent_identity" in r for r in records
    )


def validate_bundle_v1_1(
    bundle: dict[str, Any],
    *,
    issuer_public_key_hex: str | None = None,
    now: datetime | None = None,
) -> BundleV1_1ValidationResult:
    """Validate the v1.1 surface of a canonical evidence bundle.

    Performs ONLY the v1.1-specific check (the optional
    ``agent_identity`` field). Schema-level v1.0 validation continues
    to live in :mod:`tests.test_wire_spec_schemas` against the
    ``canonical-bundle-v1.1.json`` JSON Schema.

    Args:
        bundle: A canonical evidence bundle dict (parsed from JSON).
        issuer_public_key_hex: Hex-encoded Ed25519 public key of the
            DEMO-ROOT issuer. When ``None``, every record's
            ``agent_identity`` field is treated as ``invalid`` with
            reason ``"issuer pubkey not supplied"`` — relying parties
            cannot validate without out-of-band issuer pinning.
        now: Override for the current time. Useful for tests that
            evaluate against fixed-time vectors.

    Returns:
        :class:`BundleV1_1ValidationResult` carrying a per-record
        verdict list and a whole-bundle ``valid`` boolean.
    """
    if not isinstance(bundle, dict):
        return BundleV1_1ValidationResult(
            valid=False,
            record_count=0,
            reasons=["bundle must be a JSON object"],
        )

    records = bundle.get("records")
    if not isinstance(records, list):
        return BundleV1_1ValidationResult(
            valid=False,
            record_count=0,
            reasons=["bundle.records must be an array"],
        )

    verdicts: list[RecordIdentityVerdict] = []
    reasons: list[str] = []
    valid = True

    for idx, record in enumerate(records):
        if not isinstance(record, dict):
            verdicts.append(
                RecordIdentityVerdict(
                    record_index=idx,
                    status="invalid",
                    reason="record must be a JSON object",
                )
            )
            reasons.append(f"record {idx}: not a JSON object")
            valid = False
            continue

        identity = record.get("agent_identity")
        if identity is None:
            verdicts.append(
                RecordIdentityVerdict(record_index=idx, status="absent")
            )
            continue

        if issuer_public_key_hex is None:
            verdicts.append(
                RecordIdentityVerdict(
                    record_index=idx,
                    status="invalid",
                    reason="issuer pubkey not supplied",
                )
            )
            reasons.append(
                f"record {idx}: agent_identity present but no issuer "
                "pubkey supplied"
            )
            valid = False
            continue

        result: AgentIdentityValidationResult = (
            validate_agent_identity_certificate(
                identity,
                issuer_public_key_hex=issuer_public_key_hex,
                now=now,
            )
        )
        if result.valid:
            verdicts.append(
                RecordIdentityVerdict(record_index=idx, status="valid")
            )
        else:
            verdicts.append(
                RecordIdentityVerdict(
                    record_index=idx,
                    status="invalid",
                    reason=result.reason,
                )
            )
            reasons.append(
                f"record {idx}: agent_identity invalid — {result.reason}"
            )
            valid = False

    return BundleV1_1ValidationResult(
        valid=valid,
        record_count=len(records),
        record_verdicts=verdicts,
        reasons=reasons,
    )
