"""Agent identity certificate validator (AID-910 reference impl).

Apache 2.0 — public reference validator for the demo-lane Specora agent
identity certificate format. Pairs with the platform-side issuer in
``prspec_api.ai_agent_identity.sealing`` and produces byte-identical
verdicts against the golden vectors under ``vectors/agent-identity/``.

Status: investor-demo lane (CSEA-SUPPRESS-2026-05-08-002 in the platform
repo). The on-wire format identifier ``specora-aid-cert-v1-demo`` is
load-bearing — a future production format carries a different suffix
so demo-issued certs can never be confused with production state.

Design constraints:

* Stdlib-first. The :mod:`cryptography` library is required only for
  the Ed25519 signature check; everything else is :mod:`json` and
  :mod:`hashlib` from the standard library.
* No imports from the wider specora_verify CLI surface. This module
  stays small enough to vendor or reimplement in another language.
* No network calls. Validation is fully offline; the relying party
  supplies the issuer public key out-of-band.

See ``docs/readers/`` for the full demo-lane integration guide once
the AID-940 reader pass-through ships.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from specora_verify.canonical import canonical_json_bytes

CERT_FORMAT_VERSION = "specora-aid-cert-v1-demo"
"""Wire identifier for the demo-lane envelope. Production formats use
a different suffix; relying parties should refuse anything else."""


@dataclass
class AgentIdentityValidationResult:
    """Outcome of :func:`validate_agent_identity_certificate`."""

    valid: bool
    reason: str | None = None
    subject: dict[str, Any] | None = None
    issuer_key_fingerprint: str | None = None


def public_key_fingerprint(public_key_hex: str) -> str:
    """SHA-256 hex digest of the raw public-key bytes."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def validate_agent_identity_certificate(
    certificate: dict[str, Any],
    *,
    issuer_public_key_hex: str,
    now: datetime | None = None,
) -> AgentIdentityValidationResult:
    """Validate a demo-lane agent identity certificate.

    The verdict is byte-identical to the platform-side
    :func:`prspec_api.ai_agent_identity.sealing.validate_certificate`
    across the golden vectors under ``vectors/agent-identity/``.

    Args:
        certificate: Parsed cert envelope (a JSON object).
        issuer_public_key_hex: Hex-encoded Ed25519 public key of the
            DEMO-ROOT issuer, supplied out-of-band by the relying
            party (e.g. embedded in their config).
        now: Override for the current time, useful for golden-vector
            tests where ``not_after`` is fixed in the past.

    Returns:
        :class:`AgentIdentityValidationResult` with ``valid`` set true
        only if all four checks pass:

        1. ``format`` matches :data:`CERT_FORMAT_VERSION`.
        2. ``issuer_key_fingerprint`` matches the supplied issuer key.
        3. The Ed25519 signature verifies over canonical JSON of the
           envelope minus its ``signature`` field.
        4. ``now`` falls within ``[issued_at, not_after)``.
    """
    now = now or datetime.now(timezone.utc)

    if not isinstance(certificate, dict):
        return AgentIdentityValidationResult(
            valid=False, reason="certificate must be a JSON object"
        )

    if certificate.get("format") != CERT_FORMAT_VERSION:
        return AgentIdentityValidationResult(
            valid=False, reason="unsupported certificate format"
        )

    expected_fp = public_key_fingerprint(issuer_public_key_hex)
    if certificate.get("issuer_key_fingerprint") != expected_fp:
        return AgentIdentityValidationResult(
            valid=False, reason="issuer key fingerprint mismatch"
        )

    signature_b64 = certificate.get("signature")
    if not isinstance(signature_b64, str):
        return AgentIdentityValidationResult(
            valid=False, reason="missing or malformed signature"
        )

    unsigned = {k: v for k, v in certificate.items() if k != "signature"}
    signed_bytes = canonical_json_bytes(unsigned)

    if not _verify_ed25519(
        public_key_hex=issuer_public_key_hex,
        message=signed_bytes,
        signature=base64.b64decode(signature_b64),
    ):
        return AgentIdentityValidationResult(
            valid=False, reason="signature does not verify"
        )

    issued_at = _parse_rfc3339(certificate.get("issued_at"))
    not_after = _parse_rfc3339(certificate.get("not_after"))
    if issued_at is None or not_after is None:
        return AgentIdentityValidationResult(
            valid=False, reason="missing or malformed validity window"
        )
    if now < issued_at:
        return AgentIdentityValidationResult(
            valid=False, reason="certificate not yet valid"
        )
    if now >= not_after:
        return AgentIdentityValidationResult(
            valid=False, reason="certificate expired"
        )

    return AgentIdentityValidationResult(
        valid=True,
        subject=certificate.get("subject"),
        issuer_key_fingerprint=expected_fp,
    )


def _verify_ed25519(
    *, public_key_hex: str, message: bytes, signature: bytes
) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "agent identity validation requires the 'cryptography' extra: "
            "pip install specora-verify[crypto]"
        ) from exc

    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(signature, message)
        return True
    except Exception:
        return False


def _parse_rfc3339(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError:
        return None
