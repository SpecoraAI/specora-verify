"""Agent identity certificate validator (AID-910 reference impl).

Apache 2.0 — public reference validator for the Specora agent identity
certificate format ``specora-aid-cert-v1``. Pairs with the platform-side
issuer in ``prspec_api.ai_agent_identity.sealing`` and produces byte-
identical verdicts against the golden vectors under
``vectors/agent-identity/``.

The envelope carries two distinct identity blocks:

* ``subject`` — the AGENT (org_id + agent_id + identity_id).
* ``principal`` — the OWNER that the agent acts on behalf of, with
  ``{id, public_key}``. Runtime authorization networks (HonorNet) use
  ``principal.public_key`` to verify owner-signed mandates per the
  three-part authorization presentation (HonorNet ADR-009 / Specora
  ADR-PLATFORM-009). Specora attests the key, never the mandate.

The wire identifier ``specora-aid-cert-v1`` is the same in both the
prelaunch (DEMO-ROOT) and the future production (C01-rooted) lanes;
lane separation is enforced by the pinned ``issuer_key_fingerprint``,
never by the format string.

Design constraints:

* Stdlib-first. The :mod:`cryptography` library is required only for
  the Ed25519 signature check; everything else is :mod:`json` and
  :mod:`hashlib` from the standard library.
* No imports from the wider specora_verify CLI surface. This module
  stays small enough to vendor or reimplement in another language.
* No network calls. Validation is fully offline; the relying party
  supplies the issuer public key out-of-band.

See ``docs/readers/agent-identity.md`` for the integration guide.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from specora_verify.canonical import canonical_json_bytes

CERT_FORMAT_VERSION = "specora-aid-cert-v1"
"""Wire identifier for the cert envelope. Same string across both the
prelaunch (DEMO-ROOT) lane and the future production (C01-rooted) lane;
lane separation is enforced by ``issuer_key_fingerprint``. See
ADR-PLATFORM-009."""


@dataclass
class AgentIdentityValidationResult:
    """Outcome of :func:`validate_agent_identity_certificate`.

    On success, ``principal`` carries the parsed ``{id, public_key}``
    block so cross-network presentations (HonorNet ``/authorize``) can
    hand the owner public key to the mandate verifier without re-
    parsing the cert.
    """

    valid: bool
    reason: str | None = None
    subject: dict[str, Any] | None = None
    principal: dict[str, str] | None = None
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
    """Validate an agent identity certificate.

    The verdict is byte-identical to the platform-side
    :func:`prspec_api.ai_agent_identity.sealing.validate_certificate`
    across the golden vectors under ``vectors/agent-identity/``.

    Args:
        certificate: Parsed cert envelope (a JSON object).
        issuer_public_key_hex: Hex-encoded Ed25519 public key of the
            issuer (prelaunch: DEMO-ROOT; production: C01-rooted),
            supplied out-of-band by the relying party (e.g. embedded
            in their config or in their pinned-issuer registry).
        now: Override for the current time, useful for golden-vector
            tests where ``not_after`` is fixed in the past.

    Returns:
        :class:`AgentIdentityValidationResult` with ``valid`` set true
        only if all five checks pass:

        1. ``format`` matches :data:`CERT_FORMAT_VERSION`.
        2. ``issuer_key_fingerprint`` matches the supplied issuer key.
        3. The Ed25519 signature verifies over canonical JSON of the
           envelope minus its ``signature`` field.
        4. ``now`` falls within ``[issued_at, not_after)``.
        5. ``principal`` block is present and well-formed
           (``{id: str, public_key: 64-hex-char str}``).
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

    principal = certificate.get("principal")
    if not isinstance(principal, dict):
        return AgentIdentityValidationResult(
            valid=False, reason="missing or malformed principal block"
        )
    principal_id = principal.get("id")
    principal_pk = principal.get("public_key")
    if not isinstance(principal_id, str) or not principal_id:
        return AgentIdentityValidationResult(
            valid=False, reason="principal.id missing or empty"
        )
    # §5.2 mandates lowercase hex, and canonical-bundle-v1.1.json pins
    # principal.public_key to ^[0-9a-f]{64}$. Accepting uppercase here would
    # make this validator more permissive than its own schema — a cert the
    # bundle schema rejects would pass this check. Enforce lowercase only.
    if (
        not isinstance(principal_pk, str)
        or len(principal_pk) != 64
        or any(c not in "0123456789abcdef" for c in principal_pk)
    ):
        return AgentIdentityValidationResult(
            valid=False,
            reason="principal.public_key must be 64 lowercase hex chars",
        )

    return AgentIdentityValidationResult(
        valid=True,
        subject=certificate.get("subject"),
        principal={"id": principal_id, "public_key": principal_pk},
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
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    # RFC 3339 (§2.2 of the wire spec) REQUIRES an explicit UTC offset. A
    # naive timestamp would be silently coerced to the *verifier's* local
    # timezone by .astimezone(), so the same cert could be judged valid in
    # one locale and expired in another — breaking the determinism guarantee
    # that an independent verifier exists to provide. Reject it outright.
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)
