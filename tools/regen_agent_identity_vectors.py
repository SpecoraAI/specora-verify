"""Regenerate the agent-identity golden vectors + bundle vectors.

Deterministic generator: seeded Ed25519 keypairs produce stable
public keys + signatures across runs. Run after the AID-910 envelope
shape changes (e.g. ADR-PLATFORM-009).

Usage:
    python tools/regen_agent_identity_vectors.py

The script edits these files in place:

* ``vectors/agent-identity/ISSUER.json``
* ``vectors/agent-identity/{valid,expired,revoked}.json``
* ``vectors/canonical-bundle/with-agent-identity/ISSUER.json``
* ``vectors/canonical-bundle/with-agent-identity/canonical-bundle-*.canonical.json``
* ``tests/fixtures/anthropic/with-identity.ISSUER.json``
* ``tests/fixtures/anthropic/with-identity-{header,direct}.jsonl``

The ``_metadata.expectation`` strings + ``revocation`` side-channel fields
on revoked vectors are preserved; only the cert envelope itself is
rebuilt.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# Deterministic 32-byte seeds. Changing these regenerates every signed
# byte in every vector — only do it when the envelope shape changes.
ISSUER_SEED = b"specora-aid-issuer-vectors-seed1"  # 32 bytes
AGENT_VALID_SEED = b"specora-aid-agent-valid-vectors!"  # 32 bytes
AGENT_EXPIRED_SEED = b"specora-aid-agent-expired-vec!!!"  # 32 bytes
AGENT_REVOKED_SEED = b"specora-aid-agent-revoked-vec!!!"  # 32 bytes
AGENT_BUNDLE_SEED = b"specora-aid-agent-bundle-vec-key"  # 32 bytes
AGENT_BUNDLE_SEED_2 = b"specora-aid-agent-bundle-vec-2!!"  # 32 bytes
PRINCIPAL_VALID_SEED = b"specora-aid-principal-valid-vec!"  # 32 bytes
PRINCIPAL_EXPIRED_SEED = b"specora-aid-principal-expired-v!"  # 32 bytes
PRINCIPAL_REVOKED_SEED = b"specora-aid-principal-revoked-v!"  # 32 bytes
PRINCIPAL_BUNDLE_SEED = b"specora-aid-principal-bundle-key"  # 32 bytes

CERT_FORMAT_VERSION = "specora-aid-cert-v1"

ISSUER_SUBJECT = {
    "common_name": "Specora Demo Root",
    "organizational_unit": "for-demo-only-not-production",
    "organization": "Specora",
}


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def keypair_from_seed(seed: bytes) -> tuple[str, Ed25519PrivateKey]:
    assert len(seed) == 32, f"seed must be 32 bytes, got {len(seed)}"
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_bytes = private_key.public_key().public_bytes_raw()
    return public_bytes.hex(), private_key


def fingerprint(public_key_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def build_certificate(
    *,
    identity_id: str,
    org_id: str,
    agent_id: str,
    public_key_hex: str,
    principal_id: str,
    principal_public_key_hex: str,
    issuer_keypair: tuple[str, Ed25519PrivateKey],
    issued_at: str,
    not_after: str,
) -> dict[str, Any]:
    issuer_pk_hex, issuer_priv = issuer_keypair
    envelope_unsigned: dict[str, Any] = {
        "format": CERT_FORMAT_VERSION,
        "subject": {
            "identity_id": identity_id,
            "org_id": org_id,
            "agent_id": agent_id,
        },
        "principal": {
            "id": principal_id,
            "public_key": principal_public_key_hex,
        },
        "issuer": ISSUER_SUBJECT,
        "public_key": public_key_hex,
        "issuer_key_fingerprint": fingerprint(issuer_pk_hex),
        "issued_at": issued_at,
        "not_after": not_after,
    }
    signed_bytes = canonical_json_bytes(envelope_unsigned)
    signature = issuer_priv.sign(signed_bytes)
    envelope_unsigned["signature"] = base64.b64encode(signature).decode("ascii")
    return envelope_unsigned


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {path.relative_to(REPO_ROOT)}")


def write_canonical_json(path: Path, payload: dict[str, Any]) -> None:
    # No trailing newline: .canonical.json vectors are byte-canonical
    # (tests/test_wire_spec_schemas.py::test_canonical_vector_is_byte_canonical).
    path.write_text(
        canonical_json_bytes(payload).decode("utf-8"),
        encoding="utf-8",
    )
    print(f"wrote {path.relative_to(REPO_ROOT)}")


def main() -> int:
    issuer = keypair_from_seed(ISSUER_SEED)
    issuer_pk_hex, _ = issuer
    issuer_fp = fingerprint(issuer_pk_hex)

    org_id = "00000000-0000-0000-0000-0000000000aa"

    agent_valid_pk, _ = keypair_from_seed(AGENT_VALID_SEED)
    agent_expired_pk, _ = keypair_from_seed(AGENT_EXPIRED_SEED)
    agent_revoked_pk, _ = keypair_from_seed(AGENT_REVOKED_SEED)
    agent_bundle_pk, _ = keypair_from_seed(AGENT_BUNDLE_SEED)
    agent_bundle_pk_2, _ = keypair_from_seed(AGENT_BUNDLE_SEED_2)

    principal_valid_pk, _ = keypair_from_seed(PRINCIPAL_VALID_SEED)
    principal_expired_pk, _ = keypair_from_seed(PRINCIPAL_EXPIRED_SEED)
    principal_revoked_pk, _ = keypair_from_seed(PRINCIPAL_REVOKED_SEED)
    principal_bundle_pk, _ = keypair_from_seed(PRINCIPAL_BUNDLE_SEED)

    # -------- vectors/agent-identity/ -----------------------------------
    agent_identity_dir = REPO_ROOT / "vectors" / "agent-identity"
    write_json(
        agent_identity_dir / "ISSUER.json",
        {
            "_metadata": {
                "kind": "demo-vector-issuer",
                "marker": "for-demo-only-not-production",
                "subject": ISSUER_SUBJECT,
            },
            "issuer_public_key_hex": issuer_pk_hex,
        },
    )

    valid_cert = build_certificate(
        identity_id="00000000-0000-0000-0000-000000000001",
        org_id=org_id,
        agent_id="acme-demo-agent",
        public_key_hex=agent_valid_pk,
        principal_id=org_id,
        principal_public_key_hex=principal_valid_pk,
        issuer_keypair=issuer,
        issued_at="2026-05-08T12:00:00Z",
        not_after="2036-01-01T00:00:00Z",
    )
    write_json(
        agent_identity_dir / "valid.json",
        {
            "_metadata": {
                "evaluate_at": "2026-05-15T12:00:00Z",
                "expectation": "validate to OK",
                "issuer_public_key_hex": issuer_pk_hex,
                "kind": "demo-vector",
                "marker": "for-demo-only-not-production",
            },
            "certificate": valid_cert,
        },
    )

    expired_cert = build_certificate(
        identity_id="00000000-0000-0000-0000-000000000002",
        org_id=org_id,
        agent_id="acme-expired-agent",
        public_key_hex=agent_expired_pk,
        principal_id=org_id,
        principal_public_key_hex=principal_expired_pk,
        issuer_keypair=issuer,
        issued_at="2025-01-01T00:00:00Z",
        not_after="2025-01-02T00:00:00Z",
    )
    write_json(
        agent_identity_dir / "expired.json",
        {
            "_metadata": {
                "evaluate_at": "2026-05-15T12:00:00Z",
                "expectation": ("validate to FAIL with reason 'certificate expired'"),
                "issuer_public_key_hex": issuer_pk_hex,
                "kind": "demo-vector",
                "marker": "for-demo-only-not-production",
            },
            "certificate": expired_cert,
        },
    )

    revoked_cert = build_certificate(
        identity_id="00000000-0000-0000-0000-000000000003",
        org_id=org_id,
        agent_id="acme-revoked-agent",
        public_key_hex=agent_revoked_pk,
        principal_id=org_id,
        principal_public_key_hex=principal_revoked_pk,
        issuer_keypair=issuer,
        issued_at="2026-05-08T12:00:00Z",
        not_after="2036-01-01T00:00:00Z",
    )
    write_json(
        agent_identity_dir / "revoked.json",
        {
            "_metadata": {
                "evaluate_at": "2026-05-15T12:00:00Z",
                "expectation": (
                    "certificate validates cryptographically (signature OK, "
                    "not expired) but is REVOKED — relying party must "
                    "consult the issuance-events ledger for revocation "
                    "status. Demo lane represents this as a side-channel "
                    "revocation marker."
                ),
                "issuer_public_key_hex": issuer_pk_hex,
                "kind": "demo-vector",
                "marker": "for-demo-only-not-production",
            },
            "certificate": revoked_cert,
            "revocation": {
                "reason": "synthetic-demo-revocation",
                "revoked_at": "2026-05-10T12:00:00Z",
            },
        },
    )

    # -------- vectors/canonical-bundle/with-agent-identity/ -------------
    bundle_dir = REPO_ROOT / "vectors" / "canonical-bundle" / "with-agent-identity"
    write_json(
        bundle_dir / "ISSUER.json",
        {
            "_metadata": {
                "kind": "demo-vector-issuer",
                "marker": "for-demo-only-not-production",
                "subject": ISSUER_SUBJECT,
            },
            "issuer_public_key_hex": issuer_pk_hex,
        },
    )

    bundle_cert_1 = build_certificate(
        identity_id="00000000-0000-0000-0000-000000000001",
        org_id=org_id,
        agent_id="acme-bundle-agent-1",
        public_key_hex=agent_bundle_pk,
        principal_id=org_id,
        principal_public_key_hex=principal_bundle_pk,
        issuer_keypair=issuer,
        issued_at="2026-05-08T12:00:00Z",
        not_after="2036-01-01T00:00:00Z",
    )
    bundle_cert_2 = build_certificate(
        identity_id="00000000-0000-0000-0000-000000000004",
        org_id=org_id,
        agent_id="acme-bundle-agent-2",
        public_key_hex=agent_bundle_pk_2,
        principal_id=org_id,
        principal_public_key_hex=principal_bundle_pk,
        issuer_keypair=issuer,
        issued_at="2026-05-08T12:00:00Z",
        not_after="2036-01-01T00:00:00Z",
    )

    for path in sorted(bundle_dir.glob("canonical-bundle-*.canonical.json")):
        bundle = json.loads(path.read_text(encoding="utf-8"))
        for record in bundle.get("records", []):
            ident = record.get("agent_identity")
            if not ident:
                continue
            agent_id = ident.get("subject", {}).get("agent_id")
            if agent_id == "acme-bundle-agent-2":
                record["agent_identity"] = bundle_cert_2
            else:
                record["agent_identity"] = bundle_cert_1
        write_canonical_json(path, bundle)

    # -------- tests/fixtures/anthropic/ ---------------------------------
    fixtures_dir = REPO_ROOT / "tests" / "fixtures" / "anthropic"
    if fixtures_dir.exists():
        fix_issuer = fixtures_dir / "with-identity.ISSUER.json"
        if fix_issuer.exists():
            write_json(
                fix_issuer,
                {
                    "_metadata": {
                        "kind": "demo-vector-issuer",
                        "marker": "for-demo-only-not-production",
                        "subject": ISSUER_SUBJECT,
                    },
                    "issuer_public_key_hex": issuer_pk_hex,
                },
            )

        for jsonl_path in sorted(fixtures_dir.glob("with-identity*.jsonl")):
            lines: list[str] = []
            for raw in jsonl_path.read_text(encoding="utf-8").splitlines():
                if not raw.strip():
                    continue
                obj = json.loads(raw)

                def _patch_obj(o: Any) -> None:
                    if isinstance(o, dict):
                        if (
                            o.get("format")
                            in (
                                "specora-aid-cert-v1-demo",
                                CERT_FORMAT_VERSION,
                            )
                            and "subject" in o
                        ):
                            agent_id = o["subject"].get("agent_id", "acme-bundle-agent-1")
                            replacement = (
                                bundle_cert_2
                                if agent_id == "acme-bundle-agent-2"
                                else bundle_cert_1
                            )
                            o.clear()
                            o.update(replacement)
                            return
                        for v in o.values():
                            _patch_obj(v)
                    elif isinstance(o, list):
                        for v in o:
                            _patch_obj(v)

                _patch_obj(obj)
                lines.append(json.dumps(obj, sort_keys=True))
            jsonl_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"wrote {jsonl_path.relative_to(REPO_ROOT)}")

    print("\nIssuer public key:", issuer_pk_hex)
    print("Issuer fingerprint:", issuer_fp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
