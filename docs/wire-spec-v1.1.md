# Specora Wire Spec v1.1 (additive over v1.0 — demo lane)

**Status:** Demo-lane additive revision. Investor-demo only — v1.0 remains the only spec ratified for production.
**Version:** 1.1.0 (minor SemVer bump)
**License:** Apache 2.0 (same as the `specora-verify` repository)
**Canonical location:** `docs/wire-spec-v1.1.md` in [`SpecoraAI/specora-verify`](https://github.com/SpecoraAI/specora-verify)
**Authorization:** [`docs/strategy/freeze-exceptions/2026-05-08-aid-investor-demo-build.md`](https://github.com/SpecoraAI/specora-platform) (platform repo); CSEA-SUPPRESS-2026-05-08-002. Archive 2026-06-05.
**Frozen Canonicalizer:** still v1.0.0 — no change to the canonical-JSON algorithm.

> **What this spec does** — adds **one** optional field on each evidence-bundle record: `agent_identity`. v1.0 bundles validate cleanly under v1.1 (forward-compat is a hard guarantee). Adoption is opt-in.
>
> **What this spec does not do** — change the canonicalization rules, the seven payload types from v1.0 §2, the SHA-256 / Ed25519 algorithm choices, or the offline-verifier posture. None of those move.

---

## 1. Why a v1.1?

v1.0 ships the canonical evidence bundle (provider record stream → SHA-256 + Ed25519 signed bundle → independent verifier). v1.1 extends each record with an optional cryptographic claim about which agent produced the upstream action. Customers running the AID-9xx investor-demo flow want their evidence bundles to embed the agent's identity certificate so an auditor reviewing the bundle later can chain back to the issuer key.

This is a Web PKI / Sigstore pattern: the issuer (Specora, demo lane) signs a short-lived cert that binds an agent's public key to an `(org_id, agent_id, identity_id)` subject. The agent's runtime embeds this cert in the upstream request envelope. The provider's compliance reader propagates it into the canonical bundle. The verifier's `validate_bundle_v1_1` checks the cert against an out-of-band issuer pubkey and surfaces a per-record verdict.

**No inline authorization.** Specora is not in the agent → relying-party path at action time. The cert is issued at registration; verification happens out-of-band against the bundle. Guardrail 0 from the AID epic suite §1.2 binds.

---

## 2. Forward-compat guarantee

A v1.0 bundle validates clean under v1.1. The schema at `docs/schemas/canonical-bundle-v1.1.json` differs from v1.0 only by an additional optional property. The conformance test in `tests/test_wire_spec_schemas.py` exercises both v1.0 and v1.1 schemas against the v1.0 golden vectors and asserts they pass.

**v1.0 adopters do not need to change anything.** No customer integration breaks. v1.1 is an opt-in extension.

---

## 3. The `agent_identity` field

### 3.1 Where it lives

On each `records[]` entry, alongside `id`, `timestamp`, `model`, `decision`, `context`, and `upstream_signature`. v1.0 already declares `additionalProperties: true` on the record, so structurally the field is legal under v1.0 — v1.1 adds a normative shape and validation contract for it.

### 3.2 Envelope shape

The `agent_identity` envelope is the Specora cert format `specora-aid-cert-v1`. Defined inline in [`docs/schemas/canonical-bundle-v1.1.json`](schemas/canonical-bundle-v1.1.json) under `$defs/agent_identity_envelope` and equivalent to the standalone schema [`docs/schemas/agent-identity-v1.json`] (Phase 1).

```json
{
  "format": "specora-aid-cert-v1",
  "subject": {
    "identity_id": "<UUID>",
    "org_id": "<UUID>",
    "agent_id": "<vendor-supplied stable string>"
  },
  "principal": {
    "id": "<owner identifier; today the org_id>",
    "public_key": "<64-char hex Ed25519 pubkey of the OWNER>"
  },
  "issuer": {
    "common_name": "Specora Demo Root",
    "organizational_unit": "for-demo-only-not-production",
    "organization": "Specora"
  },
  "public_key": "<64-char hex Ed25519 pubkey of the AGENT>",
  "issuer_key_fingerprint": "<sha256 hex of issuer raw pubkey>",
  "issued_at": "2026-05-08T12:00:00Z",
  "not_after": "2026-06-07T12:00:00Z",
  "signature": "<base64 Ed25519 signature over canonical JSON of envelope minus this field>"
}
```

The envelope carries two distinct identity blocks. `subject` identifies the **agent** (within an org). `principal` identifies the **owner** that the agent acts on behalf of, including the owner's Ed25519 public key — used by runtime authorization networks (HonorNet) to verify owner-signed mandates per the three-part authorization presentation (HonorNet ADR-009 / Specora [ADR-PLATFORM-009](https://github.com/SpecoraAI/specora-platform/blob/staging/docs/platform/adr/ADR-PLATFORM-009-AGENT-IDENTITY-OWNER-PUBLIC-KEY.md)). Specora attests the principal public key; Specora does not custody it and never sees or evaluates mandates.

Every envelope MUST carry the `format = "specora-aid-cert-v1"` discriminator. The wire identifier is the same in both the prelaunch (DEMO-ROOT) and the future production (C01-rooted) issuance lanes; lane separation is enforced by the pinned `issuer_key_fingerprint`, not by the format string. Relying parties pin the issuer key they trust and reject envelopes signed by any other.

### 3.3 Validation rules (verifier-side)

The v1.1 validator at [`specora_verify/wire_spec.py:validate_bundle_v1_1`](../specora_verify/wire_spec.py) implements:

1. **Iterate** `bundle["records"]`. For each record:
   - If `agent_identity` is absent → record verdict = `absent` (legal, not a failure).
   - If `agent_identity` is present → call [`specora_verify.agent_identity.validate_agent_identity_certificate`](../specora_verify/agent_identity.py) with the out-of-band issuer pubkey.
2. **Aggregate** per-record verdicts. The bundle is `valid` iff every record's verdict is `absent` or `valid`. A single `invalid` verdict flips the whole bundle to `valid=False`.

The underlying cert validator (Phase 1) checks five things:

1. `format == "specora-aid-cert-v1"`.
2. `issuer_key_fingerprint` matches the SHA-256 of the supplied issuer pubkey.
3. The Ed25519 signature verifies over canonical JSON of the envelope minus its `signature` field.
4. `now` is in `[issued_at, not_after)`.
5. `principal` block is present and well-formed (`{id: non-empty string, public_key: 64-hex-char string}`).

Tampering with any field — including the `principal` block — flips the verdict to `invalid`. Because the signature covers canonical JSON of the full envelope, swapping the owner public key or owner id without re-signing produces a `signature does not verify` failure.

### 3.4 Out-of-band issuer key delivery

The verifier never contacts Specora to fetch the issuer pubkey. Relying parties pin the DEMO-ROOT issuer pubkey out-of-band — typical delivery is via a config value supplied with the deployment, or an entry in a transparency log when AID-980 ships. For the demo build the issuer pubkey is published alongside each vector set under `vectors/agent-identity/ISSUER.json` and `vectors/canonical-bundle/with-agent-identity/ISSUER.json`.

---

## 4. Versioning policy

Per [`versioning-policy.md`](versioning-policy.md):

- **MAJOR** — would have been required if the canonicalization algorithm or signing algorithm changed. Neither did. v1.x compat preserved.
- **MINOR** — a new optional property defined under `$defs/agent_identity_envelope`. v1.0 producers are unaffected.
- **PATCH** — would apply to schema clarifications without semantic change.

The Frozen Canonicalizer remains at v1.0.0. SHA-256 byte-equality of v1.0 vectors is preserved — adding an optional property does not change the bytes a v1.0 producer emits.

---

## 5. Demo-lane discipline (binding throughout)

- **Out-of-band always** — the verifier never contacts Specora at action time, regardless of v1.1 adoption.
- **Adoption opt-in** — no v1.0 customer is forced to adopt v1.1. New surface is purely additive.
- **DEMO-ROOT marker preserved** — issuer subject CN/OU/O always names the demo authority. No production root is exposed by v1.1.
- **No banned phrases** — v1.1 spec text observes the AID program kill list documented in the platform repo's banned-phrases audit (Appendix C). v1.1 is the **issuer** surface, not an inline authorization surface; framing follows that distinction throughout.
- **Banner** — every demo deployment that produces v1.1 bundles renders the "DEMO PREVIEW — NOT PRODUCT — Synthetic data only" banner per the freeze-exception §3.2.

---

## 6. Reference implementations

- **Schema** — [`docs/schemas/canonical-bundle-v1.1.json`](schemas/canonical-bundle-v1.1.json)
- **Validator (Apache 2.0)** — [`specora_verify/wire_spec.py`](../specora_verify/wire_spec.py)
- **AID-910 cert validator (Phase 1)** — [`specora_verify/agent_identity.py`](../specora_verify/agent_identity.py)
- **Conformance tests** — [`tests/test_wire_spec_schemas.py`](../tests/test_wire_spec_schemas.py), [`tests/test_wire_spec_v1_1.py`](../tests/test_wire_spec_v1_1.py)
- **Golden vectors** — `vectors/canonical-bundle/with-agent-identity/`

---

## 7. Change log

- **v1.1.0 (2026-05-08)** — first demo-lane revision. Adds optional `agent_identity` field on records. Forward-compat with v1.0 ratified by `tests/test_wire_spec_schemas.py` running every v1.0 vector against the v1.1 schema. CSEA-SUPPRESS-2026-05-08-002.
