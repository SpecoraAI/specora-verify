# Specora Wire Spec v1.0

**Status:** Normative. Ratified 2026-04-15.
**Version:** 1.0.0
**License:** Apache 2.0 (same as the `specora-verify` repository)
**Canonical location:** `docs/wire-spec-v1.0.md` in [`SpecoraAI/specora-verify`](https://github.com/SpecoraAI/specora-verify)
**Editor of record:** Specora Engineering lead + Formal methods reviewer

> This document describes a contract that already ships. It does not propose changes. If the spec and the reference implementation disagree, the reference implementation wins and the spec is amended to match — see [§10 change log](#10-change-log) and [versioning-policy.md](versioning-policy.md).

---

## 1. Overview

### 1.1 What this spec is

Specora Wire Spec v1.0 defines the on-the-wire format of **Specora evidence bundles**: the signed, canonical JSON documents that an independent verifier (`specora-verify`) consumes to produce a third-party-acceptable audit opinion about an AI system's governance posture.

Every evidence bundle conforming to this spec consists of one or more of seven canonical payload types (§2), each canonicalized according to a deterministic JSON encoding (§3), hashed with SHA-256 (§5), and — where applicable — signed with Ed25519 (§4). A verifier can check a bundle end-to-end without contacting the producer, without a network call, and without trusting any party other than whoever holds the root signing key.

### 1.2 What this spec is not

- Not an RFC-style IETF submission. v1.0 is a **practical contract**, not an IETF standard. An RFC track is Horizon C work.
- Not a complete formal grammar. A formal grammar may land in v1.1 if needed.
- Not a streaming format. Streaming / incremental verification is deferred.
- Not an inline-enforcement / guardrail contract. Specora is an **out-of-band** verifier; policy enforcement belongs in the producer.
- Not versioning guidance for customer integrations. That lives in [versioning-policy.md](versioning-policy.md).

### 1.3 Normative language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

### 1.4 Structural audit-doctrine framing

This spec exists because Specora is structurally the auditor and cannot also be the producer. The trust-bootstrap model (Big 4 auditors, NRSRO credit raters, Web PKI, EU AI Act Notified Bodies — see [trust-model.md](trust-model.md)) requires a document the producer **cannot** rewrite. That is why the canonical copy lives in a public git repository with signed commits and PR review, not behind a subdomain Specora can silently mutate.

---

## 2. Data model

A Specora evidence bundle is a set of files on disk (or equivalent in-memory objects). Each file belongs to exactly one of seven canonical payload types. All seven are already present as golden vectors in [`vectors/`](../vectors/) and are the normative reference for the field definitions below.

### 2.1 Summary table

| # | Payload type | `spec_id` field | Schema file | Vector location |
|---|---|---|---|---|
| 1 | Attestation Manifest | `attestation-manifest` | [`schemas/attestation-manifest-v1.0.json`](schemas/attestation-manifest-v1.0.json) | [`vectors/manifest/attestation-manifest-1.0.0.canonical.json`](../vectors/manifest/attestation-manifest-1.0.0.canonical.json) |
| 2 | Proof Manifest | `proof-manifest` | [`schemas/proof-manifest-v1.0.json`](schemas/proof-manifest-v1.0.json) | [`vectors/manifest/proof-manifest-1.0.0.canonical.json`](../vectors/manifest/proof-manifest-1.0.0.canonical.json) |
| 3 | Anchor Payload | `anchor-payload` | [`schemas/anchor-payload-v1.0.json`](schemas/anchor-payload-v1.0.json) | [`vectors/anchor/anchor-payload-1.0.0.canonical.json`](../vectors/anchor/anchor-payload-1.0.0.canonical.json) |
| 4 | Anchor Receipt | `anchor-receipt` | [`schemas/anchor-receipt-v1.0.json`](schemas/anchor-receipt-v1.0.json) | [`vectors/anchor-receipts/anchor-receipt-1.0.0.canonical.json`](../vectors/anchor-receipts/anchor-receipt-1.0.0.canonical.json) |
| 5 | Certification Attestation | `certification-attestation` | [`schemas/certification-attestation-v1.0.json`](schemas/certification-attestation-v1.0.json) | [`vectors/certification/certification-attestation-1.0.0.canonical.json`](../vectors/certification/certification-attestation-1.0.0.canonical.json) |
| 6 | STP Certification Attestation | `stp-certification-attestation` | [`schemas/stp-certification-attestation-v1.0.json`](schemas/stp-certification-attestation-v1.0.json) | [`vectors/stp-certification/compatible/stp-certification-attestation-1.0.0.canonical.json`](../vectors/stp-certification/compatible/stp-certification-attestation-1.0.0.canonical.json) |
| 7 | Signed Artifact Envelope | `governance-attestation` (example) | [`schemas/signed-artifact-envelope-v1.0.json`](schemas/signed-artifact-envelope-v1.0.json) | [`vectors/signature/signed-artifact-001/`](../vectors/signature/signed-artifact-001/) |

Bundles typically reference multiple payload types together: a producer emits an Attestation Manifest + Proof Manifest for a period, anchors them via an Anchor Payload + Anchor Receipt, then optionally wraps everything in a Certification Attestation or STP Certification Attestation for a specific compliance tier. The Signed Artifact Envelope (§2.8) describes the wrapper format that carries any payload alongside its detached signature.

### 2.2 Attestation Manifest (`attestation-manifest`)

A time-window snapshot of governance state for a single organization. Emitted by the producer at snapshot time; consumed by the verifier as the root object for a verification run.

| Field | Type | REQUIRED | Constraints |
|---|---|---|---|
| `id` | string (UUID v4, lowercase) | MUST | Unique per snapshot. |
| `org_id` | string (UUID v4, lowercase) | MUST | Identifies the producing organization. |
| `snapshot_type` | string enum | MUST | MUST be `"window"` in v1.0. Future snapshot types require a v1.1 extension. |
| `period_start` | string (RFC 3339 UTC `Z`) | MUST | Inclusive. MUST use the `Z` suffix. MUST NOT include fractional seconds. |
| `period_end` | string (RFC 3339 UTC `Z`) | MUST | Exclusive-or-inclusive per producer convention; MUST be ≥ `period_start`. |
| `created_at` | string (RFC 3339 UTC `Z`) | MUST | Wall-clock timestamp at which the manifest was finalized. |

See [`schemas/attestation-manifest-v1.0.json`](schemas/attestation-manifest-v1.0.json) for the normative field definitions and [`vectors/manifest/attestation-manifest-1.0.0.canonical.json`](../vectors/manifest/attestation-manifest-1.0.0.canonical.json) for the golden example.

### 2.3 Proof Manifest (`proof-manifest`)

The root commitment for a set of ledger leaves over a period. Carries the Merkle root that the Anchor Payload will commit to an external transparency log.

| Field | Type | REQUIRED | Constraints |
|---|---|---|---|
| `id` | string (UUID v4, lowercase) | MUST | |
| `org_id` | string (UUID v4, lowercase) | MUST | |
| `period_start` | string (RFC 3339 UTC `Z`) | MUST | |
| `period_end` | string (RFC 3339 UTC `Z`) | MUST | |
| `leaf_count` | integer ≥ 0 | MUST | Number of ledger leaves included in the Merkle root. |
| `root_hash` | string (lowercase hex, 64 chars) | MUST | SHA-256 Merkle root over ledger leaves. |
| `root_type` | string enum | MUST | MUST be `"daily"` in v1.0. |
| `created_at` | string (RFC 3339 UTC `Z`) | MUST | |

### 2.4 Anchor Payload (`anchor-payload`)

The exact bytes an external transparency log commits to. Carries enough metadata that a third party can recompute and confirm the anchor without access to any Specora-internal state.

| Field | Type | REQUIRED |
|---|---|---|
| `payload_schema_version` | string (`"1.0.0"` in v1.0) | MUST |
| `org_id` | string (UUID) | MUST |
| `period_start` / `period_end` | string (RFC 3339 UTC `Z`) | MUST |
| `first_seq` / `last_seq` | integer ≥ 0, `last_seq ≥ first_seq` | MUST |
| `leaf_count` | integer ≥ 0 | MUST |
| `manifest_spec_id` | string | MUST | MUST be `"proof-manifest"` in v1.0. |
| `manifest_schema_version` | string | MUST |
| `manifest_hash` | string (lowercase hex, 64 chars) | MUST | SHA-256 over the canonical form of the referenced Proof Manifest. |
| `root_hash` | string (lowercase hex, 64 chars) | MUST | Merkle root; MUST equal the referenced Proof Manifest's `root_hash`. |
| `root_type` | enum (`"daily"` in v1.0) | MUST |
| `hash_algorithm` | string (`"sha256"` in v1.0) | MUST |
| `hash_algorithm_version` | string | MUST |
| `ledger_hash_algorithm` | string (`"sha256"` in v1.0) | MUST |
| `ledger_hash_algorithm_version` | string | MUST |

### 2.5 Anchor Receipt (`anchor-receipt`)

The transparency-log response evidencing a successful anchor commit.

| Field | Type | REQUIRED |
|---|---|---|
| `schema_version` | string (`"1.0.0"`) | MUST |
| `spec_id` | string (`"anchor-receipt"`) | MUST |
| `org_id` | string (UUID) | MUST |
| `receipt_id` | string | MUST | Opaque transparency-log receipt identifier. |
| `anchor_backend` | string | MUST | e.g. `"transparency_log"`. |
| `transparency_log_index` | integer ≥ 0 | MUST |
| `payload_hash` | string (lowercase hex, 64 chars) | MUST | SHA-256 over the canonical Anchor Payload bytes. |
| `receipt_signature` | string (base64) | MUST | Signature issued by the anchor backend. |
| `receipt_timestamp` | string (RFC 3339 UTC `Z`) | MUST |
| `hash_algorithm` | string (`"sha256"`) | MUST |
| `hash_algorithm_version` | string | MUST |

### 2.6 Certification Attestation (`certification-attestation`)

Wraps a Specora enterprise-tier certification: which requirements were met, which evidence hashes prove them, which tool versions verified.

| Field | Type | REQUIRED |
|---|---|---|
| `schema_version` | string (`"1.0.0"`) | MUST |
| `spec_id` | string (`"certification-attestation"`) | MUST |
| `tier` | enum (`"enterprise"` in v1.0) | MUST |
| `integration` | object `{name, vendor_id, version}` | MUST |
| `issued_at` | string (RFC 3339 UTC `Z`) | MUST |
| `requirements_met` | array[string] | MUST | RCP identifiers (e.g. `"RCP-100"`). |
| `requirements_missing` | array[string] | MUST | MAY be empty. |
| `evidence_hashes` | object | MUST | Keys: `anchor_payload`, `anchor_receipt`, `attestation_manifest`, `proof_manifest`, `verification_output`, `meta`. Values: lowercase hex, 64 chars each. |
| `ci_badges` | array[string] | MUST | MAY be empty. Each entry is a URL. |
| `proof_surface_url` | string (URL) | MUST |
| `verified_by` | object `{specora_verify_version, node_verifier_commit}` | MUST |
| `notes` | string or null | MUST | MAY be null. |

### 2.7 STP Certification Attestation (`stp-certification-attestation`)

Wraps a Specora Trust Protocol (STP) compatibility attestation: a compatibility tier (`"compatible"` in v1.0) against the STP requirements matrix.

| Field | Type | REQUIRED |
|---|---|---|
| `schema_version` | string (`"1.0.0"`) | MUST |
| `spec_id` | string (`"stp-certification-attestation"`) | MUST |
| `tier` | enum (`"compatible"` in v1.0) | MUST |
| `protocol_version` | string (`"1.0.0"`) | MUST |
| `adapter` | object `{name, version}` | MUST |
| `issuer_key_id` | string | MUST | e.g. `"specora-root-key"`. |
| `bundle_root_hash` | string (lowercase hex, 64 chars) | MUST |
| `evidence_hashes` | object | MUST | Keys: `meta`, plus one key per evidence artifact. Values: lowercase hex, 64 chars. |
| `requirements_met` | array[string] | MUST | `STP-REQ-*` identifiers. |
| `requirements_missing` | array[string] | MUST |
| `proof_surface_url` | string (URL) | MUST |
| `issued_at` | string (RFC 3339 UTC `Z`) | MUST |

### 2.8 Signed Artifact Envelope

The on-disk layout that pairs any canonical payload with its detached Ed25519 signature and verification metadata. See [`vectors/signature/signed-artifact-001/`](../vectors/signature/signed-artifact-001/) for the reference layout.

| File | Purpose | REQUIRED |
|---|---|---|
| `artifact.canonical.json` | Canonical form of the payload (§3). | MUST |
| `artifact.json` | Pretty-printed human-readable copy. | SHOULD | MAY be omitted for non-interactive pipelines. |
| `artifact.sha256.txt` | SHA-256 of `artifact.canonical.json` bytes, lowercase hex, 64 chars, **no** `sha256:` prefix. | MUST |
| `signature.b64` | Base64-encoded Ed25519 signature (§4). | MUST |
| `pubkey.pem` | PEM-encoded Ed25519 public key. | MUST | PEM form is REQUIRED; raw and base64 forms are OPTIONAL companions. |
| `pubkey.b64` | Base64-encoded raw public key bytes (32 bytes → 44 base64 chars). | SHOULD |
| `metadata.json` | Object with `key_fingerprint_sha256`, `derived_key_id`, `signing_algorithm`, `hash_algorithm`, `signature_covers`, `note`. | MUST |

---

## 3. Canonicalization

### 3.1 Normative rule

Every payload defined in §2 has a single canonical byte sequence. The canonical form is produced by the following algorithm:

```
canonical(x) :=
    utf8_bytes(
        json.dumps(
            sort_keys_recursive(x),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    )
```

Where `sort_keys_recursive` walks the object tree and sorts every `dict` by key using Python's default Unicode code-point ordering. Lists retain their original order (lists are ordered containers; reordering them is a semantic change, not a canonicalization).

### 3.2 Field-level rules

1. **Key ordering.** Object keys MUST be sorted lexicographically by Unicode code point at every level.
2. **Separators.** JSON MUST use the compact separators `,` and `:` with no whitespace. Pretty-printing is forbidden in canonical form.
3. **Unicode.** Non-ASCII characters MUST be escaped as `\uXXXX`. The canonical form is pure ASCII. This matches `ensure_ascii=True`.
4. **Numbers.** `NaN`, `Infinity`, `-Infinity` are forbidden (`allow_nan=False`). Floats MUST be finite. Integers MUST be serialized without a fractional component.
5. **Trailing bytes.** There MUST be no trailing newline. The canonical form is exactly `len(output)` bytes.
6. **Types.** Specora-producer types that are not native JSON (datetime, Decimal, UUID, bytes, Enum) MUST be converted to their canonical JSON form **before** canonicalization:
   - `datetime` → RFC 3339 UTC with `Z` suffix, no fractional seconds (`YYYY-MM-DDTHH:MM:SSZ`).
   - `Decimal` → normalized decimal string. Never a float.
   - `UUID` → lowercase string (RFC 4122).
   - `bytes` → base64 string.
   - `Enum` → the enum member's `value` attribute.

### 3.3 Reference implementations

- **Producer side:** [`services/prspec-api/src/prspec_api/agent_execution/canonicalizer.py`](https://github.com/SpecoraAI/specora-platform/blob/a0b1af5e11110357bd821aca0eed86a967b9010e/services/prspec-api/src/prspec_api/agent_execution/canonicalizer.py) (Frozen Canonicalizer v1.0.0, ratified 2026-03-04, commit `a0b1af5e`). The constant `CANONICALIZER_VERSION = "1.0.0"` is the normative version marker.
- **Verifier side:** [`specora_verify/canonical.py`](../specora_verify/canonical.py) in this repo.

The two MUST produce byte-identical output on the intersection of their input types (primitives and containers). Any divergence is a bug in the verifier side — the producer side is frozen.

### 3.4 Relationship to JCS (RFC 8785)

The algorithm in §3.1 is **compatible with** RFC 8785 (JSON Canonicalization Scheme) on all ASCII inputs with finite numbers and no nested object-valued keys. v1.0 explicitly does **not** claim RFC 8785 conformance because:

- v1.0 forbids `NaN`/`Infinity` (RFC 8785 also forbids them — compatible).
- v1.0 uses `\uXXXX` for all non-ASCII characters; RFC 8785 keeps them as UTF-8 bytes. **This is a deliberate deviation.** Rationale: `ensure_ascii=True` produces an ASCII-only byte sequence that survives any transport layer that is not 8-bit clean without re-encoding. This is the dominant failure mode for audit evidence in transit.
- v1.0 number canonicalization relies on Python's `json.dumps` defaults, which are deterministic for integers and for most floats in the producer's input distribution. RFC 8785 number canonicalization is more rigorous. A future v1.1 **MAY** tighten the number rule to match RFC 8785 if the producer ever needs to emit non-integer numerics (currently it does not — all observed payload fields are integers, strings, or strings-typed numerics via `Decimal` → string).

v1.1 **MAY** add an `--rfc8785` mode for producers that need strict JCS interop. v1.0 does not.

### 3.5 Lean proof

The canonicalization determinism invariant is formally proven in [`formal/lean/Specora/Canonicalizer.lean`](https://github.com/SpecoraAI/specora-platform/blob/f9f7e574895ef2c42803b9c1206ba820b2739861/formal/lean/Specora/Canonicalizer.lean) (commit `f9f7e574`). The proof covers invariants `INV-AGENT-SEAL-001`, `INV-VERIFY-001`, `INV-VERIFY-002` — alphabetic key sorting, no-whitespace compaction, Unicode normalization — against the Python reference implementation. The Lean proof is a normative companion to this spec: any change to §3.2 that invalidates the proof is a v2.0 break, not a v1.x evolution.

---

## 4. Signing

### 4.1 Algorithm

**Ed25519 (RFC 8032).** No other algorithms are permitted in v1.0. This is a deliberate simplification — the spec exists to **reduce** verification surface area, not to negotiate parameters.

### 4.2 Signature envelope

A signature covers the canonical byte form of a payload's SHA-256 hex digest, UTF-8 encoded. Specifically:

```
content_to_sign = utf8_bytes(hex(sha256(canonical(payload))))
signature       = ed25519_sign(private_key, content_to_sign)
```

The `signature_covers` field of `metadata.json` (§2.8) MUST record the exact rule used. In v1.0 the only permitted value is `"manifest_hash_utf8"`, meaning "the UTF-8 bytes of the lowercase hex SHA-256 of the canonical payload bytes." A different `signature_covers` value indicates a v1.1+ envelope.

Rationale for signing the hex-encoded hash rather than the raw hash bytes: the hex form is trivially transportable in logs, CLI output, and JSON fields without base64 confusion, and reverse compatibility with auditors who paste values into tooling is a hard requirement from the trust-model framing.

### 4.3 Key identifier format

Each Ed25519 key MUST have a stable identifier derived from its public key bytes:

```
derived_key_id = "spk-" + hex(sha256(pubkey_raw_bytes))[0:16]
```

Example: `spk-e1c8139bffc31826`. The 16-hex-char truncation is enough to avoid accidental collisions in practical key registries (2^64 space) while remaining human-legible in CLI output. Producers MUST emit the derived identifier in `metadata.json`; verifiers MUST recompute it and MUST reject envelopes whose `derived_key_id` does not match the SHA-256 of the provided public key.

### 4.4 Key fingerprint

`metadata.json.key_fingerprint_sha256` MUST be the full SHA-256 hex of the raw public key bytes (64 chars). The `derived_key_id` is simply `"spk-" + fingerprint[0:16]`. Verifiers SHOULD display the full fingerprint when surfacing key information to a human auditor.

### 4.5 Verifier behavior

A conforming verifier MUST:

1. Load the public key from `pubkey.pem` (MUST) or `pubkey.b64` (OPTIONAL fallback) or `pubkey.raw` (OPTIONAL fallback).
2. Recompute `key_fingerprint_sha256` and `derived_key_id` and reject if they disagree with `metadata.json`.
3. Recompute `artifact.sha256.txt` from `artifact.canonical.json` and reject on mismatch.
4. Verify `signature.b64` against `content_to_sign` (§4.2).
5. Report a structured `SignatureVerificationResult` with explicit `valid` bool, `errors` list, and key metadata. The reference struct is [`specora_verify/signature.py::SignatureVerificationResult`](../specora_verify/signature.py).

---

## 5. Serialization and hashing

### 5.1 Character encoding

Canonical payloads MUST be UTF-8 encoded. Because canonicalization forces `ensure_ascii=True` (§3.2 rule 3), the canonical byte sequence is a strict subset of UTF-8 (pure ASCII) — any non-ASCII byte in a canonical payload is a conformance error.

### 5.2 Hash algorithm

**SHA-256** only in v1.0. Output format: **lowercase hexadecimal, 64 characters, no `sha256:` prefix, no delimiters**. This applies uniformly to `artifact.sha256.txt` files, to `manifest_hash` / `payload_hash` / `root_hash` fields inside payloads, and to the computation `hex(sha256(canonical(payload)))` referenced throughout this document.

The reference implementation is [`specora_verify/hash.py::sha256_hex`](../specora_verify/hash.py).

### 5.3 Content-addressing

Payloads are content-addressed by SHA-256 over their canonical form. This is the primary integrity mechanism. Signatures (§4) are a secondary mechanism that binds a payload's content-address to a named signing identity.

---

## 6. Versioning policy

See [`versioning-policy.md`](versioning-policy.md) for the normative version-management rules. Summary:

- **v1.0.x** — patch. Doc clarifications only. Zero normative change. Examples: fixing a typo in §2.6, tightening prose in §3.4, adding a new example under §3.2.
- **v1.1** — minor. MAY add new optional fields, new payload types, or a new `signature_covers` value. MUST include a migration note in §10 **and** MUST be accompanied by a co-updated Frozen Canonicalizer version in [`canonicalizer.py`](https://github.com/SpecoraAI/specora-platform/blob/main/services/prspec-api/src/prspec_api/agent_execution/canonicalizer.py) if the change affects canonicalization. Existing v1.0 vectors MUST still validate against v1.1 schemas.
- **v2.0** — major. Only for canonicalization changes, signing-algorithm changes, or field removals. Requires CEO + Formal methods reviewer sign-off and a documented migration path for existing bundles. v1.x vectors are NOT required to validate under v2.0 schemas.

The Frozen Canonicalizer constraint (§3.3) is the load-bearing rule: the spec cannot drift from the implementation, because the implementation is frozen and any change to it is itself a version bump.

---

## 7. Compatibility matrix

| Spec version | Schema files | Canonicalizer version | Verifier CLI minimum | Notes |
|---|---|---|---|---|
| **v1.0.0** | `schemas/*-v1.0.json` | Frozen Canonicalizer v1.0.0 (commit `a0b1af5e`) | `specora-verify` ≥ 0.1.0 (placeholder; real floor set at A01 public-flip 2026-06-14) | Initial spec. All seven payload types normative. |

Future rows are appended under v1.1, v2.0, etc. per the versioning policy.

---

## 8. Conformance

### 8.1 Producer conformance

A producer is v1.0-conformant if and only if, for every payload it emits:

1. The payload matches exactly one `spec_id` in §2.
2. The payload's canonical form (§3) validates against the corresponding schema under `docs/schemas/`.
3. If the payload is wrapped in a Signed Artifact Envelope (§2.8), the envelope layout matches §4 and the signature validates under §4.5.

### 8.2 Verifier conformance

A verifier is v1.0-conformant if and only if:

1. It accepts every well-formed v1.0 bundle and reports `valid=true` with no errors.
2. It rejects bundles where any of: the JSON Schema fails (§2), the canonicalization byte-compare fails (§3.1), the hash does not match `artifact.sha256.txt` (§5.2), the signature verification fails (§4.5), the `derived_key_id` does not match the supplied public key (§4.3).
3. It reports rejections via a structured result object that names **which** check failed. Opaque pass/fail is non-conformant.
4. It is deterministic: running the same verifier against the same bundle twice MUST produce byte-identical output (determinism is a property of the verifier, not just the canonicalizer).

### 8.3 Reader conformance

A reader (per [`docs/readers/`](readers/)) is v1.0-conformant if the bundle it produces from a provider audit log validates under §8.1 for every input the provider emits. Readers MUST NOT modify the wire format; they translate input formats to the wire format.

### 8.4 Executable conformance test

The test [`tests/test_wire_spec_schemas.py`](../tests/test_wire_spec_schemas.py) loads every schema under `docs/schemas/` and validates every canonical vector under `vectors/`. This test is the executable statement of §8.1 conformance for the seven golden vectors and is the CI gate that this spec is **not** aspirational.

---

## 9. Normative and informative references

### 9.1 Normative (required to implement the spec)

- **RFC 2119** — Key words for use in RFCs to Indicate Requirement Levels.
- **RFC 8174** — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- **RFC 4122** — A Universally Unique IDentifier (UUID) URN Namespace.
- **RFC 3339** — Date and Time on the Internet: Timestamps.
- **RFC 8032** — Edwards-Curve Digital Signature Algorithm (EdDSA). Specifically, Ed25519.
- **FIPS 180-4** — Secure Hash Standard (SHS). Specifically, SHA-256.
- **RFC 4648** — The Base16, Base32, and Base64 Data Encodings.
- **[`specora_verify/canonical.py`](../specora_verify/canonical.py)** — verifier-side reference implementation of §3.
- **[`specora_verify/signature.py`](../specora_verify/signature.py)** — verifier-side reference implementation of §4.
- **[`specora_verify/hash.py`](../specora_verify/hash.py)** — verifier-side reference implementation of §5.
- **Frozen Canonicalizer v1.0.0** — producer-side reference at [`canonicalizer.py`](https://github.com/SpecoraAI/specora-platform/blob/a0b1af5e11110357bd821aca0eed86a967b9010e/services/prspec-api/src/prspec_api/agent_execution/canonicalizer.py), commit `a0b1af5e`.
- **Lean canonicalizer proof** — formal companion at [`Canonicalizer.lean`](https://github.com/SpecoraAI/specora-platform/blob/f9f7e574895ef2c42803b9c1206ba820b2739861/formal/lean/Specora/Canonicalizer.lean), commit `f9f7e574`.

### 9.2 Informative (useful context, not required)

- **RFC 8785** — JSON Canonicalization Scheme (JCS). The algorithm in §3 is compatible with JCS on ASCII-only inputs with finite numbers. See §3.4 for the deviation rationale.
- **RFC 6962** — Certificate Transparency. Prior art for the anchor / transparency-log pattern.
- **in-toto Attestation Framework** — prior art for detached-signature attestation envelopes.
- **[`docs/trust-model.md`](trust-model.md)** — audit-doctrine framing that motivates this spec's existence and structural shape.

---

## 10. Change log

| Version | Date | Change | Canonicalizer | Author |
|---|---|---|---|---|
| **v1.0.0** | 2026-04-15 | Initial ratified release. Seven canonical payload types (Attestation Manifest, Proof Manifest, Anchor Payload, Anchor Receipt, Certification Attestation, STP Certification Attestation, Signed Artifact Envelope). Canonicalization rules §3 fixed. Ed25519 signing envelope §4 fixed. SHA-256 hashing §5 fixed. Executable conformance test `tests/test_wire_spec_schemas.py` validates seven golden vectors. Frozen Canonicalizer v1.0.0 (commit `a0b1af5e`) is the producer-side reference. Lean proof (commit `f9f7e574`) is the formal companion. Ratified by A02 emergency remediation session (Engineering lead + Formal methods reviewer) under [`b01-reader-design-notes-2026-Q2.md §9.2`](https://github.com/SpecoraAI/specora-platform/blob/main/docs/strategy/b01-reader-design-notes-2026-Q2.md). | v1.0.0 (commit `a0b1af5e`) | Specora Engineering lead + Formal methods reviewer |
