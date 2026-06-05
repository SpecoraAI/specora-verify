# Specora Canonical Evidence Bundle v1.0 — Schema

**Status:** Normative. Ratified 2026-04-15.
**Version:** 1.0.0
**License:** Apache 2.0 (same as the `specora-verify` repository)
**Canonical location:** `docs/canonical-bundle-schema-v1.0.md` in [`SpecoraAI/specora-verify`](https://github.com/SpecoraAI/specora-verify)
**Machine-readable schema:** [`docs/schemas/canonical-bundle-v1.0.json`](schemas/canonical-bundle-v1.0.json)
**Companion spec:** [Specora Wire Spec v1.0](wire-spec-v1.0.md)

> This document describes a contract that already ships. It is the normative schema for the **in-memory canonical evidence bundle** — the shape every provider reader's `bundle_payload` satisfies before signing and ledger persistence. It does **not** replace [wire-spec-v1.0.md](wire-spec-v1.0.md); it complements it. The wire spec covers the seven signed/serialized payload types that cross the network. This document covers the single pre-signing data structure the normalizer produces out of heterogeneous provider outputs.

---

## 1. Why this document exists

Specora readers ingest wildly different upstream formats:

- Anthropic Compliance API — line-delimited JSON, per-record Ed25519 signatures
- AWS CloudTrail (Bedrock AR Checks) — `{"Records": [...]}` envelope, no per-event signatures (integrity at the log-file-validation layer)
- Azure Confidential Ledger — planned
- OpenAI Compliance Platform — planned
- LangSmith Fleet export — planned

Five readers producing five different output shapes is five products. One **canonical evidence bundle** shape is a *category*. This document defines that shape so that:

1. A developer contributing a new reader has a single target to map onto.
2. The platform-side normalizer (`prspec_api.evidence_ledger.normalizer`) can round-trip any provider's bundle through the Frozen Canonicalizer and the evidence ledger with no provider-specific branching at the write path.
3. An auditor, regulator, or downstream verifier consuming a bundle does so against a single schema regardless of upstream.

The wire spec ([wire-spec-v1.0.md](wire-spec-v1.0.md)) describes what a signed, serialized Specora payload looks like on disk or across the network. This document describes what the **normalizer input** looks like. The two are related: the content under §2 below is eventually embedded into a wire-spec payload type (typically the Attestation Manifest's record set, §2.2 of the wire spec) once signed. But they are not the same shape.

---

## 2. Data model

A canonical evidence bundle is a JSON object with exactly two top-level fields: `metadata` and `records`. Extra top-level fields are not permitted (`additionalProperties: false` at the root).

### 2.1 `metadata`

Producer-side housekeeping. The normalizer copies `metadata` verbatim from the reader's output.

| Field | Type | REQUIRED | Constraints |
|---|---|---|---|
| `provider` | string | MUST | Reader registry key (e.g. `"anthropic"`, `"cloudtrail"`). |
| `reader` | string | MUST | Fully-qualified reader module path. MUST match pattern `^specora_verify\.readers\.[a-z0-9_]+$`. |
| `reader_version` | string | MUST | SemVer `MAJOR.MINOR.PATCH`. |
| `key_id` | string | MUST | Specora signing key ID under which the bundle will be signed. |
| `upstream_schema_version` | string | MUST | Upstream provider schema version observed at read time. |
| `record_count` | integer ≥ 0 | MUST | MUST equal `len(records)`. |
| `content_hash` | string | MUST | SHA-256 over `canonical_json_bytes({"records": records})`, prefixed `sha256:`. See §4. |

No other fields are permitted inside `metadata`.

### 2.2 `records`

Array of zero or more record objects. Each record captures one upstream decision event (one Claude inference, one Bedrock invocation, one LangSmith run, etc.) mapped onto a provider-neutral shape.

| Field | Type | REQUIRED | Constraints |
|---|---|---|---|
| `id` | string | MUST | Stable upstream record identifier (`record_id`, `eventID`, etc.). |
| `timestamp` | string | MUST | RFC 3339 UTC with mandatory `Z` suffix, no fractional seconds. Pattern: `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`. |
| `model` | object | MUST | `{name, version}`. Both strings. `version` MAY be empty if the upstream ID has no detectable version suffix. |
| `decision` | object | MUST | See §2.3. |
| `context` | object | MUST | `{hash}`. `hash` MUST match `^sha256:[0-9a-f]{64}$`. |
| `upstream_signature` | object | MUST | One of two shapes. See §2.4. |
| `upstream_request_id` | string | OPTIONAL | Provider request ID, when present. |
| `upstream_event_name` | string | OPTIONAL | Provider event name (e.g. CloudTrail `eventName`). |
| `aws_region` | string | OPTIONAL | AWS region, CloudTrail readers only. |
| `tool_invocations` | array of object | OPTIONAL | Provider tool-call traces, preserved verbatim. |

Records MAY carry additional provider-specific fields at the top level; these are preserved verbatim through normalization and ledger persistence but are not interpreted by downstream tooling. New well-known optional fields are added by appending to this table in a v1.x revision.

### 2.3 `decision`

| Field | Type | REQUIRED | Constraints |
|---|---|---|---|
| `outcome` | string enum | MUST | One of `"approved"`, `"rejected"`, `"deferred"`, `"escalated"`. |
| `policy_refs` | array of non-empty string | MUST | Producer policy identifiers referenced by the decision. MAY be empty. |
| `formal_verdict` | string | OPTIONAL | Provider-side formal result (e.g. Bedrock AR Checks `verdict`). |
| `proof_hash` | string | OPTIONAL | SHA-256 of the provider-side proof payload, prefixed `sha256:`. |
| `constraints` | array of string | OPTIONAL | Provider logical constraints (e.g. AR Checks `logicalConstraints`). |

No other fields are permitted inside `decision`.

### 2.4 `upstream_signature`

Per-record upstream integrity evidence. Records take exactly one of two shapes (JSON Schema `oneOf`).

**Shape A — per-record signature (Anthropic, OpenAI, LangSmith):**

| Field | Type | REQUIRED | Constraints |
|---|---|---|---|
| `alg` | string enum | MUST | MUST be `"ed25519"` in v1.0. |
| `key_id` | string | MUST | Upstream signing key identifier. |
| `value` | string | MUST | Base64-encoded signature bytes. |

**Shape B — log-level integrity (CloudTrail):**

| Field | Type | REQUIRED | Constraints |
|---|---|---|---|
| `absent_per_record` | boolean | MUST | MUST be `true`. |
| `integrity_mechanism` | string | MUST | Name of the upstream integrity mechanism (e.g. `"cloudtrail-log-file-validation"`). |
| `digest_file_ref` | string | OPTIONAL | Path or URL to the upstream digest file, if recorded. |

A producer that has neither per-record signatures nor a log-level integrity mechanism SHOULD NOT ship a reader in v1.0.

---

## 3. Canonicalization primitive

All canonicalization in this schema is performed by the **Frozen Canonicalizer v1.0.0**, ratified 2026-03-04, in the platform monorepo at `services/prspec-api/src/prspec_api/agent_execution/canonicalizer.py` (first landed in commit [`a0b1af5e`](https://github.com/SpecoraAI/specora-platform/commit/a0b1af5e) and formalized in [Specora Wire Spec v1.0 §4](wire-spec-v1.0.md#4-canonical-json-encoding)). The Lean mechanized proof of the canonicalizer's contract lives at [`formal/lean/Specora/Canonicalizer.lean`](https://github.com/SpecoraAI/specora-platform/blob/staging/formal/lean/Specora/Canonicalizer.lean).

Readers in this repository reimplement the byte-level contract in [`specora_verify/canonical.py`](../specora_verify/canonical.py). The platform-side normalizer (`prspec_api.evidence_ledger.normalizer`) and the verifier MUST produce **byte-identical** canonical JSON for the same input; this is enforced by [`tests/test_canonical.py`](../tests/test_canonical.py) in this repo and by the platform-side property tests.

### 3.1 The five canonicalization rules

Reproduced from Wire Spec v1.0 §4.1 for completeness; the wire spec is the normative reference.

1. **Object keys** sorted alphabetically at every nesting level.
2. **No whitespace** between tokens (`separators=(",", ":")`).
3. **Non-ASCII characters** escaped as `\uXXXX` (ensure_ascii=True).
4. **No NaN, no Infinity** — rejected with an error.
5. **Primitive type coercions** (applied before serialization):
   - `datetime` → UTC with `Z` suffix, no microseconds (`YYYY-MM-DDTHH:MM:SSZ`)
   - `Decimal` → normalized decimal string (never `float`)
   - `UUID` → lowercase string
   - `Enum` → `.value` string
   - `bytes` → base64
   - `set` → sorted list
   - `date` → ISO 8601

### 3.2 `metadata.content_hash` derivation

The `metadata.content_hash` field is the producer's self-attestation of the records payload:

```
content_hash = "sha256:" + hex(SHA-256(canonical_json_bytes({"records": records})))
```

It is computed over **only** the `records` array wrapped in a single-key object — `metadata` itself is not part of the hash because `metadata.content_hash` lives inside `metadata`. A verifier recomputing the content hash MUST use the same derivation.

The outer Specora signature (applied by the platform signer during bundle seal) covers the whole bundle, including `metadata.content_hash`, giving two tiers of integrity: one producer-computed tier inside the bundle (`content_hash`) and one signer-computed tier outside (the wire-spec envelope's detached signature).

---

## 4. Determinism and equivalence

A canonical evidence bundle is **deterministic in the strong sense**: given identical reader input and identical parameters (`key_id`, `schema_version`, `strict`), a reader MUST produce a byte-identical bundle across runs, Python versions, and operating systems. This is a load-bearing invariant for the verifier's replay model and is enforced by:

- Hypothesis property tests in [`tests/test_canonical.py`](../tests/test_canonical.py)
- Per-reader round-trip tests in [`tests/readers/`](../tests/readers/)
- Schema conformance tests in [`tests/schema/test_canonical_bundle_compliance.py`](../tests/schema/test_canonical_bundle_compliance.py) (added by EPIC-B02)
- Platform-side property tests in `services/prspec-api/tests/evidence_ledger/test_normalizer.py` (EPIC-B02)

Two bundles are **canonically equivalent** if and only if their `canonical_json_bytes` are byte-identical. This is the only notion of equivalence used by the verifier. String-level equivalence (e.g. different key ordering in a non-canonical JSON representation) is irrelevant and explicitly not covered by this spec.

---

## 5. Relationship to the wire spec

| Concern | Canonical Bundle (this doc) | Wire Spec v1.0 |
|---|---|---|
| Shape | In-memory normalized representation | On-the-wire signed payload types |
| Lifetime | Transient, pre-signing | Persistent, post-signing |
| Consumers | Normalizer, signer | Verifier, auditor, ledger reader |
| Signature | Not yet signed | Detached Ed25519 + envelope |
| Cardinality | One per reader invocation | Seven payload types per bundle set |

When a canonical evidence bundle is signed and persisted, its `records` array is typically embedded as the record set of an [Attestation Manifest](wire-spec-v1.0.md#22-attestation-manifest-attestation-manifest) (wire spec §2.2), with `metadata` copied into the manifest's producer metadata block. The exact embedding is governed by the wire spec and the platform-side signing service (`prspec_api.evidence_ledger.normalizer_service`).

---

## 6. Versioning

This schema follows the **SemVer lock-step** rule established in [versioning-policy.md](versioning-policy.md): the canonical bundle schema version tracks the wire spec version. A breaking change to this schema requires a wire spec major bump and an explicit migration plan for any producer already in the field. v1.x additions MUST be purely additive (new optional fields) and MUST NOT remove or tighten existing constraints.

---

## 7. Change log

- **1.0.0 (2026-04-15)** — Initial publication. Introduces canonical evidence bundle shape covering the Anthropic Compliance API and AWS CloudTrail Lake readers as shipped. Landed alongside the platform-side normalizer under EPIC-B02.
