# Golden vectors

This document is the guide to the [`vectors/`](../vectors/) tree:
what each subdirectory contains, what each file is for, how to
regenerate vectors, and how to add a new one.

Golden vectors are the **executable form** of the wire spec. If the
schemas under [`docs/schemas/`](schemas/) are the normative contract,
the vectors are the canonical instances that prove the contract is
non-vacuous. The shipped test
[`tests/test_wire_spec_schemas.py`](../tests/test_wire_spec_schemas.py)
loads every schema and validates every canonical vector on every CI
run — the combination is what makes the wire spec **falsifiable** in
CI, not merely aspirational prose.

## 1. Directory layout

```
vectors/
├── manifest/
│   ├── attestation-manifest-1.0.0.json          (pretty-printed)
│   ├── attestation-manifest-1.0.0.canonical.json
│   ├── attestation-manifest-1.0.0.sha256.txt
│   ├── proof-manifest-1.0.0.json
│   ├── proof-manifest-1.0.0.canonical.json
│   ├── proof-manifest-1.0.0.sha256.txt
│   └── README.md
├── anchor/
│   ├── anchor-payload-1.0.0.json
│   ├── anchor-payload-1.0.0.canonical.json
│   ├── anchor-payload-1.0.0.sha256.txt
│   └── README.md
├── anchor-receipts/
│   ├── anchor-receipt-1.0.0.json
│   ├── anchor-receipt-1.0.0.canonical.json
│   ├── anchor-receipt-1.0.0.sha256.txt
│   └── README.md
├── certification/
│   ├── certification-attestation-1.0.0.json
│   ├── certification-attestation-1.0.0.canonical.json
│   ├── certification-attestation-1.0.0.sha256.txt
│   └── README.md
├── stp-certification/
│   └── compatible/
│       ├── stp-certification-attestation-1.0.0.json
│       ├── stp-certification-attestation-1.0.0.canonical.json
│       └── stp-certification-attestation-1.0.0.sha256.txt
└── signature/
    ├── signed-artifact-001/
    │   ├── artifact.json              (pretty-printed payload)
    │   ├── artifact.canonical.json    (canonical bytes)
    │   ├── artifact.sha256.txt        (hex SHA-256 of canonical)
    │   ├── signature.b64              (detached Ed25519 signature)
    │   ├── pubkey.pem                 (PEM Ed25519 public key)
    │   ├── pubkey.b64                 (raw key, base64)
    │   └── metadata.json              (key fingerprint, derived key id)
    └── README.md
```

## 2. What each file type means

| Suffix | Purpose | Normative? |
|---|---|---|
| `*.json` | Human-readable pretty-printed form of the payload. Useful for review and diff. | Informative. |
| `*.canonical.json` | The **canonical bytes** per [wire-spec-v1.0.md §3](wire-spec-v1.0.md#3-canonicalization). Every byte matters. | ✅ Normative. |
| `*.sha256.txt` | Lowercase hex SHA-256 (64 chars) of the canonical bytes. No `sha256:` prefix, no trailing newline beyond the file's single line. | ✅ Normative. |
| `signature.b64` | Base64-encoded Ed25519 signature over the UTF-8 bytes of the canonical hex hash (see [§4.2](wire-spec-v1.0.md#42-signature-envelope)). | ✅ Normative. |
| `pubkey.pem` / `pubkey.b64` | The verifier's public key. PEM is primary; base64-raw is a fallback. | ✅ Normative (PEM) / SHOULD (raw). |
| `metadata.json` | `key_fingerprint_sha256`, `derived_key_id`, `signing_algorithm`, `hash_algorithm`, `signature_covers`, optional `note`. | ✅ Normative per [schemas/signed-artifact-envelope-v1.0.json](schemas/signed-artifact-envelope-v1.0.json). |
| `README.md` | Free-form notes about the specific vector — what it exercises, caveats, when it was regenerated. | Informative. |

The contract for a vector directory is: **the canonical file hashes
to the value in the sha256 file, and the pretty-printed file is
valid JSON that round-trips to the canonical file byte-for-byte.**
Breaking either of those invariants means the vector is corrupt.

## 3. The seven canonical payload types

| Type | Spec ID | Schema | Vector |
|---|---|---|---|
| Attestation Manifest | `attestation-manifest` | [schemas/attestation-manifest-v1.0.json](schemas/attestation-manifest-v1.0.json) | [manifest/attestation-manifest-1.0.0.canonical.json](../vectors/manifest/attestation-manifest-1.0.0.canonical.json) |
| Proof Manifest | `proof-manifest` | [schemas/proof-manifest-v1.0.json](schemas/proof-manifest-v1.0.json) | [manifest/proof-manifest-1.0.0.canonical.json](../vectors/manifest/proof-manifest-1.0.0.canonical.json) |
| Anchor Payload | `anchor-payload` | [schemas/anchor-payload-v1.0.json](schemas/anchor-payload-v1.0.json) | [anchor/anchor-payload-1.0.0.canonical.json](../vectors/anchor/anchor-payload-1.0.0.canonical.json) |
| Anchor Receipt | `anchor-receipt` | [schemas/anchor-receipt-v1.0.json](schemas/anchor-receipt-v1.0.json) | [anchor-receipts/anchor-receipt-1.0.0.canonical.json](../vectors/anchor-receipts/anchor-receipt-1.0.0.canonical.json) |
| Certification Attestation | `certification-attestation` | [schemas/certification-attestation-v1.0.json](schemas/certification-attestation-v1.0.json) | [certification/certification-attestation-1.0.0.canonical.json](../vectors/certification/certification-attestation-1.0.0.canonical.json) |
| STP Certification Attestation | `stp-certification-attestation` | [schemas/stp-certification-attestation-v1.0.json](schemas/stp-certification-attestation-v1.0.json) | [stp-certification/compatible/stp-certification-attestation-1.0.0.canonical.json](../vectors/stp-certification/compatible/stp-certification-attestation-1.0.0.canonical.json) |
| Governance Attestation (inside Signed Artifact Envelope) | `governance-attestation` | [schemas/governance-attestation-v1.0.json](schemas/governance-attestation-v1.0.json) | [signature/signed-artifact-001/artifact.canonical.json](../vectors/signature/signed-artifact-001/artifact.canonical.json) |

## 4. Vector canonicality (source-of-truth policy)

Per [CLAUDE.md "Multi-Repo Ownership"](https://github.com/SpecoraAI/specora-platform/blob/main/CLAUDE.md#multi-repo-ownership-read-before-committing)
and the platform-repo strategy note at
[`docs/strategy/epic-a01-drafts/11-prelaunch-gaps.md §8.4`](https://github.com/SpecoraAI/specora-platform/blob/main/docs/strategy/epic-a01-drafts/11-prelaunch-gaps.md):

**The golden vectors in this repo (`SpecoraAI/specora-verify/vectors/`)
are canonical.** The platform monorepo at
`SpecoraAI/specora-platform` also has historical copies under
`docs/public/specs/{manifest,signature,...}/vectors/`. Those copies
are deprecated pending the weekly sync job. Until the sync job
lands, vector changes MUST be made in both places in the same commit
window, and verified by running this repo's test suite against both
copies.

**Do not edit the platform-repo copies directly.** Open a PR against
this repo and mirror into the platform repo atomically.

## 5. How to regenerate a vector

Each canonical file is the output of running the canonicalizer over
the corresponding pretty-printed file. To regenerate after a change:

```sh
python3 - <<'PY'
import json, hashlib
from specora_verify.canonical import canonicalize
pretty_path = "vectors/manifest/attestation-manifest-1.0.0.json"
canonical_path = pretty_path.replace(".json", ".canonical.json")
sha256_path = pretty_path.replace(".json", ".sha256.txt")

payload = json.loads(open(pretty_path).read())
canonical = canonicalize(payload)
with open(canonical_path, "wb") as f:
    f.write(canonical)
with open(sha256_path, "w") as f:
    f.write(hashlib.sha256(canonical).hexdigest())
print(f"regenerated: {canonical_path}")
PY
```

For the signed-artifact vector, regeneration is more involved because
it requires a deterministic signing key. See
[`vectors/signature/README.md`](../vectors/signature/README.md) and
the reference regenerator at
[`tests/fixtures/anthropic/build_fixtures.py`](../tests/fixtures/anthropic/build_fixtures.py)
(reader fixtures, same pattern).

## 6. How to add a new vector

1. **Decide the payload type.** If it is one of the seven types
   above, skip to step 3. Otherwise, you are proposing a new payload
   type, which is a v1.1 change — open an issue and follow the
   [versioning policy](versioning-policy.md) before writing the
   vector.
2. **Add a schema file** under `docs/schemas/` for the new type.
   Follow the naming convention `<type>-v1.0.json`.
3. **Write the pretty-printed JSON** file under `vectors/<type>/`.
   Prefer data that exercises every field, including optional fields
   and edge cases (0, 1, many; empty arrays; null notes).
4. **Run the canonicalizer** as in §5 above to produce
   `*.canonical.json` and `*.sha256.txt`.
5. **Add a row** to `tests/test_wire_spec_schemas.py::VECTORS` so
   CI validates the new vector on every commit.
6. **Update §3 of this file** (the seven canonical payload types
   table) if the new vector represents a new type.

## 7. What makes a vector good

- **Realistic.** A vector that uses `1` for every integer field is
  technically valid but useless. Use realistic production-like
  values.
- **Round-trip clean.** The pretty-printed file MUST canonicalize to
  the canonical file byte-for-byte. No manual editing of canonical
  files ever.
- **Deterministic regeneration.** Anyone should be able to rerun the
  regeneration script and get the same output. Timestamps and UUIDs
  in vectors are fixed constants, not `now()` calls.
- **Minimal but not trivial.** If an optional field isn't exercised
  in any vector, it isn't tested. Prefer one slightly-fuller vector
  over two minimal ones.

## 8. Security note

Vectors MUST NOT contain real customer data, real signing keys, or
real API credentials. Use synthetic identifiers throughout. The
Ed25519 keys in `vectors/signature/signed-artifact-001/` are
synthetic test keys — their private halves are not stored anywhere
per the `metadata.json.note` convention.
