# API reference — `specora_verify` (Python library)

`specora-verify` is built around a stable command-line interface, but
every CLI subcommand is a thin wrapper over a small, public Python API
that you can import and call directly. This page is the reference for
that library surface.

If you only need to verify bundles in CI or at an auditor's desk,
prefer the CLI — see [quickstart.md](quickstart.md). Reach for this
page when you want to embed verification in another tool, build a
custom reader, or call canonicalization from non-CLI code.

## Stability contract

- **Public modules** documented on this page follow [Wire Spec
  v1.0](wire-spec-v1.0.md) versioning rules. Breaking changes require
  a major-version bump of the wire spec **and** of this package.
- **Underscore-prefixed names** (e.g. `_compute_key_fingerprint`) are
  internal. Do not import them; they may change in any release.
- **The `specora_verify.cli` module** is private to the CLI entry
  point. Treat it as an implementation detail.

The byte-level guarantees of canonical JSON output, hashing, and
signature verification are normative and match the wire spec exactly.
A divergence between this library and the spec is a bug in the
library, not the spec — open an issue.

## Installation

```bash
pip install specora-verify              # core (stdlib only)
pip install "specora-verify[crypto]"    # adds Ed25519 verification
pip install "specora-verify[fetchers]"  # adds S3, GitHub, DNS fetchers
pip install "specora-verify[sigstore]"  # adds Sigstore bundle support
pip install "specora-verify[all]"       # everything
```

Requires Python 3.11 or newer. Full installation matrix:
[installation.md](installation.md).

## Module map

| Module | Purpose |
|---|---|
| `specora_verify.canonical` | Canonical JSON serialization (Wire Spec v1.0 §3) |
| `specora_verify.hash` | SHA-256 hashing of canonical bytes |
| `specora_verify.signature` | Ed25519 signature verification (Wire Spec v1.0 §4) |
| `specora_verify.fingerprint` | Key fingerprint and key-id derivation |
| `specora_verify.revocation` | Offline revocation-list parsing and trust checks |
| `specora_verify.receipt` | Verification receipt generation (archivable proof) |
| `specora_verify.errors` | Exception hierarchy and CI-aware exit codes |
| `specora_verify.contracts` | Spec-id contract registry |
| `specora_verify.validators.manifest` | Manifest payload validation |
| `specora_verify.validators.bundle` | ZIP bundle structural verification |
| `specora_verify.validators.anchor` | External-anchor payload validation |
| `specora_verify.validators.certification` | Certification attestation lifecycle |
| `specora_verify.validators.chain` | Transparency-chain verification |
| `specora_verify.validators.external_anchor` | External-anchor chain verification |
| `specora_verify.readers` | Provider audit-log readers (Anthropic, CloudTrail, Azure CL, …) |
| `specora_verify.output` | Result formatters (`text` and `json`) — used by the CLI |

## Canonicalization — `specora_verify.canonical`

Canonical JSON is the foundation of every guarantee in this library.
The same input must always produce the same bytes; if it doesn't,
nothing else this library says can be trusted.

```python
from specora_verify.canonical import canonical_json_bytes, canonical_json_str

# Canonical bytes — what you hash and sign
canonical_json_bytes({"b": 2, "a": 1})
# b'{"a":1,"b":2}'

# Canonical string — for display / comparison
canonical_json_str([3, 1, 2])
# '[3,1,2]'
```

Rules (Wire Spec v1.0 §3):

- `sort_keys=True` — keys sorted lexicographically by Unicode code
  point.
- `separators=(",", ":")` — no whitespace.
- `ensure_ascii=True` — non-ASCII escaped as `\uXXXX`.
- `allow_nan=False` — `NaN`, `+Infinity`, `-Infinity` are rejected.
- UTF-8, no trailing newline.

Floats are canonicalized but their use in normative payloads is
discouraged — see [`validators.manifest._check_no_floats`](#manifest-validation--specora_verifyvalidatorsmanifest)
for the guard the manifest validator applies.

## Hashing — `specora_verify.hash`

```python
from specora_verify.hash import sha256_hex, compute_manifest_hash

sha256_hex(b'{"a":1,"b":2}')
# 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

compute_manifest_hash({"manifest": {...}})
# Equivalent to sha256_hex(canonical_json_bytes(payload))
```

## Signature verification — `specora_verify.signature`

Requires the `[crypto]` extra. Without it, `verify_signature` raises
`VerificationError(code=CRYPTO_MISSING)` — call `is_crypto_available()`
first if you need to gate behavior.

```python
from specora_verify.signature import (
    is_crypto_available,
    load_public_key,
    get_key_info,
    verify_signature,
    verify_artifact_signature,
)

if not is_crypto_available():
    raise RuntimeError("install specora-verify[crypto]")

# Load a key in any supported format (auto-detected)
pubkey = load_public_key(open("pubkey.pem").read())

# Verify a signature over a manifest hash (the canonical workflow)
result = verify_signature(
    manifest_hash="abcd...",        # hex string
    signature_b64="MEQCIQ...==",     # base64 Ed25519 signature
    public_key=pubkey,
)
assert result.verified
```

Key fields on `SignatureVerificationResult`:

- `verified: bool` — whether the signature is valid.
- `error_code: str | None` — `KEY_LOAD_FAILED`, `SIGNATURE_INVALID`,
  `SIGNATURE_FORMAT`, or `CRYPTO_MISSING`.
- `key_fingerprint: str | None` — SHA-256 fingerprint of the public
  key bytes.

The signature is verified over the **UTF-8 encoded manifest hash
hex string**, not the binary hash bytes. This matches the server-side
signing path; do not pre-decode the hex.

## Key fingerprints — `specora_verify.fingerprint`

```python
from specora_verify.fingerprint import (
    compute_key_fingerprint,
    derive_key_id,
    compute_key_fingerprint_and_id,
)

fp = compute_key_fingerprint(raw_public_key_bytes)   # hex SHA-256 fingerprint
key_id = derive_key_id(fp)                           # short canonical key id
fp, key_id = compute_key_fingerprint_and_id(raw_public_key_bytes)
```

The key-id format matches the wire spec; downstream consumers can
treat it as opaque.

## Revocation and trust — `specora_verify.revocation`

```python
from specora_verify.revocation import (
    load_revocation_list,
    check_key_trust,
)

rl = load_revocation_list("revocation.json")
result = check_key_trust(
    revocation_list=rl,
    key_fingerprint="abcd...",
    require_trusted=True,   # fail if key is not explicitly active
)
assert result.trusted
```

`load_revocation_list` validates the schema and returns a
`RevocationList`. `check_key_trust` returns a `TrustCheckResult` with
`trusted: bool`, `status: str` (`"active"`, `"revoked"`, `"unknown"`),
and an optional `revoked_at` timestamp.

## Verification receipts — `specora_verify.receipt`

Receipts are the archivable, auditor-friendly output of a verification
run — the thing you hand to a regulator months later to demonstrate
that a verification happened and what it concluded.

```python
from specora_verify.receipt import (
    generate_artifact_receipt,
    generate_bundle_receipt,
)

receipt = generate_artifact_receipt(
    artifact_path="claim.json",
    signature_path="claim.sig",
    public_key_path="pubkey.pem",
)
print(receipt.to_json(indent=2))
```

The receipt schema is normative and matches
[`docs/schemas/governance-attestation-v1.0.json`](schemas/) where
applicable.

## Manifest validation — `specora_verify.validators.manifest`

```python
from specora_verify.validators.manifest import validate_manifest

result = validate_manifest(payload, contract=None)   # contract auto-detected
if not result.valid:
    for err in result.errors:
        print(err)
```

`ManifestValidationResult.errors` is a list of human-readable strings;
each error is an explicit, fixable claim about a field, not a stack
trace.

## Bundle verification — `specora_verify.validators.bundle`

```python
from specora_verify.validators.bundle import verify_bundle

result = verify_bundle("evidence.zip")
for art in result.artifacts:
    print(art.name, art.verified, art.error)
```

`verify_bundle` walks a Specora-format ZIP, verifies the manifest,
each artifact's hash, and (if signatures are present and `[crypto]` is
installed) each artifact's signature.

## Anchor and chain validation

```python
from specora_verify.validators.anchor import validate_anchor_payload, verify_anchor_vectors
from specora_verify.validators.chain import verify_chain   # see source for full signature
from specora_verify.validators.external_anchor import (
    verify_external_anchor,
    verify_external_anchor_chain,
)
```

These cover the transparency-chain primitives in the wire spec. They
are stable but rarely needed by end users — the CLI subcommands
`anchor`, `verify-log`, `verify-external-anchor`, and `mirror` are the
usual interface.

## Certification — `specora_verify.validators.certification`

The certification module generates and validates the attestations
that a producer issues alongside a bundle.

```python
from specora_verify.validators.certification import (
    check_certification_bundle,
    generate_attestation,
    validate_attestation,
)
```

Signatures on attestations follow the same Ed25519-over-canonical-hash
contract as everything else.

## Spec-id contracts — `specora_verify.contracts`

Each known `spec_id` (manifest type) is registered with required and
optional fields. The CLI uses this registry to dispatch validation;
library users normally don't need to call it directly, but it's useful
for introspecting what manifests are supported.

```python
from specora_verify.contracts import get_contract, list_contracts
from specora_verify.contracts.registry import detect_spec_id

print(list_contracts())                         # [(spec_id, schema_version), ...]
contract = get_contract("specora.proof.v1", "1.0")
sid = detect_spec_id(payload)                   # may return None if unknown
```

## Provider readers — `specora_verify.readers`

Readers ingest provider audit-log exports and emit canonical Specora
bundle payloads — the producer half of the trust-bootstrap loop.

```python
from specora_verify.readers import get_reader, available_readers

print(available_readers())
# ['anthropic', 'azure-cl', 'cloudtrail', 'langsmith', 'openai']

reader = get_reader("anthropic")
result = reader.read(input_path="export.jsonl", key_id="spk-abcd1234")
print(result.payload)         # canonical bundle dict
print(result.warnings)        # non-fatal advisory messages
```

Every reader satisfies `ReaderProtocol` (see `readers/__init__.py`)
and is registered via the `@reader("<name>")` decorator. Adding a new
reader is documented at [`docs/readers/README.md`](readers/README.md).

The `ReadResult` dataclass exposes:

- `payload: dict` — canonical bundle payload (already in
  Wire Spec v1.0 shape).
- `warnings: list[str]` — non-fatal mapping issues; the CLI surfaces
  these on stderr.
- `metadata: dict` — provider-specific bookkeeping (record count,
  source schema version).

## Errors and exit codes — `specora_verify.errors`

```python
from specora_verify.errors import (
    VerificationError,
    HashMismatchError,
    ParseError,
    MissingFieldError,
    TypeValidationError,
    UnknownContractError,
    ZipMalformedError,
    ReaderError,
    ReaderSchemaError,
    ReaderCryptoError,
    ReaderIOError,
    map_exit_code_for_ci,
    exit_code_name,
)

try:
    verify_bundle("evidence.zip")
except VerificationError as e:
    print(e.code, e.message)
```

CI-aware exit-code mapping: `map_exit_code_for_ci(exit_code, ci_mode)`
collapses `WARN` (exit 1) to `FAIL` (exit 2) when `--ci` is set, so
CI pipelines fail loudly on what would otherwise be advisory output.

| Exit code | Meaning |
|---|---|
| `0` | `PASS` — verification succeeded. |
| `1` | `WARN` — succeeded with advisory issues; in CI mode this maps to `2`. |
| `2` | `FAIL` — verification failed. |
| `3` | `ERROR` — internal/setup error (missing extras, malformed input). |

## Output formatters — `specora_verify.output`

The `output` module is the boundary between result objects and the
two supported wire formats: `text` (human) and `json` (machine).
Library users almost never need this — call the validators directly
and shape the output yourself — but if you're embedding verification
in a tool that reuses the CLI's `--format json` schema, the
`format_*` helpers are reusable.

## Versioning

This library follows Wire Spec v1.0 lock-step versioning:

- `1.x.y` — backwards-compatible additions and bugfixes against Wire
  Spec v1.0.
- `2.0.0` — only on a wire-spec major bump.

See [`versioning-policy.md`](versioning-policy.md) for the full rule.
