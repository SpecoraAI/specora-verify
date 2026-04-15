# Anthropic Claude Enterprise Compliance API reader

Ingests a JSONL export from the Anthropic Claude Enterprise **Compliance
API** — one JSON object per line, each representing one Claude
inference call subject to the customer's Compliance API configuration
— and produces a Specora wire-spec evidence-bundle payload.

- **CLI:** `specora-verify read anthropic`
- **Module:** [`specora_verify/readers/anthropic.py`](../../specora_verify/readers/anthropic.py)
- **Tests:** [`tests/readers/test_anthropic.py`](../../tests/readers/test_anthropic.py) + [`tests/test_cli_read.py`](../../tests/test_cli_read.py)
- **Fixtures:** [`tests/fixtures/anthropic/`](../../tests/fixtures/anthropic/)
- **Example:** [`examples/anthropic-quickstart.sh`](../../examples/anthropic-quickstart.sh)
- **Schema version supported:** `1.0`

## 1. How to get the upstream export

The customer runs the Anthropic Compliance API export from their
Anthropic Enterprise console (or via `curl` against the Compliance API
using their Enterprise credentials) and downloads the resulting
JSONL file. The reader never fetches this file — it only reads one
the customer already has locally. This preserves the offline-verifier
posture of `specora-verify`.

## 2. Upstream record shape (schema v1.0)

One JSON object per line. Fields observed in the 2026-Q1 Anthropic
Compliance API schema:

```json
{
  "record_id": "rec-000001",
  "timestamp": "2026-06-10T14:22:17Z",
  "request_id": "req-a1b2c3d4",
  "model": "claude-opus-4-6",
  "model_version": "20260320",
  "input_token_count": 1843,
  "output_token_count": 412,
  "decision": "approved",
  "policy_refs": ["p-42", "p-55"],
  "context_hash": "sha256:a7f3b2...",
  "tool_invocations": [],
  "signature": {
    "alg": "ed25519",
    "key_id": "anthropic-compliance-key-2026-q1",
    "value": "MEQCIG...base64..."
  },
  "schema_version": "1.0"
}
```

## 3. Schema mapping (upstream → Specora wire spec)

| Upstream field | Specora wire spec field | Transformation |
|---|---|---|
| `record_id` | `bundle.records[].id` | Copy as-is |
| `timestamp` | `bundle.records[].timestamp` | Normalize to RFC 3339 UTC with explicit `Z` suffix (`+00:00` is rewritten to `Z`) |
| `request_id` | `bundle.records[].upstream_request_id` | Copy as-is |
| `model` | `bundle.records[].model.name` | Copy as-is |
| `model_version` | `bundle.records[].model.version` | Copy as-is |
| `decision` | `bundle.records[].decision.outcome` | Copy; enum-validated against `{approved, rejected, deferred, escalated}` |
| `policy_refs` | `bundle.records[].decision.policy_refs` | Copy as-is (must be JSON array) |
| `context_hash` | `bundle.records[].context.hash` | Copy; must start with `sha256:` |
| `signature.alg` | `bundle.records[].upstream_signature.alg` | Copy; must be `ed25519` |
| `signature.key_id` | `bundle.records[].upstream_signature.key_id` | Copy |
| `signature.value` | `bundle.records[].upstream_signature.value` | Copy as base64 |
| `tool_invocations` | `bundle.records[].tool_invocations` | Preserved verbatim when non-empty; elided when empty |
| `schema_version` | `bundle.metadata.upstream_schema_version` | Must be in `supported_schema_versions` (currently `("1.0",)`) |
| `input_token_count`, `output_token_count` | *(discarded)* | Operational telemetry — not audit evidence |

The reader also computes a content hash over the canonical JSON of
the records array and stores it in
`bundle.metadata.content_hash` (e.g. `"sha256:…"`). This is the
anchor the outer Specora signature covers when the bundle is signed.

## 4. Example invocation

```bash
specora-verify read anthropic \
    --input compliance.jsonl \
    --key-id spk-abcd1234 \
    --out bundle.json
```

The output file is canonical JSON (sorted keys, compact separators,
UTF-8, no trailing newline besides the final one the CLI adds). Two
runs against the same input produce byte-identical output.

### Optional — verify upstream Anthropic signatures offline

```bash
specora-verify read anthropic \
    --input compliance.jsonl \
    --key-id spk-abcd1234 \
    --public-key anthropic-compliance-key.hex \
    --out bundle.json
```

If `--public-key` is provided, the reader verifies every record's
`signature.value` against the supplied Ed25519 public key. A failure
raises `READER_CRYPTO_ERROR` in strict mode, or drops the record
with a warning in `--non-strict` mode.

The public key format is either raw 32 bytes or 64-character hex.

### Non-strict mode

```bash
specora-verify read anthropic \
    --input compliance.jsonl \
    --key-id spk-abcd1234 \
    --non-strict \
    --out bundle.json
```

`--non-strict` drops malformed records with a warning instead of
failing the whole read. Use this for bulk ingestion of realistic-messy
provider exports where the customer has asked you to extract what's
recoverable.

## 5. Common errors

| Error code | Meaning | What to do |
|---|---|---|
| `READER_SCHEMA_ERROR: invalid JSON at line N` | One line is not valid JSON | Inspect the line, fix the export, or re-run with `--non-strict` |
| `READER_SCHEMA_ERROR: missing required field 'X'` | A record is missing a required field | Check the upstream schema version; Anthropic may have revved the schema |
| `READER_SCHEMA_ERROR: invalid decision outcome 'X'` | The `decision` field is outside the enum | Re-check against the Anthropic Compliance API docs; file an issue if Anthropic added a new outcome value |
| `READER_SCHEMA_ERROR: context_hash must start with 'sha256:'` | An upstream record's context hash is not prefixed | Confirm the export came from the Compliance API and not a different audit surface |
| `READER_SCHEMA_ERROR: unsupported schema_version 'X'` | Upstream schema version is newer than the reader supports | Upgrade `specora-verify`, or pin `--schema-version 1.0` if Anthropic's change is backwards-compatible |
| `READER_CRYPTO_ERROR: upstream signature did not verify` | `--public-key` was provided and a record's signature failed to verify | Re-check the public key matches Anthropic's published key for the window |
| `READER_IO_ERROR: file not found` | Input path does not exist | Check the path |

## 6. References

- Anthropic Claude Enterprise Compliance API — upstream provider documentation (consult Anthropic Enterprise support for access).
- Specora wire spec — the normative bundle shape every reader targets. Wire spec v1.0 publication is tracked under EPIC-A02.
- Reader design notes — platform-repo `docs/strategy/b01-reader-design-notes-2026-Q2.md` (convention-agnostic reader design + §9 decisions log).
