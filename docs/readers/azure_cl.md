# Azure Confidential Ledger reader

Ingests an **Azure Confidential Ledger entries-with-receipts export** —
a JSON document with a top-level `{"entries": [<entry>, …]}` array —
and produces a Specora wire-spec evidence-bundle payload. Each entry
carries the customer ledger payload plus the Confidential Ledger
`receipt` block (Merkle inclusion proof + consortium signature +
optional SGX/TDX enclave quote).

The reader is **TEE-attestation-first**: when an enclave quote is
present in the receipt, it is extracted into a record-level
`tee_attestation` field as first-class evidence. This mirrors the way
the CloudTrail reader positions Bedrock Automated Reasoning Checks.

- **CLI:** `specora-verify read azure-cl`
- **Module:** [`specora_verify/readers/azure_cl.py`](../../specora_verify/readers/azure_cl.py)
- **Tests:** [`tests/readers/test_azure_cl.py`](../../tests/readers/test_azure_cl.py) + [`tests/test_cli_read.py`](../../tests/test_cli_read.py)
- **Fixtures:** [`tests/fixtures/azure_cl/`](../../tests/fixtures/azure_cl/)
- **Example:** [`examples/azure-cl-quickstart.sh`](../../examples/azure-cl-quickstart.sh)
- **Schema version supported:** `1.0`

## 1. How to get the upstream export

Azure Confidential Ledger is a CCF-backed, tamper-evident ledger
service that returns a signed **receipt** per write. To get the export
this reader ingests, aggregate the transaction entry + its receipt for
each decision record written to your ledger collection:

```bash
# Pseudocode — replace with your preferred Azure CLI / SDK + ledger client.
for tx in $(az confidentialledger list-transactions ...); do
  entry=$(az confidentialledger get-transaction  --transaction-id "$tx" ...)
  receipt=$(az confidentialledger get-receipt    --transaction-id "$tx" ...)
  jq -n --argjson e "$entry" --argjson r "$receipt" \
    '{collectionId: $e.collectionId, transactionId: $e.transactionId,
      contents: $e.contents, receipt: $r}'
done | jq -s '{entries: .}' > azure-cl-export.json
```

Each entry must contain **both** `contents` (the customer ledger
payload) and `receipt` (the Merkle inclusion proof and consortium
signature the ledger emitted at write time). An entry with one and
not the other cannot be verified by an auditor and is rejected by the
reader.

The reader **never talks to Azure directly** — it only reads a file
the customer has already exported with their own Azure credentials.
This preserves the offline-verifier posture of `specora-verify`.

### Upstream integrity model — consortium-signed receipts, not per-record ed25519

Azure Confidential Ledger receipts are signed by the **consortium
service identity** on a CCF network (ECDSA P-384 by default), not by
an ed25519 per-record content key. The reader therefore marks each
mapped record's `upstream_signature` as a descriptor:

```json
{
  "absent_per_record": true,
  "integrity_mechanism": "azure-confidential-ledger-receipt"
}
```

The full cryptographic proof — Merkle leaf components, node
certificates, inclusion path, and signature — is preserved verbatim
in a sibling `upstream_inclusion_proof` field on the same record, so
an auditor re-walking the ledger proof has everything they need. The
reader does **not** re-verify the receipt offline; that is the
auditor's job, deliberately out of scope here.

## 2. Upstream entry shape

```json
{
  "collectionId": "subledger-ai-audit-2026",
  "transactionId": "2.101",
  "contents": {
    "record": {
      "record_id": "azcl-rec-000001",
      "timestamp": "2026-06-11T09:00:00Z",
      "request_id": "req-azcl-00000001",
      "model": "gpt-4o",
      "model_version": "2024-08",
      "decision": "approved",
      "policy_refs": ["pol-1", "pol-7"],
      "context_hash": "sha256:..."
    }
  },
  "receipt": {
    "leafComponents": { "claimsDigest": "...", "commitEvidence": "...", "writeSetDigest": "..." },
    "nodeCerts": ["-----BEGIN CERTIFICATE-----\n..."],
    "proof": [{"left": "..."}, {"right": "..."}],
    "signature": "MEUCIQ...",
    "serviceId": "contoso-ccf-service",
    "enclaveQuote": "...",
    "mrenclave": "...",
    "mrsigner": "...",
    "reportData": "..."
  }
}
```

The `contents.record` shape is customer-defined — the reader
enforces the minimum required subset (`record_id`, `timestamp`,
`model`, `model_version`, `decision`, `policy_refs`, `context_hash`)
and ignores everything else so customers can include their own
metadata without breaking the bundle.

## 3. Schema mapping (upstream → Specora wire spec)

| Upstream field | Specora wire spec field | Transformation |
|---|---|---|
| `transactionId` | `records[].upstream_tx_id` | Copy verbatim (compound `view.seqno`) |
| `collectionId` | `records[].upstream_collection_id` | Copy verbatim |
| `contents.record.record_id` | `records[].id` | Copy as-is (stringified) |
| `contents.record.timestamp` | `records[].timestamp` | Normalize to RFC 3339 UTC with explicit `Z` suffix |
| `contents.record.request_id` | `records[].upstream_request_id` | Copy if present |
| `contents.record.model` | `records[].model.name` | Copy as-is |
| `contents.record.model_version` | `records[].model.version` | Copy as-is |
| `contents.record.decision` | `records[].decision.outcome` | Enum-validated `{approved, rejected, deferred, escalated}` |
| `contents.record.policy_refs` | `records[].decision.policy_refs` | Copy as an array |
| `contents.record.context_hash` | `records[].context.hash` | Copy; must start with `sha256:` |
| `receipt.leafComponents` | `records[].upstream_inclusion_proof.leafComponents` | Preserved verbatim |
| `receipt.nodeCerts` | `records[].upstream_inclusion_proof.nodeCerts` | Preserved verbatim (array) |
| `receipt.proof` | `records[].upstream_inclusion_proof.proof` | Preserved verbatim (Merkle path array) |
| `receipt.signature` | `records[].upstream_inclusion_proof.signature` | Preserved verbatim |
| `receipt.serviceId` | `records[].upstream_inclusion_proof.serviceId` | Preserved if present |
| `receipt.enclaveQuote` | `records[].tee_attestation.enclaveQuote` | Extracted as first-class TEE evidence when present |
| `receipt.mrenclave` / `mrsigner` / `reportData` | `records[].tee_attestation.{mrenclave, mrsigner, reportData}` | Preserved alongside the quote when present |
| *(derived)* | `records[].upstream_signature` | `{"absent_per_record": true, "integrity_mechanism": "azure-confidential-ledger-receipt"}` |
| *(fixed)* | `metadata.upstream_schema_version` | `"1.0"` — the reader-side Azure-CL shape version |

The additive `upstream_inclusion_proof`, `tee_attestation`, and
`upstream_collection_id` record fields ride on
`additionalProperties: true` in the canonical-bundle-v1.0 schema — no
wire-spec extension is required.

## 4. Example invocation

```bash
specora-verify read azure-cl \
    --input azure-cl-export.json \
    --key-id spk-abcd1234 \
    --out bundle.json
```

Output is canonical JSON (sorted keys, compact separators, UTF-8).
Two runs against the same input produce byte-identical output — the
determinism invariant, enforced by a hypothesis property test.

### Non-strict mode — drop broken entries with warnings

```bash
specora-verify read azure-cl \
    --input azure-cl-export.json \
    --key-id spk-abcd1234 \
    --non-strict \
    --out bundle.json
```

`--non-strict` drops malformed entries (missing `receipt`, missing
`contents.record` fields, bad `context_hash`, etc.) with a warning
instead of failing the whole read.

### `--public-key` is accepted but ignored

```bash
specora-verify read azure-cl \
    --input azure-cl-export.json \
    --key-id spk-abcd1234 \
    --public-key some-key.hex \
    --out bundle.json
```

The flag exists for interface symmetry with other readers. Azure
Confidential Ledger receipts are consortium-signed (ECDSA P-384), not
ed25519 per-record, so the key material is not used. The reader
surfaces an explicit warning via `ReadResult.warnings` whenever the
flag is set, so a user expecting verification sees it instead of a
silent ignore.

## 5. Common errors

| Error code | Meaning | What to do |
|---|---|---|
| `READER_SCHEMA_ERROR: input is not valid JSON` | File is not JSON | Check the export |
| `READER_SCHEMA_ERROR: input must be a JSON object with a top-level 'entries' array …` | Wrong envelope shape | Aggregate per-transaction responses into `{"entries": [...]}`, or hand the reader a single-entry dict with `contents` and `receipt` |
| `READER_SCHEMA_ERROR: transactionId must be a non-empty string` | Entry missing the compound transaction ID | Re-export — `GET /app/transactions/...` should return `transactionId` |
| `READER_SCHEMA_ERROR: contents.record missing required field 'context_hash'` | Customer payload incomplete | Add the field on the writer side; the reader enforces the minimum required subset |
| `READER_SCHEMA_ERROR: receipt must be a JSON object …` | Entry has no receipt | The whole point of Confidential Ledger is the receipt — re-export and attach `GET /app/transactions/{tx}/receipt` to each entry |
| `READER_SCHEMA_ERROR: receipt missing required field 'proof'` | Receipt truncated | Regenerate the receipt from the ledger |
| `READER_SCHEMA_ERROR: contents.record.context_hash must start with 'sha256:' …` | Wrong hash form | Fix the writer to emit `sha256:<hex>` |
| `READER_SCHEMA_ERROR: unsupported schema_version …` | `--schema-version` override is not in the supported set | Drop the override or pass `--schema-version 1.0` |
| `READER_IO_ERROR: file not found` | Input path does not exist | Check the path |

## 6. References

- Azure Confidential Ledger overview — [Azure Confidential Ledger documentation](https://learn.microsoft.com/en-us/azure/confidential-ledger/).
- CCF (Confidential Consortium Framework) receipts — [CCF receipts and transactions](https://microsoft.github.io/CCF/main/use_apps/verify_tx.html).
- Specora wire spec v1.0 — [`docs/wire-spec-v1.0.md`](../wire-spec-v1.0.md).
- Canonical bundle schema v1.0 — [`docs/canonical-bundle-schema-v1.0.md`](../canonical-bundle-schema-v1.0.md).
- Reader design notes — platform-repo `docs/strategy/b01-reader-design-notes-2026-Q2.md` §5 (Azure CL) and §9.4 (decisions log).
