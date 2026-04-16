# OpenAI Compliance Platform Reader

## What it is

The OpenAI Compliance Platform reader ingests audit-log exports from the
OpenAI enterprise compliance surface and maps each compliance event
(policy check, moderation decision, content-hash attestation) onto the
Specora wire-spec canonical evidence-bundle shape. The reader is
**offline** — it never calls the OpenAI API. It reads a file the
customer has already exported using their own enterprise credentials.

**Status:** design-accurate against publicly described event shapes
(DevDay 2025, Enterprise Trust Portal). Pending live-data validation
once a production export is available or NDA clearance is received.
The reader is fully exercised end-to-end against synthetic fixtures.

## Authentication model

The reader itself requires no credentials. It reads a pre-exported file.

The *export* step (outside `specora-verify`) uses the customer's
OpenAI Enterprise API credentials — either an API key scoped to the
compliance admin role or an OAuth token issued by the enterprise SSO
integration. The export endpoint (private preview as of Q2 2026)
returns a standard OpenAI list response:

```json
{"object": "list", "data": [...events...], "has_more": false}
```

`specora-verify` also accepts bare JSON arrays and JSON Lines (one
event per line) for customers who batch-export via the admin console
CSV-to-JSONL converter.

## Event shape (design-accurate preview)

Each compliance event carries at minimum:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique event identifier (e.g. `evt_abc123`) |
| `type` | string | Event type (`policy_check`, `moderation`, etc.) |
| `effective_at` | string or int | RFC 3339 UTC timestamp or unix seconds |
| `model` | string | Model ID (e.g. `gpt-4o-2024-08-06`) |
| `decision.outcome` | string | `allowed`, `blocked`, `flagged`, `escalated`, etc. |
| `decision.policy_ids` | array | Policy references that applied |
| `content_hash` | string | `sha256:` prefixed hash of redacted content |

Optional fields preserved when present:

| Field | Maps to |
|-------|---------|
| `request_id` | `records[].upstream_request_id` |
| `project_id` | `records[].upstream_project_id` |
| `moderation.*` | `records[].upstream_moderation` (verbatim) |

## Outcome mapping

The reader maps OpenAI-native outcomes to the Specora wire-spec
decision enum:

| OpenAI outcome | Wire-spec outcome |
|----------------|-------------------|
| `allowed`, `pass`, `ok` | `approved` |
| `blocked`, `denied` | `rejected` |
| `flagged`, `needs_review`, `pending` | `deferred` |
| `escalated`, `escalate`, `manual_review` | `escalated` |

## Integrity model

OpenAI Compliance Platform does **not** emit per-event cryptographic
signatures. Integrity is anchored at the TLS transport layer
(`api.openai.com`) and by the enterprise admin console's tamper-evident
audit log. Each mapped record carries:

```json
{
  "upstream_signature": {
    "absent_per_record": true,
    "integrity_mechanism": "openai-compliance-api-tls-attested"
  }
}
```

The Specora outer signature tier (Ed25519, applied by `specora-verify
run`) is what the verifier checks offline.

## How to export

1. Log in to the OpenAI Enterprise admin console.
2. Navigate to **Compliance > Audit Log > Export**.
3. Select the date range and event types.
4. Download the JSON export file.

Alternatively, use the Compliance API endpoint (private preview):

```bash
curl -s "https://api.openai.com/v1/compliance/events?limit=100" \
  -H "Authorization: Bearer $OPENAI_ADMIN_KEY" \
  -o compliance-export.json
```

## How to feed into specora-verify

```bash
# Ingest and produce a canonical bundle payload
specora-verify read openai \
    --input compliance-export.json \
    --key-id spk-your-key-id \
    --out bundle-payload.json

# Full end-to-end pipeline (read + sign + write verifiable bundle)
specora-verify run \
    --provider openai \
    --input compliance-export.json \
    --key-id spk-your-key-id \
    --private-key /path/to/ed25519.key \
    --out ./my-bundle/
```

## Module reference

- Reader: `specora_verify/readers/openai_compliance.py`
- CLI subcommand: `specora-verify read openai`
- Canonical bundle schema: `docs/schemas/canonical-bundle-v1.0.json`
- Test fixtures: `tests/fixtures/openai_compliance/`
