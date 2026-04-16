# GRC Platform Integration Guide

This guide is for GRC platform vendors (Drata, Vanta, AuditBoard, Splunk,
Workiva, and others) who want to integrate Specora as an evidence source.

## What Specora provides

Specora produces cryptographically signed evidence bundles that prove what
an AI system did, when it did it, and under what policy. Each bundle is
independently verifiable — an auditor can confirm the evidence is intact
without trusting Specora or the AI vendor that produced it.

When your platform integrates with the Specora Evidence Source API, your
customers see Specora evidence bundles alongside their existing compliance
evidence (SOC 2, ISO 27001, ISO 42001, and others).

## The evidence-source contract

The contract is defined as an OpenAPI 3.1 specification:

- **Spec:** [evidence-source-v1.yaml](../openapi/evidence-source-v1.yaml)
- **Examples:** [examples/](../openapi/examples/)
- **Wire Spec (normative):** [wire-spec-v1.0.md](../wire-spec-v1.0.md)
- **Bundle schema:** [canonical-bundle-v1.0.json](../schemas/canonical-bundle-v1.0.json)

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/evidence/bundles` | List evidence bundles (paginated) |
| GET | `/v1/evidence/bundles/{id}` | Retrieve a complete bundle |
| GET | `/v1/evidence/bundles/{id}/verification` | Retrieve verification result |
| POST | `/v1/evidence/webhooks` | Register for real-time bundle events |
| DELETE | `/v1/evidence/webhooks/{id}` | Unregister a webhook |
| GET | `/v1/evidence/schemas` | List available schemas |

## Authentication

The API uses Bearer token authentication. Each organization receives an
API key scoped to read-only evidence access. Webhook management requires
a key with the `webhooks:write` scope.

```
Authorization: Bearer spk_live_abc123...
```

Keys are issued through the Specora dashboard under Settings > API Keys.
Test keys (prefixed `spk_test_`) are available for staging environments.

## Connecting your platform

### Option 1: Polling

Poll `GET /v1/evidence/bundles` periodically with a `created_after`
filter set to the timestamp of the last bundle you ingested. Recommended
interval: every 5 minutes for near-real-time sync, or hourly for batch.

### Option 2: Webhooks (recommended)

Register a webhook endpoint via `POST /v1/evidence/webhooks`. Specora
delivers a signed POST to your URL when a bundle is created or verified.
Each delivery includes an `X-Specora-Signature` header containing the
HMAC-SHA256 of the request body using the shared secret returned at
registration time. Always verify this signature before processing.

Webhook event types:
- `bundle.created` — a new evidence bundle is available
- `bundle.verified` — verification completed with a PASS result
- `bundle.verification_failed` — verification completed with a FAIL result

## Displaying verification status

Each evidence bundle has an independent verification result accessible via
`GET /v1/evidence/bundles/{id}/verification`. The result includes:

- **status**: `pass` or `fail`
- **checks**: array of individual verification checks (schema conformance,
  canonical hash, signature, timestamp ordering)
- **verifier_version**: the `specora-verify` version used

Display the verification status prominently in your evidence library. A
`pass` means the bundle is cryptographically intact and schema-conformant.
See the [trust model](../trust-model.md) for what `pass` does and does
not prove.

## Mapping bundles to compliance controls

Evidence bundles map to compliance framework controls as follows:

### SOC 2

| SOC 2 criteria | Evidence mapping |
|----------------|------------------|
| CC6.1 (logical access) | `decision.outcome` + `decision.policy_refs` — proves policy enforcement |
| CC7.2 (system monitoring) | Bundle existence — proves AI activity is monitored and recorded |
| CC8.1 (change management) | `model.name` + `model.version` — proves model versioning is tracked |

### ISO 42001

| ISO 42001 clause | Evidence mapping |
|-------------------|------------------|
| 6.1.2 (AI risk assessment) | `decision.outcome` = `rejected` or `escalated` — proves risk-based decisions |
| 9.1 (monitoring and measurement) | Bundle with `verification.status` = `pass` — proves ongoing monitoring |
| 10.1 (continual improvement) | Temporal sequence of bundles — proves governance evolves over time |

### ISO 27001

| ISO 27001 control | Evidence mapping |
|--------------------|------------------|
| A.8.16 (monitoring activities) | Bundle creation events — proves AI system monitoring |
| A.5.23 (cloud service security) | `metadata.provider` + verification — proves cloud AI provider oversight |

## Bundle payload shape

The canonical bundle follows the schema at
[canonical-bundle-v1.0.json](../schemas/canonical-bundle-v1.0.json).
Key fields:

- `metadata.provider` — which AI provider produced the evidence
- `metadata.content_hash` — SHA-256 of the canonical records (tamper evidence)
- `records[].decision.outcome` — `approved`, `rejected`, `deferred`, or `escalated`
- `records[].decision.policy_refs` — which policies governed the decision
- `records[].model` — which AI model was used
- `records[].upstream_signature` — cryptographic signature from the provider

See [examples/get-bundle-response.json](../openapi/examples/get-bundle-response.json)
for a complete example.

## Versioning

The API includes an `X-Specora-Wire-Spec` response header indicating the
wire spec version. The current version is `1.0.0`. The wire spec follows
semver: minor versions add optional fields, major versions may change
canonicalization rules. Your integration should check the header and
handle unknown fields gracefully.

## Rate limits

The API enforces 100 requests per minute per API key. A `429` response
includes a `Retry-After` header. For high-volume integrations, use
webhooks instead of polling.

## Support

- **Technical questions:** Open an issue at
  [github.com/SpecoraAI/specora-verify](https://github.com/SpecoraAI/specora-verify/issues)
- **Partnership inquiries:** partnerships@specora.ai
- **Security disclosures:** See [SECURITY.md](../../SECURITY.md)
