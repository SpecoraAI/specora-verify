# Reader-side agent identity pass-through (AID-940 demo lane)

**Status:** Investor-demo lane. Authorized via [`docs/strategy/freeze-exceptions/2026-05-08-aid-investor-demo-build.md`](https://github.com/SpecoraAI/specora-platform) in the platform repo. CSEA-SUPPRESS-2026-05-08-002. Archive 2026-06-05.
**Wire Spec:** [v1.1](../wire-spec-v1.1.md) (the additive revision that introduced the optional `agent_identity` field on each record).

This page is the integration guide for **provider audit-log readers** that need to preserve a Specora-issued agent-identity certificate as the bundle is normalized. It is the closure for the Phase 1 CSEA Stage 4 pairing on [`specora_verify/agent_identity.py`](../../specora_verify/agent_identity.py) — the verifier-side cert validator now ships with a working reader-side companion.

---

## 1. Why a reader has to think about this

The verifier's [`validate_bundle_v1_1`](../../specora_verify/wire_spec.py) only validates an `agent_identity` envelope if a reader actually puts one on the record. Without reader pass-through, every cert issued by Specora's demo-lane DEMO-ROOT would be lost between the agent and the verifier, and the bundle would always validate `agent_identity = absent` — defeating the entire AID-9xx investor pitch.

The reader is the bridge. Its job is small: **lift any embedded cert envelope from the upstream record into the canonical bundle, and never fabricate one if the upstream record didn't ship one.**

This page says exactly how to do that for any reader.

---

## 2. The doctrine guardrails (binding for every reader)

1. **No fabrication.** If the upstream record carries no agent identity claim, the bundle record carries none either. There is no "infer the identity from the API key" or "fall back to the org default cert" path. Absence travels.
2. **No normalization.** The cert envelope is already canonical-JSON when the agent signed it. Re-serializing it would change the byte sequence the signature was computed over and break verification. Lift it verbatim.
3. **No validation.** The reader is not the verifier. The reader does not check the signature, does not check `not_after`, does not check the issuer key fingerprint. It just lifts. The verifier does the checking.
4. **No leakage.** The reader does not log the cert envelope, does not phone home, does not include it in metrics labels (the envelope contains an org_id; metric labels would unbound cardinality).

These guardrails are the same shape as the existing reader contract for upstream signatures — readers don't validate Anthropic's signature either, they just transport it. Treat `agent_identity` as another transport-only field.

---

## 3. Two embedding paths (use whichever your provider gives you)

### 3.1 Direct embedding — `record.agent_identity`

Used when the agent's runtime is SDK-instrumented (the AID-930 path) and the SDK puts the cert envelope into the request body directly. The provider's compliance API mirrors the request body verbatim, and the cert appears as a property of the record:

```jsonc
{
  "record_id": "rec-id-000001",
  "timestamp": "2026-06-10T14:22:01Z",
  "model": "claude-opus-4-6",
  "decision": "approved",
  "agent_identity": {
    "format": "specora-aid-cert-v1-demo",
    "subject": { "identity_id": "...", "org_id": "...", "agent_id": "acme-agent-7" },
    "issuer": { "common_name": "Specora Demo Root", "organizational_unit": "for-demo-only-not-production", "organization": "Specora" },
    "public_key": "...",
    "issuer_key_fingerprint": "...",
    "issued_at": "2026-05-08T12:00:00Z",
    "not_after": "2026-06-07T12:00:00Z",
    "signature": "..."
  }
}
```

### 3.2 Header propagation — `record.request_metadata["x-specora-agent-identity"]`

Used when the agent prefers to keep the request body untouched (some Anthropic clients deliberately don't mirror non-content body fields to the compliance log). The cert is attached as a propagated header instead, and the provider surfaces it under a `request_metadata` map:

```jsonc
{
  "record_id": "rec-id-000004",
  "timestamp": "2026-06-10T14:22:04Z",
  "request_metadata": {
    "x-specora-agent-identity": {
      "format": "specora-aid-cert-v1-demo",
      "subject": { "identity_id": "...", "org_id": "...", "agent_id": "acme-agent-9" },
      "issuer": { "common_name": "Specora Demo Root", "organizational_unit": "for-demo-only-not-production", "organization": "Specora" },
      "public_key": "...",
      "issuer_key_fingerprint": "...",
      "issued_at": "2026-05-08T12:00:00Z",
      "not_after": "2026-06-07T12:00:00Z",
      "signature": "..."
    }
  }
}
```

### 3.3 Reader-side priority

If a record carries **both** an embedded `agent_identity` and a header-propagated copy, the reader prefers the direct embedding. They should always be byte-equal anyway — both come from the same SDK call — but the priority gives a deterministic tie-breaker so canonicalization is reproducible.

---

## 4. Minimal reader implementation

Every reader gets a small helper. The Anthropic reference reader implements it like this:

```python
# specora_verify/readers/anthropic.py
@staticmethod
def _extract_agent_identity(record: dict) -> dict | None:
    direct = record.get("agent_identity")
    if isinstance(direct, dict):
        return direct
    request_metadata = record.get("request_metadata")
    if isinstance(request_metadata, dict):
        header_identity = request_metadata.get("x-specora-agent-identity")
        if isinstance(header_identity, dict):
            return header_identity
    return None
```

The mapped record then conditionally adds the field:

```python
identity = self._extract_agent_identity(record)
if identity is not None:
    mapped["agent_identity"] = identity
```

That is the entire reader-side surface. No more code, no validation, no logging, no metric labels.

### 4.1 Test coverage required

Every reader that adds this surface MUST also add three tests under `tests/readers/`:

1. **Direct lift** — a fixture with `record["agent_identity"]` produces a bundle with the field preserved verbatim. Verified via `validate_bundle_v1_1` with the issuer pubkey pinned out-of-band.
2. **Header lift** — same, but via `record["request_metadata"]["x-specora-agent-identity"]`.
3. **No fabrication** — an existing v1.0 fixture (no agent identity claim anywhere) produces a bundle with no `agent_identity` field on any record. This is the doctrinal anti-test.

Optional but recommended:

4. **Tampering** — mutate a lifted cert byte after the read; assert the verifier flips that record to `invalid` with reason `"signature does not verify"`. Catches "did the reader normalize the bytes" regressions.

The Anthropic reference reader's tests are at [`tests/readers/test_anthropic_identity.py`](../../tests/readers/test_anthropic_identity.py).

---

## 5. Per-reader status (demo lane)

| Reader | Status | Fixture | Test |
|---|---|---|---|
| `anthropic` | **shipped (AID-940 reference)** | `tests/fixtures/anthropic/with-identity-direct.jsonl`, `with-identity-header.jsonl` | [`tests/readers/test_anthropic_identity.py`](../../tests/readers/test_anthropic_identity.py) |
| `cloudtrail` | deferred to post-demo per [freeze-exception §3.3](https://github.com/SpecoraAI/specora-platform) |  |  |
| `azure_cl` | deferred to post-demo |  |  |
| `openai_compliance` | deferred to post-demo |  |  |
| `langsmith` | deferred to post-demo |  |  |

Adding pass-through to a deferred reader is a one-PR change that follows §4 above. The 30-line `_extract_agent_identity` helper is portable across readers because the upstream JSON keys (`agent_identity`, `request_metadata.x-specora-agent-identity`) are an SDK-side convention, not a per-provider convention.

---

## 6. Out-of-scope this page

- The AID-910 cert format itself (see [`agent-identity.md` schema reference](../../docs/schemas/canonical-bundle-v1.1.json) `$defs/agent_identity_envelope`).
- The AID-930 SDK helpers that emit the cert (see [`sdk/python/examples/agent-identity-quickstart.py`](https://github.com/SpecoraAI/specora-platform) in the platform repo).
- Production format. The `-demo` suffix is load-bearing throughout the demo lane; production will revise it.
