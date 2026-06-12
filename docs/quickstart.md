# Quickstart — Produce and verify an evidence bundle in 5 minutes

This quickstart walks the full producer-to-verifier loop for a real
provider audit log, using the Anthropic Compliance API reader shipped
in [EPIC-A03](https://github.com/SpecoraAI/specora-platform/blob/main/docs/strategy/category-switch-epic-suite.md#epic-a03--first-provider-audit-log-reader-anthropic-compliance-api----done-2026-04-15).

You will:

1. Take a sample Anthropic Compliance API JSONL export.
2. Run the `specora-verify read anthropic` CLI to produce a canonical
   bundle payload.
3. Verify the bundle is deterministic (byte-identical across runs).
4. Confirm the canonical round-trip — canonicalizing the bundle again
   produces the same bytes.
5. Understand what just happened in terms of the wire spec.

**Time:** ≤5 minutes if you already have Python 3.11+ installed.
**No network calls. No API keys. No accounts.**

> **In a hurry? The 60-second proof.** If you only want to see that this tool
> verifies what Specora signs without trusting Specora, skip ahead and run the
> shipped sample:
>
> ```sh
> pip install "specora-verify[crypto]"
> git clone https://github.com/SpecoraAI/specora-verify.git && cd specora-verify
> ./examples/verify-sample-bundle.sh            # fetch the published issuer key
> # or ./examples/verify-sample-bundle.sh --offline   # use the pinned key, no network
> ```
>
> It fetches Specora's published issuer key, checks the key's fingerprint
> against the value pinned in [issuer-key-pinning.md](issuer-key-pinning.md),
> and verifies a pre-built Specora-issued credential against it. A `PASS` means
> the credential verified on your machine against a key you pinned, with no
> Specora service in the loop. The sample is signed by the prelaunch
> **DEMO-ROOT** key (`for-demo-only-not-production`), not the production C01
> ceremony root.

## 1. Prerequisites

```sh
# Python 3.11, 3.12, or 3.13
python3 --version

# Clone the verifier
git clone https://github.com/SpecoraAI/specora-verify.git
cd specora-verify

# Install in editable mode with optional signing extras
pip install -e ".[crypto]"
```

## 2. Use the shipped fixture

The repo ships a deterministic minimal fixture at
[`tests/fixtures/anthropic/minimal-valid.jsonl`](../tests/fixtures/anthropic/minimal-valid.jsonl)
(2 records) and a realistic fixture at
[`tests/fixtures/anthropic/realistic-complex.jsonl`](../tests/fixtures/anthropic/realistic-complex.jsonl)
(47 records, 2 models, all 4 decision outcomes).

```sh
head -1 tests/fixtures/anthropic/minimal-valid.jsonl | python3 -m json.tool | head -20
```

You should see a single Anthropic compliance record: one AI decision
with input hash, decision outcome, model identifier, timestamp, and
optional upstream signature.

## 3. Read → canonical bundle

```sh
specora-verify read anthropic \
  --input  tests/fixtures/anthropic/minimal-valid.jsonl \
  --key-id spk-e1c8139bffc31826 \
  --out    /tmp/bundle.json
```

The output `/tmp/bundle.json` is a **canonical JSON payload** — sorted
keys, compact separators, ASCII-escaped, no trailing newline. See
[wire-spec-v1.0.md §3](wire-spec-v1.0.md#3-canonicalization) for the
exact rule.

This is the payload that a Signed Artifact Envelope
([§2.8](wire-spec-v1.0.md#28-signed-artifact-envelope)) would wrap.

## 4. Determinism check

The whole point of canonical serialization is that the same input
produces byte-identical output every time. Prove it:

```sh
specora-verify read anthropic \
  --input tests/fixtures/anthropic/minimal-valid.jsonl \
  --key-id spk-e1c8139bffc31826 \
  --out /tmp/bundle-run-1.json

specora-verify read anthropic \
  --input tests/fixtures/anthropic/minimal-valid.jsonl \
  --key-id spk-e1c8139bffc31826 \
  --out /tmp/bundle-run-2.json

cmp -s /tmp/bundle-run-1.json /tmp/bundle-run-2.json && echo "DETERMINISTIC ✓"
```

If the `cmp -s` check fails, your Python environment has introduced
non-determinism somewhere (most likely a non-frozen dict ordering in
an older Python, or locale-dependent float formatting). File an
issue — this is a showstopper, not a warning.

## 5. Canonical round-trip

Canonicalizing an already-canonical payload MUST produce the same
bytes:

```sh
python3 - <<'PY'
import json
from specora_verify.canonical import canonicalize
payload = json.loads(open("/tmp/bundle-run-1.json").read())
roundtripped = canonicalize(payload)
with open("/tmp/bundle-run-1.json", "rb") as f:
    assert f.read() == roundtripped, "ROUND-TRIP FAILED"
print("ROUND-TRIP PASS ✓")
PY
```

A failing round-trip means the reader produced a payload that is not
a fixed point of the canonicalizer — that is a reader bug, not a
spec bug.

## 6. Verify against the wire-spec schema

```sh
python3 - <<'PY'
import json, jsonschema
schema = json.loads(open("docs/schemas/governance-attestation-v1.0.json").read())
# Replace with the schema matching your bundle's spec_id; for readers
# that emit custom bundle.records shapes, see the reader doc.
print("Schema loaded:", schema["title"])
PY
```

Each canonical payload type in the wire spec has a schema under
[`docs/schemas/`](schemas/). The shipped test
[`tests/test_wire_spec_schemas.py`](../tests/test_wire_spec_schemas.py)
is the executable form of this step — it loads every schema and
validates every golden vector in `vectors/` in CI on every commit.

## 7. What just happened — wire-spec framing

| Step | Wire-spec reference |
|---|---|
| JSONL → canonical payload | [§3 Canonicalization](wire-spec-v1.0.md#3-canonicalization) |
| Bit-identical across runs | [§3.1 Normative rule](wire-spec-v1.0.md#31-normative-rule) + [§8.2 Verifier conformance](wire-spec-v1.0.md#82-verifier-conformance) |
| Round-trip fixed point | [§3.2 Field-level rules](wire-spec-v1.0.md#32-field-level-rules) |
| Schema validation | [§2 Data model](wire-spec-v1.0.md#2-data-model) + [`docs/schemas/`](schemas/) |
| Signing (not shown here) | [§4 Signing](wire-spec-v1.0.md#4-signing) — use the `--sign` flag with a real Ed25519 private key. |

## 8. Running the shipped end-to-end example

There is a one-command runnable version of this quickstart at
[`examples/anthropic-quickstart.sh`](../examples/anthropic-quickstart.sh):

```sh
./examples/anthropic-quickstart.sh
```

It runs steps 3–5 in sequence and prints `PASS` on success. This is
the same example that [EPIC-A03 §Deliverables](https://github.com/SpecoraAI/specora-platform/blob/main/docs/strategy/category-switch-epic-suite.md#epic-a03--first-provider-audit-log-reader-anthropic-compliance-api----done-2026-04-15) ships.

## 9. Next steps

- Read [wire-spec-v1.0.md](wire-spec-v1.0.md) end-to-end (~20 min).
- Read [readers/anthropic.md](readers/anthropic.md) for the full
  schema-mapping table from Anthropic Compliance API fields to the
  Specora bundle fields.
- Read [trust-model.md](trust-model.md) for the audit-doctrine
  framing: why the verifier is structurally separate from the
  producer, and why that matters.
- See [vectors.md](vectors.md) to add or regenerate golden vectors.
