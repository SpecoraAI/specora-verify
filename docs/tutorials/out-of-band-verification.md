# Out-of-band verification in one command

**You don't need to replace your existing governance tooling — Specora attests it.**

If you already log every LLM decision to Anthropic's Compliance API, CloudWatch + CloudTrail for AWS Bedrock, or Azure Confidential Ledger, you don't need another observability stack. You need *independent proof* that what those logs say actually happened, signed by a key you control, in a format a regulator or external auditor can check offline.

That is the job of `specora-verify run`. One command, one provider export, one signed bundle. No inline interception. No network calls to Specora. No replacement of anything you already have.

---

## Why this exists (Golden Circle)

We believe AI that acts must prove it deserves to. Proof replaces promise.

Today, most teams "govern" their AI by piping events into a dashboard and hoping nobody asks where the dashboard gets its numbers from. Dashboards are monitoring. They are not verification. Specora treats provider audit logs as raw evidence and transforms them into an independently-verifiable, cryptographically-bound bundle that an auditor can re-check on their own laptop, without talking to us.

Out-of-band verification is the bootstrap: you keep running your provider stack exactly as you do today; `specora-verify run` turns its export into proof.

---

## How it works — one pipeline, three shipped providers

```
provider export  ─►  reader  ─►  canonical bundle  ─►  Ed25519 sign  ─►  signed bundle dir
                                                                                │
                                                                                ▼
                                                                   specora-verify verify  ─►  PASS
```

The shipped readers today are:

| Provider           | CLI name      | Input                                              |
|--------------------|---------------|----------------------------------------------------|
| Anthropic          | `anthropic`   | Compliance API JSONL export                        |
| AWS CloudTrail     | `cloudtrail`  | CloudTrail JSON export (Bedrock AR Checks)         |
| Azure Conf. Ledger | `azure-cl`    | Confidential Ledger entries-with-receipts JSON     |

OpenAI Compliance Platform and LangSmith Fleet are on the B01 landing schedule and integrate with zero changes to the pipeline — the canonical bundle schema is normative and forward-compatible.

---

## What you do

### 1. Install with the crypto extra

```bash
pip install "specora-verify[crypto]"
```

The core verifier is stdlib-only, but signing needs `cryptography`. That is why the `run` subcommand requires the `crypto` extra and `verify` does not.

### 2. Export your provider's audit log

- **Anthropic**: `GET /v1/compliance/exports` → save as `export.jsonl`
- **CloudTrail**: `aws cloudtrail lookup-events --event-source bedrock.amazonaws.com --output json > export.json`
- **Azure CL**: `az confidentialledger get-ledger-entry --collection-id ... > export.json`

### 3. Generate (or supply) an Ed25519 signing key

```bash
python3 -c 'import os; open("signing.hex","w").write(os.urandom(32).hex())'
```

Your key, your custody. `specora-verify` never sees it except to sign the bundle in-process.

### 4. Run the pipeline

```bash
specora-verify run \
    --provider anthropic \
    --input export.jsonl \
    --key-id corp-auditor-2026-q2 \
    --private-key signing.hex \
    --out ./bundle-2026-q2/
```

You get:

```
bundle-2026-q2/
    payload.json       ← canonical bundle (sorted, compact JSON)
    payload.sig        ← base64 Ed25519 signature
    signing-key.pub    ← base64 public key
    metadata.json      ← provider, key_id, record_count, payload_sha256
```

### 5. Verify it — on any machine, offline

```bash
specora-verify verify \
    --artifact  ./bundle-2026-q2/payload.json \
    --signature ./bundle-2026-q2/payload.sig \
    --public-key ./bundle-2026-q2/signing-key.pub
```

`Status: PASS` (or `WARN` with a trust-list advisory) means the signature is cryptographically valid. `Status: FAIL` means the bundle has been tampered with, full stop — hand it to your security team.

### 6. Send it to your auditor

The bundle directory is self-contained. Hand the folder (or a zip of it) to an external auditor or regulator. They run exactly the same `specora-verify verify` command on their own laptop. They do not need a Specora account. They do not need network access. They do not need to trust us. That is the whole point.

---

## What happens if the bundle is tampered with

We wrote the e2e test for this — it's the single most important property of the whole pipeline. See [`tests/e2e/test_out_of_band_flow.py::test_run_verify_rejects_tampered_bundle`](../../tests/e2e/test_out_of_band_flow.py). The test:

1. Runs the full pipeline against the Anthropic fixture.
2. Confirms the bundle verifies clean.
3. Mutates one byte of the payload (adds a `__tamper__` field).
4. Confirms the verifier returns `FAIL`.

If that test ever goes green on a tampered bundle, Specora is not a verifier and we treat it as a P0 incident.

---

## Common questions

**Do I have to run this at request time?** No. `run` is explicitly an out-of-band flow. You run it on a cadence (nightly, weekly, before an audit meeting). Inline interception is a separate product surface and is not required for proof.

**Does my auditor need Specora installed?** Only the `specora-verify` CLI — which is Apache 2.0, pip-installable, under 1 MB, and stdlib-only for the core `verify` path.

**What if my provider isn't in the shipped list?** The reader interface is `ReaderProtocol`. See [`docs/readers/`](../readers/) for the contribution guide. A new reader is ~200 lines of code and drops into the same `specora-verify run --provider <name>` command with zero changes to orchestration.

**Where are the canonical schema and wire spec?**

- Canonical bundle schema: [`docs/canonical-bundle-schema-v1.0.md`](../canonical-bundle-schema-v1.0.md)
- Machine-readable JSON Schema: [`docs/schemas/canonical-bundle-v1.0.json`](../schemas/canonical-bundle-v1.0.json)
- Wire spec v1.0: [`docs/wire-spec-v1.0.md`](../wire-spec-v1.0.md)

**Can I script this in CI?** Yes. `run` returns `0` on success, `2` on reader/orchestration failure. Pipe the output dir to your artifact store and the signed bundle becomes an immutable build artifact.

---

## What this tutorial does *not* cover

- **Live inline interception.** Specora has a separate proxy/execute mode for real-time policy enforcement; out-of-band verification deliberately does not depend on it.
- **Multi-party signing.** The bundle format supports multi-sig via the evidence ledger; that's a platform feature handled by the sponsor-facing dashboard, not this CLI.
- **Foundation-hosted trust roots.** See the CNCF application and `GOVERNANCE.md` for the independence story.

Everything in this tutorial runs today, on the CLI you just installed, against the committed fixtures in `tests/fixtures/`. If any step doesn't work, that is a bug — please file it against [SpecoraAI/specora-verify](https://github.com/SpecoraAI/specora-verify).
