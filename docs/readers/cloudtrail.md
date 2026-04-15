# AWS CloudTrail Lake reader (Bedrock Automated Reasoning Checks)

Ingests a **CloudTrail JSON export** — the standard
`{"Records": [<event>, …]}` archive shape produced by CloudTrail's S3
delivery, by CloudTrail Lake query exports, and by
`aws cloudtrail lookup-events` — and produces a Specora wire-spec
evidence-bundle payload.

The reader is **Bedrock-first**: it filters on Bedrock events and
extracts the **Automated Reasoning Checks** proof payload
(`verdict`, `proofHash`, `logicalConstraints`) when present.

- **CLI:** `specora-verify read cloudtrail`
- **Module:** [`specora_verify/readers/cloudtrail.py`](../../specora_verify/readers/cloudtrail.py)
- **Tests:** [`tests/readers/test_cloudtrail.py`](../../tests/readers/test_cloudtrail.py) + [`tests/test_cli_read.py`](../../tests/test_cli_read.py)
- **Fixtures:** [`tests/fixtures/cloudtrail/`](../../tests/fixtures/cloudtrail/)
- **Example:** [`examples/cloudtrail-quickstart.sh`](../../examples/cloudtrail-quickstart.sh)
- **Schema versions supported:** CloudTrail `eventVersion` `1.08` and `1.09`

## 1. How to get the upstream export

CloudTrail delivers events to an S3 bucket (or to CloudTrail Lake). To
get the export this reader ingests, run one of:

```bash
# Option A — CloudTrail archive format from S3 delivery
aws s3 cp s3://my-cloudtrail-bucket/AWSLogs/.../file.json.gz - | gunzip > ct.json

# Option B — CloudTrail Lake query export (filter on Bedrock AR events)
aws cloudtrail start-query --query-statement \
  "SELECT * FROM <event-data-store-id> \
   WHERE eventSource = 'bedrock.amazonaws.com' \
     AND eventName IN ('InvokeModelWithAutomatedReasoning', \
                       'InvokeModelWithResponseStreamWithAutomatedReasoning', \
                       'ApplyAutomatedReasoningPolicy')" \
  --event-data-store <event-data-store-id>
# Then poll get-query-results and aggregate into {"Records": [...]}.
```

Either export produces a JSON document with a top-level `Records`
array of CloudTrail event envelopes. The reader accepts both.

The reader **never talks to AWS directly** — it only reads a file the
customer has already exported with their own AWS credentials. This
preserves the offline-verifier posture of `specora-verify`.

### Upstream integrity model — no per-event signatures

CloudTrail has **no per-event signatures**. Integrity is anchored at
the **log file validation** level: CloudTrail periodically emits a
signed digest file covering a batch of log files, and an auditor
confirms the batch with
[`aws cloudtrail validate-logs`](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html).

The reader therefore marks each mapped record's `upstream_signature`
as a descriptor:

```json
{
  "absent_per_record": true,
  "integrity_mechanism": "cloudtrail-log-file-validation"
}
```

Run `aws cloudtrail validate-logs` against the source log files
**before** handing them to the reader — that is how auditor-side trust
is established for CloudTrail inputs. This pre-processing step is
deliberately out of scope for the reader itself.

## 2. Upstream event shape (Bedrock AR Checks)

One `Records[]` entry per Bedrock inference call subject to
Automated Reasoning Checks:

```json
{
  "eventVersion": "1.09",
  "eventTime": "2026-06-10T14:22:17Z",
  "eventSource": "bedrock.amazonaws.com",
  "eventName": "InvokeModelWithAutomatedReasoning",
  "awsRegion": "us-east-1",
  "eventID": "ct-event-000001",
  "userIdentity": { "...": "..." },
  "requestParameters": {
    "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
    "automatedReasoningPolicyId": "arp-abc123",
    "inputTokens": 1543,
    "maxTokens": 2048
  },
  "responseElements": {
    "requestId": "req-bedrock-00000001",
    "modelInvocationResult": "approved",
    "automatedReasoningResult": {
      "verdict": "valid",
      "proofHash": "sha256:...",
      "logicalConstraints": ["constraint-1", "constraint-3"],
      "escalationRequired": false
    },
    "outputTokens": 389
  }
}
```

## 3. Schema mapping (upstream → Specora wire spec)

| Upstream field | Specora wire spec field | Transformation |
|---|---|---|
| `eventID` | `bundle.records[].id` | Copy as-is |
| `eventTime` | `bundle.records[].timestamp` | Normalize to RFC 3339 UTC with explicit `Z` suffix (`+00:00` rewritten) |
| `eventName` | `bundle.records[].upstream_event_name` | Copy; must be in AR-event allowlist |
| `awsRegion` | `bundle.records[].aws_region` | Copy as-is (non-empty string) |
| `responseElements.requestId` | `bundle.records[].upstream_request_id` | Copy as-is |
| `requestParameters.modelId` | `bundle.records[].model.{name, version}` | Split on `-YYYYMMDD...` boundary. `anthropic.claude-3-5-sonnet-20240620-v1:0` → `{name: "anthropic.claude-3-5-sonnet", version: "20240620-v1:0"}` |
| `requestParameters.automatedReasoningPolicyId` | `bundle.records[].decision.policy_refs[0]` | Wrapped in a single-element array |
| `responseElements.modelInvocationResult` | — *(input to enum-mapper)* | Combined with AR verdict to derive `decision.outcome` |
| `responseElements.automatedReasoningResult.verdict` | `bundle.records[].decision.formal_verdict` | Preserved verbatim (`valid` / `invalid` / `unknown`) |
| `responseElements.automatedReasoningResult.proofHash` | `bundle.records[].decision.proof_hash` | Copy; must start with `sha256:` |
| `responseElements.automatedReasoningResult.logicalConstraints` | `bundle.records[].decision.constraints` | Preserved verbatim as a JSON array |
| `responseElements.automatedReasoningResult.escalationRequired` | — *(input to enum-mapper)* | Triggers `decision.outcome = "escalated"` when true |
| *(derived)* | `bundle.records[].decision.outcome` | Mapped to enum `{approved, rejected, deferred, escalated}` — precedence: explicit escalation > AR verdict > invocation result |
| *(derived)* | `bundle.records[].context.hash` | `"sha256:" + sha256(canonical_json({requestParameters, responseElements}))` |
| *(derived)* | `bundle.records[].upstream_signature` | `{"absent_per_record": true, "integrity_mechanism": "cloudtrail-log-file-validation"}` |
| `eventVersion` | `bundle.metadata.upstream_schema_version` | Must be in `supported_schema_versions` (currently `("1.08", "1.09")`) |
| `userIdentity`, `inputTokens`, `outputTokens` | *(discarded)* | Operational telemetry — not audit evidence |

### Decision outcome mapping

| AR verdict | `escalationRequired` | `modelInvocationResult` | → wire-spec outcome |
|---|---|---|---|
| `valid` | `false` | `approved` | `approved` |
| `invalid` | `false` | `blocked` | `rejected` |
| `unknown` | `false` | `pending` | `deferred` |
| `valid` | `true` | *(any)* | `escalated` |
| *(missing)* | `false` | `approved` / `blocked` / … | fallback to invocation result |

## 4. Filtering behavior

The reader applies two filters before mapping:

1. **`eventSource` filter.** Events whose `eventSource` is not
   `bedrock.amazonaws.com` are silently skipped. This lets you point
   the reader at an un-filtered CloudTrail export containing events
   from many AWS services.
2. **AR event name allowlist.** Bedrock events whose `eventName` is
   not in the AR allowlist (`InvokeModelWithAutomatedReasoning`,
   `InvokeModelWithResponseStreamWithAutomatedReasoning`,
   `ApplyAutomatedReasoningPolicy`) are silently skipped. A plain
   `InvokeModel` call is a non-AR Bedrock invocation and has no AR
   proof to preserve.

Skipped events are aggregated into a single `non-AR` warning in
non-strict mode. Strict mode does **not** fail on skipped events —
filtering is a feature, not an error, and the whole point is to let
an auditor hand the reader an unfiltered export.

## 5. Example invocation

```bash
specora-verify read cloudtrail \
    --input cloudtrail-export.json \
    --key-id spk-abcd1234 \
    --out bundle.json
```

Output is canonical JSON (sorted keys, compact separators, UTF-8).
Two runs against the same input produce byte-identical output — the
determinism invariant, enforced by a hypothesis property test.

### Non-strict mode — drop broken records with warnings

```bash
specora-verify read cloudtrail \
    --input cloudtrail-export.json \
    --key-id spk-abcd1234 \
    --non-strict \
    --out bundle.json
```

`--non-strict` drops malformed records (missing `eventID`, invalid
`proofHash`, etc.) with a warning instead of failing the whole read.

### `--public-key` is accepted but ignored

```bash
specora-verify read cloudtrail \
    --input cloudtrail-export.json \
    --key-id spk-abcd1234 \
    --public-key some-key.hex \
    --out bundle.json
```

The flag exists for interface symmetry with other readers. CloudTrail
has no per-event signatures, so the key material is not used. Integrity
comes from pre-processing the export with
`aws cloudtrail validate-logs`.

## 6. Common errors

| Error code | Meaning | What to do |
|---|---|---|
| `READER_SCHEMA_ERROR: input is not valid JSON` | File is not JSON | Check the export — did you forget to `gunzip`? |
| `READER_SCHEMA_ERROR: input must be a JSON object with a top-level 'Records' array` | Wrong envelope shape | Confirm the export is a CloudTrail archive file or Lake export — some CLI output formats lack the `Records` wrapper |
| `READER_SCHEMA_ERROR: missing required field 'eventID'` | CloudTrail record missing a mandatory envelope field | Likely a truncated or hand-edited export — regenerate from the source |
| `READER_SCHEMA_ERROR: requestParameters.automatedReasoningPolicyId must be a non-empty string` | A Bedrock AR event is missing its policy ID | Confirm the event is genuinely AR-gated; non-AR Bedrock calls are filtered out automatically |
| `READER_SCHEMA_ERROR: automatedReasoningResult.proofHash must start with 'sha256:'` | Proof hash has the wrong form | Check against AWS's current AR Checks event schema |
| `READER_SCHEMA_ERROR: unsupported eventVersion 'X'` | CloudTrail released a new `eventVersion` | Upgrade `specora-verify`, or pin `--schema-version 1.09` if AWS's change is backwards-compatible |
| `READER_IO_ERROR: file not found` | Input path does not exist | Check the path |

## 7. References

- AWS CloudTrail event reference — [CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) and [CloudTrail Lake](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html).
- Amazon Bedrock Automated Reasoning Checks — refer to AWS's current Bedrock Guardrails documentation for the AR Checks event shape.
- CloudTrail log file validation — [Validating CloudTrail log file integrity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html).
- Specora wire spec v1.0 — [`docs/wire-spec-v1.0.md`](../wire-spec-v1.0.md).
- Reader design notes — platform-repo `docs/strategy/b01-reader-design-notes-2026-Q2.md` §4 (CloudTrail-specific) and §9 (decisions log).
