# LangSmith Fleet Reader

## What it is

The LangSmith Fleet reader ingests audit-trace exports from LangSmith
Fleet — LangChain's enterprise observability, tracing, and evaluation
platform — and maps each trace onto the Specora wire-spec canonical
evidence-bundle shape. The reader is **offline** — it never calls the
LangSmith API. It reads a file the customer has already exported using
their own LangSmith credentials.

LangSmith Fleet is used by engineering teams running LangChain-based AI
applications in production. Fleet adds enterprise features on top of
the open-source LangSmith: team workspaces, RBAC, compliance exports,
evaluation pipelines, and guardrail integrations. The trace export
captures every LLM call, chain execution, tool invocation, and
retriever step — along with human feedback and automated evaluation
results attached to each run.

**Status:** design-accurate against the publicly documented LangSmith
API (`GET /runs`, `POST /runs/query`, SDK `client.list_runs()`). Pending
live-data validation once a production Fleet export is available. The
reader is fully exercised end-to-end against synthetic fixtures.

## Authentication model

The reader itself requires no credentials. It reads a pre-exported file.

The *export* step (outside `specora-verify`) uses the customer's
LangSmith API key (scoped to the workspace). Export methods:

1. **UI export**: LangSmith dashboard > Projects > select runs > Export JSON
2. **API export**: `GET /runs` or `POST /runs/query` with filters
3. **SDK programmatic access**: `client.list_runs(project_name=...)` in
   the `langsmith` Python SDK, serialized to JSON

The export produces a JSON file with the envelope:

```json
{"runs": [...trace objects...]}
```

`specora-verify` also accepts bare JSON arrays and JSON Lines (one
trace per line) for batch export workflows.

## Event shape (design-accurate)

Each trace/run object carries at minimum:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique run identifier (UUID) |
| `name` | string | Run name (chain, agent, or tool name) |
| `run_type` | string | `chain`, `llm`, `tool`, `retriever`, `prompt`, `parser`, `embedding` |
| `start_time` | string or int | RFC 3339 UTC timestamp or unix seconds |
| `status` | string | `success`, `error`, or `pending` (streaming) |
| `evaluation.outcome` | string | Fleet compliance verdict (`pass`, `fail`, `pending`, etc.) |
| `evaluation.rule_ids` | array | Guardrail / evaluation rule references |
| `content_hash` | string | `sha256:` prefixed hash of trace content |

Optional fields preserved when present:

| Field | Maps to |
|-------|---------|
| `model_name` (or `extra.invocation_params.model_name`) | `records[].model.{name, version}` |
| `feedback[]` | `records[].upstream_feedback` (first-class) |
| `token_usage` | `records[].upstream_token_usage` |
| `total_cost` | `records[].upstream_cost` |
| `session_id` | `records[].upstream_session_id` |

## What the reader extracts as first-class evidence

### Feedback scores (LangSmith's differentiator)

LangSmith's core value proposition is the evaluation layer. Human
reviewers and automated evaluators attach typed feedback to runs:

```json
{
  "upstream_feedback": [
    {"key": "correctness", "score": 1.0, "comment": "Output matches expected", "source": "human"},
    {"key": "helpfulness", "score": 0.9, "source": "automated"}
  ]
}
```

This is the equivalent of CloudTrail's Bedrock Automated Reasoning
Checks result or OpenAI's moderation block — the evidence that an
independent party evaluated the AI output.

### Token usage and cost

When present, token counts and cost are preserved verbatim:

```json
{
  "upstream_token_usage": {"prompt_tokens": 245, "completion_tokens": 89, "total_tokens": 334},
  "upstream_cost": 0.00512
}
```

### Model identification

The reader resolves model identity from three locations (in order):
1. Top-level `model_name` field
2. `extra.invocation_params.model_name` (or `.model`)
3. `serialized.kwargs.model_name`

Model names with date suffixes (e.g. `claude-3-5-sonnet-20241022`) are
split into name + version automatically.

## Outcome mapping

The reader maps LangSmith evaluation outcomes to the Specora wire-spec
decision enum:

| LangSmith outcome | Wire-spec outcome |
|-------------------|-------------------|
| `pass`, `correct`, `ok`, `success`, `allowed` | `approved` |
| `fail`, `incorrect`, `block`, `error`, `reject` | `rejected` |
| `pending`, `needs_review`, `flagged`, `unknown` | `deferred` |
| `escalated`, `escalate`, `manual_review` | `escalated` |

## Integrity model

LangSmith Fleet does **not** emit per-trace cryptographic signatures.
Integrity is anchored at the TLS transport layer
(`api.smith.langchain.com`) and by the Fleet tenant's audit log. Each
mapped record carries:

```json
{
  "upstream_signature": {
    "absent_per_record": true,
    "integrity_mechanism": "langsmith-fleet-api-tls-attested"
  }
}
```

The Specora outer signature tier (Ed25519, applied by `specora-verify
run`) is what the verifier checks offline.

## How to export

### UI export

1. Log in to LangSmith at `smith.langchain.com`.
2. Navigate to your project.
3. Select the runs you want to export (filter by date, tags, status).
4. Click **Export > JSON** to download the trace archive.

### API export

```bash
curl -s "https://api.smith.langchain.com/runs/query" \
  -H "x-api-key: $LANGSMITH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"project_name": "my-project", "limit": 100}' \
  -o langsmith-export.json
```

### SDK programmatic access

```python
from langsmith import Client

client = Client()
runs = list(client.list_runs(project_name="my-project", limit=100))

import json
with open("langsmith-export.json", "w") as f:
    json.dump({"runs": [r.dict() for r in runs]}, f)
```

## How to feed into specora-verify

```bash
# Ingest and produce a canonical bundle payload
specora-verify read langsmith \
    --input langsmith-export.json \
    --key-id spk-your-key-id \
    --out bundle-payload.json

# Full end-to-end pipeline (read + sign + write verifiable bundle)
specora-verify run \
    --provider langsmith \
    --input langsmith-export.json \
    --key-id spk-your-key-id \
    --private-key /path/to/ed25519.key \
    --out ./my-bundle/
```

## Module reference

- Reader: `specora_verify/readers/langsmith.py`
- CLI subcommand: `specora-verify read langsmith`
- Canonical bundle schema: `docs/schemas/canonical-bundle-v1.0.json`
- Test fixtures: `tests/fixtures/langsmith/`
