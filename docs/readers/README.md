# Provider audit-log readers

`specora-verify` ships with a family of **readers** that ingest the
audit-log exports major AI providers already produce and map them onto
the Specora wire-spec evidence-bundle shape. With a reader, any
operator running on a supported platform can produce a
Specora-verifiable bundle with **zero vendor cooperation** — the
reader never talks to the upstream provider's API directly, it only
reads a file the customer has already exported.

This directory is the user-facing documentation for each shipped
reader. One file per provider, same structure everywhere:

1. Upstream schema summary (what the provider exports)
2. Schema mapping table (how each field lands in the Specora bundle)
3. Example invocation (copy-pasteable CLI command)
4. Common errors (and what to do about them)

## Currently shipped

| Reader | CLI | Docs | Fixtures | Status |
|---|---|---|---|---|
| Anthropic Claude Enterprise Compliance API | `specora-verify read anthropic` | [anthropic.md](anthropic.md) | [`tests/fixtures/anthropic/`](../../tests/fixtures/anthropic/) | shipped 2026-04-15 (A03) |
| AWS CloudTrail Lake + Bedrock Automated Reasoning Checks | `specora-verify read cloudtrail` | [cloudtrail.md](cloudtrail.md) | [`tests/fixtures/cloudtrail/`](../../tests/fixtures/cloudtrail/) | shipped 2026-04-15 (B01 #1) |

## Planned (B01 reader suite, Q3 2026)

| Reader | Upstream source |
|---|---|
| Azure Confidential Ledger | Confidential Ledger receipts for AI inference records |
| OpenAI Compliance Platform | OpenAI Compliance Platform JSONL export |
| LangSmith Fleet | LangSmith Fleet audit-log export |

Each reader is implemented behind the same `ReaderProtocol` interface
and registered via the `@reader("<name>")` decorator in
`specora_verify/readers/`. Adding a reader is one module plus one
fixture directory plus one doc file here — see [anthropic.md](anthropic.md)
and [`specora_verify/readers/anthropic.py`](../../specora_verify/readers/anthropic.py)
for the canonical worked example.

The convention-agnostic design doc that governs the reader pattern
lives in the internal Specora platform repo at
`docs/strategy/b01-reader-design-notes-2026-Q2.md` and is linked from
the epic suite entry for EPIC-A03 / EPIC-B01.

## Offline, no network calls

Every reader is offline by construction. No reader talks to the
upstream provider's API, fetches credentials, or depends on DNS. This
is load-bearing for the trust-bootstrap posture of `specora-verify`:
an auditor can run the reader on an air-gapped laptop and get the
same result as CI, by design.

## Determinism invariant

Given an identical upstream export and identical input parameters,
every reader produces a **byte-identical** canonical bundle payload
across runs. This invariant is enforced per-reader by a hypothesis
property test — see the respective test module under
`tests/readers/`.
