# Roadmap

This is the public roadmap for `specora-verify`. It is 6-month granularity and covers only the verifier project: the CLI, the wire spec, the readers, the golden vectors, and the trust-bootstrap milestones that belong to the open-source project.

**This roadmap is intentionally scoped to the OSS verifier.** Commercial product plans, revenue targets, customer pipelines, and internal business strategy are not part of this document. If you are looking for those, they belong in a different repository and are not public.

Last updated: 2026-04-15.

## Horizon 1 — 2026-H1 (current, through 2026-06-14)

### Shipped

- **v1.0.0 release** — initial Apache 2.0 public release (planned flip 2026-06-14). Private working history since 2026-04-14.
- **Wire spec v1.0** — `docs/wire-spec-v1.0.md` with 8 JSON Schemas in `docs/schemas/`.
- **Schema conformance tests** — `tests/test_wire_spec_schemas.py` executes every golden vector against every schema.
- **Versioning policy** — `docs/versioning-policy.md` describing the SemVer contract and Frozen Canonicalizer lock-step rule.
- **Trust model** — `docs/trust-model.md` describing what the verifier does and does not assume.
- **Quickstart** — `docs/quickstart.md` with end-to-end verification walkthrough.
- **Reader #1: AWS CloudTrail Lake** — `specora_verify/readers/cloudtrail.py`, `docs/readers/cloudtrail.md`, end-to-end CLI subcommand, integration tests.
- **Reader #2: Anthropic Compliance API** — `specora_verify/readers/anthropic.py`, `docs/readers/anthropic.md`, end-to-end CLI subcommand, integration tests.
- **Governance v2** — expanded [GOVERNANCE.md](GOVERNANCE.md) and [MAINTAINERS.md](MAINTAINERS.md) for CNCF Sandbox application readiness.

### In progress (target 2026-06-14 public flip)

- **Installation docs** — package install, `pipx` install, Homebrew install, standalone binary install (depends on C01 ceremony).
- **API reference** — full library reference for programmatic use.
- **Public flip** — licence check, legal sign-off, GitHub org flip from private to public, v1.0.0 tag, PyPI publish.

## Horizon 2 — 2026-H2 (2026-06-14 → 2026-12-31)

### Reader suite completion

The full reader suite is five providers:

| Reader | Status | Target |
|---|---|---|
| AWS CloudTrail Lake | **shipped** | 2026-H1 |
| Anthropic Compliance API | **shipped** | 2026-H1 |
| Azure Confidential Ledger | pending | 2026-Q3 |
| OpenAI Compliance Platform | pending | 2026-Q3 |
| LangSmith Fleet export | pending | 2026-Q4 |

Each pending reader ships as a library module + CLI subcommand + schema-mapping docs + integration tests against real fixture exports + end-to-end quickstart entry. No reader is "done" until every one of those exists and is non-trivial.

### Wire spec maintenance

- **v1.0 → v1.0.x** — bug-fix amendments that preserve bundle compatibility. Expected: clarifications to reserved fields, test-vector corrections, schema comments.
- **v1.1 planning** — begins 2026-Q4 once the first external contributions have surfaced the real-world gaps. Candidate scope: multi-signature attestations, longer-lived anchor witness lists, additional reader normalization rules. No breaking changes in v1.x.
- **RFC process** — RFCs that affect v1.1 land under `docs/rfcs/` per [GOVERNANCE.md §5](GOVERNANCE.md).

### Trust bootstrap (§8 of GOVERNANCE.md)

- **CNCF Sandbox application submission** — target 2026-10-14. Pre-submission review by an external OSS advisor. See external facing category-switch strategy notes in the `specora-platform` repo for the internal project plan (this roadmap intentionally does not link to internal docs).
- **External security audit engagement** — target engagement signed 2026-Q3; scoping complete 2026-Q4; first report 2027-Q1. Firm candidates: Trail of Bits, NCC Group, Cure53, Include Security. The audit covers the verifier CLI, wire spec, canonicalization, and release pipeline.

## Horizon 3 — 2027-H1 (2027-01-01 → 2027-06-30)

### Public root-signing ceremony (C01)

A public, witnessed, reproducible ceremony to generate the Specora signing key used for golden vectors and canonical evidence bundles. Video-recorded, multi-party, hardware-secured, publishable as a transparency artifact. Aligns with the Let's Encrypt / Sigstore pattern. Target: 2027-Q1.

### Reproducible builds

Every release must be rebuildable byte-for-byte from source by an independent auditor. Target: reproducible release pipeline in place by 2027-Q1, published verification instructions in `docs/release-signing.md`.

### Formal verification walkthrough (C08 mirror)

The `specora-platform` repo contains Lean and TLA+ proofs of the canonicalization and transparency-chain properties. A public-facing walkthrough of those proofs — **what is proven, what is not, and why it matters for audit opinions** — will ship as `docs/formal-verification-walkthrough.md`. Target: 2027-Q2. This is a user-facing explanation; the proofs themselves live in the `specora-platform` repo and are referenced by hash, not copied.

### CNCF Sandbox acceptance (target)

Target CNCF TOC review and Sandbox acceptance: 2027-Q1.

## Beyond 2027-H1

The post-2027-H1 horizon is deliberately sparse because the failure modes cluster in the next 12 months and we do not want to over-promise on post-trust-bootstrap plans. Likely directions:

- **v1.1 wire-spec release** (non-breaking) once real-world gaps have been collected.
- **Additional readers** contributed by external operators (the reader framework is documented in `docs/readers/README.md` to make this feasible without maintainer intervention on every new reader).
- **CNCF Incubation application** (requires significant external adoption, external maintainers, and demonstrated governance track record — this is not a guaranteed path).
- **v2.0 wire-spec planning** only when there is compelling evidence that the v1.x line cannot accommodate a use case without breaking.

## How this roadmap gets updated

This roadmap is a living document. It is updated:

- After every minor release
- After every maintainer vote that affects scope (see [GOVERNANCE.md §4.2](GOVERNANCE.md))
- After every community call where a new direction is proposed
- At each quarter boundary, whether or not anything has changed

Proposed changes land via pull request. Material changes to horizon or scope require a 2/3 maintainer vote per [GOVERNANCE.md](GOVERNANCE.md).

## What this roadmap will never contain

- Commercial product plans (those are internal to Specora, Inc.)
- Revenue targets, customer names, or sales pipeline
- Competitive positioning against commercial products
- Features that entangle the verifier with a specific vendor's infrastructure
- Features that break offline verification
- Features that add telemetry or "phone-home" behaviour

If a future contributor proposes any of these, the correct response is "that does not belong in this project" — not "we'll think about it."
