# Maintainers

The maintainers of `specora-verify` are listed below. Each has write access to the repository, sign-off authority on releases, and shared responsibility for security triage. See [GOVERNANCE.md](GOVERNANCE.md) for how maintainers are added, removed, and what each role commits to.

## Active maintainers

| GitHub | Name | Affiliation | Email | Responsibility area | Security sign-off | Appointed |
|---|---|---|---|---|:-:|---|
| [`@cho-cvc`](https://github.com/cho-cvc) | Nsang-Nhon Sone | Specora, Inc. | `cho@specora.ai` | Core verifier, wire-spec v1.0 conformance, CI, release engineering, cryptographic primitives, canonicalization | ✅ | 2026-04-14 |
| [`@nickcontinentalvc`](https://github.com/nickcontinentalvc) | Nick (CVC) | Specora, Inc. | `nick@specora.ai` | Provider audit-log readers (CloudTrail, Anthropic, upcoming Azure/OpenAI/LangSmith), integration tests, reader documentation | ✅ | 2026-04-14 |

Both initial maintainers are Specora, Inc. employees as of 2026-04-15. Security sign-off authority is held by both so that embargoed vulnerability reports received via [SECURITY.md](SECURITY.md) can be triaged without a single-person dependency.

## Affiliation disclosure

All currently active maintainers are Specora, Inc. employees. Specora, Inc. pays their salaries and is their primary employer. This is disclosed here and in [GOVERNANCE.md §7](GOVERNANCE.md) and will remain disclosed as long as it is true.

## Multi-maintainer commitment

Per [GOVERNANCE.md §8.1](GOVERNANCE.md), Specora commits to recruiting **at least two maintainers who are not Specora, Inc. employees within 12 months of CNCF Sandbox acceptance.** Progress is reported in the monthly community call (see [COMMUNITY.md](COMMUNITY.md)) and in every CNCF Sandbox annual review submission.

Current progress: **0 of 2 non-Specora maintainers recruited** (project is pre-CNCF-application as of 2026-04-15; the 12-month clock has not started). Candidates are actively sought — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute and [GOVERNANCE.md §3](GOVERNANCE.md) for the promotion criteria.

## Emeritus maintainers

None yet. Maintainers who step back from active maintenance are listed here and retain credit but not write access.

## Security sign-off

Maintainers marked ✅ above receive embargoed security reports sent to `security@specora.ai`. At least two maintainers must hold security sign-off at all times (see [GOVERNANCE.md §6.3](GOVERNANCE.md)). If the roster drops to one, recruiting a second is P0 and new feature releases are paused until resolved.

## Code ownership

Per-directory code ownership is defined in [.github/CODEOWNERS](.github/CODEOWNERS). CODEOWNERS entries reference maintainers by GitHub handle and are kept in sync with this file.

## Change history

- 2026-04-14 — initial roster (2 maintainers, both Specora).
- 2026-04-15 — expanded with full affiliation, responsibility, and multi-maintainer commitment disclosure for CNCF Sandbox application readiness (EPIC-B04).
