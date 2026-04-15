# Community

This document describes how to engage with the `specora-verify` community. It covers communication channels, meeting cadence, contributor recognition, and escalation paths for concerns.

If you just want to start contributing, read [CONTRIBUTING.md](CONTRIBUTING.md) first — this document is for the *ongoing relationship* with the community, not the first PR.

## Communication channels

### Primary: GitHub

- **Issues** — bug reports, feature requests, reader requests, spec clarification questions. Use the templates under `.github/ISSUE_TEMPLATE/` where available.
- **Pull requests** — code, docs, schemas, golden vectors, RFCs. See [CONTRIBUTING.md](CONTRIBUTING.md) for expectations.
- **GitHub Discussions** — open-ended questions, design debates, user-to-user help, "is this the right tool for my problem?" conversations. Not appropriate for bug reports.
- **GitHub Security Advisories** — embargoed vulnerability disclosure (see [SECURITY.md](SECURITY.md)).

### Secondary: Email

- `opensource@specora.ai` — governance, contribution, community questions that are not appropriate for a public issue.
- `security@specora.ai` — security reports (PGP-encrypted). See [SECURITY.md](SECURITY.md).
- `conduct@specora.ai` — code-of-conduct concerns. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

### Chat (future)

A CNCF Slack channel will be requested once the project is accepted into CNCF Sandbox. Until then, chat happens on GitHub Discussions to keep the archive public and searchable.

## Community call

### Cadence

Starting **2026-07** (one month after the 2026-06-14 public flip), `specora-verify` holds a **monthly community call** on the first Thursday of each month, 15:00 UTC, 60 minutes.

The cadence starts post-K14 deliberately — there is no value in holding a community call while the repo is still private. Once the flip happens, the monthly rhythm begins immediately.

### Format

- **Agenda** published 24 hours in advance as a GitHub Discussion with the `community-call` label
- **Open to anyone** — contributors, users, curious observers, downstream maintainers
- **Recorded** and posted to the project's YouTube channel (to be created pre-K14)
- **Notes** committed to `community/meeting-notes/YYYY-MM-DD.md` within 48 hours of the call
- **Standing agenda items**:
  1. Release status and upcoming releases
  2. RFC status (in flight, newly proposed, accepted, shipped)
  3. Reader-suite progress
  4. Trust-bootstrap progress (CNCF application status, audit status, ceremony status)
  5. Multi-maintainer recruitment progress (per [GOVERNANCE.md §8.1](GOVERNANCE.md))
  6. New contributor shout-outs
  7. Open floor

### Asynchronous participation

Contributors who cannot attend the live call are welcome to:

- Comment on the agenda Discussion thread before the call — their points will be raised on their behalf
- Watch the recording and follow up in the same thread
- Propose agenda items for the next call at any time

No decision is ever final because you were asleep.

## Contributor recognition

### Public recognition

- Every merged PR credits the contributor in the release notes for the next release containing it.
- New contributors are called out in the first community call after their first PR merges.
- Contributors with sustained contribution patterns are candidates for maintainer nomination per [GOVERNANCE.md §3](GOVERNANCE.md).
- Significant contributions (new readers, wire-spec RFCs, security reports, major documentation improvements) are credited in the relevant section of `docs/` and in the README.

### Swag and thank-yous

`specora-verify` does not currently have swag. If sponsorship (per [GOVERNANCE.md §7.3](GOVERNANCE.md)) enables it, swag will be offered to substantial contributors — but sponsorship cannot be directed to specific individuals or create the appearance of paid-for reviews.

### AUTHORS and NOTICE

Contributors are listed in `NOTICE` per Apache 2.0 convention. Long-time contributors may be listed in an `AUTHORS` file once the project has enough external contributors for this to be meaningful.

## How we handle disagreement

Disagreement is expected and welcome. Disagreement about ideas is how the project gets better. Disagreement about *people* is something else, and it belongs in the code-of-conduct process.

### Technical disagreement

- **Default venue:** the PR or issue where the disagreement is happening
- **If it stalls:** escalate to a maintainer-only call (outcome summarised publicly afterwards) per [GOVERNANCE.md §4.3](GOVERNANCE.md)
- **If consensus is not reached:** formal maintainer vote per [GOVERNANCE.md §4.2](GOVERNANCE.md)
- **If the vote fails:** status quo wins; the change does not land. No hard feelings; try again with new evidence.

### Code-of-conduct concerns

Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report to `conduct@specora.ai`. Reports are handled confidentially by the maintainer team; the reporting contributor is never identified without their consent.

### Private concerns about a maintainer

If you have a concern about a maintainer that you cannot raise publicly, email `opensource@specora.ai`. The email is read by all active maintainers, so if the concern is about a specific maintainer, note that in the subject line so the subject can be recused from the discussion.

## Community norms

### What we want more of

- Running-code proposals ("here's a PR, here's a failing test first") over abstract design debates
- New reader contributions with real fixture data
- Documentation improvements from first-time users (fresh eyes catch more than maintainers)
- Security reports, even for small issues
- Questions about trust-model edge cases that the docs don't address
- Post-mortems on anything the project got wrong, published openly

### What we want less of

- "Please add X" with no justification, no use case, and no willingness to implement
- Proposals that require the verifier to call home, collect telemetry, or require network access for core verification
- Proposals that entangle the verifier with a specific vendor's cloud infrastructure
- Brand or marketing discussion — this project is engineering, not marketing
- Debate about whether the project should exist — if you disagree with the project's purpose, the useful thing to do is write a different project

### Silence is a signal

If an issue goes 30 days without a maintainer response, ping the issue — it is more likely that it was missed than that it was ignored. Maintainers are human and the review SLO in [GOVERNANCE.md §2.2](GOVERNANCE.md) is aspirational during periods of heavy release work.

## External engagement

### Conferences and talks

Maintainers are encouraged to present on `specora-verify` at conferences, meetups, and foundation events. Standard conditions:

- Presentations must accurately represent the project's current state (no overclaim on maturity, adoption, or formal verification)
- Slides are archived under `community/talks/` within 30 days of the event
- The project logo and wordmark are not trademarked yet; once they are, use follows a separate trademark policy to be added

### Press and analyst questions

Questions from press or industry analysts should be routed to `opensource@specora.ai`. Maintainers can respond in an individual capacity but should make clear when they are speaking for themselves versus for the project.

## Contact summary

| What | Where |
|---|---|
| Bug report | GitHub Issues |
| Feature / reader request | GitHub Issues |
| Open-ended question | GitHub Discussions |
| Security vulnerability | `security@specora.ai` (PGP) or GitHub Security Advisory |
| Code-of-conduct concern | `conduct@specora.ai` |
| Governance or community question | `opensource@specora.ai` |
| Private maintainer concern | `opensource@specora.ai` |
| Community call agenda proposal | GitHub Discussions with `community-call` label |
