# Governance

This document describes how `specora-verify` is maintained, how decisions are made, and how the project will eventually transition to foundation-hosted, multi-party governance.

## Current state (Horizon A — Specora-stewarded)

At launch (2026-06-14), `specora-verify` is stewarded by Specora, Inc. All maintainers are Specora employees. This is a deliberate starting point, not an end state. The long-term goal (§Future state below) is to transition stewardship to a neutral foundation so the verifier is provably independent of any single vendor — including Specora itself.

### Maintainers

Maintainers have `write` access to the repository, `publish` access to PyPI, and sign-off authority on releases.

| Name | GitHub | Area | Appointed |
|---|---|---|---|
| `@cho-cvc` | Core verifier, wire-spec conformance, CI, release engineering, cryptographic primitives | 2026-04-14 |
| `@nickcontinentalvc` | Provider audit-log readers, integration tests, docs | 2026-04-14 |

Both maintainers are Specora, Inc. employees and share security sign-off authority (both can triage embargoed vulnerability reports from [SECURITY.md](SECURITY.md), so disclosure handling is not blocked on a single person). The current roster is maintained in [MAINTAINERS.md](MAINTAINERS.md).

### Emeritus maintainers

Maintainers who step back from active maintenance are listed as emeritus. They retain credit but not write access.

## Decision-making

### Lazy consensus (default)

Most changes land via lazy consensus: a PR is opened, reviewed by one maintainer (two for security-sensitive paths), and merged if no maintainer objects within the review period.

### Formal vote (reserved for)

A formal maintainer vote is required for:

1. **Adding or removing a maintainer.** Requires a 2/3 majority of active maintainers.
2. **Changing the license.** Requires unanimous maintainer agreement and legal review. The project's Apache 2.0 license is intended to be permanent.
3. **Changing the wire spec in a backwards-incompatible way.** Requires a 2/3 majority and a minimum 30-day public comment period.
4. **Transitioning stewardship to a foundation.** Requires a 2/3 majority plus Specora board approval (while still Specora-stewarded).
5. **Changing this governance document.** Requires a 2/3 majority and a minimum 14-day public comment period.

Votes happen on an open issue or pull request with `governance-vote` label. Votes are public; rationale is encouraged.

### Conflict resolution

Disagreements between maintainers are resolved by:

1. Discussion on the issue or PR in question
2. Escalation to a maintainer-only call if discussion stalls
3. A formal vote as a last resort

Maintainers are expected to disagree publicly and respectfully. Private deal-making is not how this project works.

## Release process

- **Minor releases** (e.g., 1.1.0): roughly monthly, covering bug fixes, new readers, and non-breaking features. Cut by any maintainer.
- **Patch releases** (e.g., 1.0.1): on demand for security fixes or critical bugs.
- **Major releases** (e.g., 2.0.0): reserved for wire-spec breaking changes. Require the formal-vote path above.

Every release:

1. Is tagged in Git with a signed tag
2. Produces a GitHub Release with a Sigstore-signed source tarball and wheel
3. Publishes the wheel to PyPI via a protected GitHub Actions workflow (trusted publisher, no long-lived tokens)
4. Updates the Homebrew tap (`SpecoraAI/tap`)
5. Publishes a standalone binary for Linux / macOS / Windows, each individually Sigstore-signed

Release signing keys and Sigstore identity policies are documented in [docs/release-signing.md](docs/release-signing.md).

## Funding and conflicts of interest

Specora, Inc. currently pays the salaries of every maintainer. Maintainers are expected to disclose when a PR they are reviewing relates to a commercial Specora feature or customer — not as a prohibition, but so reviewers can weight the context. A maintainer cannot single-handedly approve a change that benefits a specific Specora customer at the expense of the broader user base.

Corporate sponsorship of `specora-verify` by organizations other than Specora is welcomed once the project has an independent governance layer (see §Future state). Until then, sponsorship offers should be directed to `opensource@specora.ai`.

## Security governance

Security reports follow the process in [SECURITY.md](SECURITY.md). A maintainer-only private security mailing list handles embargoed vulnerabilities. Maintainers with security sign-off are marked in [MAINTAINERS.md](MAINTAINERS.md).

Security fixes bypass the normal review cadence but still require two-maintainer sign-off.

## Future state (Horizon B — Foundation-hosted)

Per [market-pressure-test-2026.md §2.8](../market-pressure-test-2026.md) ("Trust Bootstrap Plan"), the long-term plan is to move stewardship of `specora-verify`, the wire spec, and the golden vectors to a neutral foundation — candidates include the Linux Foundation (LF AI & Data), the Cloud Native Computing Foundation (CNCF), the Open Source Security Foundation (OpenSSF), or the Eclipse Foundation. A foundation-hosted governance model provides:

- Multi-party board representation (not just Specora employees)
- Trademark custody independent of any single commercial entity
- A public root-signing ceremony and published key-management policy
- Cross-industry contributor neutrality that is legible to auditors and regulators

The Specora commitment: **if `specora-verify` is to be the default verifier, it cannot be controlled exclusively by Specora.** The target for foundation application submission is Q4 2026, per the pressure-test milestones.

This governance document will be rewritten at that point. The Apache 2.0 license, the wire-spec compatibility guarantees, and the offline verification principle are commitments that will survive that transition intact.

## Contact

- General governance questions: `opensource@specora.ai`
- Security: `security@specora.ai`
- Code of conduct: `conduct@specora.ai`
