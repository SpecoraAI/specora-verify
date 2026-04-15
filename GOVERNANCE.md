# Governance

This document describes how `specora-verify` is maintained, how decisions are made, and how the project will eventually transition to foundation-hosted, multi-party governance.

It is written to be compatible with the [CNCF Project Governance guidance](https://contribute.cncf.io/maintainers/governance/) so that the project can be reviewed against CNCF Sandbox criteria without a rewrite.

## 1. Project scope

`specora-verify` has one job: **prove cryptographic claims about AI evidence bundles without trusting the party that produced them.** The project includes:

- The `specora_verify` Python library and CLI
- The Specora wire spec (currently v1.0) and its JSON Schemas
- The golden test vectors
- Provider audit-log readers that map existing provider exports onto the wire spec
- User-facing documentation (quickstart, trust model, reader guides, API reference)

Anything outside that scope — commercial product surfaces, dashboards, billing, policy engines, inline proxies — is explicitly not part of this project and lives in separate, commercially-stewarded repositories.

## 2. Current state (Horizon A — Specora-stewarded)

At launch (2026-06-14), `specora-verify` is stewarded by Specora, Inc. All initial maintainers are Specora employees. This is a deliberate starting point, not an end state. The long-term goal (§8 Future state) is to transition stewardship to a neutral foundation so the verifier is provably independent of any single vendor — including Specora itself.

### 2.1 Maintainer roster

The authoritative list of maintainers, with GitHub handles, affiliation, email, responsibility areas, and security sign-off status, is maintained in [MAINTAINERS.md](MAINTAINERS.md). This document describes *how* the roster changes; `MAINTAINERS.md` describes *who is on it today*.

### 2.2 Maintainer responsibilities

A maintainer commits to:

1. Reviewing pull requests in their area within 5 business days.
2. Triaging issues in their area within 10 business days.
3. Participating in release sign-off for releases affecting their area.
4. Participating in embargoed security triage when on the security sign-off list.
5. Disclosing conflicts of interest (commercial relationships, customer asks, employer asks) on any PR where the conflict could influence the review.
6. Following [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and enforcing it in public spaces.

A maintainer who cannot meet these commitments for more than 30 days should step back temporarily or move to emeritus status.

## 3. Maintainer promotion criteria

New maintainers are added by existing maintainers after demonstrating sustained contribution. There is no bar to entry by employer, geography, or affiliation — **non-Specora contributors are actively sought** and their addition is a project goal (see §8.1 commitment).

### 3.1 Eligibility criteria (all must be met)

A candidate is eligible for maintainer nomination when they have:

1. Contributed at least **10 merged pull requests** across the prior 6 months, with at least 3 in a substantive area (new reader, wire-spec change, verification path, security fix, non-trivial documentation).
2. Reviewed at least **5 pull requests** from other contributors with constructive, technically sound feedback.
3. Demonstrated adherence to the project's correctness / determinism / offline-first principles (see [CONTRIBUTING.md](CONTRIBUTING.md)).
4. Participated in at least one community call or RFC discussion.
5. Agreed in writing (via issue comment) to the maintainer responsibilities in §2.2 and the conflict-of-interest rules in §7.

### 3.2 Nomination process

1. An existing maintainer opens a public issue titled `Maintainer nomination: @candidate` with a one-paragraph rationale and links to representative contributions.
2. The issue stays open for a minimum 14-day public comment period.
3. At the end of the comment period, a formal vote is held per §4.2. Approval requires a 2/3 majority of active maintainers.
4. If approved, the candidate is added to [MAINTAINERS.md](MAINTAINERS.md) in a pull request, to `.github/CODEOWNERS` for their responsibility area, and granted write access to the repository.
5. Security sign-off authority is a separate grant and requires an additional 2/3 vote after at least 90 days of active maintainership.

### 3.3 Stepping back

A maintainer may step back at any time by opening a pull request moving their entry to the Emeritus section of [MAINTAINERS.md](MAINTAINERS.md). Emeritus maintainers retain credit but not write access.

### 3.4 Involuntary removal

A maintainer may be removed for:

- Code-of-conduct violation (see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) enforcement section)
- Sustained inactivity (no review or merge activity for 90 consecutive days without prior notice)
- Knowingly shipping a change that violates the project's correctness principles
- Undisclosed conflict of interest on a material review

Removal requires a 2/3 majority of active maintainers excluding the maintainer being considered. The affected maintainer is given the opportunity to respond before the vote. Removal decisions and rationale are recorded in a public issue.

## 4. Decision-making

### 4.1 Lazy consensus (default)

Most changes land via lazy consensus: a PR is opened, reviewed by one maintainer (two for security-sensitive paths — signature verification, canonicalization, key handling, release pipeline), and merged if no maintainer objects within the review period.

### 4.2 Formal vote (reserved for)

A formal maintainer vote is required for:

1. **Adding a maintainer.** Requires a 2/3 majority of active maintainers. See §3.2.
2. **Removing a maintainer.** Requires a 2/3 majority of active maintainers excluding the maintainer being considered. See §3.4.
3. **Granting security sign-off authority.** Requires a 2/3 majority. See §3.2.
4. **Changing the license.** Requires unanimous maintainer agreement and legal review. The project's Apache 2.0 license is intended to be permanent.
5. **Changing the wire spec in a backwards-incompatible way.** Requires a 2/3 majority, a successful RFC per §5, and a minimum 30-day public comment period.
6. **Transitioning stewardship to a foundation.** Requires a 2/3 majority plus Specora, Inc. board approval while still Specora-stewarded. Post-transition, the foundation's governance rules apply.
7. **Changing this governance document.** Requires a 2/3 majority and a minimum 14-day public comment period.
8. **Cutting a major release (≥2.0.0).** Requires a 2/3 majority because major releases imply wire-spec breaking change.

Votes happen on an open issue or pull request with the `governance-vote` label. Votes are public; rationale is encouraged; abstentions count as neither yes nor no.

### 4.3 Conflict resolution

Disagreements between maintainers are resolved by:

1. Discussion on the issue or PR in question. Most disagreements end here.
2. If discussion stalls, escalation to a maintainer-only call. The outcome of the call is summarised in a public comment on the original thread so non-maintainer contributors can see what was decided and why.
3. If the call does not produce consensus, a formal vote per §4.2 is the last resort.
4. If a formal vote is tied or fails to reach 2/3, the status quo wins — the change does not land.

Maintainers are expected to disagree publicly and respectfully. Private deal-making is not how this project works. A decision reached in private is not binding; if it matters, it has to be reproduced in the open.

## 5. RFC process for spec changes

Wire-spec changes, schema changes, new canonicalization rules, or any change that affects bundle compatibility across releases require an RFC before implementation.

### 5.1 When an RFC is required

- Adding, removing, or modifying any field in a wire-spec schema under `docs/schemas/`
- Changing canonicalization rules in `specora_verify/canonical.py`
- Changing signature, hashing, or merkle-tree primitives
- Changing the set of supported algorithms
- Changing reader-to-bundle mapping semantics in a way that affects bundle equivalence
- Changing the project's minimum supported Python version or core runtime dependencies

Bug fixes that preserve bundle compatibility do not require an RFC.

### 5.2 RFC lifecycle

1. **Draft.** Author opens a pull request adding a markdown file to `docs/rfcs/NNNN-short-title.md` using the RFC template (to be added under `docs/rfcs/0000-template.md`).
2. **Discussion.** PR stays open for a minimum 14-day public comment period. Longer for breaking changes (30 days minimum). Non-maintainers are explicitly invited to comment.
3. **Decision.** At the end of the comment period a maintainer vote per §4.2 determines acceptance. Rationale is recorded in the PR.
4. **Implementation.** If accepted, the RFC is merged as `accepted`. Implementation happens in follow-up PRs that reference the RFC number. The RFC file is updated with implementation links as work lands.
5. **Ratification.** Once implementation is complete and shipped in a release, the RFC status flips to `shipped`.

An RFC can be rejected (status `rejected`) or withdrawn by the author. Rejected RFCs are retained as historical record so the same question does not get relitigated without new information.

## 6. Security governance

Security reports follow the process in [SECURITY.md](SECURITY.md). Key rules:

### 6.1 Disclosure pipeline

1. Reports arrive at `security@specora.ai` (PGP-encrypted, key in `specora-security-public.asc`).
2. A maintainer with security sign-off authority (marked in [MAINTAINERS.md](MAINTAINERS.md)) acknowledges within 48 hours.
3. Triage, severity assessment, and embargoed fix development happen on a private fork or a private GitHub Security Advisory.
4. Embargoed fixes require two-maintainer sign-off before release.
5. Coordinated disclosure follows the 90-day industry norm unless the reporter requests shorter.
6. Public advisory, patch release, and CVE assignment happen on the coordinated disclosure date.

### 6.2 Escalation

If a security report alleges:

- Active exploitation in the wild → escalate to all security sign-off maintainers within 12 hours
- Wire-spec-level compromise → escalate to all maintainers within 24 hours and open an RFC for the fix
- Supply-chain or release-pipeline compromise → treat as P0, freeze releases, and contact Sigstore / PyPI security within 24 hours

### 6.3 No single-person bottleneck

There must be at least two maintainers with security sign-off authority at all times. If the roster drops to one, recruiting a second is P0 and new feature releases are paused until resolved.

### 6.4 Security fixes bypass the normal review cadence but still require two-maintainer sign-off

This is the only case where the 5-business-day review SLO is compressed. It is not the case where review is skipped.

## 7. Funding and conflicts of interest

Specora, Inc. currently pays the salaries of every maintainer. This is disclosed in [MAINTAINERS.md](MAINTAINERS.md) and stays disclosed as long as it is true.

### 7.1 Conflict disclosure

Maintainers must disclose when a PR they are reviewing:

- Relates to a commercial Specora feature or customer
- Relates to a competitor, customer, or employer of any maintainer
- Has been requested by a specific sponsor or partner

Disclosure is not a prohibition; it is so other reviewers can weight the context.

### 7.2 Conflict-of-interest rules

1. A maintainer cannot single-handedly approve a change that benefits a specific Specora customer at the expense of the broader user base.
2. A maintainer cannot be the sole reviewer on a change authored by a direct employer-funded colleague if the change materially affects the wire spec.
3. All wire-spec changes require review from at least one maintainer not affiliated with the author's employer once the project has non-Specora maintainers.
4. Undisclosed conflicts discovered after merge are grounds for §3.4 removal proceedings.

### 7.3 Sponsorship

Corporate sponsorship of `specora-verify` by organizations other than Specora is welcomed once the project has an independent governance layer (see §8). Until then, sponsorship offers should be directed to `opensource@specora.ai`. Sponsorship does not grant decision-making authority, seats on the maintainer team, or influence over the roadmap.

## 8. Future state (Horizon B — Foundation-hosted)

Per [market-pressure-test-2026.md §2.8](https://github.com/SpecoraAI/) ("Trust Bootstrap Plan"), the long-term plan is to move stewardship of `specora-verify`, the wire spec, and the golden vectors to a neutral foundation — **CNCF** is the primary target (cosign/Sigstore, in-toto, Open Policy Agent are already there), with **Linux Foundation** as the fallback.

### 8.1 Explicit multi-maintainer commitment

Specora commits to recruiting **at least two maintainers who are not Specora, Inc. employees within 12 months of CNCF Sandbox acceptance.** Progress against this commitment is reported in the project's monthly community call (§COMMUNITY.md) and in every CNCF Sandbox annual review submission. Failure to meet the commitment is itself a public signal and is not hidden.

### 8.2 What foundation hosting delivers

- Multi-party maintainership (not just Specora employees)
- Trademark custody independent of any single commercial entity
- A public root-signing ceremony and published key-management policy
- Cross-industry contributor neutrality that is legible to auditors and regulators
- A neutral IP home for the wire spec and golden vectors

### 8.3 The Specora commitment

**If `specora-verify` is to be the default verifier, it cannot be controlled exclusively by Specora.** The target for foundation application submission is 2026-10-14, per the category-switch trust-bootstrap milestones.

This governance document will be revised at the point of transition. The **Apache 2.0 license**, the **wire-spec compatibility guarantees**, and the **offline verification principle** are commitments that will survive that transition intact.

## 9. Release process

- **Minor releases** (e.g., 1.1.0): roughly monthly, covering bug fixes, new readers, and non-breaking features. Cut by any maintainer with the release role.
- **Patch releases** (e.g., 1.0.1): on demand for security fixes or critical bugs.
- **Major releases** (e.g., 2.0.0): reserved for wire-spec breaking changes. Require the formal-vote path above.

Every release:

1. Is tagged in Git with a signed tag
2. Produces a GitHub Release with a Sigstore-signed source tarball and wheel
3. Publishes the wheel to PyPI via a protected GitHub Actions workflow (trusted publisher, no long-lived tokens)
4. Updates the Homebrew tap (`SpecoraAI/tap`) once that tap exists
5. Eventually publishes standalone binaries for Linux / macOS / Windows, each individually Sigstore-signed (planned alongside C01 ceremony)

Release signing keys and Sigstore identity policies will be documented in `docs/release-signing.md` once the public root-signing ceremony (C01) has taken place.

## 10. Contact

- General governance questions: `opensource@specora.ai`
- Security: `security@specora.ai`
- Code of conduct: `conduct@specora.ai`
- Public discussion: [GitHub Discussions](https://github.com/SpecoraAI/specora-verify/discussions)

## 11. Document history

- 2026-04-14 — v1 drafted at repo creation alongside initial A01 import.
- 2026-04-15 — v2 (this version): expanded for CNCF Sandbox application readiness (EPIC-B04). Added project scope, maintainer promotion criteria, RFC process, security escalation, conflict-of-interest rules, multi-maintainer commitment. No breaking changes to decision-making authority.
