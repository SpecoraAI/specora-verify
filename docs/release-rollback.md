# Release Rollback & Yank Runbook

What to do when a published `specora-verify` release turns out to be bad — a
correctness defect in the verifier, a packaging/supply-chain problem, or a
leaked credential in an artifact.

> **The defining constraint for this tool.** `specora-verify` produces audit
> opinions. A bad release is not just "users have a buggy CLI" — an auditor,
> regulator, or customer may have **already run the bad build against real
> evidence and formed a conclusion**. Rollback here therefore has two goals
> that ordinary tools do not share:
>
> 1. Stop new users from getting the bad build (the usual job).
> 2. Help everyone who already ran it determine whether their verification
>    result is still trustworthy, and re-verify if not.
>
> Published artifacts are **immutable and cannot be deleted**: PyPI versions
> cannot be overwritten or un-uploaded (only *yanked*), and Sigstore signatures
> are permanently recorded in the Rekor transparency log. You roll *forward*
> with a fix; you never rewrite history.

## Severity triage (decide first)

| Severity | Definition | Action |
|---|---|---|
| **S1 — Unsound verifier** | The tool can report `PASS` for a bundle that is actually invalid (or `FAIL` for a valid one). Audit opinions may be wrong. | Full yank + security advisory + re-verification notice. Treat as a security incident; follow [SECURITY.md](../SECURITY.md). |
| **S2 — Supply-chain / artifact defect** | Wrong/corrupt artifact published, credential leaked into a build, signing identity mismatch. | Yank affected artifacts + advisory. Rotate any exposed secret. |
| **S3 — Functional bug, sound verdicts** | Crash, bad CLI ergonomics, a fetcher broken — but `PASS`/`FAIL` verdicts on the core path remain correct. | Ship a patch release. Yank only if the bug is likely to be mistaken for a verdict. |

If you are unsure whether a defect can flip a verdict, treat it as **S1**.

## Step 1 — Contain (within the hour for S1/S2)

1. **Freeze releases.** Do not cut a new tag until the fix is understood. If a
   release run is in flight, cancel the workflow.
2. **Open a private advisory** at
   `https://github.com/SpecoraAI/specora-verify/security/advisories` (do not
   discuss S1/S2 details in public issues until a fix is available).
3. **Reproduce against the golden vectors.** Confirm whether
   `specora-verify vectors verify` and `python tools/qa/run_all.py` catch the
   defect. If they do not, the fix MUST add a vector or QA case that does —
   the gap that let the bad release through is itself a defect.

## Step 2 — Yank the bad version

PyPI yank marks a release as "do not install by default" without deleting it.
A pinned `==` install still resolves (so existing lockfiles don't break), but
`pip install specora-verify` will skip a yanked version.

```bash
# Requires a PyPI maintainer account for the project (interactive — the
# trusted-publishing flow that releases versions cannot yank).
# PyPI → project → Manage → Releases → <version> → Options → Yank
```

- **GitHub Release:** edit the release for the bad tag — mark it as a
  pre-release / add a bold deprecation banner pointing to the fixed version and
  the advisory. **Do not delete the tag or release**: the Sigstore bundles are
  referenced by the immutable tag, and deleting it breaks third-party
  verification of every artifact that was legitimately signed under it.
- **Homebrew tap (`SpecoraAI/homebrew-tap`):** revert the formula PR (or open a
  new one) so the formula points at the last-good version's URL + sha256. Tap
  users get the good build on their next `brew upgrade`.
- **Binaries:** the standalone binaries attached to the bad GitHub Release stay
  (they're signed under the tag). The deprecation banner is what steers users
  off them.

## Step 3 — Roll forward with a fixed release

1. Land the fix on `staging`, then `main`, with the new/updated golden vector or
   QA case that reproduces the defect (Step 1.3).
2. Bump the version. **Skip the bad version number** — never reuse it. If
   `1.2.3` is bad, the fix is `1.2.4` (or `1.3.0`), never a re-cut `1.2.3`.
3. Update [CHANGELOG.md](../CHANGELOG.md) with a `### Security` or `### Fixed`
   entry that names the yanked version and what was wrong.
4. Tag `v{version}` and let `ci.yml` run the full gate (`test` + `security`)
   before the `release` job publishes. The release pipeline is identity-pinned
   to this repo/tag (see [release-checklist.md](release-checklist.md) L0), so
   the new artifacts verify cleanly.

## Step 4 — Notify and enable re-verification (the part unique to this tool)

For **S1/S2**, publishing a fix is not enough — people may have already relied
on the bad build.

1. **Publish the GitHub Security Advisory** (GHSA) with: affected version
   range, the fixed version, and a clear statement of *whether verdicts could
   have been wrong*. Per [SECURITY.md](../SECURITY.md), support covers the
   latest release and the two most recent prior minor versions.
2. **State the re-verification guidance explicitly.** Tell operators to:
   - Upgrade: `pip install -U specora-verify` (or `brew upgrade`), and confirm
     `specora-verify --version` is at or above the fixed version.
   - Re-run any verification whose result was used in an audit opinion,
     compliance attestation, or regulatory filing produced with an affected
     version.
   - For S1, treat prior `PASS` results from affected versions as
     **unconfirmed** until re-verified with the fixed build.
3. **Tell users how to detect the bad build they may still have**, e.g.:
   ```bash
   specora-verify --version          # is it in the affected range?
   pip index versions specora-verify # shows yanked versions struck through
   ```
4. **Cross-link** the advisory from the CHANGELOG entry and the GitHub Release
   notes for both the bad and the fixed versions.

## Step 5 — Post-incident

- Write a short retro: how the bad release passed `test` + `security` +
  `vectors verify`, and what gate now closes that gap.
- Confirm the regression vector/QA case is permanent, not a one-off.
- If a secret was exposed (S2), confirm rotation completed and the old
  credential is revoked. Note: the release pipeline uses **no long-lived
  secrets** (PyPI trusted publishing + Sigstore keyless OIDC), so the most
  likely exposure is something accidentally bundled into an artifact, not a
  stored token.

## Quick reference

```
S1 unsound verifier  → yank + GHSA + re-verification notice + roll forward
S2 supply chain      → yank + rotate + GHSA + roll forward
S3 functional bug    → patch release (yank only if mistakable for a verdict)
Never:                 reuse a version number, delete a tag, or delete a release.
Always:                add the vector/QA case that would have caught it.
```
