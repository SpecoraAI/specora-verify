# Release Checklist — Public Flip (v1.0.0, flipped 2026-06-10)

This is the gate between a private working repo and the public-trust posture
the product promises. The whole thesis of `specora-verify` is that an
independent third party can **obtain and verify the tool without trusting
the producer**. That promise is only real once every public distribution and
out-of-band verification anchor resolves.

> Status as of last edit: **flipped.** `specora-verify 1.0.0` is published on
> PyPI, this repository is public, the Homebrew tap carries the formula, and
> the wire-spec mirror at `spec.specora.ai/v1.0` resolves. The flip landed
> 2026-06-10, ahead of the original 2026-06-14 target. The remaining open
> items below are post-flip verification an operator runs against the live
> artifacts (Sigstore signature checks), not pending publish work.

## L0 — In-repo correctness (must be green before flip)

These are fully verifiable from the repo with no network and no publish step.

- [ ] `pytest -q` — full suite green.
- [ ] `python -m specora_verify vectors verify` — 18/18 golden vectors pass.
- [ ] `ruff check . && ruff format --check .`
- [ ] `mypy --strict specora_verify`
- [ ] `python tools/qa/run_all.py` — the independent QA harnesses (L2 byte-parity,
      L3 adversarial, L4 schema-rigor) all pass. See [tools/qa/README.md](../tools/qa/README.md).
- [x] **Release-pipeline identity wiring** — `specora_verify/release.py`'s
      Sigstore identity constants (`GITHUB_OWNER`/`GITHUB_REPO`,
      `SIGSTORE_WORKFLOW_PATH`, tag scheme) describe *this* repo and *this*
      repo's release job, so published signed artifacts verify. Guarded by
      `tests/test_release_identity.py` (asserts constants match pyproject's
      Repository URL, the pinned workflow exists, and the tag scheme is
      consistent). Tag scheme is `v{version}`; the release job lives in
      `ci.yml` (gated on `v*` tags), and identity is pinned via the
      `@refs/tags/v{version}` ref.

## L1 — Distribution & verification anchors (the cold-install gate)

Each item is what a stranger needs in order to obtain and independently verify
the tool. **All must be GREEN at flip.** Verify with:

```bash
# pre-flip (today): confirms the public surface is cleanly absent
python tools/qa/check_l1_distribution.py --expect-prelaunch

# flip day and after: every anchor MUST resolve or the gate fails
python tools/qa/check_l1_distribution.py
```

| Anchor | What it unlocks | Status |
|---|---|---|
| **PyPI package** `specora-verify` | `pip install specora-verify` | **Live.** `1.0.0` published via the trusted-publishing release job. |
| **GitHub repo public** `SpecoraAI/specora-verify` | source review, signed commits, issues | **Live.** Repository is public (`gh repo view` reports `PUBLIC`). |
| **GitHub release + Sigstore bundles** | signed sdist/wheel + standalone binaries; `cosign verify-blob` / `sigstore verify` before running | Release job uploads artifacts + `.sigstore` bundles. Operator verifies per L1 post-publish checklist below. |
| **Homebrew tap** `SpecoraAI/homebrew-tap` | `brew install specora-verify` | **Live.** Tap repository carries the `specora-verify` formula. |
| **Wire-spec mirror** `spec.specora.ai` | the canonical spec URL cited throughout the docs | **Live.** `spec.specora.ai/v1.0` serves the rendered wire spec (mirror of `docs/wire-spec-v1.0.md`). |

### Post-publish verification a third party should be able to do

- [ ] `pip download specora-verify --no-deps` succeeds and the wheel installs.
- [ ] `sigstore verify identity` (or `cosign verify-blob`) succeeds against the
      published `.sigstore` bundle for each binary, using the GitHub Actions
      OIDC identity — **before** executing the binary.
- [ ] The installed package's `canonical.py` / `signature.py` / `hash.py`
      match the tagged source (no supply-chain drift).
- [ ] `specora-verify vectors verify` prints `PASS` from the installed artifact.

## L2 — Claim-accuracy (docs must match availability)

- [x] README "Availability" note reflects the real flip date and is removed or
      updated once anchors are live. (Updated 2026-06-11 to post-flip state.)
- [x] No present-tense install/verification claim resolves to a 404 for a
      public reader. (`check_l1_distribution.py` is the objective test;
      endpoint reachability re-verified 2026-06-11.)
- [ ] `pyproject.toml` `Development Status` matches reality at publish time.

---

**Day-one definition of done:** `python tools/qa/check_l1_distribution.py`
exits 0 with every anchor GREEN, and a clean machine can
`pip install specora-verify`, verify its Sigstore signature, and run
`specora-verify vectors verify` to a green `PASS` — without any access this
project's maintainers control.

## L3 — When a release goes bad

Publishing is immutable: PyPI versions and Sigstore signatures cannot be
deleted, only superseded. The procedure for yanking a bad release, rolling
forward with a fix, and — critically for a verifier — notifying anyone who may
have already produced an audit opinion with the bad build is documented in
**[release-rollback.md](release-rollback.md)**. Know it *before* you need it.
