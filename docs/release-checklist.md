# Release Checklist — Public Flip (v1.0.0, target 2026-06-14)

This is the gate between a private working repo and the public-trust posture
the product promises. The whole thesis of `specora-verify` is that an
independent third party can **obtain and verify the tool without trusting
the producer**. That promise is only real once every public distribution and
out-of-band verification anchor resolves. Until they do, the README badges,
`pip install`, and `brew install` paths point at 404s.

> Status as of last edit: **pre-flip.** The public surface is intentionally
> absent. Run the L1 gate below in pre-flip mode to confirm a clean (not
> half-published) state, and in post-flip mode on flip day.

## L0 — In-repo correctness (must be green before flip)

These are fully verifiable from the repo with no network and no publish step.

- [ ] `pytest -q` — full suite green.
- [ ] `python -m specora_verify vectors verify` — 18/18 golden vectors pass.
- [ ] `ruff check . && ruff format --check .`
- [ ] `mypy --strict specora_verify`
- [ ] `python tools/qa/run_all.py` — the independent QA harnesses (L2 byte-parity,
      L3 adversarial, L4 schema-rigor) all pass. See [tools/qa/README.md](../tools/qa/README.md).

## L1 — Distribution & verification anchors (the cold-install gate)

Each item is what a stranger needs in order to obtain and independently verify
the tool. **All must be GREEN at flip.** Verify with:

```bash
# pre-flip (today): confirms the public surface is cleanly absent
python tools/qa/check_l1_distribution.py --expect-prelaunch

# flip day and after: every anchor MUST resolve or the gate fails
python tools/qa/check_l1_distribution.py
```

| Anchor | What it unlocks | Publish action |
|---|---|---|
| **PyPI package** `specora-verify` | `pip install specora-verify` | Trusted-publishing release job on the `v1.0.0` tag. |
| **GitHub repo public** `SpecoraAI/specora-verify` | source review, signed commits, issues | Org/repo private→public flip after licence + legal sign-off. |
| **GitHub release + Sigstore bundles** | signed sdist/wheel + standalone binaries; `cosign verify-blob` / `sigstore verify` before running | Release job uploads artifacts + `.sigstore` bundles. |
| **Homebrew tap** `SpecoraAI/homebrew-tap` | `brew install specora-verify` | Create + publish the tap formula. |
| **Wire-spec mirror** `spec.specora.ai` | the canonical spec URL cited throughout the docs (DNS currently NXDOMAIN) | Point DNS + serve `/v1.0` (mirror of `docs/wire-spec-v1.0.md`). |

### Post-publish verification a third party should be able to do

- [ ] `pip download specora-verify --no-deps` succeeds and the wheel installs.
- [ ] `sigstore verify identity` (or `cosign verify-blob`) succeeds against the
      published `.sigstore` bundle for each binary, using the GitHub Actions
      OIDC identity — **before** executing the binary.
- [ ] The installed package's `canonical.py` / `signature.py` / `hash.py`
      match the tagged source (no supply-chain drift).
- [ ] `specora-verify vectors verify` prints `PASS` from the installed artifact.

## L2 — Claim-accuracy (docs must match availability)

- [ ] README "Availability" note reflects the real flip date and is removed or
      updated once anchors are live.
- [ ] No present-tense install/verification claim resolves to a 404 for a
      public reader. (`check_l1_distribution.py` is the objective test.)
- [ ] `pyproject.toml` `Development Status` matches reality at publish time.

---

**Day-one definition of done:** `python tools/qa/check_l1_distribution.py`
exits 0 with every anchor GREEN, and a clean machine can
`pip install specora-verify`, verify its Sigstore signature, and run
`specora-verify vectors verify` to a green `PASS` — without any access this
project's maintainers control.
