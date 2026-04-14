# Contributing to `specora-verify`

Thank you for your interest in contributing to `specora-verify`, the independent verifier for AI systems. This project is Apache 2.0 licensed and openly developed. Anyone is welcome to submit issues and pull requests.

## What we care about

`specora-verify` has one job: **prove cryptographic claims about AI evidence bundles without trusting the party that produced them.** Every contribution is evaluated against that single goal.

Concretely, we prioritize:

1. **Correctness.** Verification cannot be "mostly right." If a verifier accepts a tampered bundle, the tool has failed its only purpose.
2. **Determinism.** Same input, same output, across every machine. No time-dependent or locale-dependent behavior. No network calls in the default verification path.
3. **Offline-first.** An auditor at a desk with no internet access must be able to verify a bundle. Every feature that requires network access must be opt-in and clearly labeled.
4. **Minimal dependencies.** The core verification path uses only the Python standard library. Cryptographic primitives (`cryptography`, `PyNaCl`) and transport clients (`httpx`, `dnspython`, `sigstore`) are optional extras that each unlock a specific feature.
5. **Backwards compatibility.** Golden vectors from published wire spec versions must keep verifying across future releases. Breaking changes require a wire-spec version bump (see [wire-spec versioning policy](https://spec.specora.ai/)).

## How to contribute

### 1. Before you start

- **Bug reports:** open an issue with a minimal reproduction — the command you ran, the input, the expected output, the actual output. Golden vectors or tampered fixtures are ideal.
- **Feature requests:** open an issue describing the verification problem you want solved. We prefer "I need to verify X" over "please add Y." Feature ideas are evaluated against the independence principle: does the feature make external verification easier, or does it entangle the verifier with a specific vendor's infrastructure?
- **Security issues:** **do not** open a public issue. See [SECURITY.md](SECURITY.md).

### 2. Development setup

```bash
git clone https://github.com/SpecoraAI/specora-verify.git
cd specora-verify
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

All tests must pass on your branch before submitting a pull request.

### 3. Coding standards

- **Style:** `ruff check .` and `ruff format .` must both be clean. CI enforces this.
- **Types:** `mypy --strict .` must be clean. All new public APIs must be fully typed.
- **Tests:** every new behavior needs a test. Every bug fix needs a regression test. Every new wire-format path needs a golden vector.
- **No runtime dependency additions** without prior discussion in an issue. The core verification path is stdlib-only and will stay that way.
- **No telemetry.** The CLI does not call home. Do not add analytics, error reporting, or crash dumps that send data anywhere. The only exception is the explicit `--telemetry=yes` flag, which is opt-in, anonymized, and off by default.

### 4. Pull request checklist

- [ ] Tests pass locally: `pytest tests/ -v`
- [ ] Lint passes: `ruff check . && ruff format --check .`
- [ ] Types pass: `mypy --strict .`
- [ ] New behavior has a test
- [ ] Public API changes are documented in the PR description
- [ ] Wire-format changes reference the corresponding wire-spec PR
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] You have read and agree to the [DCO](#developer-certificate-of-origin) below

### 5. Review process

- A maintainer will respond within 5 business days. Maintainers are listed in [GOVERNANCE.md](GOVERNANCE.md).
- PRs touching the verification path require review from two maintainers.
- PRs adding a provider audit-log reader (see [docs/readers/](docs/readers/)) require one maintainer review and a working integration test against a real fixture export.
- Security-sensitive PRs (signature verification, canonicalization, key handling) get the most scrutiny. Expect thorough review and potentially a formal verification proof for load-bearing changes.

## Developer Certificate of Origin

We use the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) to confirm that contributors have the right to submit their work. Every commit must include a `Signed-off-by` line:

```
Signed-off-by: Jane Contributor <jane@example.com>
```

Add this automatically with `git commit -s`.

By signing off, you certify that:

1. The contribution is your own original work, or
2. The contribution is based on previous work that is covered under an appropriate open-source license and you have the right to submit it under this project's license, or
3. The contribution was provided directly to you by someone who certified (1) or (2), and you have not modified it.

Specora does not require a full Contributor License Agreement (CLA). DCO sign-off is sufficient.

## Release process

Releases are cut by maintainers following the process in [GOVERNANCE.md](GOVERNANCE.md). All releases are Sigstore-signed. Release binaries are available from GitHub Releases; the PyPI package is published via a protected GitHub Actions workflow.

## Community expectations

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Be kind. Disagree with ideas, not people. Assume good faith.

## Questions

- Public: open a GitHub Discussion or issue.
- Private: `security@specora.ai` for security, `opensource@specora.ai` for governance and contribution questions.
