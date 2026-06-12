# Changelog

All notable changes to `specora-verify` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] — 2026-06-12

### Added

- **`specora-verify agent-identity verify`** subcommand — verify a Specora agent-identity
  certificate end-to-end from the command line. Fetches the issuer's published root,
  checks the cert chain, and exits non-zero on any failure. Sends an explicit
  `User-Agent: specora-verify/1.1.0` header so the published-root endpoint does not
  reject the request. ([#35])
- **Upstream-signature metadata** in bundle output — when ingesting signed records
  from providers that embed upstream signatures (currently Anthropic), readers now
  flag whether those signatures were verified (`verified`), present but not checked
  (`present_unverified`), or absent (`absent`). Unverified-but-present signatures
  emit a `stderr` warning and require `--public-key` to promote to `verified`. ([#33])
- **Internal-hostname CI guard** — `tests/test_no_internal_hostnames.py` blocks
  accidental commits of `home.lab`, `*.internal`, or `localhost` references outside
  the `tests/` directory, mirroring the monorepo `test_no_*` pattern. ([#34])

### Changed

- `.gitignore` now covers local CA cert files (`*.crt`) so home-lab trust-store
  overrides used during development are never accidentally staged.

---

## [1.0.0] — 2026-05-20

Initial public release.

- Core verifier (`specora-verify verify`) for Specora Evidence Bundles.
- Readers: Anthropic (GA), OpenAI (preview), LangSmith (preview).
- Golden test vectors aligned with Wire Spec v1.0.
- Sigstore-signed release artifacts (PyPI + GitHub Releases).
- Published-root endpoint monitoring (`api.specora.ai`, `spec.specora.ai`).

[1.1.0]: https://github.com/SpecoraAI/specora-verify/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/SpecoraAI/specora-verify/releases/tag/v1.0.0
[#33]: https://github.com/SpecoraAI/specora-verify/pull/33
[#34]: https://github.com/SpecoraAI/specora-verify/pull/34
[#35]: https://github.com/SpecoraAI/specora-verify/pull/35
