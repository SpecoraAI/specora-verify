<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/specora-logo-dark.svg">
    <img src="docs/assets/specora-logo-light.svg" alt="Specora" width="320">
  </picture>
</p>

# specora-verify

> **`specora-verify` is the independent verifier for AI systems.**
>
> Point it at an evidence bundle produced by any AI provider — Anthropic Claude Enterprise, OpenAI, Azure OpenAI, Amazon Bedrock, LangSmith Fleet — and it will tell you, offline, with no vendor account and no network calls, whether the bundle is cryptographically intact and whether the claims it carries are what they say they are.
>
> No dashboard to log into. No SaaS subscription. No phone-home. Just a command-line tool, a public wire spec, and a set of golden test vectors you can reproduce yourself.

[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/SpecoraAI/specora-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/SpecoraAI/specora-verify/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/specora-verify.svg)](https://pypi.org/project/specora-verify/)
[![Homebrew tap](https://img.shields.io/badge/homebrew-specora%2Ftap-orange)](https://github.com/SpecoraAI/homebrew-tap)
[![Wire Spec v1.0](https://img.shields.io/badge/wire%20spec-v1.0-green)](https://spec.specora.ai/v1.0)

---

## Why this exists

When an AI system takes an action on behalf of a human — approves a loan, writes a pull request, files a regulatory form, moves money — somebody eventually has to verify that the action happened the way the operator says it did. Today, that verification is a promise. You trust the vendor's dashboard, the vendor's logs, and the vendor's incident reports. If the vendor is wrong, mistaken, or compromised, you find out after the fact, if at all.

`specora-verify` replaces the promise with a proof.

**The principle:** an auditor, a regulator, a customer, or a skeptical engineer should be able to verify a claim about an AI system without trusting the party that produced the claim. That is the same principle behind `cosign` for software supply chains, Certificate Transparency for the Web PKI, and Sigstore for open-source signing. `specora-verify` brings that principle to AI evidence.

**The approach:**

- **Offline by default.** No network access is required for the core verification path. An auditor with no internet access at a client site can still verify a bundle.
- **Standard library only (for the core).** The default verifier uses Python's standard library — no proprietary blobs, no hidden dependencies, no service calls.
- **Wire spec is public.** The evidence bundle format is documented at https://spec.specora.ai/v1.0 under a permissive license. Third parties can implement alternate verifiers against the same spec.
- **Golden vectors are public.** Every claim this tool makes can be reproduced against the published test vectors. If you don't trust the CLI, verify the vectors yourself in another language.

## Install

### pip (recommended for most users)

```bash
# Core verification (stdlib only, no external deps)
pip install specora-verify

# With cryptographic signature verification
pip install "specora-verify[crypto]"

# With network fetchers (S3, GitHub, DNS)
pip install "specora-verify[fetchers]"

# With Sigstore bundle support
pip install "specora-verify[sigstore]"

# Everything
pip install "specora-verify[all]"
```

Requires Python 3.11 or newer.

### Homebrew (macOS / Linuxbrew)

```bash
brew tap SpecoraAI/tap
brew install specora-verify
```

The Homebrew formula installs the full `[all]` feature set.

### Standalone binary

Platform-specific binaries are published on every release. Each binary is Sigstore-signed; verify before running.

```bash
# Linux x86_64
curl -LO https://github.com/SpecoraAI/specora-verify/releases/latest/download/specora-verify-linux-x86_64
curl -LO https://github.com/SpecoraAI/specora-verify/releases/latest/download/specora-verify-linux-x86_64.sigstore
cosign verify-blob \
    --certificate-identity-regexp "^https://github.com/SpecoraAI/specora-verify/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle specora-verify-linux-x86_64.sigstore \
    specora-verify-linux-x86_64
chmod +x specora-verify-linux-x86_64
./specora-verify-linux-x86_64 --version
```

macOS (`darwin-arm64`, `darwin-x86_64`) and Windows (`windows-x86_64.exe`) builds are available from the same release page.

### From source

```bash
git clone https://github.com/SpecoraAI/specora-verify.git
cd specora-verify
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
specora-verify --version
```

## 60-second quickstart

Every install ships with a self-test that runs the verifier against the published golden vectors:

```bash
$ specora-verify vectors verify
============================================================
SPECORA GOLDEN VECTOR VERIFICATION
============================================================
Vectors:        18 loaded
Passed:         18
Failed:         0
Status:         PASS
============================================================
```

If this prints `PASS`, your verifier is byte-identical with the reference implementation and you can trust everything else it tells you. If it prints `FAIL`, something is wrong with either the install or the vectors — stop and investigate before relying on the tool.

## Verify an evidence bundle

```bash
# Verify a bundle ZIP produced by any Specora-compatible producer
specora-verify bundle verify my-evidence-bundle.zip

# Verify an Ed25519 signature over a canonical artifact
specora-verify verify \
    --artifact artifact.json \
    --signature signature.b64 \
    --public-key pubkey.pem

# Produce an archival verification receipt for an auditor
specora-verify emit-receipt \
    --artifact artifact.json \
    --signature signature.b64 \
    --public-key pubkey.pem \
    --out receipt.json
```

## Out-of-band verification for existing AI providers

You don't have to be a Specora customer to use this tool. `specora-verify` ships with readers for the audit-log exports that major AI providers already produce, so any operator running on those platforms can produce a Specora-verifiable bundle with zero vendor cooperation.

```bash
# Anthropic Claude Enterprise Compliance API export
specora-verify read anthropic \
    --input compliance.jsonl \
    --key-id spk-abcd1234 \
    --out bundle.sev

# Verify it
specora-verify bundle verify bundle.sev
```

Reader coverage at launch (2026-06-14):

- [x] Anthropic Compliance API — [docs](docs/readers/anthropic.md) · [module](specora_verify/readers/anthropic.py)
- [x] AWS CloudTrail Lake + Bedrock Automated Reasoning Checks — [docs](docs/readers/cloudtrail.md) · [module](specora_verify/readers/cloudtrail.py)
- [x] Azure Confidential Ledger (entries + receipts, TEE attestation extracted) — [docs](docs/readers/azure_cl.md) · [module](specora_verify/readers/azure_cl.py)
- [x] OpenAI Compliance Platform (moderation/policy-check evidence, design-accurate pending live-data validation) — [docs](docs/readers/openai-compliance.md) · [module](specora_verify/readers/openai_compliance.py)
- [x] LangSmith Fleet (feedback scores / human annotations as first-class evidence, design-accurate pending live-data validation) — [docs](docs/readers/langsmith.md) · [module](specora_verify/readers/langsmith.py)

Each reader is roughly 200 lines of Python and a schema-mapping document. Contributions for additional providers are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Trust model

`specora-verify` proves cryptographic validity. It does **not** prove institutional authority. Specifically:

**What a `PASS` means:**

1. The evidence bundle was signed by the holder of the private key corresponding to the public key you provided
2. The canonical JSON hash of the bundle matches what the signature covers
3. No bytes have been altered since signing
4. If a revocation list is provided, the signing key is not on it at the time of verification

**What a `PASS` does not mean:**

1. The public key actually belongs to the party you think it does — you must obtain the key through a trusted channel
2. The AI system actually did what the bundle claims — the verifier verifies the evidence chain, not the underlying operation
3. The evidence is fresh — `specora-verify` does not check timestamps against wall-clock time
4. Nothing has been revoked on the signer's side after you fetched their public key

For production deployments, pair `specora-verify` with a key-transparency log or a published root key ceremony. See [docs/trust-model.md](docs/trust-model.md) for the full discussion.

## Reproducing the golden vectors

Every hash and signature this tool emits is deterministic. You can verify them in a language of your choice by implementing [Wire Spec v1.0](docs/wire-spec-v1.0.md) directly. The spec is short, the cryptography is Ed25519 (RFC 8032), and the canonical JSON rules are written out explicitly.

```bash
# The vectors directory
ls vectors/manifest/
ls vectors/signature/
ls vectors/anchor/

# Cross-check a single vector by hand
specora-verify canonicalize vectors/manifest/proof-manifest-001.json | sha256sum
```

If your independent implementation disagrees with `specora-verify`, we want to know. Open an issue and include your implementation — either `specora-verify` has a bug, or the spec is ambiguous. Both are worth fixing.

## Integrations

`specora-verify` defines a public [Evidence Source API](docs/openapi/evidence-source-v1.yaml) (OpenAPI 3.1) that GRC platforms integrate against to ingest Specora evidence bundles as compliance evidence.

- **OpenAPI spec:** [docs/openapi/evidence-source-v1.yaml](docs/openapi/evidence-source-v1.yaml)
- **Example payloads:** [docs/openapi/examples/](docs/openapi/examples/)
- **GRC integration guide (for platform vendors):** [docs/integrations/grc-integration-guide.md](docs/integrations/grc-integration-guide.md)

Supported GRC platforms (commercial connectors available from Specora):

- [x] Drata — SOC 2, ISO 27001, ISO 42001
- [ ] Vanta *(planned)*
- [ ] Splunk *(planned)*
- [ ] AuditBoard *(planned)*

## Documentation

- **Wire Spec v1.0 (canonical):** [docs/wire-spec-v1.0.md](docs/wire-spec-v1.0.md) — normative contract. The `spec.specora.ai/v1.0` badge URL above is reserved for a future rendered view of this in-repo document; the repo is the authoritative source.
- **Versioning policy:** [docs/versioning-policy.md](docs/versioning-policy.md)
- **Quickstart tutorial:** [docs/quickstart.md](docs/quickstart.md)
- **Trust model:** [docs/trust-model.md](docs/trust-model.md)
- **Golden vectors guide:** [docs/vectors.md](docs/vectors.md)
- **Reader reference:** [docs/readers/](docs/readers/)
- **Evidence Source API (for GRC integrations):** [docs/openapi/evidence-source-v1.yaml](docs/openapi/evidence-source-v1.yaml)
- **Installation guide:** [docs/installation.md](docs/installation.md)
- **API reference (for library users):** [docs/api.md](docs/api.md)

## Contributing

We welcome contributions. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Bug reports, reader implementations for new providers, documentation improvements, and spec clarifications are all in scope.

## Security

Found a vulnerability? Do not open a public issue. See [SECURITY.md](SECURITY.md) for private disclosure channels.

## Governance

This project is currently stewarded by Specora, Inc., with a committed transition path to a neutral foundation (CNCF / LF / OpenSSF — decision pending Q4 2026). See [GOVERNANCE.md](GOVERNANCE.md) for the full structure, maintainer roster, and future-state plan.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

*Why is it called `specora-verify` and not something cooler?*
Because the verifier's job is to verify. Naming it anything else would suggest it does more than that — and it doesn't. The independent verifier is the entire point.
