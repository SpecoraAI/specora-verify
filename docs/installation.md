# Installation

`specora-verify` is the independent verifier for AI systems. It is
designed to install cleanly on any laptop, server, or CI runner where
Python 3.11+ is available — and to run offline once installed.

This page is the full installation reference. If you only want the
short version: `pip install specora-verify` and then
`specora-verify vectors verify` to confirm the install works.

## What you actually need

The verifier ships with a deliberately small core. Pick the install
shape that matches what you're going to do with it.

| Use case | Install command |
|---|---|
| Verify a bundle whose signatures you don't need to check (e.g. inspecting structure, debugging) | `pip install specora-verify` |
| Verify Ed25519 signatures on bundles, artifacts, or attestations | `pip install "specora-verify[crypto]"` |
| Pull bundles from S3, GitHub Releases, or DNS-anchored sources | `pip install "specora-verify[fetchers]"` |
| Verify Sigstore bundles | `pip install "specora-verify[sigstore]"` |
| Anything else — full functionality | `pip install "specora-verify[all]"` |

Auditors and CI pipelines that need the complete verification surface
should install `[all]`. The extras are additive; nothing in the core
verifier breaks if you skip them.

## Requirements

- **Python 3.11, 3.12, or 3.13.** The core path uses only the standard
  library; no compiled dependencies are required for the default
  install.
- **No network access** is required for the core verification path.
  The `[fetchers]` extra is the only thing that talks to the network,
  and only when explicitly invoked.

## Install via pip

The recommended path for most users.

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

In a fresh virtualenv, this typically resolves in seconds for the
core install and ~30s for `[all]`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "specora-verify[all]"
specora-verify --version
```

## Install via Homebrew (macOS / Linuxbrew)

```bash
brew tap SpecoraAI/tap
brew install specora-verify
```

The Homebrew formula installs the full `[all]` feature set into a
self-contained Python environment — no system Python interaction.

## Install a standalone binary

Platform-specific binaries are published on every release. Each binary
is Sigstore-signed; verify the signature before running it. This is
the install path of choice for environments where Python is not
available or where supply-chain assurance on the binary itself is
required.

### Linux (x86_64)

```bash
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

### macOS (Apple Silicon and Intel)

Replace `linux-x86_64` with `darwin-arm64` or `darwin-x86_64`. The
verification step is identical.

### Windows (x86_64)

Download `specora-verify-windows-x86_64.exe` and the matching
`.sigstore` file from the release page. Verify with `cosign` (works
in PowerShell), then run the executable directly.

### Air-gapped install

Standalone binaries are the supported path for air-gapped environments.
Download the binary and `.sigstore` file on a connected machine,
verify, then transfer both to the target host. The verifier itself
does not phone home — once installed, it runs purely on local input.

## Install from source

```bash
git clone https://github.com/SpecoraAI/specora-verify.git
cd specora-verify
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
specora-verify --version
```

The `[dev]` extra adds `pytest`, `ruff`, `mypy`, and the cryptography
stack so you can run the test suite:

```bash
pytest -q
```

This is the path you want if you're contributing a new reader or a
bugfix. See [CONTRIBUTING.md](../CONTRIBUTING.md).

## Confirm the install

Every install ships with a self-test that runs the verifier against
the published golden vectors. Run it once after every install:

```bash
specora-verify vectors verify
```

You should see:

```
============================================================
SPECORA GOLDEN VECTOR VERIFICATION
============================================================
Vectors:        18 loaded
Passed:         18
Failed:         0
Status:         PASS
============================================================
```

If this prints `PASS`, your verifier is byte-identical with the
reference implementation and you can trust everything else it tells
you. If it prints `FAIL`, something is wrong — most often a Python
version mismatch or a partial install. Stop and resolve the failure
before relying on the tool.

## CI pipelines

`specora-verify` is designed to run in CI without modification.

```yaml
# GitHub Actions example
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"

- run: pip install "specora-verify[crypto]"

- run: specora-verify --ci bundle verify path/to/evidence.zip
```

The `--ci` flag collapses advisory `WARN` results (exit code `1`) to
hard failures (exit code `2`), so a CI step fails loudly on anything
short of a clean `PASS`. See
[api.md §Errors and exit codes](api.md#errors-and-exit-codes--specora_verifyerrors)
for the full exit-code matrix.

## Upgrading

```bash
pip install --upgrade specora-verify         # pip
brew upgrade specora-verify                  # Homebrew
```

For standalone binaries, replace the file. The
[versioning policy](versioning-policy.md) governs what changes are
allowed in patch, minor, and major releases — in short, any release
within a `1.x.y` line is byte-compatible with Wire Spec v1.0.

## Uninstall

```bash
pip uninstall specora-verify
brew uninstall specora-verify
rm /usr/local/bin/specora-verify-linux-x86_64    # standalone binary
```

Nothing is left behind in your home directory. The verifier does not
maintain any persistent local state.

## Troubleshooting

**`CRYPTO_MISSING` error when verifying a signature.** The core
install does not include `cryptography` or `PyNaCl`. Re-install with
`pip install "specora-verify[crypto]"`.

**`vectors verify` reports `FAIL` immediately after install.** Check
that you are on Python 3.11+ (`python3 --version`). On older Python,
dict ordering and string-formatting differences can break canonical
JSON byte-equality.

**Standalone binary fails Sigstore verification.** Confirm you fetched
the matching `.sigstore` bundle (not from an older release), and that
your local clock is correct — Sigstore certificates have short
validity windows. Do not run an unverified binary.

**`specora-verify: command not found` after `pip install`.** The
binary lands in your virtualenv's `bin/`. Activate the venv, or use
`python -m specora_verify` instead.

For anything not covered here, open an issue at
<https://github.com/SpecoraAI/specora-verify/issues>.
