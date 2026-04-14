# Security policy

## Scope

`specora-verify` is a cryptographic verification tool. Its correctness is load-bearing on real-world audit opinions, compliance attestations, and regulatory filings. Security issues in this tool are treated with the highest priority.

This policy applies to the latest released version of `specora-verify` and the two most recent prior minor versions.

## Reporting a vulnerability

**Do not open a public GitHub issue.** Use one of the following private channels instead:

### Preferred: GitHub private vulnerability reporting

1. Go to https://github.com/SpecoraAI/specora-verify/security/advisories/new
2. Fill out the form with reproduction steps and affected versions
3. Submit — the report goes directly to the maintainers, not to public view

### Alternative: PGP-encrypted email

Email `security@specora.ai`, encrypted to the PGP key below.

**Key details:** Ed25519 (RFC 8032) sign+cert master with Curve25519 encrypt subkey, created 2026-04-14, expires 2029-04-13 (3 years)

**Fingerprint:** `0AD9D5D22E9E0FFE4B5DC4146FAD723D0A7B2BC9`

**Pretty-printed:** `0AD9 D5D2 2E9E 0FFE 4B5D  C414 6FAD 723D 0A7B 2BC9`

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEad7J/xYJKwYBBAHaRw8BAQdAWUG0mqzVOxvsRuxFGTUeY6B91ip2GJaohVCw
IgFiKxW0YlNwZWNvcmEgU2VjdXJpdHkgKFZ1bG5lcmFiaWxpdHkgZGlzY2xvc3Vy
ZSBrZXkg4oCUIFNwZWNvcmFBSS9zcGVjb3JhLXZlcmlmeSkgPHNlY3VyaXR5QHNw
ZWNvcmEuYWk+iLUEExYKAF0WIQQK2dXSLp4P/ktdxBRvrXI9CnsryQUCad7J/xsU
gAAAAAAEAA5tYW51MiwyLjUrMS4xMiwwLDMCGwMFCQWjmoAFCwkIBwICIgIGFQoJ
CAsCBBYCAwECHgcCF4AACgkQb61yPQp7K8lWgwD/eSdet8SqDBpQGaO8KD0IaxKE
ltJgo+UinQnSSvWJZgQBAJBQkxYG0Dgci169FHnqdqro/57AOFF4yNXzQGHwt7cK
uDgEad7J/xIKKwYBBAGXVQEFAQEHQERDMOdNukJdXWBqo465lRQ0l5IKuPCuiANd
DQub1gIsAwEIB4iaBBgWCgBCFiEECtnV0i6eD/5LXcQUb61yPQp7K8kFAmneyf8b
FIAAAAAABAAObWFudTIsMi41KzEuMTIsMCwzAhsMBQkFo5qAAAoJEG+tcj0KeyvJ
czwA/3H0xUSDq7oh50zfIF3baxF5oFvTmUXlv+2kEvrkr+D+AQDOtrNxunDKg6cZ
weFV/GmWOgapH+g2wK3q8h0Ohuz/DQ==
=y+09
-----END PGP PUBLIC KEY BLOCK-----
```

Verify the fingerprint matches the value in this file before trusting the key. The key is also mirrored at:

- `https://specora.ai/.well-known/security-pubkey.asc` *(pending publication — see ops tracker)*
- `keys.openpgp.org` keyserver: `gpg --keyserver hkps://keys.openpgp.org --recv-keys 0AD9D5D22E9E0FFE4B5DC4146FAD723D0A7B2BC9` *(pending upload)*

## What to include in a report

- Affected version(s) of `specora-verify`
- A minimal reproduction (command, input files, expected vs actual output)
- Impact: what does the bug let an attacker do, and against whom?
- Whether the issue is currently public (disclosed on a blog, mailing list, social media)
- Whether you intend to publish before the embargo ends
- Your preferred credit line (name, handle, affiliation — or anonymous)

## Our commitments

When you report a vulnerability privately, we commit to:

| Time from report | Action |
|---|---|
| 24 hours | Acknowledgement from a maintainer |
| 5 business days | Initial assessment: accepted, declined, or more-info-needed |
| 30 days (target) | Fix merged to `main` and a release candidate cut |
| 60 days (hard cap) | Public advisory and coordinated disclosure, whether or not a fix has shipped |

If a fix cannot be produced within 60 days, we will publish an advisory describing the issue, its impact, and interim mitigations, with credit to the reporter. Silence beyond 60 days is not a tactic we use.

## What counts as a vulnerability

### In scope

- Signature verification accepts a forged or tampered bundle
- Canonical JSON implementation diverges from the wire spec, enabling hash collisions or replay
- Revocation-list handling fails to reject a revoked key
- Anchor / chain verification accepts a broken chain
- Any path that silently degrades a `FAIL` or `ERROR` result to `PASS`
- Dependency vulnerabilities (e.g., CVE in `cryptography`) that affect `specora-verify`'s security posture
- Supply-chain issues: unauthorized publication to PyPI, compromised Homebrew tap, Sigstore bundle mismatch with the released binary

### Out of scope

- Issues in the upstream `cryptography`, `PyNaCl`, `sigstore`, `httpx`, or `dnspython` libraries that do not manifest in `specora-verify`'s usage (report to the upstream project instead)
- Denial-of-service caused by feeding unbounded input to a local CLI (this is a local tool; the user controls input size)
- Issues that require the attacker to already have full write access to the machine running `specora-verify`
- Aesthetic or usability issues in CLI output

## Safe harbor

Specora will not pursue legal action against researchers who:

1. Report vulnerabilities through the private channels above
2. Do not access, modify, or destroy data they are not authorized to access
3. Do not publish details before the coordinated disclosure date
4. Act in good faith and follow responsible disclosure norms

This safe harbor applies to `specora-verify` specifically. It does not extend to Specora's commercial products, SaaS infrastructure, or customer data.

## Credit

Researchers who report valid vulnerabilities are credited in the release notes and the public advisory, unless they prefer to remain anonymous.

## Scope of trust claims

`specora-verify` proves cryptographic validity, not authority or authenticity of key material. See the [README §Trust Model](README.md#trust-model) for what the tool does and does not prove. A verification pass is a mathematical statement ("this signature matches this bundle under this public key"), not an institutional one ("this bundle is real"). Users are responsible for obtaining public keys through trusted channels.

## Past advisories

No advisories yet. This section will be populated as advisories are published.
