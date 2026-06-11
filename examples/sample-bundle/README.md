# Sample agent-identity credential

`sample-agent-identity.json` is a pre-built `specora-aid-cert-v1` credential
that Specora issued. It exists so you can prove `specora-verify` in minute one,
against Specora's *published* issuer key, without building a bundle first and
without a Specora account.

Run it from the repo root:

```bash
pip install "specora-verify[crypto]"
../verify-sample-bundle.sh            # fetch the published key, then verify
../verify-sample-bundle.sh --offline  # verify against the pinned key, no network
```

## What it is, and what it is not

The credential is signed by the **DEMO-ROOT** key, Specora's prelaunch issuer.
Its subject carries `OU=for-demo-only-not-production`. DEMO-ROOT is **not** the
production C01 ceremony root. Lane separation is enforced by the pinned issuer
fingerprint, never by the `specora-aid-cert-v1` format string, which is the
same across lanes. See [`../../docs/issuer-key-pinning.md`](../../docs/issuer-key-pinning.md)
for the pinning and rotation contract.

Pinned issuer fingerprint:
`ebeef29a04e372d1ac9a2239beea4af8152de9a6d9e63698fa79f2720abb91b8`.

The agent and owner public keys in the credential are deterministic throwaway
keys. They certify nothing on their own. Verification only checks the DEMO-ROOT
issuer signature over the envelope.

## Provenance and regeneration

The credential is produced on the issuing host by signing with the DEMO-ROOT
private key, which never leaves that host and is never committed anywhere. The
generator lives in the platform repo
(`services/prspec-api/scripts/gen_aid_sample_credential.py`). Regenerate this
file only when DEMO-ROOT rotates; a rotation invalidates every issued
credential and this sample alike, and `tests/test_sample_bundle_example.py`
will fail until the pinned constants and this artifact are updated together.
