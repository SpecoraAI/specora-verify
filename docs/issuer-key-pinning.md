# Pinning Specora's issuer key (relying-party guide)

This page is for operators of relying parties: acceptance networks,
audit systems, or any service that verifies `specora-aid-cert-v1`
agent-identity credentials. You face one decision with real
consequences: which issuer public key your system trusts. Get it from
the wrong place and an attacker who controls that place controls which
agents your system accepts.

The rule in one sentence: **fetch the key once from the publication
endpoint, verify its fingerprint against this document, pin it in your
own configuration, and fail closed on anything unpinned.**

## How credentials name their issuer

Every `specora-aid-cert-v1` credential carries an
`issuer_key_fingerprint`: the lowercase hex SHA-256 digest of the
issuer's raw 32-byte Ed25519 public key. No multihash prefix, no
base64, no truncation. Your verifier must never trust a key the
credential itself carries; it resolves the fingerprint against keys
you pinned in advance, and rejects the credential
(`credential.untrusted_issuer` or your equivalent) when no pinned key
matches.

```python
import hashlib
fingerprint = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()
```

## Where the key is published

```
GET https://api.specora.ai/.well-known/specora-demo-root.json
```

The response carries `public_key_hex`, `issuer_key_fingerprint`, the
issuer subject, and a `for-demo-only-not-production` marker. The
endpoint returns 404 whenever the issuance lane is disabled or no key
is provisioned; it never serves a stale or placeholder key.

## Verify out-of-band before pinning

A publication endpoint alone is one channel, and one channel can be
compromised. Before pinning, confirm the fetched fingerprint against
this document (distributed through this repository's signed release
process, independent of the API host):

| Root | Fingerprint | Status |
|---|---|---|
| Prelaunch root ("DEMO-ROOT") | `ebeef29a04e372d1ac9a2239beea4af8152de9a6d9e63698fa79f2720abb91b8` | Active since 2026-06-10. Pre-production: subject carries `OU=for-demo-only-not-production`. Retires when the C01 ceremony root activates. |

If the endpoint and this table disagree, do not pin. Contact
`security@specora.ai`.

**Never pin the test-vector key.** The golden vectors in this
repository (`vectors/agent-identity/`) are signed by a fixture key
(fingerprint `495bf96fce1b9bc49c337a338571db2ea5dee9f4835a6e7919f33fa2262b98e1`)
generated from a deterministic seed published in
`tools/regen_agent_identity_vectors.py`. Anyone with this repository
can mint credentials under it. It exists so verifier tests are
reproducible, nothing more.

## Pin it, then stop fetching

Treat the verified key as configuration, not as a runtime dependency:

- Store the key (or its fingerprint) in your own secret/config store.
- Do not re-fetch at request time. Live fetching turns publication
  into an availability and trust dependency, which is exactly what
  pinning exists to remove.
- Fail closed: if your trusted-key set is empty or unreadable, refuse
  to verify rather than falling back to any built-in default.
- Alert on mismatch: a credential naming an unknown fingerprint is
  either a rotation you missed or an attack. Either way, page someone.

## Rotation contract

Rotation invalidates every outstanding credential and every pin
simultaneously, so it is never silent:

- Planned rotation: minimum 3 days' notice to registered relying
  parties, with the new fingerprint included in the notice. The new
  fingerprint also lands in the table above and at the publication
  endpoint before the cutover.
- Compromise rotation: notice goes out immediately and the cutover
  happens as fast as relying parties can re-pin, but the same steps
  run: notice, publication, fingerprint table update.
- Superseded fingerprints stay listed (marked retired), so you can
  distinguish a legitimately rotated credential from a forged one.

To register as a relying party for rotation notices, email
`security@specora.ai` with your operational contact. Relying parties
we already coordinate with are tracked on our side; if you have never
contacted us, we cannot notify you.

## Lane separation and what comes next

The prelaunch root is not the production trust anchor. Production
issuance chains to the C01 public signing ceremony root (ceremony not
yet scheduled). Lane separation is enforced by the pinned fingerprint,
never by the credential's format string, which stays
`specora-aid-cert-v1` across lanes.

Planned hardening before production GA, in this order:

1. **Key bundle with successor key**: the publication endpoint will
   serve the active key and, during rotation windows, the announced
   successor, so relying parties can pre-pin instead of cutting over
   on a flag day.
2. **Transparency-log anchoring**: issuance events and root
   transitions recorded in the public transparency log (see
   [transparency-log.md](transparency-log.md)), giving a third
   independent channel for fingerprint verification.
3. **C01 ceremony root**: the production anchor, with its own custody
   and rotation procedures published at ceremony time.

Questions, mismatches, or suspected compromise: `security@specora.ai`.
