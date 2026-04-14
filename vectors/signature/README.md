---
audience: public
visibility: public
surface: docs-site
last_reviewed: 2026-03-04
---
# Ed25519 Signature Verification Vectors

Golden test vectors for verifying Ed25519 signature verification implementation.

## Vector Structure

Each test case includes:
- `artifact.json` - The payload to verify
- `artifact.canonical.json` - Canonical JSON representation
- `artifact.sha256.txt` - SHA-256 hash of canonical bytes (64 hex chars)
- `signature.b64` - Base64-encoded Ed25519 signature (64 bytes)
- `pubkey.pem` - Ed25519 public key in PEM format
- `pubkey.b64` - Base64-encoded raw 32-byte public key
- `metadata.json` - Key fingerprint and derived key_id

## Signing Process

The signature is created over the **UTF-8 encoded SHA-256 hex string**, not the binary hash:

```
artifact → canonical JSON bytes → SHA-256 → hex string → UTF-8 bytes → Ed25519 sign
```

Example:
```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json
import hashlib

# Canonicalize
canonical = json.dumps(artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
canonical_bytes = canonical.encode("utf-8")

# Hash
hash_hex = hashlib.sha256(canonical_bytes).hexdigest()

# Sign (UTF-8 encoded hex string, NOT binary hash)
signature = private_key.sign(hash_hex.encode("utf-8"))
```

## Verification

```bash
# Verify using specora-verify
specora-verify verify \
    --artifact signed-artifact-001/artifact.json \
    --signature signed-artifact-001/signature.b64 \
    --public-key signed-artifact-001/pubkey.pem
```

## Test Cases

### signed-artifact-001

A minimal signed artifact demonstrating the complete verification flow.
This vector was generated using the same signing process as the server-side
`governance_signing_service.py` implementation.

- Artifact hash: `84de2af881d5951eb2aa54679bb67252ab471f595efb0985ced501e3d9ba087e`
- Key fingerprint: `c327a392d9a122974d8f8aea8a436bb0d5c355e9408ff5e1fb91ffa23c88e48c`
- Derived key_id: `spk-c327a392d9a12297`
