---
audience: public
visibility: public
surface: docs-site
last_reviewed: 2026-03-04
---
# Specora Anchor Payload Golden Test Vectors

This directory contains cryptographic reference vectors for Specora's public anchor payload specifications.
These "golden" vectors provide an absolute reference for third-party implementation verifiers.

## Vector Structure

For each published version of the anchor payload schema (e.g., `anchor-payload-1.0.0`), three files represent the entire canonical pipeline:

1. `*.json` - The raw, human-readable JSON payload with all required fields.
2. `*.canonical.json` - The **exact byte string** produced by canonical JSON serialization. Notice the complete lack of whitespace aside from string values, sorted keys, and strict ASCII encoding.
3. `*.sha256.txt` - The SHA-256 hexadecimal 64-character hash computed directly against the canonical bytes.

## Usage in Testing Verifiers

When implementing a custom verification client:

1. Parse `anchor-payload-1.0.0.json` into an internal object representation.
2. Serialize that object back into bytes using your implementation's canonical algorithm.
3. Assert your canonical bytes **exactly** equal `anchor-payload-1.0.0.canonical.json`.
4. Run your SHA-256 digest on your bytes.
5. Assert the output hex digest **exactly** equals the contents of `anchor-payload-1.0.0.sha256.txt`.

If any test vectors fail, your client will fail to verify live anchor payloads.

## Canonical JSON Algorithm

The canonicalization must follow [Manifest Canonical JSON Rules](../../manifest/manifest-canonical-json.md):

```python
canonical_bytes = json.dumps(
    payload,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode("utf-8")

payload_hash = hashlib.sha256(canonical_bytes).hexdigest()
```

## Current Vectors

| Schema | Hash |
|--------|------|
| anchor-payload v1.0.0 | `d3babd2037014f64b8a9c529ac0ae3dd5a4ea1cfb88bb8a6d4bbccc71c73cc5c` |

## Cross-Reference

The `manifest_hash` field in anchor payloads references a proof-manifest. Verify the chain:

1. Compute hash of proof-manifest using manifest vectors
2. Assert it matches `manifest_hash` in anchor payload
3. Compute hash of anchor payload
4. Assert it matches external receipt binding

## Self-Test with specora-verify

```bash
# Verify all anchor vectors pass
specora-verify anchor vectors verify

# Compute hash manually
specora-verify anchor hash anchor-payload-1.0.0.json
# Output: d3babd2037014f64b8a9c529ac0ae3dd5a4ea1cfb88bb8a6d4bbccc71c73cc5c
```

## Related

- [Anchor Payload Specification](../anchor-payload-1.0.0.md)
- [Manifest Vectors](../../manifest/vectors/)
