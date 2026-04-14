---
audience: public
visibility: public
surface: docs-site
last_reviewed: 2026-03-04
---
# Anchor Receipt Golden Vectors

This directory contains golden test vectors for anchor receipt specifications.

## Purpose

Golden vectors enable independent verification of receipt canonicalization and hashing implementations. Any implementation that produces byte-identical output for these vectors is correct.

## Vector Files

For each specification version, three files are provided:

| File | Contents |
|------|----------|
| `anchor-receipt-{version}.json` | Raw JSON payload (human-readable) |
| `anchor-receipt-{version}.canonical.json` | Canonical JSON bytes (exact output) |
| `anchor-receipt-{version}.sha256.txt` | SHA-256 hash of canonical bytes |

## Verification Procedure

### Step 1: Load and Parse

```python
import json
payload = json.loads(open("anchor-receipt-1.0.0.json").read())
```

### Step 2: Canonicalize

```python
canonical = json.dumps(
    payload,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode("utf-8")
```

### Step 3: Compare Bytes

```python
expected = open("anchor-receipt-1.0.0.canonical.json", "rb").read()
assert canonical == expected, "Canonical bytes mismatch"
```

### Step 4: Verify Hash

```python
import hashlib
computed_hash = hashlib.sha256(canonical).hexdigest()
expected_hash = open("anchor-receipt-1.0.0.sha256.txt").read().strip()
assert computed_hash == expected_hash, "Hash mismatch"
```

## Using specora-verify

```bash
# Verify all receipt vectors
specora-verify receipt vectors verify

# Compute hash of a receipt file
specora-verify receipt hash anchor-receipt.json

# Verify a receipt against expected hash
specora-verify receipt verify anchor-receipt.json --expected $HASH
```

## Available Vectors

| Specification | Version | Status |
|---------------|---------|--------|
| anchor-receipt | 1.0.0 | Active |

## Payload/Receipt Binding

The receipt's `payload_hash` field **MUST** match the hash of the corresponding anchor payload. For this golden vector:

```
receipt.payload_hash = d3babd2037014f64b8a9c529ac0ae3dd5a4ea1cfb88bb8a6d4bbccc71c73cc5c
```

This matches the golden vector hash in `../vectors/anchor-payload-1.0.0.sha256.txt`, demonstrating correct payload binding.

## Related Documents

- [Anchor Receipt Specification](../anchor-receipt-1.0.0.md)
- [Anchor Payload Vectors](../../vectors/README.md)
- [Manifest Canonical JSON Rules](../../../manifest/manifest-canonical-json.md)
