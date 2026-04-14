---
audience: public
visibility: public
surface: docs-site
last_reviewed: 2026-03-04
---
# Certification Attestation Golden Vectors

This directory contains golden test vectors for the certification-attestation specification.

## Files

| File | Description |
|------|-------------|
| `certification-attestation-1.0.0.json` | Example attestation payload (raw JSON) |
| `certification-attestation-1.0.0.canonical.json` | Canonical JSON bytes |
| `certification-attestation-1.0.0.sha256.txt` | SHA-256 hash of canonical bytes |

## Verification

### Python

```bash
specora-verify certify vectors verify
```

### Manual

```python
import json
import hashlib

# Load payload
with open('certification-attestation-1.0.0.json') as f:
    payload = json.load(f)

# Compute canonical bytes
canonical = json.dumps(
    payload,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode("utf-8")

# Load expected
with open('certification-attestation-1.0.0.canonical.json', 'rb') as f:
    expected_canonical = f.read()

with open('certification-attestation-1.0.0.sha256.txt') as f:
    expected_hash = f.read().strip()

# Verify
assert canonical == expected_canonical, "Canonical bytes mismatch"
assert hashlib.sha256(canonical).hexdigest() == expected_hash, "Hash mismatch"

print("Vector verification passed")
```

## Expected Values

| Version | SHA-256 Hash |
|---------|--------------|
| 1.0.0 | `dc3a8f5171eafadcb3c4ae11dabf0000e356a358e0aef2b9efaba19128fec36f` |

## Invariants

- **RCP-109:** Certification attestation hash must be deterministic and reproducible via canonical JSON.
