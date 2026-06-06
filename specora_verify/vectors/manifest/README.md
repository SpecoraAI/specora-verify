---
audience: public
visibility: public
surface: docs-site
last_reviewed: 2026-03-04
---
# Specora Manifest Golden Test Vectors

This directory contains cryptographic reference vectors for Specora's public manifest specifications.
These "golden" vectors act as an absolute bridge between platform-generated signatures/hashes and third-party implementation verifiers.

## Vector Structure

For each published version of a manifest schema (e.g., `proof-manifest-1.0.0`), three files represent the entire canonical pipeline:

1. `*.json` - The raw, human-readable Mock JSON payload spanning all strictly required fields.
2. `*.canonical.json` - The **exact byte string** produced by the Specora Canonicalization policy. Notice the complete lack of whitespace aside from string values, and strict ASCII unicode encoding.
3. `*.sha256.txt` - The SHA-256 hexadecimal 64-character hash computed directly against the canonical bytes.

## Usage in Testing Verifiers

When implementing a custom verification client or registry, add these files to your own test suites.

Your implementation must successfully:
1. Parse `proof-manifest-1.0.0.json` into an internal object representation.
2. Serialize that object back into bytes using your implementation's canonical algorithm.
3. Assert your canonical bytes **exactly** equal `proof-manifest-1.0.0.canonical.json`.
4. Run your SHA-256 digest on your bytes.
5. Assert the output hex digest **exactly** equals the contents of `proof-manifest-1.0.0.sha256.txt`.

If any test vectors fail in your client code, you will likely fail to verify live customer payloads across network boundaries.
