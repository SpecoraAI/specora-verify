# Azure Confidential Ledger reader — no test keys required

Azure Confidential Ledger receipts are signed by the consortium
service identity (ECDSA P-384) on a CCF network, not by an
ed25519 per-record content key. The reader therefore accepts
`--public-key` only for interface compatibility with other
readers and surfaces an ignore-warning via `ReadResult.warnings`.

The full cryptographic proof — Merkle inclusion path, consortium
signature, and (when present) TEE enclave quote — is preserved
verbatim under `records[].upstream_inclusion_proof` and
`records[].tee_attestation` so an auditor re-walking the ledger
proof has everything they need without the reader re-verifying
anything offline.

This directory exists so the fixture tree structurally matches
the Anthropic and CloudTrail reader fixture layouts.
