# Specora transparency log (AID-980, demo lane)

**Status:** Investor-demo lane. Authorized via [`docs/strategy/freeze-exceptions/2026-05-08-aid-investor-demo-build.md`](https://github.com/SpecoraAI/specora-platform) in the platform repo. CSEA-SUPPRESS-2026-05-08-002. Archive 2026-06-05.

A public, append-only Merkle-tree-backed log of every issuance / rotation / revocation event for the AID-9xx investor-demo lane. The model is Sigstore Rekor; this is a stripped-down filesystem-only variant suitable for the demo window. Production (`transparency.specora.ai`) is post-K14 work.

---

## 1. Why a transparency log

Specora's independence claim is structurally meaningless without a public, append-only record of every identity issued and revoked. A relying party who pins an issuer pubkey out-of-band can confirm — without contacting Specora — that an identity claim corresponds to a recorded issuance event that was logged before the relying party saw the evidence bundle.

Without the log, "Specora signed this cert" is a private claim. With the log, every cert Specora issues is publicly accountable.

The format identifier `specora-aid-tlog-v1-demo` is load-bearing throughout. Production format will revise the suffix when the C01 ceremony root is operational.

---

## 2. Wire layout

The log lives under `transparency/<epoch_id>/` in this repository (and in the demo deployment under `demo.specora.ai/transparency-log/`). Two files per epoch:

```
transparency/<epoch_id>/
├── entries.ndjson    # newline-delimited JSON, one entry per line, append-only
└── root.json         # Merkle root over entries.ndjson, refreshed on every append
```

### 2.1 entries.ndjson

Each line is a JSON object with this shape:

```jsonc
{
  "format": "specora-aid-tlog-v1-demo",
  "epoch_id": "2026-05-08",
  "seq": 0,
  "event_type": "issued",
  "identity_id": "00000000-0000-0000-0000-000000000001",
  "org_id": "00000000-0000-0000-0000-0000000000aa",
  "public_key_at_event": "...64-char hex Ed25519 pubkey...",
  "timestamp": "2026-05-08T12:00:00Z",
  "leaf_hash": "...sha256 hex over canonical-JSON of the entry minus this field..."
}
```

`seq` is per-epoch and starts at 0. Append-only at the application layer; the CI guard [`assert_monotonic_no_gaps`](../specora_verify/transparency.py) walks the on-disk file and asserts every (seq) from 0..N-1 is present.

### 2.2 root.json

```jsonc
{
  "format": "specora-aid-tlog-v1-demo",
  "epoch_id": "2026-05-08",
  "entry_count": 4,
  "merkle_root_hash": "...sha256 hex Merkle root over leaf hashes in seq order..."
}
```

Refreshed atomically on every append (write to `.tmp` + `os.replace`).

---

## 3. How a relying party uses the log

### 3.1 Fetch the log

Over plain HTTP (the entire demo log is static assets):

```
curl https://demo.specora.ai/transparency-log/2026-05-08/entries.ndjson
curl https://demo.specora.ai/transparency-log/2026-05-08/root.json
```

No authentication. No Specora contact required at validation time.

### 3.2 Verify an inclusion proof

For an evidence bundle that carries a Specora-issued cert, the relying party:

1. Walks `entries.ndjson` for the relevant epoch and finds the issuance event whose `identity_id` + `public_key_at_event` match the cert's subject.
2. Pulls the entry's `seq` and uses [`TransparencyLog.inclusion_proof`](../specora_verify/transparency.py) (or the equivalent in any other language) to compute an audit path.
3. Recomputes the Merkle root from the audit path and the entry's `leaf_hash`.
4. Asserts the recomputed root equals `root.json:merkle_root_hash`.

If the recomputed root matches, the entry is provably included in the epoch's log. The CLI / library helper at [`specora_verify.transparency.verify_inclusion_proof`](../specora_verify/transparency.py) does this end-to-end.

### 3.3 What a tampered or missing entry looks like

* **Entry missing entirely** — the relying party cannot find an `entries.ndjson` line whose `(identity_id, public_key_at_event)` matches the cert. Treat as a forgery.
* **Entry tampered post-write** — the `leaf_hash` in the entry no longer matches the SHA-256 of the canonical-JSON of the entry minus that field. Detected by the inclusion-proof verifier.
* **Root tampered** — the recomputed root does not match `root.json:merkle_root_hash`. Detected by the inclusion-proof verifier.

---

## 4. Operational model (demo lane)

The platform-side writer publishes events synchronously inside the AID-960 transaction so the log entry hits disk before the lifecycle event commits — same audit-before-action ordering as the issuance-events table. See [`platform repo`](https://github.com/SpecoraAI/specora-platform) `services/prspec-api/src/prspec_api/ai_agent_identity/transparency_log.py` for the writer.

The demo deployment serves the log as static assets from `demo.specora.ai/transparency-log/`. Production (`transparency.specora.ai`) replaces the static-asset path with an HTTP-fronted append-only blob store and adds a Sigstore-style witness gossip protocol — both post-K14.

---

## 5. CI guards

The `tests/test_transparency.py` suite covers:

- Append assigns zero-indexed `seq` per epoch
- Format marker is `specora-aid-tlog-v1-demo`
- `assert_monotonic_no_gaps` PASSes on a clean log and FAILs on a synthetic gap
- Stored Merkle root recomputes byte-equal from the on-disk leaf hashes
- Inclusion proofs verify for every entry (including odd-count edges)
- Tampered leaf hash breaks the proof verification

Empty-epoch root is the SHA-256 of an empty input (matches Sigstore Rekor's empty-tree convention).

---

## 6. What this is not (demo-fidelity caveats)

- **Not a federated log.** Production has multiple signers + witness gossip; the demo log is one writer.
- **Not a permanent log.** Demo log is archived 2026-06-05 alongside the rest of the demo lane.
- **Not fronted by `transparency.specora.ai`.** That subdomain is reserved for the production log when it lands post-K14.
- **No witness signatures.** Demo log entries are unsigned at the per-entry level; the epoch root is signed by the demo-deployment process at write time but the signature is not cryptographically rotated. Production format will add Sigstore-style witness signatures.
