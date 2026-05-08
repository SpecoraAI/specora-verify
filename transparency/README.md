# Transparency log root (AID-980, demo lane)

Append-only Merkle-tree-backed log of every AID-9xx issuance / rotation / revocation event for the investor-demo lane.

* Format: see [`docs/transparency-log.md`](../docs/transparency-log.md)
* Library: [`specora_verify/transparency.py`](../specora_verify/transparency.py)
* Tests: [`tests/test_transparency.py`](../tests/test_transparency.py)
* Authorization: [`docs/strategy/freeze-exceptions/2026-05-08-aid-investor-demo-build.md`](https://github.com/SpecoraAI/specora-platform) (platform repo). CSEA-SUPPRESS-2026-05-08-002. Archive 2026-06-05.

Per-epoch entries land under `<epoch_id>/entries.ndjson` and `<epoch_id>/root.json`. Demo deployment serves these files as static assets at `demo.specora.ai/transparency-log/`. Production deployment (`transparency.specora.ai`) is post-K14.
