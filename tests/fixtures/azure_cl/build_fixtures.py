#!/usr/bin/env python3
"""Regenerate the Azure Confidential Ledger test fixtures.

Run from the repo root:

    python tests/fixtures/azure_cl/build_fixtures.py

Deterministic — record bodies are generated in a fixed order with
stable synthetic values, so two runs produce byte-identical fixture
files. Fixtures are committed to the repo so CI does not need any
Azure credentials or SGX/TDX hardware to run. No cryptographic signing
happens here because Azure Confidential Ledger receipts are consortium-
signed (ECDSA P-384) by a CCF network, not by a per-record content
key the reader can reproduce offline; the fixture receipts are
structurally-valid synthetic blobs.

The fixtures emulate the ``{"entries": [<entry>, ...]}`` archive shape
produced by aggregating ``GET /app/transactions/{transactionId}`` +
``GET /app/transactions/{transactionId}/receipt`` responses. Each entry
carries both the customer ledger payload (``contents.record``) and the
Confidential Ledger receipt (Merkle proof + consortium signature +
optional TEE enclave quote).
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
KEYS_DIR = FIXTURE_DIR / "keys"

_COLLECTION_ID = "subledger-ai-audit-2026"
_MODELS = (
    ("gpt-4o", "2024-08"),
    ("claude-opus-4-6", "20260320"),
    ("phi-4", "2026-01"),
)
_POLICY_SETS = (
    ["pol-1", "pol-7"],
    ["pol-2"],
    ["pol-3", "pol-9", "pol-12"],
)
_DECISION_PROGRAM = ("approved", "rejected", "deferred", "escalated")
_MRENCLAVE = "a" * 64
_MRSIGNER = "b" * 64


def _fake_b64(seed: bytes, length: int = 48) -> str:
    return base64.b64encode(hashlib.sha256(seed).digest()[:length] + seed[:8]).decode(
        "ascii"
    )


def _context_hash(i: int) -> str:
    return "sha256:" + hashlib.sha256(f"ctx-seed-{i:08d}".encode("ascii")).hexdigest()


def _merkle_proof(i: int) -> list[dict]:
    left = hashlib.sha256(f"left-{i:06d}".encode("ascii")).hexdigest()
    right = hashlib.sha256(f"right-{i:06d}".encode("ascii")).hexdigest()
    return [{"left": left}, {"right": right}]


def _leaf_components(i: int) -> dict:
    return {
        "claimsDigest": hashlib.sha256(f"claims-{i:06d}".encode("ascii")).hexdigest(),
        "commitEvidence": f"ce:1.{i:04d}",
        "writeSetDigest": hashlib.sha256(
            f"ws-{i:06d}".encode("ascii")
        ).hexdigest(),
    }


def _entry(
    i: int,
    *,
    model_name: str,
    model_version: str,
    policy_refs: list[str],
    decision: str,
    include_tee: bool = True,
    collection_id: str = _COLLECTION_ID,
) -> dict:
    seqno = 100 + i
    view = 2
    transaction_id = f"{view}.{seqno}"
    record_id = f"azcl-rec-{i:06d}"
    request_id = f"req-azcl-{i:08x}"
    record = {
        "record_id": record_id,
        "timestamp": f"2026-06-11T09:{i % 60:02d}:{(i * 7) % 60:02d}Z",
        "request_id": request_id,
        "model": model_name,
        "model_version": model_version,
        "decision": decision,
        "policy_refs": list(policy_refs),
        "context_hash": _context_hash(i),
    }
    receipt: dict = {
        "leafComponents": _leaf_components(i),
        "nodeCerts": [
            f"-----BEGIN CERTIFICATE-----\nFAKE-NODE-CERT-{i}\n-----END CERTIFICATE-----"
        ],
        "proof": _merkle_proof(i),
        "signature": _fake_b64(f"sig-{i:08d}".encode("ascii")),
        "serviceId": "specora-demo-ccf-service",
    }
    if include_tee:
        receipt["enclaveQuote"] = _fake_b64(f"quote-{i:08d}".encode("ascii"), 96)
        receipt["mrenclave"] = _MRENCLAVE
        receipt["mrsigner"] = _MRSIGNER
        receipt["reportData"] = hashlib.sha256(
            f"report-{i:06d}".encode("ascii")
        ).hexdigest()
    return {
        "collectionId": collection_id,
        "transactionId": transaction_id,
        "contents": {"record": record},
        "receipt": receipt,
    }


def _pretty(entries: list[dict]) -> str:
    return json.dumps({"entries": entries}, sort_keys=True, indent=2) + "\n"


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    (KEYS_DIR / "README.md").write_text(
        "# Azure Confidential Ledger reader — no test keys required\n\n"
        "Azure Confidential Ledger receipts are signed by the consortium\n"
        "service identity (ECDSA P-384) on a CCF network, not by an\n"
        "ed25519 per-record content key. The reader therefore accepts\n"
        "`--public-key` only for interface compatibility with other\n"
        "readers and surfaces an ignore-warning via `ReadResult.warnings`.\n\n"
        "The full cryptographic proof — Merkle inclusion path, consortium\n"
        "signature, and (when present) TEE enclave quote — is preserved\n"
        "verbatim under `records[].upstream_inclusion_proof` and\n"
        "`records[].tee_attestation` so an auditor re-walking the ledger\n"
        "proof has everything they need without the reader re-verifying\n"
        "anything offline.\n\n"
        "This directory exists so the fixture tree structurally matches\n"
        "the Anthropic and CloudTrail reader fixture layouts.\n",
        encoding="utf-8",
    )

    # ------------------------------------------------------------------
    # minimal-valid.json — 2 entries, both with TEE quotes.
    # ------------------------------------------------------------------
    minimal = [
        _entry(
            1,
            model_name=_MODELS[0][0],
            model_version=_MODELS[0][1],
            policy_refs=_POLICY_SETS[0],
            decision="approved",
        ),
        _entry(
            2,
            model_name=_MODELS[1][0],
            model_version=_MODELS[1][1],
            policy_refs=_POLICY_SETS[1],
            decision="rejected",
        ),
    ]
    (FIXTURE_DIR / "minimal-valid.json").write_text(_pretty(minimal), encoding="utf-8")

    # ------------------------------------------------------------------
    # realistic-complex.json — 18 entries across 3 models, all 4 decision
    # outcomes, mix of with-TEE-quote and without, across two collections.
    # ------------------------------------------------------------------
    complex_entries: list[dict] = []
    for i in range(18):
        model_name, model_version = _MODELS[i % 3]
        decision = _DECISION_PROGRAM[i % 4]
        include_tee = (i % 3) != 2  # 12 with TEE, 6 without
        collection_id = (
            _COLLECTION_ID if i < 12 else "subledger-ai-audit-2026-eu"
        )
        complex_entries.append(
            _entry(
                200 + i,
                model_name=model_name,
                model_version=model_version,
                policy_refs=_POLICY_SETS[i % 3],
                decision=decision,
                include_tee=include_tee,
                collection_id=collection_id,
            )
        )
    (FIXTURE_DIR / "realistic-complex.json").write_text(
        _pretty(complex_entries), encoding="utf-8"
    )

    # ------------------------------------------------------------------
    # malformed.json — 5 entries, 2 deliberately broken.
    # Layout: [ok, ok, ok, missing receipt, bad context_hash]
    # Non-strict should recover 3 records with 2 warnings.
    # ------------------------------------------------------------------
    good = [
        _entry(
            500 + i,
            model_name=_MODELS[0][0],
            model_version=_MODELS[0][1],
            policy_refs=_POLICY_SETS[0],
            decision="approved",
        )
        for i in range(3)
    ]
    missing_receipt = _entry(
        600,
        model_name=_MODELS[0][0],
        model_version=_MODELS[0][1],
        policy_refs=_POLICY_SETS[0],
        decision="approved",
    )
    missing_receipt.pop("receipt")
    bad_context = _entry(
        601,
        model_name=_MODELS[0][0],
        model_version=_MODELS[0][1],
        policy_refs=_POLICY_SETS[0],
        decision="approved",
    )
    bad_context["contents"]["record"]["context_hash"] = "md5:nope"
    malformed_entries = good + [missing_receipt, bad_context]
    (FIXTURE_DIR / "malformed.json").write_text(
        _pretty(malformed_entries), encoding="utf-8"
    )

    print(f"Wrote Azure CL fixtures to {FIXTURE_DIR}")
    print(f"  minimal-valid.json      ({len(minimal)} entries)")
    print(f"  realistic-complex.json  ({len(complex_entries)} entries)")
    print(f"  malformed.json          ({len(malformed_entries)} entries, 2 broken)")


if __name__ == "__main__":
    main()
