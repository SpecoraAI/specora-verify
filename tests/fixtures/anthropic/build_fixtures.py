#!/usr/bin/env python3
"""Regenerate the Anthropic Compliance API test fixtures.

Run from the repo root:

    python tests/fixtures/anthropic/build_fixtures.py

This script is deterministic — the synthetic Ed25519 keypair is derived
from a fixed seed and the record bodies are generated in a fixed order,
so two runs produce byte-identical fixture files. Fixtures are committed
to the repo so CI does not need PyNaCl to run — but regenerating locally
requires `pip install pynacl`.

The keypair is synthetic and is ONLY for tests. It never touches
production and has no meaning outside this test suite.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from nacl.signing import SigningKey

from specora_verify.canonical import canonical_json_bytes

FIXTURE_DIR = Path(__file__).resolve().parent
KEYS_DIR = FIXTURE_DIR / "keys"

# Fixed 32-byte seed — NEVER use this pattern for anything outside tests.
_SYNTHETIC_SEED = bytes.fromhex("a03b01" + "00" * (32 - 3))


def _make_signing_key() -> SigningKey:
    return SigningKey(_SYNTHETIC_SEED)


def _sign_record(record: dict, signing_key: SigningKey, key_id: str) -> dict:
    payload = {k: v for k, v in record.items() if k != "signature"}
    signed = signing_key.sign(canonical_json_bytes(payload))
    record["signature"] = {
        "alg": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(signed.signature).decode("ascii"),
    }
    return record


def _base_record(i: int, *, model: str, decision: str, policy_refs: list[str]) -> dict:
    return {
        "record_id": f"rec-{i:06d}",
        "timestamp": f"2026-06-10T14:22:{i % 60:02d}Z",
        "request_id": f"req-a03{i:05x}",
        "model": model,
        "model_version": "20260320",
        "input_token_count": 1000 + i,
        "output_token_count": 200 + i,
        "decision": decision,
        "policy_refs": list(policy_refs),
        "context_hash": f"sha256:{(i * 0x01010101) & 0xFFFFFFFFFFFFFFFF:016x}" + "0" * 48,
        "tool_invocations": [],
        "schema_version": "1.0",
    }


def _write_jsonl(path: Path, records: list[dict]) -> None:
    lines = [json.dumps(r, sort_keys=True, separators=(",", ":")) for r in records]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    signing_key = _make_signing_key()
    verify_key = signing_key.verify_key
    key_id = "anthropic-compliance-test-key-a03"

    # Write the public key in 64-char hex form that the reader accepts.
    (KEYS_DIR / "public.hex").write_text(verify_key.encode().hex() + "\n", encoding="utf-8")
    (KEYS_DIR / "README.md").write_text(
        "# Synthetic test key (NOT FOR PRODUCTION)\n\n"
        "Ed25519 keypair derived deterministically from a fixed seed in\n"
        "`build_fixtures.py`. Used only by the Anthropic reader test suite.\n"
        "Never ship this key or use it to sign anything outside tests.\n",
        encoding="utf-8",
    )

    # minimal-valid.jsonl — 2 records, used by the fast CI roundtrip test.
    minimal = [
        _sign_record(
            _base_record(1, model="claude-opus-4-6", decision="approved", policy_refs=["p-42"]),
            signing_key,
            key_id,
        ),
        _sign_record(
            _base_record(2, model="claude-sonnet-4-6", decision="rejected", policy_refs=["p-55"]),
            signing_key,
            key_id,
        ),
    ]
    _write_jsonl(FIXTURE_DIR / "minimal-valid.jsonl", minimal)

    # realistic-complex.jsonl — 47 records covering the full decision enum,
    # two models, mixed policy refs. Matches the blog / walkthrough count.
    models = ["claude-opus-4-6", "claude-sonnet-4-6"]
    decisions = ["approved", "rejected", "deferred", "escalated"]
    complex_records = []
    for i in range(1, 48):
        rec = _base_record(
            i,
            model=models[i % 2],
            decision=decisions[i % 4],
            policy_refs=[f"p-{10 + (i % 7)}", f"p-{40 + (i % 5)}"],
        )
        complex_records.append(_sign_record(rec, signing_key, key_id))
    _write_jsonl(FIXTURE_DIR / "realistic-complex.jsonl", complex_records)

    # malformed.jsonl — 5 records, 2 deliberately broken.
    # Layout: [ok, ok, ok, broken-json, missing-field]
    good_records = [
        _sign_record(
            _base_record(
                100 + i, model="claude-opus-4-6", decision="approved", policy_refs=["p-1"]
            ),
            signing_key,
            key_id,
        )
        for i in range(3)
    ]
    malformed_lines = [
        json.dumps(good_records[0], sort_keys=True, separators=(",", ":")),
        json.dumps(good_records[1], sort_keys=True, separators=(",", ":")),
        json.dumps(good_records[2], sort_keys=True, separators=(",", ":")),
        "{this is not valid json",
        json.dumps(
            {"record_id": "rec-broken-2", "timestamp": "2026-06-10T14:22:00Z"},
            sort_keys=True,
            separators=(",", ":"),
        ),
    ]
    (FIXTURE_DIR / "malformed.jsonl").write_text(
        "\n".join(malformed_lines) + "\n", encoding="utf-8"
    )

    print(f"Wrote fixtures to {FIXTURE_DIR}")


if __name__ == "__main__":
    main()
