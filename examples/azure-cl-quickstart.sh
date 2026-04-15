#!/usr/bin/env bash
# examples/azure-cl-quickstart.sh
#
# End-to-end example: ingest the Azure Confidential Ledger fixture
# (entries + receipts + TEE attestation) through the Specora reader,
# produce a canonical bundle payload, verify it is deterministic
# across runs, and print PASS/FAIL.
#
# Run from the repo root:
#
#     ./examples/azure-cl-quickstart.sh
#
# This script uses the committed test fixture at
# tests/fixtures/azure_cl/minimal-valid.json so it has no external
# dependencies — no network, no Azure credentials, no SGX/TDX hardware,
# no API calls. The same command against a real Azure Confidential
# Ledger export (per-transaction entry + receipt aggregated into a
# {"entries": [...]} envelope) would work identically.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

INPUT="tests/fixtures/azure_cl/minimal-valid.json"
KEY_ID="spk-quickstart-azure-cl-demo"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Specora: Azure Confidential Ledger quickstart"
echo "    input:  $INPUT"
echo "    key-id: $KEY_ID"
echo

if command -v specora-verify >/dev/null 2>&1; then
    SV=(specora-verify)
else
    SV=(python3 -m specora_verify.cli)
fi

echo "==> Step 1: read Azure CL fixture → canonical bundle payload"
"${SV[@]}" read azure-cl \
    --input "$INPUT" \
    --key-id "$KEY_ID" \
    --out "$WORK/bundle-a.json"

echo "==> Step 2: re-run to verify determinism (byte-identical output)"
"${SV[@]}" read azure-cl \
    --input "$INPUT" \
    --key-id "$KEY_ID" \
    --out "$WORK/bundle-b.json"

if cmp -s "$WORK/bundle-a.json" "$WORK/bundle-b.json"; then
    echo "    determinism: PASS (bundle-a and bundle-b are byte-identical)"
else
    echo "    determinism: FAIL (bundles differ across runs)"
    diff -u "$WORK/bundle-a.json" "$WORK/bundle-b.json" || true
    exit 1
fi

echo
echo "==> Step 3: inspect produced bundle metadata + TEE attestation"
python3 - "$WORK/bundle-a.json" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
meta = payload["metadata"]
print(f"    provider:                {meta['provider']}")
print(f"    reader:                  {meta['reader']}")
print(f"    reader_version:          {meta['reader_version']}")
print(f"    upstream_schema_version: {meta['upstream_schema_version']}")
print(f"    record_count:            {meta['record_count']}")
print(f"    key_id:                  {meta['key_id']}")
print(f"    content_hash:            {meta['content_hash']}")
print()
print("    Confidential Ledger receipts + TEE attestation:")
for rec in payload["records"]:
    proof = rec["upstream_inclusion_proof"]
    print(
        f"      {rec['id']}  tx={rec['upstream_tx_id']}  "
        f"model={rec['model']['name']}"
    )
    print(
        f"        inclusion_path={len(proof['proof'])} steps  "
        f"signature={proof['signature'][:24]}..."
    )
    tee = rec.get("tee_attestation")
    if tee:
        print(
            f"        tee quote={tee['enclaveQuote'][:20]}...  "
            f"mrenclave={tee['mrenclave'][:12]}..."
        )
PY

echo
echo "==> Step 4: canonicalize round-trip (verifies the output is already canonical)"
"${SV[@]}" canonicalize "$WORK/bundle-a.json" > "$WORK/bundle-a-canonical.json"
if cmp -s "$WORK/bundle-a.json" "$WORK/bundle-a-canonical.json"; then
    echo "    canonical-form check: PASS"
else
    echo "    canonical-form check: FAIL (reader output is not canonical)"
    diff -u "$WORK/bundle-a.json" "$WORK/bundle-a-canonical.json" || true
    exit 1
fi

echo
echo "==> PASS: Azure Confidential Ledger reader quickstart end-to-end"
