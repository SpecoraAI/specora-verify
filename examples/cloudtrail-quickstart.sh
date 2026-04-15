#!/usr/bin/env bash
# examples/cloudtrail-quickstart.sh
#
# End-to-end example: ingest the AWS CloudTrail (Bedrock AR Checks)
# fixture through the Specora reader, produce a canonical bundle
# payload, verify it is deterministic across runs, and print PASS/FAIL.
#
# Run from the repo root:
#
#     ./examples/cloudtrail-quickstart.sh
#
# This script uses the committed test fixture at
# tests/fixtures/cloudtrail/minimal-valid.json so it has no external
# dependencies — no network, no AWS credentials, no API calls. The
# same command against a real CloudTrail JSON export produced by
# `aws s3 cp`, `aws cloudtrail lookup-events`, or a CloudTrail Lake
# query export would work identically.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

INPUT="tests/fixtures/cloudtrail/minimal-valid.json"
KEY_ID="spk-quickstart-cloudtrail-demo"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Specora: AWS CloudTrail (Bedrock AR Checks) quickstart"
echo "    input:  $INPUT"
echo "    key-id: $KEY_ID"
echo

# Locate the specora-verify CLI. Prefer the installed entry point if
# available, otherwise fall back to running the package module.
if command -v specora-verify >/dev/null 2>&1; then
    SV=(specora-verify)
else
    SV=(python3 -m specora_verify.cli)
fi

echo "==> Step 1: read CloudTrail fixture → canonical bundle payload"
"${SV[@]}" read cloudtrail \
    --input "$INPUT" \
    --key-id "$KEY_ID" \
    --out "$WORK/bundle-a.json"

echo "==> Step 2: re-run to verify determinism (byte-identical output)"
"${SV[@]}" read cloudtrail \
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
echo "==> Step 3: inspect produced bundle metadata + AR proof payload"
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
print("    Bedrock AR Checks proof payloads:")
for rec in payload["records"]:
    d = rec["decision"]
    print(
        f"      {rec['id']}  region={rec['aws_region']}  "
        f"model={rec['model']['name']}"
    )
    print(
        f"        verdict={d['formal_verdict']}  outcome={d['outcome']}  "
        f"proof_hash={d['proof_hash'][:24]}..."
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
echo "==> PASS: AWS CloudTrail (Bedrock AR Checks) reader quickstart end-to-end"
