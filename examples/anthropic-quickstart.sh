#!/usr/bin/env bash
# examples/anthropic-quickstart.sh
#
# End-to-end example: ingest the Anthropic Compliance API fixture
# through the Specora reader, produce a canonical bundle payload,
# verify it is deterministic across runs, and print PASS/FAIL.
#
# Run from the repo root:
#
#     ./examples/anthropic-quickstart.sh
#
# This script uses the committed test fixture at
# tests/fixtures/anthropic/minimal-valid.jsonl so it has no external
# dependencies — no network, no Anthropic credentials, no provider
# API. The same command against a real Anthropic Compliance API
# export produced by `--input <your-export.jsonl>` would work
# identically.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

INPUT="tests/fixtures/anthropic/minimal-valid.jsonl"
KEY_ID="spk-quickstart-demo"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Specora: Anthropic Compliance API quickstart"
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

echo "==> Step 1: read Anthropic fixture → canonical bundle payload"
"${SV[@]}" read anthropic \
    --input "$INPUT" \
    --key-id "$KEY_ID" \
    --out "$WORK/bundle-a.json"

echo "==> Step 2: re-run to verify determinism (byte-identical output)"
"${SV[@]}" read anthropic \
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
echo "==> Step 3: inspect produced bundle metadata"
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
echo "==> PASS: Anthropic reader quickstart end-to-end"
