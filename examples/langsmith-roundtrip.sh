#!/usr/bin/env bash
# examples/langsmith-roundtrip.sh
#
# End-to-end example: ingest the LangSmith Fleet fixture through the
# Specora reader, produce a canonical bundle payload, verify it is
# deterministic across runs, and print PASS/FAIL.
#
# Run from the repo root:
#
#     ./examples/langsmith-roundtrip.sh
#
# This script uses the committed test fixture at
# tests/fixtures/langsmith/minimal-valid.json so it has no external
# dependencies — no network, no LangSmith credentials, no API calls.
# The same command against a real LangSmith Fleet export would work
# identically.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

INPUT="tests/fixtures/langsmith/minimal-valid.json"
KEY_ID="spk-quickstart-langsmith-demo"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Specora: LangSmith Fleet quickstart"
echo "    input:  $INPUT"
echo "    key-id: $KEY_ID"
echo

if command -v specora-verify >/dev/null 2>&1; then
    SV=(specora-verify)
else
    SV=(python3 -m specora_verify.cli)
fi

echo "==> Step 1: read LangSmith fixture → canonical bundle payload"
"${SV[@]}" read langsmith \
    --input "$INPUT" \
    --key-id "$KEY_ID" \
    --out "$WORK/bundle-a.json"

echo "==> Step 2: re-run to verify determinism (byte-identical output)"
"${SV[@]}" read langsmith \
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
echo "==> Step 3: inspect produced bundle metadata + feedback evidence"
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
print("    LangSmith Fleet traces:")
for rec in payload["records"]:
    print(
        f"      {rec['id']}  type={rec.get('upstream_run_type', 'n/a')}  "
        f"model={rec['model']['name']}"
    )
    print(
        f"        outcome={rec['decision']['outcome']}  "
        f"policies={rec['decision']['policy_refs']}"
    )
    fb = rec.get("upstream_feedback")
    if fb:
        for entry in fb:
            print(
                f"        feedback: {entry.get('key')}={entry.get('score')}  "
                f"source={entry.get('source', 'n/a')}"
            )
    usage = rec.get("upstream_token_usage")
    if usage:
        print(f"        tokens: {usage}")
    cost = rec.get("upstream_cost")
    if cost is not None:
        print(f"        cost: ${cost:.5f}")
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
echo "==> PASS: LangSmith Fleet reader quickstart end-to-end"
