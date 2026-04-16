#!/usr/bin/env bash
# examples/openai-compliance-quickstart.sh
#
# End-to-end example: ingest the OpenAI Compliance Platform fixture
# through the Specora reader, produce a canonical bundle payload,
# verify it is deterministic across runs, and print PASS/FAIL.
#
# Run from the repo root:
#
#     ./examples/openai-compliance-quickstart.sh
#
# This script uses the committed test fixture at
# tests/fixtures/openai_compliance/minimal-valid.json so it has no
# external dependencies — no network, no OpenAI credentials, no API
# calls. The same command against a real OpenAI Compliance Platform
# export would work identically.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

INPUT="tests/fixtures/openai_compliance/minimal-valid.json"
KEY_ID="spk-quickstart-openai-demo"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Specora: OpenAI Compliance Platform quickstart"
echo "    input:  $INPUT"
echo "    key-id: $KEY_ID"
echo

if command -v specora-verify >/dev/null 2>&1; then
    SV=(specora-verify)
else
    SV=(python3 -m specora_verify.cli)
fi

echo "==> Step 1: read OpenAI fixture → canonical bundle payload"
"${SV[@]}" read openai \
    --input "$INPUT" \
    --key-id "$KEY_ID" \
    --out "$WORK/bundle-a.json"

echo "==> Step 2: re-run to verify determinism (byte-identical output)"
"${SV[@]}" read openai \
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
echo "==> Step 3: inspect produced bundle metadata + moderation evidence"
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
print("    OpenAI compliance events:")
for rec in payload["records"]:
    print(
        f"      {rec['id']}  type={rec.get('upstream_event_type', 'n/a')}  "
        f"model={rec['model']['name']}"
    )
    print(
        f"        outcome={rec['decision']['outcome']}  "
        f"policies={rec['decision']['policy_refs']}"
    )
    mod = rec.get("upstream_moderation")
    if mod:
        print(
            f"        moderation: flagged={mod.get('flagged')}  "
            f"categories={list(mod.get('categories', {}).keys())}"
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
echo "==> PASS: OpenAI Compliance Platform reader quickstart end-to-end"
