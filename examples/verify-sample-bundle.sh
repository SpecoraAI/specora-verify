#!/usr/bin/env bash
# examples/verify-sample-bundle.sh
#
# Prove specora-verify in minute one. This script verifies a pre-built,
# Specora-issued agent-identity credential against Specora's *published*
# issuer key, fetched from the public endpoint. You trust the key you pin,
# not the bundle that carries it. That is the whole point: an agent identity
# Specora signed verifies on your machine, offline, without Specora in the
# loop at verification time.
#
# Run from the repo root:
#
#     ./examples/verify-sample-bundle.sh              # fetch the live root
#     ./examples/verify-sample-bundle.sh --offline    # use the pinned key only
#
# The sample credential (examples/sample-bundle/sample-agent-identity.json) is
# signed by the prelaunch DEMO-ROOT key. DEMO-ROOT is a pre-production demo
# issuer (subject carries OU=for-demo-only-not-production). It is NOT the C01
# production ceremony root. See docs/issuer-key-pinning.md for the lane
# distinction and the rotation contract.
#
# Requires the crypto extra: pip install "specora-verify[crypto]"

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SAMPLE="examples/sample-bundle/sample-agent-identity.json"

# Out-of-band fingerprint, distributed through this repository's signed
# release process (independent of the API host). Verify the fetched key
# against this before trusting it. This value is also published in
# docs/issuer-key-pinning.md.
PINNED_FINGERPRINT="ebeef29a04e372d1ac9a2239beea4af8152de9a6d9e63698fa79f2720abb91b8"
PINNED_PUBLIC_KEY_HEX="5a4e96c468061f94d90b4ec2998b65b9f6b57debc32dd098ffdcd8d99d29bb3c"

ROOT_ENDPOINT="https://api.specora.ai/.well-known/specora-demo-root.json"

OFFLINE=0
if [[ "${1:-}" == "--offline" ]]; then
    OFFLINE=1
fi

echo "==> Specora: verify a published agent-identity credential offline"
echo "    sample: $SAMPLE"
echo

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ "$OFFLINE" -eq 1 ]]; then
    echo "==> Step 1: use the pinned DEMO-ROOT key (offline mode, no network)"
    ISSUER_PUBLIC_KEY_HEX="$PINNED_PUBLIC_KEY_HEX"
else
    echo "==> Step 1: fetch the published DEMO-ROOT key"
    echo "    $ROOT_ENDPOINT"
    # The endpoint rejects the default python-urllib User-Agent; curl is the
    # documented fetch path. Set a UA so a WAF does not 403 the request.
    if ! curl -fsS -A "specora-verify-example" "$ROOT_ENDPOINT" -o "$WORK/root.json"; then
        echo "    fetch FAILED (offline or endpoint unreachable)."
        echo "    Re-run with --offline to verify against the pinned key instead."
        exit 1
    fi
    ISSUER_PUBLIC_KEY_HEX="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public_key_hex'])" "$WORK/root.json")"

    echo "==> Step 2: verify the fetched key against the pinned fingerprint"
    FETCHED_FP="$(python3 -c "import hashlib,sys;print(hashlib.sha256(bytes.fromhex(sys.argv[1])).hexdigest())" "$ISSUER_PUBLIC_KEY_HEX")"
    if [[ "$FETCHED_FP" != "$PINNED_FINGERPRINT" ]]; then
        echo "    FINGERPRINT MISMATCH — do not trust this key."
        echo "      fetched: $FETCHED_FP"
        echo "      pinned:  $PINNED_FINGERPRINT"
        echo "    A mismatch is either a rotation you missed or an attack. Stop here."
        echo "    Contact security@specora.ai."
        exit 1
    fi
    echo "    fingerprint matches pinned value: $PINNED_FINGERPRINT"
fi

echo
echo "==> Step 3: verify the sample credential against the issuer key"
python3 - "$SAMPLE" "$ISSUER_PUBLIC_KEY_HEX" <<'PY'
import json
import sys

from specora_verify.agent_identity import validate_agent_identity_certificate

cert = json.load(open(sys.argv[1]))
issuer_public_key_hex = sys.argv[2]
result = validate_agent_identity_certificate(
    cert, issuer_public_key_hex=issuer_public_key_hex
)
if not result.valid:
    print(f"    verification: FAIL ({result.reason})")
    sys.exit(1)

subject = cert["subject"]
print("    verification: PASS")
print(f"    agent_id:      {subject['agent_id']}")
print(f"    org_id:        {subject['org_id']}")
print(f"    issuer:        {cert['issuer']['common_name']} "
      f"({cert['issuer']['organizational_unit']})")
print(f"    fingerprint:   {cert['issuer_key_fingerprint']}")
PY

echo
echo "==> PASS: published credential verified offline against the pinned issuer key"
