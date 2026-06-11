"""GAP-01: the shipped sample credential must verify against the published
DEMO-ROOT key, and the verify example must exit 0.

These tests are hermetic (no network): they pin the DEMO-ROOT public key and
fingerprint exactly as documented in ``docs/issuer-key-pinning.md`` and run the
example in ``--offline`` mode. The live endpoint is exercised by the
customer-edge probe at release time, not in unit CI, so the suite never flakes
on network.

If DEMO-ROOT rotates, this test fails loudly: regenerate the sample with
``services/prspec-api/scripts/gen_aid_sample_credential.py`` in the platform
repo and update the pinned constants below together.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "examples" / "sample-bundle" / "sample-agent-identity.json"
EXAMPLE = REPO_ROOT / "examples" / "verify-sample-bundle.sh"

# Documented DEMO-ROOT pin (docs/issuer-key-pinning.md). Kept in lockstep with
# the published endpoint and the example script.
DEMO_ROOT_PUBLIC_KEY_HEX = (
    "5a4e96c468061f94d90b4ec2998b65b9f6b57debc32dd098ffdcd8d99d29bb3c"
)
DEMO_ROOT_FINGERPRINT = (
    "ebeef29a04e372d1ac9a2239beea4af8152de9a6d9e63698fa79f2720abb91b8"
)

pytest.importorskip(
    "cryptography",
    reason="agent-identity verification needs the [crypto] extra (CI installs [all])",
)


def _load_sample() -> dict:
    return json.loads(SAMPLE.read_text())


def test_sample_exists_and_is_demo_lane() -> None:
    cert = _load_sample()
    assert cert["format"] == "specora-aid-cert-v1"
    # Demo-lane labeling must be unmistakable in the artifact itself.
    assert cert["issuer"]["organizational_unit"] == "for-demo-only-not-production"


def test_sample_fingerprint_matches_published_root() -> None:
    cert = _load_sample()
    assert cert["issuer_key_fingerprint"] == DEMO_ROOT_FINGERPRINT


def test_pinned_pubkey_hashes_to_documented_fingerprint() -> None:
    import hashlib

    computed = hashlib.sha256(
        bytes.fromhex(DEMO_ROOT_PUBLIC_KEY_HEX)
    ).hexdigest()
    assert computed == DEMO_ROOT_FINGERPRINT


def test_sample_verifies_against_published_root() -> None:
    from specora_verify.agent_identity import validate_agent_identity_certificate

    cert = _load_sample()
    result = validate_agent_identity_certificate(
        cert, issuer_public_key_hex=DEMO_ROOT_PUBLIC_KEY_HEX
    )
    assert result.valid, result.reason
    assert result.principal is not None


def test_sample_rejected_under_wrong_issuer_key() -> None:
    # Sanity: a credential is only as good as the key it is checked against.
    from specora_verify.agent_identity import validate_agent_identity_certificate

    wrong_key = "00" * 32
    result = validate_agent_identity_certificate(
        _load_sample(), issuer_public_key_hex=wrong_key
    )
    assert not result.valid


def test_verify_example_exits_zero_offline() -> None:
    # The acceptance criterion: the sample-bundle example exits 0 in CI.
    proc = subprocess.run(
        ["bash", str(EXAMPLE), "--offline"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin"},
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "PASS" in proc.stdout
