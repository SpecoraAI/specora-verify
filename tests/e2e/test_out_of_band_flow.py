"""EPIC-B03 end-to-end out-of-band verification flow tests.

Each test exercises the full pipeline a customer would run::

    specora-verify run --provider <p> \\
        --input <export> --key-id <id> \\
        --private-key <k> --out <dir>
    specora-verify verify \\
        --artifact <dir>/payload.json \\
        --signature <dir>/payload.sig \\
        --public-key <dir>/signing-key.pub

…against committed fixtures for every shipped B01 reader (Anthropic,
CloudTrail, Azure CL). The tamper test asserts the verifier rejects a
bundle whose payload has been mutated post-signing — the same negative
property an auditor depends on in production.

We invoke the CLI through ``specora_verify.cli.main`` in-process rather
than shelling out so the tests stay fast and stdlib-only (no subprocess
env plumbing). This matches the pattern in ``tests/test_cli_read.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from specora_verify.cli import EXIT_FAIL, EXIT_PASS, EXIT_WARN, main

# A successful verify may return EXIT_PASS (0) or EXIT_WARN (1). EXIT_WARN
# fires when the verifier has no revocation list and surfaces a trust
# warning — the signature is still cryptographically valid. For the e2e
# contract "the bundle verifies", both are acceptable; anything ≥ EXIT_FAIL
# means the signature itself did not verify.
_VERIFY_OK = {EXIT_PASS, EXIT_WARN}

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures"

# Deterministic 32-byte seed — test-only, never used outside this suite.
_SIGNING_SEED = bytes.fromhex("b0" * 32)


def _write_signing_key(tmp_path: Path) -> Path:
    """Materialize a deterministic Ed25519 private key in 64-char hex form."""
    key_path = tmp_path / "signing.hex"
    key_path.write_text(_SIGNING_SEED.hex() + "\n", encoding="utf-8")
    return key_path


def _call(argv: list[str]) -> int:
    """Invoke ``specora_verify.cli.main`` and return the would-be exit code.

    ``main`` calls ``sys.exit`` unconditionally, so we catch ``SystemExit``
    and surface the integer for the test assertion.
    """
    try:
        main(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        return code
    return 0


# Each entry: (provider, fixture_subdir, fixture_filename).
# Kept as parametrize data rather than a fixture-of-fixtures so a pytest
# --collect-only cleanly enumerates the shipped-reader coverage.
_PROVIDER_MATRIX = [
    ("anthropic", "anthropic", "minimal-valid.jsonl"),
    ("cloudtrail", "cloudtrail", "minimal-valid.json"),
    ("azure-cl", "azure_cl", "minimal-valid.json"),
]


@pytest.mark.parametrize("provider,subdir,filename", _PROVIDER_MATRIX)
def test_run_then_verify_passes(
    tmp_path: Path, provider: str, subdir: str, filename: str
) -> None:
    """`run` against a fixture produces a bundle `verify` accepts."""
    fixture = FIXTURE_ROOT / subdir / filename
    assert fixture.exists(), f"missing committed fixture: {fixture}"

    signing_key = _write_signing_key(tmp_path)
    out_dir = tmp_path / f"{provider}-bundle"

    run_code = _call(
        [
            "run",
            "--provider",
            provider,
            "--input",
            str(fixture),
            "--key-id",
            f"e2e-{provider}-key",
            "--private-key",
            str(signing_key),
            "--out",
            str(out_dir),
        ]
    )
    assert run_code == EXIT_PASS, f"run failed for provider {provider}"

    payload_path = out_dir / "payload.json"
    signature_path = out_dir / "payload.sig"
    public_key_path = out_dir / "signing-key.pub"
    metadata_path = out_dir / "metadata.json"

    assert payload_path.exists()
    assert signature_path.exists()
    assert public_key_path.exists()
    assert metadata_path.exists()

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["provider"] == provider
    assert metadata["record_count"] >= 1
    assert len(metadata["payload_sha256"]) == 64

    verify_code = _call(
        [
            "verify",
            "--artifact",
            str(payload_path),
            "--signature",
            str(signature_path),
            "--public-key",
            str(public_key_path),
        ]
    )
    assert verify_code in _VERIFY_OK, (
        f"verify rejected a freshly-signed bundle for provider {provider}"
    )


def test_run_verify_rejects_tampered_bundle(tmp_path: Path) -> None:
    """Mutating the payload post-signing must flip the verifier to FAIL.

    This is the single most important acceptance property of the whole
    out-of-band pipeline: the cryptographic binding between the provider
    export and the signed bundle must not survive tampering. A regression
    here means the product isn't a verifier, it's a renamer.
    """
    fixture = FIXTURE_ROOT / "anthropic" / "minimal-valid.jsonl"
    signing_key = _write_signing_key(tmp_path)
    out_dir = tmp_path / "anthropic-tamper"

    run_code = _call(
        [
            "run",
            "--provider",
            "anthropic",
            "--input",
            str(fixture),
            "--key-id",
            "e2e-tamper-key",
            "--private-key",
            str(signing_key),
            "--out",
            str(out_dir),
        ]
    )
    assert run_code == EXIT_PASS

    payload_path = out_dir / "payload.json"
    signature_path = out_dir / "payload.sig"
    public_key_path = out_dir / "signing-key.pub"

    # Pre-check: untampered bundle verifies.
    assert (
        _call(
            [
                "verify",
                "--artifact",
                str(payload_path),
                "--signature",
                str(signature_path),
                "--public-key",
                str(public_key_path),
            ]
        )
        in _VERIFY_OK
    )

    # Tamper the payload while keeping it valid JSON so the verifier
    # reaches the signature-check path rather than short-circuiting on a
    # parse error.
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["__tamper__"] = "injected post-signing"
    payload_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    tampered_code = _call(
        [
            "verify",
            "--artifact",
            str(payload_path),
            "--signature",
            str(signature_path),
            "--public-key",
            str(public_key_path),
        ]
    )
    assert tampered_code == EXIT_FAIL, (
        "verifier accepted a tampered payload — cryptographic binding broken"
    )


def test_run_rejects_unknown_provider(tmp_path: Path) -> None:
    """Unknown provider surfaces an orchestration error, not a crash."""
    fixture = FIXTURE_ROOT / "anthropic" / "minimal-valid.jsonl"
    signing_key = _write_signing_key(tmp_path)
    out_dir = tmp_path / "nope-bundle"

    code = _call(
        [
            "run",
            "--provider",
            "not-a-real-provider",
            "--input",
            str(fixture),
            "--key-id",
            "e2e-bad",
            "--private-key",
            str(signing_key),
            "--out",
            str(out_dir),
        ]
    )
    assert code != EXIT_PASS


def test_load_signing_key_round_trips_hex_and_raw(tmp_path: Path) -> None:
    """Both hex and raw-bytes formats load to the same Ed25519 key."""
    from specora_verify.orchestration import load_signing_key

    hex_path = tmp_path / "k.hex"
    hex_path.write_text(_SIGNING_SEED.hex() + "\n", encoding="utf-8")

    raw_path = tmp_path / "k.raw"
    raw_path.write_bytes(_SIGNING_SEED)

    hex_key = load_signing_key(hex_path)
    raw_key = load_signing_key(raw_path)

    assert isinstance(hex_key, Ed25519PrivateKey)
    assert isinstance(raw_key, Ed25519PrivateKey)

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    hex_pub = hex_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    raw_pub = raw_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert hex_pub == raw_pub
