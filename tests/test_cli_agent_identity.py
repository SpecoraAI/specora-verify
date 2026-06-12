"""CLI tests for `specora-verify agent-identity verify` (GAP-12).

The onboarding wizard tells a customer to run this exact command on the
certificate they download. These tests pin that the command verifies a real
Specora-issued certificate against the published issuer key and exits 0, so the
"verify it yourself" moment the wizard promises actually works.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from specora_verify.cli import main
from specora_verify.errors import EXIT_ERROR, EXIT_FAIL, EXIT_PASS

# The GAP-01 published sample credential + the pinned DEMO-ROOT public key
# (offline copy of api.specora.ai/.well-known/specora-demo-root.json).
SAMPLE = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "sample-bundle"
    / "sample-agent-identity.json"
)
PINNED_KEY_HEX = "5a4e96c468061f94d90b4ec2998b65b9f6b57debc32dd098ffdcd8d99d29bb3c"


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert isinstance(excinfo.value.code, int)
    return excinfo.value.code


def test_agent_identity_verify_pass_with_pinned_key(capsys) -> None:
    code = _run(
        ["agent-identity", "verify", str(SAMPLE), "--issuer-key-hex", PINNED_KEY_HEX]
    )
    assert code == EXIT_PASS
    assert "PASS" in capsys.readouterr().out


def test_agent_identity_verify_fail_with_wrong_key(capsys) -> None:
    code = _run(
        ["agent-identity", "verify", str(SAMPLE), "--issuer-key-hex", "00" * 32]
    )
    assert code == EXIT_FAIL


def test_agent_identity_verify_requires_an_issuer_source() -> None:
    # No --issuer-key-hex / --issuer-key-file / --issuer-url supplied.
    code = _run(["agent-identity", "verify", str(SAMPLE)])
    assert code == EXIT_ERROR


def test_agent_identity_verify_issuer_key_file(tmp_path: Path) -> None:
    key_file = tmp_path / "issuer.hex"
    key_file.write_text(PINNED_KEY_HEX, encoding="utf-8")
    code = _run(
        ["agent-identity", "verify", str(SAMPLE), "--issuer-key-file", str(key_file)]
    )
    assert code == EXIT_PASS


def test_agent_identity_verify_json_format(capsys) -> None:
    import json

    code = _run(
        [
            "--format",
            "json",
            "agent-identity",
            "verify",
            str(SAMPLE),
            "--issuer-key-hex",
            PINNED_KEY_HEX,
        ]
    )
    assert code == EXIT_PASS
    out = capsys.readouterr().out.strip().splitlines()
    payload = json.loads(out[-1])
    assert payload["verification"] == "PASS"
