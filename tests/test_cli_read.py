"""CLI integration tests for `specora-verify read <provider>`.

Exercises the parser, dispatch, and end-to-end reader flow via the
same entry point that installed users hit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from specora_verify.canonical import canonical_json_str
from specora_verify.cli import main
from specora_verify.errors import EXIT_ERROR, EXIT_PASS

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "anthropic"


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert isinstance(excinfo.value.code, int)
    return excinfo.value.code


def test_cli_read_anthropic_minimal_to_file(tmp_path: Path, capsys) -> None:
    out = tmp_path / "bundle.json"
    code = _run(
        [
            "read",
            "anthropic",
            "--input",
            str(FIXTURE_DIR / "minimal-valid.jsonl"),
            "--key-id",
            "spk-test-cli",
            "--out",
            str(out),
        ]
    )
    assert code == EXIT_PASS
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["metadata"]["provider"] == "anthropic"
    assert payload["metadata"]["record_count"] == 2
    assert payload["metadata"]["key_id"] == "spk-test-cli"
    captured = capsys.readouterr()
    assert "read anthropic: 2 records" in captured.err


def test_cli_read_anthropic_deterministic_across_runs(tmp_path: Path) -> None:
    out_a = tmp_path / "a.json"
    out_b = tmp_path / "b.json"
    for out in (out_a, out_b):
        code = _run(
            [
                "read",
                "anthropic",
                "--input",
                str(FIXTURE_DIR / "minimal-valid.jsonl"),
                "--key-id",
                "spk-deterministic",
                "--out",
                str(out),
            ]
        )
        assert code == EXIT_PASS
    assert out_a.read_bytes() == out_b.read_bytes()


def test_cli_read_anthropic_stdout_canonical(tmp_path: Path, capsys) -> None:
    code = _run(
        [
            "read",
            "anthropic",
            "--input",
            str(FIXTURE_DIR / "minimal-valid.jsonl"),
            "--key-id",
            "spk-stdout",
        ]
    )
    assert code == EXIT_PASS
    out = capsys.readouterr().out.strip()
    payload = json.loads(out)
    # Stdout output must be canonical (sorted keys, compact, no whitespace).
    assert out == canonical_json_str(payload)
    assert payload["metadata"]["record_count"] == 2


def test_cli_read_anthropic_strict_malformed_errors(tmp_path: Path, capsys) -> None:
    code = _run(
        [
            "read",
            "anthropic",
            "--input",
            str(FIXTURE_DIR / "malformed.jsonl"),
            "--key-id",
            "spk-strict",
        ]
    )
    assert code == EXIT_ERROR


def test_cli_read_anthropic_non_strict_recovers(tmp_path: Path, capsys) -> None:
    out = tmp_path / "bundle.json"
    code = _run(
        [
            "read",
            "anthropic",
            "--input",
            str(FIXTURE_DIR / "malformed.jsonl"),
            "--key-id",
            "spk-non-strict",
            "--non-strict",
            "--out",
            str(out),
        ]
    )
    assert code == EXIT_PASS
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["metadata"]["record_count"] == 3
    err = capsys.readouterr().err
    assert "3 records" in err
    assert "2 warnings" in err


def test_cli_read_anthropic_with_upstream_public_key(tmp_path: Path) -> None:
    out = tmp_path / "bundle.json"
    code = _run(
        [
            "read",
            "anthropic",
            "--input",
            str(FIXTURE_DIR / "minimal-valid.jsonl"),
            "--key-id",
            "spk-key-check",
            "--public-key",
            str(FIXTURE_DIR / "keys" / "public.hex"),
            "--out",
            str(out),
        ]
    )
    assert code == EXIT_PASS
