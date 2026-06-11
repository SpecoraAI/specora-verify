"""GAP-02: preview readers must be labeled and must warn on use.

OpenAI Compliance Platform and LangSmith Fleet readers are schema-accurate
against synthetic fixtures but have not been validated against a real upstream
export. They are `[preview]`. A skeptical auditor who runs one against a real
export and hits a silent mismap loses trust in every reader, so the preview
status must be impossible to miss: a per-reader flag, a `--help` label, and a
one-line stderr warning on every invocation.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from specora_verify.cli import main
from specora_verify.errors import EXIT_PASS
from specora_verify.readers import (
    PREVIEW_WARNING,
    available_readers,
    is_preview_reader,
)

OPENAI_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "openai_compliance" / "minimal-valid.json"
)
LANGSMITH_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "langsmith" / "minimal-valid.json"
)
ANTHROPIC_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "anthropic" / "minimal-valid.jsonl"
)


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert isinstance(excinfo.value.code, int)
    return excinfo.value.code


def test_preview_flag_partitions_readers_correctly() -> None:
    assert is_preview_reader("openai") is True
    assert is_preview_reader("langsmith") is True
    assert is_preview_reader("anthropic") is False
    assert is_preview_reader("cloudtrail") is False
    assert is_preview_reader("azure-cl") is False
    # Unknown readers default to non-preview rather than raising.
    assert is_preview_reader("does-not-exist") is False


def test_every_registered_reader_declares_preview_status() -> None:
    # No reader may be ambiguous about validation status.
    from specora_verify.readers import READERS

    for name in available_readers():
        assert hasattr(READERS[name], "preview"), f"{name} missing preview flag"
        assert isinstance(READERS[name].preview, bool)


def test_openai_read_emits_preview_warning(tmp_path: Path, capsys) -> None:
    out = tmp_path / "bundle.json"
    code = _run(
        [
            "read",
            "openai",
            "--input",
            str(OPENAI_FIXTURE),
            "--key-id",
            "spk-test-preview",
            "--out",
            str(out),
        ]
    )
    assert code == EXIT_PASS
    err = capsys.readouterr().err
    assert "[preview]" in err
    assert PREVIEW_WARNING in err


def test_langsmith_read_emits_preview_warning(tmp_path: Path, capsys) -> None:
    out = tmp_path / "bundle.json"
    code = _run(
        [
            "read",
            "langsmith",
            "--input",
            str(LANGSMITH_FIXTURE),
            "--key-id",
            "spk-test-preview",
            "--out",
            str(out),
        ]
    )
    assert code == EXIT_PASS
    err = capsys.readouterr().err
    assert "[preview]" in err
    assert PREVIEW_WARNING in err


def test_validated_reader_emits_no_preview_warning(tmp_path: Path, capsys) -> None:
    out = tmp_path / "bundle.json"
    code = _run(
        [
            "read",
            "anthropic",
            "--input",
            str(ANTHROPIC_FIXTURE),
            "--key-id",
            "spk-test-preview",
            "--out",
            str(out),
        ]
    )
    assert code == EXIT_PASS
    err = capsys.readouterr().err
    assert "[preview]" not in err


def test_read_help_labels_preview_readers() -> None:
    buf = io.StringIO()
    with redirect_stdout(buf), pytest.raises(SystemExit):
        main(["read", "--help"])
    help_text = buf.getvalue()
    # The provider listing in `read --help` must mark the two preview readers.
    for line in help_text.splitlines():
        if line.strip().startswith("openai") or line.strip().startswith("langsmith"):
            assert "[preview]" in line, line
