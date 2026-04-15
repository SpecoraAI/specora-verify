"""Tests for the Anthropic Compliance API reader.

Covers the five categories defined in the B01 reader design doc
(platform-repo `docs/strategy/b01-reader-design-notes-2026-Q2.md` §8):
minimal roundtrip, hypothesis determinism, realistic-complex,
malformed graceful failure, and CLI integration. The CLI integration
test lives in `tests/test_cli_read.py` so it can share the rest of
the CLI test harness.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import ReaderError, ReaderSchemaError
from specora_verify.readers import READERS, ReadResult, available_readers, get_reader
from specora_verify.readers.anthropic import AnthropicReader


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_anthropic_registered() -> None:
    assert "anthropic" in READERS
    assert "anthropic" in available_readers()
    reader = get_reader("anthropic")
    assert reader.provider_name == "anthropic"
    assert "1.0" in reader.supported_schema_versions


def test_get_reader_unknown_raises() -> None:
    with pytest.raises(KeyError):
        get_reader("no-such-provider")


# ---------------------------------------------------------------------------
# Category 1 — minimal fixture roundtrip
# ---------------------------------------------------------------------------


def test_minimal_roundtrip(anthropic_minimal: Path) -> None:
    reader = get_reader("anthropic")
    result = reader.read(
        input_path=anthropic_minimal,
        key_id="spk-test-0001",
        strict=True,
    )
    assert isinstance(result, ReadResult)
    assert result.provider == "anthropic"
    assert result.schema_version == "1.0"
    assert result.record_count == 2

    payload = result.bundle_payload
    assert payload["metadata"]["provider"] == "anthropic"
    assert payload["metadata"]["record_count"] == 2
    assert payload["metadata"]["key_id"] == "spk-test-0001"
    assert payload["metadata"]["content_hash"].startswith("sha256:")

    first, second = payload["records"]
    assert first["id"] == "rec-000001"
    assert first["model"] == {"name": "claude-opus-4-6", "version": "20260320"}
    assert first["decision"]["outcome"] == "approved"
    assert first["decision"]["policy_refs"] == ["p-42"]
    assert first["context"]["hash"].startswith("sha256:")
    assert first["upstream_signature"]["alg"] == "ed25519"

    assert second["id"] == "rec-000002"
    assert second["decision"]["outcome"] == "rejected"


def test_minimal_with_upstream_key_verification(
    anthropic_minimal: Path, anthropic_public_key: Path
) -> None:
    reader = get_reader("anthropic")
    result = reader.read(
        input_path=anthropic_minimal,
        key_id="spk-test-0001",
        public_key_path=anthropic_public_key,
        strict=True,
    )
    assert result.record_count == 2
    assert result.upstream_key_id == "anthropic-compliance-test-key-a03"
    assert result.warnings == ()


# ---------------------------------------------------------------------------
# Category 2 — Hypothesis determinism property test
# ---------------------------------------------------------------------------


@given(
    seed=st.integers(min_value=0, max_value=2**32 - 1),
    key_id=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Nd"), whitelist_characters="-_"),
        min_size=4,
        max_size=24,
    ),
)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_deterministic_output(anthropic_minimal: Path, seed: int, key_id: str) -> None:
    """Same input → byte-identical canonical bundle across repeated reads.

    The `seed` and `key_id` inputs are only used to vary the `key_id`
    parameter across examples — the reader input file is constant. We
    assert that two reads of the same file with the same key_id produce
    byte-identical canonical bundle payloads.
    """
    del seed  # varied by hypothesis to re-run the test; not consumed
    reader = get_reader("anthropic")
    a = reader.read(input_path=anthropic_minimal, key_id=key_id, strict=True)
    b = reader.read(input_path=anthropic_minimal, key_id=key_id, strict=True)
    assert canonical_json_bytes(a.bundle_payload) == canonical_json_bytes(b.bundle_payload)
    assert a.record_count == b.record_count == 2


# ---------------------------------------------------------------------------
# Category 3 — realistic-complex fixture
# ---------------------------------------------------------------------------


def test_realistic_complex(anthropic_complex: Path) -> None:
    reader = get_reader("anthropic")
    result = reader.read(
        input_path=anthropic_complex,
        key_id="spk-test-0001",
        strict=True,
    )
    assert result.record_count == 47
    models = {r["model"]["name"] for r in result.bundle_payload["records"]}
    assert models == {"claude-opus-4-6", "claude-sonnet-4-6"}
    outcomes = {r["decision"]["outcome"] for r in result.bundle_payload["records"]}
    assert outcomes == {"approved", "rejected", "deferred", "escalated"}
    for record in result.bundle_payload["records"]:
        assert record["context"]["hash"].startswith("sha256:")
        assert record["upstream_signature"]["alg"] == "ed25519"


# ---------------------------------------------------------------------------
# Category 4 — malformed graceful failure
# ---------------------------------------------------------------------------


def test_malformed_strict_fails(anthropic_malformed: Path) -> None:
    reader = get_reader("anthropic")
    with pytest.raises(ReaderError):
        reader.read(input_path=anthropic_malformed, key_id="k", strict=True)


def test_malformed_non_strict_recovers(anthropic_malformed: Path) -> None:
    reader = get_reader("anthropic")
    result = reader.read(input_path=anthropic_malformed, key_id="k", strict=False)
    assert result.record_count == 3
    assert len(result.warnings) == 2
    assert any("invalid JSON" in w or "missing" in w for w in result.warnings)


def test_missing_input_file_raises(tmp_path: Path) -> None:
    reader = get_reader("anthropic")
    with pytest.raises(ReaderError):
        reader.read(input_path=tmp_path / "does-not-exist.jsonl", key_id="k")


def test_unknown_schema_version_strict_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad-schema.jsonl"
    bad.write_text(
        json.dumps(
            {
                "record_id": "rec-x",
                "timestamp": "2026-06-10T14:22:00Z",
                "request_id": "req-x",
                "model": "claude-opus-4-6",
                "model_version": "20260320",
                "decision": "approved",
                "policy_refs": [],
                "context_hash": "sha256:" + "0" * 64,
                "signature": {"alg": "ed25519", "key_id": "k", "value": "AA=="},
                "schema_version": "99.0",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    reader = get_reader("anthropic")
    with pytest.raises(ReaderSchemaError):
        reader.read(input_path=bad, key_id="k", strict=True)


def test_empty_file_succeeds(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    reader = get_reader("anthropic")
    result = reader.read(input_path=empty, key_id="k", strict=True)
    assert result.record_count == 0
    assert result.warnings == ()


def test_reader_is_stateless(anthropic_minimal: Path) -> None:
    """Re-using a reader across calls must not leak state between invocations."""
    reader = AnthropicReader()
    r1 = reader.read(input_path=anthropic_minimal, key_id="k")
    r2 = reader.read(input_path=anthropic_minimal, key_id="k")
    assert r1.record_count == r2.record_count == 2
    assert canonical_json_bytes(r1.bundle_payload) == canonical_json_bytes(r2.bundle_payload)


def test_duplicate_record_id_warns(tmp_path: Path) -> None:
    dup = tmp_path / "dup.jsonl"
    line = json.dumps(
        {
            "record_id": "rec-dup",
            "timestamp": "2026-06-10T14:22:00Z",
            "request_id": "req-1",
            "model": "claude-opus-4-6",
            "model_version": "20260320",
            "decision": "approved",
            "policy_refs": [],
            "context_hash": "sha256:" + "0" * 64,
            "signature": {"alg": "ed25519", "key_id": "k", "value": "AA=="},
            "schema_version": "1.0",
        }
    )
    dup.write_text(line + "\n" + line + "\n", encoding="utf-8")
    reader = get_reader("anthropic")
    result = reader.read(input_path=dup, key_id="k", strict=False)
    assert result.record_count == 1
    assert any("duplicate" in w for w in result.warnings)
