"""Tests for the LangSmith Fleet reader.

Covers the five categories defined in the B01 reader design doc
(platform-repo ``docs/strategy/b01-reader-design-notes-2026-Q2.md`` §8):
registry, minimal roundtrip, hypothesis determinism, realistic-complex,
malformed graceful failure. The CLI integration tests for this reader
live in ``tests/test_cli_read.py`` alongside the other reader CLI tests.

Additional tests validate:
- Feedback scores as first-class evidence (LangSmith's differentiator)
- Streaming/partial trace handling (status=pending)
- Canonical-bundle-v1.0 JSON Schema compliance
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import ReaderError, ReaderSchemaError
from specora_verify.readers import READERS, ReadResult, available_readers, get_reader
from specora_verify.readers.langsmith import LangSmithReader

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "docs"
    / "schemas"
    / "canonical-bundle-v1.0.json"
)


def _canonical_bundle_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_langsmith_registered() -> None:
    assert "langsmith" in READERS
    assert "langsmith" in available_readers()
    reader = get_reader("langsmith")
    assert reader.provider_name == "langsmith"
    assert "langsmith-fleet-v1" in reader.supported_schema_versions


# ---------------------------------------------------------------------------
# Category 1 — minimal fixture roundtrip
# ---------------------------------------------------------------------------


def test_minimal_roundtrip(langsmith_minimal: Path) -> None:
    reader = get_reader("langsmith")
    result = reader.read(
        input_path=langsmith_minimal,
        key_id="spk-langsmith-test-0001",
        strict=True,
    )
    assert isinstance(result, ReadResult)
    assert result.provider == "langsmith"
    assert result.schema_version == "langsmith-fleet-v1"
    assert result.record_count == 2

    payload = result.bundle_payload
    assert payload["metadata"]["provider"] == "langsmith"
    assert payload["metadata"]["reader"] == "specora_verify.readers.langsmith"
    assert payload["metadata"]["record_count"] == 2
    assert payload["metadata"]["key_id"] == "spk-langsmith-test-0001"
    assert payload["metadata"]["content_hash"].startswith("sha256:")

    first, second = payload["records"]

    # First record: chain with feedback and model from top-level model_name.
    assert first["id"] == "run_ls_00000001-0000-0000-0000-000000000001"
    assert first["timestamp"] == "2026-06-12T10:15:30Z"
    assert first["model"]["name"] == "claude-3-5-sonnet"
    assert first["model"]["version"] == "20241022"
    assert first["decision"]["outcome"] == "approved"
    assert first["decision"]["policy_refs"] == [
        "rule-guardrail-1",
        "rule-toxicity-check",
    ]
    assert first["upstream_signature"]["absent_per_record"] is True
    assert first["upstream_signature"]["integrity_mechanism"] == (
        "langsmith-fleet-api-tls-attested"
    )
    assert first["upstream_run_name"] == "customer-support-chain"
    assert first["upstream_run_type"] == "chain"
    assert first["upstream_session_id"] == "sess_demo_alpha"

    # Feedback scores preserved as first-class evidence.
    fb = first["upstream_feedback"]
    assert len(fb) == 2
    assert fb[0]["key"] == "correctness"
    assert fb[0]["score"] == 1.0
    assert fb[1]["key"] == "helpfulness"
    assert fb[1]["score"] == 0.9

    # Token usage preserved.
    assert first["upstream_token_usage"]["prompt_tokens"] == 245
    assert first["upstream_token_usage"]["total_tokens"] == 334

    # Cost preserved.
    assert first["upstream_cost"] == 0.00512

    # Second record: LLM run, outcome "fail" → rejected, model from extra.
    assert second["id"] == "run_ls_00000002-0000-0000-0000-000000000002"
    assert second["decision"]["outcome"] == "rejected"
    assert second["model"]["name"] == "gpt-4o"
    assert second["model"]["version"] == "2024-08-06"
    assert second["upstream_feedback"][0]["key"] == "toxicity"
    assert second["upstream_feedback"][0]["score"] == 0.0


def test_empty_runs_array_succeeds(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"runs": []}), encoding="utf-8")
    result = get_reader("langsmith").read(input_path=empty, key_id="k", strict=True)
    assert result.record_count == 0
    assert result.warnings == ()


def test_empty_file_succeeds(tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")
    result = get_reader("langsmith").read(input_path=empty, key_id="k", strict=True)
    assert result.record_count == 0


# ---------------------------------------------------------------------------
# Category 2 — hypothesis determinism property test
# ---------------------------------------------------------------------------


@given(
    seed=st.integers(min_value=0, max_value=2**32 - 1),
    key_id=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Nd"), whitelist_characters="-_"),
        min_size=4,
        max_size=24,
    ),
)
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_deterministic_output(langsmith_minimal: Path, seed: int, key_id: str) -> None:
    """Same input -> byte-identical canonical bundle across repeated reads."""
    del seed
    reader = get_reader("langsmith")
    a = reader.read(input_path=langsmith_minimal, key_id=key_id, strict=True)
    b = reader.read(input_path=langsmith_minimal, key_id=key_id, strict=True)
    assert canonical_json_bytes(a.bundle_payload) == canonical_json_bytes(b.bundle_payload)
    assert a.record_count == b.record_count == 2


# ---------------------------------------------------------------------------
# Category 3 — realistic-complex fixture (JSONL, multi-trace batch)
# ---------------------------------------------------------------------------


def test_realistic_complex(langsmith_complex: Path) -> None:
    reader = get_reader("langsmith")
    result = reader.read(
        input_path=langsmith_complex,
        key_id="spk-langsmith-test-0001",
        strict=False,
    )
    assert result.record_count == 10

    models = {r["model"]["name"] for r in result.bundle_payload["records"]}
    assert "claude-3-5-sonnet" in models
    assert "gpt-4o" in models
    assert "gpt-4o-mini" in models

    outcomes = {r["decision"]["outcome"] for r in result.bundle_payload["records"]}
    assert outcomes == {"approved", "rejected", "deferred", "escalated"}

    # Records with feedback.
    fb_count = sum(1 for r in result.bundle_payload["records"] if "upstream_feedback" in r)
    assert fb_count == 5

    for record in result.bundle_payload["records"]:
        assert record["upstream_signature"]["absent_per_record"] is True


def test_outcome_aliases_map_correctly(langsmith_complex: Path) -> None:
    """Verify that all LangSmith outcome aliases map to wire-spec enums."""
    reader = get_reader("langsmith")
    result = reader.read(
        input_path=langsmith_complex,
        key_id="spk-langsmith-test-0001",
        strict=False,
    )
    valid = {"approved", "rejected", "deferred", "escalated"}
    for record in result.bundle_payload["records"]:
        assert record["decision"]["outcome"] in valid


def test_run_types_preserved(langsmith_complex: Path) -> None:
    """All LangSmith run types are preserved in upstream_run_type."""
    reader = get_reader("langsmith")
    result = reader.read(
        input_path=langsmith_complex,
        key_id="k",
        strict=False,
    )
    run_types = {r["upstream_run_type"] for r in result.bundle_payload["records"]}
    assert run_types == {"chain", "llm", "tool", "retriever", "prompt", "embedding"}


# ---------------------------------------------------------------------------
# Category 4 — malformed input graceful failure
# ---------------------------------------------------------------------------


def test_malformed_strict_fails(langsmith_malformed: Path) -> None:
    reader = get_reader("langsmith")
    with pytest.raises(ReaderError):
        reader.read(input_path=langsmith_malformed, key_id="k", strict=True)


def test_malformed_non_strict_recovers(langsmith_malformed: Path) -> None:
    reader = get_reader("langsmith")
    result = reader.read(input_path=langsmith_malformed, key_id="k", strict=False)
    assert result.record_count == 3
    assert len(result.warnings) == 2
    assert any("content_hash" in w or "not a JSON object" in w for w in result.warnings)


def test_missing_input_file_raises(tmp_path: Path) -> None:
    reader = get_reader("langsmith")
    with pytest.raises(ReaderError):
        reader.read(input_path=tmp_path / "does-not-exist.json", key_id="k")


def test_wrong_envelope_strict_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(42), encoding="utf-8")
    with pytest.raises(ReaderSchemaError):
        get_reader("langsmith").read(input_path=bad, key_id="k", strict=True)


def test_unsupported_schema_version_strict_fails(langsmith_minimal: Path) -> None:
    with pytest.raises(ReaderSchemaError):
        get_reader("langsmith").read(
            input_path=langsmith_minimal,
            key_id="k",
            schema_version="99.9",
            strict=True,
        )


# ---------------------------------------------------------------------------
# Category 5 — feedback scores as first-class field (LangSmith differentiator)
# ---------------------------------------------------------------------------


def test_feedback_scores_populated(langsmith_minimal: Path) -> None:
    """Feedback scores ride as first-class evidence under upstream_feedback."""
    result = get_reader("langsmith").read(
        input_path=langsmith_minimal,
        key_id="k",
        strict=True,
    )
    for record in result.bundle_payload["records"]:
        assert "upstream_feedback" in record
        for fb in record["upstream_feedback"]:
            assert "key" in fb
            assert "score" in fb


def test_feedback_absent_when_not_provided(tmp_path: Path) -> None:
    """Records without feedback should not have upstream_feedback field."""
    run = {
        "id": "run_nofb_1",
        "name": "no-feedback",
        "run_type": "chain",
        "start_time": "2026-06-12T10:00:00Z",
        "status": "success",
        "evaluation": {"outcome": "approved", "rule_ids": ["r1"]},
        "content_hash": "sha256:" + "a" * 64,
    }
    f = tmp_path / "nofb.json"
    f.write_text(json.dumps({"runs": [run]}), encoding="utf-8")
    result = get_reader("langsmith").read(input_path=f, key_id="k", strict=True)
    assert result.record_count == 1
    assert "upstream_feedback" not in result.bundle_payload["records"][0]


# ---------------------------------------------------------------------------
# Category 6 — streaming/partial trace handling
# ---------------------------------------------------------------------------


def test_streaming_partial_trace_handled(tmp_path: Path) -> None:
    """A trace with status=pending (streaming/partial) should be accepted."""
    run = {
        "id": "run_partial_1",
        "name": "streaming-chain",
        "run_type": "chain",
        "start_time": "2026-06-12T10:00:00Z",
        "status": "pending",
        "evaluation": {"outcome": "pending", "rule_ids": []},
        "content_hash": "sha256:" + "d" * 64,
    }
    f = tmp_path / "partial.json"
    f.write_text(json.dumps({"runs": [run]}), encoding="utf-8")
    result = get_reader("langsmith").read(input_path=f, key_id="k", strict=True)
    assert result.record_count == 1
    assert result.bundle_payload["records"][0]["decision"]["outcome"] == "deferred"


# ---------------------------------------------------------------------------
# Category 7 — canonical-bundle-v1.0 JSON Schema validation
# ---------------------------------------------------------------------------


def test_bundle_payload_matches_canonical_bundle_schema(
    langsmith_minimal: Path,
) -> None:
    result = get_reader("langsmith").read(
        input_path=langsmith_minimal,
        key_id="spk-langsmith-schema-check",
        strict=True,
    )
    validator = _canonical_bundle_validator()
    errors = sorted(validator.iter_errors(result.bundle_payload), key=lambda e: list(e.path))
    assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]


def test_complex_bundle_matches_canonical_bundle_schema(
    langsmith_complex: Path,
) -> None:
    result = get_reader("langsmith").read(
        input_path=langsmith_complex,
        key_id="spk-langsmith-schema-check",
        strict=False,
    )
    validator = _canonical_bundle_validator()
    errors = sorted(validator.iter_errors(result.bundle_payload), key=lambda e: list(e.path))
    assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


def test_bare_array_accepted(tmp_path: Path) -> None:
    run = {
        "id": "run_bare_1",
        "name": "bare-array-run",
        "run_type": "llm",
        "start_time": "2026-06-12T10:00:00Z",
        "status": "success",
        "model_name": "gpt-4o-2024-08-06",
        "evaluation": {"outcome": "approved", "rule_ids": ["p1"]},
        "content_hash": "sha256:" + "a" * 64,
    }
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps([run]), encoding="utf-8")
    result = get_reader("langsmith").read(input_path=bare, key_id="k", strict=True)
    assert result.record_count == 1


def test_single_bare_run_accepted(tmp_path: Path) -> None:
    run = {
        "id": "run_single_1",
        "name": "single-run",
        "run_type": "tool",
        "start_time": "2026-06-12T10:00:00Z",
        "status": "success",
        "evaluation": {"outcome": "pass", "rule_ids": []},
        "content_hash": "sha256:" + "b" * 64,
    }
    single = tmp_path / "single.json"
    single.write_text(json.dumps(run), encoding="utf-8")
    result = get_reader("langsmith").read(input_path=single, key_id="k", strict=True)
    assert result.record_count == 1


def test_public_key_passed_surfaces_ignore_warning(langsmith_minimal: Path, tmp_path: Path) -> None:
    fake_key = tmp_path / "unused.hex"
    fake_key.write_text("00" * 32 + "\n", encoding="utf-8")
    result = get_reader("langsmith").read(
        input_path=langsmith_minimal,
        key_id="spk-pk-check",
        public_key_path=fake_key,
        strict=True,
    )
    assert result.record_count == 2
    assert any("--public-key" in w and "ignored" in w for w in result.warnings)


def test_duplicate_ids_drop_second(tmp_path: Path) -> None:
    run = {
        "id": "run_dup_1",
        "name": "dup-run",
        "run_type": "chain",
        "start_time": "2026-06-12T10:00:00Z",
        "status": "success",
        "evaluation": {"outcome": "approved", "rule_ids": ["p1"]},
        "content_hash": "sha256:" + "c" * 64,
    }
    dup = tmp_path / "dup.json"
    dup.write_text(json.dumps({"runs": [run, run]}), encoding="utf-8")
    result = get_reader("langsmith").read(input_path=dup, key_id="k", strict=False)
    assert result.record_count == 1
    assert any("duplicate" in w for w in result.warnings)


def test_reader_is_stateless(langsmith_minimal: Path) -> None:
    reader = LangSmithReader()
    r1 = reader.read(input_path=langsmith_minimal, key_id="k")
    r2 = reader.read(input_path=langsmith_minimal, key_id="k")
    assert r1.record_count == r2.record_count == 2
    assert canonical_json_bytes(r1.bundle_payload) == canonical_json_bytes(r2.bundle_payload)


def test_model_from_serialized_kwargs(tmp_path: Path) -> None:
    """Model name extracted from serialized.kwargs when top-level is absent."""
    run = {
        "id": "run_ser_1",
        "name": "serialized-model",
        "run_type": "chain",
        "start_time": "2026-06-12T10:00:00Z",
        "status": "success",
        "serialized": {"kwargs": {"model_name": "claude-3-5-sonnet-20241022"}},
        "evaluation": {"outcome": "pass", "rule_ids": []},
        "content_hash": "sha256:" + "e" * 64,
    }
    f = tmp_path / "ser.json"
    f.write_text(json.dumps({"runs": [run]}), encoding="utf-8")
    result = get_reader("langsmith").read(input_path=f, key_id="k", strict=True)
    assert result.bundle_payload["records"][0]["model"]["name"] == "claude-3-5-sonnet"
    assert result.bundle_payload["records"][0]["model"]["version"] == "20241022"


def test_no_model_uses_run_type_fallback(tmp_path: Path) -> None:
    """When no model is identifiable, model.name falls back to langsmith-<run_type>."""
    run = {
        "id": "run_nomodel_1",
        "name": "no-model-run",
        "run_type": "tool",
        "start_time": "2026-06-12T10:00:00Z",
        "status": "success",
        "evaluation": {"outcome": "pass", "rule_ids": []},
        "content_hash": "sha256:" + "f" * 64,
    }
    f = tmp_path / "nomodel.json"
    f.write_text(json.dumps({"runs": [run]}), encoding="utf-8")
    result = get_reader("langsmith").read(input_path=f, key_id="k", strict=True)
    assert result.bundle_payload["records"][0]["model"]["name"] == "langsmith-tool"
    assert result.bundle_payload["records"][0]["model"]["version"] == ""
