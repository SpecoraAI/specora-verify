"""Tests for the OpenAI Compliance Platform reader.

Covers the five categories defined in the B01 reader design doc
(platform-repo ``docs/strategy/b01-reader-design-notes-2026-Q2.md`` §8):
registry, minimal roundtrip, hypothesis determinism, realistic-complex,
malformed graceful failure. The CLI integration tests for this reader
live in ``tests/test_cli_read.py`` alongside the other reader CLI tests.

An additional test validates the reader's bundle_payload against the
canonical-bundle-v1.0 JSON Schema landed in EPIC-B02.
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
from specora_verify.readers.openai_compliance import OpenAIComplianceReader

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


def test_openai_registered() -> None:
    assert "openai" in READERS
    assert "openai" in available_readers()
    reader = get_reader("openai")
    assert reader.provider_name == "openai"
    assert "openai-compliance-v1-preview" in reader.supported_schema_versions


# ---------------------------------------------------------------------------
# Category 1 — minimal fixture roundtrip
# ---------------------------------------------------------------------------


def test_minimal_roundtrip(openai_minimal: Path) -> None:
    reader = get_reader("openai")
    result = reader.read(
        input_path=openai_minimal,
        key_id="spk-openai-test-0001",
        strict=True,
    )
    assert isinstance(result, ReadResult)
    assert result.provider == "openai"
    assert result.schema_version == "openai-compliance-v1-preview"
    assert result.record_count == 2

    payload = result.bundle_payload
    assert payload["metadata"]["provider"] == "openai"
    assert payload["metadata"]["reader"] == "specora_verify.readers.openai_compliance"
    assert payload["metadata"]["record_count"] == 2
    assert payload["metadata"]["key_id"] == "spk-openai-test-0001"
    assert payload["metadata"]["content_hash"].startswith("sha256:")

    first, second = payload["records"]
    assert first["id"] == "evt_openai_00000001"
    assert first["timestamp"] == "2026-06-11T09:01:07Z"
    assert first["model"]["name"] == "gpt-4o"
    assert first["model"]["version"] == "2024-08-06"
    assert first["decision"]["outcome"] == "approved"
    assert first["decision"]["policy_refs"] == ["pol-openai-1", "pol-openai-7"]
    assert first["upstream_signature"]["absent_per_record"] is True
    assert first["upstream_signature"]["integrity_mechanism"] == (
        "openai-compliance-api-tls-attested"
    )
    assert first["upstream_request_id"] == "req_openai_00000001"
    assert first["upstream_project_id"] == "proj_synthetic_alpha"
    assert first["upstream_event_type"] == "policy_check"
    # Moderation block preserved as first-class evidence.
    mod = first["upstream_moderation"]
    assert mod["flagged"] is False
    assert "categories" in mod
    assert "category_scores" in mod

    # Second record: unix timestamp, outcome mapping blocked → rejected.
    assert second["id"] == "evt_openai_00000002"
    assert second["decision"]["outcome"] == "rejected"
    assert second["model"]["name"] == "gpt-4o-mini"
    assert second["model"]["version"] == "2024-07-18"
    assert second["upstream_moderation"]["flagged"] is True


def test_empty_data_array_succeeds(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"object": "list", "data": []}), encoding="utf-8")
    result = get_reader("openai").read(input_path=empty, key_id="k", strict=True)
    assert result.record_count == 0
    assert result.warnings == ()


def test_empty_file_succeeds(tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")
    result = get_reader("openai").read(input_path=empty, key_id="k", strict=True)
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
def test_deterministic_output(openai_minimal: Path, seed: int, key_id: str) -> None:
    """Same input -> byte-identical canonical bundle across repeated reads."""
    del seed
    reader = get_reader("openai")
    a = reader.read(input_path=openai_minimal, key_id=key_id, strict=True)
    b = reader.read(input_path=openai_minimal, key_id=key_id, strict=True)
    assert canonical_json_bytes(a.bundle_payload) == canonical_json_bytes(b.bundle_payload)
    assert a.record_count == b.record_count == 2


# ---------------------------------------------------------------------------
# Category 3 — realistic-complex fixture (JSONL)
# ---------------------------------------------------------------------------


def test_realistic_complex(openai_complex: Path) -> None:
    reader = get_reader("openai")
    result = reader.read(
        input_path=openai_complex,
        key_id="spk-openai-test-0001",
        strict=False,
    )
    assert result.record_count == 10

    models = {r["model"]["name"] for r in result.bundle_payload["records"]}
    assert models == {"gpt-4o", "gpt-4o-mini", "o1-preview"}

    outcomes = {r["decision"]["outcome"] for r in result.bundle_payload["records"]}
    assert outcomes == {"approved", "rejected", "deferred", "escalated"}

    # 4 records carry upstream_moderation, 6 do not.
    mod_count = sum(1 for r in result.bundle_payload["records"] if "upstream_moderation" in r)
    assert mod_count == 4

    for record in result.bundle_payload["records"]:
        assert record["upstream_signature"]["absent_per_record"] is True


def test_outcome_aliases_map_correctly(openai_complex: Path) -> None:
    """Verify that all OpenAI outcome aliases map to wire-spec enums."""
    reader = get_reader("openai")
    result = reader.read(
        input_path=openai_complex,
        key_id="spk-openai-test-0001",
        strict=False,
    )
    valid = {"approved", "rejected", "deferred", "escalated"}
    for record in result.bundle_payload["records"]:
        assert record["decision"]["outcome"] in valid


# ---------------------------------------------------------------------------
# Category 4 — malformed input graceful failure
# ---------------------------------------------------------------------------


def test_malformed_strict_fails(openai_malformed: Path) -> None:
    reader = get_reader("openai")
    with pytest.raises(ReaderError):
        reader.read(input_path=openai_malformed, key_id="k", strict=True)


def test_malformed_non_strict_recovers(openai_malformed: Path) -> None:
    reader = get_reader("openai")
    result = reader.read(input_path=openai_malformed, key_id="k", strict=False)
    assert result.record_count == 3
    assert len(result.warnings) == 2
    assert any("content_hash" in w or "not a JSON object" in w for w in result.warnings)


def test_missing_input_file_raises(tmp_path: Path) -> None:
    reader = get_reader("openai")
    with pytest.raises(ReaderError):
        reader.read(input_path=tmp_path / "does-not-exist.json", key_id="k")


def test_wrong_envelope_strict_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(42), encoding="utf-8")
    with pytest.raises(ReaderSchemaError):
        get_reader("openai").read(input_path=bad, key_id="k", strict=True)


def test_unsupported_schema_version_strict_fails(openai_minimal: Path) -> None:
    with pytest.raises(ReaderSchemaError):
        get_reader("openai").read(
            input_path=openai_minimal,
            key_id="k",
            schema_version="99.9",
            strict=True,
        )


def test_bare_array_accepted(tmp_path: Path) -> None:
    bare = tmp_path / "bare.json"
    event = {
        "id": "evt_bare_1",
        "type": "policy_check",
        "effective_at": "2026-06-11T10:00:00Z",
        "model": "gpt-4o-2024-08-06",
        "decision": {"outcome": "approved", "policy_ids": ["p1"]},
        "content_hash": "sha256:" + "a" * 64,
    }
    bare.write_text(json.dumps([event]), encoding="utf-8")
    result = get_reader("openai").read(input_path=bare, key_id="k", strict=True)
    assert result.record_count == 1


def test_single_bare_event_accepted(tmp_path: Path) -> None:
    single = tmp_path / "single.json"
    event = {
        "id": "evt_single_1",
        "type": "moderation",
        "effective_at": "2026-06-11T10:00:00Z",
        "model": "gpt-4o",
        "decision": {"outcome": "allowed", "policy_ids": []},
        "content_hash": "sha256:" + "b" * 64,
    }
    single.write_text(json.dumps(event), encoding="utf-8")
    result = get_reader("openai").read(input_path=single, key_id="k", strict=True)
    assert result.record_count == 1
    assert result.bundle_payload["records"][0]["model"]["version"] == ""


def test_public_key_passed_surfaces_ignore_warning(openai_minimal: Path, tmp_path: Path) -> None:
    fake_key = tmp_path / "unused.hex"
    fake_key.write_text("00" * 32 + "\n", encoding="utf-8")
    result = get_reader("openai").read(
        input_path=openai_minimal,
        key_id="spk-pk-check",
        public_key_path=fake_key,
        strict=True,
    )
    assert result.record_count == 2
    assert any("--public-key" in w and "ignored" in w for w in result.warnings)


def test_duplicate_ids_drop_second(tmp_path: Path) -> None:
    dup = tmp_path / "dup.json"
    event = {
        "id": "evt_dup_1",
        "type": "policy_check",
        "effective_at": "2026-06-11T10:00:00Z",
        "model": "gpt-4o-2024-08-06",
        "decision": {"outcome": "approved", "policy_ids": ["p1"]},
        "content_hash": "sha256:" + "c" * 64,
    }
    dup.write_text(json.dumps({"data": [event, event]}), encoding="utf-8")
    result = get_reader("openai").read(input_path=dup, key_id="k", strict=False)
    assert result.record_count == 1
    assert any("duplicate" in w for w in result.warnings)


def test_reader_is_stateless(openai_minimal: Path) -> None:
    reader = OpenAIComplianceReader()
    r1 = reader.read(input_path=openai_minimal, key_id="k")
    r2 = reader.read(input_path=openai_minimal, key_id="k")
    assert r1.record_count == r2.record_count == 2
    assert canonical_json_bytes(r1.bundle_payload) == canonical_json_bytes(r2.bundle_payload)


# ---------------------------------------------------------------------------
# Category 5 — canonical-bundle-v1.0 JSON Schema validation
# ---------------------------------------------------------------------------


def test_bundle_payload_matches_canonical_bundle_schema(
    openai_minimal: Path,
) -> None:
    result = get_reader("openai").read(
        input_path=openai_minimal,
        key_id="spk-openai-schema-check",
        strict=True,
    )
    validator = _canonical_bundle_validator()
    errors = sorted(validator.iter_errors(result.bundle_payload), key=lambda e: list(e.path))
    assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]


def test_complex_bundle_matches_canonical_bundle_schema(
    openai_complex: Path,
) -> None:
    result = get_reader("openai").read(
        input_path=openai_complex,
        key_id="spk-openai-schema-check",
        strict=False,
    )
    validator = _canonical_bundle_validator()
    errors = sorted(validator.iter_errors(result.bundle_payload), key=lambda e: list(e.path))
    assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]
