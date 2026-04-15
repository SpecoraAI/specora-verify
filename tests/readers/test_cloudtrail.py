"""Tests for the AWS CloudTrail Lake (Bedrock AR Checks) reader.

Covers the five categories defined in the B01 reader design doc
(platform-repo ``docs/strategy/b01-reader-design-notes-2026-Q2.md`` §8):
registry, minimal roundtrip, hypothesis determinism, realistic-complex,
malformed graceful failure. The CLI integration test for this reader
lives in ``tests/test_cli_read.py`` alongside the Anthropic CLI tests.

An additional test validates the reader's bundle_payload shape against
an inline JSON Schema using the same ``jsonschema`` validator pattern
as ``tests/test_wire_spec_schemas.py``. The CloudTrail reader bundle is
a provider-shape envelope (``{metadata, records}``) that is distinct
from the eight canonical wire-spec payload schemas in ``docs/schemas/``;
this distinction is recorded in the design-notes §9 decisions log as a
known divergence deferred to EPIC-B02 (canonical reader bundle schema).
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
from specora_verify.readers.cloudtrail import CloudTrailReader, _split_model_id


# Inline JSON Schema for the reader bundle payload shape. Mirrors what
# every reader produces today. Kept in the test module (not in
# ``docs/schemas/``) because the eight canonical schemas there are the
# wire-spec payload shapes, not the per-reader bundle envelope; the
# canonical reader-bundle schema is deferred to EPIC-B02.
_READER_BUNDLE_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Specora reader bundle payload (CloudTrail)",
    "type": "object",
    "required": ["metadata", "records"],
    "additionalProperties": False,
    "properties": {
        "metadata": {
            "type": "object",
            "required": [
                "provider",
                "reader",
                "reader_version",
                "key_id",
                "upstream_schema_version",
                "record_count",
                "content_hash",
            ],
            "additionalProperties": False,
            "properties": {
                "provider": {"type": "string", "const": "cloudtrail"},
                "reader": {"type": "string"},
                "reader_version": {"type": "string"},
                "key_id": {"type": "string"},
                "upstream_schema_version": {"type": "string"},
                "record_count": {"type": "integer", "minimum": 0},
                "content_hash": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            },
        },
        "records": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "id",
                    "timestamp",
                    "upstream_event_name",
                    "upstream_request_id",
                    "aws_region",
                    "model",
                    "decision",
                    "context",
                    "upstream_signature",
                ],
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "timestamp": {
                        "type": "string",
                        "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
                    },
                    "upstream_event_name": {"type": "string"},
                    "upstream_request_id": {"type": "string"},
                    "aws_region": {"type": "string"},
                    "model": {
                        "type": "object",
                        "required": ["name", "version"],
                        "additionalProperties": False,
                        "properties": {
                            "name": {"type": "string"},
                            "version": {"type": "string"},
                        },
                    },
                    "decision": {
                        "type": "object",
                        "required": [
                            "outcome",
                            "policy_refs",
                            "formal_verdict",
                            "proof_hash",
                            "constraints",
                        ],
                        "additionalProperties": False,
                        "properties": {
                            "outcome": {
                                "type": "string",
                                "enum": ["approved", "rejected", "deferred", "escalated"],
                            },
                            "policy_refs": {
                                "type": "array",
                                "items": {"type": "string"},
                                "minItems": 1,
                            },
                            "formal_verdict": {"type": "string"},
                            "proof_hash": {
                                "type": "string",
                                "pattern": "^sha256:[0-9a-f]{64}$",
                            },
                            "constraints": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                    },
                    "context": {
                        "type": "object",
                        "required": ["hash"],
                        "additionalProperties": False,
                        "properties": {
                            "hash": {
                                "type": "string",
                                "pattern": "^sha256:[0-9a-f]{64}$",
                            }
                        },
                    },
                    "upstream_signature": {
                        "type": "object",
                        "required": ["absent_per_record", "integrity_mechanism"],
                        "additionalProperties": False,
                        "properties": {
                            "absent_per_record": {"type": "boolean", "const": True},
                            "integrity_mechanism": {
                                "type": "string",
                                "const": "cloudtrail-log-file-validation",
                            },
                        },
                    },
                },
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_cloudtrail_registered() -> None:
    assert "cloudtrail" in READERS
    assert "cloudtrail" in available_readers()
    reader = get_reader("cloudtrail")
    assert reader.provider_name == "cloudtrail"
    assert "1.09" in reader.supported_schema_versions
    assert "1.08" in reader.supported_schema_versions


# ---------------------------------------------------------------------------
# Category 1 — minimal fixture roundtrip
# ---------------------------------------------------------------------------


def test_minimal_roundtrip(cloudtrail_minimal: Path) -> None:
    reader = get_reader("cloudtrail")
    result = reader.read(
        input_path=cloudtrail_minimal,
        key_id="spk-ct-test-0001",
        strict=True,
    )
    assert isinstance(result, ReadResult)
    assert result.provider == "cloudtrail"
    assert result.schema_version == "1.09"
    assert result.record_count == 2

    payload = result.bundle_payload
    assert payload["metadata"]["provider"] == "cloudtrail"
    assert payload["metadata"]["record_count"] == 2
    assert payload["metadata"]["key_id"] == "spk-ct-test-0001"
    assert payload["metadata"]["content_hash"].startswith("sha256:")

    first, second = payload["records"]
    assert first["id"] == "ct-event-000001"
    assert first["model"]["name"] == "anthropic.claude-3-5-sonnet"
    assert first["model"]["version"] == "20240620-v1:0"
    assert first["decision"]["outcome"] == "approved"
    assert first["decision"]["formal_verdict"] == "valid"
    assert first["decision"]["proof_hash"].startswith("sha256:")
    assert first["decision"]["policy_refs"] == ["arp-abc123"]
    assert first["context"]["hash"].startswith("sha256:")
    assert first["upstream_signature"]["absent_per_record"] is True
    assert first["upstream_signature"]["integrity_mechanism"] == (
        "cloudtrail-log-file-validation"
    )
    assert first["aws_region"] == "us-east-1"
    assert first["upstream_event_name"] == "InvokeModelWithAutomatedReasoning"

    assert second["decision"]["outcome"] == "rejected"
    assert second["decision"]["formal_verdict"] == "invalid"


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
def test_deterministic_output(cloudtrail_minimal: Path, seed: int, key_id: str) -> None:
    """Same input → byte-identical canonical bundle across repeated reads."""
    del seed
    reader = get_reader("cloudtrail")
    a = reader.read(input_path=cloudtrail_minimal, key_id=key_id, strict=True)
    b = reader.read(input_path=cloudtrail_minimal, key_id=key_id, strict=True)
    assert canonical_json_bytes(a.bundle_payload) == canonical_json_bytes(b.bundle_payload)
    assert a.record_count == b.record_count == 2


# ---------------------------------------------------------------------------
# Category 3 — realistic-complex fixture
# ---------------------------------------------------------------------------


def test_realistic_complex(cloudtrail_complex: Path) -> None:
    reader = get_reader("cloudtrail")
    result = reader.read(
        input_path=cloudtrail_complex,
        key_id="spk-ct-test-0001",
        strict=False,
    )
    # 24 AR events mapped; 3 non-AR Bedrock + 2 non-Bedrock silently skipped.
    assert result.record_count == 24

    models = {r["model"]["name"] for r in result.bundle_payload["records"]}
    assert "anthropic.claude-3-5-sonnet" in models
    assert "amazon.titan-text-premier-v1:0" in models

    regions = {r["aws_region"] for r in result.bundle_payload["records"]}
    assert regions == {"us-east-1", "us-west-2", "eu-central-1"}

    outcomes = {r["decision"]["outcome"] for r in result.bundle_payload["records"]}
    assert outcomes == {"approved", "rejected", "deferred", "escalated"}

    for record in result.bundle_payload["records"]:
        assert record["context"]["hash"].startswith("sha256:")
        assert record["decision"]["proof_hash"].startswith("sha256:")
        assert record["upstream_signature"]["absent_per_record"] is True

    # Non-AR and non-Bedrock events should produce a single aggregated warning
    # in non-strict mode.
    assert any("non-AR" in w for w in result.warnings)


def test_ar_proof_payload_preserved(cloudtrail_complex: Path) -> None:
    """AR Checks constraints and verdict round-trip verbatim through the reader."""
    reader = get_reader("cloudtrail")
    result = reader.read(
        input_path=cloudtrail_complex,
        key_id="spk-ct-test-0001",
        strict=False,
    )
    for record in result.bundle_payload["records"]:
        decision = record["decision"]
        assert decision["formal_verdict"] in {"valid", "invalid", "unknown"}
        assert isinstance(decision["constraints"], list)
        assert all(isinstance(c, str) for c in decision["constraints"])
        assert len(decision["constraints"]) == 2


# ---------------------------------------------------------------------------
# Category 4 — malformed input graceful failure
# ---------------------------------------------------------------------------


def test_malformed_strict_fails(cloudtrail_malformed: Path) -> None:
    reader = get_reader("cloudtrail")
    with pytest.raises(ReaderError):
        reader.read(input_path=cloudtrail_malformed, key_id="k", strict=True)


def test_malformed_non_strict_recovers(cloudtrail_malformed: Path) -> None:
    reader = get_reader("cloudtrail")
    result = reader.read(input_path=cloudtrail_malformed, key_id="k", strict=False)
    assert result.record_count == 3
    assert len(result.warnings) == 2
    assert any("missing" in w or "proofHash" in w for w in result.warnings)


def test_missing_input_file_raises(tmp_path: Path) -> None:
    reader = get_reader("cloudtrail")
    with pytest.raises(ReaderError):
        reader.read(input_path=tmp_path / "does-not-exist.json", key_id="k")


def test_unknown_event_version_strict_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad-version.json"
    bad.write_text(
        json.dumps(
            {
                "Records": [
                    {
                        "eventVersion": "99.0",
                        "eventTime": "2026-06-10T14:22:00Z",
                        "eventSource": "bedrock.amazonaws.com",
                        "eventName": "InvokeModelWithAutomatedReasoning",
                        "awsRegion": "us-east-1",
                        "eventID": "ct-event-bad",
                        "requestParameters": {
                            "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
                            "automatedReasoningPolicyId": "arp-x",
                        },
                        "responseElements": {
                            "requestId": "req-x",
                            "modelInvocationResult": "approved",
                            "automatedReasoningResult": {
                                "verdict": "valid",
                                "proofHash": "sha256:" + "0" * 64,
                                "logicalConstraints": [],
                            },
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    reader = get_reader("cloudtrail")
    with pytest.raises(ReaderSchemaError):
        reader.read(input_path=bad, key_id="k", strict=True)


def test_non_bedrock_events_skipped_silently(tmp_path: Path) -> None:
    """Reader ignores non-Bedrock events — a mixed CloudTrail export is fine."""
    mixed = tmp_path / "mixed.json"
    mixed.write_text(
        json.dumps(
            {
                "Records": [
                    {
                        "eventVersion": "1.09",
                        "eventTime": "2026-06-10T14:22:00Z",
                        "eventSource": "sts.amazonaws.com",
                        "eventName": "AssumeRole",
                        "awsRegion": "us-east-1",
                        "eventID": "sts-1",
                        "requestParameters": {},
                        "responseElements": {},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    reader = get_reader("cloudtrail")
    result = reader.read(input_path=mixed, key_id="k", strict=True)
    assert result.record_count == 0
    assert result.warnings == ()


def test_empty_records_array_succeeds(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"Records": []}), encoding="utf-8")
    reader = get_reader("cloudtrail")
    result = reader.read(input_path=empty, key_id="k", strict=True)
    assert result.record_count == 0
    assert result.warnings == ()


def test_public_key_passed_surfaces_ignore_warning(
    cloudtrail_minimal: Path, tmp_path: Path
) -> None:
    """A user who passes --public-key must be told CloudTrail ignores it.

    Closes B01 CloudTrail session 1 IAP advisory finding #2 — rather than
    silently ignoring the flag, the reader records an explicit warning
    that CloudTrail has no per-event signatures and points to the log
    file validation mechanism.
    """
    fake_key = tmp_path / "unused.hex"
    fake_key.write_text("00" * 32 + "\n", encoding="utf-8")
    reader = get_reader("cloudtrail")
    result = reader.read(
        input_path=cloudtrail_minimal,
        key_id="spk-ct-pk-check",
        public_key_path=fake_key,
        strict=True,
    )
    assert result.record_count == 2
    assert any("--public-key" in w and "ignored" in w for w in result.warnings)
    assert any("log file validation" in w for w in result.warnings)


def test_reader_is_stateless(cloudtrail_minimal: Path) -> None:
    """Re-using a reader across calls must not leak state between invocations."""
    reader = CloudTrailReader()
    r1 = reader.read(input_path=cloudtrail_minimal, key_id="k")
    r2 = reader.read(input_path=cloudtrail_minimal, key_id="k")
    assert r1.record_count == r2.record_count == 2
    assert canonical_json_bytes(r1.bundle_payload) == canonical_json_bytes(r2.bundle_payload)


# ---------------------------------------------------------------------------
# JSON Schema validation (same validator pattern as test_wire_spec_schemas.py)
# ---------------------------------------------------------------------------


def test_bundle_payload_matches_reader_bundle_schema(cloudtrail_complex: Path) -> None:
    """Validate the reader output against a JSON Schema with jsonschema.

    Uses the same validator pattern as ``tests/test_wire_spec_schemas.py``
    — load schema, instantiate a draft-2020-12 validator, call
    ``.validate(payload)``. The schema is inline (see top of this file)
    because the canonical reader-bundle schema is deferred to EPIC-B02.
    """
    reader = get_reader("cloudtrail")
    result = reader.read(
        input_path=cloudtrail_complex,
        key_id="spk-ct-schema-check",
        strict=False,
    )
    validator = jsonschema.Draft202012Validator(_READER_BUNDLE_SCHEMA)
    errors = sorted(validator.iter_errors(result.bundle_payload), key=lambda e: e.path)
    assert errors == [], [
        f"{list(e.path)}: {e.message}" for e in errors
    ]


# ---------------------------------------------------------------------------
# Model ID splitting unit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model_id,expected_name,expected_version",
    [
        (
            "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "anthropic.claude-3-5-sonnet",
            "20240620-v1:0",
        ),
        ("amazon.titan-text-premier-v1:0", "amazon.titan-text-premier-v1:0", ""),
        ("cohere.command-r-20240301", "cohere.command-r", "20240301"),
        ("simple-model", "simple-model", ""),
    ],
)
def test_split_model_id(
    model_id: str, expected_name: str, expected_version: str
) -> None:
    name, version = _split_model_id(model_id)
    assert name == expected_name
    assert version == expected_version
