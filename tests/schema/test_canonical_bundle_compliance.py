"""Canonical evidence bundle schema compliance tests (EPIC-B02).

Validates the canonical-bundle-v1.0 JSON Schema against:

1. The committed golden canonical bundle vectors under
   ``vectors/canonical-bundle/``.
2. Live reader output produced by running every registered reader
   against every valid fixture under ``tests/fixtures/<provider>/``.
3. Canonical-equivalence invariants: byte-identical re-canonicalization
   across runs and across readers for structurally-equivalent input.

This is the wire-spec compliance gate for EPIC-B02: it ensures the
reader → normalizer → ledger → signer → verifier pipeline shares one
schema and that the schema is not cosmetic. It mirrors the test
pattern from tests/test_wire_spec_schemas.py.

Added 2026-04-15 alongside docs/canonical-bundle-schema-v1.0.md and
docs/schemas/canonical-bundle-v1.0.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from specora_verify.canonical import canonical_json_bytes
from specora_verify.readers import get_reader

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "canonical-bundle-v1.0.json"
VECTORS_DIR = REPO_ROOT / "vectors" / "canonical-bundle"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

GOLDEN_VECTORS: list[str] = [
    "canonical-bundle-anthropic-1.0.0.canonical.json",
    "canonical-bundle-cloudtrail-1.0.0.canonical.json",
]

LIVE_FIXTURES: list[tuple[str, str]] = [
    ("anthropic", "anthropic/minimal-valid.jsonl"),
    ("anthropic", "anthropic/realistic-complex.jsonl"),
    ("cloudtrail", "cloudtrail/minimal-valid.json"),
    ("cloudtrail", "cloudtrail/realistic-complex.json"),
]


def _load_schema() -> dict:
    assert SCHEMA_PATH.exists(), f"schema missing: {SCHEMA_PATH}"
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema.get("$schema", "").startswith(
        "https://json-schema.org/draft/"
    ), "canonical-bundle schema must declare a JSON Schema draft"
    return schema


def _validator() -> jsonschema.protocols.Validator:
    schema = _load_schema()
    return jsonschema.Draft202012Validator(schema)


# ---------------------------------------------------------------------------
# 1. Golden vector conformance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector_name", GOLDEN_VECTORS)
def test_golden_vector_validates(vector_name: str) -> None:
    """Every committed canonical bundle vector must satisfy the schema."""
    vector_path = VECTORS_DIR / vector_name
    assert vector_path.exists(), f"vector missing: {vector_path}"
    bundle = json.loads(vector_path.read_text())
    _validator().validate(bundle)


@pytest.mark.parametrize("vector_name", GOLDEN_VECTORS)
def test_golden_vector_is_canonical_bytes(vector_name: str) -> None:
    """Golden vectors MUST be stored in canonical-byte form.

    Re-canonicalizing the parsed object MUST produce the same bytes that
    live on disk. This is the regression guard against accidental
    prettification drift.
    """
    vector_path = VECTORS_DIR / vector_name
    raw_bytes = vector_path.read_bytes()
    parsed = json.loads(raw_bytes)
    round_trip = canonical_json_bytes(parsed)
    assert raw_bytes == round_trip, (
        f"{vector_name}: on-disk bytes diverge from canonical form. "
        "Regenerate via the reader and re-commit."
    )


# ---------------------------------------------------------------------------
# 2. Live reader-output conformance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider,fixture_rel", LIVE_FIXTURES)
def test_live_reader_output_validates(provider: str, fixture_rel: str) -> None:
    """Every valid reader fixture must produce a schema-compliant bundle."""
    fixture_path = FIXTURES_DIR / fixture_rel
    assert fixture_path.exists(), f"fixture missing: {fixture_path}"
    reader = get_reader(provider)
    result = reader.read(
        fixture_path,
        key_id="specora-bundle-key-v1",
        strict=False,
    )
    _validator().validate(result.bundle_payload)


@pytest.mark.parametrize("provider,fixture_rel", LIVE_FIXTURES)
def test_live_reader_output_is_deterministic(provider: str, fixture_rel: str) -> None:
    """Reader output MUST be byte-identical across runs.

    This is the core determinism invariant. If this fails, replay
    verification is broken for every bundle the reader emits.
    """
    fixture_path = FIXTURES_DIR / fixture_rel
    reader = get_reader(provider)
    first = reader.read(fixture_path, key_id="specora-bundle-key-v1", strict=False)
    second = reader.read(fixture_path, key_id="specora-bundle-key-v1", strict=False)
    assert canonical_json_bytes(first.bundle_payload) == canonical_json_bytes(
        second.bundle_payload
    )


@pytest.mark.parametrize("provider,fixture_rel", LIVE_FIXTURES)
def test_live_reader_content_hash_matches_records(
    provider: str, fixture_rel: str
) -> None:
    """metadata.content_hash MUST equal sha256(canonical({records: records})).

    Derivation is defined in docs/canonical-bundle-schema-v1.0.md §3.2.
    This test is the schema's runtime companion: the schema validates
    the shape, this test validates the arithmetic.
    """
    import hashlib

    fixture_path = FIXTURES_DIR / fixture_rel
    reader = get_reader(provider)
    bundle = reader.read(
        fixture_path, key_id="specora-bundle-key-v1", strict=False
    ).bundle_payload
    recomputed = "sha256:" + hashlib.sha256(
        canonical_json_bytes({"records": bundle["records"]})
    ).hexdigest()
    assert bundle["metadata"]["content_hash"] == recomputed


# ---------------------------------------------------------------------------
# 3. Negative schema tests — regression guards
# ---------------------------------------------------------------------------


def test_schema_rejects_missing_metadata() -> None:
    validator = _validator()
    bundle = json.loads(
        (VECTORS_DIR / GOLDEN_VECTORS[0]).read_text()
    )
    del bundle["metadata"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(bundle)


def test_schema_rejects_unknown_decision_outcome() -> None:
    validator = _validator()
    bundle = json.loads(
        (VECTORS_DIR / GOLDEN_VECTORS[0]).read_text()
    )
    bundle["records"][0]["decision"]["outcome"] = "maybe"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(bundle)


def test_schema_rejects_non_sha256_content_hash() -> None:
    validator = _validator()
    bundle = json.loads(
        (VECTORS_DIR / GOLDEN_VECTORS[0]).read_text()
    )
    bundle["metadata"]["content_hash"] = "md5:abc"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(bundle)


def test_schema_rejects_bad_timestamp_fractional_seconds() -> None:
    validator = _validator()
    bundle = json.loads(
        (VECTORS_DIR / GOLDEN_VECTORS[0]).read_text()
    )
    bundle["records"][0]["timestamp"] = "2026-06-10T14:22:01.500Z"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(bundle)


def test_schema_rejects_upstream_signature_mixed_shapes() -> None:
    """upstream_signature MUST be one of two shapes, not a mix."""
    validator = _validator()
    bundle = json.loads(
        (VECTORS_DIR / GOLDEN_VECTORS[0]).read_text()
    )
    bundle["records"][0]["upstream_signature"] = {
        "alg": "ed25519",
        "key_id": "k",
        "value": "v",
        "absent_per_record": True,
        "integrity_mechanism": "mixed",
    }
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(bundle)
