"""Executable conformance test for Specora Wire Spec v1.0 §8.4.

Loads every JSON Schema under ``docs/schemas/`` and validates every
corresponding canonical golden vector under ``vectors/``. This is the
CI gate that makes the wire spec non-aspirational — if any schema
fails to validate any shipped vector, the whole suite fails and a
commit is blocked.

Added by the 2026-04-15 A02 emergency remediation session alongside
``docs/wire-spec-v1.0.md`` v1.0.0.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "docs" / "schemas"
VECTORS_DIR = REPO_ROOT / "vectors"

SCHEMA_VECTOR_PAIRS: list[tuple[str, str]] = [
    (
        "attestation-manifest-v1.0.json",
        "manifest/attestation-manifest-1.0.0.canonical.json",
    ),
    (
        "proof-manifest-v1.0.json",
        "manifest/proof-manifest-1.0.0.canonical.json",
    ),
    (
        "anchor-payload-v1.0.json",
        "anchor/anchor-payload-1.0.0.canonical.json",
    ),
    (
        "anchor-receipt-v1.0.json",
        "anchor-receipts/anchor-receipt-1.0.0.canonical.json",
    ),
    (
        "certification-attestation-v1.0.json",
        "certification/certification-attestation-1.0.0.canonical.json",
    ),
    (
        "stp-certification-attestation-v1.0.json",
        "stp-certification/compatible/stp-certification-attestation-1.0.0.canonical.json",
    ),
    (
        "governance-attestation-v1.0.json",
        "signature/signed-artifact-001/artifact.canonical.json",
    ),
    (
        "signed-artifact-envelope-v1.0.json",
        "signature/signed-artifact-001/metadata.json",
    ),
    (
        "canonical-bundle-v1.0.json",
        "canonical-bundle/canonical-bundle-anthropic-1.0.0.canonical.json",
    ),
    (
        "canonical-bundle-v1.0.json",
        "canonical-bundle/canonical-bundle-cloudtrail-1.0.0.canonical.json",
    ),
]


def _load_schema(name: str) -> dict:
    path = SCHEMAS_DIR / name
    assert path.exists(), f"schema missing: {path}"
    data = json.loads(path.read_text())
    assert data.get("$schema", "").startswith(
        "https://json-schema.org/draft/"
    ), f"{name}: must declare a JSON Schema draft"
    return data


def _load_vector(rel: str) -> dict:
    path = VECTORS_DIR / rel
    assert path.exists(), f"vector missing: {path}"
    return json.loads(path.read_text())


@pytest.mark.parametrize("schema_name,vector_rel", SCHEMA_VECTOR_PAIRS)
def test_schema_validates_vector(schema_name: str, vector_rel: str) -> None:
    """Every shipped schema must validate its paired golden vector."""
    schema = _load_schema(schema_name)
    vector = _load_vector(vector_rel)
    jsonschema.validate(instance=vector, schema=schema)


def test_all_schemas_have_expected_metadata() -> None:
    """Every schema under docs/schemas/ must declare $schema, $id, title, description."""
    schema_files = sorted(SCHEMAS_DIR.glob("*.json"))
    referenced = {name for name, _ in SCHEMA_VECTOR_PAIRS}
    unreferenced = [p.name for p in schema_files if p.name not in referenced]
    assert not unreferenced, (
        "schema drift: every schema under docs/schemas/ must appear in at least one "
        f"SCHEMA_VECTOR_PAIRS entry. Unreferenced: {unreferenced}"
    )
    for path in schema_files:
        data = json.loads(path.read_text())
        for key in ("$schema", "$id", "title", "description"):
            assert data.get(key), f"{path.name}: missing '{key}'"


def test_schema_rejects_missing_required_field() -> None:
    """A required-field removal must be rejected by the matching schema.

    Regression guard: guarantees the test file is actually running
    jsonschema.validate (i.e., not silently passing on everything).
    """
    schema = _load_schema("attestation-manifest-v1.0.json")
    vector = _load_vector("manifest/attestation-manifest-1.0.0.canonical.json")
    del vector["snapshot_type"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=vector, schema=schema)


def test_schema_rejects_wrong_enum_value() -> None:
    """A wrong enum value must be rejected by the matching schema.

    Regression guard: guarantees enum constraints are live.
    """
    schema = _load_schema("anchor-payload-v1.0.json")
    vector = _load_vector("anchor/anchor-payload-1.0.0.canonical.json")
    vector["hash_algorithm"] = "md5"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=vector, schema=schema)
