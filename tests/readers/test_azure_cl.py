"""Tests for the Azure Confidential Ledger reader.

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
from specora_verify.readers.azure_cl import AzureConfidentialLedgerReader

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


def test_azure_cl_registered() -> None:
    assert "azure-cl" in READERS
    assert "azure-cl" in available_readers()
    reader = get_reader("azure-cl")
    assert reader.provider_name == "azure-cl"
    assert "1.0" in reader.supported_schema_versions


# ---------------------------------------------------------------------------
# Category 1 — minimal fixture roundtrip
# ---------------------------------------------------------------------------


def test_minimal_roundtrip(azure_cl_minimal: Path) -> None:
    reader = get_reader("azure-cl")
    result = reader.read(
        input_path=azure_cl_minimal,
        key_id="spk-azcl-test-0001",
        strict=True,
    )
    assert isinstance(result, ReadResult)
    assert result.provider == "azure-cl"
    assert result.schema_version == "1.0"
    assert result.record_count == 2

    payload = result.bundle_payload
    assert payload["metadata"]["provider"] == "azure-cl"
    assert payload["metadata"]["reader"] == "specora_verify.readers.azure_cl"
    assert payload["metadata"]["record_count"] == 2
    assert payload["metadata"]["key_id"] == "spk-azcl-test-0001"
    assert payload["metadata"]["content_hash"].startswith("sha256:")

    first, second = payload["records"]
    assert first["id"] == "azcl-rec-000001"
    assert first["upstream_tx_id"] == "2.101"
    assert first["model"]["name"] == "gpt-4o"
    assert first["decision"]["outcome"] == "approved"
    assert first["upstream_signature"]["absent_per_record"] is True
    assert first["upstream_signature"]["integrity_mechanism"] == (
        "azure-confidential-ledger-receipt"
    )
    # Inclusion proof preserved verbatim.
    proof = first["upstream_inclusion_proof"]
    assert "leafComponents" in proof
    assert isinstance(proof["nodeCerts"], list) and len(proof["nodeCerts"]) == 1
    assert isinstance(proof["proof"], list) and len(proof["proof"]) == 2
    assert proof["proof"][0].get("left")
    assert proof["proof"][1].get("right")
    assert proof["signature"]
    assert proof["serviceId"] == "specora-demo-ccf-service"
    # TEE attestation extracted as first-class evidence.
    tee = first["tee_attestation"]
    assert tee["enclaveQuote"]
    assert tee["mrenclave"] == "a" * 64
    assert tee["mrsigner"] == "b" * 64
    assert "reportData" in tee
    # Collection ID preserved at record level.
    assert first["upstream_collection_id"] == "subledger-ai-audit-2026"

    assert second["decision"]["outcome"] == "rejected"
    assert second["model"]["name"] == "claude-opus-4-6"


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
def test_deterministic_output(azure_cl_minimal: Path, seed: int, key_id: str) -> None:
    """Same input → byte-identical canonical bundle across repeated reads."""
    del seed
    reader = get_reader("azure-cl")
    a = reader.read(input_path=azure_cl_minimal, key_id=key_id, strict=True)
    b = reader.read(input_path=azure_cl_minimal, key_id=key_id, strict=True)
    assert canonical_json_bytes(a.bundle_payload) == canonical_json_bytes(b.bundle_payload)
    assert a.record_count == b.record_count == 2


# ---------------------------------------------------------------------------
# Category 3 — realistic-complex fixture
# ---------------------------------------------------------------------------


def test_realistic_complex(azure_cl_complex: Path) -> None:
    reader = get_reader("azure-cl")
    result = reader.read(
        input_path=azure_cl_complex,
        key_id="spk-azcl-test-0001",
        strict=False,
    )
    assert result.record_count == 18

    models = {r["model"]["name"] for r in result.bundle_payload["records"]}
    assert models == {"gpt-4o", "claude-opus-4-6", "phi-4"}

    outcomes = {r["decision"]["outcome"] for r in result.bundle_payload["records"]}
    assert outcomes == {"approved", "rejected", "deferred", "escalated"}

    # 12 records with TEE quotes, 6 without. A cross-collection warning
    # is emitted once the second collection ID is seen.
    tee_count = sum(1 for r in result.bundle_payload["records"] if "tee_attestation" in r)
    assert tee_count == 12
    for record in result.bundle_payload["records"]:
        assert record["upstream_inclusion_proof"]["signature"]
        assert record["upstream_signature"]["absent_per_record"] is True
    assert any("collectionId" in w for w in result.warnings)


def test_tee_attestation_extracted(azure_cl_complex: Path) -> None:
    """TEE enclave quote, mrenclave, mrsigner, reportData ride first-class."""
    reader = get_reader("azure-cl")
    result = reader.read(
        input_path=azure_cl_complex,
        key_id="spk-azcl-test-0001",
        strict=False,
    )
    for record in result.bundle_payload["records"]:
        if "tee_attestation" not in record:
            continue
        tee = record["tee_attestation"]
        assert isinstance(tee["enclaveQuote"], str) and tee["enclaveQuote"]
        assert len(tee["mrenclave"]) == 64
        assert len(tee["mrsigner"]) == 64
        assert tee["reportData"]


# ---------------------------------------------------------------------------
# Category 4 — malformed input graceful failure
# ---------------------------------------------------------------------------


def test_malformed_strict_fails(azure_cl_malformed: Path) -> None:
    reader = get_reader("azure-cl")
    with pytest.raises(ReaderError):
        reader.read(input_path=azure_cl_malformed, key_id="k", strict=True)


def test_malformed_non_strict_recovers(azure_cl_malformed: Path) -> None:
    reader = get_reader("azure-cl")
    result = reader.read(input_path=azure_cl_malformed, key_id="k", strict=False)
    assert result.record_count == 3
    assert len(result.warnings) == 2
    assert any("receipt" in w or "context_hash" in w for w in result.warnings)


def test_missing_input_file_raises(tmp_path: Path) -> None:
    reader = get_reader("azure-cl")
    with pytest.raises(ReaderError):
        reader.read(input_path=tmp_path / "does-not-exist.json", key_id="k")


def test_missing_receipt_strict_fails(tmp_path: Path) -> None:
    bad = tmp_path / "no-receipt.json"
    bad.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "collectionId": "c",
                        "transactionId": "2.1",
                        "contents": {
                            "record": {
                                "record_id": "r1",
                                "timestamp": "2026-06-11T09:00:00Z",
                                "model": "gpt-4o",
                                "model_version": "2024-08",
                                "decision": "approved",
                                "policy_refs": ["p1"],
                                "context_hash": "sha256:" + "0" * 64,
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReaderSchemaError):
        get_reader("azure-cl").read(input_path=bad, key_id="k", strict=True)


def test_empty_entries_array_succeeds(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"entries": []}), encoding="utf-8")
    result = get_reader("azure-cl").read(input_path=empty, key_id="k", strict=True)
    assert result.record_count == 0
    assert result.warnings == ()


def test_wrong_envelope_strict_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad-envelope.json"
    bad.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(ReaderSchemaError):
        get_reader("azure-cl").read(input_path=bad, key_id="k", strict=True)


def test_bare_single_entry_accepted(tmp_path: Path, azure_cl_minimal: Path) -> None:
    """A single-entry JSON object (no 'entries' wrapper) is accepted."""
    wrapped = json.loads(azure_cl_minimal.read_text(encoding="utf-8"))
    single = tmp_path / "single.json"
    single.write_text(json.dumps(wrapped["entries"][0]), encoding="utf-8")
    result = get_reader("azure-cl").read(input_path=single, key_id="k", strict=True)
    assert result.record_count == 1


def test_unsupported_schema_version_strict_fails(azure_cl_minimal: Path) -> None:
    with pytest.raises(ReaderSchemaError):
        get_reader("azure-cl").read(
            input_path=azure_cl_minimal,
            key_id="k",
            schema_version="99.9",
            strict=True,
        )


def test_public_key_passed_surfaces_ignore_warning(azure_cl_minimal: Path, tmp_path: Path) -> None:
    """Azure CL ignores --public-key and must surface that loudly.

    Same pattern as the CloudTrail session-1 advisory-finding fix.
    """
    fake_key = tmp_path / "unused.hex"
    fake_key.write_text("00" * 32 + "\n", encoding="utf-8")
    result = get_reader("azure-cl").read(
        input_path=azure_cl_minimal,
        key_id="spk-azcl-pk-check",
        public_key_path=fake_key,
        strict=True,
    )
    assert result.record_count == 2
    assert any("--public-key" in w and "ignored" in w for w in result.warnings)
    assert any("consortium-signed" in w or "ECDSA" in w for w in result.warnings)


def test_reader_is_stateless(azure_cl_minimal: Path) -> None:
    reader = AzureConfidentialLedgerReader()
    r1 = reader.read(input_path=azure_cl_minimal, key_id="k")
    r2 = reader.read(input_path=azure_cl_minimal, key_id="k")
    assert r1.record_count == r2.record_count == 2
    assert canonical_json_bytes(r1.bundle_payload) == canonical_json_bytes(r2.bundle_payload)


# ---------------------------------------------------------------------------
# Category 5 — canonical-bundle-v1.0 JSON Schema validation
# ---------------------------------------------------------------------------


def test_bundle_payload_matches_canonical_bundle_schema(
    azure_cl_complex: Path,
) -> None:
    """Validate Azure CL reader output against the canonical-bundle schema.

    The additive ``upstream_inclusion_proof``, ``tee_attestation``, and
    ``upstream_collection_id`` record fields must pass under the record
    ``additionalProperties: true`` policy of the EPIC-B02 schema.
    """
    result = get_reader("azure-cl").read(
        input_path=azure_cl_complex,
        key_id="spk-azcl-schema-check",
        strict=False,
    )
    validator = _canonical_bundle_validator()
    errors = sorted(validator.iter_errors(result.bundle_payload), key=lambda e: list(e.path))
    assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]
