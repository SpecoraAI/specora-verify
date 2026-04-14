"""Manifest contract registry.

Defines the manifest contracts (spec_id + schema_version + required fields)
matching the Specora Wire Spec v1.0 (https://spec.specora.ai/v1.0).

Each contract specifies:
- spec_id: Contract type identifier (e.g., "proof-manifest")
- schema_version: Semantic version (e.g., "1.0.0")
- required_fields: Tuple of field names that must be present
- hash_algorithm: Hash algorithm used (always "sha256")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


# Type validation patterns
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HEX_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ManifestContract:
    """Definition of a manifest contract.

    A contract specifies the structure and validation rules for a
    particular manifest type and version.
    """

    spec_id: str
    schema_version: str
    required_fields: tuple[str, ...]
    hash_algorithm: str = "sha256"

    def validate_required_fields(self, data: dict[str, Any]) -> list[str]:
        """Return list of missing required fields."""
        return [f for f in self.required_fields if f not in data]

    def get_field_validators(self) -> dict[str, tuple[str, re.Pattern[str] | None]]:
        """Return field validators based on spec_id.

        Returns dict mapping field name to (expected_type, pattern) tuple.
        Pattern is None for non-string types.
        """
        if self.spec_id == "proof-manifest":
            return {
                "id": ("uuid", UUID_PATTERN),
                "org_id": ("uuid", UUID_PATTERN),
                "root_type": ("enum:daily|monthly|window", None),
                "root_hash": ("hex64", HEX_HASH_PATTERN),
                "leaf_count": ("integer", None),
                "period_start": ("iso8601_utc", TIMESTAMP_PATTERN),
                "period_end": ("iso8601_utc", TIMESTAMP_PATTERN),
                "created_at": ("iso8601_utc", TIMESTAMP_PATTERN),
            }
        elif self.spec_id == "attestation-manifest":
            return {
                "id": ("uuid", UUID_PATTERN),
                "org_id": ("uuid", UUID_PATTERN),
                "snapshot_type": (
                    "enum:window|calibration|region|drift|anomaly",
                    None,
                ),
                "period_start": ("iso8601_utc", TIMESTAMP_PATTERN),
                "period_end": ("iso8601_utc", TIMESTAMP_PATTERN),
                "created_at": ("iso8601_utc", TIMESTAMP_PATTERN),
            }
        elif self.spec_id == "anchor-payload":
            return {
                "payload_schema_version": ("string", None),
                "root_hash": ("hex64", HEX_HASH_PATTERN),
                "root_type": ("enum:daily|hourly|monthly", None),
                "period_start": ("iso8601_utc", TIMESTAMP_PATTERN),
                "period_end": ("iso8601_utc", TIMESTAMP_PATTERN),
                "leaf_count": ("integer", None),
                "first_seq": ("integer_or_null", None),
                "last_seq": ("integer_or_null", None),
                "manifest_hash": ("hex64", HEX_HASH_PATTERN),
                "manifest_spec_id": ("string", None),
                "manifest_schema_version": ("string", None),
                "hash_algorithm": ("string", None),
                "hash_algorithm_version": ("string", None),
                "ledger_hash_algorithm": ("string", None),
                "ledger_hash_algorithm_version": ("string", None),
                "org_id": ("uuid", UUID_PATTERN),  # Optional but validated if present
            }
        elif self.spec_id == "anchor-receipt":
            return {
                "spec_id": ("string", None),
                "schema_version": ("string", None),
                "org_id": ("uuid", UUID_PATTERN),
                "anchor_backend": ("string", None),
                "payload_hash": ("hex64", HEX_HASH_PATTERN),
                "receipt_id": ("string", None),
                "receipt_timestamp": ("iso8601_utc", TIMESTAMP_PATTERN),
                "receipt_signature": ("string", None),
                "hash_algorithm": ("string", None),
                "hash_algorithm_version": ("string", None),
            }
        return {}


# Proof Manifest v1.0.0
PROOF_MANIFEST_V1 = ManifestContract(
    spec_id="proof-manifest",
    schema_version="1.0.0",
    required_fields=(
        "id",
        "org_id",
        "root_type",
        "root_hash",
        "leaf_count",
        "period_start",
        "period_end",
        "created_at",
    ),
)

# Attestation Manifest v1.0.0
ATTESTATION_MANIFEST_V1 = ManifestContract(
    spec_id="attestation-manifest",
    schema_version="1.0.0",
    required_fields=(
        "id",
        "org_id",
        "snapshot_type",
        "period_start",
        "period_end",
        "created_at",
    ),
)

# Anchor Payload v1.0.0
ANCHOR_PAYLOAD_V1 = ManifestContract(
    spec_id="anchor-payload",
    schema_version="1.0.0",
    required_fields=(
        "payload_schema_version",
        "root_hash",
        "root_type",
        "period_start",
        "period_end",
        "leaf_count",
        "first_seq",
        "last_seq",
        "manifest_hash",
        "manifest_spec_id",
        "manifest_schema_version",
        "hash_algorithm",
        "hash_algorithm_version",
        "ledger_hash_algorithm",
        "ledger_hash_algorithm_version",
    ),
)

# Anchor Receipt v1.0.0
ANCHOR_RECEIPT_V1 = ManifestContract(
    spec_id="anchor-receipt",
    schema_version="1.0.0",
    required_fields=(
        "spec_id",
        "schema_version",
        "org_id",
        "anchor_backend",
        "payload_hash",
        "receipt_id",
        "receipt_timestamp",
        "receipt_signature",
        "hash_algorithm",
        "hash_algorithm_version",
    ),
)

# Contract registry
_CONTRACTS: dict[tuple[str, str], ManifestContract] = {
    ("proof-manifest", "1.0.0"): PROOF_MANIFEST_V1,
    ("attestation-manifest", "1.0.0"): ATTESTATION_MANIFEST_V1,
    ("anchor-payload", "1.0.0"): ANCHOR_PAYLOAD_V1,
    ("anchor-receipt", "1.0.0"): ANCHOR_RECEIPT_V1,
}


def get_contract(spec_id: str, schema_version: str) -> ManifestContract:
    """Lookup contract by spec_id and version.

    Args:
        spec_id: Contract type identifier
        schema_version: Semantic version string

    Returns:
        ManifestContract instance

    Raises:
        KeyError: If contract not found
    """
    key = (spec_id, schema_version)
    if key not in _CONTRACTS:
        raise KeyError(f"Unknown manifest contract: {spec_id} v{schema_version}")
    return _CONTRACTS[key]


def list_contracts() -> list[tuple[str, str]]:
    """List all registered contracts as (spec_id, version) tuples."""
    return list(_CONTRACTS.keys())


def detect_spec_id(data: dict[str, Any]) -> str | None:
    """Attempt to detect spec_id from manifest data.

    Heuristic detection based on presence of distinguishing fields:
    - anchor-receipt: has spec_id="anchor-receipt" and receipt_signature
    - anchor-payload: has payload_schema_version and manifest_hash
    - proof-manifest: has root_type, root_hash, leaf_count (but not payload_schema_version)
    - attestation-manifest: has snapshot_type

    Args:
        data: Manifest dictionary

    Returns:
        Detected spec_id or None if ambiguous
    """
    # Anchor receipt has spec_id field set to "anchor-receipt"
    if data.get("spec_id") == "anchor-receipt" or (
        "receipt_signature" in data and "payload_hash" in data
    ):
        return "anchor-receipt"
    # Anchor payload has payload_schema_version (not manifest_spec_id at top level)
    if "payload_schema_version" in data and "manifest_hash" in data:
        return "anchor-payload"
    if "root_type" in data and "root_hash" in data and "leaf_count" in data:
        return "proof-manifest"
    if "snapshot_type" in data:
        return "attestation-manifest"
    return None
