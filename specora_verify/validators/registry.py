"""Witness registry snapshot validation (PR-ENT-560).

This module provides registry snapshot verification enabling independent
verification of witness trust roots with tamper-evident history.

Registry Snapshots:
    Immutable, signed, hash-chained captures of witness registry state.
    Each snapshot references the previous via `previous_registry_hash`.

Invariants:
    - INV-REG-001: Snapshot signature binding - signature verifies against registry key
    - INV-REG-002: Snapshot hash chaining - previous_registry_hash links to prior snapshot
    - INV-REG-003: Revocation monotonicity - revoked witnesses/keys cannot become active
    - INV-REG-004: Key ID derivation consistency - key IDs match fingerprints
    - INV-REG-005: Deterministic canonicalization - registry_hash is reproducible
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, cast

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import VerificationError

# Error codes
ERR_SNAPSHOT_PARSE = "REGISTRY_SNAPSHOT_PARSE_ERROR"
ERR_SNAPSHOT_SCHEMA = "REGISTRY_SNAPSHOT_SCHEMA_ERROR"
ERR_SNAPSHOT_HASH = "REGISTRY_SNAPSHOT_HASH_MISMATCH"
ERR_SNAPSHOT_SIGNATURE = "REGISTRY_SNAPSHOT_SIGNATURE_INVALID"
ERR_CHAIN_BROKEN = "REGISTRY_CHAIN_BROKEN"
ERR_REVOCATION_VIOLATION = "REGISTRY_REVOCATION_VIOLATION"

# Validation patterns
HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REGISTRY_KEY_ID_PATTERN = re.compile(r"^rpk-[0-9a-f]{16}$")
WITNESS_KEY_ID_PATTERN = re.compile(r"^wpk-[0-9a-f]{16}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Valid values
VALID_WITNESS_STATUSES = {"active", "suspended", "revoked"}
VALID_KEY_STATUSES = {"active", "retired", "revoked"}
VALID_TRUST_LEVELS = {"internal", "external", "partner"}

# Genesis hash (all zeros)
GENESIS_HASH = "0" * 64

# Required snapshot fields
SNAPSHOT_REQUIRED_FIELDS = {
    "spec_id",
    "schema_version",
    "registry_version",
    "generated_at",
    "previous_registry_hash",
    "registry_authority",
    "witnesses",
    "registry_hash",
    "registry_key_id",
    "registry_signature",
}


class RegistryVerificationStatus(Enum):
    """Result status of registry verification."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class RegistryKey:
    """A signing key for a witness organization."""

    public_key_id: str
    public_key: str  # base64-encoded 32-byte Ed25519 key
    status: str
    created_at: str
    revoked_at: str | None = None
    revocation_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "public_key_id": self.public_key_id,
            "public_key": self.public_key,
            "status": self.status,
            "created_at": self.created_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }


@dataclass
class RegistryWitness:
    """A witness organization in the registry snapshot."""

    witness_org_id: str
    org_name: str
    trust_level: str
    status: str
    registered_at: str
    keys: list[RegistryKey] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "witness_org_id": self.witness_org_id,
            "org_name": self.org_name,
            "trust_level": self.trust_level,
            "status": self.status,
            "registered_at": self.registered_at,
            "keys": [k.to_dict() for k in self.keys],
        }


@dataclass
class RegistrySnapshot:
    """A witness registry snapshot."""

    spec_id: str
    schema_version: str
    registry_version: int
    generated_at: str
    previous_registry_hash: str
    registry_authority: str
    witnesses: list[RegistryWitness]
    registry_hash: str
    registry_key_id: str
    registry_signature: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "spec_id": self.spec_id,
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "generated_at": self.generated_at,
            "previous_registry_hash": self.previous_registry_hash,
            "registry_authority": self.registry_authority,
            "witnesses": [w.to_dict() for w in self.witnesses],
            "registry_hash": self.registry_hash,
            "registry_key_id": self.registry_key_id,
            "registry_signature": self.registry_signature,
        }

    def is_genesis(self) -> bool:
        """Check if this is a genesis snapshot."""
        return self.previous_registry_hash == GENESIS_HASH

    def get_witness(self, witness_org_id: str) -> RegistryWitness | None:
        """Look up a witness by org ID."""
        for witness in self.witnesses:
            if witness.witness_org_id == witness_org_id:
                return witness
        return None

    def get_key(self, public_key_id: str) -> tuple[RegistryWitness, RegistryKey] | None:
        """Look up a key by key ID. Returns (witness, key) or None."""
        for witness in self.witnesses:
            for key in witness.keys:
                if key.public_key_id == public_key_id:
                    return (witness, key)
        return None


@dataclass
class SnapshotVerificationResult:
    """Result of verifying a single registry snapshot."""

    valid: bool = False
    registry_version: int | None = None
    registry_hash: str | None = None
    previous_registry_hash: str | None = None
    generated_at: str | None = None
    signature_valid: bool = False
    hash_valid: bool = False
    is_genesis: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "valid": self.valid,
            "registry_version": self.registry_version,
            "registry_hash": self.registry_hash,
            "previous_registry_hash": self.previous_registry_hash,
            "generated_at": self.generated_at,
            "signature_valid": self.signature_valid,
            "hash_valid": self.hash_valid,
            "is_genesis": self.is_genesis,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class ChainVerificationResult:
    """Result of verifying a registry snapshot chain."""

    status: RegistryVerificationStatus
    chain_length: int = 0
    chain_valid: bool = False
    latest_version: int | None = None
    latest_hash: str | None = None
    revocation_violations: list[str] = field(default_factory=list)
    snapshot_results: dict[int, SnapshotVerificationResult] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Check if chain is valid."""
        return self.status in (RegistryVerificationStatus.PASS, RegistryVerificationStatus.WARN)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "valid": self.valid,
            "chain_length": self.chain_length,
            "chain_valid": self.chain_valid,
            "latest_version": self.latest_version,
            "latest_hash": self.latest_hash,
            "revocation_violations": self.revocation_violations,
            "snapshot_results": {str(v): r.to_dict() for v, r in self.snapshot_results.items()},
            "errors": self.errors,
            "warnings": self.warnings,
        }


def get_exit_code(status: RegistryVerificationStatus) -> int:
    """Map verification status to CLI exit code."""
    return {
        RegistryVerificationStatus.PASS: 0,
        RegistryVerificationStatus.WARN: 1,
        RegistryVerificationStatus.FAIL: 2,
        RegistryVerificationStatus.ERROR: 3,
    }[status]


# =============================================================================
# Key ID Derivation
# =============================================================================


def derive_registry_key_id(public_key_bytes: bytes) -> str:
    """Derive registry key ID from public key bytes.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key

    Returns:
        Key ID in format rpk-<16 hex chars>
    """
    fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
    return f"rpk-{fingerprint[:16]}"


def derive_witness_key_id(public_key_bytes: bytes) -> str:
    """Derive witness key ID from public key bytes.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key

    Returns:
        Key ID in format wpk-<16 hex chars>
    """
    fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
    return f"wpk-{fingerprint[:16]}"


# =============================================================================
# Hash Computation
# =============================================================================


def compute_registry_hash(snapshot: dict[str, Any]) -> str:
    """Compute SHA-256 hash of registry snapshot content.

    The hash is computed over the canonical JSON of the snapshot
    excluding the registry_hash and registry_signature fields.

    Args:
        snapshot: Registry snapshot dict

    Returns:
        SHA-256 hash as lowercase hex string
    """
    to_hash = {
        k: v for k, v in snapshot.items() if k not in ("registry_hash", "registry_signature")
    }
    canonical_bytes = canonical_json_bytes(to_hash)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_snapshot_signing_bytes(snapshot: dict[str, Any]) -> bytes:
    """Compute bytes to sign for registry snapshot.

    Consistent with existing signing convention: sign the SHA-256 hash
    hex string as UTF-8 bytes.

    Args:
        snapshot: Registry snapshot dict

    Returns:
        UTF-8 bytes of the hash hex string to sign
    """
    registry_hash = compute_registry_hash(snapshot)
    return registry_hash.encode("utf-8")


# =============================================================================
# Snapshot Parsing
# =============================================================================


def parse_registry_snapshot(data: dict[str, Any]) -> RegistrySnapshot:
    """Parse and validate a registry snapshot from a dictionary.

    Args:
        data: Raw snapshot dictionary

    Returns:
        Parsed RegistrySnapshot

    Raises:
        VerificationError: If schema validation fails
    """
    # Check required fields
    missing = SNAPSHOT_REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Missing required fields: {', '.join(sorted(missing))}",
        )

    # Validate spec_id
    if data["spec_id"] != "witness-registry-snapshot":
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Invalid spec_id: {data['spec_id']} (expected witness-registry-snapshot)",
        )

    # Validate schema_version
    if data["schema_version"] != "1.0.0":
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Unsupported schema_version: {data['schema_version']}",
        )

    # Validate registry_version
    version = data["registry_version"]
    if not isinstance(version, int) or version < 1:
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Invalid registry_version: {version} (must be integer >= 1)",
        )

    # Validate generated_at
    generated_at = data["generated_at"]
    if not isinstance(generated_at, str) or not TIMESTAMP_PATTERN.match(generated_at):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Invalid generated_at format: {generated_at}",
        )

    # Validate previous_registry_hash
    prev_hash = data["previous_registry_hash"]
    if not isinstance(prev_hash, str) or not HEX64_PATTERN.match(prev_hash):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Invalid previous_registry_hash format: {prev_hash}",
        )

    # Validate registry_authority
    authority = data["registry_authority"]
    if not isinstance(authority, str) or not authority.strip():
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            "Invalid registry_authority: must be non-empty string",
        )

    # Validate registry_hash
    registry_hash = data["registry_hash"]
    if not isinstance(registry_hash, str) or not HEX64_PATTERN.match(registry_hash):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Invalid registry_hash format: {registry_hash}",
        )

    # Validate registry_key_id
    registry_key_id = data["registry_key_id"]
    if not isinstance(registry_key_id, str) or not REGISTRY_KEY_ID_PATTERN.match(registry_key_id):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Invalid registry_key_id format: {registry_key_id}",
        )

    # Validate registry_signature
    registry_signature = data["registry_signature"]
    if not isinstance(registry_signature, str):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            "Invalid registry_signature: must be string",
        )
    try:
        sig_bytes = base64.b64decode(registry_signature)
        if len(sig_bytes) != 64:
            raise VerificationError(
                ERR_SNAPSHOT_SCHEMA,
                f"Invalid registry_signature: must be 64 bytes, got {len(sig_bytes)}",
            )
    except Exception as e:
        if isinstance(e, VerificationError):
            raise
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"Invalid registry_signature base64: {e}",
        ) from e

    # Parse witnesses
    witnesses_data = data["witnesses"]
    if not isinstance(witnesses_data, list):
        raise VerificationError(ERR_SNAPSHOT_SCHEMA, "witnesses must be an array")

    witnesses: list[RegistryWitness] = []
    seen_org_ids: set[str] = set()

    for i, w_data in enumerate(witnesses_data):
        witness = _parse_registry_witness(w_data, i)
        if witness.witness_org_id in seen_org_ids:
            raise VerificationError(
                ERR_SNAPSHOT_SCHEMA,
                f"witnesses[{i}].witness_org_id duplicate: {witness.witness_org_id}",
            )
        seen_org_ids.add(witness.witness_org_id)
        witnesses.append(witness)

    return RegistrySnapshot(
        spec_id=data["spec_id"],
        schema_version=data["schema_version"],
        registry_version=version,
        generated_at=generated_at,
        previous_registry_hash=prev_hash,
        registry_authority=authority,
        witnesses=witnesses,
        registry_hash=registry_hash,
        registry_key_id=registry_key_id,
        registry_signature=registry_signature,
    )


def _parse_registry_witness(data: dict[str, Any], index: int) -> RegistryWitness:
    """Parse a witness entry from snapshot."""
    if not isinstance(data, dict):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"witnesses[{index}] must be an object",
        )

    required_fields = [
        "witness_org_id",
        "org_name",
        "trust_level",
        "status",
        "registered_at",
        "keys",
    ]
    for field_name in required_fields:
        if field_name not in data:
            raise VerificationError(
                ERR_SNAPSHOT_SCHEMA,
                f"witnesses[{index}] missing required field: {field_name}",
            )

    # Validate witness_org_id
    witness_org_id = data["witness_org_id"]
    if not isinstance(witness_org_id, str) or not witness_org_id.strip():
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"witnesses[{index}].witness_org_id must be non-empty string",
        )

    # Validate org_name
    org_name = data["org_name"]
    if not isinstance(org_name, str) or not org_name.strip():
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"witnesses[{index}].org_name must be non-empty string",
        )

    # Validate trust_level
    trust_level = data["trust_level"]
    if trust_level not in VALID_TRUST_LEVELS:
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"witnesses[{index}].trust_level invalid: {trust_level}",
        )

    # Validate status
    status = data["status"]
    if status not in VALID_WITNESS_STATUSES:
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"witnesses[{index}].status invalid: {status}",
        )

    # Validate registered_at
    registered_at = data["registered_at"]
    if not isinstance(registered_at, str) or not TIMESTAMP_PATTERN.match(registered_at):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"witnesses[{index}].registered_at invalid format: {registered_at}",
        )

    # Parse keys
    keys_data = data["keys"]
    if not isinstance(keys_data, list):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"witnesses[{index}].keys must be an array",
        )

    keys: list[RegistryKey] = []
    seen_key_ids: set[str] = set()

    for j, k_data in enumerate(keys_data):
        key = _parse_registry_key(k_data, index, j)
        if key.public_key_id in seen_key_ids:
            raise VerificationError(
                ERR_SNAPSHOT_SCHEMA,
                f"witnesses[{index}].keys[{j}].public_key_id duplicate: {key.public_key_id}",
            )
        seen_key_ids.add(key.public_key_id)
        keys.append(key)

    return RegistryWitness(
        witness_org_id=witness_org_id,
        org_name=org_name,
        trust_level=trust_level,
        status=status,
        registered_at=registered_at,
        keys=keys,
    )


def _parse_registry_key(data: dict[str, Any], witness_index: int, key_index: int) -> RegistryKey:
    """Parse a key entry from witness."""
    prefix = f"witnesses[{witness_index}].keys[{key_index}]"

    if not isinstance(data, dict):
        raise VerificationError(ERR_SNAPSHOT_SCHEMA, f"{prefix} must be an object")

    required_fields = ["public_key_id", "public_key", "status", "created_at"]
    for field_name in required_fields:
        if field_name not in data:
            raise VerificationError(
                ERR_SNAPSHOT_SCHEMA,
                f"{prefix} missing required field: {field_name}",
            )

    # Validate public_key_id format
    public_key_id = data["public_key_id"]
    if not isinstance(public_key_id, str) or not WITNESS_KEY_ID_PATTERN.match(public_key_id):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"{prefix}.public_key_id invalid format: {public_key_id}",
        )

    # Validate public_key (base64-encoded 32 bytes)
    public_key = data["public_key"]
    if not isinstance(public_key, str):
        raise VerificationError(ERR_SNAPSHOT_SCHEMA, f"{prefix}.public_key must be string")

    try:
        key_bytes = base64.b64decode(public_key)
        if len(key_bytes) != 32:
            raise VerificationError(
                ERR_SNAPSHOT_SCHEMA,
                f"{prefix}.public_key must be 32 bytes, got {len(key_bytes)}",
            )
    except Exception as e:
        if isinstance(e, VerificationError):
            raise
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"{prefix}.public_key invalid base64: {e}",
        ) from e

    # Validate key ID derivation (INV-REG-004)
    expected_key_id = derive_witness_key_id(key_bytes)
    if public_key_id != expected_key_id:
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"{prefix}.public_key_id mismatch (INV-REG-004): "
            f"{public_key_id} vs expected {expected_key_id}",
        )

    # Validate status
    status = data["status"]
    if status not in VALID_KEY_STATUSES:
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"{prefix}.status invalid: {status}",
        )

    # Validate created_at
    created_at = data["created_at"]
    if not isinstance(created_at, str) or not TIMESTAMP_PATTERN.match(created_at):
        raise VerificationError(
            ERR_SNAPSHOT_SCHEMA,
            f"{prefix}.created_at invalid format: {created_at}",
        )

    # Validate optional revoked_at
    revoked_at = data.get("revoked_at")
    if revoked_at is not None:
        if not isinstance(revoked_at, str) or not TIMESTAMP_PATTERN.match(revoked_at):
            raise VerificationError(
                ERR_SNAPSHOT_SCHEMA,
                f"{prefix}.revoked_at invalid format: {revoked_at}",
            )

    return RegistryKey(
        public_key_id=public_key_id,
        public_key=public_key,
        status=status,
        created_at=created_at,
        revoked_at=revoked_at,
        revocation_reason=data.get("revocation_reason"),
    )


def load_registry_snapshot(path: Path | str) -> RegistrySnapshot:
    """Load and parse a registry snapshot from a file.

    Args:
        path: Path to JSON file

    Returns:
        Parsed RegistrySnapshot

    Raises:
        VerificationError: If file not found or parse fails
    """
    path = Path(path)
    if not path.exists():
        raise VerificationError(ERR_SNAPSHOT_PARSE, f"File not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise VerificationError(ERR_SNAPSHOT_PARSE, f"Invalid JSON: {e}") from e

    return parse_registry_snapshot(data)


# =============================================================================
# Snapshot Verification
# =============================================================================


def validate_registry_snapshot(
    snapshot: dict[str, Any] | RegistrySnapshot,
    public_key: str | None = None,
    key_format: str = "pem",
    skip_signature: bool = False,
) -> SnapshotVerificationResult:
    """Validate a registry snapshot structure and signature.

    Checks:
    1. Required fields present with correct types
    2. registry_hash matches computed hash (INV-REG-005)
    3. registry_signature verifies against public key (INV-REG-001)
    4. Key ID derivations are correct (INV-REG-004)

    Args:
        snapshot: Registry snapshot dict or parsed RegistrySnapshot
        public_key: Public key for signature verification (PEM or base64)
        key_format: Key format ("pem" or "base64")
        skip_signature: Skip signature verification

    Returns:
        SnapshotVerificationResult with validation details
    """
    errors: list[str] = []
    warnings: list[str] = []
    result = SnapshotVerificationResult()

    # Parse if needed
    if isinstance(snapshot, dict):
        try:
            parsed = parse_registry_snapshot(snapshot)
            snapshot_dict = snapshot
        except VerificationError as e:
            result.errors = [str(e)]
            return result
    else:
        parsed = snapshot
        snapshot_dict = parsed.to_dict()

    result.registry_version = parsed.registry_version
    result.registry_hash = parsed.registry_hash
    result.previous_registry_hash = parsed.previous_registry_hash
    result.generated_at = parsed.generated_at
    result.is_genesis = parsed.is_genesis()

    # Verify registry_hash (INV-REG-005)
    computed_hash = compute_registry_hash(snapshot_dict)
    if computed_hash != parsed.registry_hash:
        errors.append(
            f"Hash mismatch (INV-REG-005): computed {computed_hash[:16]}... "
            f"vs stated {parsed.registry_hash[:16]}..."
        )
    else:
        result.hash_valid = True

    # Verify signature (INV-REG-001)
    if not skip_signature:
        if not public_key:
            warnings.append("No public key provided - signature verification skipped")
        else:
            try:
                from specora_verify.signature import is_crypto_available, verify_signature

                if not is_crypto_available():
                    warnings.append(
                        "cryptography package not available - signature verification skipped"
                    )
                else:
                    # Verify signature over the registry_hash hex string
                    sig_result = verify_signature(
                        manifest_hash=parsed.registry_hash,
                        signature_b64=parsed.registry_signature,
                        public_key=public_key,
                        key_format=key_format,
                    )

                    if sig_result.valid:
                        result.signature_valid = True
                    else:
                        errors.append(
                            f"Signature verification failed (INV-REG-001): "
                            f"{'; '.join(sig_result.errors)}"
                        )
            except Exception as e:
                errors.append(f"Signature verification error: {e}")
    else:
        warnings.append("Signature verification skipped by request")

    result.errors = errors
    result.warnings = warnings
    result.valid = len(errors) == 0

    return result


# =============================================================================
# Revocation Monotonicity (INV-REG-003)
# =============================================================================


def enforce_revocation_monotonicity(
    previous: RegistrySnapshot | None,
    current: RegistrySnapshot,
) -> list[str]:
    """Check revocation monotonicity between snapshots.

    INV-REG-003: Once revoked, witnesses/keys cannot become active.

    Args:
        previous: Previous snapshot (None for genesis)
        current: Current snapshot being validated

    Returns:
        List of violation messages (empty if valid)
    """
    if not previous:
        return []

    violations: list[str] = []

    # Build lookup for previous state
    prev_witnesses: dict[str, RegistryWitness] = {w.witness_org_id: w for w in previous.witnesses}

    for witness in current.witnesses:
        prev_w = prev_witnesses.get(witness.witness_org_id)
        if not prev_w:
            continue

        # Check witness status
        if prev_w.status == "revoked" and witness.status != "revoked":
            violations.append(
                f"Witness {witness.witness_org_id} was revoked, "
                f"cannot become {witness.status} (INV-REG-003)"
            )

        # Check key statuses
        prev_keys: dict[str, RegistryKey] = {k.public_key_id: k for k in prev_w.keys}

        for key in witness.keys:
            prev_k = prev_keys.get(key.public_key_id)
            if prev_k and prev_k.status == "revoked" and key.status != "revoked":
                violations.append(
                    f"Key {key.public_key_id} was revoked, cannot become {key.status} (INV-REG-003)"
                )

    return violations


# =============================================================================
# Chain Verification
# =============================================================================


def verify_registry_chain(
    snapshots: list[RegistrySnapshot] | list[dict[str, Any]],
    public_key: str | None = None,
    key_format: str = "pem",
    skip_signature: bool = False,
) -> ChainVerificationResult:
    """Verify a chain of registry snapshots.

    Checks:
    1. Each snapshot is individually valid
    2. previous_registry_hash links correctly (INV-REG-002)
    3. registry_version is monotonically increasing
    4. Revocation monotonicity is preserved (INV-REG-003)
    5. First snapshot is a valid genesis

    Args:
        snapshots: List of snapshots (dicts or parsed), any order
        public_key: Public key for signature verification
        key_format: Key format ("pem" or "base64")
        skip_signature: Skip signature verification

    Returns:
        ChainVerificationResult with chain and per-snapshot details
    """
    errors: list[str] = []
    warnings: list[str] = []
    snapshot_results: dict[int, SnapshotVerificationResult] = {}
    revocation_violations: list[str] = []

    if not snapshots:
        return ChainVerificationResult(
            status=RegistryVerificationStatus.ERROR,
            errors=["No snapshots provided"],
        )

    # Parse all snapshots
    parsed_snapshots: list[RegistrySnapshot] = []
    for i, snapshot in enumerate(snapshots):
        if isinstance(snapshot, dict):
            try:
                parsed = parse_registry_snapshot(snapshot)
                parsed_snapshots.append(parsed)
            except VerificationError as e:
                errors.append(f"Snapshot {i}: {e}")
                return ChainVerificationResult(
                    status=RegistryVerificationStatus.ERROR,
                    errors=errors,
                )
        else:
            # Per the param type (list[RegistrySnapshot] | list[dict]), a
            # non-dict element is already a parsed RegistrySnapshot.
            parsed_snapshots.append(cast("RegistrySnapshot", snapshot))

    # Sort by registry_version
    parsed_snapshots.sort(key=lambda s: s.registry_version)

    # Validate each snapshot and check chain links
    prev_snapshot: RegistrySnapshot | None = None
    chain_valid = True

    for snapshot in parsed_snapshots:
        # Validate snapshot
        result = validate_registry_snapshot(
            snapshot,
            public_key=public_key,
            key_format=key_format,
            skip_signature=skip_signature,
        )
        snapshot_results[snapshot.registry_version] = result

        if not result.valid:
            chain_valid = False

        # Check genesis
        if prev_snapshot is None:
            if not snapshot.is_genesis():
                errors.append(
                    f"First snapshot (v{snapshot.registry_version}) must be genesis "
                    f"(previous_registry_hash must be all zeros) (INV-REG-002)"
                )
                chain_valid = False
        else:
            # Check hash chain (INV-REG-002)
            if snapshot.previous_registry_hash != prev_snapshot.registry_hash:
                errors.append(
                    f"Chain broken at v{snapshot.registry_version} (INV-REG-002): "
                    f"previous_registry_hash {snapshot.previous_registry_hash[:16]}... "
                    f"does not match prior registry_hash {prev_snapshot.registry_hash[:16]}..."
                )
                chain_valid = False

            # Check version monotonicity
            if snapshot.registry_version <= prev_snapshot.registry_version:
                errors.append(
                    f"Version not monotonically increasing: "
                    f"v{prev_snapshot.registry_version} -> v{snapshot.registry_version}"
                )
                chain_valid = False

            # Check revocation monotonicity (INV-REG-003)
            violations = enforce_revocation_monotonicity(prev_snapshot, snapshot)
            if violations:
                revocation_violations.extend(violations)
                errors.extend(violations)
                chain_valid = False

        prev_snapshot = snapshot

    # Determine status
    if not chain_valid or errors:
        status = RegistryVerificationStatus.FAIL
    elif warnings:
        status = RegistryVerificationStatus.WARN
    else:
        status = RegistryVerificationStatus.PASS

    latest = parsed_snapshots[-1] if parsed_snapshots else None

    return ChainVerificationResult(
        status=status,
        chain_length=len(parsed_snapshots),
        chain_valid=chain_valid,
        latest_version=latest.registry_version if latest else None,
        latest_hash=latest.registry_hash if latest else None,
        revocation_violations=revocation_violations,
        snapshot_results=snapshot_results,
        errors=errors,
        warnings=warnings,
    )


# =============================================================================
# Receipt Generation
# =============================================================================


@dataclass
class RegistryVerificationReceipt:
    """Verification receipt for registry snapshot."""

    schema_version: str = "1.0.0"
    verifier_version: str = ""
    verification_timestamp: str = ""
    result: SnapshotVerificationResult | ChainVerificationResult | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schema_version": self.schema_version,
            "verifier_version": self.verifier_version,
            "verification_timestamp": self.verification_timestamp,
            "result": self.result.to_dict() if self.result else None,
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def create_registry_receipt(
    result: SnapshotVerificationResult | ChainVerificationResult,
    verifier_version: str = "",
) -> RegistryVerificationReceipt:
    """Create a verification receipt for registry verification.

    Args:
        result: Verification result
        verifier_version: Version of the verifier tool

    Returns:
        RegistryVerificationReceipt
    """
    return RegistryVerificationReceipt(
        schema_version="1.0.0",
        verifier_version=verifier_version,
        verification_timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        result=result,
    )
