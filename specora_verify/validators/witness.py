"""Multi-organization witness statement validation (PR-ENT-550).

This module provides witness statement verification enabling independent
third-party attestation of external anchors.

Witness Statements:
    Independent organizations verify external anchors across multiple surfaces
    and publish signed witness statements attesting to anchor integrity.

Witness Registry:
    Contains public keys and status for known witness organizations.
    Status: active, suspended, revoked

Invariants:
    - INV-ANCHOR-013: Witness signature binding - signature verifies against registry key
    - INV-ANCHOR-014: Witness anchor hash equality - witness anchor_hash matches actual
    - INV-ANCHOR-015: Witness quorum enforcement - verification can require >= K witnesses
    - INV-ANCHOR-016: Revoked witness invalidation - revoked keys fail verification

Witness Statement Format:
    {
        "spec_id": "witness-statement",
        "schema_version": "1.0.0",
        "witness_statement_id": "ws-<uuid>",
        "timestamp": "2026-03-02T04:12:00Z",
        "anchor_hash": "d4e5f6a1...",
        "anchor_index": 1842,
        "verified_surfaces": ["github_release", "s3_versioned"],
        "verification_result": "pass",
        "verification_timestamp": "2026-03-02T04:11:58Z",
        "witness_org_id": "witness-org-alpha",
        "witness_public_key_id": "wpk-a1b2c3d4e5f6a7b8",
        "witness_signature": "base64..."
    }

Witness Registry Format:
    {
        "registry_version": 1,
        "generated_at": "2026-03-01T00:00:00Z",
        "registry_authority": "Specora Witness Authority",
        "witnesses": [
            {
                "witness_org_id": "witness-org-alpha",
                "org_name": "Witness Organization Alpha",
                "public_key": "base64-encoded-32-byte-key",
                "public_key_id": "wpk-a1b2c3d4e5f6a7b8",
                "trust_level": "external",
                "status": "active",
                "registered_at": "2026-02-01T00:00:00Z",
                "revoked_at": null,
                "revocation_reason": null
            }
        ]
    }
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
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import VerificationError

# Error codes
ERR_REGISTRY_PARSE = "WITNESS_REGISTRY_PARSE_ERROR"
ERR_REGISTRY_SCHEMA = "WITNESS_REGISTRY_SCHEMA_ERROR"
ERR_STATEMENT_PARSE = "WITNESS_STATEMENT_PARSE_ERROR"
ERR_STATEMENT_SCHEMA = "WITNESS_STATEMENT_SCHEMA_ERROR"
ERR_WITNESS_REVOKED = "WITNESS_REVOKED"
ERR_WITNESS_SUSPENDED = "WITNESS_SUSPENDED"
ERR_WITNESS_NOT_FOUND = "WITNESS_NOT_FOUND"
ERR_SIGNATURE_INVALID = "WITNESS_SIGNATURE_INVALID"
ERR_ANCHOR_MISMATCH = "WITNESS_ANCHOR_MISMATCH"

# Validation patterns
HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
WITNESS_KEY_ID_PATTERN = re.compile(r"^wpk-[0-9a-f]{16}$")
STATEMENT_ID_PATTERN = re.compile(r"^ws-[0-9a-f-]{36}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Valid values
VALID_WITNESS_STATUSES = {"active", "suspended", "revoked"}
VALID_TRUST_LEVELS = {"internal", "external", "partner"}
VALID_VERIFICATION_RESULTS = {"pass", "warn", "fail"}
VALID_SURFACES = {"github_release", "s3_versioned", "dns_txt", "local_file"}

# Required statement fields
STATEMENT_REQUIRED_FIELDS = {
    "spec_id",
    "schema_version",
    "witness_statement_id",
    "timestamp",
    "anchor_hash",
    "anchor_index",
    "verified_surfaces",
    "verification_result",
    "verification_timestamp",
    "witness_org_id",
    "witness_public_key_id",
    "witness_signature",
}


class WitnessStatus(Enum):
    """Status of a witness in the registry."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class WitnessVerificationStatus(Enum):
    """Result status of witness verification."""

    PASS = "pass"  # Quorum met, all valid
    WARN = "warn"  # Quorum met, some invalid
    FAIL = "fail"  # Quorum not met, hash mismatch, or revoked witness
    ERROR = "error"  # Operational error


@dataclass
class WitnessEntry:
    """A single witness from the registry."""

    witness_org_id: str
    org_name: str
    public_key: str  # base64-encoded 32-byte Ed25519 key
    public_key_id: str  # wpk-<16-hex>
    trust_level: str
    status: WitnessStatus
    registered_at: str
    revoked_at: str | None = None
    revocation_reason: str | None = None

    def matches(
        self,
        witness_org_id: str | None = None,
        public_key_id: str | None = None,
    ) -> bool:
        """Check if this entry matches the given identifiers."""
        if witness_org_id and self.witness_org_id == witness_org_id:
            return True
        if public_key_id and self.public_key_id == public_key_id:
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "witness_org_id": self.witness_org_id,
            "org_name": self.org_name,
            "public_key": self.public_key,
            "public_key_id": self.public_key_id,
            "trust_level": self.trust_level,
            "status": self.status.value,
            "registered_at": self.registered_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }


@dataclass
class WitnessRegistry:
    """Parsed witness registry."""

    registry_version: int
    generated_at: str
    registry_authority: str
    witnesses: list[WitnessEntry] = field(default_factory=list)

    def lookup(
        self,
        witness_org_id: str | None = None,
        public_key_id: str | None = None,
    ) -> WitnessEntry | None:
        """Look up a witness in the registry.

        Args:
            witness_org_id: Organization ID
            public_key_id: Public key ID (wpk-...)

        Returns:
            WitnessEntry if found, None otherwise
        """
        for entry in self.witnesses:
            if entry.matches(witness_org_id, public_key_id):
                return entry
        return None

    def get_active_witnesses(self) -> list[WitnessEntry]:
        """Return all active witnesses."""
        return [w for w in self.witnesses if w.status == WitnessStatus.ACTIVE]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "registry_version": self.registry_version,
            "generated_at": self.generated_at,
            "registry_authority": self.registry_authority,
            "witnesses": [w.to_dict() for w in self.witnesses],
        }


@dataclass
class WitnessStatementResult:
    """Result of validating a single witness statement."""

    valid: bool
    witness_org_id: str
    verification_result: str
    anchor_hash: str | None = None
    anchor_index: int | None = None
    signature_valid: bool = False
    witness_status: WitnessStatus | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "valid": self.valid,
            "witness_org_id": self.witness_org_id,
            "verification_result": self.verification_result,
            "anchor_hash": self.anchor_hash,
            "anchor_index": self.anchor_index,
            "signature_valid": self.signature_valid,
            "witness_status": self.witness_status.value if self.witness_status else None,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class WitnessQuorumResult:
    """Result of multi-witness quorum verification."""

    status: WitnessVerificationStatus
    quorum_required: int
    quorum_achieved: int
    witnesses_checked: int
    witnesses_valid: int
    consensus_anchor_hash: str | None = None
    consensus_anchor_index: int | None = None
    hash_mismatch_detected: bool = False
    mismatched_witnesses: list[str] = field(default_factory=list)
    statement_results: dict[str, WitnessStatementResult] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Check if verification passed or warned."""
        return self.status in (WitnessVerificationStatus.PASS, WitnessVerificationStatus.WARN)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "valid": self.valid,
            "quorum_required": self.quorum_required,
            "quorum_achieved": self.quorum_achieved,
            "witnesses_checked": self.witnesses_checked,
            "witnesses_valid": self.witnesses_valid,
            "consensus_anchor_hash": self.consensus_anchor_hash,
            "consensus_anchor_index": self.consensus_anchor_index,
            "hash_mismatch_detected": self.hash_mismatch_detected,
            "mismatched_witnesses": self.mismatched_witnesses,
            "statement_results": {k: v.to_dict() for k, v in self.statement_results.items()},
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class WitnessVerificationReceipt:
    """Verification receipt for witness quorum verification."""

    schema_version: str = "1.0.0"
    verifier_version: str = ""
    verification_timestamp: str = ""
    witness_result: WitnessQuorumResult | None = None
    registry_fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schema_version": self.schema_version,
            "verifier_version": self.verifier_version,
            "verification_timestamp": self.verification_timestamp,
            "registry_fingerprint": self.registry_fingerprint,
            "result": self.witness_result.to_dict() if self.witness_result else None,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


# =============================================================================
# Key ID Derivation
# =============================================================================


def derive_witness_key_id(public_key_bytes: bytes) -> str:
    """Derive witness public key ID from raw key bytes.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key

    Returns:
        Key ID in format wpk-<16-hex>
    """
    fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
    return f"wpk-{fingerprint[:16]}"


# =============================================================================
# Registry Loading and Parsing
# =============================================================================


def load_witness_registry(path: Path | str) -> WitnessRegistry:
    """Load and validate a witness registry from a JSON file.

    Args:
        path: Path to the registry JSON file

    Returns:
        Parsed WitnessRegistry

    Raises:
        VerificationError: If the file cannot be read or is malformed
    """
    if isinstance(path, str):
        path = Path(path)

    if not path.exists():
        raise VerificationError(
            ERR_REGISTRY_PARSE,
            f"Witness registry file not found: {path}",
        )

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise VerificationError(
            ERR_REGISTRY_PARSE,
            f"Failed to parse witness registry: {e}",
        ) from e

    return parse_witness_registry(data)


def parse_witness_registry(data: dict[str, Any]) -> WitnessRegistry:
    """Parse and validate witness registry data.

    Args:
        data: Parsed JSON data

    Returns:
        Validated WitnessRegistry

    Raises:
        VerificationError: If the data is malformed or invalid
    """
    # Validate required fields
    if "registry_version" not in data:
        raise VerificationError(ERR_REGISTRY_SCHEMA, "Missing required field: registry_version")
    if "generated_at" not in data:
        raise VerificationError(ERR_REGISTRY_SCHEMA, "Missing required field: generated_at")
    if "registry_authority" not in data:
        raise VerificationError(ERR_REGISTRY_SCHEMA, "Missing required field: registry_authority")
    if "witnesses" not in data:
        raise VerificationError(ERR_REGISTRY_SCHEMA, "Missing required field: witnesses")

    # Validate version
    version = data["registry_version"]
    if not isinstance(version, int) or version < 1:
        raise VerificationError(ERR_REGISTRY_SCHEMA, f"Invalid registry_version: {version}")

    # Validate generated_at timestamp
    generated_at = data["generated_at"]
    if not isinstance(generated_at, str) or not TIMESTAMP_PATTERN.match(generated_at):
        raise VerificationError(
            ERR_REGISTRY_SCHEMA,
            f"Invalid generated_at timestamp: {generated_at} (expected ISO8601 UTC with Z suffix)",
        )

    # Validate authority
    authority = data["registry_authority"]
    if not isinstance(authority, str) or not authority.strip():
        raise VerificationError(
            ERR_REGISTRY_SCHEMA,
            "Invalid registry_authority: must be non-empty string",
        )

    # Validate witnesses array
    witnesses_data = data["witnesses"]
    if not isinstance(witnesses_data, list):
        raise VerificationError(ERR_REGISTRY_SCHEMA, "witnesses must be an array")

    witnesses: list[WitnessEntry] = []
    seen_org_ids: set[str] = set()
    seen_key_ids: set[str] = set()

    for i, witness_data in enumerate(witnesses_data):
        if not isinstance(witness_data, dict):
            raise VerificationError(ERR_REGISTRY_SCHEMA, f"witnesses[{i}] must be an object")

        # Validate required witness fields
        required_witness_fields = [
            "witness_org_id",
            "org_name",
            "public_key",
            "public_key_id",
            "trust_level",
            "status",
            "registered_at",
        ]
        for field_name in required_witness_fields:
            if field_name not in witness_data:
                raise VerificationError(
                    ERR_REGISTRY_SCHEMA,
                    f"witnesses[{i}] missing required field: {field_name}",
                )

        # Validate witness_org_id uniqueness
        witness_org_id = witness_data["witness_org_id"]
        if not isinstance(witness_org_id, str) or not witness_org_id.strip():
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].witness_org_id must be non-empty string",
            )
        if witness_org_id in seen_org_ids:
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].witness_org_id duplicate: {witness_org_id}",
            )
        seen_org_ids.add(witness_org_id)

        # Validate org_name
        org_name = witness_data["org_name"]
        if not isinstance(org_name, str) or not org_name.strip():
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].org_name must be non-empty string",
            )

        # Validate public_key (base64-encoded 32 bytes)
        public_key = witness_data["public_key"]
        if not isinstance(public_key, str):
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].public_key must be string",
            )
        try:
            key_bytes = base64.b64decode(public_key)
            if len(key_bytes) != 32:
                raise VerificationError(
                    ERR_REGISTRY_SCHEMA,
                    f"witnesses[{i}].public_key must be 32 bytes, got {len(key_bytes)}",
                )
        except Exception as e:
            if isinstance(e, VerificationError):
                raise
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].public_key invalid base64: {e}",
            ) from e

        # Validate public_key_id format
        public_key_id = witness_data["public_key_id"]
        if not isinstance(public_key_id, str) or not WITNESS_KEY_ID_PATTERN.match(public_key_id):
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].public_key_id invalid format: {public_key_id} "
                "(expected wpk-<16 hex chars>)",
            )

        # Validate public_key_id matches derived value
        expected_key_id = derive_witness_key_id(key_bytes)
        if public_key_id != expected_key_id:
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].public_key_id mismatch: {public_key_id} "
                f"vs expected {expected_key_id}",
            )

        # Check for duplicate key IDs
        if public_key_id in seen_key_ids:
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].public_key_id duplicate: {public_key_id}",
            )
        seen_key_ids.add(public_key_id)

        # Validate trust_level
        trust_level = witness_data["trust_level"]
        if trust_level not in VALID_TRUST_LEVELS:
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].trust_level invalid: {trust_level} "
                f"(expected: {', '.join(VALID_TRUST_LEVELS)})",
            )

        # Validate status
        status_str = witness_data["status"]
        if status_str not in VALID_WITNESS_STATUSES:
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].status invalid: {status_str} "
                f"(expected: {', '.join(VALID_WITNESS_STATUSES)})",
            )
        status = WitnessStatus(status_str)

        # Validate registered_at
        registered_at = witness_data["registered_at"]
        if not isinstance(registered_at, str) or not TIMESTAMP_PATTERN.match(registered_at):
            raise VerificationError(
                ERR_REGISTRY_SCHEMA,
                f"witnesses[{i}].registered_at invalid format: {registered_at}",
            )

        # Validate optional revoked_at
        revoked_at = witness_data.get("revoked_at")
        if revoked_at is not None:
            if not isinstance(revoked_at, str) or not TIMESTAMP_PATTERN.match(revoked_at):
                raise VerificationError(
                    ERR_REGISTRY_SCHEMA,
                    f"witnesses[{i}].revoked_at invalid format: {revoked_at}",
                )

        witnesses.append(
            WitnessEntry(
                witness_org_id=witness_org_id,
                org_name=org_name,
                public_key=public_key,
                public_key_id=public_key_id,
                trust_level=trust_level,
                status=status,
                registered_at=registered_at,
                revoked_at=revoked_at,
                revocation_reason=witness_data.get("revocation_reason"),
            )
        )

    return WitnessRegistry(
        registry_version=version,
        generated_at=generated_at,
        registry_authority=authority,
        witnesses=witnesses,
    )


# =============================================================================
# Statement Validation
# =============================================================================


def compute_witness_statement_signing_bytes(statement: dict[str, Any]) -> bytes:
    """Compute bytes to sign for witness statement.

    The signature is computed over the canonical JSON of the statement
    excluding the witness_signature field.

    Args:
        statement: Witness statement dict

    Returns:
        UTF-8 bytes of canonical JSON to sign
    """
    to_sign = {k: v for k, v in statement.items() if k != "witness_signature"}
    return canonical_json_bytes(to_sign)


def validate_witness_statement(
    statement: dict[str, Any],
    registry: WitnessRegistry | None = None,
    expected_anchor_hash: str | None = None,
    skip_signature: bool = False,
) -> WitnessStatementResult:
    """Validate a witness statement structure and signature.

    Checks:
    1. Required fields present with correct types
    2. Signature verifies against registry key (INV-ANCHOR-013)
    3. Witness not revoked (INV-ANCHOR-016)
    4. anchor_hash matches expected if provided (INV-ANCHOR-014)

    Args:
        statement: Witness statement dict
        registry: Witness registry for signature verification
        expected_anchor_hash: Expected anchor hash to verify against
        skip_signature: Skip signature verification

    Returns:
        WitnessStatementResult with validation details
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Extract witness_org_id early for result
    witness_org_id = statement.get("witness_org_id", "unknown")
    verification_result = statement.get("verification_result", "unknown")
    anchor_hash = statement.get("anchor_hash")
    anchor_index = statement.get("anchor_index")

    result = WitnessStatementResult(
        valid=False,
        witness_org_id=witness_org_id,
        verification_result=verification_result,
        anchor_hash=anchor_hash,
        anchor_index=anchor_index,
    )

    # Check required fields
    missing_fields = STATEMENT_REQUIRED_FIELDS - set(statement.keys())
    if missing_fields:
        errors.append(f"Missing required fields: {', '.join(sorted(missing_fields))}")
        result.errors = errors
        return result

    # Validate spec_id
    if statement.get("spec_id") != "witness-statement":
        errors.append(f"Invalid spec_id: {statement.get('spec_id')} (expected: witness-statement)")

    # Validate schema_version
    schema_version = statement.get("schema_version")
    if schema_version != "1.0.0":
        warnings.append(f"Unknown schema_version: {schema_version} (expected: 1.0.0)")

    # Validate witness_statement_id format
    statement_id = statement.get("witness_statement_id", "")
    if not STATEMENT_ID_PATTERN.match(statement_id):
        errors.append(f"Invalid witness_statement_id format: {statement_id} (expected: ws-<uuid>)")

    # Validate timestamps
    for field_name in ["timestamp", "verification_timestamp"]:
        ts = statement.get(field_name, "")
        if not TIMESTAMP_PATTERN.match(ts):
            errors.append(f"Invalid {field_name} format: {ts} (expected ISO8601 UTC with Z)")

    # Validate anchor_hash
    if not anchor_hash or not HEX64_PATTERN.match(anchor_hash):
        errors.append(f"Invalid anchor_hash: must be 64 lowercase hex chars, got: {anchor_hash}")

    # Validate anchor_index
    if not isinstance(anchor_index, int) or anchor_index < 0:
        errors.append(f"Invalid anchor_index: must be non-negative integer, got: {anchor_index}")

    # Validate verified_surfaces
    verified_surfaces = statement.get("verified_surfaces", [])
    if not isinstance(verified_surfaces, list) or not verified_surfaces:
        errors.append("verified_surfaces must be non-empty array")
    else:
        invalid_surfaces = set(verified_surfaces) - VALID_SURFACES
        if invalid_surfaces:
            errors.append(f"Invalid verified_surfaces: {', '.join(invalid_surfaces)}")

    # Validate verification_result
    if verification_result not in VALID_VERIFICATION_RESULTS:
        errors.append(
            f"Invalid verification_result: {verification_result} "
            f"(expected: {', '.join(VALID_VERIFICATION_RESULTS)})"
        )

    # Validate witness_public_key_id format
    public_key_id = statement.get("witness_public_key_id", "")
    if not WITNESS_KEY_ID_PATTERN.match(public_key_id):
        errors.append(
            f"Invalid witness_public_key_id format: {public_key_id} (expected wpk-<16 hex chars>)"
        )

    # Check anchor hash mismatch (INV-ANCHOR-014)
    if expected_anchor_hash and anchor_hash:
        if anchor_hash != expected_anchor_hash:
            errors.append(
                f"Anchor hash mismatch (INV-ANCHOR-014): "
                f"statement has {anchor_hash[:16]}..., expected {expected_anchor_hash[:16]}..."
            )

    # If we have structural errors, return early
    if errors:
        result.errors = errors
        result.warnings = warnings
        return result

    # Look up witness in registry
    witness_entry: WitnessEntry | None = None
    if registry:
        witness_entry = registry.lookup(
            witness_org_id=witness_org_id,
            public_key_id=public_key_id,
        )

        if not witness_entry:
            errors.append(
                f"Witness not found in registry (INV-ANCHOR-013): "
                f"org_id={witness_org_id}, key_id={public_key_id}"
            )
            result.errors = errors
            result.warnings = warnings
            return result

        result.witness_status = witness_entry.status

        # Check witness status (INV-ANCHOR-016)
        if witness_entry.status == WitnessStatus.REVOKED:
            reason = witness_entry.revocation_reason or "unknown"
            errors.append(f"Witness revoked (INV-ANCHOR-016): {witness_org_id} - {reason}")
            result.errors = errors
            result.warnings = warnings
            return result

        if witness_entry.status == WitnessStatus.SUSPENDED:
            warnings.append(f"Witness suspended: {witness_org_id}")

    # Verify signature (INV-ANCHOR-013)
    if not skip_signature:
        if not registry or not witness_entry:
            warnings.append("No registry provided - signature verification skipped")
        else:
            try:
                # Import here to avoid dependency issues
                from specora_verify.signature import is_crypto_available, verify_signature

                if not is_crypto_available():
                    warnings.append(
                        "cryptography package not available - signature verification skipped"
                    )
                else:
                    # Compute bytes to verify
                    signing_bytes = compute_witness_statement_signing_bytes(statement)
                    signing_hash = hashlib.sha256(signing_bytes).hexdigest()

                    # Verify signature
                    signature_b64 = statement.get("witness_signature", "")
                    sig_result = verify_signature(
                        manifest_hash=signing_hash,
                        signature_b64=signature_b64,
                        public_key=witness_entry.public_key,
                        key_format="base64",
                    )

                    if sig_result.valid:
                        result.signature_valid = True
                    else:
                        errors.append(
                            f"Signature verification failed (INV-ANCHOR-013): "
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
# Quorum Verification
# =============================================================================


def verify_witness_quorum(
    statements: list[dict[str, Any]],
    registry: WitnessRegistry,
    quorum_required: int = 2,
    expected_anchor_hash: str | None = None,
    skip_signature: bool = False,
) -> WitnessQuorumResult:
    """Verify multiple witness statements achieve quorum.

    INV-ANCHOR-015: Verification requires >= K witnesses to agree.

    Args:
        statements: List of witness statement dicts
        registry: Witness registry for validation
        quorum_required: Minimum agreeing witnesses (K)
        expected_anchor_hash: Expected anchor hash to verify against
        skip_signature: Skip signature verification

    Returns:
        WitnessQuorumResult with consensus and individual results
    """
    errors: list[str] = []
    warnings: list[str] = []
    statement_results: dict[str, WitnessStatementResult] = {}

    if not statements:
        return WitnessQuorumResult(
            status=WitnessVerificationStatus.ERROR,
            quorum_required=quorum_required,
            quorum_achieved=0,
            witnesses_checked=0,
            witnesses_valid=0,
            errors=["No witness statements provided"],
        )

    # Validate each statement
    for statement in statements:
        result = validate_witness_statement(
            statement=statement,
            registry=registry,
            expected_anchor_hash=expected_anchor_hash,
            skip_signature=skip_signature,
        )
        statement_results[result.witness_org_id] = result

    witnesses_checked = len(statement_results)
    witnesses_valid = sum(1 for r in statement_results.values() if r.valid)

    # Group valid statements by anchor_hash
    hash_groups: dict[str, list[str]] = {}
    for org_id, result in statement_results.items():
        if result.valid and result.anchor_hash:
            if result.anchor_hash not in hash_groups:
                hash_groups[result.anchor_hash] = []
            hash_groups[result.anchor_hash].append(org_id)

    # Find consensus
    consensus_anchor_hash: str | None = None
    consensus_anchor_index: int | None = None
    quorum_achieved = 0
    hash_mismatch_detected = False
    mismatched_witnesses: list[str] = []

    if hash_groups:
        # Find largest group
        best_hash = max(hash_groups.keys(), key=lambda h: len(hash_groups[h]))
        quorum_achieved = len(hash_groups[best_hash])
        consensus_anchor_hash = best_hash

        # Get consensus index from any agreeing statement
        for org_id in hash_groups[best_hash]:
            res = statement_results[org_id]
            if res.anchor_index is not None:
                consensus_anchor_index = res.anchor_index
                break

        # Check for hash mismatches
        if len(hash_groups) > 1:
            hash_mismatch_detected = True
            for h, orgs in hash_groups.items():
                if h != best_hash:
                    mismatched_witnesses.extend(orgs)
            errors.append(
                f"Hash mismatch detected: {len(mismatched_witnesses)} witness(es) "
                f"disagree with consensus"
            )

    # Determine status
    # Hash mismatch is a tamper signal - always FAIL regardless of quorum
    if hash_mismatch_detected:
        status = WitnessVerificationStatus.FAIL
        errors.append(
            f"Hash mismatch detected (INV-ANCHOR-014): {len(mismatched_witnesses)} "
            f"witness(es) attest to different anchor_hash - potential tampering"
        )
    elif quorum_achieved >= quorum_required:
        if witnesses_valid < witnesses_checked:
            # Quorum met but some witnesses invalid (not mismatch) - WARN
            status = WitnessVerificationStatus.WARN
            warnings.append(
                f"Some witnesses invalid: {witnesses_checked - witnesses_valid} of "
                f"{witnesses_checked}"
            )
        else:
            status = WitnessVerificationStatus.PASS
    else:
        status = WitnessVerificationStatus.FAIL
        errors.append(
            f"Quorum not met (INV-ANCHOR-015): required {quorum_required}, "
            f"achieved {quorum_achieved}"
        )

    return WitnessQuorumResult(
        status=status,
        quorum_required=quorum_required,
        quorum_achieved=quorum_achieved,
        witnesses_checked=witnesses_checked,
        witnesses_valid=witnesses_valid,
        consensus_anchor_hash=consensus_anchor_hash,
        consensus_anchor_index=consensus_anchor_index,
        hash_mismatch_detected=hash_mismatch_detected,
        mismatched_witnesses=mismatched_witnesses,
        statement_results=statement_results,
        errors=errors,
        warnings=warnings,
    )


# =============================================================================
# Receipt Generation
# =============================================================================


def create_witness_receipt(
    result: WitnessQuorumResult,
    registry: WitnessRegistry | None = None,
    verifier_version: str = "",
) -> WitnessVerificationReceipt:
    """Create a verification receipt for witness quorum verification.

    Args:
        result: Witness quorum verification result
        registry: Witness registry used (for fingerprint)
        verifier_version: Version of the verifier tool

    Returns:
        WitnessVerificationReceipt for archival
    """
    registry_fingerprint: str | None = None
    if registry:
        registry_bytes = json.dumps(registry.to_dict(), sort_keys=True).encode("utf-8")
        registry_fingerprint = hashlib.sha256(registry_bytes).hexdigest()

    return WitnessVerificationReceipt(
        schema_version="1.0.0",
        verifier_version=verifier_version,
        verification_timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        witness_result=result,
        registry_fingerprint=registry_fingerprint,
    )


# =============================================================================
# Exit Code Mapping
# =============================================================================


def witness_status_to_exit_code(status: WitnessVerificationStatus) -> int:
    """Map witness verification status to CLI exit code.

    Args:
        status: Verification status

    Returns:
        Integer exit code
    """
    mapping = {
        WitnessVerificationStatus.PASS: 0,
        WitnessVerificationStatus.WARN: 1,
        WitnessVerificationStatus.FAIL: 2,
        WitnessVerificationStatus.ERROR: 3,
    }
    return mapping.get(status, 3)
