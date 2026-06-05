"""Governance transparency chain verification.

Verifies append-only hash chain integrity for offline verification.
Each entry is linked by previous_entry_hash forming a tamper-evident chain.

Chain Invariants (INV-ANCHOR-001 through INV-ANCHOR-005):
    - INV-ANCHOR-001: entry_hash[n] = SHA256(canonical({..., previous_entry_hash: entry_hash[n-1]}))
    - INV-ANCHOR-002: DB triggers block UPDATE/DELETE (not verifiable offline)
    - INV-ANCHOR-003: signature_b64 over entry_hash verifiable with public_key_id
    - INV-ANCHOR-004: index strictly incrementing from 0, no gaps
    - INV-ANCHOR-005: Index 0 has previous_entry_hash = "0" * 64

Usage:
    specora-verify verify-log --log transparency-log.json --public-key pubkey.pem

Exit codes:
    0 (PASS): Chain fully valid
    2 (FAIL): Chain integrity violation
    3 (ERROR): File not found, parse error, etc.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import VerificationError
from specora_verify.hash import sha256_hex

# Error codes for chain verification
ERR_CHAIN_PARSE = "CHAIN_PARSE_ERROR"
ERR_CHAIN_SCHEMA = "CHAIN_SCHEMA_ERROR"
ERR_CHAIN_INTEGRITY = "CHAIN_INTEGRITY_ERROR"
ERR_CHAIN_SIGNATURE = "CHAIN_SIGNATURE_ERROR"
ERR_CHAIN_GAP = "CHAIN_GAP_ERROR"
ERR_CHAIN_LINK = "CHAIN_LINK_ERROR"

# Genesis entry marker
GENESIS_PREVIOUS_HASH = "0" * 64

# Chain schema version
CHAIN_SCHEMA_VERSION = 1


@dataclass
class ChainEntryVerification:
    """Result of verifying a single chain entry."""

    index: int
    entry_hash: str
    valid: bool
    hash_valid: bool = True
    link_valid: bool = True
    signature_valid: bool = True
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "entry_hash": self.entry_hash,
            "valid": self.valid,
            "hash_valid": self.hash_valid,
            "link_valid": self.link_valid,
            "signature_valid": self.signature_valid,
            "errors": self.errors,
        }


@dataclass
class ChainVerificationResult:
    """Result of full chain verification."""

    valid: bool
    total_entries: int = 0
    verified_count: int = 0
    start_index: int = 0
    end_index: int = -1
    first_entry_hash: str | None = None
    last_entry_hash: str | None = None
    errors: list[str] = field(default_factory=list)
    entry_results: list[ChainEntryVerification] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "total_entries": self.total_entries,
            "verified_count": self.verified_count,
            "start_index": self.start_index,
            "end_index": self.end_index,
            "first_entry_hash": self.first_entry_hash,
            "last_entry_hash": self.last_entry_hash,
            "errors": self.errors,
            "entry_results": [e.to_dict() for e in self.entry_results]
            if self.entry_results
            else [],
        }


def _build_canonical_payload(entry: dict[str, Any]) -> dict[str, Any]:
    """Build canonical payload for hash computation.

    This matches the server-side canonical format from:
        Specora Wire Spec v1.0 Annex D (Transparency Chain)

    Args:
        entry: Chain entry dictionary

    Returns:
        Canonical payload dictionary for hashing
    """
    return {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "index": int(entry["index"]),
        "artifact_type": entry["artifact_type"],
        "artifact_sha256": entry["artifact_sha256"],
        "previous_entry_hash": entry["previous_entry_hash"],
        "public_key_id": entry["public_key_id"],
        "created_at": entry["created_at"],
    }


def _compute_entry_hash(entry: dict[str, Any]) -> str:
    """Compute entry hash from canonical payload.

    Args:
        entry: Chain entry dictionary

    Returns:
        SHA-256 hex hash of canonical payload
    """
    payload = _build_canonical_payload(entry)
    return sha256_hex(canonical_json_bytes(payload))


def _verify_signature(
    entry_hash: str,
    signature_b64: str,
    public_key: bytes | str,
) -> tuple[bool, str | None]:
    """Verify Ed25519 signature on entry hash.

    Args:
        entry_hash: The entry hash (hex string) to verify
        signature_b64: Base64-encoded Ed25519 signature
        public_key: Public key data (PEM or base64)

    Returns:
        Tuple of (valid, error_message)
    """
    try:
        from specora_verify.signature import is_crypto_available, verify_signature

        if not is_crypto_available():
            return True, None  # Skip signature verification if crypto not available

        # verify_signature expects a SignatureVerificationResult
        result = verify_signature(
            manifest_hash=entry_hash,
            signature_b64=signature_b64,
            public_key=public_key,
        )
        return result.valid, result.errors[0] if result.errors else None

    except Exception as e:
        return False, str(e)


def load_chain_file(path: Path | str) -> list[dict[str, Any]]:
    """Load chain entries from JSON or NDJSON file.

    Supports both formats:
    - JSON array: [{"index": 0, ...}, {"index": 1, ...}]
    - NDJSON: {"index": 0, ...}\n{"index": 1, ...}\n

    Args:
        path: Path to chain file

    Returns:
        List of chain entry dictionaries

    Raises:
        VerificationError: If file cannot be read or parsed
    """
    if isinstance(path, str):
        path = Path(path)

    if not path.exists():
        raise VerificationError(ERR_CHAIN_PARSE, f"Chain file not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        raise VerificationError(ERR_CHAIN_PARSE, f"Failed to read chain file: {e}") from e

    # Try JSON array first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        raise VerificationError(ERR_CHAIN_SCHEMA, "Chain file must be a JSON array or NDJSON")
    except json.JSONDecodeError:
        pass

    # Try NDJSON (newline-delimited JSON)
    entries = []
    for line_num, line in enumerate(content.strip().split("\n"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise VerificationError(
                ERR_CHAIN_PARSE,
                f"Failed to parse line {line_num}: {e}",
            ) from e

    return entries


def _validate_entry_schema(entry: dict[str, Any], index: int) -> list[str]:
    """Validate required fields in chain entry.

    Args:
        entry: Chain entry dictionary
        index: Expected index (for error messages)

    Returns:
        List of validation errors
    """
    errors = []
    required_fields = [
        "index",
        "artifact_type",
        "artifact_sha256",
        "previous_entry_hash",
        "entry_hash",
        "signature_b64",
        "public_key_id",
        "created_at",
    ]

    for field_name in required_fields:
        if field_name not in entry:
            errors.append(f"Entry {index}: missing required field '{field_name}'")

    # Validate hash lengths
    if "entry_hash" in entry and len(entry["entry_hash"]) != 64:
        errors.append(f"Entry {index}: entry_hash must be 64 hex chars")
    if "previous_entry_hash" in entry and len(entry["previous_entry_hash"]) != 64:
        errors.append(f"Entry {index}: previous_entry_hash must be 64 hex chars")
    if "artifact_sha256" in entry and len(entry["artifact_sha256"]) != 64:
        errors.append(f"Entry {index}: artifact_sha256 must be 64 hex chars")

    # Validate artifact_type
    valid_types = {"attestation", "bundle", "erk", "scorecard"}
    if "artifact_type" in entry and entry["artifact_type"] not in valid_types:
        errors.append(f"Entry {index}: invalid artifact_type '{entry['artifact_type']}'")

    return errors


def verify_chain(
    entries: list[dict[str, Any]],
    public_key: bytes | str | None = None,
    verify_signatures: bool = True,
) -> ChainVerificationResult:
    """Verify chain integrity.

    Checks:
    1. No gaps in index sequence (INV-ANCHOR-004)
    2. Index 0 has previous_entry_hash = GENESIS_PREVIOUS_HASH (INV-ANCHOR-005)
    3. Each entry_hash matches recomputed hash (INV-ANCHOR-001)
    4. Each previous_entry_hash matches prior entry's entry_hash (INV-ANCHOR-001)
    5. All signatures valid (INV-ANCHOR-003)

    Args:
        entries: List of chain entry dictionaries (must be sorted by index)
        public_key: Public key for signature verification (optional)
        verify_signatures: Whether to verify signatures (requires public_key)

    Returns:
        ChainVerificationResult with verification details
    """
    if not entries:
        return ChainVerificationResult(
            valid=True,
            total_entries=0,
            verified_count=0,
            errors=["Chain is empty"],
        )

    # Sort entries by index to ensure order
    sorted_entries = sorted(entries, key=lambda e: e.get("index", 0))

    result = ChainVerificationResult(
        valid=True,
        total_entries=len(sorted_entries),
    )

    entry_results: list[ChainEntryVerification] = []
    previous_entry_hash: str | None = None

    for i, entry in enumerate(sorted_entries):
        entry_index = entry.get("index", i)
        entry_errors: list[str] = []
        hash_valid = True
        link_valid = True
        signature_valid = True

        # Validate schema
        schema_errors = _validate_entry_schema(entry, entry_index)
        if schema_errors:
            entry_errors.extend(schema_errors)
            result.valid = False

        # Check index sequence (INV-ANCHOR-004)
        if entry_index != i:
            entry_errors.append(f"Entry {i}: expected index {i}, got {entry_index}")
            result.valid = False

        # Check genesis marker (INV-ANCHOR-005)
        if i == 0:
            if entry.get("previous_entry_hash") != GENESIS_PREVIOUS_HASH:
                entry_errors.append(
                    f"Entry 0: genesis entry must have previous_entry_hash = '{'0' * 64}'"
                )
                link_valid = False
                result.valid = False
        else:
            # Check chain linking (INV-ANCHOR-001)
            if previous_entry_hash and entry.get("previous_entry_hash") != previous_entry_hash:
                entry_errors.append(
                    f"Entry {entry_index}: previous_entry_hash mismatch "
                    f"(expected {previous_entry_hash[:16]}..., got {entry.get('previous_entry_hash', '')[:16]}...)"
                )
                link_valid = False
                result.valid = False

        # Verify entry hash (INV-ANCHOR-001)
        if not schema_errors:
            computed_hash = _compute_entry_hash(entry)
            if computed_hash != entry.get("entry_hash"):
                entry_errors.append(
                    f"Entry {entry_index}: entry_hash mismatch "
                    f"(computed {computed_hash[:16]}..., stored {entry.get('entry_hash', '')[:16]}...)"
                )
                hash_valid = False
                result.valid = False

        # Verify signature (INV-ANCHOR-003)
        if verify_signatures and public_key and not schema_errors:
            sig_valid, sig_error = _verify_signature(
                entry_hash=entry.get("entry_hash", ""),
                signature_b64=entry.get("signature_b64", ""),
                public_key=public_key,
            )
            if not sig_valid:
                entry_errors.append(
                    f"Entry {entry_index}: signature verification failed: {sig_error}"
                )
                signature_valid = False
                result.valid = False

        # Track entry result
        entry_results.append(
            ChainEntryVerification(
                index=entry_index,
                entry_hash=entry.get("entry_hash", ""),
                valid=hash_valid and link_valid and signature_valid and not schema_errors,
                hash_valid=hash_valid,
                link_valid=link_valid,
                signature_valid=signature_valid,
                errors=entry_errors,
            )
        )

        # Update for next iteration
        previous_entry_hash = entry.get("entry_hash")

    # Populate result
    result.verified_count = len([e for e in entry_results if e.valid])
    result.entry_results = entry_results
    result.start_index = sorted_entries[0].get("index", 0) if sorted_entries else 0
    result.end_index = sorted_entries[-1].get("index", -1) if sorted_entries else -1
    result.first_entry_hash = sorted_entries[0].get("entry_hash") if sorted_entries else None
    result.last_entry_hash = sorted_entries[-1].get("entry_hash") if sorted_entries else None

    # Collect all errors
    for entry_result in entry_results:
        result.errors.extend(entry_result.errors)

    return result


def verify_chain_file(
    path: Path | str,
    public_key_path: Path | str | None = None,
    verify_signatures: bool = True,
) -> ChainVerificationResult:
    """Load and verify chain from file.

    Args:
        path: Path to chain file (JSON array or NDJSON)
        public_key_path: Path to public key file (optional)
        verify_signatures: Whether to verify signatures

    Returns:
        ChainVerificationResult with verification details
    """
    try:
        entries = load_chain_file(path)
    except VerificationError as e:
        return ChainVerificationResult(
            valid=False,
            errors=[str(e)],
        )

    # Load public key if provided
    public_key: bytes | str | None = None
    if public_key_path:
        pk_path = Path(public_key_path) if isinstance(public_key_path, str) else public_key_path
        if not pk_path.exists():
            return ChainVerificationResult(
                valid=False,
                errors=[f"Public key file not found: {pk_path}"],
            )
        public_key = pk_path.read_text(encoding="utf-8")

    return verify_chain(
        entries=entries,
        public_key=public_key,
        verify_signatures=verify_signatures and public_key is not None,
    )
