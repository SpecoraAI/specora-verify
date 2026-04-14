"""External anchor verification.

Verifies external transparency anchors published to immutable external surfaces
(GitHub Releases, S3 versioned buckets).

External anchors form a "chain of chains" where each anchor:
- References the transparency chain head (index, hash, signature)
- Links to the previous external anchor via hash-chain
- Is signed with Ed25519 for tamper detection

Invariants (INV-ANCHOR-006 through INV-ANCHOR-008):
    - INV-ANCHOR-006: External anchor hash chaining (previous_external_anchor_hash)
    - INV-ANCHOR-007: External anchor signature binding (verifiable with key registry)
    - INV-ANCHOR-008: Publication immutability (release tags immutable)

Usage:
    specora-verify verify-external-anchor anchor.json --public-key pubkey.pem
    specora-verify verify-external-anchor-chain anchors/ --public-key pubkey.pem

Exit codes:
    0 (PASS): Anchor fully valid
    2 (FAIL): Anchor integrity violation
    3 (ERROR): File not found, parse error, etc.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import VerificationError
from specora_verify.hash import sha256_hex

# Error codes for external anchor verification
ERR_ANCHOR_PARSE = "EXTERNAL_ANCHOR_PARSE_ERROR"
ERR_ANCHOR_SCHEMA = "EXTERNAL_ANCHOR_SCHEMA_ERROR"
ERR_ANCHOR_HASH = "EXTERNAL_ANCHOR_HASH_ERROR"
ERR_ANCHOR_SIGNATURE = "EXTERNAL_ANCHOR_SIGNATURE_ERROR"
ERR_ANCHOR_CHAIN = "EXTERNAL_ANCHOR_CHAIN_ERROR"

# Genesis marker for first external anchor
EXTERNAL_ANCHOR_GENESIS_HASH = "0" * 64

# External anchor schema version
EXTERNAL_ANCHOR_SCHEMA_VERSION = 1

# Required fields in external anchor
EXTERNAL_ANCHOR_REQUIRED_FIELDS = [
    "schema_version",
    "timestamp",
    "chain_head_index",
    "chain_head_hash",
    "chain_head_signature",
    "chain_head_key_id",
    "previous_external_anchor_hash",
    "anchor_hash",
    "anchor_signature",
    "anchor_key_id",
]


@dataclass
class ExternalAnchorVerificationResult:
    """Result of verifying a single external anchor."""

    valid: bool
    chain_head_index: int = 0
    anchor_hash: str = ""
    previous_anchor_hash: str = ""
    hash_valid: bool = True
    signature_valid: bool = True
    schema_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "chain_head_index": self.chain_head_index,
            "anchor_hash": self.anchor_hash,
            "previous_anchor_hash": self.previous_anchor_hash,
            "hash_valid": self.hash_valid,
            "signature_valid": self.signature_valid,
            "schema_valid": self.schema_valid,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class ExternalAnchorChainResult:
    """Result of verifying external anchor chain."""

    valid: bool
    total_anchors: int = 0
    verified_count: int = 0
    first_anchor_hash: str | None = None
    last_anchor_hash: str | None = None
    first_chain_index: int | None = None
    last_chain_index: int | None = None
    errors: list[str] = field(default_factory=list)
    anchor_results: list[ExternalAnchorVerificationResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "total_anchors": self.total_anchors,
            "verified_count": self.verified_count,
            "first_anchor_hash": self.first_anchor_hash,
            "last_anchor_hash": self.last_anchor_hash,
            "first_chain_index": self.first_chain_index,
            "last_chain_index": self.last_chain_index,
            "errors": self.errors,
            "anchor_results": [r.to_dict() for r in self.anchor_results],
        }


def _build_anchor_payload_for_hash(anchor: dict[str, Any]) -> dict[str, Any]:
    """Build the canonical payload for computing anchor_hash.

    The anchor_hash is computed over these fields (excluding signatures):
    {
        "schema_version": 1,
        "timestamp": "...",
        "chain_head_index": 0,
        "chain_head_hash": "...",
        "chain_head_signature": "...",
        "chain_head_key_id": "...",
        "previous_external_anchor_hash": "..."
    }
    """
    return {
        "schema_version": anchor.get("schema_version", EXTERNAL_ANCHOR_SCHEMA_VERSION),
        "timestamp": anchor["timestamp"],
        "chain_head_index": anchor["chain_head_index"],
        "chain_head_hash": anchor["chain_head_hash"],
        "chain_head_signature": anchor["chain_head_signature"],
        "chain_head_key_id": anchor["chain_head_key_id"],
        "previous_external_anchor_hash": anchor["previous_external_anchor_hash"],
    }


def validate_external_anchor_schema(anchor: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate external anchor schema has all required fields."""
    errors = []

    for field_name in EXTERNAL_ANCHOR_REQUIRED_FIELDS:
        if field_name not in anchor:
            errors.append(f"Missing required field: {field_name}")

    # Validate schema version
    if anchor.get("schema_version") != EXTERNAL_ANCHOR_SCHEMA_VERSION:
        errors.append(
            f"Unsupported schema_version: {anchor.get('schema_version')} "
            f"(expected {EXTERNAL_ANCHOR_SCHEMA_VERSION})"
        )

    # Validate hash lengths
    for hash_field in ["chain_head_hash", "previous_external_anchor_hash", "anchor_hash"]:
        if hash_field in anchor:
            value = anchor[hash_field]
            if len(value) != 64 or not all(c in "0123456789abcdef" for c in value):
                errors.append(f"Invalid hash format for {hash_field}: expected 64 hex chars")

    return len(errors) == 0, errors


def verify_external_anchor(
    anchor: dict[str, Any],
    public_key_bytes: bytes | None = None,
    *,
    verify_signature: bool = True,
) -> ExternalAnchorVerificationResult:
    """Verify a single external anchor.

    Args:
        anchor: External anchor dictionary
        public_key_bytes: Ed25519 public key bytes (32 bytes) for signature verification
        verify_signature: Whether to verify the signature (requires cryptography)

    Returns:
        ExternalAnchorVerificationResult with verification status
    """
    errors: list[str] = []
    warnings: list[str] = []
    hash_valid = True
    signature_valid = True
    schema_valid = True

    # Validate schema
    schema_valid, schema_errors = validate_external_anchor_schema(anchor)
    if not schema_valid:
        errors.extend(schema_errors)
        return ExternalAnchorVerificationResult(
            valid=False,
            chain_head_index=anchor.get("chain_head_index", 0),
            anchor_hash=anchor.get("anchor_hash", ""),
            previous_anchor_hash=anchor.get("previous_external_anchor_hash", ""),
            hash_valid=False,
            signature_valid=False,
            schema_valid=False,
            errors=errors,
        )

    # Verify anchor_hash
    payload_for_hash = _build_anchor_payload_for_hash(anchor)
    computed_hash = sha256_hex(canonical_json_bytes(payload_for_hash))

    if computed_hash != anchor["anchor_hash"]:
        hash_valid = False
        errors.append(
            f"Anchor hash mismatch: computed {computed_hash[:16]}..., "
            f"stored {anchor['anchor_hash'][:16]}..."
        )

    # Verify signature if requested and key provided
    if verify_signature and public_key_bytes is not None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature

            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            signature_bytes = base64.b64decode(anchor["anchor_signature"])

            try:
                public_key.verify(signature_bytes, anchor["anchor_hash"].encode("utf-8"))
            except InvalidSignature:
                signature_valid = False
                errors.append("Anchor signature verification failed")

        except ImportError:
            warnings.append("Signature verification skipped: cryptography not installed")
        except Exception as e:
            signature_valid = False
            errors.append(f"Signature verification error: {e}")

    elif verify_signature and public_key_bytes is None:
        warnings.append("Signature verification skipped: no public key provided")

    return ExternalAnchorVerificationResult(
        valid=hash_valid and signature_valid,
        chain_head_index=anchor.get("chain_head_index", 0),
        anchor_hash=anchor.get("anchor_hash", ""),
        previous_anchor_hash=anchor.get("previous_external_anchor_hash", ""),
        hash_valid=hash_valid,
        signature_valid=signature_valid if verify_signature else True,
        schema_valid=schema_valid,
        errors=errors,
        warnings=warnings,
    )


def verify_external_anchor_chain(
    anchors: list[dict[str, Any]],
    public_key_bytes: bytes | None = None,
    *,
    verify_signatures: bool = True,
) -> ExternalAnchorChainResult:
    """Verify external anchor chain integrity.

    Checks:
    1. Each anchor's previous_external_anchor_hash matches prior anchor_hash
    2. First anchor has GENESIS hash as previous
    3. Each anchor's anchor_hash is correctly computed
    4. Signatures are valid (if public key provided)

    Args:
        anchors: List of external anchor dictionaries, in order
        public_key_bytes: Ed25519 public key bytes for signature verification
        verify_signatures: Whether to verify signatures

    Returns:
        ExternalAnchorChainResult with verification status
    """
    errors: list[str] = []
    anchor_results: list[ExternalAnchorVerificationResult] = []

    if not anchors:
        return ExternalAnchorChainResult(
            valid=True,
            total_anchors=0,
            verified_count=0,
            errors=["No anchors to verify"],
        )

    # Sort anchors by chain_head_index
    sorted_anchors = sorted(anchors, key=lambda a: a.get("chain_head_index", 0))

    expected_previous_hash = EXTERNAL_ANCHOR_GENESIS_HASH

    for i, anchor in enumerate(sorted_anchors):
        # Verify individual anchor
        result = verify_external_anchor(
            anchor,
            public_key_bytes=public_key_bytes,
            verify_signature=verify_signatures,
        )
        anchor_results.append(result)

        if not result.valid:
            errors.extend(result.errors)

        # Check chain linkage
        actual_previous = anchor.get("previous_external_anchor_hash", "")
        if actual_previous != expected_previous_hash:
            errors.append(
                f"Chain break at anchor {i} (chain_head_index={anchor.get('chain_head_index', '?')}): "
                f"previous_hash ({actual_previous[:16]}...) does not match "
                f"expected ({expected_previous_hash[:16]}...)"
            )

        # Update expected for next iteration
        expected_previous_hash = anchor.get("anchor_hash", "")

    valid = len(errors) == 0
    verified_count = sum(1 for r in anchor_results if r.valid)

    return ExternalAnchorChainResult(
        valid=valid,
        total_anchors=len(anchors),
        verified_count=verified_count,
        first_anchor_hash=sorted_anchors[0].get("anchor_hash") if sorted_anchors else None,
        last_anchor_hash=sorted_anchors[-1].get("anchor_hash") if sorted_anchors else None,
        first_chain_index=sorted_anchors[0].get("chain_head_index") if sorted_anchors else None,
        last_chain_index=sorted_anchors[-1].get("chain_head_index") if sorted_anchors else None,
        errors=errors,
        anchor_results=anchor_results,
    )


def verify_external_anchor_file(
    path: Path,
    public_key_path: Path | None = None,
    *,
    verify_signature: bool = True,
) -> ExternalAnchorVerificationResult:
    """Verify external anchor from file.

    Args:
        path: Path to external anchor JSON file
        public_key_path: Path to public key file
        verify_signature: Whether to verify signature

    Returns:
        ExternalAnchorVerificationResult
    """
    # Load anchor file
    try:
        content = path.read_text(encoding="utf-8")
        anchor = json.loads(content)
    except json.JSONDecodeError as e:
        return ExternalAnchorVerificationResult(
            valid=False,
            errors=[f"Failed to parse anchor JSON: {e}"],
            schema_valid=False,
        )
    except Exception as e:
        return ExternalAnchorVerificationResult(
            valid=False,
            errors=[f"Failed to read anchor file: {e}"],
            schema_valid=False,
        )

    # Load public key if provided
    public_key_bytes = None
    if public_key_path is not None:
        try:
            from specora_verify.signature import load_public_key

            public_key_data = public_key_path.read_text(encoding="utf-8")
            public_key = load_public_key(public_key_data)

            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            public_key_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        except ImportError:
            pass  # cryptography not installed
        except Exception as e:
            return ExternalAnchorVerificationResult(
                valid=False,
                errors=[f"Failed to load public key: {e}"],
            )

    return verify_external_anchor(
        anchor,
        public_key_bytes=public_key_bytes,
        verify_signature=verify_signature,
    )


def verify_external_anchor_chain_dir(
    directory: Path,
    public_key_path: Path | None = None,
    *,
    verify_signatures: bool = True,
) -> ExternalAnchorChainResult:
    """Verify external anchor chain from directory of anchor files.

    Args:
        directory: Path to directory containing anchor JSON files
        public_key_path: Path to public key file
        verify_signatures: Whether to verify signatures

    Returns:
        ExternalAnchorChainResult
    """
    if not directory.is_dir():
        return ExternalAnchorChainResult(
            valid=False,
            errors=[f"Not a directory: {directory}"],
        )

    # Find all anchor JSON files
    anchor_files = sorted(directory.glob("*.json"))

    if not anchor_files:
        return ExternalAnchorChainResult(
            valid=False,
            errors=[f"No anchor JSON files found in {directory}"],
        )

    # Load all anchors
    anchors: list[dict[str, Any]] = []
    load_errors: list[str] = []

    for anchor_file in anchor_files:
        try:
            content = anchor_file.read_text(encoding="utf-8")
            anchor = json.loads(content)
            anchors.append(anchor)
        except Exception as e:
            load_errors.append(f"Failed to load {anchor_file.name}: {e}")

    if load_errors:
        return ExternalAnchorChainResult(
            valid=False,
            total_anchors=len(anchor_files),
            errors=load_errors,
        )

    # Load public key if provided
    public_key_bytes = None
    if public_key_path is not None:
        try:
            from specora_verify.signature import load_public_key

            public_key_data = public_key_path.read_text(encoding="utf-8")
            public_key = load_public_key(public_key_data)

            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            public_key_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        except ImportError:
            pass  # cryptography not installed
        except Exception as e:
            return ExternalAnchorChainResult(
                valid=False,
                errors=[f"Failed to load public key: {e}"],
            )

    return verify_external_anchor_chain(
        anchors,
        public_key_bytes=public_key_bytes,
        verify_signatures=verify_signatures,
    )
