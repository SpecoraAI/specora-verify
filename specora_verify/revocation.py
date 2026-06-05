"""Offline key revocation list support.

This module provides offline key trust verification using a JSON revocation list.
The verifier remains offline - no network access is performed.

Key States:
    - active: Key is trusted for signing
    - retired: Key is no longer used for new signatures but existing signatures are valid
    - revoked: Key has been compromised or invalidated; signatures should not be trusted

Trust Decisions:
    - ACTIVE key: PASS (no trust warning)
    - RETIRED key: WARN by default, FAIL with --require-trusted-key
    - REVOKED key: FAIL (always)
    - UNKNOWN key: WARN by default, FAIL with --require-trusted-key

Revocation List Format:
    {
        "version": 1,
        "generated_at": "2026-03-01T00:00:00Z",
        "authority": "Specora Key Authority",
        "keys": [
            {
                "derived_key_id": "spk-0123abcd4567ef89",
                "fingerprint_sha256": "0123abcd...full64hex...",
                "status": "active|retired|revoked",
                "status_reason": "rotation|compromise|deprecation",
                "effective_at": "2026-02-15T00:00:00Z"
            }
        ]
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from specora_verify.errors import VerificationError

# Error codes for revocation operations
ERR_REVOCATION_PARSE = "REVOCATION_LIST_PARSE_ERROR"
ERR_REVOCATION_SCHEMA = "REVOCATION_LIST_SCHEMA_ERROR"
ERR_KEY_REVOKED = "KEY_REVOKED"
ERR_KEY_RETIRED = "KEY_RETIRED"
ERR_KEY_UNKNOWN = "KEY_TRUST_UNKNOWN"

# Key status values
KEY_STATUS_ACTIVE = "active"
KEY_STATUS_RETIRED = "retired"
KEY_STATUS_REVOKED = "revoked"
KEY_STATUS_UNKNOWN = "unknown"

# Valid status values
VALID_KEY_STATUSES = {KEY_STATUS_ACTIVE, KEY_STATUS_RETIRED, KEY_STATUS_REVOKED}

# Regex patterns for validation
HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_PATTERN = re.compile(r"^spk-[0-9a-f]{16}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


@dataclass
class KeyEntry:
    """A single key entry from the revocation list."""

    derived_key_id: str
    fingerprint_sha256: str
    status: str
    status_reason: str | None = None
    effective_at: str | None = None

    def matches(self, key_id: str | None = None, fingerprint: str | None = None) -> bool:
        """Check if this entry matches the given key identifiers.

        Args:
            key_id: Derived key ID (spk-...)
            fingerprint: Full SHA-256 fingerprint

        Returns:
            True if either identifier matches
        """
        if key_id and self.derived_key_id == key_id:
            return True
        if fingerprint and self.fingerprint_sha256 == fingerprint:
            return True
        return False


@dataclass
class RevocationList:
    """Parsed revocation list."""

    version: int
    generated_at: str
    authority: str
    keys: list[KeyEntry] = field(default_factory=list)

    def lookup(
        self,
        key_id: str | None = None,
        fingerprint: str | None = None,
    ) -> KeyEntry | None:
        """Look up a key in the revocation list.

        Args:
            key_id: Derived key ID (spk-...)
            fingerprint: Full SHA-256 fingerprint

        Returns:
            KeyEntry if found, None otherwise
        """
        for entry in self.keys:
            if entry.matches(key_id, fingerprint):
                return entry
        return None

    def get_status(
        self,
        key_id: str | None = None,
        fingerprint: str | None = None,
    ) -> str:
        """Get the status of a key.

        Args:
            key_id: Derived key ID (spk-...)
            fingerprint: Full SHA-256 fingerprint

        Returns:
            Key status: "active", "retired", "revoked", or "unknown"
        """
        entry = self.lookup(key_id, fingerprint)
        if entry:
            return entry.status
        return KEY_STATUS_UNKNOWN


@dataclass
class TrustCheckResult:
    """Result of a key trust check."""

    key_status: str
    revocation_list_provided: bool
    require_trusted_key: bool
    trusted: bool
    warning: str | None = None
    error: str | None = None
    entry: KeyEntry | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        result: dict[str, Any] = {
            "revocation_list_provided": self.revocation_list_provided,
            "key_status": self.key_status,
            "require_trusted_key": self.require_trusted_key,
            "trusted": self.trusted,
        }
        if self.warning:
            result["warning"] = self.warning
        if self.error:
            result["error"] = self.error
        if self.entry:
            result["status_reason"] = self.entry.status_reason
            result["effective_at"] = self.entry.effective_at
        return result


def load_revocation_list(path: Path | str) -> RevocationList:
    """Load and validate a revocation list from a JSON file.

    Args:
        path: Path to the revocation list JSON file

    Returns:
        Parsed RevocationList

    Raises:
        VerificationError: If the file cannot be read or is malformed
    """
    if isinstance(path, str):
        path = Path(path)

    if not path.exists():
        raise VerificationError(
            ERR_REVOCATION_PARSE,
            f"Revocation list file not found: {path}",
        )

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise VerificationError(
            ERR_REVOCATION_PARSE,
            f"Failed to parse revocation list: {e}",
        ) from e

    return parse_revocation_list(data)


def parse_revocation_list(data: dict[str, Any]) -> RevocationList:
    """Parse and validate revocation list data.

    Args:
        data: Parsed JSON data

    Returns:
        Validated RevocationList

    Raises:
        VerificationError: If the data is malformed or invalid
    """
    # Validate required fields
    if "version" not in data:
        raise VerificationError(ERR_REVOCATION_SCHEMA, "Missing required field: version")
    if "generated_at" not in data:
        raise VerificationError(ERR_REVOCATION_SCHEMA, "Missing required field: generated_at")
    if "authority" not in data:
        raise VerificationError(ERR_REVOCATION_SCHEMA, "Missing required field: authority")
    if "keys" not in data:
        raise VerificationError(ERR_REVOCATION_SCHEMA, "Missing required field: keys")

    # Validate version
    version = data["version"]
    if not isinstance(version, int) or version < 1:
        raise VerificationError(ERR_REVOCATION_SCHEMA, f"Invalid version: {version}")

    # Validate generated_at timestamp
    generated_at = data["generated_at"]
    if not isinstance(generated_at, str) or not TIMESTAMP_PATTERN.match(generated_at):
        raise VerificationError(
            ERR_REVOCATION_SCHEMA,
            f"Invalid generated_at timestamp: {generated_at} (expected ISO8601 UTC with Z suffix)",
        )

    # Validate authority
    authority = data["authority"]
    if not isinstance(authority, str) or not authority.strip():
        raise VerificationError(
            ERR_REVOCATION_SCHEMA, "Invalid authority: must be non-empty string"
        )

    # Validate keys array
    keys_data = data["keys"]
    if not isinstance(keys_data, list):
        raise VerificationError(ERR_REVOCATION_SCHEMA, "keys must be an array")

    keys: list[KeyEntry] = []
    for i, key_data in enumerate(keys_data):
        if not isinstance(key_data, dict):
            raise VerificationError(ERR_REVOCATION_SCHEMA, f"keys[{i}] must be an object")

        # Validate required key fields
        if "derived_key_id" not in key_data:
            raise VerificationError(
                ERR_REVOCATION_SCHEMA,
                f"keys[{i}] missing required field: derived_key_id",
            )
        if "fingerprint_sha256" not in key_data:
            raise VerificationError(
                ERR_REVOCATION_SCHEMA,
                f"keys[{i}] missing required field: fingerprint_sha256",
            )
        if "status" not in key_data:
            raise VerificationError(
                ERR_REVOCATION_SCHEMA,
                f"keys[{i}] missing required field: status",
            )

        # Validate derived_key_id format
        derived_key_id = key_data["derived_key_id"]
        if not isinstance(derived_key_id, str) or not KEY_ID_PATTERN.match(derived_key_id):
            raise VerificationError(
                ERR_REVOCATION_SCHEMA,
                f"keys[{i}].derived_key_id invalid format: {derived_key_id} "
                "(expected spk-<16 hex chars>)",
            )

        # Validate fingerprint_sha256 format
        fingerprint = key_data["fingerprint_sha256"]
        if not isinstance(fingerprint, str) or not HEX64_PATTERN.match(fingerprint):
            raise VerificationError(
                ERR_REVOCATION_SCHEMA,
                f"keys[{i}].fingerprint_sha256 invalid format: must be 64 lowercase hex chars",
            )

        # Validate derived_key_id matches fingerprint
        expected_key_id = f"spk-{fingerprint[:16]}"
        if derived_key_id != expected_key_id:
            raise VerificationError(
                ERR_REVOCATION_SCHEMA,
                f"keys[{i}].derived_key_id mismatch: {derived_key_id} "
                f"vs expected {expected_key_id}",
            )

        # Validate status
        status = key_data["status"]
        if status not in VALID_KEY_STATUSES:
            raise VerificationError(
                ERR_REVOCATION_SCHEMA,
                f"keys[{i}].status invalid: {status} (expected: {', '.join(VALID_KEY_STATUSES)})",
            )

        # Validate optional effective_at
        effective_at = key_data.get("effective_at")
        if effective_at is not None:
            if not isinstance(effective_at, str) or not TIMESTAMP_PATTERN.match(effective_at):
                raise VerificationError(
                    ERR_REVOCATION_SCHEMA,
                    f"keys[{i}].effective_at invalid format: {effective_at}",
                )

        keys.append(
            KeyEntry(
                derived_key_id=derived_key_id,
                fingerprint_sha256=fingerprint,
                status=status,
                status_reason=key_data.get("status_reason"),
                effective_at=effective_at,
            )
        )

    return RevocationList(
        version=version,
        generated_at=generated_at,
        authority=authority,
        keys=keys,
    )


def check_key_trust(
    revocation_list: RevocationList | None,
    key_id: str | None = None,
    fingerprint: str | None = None,
    require_trusted_key: bool = False,
) -> TrustCheckResult:
    """Check the trust status of a key against a revocation list.

    Args:
        revocation_list: Loaded revocation list (or None if not provided)
        key_id: Derived key ID (spk-...)
        fingerprint: Full SHA-256 fingerprint
        require_trusted_key: If True, require key to be explicitly active

    Returns:
        TrustCheckResult with trust decision

    Behavior:
        - No revocation list: trusted=True, warning="No revocation list provided"
        - ACTIVE: trusted=True
        - RETIRED: trusted=True (warn), or trusted=False if require_trusted_key
        - REVOKED: trusted=False (error)
        - UNKNOWN: trusted=True (warn), or trusted=False if require_trusted_key
    """
    # No revocation list provided
    if revocation_list is None:
        return TrustCheckResult(
            key_status=KEY_STATUS_UNKNOWN,
            revocation_list_provided=False,
            require_trusted_key=require_trusted_key,
            trusted=True,
            warning="No revocation list provided - key trust not verified",
        )

    # Look up the key
    entry = revocation_list.lookup(key_id, fingerprint)
    status = entry.status if entry else KEY_STATUS_UNKNOWN

    # Determine trust based on status
    if status == KEY_STATUS_ACTIVE:
        return TrustCheckResult(
            key_status=KEY_STATUS_ACTIVE,
            revocation_list_provided=True,
            require_trusted_key=require_trusted_key,
            trusted=True,
            entry=entry,
        )

    if status == KEY_STATUS_RETIRED:
        if require_trusted_key:
            return TrustCheckResult(
                key_status=KEY_STATUS_RETIRED,
                revocation_list_provided=True,
                require_trusted_key=require_trusted_key,
                trusted=False,
                error="Key is retired and --require-trusted-key is set",
                entry=entry,
            )
        return TrustCheckResult(
            key_status=KEY_STATUS_RETIRED,
            revocation_list_provided=True,
            require_trusted_key=require_trusted_key,
            trusted=True,
            warning="Key is retired - consider using a newer key for new signatures",
            entry=entry,
        )

    if status == KEY_STATUS_REVOKED:
        reason = entry.status_reason if entry else "unknown"
        return TrustCheckResult(
            key_status=KEY_STATUS_REVOKED,
            revocation_list_provided=True,
            require_trusted_key=require_trusted_key,
            trusted=False,
            error=f"Key has been revoked: {reason}",
            entry=entry,
        )

    # Unknown key
    if require_trusted_key:
        return TrustCheckResult(
            key_status=KEY_STATUS_UNKNOWN,
            revocation_list_provided=True,
            require_trusted_key=require_trusted_key,
            trusted=False,
            error="Key not found in revocation list and --require-trusted-key is set",
        )
    return TrustCheckResult(
        key_status=KEY_STATUS_UNKNOWN,
        revocation_list_provided=True,
        require_trusted_key=require_trusted_key,
        trusted=True,
        warning="Key not found in revocation list - trust unknown",
    )
