"""Verification receipt generation.

This module generates machine-readable verification receipts that auditors
can archive as proof of verification. Receipts capture:

- Tool version and environment
- Canonicalization policy used
- Hash and signature verification results
- Public key fingerprint and derived key_id
- Timestamp and exit status

Receipts are deterministic except for the verified_at timestamp field.
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from specora_verify import __version__
from specora_verify.canonical import canonical_json_bytes
from specora_verify.fingerprint import compute_key_fingerprint, derive_key_id
from specora_verify.hash import sha256_hex

# Canonicalization policy (must match canonical.py implementation)
CANONICALIZATION_POLICY = {
    "sort_keys": True,
    "separators": [",", ":"],
    "ensure_ascii": True,
    "encoding": "utf-8",
}


@dataclass
class ToolInfo:
    """Information about the verification tool."""

    name: str = "specora-verify"
    version: str = __version__
    python: str = field(default_factory=lambda: platform.python_version())
    crypto_backend: str = "none"
    build: dict[str, str | None] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "python": self.python,
            "crypto_backend": self.crypto_backend,
            "build": self.build,
        }


@dataclass
class HashInfo:
    """Hash computation result."""

    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"sha256": self.sha256}


@dataclass
class SignatureInfo:
    """Signature verification result."""

    algo: str = "ed25519"
    covers: str = "manifest_hash_utf8"
    valid: bool | None = None  # None if crypto not available

    def to_dict(self) -> dict[str, Any]:
        return {
            "algo": self.algo,
            "covers": self.covers,
            "valid": self.valid,
        }


@dataclass
class PublicKeyInfo:
    """Public key information."""

    format: str | None = None
    fingerprint_sha256: str | None = None
    derived_key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "fingerprint_sha256": self.fingerprint_sha256,
            "derived_key_id": self.derived_key_id,
        }


@dataclass
class TrustInfo:
    """Key trust verification information."""

    revocation_list_provided: bool = False
    key_status: str = "unknown"  # active, retired, revoked, unknown
    require_trusted_key: bool = False
    trusted: bool = True
    warning: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
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
        return result


@dataclass
class VerificationInfo:
    """Complete verification information."""

    type: str  # "artifact" or "bundle"
    canonicalization: dict[str, Any] = field(default_factory=lambda: CANONICALIZATION_POLICY.copy())
    hash: HashInfo | None = None
    signature: SignatureInfo | None = None
    public_key: PublicKeyInfo | None = None
    trust: TrustInfo | None = None
    result: str = "FAIL"  # "PASS", "WARN", or "FAIL"
    errors: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": self.type,
            "canonicalization": self.canonicalization,
            "hash": self.hash.to_dict() if self.hash else None,
            "signature": self.signature.to_dict() if self.signature else None,
            "public_key": self.public_key.to_dict() if self.public_key else None,
            "result": self.result,
            "errors": self.errors,
        }
        if self.trust:
            result["trust"] = self.trust.to_dict()
        return result


@dataclass
class VerificationReceipt:
    """Complete verification receipt."""

    tool: ToolInfo
    verification: VerificationInfo
    verified_at: str = field(
        default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool.to_dict(),
            "verification": self.verification.to_dict(),
            "verified_at": self.verified_at,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize receipt to JSON."""
        return json.dumps(self.to_dict(), indent=indent)


def _detect_crypto_backend() -> str:
    """Detect which cryptography backend is available."""
    try:
        import cryptography

        return f"cryptography-{cryptography.__version__}"
    except ImportError:
        pass

    try:
        import nacl

        return f"pynacl-{nacl.__version__}"
    except ImportError:
        pass

    return "none"


def _get_tool_info() -> ToolInfo:
    """Get current tool information."""
    return ToolInfo(
        name="specora-verify",
        version=__version__,
        python=platform.python_version(),
        crypto_backend=_detect_crypto_backend(),
        build={},
    )


def generate_artifact_receipt(
    artifact: dict[str, Any],
    signature_b64: str | None = None,
    public_key_data: str | bytes | None = None,
    public_key_format: str = "auto",
    allow_hash_only: bool = False,
    trust_result: Any = None,
) -> VerificationReceipt:
    """Generate a verification receipt for an artifact.

    Args:
        artifact: The artifact dictionary to verify
        signature_b64: Optional base64-encoded signature
        public_key_data: Optional public key data (PEM, base64, or raw)
        public_key_format: Key format hint ("pem", "base64", "raw", "auto")
        allow_hash_only: If True, allow PASS result for hash-only verification
        trust_result: Optional TrustCheckResult from revocation check

    Returns:
        VerificationReceipt with complete verification details
    """
    tool_info = _get_tool_info()
    errors: list[dict[str, str]] = []

    # Compute hash
    canonical_bytes = canonical_json_bytes(artifact)
    artifact_hash = sha256_hex(canonical_bytes)

    # Convert trust_result to TrustInfo if provided
    trust_info = None
    if trust_result:
        trust_info = TrustInfo(
            revocation_list_provided=trust_result.revocation_list_provided,
            key_status=trust_result.key_status,
            require_trusted_key=trust_result.require_trusted_key,
            trusted=trust_result.trusted,
            warning=trust_result.warning,
            error=trust_result.error,
        )

    verification = VerificationInfo(
        type="artifact",
        hash=HashInfo(sha256=artifact_hash),
        trust=trust_info,
    )

    # Check if we have signature verification inputs
    has_signature_inputs = signature_b64 is not None and public_key_data is not None

    if has_signature_inputs:
        # Attempt signature verification
        try:
            from specora_verify.signature import (
                is_crypto_available,
                load_public_key,
                verify_signature,
            )

            if not is_crypto_available():
                verification.signature = SignatureInfo(valid=None)
                verification.public_key = PublicKeyInfo(format=public_key_format)
                errors.append(
                    {
                        "code": "CRYPTO_MISSING",
                        "message": "Cryptography library not available for signature verification",
                    }
                )
            else:
                # Load public key and get info
                pub_key = load_public_key(public_key_data, public_key_format)

                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

                raw_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
                fingerprint = compute_key_fingerprint(raw_bytes)
                derived_id = derive_key_id(fingerprint)

                # Detect key format
                if isinstance(public_key_data, str) and public_key_data.startswith("-----BEGIN"):
                    detected_format = "pem"
                elif isinstance(public_key_data, bytes) and len(public_key_data) == 32:
                    detected_format = "raw32"
                else:
                    detected_format = "base64"

                verification.public_key = PublicKeyInfo(
                    format=detected_format,
                    fingerprint_sha256=fingerprint,
                    derived_key_id=derived_id,
                )

                # Verify signature
                result = verify_signature(
                    manifest_hash=artifact_hash,
                    signature_b64=signature_b64,
                    public_key=pub_key,
                )

                verification.signature = SignatureInfo(
                    algo="ed25519",
                    covers="manifest_hash_utf8",
                    valid=result.valid,
                )

                if result.valid:
                    # Determine result based on signature and trust
                    if trust_info and not trust_info.trusted:
                        verification.result = "FAIL"
                        if trust_info.error:
                            errors.append({"code": "KEY_TRUST_FAILED", "message": trust_info.error})
                    elif trust_info and trust_info.warning:
                        verification.result = "WARN"
                    else:
                        verification.result = "PASS"
                else:
                    for err in result.errors:
                        errors.append({"code": "SIGNATURE_INVALID", "message": err})

        except Exception as e:
            verification.signature = SignatureInfo(valid=False)
            errors.append({"code": "VERIFICATION_ERROR", "message": str(e)})
    else:
        # Hash-only verification
        if allow_hash_only:
            verification.result = "PASS"
            verification.signature = None
            verification.public_key = None
        else:
            errors.append(
                {
                    "code": "SIGNATURE_MISSING",
                    "message": "No signature or public key provided. Use --allow-hash-only for hash-only verification.",
                }
            )

    verification.errors = errors

    return VerificationReceipt(
        tool=tool_info,
        verification=verification,
    )


def generate_bundle_receipt(
    manifest: dict[str, Any],
    public_key_data: str | bytes | None = None,
    public_key_format: str = "auto",
) -> VerificationReceipt:
    """Generate a verification receipt for a bundle manifest.

    Bundle verification checks manifest structure and component hashes.
    Signature verification is optional if public_key_data is provided.

    Args:
        manifest: The manifest dictionary
        public_key_data: Optional public key data for signature verification
        public_key_format: Key format hint

    Returns:
        VerificationReceipt with complete verification details
    """
    tool_info = _get_tool_info()
    errors: list[dict[str, str]] = []

    # Compute manifest hash
    canonical_bytes = canonical_json_bytes(manifest)
    manifest_hash = sha256_hex(canonical_bytes)

    verification = VerificationInfo(
        type="bundle",
        hash=HashInfo(sha256=manifest_hash),
    )

    # Check manifest structure
    if "signing" in manifest:
        signing = manifest["signing"]
        signature_b64 = signing.get("signature_b64")
        manifest_sha256 = signing.get("manifest_sha256")

        # Verify internal hash matches
        if manifest_sha256:
            # Compute hash of manifest excluding signing block
            manifest_for_hash = {k: v for k, v in manifest.items() if k != "signing"}
            computed = sha256_hex(canonical_json_bytes(manifest_for_hash))
            if computed != manifest_sha256:
                errors.append(
                    {
                        "code": "HASH_MISMATCH",
                        "message": f"Manifest hash mismatch: computed {computed}, declared {manifest_sha256}",
                    }
                )

        # Verify signature if key provided
        if public_key_data and signature_b64:
            try:
                from specora_verify.signature import (
                    is_crypto_available,
                    load_public_key,
                    verify_signature,
                )

                if not is_crypto_available():
                    verification.signature = SignatureInfo(valid=None)
                    errors.append(
                        {
                            "code": "CRYPTO_MISSING",
                            "message": "Cryptography library not available",
                        }
                    )
                else:
                    pub_key = load_public_key(public_key_data, public_key_format)

                    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

                    raw_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
                    fingerprint = compute_key_fingerprint(raw_bytes)
                    derived_id = derive_key_id(fingerprint)

                    if isinstance(public_key_data, str) and public_key_data.startswith(
                        "-----BEGIN"
                    ):
                        detected_format = "pem"
                    elif isinstance(public_key_data, bytes) and len(public_key_data) == 32:
                        detected_format = "raw32"
                    else:
                        detected_format = "base64"

                    verification.public_key = PublicKeyInfo(
                        format=detected_format,
                        fingerprint_sha256=fingerprint,
                        derived_key_id=derived_id,
                    )

                    # Use manifest_sha256 as the signed hash
                    hash_to_verify = manifest_sha256 or manifest_hash
                    result = verify_signature(
                        manifest_hash=hash_to_verify,
                        signature_b64=signature_b64,
                        public_key=pub_key,
                    )

                    verification.signature = SignatureInfo(
                        algo="ed25519",
                        covers="manifest_hash_utf8",
                        valid=result.valid,
                    )

                    if not result.valid:
                        for err in result.errors:
                            errors.append({"code": "SIGNATURE_INVALID", "message": err})

            except Exception as e:
                verification.signature = SignatureInfo(valid=False)
                errors.append({"code": "VERIFICATION_ERROR", "message": str(e)})

    # Determine overall result
    if not errors:
        verification.result = "PASS"
    else:
        verification.result = "FAIL"

    verification.errors = errors

    return VerificationReceipt(
        tool=tool_info,
        verification=verification,
    )
