"""Exit codes and error definitions for specora-verify.

Exit code contract (RCP-96):
- 0: PASS - Verification succeeded
- 1: WARN - Non-fatal issues detected (e.g., retired key, unknown key trust)
- 2: FAIL - Verification failed (hash mismatch, invalid structure, revoked key)
- 3: ERROR - Operational error (file not found, parse error, etc.)

CI Mode:
- With --ci flag, WARN (1) is mapped to FAIL (2) for pipeline compatibility.
- This ensures any non-zero "warning" exits as failure in automated contexts.
"""

from __future__ import annotations

# Exit codes matching CI convention
EXIT_PASS = 0
EXIT_WARN = 1  # Warning-level issues (retired key, unknown trust)
EXIT_FAIL = 2
EXIT_ERROR = 3


def map_exit_code_for_ci(exit_code: int, ci_mode: bool) -> int:
    """Map exit code for CI mode.

    In CI mode, WARN (1) is mapped to FAIL (2) so pipelines treat
    any non-zero as failure.

    Args:
        exit_code: Original exit code
        ci_mode: Whether CI mode is enabled

    Returns:
        Mapped exit code
    """
    if ci_mode and exit_code == EXIT_WARN:
        return EXIT_FAIL
    return exit_code


def exit_code_name(exit_code: int) -> str:
    """Get human-readable name for exit code."""
    return {
        EXIT_PASS: "PASS",
        EXIT_WARN: "WARN",
        EXIT_FAIL: "FAIL",
        EXIT_ERROR: "ERROR",
    }.get(exit_code, "UNKNOWN")


class VerificationError(Exception):
    """Base exception for verification errors."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class FileNotFoundError(VerificationError):
    """Input file does not exist."""

    def __init__(self, path: str) -> None:
        super().__init__("FILE_NOT_FOUND", f"File not found: {path}")
        self.path = path


class ParseError(VerificationError):
    """JSON parse failure."""

    def __init__(self, path: str, detail: str) -> None:
        super().__init__("PARSE_ERROR", f"Failed to parse {path}: {detail}")
        self.path = path
        self.detail = detail


class MissingFieldError(VerificationError):
    """Required field missing from manifest."""

    def __init__(self, field: str, spec_id: str) -> None:
        super().__init__(
            "MISSING_FIELD",
            f"Required field '{field}' missing for {spec_id}",
        )
        self.field = field
        self.spec_id = spec_id


class TypeValidationError(VerificationError):
    """Field type constraint violation."""

    def __init__(self, field: str, expected: str, actual: str) -> None:
        super().__init__(
            "TYPE_ERROR",
            f"Field '{field}' expected {expected}, got {actual}",
        )
        self.field = field
        self.expected = expected
        self.actual = actual


class HashMismatchError(VerificationError):
    """Computed hash differs from expected."""

    def __init__(self, computed: str, expected: str) -> None:
        super().__init__(
            "HASH_MISMATCH",
            f"Hash mismatch: computed {computed}, expected {expected}",
        )
        self.computed = computed
        self.expected = expected


class UnknownContractError(VerificationError):
    """Unrecognized spec_id or schema version."""

    def __init__(self, spec_id: str, version: str) -> None:
        super().__init__(
            "UNKNOWN_CONTRACT",
            f"Unknown manifest contract: {spec_id} v{version}",
        )
        self.spec_id = spec_id
        self.version = version


class ZipMalformedError(VerificationError):
    """Invalid ZIP structure."""

    def __init__(self, detail: str) -> None:
        super().__init__("ZIP_MALFORMED", f"Malformed ZIP bundle: {detail}")
        self.detail = detail
