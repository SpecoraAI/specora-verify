"""Golden vector verification tests.

RCP-95 enforcement: The verifier must pass golden vector parity tests.
These tests verify byte-identical canonical output and matching SHA-256 hashes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from specora_verify.canonical import canonical_json_bytes
from specora_verify.hash import sha256_hex
from specora_verify.validators.vectors import verify_single_vector, verify_vectors


# Path to golden vectors
VECTORS_DIR = Path(__file__).parent.parent / "vectors" / "manifest"


class TestGoldenVectorParity:
    """RCP-95: Golden vector parity tests."""

    @pytest.mark.parametrize(
        "spec_id,version",
        [
            ("proof-manifest", "1.0.0"),
            ("attestation-manifest", "1.0.0"),
        ],
    )
    def test_canonical_bytes_match_golden_vector(
        self,
        spec_id: str,
        version: str,
    ) -> None:
        """Canonical bytes must exactly match published vectors."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        # Load vector files
        json_file = VECTORS_DIR / f"{spec_id}-{version}.json"
        canonical_file = VECTORS_DIR / f"{spec_id}-{version}.canonical.json"
        sha256_file = VECTORS_DIR / f"{spec_id}-{version}.sha256.txt"

        if not json_file.exists():
            pytest.skip(f"Vector file not found: {json_file}")

        # Parse payload
        payload = json.loads(json_file.read_text(encoding="utf-8"))

        # Load expected canonical bytes
        expected_bytes = canonical_file.read_bytes()

        # Load expected hash
        expected_hash = sha256_file.read_text(encoding="utf-8").strip()

        # Compute canonical bytes and hash
        actual_bytes = canonical_json_bytes(payload)
        actual_hash = sha256_hex(actual_bytes)

        # Verify byte-for-byte parity
        assert actual_bytes == expected_bytes, (
            f"Canonical bytes mismatch for {spec_id} v{version}.\n"
            f"Expected: {expected_bytes!r}\n"
            f"Actual:   {actual_bytes!r}"
        )

        # Verify hash parity
        assert actual_hash == expected_hash, (
            f"Hash mismatch for {spec_id} v{version}.\n"
            f"Expected: {expected_hash}\n"
            f"Actual:   {actual_hash}"
        )

    def test_proof_manifest_known_hash(self) -> None:
        """Proof manifest v1.0.0 must produce known hash."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        json_file = VECTORS_DIR / "proof-manifest-1.0.0.json"
        if not json_file.exists():
            pytest.skip(f"Vector file not found: {json_file}")

        payload = json.loads(json_file.read_text(encoding="utf-8"))
        actual_hash = sha256_hex(canonical_json_bytes(payload))

        # Known hash from golden vector
        expected_hash = "4e4cd3656219d8d8b52e75c94f20ce03f2ee592e71d8d6f49c17facfdbf960af"
        assert actual_hash == expected_hash


class TestVerifyVectorsFunction:
    """Tests for verify_vectors() function."""

    def test_verify_all_vectors_pass(self) -> None:
        """verify_vectors() must pass for all known vectors."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        result = verify_vectors(VECTORS_DIR)

        assert result.valid, f"Vector verification failed: {result.errors}"
        assert result.total >= 2
        assert result.passed == result.total
        assert result.failed == 0

    def test_verify_single_vector(self) -> None:
        """verify_single_vector() must work for individual vectors."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        result = verify_single_vector(VECTORS_DIR, "proof-manifest", "1.0.0")

        assert result.valid
        assert result.bytes_match
        assert result.hash_match
        assert result.computed_hash == result.expected_hash

    def test_missing_vectors_directory(self, tmp_path: Path) -> None:
        """Missing vectors directory must fail gracefully."""
        nonexistent = tmp_path / "nonexistent"
        result = verify_vectors(nonexistent)

        assert not result.valid
        assert "not found" in result.errors[0].lower()


class TestVectorFileIntegrity:
    """Tests for vector file integrity."""

    def test_all_vector_files_exist(self) -> None:
        """All expected vector files must exist."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        expected_files = [
            "proof-manifest-1.0.0.json",
            "proof-manifest-1.0.0.canonical.json",
            "proof-manifest-1.0.0.sha256.txt",
            "attestation-manifest-1.0.0.json",
            "attestation-manifest-1.0.0.canonical.json",
            "attestation-manifest-1.0.0.sha256.txt",
        ]

        for filename in expected_files:
            filepath = VECTORS_DIR / filename
            assert filepath.exists(), f"Missing vector file: {filepath}"

    def test_sha256_files_format(self) -> None:
        """SHA-256 files must contain valid 64-char hex strings."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        sha_files = list(VECTORS_DIR.glob("*.sha256.txt"))
        assert len(sha_files) >= 2

        for sha_file in sha_files:
            content = sha_file.read_text(encoding="utf-8").strip()
            assert len(content) == 64, f"Invalid hash length in {sha_file}: {len(content)}"
            assert all(c in "0123456789abcdef" for c in content), (
                f"Invalid hex characters in {sha_file}"
            )

    def test_canonical_files_are_valid_json(self) -> None:
        """Canonical files must be valid JSON."""
        if not VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {VECTORS_DIR}")

        canonical_files = list(VECTORS_DIR.glob("*.canonical.json"))
        assert len(canonical_files) >= 2

        for canonical_file in canonical_files:
            content = canonical_file.read_bytes()
            # Must be valid JSON
            parsed = json.loads(content)
            assert isinstance(parsed, dict)
            # Must have no trailing newline
            assert not content.endswith(b"\n"), f"Trailing newline in {canonical_file}"
