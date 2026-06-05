"""Tests for anchor golden vector verification (RCP-100)."""

from __future__ import annotations

from pathlib import Path

import pytest

from specora_verify.canonical import canonical_json_bytes
from specora_verify.hash import sha256_hex
from specora_verify.validators.anchor import (
    verify_anchor_vectors,
    verify_single_anchor_vector,
)

# Path to anchor vectors
ANCHOR_VECTORS_DIR = Path(__file__).parent.parent / "vectors" / "anchor"


class TestAnchorVectorParity:
    """RCP-100: Anchor vector parity tests."""

    def test_anchor_vectors_exist(self) -> None:
        """Anchor vectors directory must exist."""
        assert ANCHOR_VECTORS_DIR.exists(), f"Vectors directory not found: {ANCHOR_VECTORS_DIR}"

    def test_anchor_payload_v1_vector_exists(self) -> None:
        """anchor-payload-1.0.0 vector files must exist."""
        if not ANCHOR_VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {ANCHOR_VECTORS_DIR}")

        assert (ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.json").exists()
        assert (ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.canonical.json").exists()
        assert (ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.sha256.txt").exists()

    def test_anchor_payload_v1_bytes_parity(self) -> None:
        """Canonical bytes must match golden vector exactly."""
        if not ANCHOR_VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {ANCHOR_VECTORS_DIR}")

        import json

        # Load payload
        payload_file = ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.json"
        payload = json.loads(payload_file.read_text(encoding="utf-8"))

        # Load expected canonical bytes
        canonical_file = ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.canonical.json"
        expected_bytes = canonical_file.read_bytes()

        # Compute our canonical bytes
        computed_bytes = canonical_json_bytes(payload)

        assert computed_bytes == expected_bytes, (
            f"Canonical bytes mismatch. "
            f"Computed {len(computed_bytes)} bytes, expected {len(expected_bytes)} bytes."
        )

    def test_anchor_payload_v1_hash_parity(self) -> None:
        """SHA-256 hash must match golden vector exactly."""
        if not ANCHOR_VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {ANCHOR_VECTORS_DIR}")

        import json

        # Load payload
        payload_file = ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.json"
        payload = json.loads(payload_file.read_text(encoding="utf-8"))

        # Load expected hash
        sha256_file = ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.sha256.txt"
        expected_hash = sha256_file.read_text(encoding="utf-8").strip()

        # Compute our hash
        computed_bytes = canonical_json_bytes(payload)
        computed_hash = sha256_hex(computed_bytes)

        assert computed_hash == expected_hash, (
            f"Hash mismatch. Computed {computed_hash}, expected {expected_hash}"
        )


class TestVerifyAnchorVectors:
    """Tests for verify_anchor_vectors function."""

    def test_verify_anchor_vectors_pass(self) -> None:
        """verify_anchor_vectors must pass with valid vectors."""
        if not ANCHOR_VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {ANCHOR_VECTORS_DIR}")

        result = verify_anchor_vectors(ANCHOR_VECTORS_DIR)

        assert result.valid
        assert result.total == 1
        assert result.passed == 1
        assert result.failed == 0
        assert len(result.results) == 1
        assert result.results[0].spec_id == "anchor-payload"
        assert result.results[0].version == "1.0.0"

    def test_verify_single_anchor_vector_pass(self) -> None:
        """verify_single_anchor_vector must pass for valid vector."""
        if not ANCHOR_VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {ANCHOR_VECTORS_DIR}")

        result = verify_single_anchor_vector(ANCHOR_VECTORS_DIR, "anchor-payload", "1.0.0")

        assert result.valid
        assert result.bytes_match
        assert result.hash_match
        assert len(result.errors) == 0

    def test_verify_anchor_vectors_missing_dir(self, tmp_path: Path) -> None:
        """verify_anchor_vectors must fail for missing directory."""
        nonexistent = tmp_path / "nonexistent"

        result = verify_anchor_vectors(nonexistent)

        assert not result.valid
        assert "not found" in result.errors[0].lower()


class TestAnchorVectorDeterminism:
    """Tests for anchor hash determinism (RCP-98)."""

    def test_same_payload_same_hash(self) -> None:
        """Same anchor payload must produce same hash."""
        if not ANCHOR_VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {ANCHOR_VECTORS_DIR}")

        import json

        payload_file = ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.json"
        payload = json.loads(payload_file.read_text(encoding="utf-8"))

        hash1 = sha256_hex(canonical_json_bytes(payload))
        hash2 = sha256_hex(canonical_json_bytes(payload))

        assert hash1 == hash2

    def test_reloaded_payload_same_hash(self) -> None:
        """Reloading payload from JSON must produce same hash."""
        if not ANCHOR_VECTORS_DIR.exists():
            pytest.skip(f"Vectors directory not found: {ANCHOR_VECTORS_DIR}")

        import json

        payload_file = ANCHOR_VECTORS_DIR / "anchor-payload-1.0.0.json"

        # Load twice
        payload1 = json.loads(payload_file.read_text(encoding="utf-8"))
        payload2 = json.loads(payload_file.read_text(encoding="utf-8"))

        hash1 = sha256_hex(canonical_json_bytes(payload1))
        hash2 = sha256_hex(canonical_json_bytes(payload2))

        assert hash1 == hash2
