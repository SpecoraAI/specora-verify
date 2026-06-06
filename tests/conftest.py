"""Pytest fixtures for specora-verify tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def vectors_dir() -> Path:
    """Path to golden vectors directory."""
    return Path(__file__).parent.parent / "specora_verify" / "vectors" / "manifest"


@pytest.fixture
def sample_proof_manifest() -> dict:
    """Sample proof manifest for testing."""
    return {
        "id": "e3e817d2-0a81-4ebc-81b8-6a3f12b7a9f1",
        "org_id": "c16922ef-95de-4d43-ac62-a279fac7e14f",
        "root_type": "daily",
        "root_hash": "a4d31481f3caafb2cc89bdf11f422eb1cf658603672d2fb4ab21dcba67d3e6ba",
        "leaf_count": 4250,
        "period_start": "2026-03-01T00:00:00Z",
        "period_end": "2026-03-01T23:59:59Z",
        "created_at": "2026-03-02T01:15:30Z",
    }


@pytest.fixture
def sample_attestation_manifest() -> dict:
    """Sample attestation manifest for testing."""
    return {
        "id": "f5168aa6-8d59-4b61-9c17-98e3b5e406f8",
        "org_id": "c16922ef-95de-4d43-ac62-a279fac7e14f",
        "snapshot_type": "window",
        "period_start": "2026-02-01T00:00:00Z",
        "period_end": "2026-02-28T23:59:59Z",
        "created_at": "2026-03-01T10:00:00Z",
    }
