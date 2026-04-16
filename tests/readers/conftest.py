"""Shared fixtures for reader tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def anthropic_fixture_dir() -> Path:
    return FIXTURE_ROOT / "anthropic"


@pytest.fixture
def anthropic_minimal(anthropic_fixture_dir: Path) -> Path:
    return anthropic_fixture_dir / "minimal-valid.jsonl"


@pytest.fixture
def anthropic_complex(anthropic_fixture_dir: Path) -> Path:
    return anthropic_fixture_dir / "realistic-complex.jsonl"


@pytest.fixture
def anthropic_malformed(anthropic_fixture_dir: Path) -> Path:
    return anthropic_fixture_dir / "malformed.jsonl"


@pytest.fixture
def anthropic_public_key(anthropic_fixture_dir: Path) -> Path:
    return anthropic_fixture_dir / "keys" / "public.hex"


@pytest.fixture
def cloudtrail_fixture_dir() -> Path:
    return FIXTURE_ROOT / "cloudtrail"


@pytest.fixture
def cloudtrail_minimal(cloudtrail_fixture_dir: Path) -> Path:
    return cloudtrail_fixture_dir / "minimal-valid.json"


@pytest.fixture
def cloudtrail_complex(cloudtrail_fixture_dir: Path) -> Path:
    return cloudtrail_fixture_dir / "realistic-complex.json"


@pytest.fixture
def cloudtrail_malformed(cloudtrail_fixture_dir: Path) -> Path:
    return cloudtrail_fixture_dir / "malformed.json"


@pytest.fixture
def azure_cl_fixture_dir() -> Path:
    return FIXTURE_ROOT / "azure_cl"


@pytest.fixture
def azure_cl_minimal(azure_cl_fixture_dir: Path) -> Path:
    return azure_cl_fixture_dir / "minimal-valid.json"


@pytest.fixture
def azure_cl_complex(azure_cl_fixture_dir: Path) -> Path:
    return azure_cl_fixture_dir / "realistic-complex.json"


@pytest.fixture
def azure_cl_malformed(azure_cl_fixture_dir: Path) -> Path:
    return azure_cl_fixture_dir / "malformed.json"


@pytest.fixture
def openai_fixture_dir() -> Path:
    return FIXTURE_ROOT / "openai_compliance"


@pytest.fixture
def openai_minimal(openai_fixture_dir: Path) -> Path:
    return openai_fixture_dir / "minimal-valid.json"


@pytest.fixture
def openai_complex(openai_fixture_dir: Path) -> Path:
    return openai_fixture_dir / "realistic-complex.jsonl"


@pytest.fixture
def openai_malformed(openai_fixture_dir: Path) -> Path:
    return openai_fixture_dir / "malformed.json"
