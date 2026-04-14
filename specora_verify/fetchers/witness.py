"""Witness statement fetching (PR-ENT-550).

Loads witness statements from local files or directories.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class WitnessStatementFetchResult:
    """Result of fetching a witness statement."""

    success: bool
    witness_org_id: str | None = None
    statement: dict[str, Any] | None = None
    error: str | None = None
    fetch_latency_ms: int = 0
    source_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "witness_org_id": self.witness_org_id,
            "statement": self.statement,
            "error": self.error,
            "fetch_latency_ms": self.fetch_latency_ms,
            "source_path": self.source_path,
        }


def load_local_witness_statement(path: Path | str) -> WitnessStatementFetchResult:
    """Load witness statement from local JSON file.

    Args:
        path: Path to the witness statement JSON file

    Returns:
        WitnessStatementFetchResult with statement data or error
    """
    if isinstance(path, str):
        path = Path(path)

    start_time = time.monotonic()

    if not path.exists():
        return WitnessStatementFetchResult(
            success=False,
            error=f"File not found: {path}",
            source_path=str(path),
        )

    try:
        content = path.read_text(encoding="utf-8")
        statement = json.loads(content)
    except json.JSONDecodeError as e:
        return WitnessStatementFetchResult(
            success=False,
            error=f"Failed to parse JSON: {e}",
            source_path=str(path),
            fetch_latency_ms=int((time.monotonic() - start_time) * 1000),
        )
    except Exception as e:
        return WitnessStatementFetchResult(
            success=False,
            error=f"Failed to read file: {e}",
            source_path=str(path),
            fetch_latency_ms=int((time.monotonic() - start_time) * 1000),
        )

    # Extract witness_org_id if present
    witness_org_id = statement.get("witness_org_id")

    return WitnessStatementFetchResult(
        success=True,
        witness_org_id=witness_org_id,
        statement=statement,
        source_path=str(path),
        fetch_latency_ms=int((time.monotonic() - start_time) * 1000),
    )


def load_local_witness_statements_dir(
    directory: Path | str,
    pattern: str = "*.json",
) -> list[WitnessStatementFetchResult]:
    """Load all witness statements from a directory.

    Args:
        directory: Directory containing witness statement JSON files
        pattern: Glob pattern for files to load (default: *.json)

    Returns:
        List of WitnessStatementFetchResult for each file
    """
    if isinstance(directory, str):
        directory = Path(directory)

    if not directory.exists():
        return [
            WitnessStatementFetchResult(
                success=False,
                error=f"Directory not found: {directory}",
                source_path=str(directory),
            )
        ]

    if not directory.is_dir():
        return [
            WitnessStatementFetchResult(
                success=False,
                error=f"Not a directory: {directory}",
                source_path=str(directory),
            )
        ]

    results: list[WitnessStatementFetchResult] = []

    for file_path in sorted(directory.glob(pattern)):
        if file_path.is_file():
            result = load_local_witness_statement(file_path)
            results.append(result)

    return results
