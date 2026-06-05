"""Registry snapshot fetchers (PR-ENT-560).

This module provides functions to load registry snapshots from local files
and directories. Follows offline-first design for auditor workflows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from specora_verify.errors import VerificationError
from specora_verify.validators.registry import (
    RegistrySnapshot,
    parse_registry_snapshot,
)


@dataclass
class SnapshotFetchResult:
    """Result of fetching a registry snapshot."""

    success: bool
    registry_version: int | None = None
    snapshot: RegistrySnapshot | None = None
    raw_data: dict[str, Any] | None = None
    file_path: str | None = None
    error: str | None = None
    fetch_latency_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "registry_version": self.registry_version,
            "file_path": self.file_path,
            "error": self.error,
            "fetch_latency_ms": self.fetch_latency_ms,
        }


def load_local_registry_snapshot(path: Path | str) -> SnapshotFetchResult:
    """Load a registry snapshot from a local file.

    Args:
        path: Path to the snapshot JSON file

    Returns:
        SnapshotFetchResult with parsed snapshot or error
    """
    import time

    start = time.monotonic()
    path = Path(path)

    if not path.exists():
        return SnapshotFetchResult(
            success=False,
            file_path=str(path),
            error=f"File not found: {path}",
        )

    if not path.is_file():
        return SnapshotFetchResult(
            success=False,
            file_path=str(path),
            error=f"Not a file: {path}",
        )

    try:
        raw_data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return SnapshotFetchResult(
            success=False,
            file_path=str(path),
            error=f"Invalid JSON: {e}",
            fetch_latency_ms=int((time.monotonic() - start) * 1000),
        )

    try:
        snapshot = parse_registry_snapshot(raw_data)
    except VerificationError as e:
        return SnapshotFetchResult(
            success=False,
            file_path=str(path),
            raw_data=raw_data,
            error=str(e),
            fetch_latency_ms=int((time.monotonic() - start) * 1000),
        )

    return SnapshotFetchResult(
        success=True,
        registry_version=snapshot.registry_version,
        snapshot=snapshot,
        raw_data=raw_data,
        file_path=str(path),
        fetch_latency_ms=int((time.monotonic() - start) * 1000),
    )


def load_local_registry_chain(
    directory: Path | str,
    pattern: str = "*.json",
) -> list[SnapshotFetchResult]:
    """Load all registry snapshots from a directory.

    Args:
        directory: Directory containing snapshot JSON files
        pattern: Glob pattern for snapshot files (default: "*.json")

    Returns:
        List of SnapshotFetchResult, one per file found
    """
    directory = Path(directory)

    if not directory.exists():
        return [
            SnapshotFetchResult(
                success=False,
                file_path=str(directory),
                error=f"Directory not found: {directory}",
            )
        ]

    if not directory.is_dir():
        return [
            SnapshotFetchResult(
                success=False,
                file_path=str(directory),
                error=f"Not a directory: {directory}",
            )
        ]

    results: list[SnapshotFetchResult] = []
    for path in sorted(directory.glob(pattern)):
        if path.is_file():
            result = load_local_registry_snapshot(path)
            results.append(result)

    return results


def load_registry_snapshots_sorted(
    directory: Path | str,
    pattern: str = "*.json",
) -> tuple[list[RegistrySnapshot], list[str]]:
    """Load and sort registry snapshots by version.

    Convenience function that loads all snapshots, parses them,
    sorts by registry_version, and returns errors separately.

    Args:
        directory: Directory containing snapshot JSON files
        pattern: Glob pattern for snapshot files

    Returns:
        Tuple of (sorted snapshots, error messages)
    """
    results = load_local_registry_chain(directory, pattern)

    snapshots: list[RegistrySnapshot] = []
    errors: list[str] = []

    for result in results:
        if result.success and result.snapshot:
            snapshots.append(result.snapshot)
        elif result.error:
            errors.append(f"{result.file_path}: {result.error}")

    # Sort by registry_version
    snapshots.sort(key=lambda s: s.registry_version)

    return snapshots, errors
