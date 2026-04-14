"""Local file anchor loader (PR-ENT-540).

Loads external anchors from local files for offline verification.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from specora_verify.validators.mirror import MirrorSource, SourceResult


def load_local_anchor(
    path: str | Path,
    source_type: MirrorSource = MirrorSource.LOCAL_FILE,
) -> SourceResult:
    """Load an external anchor from a local file.

    Used for offline verification when anchors have been downloaded
    or exported from their publication surfaces.

    Args:
        path: Path to the anchor JSON file
        source_type: Source type to report (allows simulating GitHub/S3/etc.)

    Returns:
        SourceResult with anchor data or error
    """
    start = time.time()
    file_path = Path(path)

    if not file_path.exists():
        return SourceResult(
            source=source_type,
            reachable=False,
            error=f"File not found: {path}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )

    if not file_path.is_file():
        return SourceResult(
            source=source_type,
            reachable=False,
            error=f"Path is not a file: {path}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            anchor_data = json.load(f)

        # Validate it looks like an anchor
        if not isinstance(anchor_data, dict):
            return SourceResult(
                source=source_type,
                reachable=True,
                error="File does not contain a valid JSON object",
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

        anchor_hash = anchor_data.get("anchor_hash")
        chain_head_index = anchor_data.get("chain_head_index")

        if not anchor_hash:
            return SourceResult(
                source=source_type,
                reachable=True,
                error="File does not contain anchor_hash field",
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

        return SourceResult(
            source=source_type,
            reachable=True,
            anchor_hash=anchor_hash,
            chain_head_index=chain_head_index,
            anchor_data=anchor_data,
            fetch_latency_ms=int((time.time() - start) * 1000),
        )

    except json.JSONDecodeError as e:
        return SourceResult(
            source=source_type,
            reachable=True,
            error=f"Invalid JSON: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
    except Exception as e:
        return SourceResult(
            source=source_type,
            reachable=False,
            error=f"Error reading file: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )


def load_local_dns_txt(
    path: str | Path,
) -> SourceResult:
    """Load a DNS TXT record value from a local file.

    The file should contain the raw TXT record value:
    v=sa1;i={chain_head_index};h={anchor_hash[:32]};t={unix_timestamp}

    Args:
        path: Path to the text file containing the TXT record value

    Returns:
        SourceResult with parsed anchor fingerprint or error
    """
    from specora_verify.fetchers.dns import parse_dns_txt_value

    start = time.time()
    file_path = Path(path)

    if not file_path.exists():
        return SourceResult(
            source=MirrorSource.DNS_TXT,
            reachable=False,
            error=f"File not found: {path}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            txt_value = f.read().strip()

        # Try to parse as JSON first (might be a full anchor file)
        try:
            data = json.loads(txt_value)
            if isinstance(data, dict) and "anchor_hash" in data:
                # It's a full anchor file, extract the hash prefix
                anchor_hash = data.get("anchor_hash", "")
                return SourceResult(
                    source=MirrorSource.DNS_TXT,
                    reachable=True,
                    anchor_hash=anchor_hash[:32],  # DNS only has 32 chars
                    chain_head_index=data.get("chain_head_index"),
                    anchor_data={
                        "anchor_hash_prefix": anchor_hash[:32],
                        "chain_head_index": data.get("chain_head_index"),
                        "source": "local_json",
                    },
                    fetch_latency_ms=int((time.time() - start) * 1000),
                )
        except json.JSONDecodeError:
            pass  # Not JSON, try TXT record format

        # Parse as TXT record format
        parsed = parse_dns_txt_value(txt_value)
        if parsed:
            chain_index_str = parsed.get("i")
            chain_index = int(chain_index_str) if chain_index_str else None

            return SourceResult(
                source=MirrorSource.DNS_TXT,
                reachable=True,
                anchor_hash=parsed.get("h"),
                chain_head_index=chain_index,
                anchor_data={
                    "version": parsed.get("v"),
                    "chain_head_index": chain_index,
                    "anchor_hash_prefix": parsed.get("h"),
                    "timestamp": parsed.get("t"),
                    "raw_txt": txt_value,
                },
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

        return SourceResult(
            source=MirrorSource.DNS_TXT,
            reachable=True,
            error="File does not contain valid Specora anchor TXT format",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )

    except Exception as e:
        return SourceResult(
            source=MirrorSource.DNS_TXT,
            reachable=False,
            error=f"Error reading file: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
