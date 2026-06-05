"""S3 anchor fetcher (PR-ENT-540).

Fetches external anchors from S3 versioned buckets via public URLs.
"""

from __future__ import annotations

import time

from specora_verify.validators.mirror import MirrorSource, SourceResult


def fetch_latest_s3_anchor(
    url: str,
    timeout: float = 30.0,
) -> SourceResult:
    """Fetch latest external anchor from S3 public URL.

    The URL should point directly to the anchor JSON file or to a prefix
    where anchor files are stored with the naming pattern:
    {prefix}{index:08d}-{hash[:8]}.json

    Args:
        url: S3 public URL to anchor.json or listing endpoint
        timeout: HTTP request timeout in seconds

    Returns:
        SourceResult with anchor data or error
    """
    start = time.time()

    try:
        import httpx

        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            # If URL ends with .json, fetch directly
            if url.endswith(".json"):
                response = client.get(url)
                response.raise_for_status()
                anchor_data = response.json()

                return SourceResult(
                    source=MirrorSource.S3_VERSIONED,
                    reachable=True,
                    anchor_hash=anchor_data.get("anchor_hash"),
                    chain_head_index=anchor_data.get("chain_head_index"),
                    anchor_data=anchor_data,
                    fetch_latency_ms=int((time.time() - start) * 1000),
                )

            # Otherwise, try to list and find latest anchor
            # This requires the S3 bucket to have listing enabled
            # or we need to know the exact file name
            return SourceResult(
                source=MirrorSource.S3_VERSIONED,
                reachable=False,
                error="S3 URL must point directly to anchor.json file",
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

    except ImportError:
        return SourceResult(
            source=MirrorSource.S3_VERSIONED,
            reachable=False,
            error="httpx not installed. Install with: pip install httpx",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
    except Exception as e:
        return SourceResult(
            source=MirrorSource.S3_VERSIONED,
            reachable=False,
            error=f"Request error: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )


def fetch_s3_anchor_by_index(
    bucket_url: str,
    index: int,
    prefix: str = "external-anchors/",
    timeout: float = 30.0,
) -> SourceResult:
    """Fetch a specific anchor by chain head index from S3.

    Constructs the URL using the known naming pattern:
    {bucket_url}/{prefix}{index:08d}-*.json

    Args:
        bucket_url: Base S3 bucket URL (e.g., https://bucket.s3.amazonaws.com)
        index: Chain head index to fetch
        prefix: Key prefix for anchor files
        timeout: HTTP request timeout in seconds

    Returns:
        SourceResult with anchor data or error
    """
    start = time.time()

    try:
        import httpx

        # Try common hash prefixes (we don't know the exact hash)
        # This is a best-effort approach; for exact fetching, use the direct URL
        base_url = bucket_url.rstrip("/")
        prefix = prefix.rstrip("/") + "/"

        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            # Try to fetch the S3 listing to find the exact file
            # Note: This requires list access or knowing the exact filename
            list_url = f"{base_url}?prefix={prefix}{index:08d}-&list-type=2"

            try:
                list_response = client.get(list_url)
                if list_response.status_code == 200:
                    # Parse XML listing
                    import xml.etree.ElementTree as ET

                    root = ET.fromstring(list_response.text)
                    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}

                    for content in root.findall(".//s3:Contents", ns):
                        key_elem = content.find("s3:Key", ns)
                        if key_elem is not None and key_elem.text:
                            key = key_elem.text
                            if key.startswith(f"{prefix}{index:08d}-"):
                                # Found it - fetch the actual file
                                anchor_url = f"{base_url}/{key}"
                                anchor_response = client.get(anchor_url)
                                anchor_response.raise_for_status()
                                anchor_data = anchor_response.json()

                                return SourceResult(
                                    source=MirrorSource.S3_VERSIONED,
                                    reachable=True,
                                    anchor_hash=anchor_data.get("anchor_hash"),
                                    chain_head_index=anchor_data.get("chain_head_index"),
                                    anchor_data=anchor_data,
                                    fetch_latency_ms=int((time.time() - start) * 1000),
                                )

            except Exception:
                pass  # Listing not available, fall through

            return SourceResult(
                source=MirrorSource.S3_VERSIONED,
                reachable=True,
                error=f"Anchor for index {index} not found in S3",
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

    except ImportError:
        return SourceResult(
            source=MirrorSource.S3_VERSIONED,
            reachable=False,
            error="httpx not installed. Install with: pip install httpx",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
    except Exception as e:
        return SourceResult(
            source=MirrorSource.S3_VERSIONED,
            reachable=False,
            error=f"Request error: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )


async def fetch_latest_s3_anchor_async(
    url: str,
    timeout: float = 30.0,
) -> SourceResult:
    """Async version of fetch_latest_s3_anchor."""
    start = time.time()

    try:
        import httpx

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            if url.endswith(".json"):
                response = await client.get(url)
                response.raise_for_status()
                anchor_data = response.json()

                return SourceResult(
                    source=MirrorSource.S3_VERSIONED,
                    reachable=True,
                    anchor_hash=anchor_data.get("anchor_hash"),
                    chain_head_index=anchor_data.get("chain_head_index"),
                    anchor_data=anchor_data,
                    fetch_latency_ms=int((time.time() - start) * 1000),
                )

            return SourceResult(
                source=MirrorSource.S3_VERSIONED,
                reachable=False,
                error="S3 URL must point directly to anchor.json file",
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

    except ImportError:
        return SourceResult(
            source=MirrorSource.S3_VERSIONED,
            reachable=False,
            error="httpx not installed. Install with: pip install httpx",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
    except Exception as e:
        return SourceResult(
            source=MirrorSource.S3_VERSIONED,
            reachable=False,
            error=f"Request error: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
