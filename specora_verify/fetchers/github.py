"""GitHub Release anchor fetcher (PR-ENT-540).

Fetches external anchors from GitHub Releases.
"""

from __future__ import annotations

import time

from specora_verify.validators.mirror import MirrorSource, SourceResult


def fetch_latest_github_anchor(
    repo: str,
    tag_prefix: str = "anchor-",
    timeout: float = 30.0,
) -> SourceResult:
    """Fetch latest external anchor from GitHub releases.

    Args:
        repo: Repository in owner/repo format
        tag_prefix: Tag name prefix to filter releases
        timeout: HTTP request timeout in seconds

    Returns:
        SourceResult with anchor data or error
    """
    start = time.time()

    try:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            # Get latest release matching prefix
            response = client.get(
                f"https://api.github.com/repos/{repo}/releases",
                headers={"Accept": "application/vnd.github+json"},
            )
            response.raise_for_status()

            releases = response.json()
            anchor_release = None
            for r in releases:
                if r.get("tag_name", "").startswith(tag_prefix):
                    anchor_release = r
                    break

            if not anchor_release:
                return SourceResult(
                    source=MirrorSource.GITHUB_RELEASE,
                    reachable=True,
                    error=f"No anchor release found with prefix '{tag_prefix}'",
                    fetch_latency_ms=int((time.time() - start) * 1000),
                )

            # Find anchor.json asset
            asset_url = None
            for asset in anchor_release.get("assets", []):
                if asset.get("name") == "anchor.json":
                    asset_url = asset.get("browser_download_url")
                    break

            if not asset_url:
                return SourceResult(
                    source=MirrorSource.GITHUB_RELEASE,
                    reachable=True,
                    error="anchor.json asset not found in release",
                    fetch_latency_ms=int((time.time() - start) * 1000),
                )

            # Download anchor
            anchor_response = client.get(asset_url)
            anchor_response.raise_for_status()
            anchor_data = anchor_response.json()

            return SourceResult(
                source=MirrorSource.GITHUB_RELEASE,
                reachable=True,
                anchor_hash=anchor_data.get("anchor_hash"),
                chain_head_index=anchor_data.get("chain_head_index"),
                anchor_data=anchor_data,
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

    except ImportError:
        return SourceResult(
            source=MirrorSource.GITHUB_RELEASE,
            reachable=False,
            error="httpx not installed. Install with: pip install httpx",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
    except Exception as e:
        return SourceResult(
            source=MirrorSource.GITHUB_RELEASE,
            reachable=False,
            error=f"Request error: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )


async def fetch_latest_github_anchor_async(
    repo: str,
    tag_prefix: str = "anchor-",
    timeout: float = 30.0,
) -> SourceResult:
    """Async version of fetch_latest_github_anchor.

    Args:
        repo: Repository in owner/repo format
        tag_prefix: Tag name prefix to filter releases
        timeout: HTTP request timeout in seconds

    Returns:
        SourceResult with anchor data or error
    """
    start = time.time()

    try:
        import httpx

        async with httpx.AsyncClient(timeout=timeout) as client:
            # Get latest release matching prefix
            response = await client.get(
                f"https://api.github.com/repos/{repo}/releases",
                headers={"Accept": "application/vnd.github+json"},
            )
            response.raise_for_status()

            releases = response.json()
            anchor_release = None
            for r in releases:
                if r.get("tag_name", "").startswith(tag_prefix):
                    anchor_release = r
                    break

            if not anchor_release:
                return SourceResult(
                    source=MirrorSource.GITHUB_RELEASE,
                    reachable=True,
                    error=f"No anchor release found with prefix '{tag_prefix}'",
                    fetch_latency_ms=int((time.time() - start) * 1000),
                )

            # Find anchor.json asset
            asset_url = None
            for asset in anchor_release.get("assets", []):
                if asset.get("name") == "anchor.json":
                    asset_url = asset.get("browser_download_url")
                    break

            if not asset_url:
                return SourceResult(
                    source=MirrorSource.GITHUB_RELEASE,
                    reachable=True,
                    error="anchor.json asset not found in release",
                    fetch_latency_ms=int((time.time() - start) * 1000),
                )

            # Download anchor
            anchor_response = await client.get(asset_url)
            anchor_response.raise_for_status()
            anchor_data = anchor_response.json()

            return SourceResult(
                source=MirrorSource.GITHUB_RELEASE,
                reachable=True,
                anchor_hash=anchor_data.get("anchor_hash"),
                chain_head_index=anchor_data.get("chain_head_index"),
                anchor_data=anchor_data,
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

    except ImportError:
        return SourceResult(
            source=MirrorSource.GITHUB_RELEASE,
            reachable=False,
            error="httpx not installed. Install with: pip install httpx",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
    except Exception as e:
        return SourceResult(
            source=MirrorSource.GITHUB_RELEASE,
            reachable=False,
            error=f"Request error: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
