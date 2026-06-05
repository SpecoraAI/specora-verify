"""DNS TXT anchor fetcher (PR-ENT-540).

Fetches anchor fingerprints from DNS TXT records.

DNS TXT Format:
    v=sa1;i={chain_head_index};h={anchor_hash[:32]};t={unix_timestamp}
"""

from __future__ import annotations

import time

from specora_verify.validators.mirror import MirrorSource, SourceResult


def parse_dns_txt_value(txt_value: str) -> dict[str, str] | None:
    """Parse DNS TXT record value into components.

    Args:
        txt_value: TXT record value (v=sa1;i=42;h=abc123...;t=1709308800)

    Returns:
        Dictionary with parsed values or None if invalid
    """
    if not txt_value.startswith("v=sa1;"):
        return None

    try:
        parts = {}
        for segment in txt_value.split(";"):
            if "=" in segment:
                key, value = segment.split("=", 1)
                parts[key] = value
        return parts
    except Exception:
        return None


def fetch_dns_txt_anchor(
    fqdn: str,
    timeout: float = 10.0,
) -> SourceResult:
    """Fetch anchor fingerprint from DNS TXT record.

    The DNS TXT record contains a truncated anchor fingerprint in the format:
    v=sa1;i={chain_head_index};h={anchor_hash[:32]};t={unix_timestamp}

    Args:
        fqdn: Fully qualified domain name (e.g., _specora-anchor.example.com)
        timeout: DNS resolution timeout in seconds

    Returns:
        SourceResult with anchor fingerprint or error

    Note:
        DNS TXT records only contain the first 32 characters of the anchor_hash
        due to TXT record size limits. The mirror verifier should compare
        hash prefixes when cross-checking against DNS.
    """
    start = time.time()

    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout

        answers = resolver.resolve(fqdn, "TXT")

        for rdata in answers:
            # Remove quotes from TXT record value
            txt_value = str(rdata).strip('"')

            if txt_value.startswith("v=sa1;"):
                parsed = parse_dns_txt_value(txt_value)
                if parsed:
                    chain_index_str = parsed.get("i")
                    chain_index = int(chain_index_str) if chain_index_str else None

                    return SourceResult(
                        source=MirrorSource.DNS_TXT,
                        reachable=True,
                        anchor_hash=parsed.get("h"),  # Note: truncated to 32 chars
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
            error="No valid Specora anchor TXT record found",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )

    except ImportError:
        return SourceResult(
            source=MirrorSource.DNS_TXT,
            reachable=False,
            error="dnspython not installed. Install with: pip install dnspython",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )
    except Exception as e:
        error_type = type(e).__name__

        # Handle specific DNS errors
        if "NXDOMAIN" in str(e) or "NXDOMAIN" in error_type:
            return SourceResult(
                source=MirrorSource.DNS_TXT,
                reachable=False,
                error=f"DNS domain not found: {fqdn}",
                fetch_latency_ms=int((time.time() - start) * 1000),
            )
        if "NoAnswer" in str(e) or "NoAnswer" in error_type:
            return SourceResult(
                source=MirrorSource.DNS_TXT,
                reachable=True,
                error="No TXT record found at this domain",
                fetch_latency_ms=int((time.time() - start) * 1000),
            )
        if "Timeout" in str(e) or "Timeout" in error_type:
            return SourceResult(
                source=MirrorSource.DNS_TXT,
                reachable=False,
                error=f"DNS resolution timed out after {timeout}s",
                fetch_latency_ms=int((time.time() - start) * 1000),
            )

        return SourceResult(
            source=MirrorSource.DNS_TXT,
            reachable=False,
            error=f"DNS error: {e}",
            fetch_latency_ms=int((time.time() - start) * 1000),
        )


async def fetch_dns_txt_anchor_async(
    fqdn: str,
    timeout: float = 10.0,
) -> SourceResult:
    """Async version of fetch_dns_txt_anchor.

    Note: dnspython's async support requires additional setup.
    This is a wrapper that runs the sync version in a thread pool.
    """
    import asyncio

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fetch_dns_txt_anchor, fqdn, timeout)
