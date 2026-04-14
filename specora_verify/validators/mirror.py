"""Multi-surface mirror verification (PR-ENT-540).

Fetches external anchors from multiple surfaces and cross-checks consistency.

Invariants:
- INV-ANCHOR-009: Multi-surface consistency - anchor_hash must match across all surfaces
- INV-ANCHOR-011: Mirror verifier cross-check - third-party verifiable consistency
- INV-ANCHOR-012: Tamper-evidence - no single compromised surface can modify history undetected
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MirrorSource(Enum):
    """Mirror source identifiers."""

    GITHUB_RELEASE = "github_release"
    S3_VERSIONED = "s3_versioned"
    DNS_TXT = "dns_txt"
    LOCAL_FILE = "local_file"


class MirrorStatus(Enum):
    """Mirror verification status."""

    PASS = "pass"  # Quorum met, all sources agree
    WARN = "warn"  # Quorum met, some sources unreachable
    FAIL = "fail"  # Hash mismatch detected (INV-ANCHOR-009 violation)
    ERROR = "error"  # Unable to reach quorum


@dataclass
class SourceResult:
    """Result from a single source fetch and verification."""

    source: MirrorSource
    reachable: bool
    anchor_hash: str | None = None
    chain_head_index: int | None = None
    anchor_data: dict[str, Any] | None = None
    error: str | None = None
    fetch_latency_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source": self.source.value,
            "reachable": self.reachable,
            "anchor_hash": self.anchor_hash,
            "chain_head_index": self.chain_head_index,
            "error": self.error,
            "fetch_latency_ms": self.fetch_latency_ms,
        }


@dataclass
class MirrorVerificationResult:
    """Result of multi-surface mirror verification."""

    status: MirrorStatus
    quorum_required: int
    quorum_achieved: int
    sources_checked: int
    sources_reachable: int
    consensus_anchor_hash: str | None = None
    consensus_chain_index: int | None = None
    hash_mismatch_detected: bool = False
    mismatched_sources: list[str] = field(default_factory=list)
    source_results: dict[str, SourceResult] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Check if verification passed or warned."""
        return self.status in (MirrorStatus.PASS, MirrorStatus.WARN)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "status": self.status.value,
            "valid": self.valid,
            "quorum_required": self.quorum_required,
            "quorum_achieved": self.quorum_achieved,
            "sources_checked": self.sources_checked,
            "sources_reachable": self.sources_reachable,
            "consensus_anchor_hash": self.consensus_anchor_hash,
            "consensus_chain_index": self.consensus_chain_index,
            "hash_mismatch_detected": self.hash_mismatch_detected,
            "mismatched_sources": self.mismatched_sources,
            "sources": {
                name: result.to_dict() for name, result in self.source_results.items()
            },
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class MirrorVerificationReceipt:
    """Verification receipt for archival."""

    schema_version: str = "1.0.0"
    verifier_version: str = ""
    verification_timestamp: str = ""
    result: MirrorVerificationResult | None = None
    public_key_fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schema_version": self.schema_version,
            "verifier_version": self.verifier_version,
            "verification_timestamp": self.verification_timestamp,
            "public_key_fingerprint": self.public_key_fingerprint,
            "result": self.result.to_dict() if self.result else None,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def verify_mirror_consistency(
    source_results: dict[str, SourceResult],
    quorum_required: int = 2,
) -> MirrorVerificationResult:
    """Verify consistency across mirror sources.

    INV-ANCHOR-009: Multi-surface consistency
    INV-ANCHOR-011: Mirror verifier cross-check

    Algorithm:
    1. Collect anchor_hash from each reachable source
    2. Check for hash consensus (all must match)
    3. DNS returns truncated hash (32 chars) - compare prefix only
    4. Evaluate quorum (>= K sources agree)
    5. Return PASS/WARN/FAIL based on consensus and reachability

    Args:
        source_results: Results from each source fetch
        quorum_required: Minimum number of agreeing sources (K in K-of-N)

    Returns:
        MirrorVerificationResult with status and details
    """
    # Filter to reachable sources with anchor hashes
    reachable_sources = {
        name: r
        for name, r in source_results.items()
        if r.reachable and r.anchor_hash
    }

    sources_checked = len(source_results)
    sources_reachable = len(reachable_sources)
    errors: list[str] = []
    warnings: list[str] = []

    # Check if we can even reach quorum
    if sources_reachable < quorum_required:
        unreachable = [n for n, r in source_results.items() if not r.reachable]
        errors.append(
            f"Insufficient reachable sources: {sources_reachable} < {quorum_required}"
        )
        if unreachable:
            errors.append(f"Unreachable sources: {', '.join(unreachable)}")

        return MirrorVerificationResult(
            status=MirrorStatus.ERROR,
            quorum_required=quorum_required,
            quorum_achieved=sources_reachable,
            sources_checked=sources_checked,
            sources_reachable=sources_reachable,
            source_results=source_results,
            errors=errors,
        )

    # Build hash consensus map
    # DNS TXT only contains first 32 chars of hash, so we need special handling
    hash_groups: dict[str, list[str]] = {}  # hash_prefix -> list of source names

    for name, result in reachable_sources.items():
        hash_value = result.anchor_hash
        if not hash_value:
            continue

        # For DNS, we only have 32 chars; for others, take first 32 for comparison
        hash_prefix = hash_value[:32]

        if hash_prefix not in hash_groups:
            hash_groups[hash_prefix] = []
        hash_groups[hash_prefix].append(name)

    if not hash_groups:
        errors.append("No valid anchor hashes found in reachable sources")
        return MirrorVerificationResult(
            status=MirrorStatus.ERROR,
            quorum_required=quorum_required,
            quorum_achieved=0,
            sources_checked=sources_checked,
            sources_reachable=sources_reachable,
            source_results=source_results,
            errors=errors,
        )

    # Find consensus (largest group)
    consensus_prefix = max(hash_groups.keys(), key=lambda h: len(hash_groups[h]))
    consensus_sources = hash_groups[consensus_prefix]
    quorum_achieved = len(consensus_sources)

    # Find mismatched sources (sources not in consensus group)
    mismatched_sources: list[str] = []
    for prefix, sources in hash_groups.items():
        if prefix != consensus_prefix:
            mismatched_sources.extend(sources)

    hash_mismatch = len(mismatched_sources) > 0

    # Get full consensus hash from a non-DNS source if available
    consensus_hash = None
    consensus_index = None
    for source_name in consensus_sources:
        result = reachable_sources[source_name]
        if result.source != MirrorSource.DNS_TXT and result.anchor_hash:
            consensus_hash = result.anchor_hash
            consensus_index = result.chain_head_index
            break

    # If all consensus sources are DNS, use the truncated hash
    if consensus_hash is None:
        consensus_hash = consensus_prefix
        # Get index from any consensus source
        for source_name in consensus_sources:
            result = reachable_sources[source_name]
            if result.chain_head_index is not None:
                consensus_index = result.chain_head_index
                break

    # Determine final status
    if hash_mismatch:
        status = MirrorStatus.FAIL
        errors.append(
            f"Hash mismatch detected (INV-ANCHOR-009 violation): "
            f"sources {', '.join(mismatched_sources)} disagree with consensus"
        )
    elif quorum_achieved >= quorum_required:
        if sources_reachable < sources_checked:
            status = MirrorStatus.WARN
            unreachable = [n for n, r in source_results.items() if not r.reachable]
            warnings.append(f"Some sources unreachable: {', '.join(unreachable)}")
        else:
            status = MirrorStatus.PASS
    else:
        status = MirrorStatus.ERROR
        errors.append(
            f"Quorum not achieved: {quorum_achieved} < {quorum_required}"
        )

    return MirrorVerificationResult(
        status=status,
        quorum_required=quorum_required,
        quorum_achieved=quorum_achieved,
        sources_checked=sources_checked,
        sources_reachable=sources_reachable,
        consensus_anchor_hash=consensus_hash,
        consensus_chain_index=consensus_index,
        hash_mismatch_detected=hash_mismatch,
        mismatched_sources=mismatched_sources,
        source_results=source_results,
        errors=errors,
        warnings=warnings,
    )


def create_mirror_receipt(
    result: MirrorVerificationResult,
    verifier_version: str = "",
    public_key_fingerprint: str | None = None,
) -> MirrorVerificationReceipt:
    """Create a verification receipt for archival.

    Args:
        result: Mirror verification result
        verifier_version: Version of the verifier tool
        public_key_fingerprint: SHA-256 fingerprint of public key used

    Returns:
        MirrorVerificationReceipt for archival
    """
    return MirrorVerificationReceipt(
        schema_version="1.0.0",
        verifier_version=verifier_version,
        verification_timestamp=datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        result=result,
        public_key_fingerprint=public_key_fingerprint,
    )


def status_to_exit_code(status: MirrorStatus) -> int:
    """Convert mirror status to CLI exit code.

    Exit codes follow the specora-verify contract:
    - 0: PASS
    - 1: WARN
    - 2: FAIL
    - 3: ERROR

    Args:
        status: Mirror verification status

    Returns:
        Integer exit code
    """
    mapping = {
        MirrorStatus.PASS: 0,
        MirrorStatus.WARN: 1,
        MirrorStatus.FAIL: 2,
        MirrorStatus.ERROR: 3,
    }
    return mapping.get(status, 3)


# =============================================================================
# Anchor Chain Verification (verify-anchors)
# =============================================================================


@dataclass
class AnchorVerificationDetail:
    """Verification result for a single anchor in the chain."""

    chain_index: int
    anchor_hash: str | None = None
    previous_anchor_hash: str | None = None
    sources_checked: int = 0
    sources_reachable: int = 0
    sources_agreeing: int = 0
    cross_surface_match: bool = True
    chain_linkage_valid: bool = True
    signature_valid: bool | None = None  # None if not checked
    errors: list[str] = field(default_factory=list)
    source_results: dict[str, SourceResult] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "chain_index": self.chain_index,
            "anchor_hash": self.anchor_hash,
            "previous_anchor_hash": self.previous_anchor_hash,
            "sources_checked": self.sources_checked,
            "sources_reachable": self.sources_reachable,
            "sources_agreeing": self.sources_agreeing,
            "cross_surface_match": self.cross_surface_match,
            "chain_linkage_valid": self.chain_linkage_valid,
            "signature_valid": self.signature_valid,
            "errors": self.errors,
        }


@dataclass
class AnchorChainVerificationResult:
    """Result of multi-anchor chain verification."""

    status: MirrorStatus
    total_anchors: int
    verified_anchors: int
    first_index: int | None = None
    last_index: int | None = None
    chain_linkage_valid: bool = True
    cross_surface_consistent: bool = True
    mismatched_indices: list[int] = field(default_factory=list)
    broken_linkages: list[int] = field(default_factory=list)
    anchor_details: list[AnchorVerificationDetail] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Check if verification passed or warned."""
        return self.status in (MirrorStatus.PASS, MirrorStatus.WARN)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "valid": self.valid,
            "total_anchors": self.total_anchors,
            "verified_anchors": self.verified_anchors,
            "first_index": self.first_index,
            "last_index": self.last_index,
            "chain_linkage_valid": self.chain_linkage_valid,
            "cross_surface_consistent": self.cross_surface_consistent,
            "mismatched_indices": self.mismatched_indices,
            "broken_linkages": self.broken_linkages,
            "anchor_details": [d.to_dict() for d in self.anchor_details],
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class AnchorChainVerificationReceipt:
    """Receipt for anchor chain verification."""

    schema_version: str = "1.0.0"
    verifier_version: str = ""
    verification_timestamp: str = ""
    result: AnchorChainVerificationResult | None = None
    public_key_fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schema_version": self.schema_version,
            "verifier_version": self.verifier_version,
            "verification_timestamp": self.verification_timestamp,
            "public_key_fingerprint": self.public_key_fingerprint,
            "result": self.result.to_dict() if self.result else None,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def verify_anchor_chain(
    anchors_by_source: dict[str, list[SourceResult]],
    quorum_required: int = 2,
    verify_linkage: bool = True,
) -> AnchorChainVerificationResult:
    """Verify a chain of anchors across multiple sources.

    For each anchor index:
    1. Cross-check hash consistency across sources (INV-ANCHOR-009)
    2. Verify previous_anchor_hash linkage (chain-of-chains)
    3. Aggregate results into chain verification status

    Args:
        anchors_by_source: Dict mapping source name to list of SourceResults
                          (sorted by chain_head_index ascending)
        quorum_required: Minimum agreeing sources per anchor
        verify_linkage: Whether to verify previous_anchor_hash linkage

    Returns:
        AnchorChainVerificationResult with per-anchor details
    """
    errors: list[str] = []
    warnings: list[str] = []
    anchor_details: list[AnchorVerificationDetail] = []
    mismatched_indices: list[int] = []
    broken_linkages: list[int] = []

    # Build index -> source -> SourceResult mapping
    index_map: dict[int, dict[str, SourceResult]] = {}

    for source_name, results in anchors_by_source.items():
        for result in results:
            if result.chain_head_index is not None:
                if result.chain_head_index not in index_map:
                    index_map[result.chain_head_index] = {}
                index_map[result.chain_head_index][source_name] = result

    if not index_map:
        return AnchorChainVerificationResult(
            status=MirrorStatus.ERROR,
            total_anchors=0,
            verified_anchors=0,
            errors=["No anchors found in any source"],
        )

    # Sort indices
    sorted_indices = sorted(index_map.keys())
    first_index = sorted_indices[0]
    last_index = sorted_indices[-1]

    # Track previous anchor hash for linkage verification
    expected_previous_hash: str | None = None
    chain_linkage_valid = True
    cross_surface_consistent = True

    for idx in sorted_indices:
        source_results = index_map[idx]
        detail = AnchorVerificationDetail(
            chain_index=idx,
            sources_checked=len(source_results),
            source_results=source_results,
        )

        # Collect hashes from reachable sources
        hashes: dict[str, list[str]] = {}  # hash_prefix -> source names
        full_hashes: dict[str, str] = {}  # source_name -> full hash

        for source_name, result in source_results.items():
            if result.reachable and result.anchor_hash:
                detail.sources_reachable += 1
                # Use 32-char prefix for comparison (DNS compatibility)
                prefix = result.anchor_hash[:32]
                if prefix not in hashes:
                    hashes[prefix] = []
                hashes[prefix].append(source_name)
                full_hashes[source_name] = result.anchor_hash

        if not hashes:
            detail.errors.append("No reachable sources with valid hashes")
            detail.cross_surface_match = False
            anchor_details.append(detail)
            continue

        # Find consensus hash
        consensus_prefix = max(hashes.keys(), key=lambda h: len(hashes[h]))
        agreeing_sources = hashes[consensus_prefix]
        detail.sources_agreeing = len(agreeing_sources)

        # Get full hash from a non-DNS source if available
        for source_name in agreeing_sources:
            if len(full_hashes.get(source_name, "")) == 64:
                detail.anchor_hash = full_hashes[source_name]
                break
        if not detail.anchor_hash:
            detail.anchor_hash = consensus_prefix

        # Check for cross-surface mismatch
        if len(hashes) > 1:
            detail.cross_surface_match = False
            cross_surface_consistent = False
            mismatched_indices.append(idx)
            mismatched_sources = [
                s for p, sources in hashes.items() if p != consensus_prefix for s in sources
            ]
            detail.errors.append(
                f"Hash mismatch: {', '.join(mismatched_sources)} disagree with consensus"
            )

        # Get previous_anchor_hash from anchor data
        for source_name in agreeing_sources:
            result = source_results[source_name]
            if result.anchor_data:
                prev_hash = result.anchor_data.get(
                    "previous_anchor_hash"
                ) or result.anchor_data.get("previous_external_anchor_hash")
                if prev_hash:
                    detail.previous_anchor_hash = prev_hash
                    break

        # Verify chain linkage
        if verify_linkage and expected_previous_hash is not None:
            if detail.previous_anchor_hash != expected_previous_hash:
                detail.chain_linkage_valid = False
                chain_linkage_valid = False
                broken_linkages.append(idx)
                detail.errors.append(
                    f"Chain linkage broken: expected {expected_previous_hash[:16]}..., "
                    f"got {(detail.previous_anchor_hash or 'null')[:16] if detail.previous_anchor_hash else 'null'}..."
                )

        # Update expected previous hash for next iteration
        expected_previous_hash = detail.anchor_hash

        anchor_details.append(detail)

    # Determine overall status
    verified_count = sum(
        1 for d in anchor_details if d.cross_surface_match and d.chain_linkage_valid
    )

    if mismatched_indices or broken_linkages:
        status = MirrorStatus.FAIL
        if mismatched_indices:
            errors.append(f"Cross-surface hash mismatch at indices: {mismatched_indices}")
        if broken_linkages:
            errors.append(f"Chain linkage broken at indices: {broken_linkages}")
    elif verified_count < len(anchor_details):
        status = MirrorStatus.WARN
        warnings.append("Some anchors could not be fully verified")
    else:
        status = MirrorStatus.PASS

    return AnchorChainVerificationResult(
        status=status,
        total_anchors=len(sorted_indices),
        verified_anchors=verified_count,
        first_index=first_index,
        last_index=last_index,
        chain_linkage_valid=chain_linkage_valid,
        cross_surface_consistent=cross_surface_consistent,
        mismatched_indices=mismatched_indices,
        broken_linkages=broken_linkages,
        anchor_details=anchor_details,
        errors=errors,
        warnings=warnings,
    )


def create_anchor_chain_receipt(
    result: AnchorChainVerificationResult,
    verifier_version: str = "",
    public_key_fingerprint: str | None = None,
) -> AnchorChainVerificationReceipt:
    """Create a verification receipt for anchor chain verification.

    Args:
        result: Anchor chain verification result
        verifier_version: Version of the verifier tool
        public_key_fingerprint: SHA-256 fingerprint of public key used

    Returns:
        AnchorChainVerificationReceipt for archival
    """
    return AnchorChainVerificationReceipt(
        schema_version="1.0.0",
        verifier_version=verifier_version,
        verification_timestamp=datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        result=result,
        public_key_fingerprint=public_key_fingerprint,
    )
