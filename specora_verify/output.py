"""Output formatting for specora-verify.

Supports text (human-readable) and JSON (machine-readable) output modes.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from specora_verify.validators.anchor import AnchorValidationResult, AnchorVectorVerificationResult
from specora_verify.validators.bundle import BundleVerificationResult
from specora_verify.validators.certification import (
    CertificationAttestationResult,
    CertificationCheckResult,
    CertificationVectorVerificationResult,
)
from specora_verify.validators.chain import ChainVerificationResult
from specora_verify.validators.manifest import ManifestValidationResult
from specora_verify.validators.receipt import (
    ReceiptValidationResult,
    ReceiptVectorVerificationResult,
)
from specora_verify.validators.stp import (
    STPInitResult,
    STPInspectResult,
    STPSimulateResult,
    STPVectorsResult,
    STPVerifyResult,
)
from specora_verify.validators.stp_certification import (
    STPCertificationAttestationResult,
    STPCertificationCheckResult,
    STPCertificationVectorVerificationResult,
)
from specora_verify.validators.vectors import VectorVerificationResult

if TYPE_CHECKING:
    from specora_verify.signature import KeyInfo, SignatureVerificationResult


DIVIDER = "=" * 60


def format_manifest_result(
    result: ManifestValidationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format manifest validation result.

    Args:
        result: Validation result
        output_format: "text" or "json"
        file_path: Path to manifest file (for display)

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA MANIFEST VERIFICATION",
        DIVIDER,
        f"File:           {file_path}",
        f"Spec ID:        {result.spec_id or 'unknown'}",
        f"Schema Version: {result.schema_version or 'unknown'}",
        f"Computed Hash:  {result.computed_hash or 'N/A'}",
    ]

    if result.expected_hash:
        lines.append(f"Expected Hash:  {result.expected_hash}")

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_hash_result(
    hash_value: str,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format hash computation result.

    Args:
        hash_value: Computed SHA-256 hash
        output_format: "text" or "json"
        file_path: Path to manifest file

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(
            {
                "file": file_path,
                "hash": hash_value,
                "algorithm": "sha256",
            },
            indent=2,
        )

    return hash_value


def format_vectors_result(
    result: VectorVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format golden vector verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    lines = [
        DIVIDER,
        "SPECORA GOLDEN VECTOR VERIFICATION",
        DIVIDER,
        f"Vectors Dir:    {result.vectors_dir}",
        f"Total:          {result.total}",
        f"Passed:         {result.passed}",
        f"Failed:         {result.failed}",
    ]

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.results:
        lines.append("")
        lines.append("Results:")
        for r in result.results:
            status_str = "PASS" if r.valid else "FAIL"
            lines.append(f"  [{status_str}] {r.spec_id} v{r.version}")
            if not r.valid:
                for error in r.errors:
                    lines.append(f"       {error}")

    if result.errors and not any(r.errors for r in result.results):
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_bundle_result(
    result: BundleVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format bundle verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    lines = [
        DIVIDER,
        "SPECORA BUNDLE VERIFICATION",
        DIVIDER,
        f"Bundle:         {result.bundle_path}",
        f"Schema Version: {result.schema_version or 'unknown'}",
        f"Manifest Hash:  {result.manifest_hash or 'N/A'}",
        f"Artifacts OK:   {result.artifacts_verified}",
        f"Artifacts Fail: {result.artifacts_failed}",
    ]

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.artifacts:
        lines.append("")
        lines.append("Artifacts:")
        for a in result.artifacts:
            status_str = "OK" if a.valid else "FAIL"
            lines.append(f"  [{status_str}] {a.name} ({a.size_bytes} bytes)")
            if not a.valid and a.error:
                lines.append(f"       {a.error}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_anchor_result(
    result: AnchorValidationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format anchor payload validation result.

    Args:
        result: Validation result
        output_format: "text" or "json"
        file_path: Path to anchor payload file (for display)

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA ANCHOR PAYLOAD VERIFICATION",
        DIVIDER,
        f"File:           {file_path}",
        f"Schema Version: {result.schema_version or 'unknown'}",
        f"Root Type:      {result.root_type or 'unknown'}",
        f"Manifest Hash:  {result.manifest_hash or 'N/A'}",
        f"Computed Hash:  {result.computed_hash or 'N/A'}",
    ]

    if result.expected_hash:
        lines.append(f"Expected Hash:  {result.expected_hash}")

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_anchor_vectors_result(
    result: AnchorVectorVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format anchor golden vector verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    lines = [
        DIVIDER,
        "SPECORA ANCHOR VECTOR VERIFICATION",
        DIVIDER,
        f"Vectors Dir:    {result.vectors_dir}",
        f"Total:          {result.total}",
        f"Passed:         {result.passed}",
        f"Failed:         {result.failed}",
    ]

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.results:
        lines.append("")
        for r in result.results:
            status_str = "PASS" if r.valid else "FAIL"
            lines.append(f"  [{status_str}] {r.spec_id} v{r.version}")
            if not r.valid:
                for error in r.errors:
                    lines.append(f"       {error}")

    if result.errors and not any(r.errors for r in result.results):
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_receipt_result(
    result: ReceiptValidationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format anchor receipt validation result.

    Args:
        result: Validation result
        output_format: "text" or "json"
        file_path: Path to anchor receipt file (for display)

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA ANCHOR RECEIPT VERIFICATION",
        DIVIDER,
        f"File:           {file_path}",
        f"Schema Version: {result.schema_version or 'unknown'}",
        f"Anchor Backend: {result.anchor_backend or 'unknown'}",
        f"Receipt ID:     {result.receipt_id or 'N/A'}",
        f"Payload Hash:   {result.payload_hash or 'N/A'}",
        f"Computed Hash:  {result.computed_hash or 'N/A'}",
    ]

    if result.expected_hash:
        lines.append(f"Expected Hash:  {result.expected_hash}")

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_receipt_vectors_result(
    result: ReceiptVectorVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format receipt golden vector verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    lines = [
        DIVIDER,
        "SPECORA RECEIPT VECTOR VERIFICATION",
        DIVIDER,
        f"Vectors Dir:    {result.vectors_dir}",
        f"Total:          {result.total}",
        f"Passed:         {result.passed}",
        f"Failed:         {result.failed}",
    ]

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.results:
        lines.append("")
        for r in result.results:
            status_str = "PASS" if r.valid else "FAIL"
            lines.append(f"  [{status_str}] {r.spec_id} v{r.version}")
            if not r.valid:
                for error in r.errors:
                    lines.append(f"       {error}")

    if result.errors and not any(r.errors for r in result.results):
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_signature_result(
    result: SignatureVerificationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
    trust_result: Any = None,
) -> str:
    """Format signature verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"
        file_path: Path to artifact file (for display)
        trust_result: Optional TrustCheckResult from revocation check

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        if trust_result:
            data["trust"] = trust_result.to_dict()
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA SIGNATURE VERIFICATION",
        DIVIDER,
        f"File:           {file_path}",
        f"Algorithm:      {result.algorithm}",
        f"Manifest Hash:  {result.manifest_hash or 'N/A'}",
        f"Key Fingerprint:{result.key_fingerprint or 'N/A'}",
    ]

    # Determine overall status
    if not result.valid:
        status = "FAIL"
    elif trust_result and not trust_result.trusted:
        status = "FAIL"
    elif trust_result and trust_result.warning:
        status = "WARN"
    else:
        status = "PASS"

    lines.append(f"Status:         {status}")

    # Add trust information if available
    if trust_result:
        lines.append("")
        lines.append("Key Trust:")
        lines.append(
            f"  Revocation List: {'provided' if trust_result.revocation_list_provided else 'not provided'}"
        )
        lines.append(f"  Key Status:      {trust_result.key_status}")
        if trust_result.warning:
            lines.append(f"  Warning:         {trust_result.warning}")
        if trust_result.error:
            lines.append(f"  Error:           {trust_result.error}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_key_info(
    info: KeyInfo,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format public key info.

    Args:
        info: Key information
        output_format: "text" or "json"
        file_path: Path to key file (for display)

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = info.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA PUBLIC KEY INFO",
        DIVIDER,
        f"File:           {file_path}",
        f"Algorithm:      {info.algorithm}",
        f"Key Size:       {info.key_size_bits} bits",
        f"Curve:          {info.curve or 'N/A'}",
        f"Format:         {info.format}",
        f"Fingerprint:    {info.fingerprint or 'N/A'}",
    ]

    status = "VALID" if info.valid else "INVALID"
    lines.append(f"Status:         {status}")

    if info.error:
        lines.append("")
        lines.append("Error:")
        lines.append(f"  {info.error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_certification_check_result(
    result: CertificationCheckResult,
    *,
    output_format: str = "text",
) -> str:
    """Format certification bundle check result.

    Args:
        result: Check result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    lines = [
        DIVIDER,
        "SPECORA CERTIFICATION BUNDLE CHECK",
        DIVIDER,
        f"Bundle:         {result.bundle_path}",
        f"Tier:           {result.tier}",
        f"Artifacts OK:   {len(result.artifacts_found)}",
        f"Artifacts Missing: {len(result.artifacts_missing)}",
        f"Requirements Met: {len(result.requirements_met)}",
        f"Requirements Missing: {len(result.requirements_missing)}",
    ]

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.artifacts_missing:
        lines.append("")
        lines.append("Missing Artifacts:")
        for artifact in result.artifacts_missing:
            lines.append(f"  - {artifact}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_certification_attestation_result(
    result: CertificationAttestationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format certification attestation validation result.

    Args:
        result: Validation result
        output_format: "text" or "json"
        file_path: Path to attestation file (for display)

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA CERTIFICATION ATTESTATION VERIFICATION",
        DIVIDER,
        f"File:           {file_path}",
        f"Spec ID:        {result.spec_id or 'unknown'}",
        f"Schema Version: {result.schema_version or 'unknown'}",
        f"Tier:           {result.tier or 'unknown'}",
        f"Computed Hash:  {result.computed_hash or 'N/A'}",
    ]

    if result.expected_hash:
        lines.append(f"Expected Hash:  {result.expected_hash}")

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_certification_vectors_result(
    result: CertificationVectorVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format certification golden vector verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    lines = [
        DIVIDER,
        "SPECORA CERTIFICATION VECTOR VERIFICATION",
        DIVIDER,
        f"Vectors Dir:    {result.vectors_dir}",
        f"Total:          {result.total}",
        f"Passed:         {result.passed}",
        f"Failed:         {result.failed}",
    ]

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.results:
        lines.append("")
        for r in result.results:
            status_str = "PASS" if r.valid else "FAIL"
            lines.append(f"  [{status_str}] {r.spec_id} v{r.version}")
            if not r.valid:
                for error in r.errors:
                    lines.append(f"       {error}")

    if result.errors and not any(r.errors for r in result.results):
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_error(
    message: str,
    *,
    output_format: str = "text",
    code: str = "ERROR",
) -> str:
    """Format an error message.

    Args:
        message: Error message
        output_format: "text" or "json"
        code: Error code

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(
            {
                "status": "error",
                "code": code,
                "message": message,
            },
            indent=2,
        )

    return f"ERROR [{code}]: {message}"


def format_chain_result(
    result: ChainVerificationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format chain verification result.

    Args:
        result: Chain verification result
        output_format: "text" or "json"
        file_path: Path to chain file (for display)

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA TRANSPARENCY CHAIN VERIFICATION",
        DIVIDER,
        f"File:            {file_path}",
        f"Total Entries:   {result.total_entries}",
        f"Verified Count:  {result.verified_count}",
    ]

    if result.total_entries > 0:
        lines.append(f"Index Range:     {result.start_index} - {result.end_index}")
        if result.first_entry_hash:
            lines.append(f"First Hash:      {result.first_entry_hash[:16]}...")
        if result.last_entry_hash:
            lines.append(f"Last Hash:       {result.last_entry_hash[:16]}...")

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:          {status}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        # Limit to first 10 errors to avoid overwhelming output
        for error in result.errors[:10]:
            lines.append(f"  - {error}")
        if len(result.errors) > 10:
            lines.append(f"  ... and {len(result.errors) - 10} more errors")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_external_anchor_result(
    result: ExternalAnchorVerificationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format external anchor verification result.

    Args:
        result: Verification result from validators.external_anchor
        output_format: "text" or "json"
        file_path: Path to anchor file (for display)

    Returns:
        Formatted string output
    """
    # Import here to avoid circular imports

    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA EXTERNAL ANCHOR VERIFICATION",
        DIVIDER,
        f"File:           {file_path}",
        f"Chain Index:    {result.chain_head_index}",
        f"Anchor Hash:    {result.anchor_hash[:16]}..."
        if result.anchor_hash
        else "Anchor Hash:    N/A",
        f"Previous Hash:  {result.previous_anchor_hash[:16]}..."
        if result.previous_anchor_hash
        else "Previous Hash:  N/A",
    ]

    lines.append(f"Hash Valid:     {'YES' if result.hash_valid else 'NO'}")
    lines.append(f"Signature Valid:{'YES' if result.signature_valid else 'NO'}")
    lines.append(f"Schema Valid:   {'YES' if result.schema_valid else 'NO'}")

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:         {status}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_external_anchor_chain_result(
    result: ExternalAnchorChainResult,
    *,
    output_format: str = "text",
    directory_path: str = "",
) -> str:
    """Format external anchor chain verification result.

    Args:
        result: Verification result from validators.external_anchor
        output_format: "text" or "json"
        directory_path: Path to anchors directory (for display)

    Returns:
        Formatted string output
    """
    # Import here to avoid circular imports

    if output_format == "json":
        data = result.to_dict()
        data["directory"] = directory_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "SPECORA EXTERNAL ANCHOR CHAIN VERIFICATION",
        DIVIDER,
        f"Directory:       {directory_path}",
        f"Total Anchors:   {result.total_anchors}",
        f"Verified Count:  {result.verified_count}",
    ]

    if result.first_chain_index is not None:
        lines.append(f"Chain Index Range: {result.first_chain_index} - {result.last_chain_index}")
    if result.first_anchor_hash:
        lines.append(f"First Hash:      {result.first_anchor_hash[:16]}...")
    if result.last_anchor_hash:
        lines.append(f"Last Hash:       {result.last_anchor_hash[:16]}...")

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:          {status}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors[:10]:
            lines.append(f"  - {error}")
        if len(result.errors) > 10:
            lines.append(f"  ... and {len(result.errors) - 10} more errors")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_mirror_result(
    result: MirrorVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format mirror verification result.

    Args:
        result: Mirror verification result from validators.mirror
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    # Import here to avoid circular imports
    from specora_verify.validators.mirror import MirrorStatus

    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    # Map status to display string
    status_display = {
        MirrorStatus.PASS: "PASS",
        MirrorStatus.WARN: "WARN",
        MirrorStatus.FAIL: "FAIL",
        MirrorStatus.ERROR: "ERROR",
    }

    lines = [
        DIVIDER,
        "SPECORA MIRROR VERIFICATION",
        DIVIDER,
        f"Sources Checked:    {result.sources_checked}",
        f"Sources Reachable:  {result.sources_reachable}",
        f"Quorum Required:    {result.quorum_required}",
        f"Quorum Achieved:    {result.quorum_achieved}",
    ]

    if result.consensus_anchor_hash:
        hash_display = result.consensus_anchor_hash
        if len(hash_display) > 32:
            hash_display = f"{hash_display[:16]}...{hash_display[-8:]}"
        lines.append(f"Consensus Hash:     {hash_display}")

    if result.consensus_chain_index is not None:
        lines.append(f"Chain Index:        {result.consensus_chain_index}")

    if result.hash_mismatch_detected:
        lines.append("Hash Mismatch:      YES (INV-ANCHOR-009 violation)")
        if result.mismatched_sources:
            lines.append(f"Mismatched Sources: {', '.join(result.mismatched_sources)}")

    lines.append(f"Status:             {status_display.get(result.status, 'UNKNOWN')}")

    # Show per-source results
    if result.source_results:
        lines.append("")
        lines.append("Sources:")
        for name, source_result in result.source_results.items():
            reachable = "OK" if source_result.reachable else "UNREACHABLE"
            hash_info = ""
            if source_result.anchor_hash:
                h = source_result.anchor_hash
                hash_info = f" hash={h[:16]}..."
            latency = f" ({source_result.fetch_latency_ms}ms)"
            lines.append(f"  [{reachable}] {name}{hash_info}{latency}")
            if source_result.error:
                lines.append(f"         Error: {source_result.error}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_anchor_chain_result(
    result: AnchorChainVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format anchor chain verification result.

    Args:
        result: Anchor chain verification result from validators.mirror
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    # Import here to avoid circular imports
    from specora_verify.validators.mirror import MirrorStatus

    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    # Map status to display string
    status_display = {
        MirrorStatus.PASS: "PASS",
        MirrorStatus.WARN: "WARN",
        MirrorStatus.FAIL: "FAIL",
        MirrorStatus.ERROR: "ERROR",
    }

    lines = [
        DIVIDER,
        "SPECORA ANCHOR CHAIN VERIFICATION",
        DIVIDER,
        f"Total Anchors:      {result.total_anchors}",
        f"Verified Anchors:   {result.verified_anchors}",
    ]

    if result.first_index is not None:
        lines.append(f"Index Range:        {result.first_index} - {result.last_index}")

    lines.append(f"Chain Linkage:      {'VALID' if result.chain_linkage_valid else 'BROKEN'}")
    lines.append(
        f"Cross-Surface:      {'CONSISTENT' if result.cross_surface_consistent else 'MISMATCH'}"
    )

    if result.mismatched_indices:
        lines.append(f"Mismatched At:      {result.mismatched_indices}")

    if result.broken_linkages:
        lines.append(f"Broken Links At:    {result.broken_linkages}")

    lines.append(f"Status:             {status_display.get(result.status, 'UNKNOWN')}")

    # Show per-anchor summary (limit to first 10)
    if result.anchor_details:
        lines.append("")
        lines.append("Anchor Details:")
        for detail in result.anchor_details[:10]:
            status_mark = (
                "OK" if detail.cross_surface_match and detail.chain_linkage_valid else "FAIL"
            )
            hash_str = f"{detail.anchor_hash[:16]}..." if detail.anchor_hash else "N/A"
            lines.append(f"  [{status_mark}] #{detail.chain_index}: {hash_str}")
            if detail.errors:
                for err in detail.errors:
                    lines.append(f"         {err}")
        if len(result.anchor_details) > 10:
            lines.append(f"  ... and {len(result.anchor_details) - 10} more anchors")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


# =============================================================================
# Witness Verification Formatters (PR-ENT-550)
# =============================================================================


def format_witness_statement_result(
    result: WitnessStatementResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format single witness statement verification result.

    Args:
        result: WitnessStatementResult from validation
        output_format: "text" or "json"
        file_path: Optional file path for display

    Returns:
        Formatted string
    """

    if output_format == "json":
        output = result.to_dict()
        if file_path:
            output["file_path"] = file_path
        return json.dumps(output, indent=2, sort_keys=True)

    # Text format
    lines = [DIVIDER, "SPECORA WITNESS STATEMENT VERIFICATION", DIVIDER]

    if file_path:
        lines.append(f"File:               {file_path}")

    lines.append(f"Witness Org:        {result.witness_org_id}")
    lines.append(f"Verification:       {result.verification_result}")

    if result.anchor_hash:
        hash_display = f"{result.anchor_hash[:16]}...{result.anchor_hash[-8:]}"
        lines.append(f"Anchor Hash:        {hash_display}")

    if result.anchor_index is not None:
        lines.append(f"Anchor Index:       {result.anchor_index}")

    lines.append(f"Signature Valid:    {'YES' if result.signature_valid else 'NO'}")

    if result.witness_status:
        lines.append(f"Witness Status:     {result.witness_status.value.upper()}")

    status_display = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:             {status_display}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_witness_quorum_result(
    result: WitnessQuorumResult,
    *,
    output_format: str = "text",
) -> str:
    """Format witness quorum verification result.

    Args:
        result: WitnessQuorumResult from verification
        output_format: "text" or "json"

    Returns:
        Formatted string
    """
    from specora_verify.validators.witness import WitnessVerificationStatus

    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)

    # Text format
    lines = [DIVIDER, "SPECORA WITNESS QUORUM VERIFICATION", DIVIDER]

    lines.append(f"Witnesses Checked:  {result.witnesses_checked}")
    lines.append(f"Witnesses Valid:    {result.witnesses_valid}")
    lines.append(f"Quorum Required:    {result.quorum_required}")
    lines.append(f"Quorum Achieved:    {result.quorum_achieved}")

    if result.consensus_anchor_hash:
        hash_display = f"{result.consensus_anchor_hash[:16]}...{result.consensus_anchor_hash[-8:]}"
        lines.append(f"Consensus Hash:     {hash_display}")

    if result.consensus_anchor_index is not None:
        lines.append(f"Consensus Index:    {result.consensus_anchor_index}")

    lines.append(f"Hash Mismatch:      {'YES' if result.hash_mismatch_detected else 'NO'}")

    status_display = {
        WitnessVerificationStatus.PASS: "PASS",
        WitnessVerificationStatus.WARN: "WARN",
        WitnessVerificationStatus.FAIL: "FAIL",
        WitnessVerificationStatus.ERROR: "ERROR",
    }
    lines.append(f"Status:             {status_display.get(result.status, 'UNKNOWN')}")

    # Show per-witness results
    if result.statement_results:
        lines.append("")
        lines.append("Witnesses:")
        for org_id, stmt_result in result.statement_results.items():
            status_mark = "VALID" if stmt_result.valid else "INVALID"
            sig_status = "valid" if stmt_result.signature_valid else "invalid"
            witness_status = (
                stmt_result.witness_status.value if stmt_result.witness_status else "unknown"
            )
            lines.append(f"  [{status_mark}] {org_id}")
            lines.append(
                f"         Verification: {stmt_result.verification_result} | Signature: {sig_status} | Status: {witness_status}"
            )
            if stmt_result.errors:
                for err in stmt_result.errors:
                    lines.append(f"         Error: {err}")

    if result.mismatched_witnesses:
        lines.append("")
        lines.append(f"Mismatched Witnesses: {', '.join(result.mismatched_witnesses)}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_witness_registry_info(
    registry: WitnessRegistry,
    *,
    output_format: str = "text",
) -> str:
    """Format witness registry information.

    Args:
        registry: WitnessRegistry object
        output_format: "text" or "json"

    Returns:
        Formatted string
    """
    from specora_verify.validators.witness import WitnessStatus

    if output_format == "json":
        return json.dumps(registry.to_dict(), indent=2, sort_keys=True)

    # Text format
    lines = [DIVIDER, "SPECORA WITNESS REGISTRY", DIVIDER]

    lines.append(f"Version:            {registry.registry_version}")
    lines.append(f"Generated:          {registry.generated_at}")
    lines.append(f"Authority:          {registry.registry_authority}")
    lines.append(f"Total Witnesses:    {len(registry.witnesses)}")

    active_count = sum(1 for w in registry.witnesses if w.status == WitnessStatus.ACTIVE)
    revoked_count = sum(1 for w in registry.witnesses if w.status == WitnessStatus.REVOKED)
    suspended_count = sum(1 for w in registry.witnesses if w.status == WitnessStatus.SUSPENDED)

    lines.append(f"Active:             {active_count}")
    lines.append(f"Suspended:          {suspended_count}")
    lines.append(f"Revoked:            {revoked_count}")

    if registry.witnesses:
        lines.append("")
        lines.append("Witnesses:")
        for witness in registry.witnesses:
            status_display = witness.status.value.upper()
            lines.append(f"  [{status_display}] {witness.witness_org_id}")
            lines.append(f"         Name: {witness.org_name}")
            lines.append(f"         Key ID: {witness.public_key_id}")
            lines.append(f"         Trust: {witness.trust_level}")
            if witness.revoked_at:
                lines.append(f"         Revoked: {witness.revoked_at}")
                if witness.revocation_reason:
                    lines.append(f"         Reason: {witness.revocation_reason}")

    lines.append(DIVIDER)
    return "\n".join(lines)


# =============================================================================
# Registry Snapshot Formatters (PR-ENT-560)
# =============================================================================


def format_registry_snapshot_result(
    result: SnapshotVerificationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format registry snapshot verification result.

    Args:
        result: SnapshotVerificationResult object
        output_format: "text" or "json"
        file_path: Optional file path for display

    Returns:
        Formatted string
    """

    if output_format == "json":
        data = result.to_dict()
        if file_path:
            data["file_path"] = file_path
        return json.dumps(data, indent=2, sort_keys=True)

    # Text format
    lines = [DIVIDER, "SPECORA REGISTRY SNAPSHOT VERIFICATION", DIVIDER]

    if file_path:
        lines.append(f"File:               {file_path}")

    if result.registry_version is not None:
        lines.append(f"Version:            {result.registry_version}")
    if result.generated_at:
        lines.append(f"Generated:          {result.generated_at}")
    if result.registry_hash:
        lines.append(
            f"Registry Hash:      {result.registry_hash[:16]}...{result.registry_hash[-8:]}"
        )
    if result.previous_registry_hash:
        if result.is_genesis:
            lines.append("Previous Hash:      (genesis)")
        else:
            lines.append(f"Previous Hash:      {result.previous_registry_hash[:16]}...")

    lines.append(f"Hash Valid:         {'YES' if result.hash_valid else 'NO'}")
    lines.append(
        f"Signature Valid:    {'YES' if result.signature_valid else 'NO' if not result.warnings else 'SKIPPED'}"
    )

    status = "PASS" if result.valid else "FAIL"
    lines.append(f"Status:             {status}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_registry_chain_result(
    result: ChainVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format registry chain verification result.

    Args:
        result: ChainVerificationResult object
        output_format: "text" or "json"

    Returns:
        Formatted string
    """

    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)

    # Text format
    lines = [DIVIDER, "SPECORA REGISTRY CHAIN VERIFICATION", DIVIDER]

    lines.append(f"Chain Length:       {result.chain_length}")
    lines.append(f"Chain Valid:        {'YES' if result.chain_valid else 'NO'}")
    if result.latest_version is not None:
        lines.append(f"Latest Version:     {result.latest_version}")
    if result.latest_hash:
        lines.append(f"Latest Hash:        {result.latest_hash[:16]}...{result.latest_hash[-8:]}")

    status_display = result.status.value.upper()
    lines.append(f"Status:             {status_display}")

    if result.snapshot_results:
        lines.append("")
        lines.append("Snapshots:")
        for version in sorted(result.snapshot_results.keys()):
            snap_result = result.snapshot_results[version]
            status = "VALID" if snap_result.valid else "INVALID"
            genesis_marker = " (genesis)" if snap_result.is_genesis else ""
            lines.append(f"  [v{version:04d}] {status}{genesis_marker}")
            if not snap_result.valid and snap_result.errors:
                for error in snap_result.errors[:2]:  # Show first 2 errors
                    lines.append(f"           Error: {error[:60]}...")

    if result.revocation_violations:
        lines.append("")
        lines.append("Revocation Violations:")
        for violation in result.revocation_violations:
            lines.append(f"  - {violation}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    if result.errors and not result.revocation_violations:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_registry_snapshot_info(
    snapshot: RegistrySnapshot,
    *,
    output_format: str = "text",
) -> str:
    """Format registry snapshot information.

    Args:
        snapshot: RegistrySnapshot object
        output_format: "text" or "json"

    Returns:
        Formatted string
    """

    if output_format == "json":
        return json.dumps(snapshot.to_dict(), indent=2, sort_keys=True)

    # Text format
    lines = [DIVIDER, "SPECORA REGISTRY SNAPSHOT", DIVIDER]

    lines.append(f"Version:            {snapshot.registry_version}")
    lines.append(f"Generated:          {snapshot.generated_at}")
    lines.append(f"Authority:          {snapshot.registry_authority}")
    lines.append(
        f"Registry Hash:      {snapshot.registry_hash[:16]}...{snapshot.registry_hash[-8:]}"
    )

    if snapshot.is_genesis():
        lines.append("Previous Hash:      (genesis)")
    else:
        lines.append(f"Previous Hash:      {snapshot.previous_registry_hash[:16]}...")

    lines.append(f"Signing Key:        {snapshot.registry_key_id}")
    lines.append(f"Total Witnesses:    {len(snapshot.witnesses)}")

    active_count = sum(1 for w in snapshot.witnesses if w.status == "active")
    revoked_count = sum(1 for w in snapshot.witnesses if w.status == "revoked")
    suspended_count = sum(1 for w in snapshot.witnesses if w.status == "suspended")

    lines.append(f"Active:             {active_count}")
    lines.append(f"Suspended:          {suspended_count}")
    lines.append(f"Revoked:            {revoked_count}")

    if snapshot.witnesses:
        lines.append("")
        lines.append("Witnesses:")
        for witness in snapshot.witnesses:
            status_display = witness.status.upper()
            lines.append(f"  [{status_display}] {witness.witness_org_id}")
            lines.append(f"         Name: {witness.org_name}")
            lines.append(f"         Trust: {witness.trust_level}")
            lines.append(f"         Keys: {len(witness.keys)}")
            for key in witness.keys:
                key_status = key.status.upper()
                lines.append(f"           [{key_status}] {key.public_key_id}")

    lines.append(DIVIDER)
    return "\n".join(lines)


# =============================================================================
# STP Output Formatters (PLATFORM-470)
# =============================================================================


def format_stp_init_result(
    result: STPInitResult,
    *,
    output_format: str = "text",
) -> str:
    """Format STP scaffold initialization result.

    Args:
        result: Initialization result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    status = "SUCCESS" if result.success else "FAILED"
    lines = [
        DIVIDER,
        "STP INTEGRATION SCAFFOLD",
        DIVIDER,
        f"Status:       {status}",
        f"Output:       {result.output_dir}",
        f"Runtime:      {result.runtime}",
    ]

    if result.files_created:
        lines.append("")
        lines.append("Files Created:")
        for f in result.files_created:
            lines.append(f"  - {f}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in result.warnings:
            lines.append(f"  - {w}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for e in result.errors:
            lines.append(f"  - {e}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_stp_verify_result(
    result: STPVerifyResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format STP message verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"
        file_path: Path to message file

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    status = "PASS" if result.valid else "FAIL"
    lines = [
        DIVIDER,
        "STP MESSAGE VERIFICATION",
        DIVIDER,
        f"File:             {file_path}",
        f"Message Type:     {result.message_type or 'unknown'}",
        f"Protocol Version: {result.protocol_version or 'unknown'}",
        f"Schema Valid:     {'Yes' if result.schema_valid else 'No'}",
    ]

    if result.seal_valid is not None:
        lines.append(f"Seal Valid:       {'Yes' if result.seal_valid else 'No'}")
    if result.computed_seal:
        lines.append(f"Computed Seal:    {result.computed_seal[:32]}...")

    lines.append(f"Status:           {status}")

    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in result.warnings:
            lines.append(f"  - {w}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for e in result.errors:
            lines.append(f"  - {e}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_stp_simulate_result(
    result: STPSimulateResult,
    *,
    output_format: str = "text",
) -> str:
    """Format STP decision simulation result.

    Args:
        result: Simulation result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    decision_display = result.decision.upper()
    lines = [
        DIVIDER,
        "STP DECISION SIMULATION",
        DIVIDER,
        f"Decision:     {decision_display}",
        f"Trust Score:  {result.trust_score}",
        f"Policy:       {result.policy_path}",
        f"Policy Hash:  {result.policy_hash[:32]}..."
        if result.policy_hash
        else "Policy Hash:  N/A",
    ]

    if result.restrictions:
        lines.append(f"Restrictions: {json.dumps(result.restrictions)}")

    if result.reasons:
        lines.append("")
        lines.append("Reasons:")
        for r in result.reasons:
            lines.append(f"  - {r}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_stp_inspect_result(
    result: STPInspectResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format STP artifact inspection result.

    Args:
        result: Inspection result
        output_format: "text" or "json"
        file_path: Path to artifact file

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    lines = [
        DIVIDER,
        "STP ARTIFACT INSPECTION",
        DIVIDER,
        f"File:             {file_path}",
        f"Artifact Type:    {result.artifact_type}",
        f"Message Type:     {result.message_type or 'N/A'}",
        f"Protocol Version: {result.protocol_version or 'N/A'}",
        f"Timestamp:        {result.timestamp or 'N/A'}",
    ]

    if result.computed_seal:
        lines.append(f"Computed Seal:    {result.computed_seal}")

    if result.chain_position is not None:
        lines.append(f"Chain Position:   {result.chain_position}")

    if result.fields:
        lines.append("")
        lines.append("Fields:")
        for key, value in result.fields.items():
            if isinstance(value, dict):
                lines.append(f"  {key}:")
                for k, v in value.items():
                    lines.append(f"    {k}: {v}")
            else:
                lines.append(f"  {key}: {value}")

    if result.canonical_json:
        lines.append("")
        lines.append("Canonical JSON:")
        lines.append(result.canonical_json)

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_stp_vectors_result(
    result: STPVectorsResult,
    *,
    output_format: str = "text",
) -> str:
    """Format STP vector verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    status = "PASS" if result.valid else "FAIL"
    lines = [
        DIVIDER,
        "STP GOLDEN VECTOR VERIFICATION",
        DIVIDER,
        f"Vectors Dir: {result.vectors_dir}",
        f"Total:       {result.total}",
        f"Passed:      {result.passed}",
        f"Failed:      {result.failed}",
        f"Status:      {status}",
    ]

    if result.results:
        lines.append("")
        lines.append("Results:")
        for r in result.results:
            status_mark = "+" if r.valid else "x"
            lines.append(f"  {status_mark} {r.spec_id} v{r.version}")
            if not r.valid and r.errors:
                for e in r.errors:
                    lines.append(f"      {e}")

    if result.errors and not result.results:
        lines.append("")
        lines.append("Errors:")
        for e in result.errors:
            lines.append(f"  - {e}")

    lines.append(DIVIDER)
    return "\n".join(lines)


# =============================================================================
# STP Certification Formatters
# =============================================================================


def format_stp_certification_scaffold_result(
    result: STPCertificationCheckResult,
    *,
    output_format: str = "text",
) -> str:
    """Format STP certification scaffold generation result.

    Args:
        result: Scaffold generation result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    status = "SUCCESS" if result.valid else "FAILED"
    lines = [
        DIVIDER,
        "STP CERTIFICATION SCAFFOLD",
        DIVIDER,
        f"Tier:           {result.tier}",
        f"Adapter:        {result.adapter_name} v{result.adapter_version}",
        f"Output:         {result.bundle_path}",
        f"Status:         {status}",
    ]

    if result.artifacts_found:
        lines.append("")
        lines.append("Files Created:")
        for artifact in result.artifacts_found:
            lines.append(f"  + {artifact}")

    if result.requirements_missing:
        lines.append("")
        lines.append("Requirements (pending verification):")
        for req in result.requirements_missing[:5]:
            lines.append(f"  - {req}")
        if len(result.requirements_missing) > 5:
            lines.append(f"  ... and {len(result.requirements_missing) - 5} more")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for e in result.errors:
            lines.append(f"  - {e}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_stp_certification_check_result(
    result: STPCertificationCheckResult,
    *,
    output_format: str = "text",
) -> str:
    """Format STP certification bundle check result.

    Args:
        result: Check result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    status = "PASS" if result.valid else "FAIL"
    lines = [
        DIVIDER,
        "STP CERTIFICATION CHECK",
        DIVIDER,
        f"Tier:               {result.tier}",
        f"Bundle:             {result.bundle_path}",
        f"Adapter:            {result.adapter_name} v{result.adapter_version}",
        f"Artifacts Found:    {len(result.artifacts_found)}",
        f"Artifacts Missing:  {len(result.artifacts_missing)}",
        f"Requirements Met:   {len(result.requirements_met)}",
        f"Requirements Miss:  {len(result.requirements_missing)}",
        f"Status:             {status}",
    ]

    if result.artifacts_missing:
        lines.append("")
        lines.append("Missing Artifacts:")
        for artifact in result.artifacts_missing:
            lines.append(f"  - {artifact}")

    if result.requirements_met:
        lines.append("")
        lines.append("Requirements Met:")
        for req in result.requirements_met[:5]:
            lines.append(f"  + {req}")
        if len(result.requirements_met) > 5:
            lines.append(f"  ... and {len(result.requirements_met) - 5} more")

    if result.requirements_missing:
        lines.append("")
        lines.append("Requirements Missing:")
        for req in result.requirements_missing[:5]:
            lines.append(f"  - {req}")
        if len(result.requirements_missing) > 5:
            lines.append(f"  ... and {len(result.requirements_missing) - 5} more")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for e in result.errors:
            lines.append(f"  - {e}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_stp_certification_attestation_result(
    result: STPCertificationAttestationResult,
    *,
    output_format: str = "text",
    file_path: str = "",
) -> str:
    """Format STP certification attestation validation result.

    Args:
        result: Attestation validation result
        output_format: "text" or "json"
        file_path: Path to attestation file (for display)

    Returns:
        Formatted string output
    """
    if output_format == "json":
        data = result.to_dict()
        data["file"] = file_path
        return json.dumps(data, indent=2)

    status = "PASS" if result.valid else "FAIL"
    lines = [
        DIVIDER,
        "STP CERTIFICATION ATTESTATION",
        DIVIDER,
        f"File:           {file_path}",
        f"Spec ID:        {result.spec_id or 'unknown'}",
        f"Schema Version: {result.schema_version or 'unknown'}",
        f"Tier:           {result.tier or 'unknown'}",
        f"Adapter:        {result.adapter_name or 'unknown'} v{result.adapter_version or 'unknown'}",
        f"Computed Hash:  {result.computed_hash or 'N/A'}",
    ]

    if result.expected_hash:
        lines.append(f"Expected Hash:  {result.expected_hash}")

    if result.signature_valid is not None:
        sig_status = "valid" if result.signature_valid else "INVALID"
        lines.append(f"Signature:      {sig_status}")

    lines.append(f"Status:         {status}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for e in result.errors:
            lines.append(f"  - {e}")

    lines.append(DIVIDER)
    return "\n".join(lines)


def format_stp_certification_vectors_result(
    result: STPCertificationVectorVerificationResult,
    *,
    output_format: str = "text",
) -> str:
    """Format STP certification vector verification result.

    Args:
        result: Verification result
        output_format: "text" or "json"

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    status = "PASS" if result.valid else "FAIL"
    lines = [
        DIVIDER,
        "STP CERTIFICATION VECTOR VERIFICATION",
        DIVIDER,
        f"Vectors Dir: {result.vectors_dir}",
        f"Total:       {result.total}",
        f"Passed:      {result.passed}",
        f"Failed:      {result.failed}",
        f"Status:      {status}",
    ]

    if result.results:
        lines.append("")
        lines.append("Results:")
        for r in result.results:
            status_mark = "+" if r.valid else "x"
            lines.append(f"  {status_mark} {r.spec_id} v{r.version} ({r.tier})")
            if not r.valid and r.errors:
                for e in r.errors:
                    lines.append(f"      {e}")

    if result.errors and not result.results:
        lines.append("")
        lines.append("Errors:")
        for e in result.errors:
            lines.append(f"  - {e}")

    lines.append(DIVIDER)
    return "\n".join(lines)
