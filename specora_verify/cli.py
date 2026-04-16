"""Command-line interface for specora-verify.

Usage:
    specora-verify verify --artifact <file> --signature <sig.b64> --public-key <key.pem>
    specora-verify verify-log --log <file> [--public-key <key.pem>]
    specora-verify verify-external-anchor <file> [--public-key <key.pem>] [--skip-signature]
    specora-verify verify-external-anchor-chain <dir> [--public-key <key.pem>] [--skip-signatures]
    specora-verify emit-receipt --artifact <file> [--signature <sig.b64>] [--public-key <key.pem>] [--out <receipt.json>]
    specora-verify canonicalize <file>
    specora-verify key-info --public-key <key.pem>
    specora-verify vectors verify [--vectors-dir DIR]
    specora-verify manifest hash <file>
    specora-verify manifest verify <file> [--expected-hash HASH] [--spec-id ID] [--schema-version VER]
    specora-verify bundle verify <file>
    specora-verify anchor vectors verify [--vectors-dir DIR]
    specora-verify anchor hash <file>
    specora-verify anchor verify <file> [--expected HASH]
    specora-verify receipt vectors verify [--vectors-dir DIR]
    specora-verify receipt hash <file>
    specora-verify receipt verify <file> [--expected HASH]
    specora-verify certify scaffold --tier <basic|enterprise|regulated> --name <name> --version <ver> [--out <dir>]
    specora-verify certify check --tier <basic|enterprise|regulated> --bundle <path>
    specora-verify certify attest --tier <...> --bundle <path> --out <attestation.json>
    specora-verify certify vectors verify [--vectors-dir DIR]
    specora-verify certify hash <file>
    specora-verify stp init [--runtime <runtime>] [--org-id <uuid>] [--out <dir>]
    specora-verify stp verify <file> [--schema <type>] [--strict] [--check-seal]
    specora-verify stp simulate <file> [--policy <file>] [--trust-score <0-100>]
    specora-verify stp inspect <file> [--show-seal] [--show-chain] [--show-canonical]
    specora-verify stp vectors verify [--vectors-dir DIR]
    specora-verify stp hash <file>
    specora-verify stp certify scaffold --tier <compatible|governed|enterprise> --adapter-name <name> [--out <dir>]
    specora-verify stp certify check --tier <compatible|governed|enterprise> --bundle <path>
    specora-verify stp certify attest --tier <...> --bundle <path> --out <attestation.json> --issued-at <ts>
    specora-verify stp certify verify <file> [--expected HASH]
    specora-verify stp certify vectors verify [--vectors-dir DIR]
    specora-verify mirror verify-latest [--github-repo REPO] [--s3-url URL] [--dns-fqdn FQDN] [--quorum N]
    specora-verify mirror verify-anchors --since DATE [--github-repo REPO] [--s3-prefix URL] [--quorum N]

Global Options:
    --ci                        CI mode: map WARN exit code to FAIL (exit 2)
    --revocation-list <file>    Path to offline key revocation list JSON
    --require-trusted-key       Fail if key is not explicitly active in revocation list

Exit codes:
    0 - PASS (verification succeeded)
    1 - WARN (retired key, unknown key trust, some sources unreachable)
    2 - FAIL (verification failed, revoked key, hash mismatch)
    3 - ERROR (operational error: file not found, parse error, quorum failure)

CI Mode:
    With --ci, WARN (1) is mapped to FAIL (2) for pipeline compatibility.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn

from specora_verify import __version__
from specora_verify.canonical import canonical_json_str
from specora_verify.errors import (
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_PASS,
    EXIT_WARN,
    exit_code_name,
    map_exit_code_for_ci,
)
from specora_verify.hash import compute_manifest_hash
from specora_verify.output import (
    format_anchor_result,
    format_anchor_vectors_result,
    format_bundle_result,
    format_certification_attestation_result,
    format_certification_check_result,
    format_certification_vectors_result,
    format_chain_result,
    format_error,
    format_hash_result,
    format_key_info,
    format_manifest_result,
    format_receipt_result,
    format_receipt_vectors_result,
    format_signature_result,
    format_stp_init_result,
    format_stp_certification_attestation_result,
    format_stp_certification_check_result,
    format_stp_certification_scaffold_result,
    format_stp_certification_vectors_result,
    format_stp_inspect_result,
    format_stp_simulate_result,
    format_stp_vectors_result,
    format_stp_verify_result,
    format_vectors_result,
)
from specora_verify.validators.anchor import validate_anchor_payload, verify_anchor_vectors
from specora_verify.validators.bundle import verify_bundle
from specora_verify.validators.certification import (
    check_certification_bundle,
    generate_attestation,
    validate_attestation,
    verify_certification_vectors,
)
from specora_verify.validators.manifest import validate_manifest
from specora_verify.validators.receipt import validate_receipt, verify_receipt_vectors
from specora_verify.validators.stp import (
    generate_stp_scaffold,
    inspect_stp_artifact,
    simulate_stp_decision,
    validate_stp_message,
    verify_stp_vectors,
)
from specora_verify.validators.stp_certification import (
    check_stp_certification_bundle,
    generate_stp_certification_attestation,
    generate_stp_certification_scaffold,
    validate_stp_certification_attestation,
    verify_stp_certification_vectors,
)
from specora_verify.stp_contracts import STP_RUNTIME_TYPES
from specora_verify.validators.vectors import verify_vectors


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="specora-verify",
        description="Specora Public Manifest Verifier CLI - Verify proof manifests and bundles offline",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"specora-verify {__version__}",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: map WARN exit code to FAIL (exit 2) for pipeline compatibility",
    )
    parser.add_argument(
        "--revocation-list",
        type=Path,
        help="Path to offline key revocation list JSON for trust verification",
    )
    parser.add_argument(
        "--require-trusted-key",
        action="store_true",
        help="Fail if key is not explicitly active in revocation list",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # verify command (signature verification)
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify Ed25519 signature on artifact",
    )
    verify_parser.add_argument(
        "--artifact",
        type=Path,
        required=True,
        help="Path to artifact JSON file",
    )
    verify_parser.add_argument(
        "--signature",
        type=Path,
        required=True,
        help="Path to signature file (base64 encoded)",
    )
    verify_parser.add_argument(
        "--public-key",
        type=Path,
        required=True,
        help="Path to public key file (PEM or base64)",
    )

    # verify-log command (chain verification)
    verify_log_parser = subparsers.add_parser(
        "verify-log",
        help="Verify transparency chain integrity offline",
    )
    verify_log_parser.add_argument(
        "--log",
        type=Path,
        required=True,
        help="Path to transparency log file (JSON array or NDJSON)",
    )
    verify_log_parser.add_argument(
        "--public-key",
        type=Path,
        help="Path to public key file for signature verification (optional)",
    )
    verify_log_parser.add_argument(
        "--skip-signatures",
        action="store_true",
        help="Skip signature verification (only verify chain integrity)",
    )

    # canonicalize command
    canonicalize_parser = subparsers.add_parser(
        "canonicalize",
        help="Output canonical JSON form of artifact",
    )
    canonicalize_parser.add_argument(
        "file",
        type=Path,
        help="Artifact JSON file to canonicalize",
    )

    # key-info command
    key_info_parser = subparsers.add_parser(
        "key-info",
        help="Display public key information",
    )
    key_info_parser.add_argument(
        "--public-key",
        type=Path,
        required=True,
        help="Path to public key file (PEM or base64)",
    )

    # emit-receipt command
    emit_receipt_parser = subparsers.add_parser(
        "emit-receipt",
        help="Generate verification receipt (archivable proof of verification)",
    )
    emit_receipt_parser.add_argument(
        "--artifact",
        type=Path,
        help="Path to artifact JSON file",
    )
    emit_receipt_parser.add_argument(
        "--manifest",
        type=Path,
        help="Path to manifest JSON file (for bundle verification)",
    )
    emit_receipt_parser.add_argument(
        "--signature",
        type=Path,
        help="Path to signature file (base64 encoded)",
    )
    emit_receipt_parser.add_argument(
        "--public-key",
        type=Path,
        help="Path to public key file (PEM or base64)",
    )
    emit_receipt_parser.add_argument(
        "--out",
        type=Path,
        help="Output file for receipt JSON (default: stdout)",
    )
    emit_receipt_parser.add_argument(
        "--allow-hash-only",
        action="store_true",
        help="Allow PASS result for hash-only verification (no signature)",
    )

    # vectors command
    vectors_parser = subparsers.add_parser(
        "vectors",
        help="Golden vector operations",
    )
    vectors_sub = vectors_parser.add_subparsers(dest="vectors_command")

    vectors_verify = vectors_sub.add_parser(
        "verify",
        help="Verify golden test vectors (self-test)",
    )
    vectors_verify.add_argument(
        "--vectors-dir",
        type=Path,
        help="Path to vectors directory (default: bundled)",
    )

    # manifest command
    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Manifest operations",
    )
    manifest_sub = manifest_parser.add_subparsers(dest="manifest_command")

    # manifest hash
    manifest_hash = manifest_sub.add_parser(
        "hash",
        help="Compute canonical SHA-256 hash of manifest",
    )
    manifest_hash.add_argument(
        "file",
        type=Path,
        help="Manifest JSON file",
    )

    # manifest verify
    manifest_verify = manifest_sub.add_parser(
        "verify",
        help="Verify manifest structure and optionally hash",
    )
    manifest_verify.add_argument(
        "file",
        type=Path,
        help="Manifest JSON file",
    )
    manifest_verify.add_argument(
        "--expected-hash",
        help="Expected SHA-256 hash to verify against",
    )
    manifest_verify.add_argument(
        "--spec-id",
        help="Override spec_id detection (e.g., proof-manifest)",
    )
    manifest_verify.add_argument(
        "--schema-version",
        help="Override schema version (e.g., 1.0.0)",
    )

    # bundle command
    bundle_parser = subparsers.add_parser(
        "bundle",
        help="Bundle operations",
    )
    bundle_sub = bundle_parser.add_subparsers(dest="bundle_command")

    bundle_verify = bundle_sub.add_parser(
        "verify",
        help="Verify proof bundle ZIP integrity",
    )
    bundle_verify.add_argument(
        "file",
        type=Path,
        help="Bundle ZIP file",
    )

    # anchor command
    anchor_parser = subparsers.add_parser(
        "anchor",
        help="Anchor payload operations",
    )
    anchor_sub = anchor_parser.add_subparsers(dest="anchor_command")

    # anchor vectors verify
    anchor_vectors = anchor_sub.add_parser(
        "vectors",
        help="Anchor vector operations",
    )
    anchor_vectors_sub = anchor_vectors.add_subparsers(dest="anchor_vectors_command")

    anchor_vectors_verify = anchor_vectors_sub.add_parser(
        "verify",
        help="Verify anchor golden test vectors",
    )
    anchor_vectors_verify.add_argument(
        "--vectors-dir",
        type=Path,
        help="Path to anchor vectors directory (default: bundled)",
    )

    # anchor hash
    anchor_hash = anchor_sub.add_parser(
        "hash",
        help="Compute canonical SHA-256 hash of anchor payload",
    )
    anchor_hash.add_argument(
        "file",
        type=Path,
        help="Anchor payload JSON file",
    )

    # anchor verify
    anchor_verify = anchor_sub.add_parser(
        "verify",
        help="Verify anchor payload structure and optionally hash",
    )
    anchor_verify.add_argument(
        "file",
        type=Path,
        help="Anchor payload JSON file",
    )
    anchor_verify.add_argument(
        "--expected",
        help="Expected SHA-256 hash to verify against",
    )

    # receipt command
    receipt_parser = subparsers.add_parser(
        "receipt",
        help="Anchor receipt operations",
    )
    receipt_sub = receipt_parser.add_subparsers(dest="receipt_command")

    # receipt vectors verify
    receipt_vectors = receipt_sub.add_parser(
        "vectors",
        help="Receipt vector operations",
    )
    receipt_vectors_sub = receipt_vectors.add_subparsers(dest="receipt_vectors_command")

    receipt_vectors_verify = receipt_vectors_sub.add_parser(
        "verify",
        help="Verify receipt golden test vectors",
    )
    receipt_vectors_verify.add_argument(
        "--vectors-dir",
        type=Path,
        help="Path to receipt vectors directory (default: bundled)",
    )

    # receipt hash
    receipt_hash = receipt_sub.add_parser(
        "hash",
        help="Compute canonical SHA-256 hash of anchor receipt",
    )
    receipt_hash.add_argument(
        "file",
        type=Path,
        help="Anchor receipt JSON file",
    )

    # receipt verify
    receipt_verify = receipt_sub.add_parser(
        "verify",
        help="Verify anchor receipt structure and optionally hash",
    )
    receipt_verify.add_argument(
        "file",
        type=Path,
        help="Anchor receipt JSON file",
    )
    receipt_verify.add_argument(
        "--expected",
        help="Expected SHA-256 hash to verify against",
    )

    # certify command
    certify_parser = subparsers.add_parser(
        "certify",
        help="Certification operations",
    )
    certify_sub = certify_parser.add_subparsers(dest="certify_command")

    # certify scaffold
    certify_scaffold = certify_sub.add_parser(
        "scaffold",
        help="Generate certification bundle scaffold for a tier",
    )
    certify_scaffold.add_argument(
        "--tier",
        required=True,
        choices=["basic", "enterprise", "regulated"],
        help="Certification tier",
    )
    certify_scaffold.add_argument(
        "--name",
        required=True,
        help="Platform/integration name",
    )
    certify_scaffold.add_argument(
        "--version",
        required=True,
        dest="platform_version",
        help="Platform/integration version (semver)",
    )
    certify_scaffold.add_argument(
        "--out",
        type=Path,
        default=Path("./certification_bundle"),
        help="Output directory (default: ./certification_bundle)",
    )
    certify_scaffold.add_argument(
        "--vendor-id",
        help="Optional vendor UUID",
    )
    certify_scaffold.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output directory",
    )

    # certify check
    certify_check = certify_sub.add_parser(
        "check",
        help="Check certification bundle against tier requirements",
    )
    certify_check.add_argument(
        "--tier",
        required=True,
        choices=["basic", "enterprise", "regulated"],
        help="Certification tier to check against",
    )
    certify_check.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="Path to certification bundle directory",
    )

    # certify attest
    certify_attest = certify_sub.add_parser(
        "attest",
        help="Generate certification attestation for a bundle",
    )
    certify_attest.add_argument(
        "--tier",
        required=True,
        choices=["basic", "enterprise", "regulated"],
        help="Certification tier",
    )
    certify_attest.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="Path to certification bundle directory",
    )
    certify_attest.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output path for attestation JSON",
    )
    certify_attest.add_argument(
        "--issued-at",
        required=True,
        help="ISO8601 timestamp for attestation (e.g., 2026-03-01T00:00:00Z)",
    )
    certify_attest.add_argument(
        "--integration-name",
        required=True,
        help="Integration identifier",
    )
    certify_attest.add_argument(
        "--integration-version",
        required=True,
        help="Integration version",
    )
    certify_attest.add_argument(
        "--vendor-id",
        help="Optional vendor UUID",
    )
    certify_attest.add_argument(
        "--proof-surface-url",
        default="https://specora.ai/proof",
        help="URL to proof surface (default: https://specora.ai/proof)",
    )

    # certify vectors verify
    certify_vectors = certify_sub.add_parser(
        "vectors",
        help="Certification vector operations",
    )
    certify_vectors_sub = certify_vectors.add_subparsers(dest="certify_vectors_command")

    certify_vectors_verify = certify_vectors_sub.add_parser(
        "verify",
        help="Verify certification golden test vectors",
    )
    certify_vectors_verify.add_argument(
        "--vectors-dir",
        type=Path,
        help="Path to certification vectors directory (default: bundled)",
    )

    # certify hash
    certify_hash = certify_sub.add_parser(
        "hash",
        help="Compute canonical SHA-256 hash of certification attestation",
    )
    certify_hash.add_argument(
        "file",
        type=Path,
        help="Certification attestation JSON file",
    )

    # certify verify (attestation validation)
    certify_verify = certify_sub.add_parser(
        "verify",
        help="Verify certification attestation structure and optionally hash",
    )
    certify_verify.add_argument(
        "file",
        type=Path,
        help="Certification attestation JSON file",
    )
    certify_verify.add_argument(
        "--expected",
        help="Expected SHA-256 hash to verify against",
    )

    # verify-external-anchor command
    verify_external_anchor_parser = subparsers.add_parser(
        "verify-external-anchor",
        help="Verify external transparency anchor",
    )
    verify_external_anchor_parser.add_argument(
        "file",
        type=Path,
        help="External anchor JSON file",
    )
    verify_external_anchor_parser.add_argument(
        "--public-key",
        type=Path,
        help="Path to public key file for signature verification (optional)",
    )
    verify_external_anchor_parser.add_argument(
        "--skip-signature",
        action="store_true",
        help="Skip signature verification",
    )

    # verify-external-anchor-chain command
    verify_external_chain_parser = subparsers.add_parser(
        "verify-external-anchor-chain",
        help="Verify chain of external transparency anchors",
    )
    verify_external_chain_parser.add_argument(
        "directory",
        type=Path,
        help="Directory containing external anchor JSON files",
    )
    verify_external_chain_parser.add_argument(
        "--public-key",
        type=Path,
        help="Path to public key file for signature verification (optional)",
    )
    verify_external_chain_parser.add_argument(
        "--skip-signatures",
        action="store_true",
        help="Skip signature verification",
    )

    # =========================================================================
    # mirror command group (PR-ENT-540: Multi-Surface Mirror Verification)
    # =========================================================================
    mirror_parser = subparsers.add_parser(
        "mirror",
        help="Multi-surface mirror verification (PR-ENT-540)",
    )
    mirror_sub = mirror_parser.add_subparsers(
        dest="mirror_command",
        help="Mirror verification commands",
    )

    # mirror verify-latest
    mirror_verify_latest = mirror_sub.add_parser(
        "verify-latest",
        help="Verify latest anchor across multiple surfaces",
    )
    mirror_verify_latest.add_argument(
        "--github-repo",
        type=str,
        help="GitHub repository in owner/repo format",
    )
    mirror_verify_latest.add_argument(
        "--s3-url",
        type=str,
        help="S3 public URL to latest anchor.json",
    )
    mirror_verify_latest.add_argument(
        "--dns-fqdn",
        type=str,
        help="DNS FQDN for TXT record (e.g., _specora-anchor.example.com)",
    )
    mirror_verify_latest.add_argument(
        "--quorum",
        type=int,
        default=2,
        help="Minimum number of agreeing sources required (default: 2)",
    )
    mirror_verify_latest.add_argument(
        "--public-key",
        type=Path,
        help="Path to public key for signature verification",
    )
    mirror_verify_latest.add_argument(
        "--emit-receipt",
        type=Path,
        help="Output path for verification receipt JSON",
    )
    mirror_verify_latest.add_argument(
        "--offline",
        action="store_true",
        help="Offline mode: use local files instead of fetching",
    )
    mirror_verify_latest.add_argument(
        "--local-github",
        type=Path,
        help="Local path to GitHub anchor.json (for --offline mode)",
    )
    mirror_verify_latest.add_argument(
        "--local-s3",
        type=Path,
        help="Local path to S3 anchor.json (for --offline mode)",
    )
    mirror_verify_latest.add_argument(
        "--local-dns",
        type=Path,
        help="Local path to DNS TXT value file (for --offline mode)",
    )

    # mirror verify-anchors
    mirror_verify_anchors = mirror_sub.add_parser(
        "verify-anchors",
        help="Verify anchor history across surfaces",
    )
    mirror_verify_anchors.add_argument(
        "--since",
        type=str,
        required=True,
        help="Start date (ISO8601 or YYYY-MM-DD)",
    )
    mirror_verify_anchors.add_argument(
        "--github-repo",
        type=str,
        help="GitHub repository in owner/repo format",
    )
    mirror_verify_anchors.add_argument(
        "--s3-prefix",
        type=str,
        help="S3 prefix URL for anchor history",
    )
    mirror_verify_anchors.add_argument(
        "--quorum",
        type=int,
        default=2,
        help="Minimum number of agreeing sources required (default: 2)",
    )
    mirror_verify_anchors.add_argument(
        "--public-key",
        type=Path,
        help="Path to public key for signature verification",
    )
    mirror_verify_anchors.add_argument(
        "--emit-receipt",
        type=Path,
        help="Output path for verification receipt JSON",
    )
    mirror_verify_anchors.add_argument(
        "--offline",
        action="store_true",
        help="Offline mode: use local directories instead of fetching",
    )
    mirror_verify_anchors.add_argument(
        "--local-github-dir",
        type=Path,
        help="Local directory containing GitHub anchor JSON files (for --offline mode)",
    )
    mirror_verify_anchors.add_argument(
        "--local-s3-dir",
        type=Path,
        help="Local directory containing S3 anchor JSON files (for --offline mode)",
    )

    # =========================================================================
    # witness command group (PR-ENT-550: Multi-Organization Mirror Witnesses)
    # =========================================================================
    witness_parser = subparsers.add_parser(
        "witness",
        help="Multi-organization witness verification (PR-ENT-550)",
    )
    witness_sub = witness_parser.add_subparsers(
        dest="witness_command",
        help="Witness verification commands",
    )

    # witness verify <statement.json>
    witness_verify = witness_sub.add_parser(
        "verify",
        help="Verify a single witness statement",
    )
    witness_verify.add_argument(
        "statement",
        type=Path,
        help="Path to witness statement JSON file",
    )
    witness_verify.add_argument(
        "--anchor",
        type=Path,
        help="Path to anchor JSON file for hash comparison",
    )
    witness_verify.add_argument(
        "--registry",
        type=Path,
        help="Path to witness registry JSON file",
    )
    witness_verify.add_argument(
        "--dangerously-skip-signature",
        action="store_true",
        dest="skip_signature",
        help="Skip signature verification (DANGEROUS: disables cryptographic verification)",
    )

    # witness verify-network
    witness_verify_network = witness_sub.add_parser(
        "verify-network",
        help="Verify multiple witnesses achieve quorum",
    )
    witness_verify_network.add_argument(
        "--statements-dir",
        type=Path,
        required=True,
        help="Directory containing witness statement JSON files",
    )
    witness_verify_network.add_argument(
        "--registry",
        type=Path,
        required=True,
        help="Path to witness registry JSON file",
    )
    witness_verify_network.add_argument(
        "--min-witnesses",
        type=int,
        default=2,
        help="Minimum number of agreeing witnesses required (default: 2)",
    )
    witness_verify_network.add_argument(
        "--anchor",
        type=Path,
        help="Path to anchor JSON file for hash comparison",
    )
    witness_verify_network.add_argument(
        "--emit-receipt",
        type=Path,
        help="Output path for verification receipt JSON",
    )
    witness_verify_network.add_argument(
        "--dangerously-skip-signature",
        action="store_true",
        dest="skip_signature",
        help="Skip signature verification (DANGEROUS: disables cryptographic verification)",
    )

    # witness registry-info
    witness_registry_info = witness_sub.add_parser(
        "registry-info",
        help="Display witness registry information",
    )
    witness_registry_info.add_argument(
        "--registry",
        type=Path,
        required=True,
        help="Path to witness registry JSON file",
    )

    # -------------------------------------------------------------------------
    # Registry Snapshot Commands (PR-ENT-560)
    # -------------------------------------------------------------------------

    registry_parser = subparsers.add_parser(
        "registry",
        help="Registry snapshot verification (PR-ENT-560)",
    )
    registry_sub = registry_parser.add_subparsers(
        dest="registry_command",
        help="Registry verification commands",
    )

    # registry verify <snapshot.json>
    registry_verify = registry_sub.add_parser(
        "verify",
        help="Verify a single registry snapshot",
    )
    registry_verify.add_argument(
        "snapshot",
        type=Path,
        help="Path to registry snapshot JSON file",
    )
    registry_verify.add_argument(
        "--public-key",
        type=Path,
        help="Path to registry signing public key (PEM or base64 file)",
    )
    registry_verify.add_argument(
        "--key-format",
        choices=["pem", "base64"],
        default="pem",
        help="Public key format (default: pem)",
    )
    registry_verify.add_argument(
        "--dangerously-skip-signature",
        action="store_true",
        dest="skip_signature",
        help="Skip signature verification (DANGEROUS: disables cryptographic verification)",
    )
    registry_verify.add_argument(
        "--emit-receipt",
        type=Path,
        help="Output path for verification receipt JSON",
    )

    # registry verify-chain <directory>
    registry_verify_chain = registry_sub.add_parser(
        "verify-chain",
        help="Verify a chain of registry snapshots",
    )
    registry_verify_chain.add_argument(
        "snapshots_dir",
        type=Path,
        help="Directory containing registry snapshot JSON files",
    )
    registry_verify_chain.add_argument(
        "--public-key",
        type=Path,
        help="Path to registry signing public key (PEM or base64 file)",
    )
    registry_verify_chain.add_argument(
        "--key-format",
        choices=["pem", "base64"],
        default="pem",
        help="Public key format (default: pem)",
    )
    registry_verify_chain.add_argument(
        "--dangerously-skip-signature",
        action="store_true",
        dest="skip_signature",
        help="Skip signature verification (DANGEROUS: disables cryptographic verification)",
    )
    registry_verify_chain.add_argument(
        "--emit-receipt",
        type=Path,
        help="Output path for verification receipt JSON",
    )

    # registry info <snapshot.json>
    registry_info = registry_sub.add_parser(
        "info",
        help="Display registry snapshot information",
    )
    registry_info.add_argument(
        "snapshot",
        type=Path,
        help="Path to registry snapshot JSON file",
    )

    # -------------------------------------------------------------------------
    # STP Commands (PLATFORM-470)
    # -------------------------------------------------------------------------

    stp_parser = subparsers.add_parser(
        "stp",
        help="Specora Trust Protocol operations (PLATFORM-470)",
    )
    stp_sub = stp_parser.add_subparsers(
        dest="stp_command",
        help="STP commands",
    )

    # stp init
    stp_init = stp_sub.add_parser(
        "init",
        help="Initialize STP integration scaffold",
    )
    stp_init.add_argument(
        "--runtime",
        choices=STP_RUNTIME_TYPES,
        default="custom",
        help="Target runtime environment (default: custom)",
    )
    stp_init.add_argument(
        "--org-id",
        help="Organization UUID (generates placeholder if omitted)",
    )
    stp_init.add_argument(
        "--out",
        type=Path,
        default=Path("./.specora-stp"),
        help="Output directory (default: ./.specora-stp)",
    )
    stp_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing directory",
    )

    # stp verify <file>
    stp_verify = stp_sub.add_parser(
        "verify",
        help="Verify STP message against protocol schema",
    )
    stp_verify.add_argument(
        "file",
        type=Path,
        help="STP message JSON file",
    )
    stp_verify.add_argument(
        "--schema",
        help="Expected message type (auto-detected if omitted)",
    )
    stp_verify.add_argument(
        "--strict",
        action="store_true",
        help="Fail on warnings (protocol version mismatch, etc.)",
    )
    stp_verify.add_argument(
        "--check-seal",
        action="store_true",
        help="Verify seal integrity",
    )
    stp_verify.add_argument(
        "--expected-seal",
        help="Expected seal hash to verify against",
    )

    # stp simulate <file>
    stp_simulate = stp_sub.add_parser(
        "simulate",
        help="Simulate STP governance decision locally",
    )
    stp_simulate.add_argument(
        "file",
        type=Path,
        help="STP execution.authorize request JSON file",
    )
    stp_simulate.add_argument(
        "--policy",
        type=Path,
        help="Policy JSON file (default: .specora-stp/policy.json)",
    )
    stp_simulate.add_argument(
        "--trust-score",
        type=float,
        default=50.0,
        help="Assumed trust score 0-100 (default: 50.0)",
    )

    # stp inspect <file>
    stp_inspect = stp_sub.add_parser(
        "inspect",
        help="Inspect STP artifact details",
    )
    stp_inspect.add_argument(
        "file",
        type=Path,
        help="STP artifact JSON file",
    )
    stp_inspect.add_argument(
        "--show-seal",
        action="store_true",
        help="Show computed seal hash",
    )
    stp_inspect.add_argument(
        "--show-chain",
        action="store_true",
        help="Show chain position info",
    )
    stp_inspect.add_argument(
        "--show-canonical",
        action="store_true",
        help="Output canonical JSON form",
    )

    # stp vectors verify
    stp_vectors = stp_sub.add_parser(
        "vectors",
        help="STP vector operations",
    )
    stp_vectors_sub = stp_vectors.add_subparsers(dest="stp_vectors_command")

    stp_vectors_verify = stp_vectors_sub.add_parser(
        "verify",
        help="Verify STP golden test vectors",
    )
    stp_vectors_verify.add_argument(
        "--vectors-dir",
        type=Path,
        help="Path to STP vectors directory (default: bundled)",
    )

    # stp hash <file>
    stp_hash = stp_sub.add_parser(
        "hash",
        help="Compute canonical SHA-256 hash of STP artifact",
    )
    stp_hash.add_argument(
        "file",
        type=Path,
        help="STP artifact JSON file",
    )

    # stp certify subcommands
    stp_certify = stp_sub.add_parser(
        "certify",
        help="STP certification operations",
    )
    stp_certify_sub = stp_certify.add_subparsers(dest="stp_certify_command")

    # stp certify scaffold
    stp_certify_scaffold = stp_certify_sub.add_parser(
        "scaffold",
        help="Generate STP certification bundle scaffold",
    )
    stp_certify_scaffold.add_argument(
        "--tier",
        required=True,
        choices=["compatible", "governed", "enterprise"],
        help="Certification tier",
    )
    stp_certify_scaffold.add_argument(
        "--adapter-name",
        required=True,
        help="Adapter/integration name being certified",
    )
    stp_certify_scaffold.add_argument(
        "--adapter-version",
        default="1.0.0",
        help="Adapter version (default: 1.0.0)",
    )
    stp_certify_scaffold.add_argument(
        "--vendor-name",
        default="",
        help="Vendor/organization name",
    )
    stp_certify_scaffold.add_argument(
        "--out",
        type=Path,
        default=Path("./stp-certification-bundle"),
        help="Output directory (default: ./stp-certification-bundle)",
    )
    stp_certify_scaffold.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing directory",
    )

    # stp certify check
    stp_certify_check = stp_certify_sub.add_parser(
        "check",
        help="Check STP certification bundle against tier requirements",
    )
    stp_certify_check.add_argument(
        "--tier",
        required=True,
        choices=["compatible", "governed", "enterprise"],
        help="Certification tier to check against",
    )
    stp_certify_check.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="Path to certification bundle directory",
    )

    # stp certify attest
    stp_certify_attest = stp_certify_sub.add_parser(
        "attest",
        help="Generate STP certification attestation for a bundle",
    )
    stp_certify_attest.add_argument(
        "--tier",
        required=True,
        choices=["compatible", "governed", "enterprise"],
        help="Certification tier",
    )
    stp_certify_attest.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="Path to certification bundle directory",
    )
    stp_certify_attest.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output path for attestation JSON",
    )
    stp_certify_attest.add_argument(
        "--issued-at",
        required=True,
        help="ISO8601 timestamp for attestation (e.g., 2026-03-01T00:00:00Z)",
    )

    # stp certify vectors verify
    stp_certify_vectors = stp_certify_sub.add_parser(
        "vectors",
        help="STP certification vector operations",
    )
    stp_certify_vectors_sub = stp_certify_vectors.add_subparsers(
        dest="stp_certify_vectors_command"
    )
    stp_certify_vectors_verify = stp_certify_vectors_sub.add_parser(
        "verify",
        help="Verify STP certification golden test vectors",
    )
    stp_certify_vectors_verify.add_argument(
        "--vectors-dir",
        type=Path,
        help="Path to STP certification vectors directory (default: bundled)",
    )

    # stp certify verify
    stp_certify_verify = stp_certify_sub.add_parser(
        "verify",
        help="Verify STP certification attestation",
    )
    stp_certify_verify.add_argument(
        "file",
        type=Path,
        help="STP certification attestation JSON file",
    )
    stp_certify_verify.add_argument(
        "--expected",
        help="Expected SHA-256 hash to verify against",
    )

    # read command — provider audit-log readers
    read_parser = subparsers.add_parser(
        "read",
        help="Ingest a provider audit-log export and emit a Specora evidence bundle payload",
    )
    read_sub = read_parser.add_subparsers(dest="read_command")

    read_anthropic = read_sub.add_parser(
        "anthropic",
        help="Read an Anthropic Claude Enterprise Compliance API JSONL export",
    )
    read_anthropic.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to the Anthropic Compliance API JSONL export",
    )
    read_anthropic.add_argument(
        "--key-id",
        required=True,
        help="Specora signing key ID to associate with the emitted bundle payload",
    )
    read_anthropic.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help="Optional Ed25519 public key (raw 32 bytes or 64-char hex) to verify upstream signatures",
    )
    read_anthropic.add_argument(
        "--schema-version",
        default=None,
        help="Override the expected upstream schema version (default: per-record declared version)",
    )
    read_anthropic.add_argument(
        "--non-strict",
        action="store_true",
        help="Drop malformed records with warnings instead of failing the read",
    )
    read_anthropic.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the canonical bundle payload JSON to this path (default: stdout)",
    )

    read_azure_cl = read_sub.add_parser(
        "azure-cl",
        help="Read an Azure Confidential Ledger entries-with-receipts export",
    )
    read_azure_cl.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to an Azure Confidential Ledger JSON export ({'entries': [...]})",
    )
    read_azure_cl.add_argument(
        "--key-id",
        required=True,
        help="Specora signing key ID to associate with the emitted bundle payload",
    )
    read_azure_cl.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help=(
            "Accepted for interface compatibility with other readers. Azure "
            "Confidential Ledger receipts are consortium-signed (ECDSA P-384), "
            "not ed25519; the full inclusion proof is preserved in the bundle."
        ),
    )
    read_azure_cl.add_argument(
        "--schema-version",
        default=None,
        help="Override the reader-side Azure-CL schema version (default: 1.0)",
    )
    read_azure_cl.add_argument(
        "--non-strict",
        action="store_true",
        help="Drop malformed entries with warnings instead of failing the read",
    )
    read_azure_cl.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the canonical bundle payload JSON to this path (default: stdout)",
    )

    read_cloudtrail = read_sub.add_parser(
        "cloudtrail",
        help="Read an AWS CloudTrail JSON export (Bedrock AR Checks)",
    )
    read_cloudtrail.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to a CloudTrail JSON export ({'Records': [...]})",
    )
    read_cloudtrail.add_argument(
        "--key-id",
        required=True,
        help="Specora signing key ID to associate with the emitted bundle payload",
    )
    read_cloudtrail.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help=(
            "Accepted for interface compatibility with other readers. CloudTrail "
            "has no per-event signatures; integrity is anchored at the log file "
            "validation level (aws cloudtrail validate-logs)."
        ),
    )
    read_cloudtrail.add_argument(
        "--schema-version",
        default=None,
        help="Override the expected CloudTrail eventVersion (default: per-record)",
    )
    read_cloudtrail.add_argument(
        "--non-strict",
        action="store_true",
        help=(
            "Drop malformed records with warnings instead of failing. Non-AR "
            "Bedrock invocations and non-Bedrock events are always silently skipped."
        ),
    )
    read_cloudtrail.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the canonical bundle payload JSON to this path (default: stdout)",
    )

    read_openai = read_sub.add_parser(
        "openai",
        help="Read an OpenAI Compliance Platform audit-log export",
    )
    read_openai.add_argument(
        "--input",
        required=True,
        type=Path,
        help=(
            "Path to an OpenAI Compliance Platform export "
            "({'object': 'list', 'data': [...]}, a bare JSON array, "
            "or JSONL)"
        ),
    )
    read_openai.add_argument(
        "--key-id",
        required=True,
        help="Specora signing key ID to associate with the emitted bundle payload",
    )
    read_openai.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help=(
            "Accepted for interface compatibility with other readers. OpenAI "
            "Compliance Platform does not emit per-event signatures; integrity "
            "is anchored at the TLS transport layer and by the enterprise "
            "admin console's tamper-evident audit log."
        ),
    )
    read_openai.add_argument(
        "--schema-version",
        default=None,
        help=(
            "Override the reader-side OpenAI schema version "
            "(default: openai-compliance-v1-preview)"
        ),
    )
    read_openai.add_argument(
        "--non-strict",
        action="store_true",
        help="Drop malformed events with warnings instead of failing the read",
    )
    read_openai.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the canonical bundle payload JSON to this path (default: stdout)",
    )

    read_langsmith = read_sub.add_parser(
        "langsmith",
        help="Read a LangSmith Fleet audit-trace export",
    )
    read_langsmith.add_argument(
        "--input",
        required=True,
        type=Path,
        help=(
            "Path to a LangSmith Fleet trace export "
            "({'runs': [...]}, a bare JSON array, or JSONL)"
        ),
    )
    read_langsmith.add_argument(
        "--key-id",
        required=True,
        help="Specora signing key ID to associate with the emitted bundle payload",
    )
    read_langsmith.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help=(
            "Accepted for interface compatibility with other readers. LangSmith "
            "Fleet does not emit per-trace signatures; integrity is anchored at "
            "the TLS transport layer and by the Fleet tenant's audit log."
        ),
    )
    read_langsmith.add_argument(
        "--schema-version",
        default=None,
        help=(
            "Override the reader-side LangSmith schema version "
            "(default: langsmith-fleet-v1)"
        ),
    )
    read_langsmith.add_argument(
        "--non-strict",
        action="store_true",
        help="Drop malformed traces with warnings instead of failing the read",
    )
    read_langsmith.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write the canonical bundle payload JSON to this path (default: stdout)",
    )

    # run command (EPIC-B03: end-to-end out-of-band flow)
    # Note: `_dispatch_read` stays read-only. `run` is deliberately a
    # separate code path that composes reader + signer + on-disk bundle
    # writer. Keeping the two separated means `read` continues to do one
    # thing (print canonical JSON to stdout or --out) and `run` owns the
    # full e2e pipeline — no silent mode-switch on an existing command.
    run_parser = subparsers.add_parser(
        "run",
        help="Run the end-to-end out-of-band verification pipeline (EPIC-B03)",
        description=(
            "Read a provider audit-log export, normalize it to a canonical "
            "Specora evidence bundle, sign it with an Ed25519 key, and write "
            "a verifiable bundle directory. The output can be fed directly "
            "into 'specora-verify verify'."
        ),
    )
    run_parser.add_argument(
        "--provider",
        required=True,
        help="Provider name (e.g. anthropic, cloudtrail, azure-cl)",
    )
    run_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to the provider audit-log export",
    )
    run_parser.add_argument(
        "--key-id",
        required=True,
        help="Specora signing key ID to record in the bundle metadata",
    )
    run_parser.add_argument(
        "--private-key",
        required=True,
        type=Path,
        help=(
            "Path to the Ed25519 private key used to sign the bundle "
            "(64-char hex, raw 32 bytes, or unencrypted PEM PKCS#8)"
        ),
    )
    run_parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output directory for the signed bundle (created if missing)",
    )
    run_parser.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help="Optional upstream provider public key (forwarded to the reader)",
    )
    run_parser.add_argument(
        "--schema-version",
        default=None,
        help="Override the expected upstream schema version",
    )
    run_parser.add_argument(
        "--non-strict",
        action="store_true",
        help="Drop malformed records with warnings instead of failing the read",
    )

    return parser


def _check_skip_signature_in_ci(args: argparse.Namespace) -> int | None:
    """Check if skip_signature is used in CI mode and return error if so.

    Returns:
        EXIT_ERROR if skip_signature is used in CI mode, None otherwise.
    """
    if getattr(args, "ci", False) and getattr(args, "skip_signature", False):
        print(
            format_error(
                f"--dangerously-skip-signature cannot be used with --ci mode. "
                f"CI pipelines must verify cryptographic signatures for institutional trust. "
                f"If you need to skip signatures during development, run without --ci.",
                output_format=getattr(args, "format", "text"),
                code="SKIP_SIGNATURE_IN_CI",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR
    return None


def _load_json_file(path: Path, output_format: str) -> dict | None:
    """Load and parse a JSON file, printing errors as needed."""
    if not path.exists():
        print(
            format_error(f"File not found: {path}", output_format=output_format, code="FILE_NOT_FOUND"),
            file=sys.stderr,
        )
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(
            format_error(f"Failed to parse {path}: {e}", output_format=output_format, code="PARSE_ERROR"),
            file=sys.stderr,
        )
        return None


def _dispatch_read(args: argparse.Namespace, provider: str) -> int:
    """Shared dispatch path for every ``specora-verify read <provider>`` subcommand.

    **Architectural contract (recorded 2026-04-15, B01 CloudTrail session 1
    chore commit).** This helper is the single code path every provider
    reader subcommand goes through. A new reader integrates as follows:

    1. Implement ``ReaderProtocol`` in ``specora_verify/readers/<provider>.py``.
    2. Register via the ``@reader("<provider>")`` decorator so it lands in
       the ``READERS`` dict at import time.
    3. Add an ``argparse`` subparser under ``read_sub`` with the standard
       argument set — ``--input``, ``--key-id``, ``--public-key``,
       ``--schema-version``, ``--non-strict``, ``--out`` — matching the
       shape ``_dispatch_read`` expects on ``args``.
    4. Add a one-line ``cmd_read_<provider>`` wrapper that returns
       ``_dispatch_read(args, "<provider>")`` and wire it into the
       ``args.read_command`` elif ladder below.

    Any reader that needs to bypass this path (different argument shape,
    different output contract, non-canonical bundle emission) requires a
    prior design note in ``docs/strategy/b01-reader-design-notes-2026-Q2.md``
    with CEO + Engineering lead sign-off. Do not silently fork the dispatch
    layer — the whole point of this helper is that every new reader inherits
    identical CLI ergonomics, warning surfacing, canonical JSON output,
    and exit-code handling without re-implementing them.
    """
    from specora_verify.canonical import canonical_json_str
    from specora_verify.errors import ReaderError
    from specora_verify.readers import get_reader

    try:
        reader_impl = get_reader(provider)
        result = reader_impl.read(
            input_path=args.input,
            key_id=args.key_id,
            public_key_path=args.public_key,
            schema_version=args.schema_version,
            strict=not args.non_strict,
        )
    except ReaderError as exc:
        print(
            format_error(
                str(exc),
                output_format=args.format,
                code=getattr(exc, "code", "READER_ERROR"),
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    output = canonical_json_str(result.bundle_payload)
    if args.out:
        args.out.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    if args.format == "json":
        summary = {
            "provider": result.provider,
            "schema_version": result.schema_version,
            "record_count": result.record_count,
            "upstream_key_id": result.upstream_key_id,
            "warnings": list(result.warnings),
            "out": str(args.out) if args.out else None,
        }
        print(json.dumps(summary), file=sys.stderr)
    else:
        print(
            f"read {provider}: {result.record_count} records, "
            f"schema {result.schema_version}, "
            f"{len(result.warnings)} warnings",
            file=sys.stderr,
        )
        for warning in result.warnings:
            print(f"  warning: {warning}", file=sys.stderr)

    return EXIT_PASS


def cmd_read_anthropic(args: argparse.Namespace) -> int:
    """Handle: specora-verify read anthropic --input <jsonl> ..."""
    return _dispatch_read(args, "anthropic")


def cmd_read_cloudtrail(args: argparse.Namespace) -> int:
    """Handle: specora-verify read cloudtrail --input <json> ..."""
    return _dispatch_read(args, "cloudtrail")


def cmd_read_azure_cl(args: argparse.Namespace) -> int:
    """Handle: specora-verify read azure-cl --input <json> ..."""
    return _dispatch_read(args, "azure-cl")


def cmd_read_openai(args: argparse.Namespace) -> int:
    """Handle: specora-verify read openai --input <json> ..."""
    return _dispatch_read(args, "openai")


def cmd_read_langsmith(args: argparse.Namespace) -> int:
    """Handle: specora-verify read langsmith --input <json> ..."""
    return _dispatch_read(args, "langsmith")


def cmd_run(args: argparse.Namespace) -> int:
    """Handle: specora-verify run --provider <p> --input <f> ... --out <dir>

    EPIC-B03 end-to-end orchestration. Imports the orchestration module
    lazily so the core ``read`` / ``verify`` paths stay independent of
    the ``cryptography`` optional dependency (signing requires it, but
    stdlib-only verification does not).
    """
    from specora_verify.errors import ReaderError
    from specora_verify.orchestration import OrchestrationError, run_pipeline

    try:
        result = run_pipeline(
            provider=args.provider,
            input_path=args.input,
            key_id=args.key_id,
            private_key_path=args.private_key,
            out_dir=args.out,
            public_key_path=args.public_key,
            schema_version=args.schema_version,
            strict=not args.non_strict,
        )
    except ReaderError as exc:
        print(
            format_error(
                str(exc),
                output_format=args.format,
                code=getattr(exc, "code", "READER_ERROR"),
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR
    except OrchestrationError as exc:
        print(
            format_error(
                str(exc),
                output_format=args.format,
                code="ORCHESTRATION_ERROR",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    if args.format == "json":
        summary = {
            "provider": result.provider,
            "record_count": result.record_count,
            "payload_sha256": result.payload_sha256,
            "warnings": list(result.warnings),
            "bundle_dir": str(result.bundle_dir),
            "payload": str(result.payload_path),
            "signature": str(result.signature_path),
            "public_key": str(result.public_key_path),
            "metadata": str(result.metadata_path),
        }
        print(json.dumps(summary))
    else:
        print(
            f"run {result.provider}: {result.record_count} records -> {result.bundle_dir}",
            file=sys.stderr,
        )
        print(f"  payload:    {result.payload_path}", file=sys.stderr)
        print(f"  signature:  {result.signature_path}", file=sys.stderr)
        print(f"  public key: {result.public_key_path}", file=sys.stderr)
        print(f"  metadata:   {result.metadata_path}", file=sys.stderr)
        for warning in result.warnings:
            print(f"  warning: {warning}", file=sys.stderr)
        print(
            "verify with: specora-verify verify "
            f"--artifact {result.payload_path} "
            f"--signature {result.signature_path} "
            f"--public-key {result.public_key_path}",
            file=sys.stderr,
        )

    return EXIT_PASS


def cmd_vectors_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify vectors verify"""
    result = verify_vectors(args.vectors_dir)
    print(format_vectors_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_manifest_hash(args: argparse.Namespace) -> int:
    """Handle: specora-verify manifest hash <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    hash_value = compute_manifest_hash(payload)
    print(format_hash_result(hash_value, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS


def cmd_manifest_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify manifest verify <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    result = validate_manifest(
        payload,
        expected_hash=args.expected_hash,
        spec_id=args.spec_id,
        schema_version=args.schema_version,
    )
    print(format_manifest_result(result, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_bundle_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify bundle verify <file>"""
    if not args.file.exists():
        print(
            format_error(
                f"File not found: {args.file}",
                output_format=args.format,
                code="FILE_NOT_FOUND",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    result = verify_bundle(args.file)
    print(format_bundle_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_anchor_vectors_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify anchor vectors verify"""
    result = verify_anchor_vectors(args.vectors_dir)
    print(format_anchor_vectors_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_anchor_hash(args: argparse.Namespace) -> int:
    """Handle: specora-verify anchor hash <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    hash_value = compute_manifest_hash(payload)
    print(format_hash_result(hash_value, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS


def cmd_anchor_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify anchor verify <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    result = validate_anchor_payload(payload, expected_hash=args.expected)
    print(format_anchor_result(result, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_receipt_vectors_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify receipt vectors verify"""
    result = verify_receipt_vectors(args.vectors_dir)
    print(format_receipt_vectors_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_receipt_hash(args: argparse.Namespace) -> int:
    """Handle: specora-verify receipt hash <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    hash_value = compute_manifest_hash(payload)
    print(format_hash_result(hash_value, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS


def cmd_receipt_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify receipt verify <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    result = validate_receipt(payload, expected_hash=args.expected)
    print(format_receipt_result(result, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_verify_signature(args: argparse.Namespace) -> int:
    """Handle: specora-verify verify --artifact --signature --public-key"""
    # Check cryptography availability
    try:
        from specora_verify.signature import is_crypto_available, verify_signature

        if not is_crypto_available():
            print(
                format_error(
                    "Signature verification requires 'cryptography' package. "
                    "Install with: pip install specora-verify[crypto]",
                    output_format=args.format,
                    code="CRYPTO_MISSING",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR
    except ImportError as e:
        print(
            format_error(f"Failed to import signature module: {e}", output_format=args.format),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load artifact
    payload = _load_json_file(args.artifact, args.format)
    if payload is None:
        return EXIT_ERROR

    # Compute hash
    artifact_hash = compute_manifest_hash(payload)

    # Load signature
    if not args.signature.exists():
        print(
            format_error(f"Signature file not found: {args.signature}", output_format=args.format),
            file=sys.stderr,
        )
        return EXIT_ERROR

    signature_b64 = args.signature.read_text(encoding="utf-8").strip()

    # Load public key
    if not args.public_key.exists():
        print(
            format_error(f"Public key file not found: {args.public_key}", output_format=args.format),
            file=sys.stderr,
        )
        return EXIT_ERROR

    public_key_data = args.public_key.read_text(encoding="utf-8")

    # Verify signature
    result = verify_signature(
        manifest_hash=artifact_hash,
        signature_b64=signature_b64,
        public_key=public_key_data,
    )

    # Check key trust if revocation list provided
    trust_result = None
    if hasattr(args, "revocation_list_data"):
        from specora_verify.fingerprint import derive_key_id
        from specora_verify.revocation import check_key_trust

        trust_result = check_key_trust(
            revocation_list=args.revocation_list_data,
            key_id=derive_key_id(result.key_fingerprint) if result.key_fingerprint else None,
            fingerprint=result.key_fingerprint,
            require_trusted_key=getattr(args, "require_trusted_key", False),
        )

    # Output result with trust info
    print(
        format_signature_result(
            result,
            output_format=args.format,
            file_path=str(args.artifact),
            trust_result=trust_result,
        )
    )

    # Determine exit code
    if not result.valid:
        return EXIT_FAIL

    if trust_result and not trust_result.trusted:
        return EXIT_FAIL

    if trust_result and trust_result.warning:
        return EXIT_WARN

    return EXIT_PASS


def cmd_verify_log(args: argparse.Namespace) -> int:
    """Handle: specora-verify verify-log --log <file> [--public-key <key.pem>]

    Verifies transparency chain integrity offline.

    Exit codes:
        0 (PASS): Chain fully valid
        2 (FAIL): Chain integrity violation
        3 (ERROR): File not found, parse error, etc.
    """
    from specora_verify.validators.chain import verify_chain_file

    # Verify log file exists
    if not args.log.exists():
        print(
            format_error(
                f"Log file not found: {args.log}",
                output_format=args.format,
                code="FILE_NOT_FOUND",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Verify public key exists if provided
    public_key_path = None
    if args.public_key:
        if not args.public_key.exists():
            print(
                format_error(
                    f"Public key file not found: {args.public_key}",
                    output_format=args.format,
                    code="FILE_NOT_FOUND",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR
        public_key_path = args.public_key

    # Verify chain
    verify_signatures = not getattr(args, "skip_signatures", False)
    result = verify_chain_file(
        path=args.log,
        public_key_path=public_key_path,
        verify_signatures=verify_signatures,
    )

    # Output result
    print(format_chain_result(result, output_format=args.format, file_path=str(args.log)))

    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_canonicalize(args: argparse.Namespace) -> int:
    """Handle: specora-verify canonicalize <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    canonical = canonical_json_str(payload)
    print(canonical)
    return EXIT_PASS


def cmd_key_info(args: argparse.Namespace) -> int:
    """Handle: specora-verify key-info --public-key"""
    # Check cryptography availability
    try:
        from specora_verify.signature import get_key_info, is_crypto_available

        if not is_crypto_available():
            print(
                format_error(
                    "Key info requires 'cryptography' package. "
                    "Install with: pip install specora-verify[crypto]",
                    output_format=args.format,
                    code="CRYPTO_MISSING",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR
    except ImportError as e:
        print(
            format_error(f"Failed to import signature module: {e}", output_format=args.format),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load public key
    if not args.public_key.exists():
        print(
            format_error(f"Public key file not found: {args.public_key}", output_format=args.format),
            file=sys.stderr,
        )
        return EXIT_ERROR

    public_key_data = args.public_key.read_text(encoding="utf-8")

    # Get key info
    info = get_key_info(public_key_data)

    print(format_key_info(info, output_format=args.format, file_path=str(args.public_key)))
    return EXIT_PASS if info.valid else EXIT_FAIL


def cmd_emit_receipt(args: argparse.Namespace) -> int:
    """Handle: specora-verify emit-receipt"""
    from specora_verify.receipt import generate_artifact_receipt, generate_bundle_receipt

    # Must have either artifact or manifest
    if not args.artifact and not args.manifest:
        print(
            format_error(
                "Must provide either --artifact or --manifest",
                output_format=args.format,
                code="MISSING_INPUT",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    if args.artifact and args.manifest:
        print(
            format_error(
                "Cannot specify both --artifact and --manifest",
                output_format=args.format,
                code="INVALID_INPUT",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load signature if provided
    signature_b64 = None
    if args.signature:
        if not args.signature.exists():
            print(
                format_error(f"Signature file not found: {args.signature}", output_format=args.format),
                file=sys.stderr,
            )
            return EXIT_ERROR
        signature_b64 = args.signature.read_text(encoding="utf-8").strip()

    # Load public key if provided
    public_key_data = None
    if args.public_key:
        if not args.public_key.exists():
            print(
                format_error(f"Public key file not found: {args.public_key}", output_format=args.format),
                file=sys.stderr,
            )
            return EXIT_ERROR
        public_key_data = args.public_key.read_text(encoding="utf-8")

    # Compute trust result if revocation list and public key provided
    trust_result = None
    if hasattr(args, "revocation_list_data") and args.revocation_list_data and public_key_data:
        try:
            from specora_verify.fingerprint import compute_key_fingerprint, derive_key_id
            from specora_verify.revocation import check_key_trust
            from specora_verify.signature import is_crypto_available, load_public_key

            if is_crypto_available():
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

                pub_key = load_public_key(public_key_data)
                raw_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
                fingerprint = compute_key_fingerprint(raw_bytes)
                key_id = derive_key_id(fingerprint)

                trust_result = check_key_trust(
                    revocation_list=args.revocation_list_data,
                    key_id=key_id,
                    fingerprint=fingerprint,
                    require_trusted_key=getattr(args, "require_trusted_key", False),
                )
        except Exception:
            pass  # Trust check is best-effort; signature verification is primary

    # Generate receipt based on input type
    if args.artifact:
        payload = _load_json_file(args.artifact, args.format)
        if payload is None:
            return EXIT_ERROR

        receipt = generate_artifact_receipt(
            artifact=payload,
            signature_b64=signature_b64,
            public_key_data=public_key_data,
            allow_hash_only=args.allow_hash_only,
            trust_result=trust_result,
        )
    else:
        payload = _load_json_file(args.manifest, args.format)
        if payload is None:
            return EXIT_ERROR

        receipt = generate_bundle_receipt(
            manifest=payload,
            public_key_data=public_key_data,
        )

    # Output receipt
    receipt_json = receipt.to_json(indent=2)

    if args.out:
        args.out.write_text(receipt_json, encoding="utf-8")
        if args.format == "text":
            print(f"Receipt written to: {args.out}")
    else:
        print(receipt_json)

    # Determine exit code based on result
    if receipt.verification.result == "PASS":
        return EXIT_PASS
    elif receipt.verification.result == "WARN":
        return EXIT_WARN
    else:
        return EXIT_FAIL


def cmd_certify_scaffold(args: argparse.Namespace) -> int:
    """Handle: specora-verify certify scaffold --tier --name --version [--out]"""
    from specora_verify.scaffold import generate_scaffold

    result = generate_scaffold(
        output_dir=args.out,
        tier=args.tier,
        name=args.name,
        version=args.platform_version,
        vendor_id=args.vendor_id,
        force=args.force,
    )

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        if result.success:
            print("============================================================")
            print("SPECORA CERTIFICATION BUNDLE SCAFFOLD")
            print("============================================================")
            print(f"Tier:       {result.tier}")
            print(f"Platform:   {result.name} v{result.version}")
            print(f"Output:     {result.output_dir}")
            print("============================================================")
            print("")
            print("Files created:")
            for f in result.files_created:
                print(f"  - {f}")
            print("")
            if result.warnings:
                print("Warnings:")
                for w in result.warnings:
                    print(f"  - {w}")
                print("")
            print("Next steps:")
            print(f"  1. Update manifest files with your actual data")
            print(f"  2. Run: specora-verify vectors verify")
            print(f"  3. Run: specora-verify certify check --tier {result.tier} --bundle {result.output_dir}")
            print(f"  4. See {result.output_dir}/INSTRUCTIONS.md for details")
            print("============================================================")
        else:
            print("ERROR: Scaffold generation failed", file=sys.stderr)
            for e in result.errors:
                print(f"  - {e}", file=sys.stderr)

    return EXIT_PASS if result.success else EXIT_ERROR


def cmd_certify_check(args: argparse.Namespace) -> int:
    """Handle: specora-verify certify check --tier <tier> --bundle <path>"""
    if not args.bundle.exists():
        print(
            format_error(
                f"Bundle directory not found: {args.bundle}",
                output_format=args.format,
                code="BUNDLE_NOT_FOUND",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    result = check_certification_bundle(args.bundle, args.tier)
    print(format_certification_check_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_certify_attest(args: argparse.Namespace) -> int:
    """Handle: specora-verify certify attest --tier <tier> --bundle <path> --out <file>"""
    if not args.bundle.exists():
        print(
            format_error(
                f"Bundle directory not found: {args.bundle}",
                output_format=args.format,
                code="BUNDLE_NOT_FOUND",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    attestation = generate_attestation(
        bundle_path=args.bundle,
        tier=args.tier,
        issued_at=args.issued_at,
        integration_name=args.integration_name,
        integration_version=args.integration_version,
        vendor_id=args.vendor_id,
        proof_surface_url=args.proof_surface_url,
        specora_verify_version=__version__,
    )

    # Write attestation
    attestation_json = json.dumps(attestation, indent=2, sort_keys=True)
    args.out.write_text(attestation_json, encoding="utf-8")

    if args.format == "text":
        from specora_verify.canonical import canonical_json_bytes
        from specora_verify.hash import sha256_hex

        attestation_hash = sha256_hex(canonical_json_bytes(attestation))
        print(f"Attestation written to: {args.out}")
        print(f"Attestation hash: {attestation_hash}")
    else:
        print(attestation_json)

    return EXIT_PASS


def cmd_certify_vectors_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify certify vectors verify"""
    result = verify_certification_vectors(args.vectors_dir)
    print(format_certification_vectors_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_certify_hash(args: argparse.Namespace) -> int:
    """Handle: specora-verify certify hash <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    hash_value = compute_manifest_hash(payload)
    print(format_hash_result(hash_value, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS


def cmd_certify_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify certify verify <file>"""
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    result = validate_attestation(payload, expected_hash=args.expected)
    print(format_certification_attestation_result(result, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_verify_external_anchor(args: argparse.Namespace) -> int:
    """Handle: specora-verify verify-external-anchor <file>"""
    from specora_verify.output import format_external_anchor_result
    from specora_verify.validators.external_anchor import verify_external_anchor_file

    # Verify file exists
    if not args.file.exists():
        print(
            format_error(
                f"Anchor file not found: {args.file}",
                output_format=args.format,
                code="FILE_NOT_FOUND",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Verify public key exists if provided
    public_key_path = None
    if hasattr(args, "public_key") and args.public_key:
        if not args.public_key.exists():
            print(
                format_error(
                    f"Public key file not found: {args.public_key}",
                    output_format=args.format,
                    code="FILE_NOT_FOUND",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR
        public_key_path = args.public_key

    # Verify anchor
    verify_signature = not getattr(args, "skip_signature", False)
    result = verify_external_anchor_file(
        path=args.file,
        public_key_path=public_key_path,
        verify_signature=verify_signature,
    )

    # Output result
    print(format_external_anchor_result(result, output_format=args.format, file_path=str(args.file)))

    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_verify_external_anchor_chain(args: argparse.Namespace) -> int:
    """Handle: specora-verify verify-external-anchor-chain <directory>"""
    from specora_verify.output import format_external_anchor_chain_result
    from specora_verify.validators.external_anchor import verify_external_anchor_chain_dir

    # Verify directory exists
    if not args.directory.exists():
        print(
            format_error(
                f"Directory not found: {args.directory}",
                output_format=args.format,
                code="DIRECTORY_NOT_FOUND",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    if not args.directory.is_dir():
        print(
            format_error(
                f"Not a directory: {args.directory}",
                output_format=args.format,
                code="NOT_A_DIRECTORY",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Verify public key exists if provided
    public_key_path = None
    if hasattr(args, "public_key") and args.public_key:
        if not args.public_key.exists():
            print(
                format_error(
                    f"Public key file not found: {args.public_key}",
                    output_format=args.format,
                    code="FILE_NOT_FOUND",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR
        public_key_path = args.public_key

    # Verify chain
    verify_signatures = not getattr(args, "skip_signatures", False)
    result = verify_external_anchor_chain_dir(
        directory=args.directory,
        public_key_path=public_key_path,
        verify_signatures=verify_signatures,
    )

    # Output result
    print(format_external_anchor_chain_result(result, output_format=args.format, directory_path=str(args.directory)))

    return EXIT_PASS if result.valid else EXIT_FAIL


# =============================================================================
# Mirror Commands (PR-ENT-540)
# =============================================================================


def cmd_mirror_verify_latest(args: argparse.Namespace) -> int:
    """Handle: specora-verify mirror verify-latest

    Verifies the latest external anchor across multiple surfaces.
    """
    from specora_verify.validators.mirror import (
        MirrorSource,
        MirrorStatus,
        SourceResult,
        create_mirror_receipt,
        status_to_exit_code,
        verify_mirror_consistency,
    )
    from specora_verify.output import format_mirror_result

    source_results: dict[str, SourceResult] = {}

    # Offline mode: use local files
    if getattr(args, "offline", False):
        from specora_verify.fetchers.local import load_local_anchor, load_local_dns_txt

        if hasattr(args, "local_github") and args.local_github:
            source_results["github_release"] = load_local_anchor(
                args.local_github, MirrorSource.GITHUB_RELEASE
            )

        if hasattr(args, "local_s3") and args.local_s3:
            source_results["s3_versioned"] = load_local_anchor(
                args.local_s3, MirrorSource.S3_VERSIONED
            )

        if hasattr(args, "local_dns") and args.local_dns:
            source_results["dns_txt"] = load_local_dns_txt(args.local_dns)

    else:
        # Online mode: fetch from sources
        if hasattr(args, "github_repo") and args.github_repo:
            from specora_verify.fetchers.github import fetch_latest_github_anchor

            source_results["github_release"] = fetch_latest_github_anchor(args.github_repo)

        if hasattr(args, "s3_url") and args.s3_url:
            from specora_verify.fetchers.s3 import fetch_latest_s3_anchor

            source_results["s3_versioned"] = fetch_latest_s3_anchor(args.s3_url)

        if hasattr(args, "dns_fqdn") and args.dns_fqdn:
            from specora_verify.fetchers.dns import fetch_dns_txt_anchor

            source_results["dns_txt"] = fetch_dns_txt_anchor(args.dns_fqdn)

    # Check if we have any sources
    if not source_results:
        print(
            format_error(
                "No sources specified. Use --github-repo, --s3-url, or --dns-fqdn",
                output_format=args.format,
                code="NO_SOURCES",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Verify consistency
    quorum = getattr(args, "quorum", 2)
    result = verify_mirror_consistency(source_results, quorum_required=quorum)

    # Format and output
    print(format_mirror_result(result, output_format=args.format))

    # Emit receipt if requested
    if hasattr(args, "emit_receipt") and args.emit_receipt:
        from specora_verify import __version__

        receipt = create_mirror_receipt(
            result,
            verifier_version=__version__,
        )
        try:
            args.emit_receipt.write_text(receipt.to_json(), encoding="utf-8")
            if args.format == "text":
                print(f"\nReceipt written to: {args.emit_receipt}")
        except Exception as e:
            print(
                format_error(
                    f"Failed to write receipt: {e}",
                    output_format=args.format,
                    code="WRITE_ERROR",
                ),
                file=sys.stderr,
            )

    return status_to_exit_code(result.status)


def cmd_mirror_verify_anchors(args: argparse.Namespace) -> int:
    """Handle: specora-verify mirror verify-anchors --since <date>

    Verifies anchor history across surfaces starting from a given date.
    Supports both online (fetching from sources) and offline (local directory) modes.
    """
    from datetime import datetime
    from specora_verify.output import format_anchor_chain_result
    from specora_verify.validators.mirror import (
        MirrorSource,
        SourceResult,
        create_anchor_chain_receipt,
        status_to_exit_code,
        verify_anchor_chain,
    )

    # Parse since date
    since_str = getattr(args, "since", None)
    if not since_str:
        print(
            format_error(
                "--since date is required",
                output_format=args.format,
                code="MISSING_SINCE",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Validate date format (we use string comparison for simplicity)
    try:
        # Normalize to YYYY-MM-DD prefix for string comparison
        for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"]:
            try:
                parsed = datetime.strptime(since_str, fmt)
                since_date_str = parsed.strftime("%Y-%m-%d")
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"Could not parse date: {since_str}")
    except ValueError as e:
        print(
            format_error(str(e), output_format=args.format, code="INVALID_DATE"),
            file=sys.stderr,
        )
        return EXIT_ERROR

    anchors_by_source: dict[str, list[SourceResult]] = {}
    quorum = getattr(args, "quorum", 2)

    # Offline mode: load anchors from local directories
    if getattr(args, "offline", False):
        from specora_verify.fetchers.local import load_local_anchor

        # Load from local directories specified
        local_github_dir = getattr(args, "local_github_dir", None)
        local_s3_dir = getattr(args, "local_s3_dir", None)

        if not local_github_dir and not local_s3_dir:
            print(
                format_error(
                    "Offline mode requires --local-github-dir or --local-s3-dir",
                    output_format=args.format,
                    code="MISSING_LOCAL_DIRS",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR

        # Load anchors from local directories
        from pathlib import Path

        if local_github_dir:
            github_dir = Path(local_github_dir)
            if github_dir.exists() and github_dir.is_dir():
                github_anchors = []
                for anchor_file in sorted(github_dir.glob("*.json")):
                    result = load_local_anchor(anchor_file, MirrorSource.GITHUB_RELEASE)
                    if result.reachable and result.anchor_data:
                        # Filter by date if timestamp available
                        timestamp = result.anchor_data.get("timestamp", "")
                        if timestamp >= since_date_str or not timestamp:
                            github_anchors.append(result)
                if github_anchors:
                    anchors_by_source["github_release"] = github_anchors

        if local_s3_dir:
            s3_dir = Path(local_s3_dir)
            if s3_dir.exists() and s3_dir.is_dir():
                s3_anchors = []
                for anchor_file in sorted(s3_dir.glob("*.json")):
                    result = load_local_anchor(anchor_file, MirrorSource.S3_VERSIONED)
                    if result.reachable and result.anchor_data:
                        timestamp = result.anchor_data.get("timestamp", "")
                        if timestamp >= since_date_str or not timestamp:
                            s3_anchors.append(result)
                if s3_anchors:
                    anchors_by_source["s3_versioned"] = s3_anchors

    else:
        # Online mode: fetch from remote sources
        # Note: This requires listing capabilities which may not be available
        # For now, provide a helpful message about using offline mode
        github_repo = getattr(args, "github_repo", None)
        s3_prefix = getattr(args, "s3_prefix", None)

        if not github_repo and not s3_prefix:
            print(
                format_error(
                    "Online mode requires --github-repo or --s3-prefix",
                    output_format=args.format,
                    code="MISSING_SOURCES",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR

        # For online mode, we would need to:
        # 1. List releases from GitHub
        # 2. List objects from S3
        # 3. Fetch each anchor
        # This is complex and rate-limited, so for v1 we require offline mode
        print(
            format_error(
                "Online verify-anchors requires listing many objects and is rate-limited. "
                "For now, use offline mode: download anchors locally first, then use "
                "--offline --local-github-dir <dir> --local-s3-dir <dir>",
                output_format=args.format,
                code="ONLINE_NOT_SUPPORTED",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Check if we have any anchors
    if not anchors_by_source:
        print(
            format_error(
                f"No anchors found since {since_str}",
                output_format=args.format,
                code="NO_ANCHORS",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Verify anchor chain
    result = verify_anchor_chain(
        anchors_by_source,
        quorum_required=quorum,
        verify_linkage=True,
    )

    # Format and output
    print(format_anchor_chain_result(result, output_format=args.format))

    # Emit receipt if requested
    if hasattr(args, "emit_receipt") and args.emit_receipt:
        from specora_verify import __version__

        receipt = create_anchor_chain_receipt(
            result,
            verifier_version=__version__,
        )
        try:
            args.emit_receipt.write_text(receipt.to_json(), encoding="utf-8")
            if args.format == "text":
                print(f"\nReceipt written to: {args.emit_receipt}")
        except Exception as e:
            print(
                format_error(
                    f"Failed to write receipt: {e}",
                    output_format=args.format,
                    code="WRITE_ERROR",
                ),
                file=sys.stderr,
            )

    return status_to_exit_code(result.status)


# =============================================================================
# Witness Command Handlers (PR-ENT-550)
# =============================================================================


def cmd_witness_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify witness verify <statement.json>

    Validates a single witness statement structure and optionally verifies
    the signature against a witness registry.
    """
    # Block skip_signature in CI mode
    ci_error = _check_skip_signature_in_ci(args)
    if ci_error is not None:
        return ci_error

    from specora_verify.fetchers.witness import load_local_witness_statement
    from specora_verify.output import format_witness_statement_result
    from specora_verify.validators.witness import (
        WitnessVerificationStatus,
        load_witness_registry,
        validate_witness_statement,
        witness_status_to_exit_code,
    )

    # Load witness statement
    fetch_result = load_local_witness_statement(args.statement)
    if not fetch_result.success:
        print(
            format_error(
                fetch_result.error or f"Failed to load statement: {args.statement}",
                output_format=args.format,
                code="STATEMENT_LOAD_ERROR",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    statement = fetch_result.statement

    # Load registry if provided
    registry = None
    if hasattr(args, "registry") and args.registry:
        try:
            registry = load_witness_registry(args.registry)
        except Exception as e:
            print(
                format_error(
                    f"Failed to load registry: {e}",
                    output_format=args.format,
                    code="REGISTRY_LOAD_ERROR",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR

    # Load anchor for hash comparison if provided
    expected_anchor_hash = None
    if hasattr(args, "anchor") and args.anchor:
        anchor_data = _load_json_file(args.anchor, args.format)
        if anchor_data:
            expected_anchor_hash = anchor_data.get("anchor_hash")

    # Validate statement
    result = validate_witness_statement(
        statement=statement,
        registry=registry,
        expected_anchor_hash=expected_anchor_hash,
        skip_signature=getattr(args, "skip_signature", False),
    )

    # Format and output
    print(
        format_witness_statement_result(
            result,
            output_format=args.format,
            file_path=str(args.statement),
        )
    )

    if result.valid:
        return EXIT_PASS
    else:
        return EXIT_FAIL


def cmd_witness_verify_network(args: argparse.Namespace) -> int:
    """Handle: specora-verify witness verify-network

    Verifies multiple witness statements achieve quorum consensus.
    """
    # Block skip_signature in CI mode
    ci_error = _check_skip_signature_in_ci(args)
    if ci_error is not None:
        return ci_error

    from specora_verify.fetchers.witness import load_local_witness_statements_dir
    from specora_verify.output import format_witness_quorum_result
    from specora_verify.validators.witness import (
        create_witness_receipt,
        load_witness_registry,
        verify_witness_quorum,
        witness_status_to_exit_code,
    )

    # Load registry
    try:
        registry = load_witness_registry(args.registry)
    except Exception as e:
        print(
            format_error(
                f"Failed to load registry: {e}",
                output_format=args.format,
                code="REGISTRY_LOAD_ERROR",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load statements from directory
    fetch_results = load_local_witness_statements_dir(args.statements_dir)
    statements = [r.statement for r in fetch_results if r.success and r.statement]

    if not statements:
        print(
            format_error(
                f"No valid witness statements found in: {args.statements_dir}",
                output_format=args.format,
                code="NO_STATEMENTS",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load anchor for hash comparison if provided
    expected_anchor_hash = None
    if hasattr(args, "anchor") and args.anchor:
        anchor_data = _load_json_file(args.anchor, args.format)
        if anchor_data:
            expected_anchor_hash = anchor_data.get("anchor_hash")

    # Verify quorum
    quorum_required = getattr(args, "min_witnesses", 2)
    result = verify_witness_quorum(
        statements=statements,
        registry=registry,
        quorum_required=quorum_required,
        expected_anchor_hash=expected_anchor_hash,
        skip_signature=getattr(args, "skip_signature", False),
    )

    # Format and output
    print(format_witness_quorum_result(result, output_format=args.format))

    # Emit receipt if requested
    if hasattr(args, "emit_receipt") and args.emit_receipt:
        from specora_verify import __version__

        receipt = create_witness_receipt(
            result=result,
            registry=registry,
            verifier_version=__version__,
        )
        try:
            args.emit_receipt.write_text(receipt.to_json(), encoding="utf-8")
            if args.format == "text":
                print(f"\nReceipt written to: {args.emit_receipt}")
        except Exception as e:
            print(
                format_error(
                    f"Failed to write receipt: {e}",
                    output_format=args.format,
                    code="WRITE_ERROR",
                ),
                file=sys.stderr,
            )

    return witness_status_to_exit_code(result.status)


def cmd_witness_registry_info(args: argparse.Namespace) -> int:
    """Handle: specora-verify witness registry-info

    Displays information about a witness registry.
    """
    from specora_verify.output import format_witness_registry_info
    from specora_verify.validators.witness import load_witness_registry

    try:
        registry = load_witness_registry(args.registry)
    except Exception as e:
        print(
            format_error(
                f"Failed to load registry: {e}",
                output_format=args.format,
                code="REGISTRY_LOAD_ERROR",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    print(format_witness_registry_info(registry, output_format=args.format))
    return EXIT_PASS


# =============================================================================
# Registry Snapshot Commands (PR-ENT-560)
# =============================================================================


def cmd_registry_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify registry verify

    Verifies a single registry snapshot signature and structure.
    """
    # Block skip_signature in CI mode
    ci_error = _check_skip_signature_in_ci(args)
    if ci_error is not None:
        return ci_error

    from specora_verify.output import format_registry_snapshot_result
    from specora_verify.validators.registry import (
        create_registry_receipt,
        get_exit_code,
        load_registry_snapshot,
        validate_registry_snapshot,
    )

    # Load snapshot
    try:
        snapshot = load_registry_snapshot(args.snapshot)
    except Exception as e:
        print(
            format_error(
                f"Failed to load snapshot: {e}",
                output_format=args.format,
                code="SNAPSHOT_LOAD_ERROR",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load public key if provided
    public_key = None
    if hasattr(args, "public_key") and args.public_key:
        try:
            public_key = args.public_key.read_text(encoding="utf-8").strip()
        except Exception as e:
            print(
                format_error(
                    f"Failed to load public key: {e}",
                    output_format=args.format,
                    code="KEY_LOAD_ERROR",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR

    # Validate snapshot
    result = validate_registry_snapshot(
        snapshot=snapshot,
        public_key=public_key,
        key_format=getattr(args, "key_format", "pem"),
        skip_signature=getattr(args, "skip_signature", False),
    )

    # Format and output
    print(
        format_registry_snapshot_result(
            result,
            output_format=args.format,
            file_path=str(args.snapshot),
        )
    )

    # Emit receipt if requested
    if hasattr(args, "emit_receipt") and args.emit_receipt:
        from specora_verify import __version__

        receipt = create_registry_receipt(
            result=result,
            verifier_version=__version__,
        )
        try:
            args.emit_receipt.write_text(receipt.to_json(), encoding="utf-8")
            if args.format == "text":
                print(f"\nReceipt written to: {args.emit_receipt}")
        except Exception as e:
            print(
                format_error(
                    f"Failed to write receipt: {e}",
                    output_format=args.format,
                    code="WRITE_ERROR",
                ),
                file=sys.stderr,
            )

    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_registry_verify_chain(args: argparse.Namespace) -> int:
    """Handle: specora-verify registry verify-chain

    Verifies a chain of registry snapshots.
    """
    # Block skip_signature in CI mode
    ci_error = _check_skip_signature_in_ci(args)
    if ci_error is not None:
        return ci_error

    from specora_verify.fetchers.registry import load_registry_snapshots_sorted
    from specora_verify.output import format_registry_chain_result
    from specora_verify.validators.registry import (
        create_registry_receipt,
        get_exit_code,
        verify_registry_chain,
    )

    # Load snapshots from directory
    snapshots, load_errors = load_registry_snapshots_sorted(args.snapshots_dir)

    if not snapshots:
        print(
            format_error(
                f"No valid registry snapshots found in: {args.snapshots_dir}",
                output_format=args.format,
                code="NO_SNAPSHOTS",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load public key if provided
    public_key = None
    if hasattr(args, "public_key") and args.public_key:
        try:
            public_key = args.public_key.read_text(encoding="utf-8").strip()
        except Exception as e:
            print(
                format_error(
                    f"Failed to load public key: {e}",
                    output_format=args.format,
                    code="KEY_LOAD_ERROR",
                ),
                file=sys.stderr,
            )
            return EXIT_ERROR

    # Verify chain
    result = verify_registry_chain(
        snapshots=snapshots,
        public_key=public_key,
        key_format=getattr(args, "key_format", "pem"),
        skip_signature=getattr(args, "skip_signature", False),
    )

    # Format and output
    print(format_registry_chain_result(result, output_format=args.format))

    # Emit receipt if requested
    if hasattr(args, "emit_receipt") and args.emit_receipt:
        from specora_verify import __version__

        receipt = create_registry_receipt(
            result=result,
            verifier_version=__version__,
        )
        try:
            args.emit_receipt.write_text(receipt.to_json(), encoding="utf-8")
            if args.format == "text":
                print(f"\nReceipt written to: {args.emit_receipt}")
        except Exception as e:
            print(
                format_error(
                    f"Failed to write receipt: {e}",
                    output_format=args.format,
                    code="WRITE_ERROR",
                ),
                file=sys.stderr,
            )

    return get_exit_code(result.status)


def cmd_registry_info(args: argparse.Namespace) -> int:
    """Handle: specora-verify registry info

    Displays information about a registry snapshot.
    """
    from specora_verify.output import format_registry_snapshot_info
    from specora_verify.validators.registry import load_registry_snapshot

    try:
        snapshot = load_registry_snapshot(args.snapshot)
    except Exception as e:
        print(
            format_error(
                f"Failed to load snapshot: {e}",
                output_format=args.format,
                code="SNAPSHOT_LOAD_ERROR",
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    print(format_registry_snapshot_info(snapshot, output_format=args.format))
    return EXIT_PASS


# =============================================================================
# STP Command Handlers (PLATFORM-470)
# =============================================================================


def cmd_stp_init(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp init

    Initialize STP integration scaffold.
    """
    result = generate_stp_scaffold(
        output_dir=args.out,
        runtime=args.runtime,
        org_id=args.org_id,
        force=args.force,
    )
    print(format_stp_init_result(result, output_format=args.format))
    return EXIT_PASS if result.success else EXIT_FAIL


def cmd_stp_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp verify <file>

    Verify STP message against protocol schema.
    """
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    result = validate_stp_message(
        payload,
        message_type=args.schema,
        strict=args.strict,
        check_seal=args.check_seal,
        expected_seal=args.expected_seal if hasattr(args, "expected_seal") else None,
    )
    print(format_stp_verify_result(result, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_stp_simulate(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp simulate <file>

    Simulate STP governance decision locally.
    """
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    policy_path = args.policy
    if policy_path is None:
        # Try default policy location
        default_policy = Path(".specora-stp/policy.json")
        if default_policy.exists():
            policy_path = default_policy

    result = simulate_stp_decision(
        payload,
        policy_path=policy_path,
        trust_score=args.trust_score,
    )
    print(format_stp_simulate_result(result, output_format=args.format))
    return EXIT_PASS


def cmd_stp_inspect(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp inspect <file>

    Inspect STP artifact details.
    """
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    result = inspect_stp_artifact(
        payload,
        show_seal=args.show_seal,
        show_chain=args.show_chain,
        show_canonical=args.show_canonical,
    )
    print(format_stp_inspect_result(result, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS


def cmd_stp_vectors_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp vectors verify

    Verify STP golden test vectors.
    """
    result = verify_stp_vectors(args.vectors_dir)
    print(format_stp_vectors_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_stp_hash(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp hash <file>

    Compute canonical SHA-256 hash of STP artifact.
    """
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    hash_value = compute_manifest_hash(payload)
    print(format_hash_result(hash_value, output_format=args.format, file_path=str(args.file)))
    return EXIT_PASS


# =============================================================================
# STP Certification Command Handlers
# =============================================================================


def cmd_stp_certify_scaffold(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp certify scaffold

    Generate STP certification bundle scaffold for a tier.
    """
    result = generate_stp_certification_scaffold(
        output_dir=args.out,
        tier=args.tier,
        adapter_name=args.adapter_name,
        adapter_version=args.adapter_version,
        vendor_name=args.vendor_name,
        force=args.force,
    )
    print(format_stp_certification_scaffold_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_ERROR


def cmd_stp_certify_check(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp certify check

    Check STP certification bundle against tier requirements.
    """
    result = check_stp_certification_bundle(
        bundle_path=args.bundle,
        tier=args.tier,
    )
    print(format_stp_certification_check_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_stp_certify_attest(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp certify attest

    Generate STP certification attestation for a bundle.
    """
    attestation = generate_stp_certification_attestation(
        bundle_path=args.bundle,
        tier=args.tier,
        issued_at=args.issued_at,
    )

    # Write attestation to output file
    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(attestation, indent=2), encoding="utf-8")
    except OSError as e:
        print(
            format_error(
                f"Failed to write attestation: {e}",
                output_format=args.format,
            ),
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Validate the generated attestation
    result = validate_stp_certification_attestation(attestation)
    print(format_stp_certification_attestation_result(
        result, output_format=args.format, file_path=str(args.out)
    ))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_stp_certify_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp certify verify <file>

    Verify STP certification attestation structure.
    """
    payload = _load_json_file(args.file, args.format)
    if payload is None:
        return EXIT_ERROR

    result = validate_stp_certification_attestation(
        payload,
        expected_hash=getattr(args, "expected", None),
    )
    print(format_stp_certification_attestation_result(
        result, output_format=args.format, file_path=str(args.file)
    ))
    return EXIT_PASS if result.valid else EXIT_FAIL


def cmd_stp_certify_vectors_verify(args: argparse.Namespace) -> int:
    """Handle: specora-verify stp certify vectors verify

    Verify STP certification golden test vectors.
    """
    vectors_dir = getattr(args, "vectors_dir", None)
    result = verify_stp_certification_vectors(vectors_dir)
    print(format_stp_certification_vectors_result(result, output_format=args.format))
    return EXIT_PASS if result.valid else EXIT_FAIL


def main(argv: list[str] | None = None) -> NoReturn:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Default format attribute if not set
    if not hasattr(args, "format"):
        args.format = "text"

    # Default CI mode if not set
    if not hasattr(args, "ci"):
        args.ci = False

    # Load revocation list if provided
    args.revocation_list_data = None
    if hasattr(args, "revocation_list") and args.revocation_list:
        try:
            from specora_verify.revocation import load_revocation_list

            args.revocation_list_data = load_revocation_list(args.revocation_list)
        except Exception as e:
            print(
                format_error(
                    f"Failed to load revocation list: {e}",
                    output_format=args.format,
                    code="REVOCATION_LIST_ERROR",
                ),
                file=sys.stderr,
            )
            sys.exit(EXIT_ERROR)

    # Default require_trusted_key if not set
    if not hasattr(args, "require_trusted_key"):
        args.require_trusted_key = False

    # Route to appropriate handler
    exit_code = EXIT_ERROR

    if args.command == "verify":
        exit_code = cmd_verify_signature(args)
    elif args.command == "verify-log":
        exit_code = cmd_verify_log(args)
    elif args.command == "emit-receipt":
        exit_code = cmd_emit_receipt(args)
    elif args.command == "canonicalize":
        exit_code = cmd_canonicalize(args)
    elif args.command == "key-info":
        exit_code = cmd_key_info(args)
    elif args.command == "vectors":
        if args.vectors_command == "verify":
            exit_code = cmd_vectors_verify(args)
        else:
            parser.print_help()
    elif args.command == "manifest":
        if args.manifest_command == "hash":
            exit_code = cmd_manifest_hash(args)
        elif args.manifest_command == "verify":
            exit_code = cmd_manifest_verify(args)
        else:
            parser.print_help()
    elif args.command == "bundle":
        if args.bundle_command == "verify":
            exit_code = cmd_bundle_verify(args)
        else:
            parser.print_help()
    elif args.command == "anchor":
        if args.anchor_command == "vectors":
            if hasattr(args, "anchor_vectors_command") and args.anchor_vectors_command == "verify":
                exit_code = cmd_anchor_vectors_verify(args)
            else:
                parser.print_help()
        elif args.anchor_command == "hash":
            exit_code = cmd_anchor_hash(args)
        elif args.anchor_command == "verify":
            exit_code = cmd_anchor_verify(args)
        else:
            parser.print_help()
    elif args.command == "receipt":
        if args.receipt_command == "vectors":
            if hasattr(args, "receipt_vectors_command") and args.receipt_vectors_command == "verify":
                exit_code = cmd_receipt_vectors_verify(args)
            else:
                parser.print_help()
        elif args.receipt_command == "hash":
            exit_code = cmd_receipt_hash(args)
        elif args.receipt_command == "verify":
            exit_code = cmd_receipt_verify(args)
        else:
            parser.print_help()
    elif args.command == "certify":
        if args.certify_command == "scaffold":
            exit_code = cmd_certify_scaffold(args)
        elif args.certify_command == "check":
            exit_code = cmd_certify_check(args)
        elif args.certify_command == "attest":
            exit_code = cmd_certify_attest(args)
        elif args.certify_command == "vectors":
            if hasattr(args, "certify_vectors_command") and args.certify_vectors_command == "verify":
                exit_code = cmd_certify_vectors_verify(args)
            else:
                parser.print_help()
        elif args.certify_command == "hash":
            exit_code = cmd_certify_hash(args)
        elif args.certify_command == "verify":
            exit_code = cmd_certify_verify(args)
        else:
            parser.print_help()
    elif args.command == "read":
        if args.read_command == "anthropic":
            exit_code = cmd_read_anthropic(args)
        elif args.read_command == "cloudtrail":
            exit_code = cmd_read_cloudtrail(args)
        elif args.read_command == "azure-cl":
            exit_code = cmd_read_azure_cl(args)
        elif args.read_command == "openai":
            exit_code = cmd_read_openai(args)
        elif args.read_command == "langsmith":
            exit_code = cmd_read_langsmith(args)
        else:
            parser.print_help()
    elif args.command == "run":
        exit_code = cmd_run(args)
    elif args.command == "verify-external-anchor":
        exit_code = cmd_verify_external_anchor(args)
    elif args.command == "verify-external-anchor-chain":
        exit_code = cmd_verify_external_anchor_chain(args)
    elif args.command == "mirror":
        if args.mirror_command == "verify-latest":
            exit_code = cmd_mirror_verify_latest(args)
        elif args.mirror_command == "verify-anchors":
            exit_code = cmd_mirror_verify_anchors(args)
        else:
            parser.print_help()
    elif args.command == "witness":
        if args.witness_command == "verify":
            exit_code = cmd_witness_verify(args)
        elif args.witness_command == "verify-network":
            exit_code = cmd_witness_verify_network(args)
        elif args.witness_command == "registry-info":
            exit_code = cmd_witness_registry_info(args)
        else:
            parser.print_help()
    elif args.command == "registry":
        if args.registry_command == "verify":
            exit_code = cmd_registry_verify(args)
        elif args.registry_command == "verify-chain":
            exit_code = cmd_registry_verify_chain(args)
        elif args.registry_command == "info":
            exit_code = cmd_registry_info(args)
        else:
            parser.print_help()
    elif args.command == "stp":
        if args.stp_command == "init":
            exit_code = cmd_stp_init(args)
        elif args.stp_command == "verify":
            exit_code = cmd_stp_verify(args)
        elif args.stp_command == "simulate":
            exit_code = cmd_stp_simulate(args)
        elif args.stp_command == "inspect":
            exit_code = cmd_stp_inspect(args)
        elif args.stp_command == "vectors":
            if hasattr(args, "stp_vectors_command") and args.stp_vectors_command == "verify":
                exit_code = cmd_stp_vectors_verify(args)
            else:
                parser.print_help()
        elif args.stp_command == "hash":
            exit_code = cmd_stp_hash(args)
        elif args.stp_command == "certify":
            if args.stp_certify_command == "scaffold":
                exit_code = cmd_stp_certify_scaffold(args)
            elif args.stp_certify_command == "check":
                exit_code = cmd_stp_certify_check(args)
            elif args.stp_certify_command == "attest":
                exit_code = cmd_stp_certify_attest(args)
            elif args.stp_certify_command == "verify":
                exit_code = cmd_stp_certify_verify(args)
            elif args.stp_certify_command == "vectors":
                if hasattr(args, "stp_certify_vectors_command") and args.stp_certify_vectors_command == "verify":
                    exit_code = cmd_stp_certify_vectors_verify(args)
                else:
                    parser.print_help()
            else:
                parser.print_help()
        else:
            parser.print_help()
    else:
        parser.print_help()

    # Apply CI mode exit code mapping
    original_exit_code = exit_code
    exit_code = map_exit_code_for_ci(exit_code, args.ci)

    # If CI mode changed the exit code, output a message
    if args.ci and original_exit_code != exit_code:
        original_name = exit_code_name(original_exit_code)
        mapped_name = exit_code_name(exit_code)
        if args.format == "json":
            print(
                json.dumps(
                    {
                        "ci_mode": True,
                        "original_status": original_name,
                        "mapped_status": mapped_name,
                        "exit_code": exit_code,
                    }
                ),
                file=sys.stderr,
            )
        else:
            print(
                f"\n[CI MODE] Status {original_name} mapped to {mapped_name} (exit {exit_code})",
                file=sys.stderr,
            )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
