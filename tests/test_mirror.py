"""Tests for mirror verification (PR-ENT-540).

Tests for multi-surface consistency verification across
GitHub Releases, S3, and DNS TXT records.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from specora_verify.fetchers.local import load_local_anchor, load_local_dns_txt
from specora_verify.validators.mirror import (
    MirrorSource,
    MirrorStatus,
    SourceResult,
    create_mirror_receipt,
    status_to_exit_code,
    verify_mirror_consistency,
)


# Path to mirror test fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "mirror"


class TestSourceResult:
    """Tests for SourceResult dataclass."""

    def test_source_result_to_dict(self) -> None:
        """SourceResult.to_dict() returns expected structure."""
        result = SourceResult(
            source=MirrorSource.GITHUB_RELEASE,
            reachable=True,
            anchor_hash="d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
            chain_head_index=42,
            fetch_latency_ms=150,
        )

        d = result.to_dict()

        assert d["source"] == "github_release"
        assert d["reachable"] is True
        assert d["anchor_hash"] == "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
        assert d["chain_head_index"] == 42
        assert d["fetch_latency_ms"] == 150

    def test_source_result_unreachable(self) -> None:
        """SourceResult with error."""
        result = SourceResult(
            source=MirrorSource.DNS_TXT,
            reachable=False,
            error="DNS resolution failed",
            fetch_latency_ms=5000,
        )

        assert result.reachable is False
        assert result.anchor_hash is None
        assert result.error == "DNS resolution failed"


class TestLoadLocalAnchor:
    """Tests for local anchor loading."""

    def test_load_valid_github_anchor(self) -> None:
        """Load valid GitHub anchor from local file."""
        result = load_local_anchor(
            FIXTURES_DIR / "valid-github.json",
            MirrorSource.GITHUB_RELEASE,
        )

        assert result.reachable is True
        assert result.anchor_hash == "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
        assert result.chain_head_index == 42
        assert result.error is None
        assert result.source == MirrorSource.GITHUB_RELEASE

    def test_load_valid_s3_anchor(self) -> None:
        """Load valid S3 anchor from local file."""
        result = load_local_anchor(
            FIXTURES_DIR / "valid-s3.json",
            MirrorSource.S3_VERSIONED,
        )

        assert result.reachable is True
        assert result.anchor_hash == "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
        assert result.source == MirrorSource.S3_VERSIONED

    def test_load_nonexistent_file(self) -> None:
        """Loading nonexistent file returns unreachable result."""
        result = load_local_anchor(
            FIXTURES_DIR / "does-not-exist.json",
            MirrorSource.GITHUB_RELEASE,
        )

        assert result.reachable is False
        assert result.anchor_hash is None
        assert "not found" in result.error.lower()

    def test_load_dns_txt_record(self) -> None:
        """Load DNS TXT record value from local file."""
        result = load_local_dns_txt(FIXTURES_DIR / "valid-dns.txt")

        assert result.reachable is True
        assert result.source == MirrorSource.DNS_TXT
        # DNS has truncated 32-char hash prefix
        assert result.anchor_hash == "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"
        assert result.chain_head_index == 42


class TestVerifyMirrorConsistency:
    """Tests for verify_mirror_consistency function."""

    def test_all_sources_agree_pass(self) -> None:
        """All sources agree - should PASS."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
            "s3_versioned": load_local_anchor(
                FIXTURES_DIR / "valid-s3.json",
                MirrorSource.S3_VERSIONED,
            ),
        }

        result = verify_mirror_consistency(source_results, quorum_required=2)

        assert result.status == MirrorStatus.PASS
        assert result.valid is True
        assert result.quorum_achieved == 2
        assert result.quorum_required == 2
        assert result.sources_checked == 2
        assert result.sources_reachable == 2
        assert result.hash_mismatch_detected is False
        assert result.consensus_anchor_hash is not None
        assert len(result.errors) == 0

    def test_hash_mismatch_fail(self) -> None:
        """Hash mismatch detected - should FAIL (INV-ANCHOR-009)."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
            "s3_versioned": load_local_anchor(
                FIXTURES_DIR / "mismatch-s3.json",
                MirrorSource.S3_VERSIONED,
            ),
        }

        result = verify_mirror_consistency(source_results, quorum_required=2)

        assert result.status == MirrorStatus.FAIL
        assert result.valid is False
        assert result.hash_mismatch_detected is True
        assert len(result.mismatched_sources) > 0
        assert any("INV-ANCHOR-009" in e for e in result.errors)

    def test_partial_reachable_warn(self) -> None:
        """Some sources unreachable but quorum met - should WARN."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
            "s3_versioned": load_local_anchor(
                FIXTURES_DIR / "valid-s3.json",
                MirrorSource.S3_VERSIONED,
            ),
            "dns_txt": SourceResult(
                source=MirrorSource.DNS_TXT,
                reachable=False,
                error="DNS resolution failed",
            ),
        }

        result = verify_mirror_consistency(source_results, quorum_required=2)

        assert result.status == MirrorStatus.WARN
        assert result.valid is True
        assert result.quorum_achieved == 2
        assert result.sources_reachable == 2
        assert result.sources_checked == 3
        assert len(result.warnings) > 0

    def test_quorum_failure_error(self) -> None:
        """Cannot reach quorum - should ERROR."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
            "s3_versioned": SourceResult(
                source=MirrorSource.S3_VERSIONED,
                reachable=False,
                error="S3 bucket not found",
            ),
        }

        result = verify_mirror_consistency(source_results, quorum_required=2)

        assert result.status == MirrorStatus.ERROR
        assert result.valid is False
        assert result.quorum_achieved == 1
        assert result.quorum_required == 2
        assert len(result.errors) > 0

    def test_dns_truncation_matches(self) -> None:
        """DNS 32-char prefix should match full hash prefix."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
            "dns_txt": load_local_dns_txt(FIXTURES_DIR / "valid-dns.txt"),
        }

        result = verify_mirror_consistency(source_results, quorum_required=2)

        assert result.status == MirrorStatus.PASS
        assert result.valid is True
        assert result.quorum_achieved == 2
        assert result.hash_mismatch_detected is False

    def test_consensus_hash_from_non_dns_source(self) -> None:
        """Consensus hash should be full hash from non-DNS source."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
            "s3_versioned": load_local_anchor(
                FIXTURES_DIR / "valid-s3.json",
                MirrorSource.S3_VERSIONED,
            ),
            "dns_txt": load_local_dns_txt(FIXTURES_DIR / "valid-dns.txt"),
        }

        result = verify_mirror_consistency(source_results, quorum_required=2)

        # Consensus hash should be full 64-char hash from GitHub or S3
        assert result.consensus_anchor_hash is not None
        assert len(result.consensus_anchor_hash) == 64
        assert result.consensus_chain_index == 42


class TestMirrorVerificationResult:
    """Tests for MirrorVerificationResult."""

    def test_to_dict(self) -> None:
        """MirrorVerificationResult.to_dict() returns expected structure."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
            "s3_versioned": load_local_anchor(
                FIXTURES_DIR / "valid-s3.json",
                MirrorSource.S3_VERSIONED,
            ),
        }

        result = verify_mirror_consistency(source_results, quorum_required=2)
        d = result.to_dict()

        assert d["status"] == "pass"
        assert d["valid"] is True
        assert d["quorum_required"] == 2
        assert d["quorum_achieved"] == 2
        assert "sources" in d
        assert "github_release" in d["sources"]
        assert "s3_versioned" in d["sources"]


class TestCreateMirrorReceipt:
    """Tests for create_mirror_receipt function."""

    def test_create_receipt(self) -> None:
        """create_mirror_receipt generates valid receipt."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
            "s3_versioned": load_local_anchor(
                FIXTURES_DIR / "valid-s3.json",
                MirrorSource.S3_VERSIONED,
            ),
        }

        result = verify_mirror_consistency(source_results, quorum_required=2)
        receipt = create_mirror_receipt(
            result,
            verifier_version="0.1.0-test",
            public_key_fingerprint="abc123",
        )

        assert receipt.schema_version == "1.0.0"
        assert receipt.verifier_version == "0.1.0-test"
        assert receipt.verification_timestamp is not None
        assert receipt.verification_timestamp.endswith("Z")
        assert receipt.public_key_fingerprint == "abc123"
        assert receipt.result is result

    def test_receipt_to_json(self) -> None:
        """Receipt can be serialized to JSON."""
        source_results = {
            "github_release": load_local_anchor(
                FIXTURES_DIR / "valid-github.json",
                MirrorSource.GITHUB_RELEASE,
            ),
        }

        result = verify_mirror_consistency(source_results, quorum_required=1)
        receipt = create_mirror_receipt(result, verifier_version="0.1.0")

        json_str = receipt.to_json()

        assert '"schema_version": "1.0.0"' in json_str
        assert '"verifier_version": "0.1.0"' in json_str


class TestStatusToExitCode:
    """Tests for status_to_exit_code function."""

    def test_pass_returns_0(self) -> None:
        """PASS status returns exit code 0."""
        assert status_to_exit_code(MirrorStatus.PASS) == 0

    def test_warn_returns_1(self) -> None:
        """WARN status returns exit code 1."""
        assert status_to_exit_code(MirrorStatus.WARN) == 1

    def test_fail_returns_2(self) -> None:
        """FAIL status returns exit code 2."""
        assert status_to_exit_code(MirrorStatus.FAIL) == 2

    def test_error_returns_3(self) -> None:
        """ERROR status returns exit code 3."""
        assert status_to_exit_code(MirrorStatus.ERROR) == 3


# Path to chain test fixtures
CHAIN_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "mirror" / "chain"


class TestVerifyAnchorChain:
    """Tests for verify_anchor_chain function."""

    def test_valid_chain_pass(self) -> None:
        """Valid chain with consistent hashes - should PASS."""
        from specora_verify.validators.mirror import verify_anchor_chain

        # Load anchors from chain fixtures
        anchors_by_source = {
            "github_release": [
                load_local_anchor(CHAIN_FIXTURES_DIR / "anchor-00000001.json", MirrorSource.GITHUB_RELEASE),
                load_local_anchor(CHAIN_FIXTURES_DIR / "anchor-00000002.json", MirrorSource.GITHUB_RELEASE),
                load_local_anchor(CHAIN_FIXTURES_DIR / "anchor-00000003.json", MirrorSource.GITHUB_RELEASE),
            ],
        }

        result = verify_anchor_chain(anchors_by_source, quorum_required=1)

        assert result.status == MirrorStatus.PASS
        assert result.valid is True
        assert result.total_anchors == 3
        assert result.verified_anchors == 3
        assert result.first_index == 1
        assert result.last_index == 3
        assert result.chain_linkage_valid is True
        assert result.cross_surface_consistent is True
        assert len(result.broken_linkages) == 0

    def test_chain_linkage_verified(self) -> None:
        """Chain linkage should be verified correctly."""
        from specora_verify.validators.mirror import verify_anchor_chain

        anchors_by_source = {
            "github_release": [
                load_local_anchor(CHAIN_FIXTURES_DIR / "anchor-00000001.json", MirrorSource.GITHUB_RELEASE),
                load_local_anchor(CHAIN_FIXTURES_DIR / "anchor-00000002.json", MirrorSource.GITHUB_RELEASE),
            ],
        }

        result = verify_anchor_chain(anchors_by_source, quorum_required=1, verify_linkage=True)

        # First anchor (index 1) links to genesis, second links to first
        assert result.chain_linkage_valid is True
        assert len(result.anchor_details) == 2

        # Check that anchor 2's previous_hash matches anchor 1's hash
        detail1 = result.anchor_details[0]
        detail2 = result.anchor_details[1]
        assert detail2.previous_anchor_hash == detail1.anchor_hash

    def test_cross_surface_consistency(self) -> None:
        """Cross-surface consistency should be verified."""
        from specora_verify.validators.mirror import verify_anchor_chain

        # Same anchors from two sources
        anchors_by_source = {
            "github_release": [
                load_local_anchor(CHAIN_FIXTURES_DIR / "anchor-00000001.json", MirrorSource.GITHUB_RELEASE),
            ],
            "s3_versioned": [
                load_local_anchor(CHAIN_FIXTURES_DIR / "anchor-00000001.json", MirrorSource.S3_VERSIONED),
            ],
        }

        result = verify_anchor_chain(anchors_by_source, quorum_required=2)

        assert result.status == MirrorStatus.PASS
        assert result.cross_surface_consistent is True
        assert len(result.mismatched_indices) == 0

    def test_no_anchors_error(self) -> None:
        """Empty anchors should return ERROR."""
        from specora_verify.validators.mirror import verify_anchor_chain

        result = verify_anchor_chain({}, quorum_required=1)

        assert result.status == MirrorStatus.ERROR
        assert result.total_anchors == 0
        assert "No anchors found" in result.errors[0]


class TestAnchorChainVerificationResult:
    """Tests for AnchorChainVerificationResult."""

    def test_to_dict(self) -> None:
        """to_dict() returns expected structure."""
        from specora_verify.validators.mirror import verify_anchor_chain

        anchors_by_source = {
            "github_release": [
                load_local_anchor(CHAIN_FIXTURES_DIR / "anchor-00000001.json", MirrorSource.GITHUB_RELEASE),
            ],
        }

        result = verify_anchor_chain(anchors_by_source, quorum_required=1)
        d = result.to_dict()

        assert d["status"] == "pass"
        assert d["valid"] is True
        assert d["total_anchors"] == 1
        assert "anchor_details" in d
        assert len(d["anchor_details"]) == 1
