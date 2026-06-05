"""AID-980 transparency log tests.

CSEA-SUPPRESS-2026-05-08-002 / archive 2026-06-05.

Covers:

* Append / read / read-back round trip
* Monotonic seq with no gaps
* Merkle root recomputation matches stored root
* Inclusion-proof verifies against the stored Merkle root
* Tampering with an entry breaks the inclusion proof
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from specora_verify.transparency import (
    LOG_FORMAT_VERSION,
    TransparencyLog,
    assert_monotonic_no_gaps,
    merkle_root,
    verify_inclusion_proof,
)


@pytest.fixture
def log(tmp_path: Path) -> TransparencyLog:
    return TransparencyLog(tmp_path)


def _seed(log: TransparencyLog, count: int, *, epoch: str = "2026-05-08") -> None:
    for i in range(count):
        log.append_entry(
            epoch_id=epoch,
            event_type="issued" if i % 2 == 0 else "rotated",
            identity_id=f"00000000-0000-0000-0000-{str(i).zfill(12)}",
            org_id="00000000-0000-0000-0000-0000000000aa",
            public_key_at_event="a" * 64,
            timestamp=f"2026-05-08T12:00:{str(i).zfill(2)}Z",
        )


class TestAppend:
    def test_append_assigns_zero_indexed_seq(self, log):
        e0 = log.append_entry(
            epoch_id="2026-05-08",
            event_type="registered",
            identity_id="id-0",
            org_id="org-a",
            public_key_at_event="a" * 64,
            timestamp="2026-05-08T12:00:00Z",
        )
        e1 = log.append_entry(
            epoch_id="2026-05-08",
            event_type="issued",
            identity_id="id-0",
            org_id="org-a",
            public_key_at_event="a" * 64,
            timestamp="2026-05-08T12:00:01Z",
        )
        assert e0.seq == 0
        assert e1.seq == 1
        assert e0.leaf_hash != e1.leaf_hash

    def test_format_marker_is_demo(self, log):
        e = log.append_entry(
            epoch_id="2026-05-08",
            event_type="issued",
            identity_id="id-0",
            org_id="org-a",
            public_key_at_event="a" * 64,
            timestamp="2026-05-08T12:00:00Z",
        )
        # The on-disk file carries the load-bearing -demo suffix.
        path = (log.root_dir / "2026-05-08" / "entries.ndjson").read_text()
        assert LOG_FORMAT_VERSION in path
        assert "specora-aid-tlog-v1-demo" in path
        assert e.leaf_hash


class TestMonotonicity:
    def test_no_gaps_in_clean_log(self, log):
        _seed(log, 5)
        assert_monotonic_no_gaps(log, "2026-05-08")  # raises on gap

    def test_assert_monotonic_fails_on_synthetic_gap(self, log, tmp_path):
        _seed(log, 3)
        # Synthesize a corrupted entries file with a gap at seq=1.
        path = tmp_path / "2026-05-08" / "entries.ndjson"
        lines = [json.loads(ln) for ln in path.read_text().splitlines()]
        lines[1]["seq"] = 5  # corrupt
        path.write_text(
            "\n".join(json.dumps(ln, separators=(",", ":")) for ln in lines) + "\n"
        )
        with pytest.raises(AssertionError, match="gap"):
            assert_monotonic_no_gaps(log, "2026-05-08")


class TestMerkleRoot:
    def test_root_recomputes_to_stored(self, log):
        _seed(log, 4)
        stored = log.epoch_root("2026-05-08")
        leaf_hashes = [e["leaf_hash"] for e in log._read_entries("2026-05-08")]
        recomputed = merkle_root(leaf_hashes)
        assert stored["merkle_root_hash"] == recomputed
        assert stored["entry_count"] == 4

    def test_empty_epoch_has_well_defined_root(self, log):
        # No entries → empty-root constant
        log.root_dir.joinpath("2026-05-08").mkdir(parents=True)
        from specora_verify.transparency import merkle_root as mr

        assert mr([]).startswith("e3b0c44298fc1c14")  # SHA-256 of empty


class TestInclusionProof:
    def test_proof_verifies_for_every_entry(self, log):
        _seed(log, 7)  # odd count exercises the right-edge path
        for seq in range(7):
            proof = log.inclusion_proof(epoch_id="2026-05-08", seq=seq)
            assert verify_inclusion_proof(proof), f"inclusion proof failed at seq={seq}"

    def test_tampered_leaf_breaks_proof(self, log):
        _seed(log, 4)
        proof = log.inclusion_proof(epoch_id="2026-05-08", seq=2)
        # Mutate the proof by flipping a hex char on the leaf hash.
        bad_leaf = ("0" if proof.leaf_hash[0] != "0" else "1") + proof.leaf_hash[1:]
        from dataclasses import replace

        bad = replace(proof, leaf_hash=bad_leaf)
        assert not verify_inclusion_proof(bad)
