"""AID-980 — Public transparency log + inclusion-proof tool (demo lane).

Apache 2.0. CSEA-SUPPRESS-2026-05-08-002 / archive 2026-06-05.

Append-only Merkle-tree-backed log of every issuance / rotation /
revocation event for the AID-9xx investor-demo lane. Sigstore Rekor
is the design model; this is a stripped-down filesystem-only variant
suitable for the demo window. Production transparency log
(``transparency.specora.ai``) is post-K14 work.

Wire-level format (one JSON file per epoch under
``transparency/<epoch_id>/``):

    transparency/<epoch_id>/entries.ndjson    — newline-delimited JSON,
                                                one entry per line; the
                                                immutable record. Append
                                                only.
    transparency/<epoch_id>/root.json         — Merkle root over the
                                                entries.ndjson contents.

Invariants:

* **Append-only** — entries are written once, never updated, never
  deleted. The CI guard ``test_transparency_log_no_gaps`` walks the
  on-disk state and asserts every (epoch, seq) pair from 0..N-1 is
  present.
* **Monotonic seq** — per-epoch sequence numbers start at 0 and
  increment by 1 per write. No gaps.
* **Merkle linkage** — every entry's ``leaf_hash`` is SHA-256 over
  canonical-JSON of the entry minus ``leaf_hash``. The epoch's
  ``merkle_root_hash`` is the binary Merkle tree root over leaf hashes
  in seq order, hashed with SHA-256.
* **Format identifier load-bearing** — every entry carries
  ``format = "specora-aid-tlog-v1-demo"``. The ``-demo`` suffix is
  intentional; production format will revise.

Doctrine: out-of-band always. Reading the log requires no contact
with Specora. The relying party fetches the log over plain HTTP from
the demo subdomain (``demo.specora.ai/transparency-log/``).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes

LOG_FORMAT_VERSION = "specora-aid-tlog-v1-demo"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransparencyLogEntry:
    """One log entry — an issuance / rotation / revocation event."""

    epoch_id: str
    seq: int
    event_type: str  # one of registered|issued|rotated|revoked
    identity_id: str
    org_id: str
    public_key_at_event: str | None
    timestamp: str  # RFC 3339 UTC "Z"
    leaf_hash: str  # SHA-256 hex of the canonical JSON of the entry minus leaf_hash

    def to_json(self) -> dict[str, Any]:
        return {
            "format": LOG_FORMAT_VERSION,
            "epoch_id": self.epoch_id,
            "seq": self.seq,
            "event_type": self.event_type,
            "identity_id": self.identity_id,
            "org_id": self.org_id,
            "public_key_at_event": self.public_key_at_event,
            "timestamp": self.timestamp,
            "leaf_hash": self.leaf_hash,
        }


@dataclass
class InclusionProof:
    """Proof that an entry is included in an epoch's Merkle tree."""

    epoch_id: str
    seq: int
    leaf_hash: str
    merkle_root_hash: str
    audit_path: list[tuple[str, str]]  # (sibling_hash, "left"|"right")

    def to_json(self) -> dict[str, Any]:
        return {
            "format": LOG_FORMAT_VERSION,
            "epoch_id": self.epoch_id,
            "seq": self.seq,
            "leaf_hash": self.leaf_hash,
            "merkle_root_hash": self.merkle_root_hash,
            "audit_path": [{"sibling": s, "position": p} for s, p in self.audit_path],
        }


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


def _leaf_hash(entry_without_leaf_hash: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(entry_without_leaf_hash)).hexdigest()


def _internal_hash(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(leaf_hashes: list[str]) -> str:
    """Compute Merkle root over an ordered list of leaf hashes.

    Empty list returns the SHA-256 of an empty string (matches Sigstore
    Rekor's empty-tree convention). Odd levels duplicate the rightmost
    hash before pairing, the standard Merkle convention.
    """
    if not leaf_hashes:
        return hashlib.sha256(b"").hexdigest()
    layer = list(leaf_hashes)
    while len(layer) > 1:
        nxt: list[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(_internal_hash(left, right))
        layer = nxt
    return layer[0]


def compute_inclusion_proof(*, leaf_index: int, leaf_hashes: list[str]) -> list[tuple[str, str]]:
    """Build the audit path for ``leaf_index`` over ``leaf_hashes``."""
    if leaf_index < 0 or leaf_index >= len(leaf_hashes):
        raise IndexError("leaf_index out of range")
    layer = list(leaf_hashes)
    idx = leaf_index
    path: list[tuple[str, str]] = []
    while len(layer) > 1:
        if idx % 2 == 1:
            sibling = layer[idx - 1]
            path.append((sibling, "left"))
        else:
            if idx + 1 < len(layer):
                sibling = layer[idx + 1]
            else:
                sibling = layer[idx]
            path.append((sibling, "right"))
        nxt: list[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(_internal_hash(left, right))
        layer = nxt
        idx //= 2
    return path


def verify_inclusion_proof(proof: InclusionProof) -> bool:
    """Verify an inclusion proof reproduces the claimed Merkle root."""
    h = proof.leaf_hash
    for sibling, position in proof.audit_path:
        if position == "left":
            h = _internal_hash(sibling, h)
        else:
            h = _internal_hash(h, sibling)
    return h == proof.merkle_root_hash


# ---------------------------------------------------------------------------
# On-disk transparency log (filesystem-backed for the demo)
# ---------------------------------------------------------------------------


class TransparencyLog:
    """Append-only filesystem-backed transparency log.

    Demo-equivalent of Sigstore Rekor — same wire-level shape, same
    Merkle linkage, same out-of-band fetch posture. Production
    deployment swaps the filesystem store for an HTTP-fronted append-
    only blob store.
    """

    def __init__(self, root_dir: Path | str) -> None:
        self.root_dir = Path(root_dir)

    # ---- Append path -------------------------------------------------

    def append_entry(
        self,
        *,
        epoch_id: str,
        event_type: str,
        identity_id: str,
        org_id: str,
        public_key_at_event: str | None,
        timestamp: str,
    ) -> TransparencyLogEntry:
        """Append a new entry to ``epoch_id``. Allocates seq atomically.

        Caller must serialize calls per epoch — concurrent appends to
        the same epoch must be coordinated by the caller (in the
        platform service, the AID-960 service-layer transaction
        provides the natural serialization).
        """
        epoch_dir = self.root_dir / epoch_id
        epoch_dir.mkdir(parents=True, exist_ok=True)
        entries_path = epoch_dir / "entries.ndjson"

        existing = self._read_entries(epoch_id)
        next_seq = len(existing)

        entry_partial = {
            "format": LOG_FORMAT_VERSION,
            "epoch_id": epoch_id,
            "seq": next_seq,
            "event_type": event_type,
            "identity_id": identity_id,
            "org_id": org_id,
            "public_key_at_event": public_key_at_event,
            "timestamp": timestamp,
        }
        leaf = _leaf_hash(entry_partial)
        full = {**entry_partial, "leaf_hash": leaf}

        with open(entries_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(full, separators=(",", ":")) + "\n")

        # Refresh the epoch root metadata.
        self._refresh_root(epoch_id)

        return TransparencyLogEntry(
            epoch_id=epoch_id,
            seq=next_seq,
            event_type=event_type,
            identity_id=identity_id,
            org_id=org_id,
            public_key_at_event=public_key_at_event,
            timestamp=timestamp,
            leaf_hash=leaf,
        )

    def _refresh_root(self, epoch_id: str) -> None:
        entries = self._read_entries(epoch_id)
        leaf_hashes = [e["leaf_hash"] for e in entries]
        root = merkle_root(leaf_hashes)
        root_payload = {
            "format": LOG_FORMAT_VERSION,
            "epoch_id": epoch_id,
            "entry_count": len(entries),
            "merkle_root_hash": root,
        }
        root_path = self.root_dir / epoch_id / "root.json"
        tmp_path = root_path.with_suffix(root_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(root_payload, indent=2, sort_keys=True) + "\n")
        os.replace(tmp_path, root_path)

    # ---- Read / proof path ------------------------------------------

    def get_entry(self, *, epoch_id: str, seq: int) -> TransparencyLogEntry | None:
        entries = self._read_entries(epoch_id)
        if 0 <= seq < len(entries):
            e = entries[seq]
            return TransparencyLogEntry(
                epoch_id=e["epoch_id"],
                seq=e["seq"],
                event_type=e["event_type"],
                identity_id=e["identity_id"],
                org_id=e["org_id"],
                public_key_at_event=e["public_key_at_event"],
                timestamp=e["timestamp"],
                leaf_hash=e["leaf_hash"],
            )
        return None

    def epoch_root(self, epoch_id: str) -> dict[str, Any]:
        path = self.root_dir / epoch_id / "root.json"
        return json.loads(path.read_text())

    def inclusion_proof(self, *, epoch_id: str, seq: int) -> InclusionProof:
        entries = self._read_entries(epoch_id)
        if seq < 0 or seq >= len(entries):
            raise IndexError(f"seq {seq} out of range for {epoch_id}")
        leaf_hashes = [e["leaf_hash"] for e in entries]
        path = compute_inclusion_proof(leaf_index=seq, leaf_hashes=leaf_hashes)
        return InclusionProof(
            epoch_id=epoch_id,
            seq=seq,
            leaf_hash=leaf_hashes[seq],
            merkle_root_hash=merkle_root(leaf_hashes),
            audit_path=path,
        )

    # ---- Internal ----------------------------------------------------

    def _read_entries(self, epoch_id: str) -> list[dict[str, Any]]:
        path = self.root_dir / epoch_id / "entries.ndjson"
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                out.append(json.loads(line))
        return out


# ---------------------------------------------------------------------------
# Monotonicity audit
# ---------------------------------------------------------------------------


def assert_monotonic_no_gaps(log: TransparencyLog, epoch_id: str) -> None:
    """Walk the log on disk and assert every seq from 0..N-1 is present.

    Used by CI gates and by the platform-side
    test_transparency_log_no_gaps test. Raises AssertionError on any
    gap. Returns None on a clean log.
    """
    entries = log._read_entries(epoch_id)  # noqa: SLF001 — internal but stable
    for expected, e in enumerate(entries):
        if e["seq"] != expected:
            raise AssertionError(
                f"transparency log gap in epoch {epoch_id}: expected seq {expected}, got {e['seq']}"
            )
        if e["format"] != LOG_FORMAT_VERSION:
            raise AssertionError(
                f"transparency log entry has unexpected format "
                f"{e['format']!r} (expected {LOG_FORMAT_VERSION!r})"
            )
