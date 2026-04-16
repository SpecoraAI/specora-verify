"""End-to-end out-of-band verification orchestration (EPIC-B03).

This module assembles the pieces shipped individually by A03 (Anthropic
reader), B01 (CloudTrail + Azure CL readers) and B02 (canonical bundle
schema + normalizer) into a single runnable pipeline:

    provider export  -->  reader  -->  canonical bundle payload
                                       -->  sign (Ed25519)
                                       -->  on-disk signed bundle directory
                                       -->  ``specora-verify verify`` (PASS)

The CLI entry point is ``specora-verify run --provider <p> --input <f>
--key-id <id> --private-key <k> --out <bundle-dir>``. It dispatches to
the already-registered provider reader via the same ``READERS`` registry
``specora-verify read`` uses — the shipped reader files stay untouched,
orchestration is a layer on top (per EPIC-B03 constraints).

Output layout (a single on-disk directory, given by ``--out``):

    <out>/
        payload.json       canonical bundle payload (sorted, compact JSON)
        payload.sig        base64 Ed25519 signature over
                           compute_manifest_hash(payload).encode("utf-8")
        signing-key.pub    64-char hex Ed25519 public key
        metadata.json      provider, key_id, schema_version, record_count,
                           warnings, payload_sha256

A bundle directory written this way verifies cleanly with::

    specora-verify verify \\
        --artifact <out>/payload.json \\
        --signature <out>/payload.sig \\
        --public-key <out>/signing-key.pub

which is what ``tests/e2e/test_out_of_band_flow.py`` asserts end-to-end
for every shipped provider, plus a deliberate-tamper negative case.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_str
from specora_verify.errors import ReaderError
from specora_verify.hash import compute_manifest_hash
from specora_verify.readers import ReadResult, available_readers, get_reader

__all__ = [
    "OrchestrationError",
    "RunResult",
    "run_pipeline",
    "load_signing_key",
]


class OrchestrationError(Exception):
    """Raised when the end-to-end pipeline cannot complete.

    Distinct from :class:`specora_verify.errors.ReaderError` so callers
    can tell reader failure (bad input) from orchestration failure (bad
    key material, unwritable output, etc.).
    """


@dataclass(frozen=True)
class RunResult:
    """Outcome of a successful ``run_pipeline`` invocation.

    Attributes:
        bundle_dir: Directory the signed bundle was written to.
        payload_path: ``<bundle_dir>/payload.json``.
        signature_path: ``<bundle_dir>/payload.sig``.
        public_key_path: ``<bundle_dir>/signing-key.pub``.
        metadata_path: ``<bundle_dir>/metadata.json``.
        provider: Provider name that was dispatched to.
        record_count: Records mapped by the reader.
        payload_sha256: SHA-256 of the canonical payload (same value the
            signature was computed over).
        warnings: Tuple of non-fatal reader warnings.
    """

    bundle_dir: Path
    payload_path: Path
    signature_path: Path
    public_key_path: Path
    metadata_path: Path
    provider: str
    record_count: int
    payload_sha256: str
    warnings: tuple[str, ...]


def load_signing_key(path: Path) -> Any:
    """Load an Ed25519 private key from ``path``.

    Accepted formats:

    * 64-char hex (raw 32-byte seed, with or without trailing newline)
    * Raw 32 bytes (binary)
    * PEM-encoded ``PRIVATE KEY`` (PKCS#8 unencrypted)

    Returns an ``Ed25519PrivateKey`` from the ``cryptography`` library.
    The ``cryptography`` extra (``pip install specora-verify[crypto]``)
    is required because signing is not in the stdlib-only core.

    Raises:
        OrchestrationError: on missing file, unsupported format, or
            missing ``cryptography`` dependency.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:
        raise OrchestrationError(
            "Signing requires the 'cryptography' package. Install with: "
            "pip install specora-verify[crypto]"
        ) from exc

    if not path.exists():
        raise OrchestrationError(f"Signing key file not found: {path}")

    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace").strip()

    if text.startswith("-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except Exception as exc:
            raise OrchestrationError(f"Failed to load PEM private key: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise OrchestrationError(
                f"Expected Ed25519 private key, got {type(key).__name__}"
            )
        return key

    hex_candidate = text.replace("\n", "").replace(" ", "")
    if len(hex_candidate) == 64 and all(c in "0123456789abcdefABCDEF" for c in hex_candidate):
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_candidate))

    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)

    raise OrchestrationError(
        "Unrecognized signing key format. Expected 64-char hex, raw 32 bytes, "
        "or unencrypted PEM PRIVATE KEY."
    )


def _read_provider(
    provider: str,
    *,
    input_path: Path,
    key_id: str,
    public_key_path: Path | None,
    schema_version: str | None,
    strict: bool,
) -> ReadResult:
    if provider not in available_readers():
        raise OrchestrationError(
            f"Unknown provider '{provider}'. Available: {available_readers()}"
        )
    try:
        reader_impl = get_reader(provider)
        return reader_impl.read(
            input_path=input_path,
            key_id=key_id,
            public_key_path=public_key_path,
            schema_version=schema_version,
            strict=strict,
        )
    except ReaderError:
        raise
    except Exception as exc:
        raise OrchestrationError(f"Reader '{provider}' failed: {exc}") from exc


def _sign_payload(payload: dict, signing_key: Any) -> tuple[str, str, str]:
    """Sign a canonical bundle payload.

    Returns a 3-tuple ``(payload_sha256, signature_b64, public_key_hex)``.
    The signature is computed over the UTF-8 bytes of the hex hash — this
    matches the verify-side contract in ``specora_verify.signature``::

        message_bytes = manifest_hash.encode("utf-8")
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    payload_sha256 = compute_manifest_hash(payload)
    signature_bytes = signing_key.sign(payload_sha256.encode("utf-8"))
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    public_key = signing_key.public_key()
    raw_pub = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    # Emit as base64 — that is the shape ``load_public_key`` in the
    # verifier auto-detects for non-PEM, non-32-byte-raw input. Hex would
    # be mis-parsed as base64 (64 chars decodes to 48 bytes, not 32).
    public_key_b64 = base64.b64encode(raw_pub).decode("ascii")

    return payload_sha256, signature_b64, public_key_b64


def run_pipeline(
    *,
    provider: str,
    input_path: Path,
    key_id: str,
    private_key_path: Path,
    out_dir: Path,
    public_key_path: Path | None = None,
    schema_version: str | None = None,
    strict: bool = True,
) -> RunResult:
    """Run the full out-of-band verification pipeline.

    Steps:
      1. Dispatch to the registered provider reader → canonical bundle
         payload (dict).
      2. Sign ``compute_manifest_hash(payload).encode("utf-8")`` with the
         supplied Ed25519 private key.
      3. Write ``payload.json``, ``payload.sig``, ``signing-key.pub``,
         and ``metadata.json`` into ``out_dir``.

    The returned :class:`RunResult` carries the on-disk paths so the
    caller (CLI, e2e test, tutorial) can immediately invoke
    ``specora-verify verify`` against them.

    Raises:
        OrchestrationError: on orchestration-layer failure.
        ReaderError: on provider-reader failure (passed through).
    """
    signing_key = load_signing_key(private_key_path)

    result = _read_provider(
        provider,
        input_path=input_path,
        key_id=key_id,
        public_key_path=public_key_path,
        schema_version=schema_version,
        strict=strict,
    )

    payload = result.bundle_payload
    payload_sha256, signature_b64, public_key_b64 = _sign_payload(payload, signing_key)

    out_dir.mkdir(parents=True, exist_ok=True)
    payload_path = out_dir / "payload.json"
    signature_path = out_dir / "payload.sig"
    public_key_path_out = out_dir / "signing-key.pub"
    metadata_path = out_dir / "metadata.json"

    payload_path.write_text(canonical_json_str(payload) + "\n", encoding="utf-8")
    signature_path.write_text(signature_b64 + "\n", encoding="utf-8")
    public_key_path_out.write_text(public_key_b64 + "\n", encoding="utf-8")

    metadata = {
        "provider": result.provider,
        "key_id": key_id,
        "schema_version": result.schema_version,
        "record_count": result.record_count,
        "upstream_key_id": result.upstream_key_id,
        "warnings": list(result.warnings),
        "payload_sha256": payload_sha256,
        "pipeline": "specora-verify run / EPIC-B03",
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return RunResult(
        bundle_dir=out_dir,
        payload_path=payload_path,
        signature_path=signature_path,
        public_key_path=public_key_path_out,
        metadata_path=metadata_path,
        provider=result.provider,
        record_count=result.record_count,
        payload_sha256=payload_sha256,
        warnings=tuple(result.warnings),
    )
