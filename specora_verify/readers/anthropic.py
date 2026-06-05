"""Anthropic Claude Enterprise Compliance API reader.

Ingests a JSONL export from the Anthropic Compliance API (one JSON object
per line, each representing one Claude inference call subject to the
customer's Compliance API configuration) and maps each record onto the
Specora wire-spec evidence-bundle shape.

The reader never talks to Anthropic's API directly — it consumes a file
the customer has already exported with their Anthropic Enterprise
credentials. This preserves the offline-verifier posture of
`specora-verify`.

Upstream schema reference: Anthropic Claude Enterprise Compliance API,
schema version "1.0". Field names follow Anthropic's public documentation
as observed 2026-Q1; if Anthropic revs the schema, add the new version to
`supported_schema_versions` and branch on it inside `_map_record`.

Schema mapping (upstream → Specora wire spec):

    record_id         → bundle.records[].id
    timestamp         → bundle.records[].timestamp          (RFC 3339 UTC "Z")
    request_id        → bundle.records[].upstream_request_id
    model             → bundle.records[].model.name
    model_version     → bundle.records[].model.version
    decision          → bundle.records[].decision.outcome   (enum-validated)
    policy_refs       → bundle.records[].decision.policy_refs
    context_hash      → bundle.records[].context.hash       ("sha256:..." validated)
    signature.*       → bundle.records[].upstream_signature.*
    schema_version    → bundle.metadata.upstream_schema_version
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import (
    ReaderCryptoError,
    ReaderIOError,
    ReaderSchemaError,
)
from specora_verify.hash import sha256_hex
from specora_verify.readers import ReadResult, reader

_SUPPORTED_VERSIONS: tuple[str, ...] = ("1.0",)
_VALID_DECISIONS = frozenset({"approved", "rejected", "deferred", "escalated"})
_REQUIRED_RECORD_FIELDS = (
    "record_id",
    "timestamp",
    "request_id",
    "model",
    "model_version",
    "decision",
    "policy_refs",
    "context_hash",
    "schema_version",
)
_PROVIDER = "anthropic"


@dataclass
class _RecordOutcome:
    """Internal result of mapping one upstream line.

    mapped is the Specora-wire-spec record if the line parsed, or None
    if it was dropped in non-strict mode. warning is a human-readable
    diagnostic for non-strict dropped records, or None on success.
    """

    mapped: dict[str, Any] | None
    warning: str | None


@reader(_PROVIDER)
class AnthropicReader:
    """Anthropic Claude Enterprise Compliance API reader."""

    provider_name: str = _PROVIDER
    provider_description: str = (
        "Anthropic Claude Enterprise Compliance API JSONL export reader. "
        "Ingests per-inference decision records and produces a Specora "
        "wire-spec evidence bundle. Offline, no network calls."
    )
    supported_schema_versions: tuple[str, ...] = _SUPPORTED_VERSIONS

    def read(
        self,
        input_path: Path,
        *,
        key_id: str,
        public_key_path: Path | None = None,
        schema_version: str | None = None,
        strict: bool = True,
    ) -> ReadResult:
        """Ingest an Anthropic Compliance API JSONL export.

        Args:
            input_path: Path to a JSONL export file (one record per line).
            key_id: Specora signing key ID to associate with the bundle.
            public_key_path: Optional Ed25519 public key for verifying the
                upstream per-record signatures. If provided, every record's
                `signature.value` is verified against it; a failure raises
                ReaderCryptoError in strict mode or emits a warning and
                drops the record in non-strict mode.
            schema_version: Optional override for the expected upstream
                schema version. If None, each record's declared
                `schema_version` is used directly.
            strict: If True, the first malformed record fails the whole
                read. If False, malformed records are dropped and recorded
                in ReadResult.warnings.

        Returns:
            ReadResult with a canonical wire-spec bundle payload.

        Raises:
            ReaderIOError: input file missing or unreadable.
            ReaderSchemaError: schema mismatch (strict mode only).
            ReaderCryptoError: upstream signature verification failed
                (strict mode only, and only when public_key_path is set).
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise ReaderIOError(str(input_path), "file not found")
        try:
            raw = input_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReaderIOError(str(input_path), f"read failed: {exc}") from exc

        public_key_bytes = self._load_public_key(public_key_path) if public_key_path else None

        mapped_records: list[dict[str, Any]] = []
        warnings: list[str] = []
        seen_ids: set[str] = set()
        upstream_key_id: str | None = None
        observed_schema_version: str | None = None

        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            outcome = self._map_line(
                line,
                lineno=lineno,
                strict=strict,
                seen_ids=seen_ids,
                public_key_bytes=public_key_bytes,
                forced_schema_version=schema_version,
            )
            if outcome.warning is not None:
                warnings.append(outcome.warning)
            if outcome.mapped is not None:
                record = outcome.mapped
                mapped_records.append(record)
                if observed_schema_version is None:
                    observed_schema_version = record["_schema_version"]
                if upstream_key_id is None:
                    sig = record.get("upstream_signature")
                    if isinstance(sig, dict):
                        upstream_key_id = sig.get("key_id")

        # Strip internal bookkeeping fields before emission.
        for record in mapped_records:
            record.pop("_schema_version", None)

        effective_schema_version = observed_schema_version or (
            schema_version or _SUPPORTED_VERSIONS[-1]
        )

        bundle_payload = self._build_bundle_payload(
            records=mapped_records,
            key_id=key_id,
            schema_version=effective_schema_version,
        )

        return ReadResult(
            provider=_PROVIDER,
            schema_version=effective_schema_version,
            record_count=len(mapped_records),
            bundle_payload=bundle_payload,
            upstream_key_id=upstream_key_id,
            warnings=tuple(warnings),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _map_line(
        self,
        line: str,
        *,
        lineno: int,
        strict: bool,
        seen_ids: set[str],
        public_key_bytes: bytes | None,
        forced_schema_version: str | None,
    ) -> _RecordOutcome:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            if strict:
                raise ReaderSchemaError(_PROVIDER, f"invalid JSON: {exc.msg}", line=lineno) from exc
            return _RecordOutcome(mapped=None, warning=f"line {lineno}: invalid JSON ({exc.msg})")

        if not isinstance(record, dict):
            if strict:
                raise ReaderSchemaError(_PROVIDER, "record is not a JSON object", line=lineno)
            return _RecordOutcome(
                mapped=None, warning=f"line {lineno}: record is not a JSON object"
            )

        try:
            self._validate_record_shape(record, lineno=lineno)
        except ReaderSchemaError as exc:
            if strict:
                raise
            return _RecordOutcome(mapped=None, warning=f"line {lineno}: {exc.detail}")

        version = forced_schema_version or record["schema_version"]
        if version not in _SUPPORTED_VERSIONS:
            if strict:
                raise ReaderSchemaError(
                    _PROVIDER,
                    f"unsupported schema_version {version!r} (supported: {_SUPPORTED_VERSIONS})",
                    line=lineno,
                )
            return _RecordOutcome(
                mapped=None,
                warning=f"line {lineno}: unsupported schema_version {version!r}",
            )

        record_id = record["record_id"]
        if record_id in seen_ids:
            return _RecordOutcome(
                mapped=None,
                warning=f"line {lineno}: duplicate record_id {record_id!r} (first occurrence wins)",
            )
        seen_ids.add(record_id)

        try:
            mapped = self._map_record(record)
        except ReaderSchemaError as exc:
            if strict:
                exc.line = lineno
                raise
            return _RecordOutcome(mapped=None, warning=f"line {lineno}: {exc.detail}")

        signature = record.get("signature")
        if signature is None:
            if strict:
                raise ReaderSchemaError(_PROVIDER, "missing upstream signature", line=lineno)
            return _RecordOutcome(mapped=None, warning=f"line {lineno}: missing upstream signature")

        if public_key_bytes is not None:
            try:
                self._verify_upstream_signature(record, signature, public_key_bytes)
            except ReaderCryptoError as exc:
                if strict:
                    raise
                return _RecordOutcome(mapped=None, warning=f"line {lineno}: {exc.detail}")

        mapped["_schema_version"] = version
        return _RecordOutcome(mapped=mapped, warning=None)

    def _validate_record_shape(self, record: dict[str, Any], *, lineno: int) -> None:
        for field_name in _REQUIRED_RECORD_FIELDS:
            if field_name not in record:
                raise ReaderSchemaError(
                    _PROVIDER, f"missing required field {field_name!r}", line=lineno
                )
        if not isinstance(record["policy_refs"], list):
            raise ReaderSchemaError(_PROVIDER, "policy_refs must be a JSON array", line=lineno)

    def _map_record(self, record: dict[str, Any]) -> dict[str, Any]:
        decision = record["decision"]
        if decision not in _VALID_DECISIONS:
            raise ReaderSchemaError(
                _PROVIDER,
                f"invalid decision outcome {decision!r} "
                f"(expected one of {sorted(_VALID_DECISIONS)})",
            )

        context_hash = record["context_hash"]
        if not isinstance(context_hash, str) or not context_hash.startswith("sha256:"):
            raise ReaderSchemaError(
                _PROVIDER,
                f"context_hash must start with 'sha256:' (got {context_hash!r})",
            )

        timestamp = self._normalize_timestamp(record["timestamp"])

        signature = record.get("signature") or {}
        upstream_signature: dict[str, Any] = {}
        if signature:
            alg = signature.get("alg", "")
            if alg and alg != "ed25519":
                raise ReaderSchemaError(
                    _PROVIDER,
                    f"upstream signature alg must be ed25519 (got {alg!r})",
                )
            upstream_signature = {
                "alg": alg or "ed25519",
                "key_id": signature.get("key_id", ""),
                "value": signature.get("value", ""),
            }

        mapped: dict[str, Any] = {
            "id": record["record_id"],
            "timestamp": timestamp,
            "upstream_request_id": record["request_id"],
            "model": {
                "name": record["model"],
                "version": record["model_version"],
            },
            "decision": {
                "outcome": decision,
                "policy_refs": list(record["policy_refs"]),
            },
            "context": {"hash": context_hash},
            "upstream_signature": upstream_signature,
        }
        tool_invocations = record.get("tool_invocations")
        if isinstance(tool_invocations, list) and tool_invocations:
            mapped["tool_invocations"] = tool_invocations

        # AID-940: agent identity pass-through (Wire Spec v1.1).
        # Anthropic's Compliance API does not natively surface the
        # Specora agent-identity claim, so the SDK-side path embeds the
        # cert envelope under either:
        #   * record["agent_identity"] — direct embedding by the
        #     SDK-instrumented agent runtime
        #   * record["request_metadata"]["x-specora-agent-identity"] —
        #     header-style propagation via the request envelope
        # The reader lifts whichever is present without inspection
        # (validation is the verifier's job, not the reader's). Absent
        # claims pass through silently — the v1.1 envelope is OPTIONAL.
        # Doctrine: this reader NEVER fabricates an identity claim. If
        # the upstream record has no claim, the bundle has no claim.
        identity = self._extract_agent_identity(record)
        if identity is not None:
            mapped["agent_identity"] = identity

        return mapped

    @staticmethod
    def _extract_agent_identity(record: dict[str, Any]) -> dict[str, Any] | None:
        """Lift any embedded Specora agent_identity envelope.

        Two sources are accepted, in priority order:

        1. ``record["agent_identity"]`` — the SDK-direct path. When the
           agent uses :func:`specora.agent_identity.sign_action` the SDK
           emits the cert envelope onto the upstream request body, the
           Anthropic Compliance API mirrors it back, and it appears
           here.
        2. ``record["request_metadata"]["x-specora-agent-identity"]`` —
           the header-propagated path. Used by agents that prefer to
           keep the body untouched and inject the envelope as a
           propagated header instead.

        The reader returns the envelope as-is — no validation, no
        normalization — so that the verifier's validate_bundle_v1_1
        sees byte-identical input to what the agent runtime signed.
        """
        direct = record.get("agent_identity")
        if isinstance(direct, dict):
            return direct
        request_metadata = record.get("request_metadata")
        if isinstance(request_metadata, dict):
            header_identity = request_metadata.get("x-specora-agent-identity")
            if isinstance(header_identity, dict):
                return header_identity
        return None

    @staticmethod
    def _normalize_timestamp(value: Any) -> str:
        if not isinstance(value, str):
            raise ReaderSchemaError(
                _PROVIDER, f"timestamp must be a string (got {type(value).__name__})"
            )
        if value.endswith("Z"):
            return value
        if value.endswith("+00:00"):
            return value[: -len("+00:00")] + "Z"
        raise ReaderSchemaError(
            _PROVIDER,
            f"timestamp must be RFC 3339 UTC with 'Z' or '+00:00' suffix (got {value!r})",
        )

    def _verify_upstream_signature(
        self, record: dict[str, Any], signature: dict[str, Any], public_key_bytes: bytes
    ) -> None:
        """Best-effort upstream Ed25519 signature check.

        If PyNaCl is not installed, we do not block — the reader still
        preserves the signature verbatim in the mapped record, and the
        Specora bundle wraps it in a second signature tier that the
        verifier checks offline. We only raise ReaderCryptoError when we
        have the capability AND the check fails.
        """
        try:
            from nacl.exceptions import BadSignatureError
            from nacl.signing import VerifyKey
        except ImportError:
            return

        sig_value = signature.get("value")
        if not isinstance(sig_value, str) or not sig_value:
            raise ReaderCryptoError(_PROVIDER, "upstream signature value is empty")

        payload_copy = {k: v for k, v in record.items() if k != "signature"}
        message = canonical_json_bytes(payload_copy)

        try:
            import base64

            sig_bytes = base64.b64decode(sig_value, validate=True)
        except (ValueError, TypeError) as exc:
            raise ReaderCryptoError(
                _PROVIDER, f"upstream signature is not valid base64: {exc}"
            ) from exc

        try:
            VerifyKey(public_key_bytes).verify(message, sig_bytes)
        except BadSignatureError as exc:
            raise ReaderCryptoError(
                _PROVIDER,
                f"upstream signature did not verify against the provided public key "
                f"(record_id={record.get('record_id')!r})",
            ) from exc

    @staticmethod
    def _load_public_key(path: Path) -> bytes:
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise ReaderIOError(str(path), f"public key read failed: {exc}") from exc
        # Accept either raw 32-byte Ed25519 keys or hex-encoded 64-char strings.
        if len(raw) == 32:
            return raw
        stripped = raw.strip()
        try:
            decoded = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReaderCryptoError(
                _PROVIDER,
                f"public key at {path} is neither 32 raw bytes nor hex-encoded",
            ) from exc
        if len(decoded) != 32:
            raise ReaderCryptoError(
                _PROVIDER,
                f"public key at {path} decoded to {len(decoded)} bytes (expected 32)",
            )
        return decoded

    @staticmethod
    def _build_bundle_payload(
        *, records: list[dict[str, Any]], key_id: str, schema_version: str
    ) -> dict[str, Any]:
        """Assemble the canonical wire-spec bundle payload.

        The returned dict is round-tripped through canonical_json_bytes
        below to compute a stable content hash; that hash is the anchor
        the outer signature covers.
        """
        payload: dict[str, Any] = {
            "metadata": {
                "provider": _PROVIDER,
                "reader": "specora_verify.readers.anthropic",
                "reader_version": "1.0.0",
                "key_id": key_id,
                "upstream_schema_version": schema_version,
                "record_count": len(records),
            },
            "records": records,
        }
        payload["metadata"]["content_hash"] = "sha256:" + sha256_hex(
            canonical_json_bytes({"records": records})
        )
        return payload
