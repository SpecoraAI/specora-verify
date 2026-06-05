"""Azure Confidential Ledger reader.

Ingests a combined **entries-with-receipt** JSON export from Azure
Confidential Ledger — one entry per AI decision record written to the
customer's ledger collection, each carrying the Confidential Ledger
``receipt`` block the service emitted at write time (Merkle inclusion
proof, consortium signature, and optional SGX/TDX enclave quote). The
reader maps each entry onto the Specora wire-spec evidence-bundle
shape and preserves the cryptographic proof material verbatim so an
auditor can independently re-walk the inclusion path.

The reader is **TEE-attestation-first**: when a receipt carries an
enclave quote it is extracted into a record-level ``tee_attestation``
field, mirroring the way the CloudTrail reader positions Bedrock AR
Checks as its first-class evidence payload. This is the strategic
pre-emption against Microsoft owning the verifiable-enclave-evidence
story for Azure OpenAI + Confidential Ledger.

The reader never talks to Azure directly — it only reads a file the
customer has already exported with their own Azure credentials. This
preserves the offline-verifier posture of ``specora-verify``.

Upstream integrity model. Azure Confidential Ledger receipts are
signed by the consortium service identity (ECDSA P-384), not by an
ed25519 per-record content key. The reader therefore sets
``upstream_signature`` on each mapped record to a descriptor dict

    {
        "absent_per_record": true,
        "integrity_mechanism": "azure-confidential-ledger-receipt",
    }

and stashes the actual cryptographic proof in a sibling
``upstream_inclusion_proof`` record field so nothing is lost.

Upstream schema reference: Azure Confidential Ledger transaction /
receipt API shape. The customer ledger payload inside ``contents`` is
customer-defined; the reader enforces a minimum required subset
(timestamp, model, decision, policy_refs, context_hash) and preserves
any additional fields as-is via ``additionalProperties`` on the
canonical-bundle record schema.

Schema mapping (upstream → Specora wire spec):

    transactionId                       → records[].upstream_tx_id
    collectionId                        → records[].upstream_collection_id
    contents.record.record_id           → records[].id
    contents.record.timestamp           → records[].timestamp (RFC 3339 UTC "Z")
    contents.record.request_id          → records[].upstream_request_id
    contents.record.model               → records[].model.name
    contents.record.model_version       → records[].model.version
    contents.record.decision            → records[].decision.outcome
    contents.record.policy_refs         → records[].decision.policy_refs
    contents.record.context_hash        → records[].context.hash
    receipt.{leafComponents,nodeCerts,
             proof,signature,serviceId} → records[].upstream_inclusion_proof
    receipt.enclaveQuote (+ mrenclave,
             mrsigner, reportData)      → records[].tee_attestation
    (reader)                            → metadata.upstream_schema_version = "1.0"
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import ReaderIOError, ReaderSchemaError
from specora_verify.hash import sha256_hex
from specora_verify.readers import ReadResult, reader

_SUPPORTED_VERSIONS: tuple[str, ...] = ("1.0",)
_VALID_DECISIONS = frozenset({"approved", "rejected", "deferred", "escalated"})
_PROVIDER = "azure-cl"
_REQUIRED_RECORD_FIELDS = (
    "record_id",
    "timestamp",
    "model",
    "model_version",
    "decision",
    "policy_refs",
    "context_hash",
)
_REQUIRED_RECEIPT_FIELDS = ("leafComponents", "nodeCerts", "proof", "signature")


@dataclass
class _EntryOutcome:
    mapped: dict[str, Any] | None
    warning: str | None


@reader(_PROVIDER)
class AzureConfidentialLedgerReader:
    """Azure Confidential Ledger (entries + receipts) reader."""

    provider_name: str = _PROVIDER
    provider_description: str = (
        "Azure Confidential Ledger entries-with-receipts reader. Ingests a "
        "JSON export ({'entries': [{contents, receipt}, ...]}) and produces "
        "a Specora wire-spec evidence bundle. TEE enclave quotes are "
        "extracted as first-class evidence. Offline, no network calls."
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
        """Ingest an Azure Confidential Ledger JSON export.

        Args:
            input_path: Path to a JSON file with a top-level ``entries``
                array. A bare single-entry JSON object is also accepted
                and treated as a one-element archive.
            key_id: Specora signing key ID to associate with the bundle.
            public_key_path: Accepted for interface symmetry with other
                readers but ignored — Confidential Ledger receipts are
                consortium-signed via ECDSA P-384, not ed25519. A warning
                is surfaced in ``ReadResult.warnings`` when this is set,
                matching the CloudTrail session 1 advisory-fix pattern.
            schema_version: Optional override for the reader-side
                Azure-CL schema version. Must be in
                ``supported_schema_versions`` if set.
            strict: If True, the first malformed entry fails the read.
                If False, malformed entries are dropped with warnings.

        Returns:
            ReadResult with a canonical wire-spec bundle payload.

        Raises:
            ReaderIOError: input file missing or unreadable.
            ReaderSchemaError: schema mismatch (strict mode only).
        """
        public_key_notice: str | None = None
        if public_key_path is not None:
            public_key_notice = (
                f"--public-key {public_key_path!s} was provided but is ignored: "
                "Azure Confidential Ledger receipts are consortium-signed "
                "(ECDSA P-384), not ed25519 per-record. The full inclusion "
                "proof and signature are preserved under "
                "records[].upstream_inclusion_proof. See docs/readers/azure_cl.md §1."
            )

        input_path = Path(input_path)
        if not input_path.exists():
            raise ReaderIOError(str(input_path), "file not found")
        try:
            raw = input_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReaderIOError(str(input_path), f"read failed: {exc}") from exc

        try:
            parsed = json.loads(raw) if raw.strip() else {"entries": []}
        except json.JSONDecodeError as exc:
            raise ReaderSchemaError(_PROVIDER, f"input is not valid JSON: {exc.msg}") from exc

        entries_in = self._extract_entries(parsed)

        effective_schema_version = schema_version or _SUPPORTED_VERSIONS[-1]
        if effective_schema_version not in _SUPPORTED_VERSIONS:
            raise ReaderSchemaError(
                _PROVIDER,
                f"unsupported schema_version {effective_schema_version!r} "
                f"(supported: {_SUPPORTED_VERSIONS})",
            )

        mapped_records: list[dict[str, Any]] = []
        warnings: list[str] = []
        seen_ids: set[str] = set()
        first_collection_id: str | None = None

        for index, entry in enumerate(entries_in):
            outcome = self._map_entry(
                entry,
                index=index,
                strict=strict,
                seen_ids=seen_ids,
            )
            if outcome.warning is not None:
                warnings.append(outcome.warning)
            if outcome.mapped is not None:
                entry_collection = outcome.mapped.get("upstream_collection_id")
                if first_collection_id is None:
                    first_collection_id = entry_collection
                elif entry_collection and entry_collection != first_collection_id:
                    warnings.append(
                        f"record[{index}]: collectionId "
                        f"{entry_collection!r} differs from first-seen "
                        f"{first_collection_id!r}"
                    )
                mapped_records.append(outcome.mapped)

        if public_key_notice is not None:
            warnings.append(public_key_notice)

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
            upstream_key_id=None,
            warnings=tuple(warnings),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_entries(parsed: Any) -> list[dict[str, Any]]:
        if isinstance(parsed, dict) and "entries" in parsed:
            entries = parsed["entries"]
            if not isinstance(entries, list):
                raise ReaderSchemaError(_PROVIDER, "'entries' must be a JSON array")
            return entries
        # Bare single-entry shape — treat as a one-element archive.
        if isinstance(parsed, dict) and "contents" in parsed and "receipt" in parsed:
            return [parsed]
        raise ReaderSchemaError(
            _PROVIDER,
            "input must be a JSON object with a top-level 'entries' array "
            "(Azure Confidential Ledger entries-with-receipts export shape) "
            "or a single entry dict with 'contents' and 'receipt' keys",
        )

    def _map_entry(
        self,
        entry: Any,
        *,
        index: int,
        strict: bool,
        seen_ids: set[str],
    ) -> _EntryOutcome:
        location = f"record[{index}]"
        if not isinstance(entry, dict):
            if strict:
                raise ReaderSchemaError(_PROVIDER, f"{location} is not a JSON object")
            return _EntryOutcome(mapped=None, warning=f"{location}: not a JSON object")

        try:
            mapped = self._map_entry_strict(entry)
        except ReaderSchemaError as exc:
            if strict:
                raise
            return _EntryOutcome(mapped=None, warning=f"{location}: {exc.detail}")

        record_id = mapped["id"]
        if record_id in seen_ids:
            return _EntryOutcome(
                mapped=None,
                warning=(f"{location}: duplicate record_id {record_id!r} (first occurrence wins)"),
            )
        seen_ids.add(record_id)
        return _EntryOutcome(mapped=mapped, warning=None)

    def _map_entry_strict(self, entry: dict[str, Any]) -> dict[str, Any]:
        tx_id = entry.get("transactionId")
        if not isinstance(tx_id, str) or not tx_id:
            raise ReaderSchemaError(_PROVIDER, "transactionId must be a non-empty string")

        contents = entry.get("contents")
        if not isinstance(contents, dict):
            raise ReaderSchemaError(_PROVIDER, "contents must be a JSON object")
        record = contents.get("record")
        if not isinstance(record, dict):
            raise ReaderSchemaError(_PROVIDER, "contents.record must be a JSON object")

        for field_name in _REQUIRED_RECORD_FIELDS:
            if field_name not in record:
                raise ReaderSchemaError(
                    _PROVIDER,
                    f"contents.record missing required field {field_name!r}",
                )
        if not isinstance(record["policy_refs"], list):
            raise ReaderSchemaError(_PROVIDER, "contents.record.policy_refs must be a JSON array")

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
                f"contents.record.context_hash must start with 'sha256:' (got {context_hash!r})",
            )

        timestamp = self._normalize_timestamp(record["timestamp"])

        receipt = entry.get("receipt")
        if not isinstance(receipt, dict):
            raise ReaderSchemaError(
                _PROVIDER,
                "receipt must be a JSON object — the whole point of "
                "Confidential Ledger is the receipt, a record without "
                "one is not verifiable",
            )
        for field_name in _REQUIRED_RECEIPT_FIELDS:
            if field_name not in receipt:
                raise ReaderSchemaError(
                    _PROVIDER,
                    f"receipt missing required field {field_name!r}",
                )
        if not isinstance(receipt["nodeCerts"], list):
            raise ReaderSchemaError(_PROVIDER, "receipt.nodeCerts must be a JSON array")
        if not isinstance(receipt["proof"], list):
            raise ReaderSchemaError(_PROVIDER, "receipt.proof must be a JSON array")

        inclusion_proof: dict[str, Any] = {
            "leafComponents": receipt["leafComponents"],
            "nodeCerts": list(receipt["nodeCerts"]),
            "proof": list(receipt["proof"]),
            "signature": receipt["signature"],
        }
        if "serviceId" in receipt:
            inclusion_proof["serviceId"] = receipt["serviceId"]

        tee_attestation: dict[str, Any] | None = None
        if "enclaveQuote" in receipt:
            quote = receipt["enclaveQuote"]
            if not isinstance(quote, str) or not quote:
                raise ReaderSchemaError(
                    _PROVIDER,
                    "receipt.enclaveQuote must be a non-empty string (base64 SGX/TDX quote)",
                )
            tee_attestation = {"enclaveQuote": quote}
            for optional_field in ("mrenclave", "mrsigner", "reportData"):
                if optional_field in receipt:
                    tee_attestation[optional_field] = receipt[optional_field]

        mapped: dict[str, Any] = {
            "id": str(record["record_id"]),
            "timestamp": timestamp,
            "upstream_tx_id": tx_id,
            "model": {
                "name": record["model"],
                "version": record["model_version"],
            },
            "decision": {
                "outcome": decision,
                "policy_refs": list(record["policy_refs"]),
            },
            "context": {"hash": context_hash},
            "upstream_signature": {
                "absent_per_record": True,
                "integrity_mechanism": "azure-confidential-ledger-receipt",
            },
            "upstream_inclusion_proof": inclusion_proof,
        }
        if tee_attestation is not None:
            mapped["tee_attestation"] = tee_attestation

        request_id = record.get("request_id")
        if isinstance(request_id, str) and request_id:
            mapped["upstream_request_id"] = request_id

        collection_id = entry.get("collectionId")
        if isinstance(collection_id, str) and collection_id:
            mapped["upstream_collection_id"] = collection_id
        return mapped

    @staticmethod
    def _normalize_timestamp(value: Any) -> str:
        if not isinstance(value, str):
            raise ReaderSchemaError(
                _PROVIDER,
                f"timestamp must be a string (got {type(value).__name__})",
            )
        if value.endswith("Z"):
            return value
        if value.endswith("+00:00"):
            return value[: -len("+00:00")] + "Z"
        raise ReaderSchemaError(
            _PROVIDER,
            f"timestamp must be RFC 3339 UTC with 'Z' or '+00:00' suffix (got {value!r})",
        )

    @staticmethod
    def _build_bundle_payload(
        *, records: list[dict[str, Any]], key_id: str, schema_version: str
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "metadata": {
                "provider": _PROVIDER,
                "reader": "specora_verify.readers.azure_cl",
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


__all__ = ["AzureConfidentialLedgerReader"]
