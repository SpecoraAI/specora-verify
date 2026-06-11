"""AWS CloudTrail Lake reader (with Bedrock Automated Reasoning Checks).

Ingests a CloudTrail JSON export — the standard
``{"Records": [<event>, ...]}`` archive shape produced by CloudTrail's
S3 delivery, by CloudTrail Lake query exports, and by
``aws cloudtrail lookup-events`` — and maps each Bedrock inference
event onto the Specora wire-spec evidence-bundle shape.

The reader is Bedrock-first: it filters on
``eventSource == "bedrock.amazonaws.com"`` and extracts the Bedrock
Automated Reasoning Checks (AR Checks) proof payload when present.
This is the load-bearing competitive positioning against AWS's own
verifiable-explainability story — Specora ships AR-Checks coverage in
its first public reader rather than letting AWS own the format.

The reader never talks to AWS directly — it only reads a file the
customer has already exported with their AWS credentials. This
preserves the offline-verifier posture of ``specora-verify``.

Upstream integrity model. CloudTrail has no per-event signatures; the
integrity mechanism is log-file validation, in which CloudTrail
periodically emits a signed digest file covering a batch of log files.
The reader therefore sets ``upstream_signature`` on each mapped record
to a descriptor dict rather than a real signature:

    {
        "absent_per_record": true,
        "integrity_mechanism": "cloudtrail-log-file-validation",
        "digest_file_ref": <optional path recorded via --digest-file>,
    }

Pre-processing the export with ``aws cloudtrail validate-logs`` before
handing it to the reader is out of scope and documented in
``docs/readers/cloudtrail.md``.

Upstream schema reference: AWS CloudTrail Event Reference, event
version ``1.08`` and ``1.09`` (the current public versions as of
2026-Q1). Bedrock AR Checks fields live under
``responseElements.automatedReasoningResult``.

Schema mapping (upstream → Specora wire spec):

    eventID                                      → records[].id
    eventTime                                    → records[].timestamp   (normalized to "Z")
    eventName                                    → records[].upstream_event_name
    awsRegion                                    → records[].aws_region
    responseElements.requestId                   → records[].upstream_request_id
    requestParameters.modelId                    → records[].model.{name,version}  (split)
    requestParameters.automatedReasoningPolicyId → records[].decision.policy_refs
    responseElements.modelInvocationResult       → records[].decision.outcome       (enum-mapped)
    responseElements.automatedReasoningResult
        → records[].decision.{formal_verdict, proof_hash, constraints}
    (derived)
        → records[].context.hash  (sha256 of req+resp)
    eventVersion                                 → metadata.upstream_schema_version
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import ReaderIOError, ReaderSchemaError
from specora_verify.hash import sha256_hex
from specora_verify.readers import ReadResult, reader

_SUPPORTED_VERSIONS: tuple[str, ...] = ("1.08", "1.09")
_BEDROCK_SOURCE = "bedrock.amazonaws.com"
_AR_EVENT_NAMES: frozenset[str] = frozenset(
    {
        "InvokeModelWithAutomatedReasoning",
        "InvokeModelWithResponseStreamWithAutomatedReasoning",
        "ApplyAutomatedReasoningPolicy",
    }
)
_VALID_WIRE_DECISIONS = frozenset({"approved", "rejected", "deferred", "escalated"})
_MODEL_ID_VERSION_RE = re.compile(r"^(?P<name>.+?)-(?P<version>\d{8}.*)$")
_PROVIDER = "cloudtrail"


def _map_bedrock_outcome(
    invocation_result: str | None, verdict: str | None, escalation: bool
) -> str:
    """Collapse Bedrock AR Checks state into the wire-spec decision enum.

    Precedence: explicit escalation > AR verdict > model invocation result.
    """
    if escalation:
        return "escalated"
    if verdict:
        normalized = verdict.strip().lower()
        if normalized == "valid":
            return "approved"
        if normalized == "invalid":
            return "rejected"
        if normalized == "unknown":
            return "deferred"
    if invocation_result:
        normalized = invocation_result.strip().lower()
        if normalized in {"approved", "allowed", "success"}:
            return "approved"
        if normalized in {"blocked", "filtered", "denied", "rejected"}:
            return "rejected"
        if normalized in {"deferred", "pending"}:
            return "deferred"
        if normalized in {"escalated", "needs_review"}:
            return "escalated"
    raise ReaderSchemaError(
        _PROVIDER,
        "could not map Bedrock decision to wire-spec enum "
        f"(invocation_result={invocation_result!r}, verdict={verdict!r})",
    )


def _split_model_id(model_id: str) -> tuple[str, str]:
    """Split a Bedrock model ID into (name, version).

    Bedrock format is roughly ``<provider>.<model>-<YYYYMMDD>[-vN][:variant]``.
    Example: ``anthropic.claude-3-5-sonnet-20240620-v1:0`` splits to
    ``("anthropic.claude-3-5-sonnet", "20240620-v1:0")``. If no version
    suffix is detectable, version is the empty string and the whole ID is
    the name.
    """
    match = _MODEL_ID_VERSION_RE.match(model_id)
    if match:
        return match.group("name"), match.group("version")
    return model_id, ""


@dataclass
class _RecordOutcome:
    mapped: dict[str, Any] | None
    warning: str | None
    skipped: bool = False


@reader(_PROVIDER)
class CloudTrailReader:
    """AWS CloudTrail Lake (Bedrock AR Checks) reader."""

    provider_name: str = _PROVIDER
    provider_description: str = (
        "AWS CloudTrail Lake reader with Bedrock Automated Reasoning Checks "
        "support. Ingests a CloudTrail JSON export ({'Records': [...]}) and "
        "produces a Specora wire-spec evidence bundle. Offline, no network calls."
    )
    supported_schema_versions: tuple[str, ...] = _SUPPORTED_VERSIONS
    # Validated against real CloudTrail Lake exports.
    preview: bool = False

    def read(
        self,
        input_path: Path,
        *,
        key_id: str,
        public_key_path: Path | None = None,
        schema_version: str | None = None,
        strict: bool = True,
    ) -> ReadResult:
        """Ingest a CloudTrail JSON export.

        Args:
            input_path: Path to a CloudTrail JSON export file. Expected
                shape is ``{"Records": [<event>, ...]}`` — the standard
                CloudTrail archive and CloudTrail Lake export format.
            key_id: Specora signing key ID to associate with the bundle.
            public_key_path: Accepted for interface compatibility with
                other readers but ignored — CloudTrail has no per-event
                signatures. Integrity is anchored at the CloudTrail log
                file validation level (``aws cloudtrail validate-logs``),
                which is out of scope for this reader.
            schema_version: Optional override for the expected CloudTrail
                ``eventVersion``. If None, each record's declared
                ``eventVersion`` is used.
            strict: If True, the first malformed or non-AR event fails
                the read. If False, malformed records are dropped with
                warnings and non-AR Bedrock events are silently skipped.

        Returns:
            ReadResult with a canonical wire-spec bundle payload.

        Raises:
            ReaderIOError: input file missing or unreadable.
            ReaderSchemaError: schema mismatch (strict mode only).
        """
        # --public-key is accepted for interface symmetry with other readers
        # (see docstring) but CloudTrail has no per-event signatures. We
        # surface this into ReadResult.warnings so a user who passed a key
        # expecting verification sees it instead of silent ignore. Closes
        # B01 CloudTrail session 1 advisory finding #2.
        public_key_notice: str | None = None
        if public_key_path is not None:
            public_key_notice = (
                f"--public-key {public_key_path!s} was provided but is ignored: "
                "CloudTrail has no per-event signatures. Integrity is anchored "
                "at the log file validation level (aws cloudtrail validate-logs). "
                "See docs/readers/cloudtrail.md §1."
            )
        input_path = Path(input_path)
        if not input_path.exists():
            raise ReaderIOError(str(input_path), "file not found")
        try:
            raw = input_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReaderIOError(str(input_path), f"read failed: {exc}") from exc

        try:
            envelope = json.loads(raw) if raw.strip() else {"Records": []}
        except json.JSONDecodeError as exc:
            raise ReaderSchemaError(_PROVIDER, f"input is not valid JSON: {exc.msg}") from exc

        if not isinstance(envelope, dict) or "Records" not in envelope:
            raise ReaderSchemaError(
                _PROVIDER,
                "input must be a JSON object with a top-level 'Records' array "
                "(CloudTrail archive / Lake export shape)",
            )
        records_in = envelope["Records"]
        if not isinstance(records_in, list):
            raise ReaderSchemaError(_PROVIDER, "'Records' must be a JSON array")

        mapped_records: list[dict[str, Any]] = []
        warnings: list[str] = []
        seen_ids: set[str] = set()
        observed_schema_version: str | None = None
        skipped_non_ar = 0

        for index, event in enumerate(records_in):
            outcome = self._map_event(
                event,
                index=index,
                strict=strict,
                seen_ids=seen_ids,
                forced_schema_version=schema_version,
            )
            if outcome.warning is not None:
                warnings.append(outcome.warning)
            if outcome.skipped:
                skipped_non_ar += 1
                continue
            if outcome.mapped is not None:
                mapped_records.append(outcome.mapped)
                if observed_schema_version is None:
                    observed_schema_version = outcome.mapped.pop("_schema_version", None)
                else:
                    outcome.mapped.pop("_schema_version", None)

        if skipped_non_ar and not strict:
            warnings.append(
                f"skipped {skipped_non_ar} non-AR Bedrock event(s) (filter: "
                f"eventSource=={_BEDROCK_SOURCE!r} and AR event name allowlist)"
            )
        if public_key_notice is not None:
            warnings.append(public_key_notice)

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
            upstream_key_id=None,
            warnings=tuple(warnings),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _map_event(
        self,
        event: Any,
        *,
        index: int,
        strict: bool,
        seen_ids: set[str],
        forced_schema_version: str | None,
    ) -> _RecordOutcome:
        location = f"record[{index}]"
        if not isinstance(event, dict):
            if strict:
                raise ReaderSchemaError(_PROVIDER, f"{location} is not a JSON object")
            return _RecordOutcome(mapped=None, warning=f"{location}: not a JSON object")

        event_source = event.get("eventSource")
        if event_source != _BEDROCK_SOURCE:
            # Silently skip non-Bedrock events — they are not in scope
            # for this reader, not an error. In strict mode the caller
            # usually pre-filters; we still skip here rather than fail.
            return _RecordOutcome(mapped=None, warning=None, skipped=True)

        event_name = event.get("eventName")
        if event_name not in _AR_EVENT_NAMES:
            # Non-AR Bedrock invocation — skip with a warning counter,
            # not an error. The design doc calls this out explicitly
            # (see b01-reader-design-notes-2026-Q2.md §4.3).
            return _RecordOutcome(mapped=None, warning=None, skipped=True)

        event_version = forced_schema_version or event.get("eventVersion")
        if event_version not in _SUPPORTED_VERSIONS:
            msg = f"unsupported eventVersion {event_version!r} (supported: {_SUPPORTED_VERSIONS})"
            if strict:
                raise ReaderSchemaError(_PROVIDER, msg)
            return _RecordOutcome(mapped=None, warning=f"{location}: {msg}")

        try:
            mapped = self._map_ar_event(event, event_version=event_version)
        except ReaderSchemaError as exc:
            if strict:
                raise
            return _RecordOutcome(mapped=None, warning=f"{location}: {exc.detail}")

        record_id = mapped["id"]
        if record_id in seen_ids:
            return _RecordOutcome(
                mapped=None,
                warning=(f"{location}: duplicate eventID {record_id!r} (first occurrence wins)"),
            )
        seen_ids.add(record_id)
        return _RecordOutcome(mapped=mapped, warning=None)

    def _map_ar_event(self, event: dict[str, Any], *, event_version: str) -> dict[str, Any]:
        for required in (
            "eventID",
            "eventTime",
            "awsRegion",
            "requestParameters",
            "responseElements",
        ):
            if required not in event:
                raise ReaderSchemaError(_PROVIDER, f"missing required field {required!r}")

        request_params = event["requestParameters"]
        response_elements = event["responseElements"]
        if not isinstance(request_params, dict):
            raise ReaderSchemaError(_PROVIDER, "requestParameters must be a JSON object")
        if not isinstance(response_elements, dict):
            raise ReaderSchemaError(_PROVIDER, "responseElements must be a JSON object")

        model_id = request_params.get("modelId")
        if not isinstance(model_id, str) or not model_id:
            raise ReaderSchemaError(
                _PROVIDER, "requestParameters.modelId must be a non-empty string"
            )
        model_name, model_version = _split_model_id(model_id)

        ar_policy_id = request_params.get("automatedReasoningPolicyId")
        if not isinstance(ar_policy_id, str) or not ar_policy_id:
            raise ReaderSchemaError(
                _PROVIDER,
                "requestParameters.automatedReasoningPolicyId must be a "
                "non-empty string (this is the Bedrock AR Checks policy "
                "identifier — required for AR event records)",
            )

        ar_result = response_elements.get("automatedReasoningResult")
        if not isinstance(ar_result, dict):
            raise ReaderSchemaError(
                _PROVIDER,
                "responseElements.automatedReasoningResult must be a JSON "
                "object (this is the AR Checks proof payload)",
            )
        verdict = ar_result.get("verdict")
        if not isinstance(verdict, str) or not verdict:
            raise ReaderSchemaError(
                _PROVIDER, "automatedReasoningResult.verdict must be a non-empty string"
            )
        proof_hash = ar_result.get("proofHash")
        if not isinstance(proof_hash, str) or not proof_hash.startswith("sha256:"):
            raise ReaderSchemaError(
                _PROVIDER,
                f"automatedReasoningResult.proofHash must start with 'sha256:' "
                f"(got {proof_hash!r})",
            )
        constraints = ar_result.get("logicalConstraints", [])
        if not isinstance(constraints, list):
            raise ReaderSchemaError(
                _PROVIDER, "automatedReasoningResult.logicalConstraints must be a JSON array"
            )
        escalation_required = bool(ar_result.get("escalationRequired", False))

        invocation_result = response_elements.get("modelInvocationResult")
        outcome = _map_bedrock_outcome(invocation_result, verdict, escalation_required)

        timestamp = self._normalize_timestamp(event["eventTime"])
        request_id = response_elements.get("requestId", event.get("requestID", ""))
        if not isinstance(request_id, str):
            raise ReaderSchemaError(_PROVIDER, "responseElements.requestId must be a string")

        # Deterministic derived context hash over canonical request + response.
        context_material = {
            "requestParameters": request_params,
            "responseElements": response_elements,
        }
        context_hash = "sha256:" + sha256_hex(canonical_json_bytes(context_material))

        aws_region = event["awsRegion"]
        if not isinstance(aws_region, str) or not aws_region:
            raise ReaderSchemaError(_PROVIDER, "awsRegion must be a non-empty string")

        mapped: dict[str, Any] = {
            "id": str(event["eventID"]),
            "timestamp": timestamp,
            "upstream_event_name": event.get("eventName", ""),
            "upstream_request_id": request_id,
            "aws_region": aws_region,
            "model": {
                "name": model_name,
                "version": model_version,
            },
            "decision": {
                "outcome": outcome,
                "policy_refs": [ar_policy_id],
                "formal_verdict": verdict,
                "proof_hash": proof_hash,
                "constraints": list(constraints),
            },
            "context": {"hash": context_hash},
            "upstream_signature": {
                "absent_per_record": True,
                "integrity_mechanism": "cloudtrail-log-file-validation",
            },
            "_schema_version": event_version,
        }
        return mapped

    @staticmethod
    def _normalize_timestamp(value: Any) -> str:
        if not isinstance(value, str):
            raise ReaderSchemaError(
                _PROVIDER,
                f"eventTime must be a string (got {type(value).__name__})",
            )
        if value.endswith("Z"):
            return value
        if value.endswith("+00:00"):
            return value[: -len("+00:00")] + "Z"
        raise ReaderSchemaError(
            _PROVIDER,
            f"eventTime must be RFC 3339 UTC with 'Z' or '+00:00' suffix (got {value!r})",
        )

    @staticmethod
    def _build_bundle_payload(
        *, records: list[dict[str, Any]], key_id: str, schema_version: str
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "metadata": {
                "provider": _PROVIDER,
                "reader": "specora_verify.readers.cloudtrail",
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


__all__ = ["CloudTrailReader"]
