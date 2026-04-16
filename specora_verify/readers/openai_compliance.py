"""OpenAI Compliance Platform reader.

Ingests a JSON export from the OpenAI Compliance Platform audit-log
surface (one event per authorized AI action evaluated against the
customer's compliance policies) and maps each event onto the Specora
wire-spec evidence-bundle shape.

The reader never talks to OpenAI directly — it only reads a file the
customer has already exported with their own OpenAI enterprise
credentials. This preserves the offline-verifier posture of
``specora-verify``.

Status — design-accurate, pending live-data validation.
===========================================================
As of the B01 session-3 landing (2026-04-15), the OpenAI Compliance
Platform audit-event shape is only available through the enterprise
admin console and a private preview API that is not yet in the public
OpenAI API Reference. The event shape implemented here is
**design-accurate** against what OpenAI has publicly described (at
DevDay 2025 and in the Enterprise Trust Portal docs) and matches the
standard OpenAI list-response envelope ``{"object": "list", "data":
[...], "has_more": bool}`` used across the rest of the public API.

When OpenAI publishes the canonical schema (or when Specora receives
sign-off to run against a real enterprise export), the reader's
``_REQUIRED_EVENT_FIELDS``, ``_EVENT_TYPE_PREFIX``, and the outcome
mapping in ``_map_outcome`` are the three points that will need to
be reconciled with production shape. The rest of the reader is
structural: envelope parsing, timestamp normalization, duplicate
detection, bundle assembly. See the B01 design notes §9.5 for the
reconciliation checklist.

First-class field decision: "authorized action" = ``decision.outcome``.
===================================================================
The strategic question every reader answers is: *what did the upstream
provider actually authorize?* For OpenAI Compliance Platform, the
equivalent of CloudTrail's Bedrock Automated Reasoning Checks result
and Azure Confidential Ledger's TEE quote is the
**moderation / policy-check outcome** that the compliance engine
produced for each inference call. The reader lifts this into three
places:

    * the standard ``decision.outcome`` wire-spec enum
      (``approved`` | ``rejected`` | ``deferred`` | ``escalated``)
    * the standard ``decision.policy_refs`` list (OpenAI
      ``policy_ids``)
    * a record-level ``upstream_moderation`` dict that preserves the
      raw OpenAI moderation block (``flagged``, ``categories``,
      ``category_scores``, and any OpenAI-native fields) verbatim so
      auditors can walk OpenAI's own evaluation independently.

Upstream integrity model. OpenAI Compliance Platform does NOT emit
per-event signatures today. Integrity is anchored at the transport
layer (TLS to ``api.openai.com``) and by the enterprise admin console's
tamper-evident audit log. The reader therefore sets
``upstream_signature`` on each mapped record to the canonical
"absent-per-record" descriptor:

    {
        "absent_per_record": true,
        "integrity_mechanism": "openai-compliance-api-tls-attested",
    }

which matches the CloudTrail and Azure CL conventions. The Specora
outer signature tier is what the verifier actually checks offline.

Schema mapping (upstream → Specora wire spec):

    id                           → records[].id
    effective_at                 → records[].timestamp
                                     (RFC 3339 UTC "Z", also accepts
                                      unix seconds and ISO with
                                      "+00:00")
    request_id                   → records[].upstream_request_id
    type                         → records[].upstream_event_type
    project_id                   → records[].upstream_project_id
    model                        → records[].model.{name,version}
                                     (split on the last "-YYYY-MM"
                                      suffix OpenAI uses)
    decision.outcome             → records[].decision.outcome
    decision.policy_ids          → records[].decision.policy_refs
    content_hash                 → records[].context.hash
    moderation.*                 → records[].upstream_moderation
    (reader-derived)             → metadata.upstream_schema_version =
                                    "openai-compliance-v1-preview"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from specora_verify.canonical import canonical_json_bytes
from specora_verify.errors import ReaderIOError, ReaderSchemaError
from specora_verify.hash import sha256_hex
from specora_verify.readers import ReadResult, reader

_PROVIDER = "openai"
_SUPPORTED_VERSIONS: tuple[str, ...] = ("openai-compliance-v1-preview",)
_VALID_WIRE_DECISIONS = frozenset(
    {"approved", "rejected", "deferred", "escalated"}
)
_REQUIRED_EVENT_FIELDS: tuple[str, ...] = (
    "id",
    "type",
    "effective_at",
    "model",
    "decision",
    "content_hash",
)
# OpenAI uses model IDs like "gpt-4o-2024-08-06" or "gpt-4o-mini-2024-07-18".
# Split the trailing "-YYYY-MM-DD" (or "-YYYY-MM") into the version field.
_MODEL_ID_DATE_RE = re.compile(
    r"^(?P<name>.+?)-(?P<version>\d{4}-\d{2}(?:-\d{2})?)$"
)


@dataclass
class _EventOutcome:
    mapped: dict | None
    warning: str | None


def _map_outcome(raw: Any) -> str:
    """Collapse OpenAI compliance outcomes into the wire-spec enum.

    OpenAI's moderation surface uses terms like ``allowed`` /
    ``blocked`` / ``flagged`` / ``needs_review`` across the public
    Moderations API and the enterprise compliance admin console; the
    preview Compliance Platform export reuses the same vocabulary.
    """
    if not isinstance(raw, str):
        raise ReaderSchemaError(
            _PROVIDER,
            f"decision.outcome must be a string (got {type(raw).__name__})",
        )
    normalized = raw.strip().lower()
    if normalized in _VALID_WIRE_DECISIONS:
        return normalized
    if normalized in {"allowed", "pass", "passed", "allow", "ok"}:
        return "approved"
    if normalized in {"blocked", "denied", "deny", "reject", "block"}:
        return "rejected"
    if normalized in {"flagged", "needs_review", "review", "pending"}:
        return "deferred"
    if normalized in {"escalate", "manual_review"}:
        return "escalated"
    raise ReaderSchemaError(
        _PROVIDER,
        f"could not map OpenAI decision outcome {raw!r} to wire-spec enum "
        f"(expected one of {sorted(_VALID_WIRE_DECISIONS)} or a known alias)",
    )


def _split_model_id(model_id: str) -> tuple[str, str]:
    """Split an OpenAI model ID into (name, version)."""
    if not isinstance(model_id, str) or not model_id:
        raise ReaderSchemaError(
            _PROVIDER, f"model must be a non-empty string (got {model_id!r})"
        )
    match = _MODEL_ID_DATE_RE.match(model_id)
    if match:
        return match.group("name"), match.group("version")
    # Aliases like "gpt-4o" with no date suffix — keep whole string as name.
    return model_id, ""


def _normalize_timestamp(value: Any) -> str:
    """Accept RFC 3339 ``Z`` / ``+00:00`` strings and unix seconds ints."""
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        if value.endswith("Z"):
            # Reject fractional seconds — canonical schema forbids them.
            if "." in value:
                raise ReaderSchemaError(
                    _PROVIDER,
                    f"timestamp must not include fractional seconds "
                    f"(got {value!r})",
                )
            return value
        if value.endswith("+00:00"):
            stripped = value[: -len("+00:00")]
            if "." in stripped:
                raise ReaderSchemaError(
                    _PROVIDER,
                    f"timestamp must not include fractional seconds "
                    f"(got {value!r})",
                )
            return stripped + "Z"
    raise ReaderSchemaError(
        _PROVIDER,
        f"timestamp must be RFC 3339 UTC ('Z' or '+00:00') or unix seconds "
        f"(got {value!r})",
    )


@reader(_PROVIDER)
class OpenAIComplianceReader:
    """OpenAI Compliance Platform audit-log export reader."""

    provider_name: str = _PROVIDER
    provider_description: str = (
        "OpenAI Compliance Platform audit-log export reader. Ingests the "
        "enterprise compliance export ({'object': 'list', 'data': [...]} "
        "envelope or JSONL) and produces a Specora wire-spec evidence "
        "bundle. Moderation/policy-check outcomes ride as first-class "
        "evidence under records[].upstream_moderation. Offline, no "
        "network calls. Design-accurate against the preview schema "
        "pending live-data validation."
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
        """Ingest an OpenAI Compliance Platform export.

        Args:
            input_path: Path to the export file. Accepts either the
                standard OpenAI list envelope
                (``{"object": "list", "data": [...], "has_more": bool}``)
                as a single JSON document, or JSON Lines with one event
                per line. A bare top-level JSON array is also accepted.
            key_id: Specora signing key ID to associate with the bundle.
            public_key_path: Accepted for interface symmetry with other
                readers but ignored — OpenAI Compliance Platform does
                not emit per-event signatures. When provided, a loud
                warning is surfaced in ``ReadResult.warnings`` matching
                the CloudTrail / Azure-CL pattern.
            schema_version: Optional override. If set, must be in
                ``supported_schema_versions``.
            strict: If True, the first malformed event fails the read.
                If False, malformed events are dropped with warnings.

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
                "OpenAI Compliance Platform does not emit per-event signatures. "
                "Integrity is anchored at the TLS transport layer and by the "
                "enterprise admin console's tamper-evident audit log. The "
                "Specora outer signature tier is what the verifier checks. "
                "See docs/readers/openai-compliance.md §1."
            )

        input_path = Path(input_path)
        if not input_path.exists():
            raise ReaderIOError(str(input_path), "file not found")
        try:
            raw = input_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReaderIOError(str(input_path), f"read failed: {exc}") from exc

        effective_schema_version = schema_version or _SUPPORTED_VERSIONS[-1]
        if effective_schema_version not in _SUPPORTED_VERSIONS:
            raise ReaderSchemaError(
                _PROVIDER,
                f"unsupported schema_version {effective_schema_version!r} "
                f"(supported: {_SUPPORTED_VERSIONS})",
            )

        events_in = self._extract_events(raw, strict=strict)

        mapped_records: list[dict] = []
        warnings: list[str] = []
        seen_ids: set[str] = set()

        for index, event in enumerate(events_in):
            outcome = self._map_event(
                event, index=index, strict=strict, seen_ids=seen_ids
            )
            if outcome.warning is not None:
                warnings.append(outcome.warning)
            if outcome.mapped is not None:
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

    def _extract_events(self, raw: str, *, strict: bool) -> list:
        stripped = raw.strip()
        if not stripped:
            return []
        # JSONL detection: multi-line where every non-empty line parses
        # as a JSON object. Fall through to single-document parsing if
        # the first non-empty line starts with '{' or '[' suggesting a
        # pretty-printed list envelope.
        if "\n" in stripped and not stripped.lstrip().startswith(("[", "{")):
            return self._parse_jsonl(raw, strict=strict)
        if "\n" in stripped:
            first_nonspace = stripped.lstrip()[0]
            if first_nonspace == "{":
                # Disambiguate: JSONL of objects vs a single JSON object.
                # If the raw text parses cleanly as one JSON document,
                # treat it as the list envelope.
                try:
                    parsed = json.loads(stripped)
                except json.JSONDecodeError:
                    return self._parse_jsonl(raw, strict=strict)
                return self._extract_from_parsed(parsed)
            if first_nonspace == "[":
                parsed = json.loads(stripped)
                return self._extract_from_parsed(parsed)
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ReaderSchemaError(
                _PROVIDER, f"input is not valid JSON: {exc.msg}"
            ) from exc
        return self._extract_from_parsed(parsed)

    @staticmethod
    def _extract_from_parsed(parsed: Any) -> list:
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            if "data" in parsed:
                data = parsed["data"]
                if not isinstance(data, list):
                    raise ReaderSchemaError(
                        _PROVIDER, "'data' must be a JSON array"
                    )
                return data
            if "events" in parsed:
                events = parsed["events"]
                if not isinstance(events, list):
                    raise ReaderSchemaError(
                        _PROVIDER, "'events' must be a JSON array"
                    )
                return events
            # A single bare event dict — treat as a one-element archive.
            if "id" in parsed and "type" in parsed:
                return [parsed]
        raise ReaderSchemaError(
            _PROVIDER,
            "input must be an OpenAI list envelope "
            "({'object': 'list', 'data': [...]}), a bare JSON array of "
            "events, a JSONL file, or a single event object with 'id' "
            "and 'type' fields",
        )

    def _parse_jsonl(self, raw: str, *, strict: bool) -> list:
        events: list = []
        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                if strict:
                    raise ReaderSchemaError(
                        _PROVIDER,
                        f"invalid JSON in JSONL line: {exc.msg}",
                        line=lineno,
                    ) from exc
                # Non-strict: surface malformed lines as sentinels that
                # _map_event will turn into warnings.
                events.append({"__malformed__": True, "__lineno__": lineno})
        return events

    def _map_event(
        self,
        event: Any,
        *,
        index: int,
        strict: bool,
        seen_ids: set[str],
    ) -> _EventOutcome:
        location = f"event[{index}]"
        if isinstance(event, dict) and event.get("__malformed__") is True:
            lineno = event.get("__lineno__", index)
            return _EventOutcome(
                mapped=None,
                warning=f"{location}: malformed JSONL at line {lineno}",
            )
        if not isinstance(event, dict):
            if strict:
                raise ReaderSchemaError(
                    _PROVIDER, f"{location} is not a JSON object"
                )
            return _EventOutcome(
                mapped=None, warning=f"{location}: not a JSON object"
            )

        try:
            mapped = self._map_event_strict(event)
        except ReaderSchemaError as exc:
            if strict:
                raise
            return _EventOutcome(
                mapped=None, warning=f"{location}: {exc.detail}"
            )

        record_id = mapped["id"]
        if record_id in seen_ids:
            return _EventOutcome(
                mapped=None,
                warning=(
                    f"{location}: duplicate event id {record_id!r} "
                    f"(first occurrence wins)"
                ),
            )
        seen_ids.add(record_id)
        return _EventOutcome(mapped=mapped, warning=None)

    def _map_event_strict(self, event: dict) -> dict:
        for field_name in _REQUIRED_EVENT_FIELDS:
            if field_name not in event:
                raise ReaderSchemaError(
                    _PROVIDER, f"missing required field {field_name!r}"
                )
        decision = event["decision"]
        if not isinstance(decision, dict):
            raise ReaderSchemaError(
                _PROVIDER, "decision must be a JSON object"
            )
        if "outcome" not in decision:
            raise ReaderSchemaError(
                _PROVIDER, "decision.outcome missing"
            )
        policy_refs_raw = decision.get("policy_ids", decision.get("policy_refs", []))
        if not isinstance(policy_refs_raw, list):
            raise ReaderSchemaError(
                _PROVIDER, "decision.policy_ids must be a JSON array"
            )

        outcome = _map_outcome(decision["outcome"])

        context_hash = event["content_hash"]
        if (
            not isinstance(context_hash, str)
            or not context_hash.startswith("sha256:")
            or len(context_hash) != len("sha256:") + 64
        ):
            raise ReaderSchemaError(
                _PROVIDER,
                f"content_hash must be 'sha256:<64-hex>' (got {context_hash!r})",
            )

        timestamp = _normalize_timestamp(event["effective_at"])
        model_name, model_version = _split_model_id(event["model"])

        event_id = event["id"]
        if not isinstance(event_id, str) or not event_id:
            raise ReaderSchemaError(
                _PROVIDER, f"event id must be a non-empty string (got {event_id!r})"
            )

        mapped: dict[str, Any] = {
            "id": event_id,
            "timestamp": timestamp,
            "upstream_event_type": str(event["type"]),
            "model": {"name": model_name, "version": model_version},
            "decision": {
                "outcome": outcome,
                "policy_refs": [str(p) for p in policy_refs_raw],
            },
            "context": {"hash": context_hash},
            "upstream_signature": {
                "absent_per_record": True,
                "integrity_mechanism": "openai-compliance-api-tls-attested",
            },
        }

        request_id = event.get("request_id")
        if isinstance(request_id, str) and request_id:
            mapped["upstream_request_id"] = request_id

        project_id = event.get("project_id")
        if isinstance(project_id, str) and project_id:
            mapped["upstream_project_id"] = project_id

        moderation = event.get("moderation")
        if isinstance(moderation, dict) and moderation:
            mapped["upstream_moderation"] = self._normalize_moderation(moderation)

        return mapped

    @staticmethod
    def _normalize_moderation(moderation: dict) -> dict:
        """Preserve the OpenAI moderation block verbatim, sorted keys only.

        Canonicalization is handled by canonical_json_bytes at bundle
        serialization time; we just make sure nested dict keys are
        deterministically ordered in our own structure for clarity.
        """
        normalized: dict[str, Any] = {}
        for key in sorted(moderation):
            normalized[key] = moderation[key]
        return normalized

    @staticmethod
    def _build_bundle_payload(
        *, records: list[dict], key_id: str, schema_version: str
    ) -> dict:
        payload = {
            "metadata": {
                "provider": _PROVIDER,
                "reader": "specora_verify.readers.openai_compliance",
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


__all__ = ["OpenAIComplianceReader"]
