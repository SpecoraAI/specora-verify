"""LangSmith Fleet audit-trace reader.

Ingests a JSON export of LangSmith Fleet traces — the enterprise
observability and tracing platform for LangChain applications — and maps
each trace onto the Specora wire-spec evidence-bundle shape.

The reader never talks to LangSmith directly — it only reads a file the
customer has already exported with their own LangSmith credentials. This
preserves the offline-verifier posture of ``specora-verify``.

Status — design-accurate, pending live-data validation.
===========================================================
As of the B01 session-4 landing (2026-04-18), the LangSmith Fleet trace
export shape is based on what LangSmith has publicly documented in their
API reference, Python SDK, and enterprise documentation. The trace
export format implemented here is **design-accurate** against the
published LangSmith API (``GET /runs``, ``POST /runs/query``, and the
SDK ``client.list_runs()`` / ``client.read_run()`` methods).

When LangSmith revises the export shape (or when Specora receives
sign-off to run against a real Fleet export), the reader's
``_REQUIRED_RUN_FIELDS``, ``_RUN_TYPE_ALLOWLIST``, and the outcome
mapping in ``_map_outcome`` are the three points that will need to be
reconciled with production shape. Same reconciliation precedent as B01
session 3 (OpenAI reader).

First-class field decision: feedback scores / human annotations.
================================================================
The strategic question every reader answers is: *what did the upstream
provider actually evaluate?* For LangSmith Fleet, the differentiator
is **feedback scores and human annotations** — the evaluation layer
that sits on top of raw trace data. Operators and reviewers attach
typed feedback (correctness, helpfulness, toxicity, custom keys) to
runs, and LangSmith Fleet's compliance export surfaces these as
first-class evidence. The reader lifts this into:

    * the standard ``decision.outcome`` wire-spec enum, derived from
      the ``evaluation.outcome`` field in the trace export
    * the standard ``decision.policy_refs`` list (LangSmith Fleet
      ``evaluation.rule_ids`` — guardrail or evaluation rule refs)
    * a record-level ``upstream_feedback`` list that preserves the
      raw LangSmith feedback entries (key, score, comment, source)
      verbatim so auditors can walk the human evaluation independently
    * ``upstream_token_usage`` preserving token counts when present
    * ``upstream_cost`` preserving cost data when present

Upstream integrity model. LangSmith Fleet does NOT emit per-trace
cryptographic signatures today. Integrity is anchored at the transport
layer (TLS to ``api.smith.langchain.com``) and by the Fleet tenant's
audit log. The reader therefore sets ``upstream_signature`` on each
mapped record to the canonical "absent-per-record" descriptor:

    {
        "absent_per_record": true,
        "integrity_mechanism": "langsmith-fleet-api-tls-attested",
    }

which matches the CloudTrail, Azure CL, and OpenAI conventions.

Schema mapping (upstream → Specora wire spec):

    id                        → records[].id
    start_time                → records[].timestamp       (RFC 3339 UTC "Z")
    name                      → records[].upstream_run_name
    run_type                  → records[].upstream_run_type
    session_id                → records[].upstream_session_id
    extra.invocation_params
        .model_name           → records[].model.name
    model_version (or split)  → records[].model.version
    evaluation.outcome        → records[].decision.outcome (enum-mapped)
    evaluation.rule_ids       → records[].decision.policy_refs
    content_hash              → records[].context.hash     ("sha256:...")
    feedback[]                → records[].upstream_feedback
    token_usage               → records[].upstream_token_usage
    total_cost                → records[].upstream_cost
    (absent)                  → records[].upstream_signature (absent descriptor)
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

_PROVIDER = "langsmith"
_SUPPORTED_VERSIONS: tuple[str, ...] = ("langsmith-fleet-v1",)
_VALID_WIRE_DECISIONS = frozenset(
    {"approved", "rejected", "deferred", "escalated"}
)
_REQUIRED_RUN_FIELDS: tuple[str, ...] = (
    "id",
    "run_type",
    "start_time",
    "status",
    "evaluation",
    "content_hash",
)
_RUN_TYPE_ALLOWLIST = frozenset(
    {"chain", "llm", "tool", "retriever", "prompt", "parser", "embedding"}
)
# LangSmith model names may carry a date suffix like "claude-3-5-sonnet-20241022"
# or "gpt-4o-2024-08-06". Split it off as version.
_MODEL_NAME_DATE_RE = re.compile(
    r"^(?P<name>.+?)-(?P<version>\d{4}(?:-?\d{2}){1,2}(?:-.*)?)$"
)


@dataclass
class _RunOutcome:
    mapped: dict | None
    warning: str | None


def _map_outcome(raw: Any) -> str:
    """Collapse LangSmith evaluation outcomes into the wire-spec enum.

    LangSmith Fleet evaluation rules produce verdicts like ``pass``,
    ``fail``, ``needs_review``, etc. Map them to the canonical set.
    """
    if not isinstance(raw, str):
        raise ReaderSchemaError(
            _PROVIDER,
            f"evaluation.outcome must be a string (got {type(raw).__name__})",
        )
    normalized = raw.strip().lower()
    if normalized in _VALID_WIRE_DECISIONS:
        return normalized
    if normalized in {"pass", "passed", "correct", "ok", "success", "allow", "allowed"}:
        return "approved"
    if normalized in {"fail", "failed", "incorrect", "block", "blocked", "error", "reject"}:
        return "rejected"
    if normalized in {"pending", "needs_review", "review", "flagged", "unknown"}:
        return "deferred"
    if normalized in {"escalate", "escalated", "manual_review"}:
        return "escalated"
    raise ReaderSchemaError(
        _PROVIDER,
        f"could not map LangSmith evaluation outcome {raw!r} to wire-spec enum "
        f"(expected one of {sorted(_VALID_WIRE_DECISIONS)} or a known alias)",
    )


def _split_model_name(model_name: str) -> tuple[str, str]:
    """Split a model name into (name, version)."""
    if not isinstance(model_name, str) or not model_name:
        return "", ""
    match = _MODEL_NAME_DATE_RE.match(model_name)
    if match:
        return match.group("name"), match.group("version")
    return model_name, ""


def _normalize_timestamp(value: Any) -> str:
    """Accept RFC 3339 Z / +00:00 strings and ISO strings."""
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        if value.endswith("Z"):
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
class LangSmithReader:
    """LangSmith Fleet audit-trace export reader."""

    provider_name: str = _PROVIDER
    provider_description: str = (
        "LangSmith Fleet audit-trace export reader. Ingests enterprise "
        "trace exports ({'runs': [...]} envelope, bare JSON array, or JSONL) "
        "and produces a Specora wire-spec evidence bundle. Feedback scores "
        "and human annotations ride as first-class evidence under "
        "records[].upstream_feedback. Offline, no network calls. "
        "Design-accurate against the LangSmith API reference pending "
        "live-data validation."
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
        """Ingest a LangSmith Fleet trace export.

        Args:
            input_path: Path to the export file. Accepts:
                - ``{"runs": [...]}`` envelope (Fleet batch export)
                - Bare JSON array of run objects
                - JSON Lines (one run per line)
                - A single run object with ``id`` and ``run_type``
            key_id: Specora signing key ID to associate with the bundle.
            public_key_path: Accepted for interface symmetry with other
                readers but ignored — LangSmith Fleet does not emit
                per-trace signatures.
            schema_version: Optional override. If set, must be in
                ``supported_schema_versions``.
            strict: If True, the first malformed run fails the read.
                If False, malformed runs are dropped with warnings.

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
                "LangSmith Fleet does not emit per-trace signatures. "
                "Integrity is anchored at the TLS transport layer and by the "
                "Fleet tenant's audit log. The Specora outer signature tier "
                "is what the verifier checks. See docs/readers/langsmith.md §1."
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

        runs_in = self._extract_runs(raw, strict=strict)

        mapped_records: list[dict] = []
        warnings: list[str] = []
        seen_ids: set[str] = set()

        for index, run in enumerate(runs_in):
            outcome = self._map_run(
                run, index=index, strict=strict, seen_ids=seen_ids
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

    def _extract_runs(self, raw: str, *, strict: bool) -> list:
        stripped = raw.strip()
        if not stripped:
            return []
        # JSONL detection: multi-line where first non-empty char is not
        # '[' or '{' suggesting a pretty-printed single document.
        if "\n" in stripped and not stripped.lstrip().startswith(("[", "{")):
            return self._parse_jsonl(raw, strict=strict)
        if "\n" in stripped:
            first_nonspace = stripped.lstrip()[0]
            if first_nonspace == "{":
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
            if "runs" in parsed:
                runs = parsed["runs"]
                if not isinstance(runs, list):
                    raise ReaderSchemaError(
                        _PROVIDER, "'runs' must be a JSON array"
                    )
                return runs
            if "data" in parsed:
                data = parsed["data"]
                if not isinstance(data, list):
                    raise ReaderSchemaError(
                        _PROVIDER, "'data' must be a JSON array"
                    )
                return data
            # A single bare run object.
            if "id" in parsed and "run_type" in parsed:
                return [parsed]
        raise ReaderSchemaError(
            _PROVIDER,
            "input must be a LangSmith Fleet export envelope "
            "({'runs': [...]}), a bare JSON array of runs, "
            "a JSONL file, or a single run object with 'id' "
            "and 'run_type' fields",
        )

    def _parse_jsonl(self, raw: str, *, strict: bool) -> list:
        runs: list = []
        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                runs.append(json.loads(line))
            except json.JSONDecodeError as exc:
                if strict:
                    raise ReaderSchemaError(
                        _PROVIDER,
                        f"invalid JSON in JSONL line: {exc.msg}",
                        line=lineno,
                    ) from exc
                runs.append({"__malformed__": True, "__lineno__": lineno})
        return runs

    def _map_run(
        self,
        run: Any,
        *,
        index: int,
        strict: bool,
        seen_ids: set[str],
    ) -> _RunOutcome:
        location = f"run[{index}]"
        if isinstance(run, dict) and run.get("__malformed__") is True:
            lineno = run.get("__lineno__", index)
            return _RunOutcome(
                mapped=None,
                warning=f"{location}: malformed JSONL at line {lineno}",
            )
        if not isinstance(run, dict):
            if strict:
                raise ReaderSchemaError(
                    _PROVIDER, f"{location} is not a JSON object"
                )
            return _RunOutcome(
                mapped=None, warning=f"{location}: not a JSON object"
            )

        try:
            mapped = self._map_run_strict(run)
        except ReaderSchemaError as exc:
            if strict:
                raise
            return _RunOutcome(
                mapped=None, warning=f"{location}: {exc.detail}"
            )

        record_id = mapped["id"]
        if record_id in seen_ids:
            return _RunOutcome(
                mapped=None,
                warning=(
                    f"{location}: duplicate run id {record_id!r} "
                    f"(first occurrence wins)"
                ),
            )
        seen_ids.add(record_id)
        return _RunOutcome(mapped=mapped, warning=None)

    def _map_run_strict(self, run: dict) -> dict:
        for field_name in _REQUIRED_RUN_FIELDS:
            if field_name not in run:
                raise ReaderSchemaError(
                    _PROVIDER, f"missing required field {field_name!r}"
                )

        evaluation = run["evaluation"]
        if not isinstance(evaluation, dict):
            raise ReaderSchemaError(
                _PROVIDER, "evaluation must be a JSON object"
            )
        if "outcome" not in evaluation:
            raise ReaderSchemaError(
                _PROVIDER, "evaluation.outcome missing"
            )
        policy_refs_raw = evaluation.get(
            "rule_ids", evaluation.get("policy_refs", [])
        )
        if not isinstance(policy_refs_raw, list):
            raise ReaderSchemaError(
                _PROVIDER, "evaluation.rule_ids must be a JSON array"
            )

        outcome = _map_outcome(evaluation["outcome"])

        content_hash = run["content_hash"]
        if (
            not isinstance(content_hash, str)
            or not content_hash.startswith("sha256:")
            or len(content_hash) != len("sha256:") + 64
        ):
            raise ReaderSchemaError(
                _PROVIDER,
                f"content_hash must be 'sha256:<64-hex>' (got {content_hash!r})",
            )

        timestamp = _normalize_timestamp(run["start_time"])

        run_id = run["id"]
        if not isinstance(run_id, str) or not run_id:
            raise ReaderSchemaError(
                _PROVIDER, f"run id must be a non-empty string (got {run_id!r})"
            )

        run_type = run["run_type"]
        if not isinstance(run_type, str) or run_type not in _RUN_TYPE_ALLOWLIST:
            raise ReaderSchemaError(
                _PROVIDER,
                f"run_type must be one of {sorted(_RUN_TYPE_ALLOWLIST)} "
                f"(got {run_type!r})",
            )

        # Model identification: explicit field or nested in extra.
        model_name_raw = run.get("model_name", "")
        if not model_name_raw:
            extra = run.get("extra")
            if isinstance(extra, dict):
                invocation_params = extra.get("invocation_params")
                if isinstance(invocation_params, dict):
                    model_name_raw = invocation_params.get("model_name", "")
                    if not model_name_raw:
                        model_name_raw = invocation_params.get("model", "")
        if not model_name_raw:
            model_name_raw = run.get("serialized", {}).get("kwargs", {}).get(
                "model_name", ""
            ) if isinstance(run.get("serialized"), dict) else ""
        if not isinstance(model_name_raw, str):
            model_name_raw = str(model_name_raw) if model_name_raw else ""

        model_name, model_version = _split_model_name(model_name_raw)
        # Allow explicit model_version override.
        explicit_version = run.get("model_version")
        if isinstance(explicit_version, str) and explicit_version:
            model_version = explicit_version

        # If no model name found at all, use run_type as fallback so the
        # model.name field is never empty (schema requires minLength 1).
        if not model_name:
            model_name = f"langsmith-{run_type}"

        mapped: dict[str, Any] = {
            "id": run_id,
            "timestamp": timestamp,
            "upstream_run_name": str(run.get("name", "")),
            "upstream_run_type": run_type,
            "model": {"name": model_name, "version": model_version},
            "decision": {
                "outcome": outcome,
                "policy_refs": [str(p) for p in policy_refs_raw],
            },
            "context": {"hash": content_hash},
            "upstream_signature": {
                "absent_per_record": True,
                "integrity_mechanism": "langsmith-fleet-api-tls-attested",
            },
        }

        # Optional session ID.
        session_id = run.get("session_id")
        if isinstance(session_id, str) and session_id:
            mapped["upstream_session_id"] = session_id

        # First-class field: feedback scores / human annotations.
        feedback = run.get("feedback")
        if isinstance(feedback, list) and feedback:
            mapped["upstream_feedback"] = self._normalize_feedback(feedback)

        # Token usage.
        token_usage = run.get("token_usage")
        if isinstance(token_usage, dict) and token_usage:
            mapped["upstream_token_usage"] = {
                k: v for k, v in sorted(token_usage.items())
            }

        # Cost.
        total_cost = run.get("total_cost")
        if total_cost is not None and isinstance(total_cost, (int, float)):
            mapped["upstream_cost"] = float(total_cost)

        return mapped

    @staticmethod
    def _normalize_feedback(feedback: list) -> list:
        """Preserve LangSmith feedback entries, sorted for determinism."""
        normalized: list[dict[str, Any]] = []
        for entry in feedback:
            if not isinstance(entry, dict):
                continue
            item: dict[str, Any] = {}
            for key in sorted(entry):
                item[key] = entry[key]
            normalized.append(item)
        # Sort by (key, score) for deterministic ordering.
        normalized.sort(
            key=lambda e: (e.get("key", ""), e.get("score", 0))
        )
        return normalized

    @staticmethod
    def _build_bundle_payload(
        *, records: list[dict], key_id: str, schema_version: str
    ) -> dict:
        payload = {
            "metadata": {
                "provider": _PROVIDER,
                "reader": "specora_verify.readers.langsmith",
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


__all__ = ["LangSmithReader"]
