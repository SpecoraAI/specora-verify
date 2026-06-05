#!/usr/bin/env python3
"""Regenerate the AWS CloudTrail Lake (Bedrock AR Checks) test fixtures.

Run from the repo root:

    python tests/fixtures/cloudtrail/build_fixtures.py

This script is deterministic — record bodies are generated in a fixed
order with stable synthetic values, so two runs produce byte-identical
fixture files. Fixtures are committed to the repo so CI does not need
any AWS credentials or PyNaCl to run. No cryptographic signing happens
here because CloudTrail has no per-event signatures; integrity is
anchored at the CloudTrail log file validation level.

The fixtures emulate the ``{"Records": [<event>, ...]}`` archive shape
that CloudTrail's S3 delivery produces and that CloudTrail Lake
exports use. Each event is a valid CloudTrail envelope with Bedrock
Automated Reasoning Checks fields nested inside.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
KEYS_DIR = FIXTURE_DIR / "keys"

_REGIONS = ("us-east-1", "us-west-2", "eu-central-1")
_MODEL_IDS = (
    "anthropic.claude-3-5-sonnet-20240620-v1:0",
    "amazon.titan-text-premier-v1:0",
)
_AR_POLICIES = ("arp-abc123", "arp-def456", "arp-ghi789")
# (wire-spec decision, AR verdict, modelInvocationResult, escalation)
_DECISION_PROGRAM = (
    ("approved", "valid", "approved", False),
    ("rejected", "invalid", "blocked", False),
    ("deferred", "unknown", "pending", False),
    ("escalated", "valid", "approved", True),
)


def _base_event(
    i: int,
    *,
    region: str,
    model_id: str,
    ar_policy_id: str,
    verdict: str,
    invocation_result: str,
    escalation: bool,
    include_ar: bool = True,
    event_name: str = "InvokeModelWithAutomatedReasoning",
) -> dict:
    event_id = f"ct-event-{i:06d}"
    request_id = f"req-bedrock-{i:08x}"
    response_elements: dict = {
        "requestId": request_id,
        "modelInvocationResult": invocation_result,
        "outputTokens": 300 + (i % 200),
    }
    if include_ar:
        proof_seed = f"ct-proof-seed-{i:06d}".encode("ascii")
        proof_hash = "sha256:" + hashlib.sha256(proof_seed).hexdigest()
        response_elements["automatedReasoningResult"] = {
            "verdict": verdict,
            "proofHash": proof_hash,
            "logicalConstraints": [
                f"constraint-{(i % 5) + 1}",
                f"constraint-{(i % 7) + 1}",
            ],
            "escalationRequired": escalation,
        }
    return {
        "eventVersion": "1.09",
        "eventTime": f"2026-06-10T14:22:{i % 60:02d}Z",
        "eventSource": "bedrock.amazonaws.com",
        "eventName": event_name,
        "awsRegion": region,
        "eventID": event_id,
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": f"AROA{i:08X}:bedrock-caller",
            "arn": f"arn:aws:sts::123456789012:assumed-role/bedrock-caller/{i}",
            "accountId": "123456789012",
        },
        "requestParameters": {
            "modelId": model_id,
            "automatedReasoningPolicyId": ar_policy_id,
            "inputTokens": 1000 + (i % 500),
            "maxTokens": 2048,
        },
        "responseElements": response_elements,
    }


def _canonical_records(records: list[dict]) -> str:
    return json.dumps(
        {"Records": records},
        sort_keys=True,
        separators=(",", ":"),
    )


def _pretty_records(records: list[dict]) -> str:
    return json.dumps({"Records": records}, sort_keys=True, indent=2) + "\n"


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    (KEYS_DIR / "README.md").write_text(
        "# CloudTrail reader — no test keys required\n\n"
        "AWS CloudTrail has no per-event signatures. Integrity is anchored\n"
        "at the CloudTrail log file validation level (signed digest files\n"
        "emitted periodically by CloudTrail itself).\n\n"
        "The CloudTrail reader therefore accepts `--public-key` only for\n"
        "interface compatibility with other readers and ignores it. This\n"
        "directory exists so the fixture tree structurally matches the\n"
        "Anthropic reader fixture layout.\n",
        encoding="utf-8",
    )

    # ------------------------------------------------------------------
    # minimal-valid.json — 2 AR events, both us-east-1.
    # ------------------------------------------------------------------
    minimal = [
        _base_event(
            1,
            region="us-east-1",
            model_id=_MODEL_IDS[0],
            ar_policy_id=_AR_POLICIES[0],
            verdict="valid",
            invocation_result="approved",
            escalation=False,
        ),
        _base_event(
            2,
            region="us-east-1",
            model_id=_MODEL_IDS[0],
            ar_policy_id=_AR_POLICIES[1],
            verdict="invalid",
            invocation_result="blocked",
            escalation=False,
        ),
    ]
    (FIXTURE_DIR / "minimal-valid.json").write_text(_pretty_records(minimal), encoding="utf-8")

    # ------------------------------------------------------------------
    # realistic-complex.json — 24 AR events, 3 regions, 2 models,
    # mix of all four wire-spec decision outcomes. Plus 3 non-AR
    # Bedrock events that the reader must silently skip. Plus 2
    # non-Bedrock events (STS, S3) that the reader must silently skip.
    # Total: 29 CloudTrail records → 24 mapped.
    # ------------------------------------------------------------------
    complex_records: list[dict] = []
    for i in range(1, 25):
        wire, verdict, invocation_result, escalation = _DECISION_PROGRAM[i % 4]
        del wire  # derivation only; the reader recomputes it
        complex_records.append(
            _base_event(
                200 + i,
                region=_REGIONS[i % 3],
                model_id=_MODEL_IDS[i % 2],
                ar_policy_id=_AR_POLICIES[i % 3],
                verdict=verdict,
                invocation_result=invocation_result,
                escalation=escalation,
            )
        )
    # Non-AR Bedrock invocations (no AR fields, different event name).
    for i in range(1, 4):
        non_ar = _base_event(
            300 + i,
            region="us-east-1",
            model_id=_MODEL_IDS[0],
            ar_policy_id="arp-unused",
            verdict="valid",
            invocation_result="approved",
            escalation=False,
            include_ar=False,
            event_name="InvokeModel",
        )
        non_ar["requestParameters"].pop("automatedReasoningPolicyId", None)
        complex_records.append(non_ar)
    # Non-Bedrock events — completely different eventSource.
    complex_records.append(
        {
            "eventVersion": "1.09",
            "eventTime": "2026-06-10T14:23:00Z",
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "awsRegion": "us-east-1",
            "eventID": "ct-event-400001",
            "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/demo"},
            "responseElements": {},
        }
    )
    complex_records.append(
        {
            "eventVersion": "1.09",
            "eventTime": "2026-06-10T14:23:01Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "eventID": "ct-event-400002",
            "requestParameters": {"bucketName": "demo-bucket"},
            "responseElements": {},
        }
    )
    (FIXTURE_DIR / "realistic-complex.json").write_text(
        _pretty_records(complex_records), encoding="utf-8"
    )

    # ------------------------------------------------------------------
    # malformed.json — 5 CloudTrail events, 2 deliberately broken.
    # Layout: [ok, ok, ok, missing required field, broken AR payload]
    # Non-strict should recover 3 records with 2 warnings.
    # ------------------------------------------------------------------
    good = [
        _base_event(
            500 + i,
            region="us-east-1",
            model_id=_MODEL_IDS[0],
            ar_policy_id=_AR_POLICIES[0],
            verdict="valid",
            invocation_result="approved",
            escalation=False,
        )
        for i in range(3)
    ]
    missing_field = _base_event(
        600,
        region="us-east-1",
        model_id=_MODEL_IDS[0],
        ar_policy_id=_AR_POLICIES[0],
        verdict="valid",
        invocation_result="approved",
        escalation=False,
    )
    missing_field.pop("eventID")  # required field
    broken_ar = _base_event(
        601,
        region="us-east-1",
        model_id=_MODEL_IDS[0],
        ar_policy_id=_AR_POLICIES[0],
        verdict="valid",
        invocation_result="approved",
        escalation=False,
    )
    broken_ar["responseElements"]["automatedReasoningResult"]["proofHash"] = "not-a-hash"
    malformed_records = good + [missing_field, broken_ar]
    (FIXTURE_DIR / "malformed.json").write_text(
        _pretty_records(malformed_records), encoding="utf-8"
    )

    print(f"Wrote CloudTrail fixtures to {FIXTURE_DIR}")
    print(f"  minimal-valid.json      ({len(minimal)} events)")
    print(f"  realistic-complex.json  ({len(complex_records)} events, 24 AR)")
    print(f"  malformed.json          ({len(malformed_records)} events, 2 broken)")
    # Silence the lint for unused helper if nothing uses it.
    _ = _canonical_records


if __name__ == "__main__":
    main()
