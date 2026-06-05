"""Specora Trust Protocol Validators.

Validates STP messages, artifacts, and integration scaffolds.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from specora_verify.canonical import canonical_json_bytes
from specora_verify.hash import sha256_hex
from specora_verify.stp_contracts import (
    STP_ACTION_TYPES,
    STP_CAPABILITIES,
    STP_EXECUTION_STATUSES,
    STP_MESSAGE_TYPES,
    STP_PAYLOAD_REQUIRED_FIELDS,
    STP_PROTOCOL_VERSION,
    STP_REQUIRED_FIELDS,
    STP_RESPONSE_TYPES,
    STP_RESULT_REQUIRED_FIELDS,
    STP_RUNTIME_TYPES,
)

# =============================================================================
# Default vectors directory
# =============================================================================

DEFAULT_STP_VECTORS_DIR = Path(__file__).parent.parent.parent / "vectors" / "stp"


# =============================================================================
# Result Dataclasses
# =============================================================================


@dataclass
class STPInitResult:
    """Result of STP initialization scaffold generation."""

    success: bool
    output_dir: str
    runtime: str
    files_created: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output_dir": self.output_dir,
            "runtime": self.runtime,
            "files_created": self.files_created,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class STPVerifyResult:
    """Result of STP message verification."""

    valid: bool
    message_type: str | None = None
    protocol_version: str | None = None
    schema_valid: bool = False
    seal_valid: bool | None = None
    computed_seal: str | None = None
    expected_seal: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "message_type": self.message_type,
            "protocol_version": self.protocol_version,
            "schema_valid": self.schema_valid,
            "seal_valid": self.seal_valid,
            "computed_seal": self.computed_seal,
            "expected_seal": self.expected_seal,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class STPSimulateResult:
    """Result of STP decision simulation."""

    decision: str  # allow, block, require_approval, restrict
    policy_hash: str
    policy_path: str
    trust_score: float
    reasons: list[str] = field(default_factory=list)
    restrictions: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "policy_hash": self.policy_hash,
            "policy_path": self.policy_path,
            "trust_score": self.trust_score,
            "reasons": self.reasons,
            "restrictions": self.restrictions,
        }


@dataclass
class STPInspectResult:
    """Result of STP artifact inspection."""

    artifact_type: str
    message_type: str | None = None
    protocol_version: str = ""
    timestamp: str | None = None
    computed_seal: str | None = None
    chain_position: int | None = None
    canonical_json: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_type": self.artifact_type,
            "message_type": self.message_type,
            "protocol_version": self.protocol_version,
            "timestamp": self.timestamp,
            "computed_seal": self.computed_seal,
            "chain_position": self.chain_position,
            "canonical_json": self.canonical_json,
            "fields": self.fields,
        }


@dataclass
class STPVectorResult:
    """Result for a single STP vector verification."""

    spec_id: str
    version: str
    bytes_match: bool
    hash_match: bool
    computed_hash: str
    expected_hash: str
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.bytes_match and self.hash_match

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_id": self.spec_id,
            "version": self.version,
            "valid": self.valid,
            "bytes_match": self.bytes_match,
            "hash_match": self.hash_match,
            "computed_hash": self.computed_hash,
            "expected_hash": self.expected_hash,
            "errors": self.errors,
        }


@dataclass
class STPVectorsResult:
    """Result of STP golden vector verification."""

    valid: bool
    vectors_dir: str
    total: int
    passed: int
    failed: int
    results: list[STPVectorResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "vectors_dir": self.vectors_dir,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
        }


# =============================================================================
# Scaffold Generation
# =============================================================================


def generate_stp_scaffold(
    output_dir: Path,
    runtime: str = "custom",
    org_id: str | None = None,
    force: bool = False,
) -> STPInitResult:
    """Generate STP integration scaffold.

    Args:
        output_dir: Directory to create scaffold in
        runtime: Target runtime type (cursor, langgraph, etc.)
        org_id: Organization ID (generates placeholder if not provided)
        force: Overwrite existing directory

    Returns:
        STPInitResult with generation details
    """
    result = STPInitResult(
        success=True,
        output_dir=str(output_dir),
        runtime=runtime,
    )

    # Validate runtime
    if runtime not in STP_RUNTIME_TYPES:
        result.warnings.append(
            f"Unknown runtime '{runtime}'. Valid options: {', '.join(STP_RUNTIME_TYPES)}"
        )

    # Check output directory
    if output_dir.exists():
        if not force:
            result.success = False
            result.errors.append(
                f"Output directory already exists: {output_dir}. Use --force to overwrite."
            )
            return result
        shutil.rmtree(output_dir)

    # Create directory structure
    try:
        output_dir.mkdir(parents=True)
        (output_dir / "proofs").mkdir()
        (output_dir / "verification").mkdir()
    except OSError as e:
        result.success = False
        result.errors.append(f"Failed to create directories: {e}")
        return result

    # Generate org_id if not provided
    if not org_id:
        org_id = str(uuid4())
        result.warnings.append(f"Generated placeholder org_id: {org_id}")

    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Generate config.json
    config = {
        "stp_version": STP_PROTOCOL_VERSION,
        "runtime": runtime,
        "org_id": org_id,
        "created_at": timestamp,
        "dev_mode": True,
        "api_url": "http://localhost:8765",
    }
    config_path = output_dir / "config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    result.files_created.append("config.json")

    # Generate sample-identity.json
    identity_request = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "agent.identity",
        "timestamp": timestamp,
        "payload": {
            "agent_name": f"sample-{runtime}-agent",
            "agent_version": "1.0.0",
            "runtime": runtime,
            "capabilities_requested": ["read_code", "write_code"],
            "owner_context": {
                "org_id": org_id,
            },
        },
    }
    identity_path = output_dir / "sample-identity.json"
    identity_path.write_text(json.dumps(identity_request, indent=2), encoding="utf-8")
    result.files_created.append("sample-identity.json")

    # Generate sample-authorize.json
    authorize_request = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "execution.authorize",
        "timestamp": timestamp,
        "payload": {
            "agent_identity_id": "00000000-0000-0000-0000-000000000000",
            "action_type": "code_edit",
            "tools_requested": ["filesystem"],
            "mode": "enforce",
        },
    }
    authorize_path = output_dir / "sample-authorize.json"
    authorize_path.write_text(json.dumps(authorize_request, indent=2), encoding="utf-8")
    result.files_created.append("sample-authorize.json")

    # Generate sample-record.json
    record_request = {
        "protocol_version": STP_PROTOCOL_VERSION,
        "message_type": "execution.record",
        "timestamp": timestamp,
        "payload": {
            "authorization_id": "00000000-0000-0000-0000-000000000000",
            "status": "success",
            "output_hash": "0" * 64,
            "duration_ms": 1000,
        },
    }
    record_path = output_dir / "sample-record.json"
    record_path.write_text(json.dumps(record_request, indent=2), encoding="utf-8")
    result.files_created.append("sample-record.json")

    # Generate policy.json (sample governance policy)
    policy = {
        "policy_id": str(uuid4()),
        "policy_version": "1.0.0",
        "rules": [
            {
                "action_type": "code_edit",
                "decision": "allow",
                "required_capabilities": ["write_code"],
                "required_trust_tier": 1,
            },
            {
                "action_type": "command_execute",
                "decision": "require_approval",
                "required_capabilities": ["execute_commands"],
                "required_trust_tier": 3,
            },
        ],
        "default_decision": "block",
    }
    policy_path = output_dir / "policy.json"
    policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    result.files_created.append("policy.json")

    # Generate README.md
    readme = f"""# STP Integration Scaffold

Generated for runtime: **{runtime}**

## Files

- `config.json` - STP configuration
- `sample-identity.json` - Sample agent.identity request
- `sample-authorize.json` - Sample execution.authorize request
- `sample-record.json` - Sample execution.record request
- `policy.json` - Sample governance policy

## Usage

### 1. Verify Messages

```bash
specora-verify stp verify sample-identity.json
specora-verify stp verify sample-authorize.json
```

### 2. Simulate Decisions

```bash
specora-verify stp simulate sample-authorize.json --policy policy.json
```

### 3. Test with Dev Mode

```bash
specora dev --port 8765
```

Then use the sample messages against `http://localhost:8765/api/v1/stp/`.

## Documentation

- [STP Adoption Guide](https://docs.specora.ai/protocol/stp-adoption)
- [Adapter Development](https://docs.specora.ai/protocol/stp-adapters)
- [Certification](https://docs.specora.ai/protocol/stp-certification)
"""
    readme_path = output_dir / "README.md"
    readme_path.write_text(readme, encoding="utf-8")
    result.files_created.append("README.md")

    return result


# =============================================================================
# Message Validation
# =============================================================================


def validate_stp_message(
    payload: dict[str, Any],
    *,
    message_type: str | None = None,
    strict: bool = False,
    check_seal: bool = False,
    expected_seal: str | None = None,
) -> STPVerifyResult:
    """Validate an STP message against the protocol schema.

    Args:
        payload: STP message dictionary
        message_type: Expected message type (auto-detected if not provided)
        strict: Fail on warnings (protocol version mismatch, etc.)
        check_seal: Verify seal integrity
        expected_seal: Expected seal hash

    Returns:
        STPVerifyResult with validation details
    """
    result = STPVerifyResult(valid=True)
    errors: list[str] = []
    warnings: list[str] = []

    # Detect message type
    detected_type = payload.get("message_type")
    result.message_type = detected_type

    if message_type and detected_type != message_type:
        errors.append(f"Message type mismatch: expected '{message_type}', got '{detected_type}'")

    # Validate message type is known
    all_types = STP_MESSAGE_TYPES + STP_RESPONSE_TYPES
    if detected_type and detected_type not in all_types:
        errors.append(f"Unknown message type: {detected_type}")

    # Validate protocol version
    protocol_version = payload.get("protocol_version")
    result.protocol_version = protocol_version

    if protocol_version != STP_PROTOCOL_VERSION:
        msg = f"Protocol version mismatch: expected '{STP_PROTOCOL_VERSION}', got '{protocol_version}'"
        if strict:
            errors.append(msg)
        else:
            warnings.append(msg)

    # Validate required fields
    if detected_type and detected_type in STP_REQUIRED_FIELDS:
        required = STP_REQUIRED_FIELDS[detected_type]
        for field_name in required:
            if field_name not in payload:
                errors.append(f"Missing required field: {field_name}")

    # Validate payload/result fields
    if detected_type in STP_MESSAGE_TYPES:
        payload_data = payload.get("payload", {})
        if detected_type in STP_PAYLOAD_REQUIRED_FIELDS:
            for field_name in STP_PAYLOAD_REQUIRED_FIELDS[detected_type]:
                if field_name not in payload_data:
                    errors.append(f"Missing required payload field: {field_name}")

        # Validate specific fields
        _validate_payload_values(detected_type, payload_data, errors, warnings)

    elif detected_type in STP_RESPONSE_TYPES:
        result_data = payload.get("result", {})
        base_type = detected_type  # e.g., "agent.identity.response"
        if base_type in STP_RESULT_REQUIRED_FIELDS:
            for field_name in STP_RESULT_REQUIRED_FIELDS[base_type]:
                if field_name not in result_data:
                    errors.append(f"Missing required result field: {field_name}")

    # Check seal if requested
    if check_seal:
        computed_seal = sha256_hex(canonical_json_bytes(payload))
        result.computed_seal = computed_seal

        if expected_seal:
            result.expected_seal = expected_seal
            result.seal_valid = computed_seal == expected_seal
            if not result.seal_valid:
                errors.append(f"Seal mismatch: computed {computed_seal}, expected {expected_seal}")
        else:
            result.seal_valid = True

    result.schema_valid = len(errors) == 0
    result.valid = len(errors) == 0
    result.errors = errors
    result.warnings = warnings

    return result


def _validate_payload_values(
    message_type: str,
    payload: dict[str, Any],
    errors: list[str],
    warnings: list[str],
) -> None:
    """Validate payload field values against STP contracts."""
    if message_type == "agent.identity":
        runtime = payload.get("runtime")
        if runtime and runtime not in STP_RUNTIME_TYPES:
            warnings.append(
                f"Unknown runtime type: {runtime}. Valid options: {', '.join(STP_RUNTIME_TYPES)}"
            )

        capabilities = payload.get("capabilities_requested", [])
        for cap in capabilities:
            if cap not in STP_CAPABILITIES:
                warnings.append(
                    f"Unknown capability: {cap}. Valid options: {', '.join(STP_CAPABILITIES)}"
                )

    elif message_type == "execution.authorize":
        action_type = payload.get("action_type")
        if action_type and action_type not in STP_ACTION_TYPES:
            warnings.append(
                f"Unknown action type: {action_type}. Valid options: {', '.join(STP_ACTION_TYPES)}"
            )

    elif message_type == "execution.record":
        status = payload.get("status")
        if status and status not in STP_EXECUTION_STATUSES:
            errors.append(
                f"Invalid status: {status}. Valid options: {', '.join(STP_EXECUTION_STATUSES)}"
            )


# =============================================================================
# Decision Simulation
# =============================================================================


def simulate_stp_decision(
    request: dict[str, Any],
    *,
    policy_path: Path | None = None,
    policy_data: dict[str, Any] | None = None,
    trust_score: float = 50.0,
) -> STPSimulateResult:
    """Simulate a governance decision for an STP authorization request.

    Args:
        request: STP execution.authorize request
        policy_path: Path to policy JSON file
        policy_data: Policy dictionary (alternative to policy_path)
        trust_score: Assumed trust score (0-100)

    Returns:
        STPSimulateResult with simulated decision
    """
    # Load policy
    policy: dict[str, Any] = {}
    policy_path_str = "default"

    if policy_path:
        policy_path_str = str(policy_path)
        try:
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return STPSimulateResult(
                decision="block",
                policy_hash="",
                policy_path=policy_path_str,
                trust_score=trust_score,
                reasons=[f"Failed to load policy: {e}"],
            )
    elif policy_data:
        policy = policy_data
        policy_path_str = "inline"

    # Compute policy hash
    policy_hash = sha256_hex(canonical_json_bytes(policy)) if policy else ""

    # Extract action type from request
    payload = request.get("payload", {})
    action_type = payload.get("action_type", "unknown")

    # Find matching rule
    rules = policy.get("rules", [])
    default_decision = policy.get("default_decision", "block")

    reasons: list[str] = []
    decision = default_decision
    restrictions: dict[str, Any] | None = None

    for rule in rules:
        if rule.get("action_type") == action_type:
            # Check trust tier requirement
            required_tier = rule.get("required_trust_tier", 0)
            # Approximate tier from score: 0-20=0, 20-40=1, 40-60=2, 60-80=3, 80-100=4
            current_tier = int(trust_score / 20)

            if current_tier >= required_tier:
                decision = rule.get("decision", "allow")
                reasons.append(f"Matched rule for action_type={action_type}: decision={decision}")
                restrictions = rule.get("restrictions")
            else:
                decision = "block"
                reasons.append(
                    f"Trust tier insufficient: required={required_tier}, current={current_tier}"
                )
            break
    else:
        reasons.append(
            f"No matching rule for action_type={action_type}, using default: {default_decision}"
        )

    return STPSimulateResult(
        decision=decision,
        policy_hash=policy_hash,
        policy_path=policy_path_str,
        trust_score=trust_score,
        reasons=reasons,
        restrictions=restrictions,
    )


# =============================================================================
# Artifact Inspection
# =============================================================================


def inspect_stp_artifact(
    payload: dict[str, Any],
    *,
    show_seal: bool = False,
    show_chain: bool = False,
    show_canonical: bool = False,
) -> STPInspectResult:
    """Inspect STP artifact details.

    Args:
        payload: STP artifact dictionary
        show_seal: Compute and include seal hash
        show_chain: Include chain position info
        show_canonical: Include canonical JSON form

    Returns:
        STPInspectResult with artifact details
    """
    # Determine artifact type
    message_type = payload.get("message_type")
    if message_type:
        if message_type in STP_MESSAGE_TYPES:
            artifact_type = "request"
        elif message_type in STP_RESPONSE_TYPES:
            artifact_type = "response"
        else:
            artifact_type = "unknown"
    elif "attestation_bundle" in payload:
        artifact_type = "attestation_bundle"
    else:
        artifact_type = "unknown"

    result = STPInspectResult(
        artifact_type=artifact_type,
        message_type=message_type,
        protocol_version=payload.get("protocol_version", ""),
        timestamp=payload.get("timestamp"),
    )

    # Compute seal
    if show_seal:
        result.computed_seal = sha256_hex(canonical_json_bytes(payload))

    # Extract chain position
    if show_chain:
        # Check various locations for chain position
        if "result" in payload:
            result.chain_position = payload["result"].get("chain_position")
        elif "attestation_bundle" in payload:
            bundle = payload["attestation_bundle"]
            if "executions" in bundle and bundle["executions"]:
                result.chain_position = bundle["executions"][0].get("chain_position")

    # Generate canonical JSON
    if show_canonical:
        result.canonical_json = canonical_json_bytes(payload).decode("utf-8")

    # Extract key fields based on artifact type
    if artifact_type == "request":
        result.fields = {
            "payload": payload.get("payload", {}),
        }
    elif artifact_type == "response":
        result.fields = {
            "result": payload.get("result", {}),
        }
    elif artifact_type == "attestation_bundle":
        bundle = payload.get("attestation_bundle", {})
        result.fields = {
            "bundle_id": bundle.get("bundle_id"),
            "bundle_root_hash": bundle.get("bundle_root_hash"),
            "execution_count": len(bundle.get("executions", [])),
        }
    else:
        result.fields = dict(payload)

    return result


# =============================================================================
# Vector Verification
# =============================================================================


def _load_stp_vector_files(
    vectors_dir: Path,
    spec_id: str,
    version: str,
) -> tuple[dict[str, Any] | None, bytes | None, str | None, list[str]]:
    """Load the three vector files for an STP spec."""
    errors: list[str] = []

    json_file = vectors_dir / f"{spec_id}-{version}.json"
    canonical_file = vectors_dir / f"{spec_id}-{version}.canonical.json"
    sha256_file = vectors_dir / f"{spec_id}-{version}.sha256.txt"

    payload = None
    if json_file.exists():
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse {json_file.name}: {e}")
    else:
        errors.append(f"Vector file not found: {json_file.name}")

    canonical_bytes = None
    if canonical_file.exists():
        canonical_bytes = canonical_file.read_bytes()
    else:
        errors.append(f"Canonical file not found: {canonical_file.name}")

    expected_hash = None
    if sha256_file.exists():
        expected_hash = sha256_file.read_text(encoding="utf-8").strip()
    else:
        errors.append(f"Hash file not found: {sha256_file.name}")

    return payload, canonical_bytes, expected_hash, errors


def verify_single_stp_vector(
    vectors_dir: Path,
    spec_id: str,
    version: str,
) -> STPVectorResult:
    """Verify a single STP golden vector."""
    payload, expected_bytes, expected_hash, load_errors = _load_stp_vector_files(
        vectors_dir, spec_id, version
    )

    if load_errors or payload is None or expected_bytes is None or expected_hash is None:
        return STPVectorResult(
            spec_id=spec_id,
            version=version,
            bytes_match=False,
            hash_match=False,
            computed_hash="",
            expected_hash=expected_hash or "",
            errors=load_errors,
        )

    computed_bytes = canonical_json_bytes(payload)
    computed_hash = sha256_hex(computed_bytes)

    bytes_match = computed_bytes == expected_bytes
    hash_match = computed_hash == expected_hash

    errors: list[str] = []
    if not bytes_match:
        errors.append(
            f"Canonical bytes mismatch for {spec_id} v{version}. "
            f"Computed {len(computed_bytes)} bytes, expected {len(expected_bytes)} bytes."
        )
    if not hash_match:
        errors.append(
            f"Hash mismatch for {spec_id} v{version}. "
            f"Computed {computed_hash}, expected {expected_hash}."
        )

    return STPVectorResult(
        spec_id=spec_id,
        version=version,
        bytes_match=bytes_match,
        hash_match=hash_match,
        computed_hash=computed_hash,
        expected_hash=expected_hash,
        errors=errors,
    )


def verify_stp_vectors(
    vectors_dir: Path | str | None = None,
) -> STPVectorsResult:
    """Verify all STP golden vectors.

    Args:
        vectors_dir: Path to STP vectors directory (default: bundled)

    Returns:
        STPVectorsResult with all verification details
    """
    if vectors_dir is None:
        vectors_dir = DEFAULT_STP_VECTORS_DIR
    elif isinstance(vectors_dir, str):
        vectors_dir = Path(vectors_dir)

    result = STPVectorsResult(
        valid=True,
        vectors_dir=str(vectors_dir),
        total=0,
        passed=0,
        failed=0,
    )

    if not vectors_dir.exists():
        result.valid = False
        result.errors.append(f"STP vectors directory not found: {vectors_dir}")
        return result

    # Known STP vectors to verify
    known_vectors = [
        ("agent-identity-request", "1.0.0"),
        ("agent-identity-response", "1.0.0"),
        ("execution-authorize-request", "1.0.0"),
        ("execution-authorize-response", "1.0.0"),
        ("execution-record-request", "1.0.0"),
        ("execution-record-response", "1.0.0"),
        ("execution-attest-request", "1.0.0"),
        ("execution-attest-response", "1.0.0"),
    ]

    for spec_id, version in known_vectors:
        vector_result = verify_single_stp_vector(vectors_dir, spec_id, version)
        result.results.append(vector_result)
        result.total += 1

        if vector_result.valid:
            result.passed += 1
        else:
            result.failed += 1
            result.valid = False
            result.errors.extend(vector_result.errors)

    return result
