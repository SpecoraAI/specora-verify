"""Specora Trust Protocol Contracts.

Local copies of STP enums and constants for CLI independence.
This allows specora-verify to validate STP messages without
without depending on any internal Specora package.

These values are the normative reference from Specora Wire Spec v1.0 Annex E.
"""

from __future__ import annotations

from typing import Dict, List, Set

# =============================================================================
# Protocol Constants (Frozen)
# =============================================================================

STP_PROTOCOL_VERSION = "1.0.0"
"""Protocol version - frozen, immutable."""

STP_SCHEMA_VERSION = 1
"""Schema version for Pydantic models."""

STP_NAMESPACE = "57700000-5770-4570-8d1a-570000000700"
"""UUID namespace for deterministic ID generation - frozen."""


# =============================================================================
# Message Types (4 values)
# =============================================================================

STP_MESSAGE_TYPES: List[str] = [
    "agent.identity",
    "execution.authorize",
    "execution.record",
    "execution.attest",
]

STP_RESPONSE_TYPES: List[str] = [
    "agent.identity.response",
    "execution.authorize.response",
    "execution.record.response",
    "execution.attest.response",
]


# =============================================================================
# Decisions (4 values)
# =============================================================================

STP_DECISIONS: List[str] = [
    "allow",
    "block",
    "require_approval",
    "restrict",
]


# =============================================================================
# Runtime Types (10 values)
# =============================================================================

STP_RUNTIME_TYPES: List[str] = [
    # Coding Tools
    "cursor",
    "aider",
    "codex_cli",
    "claude_code",
    "windsurf",
    # Agent Frameworks
    "langgraph",
    "crewai",
    "autogen",
    # Enterprise
    "temporal",
    # Generic
    "custom",
]


# =============================================================================
# Capabilities (12 values)
# =============================================================================

STP_CAPABILITIES: List[str] = [
    # Read Operations
    "read_documents",
    "read_code",
    "read_data",
    # Write Operations
    "write_code",
    "write_documents",
    "write_data",
    # Execute Operations
    "execute_code",
    "execute_commands",
    # External Operations
    "invoke_models",
    "access_network",
    "access_database",
    # Privileged Operations
    "privileged_operations",
]


# =============================================================================
# Action Types (15 values)
# =============================================================================

STP_ACTION_TYPES: List[str] = [
    # Code Operations
    "code_read",
    "code_edit",
    "code_execute",
    # File Operations
    "file_read",
    "file_write",
    # Model Operations
    "model_invoke",
    # System Operations
    "command_execute",
    "network_request",
    # Non-LLM Actions (PLATFORM-460)
    "deploy_service",
    "database_operation",
    "document_access",
    "workflow_execution",
    "agent_coordination",
    "secret_access",
    "human_approval_request",
]

STP_NON_LLM_ACTION_TYPES: Set[str] = {
    "deploy_service",
    "database_operation",
    "document_access",
    "workflow_execution",
    "agent_coordination",
    "secret_access",
    "human_approval_request",
}


# =============================================================================
# Execution Status (5 values)
# =============================================================================

STP_EXECUTION_STATUSES: List[str] = [
    "success",
    "failure",
    "timeout",
    "cancelled",
    "partial",
]


# =============================================================================
# Attestation Status (4 values)
# =============================================================================

STP_ATTESTATION_STATUSES: List[str] = [
    "pending",
    "signed",
    "verified",
    "invalid",
]


# =============================================================================
# Backend Types (6 values) - PLATFORM-460
# =============================================================================

STP_BACKEND_TYPES: List[str] = [
    "llm",
    "local_model",
    "fine_tuned",
    "tool_api",
    "workflow_engine",
    "human_operator",
]

STP_NON_LLM_BACKEND_TYPES: Set[str] = {
    "tool_api",
    "workflow_engine",
    "human_operator",
}


# =============================================================================
# Schema Requirements
# =============================================================================

# Required fields by message type
STP_REQUIRED_FIELDS: Dict[str, List[str]] = {
    "agent.identity": [
        "protocol_version",
        "message_type",
        "timestamp",
        "payload",
    ],
    "agent.identity.response": [
        "protocol_version",
        "message_type",
        "timestamp",
        "result",
    ],
    "execution.authorize": [
        "protocol_version",
        "message_type",
        "timestamp",
        "payload",
    ],
    "execution.authorize.response": [
        "protocol_version",
        "message_type",
        "timestamp",
        "result",
    ],
    "execution.record": [
        "protocol_version",
        "message_type",
        "timestamp",
        "payload",
    ],
    "execution.record.response": [
        "protocol_version",
        "message_type",
        "timestamp",
        "result",
    ],
    "execution.attest": [
        "protocol_version",
        "message_type",
        "timestamp",
        "payload",
    ],
    "execution.attest.response": [
        "protocol_version",
        "message_type",
        "timestamp",
        "result",
    ],
}

# Payload required fields by message type
STP_PAYLOAD_REQUIRED_FIELDS: Dict[str, List[str]] = {
    "agent.identity": [
        "agent_name",
        "runtime",
    ],
    "execution.authorize": [
        "agent_identity_id",
        "action_type",
    ],
    "execution.record": [
        "authorization_id",
        "status",
    ],
    "execution.attest": [
        "execution_ids",
    ],
}

# Result required fields by message type
STP_RESULT_REQUIRED_FIELDS: Dict[str, List[str]] = {
    "agent.identity.response": [
        "agent_identity_id",
        "trust_tier",
        "trust_score",
        "lifecycle_state",
    ],
    "execution.authorize.response": [
        "decision",
    ],
    "execution.record.response": [
        "recorded",
    ],
    "execution.attest.response": [
        "attestation_bundle",
    ],
}


# =============================================================================
# Cardinality Validation
# =============================================================================

def get_total_enum_cardinality() -> int:
    """Get total cardinality of all STP enums.

    Returns:
        Total number of unique enum values

    Invariant: INV-STP-CARD-001
        Must not exceed 100 to prevent Prometheus explosion.
    """
    return (
        len(STP_MESSAGE_TYPES)
        + len(STP_DECISIONS)
        + len(STP_RUNTIME_TYPES)
        + len(STP_CAPABILITIES)
        + len(STP_ACTION_TYPES)
        + len(STP_EXECUTION_STATUSES)
        + len(STP_ATTESTATION_STATUSES)
        + len(STP_BACKEND_TYPES)
    )


def validate_enum_cardinality() -> bool:
    """Validate enum cardinality is within bounds.

    Returns:
        True if cardinality is safe (< 100)

    Raises:
        AssertionError: If cardinality exceeds limit
    """
    total = get_total_enum_cardinality()
    max_cardinality = 100
    assert total < max_cardinality, (
        f"STP enum cardinality {total} exceeds limit {max_cardinality}"
    )
    return True


# Validate cardinality on import
_cardinality = get_total_enum_cardinality()
assert _cardinality < 100, f"STP enum cardinality {_cardinality} exceeds 100"
