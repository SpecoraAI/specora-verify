"""Provider audit-log reader subpackage.

Readers ingest upstream provider audit-log exports (Anthropic Compliance
API, AWS CloudTrail Lake, Azure Confidential Ledger, OpenAI Compliance
Platform, LangSmith Fleet) and map them onto the Specora wire-spec
evidence-bundle shape, without ever talking to the upstream provider's
API directly. This preserves the "offline verifier, no network calls"
posture of `specora-verify`.

Interface contract (decided 2026-04-14, see platform-repo
`docs/strategy/b01-reader-design-notes-2026-Q2.md` §9.0):

    * Subpackage: `specora_verify/readers/`
    * Interface: `ReaderProtocol` (PEP 544) + `@reader("<name>")`
      decorator registering into `READERS`
    * Error hierarchy: `ReaderError` + subclasses in `errors.py`
    * CLI: `specora-verify read <provider> --input <path> --key-id <id>`

Readers are stateless — one instance per process, reused across
invocations. The entire contract is `read(input_path, ...) -> ReadResult`.
Given identical input and parameters, `read` must produce a
byte-identical canonical bundle payload across runs (determinism
invariant, enforced by hypothesis property tests).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

__all__ = [
    "READERS",
    "ReaderProtocol",
    "ReadResult",
    "reader",
    "get_reader",
    "available_readers",
]


@dataclass(frozen=True)
class ReadResult:
    """Canonical shape every reader returns.

    Attributes:
        provider: Matches ReaderProtocol.provider_name.
        schema_version: Upstream schema version actually parsed.
        record_count: Number of decision records successfully mapped.
        bundle_payload: Canonical (wire-spec-compliant) bundle dict ready
            to be signed and written via `specora_verify.output` helpers.
        upstream_key_id: Upstream signing key ID, if the upstream provides
            per-record signatures. None if the upstream export is unsigned.
        warnings: Non-fatal issues accumulated during non-strict reads.
    """

    provider: str
    schema_version: str
    record_count: int
    bundle_payload: dict
    upstream_key_id: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)


@runtime_checkable
class ReaderProtocol(Protocol):
    """Interface every provider audit-log reader must implement."""

    provider_name: str
    provider_description: str
    supported_schema_versions: tuple[str, ...]

    def read(
        self,
        input_path: Path,
        *,
        key_id: str,
        public_key_path: Path | None = None,
        schema_version: str | None = None,
        strict: bool = True,
    ) -> ReadResult:
        ...


READERS: dict[str, ReaderProtocol] = {}


def reader(name: str) -> Callable[[type], type]:
    """Register a reader class under a provider name.

    Usage::

        @reader("anthropic")
        class AnthropicReader:
            provider_name = "anthropic"
            ...

    The decorator instantiates the class once and stores the instance in
    the `READERS` registry. CLI dispatch reads from this registry.
    """

    def decorator(cls: type) -> type:
        instance = cls()
        if not isinstance(instance, ReaderProtocol):
            raise TypeError(
                f"Reader class {cls.__name__} registered under '{name}' "
                f"does not satisfy ReaderProtocol. Required attributes: "
                f"provider_name, provider_description, supported_schema_versions, "
                f"and a read() method."
            )
        READERS[name] = instance
        return cls

    return decorator


def get_reader(name: str) -> ReaderProtocol:
    """Return the registered reader for `name`, raising KeyError if absent."""
    if name not in READERS:
        raise KeyError(
            f"No reader registered for provider '{name}'. "
            f"Available readers: {sorted(READERS)}"
        )
    return READERS[name]


def available_readers() -> list[str]:
    """Return a sorted list of registered provider names."""
    return sorted(READERS)


from specora_verify.readers import anthropic  # noqa: E402,F401  — registers "anthropic"
from specora_verify.readers import cloudtrail  # noqa: E402,F401  — registers "cloudtrail"
