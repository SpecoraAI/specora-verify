"""CI guard: no internal hostnames or internal URLs in the public repo (GAP-16).

`specora-verify` is a PUBLIC, world-readable repository. A committed internal
hostname leaks internal infrastructure topology and, worse, can mislead an
auditor into believing an endpoint is reachable when it is not. This guard
mirrors the monorepo `test_no_*` pattern; the repo's own deny-list calls for
exactly this guard post-launch.

Detected patterns (scanned across all git-tracked text files):

  * ``home.lab``  — home-lab / LAN host suffix (e.g. ``glitchtip.home.lab``)
  * ``*.internal``— internal-only DNS suffix (k8s service / corp), in a URL or
    as a multi-label host, so a Python attribute access like ``self.internal``
    is not a false positive.
  * ``localhost`` — local-bound dev services, outside ``tests/`` and a small
    explicit allowlist of intentional public local-server examples.

If this guard fails, the fix is to **remove** the internal reference, not to
extend the allowlist. The allowlist exists only for genuinely-public
local-server examples (e.g. "run the STP test server on localhost and point
the validator at it").
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent

# This guard file necessarily contains the literal patterns it bans; exclude it.
_SELF = "tests/test_no_internal_hostnames.py"

# Files where a `localhost` reference is an intentional, public part of the
# tool's documented behaviour (self-hosted local servers a user runs and points
# the verifier at). Keep this list tiny and justified.
_LOCALHOST_ALLOWLIST: frozenset[str] = frozenset(
    {
        # STP validator documents running a local STP test server on
        # localhost:8765 and pointing the validator at it. Public, intentional.
        "specora_verify/validators/stp.py",
    }
)

# Extensions that are text we care about. We also scan extensionless files
# (shell scripts, LICENSE, etc.) via a best-effort UTF-8 decode.
_BINARY_SUFFIXES = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".whl", ".gz", ".zip"}
)

_HOME_LAB = re.compile(r"home\.lab")
# `*.internal` only in URL position or as a multi-label host, to avoid matching
# Python attribute access such as `self.internal` or `obj.internal_state`.
_DOT_INTERNAL = re.compile(
    r"(?:https?://[^\s\"'`)]*\.internal\b)|(?:\b[a-z0-9-]+\.[a-z0-9-]+\.internal\b)"
)
_LOCALHOST = re.compile(r"\blocalhost\b")


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def _read_text(rel_path: str) -> str | None:
    path = _REPO_ROOT / rel_path
    if path.suffix.lower() in _BINARY_SUFFIXES:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def test_no_home_lab_or_dot_internal_hosts() -> None:
    """`home.lab` and `*.internal` hosts must never appear in tracked files."""
    violations: list[str] = []
    for rel in _tracked_files():
        if rel == _SELF:
            continue
        text = _read_text(rel)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _HOME_LAB.search(line):
                violations.append(f"{rel}:{lineno}: home.lab -> {line.strip()}")
            if _DOT_INTERNAL.search(line):
                violations.append(f"{rel}:{lineno}: *.internal -> {line.strip()}")
    assert not violations, "Internal hostnames found in public repo:\n" + "\n".join(violations)


def test_no_localhost_outside_tests_and_allowlist() -> None:
    """`localhost` must not appear outside tests/ and the explicit allowlist."""
    violations: list[str] = []
    for rel in _tracked_files():
        if rel == _SELF or rel in _LOCALHOST_ALLOWLIST:
            continue
        # Test code and fixtures legitimately bind local mock servers.
        if rel.startswith("tests/"):
            continue
        text = _read_text(rel)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _LOCALHOST.search(line):
                violations.append(f"{rel}:{lineno}: localhost -> {line.strip()}")
    assert not violations, (
        "localhost found outside tests/ and the allowlist (remove it, or — only "
        "for an intentional public local-server example — add the file to "
        "_LOCALHOST_ALLOWLIST with justification):\n" + "\n".join(violations)
    )


@pytest.mark.parametrize(
    "sample,should_flag",
    [
        ("connect to glitchtip.home.lab:9000", True),
        ("https://prspec-api.specora.internal/v1", True),
        ("postgres.db.internal:5432", True),
        ("self.internal_state = {}", False),
        ("return obj.internal", False),
        ("see api.specora.ai for the published root", False),
    ],
)
def test_internal_host_regexes_behaviour(sample: str, should_flag: bool) -> None:
    """Lock the regex behaviour so future edits do not silently widen/narrow it."""
    flagged = bool(_HOME_LAB.search(sample) or _DOT_INTERNAL.search(sample))
    assert flagged is should_flag
