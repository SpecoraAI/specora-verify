"""Wiring guards for the release / Sigstore identity-pinning constants.

These assert that ``specora_verify.release``'s identity constants actually
describe *this* repository and *this* repo's release workflow. They have no
third-party dependency (no sigstore), so they always run.

Motivation: the constants shipped pointing at a different repo
(``specora/software-automate``) and a non-existent workflow
(``specora-verify-release.yml``), which would have made every published,
signed release fail third-party verification. A green test suite never
noticed, because nothing checked the constants against reality. These do.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from specora_verify import release

REPO_ROOT = Path(__file__).resolve().parents[1]


def _repo_owner_and_name() -> tuple[str, str]:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    repo_url = data["project"]["urls"]["Repository"]  # https://github.com/<owner>/<repo>
    owner, repo = repo_url.rstrip("/").split("/")[-2:]
    return owner, repo


def test_owner_and_repo_match_pyproject() -> None:
    owner, repo = _repo_owner_and_name()
    assert release.GITHUB_OWNER == owner, (
        f"GITHUB_OWNER={release.GITHUB_OWNER!r} != pyproject Repository owner {owner!r}"
    )
    assert release.GITHUB_REPO == repo, (
        f"GITHUB_REPO={release.GITHUB_REPO!r} != pyproject Repository name {repo!r}"
    )
    assert release.SIGSTORE_EXPECTED_REPOSITORY == f"{owner}/{repo}"


def test_pinned_signing_workflow_exists() -> None:
    """The workflow the Sigstore identity is pinned to must be a real file."""
    workflow = REPO_ROOT / release.SIGSTORE_WORKFLOW_PATH
    assert workflow.exists(), f"pinned signing workflow missing: {workflow}"


def test_cert_identity_pattern_is_internally_consistent() -> None:
    identity = release.SIGSTORE_CERT_IDENTITY_PATTERN.format(version="1.2.3")
    assert identity == (
        f"https://github.com/{release.GITHUB_OWNER}/{release.GITHUB_REPO}/"
        f"{release.SIGSTORE_WORKFLOW_PATH}@refs/tags/v1.2.3"
    )


def test_pinned_workflow_triggers_on_the_expected_tag_scheme() -> None:
    """The identity pins ``@refs/tags/v{version}``; the pinned workflow must
    actually fire on that ``v*`` tag scheme, or no release run would ever
    produce a matching certificate identity."""
    workflow_text = (REPO_ROOT / release.SIGSTORE_WORKFLOW_PATH).read_text()
    assert "refs/tags/v" in workflow_text or '"v*"' in workflow_text or "'v*'" in workflow_text, (
        "pinned workflow does not appear to trigger on v* tags — identity "
        "pattern and workflow trigger have diverged"
    )
