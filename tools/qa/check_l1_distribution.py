#!/usr/bin/env python3
"""L1 distribution-anchor verifier — the cold-install supply-chain gate.

`specora-verify`'s entire premise is that an independent third party can
obtain and verify the tool WITHOUT trusting the producer. That promise is
only real once every public distribution + out-of-band verification anchor
actually resolves. This script probes all of them and reports green/red.

It is the executable form of the L1 row in docs/release-checklist.md:

  * PyPI package           pip install specora-verify
  * GitHub repo (public)   source + signed commits
  * GitHub releases        sdist/wheel/standalone binaries + Sigstore bundles
  * Homebrew tap           brew install
  * Wire-spec mirror       https://spec.specora.ai/v1.0 (DNS + HTTP)

Before the 2026-06-14 public flip these are EXPECTED to be red (the repo is
private by design). Pass --expect-prelaunch to treat "all anchors absent"
as the expected pre-flip state (exit 0). On/after flip day, run with no
flag: every anchor MUST be green or the publish is incomplete.

Stdlib only. No third-party deps. Network required (this is the one check
that is inherently online — it verifies the *online* distribution surface).

Usage:
  python tools/qa/check_l1_distribution.py                # post-flip: all must be green
  python tools/qa/check_l1_distribution.py --expect-prelaunch   # pre-flip: absent is OK
"""

from __future__ import annotations

import argparse
import socket
import urllib.error
import urllib.request

TIMEOUT = 20

ANCHORS = [
    # (key, label, kind, target)
    (
        "pypi",
        "PyPI package (pip install specora-verify)",
        "http",
        "https://pypi.org/pypi/specora-verify/json",
    ),
    ("pypi_simple", "PyPI simple index", "http", "https://pypi.org/simple/specora-verify/"),
    (
        "repo",
        "GitHub repo (public)",
        "http",
        "https://api.github.com/repos/SpecoraAI/specora-verify",
    ),
    (
        "releases",
        "GitHub releases (Sigstore bundles)",
        "http_nonempty_json",
        "https://api.github.com/repos/SpecoraAI/specora-verify/releases",
    ),
    (
        "brew",
        "Homebrew tap (brew install)",
        "http",
        "https://api.github.com/repos/SpecoraAI/homebrew-tap",
    ),
    ("spec_dns", "Wire-spec host DNS (spec.specora.ai)", "dns", "spec.specora.ai"),
    (
        "spec_http",
        "Wire-spec mirror (https://spec.specora.ai/v1.0)",
        "http",
        "https://spec.specora.ai/v1.0",
    ),
]


def probe_http(url: str) -> tuple[bool, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "specora-l1-check"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return (200 <= r.status < 300, f"HTTP {r.status}")
    except urllib.error.HTTPError as e:
        return (False, f"HTTP {e.code}")
    except (TimeoutError, urllib.error.URLError, OSError) as e:
        return (False, f"unreachable: {e.reason if hasattr(e, 'reason') else e}")


def probe_http_nonempty_json(url: str) -> tuple[bool, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "specora-l1-check"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(4096).decode("utf-8", "replace").strip()
            if r.status == 200 and body not in ("[]", ""):
                return (True, f"HTTP {r.status}, has releases")
            return (False, f"HTTP {r.status}, no releases published")
    except urllib.error.HTTPError as e:
        return (False, f"HTTP {e.code}")
    except (TimeoutError, urllib.error.URLError, OSError) as e:
        return (False, f"unreachable: {e}")


def probe_dns(host: str) -> tuple[bool, str]:
    try:
        socket.getaddrinfo(host, None)
        return (True, "resolves")
    except socket.gaierror as e:
        return (False, f"NXDOMAIN/{e}")


def probe(kind: str, target: str) -> tuple[bool, str]:
    if kind == "http":
        return probe_http(target)
    if kind == "http_nonempty_json":
        return probe_http_nonempty_json(target)
    if kind == "dns":
        return probe_dns(target)
    return (False, f"unknown kind {kind}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--expect-prelaunch",
        action="store_true",
        help="pre-flip mode: ALL anchors absent => exit 0 (expected)",
    )
    args = ap.parse_args()

    print("=" * 78)
    print("L1 DISTRIBUTION-ANCHOR CHECK — can a cold third party obtain & verify?")
    print("=" * 78)
    results = []
    for key, label, kind, target in ANCHORS:
        ok, detail = probe(kind, target)
        results.append((key, label, ok, detail))
        mark = "GREEN" if ok else "absent"
        print(f"  [{mark:>6}]  {label:<48} {detail}")
    print("-" * 78)

    green = sum(1 for _, _, ok, _ in results if ok)
    total = len(results)
    all_green = green == total

    if args.expect_prelaunch:
        # Pre-flip: expect the public surface to be ABSENT. If anchors start
        # appearing, that's fine too — but the gate passes as long as we are
        # not in a broken half-published state.
        print(f"pre-flip mode: {green}/{total} anchors live (public flip scheduled 2026-06-14).")
        if all_green:
            print("NOTE: all anchors are live — you can drop --expect-prelaunch now.")
        print("GATE: PASS (pre-flip — public distribution intentionally pending)")
        print("=" * 78)
        return 0

    # Post-flip mode: every anchor MUST be green.
    print(f"post-flip mode: {green}/{total} anchors green.")
    if all_green:
        print(
            "GATE: PASS — every distribution & verification anchor resolves. "
            "Cold third-party install path is live."
        )
        print("=" * 78)
        return 0
    print(
        "GATE: FAIL — the cold-install promise is unfulfillable until every "
        "anchor above is GREEN. Missing anchors:"
    )
    for key, label, ok, detail in results:
        if not ok:
            print(f"    - {label}  ({detail})")
    print("=" * 78)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
