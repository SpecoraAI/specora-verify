#!/usr/bin/env python3
"""Build the spec.specora.ai GitHub Pages site from the in-repo wire spec.

The hosted spec at https://spec.specora.ai/v1.0 MUST stay byte-faithful to the
authoritative source (docs/wire-spec-v1.0.md), or the "canonical mirror"
silently goes stale. This script regenerates the whole site directory from that
source; the spec-site workflow runs it on every change and pushes the result to
the gh-pages branch — so the mirror can never drift.

Usage: python scripts/build_spec_site.py <output-dir>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SPEC_SRC = REPO / "docs" / "wire-spec-v1.0.md"
GH_BLOB = "https://github.com/SpecoraAI/specora-verify/blob/main"
CUSTOM_DOMAIN = "spec.specora.ai"

# Repo-relative links in the markdown don't resolve on the Pages site, so
# rewrite them to absolute GitHub URLs. Order matters (most specific first).
LINK_REWRITES = [
    (r"\]\(\.\./specora_verify/", f"]({GH_BLOB}/specora_verify/"),
    (r"\]\(schemas/", f"]({GH_BLOB}/docs/schemas/"),
    (r"\]\((versioning-policy|trust-model|vectors)\.md", rf"]({GH_BLOB}/docs/\1.md"),
]

CONFIG_YML = (
    "title: Specora Wire Spec\n"
    "description: On-the-wire format for Specora evidence bundles "
    "— the contract specora-verify checks.\n"
    "theme: jekyll-theme-cayman\n"
)

INDEX_MD = """---
title: Specora Wire Spec
---

# Specora Wire Spec

The on-the-wire format for **Specora evidence bundles** — the signed, canonical
JSON documents that [`specora-verify`](https://github.com/SpecoraAI/specora-verify)
consumes to produce a third-party-acceptable audit opinion.

- **[Wire Spec v1.0](v1.0/)** — current ratified version.

Verify it yourself: `pip install specora-verify` then `specora-verify vectors verify`.
"""


def render_spec_page() -> str:
    body = SPEC_SRC.read_text(encoding="utf-8")
    for pattern, repl in LINK_REWRITES:
        body = re.sub(pattern, repl, body)
    banner = (
        f"> Canonical hosted mirror of "
        f"[`docs/wire-spec-v1.0.md`]({GH_BLOB}/docs/wire-spec-v1.0.md). "
        f"Authoritative source lives in the public git repo.\n\n"
    )
    return f"---\ntitle: Specora Wire Spec v1.0\n---\n\n{banner}{body}"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: build_spec_site.py <output-dir>", file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    (out / "v1.0").mkdir(parents=True, exist_ok=True)
    (out / "CNAME").write_text(f"{CUSTOM_DOMAIN}\n", encoding="utf-8")
    (out / "_config.yml").write_text(CONFIG_YML, encoding="utf-8")
    (out / "index.md").write_text(INDEX_MD, encoding="utf-8")
    (out / "v1.0" / "index.md").write_text(render_spec_page(), encoding="utf-8")
    print(f"built spec site -> {out} (v1.0 from {SPEC_SRC.relative_to(REPO)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
