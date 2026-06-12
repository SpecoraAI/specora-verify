#!/usr/bin/env python3
"""Build the spec.specora.ai GitHub Pages site from the in-repo wire spec.

The hosted spec at https://spec.specora.ai/v1.0 MUST stay byte-faithful to the
authoritative source (docs/wire-spec-v1.0.md), or the "canonical mirror"
silently goes stale. This script regenerates the whole site directory from that
source; the spec-site workflow runs it on every change and pushes the result to
the gh-pages branch — so the mirror can never drift.

The site is branded (Specora navy + the brand logo, assets under
scripts/spec_site_assets/), rendered through a self-contained Jekyll layout —
no remote theme.

Usage: python scripts/build_spec_site.py <output-dir>
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SPEC_SRC = REPO / "docs" / "wire-spec-v1.0.md"
ASSETS_SRC = Path(__file__).resolve().parent / "spec_site_assets"
GH_BLOB = "https://github.com/SpecoraAI/specora-verify/blob/main"
CUSTOM_DOMAIN = "spec.specora.ai"

# Repo-relative links in the markdown don't resolve on the Pages site, so
# rewrite them to absolute GitHub URLs. Order matters (most specific first).
LINK_REWRITES = [
    (r"\]\(\.\./specora_verify/", f"]({GH_BLOB}/specora_verify/"),
    (r"\]\(schemas/", f"]({GH_BLOB}/docs/schemas/"),
    (r"\]\((versioning-policy|trust-model|vectors)\.md", rf"]({GH_BLOB}/docs/\1.md"),
]

CONFIG_YML = """\
title: Specora Wire Spec
description: On-the-wire format for Specora evidence bundles — what specora-verify checks.
markdown: kramdown
defaults:
  - scope:
      path: ""
    values:
      layout: default
"""

LAYOUT_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ page.title | default: site.title }}</title>
  <meta name="description" content="{{ site.description }}">
  <link rel="icon" type="image/svg+xml" href="{{ '/assets/favicon.svg' | relative_url }}">
  <link rel="stylesheet" href="{{ '/assets/css/style.css' | relative_url }}">
</head>
<body>
  <header class="hero">
    <div class="wrap">
      <a class="brand" href="{{ '/' | relative_url }}" aria-label="Specora">
        <img class="logo" src="{{ '/assets/logo-white.svg' | relative_url }}" alt="Specora">
      </a>
      <p class="tagline">{{ site.description }}</p>
      <nav class="actions">
        <a class="btn" href="https://github.com/SpecoraAI/specora-verify">View on GitHub</a>
        <a class="btn btn-ghost"
           href="https://pypi.org/project/specora-verify/">Install from PyPI</a>
      </nav>
    </div>
  </header>
  <main class="wrap content">
    {{ content }}
  </main>
  <footer class="site-footer">
    <div class="wrap">
      <strong>specora-verify</strong> &middot;
      maintained by <a href="https://github.com/SpecoraAI">SpecoraAI</a> &middot;
      <a href="https://github.com/SpecoraAI/specora-verify">source</a> &middot;
      Apache-2.0
    </div>
  </footer>
</body>
</html>
"""

STYLE_CSS = """\
:root {
  --navy: #0a1a2f;
  --navy-2: #13283f;
  --ink: #1b2430;
  --muted: #5b6b7c;
  --accent: #2f6fed;
  --line: #e6eaf0;
  --code-bg: #f5f7fa;
  --max: 820px;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  color: var(--ink);
  font: 16px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        Helvetica, Arial, sans-serif;
  background: #fff;
}
.wrap { max-width: var(--max); margin: 0 auto; padding: 0 24px; }

/* Hero */
.hero {
  background: linear-gradient(160deg, var(--navy) 0%, var(--navy-2) 100%);
  color: #fff;
  padding: 56px 0 48px;
  text-align: center;
  border-bottom: 3px solid var(--accent);
}
.hero .brand { display: inline-block; }
.hero .logo { width: 280px; max-width: 70vw; height: auto; }
.hero .tagline {
  margin: 22px auto 26px;
  max-width: 640px;
  color: #c7d3e2;
  font-size: 1.05rem;
}
.actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
.btn {
  display: inline-block;
  padding: 9px 18px;
  border-radius: 8px;
  font-weight: 600;
  font-size: .94rem;
  text-decoration: none;
  background: var(--accent);
  color: #fff;
  border: 1px solid var(--accent);
  transition: opacity .15s ease;
}
.btn:hover { opacity: .9; }
.btn-ghost { background: transparent; color: #fff; border-color: rgba(255,255,255,.35); }
.btn-ghost:hover { border-color: #fff; }

/* Content */
.content { padding: 48px 24px 64px; }
.content h1, .content h2, .content h3, .content h4 {
  color: var(--navy);
  line-height: 1.25;
  margin: 2em 0 .6em;
  font-weight: 700;
}
.content h1 { font-size: 2rem; margin-top: .2em; }
.content h2 { font-size: 1.5rem; padding-bottom: .3em; border-bottom: 1px solid var(--line); }
.content h3 { font-size: 1.2rem; }
.content p, .content li { color: var(--ink); }
.content a { color: var(--accent); text-decoration: none; }
.content a:hover { text-decoration: underline; }
.content hr { border: 0; border-top: 1px solid var(--line); margin: 2.4em 0; }

.content code {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .88em;
  background: var(--code-bg);
  padding: .15em .4em;
  border-radius: 5px;
}
.content pre {
  background: var(--code-bg);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 16px 18px;
  overflow: auto;
}
.content pre code { background: none; padding: 0; }

.content table {
  border-collapse: collapse;
  width: 100%;
  margin: 1.4em 0;
  font-size: .94rem;
  display: block;
  overflow-x: auto;
}
.content th, .content td { border: 1px solid var(--line); padding: 8px 12px; text-align: left; }
.content th { background: #f0f4f9; color: var(--navy); font-weight: 600; }
.content tr:nth-child(even) td { background: #fafbfd; }

.content blockquote {
  margin: 1.4em 0;
  padding: 2px 18px;
  border-left: 4px solid var(--accent);
  background: #f7f9fc;
  color: var(--muted);
}
.content blockquote p { margin: .7em 0; }

/* Footer */
.site-footer {
  border-top: 1px solid var(--line);
  padding: 28px 0 40px;
  color: var(--muted);
  font-size: .9rem;
  text-align: center;
}
.site-footer a { color: var(--muted); }
.site-footer a:hover { color: var(--navy); }

@media (max-width: 600px) {
  .hero { padding: 40px 0 36px; }
  .content { padding: 32px 20px 48px; }
}
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


INDEX_MD = """\
---
title: Specora Wire Spec
---

# Specora Wire Spec

The on-the-wire format for **Specora evidence bundles** — the signed, canonical
JSON documents that [`specora-verify`](https://github.com/SpecoraAI/specora-verify)
consumes to produce a third-party-acceptable audit opinion.

- **[Wire Spec v1.0](v1.0/)** — current ratified version.

Verify it yourself: `pip install specora-verify` then `specora-verify vectors verify`.
"""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: build_spec_site.py <output-dir>", file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    (out / "v1.0").mkdir(parents=True, exist_ok=True)
    (out / "_layouts").mkdir(parents=True, exist_ok=True)
    (out / "assets" / "css").mkdir(parents=True, exist_ok=True)

    (out / "CNAME").write_text(f"{CUSTOM_DOMAIN}\n", encoding="utf-8")
    (out / "_config.yml").write_text(CONFIG_YML, encoding="utf-8")
    (out / "_layouts" / "default.html").write_text(LAYOUT_HTML, encoding="utf-8")
    (out / "assets" / "css" / "style.css").write_text(STYLE_CSS, encoding="utf-8")
    (out / "index.md").write_text(INDEX_MD, encoding="utf-8")
    (out / "v1.0" / "index.md").write_text(render_spec_page(), encoding="utf-8")

    # Brand assets (logo + favicon), committed under scripts/spec_site_assets/.
    for name in ("logo-white.svg", "logo-navy.svg", "favicon.svg"):
        shutil.copyfile(ASSETS_SRC / name, out / "assets" / name)

    print(f"built branded spec site -> {out} (v1.0 from {SPEC_SRC.relative_to(REPO)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
