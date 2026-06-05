#!/usr/bin/env python3
"""Run the independent QA harnesses (L2/L3/L4) and report a combined verdict.

These harnesses verify the tool the way a skeptical third party would —
they do NOT trust the project's own pytest suite:

  L2  l2-go/main.go        independent Go reimplementation; byte-parity of
                           canonicalize+hash+verify against the 18 golden
                           vectors (needs `go`; skipped with a notice if absent).
  L3  l3_adversarial.py    mints valid signatures/certs with a fresh keypair,
                           then tampers and asserts every forgery is rejected.
  L4  l4_schema_fuzz.py    mutates every constrained schema leaf and asserts
                           the JSON Schema rejects each spec violation
                           (needs `jsonschema`).

L1 (the online distribution gate) is intentionally separate — run
`check_l1_distribution.py`, since it is the one inherently-online check.

Exit 0 only if every available harness passes.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(label: str, argv: list[str], cwd: Path | None = None) -> int:
    print("\n" + "#" * 78)
    print(f"# {label}")
    print("#" * 78)
    proc = subprocess.run(argv, cwd=str(cwd) if cwd else None)
    return proc.returncode


def main() -> int:
    py = sys.executable
    rc = {}

    rc["L3 adversarial"] = run(
        "L3 — adversarial forgery harness", [py, str(HERE / "l3_adversarial.py")]
    )
    rc["L4 schema-fuzz"] = run(
        "L4 — schema-rigor fuzzer", [py, str(HERE / "l4_schema_fuzz.py")]
    )

    if shutil.which("go"):
        rc["L2 byte-parity"] = run(
            "L2 — independent Go byte-parity",
            ["go", "run", "main.go"],
            cwd=HERE / "l2-go",
        )
    else:
        print("\n[L2] 'go' not found on PATH — skipping the independent "
              "byte-parity harness. Install Go to run it.")
        rc["L2 byte-parity"] = None

    print("\n" + "=" * 78)
    print("COMBINED QA VERDICT")
    print("=" * 78)
    failed = []
    for label, code in rc.items():
        if code is None:
            status = "SKIPPED"
        elif code == 0:
            status = "PASS"
        else:
            status = "FAIL"
            failed.append(label)
        print(f"  {label:<22} {status}")
    print("=" * 78)
    if failed:
        print(f"RESULT: FAIL ({', '.join(failed)})")
        return 1
    print("RESULT: all available harnesses PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
