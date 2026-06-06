#!/usr/bin/env python3
"""Level-4 schema-rigor audit for specora-verify.

The repo's test_wire_spec_schemas.py proves each schema ACCEPTS its golden
vector. This harness proves each schema REJECTS spec-violating mutations —
the half that actually makes §8.2 ("a verifier rejects bundles where the
JSON Schema fails") load-bearing. It introspects each schema and, walking
the instance alongside it, mutates every constrained leaf:

  * pattern  -> a string that violates the regex
  * enum     -> a value not in the enum
  * required -> drop the field
  * additionalProperties:false -> inject an unknown key

Each mutation that the schema FAILS to reject is a permissiveness finding.
It also flags hash fields whose pattern does not pin lowercase 64-hex
(§5.2), since loose hex patterns are a real content-addressing risk.

Run: /tmp/specora-qa-venv/bin/python /tmp/specora_l4_schema_fuzz.py
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[2]  # repo root (tools/qa/ -> ../../)
SCHEMAS = ROOT / "docs" / "schemas"
VECTORS = ROOT / "specora_verify" / "vectors"

PAIRS = [
    ("attestation-manifest-v1.0.json", "manifest/attestation-manifest-1.0.0.canonical.json"),
    ("proof-manifest-v1.0.json", "manifest/proof-manifest-1.0.0.canonical.json"),
    ("anchor-payload-v1.0.json", "anchor/anchor-payload-1.0.0.canonical.json"),
    ("anchor-receipt-v1.0.json", "anchor-receipts/anchor-receipt-1.0.0.canonical.json"),
    (
        "certification-attestation-v1.0.json",
        "certification/certification-attestation-1.0.0.canonical.json",
    ),
    (
        "stp-certification-attestation-v1.0.json",
        "stp-certification/compatible/stp-certification-attestation-1.0.0.canonical.json",
    ),
    ("governance-attestation-v1.0.json", "signature/signed-artifact-001/artifact.canonical.json"),
    ("signed-artifact-envelope-v1.0.json", "signature/signed-artifact-001/metadata.json"),
    (
        "canonical-bundle-v1.0.json",
        "canonical-bundle/canonical-bundle-anthropic-1.0.0.canonical.json",
    ),
    (
        "canonical-bundle-v1.1.json",
        "canonical-bundle/with-agent-identity/canonical-bundle-with-identity-1.0.0.canonical.json",
    ),
]

REJECTED = "rejected"  # schema correctly raised ValidationError (good)
ACCEPTED = "ACCEPTED"  # schema let the violation through (finding)

results = []  # (schema, path, mutation, outcome, note)
flags = []  # (schema, path, note)


def rejects(schema, instance) -> bool:
    try:
        jsonschema.validate(instance=instance, schema=schema)
        return False
    except jsonschema.ValidationError:
        return True
    except jsonschema.SchemaError as e:
        raise RuntimeError(f"schema invalid: {e}")


def set_at(obj, path, value):
    o = obj
    for k in path[:-1]:
        o = o[k]
    o[path[-1]] = value


def del_at(obj, path):
    o = obj
    for k in path[:-1]:
        o = o[k]
    del o[path[-1]]


def violate_pattern(pattern: str) -> str:
    """Produce a string guaranteed NOT to match `pattern`."""
    # universal non-match: a long string of chars unlikely in tight patterns
    cand = "ZZZ!!!___" * 9
    if not re.search(pattern, cand):
        return cand
    return "\x00bogus\x00"


def violate_enum(enum_vals):
    base = "__not_a_member__"
    if base not in enum_vals:
        return base
    return {"__nope__": True}


def walk(schema_node, inst, path, sname, root_schema, root_inst):
    """Recurse properties; at each constrained leaf, mutate and test."""
    if not isinstance(schema_node, dict):
        return
    props = schema_node.get("properties", {})
    required = schema_node.get("required", [])
    addl = schema_node.get("additionalProperties", True)

    # additionalProperties:false -> unknown key must be rejected
    if addl is False and isinstance(inst, dict):
        mut = copy.deepcopy(root_inst)
        set_at(mut, path + ["__unexpected_field__"], "x")
        outcome = REJECTED if rejects(root_schema, mut) else ACCEPTED
        results.append((sname, "/".join(map(str, path)) or ".", "unknown-property", outcome, ""))

    # required-field removal must be rejected
    for r in required:
        if isinstance(inst, dict) and r in inst:
            mut = copy.deepcopy(root_inst)
            del_at(mut, path + [r])
            outcome = REJECTED if rejects(root_schema, mut) else ACCEPTED
            results.append((sname, "/".join(map(str, path + [r])), "drop-required", outcome, ""))

    for key, subschema in props.items():
        if not isinstance(inst, dict) or key not in inst:
            continue
        p = path + [key]
        # pattern violation
        if "pattern" in subschema and isinstance(inst[key], str):
            pat = subschema["pattern"]
            mut = copy.deepcopy(root_inst)
            set_at(mut, p, violate_pattern(pat))
            outcome = REJECTED if rejects(root_schema, mut) else ACCEPTED
            results.append((sname, "/".join(map(str, p)), f"pattern≠ {pat[:24]}", outcome, ""))
            # hash-field rigor: is it pinned to lowercase 64-hex? (§5.2)
            looks_hashish = any(t in key for t in ("hash", "root", "fingerprint"))
            if looks_hashish:
                pins = "64" in pat or "{64}" in pat
                # try uppercase variant of the real value
                mut_u = copy.deepcopy(root_inst)
                val = inst[key]
                if isinstance(val, str) and re.fullmatch(r"[0-9a-f]+", val):
                    set_at(mut_u, p, val.upper())
                    up_rejected = rejects(root_schema, mut_u)
                    if not up_rejected:
                        flags.append(
                            (
                                sname,
                                "/".join(map(str, p)),
                                f"hash field accepts UPPERCASE hex (pattern={pat}); "
                                "§5.2 mandates lowercase",
                            )
                        )
                if not pins:
                    flags.append(
                        (
                            sname,
                            "/".join(map(str, p)),
                            f"hash field pattern does not pin 64-char length (pattern={pat})",
                        )
                    )
        # enum violation
        if "enum" in subschema:
            mut = copy.deepcopy(root_inst)
            set_at(mut, p, violate_enum(subschema["enum"]))
            outcome = REJECTED if rejects(root_schema, mut) else ACCEPTED
            results.append((sname, "/".join(map(str, p)), "enum-violation", outcome, ""))
        # recurse into nested objects / array items
        if subschema.get("type") == "object" or "properties" in subschema:
            walk(subschema, inst[key], p, sname, root_schema, root_inst)
        if subschema.get("type") == "array" and isinstance(inst[key], list) and inst[key]:
            items = subschema.get("items", {})
            if isinstance(items, dict) and ("properties" in items or items.get("type") == "object"):
                walk(items, inst[key][0], p + [0], sname, root_schema, root_inst)


def main():
    for sname, vrel in PAIRS:
        schema = json.loads((SCHEMAS / sname).read_text())
        inst = json.loads((VECTORS / vrel).read_bytes())
        # baseline: the golden vector must validate
        if rejects(schema, inst):
            results.append(
                (sname, ".", "BASELINE-should-accept", ACCEPTED, "golden vector rejected!")
            )
            continue
        walk(schema, inst, [], sname, schema, inst)

    width = 100
    print("=" * width)
    print("SPECORA WIRE SPEC — LEVEL 4 SCHEMA-RIGOR AUDIT (does the schema REJECT bad input?)")
    print("=" * width)
    accepted = [r for r in results if r[3] == ACCEPTED]
    by_schema = {}
    for sname, path, mut, outcome, note in results:
        by_schema.setdefault(sname, []).append((path, mut, outcome))
    for sname in [p[0] for p in PAIRS]:
        rows = by_schema.get(sname, [])
        rej = sum(1 for _, _, o in rows if o == REJECTED)
        acc = sum(1 for _, _, o in rows if o == ACCEPTED)
        status = "OK" if acc == 0 else f"*** {acc} ACCEPTED ***"
        print(f"\n{sname}   ({rej} mutations rejected, {acc} accepted)  {status}")
        for path, mut, outcome in rows:
            if outcome == ACCEPTED:
                print(f"    ACCEPTED  {path:<32} {mut}")
    print("\n" + "-" * width)
    print(
        f"total mutations: {len(results)}   rejected(good): "
        f"{sum(1 for r in results if r[3] == REJECTED)}   ACCEPTED(finding): {len(accepted)}"
    )

    if flags:
        print("\n" + "=" * width)
        print("HASH-FIELD RIGOR FLAGS (§5.2 lowercase 64-hex):")
        for sname, path, note in flags:
            print(f"  [{sname}] {path}: {note}")
    else:
        print("\nHash-field rigor: all hash/root/fingerprint patterns pin lowercase 64-hex. ✓")

    print("\n" + "=" * width)
    if accepted:
        print(f"VERDICT: {len(accepted)} schema-permissiveness finding(s) — see ACCEPTED rows.")
    else:
        print("VERDICT: every spec-violating mutation was rejected. Schemas are constraining.")
    print("=" * width)
    return 1 if accepted else 0


if __name__ == "__main__":
    raise SystemExit(main())
