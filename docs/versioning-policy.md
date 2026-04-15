# Specora Wire Spec — Versioning Policy

**Status:** Normative. Ratified 2026-04-15 alongside Wire Spec v1.0.0.

This document is the standalone version-management rule set for the
Specora Wire Spec, its JSON Schemas, and the Frozen Canonicalizer. It
is referenced from §6 of [`wire-spec-v1.0.md`](wire-spec-v1.0.md).

## 1. What this policy governs

This policy governs **five artifacts that MUST evolve in lock-step**:

1. [`docs/wire-spec-v1.0.md`](wire-spec-v1.0.md) — the normative prose.
2. [`docs/schemas/*.json`](schemas/) — the machine-readable JSON Schemas.
3. [`specora_verify/canonical.py`](../specora_verify/canonical.py) — the verifier-side canonicalization reference.
4. [`services/prspec-api/src/prspec_api/agent_execution/canonicalizer.py`](https://github.com/SpecoraAI/specora-platform/blob/main/services/prspec-api/src/prspec_api/agent_execution/canonicalizer.py) — the producer-side **Frozen Canonicalizer** (v1.0.0, ratified 2026-03-04, commit `a0b1af5e`).
5. [`formal/lean/Specora/Canonicalizer.lean`](https://github.com/SpecoraAI/specora-platform/blob/main/formal/lean/Specora/Canonicalizer.lean) — the formal proof.

Drift between any two of these is a **process failure**, not a bug.
The versioning policy exists to make drift structurally hard.

## 2. Semantic versioning

The wire spec follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) with the additional rules in §3–§5 below.

### 2.1 Patch — v1.0.x

**What it MAY change:** prose clarifications, typos, example fixes, non-normative references, `README.md`-style cleanups inside the spec document itself.

**What it MUST NOT change:** any schema file; any field definition; any canonicalization rule; any signing rule; any MUST/SHOULD/MAY statement; the compatibility matrix; the set of canonical payload types; the Frozen Canonicalizer.

**Review requirement:** Engineering lead sign-off. No CEO sign-off required. No Formal methods reviewer sign-off required.

**Release cadence:** as needed. Patch releases are cheap and encouraged.

### 2.2 Minor — v1.1, v1.2, ...

**What it MAY change:** add a new optional field to an existing payload; add a new payload type; add a new permitted value to an existing enum **only if** the enum's `default` interpretation is unambiguous under v1.0 reading; add a new `signature_covers` value; add a new reference in §9.

**What it MUST NOT change:** remove a field; narrow a field's type; change canonicalization rules in a way that alters byte output for any existing v1.0 payload; change the signing algorithm; change the hash algorithm; break a previously-valid v1.0.x vector.

**Review requirement:** Engineering lead + CEO sign-off. Formal methods reviewer sign-off is REQUIRED if the change touches canonicalization (§3 of the spec) or signing (§4 of the spec). The Lean proof MUST be re-run and any failing lemmas MUST be updated before merge.

**Backward compatibility gate:** Every existing v1.0 golden vector MUST still validate under the v1.1 schemas. The existing `tests/test_wire_spec_schemas.py` test is the automated gate — the test MUST continue to pass with v1.1 schemas checked in.

**Frozen Canonicalizer rule:** If v1.1 touches canonicalization or signing, the Frozen Canonicalizer version MUST be bumped in the same session, in a co-updated PR that lands the canonicalizer bump and the wire-spec bump as a single atomic commit (or two commits in the same PR). A wire-spec v1.1 without a matching canonicalizer bump — or a canonicalizer v1.1 without a matching wire-spec bump — is a process violation.

### 2.3 Major — v2.0, v3.0, ...

**What it MAY change:** anything.

**What it MUST still provide:** a documented migration path for existing v1.x bundles. "Drop support" is not a migration path.

**Review requirement:** CEO + Formal methods reviewer sign-off. Engineering lead sign-off is necessary but not sufficient. A new Lean proof MUST exist for the new canonicalization before merge.

**Backward compatibility gate:** None. v1.x vectors are NOT required to validate under v2.0 schemas. v1.x verifiers are NOT required to handle v2.0 bundles.

**Release cadence:** rare. v2.0 is reserved for changes that cannot fit inside the v1.x shape. The expected frequency is measured in years.

## 3. The Frozen Canonicalizer rule

The Frozen Canonicalizer (§1 item 4 above) is load-bearing for this
policy. It is **frozen** in the sense that:

- Its file content at commit `a0b1af5e` is the normative v1.0.0 reference.
- Any change to that file in the monorepo is, by definition, a
  canonicalizer version bump.
- A canonicalizer version bump that does not correspond to a wire-spec
  version bump is a **process violation** and MUST be reverted before
  the next commit window.
- A wire-spec minor-or-major bump that touches §3 of the spec MUST
  include a canonicalizer version bump in the same PR.

This rule is enforced at two layers:

1. **CLAUDE.md** ["CRITICAL: Mandatory Dual Audit Before Commit"](../../../Users/chosone/Documents/CVC/Projects/software-automate/CLAUDE.md) block — IAP Stage 1 flags any canonicalizer delta; CSEA Stage 5 flags any wire-spec delta without a matching canonicalizer delta.
2. **This document** — human review under the Review Requirement clause above.

## 4. Schema evolution

JSON Schemas under `docs/schemas/` follow the same SemVer contract as
the prose spec, with an additional rule: **every schema filename
includes the major.minor version**. The v1.0 schemas are named
`*-v1.0.json`. v1.1 additions will be named `*-v1.1.json` and will
coexist with the v1.0 copies.

Removal of a schema file is a v2.0 operation.

## 5. Compatibility matrix

The compatibility matrix in §7 of the wire spec is the authoritative
map from spec version → schema files → canonicalizer version →
minimum verifier CLI version. Every minor and major release MUST
append a row. Patch releases MUST NOT modify existing rows.

## 6. Deprecation policy

A field or payload type MAY be marked `deprecated` in a minor release.
A deprecated field MUST continue to validate for the full remainder
of the major version in which it was deprecated. Removal is a v2.0
operation.

The policy is deliberately strict because every external integrator
has written code against the current shape; we cannot remove fields
without a major bump without violating the independent-verifier
posture this whole program rests on.

## 7. Security fixes

A security fix that requires a normative change (e.g., a new signing
algorithm because Ed25519 is broken) is **always** a major bump. It
does not matter whether the fix is "small." Security-motivated
breaking changes still follow §2.3.

A security fix that does not require a normative change (e.g., a
tighter validator rule that rejects bundles the spec already said
were invalid) is a patch bump.

## 8. Change log

| Date | Change | By |
|---|---|---|
| 2026-04-15 | Versioning policy ratified alongside Wire Spec v1.0.0. Establishes patch/minor/major semantics, Frozen Canonicalizer lock-step rule, schema-filename convention, security-fix classification. | A02 emergency execution session + Engineering lead |
