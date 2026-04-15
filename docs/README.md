# Specora Verifier — Documentation

This directory is the canonical documentation tree for the Specora
independent verifier and wire spec. Everything in this tree is
normative for external integrators; everything outside this tree
(tests, fixtures, source) is implementation detail.

## What lives here

| File / directory | Purpose | Normative? |
|---|---|---|
| [`wire-spec-v1.0.md`](wire-spec-v1.0.md) | **Wire Spec v1.0** — data model, canonicalization, signing, versioning, compatibility for Specora evidence bundles. | ✅ Normative. |
| [`schemas/`](schemas/) | Machine-readable JSON Schema documents referenced from the wire spec. Each `*-v1.0.json` file is the normative schema for a single canonical payload type. | ✅ Normative. |
| [`versioning-policy.md`](versioning-policy.md) | Standalone versioning policy for the wire spec and its schemas. Referenced from §6 of the wire spec. | ✅ Normative. |
| [`quickstart.md`](quickstart.md) | "How to produce and verify an evidence bundle in 5 minutes" using the Anthropic reader. Runnable end-to-end. | Informative. |
| [`vectors.md`](vectors.md) | Guide to the `vectors/` golden-vector tree: what each subdirectory contains, how to regenerate, how to add a new vector. | Informative. |
| [`trust-model.md`](trust-model.md) | Short audit-doctrine framing: why an independent verifier is structurally required, and the four precedents (Big 4 / NRSRO / Web PKI / EU Notified Bodies). | Informative. |
| [`readers/`](readers/) | Per-provider reader guides (Anthropic first; more under EPIC-B01). Each reader doc maps a provider audit-log schema onto the wire spec. | Informative. |

## Audience

The Wire Spec is written for **three readers**, in priority order:

1. **External integrators** — anyone building a producer or verifier that needs to emit or consume evidence bundles conforming to the Specora contract. The spec is self-contained: you should be able to implement a verifier from it without reading the reference code.
2. **Auditors and regulators** — the trust-model doc and spec §9 (conformance) explain what you are signing off on when you cite "Specora Wire Spec v1.0" in an engagement letter.
3. **Reader authors** — `docs/readers/` shows how each provider audit log maps onto the wire spec.

## Where the authority lives

The **in-repo** document at `docs/wire-spec-v1.0.md` is the single
source of truth. The GitHub commit history, signed tags, and PR
review are the audit trail. The `https://spec.specora.ai/v1.0` badge
in the README is a brand surface; when/if that subdomain is
provisioned, it will serve a rendered view of this document, never a
parallel source.

See [versioning-policy.md](versioning-policy.md) for the rules that
govern how this tree evolves across v1.0.x, v1.1, and v2.0.
