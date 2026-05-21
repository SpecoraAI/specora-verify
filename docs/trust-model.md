# Trust model — why an independent verifier is structurally required

This document is the 1–2 page framing of **why** Specora exists as a
third-party verifier rather than as a feature inside an AI model
vendor's platform. It is written for auditors, regulators, and
external integrators who need to decide whether the Specora wire
spec and verifier are something they can stand behind.

If you are an implementer looking for the normative contract, read
[wire-spec-v1.0.md](wire-spec-v1.0.md) instead. This document is
informative.

## 1. The structural argument

You cannot audit yourself. This is not a slogan; it is the reason
every modern market with stakes requires an **independent** auditor
whose incentives are structurally separate from the party being
audited.

AI systems that act on behalf of enterprises are now at the stakes
threshold. An AI agent that moves money, sends an email, writes a
database, or answers a regulator is taking actions whose
consequences a human will eventually be asked about. The question
"did this AI behave correctly?" is no longer rhetorical; it is a
compliance artifact in every major jurisdiction (EU AI Act risk
classification, NIST AI RMF, ISO/IEC 42001, SEC cybersecurity
disclosure, HIPAA reasonable safeguards, the NYC AEDT law, and
more).

When a producer of an AI action is also the party asserting that the
action was compliant, the incentive to describe the action favorably
is structural, not moral. It is the same problem that produced every
independent-auditor market in history. The structural fix is an
**out-of-band** verifier: a party that consumes the producer's
audit-log exhaust, re-canonicalizes it, and issues a
cryptographically-anchored opinion that the producer cannot rewrite.

That is what Specora is. The wire spec in this directory is the
on-the-wire contract that makes out-of-band verification possible.

## 2. Four precedents

Specora's structural shape is not novel. Every comparable
independent-verification market has converged on the same pattern:

### 2.1 Big Four audit firms (financial statements)

Public companies cannot issue their own audited financials. A
structurally separate firm (PwC, EY, Deloitte, KPMG) issues the
audit opinion. The auditor's liability is separate; the auditor's
revenue comes from a different contract. The auditor's opinion is
what a regulator, an investor, or a lender relies on. The producer
cannot rewrite the opinion. **Specora is the Big Four for AI.**

### 2.2 NRSROs (credit ratings)

Nationally Recognized Statistical Rating Organizations (Moody's,
S&P, Fitch) issue credit ratings on debt instruments. The issuer of
the debt pays, but the rating is the rater's property, not the
issuer's. The SEC recognizes a specific, small list of NRSROs
because structural independence is what makes the rating credible
to the market. **Specora's trust-bootstrap arc (CNCF hosting →
external audit → public signing ceremony → EU AI Act Notified Body
scoping) is the same recognition arc.**

### 2.3 Web PKI (TLS certificate transparency)

The Web PKI ecosystem rests on two structurally separate primitives:
certificate authorities that issue certificates, and transparency
logs ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)) that
record every issued certificate for public audit. A certificate
whose issuance is not in a transparency log is not trusted by
modern browsers. The log operator is structurally separate from
the certificate authority. **The Specora anchor / anchor-receipt
payloads (§2.4, §2.5 of the wire spec) are direct prior art from
this pattern — a canonical payload, committed to a transparency
log run by a party who is not the producer.**

### 2.4 EU Notified Bodies (product conformity)

Under the EU AI Act, high-risk AI systems must be conformity-assessed
before placement on the market. The assessment is performed by a
**Notified Body** — a structurally separate organization designated
by a member state, periodically re-reviewed, with legally prescribed
independence criteria. The producer of the AI system cannot be its
own Notified Body. **Specora's 2026-Q4 EU AI Act Notified Body
scoping workstream is the direct application of this pattern.**

These four precedents are not cherry-picked. They are the exhaustive
list of modern markets that have successfully solved the
"independent verification of a producer's claims" problem. Every one
of them has the same shape: structural separation + public record
+ named liability. Specora inherits all three.

## 3. What Specora explicitly is, and is not

**Specora is:** an out-of-band verifier for AI governance claims. It
consumes provider audit logs (Anthropic Compliance API, AWS
CloudTrail Lake, Azure Confidential Ledger, OpenAI Compliance
Platform, LangSmith Fleet export — the first of these ships in
[EPIC-A03](https://github.com/SpecoraAI/specora-platform/blob/main/docs/strategy/category-switch-epic-suite.md#epic-a03--first-provider-audit-log-reader-anthropic-compliance-api----done-2026-04-15);
the remaining four in EPIC-B01), normalizes them via the readers in
[`docs/readers/`](readers/), canonicalizes the result per
[§3 of the wire spec](wire-spec-v1.0.md#3-canonicalization), signs
with Ed25519 per [§4](wire-spec-v1.0.md#4-signing), and produces
evidence bundles an auditor can cite in an engagement letter.

**Specora is not:** an inline guardrail, a proxy, a policy engine, a
model-safety filter, a prompt-injection detector, a DLP system, or a
governance dashboard. Those products compete in the inline-enforcement
category, which Specora has deliberately exited (see
[`docs/strategy/category-switch-epic-suite.md`](https://github.com/SpecoraAI/specora-platform/blob/main/docs/strategy/category-switch-epic-suite.md)
§1.2). The category switch is not "expand to verification too"; it
is "move entirely to the structurally-separate verifier role that
hyperscalers and model vendors cannot credibly occupy for the same
reason Enron's auditor cannot audit Enron."

## 4. What this means for you

**If you are an auditor:** the wire spec gives you a citable
standard you can write into an engagement letter. "Evidence bundles
conforming to Specora Wire Spec v1.0" is a sentence you can sign.
The Lean proof ([`formal/lean/Specora/Canonicalizer.lean`](https://github.com/SpecoraAI/specora-platform/blob/main/formal/lean/Specora/Canonicalizer.lean))
is the formal companion that makes the canonicalization contract
auditable on the other side.

**If you are a regulator:** Specora is the independent-verification
tier for AI systems. The trust-bootstrap arc (CNCF hosting in
2026-Q4, external security audit, public root-signing ceremony, EU
AI Act Notified Body scoping) is the recognition path. Engagement on
scoping is welcomed; see [`CONTRIBUTING.md`](../CONTRIBUTING.md) and
[`GOVERNANCE.md`](../GOVERNANCE.md).

**If you are an external integrator:** read [quickstart.md](quickstart.md).
You can produce and verify a bundle in under 5 minutes with no
Specora account, no API key, and no network call.

**If you are an enterprise considering Specora:** the independence
is the product. A Specora opinion you pay for and can influence is
structurally no different from a producer's self-attestation. What
makes a Specora opinion valuable is that the verifier's incentives
are separate from yours. The OSS Apache-2.0 verifier in this
repository, the Lean proof in the monorepo, and the CNCF-hosted
public root key are all load-bearing: they are what make it
structurally impossible for Specora to quietly favor a paying
customer. That is the thing you are buying. It is also the thing we
are most unwilling to compromise.

## 5. Agent Identity Theorems (AID-970, demo lane)

The investor-demo lane authorized in [`freeze-exceptions/2026-05-08-aid-investor-demo-build.md`](https://github.com/SpecoraAI/specora-platform) (platform repo, CSEA-SUPPRESS-2026-05-08-002, archive 2026-06-05) extends the verifier into an issuer for AI agent identity certificates. Three Lean theorems anchor that extension. Each one is proven in [`formal/lean/Specora/AgentIdentity/Theorems.lean`](https://github.com/SpecoraAI/specora-platform) in the platform monorepo with no `sorry` and no Mathlib axioms; the matching TLA+ model lives at [`formal/tla/agent_identity_revocation.tla`](https://github.com/SpecoraAI/specora-platform).

### 5.1 THM-AID-UNIQ — Identity uniqueness

> **Statement.** At any point in time, at most one identity certificate is in the `active` state for a given `(org_id, agent_id)` pair.

This is the schema-level partial unique index on `prspec.ai_agent_identities` written into the migration at [`migrations/versions/1376_aid_900_*`](https://github.com/SpecoraAI/specora-platform). The Lean formulation (`wellformed_registry`) makes it a property of every reachable registry state. The runtime service (`AIAgentIdentityService.register_agent`) raises `AIAgentIdentityAlreadyActive` *before* attempting an INSERT that would violate the index, so the theorem is preserved by every state transition the API exposes.

**Why it matters.** A relying party that pins a particular issued cert can be confident no second `active` cert exists for the same agent at the same time. Replay defenses and revocation lists are well-defined.

### 5.2 THM-AID-SIG — Signature integrity

> **Statement.** The bundle's `agent_identity` field validates if and only if (a) the cert chains to the active issuer root pubkey supplied out-of-band, **and** (b) the bundle's outer signature covers the field, **and** (c) the cert's Ed25519 signature verifies.

The "if and only if" is what makes the verifier's [`validate_bundle_v1_1`](../specora_verify/wire_spec.py) reliable: tampering with any of the three sub-claims flips the verdict to FAIL. The verifier-side test [`tests/test_wire_spec_v1_1.py::TestTampering`](../tests/test_wire_spec_v1_1.py) exercises the contrapositive directly — mutate the cert's subject, the bundle flips to `invalid` with reason `"signature does not verify"`.

**Why it matters.** A relying party reading the canonical bundle later can trust the agent identity claim as much as the bundle's outer signature. The two are cryptographically linked by canonical-JSON inclusion; nobody between the signer and the verifier can substitute or strip the cert without detection.

### 5.3 THM-AID-REV — Revocation propagation

> **Statement.** Once an identity transitions to `revoked` and is recorded as the head of the registry, no subsequent lookup for `(org_id, agent_id)` returns an `active` row.

The Lean proof relies on the head-wins lookup pattern — newest writes prepended, `List.find?` returns the first match. Prepending a `revoked` row in front of any earlier `active` row dominates the lookup. The matching TLA+ liveness claim (`RevocationVisibleEventually` in `agent_identity_revocation.tla`) bounds the verifier's cache-refresh delay to a fixed number of model ticks, so the model checker can verify that revocation visibility is not just eventual but *bounded*.

**Why it matters.** A revoked agent cannot rejoin the `active` set without a fresh registration. The relying party's revocation list can be a simple "highest-`revoked_at` wins" lookup against the issuance-events ledger.

### 5.4 Demo-fidelity caveats

The demo runtime is feature-flagged off in production deployments per the freeze-exception §3.1. The Lean module carries one `[advisory-no-runtime]` axiom (`runtime_correspondence`) that asserts the Python service preserves `wellformed_registry` across every transition. That assertion is verified end-to-end by the Lane B integration test at [`services/prspec-api/tests/test_db/test_aid_960_lifecycle_pairing.py`](https://github.com/SpecoraAI/specora-platform) — but the formal theorem statement uses an axiom rather than a fully-derived chain because the runtime wiring is post-archive (post-2026-06-05) work.

The cert format identifier is `specora-aid-cert-v1`. The same identifier covers both the prelaunch (DEMO-ROOT-signed) and the future production (C01-rooted) issuance lanes; relying parties separate the two by pinning the issuer key fingerprint, never by reading the format string. The cert envelope carries two sealed identity blocks — `subject` (the AGENT) and `principal` (the OWNER, including the owner's Ed25519 public key, per [ADR-PLATFORM-009](https://github.com/SpecoraAI/specora-platform/blob/staging/docs/platform/adr/ADR-PLATFORM-009-AGENT-IDENTITY-OWNER-PUBLIC-KEY.md)). Runtime authorization networks use the principal public key to verify owner-signed mandates in the three-part authorization presentation (HonorNet ADR-009); Specora attests the key and never sees or evaluates the mandate.

## 6. Further reading

- [wire-spec-v1.0.md](wire-spec-v1.0.md) — normative contract.
- [wire-spec-v1.1.md](wire-spec-v1.1.md) — additive demo-lane revision (agent identity).
- [readers/agent-identity.md](readers/agent-identity.md) — reader-side pass-through guide.
- [versioning-policy.md](versioning-policy.md) — how the spec will
  evolve without breaking the trust model.
- [quickstart.md](quickstart.md) — runnable end-to-end example.
- [vectors.md](vectors.md) — golden vectors, the executable form of
  the contract.
- Platform repo: [`docs/strategy/market-pressure-test-2026.md` §2.5–§2.7](https://github.com/SpecoraAI/specora-platform/blob/main/docs/strategy/market-pressure-test-2026.md) — the strategic case for the category switch.
- Platform repo: [`docs/strategy/category-switch-epic-suite.md`](https://github.com/SpecoraAI/specora-platform/blob/main/docs/strategy/category-switch-epic-suite.md) — the execution plan.
