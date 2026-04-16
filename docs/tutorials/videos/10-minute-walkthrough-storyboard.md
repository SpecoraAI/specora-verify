# 10-minute out-of-band verification walkthrough — storyboard

**Status.** EPIC-B03 deliverable. Storyboard for the A09 launch-day video. Grounded in the real CLI flow as shipped in `specora_verify/orchestration.py` and `specora-verify run --provider <p>`. No aspirational features. If a step can't be recorded today against the committed fixtures, it is not in this storyboard.

**Coordination with A09.** As of 2026-04-15 A09 had not yet drafted a written walkthrough script. This storyboard is the first draft and becomes the source of truth. When A09 adds a script file, cross-link from here and reconcile in a single follow-up commit rather than maintaining two parallel drafts.

**Audience.** An auditor, compliance officer, or developer who has heard "AI governance" too many times and is skeptical we have anything new. The whole video has to answer the question *"Why should I run this instead of just trusting my provider's dashboard?"*

**Belief opening (the WHY).** We believe AI that acts must prove it deserves to. The hook is proof, not features.

---

## Segment layout (10:00 total)

| # | Time  | Segment                          | On-screen                                                         |
|---|-------|----------------------------------|-------------------------------------------------------------------|
| 1 | 0:00–0:45 | Belief opening                   | Narrator to camera, no CLI. Black background, white text.        |
| 2 | 0:45–1:45 | The problem with dashboards      | Screenshot of a generic monitoring dashboard, then a red X.      |
| 3 | 1:45–2:45 | The out-of-band architecture      | Static diagram (export → reader → canonical → signer → verify). |
| 4 | 2:45–4:15 | Live: `pip install` + export file | Terminal, real fixture path.                                     |
| 5 | 4:15–6:00 | Live: `specora-verify run` demo   | Terminal, real output.                                           |
| 6 | 6:00–7:15 | Live: `specora-verify verify` PASS| Terminal showing green PASS.                                     |
| 7 | 7:15–8:30 | Live: tamper → FAIL               | Terminal, deliberate mutation, red FAIL.                         |
| 8 | 8:30–9:15 | Handoff to auditor                | Screen recording of copying the folder.                          |
| 9 | 9:15–10:00| Close: foundation + independence  | Narrator + CNCF logo placeholder.                                |

---

## Segment 1 — 0:00–0:45  Belief opening

**Narration.**
> "We believe AI that acts must prove it deserves to. Proof replaces promise. Every time an AI system takes an action on your behalf, somebody — a regulator, an auditor, your board — is going to ask you to prove that action was allowed. Dashboards are not proof. Screenshots are not proof. This video is about what proof actually looks like."

**On screen.** Plain title card. No product name for the first 30 seconds — the belief lands before the brand.

---

## Segment 2 — 0:45–1:45  The problem with dashboards

**Narration.**
> "Most teams today 'govern' their AI by piping events into a dashboard. Dashboards tell you what the dashboard thinks happened. They do not tell you what your provider actually did, and they definitely don't tell a third party anything they can check for themselves. That's not governance. That's self-reporting."

**On screen.** A stock monitoring dashboard. Superimpose the word "SELF-REPORTED" in red.

---

## Segment 3 — 1:45–2:45  The out-of-band architecture

**Narration.**
> "Here's what changes. You already log every AI decision to somewhere — Anthropic's Compliance API, AWS CloudTrail for Bedrock, Azure Confidential Ledger. Specora does not replace that. Specora takes the export, normalizes it into a canonical bundle, signs it with a key you control, and produces a file your auditor can verify offline on their own laptop. You don't give up any tool you already run. You add one command."

**On screen.** Static diagram identical to the one in `docs/tutorials/out-of-band-verification.md`:
```
provider export → reader → canonical bundle → Ed25519 sign → signed bundle dir → specora-verify verify → PASS
```

---

## Segment 4 — 2:45–4:15  Install + fixture

**Terminal commands (real, no fakery).**
```bash
pip install "specora-verify[crypto]"
ls tests/fixtures/anthropic/minimal-valid.jsonl
head -1 tests/fixtures/anthropic/minimal-valid.jsonl
```

**Narration.**
> "Here's the install — one pip command, stdlib-only core plus the crypto extra. Here's a real export from Anthropic's Compliance API. It's JSONL. Two records, one signed decision each. We don't mock this — this is the exact fixture the test suite runs against."

---

## Segment 5 — 4:15–6:00  `specora-verify run`

**Terminal.**
```bash
python3 -c 'import os; open("signing.hex","w").write(os.urandom(32).hex())'

specora-verify run \
    --provider anthropic \
    --input tests/fixtures/anthropic/minimal-valid.jsonl \
    --key-id demo-q2 \
    --private-key signing.hex \
    --out ./demo-bundle/

ls demo-bundle/
cat demo-bundle/metadata.json
```

**Narration.**
> "One command. Reader picks up the export. Canonical schema normalizes it. Ed25519 signs it. Output is four files: the payload, the signature, the public key, and a metadata file with the payload SHA-256. Your key, your custody. We never see it."

---

## Segment 6 — 6:00–7:15  `specora-verify verify` PASS

**Terminal.**
```bash
specora-verify verify \
    --artifact  demo-bundle/payload.json \
    --signature demo-bundle/payload.sig \
    --public-key demo-bundle/signing-key.pub
echo "exit=$?"
```

**Narration.**
> "Now I'm an auditor on a different laptop. No Specora account. No network. I run `specora-verify verify` against the three files. Status PASS. The signature is cryptographically bound to the canonical bundle. If anyone had tampered with the payload between the provider export and now, this would fail."

**On screen.** Green PASS. Hold on-screen for 3 seconds — this is the moment of the whole video.

---

## Segment 7 — 7:15–8:30  Tamper → FAIL

**Terminal.**
```bash
python3 -c 'import json; p=json.load(open("demo-bundle/payload.json")); p["__tamper__"]="oops"; open("demo-bundle/payload.json","w").write(json.dumps(p,sort_keys=True,separators=(",",":"))+"\n")'

specora-verify verify \
    --artifact  demo-bundle/payload.json \
    --signature demo-bundle/payload.sig \
    --public-key demo-bundle/signing-key.pub
echo "exit=$?"
```

**Narration.**
> "Here's the test nobody else passes. I mutate one byte of the payload — not the signature, just the payload. I run verify again. Status FAIL. This is what 'cryptographic binding' actually means. We have an end-to-end test in the public repo that asserts exactly this property, and if it ever goes green on a tampered bundle, we treat it as a P0 incident."

**On screen.** Red FAIL. Cut to `tests/e2e/test_out_of_band_flow.py::test_run_verify_rejects_tampered_bundle` in an editor.

---

## Segment 8 — 8:30–9:15  Handoff to auditor

**Narration.**
> "The bundle directory is self-contained. You zip it. You send it. Your auditor runs the same verify command on their laptop. They don't trust us — they trust the math. This is what independent verification looks like."

**On screen.** Screen recording of zipping `demo-bundle/` and dropping it into a fictional `auditor-inbox/` folder.

---

## Segment 9 — 9:15–10:00  Close

**Narration.**
> "Specora is applying to CNCF for neutral governance. The verifier is Apache 2.0 on GitHub. The wire spec is versioned and signed. The whole point is that you don't have to trust Specora — you have to trust the verifier, the math, and the provider you're already using. Proof replaces promise."

**On-screen.**
- `github.com/SpecoraAI/specora-verify`
- CNCF sandbox-application placeholder (B04)
- Tagline: *"AI that acts must prove it deserves to."*

---

## Production notes

- **Record on a clean terminal** — zsh with no custom prompt, white-on-black, font ≥ 18pt, window 120×32.
- **No fake speedups** — if a command takes 3 seconds, it takes 3 seconds. Speeding up commits a trust violation on a video about proof.
- **No blurring of CLI output** — everything shown must be reproducible from the committed repo.
- **Version-lock**. Shoot against a tagged release (`v1.1.0` or whatever ships with B03), call out the tag on screen at 0:20, and re-shoot for any CLI-affecting release.

## Open questions for A09

1. Do we want the belief opening to use a voice-over or a narrator-to-camera shot? This storyboard assumes voice-over for segments 1–3 and terminal screen-share for 4–8.
2. Captioning: EN by launch, DE/JA as fast-follow?
3. Do we host on YouTube (public), Loom (gated), or our own site? Decision affects thumbnail + SEO copy.
4. Is there a companion blog post? If so it should cross-link to [`docs/tutorials/out-of-band-verification.md`](../out-of-band-verification.md).
