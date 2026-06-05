# Independent QA harnesses

These verify `specora-verify` the way a skeptical, independent third party
would — they deliberately do **not** trust the project's own `pytest` suite.
Each was written to answer one question the green suite structurally cannot.

| Harness | Question it answers | Needs |
|---|---|---|
| [`l2-go/main.go`](l2-go/main.go) | Is the wire spec faithfully implementable from the spec alone? Reimplements canonicalize + SHA-256 + Ed25519-verify in Go (own JSON serializer, not Go's encoder) and checks **byte-parity** against all 18 golden vectors. | `go` |
| [`l3_adversarial.py`](l3_adversarial.py) | Can a forged/invalid input be made to **pass**? Mints genuinely-valid signatures and certs with a fresh keypair, then tampers (byte flips, wrong key, expiry, spoofed fingerprint, …) and asserts every forgery is rejected. | `specora-verify[crypto]` |
| [`l4_schema_fuzz.py`](l4_schema_fuzz.py) | Do the JSON Schemas actually **reject** bad input (not just accept the golden vector)? Mutates every constrained schema leaf — bad hex casing/length, wrong enums, dropped required fields, unknown properties — and asserts rejection. | `jsonschema` |
| [`check_l1_distribution.py`](check_l1_distribution.py) | Can a cold stranger **obtain and verify** the tool? Probes every public distribution + out-of-band verification anchor (PyPI, GitHub repo/releases+Sigstore, Homebrew, `spec.specora.ai`). | network |

## Run

```bash
# everything offline (L2 + L3 + L4)
python tools/qa/run_all.py

# individual harnesses
python tools/qa/l3_adversarial.py
python tools/qa/l4_schema_fuzz.py
( cd tools/qa/l2-go && go run main.go )

# L1 — online distribution gate (see docs/release-checklist.md)
python tools/qa/check_l1_distribution.py --expect-prelaunch   # before 2026-06-14
python tools/qa/check_l1_distribution.py                      # on/after flip day
```

Install the verification extras into a venv first:

```bash
pip install -e ".[crypto]" jsonschema
```

## What they found (2026-06-05 run)

All four levels were run as a third-party QA pass. Findings (all in-repo
defects fixed, with regression guards added to `tests/`):

- **L3:** 31/31 forgery cases rejected. Found a timezone-naive timestamp bug
  in `agent_identity.py` (`_parse_rfc3339` coerced tz-less timestamps to host
  local time → same cert valid in one locale, expired in another). **Fixed.**
- **L2:** 6/6 core vectors byte-identical. Found a trailing newline on 4 v1.1
  canonical vectors (violated wire-spec §3.2 "no trailing newline"; hidden
  from CI because every consumer used `json.loads`, which tolerates trailing
  whitespace). **Fixed + byte-canonical guard added.**
- **L4:** 172/172 schema mutations rejected. Found `agent_identity.py`
  accepting uppercase `principal.public_key` while the schema + §5.2 pin
  lowercase (code looser than its own schema). **Fixed.**
- **L1:** every public anchor 404/NXDOMAIN — expected pre-flip (public
  release 2026-06-14). Tracked in [docs/release-checklist.md](../../docs/release-checklist.md).
