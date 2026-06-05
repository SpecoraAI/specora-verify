#!/usr/bin/env python3
"""Level-3 adversarial QA harness for specora-verify.

Third-party posture: we do NOT trust the repo's own green test suite. We mint
genuinely-valid signatures/certs with our OWN keypair, then tamper and confirm
the verifier REJECTS each forgery. A case that *should* FAIL but PASSes is a
forged-PASS (critical). A case that *should* PASS but FAILs is a false-negative.
FLAG cases document behavior that is technically correct but a trust footgun.

Run: /tmp/specora-qa-venv/bin/python /tmp/specora_adversarial_qa.py
"""
from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from specora_verify.canonical import canonical_json_bytes
from specora_verify.hash import compute_manifest_hash, sha256_hex
from specora_verify.signature import verify_artifact_signature
from specora_verify.agent_identity import (
    validate_agent_identity_certificate,
    public_key_fingerprint,
)
from specora_verify.wire_spec import validate_bundle_v1_1

# ---------------------------------------------------------------- result model
RESULTS = []  # (id, category, intent, expected, observed, ok, note)

PASS_OK = "PASS-ALLOWED"   # a valid input; verifier SHOULD accept
MUST_FAIL = "MUST-FAIL"    # a forged/invalid input; verifier MUST reject
FLAG = "FLAG"              # behavior is "correct" but worth surfacing


def record(tid, category, intent, expected, accepted, note=""):
    """accepted = did the verifier treat the input as valid/PASS?"""
    if expected == PASS_OK:
        ok = accepted is True
    elif expected == MUST_FAIL:
        ok = accepted is False
    else:  # FLAG — we just observe, ok reflects whether our prediction held
        ok = True
    RESULTS.append((tid, category, intent, expected, accepted, ok, note))


# ----------------------------------------------------------------- key helpers
def raw_pub(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def pub_b64(sk: Ed25519PrivateKey) -> str:
    return base64.b64encode(raw_pub(sk)).decode()


def pub_hex(sk: Ed25519PrivateKey) -> str:
    return raw_pub(sk).hex()


# deterministic keys (seed from fixed bytes so the run is reproducible)
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ATTACKER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
ROGUE_ISSUER = Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)


# ==================================================================== SIGNATURE
def sig_over_hash(sk: Ed25519PrivateKey, manifest_hash: str) -> str:
    return base64.b64encode(sk.sign(manifest_hash.encode("utf-8"))).decode()


def signature_suite():
    artifact = {
        "spec_id": "governance-attestation",
        "org_id": "org-demo-001",
        "policies_evaluated": 5,
        "all_policies_passed": True,
    }
    h = compute_manifest_hash(artifact)
    good_sig = sig_over_hash(SIGNER, h)
    pk = pub_b64(SIGNER)

    def accepted(hash_arg, sig_arg, key_arg):
        try:
            return verify_artifact_signature(hash_arg, sig_arg, key_arg).valid
        except Exception:
            return False

    # SIG-00 baseline
    record("SIG-00", "signature", "valid sig, correct key", PASS_OK,
           accepted(h, good_sig, pk))

    # SIG-01 single-byte tamper in artifact -> hash changes
    tampered = copy.deepcopy(artifact)
    tampered["all_policies_passed"] = False
    record("SIG-01", "signature", "1-field tamper (pass->fail flipped)", MUST_FAIL,
           accepted(compute_manifest_hash(tampered), good_sig, pk))

    # SIG-02 verify good sig against attacker's key
    record("SIG-02", "signature", "valid sig verified vs WRONG pubkey", MUST_FAIL,
           accepted(h, good_sig, pub_b64(ATTACKER)))

    # SIG-03/04 wrong signature length
    sig_bytes = base64.b64decode(good_sig)
    record("SIG-03", "signature", "truncated signature (63 bytes)", MUST_FAIL,
           accepted(h, base64.b64encode(sig_bytes[:-1]).decode(), pk))
    record("SIG-04", "signature", "extended signature (65 bytes)", MUST_FAIL,
           accepted(h, base64.b64encode(sig_bytes + b"\x00").decode(), pk))

    # SIG-05 all-zero signature
    record("SIG-05", "signature", "all-zero 64-byte signature", MUST_FAIL,
           accepted(h, base64.b64encode(b"\x00" * 64).decode(), pk))

    # SIG-06 empty signature
    record("SIG-06", "signature", "empty signature string", MUST_FAIL,
           accepted(h, "", pk))

    # SIG-07 uppercase hex hash (code requires lowercase)
    record("SIG-07", "signature", "uppercase hex hash", MUST_FAIL,
           accepted(h.upper(), good_sig, pk))

    # SIG-08 wrong-length hash
    record("SIG-08", "signature", "hash wrong length (63 chars)", MUST_FAIL,
           accepted(h[:-1], good_sig, pk))

    # SIG-09 signature substitution: sig valid over H1, presented with H2
    other = {"spec_id": "different", "org_id": "evil"}
    h2 = compute_manifest_hash(other)
    record("SIG-09", "signature", "valid sig over H1 presented with H2", MUST_FAIL,
           accepted(h2, good_sig, pk))

    # SIG-10 non-base64 signature
    record("SIG-10", "signature", "non-base64 signature garbage", MUST_FAIL,
           accepted(h, "!!!not base64!!!", pk))

    # SIG-11 forged sig: attacker signs same hash with their own key, but
    #        relying party pins the real signer key
    forged = sig_over_hash(ATTACKER, h)
    record("SIG-11", "signature", "attacker-signed hash vs pinned real key", MUST_FAIL,
           accepted(h, forged, pk))


# =============================================================== CANONICALIZATION
def canon_suite():
    # CANON-01/02 NaN / Infinity must be rejected (allow_nan=False)
    for tid, val, label in [
        ("CANON-01", float("nan"), "NaN"),
        ("CANON-02", float("inf"), "Infinity"),
    ]:
        try:
            canonical_json_bytes({"x": val})
            accepted = True  # produced output for a non-finite number -> bad
        except ValueError:
            accepted = False
        record(tid, "canonical", f"{label} numeric value", MUST_FAIL, accepted)

    # CANON-03 determinism: key reorder -> identical canonical hash (correctness)
    a = {"b": 2, "a": 1, "z": {"y": 9, "x": 8}}
    b = {"z": {"x": 8, "y": 9}, "a": 1, "b": 2}
    same = compute_manifest_hash(a) == compute_manifest_hash(b)
    record("CANON-03", "canonical", "reordered keys -> same hash (determinism)",
           PASS_OK, same)

    # CANON-04 duplicate-key smuggling: two different raw texts, one parsed dict
    raw1 = '{"amount": 100, "amount": 1}'   # last-wins in json.loads
    raw2 = '{"amount": 1}'
    same_hash = sha256_hex(canonical_json_bytes(json.loads(raw1))) == \
                sha256_hex(canonical_json_bytes(json.loads(raw2)))
    record("CANON-04", "canonical",
           "duplicate-key JSON collapses to one hash (wire!=hashed bytes)",
           FLAG, same_hash,
           note="verifier hashes PARSED json; duplicate keys silently collapse "
                "(last-wins). On-the-wire bytes are not what's signed unless the "
                "producer hashes raw text.")

    # CANON-05 Unicode NFC vs NFD not normalized -> different hash
    nfc = {"name": "café"}          # composed e-acute
    nfd = {"name": "café"}         # e + combining acute
    differ = compute_manifest_hash(nfc) != compute_manifest_hash(nfd)
    record("CANON-05", "canonical",
           "NFC vs NFD unicode produce different hashes (no normalization)",
           FLAG, differ,
           note="canonicalization is byte-faithful, not Unicode-normalizing; "
                "visually identical strings can yield different verdicts.")


# ================================================================ AGENT IDENTITY
def mint_cert(issuer_sk: Ed25519PrivateKey, *, issued_at, not_after,
              principal_pk=None, fmt="specora-aid-cert-v1",
              fingerprint=None, principal_override=None):
    principal = {
        "id": "00000000-0000-0000-0000-0000000000aa",
        "public_key": principal_pk or pub_hex(ATTACKER),
    }
    if principal_override is not None:
        principal = principal_override
    cert = {
        "format": fmt,
        "issued_at": issued_at,
        "not_after": not_after,
        "issuer_key_fingerprint": fingerprint or public_key_fingerprint(pub_hex(issuer_sk)),
        "issuer": {"common_name": "Test Root", "organization": "QA"},
        "public_key": pub_hex(SIGNER),
        "principal": principal,
        "subject": {
            "org_id": "00000000-0000-0000-0000-0000000000aa",
            "agent_id": "qa-agent",
            "identity_id": "00000000-0000-0000-0000-000000000001",
        },
    }
    unsigned = {k: v for k, v in cert.items() if k != "signature"}
    cert["signature"] = base64.b64encode(
        issuer_sk.sign(canonical_json_bytes(unsigned))
    ).decode()
    return cert


def aid_accepted(cert, issuer_hex, now):
    try:
        return validate_agent_identity_certificate(
            cert, issuer_public_key_hex=issuer_hex, now=now).valid
    except Exception:
        return False


def aid_suite():
    ISS_HEX = pub_hex(ISSUER)
    NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)

    # AID-00 baseline valid
    c = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00Z",
                  not_after="2026-06-07T12:00:00Z")
    record("AID-00", "agent-id", "valid cert, pinned issuer", PASS_OK,
           aid_accepted(c, ISS_HEX, NOW))

    # AID-01 tamper principal.public_key after signing
    t = copy.deepcopy(c)
    t["principal"]["public_key"] = pub_hex(ROGUE_ISSUER)
    record("AID-01", "agent-id", "tamper principal.public_key post-sign", MUST_FAIL,
           aid_accepted(t, ISS_HEX, NOW))

    # AID-02 tamper subject.org_id after signing
    t = copy.deepcopy(c)
    t["subject"]["org_id"] = "attacker-org"
    record("AID-02", "agent-id", "tamper subject.org_id post-sign", MUST_FAIL,
           aid_accepted(t, ISS_HEX, NOW))

    # AID-03 expired
    exp = mint_cert(ISSUER, issued_at="2025-01-01T00:00:00Z",
                    not_after="2025-01-02T00:00:00Z")
    record("AID-03", "agent-id", "expired cert (now >= not_after)", MUST_FAIL,
           aid_accepted(exp, ISS_HEX, NOW))

    # AID-04 not yet valid
    nyv = mint_cert(ISSUER, issued_at="2027-01-01T00:00:00Z",
                    not_after="2027-02-01T00:00:00Z")
    record("AID-04", "agent-id", "not-yet-valid (now < issued_at)", MUST_FAIL,
           aid_accepted(nyv, ISS_HEX, NOW))

    # AID-05 wrong issuer pinned (relying party pins rogue key)
    record("AID-05", "agent-id", "valid cert vs WRONG pinned issuer key", MUST_FAIL,
           aid_accepted(c, pub_hex(ROGUE_ISSUER), NOW))

    # AID-06 unsupported format
    badfmt = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00Z",
                       not_after="2026-06-07T12:00:00Z", fmt="evil-cert-v9")
    record("AID-06", "agent-id", "unsupported cert format string", MUST_FAIL,
           aid_accepted(badfmt, ISS_HEX, NOW))

    # AID-07 missing principal block (re-sign so signature is otherwise valid)
    noprinc = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00Z",
                        not_after="2026-06-07T12:00:00Z")
    del noprinc["principal"]
    unsigned = {k: v for k, v in noprinc.items() if k != "signature"}
    noprinc["signature"] = base64.b64encode(
        ISSUER.sign(canonical_json_bytes(unsigned))).decode()
    record("AID-07", "agent-id", "principal block absent (validly signed)", MUST_FAIL,
           aid_accepted(noprinc, ISS_HEX, NOW))

    # AID-08 principal.public_key wrong length
    badpk = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00Z",
                      not_after="2026-06-07T12:00:00Z", principal_pk="dead")
    record("AID-08", "agent-id", "principal.public_key not 64 hex chars", MUST_FAIL,
           aid_accepted(badpk, ISS_HEX, NOW))

    # AID-09 attacker self-signs with own key AND forges matching fingerprint,
    #        but relying party pins the REAL issuer key
    forged = mint_cert(ATTACKER, issued_at="2026-05-08T12:00:00Z",
                       not_after="2026-06-07T12:00:00Z",
                       fingerprint=public_key_fingerprint(ISS_HEX))  # claims real fp
    record("AID-09", "agent-id", "attacker self-sign + spoofed fingerprint", MUST_FAIL,
           aid_accepted(forged, ISS_HEX, NOW))

    # AID-10 boundary: now == not_after  -> expired (code: now >= not_after)
    bound = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00Z",
                      not_after="2026-05-15T12:00:00Z")
    record("AID-10", "agent-id", "boundary now == not_after", MUST_FAIL,
           aid_accepted(bound, ISS_HEX, NOW))

    # AID-11 boundary: now == issued_at -> valid (code: now < issued_at fails)
    bound2 = mint_cert(ISSUER, issued_at="2026-05-15T12:00:00Z",
                       not_after="2026-06-01T12:00:00Z")
    record("AID-11", "agent-id", "boundary now == issued_at (valid)", PASS_OK,
           aid_accepted(bound2, ISS_HEX, NOW))

    # AID-12 REVOKED-but-cryptographically-valid cert (THM-AID-REV gap)
    revoked = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00Z",
                        not_after="2026-06-07T12:00:00Z")
    revoked_accepted = aid_accepted(revoked, ISS_HEX, NOW)
    record("AID-12", "agent-id",
           "revoked cert still validates (no revocation input)", FLAG,
           revoked_accepted,
           note="offline validator has NO revocation channel; a revoked cert "
                "returns valid=True. THM-AID-REV is the relying party's job via "
                "a side-channel ledger. A PASS here != 'not revoked'.")

    # AID-13 timezone-naive timestamps (parser uses astimezone -> assumes LOCAL tz)
    naive = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00",
                      not_after="2026-06-07T12:00:00")  # no 'Z'
    naive_accepted = aid_accepted(naive, ISS_HEX, NOW)
    record("AID-13", "agent-id",
           "tz-naive validity window (local-tz coercion)", FLAG, naive_accepted,
           note="_parse_rfc3339 calls .astimezone() on naive datetimes, which "
                "assumes the HOST local timezone. Same cert can flip verdict near "
                "a window boundary depending on where it's verified.")

    # AID-14 uppercase principal.public_key hex accepted (vs lowercase-only in sig path)
    upper = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00Z",
                      not_after="2026-06-07T12:00:00Z",
                      principal_pk=pub_hex(ATTACKER).upper())
    upper_accepted = aid_accepted(upper, ISS_HEX, NOW)
    record("AID-14", "agent-id",
           "uppercase principal.public_key accepted", FLAG, upper_accepted,
           note="agent_identity allows [0-9a-fA-F] for principal.public_key, but "
                "signature.py rejects uppercase manifest hashes. Inconsistent hex "
                "casing policy across the trust surface.")


# ===================================================================== BUNDLE
def bundle_suite():
    ISS_HEX = pub_hex(ISSUER)
    NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc)
    cert = mint_cert(ISSUER, issued_at="2026-05-08T12:00:00Z",
                     not_after="2026-06-07T12:00:00Z")

    def bundle_valid(bundle, issuer_hex):
        try:
            return validate_bundle_v1_1(bundle, issuer_public_key_hex=issuer_hex,
                                        now=NOW).valid
        except Exception:
            return False

    # BUNDLE-01 valid bundle w/ identity
    b = {"records": [{"event": "x", "agent_identity": cert}]}
    record("BUNDLE-01", "bundle", "valid bundle w/ identity + issuer", PASS_OK,
           bundle_valid(b, ISS_HEX))

    # BUNDLE-02 tampered agent_identity
    bt = copy.deepcopy(b)
    bt["records"][0]["agent_identity"]["subject"]["agent_id"] = "evil"
    record("BUNDLE-02", "bundle", "tampered agent_identity in record", MUST_FAIL,
           bundle_valid(bt, ISS_HEX))

    # BUNDLE-03 identity present but no issuer key supplied
    record("BUNDLE-03", "bundle", "identity present, issuer key = None", MUST_FAIL,
           bundle_valid(b, None))

    # BUNDLE-04 records not a list
    record("BUNDLE-04", "bundle", "records is not an array", MUST_FAIL,
           bundle_valid({"records": {"oops": 1}}, ISS_HEX))

    # BUNDLE-05 empty records -> vacuously valid
    empty_accepted = bundle_valid({"records": []}, ISS_HEX)
    record("BUNDLE-05", "bundle", "empty records list (vacuous PASS)", FLAG,
           empty_accepted,
           note="a bundle with zero records validates true. An evidence bundle "
                "that lost all its records is indistinguishable from a clean one.")


# ======================================================================= REPORT
def main():
    signature_suite()
    canon_suite()
    aid_suite()
    bundle_suite()

    width = 86
    print("=" * width)
    print("SPECORA-VERIFY — LEVEL 3 ADVERSARIAL QA")
    print("=" * width)
    hdr = f"{'ID':<11}{'CATEGORY':<11}{'EXPECTED':<13}{'ACCEPTED':<10}{'RESULT'}"
    print(hdr)
    print("-" * width)

    crit = []      # MUST-FAIL that was accepted (forged PASS) OR PASS that failed
    flags = []
    for tid, cat, intent, expected, accepted, ok, note in RESULTS:
        acc = "yes" if accepted else "no"
        if expected == FLAG:
            verdict = "FLAG"
        elif ok:
            verdict = "ok"
        else:
            verdict = "*** DEFECT ***"
            crit.append((tid, intent, expected, accepted))
        print(f"{tid:<11}{cat:<11}{expected:<13}{acc:<10}{verdict}")
        print(f"           └─ {intent}")
        if note and expected == FLAG:
            flags.append((tid, note))

    print("-" * width)
    total = len(RESULTS)
    flagn = sum(1 for r in RESULTS if r[3] == FLAG)
    defects = len(crit)
    graded = total - flagn
    print(f"Graded cases: {graded}   passed: {graded - defects}   "
          f"DEFECTS: {defects}   flags: {flagn}")

    if crit:
        print("\n" + "!" * width)
        print("CRITICAL DEFECTS (forged input accepted, or valid input rejected):")
        for tid, intent, expected, accepted in crit:
            print(f"  [{tid}] expected {expected}, accepted={accepted}: {intent}")

    if flags:
        print("\n" + "=" * width)
        print("TRUST FLAGS (behavior is 'correct' but a third party must surface it):")
        for tid, note in flags:
            print(f"\n  [{tid}]")
            for line in _wrap(note, width - 8):
                print(f"      {line}")

    print("\n" + "=" * width)
    print("VERDICT:", "DEFECTS FOUND" if crit else
          "No forged-PASS defects. See trust flags for disclosure gaps.")
    print("=" * width)
    return 1 if crit else 0


def _wrap(text, w):
    words, line, out = text.split(), "", []
    for word in words:
        if len(line) + len(word) + 1 > w:
            out.append(line); line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
