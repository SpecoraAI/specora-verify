// Level-2 independent reimplementation of the Specora Wire Spec v1.0 verifier.
//
// Written from docs/wire-spec-v1.0.md §3 (canonicalization), §4 (signing),
// §5 (hashing) — NOT from specora_verify/*.py. Go stdlib only. The goal is
// byte-parity against the 18 golden vectors. Any divergence is a finding:
// either the spec is ambiguous or a vector is wrong.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ---- §3 canonicalization: our own serializer matching Python json.dumps(
//      sort_keys=True, separators=(",",":"), ensure_ascii=True, allow_nan=False)

func canonical(v interface{}, b *strings.Builder) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJSONString(x, b)
	case json.Number:
		s := string(x)
		if isIntegerToken(s) {
			// Python re-emits ints via str(int(...)); normalize via big.Int
			// so "-0" -> "0" and large ints stay exact.
			z := new(big.Int)
			if _, ok := z.SetString(s, 10); !ok {
				return fmt.Errorf("bad integer token %q", s)
			}
			b.WriteString(z.String())
		} else {
			// §3.4: producer emits no non-integer numerics in v1.0.
			return fmt.Errorf("NON-INTEGER NUMBER %q: spec §3.4 leaves float "+
				"re-emission to Python repr; independent parity not defined", s)
		}
	case []interface{}:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonical(e, b); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// UTF-8 byte-lexicographic order == Unicode code-point order (§3.2.1)
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(k, b)
			b.WriteByte(':')
			if err := canonical(x[k], b); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func isIntegerToken(s string) bool {
	return !strings.ContainsAny(s, ".eE")
}

// writeJSONString replicates CPython's c_encode_basestring_ascii:
// escape " and \, short escapes for \b\t\n\f\r, and \uXXXX (lowercase) for
// any rune < 0x20 or > 0x7e. '/' is NOT escaped. >0xFFFF -> surrogate pair.
func writeJSONString(s string, b *strings.Builder) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		default:
			if r < 0x20 || r > 0x7e {
				if r > 0xffff {
					r -= 0x10000
					hi := 0xd800 + (r >> 10)
					lo := 0xdc00 + (r & 0x3ff)
					fmt.Fprintf(b, "\\u%04x\\u%04x", hi, lo)
				} else {
					fmt.Fprintf(b, "\\u%04x", r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func canonicalBytes(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var b strings.Builder
	if err := canonical(v, &b); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ---- reporting

type row struct {
	name, check, status, detail string
}

var rows []row

func add(name, check, status, detail string) {
	rows = append(rows, row{name, check, status, detail})
}

const PASS = "PASS"
const FAIL = "FAIL"
const FLAG = "FLAG"

// canonicalAndHash: re-canonicalize source, byte-compare to stored canonical,
// hash-compare to stored sha256 (when present).
func checkPayload(name, srcPath, canonPath, shaPath string) {
	src, err := os.ReadFile(srcPath)
	if err != nil {
		add(name, "read-source", FAIL, err.Error())
		return
	}
	storedCanon, err := os.ReadFile(canonPath)
	if err != nil {
		add(name, "read-canonical", FAIL, err.Error())
		return
	}
	mine, err := canonicalBytes(src)
	if err != nil {
		add(name, "canonicalize", FAIL, err.Error())
		return
	}
	if string(mine) == string(storedCanon) {
		add(name, "canonical-byte-parity", PASS,
			fmt.Sprintf("%d bytes identical", len(mine)))
	} else {
		add(name, "canonical-byte-parity", FAIL, firstDiff(mine, storedCanon))
	}
	if shaPath != "" {
		stored, err := os.ReadFile(shaPath)
		if err != nil {
			add(name, "read-sha", FAIL, err.Error())
			return
		}
		want := strings.TrimSpace(string(stored))
		got := sha256hex(mine)
		gotStored := sha256hex(storedCanon)
		if got == want && gotStored == want {
			add(name, "sha256-parity", PASS, got[:16]+"…")
		} else {
			add(name, "sha256-parity", FAIL,
				fmt.Sprintf("want=%s mine=%s storedfile=%s", want[:12], got[:12], gotStored[:12]))
		}
	}
}

// idempotency: canonicalizing an already-canonical doc yields itself.
func checkIdempotent(name, canonPath string) {
	storedCanon, err := os.ReadFile(canonPath)
	if err != nil {
		add(name, "read-canonical", FAIL, err.Error())
		return
	}
	mine, err := canonicalBytes(storedCanon)
	if err != nil {
		add(name, "canonicalize", FAIL, err.Error())
		return
	}
	if string(mine) == string(storedCanon) {
		add(name, "canonical-idempotent", PASS,
			fmt.Sprintf("%d bytes", len(mine)))
	} else {
		add(name, "canonical-idempotent", FAIL, firstDiff(mine, storedCanon))
	}
}

func firstDiff(a, b []byte) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			lo := i - 12
			if lo < 0 {
				lo = 0
			}
			return fmt.Sprintf("diverge@%d mine…%q vs stored…%q (len %d vs %d)",
				i, snip(a, lo, i+12), snip(b, lo, i+12), len(a), len(b))
		}
	}
	return fmt.Sprintf("prefix-equal but len %d vs %d", len(a), len(b))
}

func snip(b []byte, lo, hi int) string {
	if lo < 0 {
		lo = 0
	}
	if hi > len(b) {
		hi = len(b)
	}
	return string(b[lo:hi])
}

// ---- §4 signing: independent Ed25519 verification of the signed-artifact vector
func checkSignatureVector(dir string) {
	name := "signed-artifact-001"
	canon, err := os.ReadFile(filepath.Join(dir, "artifact.canonical.json"))
	if err != nil {
		add(name, "read", FAIL, err.Error())
		return
	}
	// re-derive content_to_sign = utf8(hex(sha256(canonical(payload)))) §4.2
	src, _ := os.ReadFile(filepath.Join(dir, "artifact.json"))
	mine, err := canonicalBytes(src)
	if err != nil {
		add(name, "canonicalize", FAIL, err.Error())
		return
	}
	if string(mine) != string(canon) {
		add(name, "canonical-byte-parity", FAIL, firstDiff(mine, canon))
	} else {
		add(name, "canonical-byte-parity", PASS, fmt.Sprintf("%d bytes", len(mine)))
	}
	digest := sha256hex(mine)
	contentToSign := []byte(digest) // utf8 of lowercase hex

	pkB64, _ := os.ReadFile(filepath.Join(dir, "pubkey.b64"))
	pkRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pkB64)))
	if err != nil || len(pkRaw) != ed25519.PublicKeySize {
		add(name, "load-pubkey", FAIL, fmt.Sprintf("len=%d err=%v", len(pkRaw), err))
		return
	}
	sigB64, _ := os.ReadFile(filepath.Join(dir, "signature.b64"))
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		add(name, "load-signature", FAIL, fmt.Sprintf("len=%d err=%v", len(sig), err))
		return
	}
	// positive verification
	if ed25519.Verify(ed25519.PublicKey(pkRaw), contentToSign, sig) {
		add(name, "ed25519-verify (independent)", PASS, "signature valid over utf8(hex(sha256(canon)))")
	} else {
		add(name, "ed25519-verify (independent)", FAIL, "signature did NOT verify")
	}
	// negative control: verify against the RAW hash bytes (not hex) must fail
	rawDigest := sha256.Sum256(mine)
	if ed25519.Verify(ed25519.PublicKey(pkRaw), rawDigest[:], sig) {
		add(name, "neg-control raw-hash-bytes", FAIL, "verified over RAW bytes — envelope ambiguous!")
	} else {
		add(name, "neg-control raw-hash-bytes", PASS, "correctly rejects raw-hash signing variant")
	}

	// §4.3/4.4 derived_key_id + fingerprint cross-check against metadata.json
	var meta map[string]interface{}
	mb, _ := os.ReadFile(filepath.Join(dir, "metadata.json"))
	json.Unmarshal(mb, &meta)
	fp := sha256hex(pkRaw)
	wantFp, _ := meta["key_fingerprint_sha256"].(string)
	wantKid, _ := meta["derived_key_id"].(string)
	myKid := "spk-" + fp[:16]
	if fp == wantFp && myKid == wantKid {
		add(name, "key-id + fingerprint (§4.3/4.4)", PASS, myKid)
	} else {
		add(name, "key-id + fingerprint (§4.3/4.4)", FAIL,
			fmt.Sprintf("fp want=%s got=%s; kid want=%s got=%s", wantFp[:12], fp[:12], wantKid, myKid))
	}
	// pubkey.b64 vs pubkey.pem consistency
	pemRaw, err := os.ReadFile(filepath.Join(dir, "pubkey.pem"))
	if err == nil {
		if rawFromPEM := ed25519FromPEM(pemRaw); rawFromPEM != nil {
			if string(rawFromPEM) == string(pkRaw) {
				add(name, "pubkey.pem == pubkey.b64", PASS, "32 raw bytes match")
			} else {
				add(name, "pubkey.pem == pubkey.b64", FAIL, "PEM and b64 keys differ")
			}
		}
	}
}

// ed25519FromPEM extracts the 32 raw bytes from a PKIX PEM Ed25519 key
// without x509 (the last 32 bytes of the DER are the raw key for Ed25519 SPKI).
func ed25519FromPEM(pem []byte) []byte {
	s := string(pem)
	start := strings.Index(s, "-----BEGIN PUBLIC KEY-----")
	end := strings.Index(s, "-----END PUBLIC KEY-----")
	if start < 0 || end < 0 {
		return nil
	}
	body := s[start+len("-----BEGIN PUBLIC KEY-----") : end]
	body = strings.Join(strings.Fields(body), "")
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(der) < 32 {
		return nil
	}
	return der[len(der)-32:]
}

// ---- §4 agent-identity cert verification (independent), incl. the 3 vectors
func checkAgentIdentity(path, label, expect string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		add("aid:"+label, "read", FAIL, err.Error())
		return
	}
	var top map[string]interface{}
	if err := json.Unmarshal(raw, &top); err != nil {
		add("aid:"+label, "parse", FAIL, err.Error())
		return
	}
	meta, _ := top["_metadata"].(map[string]interface{})
	issuerHex, _ := meta["issuer_public_key_hex"].(string)
	cert, _ := top["certificate"].(map[string]interface{})
	// re-decode cert via UseNumber for canonical fidelity
	cb, _ := json.Marshal(cert)
	var certNum interface{}
	d := json.NewDecoder(strings.NewReader(string(cb)))
	d.UseNumber()
	d.Decode(&certNum)
	cm := certNum.(map[string]interface{})
	sigB64, _ := cm["signature"].(string)
	delete(cm, "signature")
	var b strings.Builder
	if err := canonical(cm, &b); err != nil {
		add("aid:"+label, "canonicalize", FAIL, err.Error())
		return
	}
	issuerRaw, err := hex.DecodeString(issuerHex)
	if err != nil || len(issuerRaw) != 32 {
		add("aid:"+label, "issuer-key", FAIL, fmt.Sprintf("len=%d", len(issuerRaw)))
		return
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		add("aid:"+label, "signature", FAIL, fmt.Sprintf("len=%d", len(sig)))
		return
	}
	sigOK := ed25519.Verify(ed25519.PublicKey(issuerRaw), []byte(b.String()), sig)
	// our independent verdict on signature only
	switch expect {
	case "valid", "revoked":
		// both are cryptographically valid signatures (revoked is valid-but-revoked)
		if sigOK {
			add("aid:"+label, "ed25519 cert-sig (independent)", PASS, "signature verifies")
		} else {
			add("aid:"+label, "ed25519 cert-sig (independent)", FAIL, "should verify but did not")
		}
	case "expired":
		if sigOK {
			add("aid:"+label, "ed25519 cert-sig (independent)", PASS, "sig verifies (rejection is time-based, not sig)")
		} else {
			add("aid:"+label, "ed25519 cert-sig (independent)", FAIL, "expected sig OK")
		}
	}
	if label == "revoked" {
		add("aid:revoked", "revocation-gap", FLAG,
			"sig+window valid; offline verify has NO revocation input → would report valid")
	}
}

func repoVectorsDir() string {
	// Derive the repo root from this source file's location:
	// tools/qa/l2-go/main.go -> ../../../vectors. Allows `go run` from anywhere.
	_, self, _, ok := runtime.Caller(0)
	if ok {
		root := filepath.Join(filepath.Dir(self), "..", "..", "..")
		if abs, err := filepath.Abs(filepath.Join(root, "specora_verify", "vectors")); err == nil {
			if _, statErr := os.Stat(abs); statErr == nil {
				return abs
			}
		}
	}
	// Fallback: walk up from cwd looking for a vectors/ dir.
	wd, _ := os.Getwd()
	for d := wd; d != "/" && d != ""; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "specora_verify", "vectors")); err == nil {
			return filepath.Join(d, "specora_verify", "vectors")
		}
	}
	return "vectors"
}

func main() {
	root := repoVectorsDir()
	j := func(p ...string) string { return filepath.Join(append([]string{root}, p...)...) }

	// 6 payload vectors with source+canonical+sha
	checkPayload("attestation-manifest", j("manifest", "attestation-manifest-1.0.0.json"),
		j("manifest", "attestation-manifest-1.0.0.canonical.json"),
		j("manifest", "attestation-manifest-1.0.0.sha256.txt"))
	checkPayload("proof-manifest", j("manifest", "proof-manifest-1.0.0.json"),
		j("manifest", "proof-manifest-1.0.0.canonical.json"),
		j("manifest", "proof-manifest-1.0.0.sha256.txt"))
	checkPayload("anchor-payload", j("anchor", "anchor-payload-1.0.0.json"),
		j("anchor", "anchor-payload-1.0.0.canonical.json"),
		j("anchor", "anchor-payload-1.0.0.sha256.txt"))
	checkPayload("anchor-receipt", j("anchor-receipts", "anchor-receipt-1.0.0.json"),
		j("anchor-receipts", "anchor-receipt-1.0.0.canonical.json"),
		j("anchor-receipts", "anchor-receipt-1.0.0.sha256.txt"))
	checkPayload("certification-attestation", j("certification", "certification-attestation-1.0.0.json"),
		j("certification", "certification-attestation-1.0.0.canonical.json"),
		j("certification", "certification-attestation-1.0.0.sha256.txt"))
	checkPayload("stp-certification-attestation", j("stp-certification", "compatible", "stp-certification-attestation-1.0.0.json"),
		j("stp-certification", "compatible", "stp-certification-attestation-1.0.0.canonical.json"),
		j("stp-certification", "compatible", "stp-certification-attestation-1.0.0.sha256.txt"))

	// signature envelope (payload #7)
	checkSignatureVector(j("signature", "signed-artifact-001"))

	// canonical-bundle vectors: idempotency only (no source/sha shipped)
	for _, f := range []string{
		"canonical-bundle-anthropic-1.0.0.canonical.json",
		"canonical-bundle-cloudtrail-1.0.0.canonical.json",
	} {
		checkIdempotent("bundle:"+strings.TrimSuffix(f, "-1.0.0.canonical.json"), j("canonical-bundle", f))
	}
	for _, f := range []string{
		"canonical-bundle-with-identity-1.0.0.canonical.json",
		"canonical-bundle-mixed-identity-1.0.0.canonical.json",
		"canonical-bundle-partial-identity-1.0.0.canonical.json",
		"canonical-bundle-empty-with-identity-allowed-1.0.0.canonical.json",
	} {
		checkIdempotent("bundle:"+strings.TrimSuffix(f, "-1.0.0.canonical.json"),
			j("canonical-bundle", "with-agent-identity", f))
	}

	// agent-identity certs
	checkAgentIdentity(j("agent-identity", "valid.json"), "valid", "valid")
	checkAgentIdentity(j("agent-identity", "expired.json"), "expired", "expired")
	checkAgentIdentity(j("agent-identity", "revoked.json"), "revoked", "revoked")

	// ---- report
	fmt.Println(strings.Repeat("=", 92))
	fmt.Println("SPECORA WIRE SPEC v1.0 — LEVEL 2 INDEPENDENT GO REIMPLEMENTATION (byte-parity)")
	fmt.Println(strings.Repeat("=", 92))
	fmt.Printf("%-34s %-34s %-6s\n", "VECTOR", "CHECK", "RESULT")
	fmt.Println(strings.Repeat("-", 92))
	pass, fail, flag := 0, 0, 0
	for _, r := range rows {
		mark := r.status
		switch r.status {
		case PASS:
			pass++
		case FAIL:
			fail++
			mark = "*** FAIL ***"
		case FLAG:
			flag++
		}
		fmt.Printf("%-34s %-34s %-6s\n", r.name, r.check, mark)
		if r.status != PASS {
			fmt.Printf("    └─ %s\n", r.detail)
		}
	}
	fmt.Println(strings.Repeat("-", 92))
	fmt.Printf("checks: %d   PASS: %d   FAIL: %d   FLAG: %d\n", len(rows), pass, fail, flag)
	fmt.Println(strings.Repeat("=", 92))
	if fail > 0 {
		os.Exit(1)
	}
}
