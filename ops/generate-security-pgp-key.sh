#!/usr/bin/env bash
#
# generate-security-pgp-key.sh
#
# Ops runbook script for generating the security@specora.ai PGP key used
# for private vulnerability disclosure on specora-verify (and any other
# Specora OSS project that references this key in its SECURITY.md).
#
# === Why this exists as a runbook, not an automated job ===
#
# PGP keys for security disclosure are the root of a trust chain.  If the
# private key is compromised, an attacker can read embargoed vulnerability
# reports before they are fixed.  The private key MUST therefore:
#
#   1. Be generated on a hardened workstation you control (not a CI runner,
#      not an AI-agent sandbox, not a shared dev machine).
#   2. Have its master key stored offline (air-gapped USB, hardware token,
#      or at minimum a dedicated password manager entry).
#   3. Have a clear custodian (a named human, not a role inbox).
#   4. Have a documented rotation schedule (this script uses a 3-year expiry).
#
# Run this script ONCE, interactively, on a trusted workstation.  Follow
# the checklist at the end to publish the public key and hand the private
# key to the security custodian.
#
# === Requirements ===
#
#   - GnuPG 2.2+ (macOS: brew install gnupg ; Linux: apt install gnupg)
#   - A named human custodian for the private key
#   - Access to https://github.com/SpecoraAI/specora-verify to commit
#     the public key block into SECURITY.md
#   - Access to the specora.ai web root to publish
#     /.well-known/security.txt
#
# === Usage ===
#
#   ./generate-security-pgp-key.sh
#
# The script creates an ISOLATED GnuPG home at ./gnupg-specora-security/
# so your personal PGP keyring is untouched.  When the script finishes,
# the isolated home contains the only copy of the private key on disk.
# Move it to secure storage and delete the working directory.
#
# === What you get ===
#
#   ./gnupg-specora-security/            isolated GnuPG home (contains
#                                        private key — secure storage)
#   ./specora-security-public.asc        ASCII-armored public key block
#                                        (safe to commit to the repo and
#                                        publish anywhere)
#   ./specora-security-fingerprint.txt   40-char fingerprint for
#                                        inclusion in SECURITY.md
#   ./specora-security-revocation.asc    revocation certificate — STORE
#                                        THIS SEPARATELY from the private
#                                        key, ideally on offline media
#
set -euo pipefail

# ----- configuration -----
REAL_NAME="Specora Security"
EMAIL="security@specora.ai"
COMMENT="Vulnerability disclosure key — SpecoraAI/specora-verify"
KEY_TYPE="EDDSA"
KEY_CURVE="Ed25519"
SUBKEY_TYPE="ECDH"
SUBKEY_CURVE="Curve25519"
EXPIRY="3y"

GNUPGHOME_LOCAL="$(pwd)/gnupg-specora-security"
PUBLIC_OUT="$(pwd)/specora-security-public.asc"
FINGERPRINT_OUT="$(pwd)/specora-security-fingerprint.txt"
REVOCATION_OUT="$(pwd)/specora-security-revocation.asc"

# ----- preflight -----
if ! command -v gpg >/dev/null 2>&1; then
    echo "ERROR: gpg is not installed.  On macOS: brew install gnupg" >&2
    exit 1
fi

if [[ -e "$GNUPGHOME_LOCAL" ]]; then
    echo "ERROR: $GNUPGHOME_LOCAL already exists.  Refusing to overwrite." >&2
    echo "If this is a retry, move the old directory aside first." >&2
    exit 1
fi

mkdir -p "$GNUPGHOME_LOCAL"
chmod 700 "$GNUPGHOME_LOCAL"
export GNUPGHOME="$GNUPGHOME_LOCAL"

echo "=== Specora security PGP key generation ==="
echo "Isolated GnuPG home: $GNUPGHOME_LOCAL"
echo
echo "You will be prompted for a passphrase.  Requirements:"
echo "  - At least 20 characters"
echo "  - Generated from a password manager, not typed from memory"
echo "  - Stored in the password manager entry tagged 'specora-security-pgp'"
echo
read -r -p "Press ENTER when ready to generate the key..."

# ----- key generation via batch file (non-interactive for key params,
#       still prompts for passphrase) -----
BATCH_FILE="$(mktemp)"
trap 'rm -f "$BATCH_FILE"' EXIT

cat > "$BATCH_FILE" <<EOF
%echo Generating Specora security disclosure key
Key-Type: $KEY_TYPE
Key-Curve: $KEY_CURVE
Key-Usage: sign cert
Subkey-Type: $SUBKEY_TYPE
Subkey-Curve: $SUBKEY_CURVE
Subkey-Usage: encrypt
Name-Real: $REAL_NAME
Name-Comment: $COMMENT
Name-Email: $EMAIL
Expire-Date: $EXPIRY
%ask-passphrase
%commit
%echo Done
EOF

gpg --batch --generate-key "$BATCH_FILE"

# ----- capture fingerprint and export public key -----
FPR=$(gpg --list-secret-keys --with-colons "$EMAIL" \
        | awk -F: '/^fpr:/ { print $10; exit }')

if [[ -z "$FPR" ]]; then
    echo "ERROR: failed to read fingerprint after generation" >&2
    exit 1
fi

echo "$FPR" > "$FINGERPRINT_OUT"
gpg --armor --export "$FPR" > "$PUBLIC_OUT"

# ----- generate revocation certificate -----
# This allows revoking the key even if the private key is lost.
# STORE IT SEPARATELY from the private key.
gpg --output "$REVOCATION_OUT" --gen-revoke --batch --yes \
    --pinentry-mode loopback "$FPR" <<EOF
y
0
No reason given
y
EOF
chmod 600 "$REVOCATION_OUT"

# ----- pretty-print fingerprint for display -----
PRETTY_FPR=$(echo "$FPR" | sed 's/\(....\)/\1 /g' | sed 's/  / /g')

echo
echo "=== Key generated ==="
echo "Fingerprint:  $PRETTY_FPR"
echo "Public key:   $PUBLIC_OUT"
echo "Private key:  inside $GNUPGHOME_LOCAL (MOVE TO SECURE STORAGE)"
echo "Revocation:   $REVOCATION_OUT (STORE SEPARATELY)"
echo
echo "=== Post-generation checklist ==="
cat <<CHECKLIST
  [ ] Copy $PUBLIC_OUT — this is the only artifact safe to publish.
  [ ] Paste the fingerprint above into SECURITY.md (replace the
      TODO(ops) block) and open a PR on SpecoraAI/specora-verify.
  [ ] Upload the public key to at least one keyserver:
          gpg --keyserver hkps://keys.openpgp.org --send-keys $FPR
      Then verify the upload:
          curl -sS "https://keys.openpgp.org/vks/v1/by-fingerprint/$FPR" | head
  [ ] Publish /.well-known/security.txt on specora.ai containing:
          Contact: mailto:security@specora.ai
          Encryption: https://specora.ai/.well-known/security-pubkey.asc
          Preferred-Languages: en
          Canonical: https://specora.ai/.well-known/security.txt
          Expires: <ISO-8601 date 1y from today>
      and publish /.well-known/security-pubkey.asc = $PUBLIC_OUT
  [ ] Move $GNUPGHOME_LOCAL to secure offline storage (encrypted USB,
      YubiKey, password manager attached file, or air-gapped workstation).
      Do NOT leave it on the workstation after this step.
  [ ] Store $REVOCATION_OUT in a DIFFERENT secure location from the
      private key (different vault, different device).  If the private
      key is ever compromised or lost, this file is how we revoke it.
  [ ] Name a custodian for the private key.  Record the custodian in
      docs/strategy/epic-a01-drafts/11-prelaunch-gaps.md and in the
      password manager entry.
  [ ] Calendar a rotation reminder for 30 months from today (6 months
      before the 3-year expiry).
  [ ] Delete the working directory on this workstation:
          rm -rf "$GNUPGHOME_LOCAL" "$FINGERPRINT_OUT"
      Keep only $PUBLIC_OUT (safe) and $REVOCATION_OUT (secure).
CHECKLIST

echo
echo "Key generation complete."
