#!/usr/bin/env bash
set -euo pipefail

# Generates Sparkle Ed25519 keys using Sparkle generate_keys tool.
# Writes:
#   out/sparkle_ed25519_public.txt  (SUPublicEDKey to paste into Info.plist)
#   out/sparkle_ed25519_private.key (private key file; base64 it into SPARKLE_ED25519_PRIVKEY_B64 secret)

mkdir -p out
TOOLS=($(./scripts/release/fetch_sparkle_tools.sh))
GENKEYS="${TOOLS[1]}"

"$GENKEYS" > out/sparkle_keys.txt

# Heuristic split: keep whole output too
cp -f out/sparkle_keys.txt out/sparkle_ed25519_public.txt
# You will manually extract the private key content to a file (varies by Sparkle version output format).
echo ""
echo "Wrote out/sparkle_keys.txt"
echo "Now:"
echo "  - paste SUPublicEDKey into your macOS Info.plist (Sparkle setup)"
echo "  - save the Ed25519 private key to out/sparkle_ed25519_private.key"
echo "  - then: base64 out/sparkle_ed25519_private.key | pbcopy -> set secret SPARKLE_ED25519_PRIVKEY_B64"
