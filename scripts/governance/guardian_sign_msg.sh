#!/usr/bin/env bash
set -euo pipefail
# Usage:
#   ./scripts/governance/guardian_sign_msg.sh <guardian_priv_pem> <msg_string>
PRIV="$1"
MSG="$2"
TMP="/tmp/gmf_guardian_msg.txt"
echo -n "$MSG" > "$TMP"
SIG_B64="$(openssl pkeyutl -sign -inkey "$PRIV" -rawin -in "$TMP" | openssl base64 -A)"
echo "$SIG_B64"
