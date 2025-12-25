#!/usr/bin/env bash
set -euo pipefail
RULE="governance/rules/v1.json"
HASH_FILE="governance/rules/v1.sha256"
SIGSET_OUT="governance/rules/v1.sigset.json"

RULE_HASH="$(cat "$HASH_FILE")"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# message = "GMF_RULES_V1|<sha256>|<timestamp>"
MSG="GMF_RULES_V1|$RULE_HASH|$TS"
TMP="/tmp/gmf_rules_msg.txt"
echo -n "$MSG" > "$TMP"

# produce signatures
SIGS=()
for PRIV in governance/vault/*.ed25519.priv.pem; do
  ID="$(basename "$PRIV" | sed 's/.ed25519.priv.pem//')"
  SIG_B64="$(openssl pkeyutl -sign -inkey "$PRIV" -rawin -in "$TMP" | openssl base64 -A)"
  SIGS+=("{\"signer\":\"$ID\",\"sig_b64\":\"$SIG_B64\"}")
done

cat > "$SIGSET_OUT" <<EOF
{
  "rules_version": "v1",
  "rules_sha256": "$RULE_HASH",
  "msg": "$MSG",
  "issued_at": "$TS",
  "sig_suite": "ed25519",
  "threshold": 2,
  "signatures": [$(IFS=, ; echo "${SIGS[*]}")]
}
