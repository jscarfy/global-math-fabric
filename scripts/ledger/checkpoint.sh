#!/usr/bin/env bash
set -euo pipefail
ROOT_HEX="$(./scripts/ledger/merkle_root.py)"
RULE_SHA="$(cat governance/rules/v1.sha256)"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
MSG="GMF_LEDGER_CHECKPOINT|$ROOT_HEX|$RULE_SHA|$TS"

TMP="/tmp/gmf_checkpoint_msg.txt"
echo -n "$MSG" > "$TMP"

mkdir -p ledger/checkpoints
OUT="ledger/checkpoints/checkpoint-$TS.json"

SIGS=()
for PRIV in governance/vault/*.ed25519.priv.pem; do
  ID="$(basename "$PRIV" | sed 's/.ed25519.priv.pem//')"
  SIG_B64="$(openssl pkeyutl -sign -inkey "$PRIV" -rawin -in "$TMP" | openssl base64 -A)"
  SIGS+=("{\"signer\":\"$ID\",\"sig_b64\":\"$SIG_B64\"}")
done

cat > "$OUT" <<EOF
{
  "checkpoint_v": 1,
  "ts": "$TS",
  "ledger_root_sha256": "$ROOT_HEX",
  "rules_sha256": "$RULE_SHA",
  "guardian_set_id": "guardian_set_v1",
  "msg": "$MSG",
  "sig_suite": "ed25519",
  "threshold": 2,
  "signatures": [$(IFS=, ; echo "${SIGS[*]}")]
}
