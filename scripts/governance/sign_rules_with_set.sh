#!/usr/bin/env bash
set -euo pipefail

RULE_PATH="${1:-governance/rules/v1.json}"
SET_ID="${2:-guardian_set_v2}"

REG="governance/signers/registry.json"
SET_JSON="$(python3 - <<PY
import json
reg=json.load(open("$REG","r",encoding="utf-8"))
print(reg["sets"]["$SET_ID"])
PY
)"

RULE_CANON="$(cat "$RULE_PATH" | ./scripts/governance/canon_json.py)"
RULE_SHA="$(python3 - <<PY
import hashlib,sys
s=sys.stdin.read().encode("utf-8")
print(hashlib.sha256(s).hexdigest())
PY <<<"$RULE_CANON")"

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
MSG="GMF_RULES|$RULE_SHA|$SET_ID|$TS"
TMP="/tmp/gmf_rules_msg.txt"
echo -n "$MSG" > "$TMP"

# read threshold + signers count
THR="$(python3 - <<PY
import json
d=json.load(open("$SET_JSON","r",encoding="utf-8"))
print(d["threshold"])
PY
)"

SIGS=()
# private keys assumed under governance/vault/<SET_ID>/guardian-i...
for PRIV in governance/vault/$SET_ID/*.ed25519.priv.pem; do
  SID="$(basename "$PRIV" | sed 's/.ed25519.priv.pem//')"
  FULL_SID="$SET_ID:$SID"
  SIG_B64="$(openssl pkeyutl -sign -inkey "$PRIV" -rawin -in "$TMP" | openssl base64 -A)"
  SIGS+=("{\"signer\":\"$FULL_SID\",\"sig_b64\":\"$SIG_B64\"}")
done

OUT="governance/rules/$(basename "$RULE_PATH" .json).sigset.$SET_ID.json"
cat > "$OUT" <<EOF2
{
  "rules_version": "$(python3 -c "import json;print(json.load(open('$RULE_PATH','r',encoding='utf-8')).get('rules_version','v1'))")",
  "rules_sha256": "$RULE_SHA",
  "guardian_set_id": "$SET_ID",
  "msg": "$MSG",
  "issued_at": "$TS",
  "sig_suite": "ed25519",
  "threshold": $THR,
  "signatures": [$(IFS=, ; echo "${SIGS[*]}")]
}
EOF2

echo "Wrote $OUT"
echo "NOTE: to activate on server, set GMF_RULES_SIGSET_PATH=$OUT (or update env)."
