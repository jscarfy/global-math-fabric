#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/governance/certify_guardian_set_transition.sh <OLD_SET_ID> <NEW_SET_ID>
OLD_SET_ID="${1:?old guardian_set_id required}"
NEW_SET_ID="${2:?new guardian_set_id required}"

REG="governance/signers/registry.json"

OLD_SET_JSON="$(python3 - <<PY
import json
reg=json.load(open("$REG","r",encoding="utf-8"))
print(reg["sets"]["$OLD_SET_ID"])
PY
)"
NEW_SET_JSON="$(python3 - <<PY
import json
reg=json.load(open("$REG","r",encoding="utf-8"))
print(reg["sets"]["$NEW_SET_ID"])
PY
)"

# canonical sha256(new_guardian_set_json)
NEW_CANON="$(cat "$NEW_SET_JSON" | ./scripts/governance/canon_json.py)"
NEW_SHA="$(python3 - <<PY
import hashlib,sys
s=sys.stdin.read().encode("utf-8")
print(hashlib.sha256(s).hexdigest())
PY <<<"$NEW_CANON")"

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
MSG="GMF_GUARDIAN_SET_TRANSITION|old:$OLD_SET_ID|new:$NEW_SET_ID|new_set_sha256:$NEW_SHA|ts:$TS"
TMP="/tmp/gmf_transition_msg.txt"
echo -n "$MSG" > "$TMP"

# threshold from OLD set json
THR="$(python3 - <<PY
import json
d=json.load(open("$OLD_SET_JSON","r",encoding="utf-8"))
print(d["threshold"])
PY
)"

# private keys location:
# - preferred: governance/vault/<OLD_SET_ID>/*.priv.pem
# - legacy v1: governance/vault/*.priv.pem
PRIV_GLOB="governance/vault/$OLD_SET_ID/*.ed25519.priv.pem"
if ! ls $PRIV_GLOB >/dev/null 2>&1; then
  PRIV_GLOB="governance/vault/*.ed25519.priv.pem"
fi

SIGS=()
for PRIV in $PRIV_GLOB; do
  BASE="$(basename "$PRIV" | sed 's/.ed25519.priv.pem//')"
  # signer id must match what's in guardian_set json:
  # - if keys under vault/<set>, we use "<set>:<base>"
  # - else (legacy), use "<base>" and also try "<set>:<base>" (keep both)
  if [[ "$PRIV" == governance/vault/$OLD_SET_ID/* ]]; then
    SID="$OLD_SET_ID:$BASE"
  else
    # legacy v1 keys were "guardian-1"... and guardian_set_v1.json likely uses "guardian-1"
    SID="$BASE"
  fi
  SIG_B64="$(openssl pkeyutl -sign -inkey "$PRIV" -rawin -in "$TMP" | openssl base64 -A)"
  SIGS+=("{\"signer\":\"$SID\",\"sig_b64\":\"$SIG_B64\"}")
done

OUT="governance/signers/transitions/transition-${OLD_SET_ID}-to-${NEW_SET_ID}-${TS}.json"
cat > "$OUT" <<EOF2
{
  "transition_v": 1,
  "kind": "guardian_set_transition",
  "issued_at": "$TS",
  "old_guardian_set_id": "$OLD_SET_ID",
  "new_guardian_set_id": "$NEW_SET_ID",
  "new_guardian_set_sha256": "$NEW_SHA",
  "msg": "$MSG",
  "sig_suite": "ed25519",
  "threshold": $THR,
  "signatures": [$(IFS=, ; echo "${SIGS[*]}")]
}
EOF2

echo "Wrote $OUT"
echo "MSG: $MSG"
