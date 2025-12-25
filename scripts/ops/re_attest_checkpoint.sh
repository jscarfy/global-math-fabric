#!/usr/bin/env bash
set -euo pipefail

# Re-attest a historical checkpoint msg with a NEW guardian set (ed25519 for now).
# Usage:
#   ./scripts/ops/re_attest_checkpoint.sh <checkpoint_json> <new_guardian_set_id>
CP_JSON="${1:?checkpoint json required}"
NEW_SET_ID="${2:?new guardian_set_id required}"

REG="governance/signers/registry.json"
NEW_SET_JSON="$(python3 - <<PY
import json
reg=json.load(open("$REG","r",encoding="utf-8"))
print(reg["sets"]["$NEW_SET_ID"])
PY
)"

OLD_SET_ID="$(python3 - <<PY
import json
cp=json.load(open("$CP_JSON","r",encoding="utf-8"))
print(cp.get("guardian_set_id",""))
PY
)"

MSG="$(python3 - <<PY
import json
cp=json.load(open("$CP_JSON","r",encoding="utf-8"))
print(cp["msg"])
PY
)"

# The re-attestation message binds the old msg hash + new set id + timestamp
OLD_MSG_SHA="$(python3 - <<PY
import hashlib,sys
print(hashlib.sha256(sys.stdin.read().encode('utf-8')).hexdigest())
PY <<<"$MSG")"

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
ATTEST_MSG="GMF_REATTEST|old_msg_sha256:$OLD_MSG_SHA|new_guardian_set_id:$NEW_SET_ID|ts:$TS"
TMP="/tmp/gmf_reattest_msg.txt"
echo -n "$ATTEST_MSG" > "$TMP"

THR="$(python3 - <<PY
import json
d=json.load(open("$NEW_SET_JSON","r",encoding="utf-8"))
print(d["threshold"])
PY
)"

SIGS=()
for PRIV in governance/vault/$NEW_SET_ID/*.ed25519.priv.pem; do
  SID="$(basename "$PRIV" | sed 's/.ed25519.priv.pem//')"
  FULL_SID="$NEW_SET_ID:$SID"
  SIG_B64="$(openssl pkeyutl -sign -inkey "$PRIV" -rawin -in "$TMP" | openssl base64 -A)"
  SIGS+=("{\"signer\":\"$FULL_SID\",\"sig_b64\":\"$SIG_B64\"}")
done

OUT="ledger/attestations/reattest-${OLD_MSG_SHA}-to-${NEW_SET_ID}-${TS}.json"
cat > "$OUT" <<EOF2
{
  "attestation_v": 1,
  "kind": "checkpoint_re_attestation",
  "issued_at": "$TS",
  "old_checkpoint_guardian_set_id": "$OLD_SET_ID",
  "old_checkpoint_msg_sha256": "$OLD_MSG_SHA",
  "new_guardian_set_id": "$NEW_SET_ID",
  "msg": "$ATTEST_MSG",
  "sig_suite": "ed25519",
  "threshold": $THR,
  "signatures": [$(IFS=, ; echo "${SIGS[*]}")],
  "note": "This re-attests the old checkpoint message hash under a newer guardian set."
}
EOF2

echo "Wrote $OUT"
