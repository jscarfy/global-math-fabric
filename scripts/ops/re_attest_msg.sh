#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/ops/re_attest_msg.sh <msg_file_or_-for-stdin> <new_guardian_set_id>
MSG_IN="${1:?msg input file or - required}"
NEW_SET_ID="${2:?new guardian_set_id required}"
REG="governance/signers/registry.json"

NEW_SET_JSON="$(python3 - <<PY
import json
reg=json.load(open("$REG","r",encoding="utf-8"))
print(reg["sets"]["$NEW_SET_ID"])
PY
)"

# read msg
if [ "$MSG_IN" = "-" ]; then
  MSG="$(cat)"
else
  MSG="$(cat "$MSG_IN")"
fi

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

OUT="ledger/attestations/reattest-${OLD_MSG_SHA}-by-${NEW_SET_ID}-${TS}.json"
cat > "$OUT" <<EOF2
{
  "attestation_v": 1,
  "kind": "msg_hash_re_attestation",
  "issued_at": "$TS",
  "old_msg_sha256": "$OLD_MSG_SHA",
  "new_guardian_set_id": "$NEW_SET_ID",
  "msg": "$ATTEST_MSG",
  "sig_suite": "ed25519",
  "threshold": $THR,
  "signatures": [$(IFS=, ; echo "${SIGS[*]}")]
}
EOF2

echo "Wrote $OUT"
