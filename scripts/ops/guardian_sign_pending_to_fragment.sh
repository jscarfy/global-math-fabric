#!/usr/bin/env bash
set -euo pipefail

PENDING_JSON="${1:?pending_checkpoint.json required}"
PRIV_PEM="${2:?guardian private pem required}"
GUARDIAN_ID="${3:?guardian id required}"
OUT="${4:-fragment-${GUARDIAN_ID}.json}"

MSG="$(python3 - <<PY
import json
d=json.load(open("$PENDING_JSON","r",encoding="utf-8"))
print(d["msg"])
PY
)"

TMP="/tmp/gmf_guardian_msg.txt"
echo -n "$MSG" > "$TMP"

SIG_B64="$(openssl pkeyutl -sign -inkey "$PRIV_PEM" -rawin -in "$TMP" | openssl base64 -A)"

python3 - <<PY
import json
out={"signer":"$GUARDIAN_ID","sig_b64":"$SIG_B64"}
json.dump(out, open("$OUT","w",encoding="utf-8"), ensure_ascii=False, sort_keys=True, indent=2)
print("Wrote:", "$OUT")
PY
