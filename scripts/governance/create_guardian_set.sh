#!/usr/bin/env bash
set -euo pipefail

SET_ID="${1:-guardian_set_v2}"
N="${2:-5}"
THRESHOLD="${3:-3}"

VAULT_DIR="governance/vault/$SET_ID"
PUB_DIR="governance/signers/$SET_ID"
mkdir -p "$VAULT_DIR" "$PUB_DIR"

# generate N ed25519 keypairs
for i in $(seq 1 "$N"); do
  PRIV="$VAULT_DIR/guardian-$i.ed25519.priv.pem"
  PUB="$PUB_DIR/guardian-$i.ed25519.pub.pem"
  if [ -f "$PRIV" ]; then
    echo "exists: $PRIV"
    continue
  fi
  openssl genpkey -algorithm Ed25519 -out "$PRIV"
  openssl pkey -in "$PRIV" -pubout -out "$PUB"
  echo "generated $SET_ID guardian-$i"
done

# build guardian_set json
OUT_JSON="governance/signers/${SET_ID}.json"
{
  echo '{'
  echo "  \"guardian_set_id\": \"${SET_ID}\","
  echo "  \"threshold\": ${THRESHOLD},"
  echo '  "signers": ['
  for i in $(seq 1 "$N"); do
    comma=","
    [ "$i" = "$N" ] && comma=""
    echo "    {\"id\":\"${SET_ID}:guardian-$i\",\"pub_pem\":\"governance/signers/${SET_ID}/guardian-$i.ed25519.pub.pem\"}${comma}"
  done
  echo '  ]'
  echo '}'
} > "$OUT_JSON"

# update registry
python3 - <<PY
import json
reg_path="governance/signers/registry.json"
reg=json.load(open(reg_path,"r",encoding="utf-8"))
reg.setdefault("sets",{})
reg["sets"]["$SET_ID"]="governance/signers/${SET_ID}.json"
# do NOT auto-activate; activation is a governance act (you can edit later)
json.dump(reg, open(reg_path,"w",encoding="utf-8"), ensure_ascii=False, sort_keys=True, indent=2)
print("Updated registry:", reg_path)
PY

echo "Wrote: $OUT_JSON"
echo "Vault keys in: $VAULT_DIR (DO NOT COMMIT)"
