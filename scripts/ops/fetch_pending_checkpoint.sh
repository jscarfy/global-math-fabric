#!/usr/bin/env bash
set -euo pipefail
API_BASE="${API_BASE:-http://localhost:8080}"
OUT="${OUT:-/tmp/pending_checkpoint.json}"

curl -fsS "$API_BASE/ledger/checkpoint/pending" > "$OUT"
echo "Wrote: $OUT"
echo "MSG:"
python3 - <<PY
import json
d=json.load(open("$OUT","r",encoding="utf-8"))
print(d.get("msg",""))
PY
