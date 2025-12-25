#!/usr/bin/env bash
set -euo pipefail

RECEIPTS="${1:?usage: make_proof_bundle.sh /path/to/receipts.jsonl}"
OUT="${2:-proof_bundle.tar.gz}"

tmp="$(mktemp -d)"
cp -R ledger/policies "$tmp/policies"
cp -R ledger/daily_roots "$tmp/daily_roots"
cp -R ledger/audit "$tmp/audit"

# hash receipts (content-address)
python3 - <<PY
import hashlib, sys
p=sys.argv[1]
h=hashlib.sha256()
with open(p,'rb') as f:
    for b in iter(lambda: f.read(1024*1024), b''):
        h.update(b)
print(h.hexdigest())
PY "$RECEIPTS" > "$tmp/receipts_sha256.txt"

tar -czf "$OUT" -C "$tmp" .
rm -rf "$tmp"
echo "Wrote $OUT"
