#!/usr/bin/env bash
set -euo pipefail
DAY="${1:?usage: anchor_merkle_roots_to_daily_extras.sh YYYY-MM-DD}"
OUTDIR="ledger/daily_roots_extras/$DAY"
mkdir -p "$OUTDIR"

# collect all merkle root json files for that day
python3 - <<PY
import glob, hashlib, json, os, sys
day=sys.argv[1]
files=glob.glob("ledger/merkle_roots/*/%s.json"%day)
h=hashlib.sha256()
for fp in sorted(files):
    with open(fp,'rb') as f:
        h.update(f.read())
print(h.hexdigest())
PY "$DAY" > "$OUTDIR/merkle_roots_sha256.txt"

echo "Anchored: $OUTDIR/merkle_roots_sha256.txt"
