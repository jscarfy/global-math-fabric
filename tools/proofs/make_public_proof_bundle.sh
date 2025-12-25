#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:?usage: make_public_proof_bundle.sh BASE_URL ACCOUNT DAY IDX [OUT.tar.gz]}"
ACCOUNT="${2:?}"
DAY="${3:?}"
IDX="${4:?}"
OUT="${5:-dist/proofs/proof_${ACCOUNT}_${DAY}_idx${IDX}.tar.gz}"

tmp="$(mktemp -d)"

# 1) fetch merkle root + proof
curl -fsSL "$BASE_URL/api/merkle/root/$ACCOUNT/$DAY"  -o "$tmp/merkle_root.json"
curl -fsSL "$BASE_URL/api/merkle/proof/$ACCOUNT/$DAY/$IDX" -o "$tmp/merkle_proof.json"

# 2) best-effort fetch daily_root json file for that day:
#    如果你后续愿意，我可以给 daily_root 做一个明确 API；目前先从 repo 文件夹复制（需要本地有 ledger）
if compgen -G "ledger/daily_roots/**/*${DAY}*.json" > /dev/null; then
  # pick largest json as "main"
  DR="$(ls -S ledger/daily_roots/**/*${DAY}*.json 2>/dev/null | head -n 1)"
  cp "$DR" "$tmp/daily_root.json"
fi

# 3) include policies + audit snapshot (optional but helpful)
if [ -d ledger/policies ]; then cp -R ledger/policies "$tmp/policies"; fi
if [ -d ledger/audit ]; then cp -R ledger/audit "$tmp/audit"; fi

# 4) pack
tar -czf "$OUT" -C "$tmp" .
rm -rf "$tmp"
echo "Wrote $OUT"
