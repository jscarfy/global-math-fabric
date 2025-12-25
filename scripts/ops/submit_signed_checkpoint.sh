#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8080}"
SIGNED_JSON="${1:?signed_checkpoint.json required}"

echo "[1/2] submit checkpoint..."
curl -fsS -X POST "$API_BASE/ledger/checkpoint/submit" \
  -H "Content-Type: application/json" \
  --data-binary @"$SIGNED_JSON" | python3 -m json.tool | head -n 80

echo
echo "[2/2] checkpoint status..."
curl -fsS "$API_BASE/ledger/checkpoint/status" | python3 -m json.tool | head -n 80
