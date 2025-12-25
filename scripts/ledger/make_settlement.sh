#!/usr/bin/env bash
set -euo pipefail
# usage: make_settlement.sh YYYY-MM-DD SERVER_SK_B64 [PREV_ROOT_HEX]
DATE="${1:?}"
SERVER_SK_B64="${2:?}"
PREV="${3:-}"

IN="ledger/inbox/${DATE}.ssr.jsonl"
OUT="releases/ledger/${DATE}.json"
POLICY="protocol/credits/v1/CREDITS_POLICY.md"

[ -f "$IN" ] || { echo "Missing $IN" 1>&2; exit 2; }

mkdir -p releases/ledger

ARGS=(--in-jsonl "$IN" --out-json "$OUT" --date "$DATE" --policy-path "$POLICY" --server-sk-b64 "$SERVER_SK_B64")
if [ -n "$PREV" ]; then
  ARGS+=(--prev-root-hex "$PREV")
fi

cargo run -q --manifest-path native/Cargo.toml -p gmf_ledger -- "${ARGS[@]}"

echo "Wrote $OUT"
