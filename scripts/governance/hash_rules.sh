#!/usr/bin/env bash
set -euo pipefail
RULE="$1"
OUT="$2"
CANON="$(cat "$RULE" | ./scripts/governance/canon_json.py)"
python3 - <<PY
import hashlib,sys
s=sys.stdin.read().encode("utf-8")
print(hashlib.sha256(s).hexdigest())
PY <<<"$CANON" > "$OUT"
