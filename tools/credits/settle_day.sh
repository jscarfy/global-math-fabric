#!/usr/bin/env bash
set -euo pipefail
DATE="${1:-}"
if [[ -z "$DATE" ]]; then
  echo "Usage: $0 YYYY-MM-DD" >&2
  exit 2
fi

RELAY="${GMF_RELAY:-http://127.0.0.1:8787}"
TOKEN="${GMF_ADMIN_TOKEN:-}"

# 1) ensure final exists (write-once; if already exists, relay returns it)
if [[ -n "$TOKEN" ]]; then
  curl -fsS "${RELAY}/v1/ledger/finalize/${DATE}?token=${TOKEN}" >/dev/null || true
else
  # if no token configured, try finalize without token (only works if relay doesn't enforce)
  curl -fsS "${RELAY}/v1/ledger/finalize/${DATE}" >/dev/null || true
fi

# 2) fetch final to local ledger/snapshots if not present
mkdir -p ledger/snapshots
curl -fsS "${RELAY}/v1/ledger/final/${DATE}" > "ledger/snapshots/${DATE}.final.json"

# 3) export from final

# 3.5) HARD GATE: triple-anchor must exist+verify before any canonical export
./tools/settlement/verify_triple_anchor.sh "${DATE}"

./tools/credits/export_from_final.py "${DATE}"



# 4) fetch audit summary (best-effort) and export audit points
mkdir -p ledger/audit
curl -fsS "${RELAY}/v1/audit/summary/${DATE}" > "ledger/audit/${DATE}.audit_summary.json" || true


# 4.5) fetch audit_final (best-effort; immutable)
curl -fsS "${RELAY}/v1/audit/final/${DATE}" > "ledger/audit/${DATE}.audit_final.json" || true


./tools/audit/export_audit_points.py "${DATE}"

# 4.9) write canonical_totals.json for multi-day reports
./tools/reports/write_canonical_totals.py "${DATE}"

echo "OK: settled ${DATE} using immutable final snapshot anchor."
