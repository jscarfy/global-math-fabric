#!/usr/bin/env bash
set -euo pipefail

: "${GMF_RELAY:?Set GMF_RELAY}"
: "${GMF_ADMIN_TOKEN:?Set GMF_ADMIN_TOKEN}"

YM="$(python3 - <<'PY'
from datetime import date
y,m = date.today().year, date.today().month
m -= 1
if m == 0: y, m = y-1, 12
print(f"{y:04d}-{m:02d}")
PY
)"

echo "[auto] last month = $YM"

# 1) canonical_export（會先 triple-anchor gate: report-side）
./tools/reports/export_monthly_canonical.sh "$YM" || true

# 2) 等 helper 產 receipts
sleep 20

# 3) finalize export_audit_final（write-once）
./tools/reports/finalize_export_audit_month.sh "$YM" || true

# 4) 等 helper 對 canonical_export + export_audit_final 做 meta_attest
sleep 15

# 5) finalize period meta_audit_final（write-once）
./tools/reports/finalize_meta_audit_month.sh "$YM" || true

# 6) export triple-anchor gate + publish bundle
./tools/reports/verify_export_triple_anchor.sh monthly "$YM"
./tools/publish/package_period.py monthly "$YM"

echo "[auto] DONE monthly $YM"
