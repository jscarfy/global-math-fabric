#!/usr/bin/env bash
set -euo pipefail

: "${GMF_RELAY:?Set GMF_RELAY}"
: "${GMF_ADMIN_TOKEN:?Set GMF_ADMIN_TOKEN}"

Y="$(python3 - <<'PY'
from datetime import date
print(f"{date.today().year-1:04d}")
PY
)"

echo "[auto] last year = $Y"

./tools/reports/export_yearly_canonical.sh "$Y" || true
sleep 20
./tools/reports/finalize_export_audit_year.sh "$Y" || true
sleep 15
./tools/reports/finalize_meta_audit_year.sh "$Y" || true

./tools/reports/verify_export_triple_anchor.sh yearly "$Y"
./tools/publish/package_period.py yearly "$Y"

echo "[auto] DONE yearly $Y"
