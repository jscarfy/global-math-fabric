#!/usr/bin/env bash
set -euo pipefail
Y="${1:-}"
RELAY="${GMF_RELAY:-}"
TOKEN="${GMF_ADMIN_TOKEN:-}"
[[ -n "$Y" ]] || { echo "Usage: finalize_year.sh YYYY" >&2; exit 2; }
[[ -n "$RELAY" ]] || { echo "Set GMF_RELAY" >&2; exit 2; }

curl -fsS "${RELAY}/v1/reports/yearly/finalize/${Y}?token=${TOKEN}" | head -n 80
