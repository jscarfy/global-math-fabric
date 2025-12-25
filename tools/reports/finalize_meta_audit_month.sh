#!/usr/bin/env bash
set -euo pipefail
YM="${1:-}"
RELAY="${GMF_RELAY:-}"
TOKEN="${GMF_ADMIN_TOKEN:-}"
[[ -n "$YM" ]] || { echo "Usage: finalize_meta_audit_month.sh YYYY-MM" >&2; exit 2; }
[[ -n "$RELAY" ]] || { echo "Set GMF_RELAY" >&2; exit 2; }
curl -fsS "${RELAY}/v1/meta_audit/finalize/${YM}?token=${TOKEN}" | head -n 80
