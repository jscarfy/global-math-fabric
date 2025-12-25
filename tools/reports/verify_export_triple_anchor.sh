#!/usr/bin/env bash
set -euo pipefail
KIND="${1:-}"   # monthly|yearly
PID="${2:-}"    # YYYY-MM|YYYY
[[ -n "$KIND" && -n "$PID" ]] || { echo "Usage: $0 monthly YYYY-MM | $0 yearly YYYY" >&2; exit 2; }

if [[ "$KIND" == "monthly" ]]; then
  EXP="ledger/reports/monthly/${PID}.monthly_canonical_export.json"
  AUD="ledger/export_audit/monthly/${PID}.export_audit_final.json"
  META="ledger/meta_audit/${PID}.meta_audit_final.json"
elif [[ "$KIND" == "yearly" ]]; then
  EXP="ledger/reports/yearly/${PID}.yearly_canonical_export.json"
  AUD="ledger/export_audit/yearly/${PID}.export_audit_final.json"
  META="ledger/meta_audit/${PID}.meta_audit_final.json"
else
  echo "bad KIND: $KIND" >&2
  exit 2
fi

[[ -f "$EXP"  ]] || { echo "FATAL: missing $EXP" >&2; exit 2; }
[[ -f "$AUD"  ]] || { echo "FATAL: missing $AUD" >&2; exit 2; }
[[ -f "$META" ]] || { echo "FATAL: missing $META" >&2; exit 2; }

native/target/release/gmf_canonical_export_verify --export-path "$EXP"
native/target/release/gmf_meta_audit_final_verify --meta-audit-final-path "$META" --verify-meta-audit-log true

echo "OK: export triple-anchor verified: $KIND $PID"
