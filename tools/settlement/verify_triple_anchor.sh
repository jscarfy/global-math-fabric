#!/usr/bin/env bash
set -euo pipefail

DATE="${1:-}"
if [[ -z "$DATE" ]]; then
  echo "Usage: $0 YYYY-MM-DD" >&2
  exit 2
fi

# required files
FINAL="ledger/snapshots/${DATE}.final.json"
AUDIT_FINAL="ledger/audit/${DATE}.audit_final.json"
META_FINAL="ledger/meta_audit/${DATE}.meta_audit_final.json"

[[ -f "$FINAL" ]] || { echo "FATAL: missing $FINAL" >&2; exit 2; }
[[ -f "$AUDIT_FINAL" ]] || { echo "FATAL: missing $AUDIT_FINAL" >&2; exit 2; }
[[ -f "$META_FINAL" ]] || { echo "FATAL: missing $META_FINAL" >&2; exit 2; }

# verify signatures + hashes (via Rust CLIs)
native/target/release/gmf_final_verify --final-path "$FINAL" --verify-inbox true
native/target/release/gmf_audit_final_verify --audit-final-path "$AUDIT_FINAL" --verify-audit-log true
native/target/release/gmf_meta_audit_final_verify --meta-audit-final-path "$META_FINAL" --verify-meta-audit-log true

echo "OK: triple-anchor verified for ${DATE}"
