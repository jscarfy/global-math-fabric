# Export Audit (v1)

Devices can produce receipts that they verified a canonical_export anchor.

## Log files (append-only)
- Monthly: `ledger/export_audit/monthly/YYYY-MM.export_audit.jsonl`
- Yearly:  `ledger/export_audit/yearly/YYYY.export_audit.jsonl`

## Receipt envelope (one per line)
{
  "export_audit_payload": {
    "report_kind": "monthly" | "yearly",
    "period_id": "YYYY-MM" | "YYYY",
    "target_export_rollup_sha256": "<canonical_export_payload.rollup.export_rollup_sha256>",
    "verifier_result_ok": true,
    "verifier_detail": { ... },
    "device_id": "<from consent>",
    "device_pubkey_b64": "...",
    "server_time_unix_ms": 123
  },
  "server_pubkey_b64": "...",
  "server_sig_b64": "..." // signature over SHA256(canonical_json_bytes(export_audit_payload))
}

## Final anchor (write-once)
- Monthly: `ledger/export_audit/monthly/YYYY-MM.export_audit_final.json`
- Yearly:  `ledger/export_audit/yearly/YYYY.export_audit_final.json`

Final payload binds:
- export_audit_log_sha256
- counts (ok/bad/unique_devices)
