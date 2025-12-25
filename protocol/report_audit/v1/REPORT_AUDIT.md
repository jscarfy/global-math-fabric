# Report Audit (v1)

Devices can produce receipts that they verified a monthly/yearly report anchor.

## Log files (append-only)
- Monthly: `ledger/report_audit/monthly/YYYY-MM.report_audit.jsonl`
- Yearly:  `ledger/report_audit/yearly/YYYY.report_audit.jsonl`

## Receipt envelope (one per line)
{
  "report_audit_payload": {
    "report_kind": "monthly" | "yearly",
    "period_id": "YYYY-MM" | "YYYY",
    "target_rollup_sha256": "<report rollup sha256>",
    "verifier_result_ok": true,
    "verifier_detail": { ... },  // optional diagnostic
    "device_id": "<from consent>",
    "device_pubkey_b64": "...",
    "server_time_unix_ms": 123
  },
  "server_pubkey_b64": "...",
  "server_sig_b64": "..." // signature over SHA256(canonical_json_bytes(report_audit_payload))
}

## Final anchor (write-once)
- Monthly: `ledger/report_audit/monthly/YYYY-MM.report_audit_final.json`
- Yearly:  `ledger/report_audit/yearly/YYYY.report_audit_final.json`

Payload binds:
- report_audit_log_sha256
- counts (ok/bad/unique_devices)
