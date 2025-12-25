# Multi-day Report Anchor (v1)

A monthly/yearly report is a **write-once** server-signed anchor that aggregates only dates satisfying the **Triple Anchor Rule**.

## Paths
- Monthly: `ledger/reports/monthly/YYYY-MM.monthly_final.json`
- Yearly:  `ledger/reports/yearly/YYYY.yearly_final.json`

## Payload schema (monthly_final_payload / yearly_final_payload)
- kind: "monthly" | "yearly"
- period_id: "YYYY-MM" | "YYYY"
- generated_at_unix_ms: int
- included_dates: [ "YYYY-MM-DD", ... ] (UTC dates)
- excluded_dates: [ ... ] (optional; for transparency)
- aggregates:
  - days_count: int
  - sum_main_credits_micro: int|null (optional; can be filled by settlement pipeline)
  - sum_audit_points_micro: int|null (optional)
- bindings:
  - daily_final_ssr_sha256_list: [hex...]
  - daily_audit_log_sha256_list: [hex...]
  - daily_meta_audit_log_sha256_list: [hex...]
- merkle_or_rollup:
  - rollup_sha256: hex  // sha256(canonical_json_bytes(bindings + included_dates))
  - method: "sha256_canon_v1"

## Envelope
{
  "<kind>_final_payload": <payload>,
  "server_pubkey_b64": "...",
  "server_sig_b64": "..." // signature over SHA256(canonical_json_bytes(payload))
}

## Immutability
Write-once. If file exists, it MUST NOT be overwritten.
