# gmf/task_result/v1 — ledger_audit

## Task params (gmf/task/v1)
- kind = "ledger_audit"
- params.date: "YYYY-MM-DD" (required)
- params.ledger_endpoint: string (optional; default "/v1/ledger/ssr/<date>")
- params.top_n: int (default 1000)
- params.expected_policy_id: string (optional)

## result_core fields
- ok: bool
- exit_code: int
- date: string
- ssr_total: int
- credits_devices: int
- credits_total_micro: int
- leaderboard_top_n: int
- leaderboard_digest_sha256: string
- credits_export_digest_sha256: string
- relay_base_url: string
- notes: string (optional)

## Determinism
- credits_export_digest_sha256 MUST be sha256 over canonical JSON (sorted keys, no whitespace) of:
  {"date":..., "credits_micro_by_device_id":{...}}
- leaderboard_digest_sha256 MUST be sha256 over canonical JSON of:
  {"date":..., "entries":[{"device_id":..., "credits_micro":...}, ... top_n ...]}
