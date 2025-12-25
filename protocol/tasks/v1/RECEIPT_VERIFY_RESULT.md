# gmf/task_result/v1 — receipt_verify

## Task params (gmf/task/v1)
- kind = "receipt_verify"
- params.date: "YYYY-MM-DD" (required)
- params.ledger_endpoint: string (optional; default "/v1/ledger/ssr/<date>")
- params.require_server_sig: bool (default true)
- params.expected_policy_id: string (optional hard-gate)

## result_core fields
- ok: bool
- exit_code: int
- date: string
- ssr_total: int
- ssr_valid_sig: int
- ssr_invalid_sig: int
- ssr_parse_errors: int
- policy_ids: [string]  (distinct observed)
- ledger_digest_sha256: string
- relay_base_url: string
- notes: string (optional)

## Determinism
ledger_digest_sha256 MUST be the sha256 over the exact downloaded bytes (verbatim) of the SSR JSONL file.
