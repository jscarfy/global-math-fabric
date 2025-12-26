# Credit Statement Final (v1)

A period-final deterministic aggregation of accepted receipts.

## credit_statement_final_payload
- version: "credit_statement_final_v1"
- report_kind: "monthly"|"yearly"
- period_id: string
- credit_policy_sha256: hex string
- receipts_log_sha256: hex string   # sha256(receipts.jsonl for that period)
- total_minted_micro: int64
- device_credits: array of { device_pubkey_b64, minted_micro } sorted by (minted desc, pubkey asc)
- generated_at_unix_ms: int64

## envelope
- credit_statement_final_payload
- server_pubkey_b64
- server_sig_b64   # ed25519 over sha256(canonical(payload))
