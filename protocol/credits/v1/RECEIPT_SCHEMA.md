# Task Completion Receipt Schema (v1)

A receipt is issued ONLY by Relay (server-signed), after accepting a completed work unit.

## receipt_payload (canonical JSON)
- version: "task_receipt_v1"
- task_id: string
- work_unit_id: string
- device_id: string
- device_pubkey_b64: string
- issued_at_unix_ms: int64
- verifier_result_ok: bool
- minted_credit_micro: int64  (deterministic)
- credit_policy_sha256: hex string
- report_kind: optional ("monthly"|"yearly"|...)
- period_id: optional ("YYYY-MM"|"YYYY"|...)
- detail: small JSON (non-authoritative)

## envelope
- receipt_payload: object
- server_pubkey_b64: string
- server_sig_b64: string   # ed25519 over sha256(canonical(receipt_payload))

## Deterministic minting
Let task.credit_micro_total = C, task.replicas = R.
Each accepted replica mints floor(C/R). Remainder is burned (never minted).
