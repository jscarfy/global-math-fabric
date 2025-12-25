# GMF Audit Final (v1)

## Purpose
`ledger/audit/<date>.audit_final.json` is the immutable “audit consensus anchor” for `<date>`.

It freezes:
- The exact audit log content hash (sha256 of `ledger/audit/<date>.audit.jsonl`)
- Summary counts (unique devices, receipts, signature health)
- The linkage to the immutable ledger settlement anchor (`ledger/snapshots/<date>.final.json`)

## File format
JSON object:
- audit_final_payload: object
  - date: "YYYY-MM-DD"
  - finalized_at_unix_ms: int
  - audit_log_sha256: hex sha256 of verbatim bytes of `ledger/audit/<date>.audit.jsonl`
  - audit_total_lines: int
  - audit_total_bytes: int
  - audit_sig_ok: int
  - audit_sig_bad: int
  - audit_parse_errors: int
  - unique_devices: int
  - unique_device_pubkeys: int
  - final_ssr_sha256: hex (copied from final_payload.ssr_sha256)
  - final_server_pubkey_b64: string
  - final_server_sig_b64: string
- server_pubkey_b64: base64(ed25519 pubkey)
- server_sig_b64: base64(signature) over SHA256(canonical_json_bytes(audit_final_payload))

## Immutability
Write-once. If present, MUST NOT be overwritten.
