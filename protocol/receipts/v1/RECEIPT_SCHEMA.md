# Receipt Schema v1 (Server-Signed Receipt = SSR)

We use canonical JSON (RFC 8785 / JCS) before hashing/signing.

## Objects

### ClientClaim (device-signed, optional to publish)
- protocol: "gmf/receipt/v1"
- claim_id: hex(sha256(jcs(claim_payload)))
- device_pubkey_b64: Ed25519 public key (base64)
- device_id: hex(sha256(device_pubkey))
- session_id: random uuid
- task_id: server-issued task id (string) OR "user-submission"
- started_at, ended_at: RFC3339 timestamps
- metrics: { cpu_ms, gpu_ms, bytes_in, bytes_out }
- artifacts: [{ kind, hash_alg, hash_hex }]
- prev_claim_hash_hex: to form an optional hash-chain per device
- device_sig_b64: Ed25519 signature over sha256(jcs(claim_payload))

### ServerSignedReceipt (SSR, authoritative)
- protocol: "gmf/ssr/v1"
- receipt_id: hex(sha256(jcs(receipt_payload)))
- policy_id: hex(sha256(CREDITS_POLICY.md bytes))
- claim_id: link to ClientClaim (optional)
- device_id
- task_id
- accepted_artifacts: [...]
- credits_delta_micro: int64
- reason_code: enum
- server_pubkey_b64
- server_sig_b64: Ed25519 signature over sha256(jcs(receipt_payload))

