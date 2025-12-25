# GMF Ledger (Daily Transparency Log)

- SSR entries are collected in `ledger/inbox/YYYY-MM-DD.ssr.jsonl`
- Settlement is published to `releases/ledger/YYYY-MM-DD.json`
- Each settlement is:
  - policy-pinned (policy_id = SHA256(policy file))
  - tamper-evident (Merkle root + signature)
  - chainable (prev_merkle_root_hex)

Verification:
1) Canonicalize settlement header with RFC8785 (JCS)
2) Verify Ed25519 signature (server_pubkey_b64)
3) Verify Merkle root computed from entry hashes (CT-style prefixes)
