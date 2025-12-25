# Settlement Schema v1 (Daily Transparency Log)

Merkle tree hashing follows CT-style prefixes (RFC 6962):
- leaf_hash = SHA256(0x00 || entry_hash)
- node_hash = SHA256(0x01 || left || right)

Settlement day file:
- protocol: "gmf/settlement/v1"
- date: "YYYY-MM-DD"
- policy_id: pinned policy hash
- tree_size: number of SSR entries
- merkle_root_hex: hex(root)
- prev_merkle_root_hex: chain settlements day-to-day
- entries:
  - entry_hash_hex (SHA256 of canonical SSR payload)
- server_pubkey_b64
- settlement_sig_b64: Ed25519 signature over SHA256(canonical settlement header)

Publishing:
- Put into `releases/ledger/YYYY-MM-DD.json`
- (Optional) inclusion proofs per device can be published separately.
