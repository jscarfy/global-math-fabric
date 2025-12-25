# GMF Ledger Final Snapshot (v1)

## Purpose
`ledger/snapshots/<date>.final.json` is the immutable settlement anchor for date `<date>`.

## File format
JSON object:
- final_payload: object
  - date: "YYYY-MM-DD"
  - finalized_at_unix_ms: int
  - ssr_sha256: hex sha256 of *verbatim* bytes of `ledger/inbox/<date>.ssr.jsonl`
  - total_bytes: int
  - total_lines: int
  - policy: string (e.g. "credits_policy_v2_deterministic")
  - inbox_file: string path
- server_pubkey_b64: base64(ed25519 pubkey 32 bytes)
- server_sig_b64: base64(ed25519 signature 64 bytes) over:
  SHA256( canonical_json_bytes(final_payload) )

## Settlement rule
A credits/leaderboard export for `<date>` MUST:
1) Load `<date>.final.json`
2) Verify inbox file exists and SHA256(inbox_bytes) == final_payload.ssr_sha256
3) Carry final snapshot’s `server_pubkey_b64` and `server_sig_b64` in the export metadata
4) Be reproducible from (final.json + inbox file + policy).

## Immutability
`<date>.final.json` is write-once. If present, it is authoritative and MUST NOT be overwritten.
