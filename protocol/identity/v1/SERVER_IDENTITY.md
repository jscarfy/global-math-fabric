# GMF Server Identity (v1)

## Canonical server public key
The canonical GMF chain identity includes a single Ed25519 server public key:
- `ledger/identity/server_pubkey_b64.txt`

All immutable artifacts (e.g. `ledger/snapshots/<date>.final.json`) MUST be verifiable under this key.

## Key rotation rule (hard rule)
Rotating the server key is treated as a **chain fork**:
- New key => new chain identity directory (e.g. `ledger/identity/v2/`) and new genesis / policy id.
- Old chain remains historically verifiable forever under the old key.

Rationale: ensures 20/5000/5e8 years later, nobody debates which key was “the real one”.
