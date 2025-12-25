# GMF Credit Policy v2 — Bundle v1 + Merkle Audit (Immutable)

This policy defines what counts as **verified contribution** and how credits are computed.
It is intended to be immutable once its `policy_hash` is published.

## 1. Credits are based on verified submissions only
Credits are awarded only for submissions accepted by the server verification pipeline.
Runtime/uptime is not used for credit.

## 2. Audited submissions MUST use Bundle Format v1
When a lease is flagged `audit_required=true`, the submit payload MUST satisfy:

- `bundle_format == "gmf_bundle_v1"`
- `header_sha256 == sha256(header_bytes)` (hex, lowercase)
- Merkle proof samples MUST include the chunk at index `idx=0` (the header chunk)

### 2.1 Bundle v1 header (must be contained in chunk 0)
The first chunk (idx=0) MUST be a UTF-8 JSON object with:
- `kind == "gmf_trace_bundle_header"`
- `version == 1`
- `format == "gmf_bundle_v1"`
- `files`: array of entries with `{name, sha256, bytes}`
- required file names MUST include:
  - `Main.lean`
  - `build.log`
  - `versions.json`

The server verifies `header_sha256` against the actual header bytes from chunk 0.

## 3. Merkle audit indices rule
For audited jobs, the expected sample indices are:
- Always include index 0
- Remaining indices are derived deterministically from `(seed_hex, num_chunks, sample_k)`.

## 4. Disputes
In any dispute, the published `policy_hash` and the public daily root chain are the source of truth.
