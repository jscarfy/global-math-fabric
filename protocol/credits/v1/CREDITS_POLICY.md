# GMF Credits Policy v1 (Immutable)

**Goal:** freeze the “how to split the cake” rules so disputes remain *auditable* and *non-retroactive*.

## Non-retroactivity
- A settlement day references **policy_id** = SHA256 of this file.
- Future policy versions MUST NOT change past settlements. New policy => new policy_id.

## What counts (authoritative)
Only **Server-Signed Receipts** (SSR) count.  
Client “claims” (CPU time, GPU time, etc.) are not credits until the server issues SSR.

## Credit units
- `credit_unit = microcredit` (1e-6 credit). All deltas are integers.

## Credit formula (v1)
Server computes `credits_delta_micro` from:
- `contribution_type` (enum)
- `accepted_artifacts` (hashes of accepted submissions)
- `verified_work_units` (deterministic tasks with verifiable outputs)

Recommended baseline weights (server-configured constants, baked into policy file):
- Accepted proof/lemma: +1_000_000 micro (1.0 credit)
- Accepted patch (non-proof): +200_000 micro
- Verified compute batch (server-issued task, deterministic output): +rate_per_ms * verified_cpu_ms
- Invalid / rejected: 0 (or negative only if fraud is proven & flagged in receipt)

## Anti-fraud / transparency
- Device signs the claim.
- Server signs the receipt (SSR) after verification.
- Daily settlement publishes Merkle root + signature. Anyone can verify inclusion proofs.

## Upgrades
- New policy => new folder `protocol/credits/vN/`.
- Settlements MUST store `policy_id` so the rule set for any day is forever pinned.
