# GMF Long-Time Verification Spec (Minimal)

This project is designed for extremely long time horizons.

Hard invariants:
1) Only server-issued, signed receipts count.
2) Each receipt binds the task_manifest_hash and rules_hash used at issuance time.
3) Rules are versioned; no retroactive changes. Old receipts remain valid under their own rules_hash forever.
4) Receipts are stored in an append-only log; Merkle roots are checkpointed and (threshold-)signed by guardians.

To verify contribution:
- Verify receipt signature(s).
- Verify receipt.rules_sha256 matches a published rules file.
- Verify the rules file is (threshold-)signed by the guardian set for that era.
- Optionally: verify the receipt exists in the public receipts.jsonl and the Merkle root matches a checkpoint.

Crypto agility:
- Future eras may add new hash/signature suites. Old receipts remain verifiable by keeping the old public keys and algorithm specs.
- When an algorithm becomes obsolete, a new era publishes a re-attestation: mapping old receipts/roots to new signatures.

Data formats:
- Canonical JSON is used: sorted keys, UTF-8, compact separators.
- receipts.jsonl stores one receipt envelope JSON per line.
- checkpoints are JSON files signed by guardians.

Survival strategy:
- Replicate: store rules + guardian pubkeys + ledger checkpoints in many independent archives.
- Keep the verification spec with the data.
