# Credit Policy v1 (Immutable)

## Unit of credit
- micro-credit (integer)

## Source of truth
Credits are minted ONLY from:
- server-issued tasks (task_id, kind, credit_micro_total, replicas)
- server-signed receipts (proof of correct verification / work)
- audits/finals binding log sha256 (write-once)
- meta-audit consensus over anchors

## Rule
For a task T with `credit_micro_total` and `replicas = r`:
- total mintable for T is EXACTLY credit_micro_total
- each accepted replica receipt mints credit_micro_total / r (integer division must be defined; remainder burned or assigned deterministically)

## Acceptance criteria (minimum)
A receipt is accepted if:
- consent token is valid (opt-in, server-signed)
- receipt payload references an existing task_id/work_unit_id
- verifier_result_ok == true
- server signature on receipt is valid
- anti-dup: same work_unit_id cannot mint twice

## Long-term invariants
- Policy file is versioned; credits in a period reference policy version hash.
- Any later policy change requires new version; old periods remain governed by old version.

