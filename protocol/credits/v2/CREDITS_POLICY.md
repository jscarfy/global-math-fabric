# GMF Credits Policy v2 (Deterministic, Audit-Friendly)

## Goals
- Deterministic: same task + same verified result agreement => same credits outcome.
- Long-horizon stable: rules should remain meaningful across decades.
- Auditability: SSR payloads must include enough fields to recompute credits.

## Units
All credits are measured in micro-credits (integer).

## Task-level pricing (lean_check)
A task MAY include:
- params.file_count: integer >= 1
- params.credit_base_micro: integer >= 0 (default 500000)
- params.credit_per_file_micro: integer >= 0 (default 150000)

Then the task's declared `credit_micro_total` SHOULD be:
credit_micro_total = credit_base_micro + credit_per_file_micro * file_count

If file_count is missing, pricing falls back to the task's declared credit_micro_total.

## Replica splitting
If replicas = R >= 1 and agreement is reached:
Each winning replica device gets:
credits_delta_micro = floor(credit_micro_total / R)

Any remainder stays unallocated (deterministic).

## Spotcheck penalties
If spotcheck performed and fails:
winning devices get:
credits_delta_micro = -floor(credit_micro_total / R)
fraud_flag = true
reason_code = "spotcheck_failed"

## Rejections
If hard-gate rejects submission:
credits_delta_micro = 0
reason_code = "rejected_expected_source_mismatch"
and SSR MUST store reject_reason.

## Required SSR fields (for recomputation)
- policy_id
- task_id, task_kind, task_params
- replica_winners, credits_delta_micro
- reason_code, fraud_flag
- work_unit_id, unit_owner_task_id (when applicable)
