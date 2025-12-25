# Triple Anchor Rule (v1)

A report/export for date `D` is considered *civilization-grade immutable* iff the following three write-once anchors exist and verify:

1) `ledger/snapshots/D.final.json` (final ledger settlement anchor)
2) `ledger/audit/D.audit_final.json` (audit consensus anchor; binds audit log sha256)
3) `ledger/meta_audit/D.meta_audit_final.json` (meta-audit consensus anchor; binds meta-audit log sha256)

A “multi-day / monthly / yearly / century report” MUST only aggregate days that satisfy (1)-(3).
If any day fails, the report is invalid and MUST NOT be published as canonical.

Rationale: forms a three-layer fixed point preventing later disputes:
- settlement anchor (what happened)
- audit anchor (who verified it)
- meta-audit anchor (who verified the verification)
