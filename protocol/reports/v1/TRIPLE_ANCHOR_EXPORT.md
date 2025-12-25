# Triple Anchor for Canonical Export (v1)

A period export is canonical iff:

Monthly (YYYY-MM):
1) `ledger/reports/monthly/YYYY-MM.monthly_canonical_export.json`
2) `ledger/export_audit/monthly/YYYY-MM.export_audit_final.json`
3) `ledger/meta_audit/YYYY-MM.meta_audit_final.json`

Yearly (YYYY):
1) `ledger/reports/yearly/YYYY.yearly_canonical_export.json`
2) `ledger/export_audit/yearly/YYYY.export_audit_final.json`
3) `ledger/meta_audit/YYYY.meta_audit_final.json`
