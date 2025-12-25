# Triple Anchor for Month/Year (v1)

A month/year period is canonical iff:

Month (YYYY-MM):
1) `ledger/reports/monthly/YYYY-MM.monthly_final.json`
2) `ledger/report_audit/monthly/YYYY-MM.report_audit_final.json`
3) `ledger/meta_audit/YYYY-MM.meta_audit_final.json`  (period meta-audit final)

Year (YYYY):
1) `ledger/reports/yearly/YYYY.yearly_final.json`
2) `ledger/report_audit/yearly/YYYY.report_audit_final.json`
3) `ledger/meta_audit/YYYY.meta_audit_final.json`

Period meta-audit final is a write-once server-signed summary of meta-audit receipts for that period
(which can include attestations of: monthly/yearly report anchors and report_audit_final anchors).
