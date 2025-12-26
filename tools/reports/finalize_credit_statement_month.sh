#!/usr/bin/env bash
set -euo pipefail
YM="${1:?usage: finalize_credit_statement_month.sh YYYY-MM}"
: "${GMF_RELAY:?set GMF_RELAY}"
curl -fsSL "${GMF_RELAY}/v1/credits/statement/finalize/monthly/${YM}" | tee "ledger/credits/final/monthly/${YM}.credit_statement_final.json" >/dev/null
echo "OK: finalized credit_statement_final monthly ${YM}"
