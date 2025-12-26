#!/usr/bin/env bash
set -euo pipefail
Y="${1:?usage: finalize_credit_statement_year.sh YYYY}"
: "${GMF_RELAY:?set GMF_RELAY}"
curl -fsSL "${GMF_RELAY}/v1/credits/statement/finalize/yearly/${Y}" | tee "ledger/credits/final/yearly/${Y}.credit_statement_final.json" >/dev/null
echo "OK: finalized credit_statement_final yearly ${Y}"
