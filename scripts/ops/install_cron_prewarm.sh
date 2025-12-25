#!/usr/bin/env bash
set -euo pipefail
API_BASE="${API_BASE:-http://localhost:8080}"
BUDGET="${BUDGET:-50000}"

LINE="*/2 * * * * curl -fsS -X POST \"$API_BASE/ledger/cache/prewarm?budget_nodes=$BUDGET\" >/dev/null 2>&1"
( crontab -l 2>/dev/null; echo "$LINE" ) | awk '!x[$0]++' | crontab -
echo "Installed cron prewarm every 2 minutes."
