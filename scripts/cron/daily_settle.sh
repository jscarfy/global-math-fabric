#!/usr/bin/env bash
set -euo pipefail
DAY="${1:?usage: daily_settle.sh YYYY-MM-DD}"

# 1) build merkle roots for that day from partitioned receipts
./tools/merkle/build_receipt_merkle_roots_from_partitions.py --day "$DAY"

# 2) (re)build daily root artifacts as your repo defines
./scripts/audit/build_daily_root_manifest.py

# 3) inject merkle_roots_sha256 into the daily_root JSON
./tools/merkle/inject_merkle_roots_sha256_into_daily_root.py --day "$DAY"

# 4) update audit + mirror
./scripts/audit/update_audit_from_daily_roots.py
./scripts/mirror/mirror_to_git.sh

echo "OK daily_settle $DAY"
