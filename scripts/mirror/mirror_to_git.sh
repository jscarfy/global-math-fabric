#!/usr/bin/env bash
set -euo pipefail

SRC_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIRROR_DIR="${GMF_AUDIT_GIT_MIRROR_DIR:-/volumes/expansion/global_math/global-math-fabric-mirrors/gmf-audit-mirror}"

cd "$SRC_ROOT"
./scripts/audit/partition_receipts.py >/dev/null
./scripts/audit/build_verifications_manifest.py >/dev/null
./scripts/audit/build_daily_root_manifest.py >/dev/null
./scripts/audit/update_audit_from_daily_roots.py >/dev/null
./scripts/audit/update_audit_from_manifests.py >/dev/null
./scripts/audit/update_audit.py >/dev/null

mkdir -p "$MIRROR_DIR"
cd "$MIRROR_DIR"

# init if missing
if [ ! -d .git ]; then
  git init
fi

mkdir -p ledger/policies ledger/policies/manifests ledger/audit ledger/receipts/manifests ledger/verifications/manifests ledger/xlinks/manifests ledger/audit_bundles/manifests ledger/audit_transcripts/manifests ledger/daily_roots
rsync -av --delete "$SRC_ROOT/ledger/policies/" ./ledger/policies/ 2>/dev/null || true
rsync -av --delete "$SRC_ROOT/ledger/audit/" ./ledger/audit/
rsync -av --delete "$SRC_ROOT/ledger/receipts/manifests/" ./ledger/receipts/manifests/ 2>/dev/null || true
rsync -av --delete "$SRC_ROOT/ledger/verifications/manifests/" ./ledger/verifications/manifests/ 2>/dev/null || true
rsync -av --delete "$SRC_ROOT/ledger/daily_roots/" ./ledger/daily_roots/ 2>/dev/null || true

git add ledger
git commit -m "mirror: $(date -u +%F) checkpoint" >/dev/null || true
git push >/dev/null || true

echo "OK: mirrored to git at $MIRROR_DIR"
