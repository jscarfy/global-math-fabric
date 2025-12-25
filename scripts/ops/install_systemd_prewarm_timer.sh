#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8080}"
BUDGET="${BUDGET:-50000}"
NAME="gmf-prewarm"

mkdir -p "$HOME/.config/systemd/user"

cat > "$HOME/.config/systemd/user/$NAME.service" <<EOF2
[Unit]
Description=GMF Merkle cache prewarm (budgeted)

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsS -X POST "$API_BASE/ledger/cache/prewarm?budget_nodes=$BUDGET"
EOF2

cat > "$HOME/.config/systemd/user/$NAME.timer" <<EOF2
[Unit]
Description=Run GMF prewarm periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=10s

[Install]
WantedBy=default.target
EOF2

systemctl --user daemon-reload
systemctl --user enable --now "$NAME.timer"
echo "Installed: systemctl --user status $NAME.timer"
