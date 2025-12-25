#!/usr/bin/env bash
set -euo pipefail
APP_PATH="${1:?usage: linux_systemd_user.sh /absolute/path/to/gmf_app}"
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/gmf.service <<EOF
[Unit]
Description=Global Math Fabric (user)

[Service]
Type=simple
ExecStart=${APP_PATH}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now gmf.service
echo "Enabled: systemctl --user status gmf.service"
