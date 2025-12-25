#!/usr/bin/env bash
set -euo pipefail
APP_BIN="${1:?usage: macos_launchagent.sh /absolute/path/to/gmf_binary}"
PLIST="$HOME/Library/LaunchAgents/com.gmf.fabric.plist"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.gmf.fabric</string>
  <key>ProgramArguments</key>
  <array><string>${APP_BIN}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
EOF
launchctl unload "$PLIST" >/dev/null 2>&1 || true
launchctl load "$PLIST"
echo "Loaded LaunchAgent: launchctl list | grep com.gmf.fabric"
