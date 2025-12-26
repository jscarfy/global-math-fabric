#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"     # owner/repo
RELAY="${2:-}"    # http(s)://host:8787
DEVICE_NAME="${3:-$(hostname)}"

[[ -n "$REPO" ]] || { echo "Usage: install.sh <owner/repo> <relay_url> [device_name]" >&2; exit 2; }
[[ -n "$RELAY" ]] || { echo "Usage: install.sh <owner/repo> <relay_url> [device_name]" >&2; exit 2; }

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m | tr '[:upper:]' '[:lower:]')"

case "$OS" in
  linux) OSN="linux" ;;
  darwin) OSN="macos" ;;
  *) echo "Unsupported OS: $OS"; exit 2 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCHN="x86_64" ;;
  aarch64|arm64) ARCHN="arm64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 2 ;;
esac

AGENT="gmf_agent-${OSN}-${ARCHN}"
WORKER="gmf_worker-${OSN}-${ARCHN}"

API="https://api.github.com/repos/${REPO}/releases/latest"

echo "[install] repo=$REPO os=$OSN arch=$ARCHN"
echo "[install] fetching latest release metadata..."
JSON="$(curl -fsSL "$API")"

url_for () {
  local name="$1"
  python3 - <<PY
import json,sys
j=json.loads(sys.stdin.read())
name="$name"
for a in j.get("assets",[]):
    if a.get("name")==name:
        print(a.get("browser_download_url",""))
        sys.exit(0)
print("")
sys.exit(0)
PY
}

AGENT_URL="$(printf "%s" "$JSON" | url_for "$AGENT")"
WORKER_URL="$(printf "%s" "$JSON" | url_for "$WORKER")"

[[ -n "$AGENT_URL" ]] || { echo "Could not find asset $AGENT in latest release"; exit 2; }
[[ -n "$WORKER_URL" ]] || { echo "Could not find asset $WORKER in latest release"; exit 2; }

BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"

echo "[install] downloading $AGENT ..."
curl -fsSL "$AGENT_URL" -o "$BIN_DIR/gmf_agent"
echo "[install] downloading $WORKER ..."
curl -fsSL "$WORKER_URL" -o "$BIN_DIR/gmf_worker"

chmod +x "$BIN_DIR/gmf_agent" "$BIN_DIR/gmf_worker"

echo "[install] OK. Next:"
echo "  $BIN_DIR/gmf_agent init --relay $RELAY --device-name \"$DEVICE_NAME\""
echo "  $BIN_DIR/gmf_agent enroll"
echo "  $BIN_DIR/gmf_agent run --loop-seconds 5"
