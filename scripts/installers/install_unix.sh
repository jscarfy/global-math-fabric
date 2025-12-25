#!/usr/bin/env bash
set -euo pipefail

OWNER="${OWNER:-pujustinyang}"
REPO="${REPO:-global-math-fabric}"
BIN_NAME="gmf-client"

OS="$(uname -s)"
case "$OS" in
  Linux)  ASSET_OS="Linux" ;;
  Darwin) ASSET_OS="macOS" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# GitHub API: latest release
API="https://api.github.com/repos/$OWNER/$REPO/releases/latest"
URL="$(curl -fsSL "$API" | python3 - <<PY
import json,sys
d=json.load(sys.stdin)
assets=d.get("assets",[])
want=None
for a in assets:
  n=a.get("name","")
  if n == f"{BIN_NAME}-{ASSET_OS}":
    want=a.get("browser_download_url")
    break
if not want:
  raise SystemExit("Could not find asset: "+f"{BIN_NAME}-{ASSET_OS}")
print(want)
PY
)"

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fL "$URL" -o "$TMP/$BIN_NAME"
chmod +x "$TMP/$BIN_NAME"
mv "$TMP/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"

echo "Installed: $INSTALL_DIR/$BIN_NAME"
echo "Ensure $INSTALL_DIR is on PATH."
echo "Next:"
echo "  $BIN_NAME setup --api http://<your-server>:8000 --client-id <your-id> --display-name <name>"
echo "  $BIN_NAME run --only-on-ac --max-cpu-percent 70"
