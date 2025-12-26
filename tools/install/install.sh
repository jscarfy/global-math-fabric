#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"
RELAY="${2:-}"
[[ -n "$REPO" ]] || { echo "Usage: install.sh <github_owner/repo> <relay_url>" >&2; exit 2; }
[[ -n "$RELAY" ]] || { echo "Usage: install.sh <github_owner/repo> <relay_url>" >&2; exit 2; }

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"

echo "Installing to $BIN_DIR for os=$OS arch=$ARCH"
echo "NOTE: this script expects you published release assets named like: gmf_agent-<os>-<arch>, gmf_worker-<os>-<arch>"

# naive: user provides direct URLs later; keep this minimal and explicit.
echo "Please download the two binaries from GitHub Releases and place them into:"
echo "  $BIN_DIR/gmf_agent"
echo "  $BIN_DIR/gmf_worker"
echo ""
echo "Then run:"
echo "  chmod +x $BIN_DIR/gmf_agent $BIN_DIR/gmf_worker"
echo "  $BIN_DIR/gmf_agent init --relay $RELAY --device-name \"$(hostname)\""
echo "  $BIN_DIR/gmf_agent enroll"
echo "  $BIN_DIR/gmf_agent run --loop-seconds 5"
