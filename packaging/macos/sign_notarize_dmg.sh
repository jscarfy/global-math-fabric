#!/usr/bin/env bash
set -euo pipefail

APP_PATH="${1:?usage: sign_notarize_dmg.sh path/to/Your.app}"
DMG_OUT="${2:-dist/updates/GMF-mac.dmg}"

# 必填：Developer ID Application 证书身份（Keychain 里可见）
CODESIGN_ID="${CODESIGN_ID:?export CODESIGN_ID='Developer ID Application: ...'}"

# 必填：notarytool credentials（推荐用 notarytool store-credentials 预存）
NOTARY_PROFILE="${NOTARY_PROFILE:?export NOTARY_PROFILE='gmf-notary'}"

mkdir -p dist/updates

echo "[1] codesign app..."
codesign --force --options runtime --deep --sign "$CODESIGN_ID" "$APP_PATH"

echo "[2] create dmg (requires create-dmg via brew)..."
command -v create-dmg >/dev/null 2>&1 || { echo "Install create-dmg: brew install create-dmg"; exit 1; }
rm -f "$DMG_OUT"
create-dmg --overwrite "$DMG_OUT" "$APP_PATH"

echo "[3] notarize dmg (notarytool submit --wait)..."
xcrun notarytool submit "$DMG_OUT" --keychain-profile "$NOTARY_PROFILE" --wait

echo "[4] staple ticket..."
xcrun stapler staple "$DMG_OUT"

echo "OK: $DMG_OUT"
