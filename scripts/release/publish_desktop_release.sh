#!/usr/bin/env bash
set -euo pipefail

TAG="${1:?usage: publish_desktop_release.sh v0.1.0}"
REPO_REMOTE="${2:-origin}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_DIR="$ROOT/clients/gmf_mobile_flutter"
OUT_DIR="$ROOT/dist/releases/$TAG"
mkdir -p "$OUT_DIR"

command -v gh >/dev/null 2>&1 || { echo "Missing gh CLI"; exit 1; }

pushd "$APP_DIR" >/dev/null
flutter clean
flutter pub get

# Build (best-effort)
flutter build windows --release || true
flutter build macos --release || true
flutter build linux --release  || true
popd >/dev/null

# Pack artifacts (paths may vary; adjust if needed)
WIN="$APP_DIR/build/windows/x64/runner/Release"
MAC="$APP_DIR/build/macos/Build/Products/Release"
LIN="$APP_DIR/build/linux/x64/release/bundle"

ASSETS=()

if [ -d "$WIN" ]; then
  (cd "$WIN" && zip -qr "$OUT_DIR/gmf-windows-x64.zip" .)
  ASSETS+=("$OUT_DIR/gmf-windows-x64.zip")
fi
if [ -d "$MAC" ]; then
  tar -czf "$OUT_DIR/gmf-macos.tar.gz" -C "$MAC" .
  ASSETS+=("$OUT_DIR/gmf-macos.tar.gz")
fi
if [ -d "$LIN" ]; then
  tar -czf "$OUT_DIR/gmf-linux-x64.tar.gz" -C "$LIN" .
  ASSETS+=("$OUT_DIR/gmf-linux-x64.tar.gz")
fi

if [ "${#ASSETS[@]}" -eq 0 ]; then
  echo "No desktop artifacts found. Check build paths."
  exit 1
fi

# Create or update GitHub release
gh release view "$TAG" >/dev/null 2>&1 || gh release create "$TAG" -t "$TAG" -n "GMF desktop release $TAG"
gh release upload "$TAG" "${ASSETS[@]}" --clobber

# Generate appcast.xml (Sparkle-like minimal). You MUST fill Sparkle signatures later if you enforce them.
APPCAST="$ROOT/releases/appcast.xml"
REPO_URL="$(git remote get-url "$REPO_REMOTE" | sed 's#git@github.com:#https://github.com/#; s#\.git$##')"

tmp="$(mktemp)"
{
  echo '<?xml version="1.0" encoding="utf-8"?>'
  echo '<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">'
  echo '  <channel>'
  echo '    <title>GMF Desktop Updates</title>'
  echo "    <link>$REPO_URL</link>"
  echo '    <item>'
  echo "      <title>$TAG</title>"
  echo "      <sparkle:version>${TAG#v}</sparkle:version>"
  echo "      <sparkle:shortVersionString>${TAG#v}</sparkle:shortVersionString>"
  for A in "${ASSETS[@]}"; do
    FN="$(basename "$A")"
    SIZE="$(python3 - <<PY
import os,sys
print(os.path.getsize(sys.argv[1]))
PY "$A")"
    SHA="$(python3 - <<PY
import hashlib,sys
h=hashlib.sha256()
with open(sys.argv[1],'rb') as f:
  for b in iter(lambda: f.read(1024*1024), b''):
    h.update(b)
print(h.hexdigest())
PY "$A")"
    URL="$REPO_URL/releases/download/$TAG/$FN"
    echo "      <enclosure url=\"$URL\" length=\"$SIZE\" type=\"application/octet-stream\" sparkle:edSignature=\"$SHA\"/>"
  done
  echo '      <description>GMF desktop update.</description>'
  echo '    </item>'
  echo '  </channel>'
  echo '</rss>'
} > "$tmp"

mkdir -p "$(dirname "$APPCAST")"
mv "$tmp" "$APPCAST"

echo "Updated $APPCAST"
echo "Next: publish releases/appcast.xml somewhere reachable (GitHub Pages or your server) and set DesktopUpdate feed URL to it."
