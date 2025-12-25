#!/usr/bin/env bash
set -euo pipefail

# Requires:
#  - gh auth (CI: GH_TOKEN)
#  - SPARKLE_ED25519_PRIVKEY_B64 env
#  - releases/macos/gmf-macos.dmg exists in repo
# Produces:
#  - releases/appcast.xml (or whatever SUFeedURL lastPathComponent is)

OWNER_REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$OWNER_REPO" ]; then
  ORIGIN="$(git remote get-url origin)"
  if [[ "$ORIGIN" =~ ^git@github.com:(.+)/(.+)\.git$ ]]; then
    OWNER_REPO="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
  elif [[ "$ORIGIN" =~ ^https://github.com/(.+)/(.+)(\.git)?$ ]]; then
    OWNER_REPO="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
  else
    echo "Cannot determine OWNER/REPO" 1>&2
    exit 2
  fi
fi

OWNER="${OWNER_REPO%/*}"
REPO="${OWNER_REPO#*/}"
PAGES_BASE="https://${OWNER}.github.io/${REPO}"

DMG="releases/macos/gmf-macos.dmg"
if [ ! -f "$DMG" ]; then
  echo "ERROR: $DMG missing. (publish-macos-dmg-to-pages must run first)" 1>&2
  exit 3
fi

TOOLS=($(./scripts/release/fetch_sparkle_tools.sh))
APPCAST_TOOL="${TOOLS[0]}"

KEYFILE="$(mktemp)"
echo "${SPARKLE_ED25519_PRIVKEY_B64}" | base64 -d > "$KEYFILE"

# generate_appcast writes feed based on SUFeedURL inside archive metadata;
# download-url-prefix makes item URLs point to Pages.
"$APPCAST_TOOL" "$(dirname "$DMG")" \
  --download-url-prefix "${PAGES_BASE}/releases/macos/" \
  --ed-key-file "$KEYFILE"

rm -f "$KEYFILE"

# If tool created feed with different name, normalize to releases/appcast.xml if present
# (Best practice: set SUFeedURL in your app to .../releases/appcast.xml)
if [ -f "releases/appcast.xml" ]; then
  echo "OK: releases/appcast.xml updated"
else
  echo "NOTE: generate_appcast did not write releases/appcast.xml. Ensure SUFeedURL lastPathComponent is appcast.xml."
  ls -la releases || true
fi
