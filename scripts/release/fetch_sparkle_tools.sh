#!/usr/bin/env bash
set -euo pipefail

# output: prints absolute paths to tools: generate_appcast + generate_keys
# needs: gh (in CI already), tar, python3

TMP="${TMPDIR:-/tmp}/sparkle-tools"
rm -rf "$TMP"; mkdir -p "$TMP"
cd "$TMP"

# Fetch latest Sparkle release assets and pick Sparkle-*.tar.xz
JSON="$(mktemp)"
gh api repos/sparkle-project/Sparkle/releases/latest > "$JSON"

URL="$(python3 - <<'PY'
import json,sys,re
j=json.load(open(sys.argv[1],'r',encoding='utf-8'))
assets=j.get('assets',[])
cand=[a.get('browser_download_url','') for a in assets if re.search(r"Sparkle-.*\.tar\.xz$", a.get('name',''))]
print(cand[0] if cand else "")
PY
"$JSON")"

if [ -z "$URL" ]; then
  echo "ERROR: cannot find Sparkle-*.tar.xz in sparkle-project/Sparkle latest release assets" 1>&2
  exit 2
fi

curl -L "$URL" -o sparkle.tar.xz
tar -xf sparkle.tar.xz

# find tools
APPCAST="$(find . -type f -name generate_appcast -perm -111 | head -n 1 || true)"
GENKEYS="$(find . -type f -name generate_keys -perm -111 | head -n 1 || true)"

if [ -z "$APPCAST" ] || [ -z "$GENKEYS" ]; then
  echo "ERROR: cannot locate Sparkle CLI tools in extracted archive" 1>&2
  exit 3
fi

echo "$(cd "$(dirname "$APPCAST")" && pwd)/$(basename "$APPCAST")"
echo "$(cd "$(dirname "$GENKEYS")" && pwd)/$(basename "$GENKEYS")"
