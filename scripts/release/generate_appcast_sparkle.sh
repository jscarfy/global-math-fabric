#!/usr/bin/env bash
set -euo pipefail

UPDATES_DIR="${1:-dist/updates}"
OUT_XML="${2:-releases/appcast.xml}"

if [ ! -x tools/sparkle/bin/generate_appcast ]; then
  echo "Missing tools/sparkle/bin/generate_appcast"
  exit 1
fi

mkdir -p "$(dirname "$OUT_XML")"
# generate_appcast 会用钥匙串生成签名（会弹权限提示）  [oai_citation:5‡Sparkle Project](https://sparkle-project.org/documentation/?utm_source=chatgpt.com)
tools/sparkle/bin/generate_appcast "$UPDATES_DIR" --output "$OUT_XML"

echo "Wrote $OUT_XML"
