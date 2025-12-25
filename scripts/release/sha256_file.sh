#!/usr/bin/env bash
set -euo pipefail
FILE="${1:?usage: sha256_file.sh <file>}"
OUT="${2:-${FILE}.sha256}"

# cross-platform: use sha256sum if present, else shasum -a 256
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$FILE" > "$OUT"
else
  shasum -a 256 "$FILE" > "$OUT"
fi
echo "Wrote $OUT"
