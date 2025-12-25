#!/usr/bin/env bash
set -euo pipefail

TAG="${1:?usage: set_macos_plist_version_from_tag.sh vX.Y.Z [plist]}"
PLIST="${2:-macos/Runner/Info.plist}"

V="${TAG#v}"
echo "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "bad tag: $TAG" 1>&2; exit 2; }
BUILD="${V}.0"

if [ ! -f "$PLIST" ]; then
  echo "ERROR: plist not found: $PLIST" 1>&2
  exit 3
fi

# Set keys (create if missing)
for kv in "CFBundleShortVersionString:$V" "CFBundleVersion:$BUILD"; do
  K="${kv%%:*}"; VAL="${kv#*:}"
  if /usr/libexec/PlistBuddy -c "Print :$K" "$PLIST" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Set :$K $VAL" "$PLIST"
  else
    /usr/libexec/PlistBuddy -c "Add :$K string $VAL" "$PLIST"
  fi
done

echo "OK: set $PLIST"
echo "  CFBundleShortVersionString=$V"
echo "  CFBundleVersion=$BUILD"
