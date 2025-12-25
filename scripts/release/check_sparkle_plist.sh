#!/usr/bin/env bash
set -euo pipefail

PLIST="${1:-macos/Runner/Info.plist}"

if [ ! -f "$PLIST" ]; then
  echo "ERROR: Info.plist not found: $PLIST" 1>&2
  exit 2
fi

# Read keys (empty if missing)
SUPUB="$(/usr/libexec/PlistBuddy -c 'Print :SUPublicEDKey' "$PLIST" 2>/dev/null || true)"
SUFEED="$(/usr/libexec/PlistBuddy -c 'Print :SUFeedURL' "$PLIST" 2>/dev/null || true)"

if [ -z "${SUPUB}" ]; then
  echo "ERROR: SUPublicEDKey missing/empty in $PLIST" 1>&2
  exit 3
fi

if [ -z "${SUFEED}" ]; then
  echo "ERROR: SUFeedURL missing/empty in $PLIST" 1>&2
  exit 4
fi

# Must end with /releases/appcast.xml (hard requirement for our publishing layout)
case "$SUFEED" in
  */releases/appcast.xml) ;;
  *)
    echo "ERROR: SUFeedURL must end with /releases/appcast.xml, got: $SUFEED" 1>&2
    exit 5
    ;;
esac

echo "OK: Sparkle keys present"
echo "  SUFeedURL=$SUFEED"
echo "  SUPublicEDKey(len)=${#SUPUB}"
