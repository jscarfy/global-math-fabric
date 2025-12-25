#!/usr/bin/env bash
set -euo pipefail
TAG="${1:?usage: version_from_tag.sh vX.Y.Z}"

# strip leading v
V="${TAG#v}"
# basic sanity
echo "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "bad tag: $TAG"; exit 2; }

MSIX_VERSION="${V}.0"   # msix wants 4-part version
echo "$MSIX_VERSION"
