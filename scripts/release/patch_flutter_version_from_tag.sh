#!/usr/bin/env bash
set -euo pipefail
TAG="${1:?usage: patch_flutter_version_from_tag.sh vX.Y.Z BUILD_NUMBER PUBSPEC}"
BUILD="${2:?}"
PUBSPEC="${3:-clients/gmf_mobile_flutter/pubspec.yaml}"

V="${TAG#v}"
echo "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "bad tag: $TAG" 1>&2; exit 2; }

# Flutter version format: x.y.z+build
NEW="version: ${V}+${BUILD}"

python3 - <<PY
from pathlib import Path
import re
p=Path("$PUBSPEC")
s=p.read_text()
if re.search(r'^version:\s*', s, flags=re.M):
    s=re.sub(r'^version:\s*.*$', "$NEW", s, flags=re.M)
else:
    s="$NEW\n"+s
p.write_text(s)
print("Patched", p, "=>", "$NEW")
PY
