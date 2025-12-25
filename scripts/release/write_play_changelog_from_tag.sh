#!/usr/bin/env bash
set -euo pipefail

TAG="${1:?usage: write_play_changelog_from_tag.sh vX.Y.Z BUILD_NUMBER [locale] [outdir]}"
BUILD="${2:?}"
LOCALE="${3:-en-US}"
OUTDIR="${4:-clients/gmf_mobile_flutter/android/fastlane/metadata/android}"

V="${TAG#v}"
echo "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "bad tag: $TAG" 1>&2; exit 2; }
echo "$BUILD" | grep -Eq '^[0-9]+$' || { echo "bad build number: $BUILD" 1>&2; exit 3; }

# find previous v* tag (best-effort) to produce a clean range
PREV="$(git tag --list 'v*' --sort=-v:refname | grep -v "^${TAG}$" | head -n 1 || true)"
RANGE=""
if [ -n "$PREV" ]; then
  RANGE="${PREV}..${TAG}"
else
  RANGE="${TAG}"
fi

# Collect commit subjects (no merges), make bullet list
CHANGES="$(git log --no-merges --pretty=format:'- %s' ${RANGE} || true)"
if [ -z "$CHANGES" ]; then
  CHANGES="- (No commit messages found for ${RANGE})"
fi

# Be conservative: keep within ~450 chars (Play UI often truncates; you can raise if needed)
MAX_CHARS="${PLAY_CHANGELOG_MAX_CHARS:-450}"

BODY="GMF ${TAG}\n${CHANGES}"
python3 - <<PY
import os
max_chars=int(os.environ.get("MAX_CHARS","450"))
body=os.environ["BODY"]
if len(body) > max_chars:
    body=body[:max_chars-3].rstrip()+"..."
print(body)
PY > /tmp/gmf_play_whatsnew.txt

TARGET_DIR="${OUTDIR}/${LOCALE}/changelogs"
mkdir -p "$TARGET_DIR"
cp -f /tmp/gmf_play_whatsnew.txt "${TARGET_DIR}/${BUILD}.txt"
# also write default.txt as fallback
cp -f /tmp/gmf_play_whatsnew.txt "${TARGET_DIR}/default.txt"

echo "Wrote:"
echo "  ${TARGET_DIR}/${BUILD}.txt"
echo "  ${TARGET_DIR}/default.txt"
echo "Range: ${RANGE}"
