#!/usr/bin/env bash
set -euo pipefail

TAG="${1:?usage: generate_release_notes_html.sh vX.Y.Z}"
OUT="releases/RELEASE_NOTES/${TAG}.html"

# Best-effort: find previous tag
PREV="$(git tag --list 'v*' --sort=-v:refname | grep -v "^${TAG}$" | head -n 1 || true)"

RANGE=""
if [ -n "$PREV" ]; then
  RANGE="${PREV}..${TAG}"
else
  RANGE="${TAG}"
fi

DATE_UTC="$(date -u +'%Y-%m-%d %H:%M UTC')"

CHANGES="$(git log --no-merges --pretty=format:'<li><code>%h</code> %s</li>' ${RANGE} || true)"
if [ -z "$CHANGES" ]; then
  CHANGES="<li>(No commit messages found for ${RANGE})</li>"
fi

cat > "$OUT" <<HTML
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>GMF Release Notes ${TAG}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; margin: 24px; max-width: 880px; }
    code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
    .muted { color: #666; }
  </style>
</head>
<body>
  <h1>Global Math Fabric — Release Notes ${TAG}</h1>
  <p class="muted">Generated: ${DATE_UTC}</p>
  <p class="muted">Range: <code>${RANGE}</code></p>

  <h2>Changes</h2>
  <ul>
    ${CHANGES}
  </ul>

  <h2>Safety / Transparency</h2>
  <ul>
    <li>Explicit consent required for background contribution.</li>
    <li>Visible running via tray/foreground notification.</li>
    <li>Pause/Stop anytime; revoke consent to hard-stop.</li>
  </ul>
</body>
</html>
HTML

echo "Wrote $OUT"
