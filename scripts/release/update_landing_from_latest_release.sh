#!/usr/bin/env bash
set -euo pipefail

# Requires GH_TOKEN in env when running in CI (or you are gh auth login locally)
# Also requires git remote origin to be GitHub.

OWNER_REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$OWNER_REPO" ]; then
  # local fallback: parse origin
  ORIGIN="$(git remote get-url origin)"
  if [[ "$ORIGIN" =~ ^git@github.com:(.+)/(.+)\.git$ ]]; then
    OWNER_REPO="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
  elif [[ "$ORIGIN" =~ ^https://github.com/(.+)/(.+)(\.git)?$ ]]; then
    OWNER_REPO="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
  else
    echo "Cannot determine GitHub repo (GITHUB_REPOSITORY empty and origin not parseable): $ORIGIN" 1>&2
    exit 2
  fi
fi

OWNER="${OWNER_REPO%/*}"
REPO="${OWNER_REPO#*/}"
PAGES_BASE="https://${OWNER}.github.io/${REPO}"

# Fetch latest release JSON
# - If no releases exist yet, this will fail; we handle by generating a page without mac dmg links.
LATEST_JSON="$(mktemp)"
if gh api "repos/${OWNER_REPO}/releases/latest" > "$LATEST_JSON" 2>/dev/null; then
  HAVE_RELEASE=1
else
  HAVE_RELEASE=0
  echo "{}" > "$LATEST_JSON"
fi

ANDROID_LINK=""
if [ -f releases/android_play_link.txt ]; then
  ANDROID_LINK="$(grep -v '^\s*#' releases/android_play_link.txt | head -n 1 | tr -d '\r' || true)"
fi

python3 - <<'PY'
import json, os, re
from pathlib import Path

pages = os.environ["PAGES_BASE"]
have_release = os.environ.get("HAVE_RELEASE","0") == "1"
android = os.environ.get("ANDROID_LINK","").strip()

j = json.load(open(os.environ["LATEST_JSON"],"r",encoding="utf-8"))
assets = j.get("assets", []) if isinstance(j, dict) else []

def pick(patterns):
    """Return first asset browser_download_url matching any regex pattern (case-insensitive)."""
    for pat in patterns:
        r = re.compile(pat, re.I)
        for a in assets:
            name = a.get("name","")
            url  = a.get("browser_download_url","")
            if name and url and r.search(name):
                return (name, url)
    return None

win_msix = pick([r"\.msix$"])
win_appinstaller = None  # we serve from Pages, not release assets
win_cer = f"{pages}/releases/windows/gmf.cer"
win_appinstaller = f"{pages}/releases/windows/gmf.appinstaller"

mac_dmg = pick([r"\.dmg$"])
mac_zip = pick([r"mac", r"\.zip$"])  # best-effort if you upload gmf-macos.zip

# Sparkle appcast always from Pages
appcast = f"{pages}/releases/appcast.xml"
install_md = f"{pages}/releases/INSTALL.md"
landing = f"{pages}/"

def btn(href, text):
    return f'<a class="btn" href="{href}">{text}</a>'

mac_section = []
mac_section.append(f"<h2>macOS</h2>")
mac_section.append(btn(appcast,"Auto-update Feed (Sparkle)"))
if mac_dmg:
    mac_section.append(btn(mac_dmg[1], f"Download DMG ({mac_dmg[0]})"))
if mac_zip:
    mac_section.append(btn(mac_zip[1], f"Download ZIP ({mac_zip[0]})"))
mac_section.append('<p class="muted">If DMG/ZIP links are missing, upload notarized artifacts to the latest GitHub Release.</p>')

android_section = []
android_section.append("<h2>Android</h2>")
apk_url = f"{pages}/releases/android/latest.apk"
apk_sha = f"{pages}/releases/android/latest.apk.sha256"
apk_exists = Path("releases/android/latest.apk").exists()
ias_file = Path("releases/android/internal_app_sharing_url.txt")
ias_url = ias_file.read_text().strip() if ias_file.exists() else ""
if android and android.startswith("http"):
    android_section.append(btn(android,"Play internal testing link"))
else:
    android_section.append('<p class="muted">Maintainer: put Play internal testing link into <code>releases/android_play_link.txt</code>.</p>')
if apk_exists:
    android_section.append(btn(apk_url, "Download APK (latest.apk)"))
    if Path("releases/android/latest.apk.sha256").exists():
        android_section.append(btn(apk_sha, "SHA256 (latest.apk.sha256)"))
    android_section.append('<p class="muted">Sideload: enable “Install unknown apps” for your browser/file manager, then install. You can always Pause/Stop inside the app.</p>')
if ias_url.startswith("http"):
    android_section.append(btn(ias_url, "Install via Internal App Sharing (fast link)"))

html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Global Math Fabric</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 24px; max-width: 820px; }}
    .card {{ border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 12px 0; }}
    a.btn {{ display: inline-block; padding: 10px 14px; border-radius: 10px; border: 1px solid #333;
            text-decoration: none; margin: 6px 8px 6px 0; }}
    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
    .muted {{ color: #666; }}
  </style>
</head>
<body>
  <h1>Global Math Fabric</h1>
  <p class="muted">Install links (auto-updating where supported). Visible-run + Pause/Stop + explicit consent.</p>

  <div class="card">
    <h2>Windows</h2>
    {btn(win_appinstaller,"Install (AppInstaller)")}
    {btn(win_cer,"First-time Cert (gmf.cer)")}
    <p class="muted">AppInstaller supports update settings in <code>.appinstaller</code>. If self-signed: import <code>gmf.cer</code> into Trusted People (Current User), then install.</p>
  </div>

  <div class="card">
    {''.join(mac_section)}
  </div>

  <div class="card">
    {''.join(android_section)}
  </div>

  <div class="card">
    <h2>Install Guide</h2>
    {btn(install_md,"INSTALL.md")}
  </div>

  <p class="muted">Home: <code>{landing}</code></p>
  <p class="muted">Pages base: <code>{pages}</code></p>
</body>
</html>
"""

Path("releases").mkdir(parents=True, exist_ok=True)
Path("releases/index.html").write_text(html, encoding="utf-8")
print("Wrote releases/index.html")

# Also generate Flutter BuildConfig.pagesBase (keep in sync)
Path("clients/gmf_mobile_flutter/lib/gmf").mkdir(parents=True, exist_ok=True)
Path("clients/gmf_mobile_flutter/lib/gmf/build_config.dart").write_text(
    f"// Generated by update_landing_from_latest_release.sh\nclass BuildConfig {{\n  static const pagesBase = \"{pages}\";\n}}\n",
    encoding="utf-8"
)
print("Wrote clients/gmf_mobile_flutter/lib/gmf/build_config.dart")
PY
