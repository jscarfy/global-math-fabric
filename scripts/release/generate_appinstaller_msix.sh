#!/usr/bin/env bash
set -euo pipefail

# usage: generate_appinstaller_msix.sh PACKAGE_NAME PUBLISHER VERSION MSIX_URL OUT.appinstaller
PACKAGE_NAME="${1:?}"        # e.g. com.globalmathfabric.gmf
PUBLISHER="${2:?}"           # e.g. CN=GMF
VERSION="${3:?}"             # e.g. 0.1.0.0
MSIX_URL="${4:?}"            # https://.../gmf-windows-x64.msix
OUT="${5:-releases/windows/gmf.appinstaller}"

# AppInstaller schema (s4=2021) for AutomaticBackgroundTask / UpdateSettings
cat > "$OUT" <<XML
<?xml version="1.0" encoding="utf-8"?>
<s4:AppInstaller
  xmlns:s4="http://schemas.microsoft.com/appx/appinstaller/2021"
  Uri="${MSIX_URL}.appinstaller"
  Version="${VERSION}">
  <s4:MainPackage
    Name="${PACKAGE_NAME}"
    Publisher="${PUBLISHER}"
    Version="${VERSION}"
    Uri="${MSIX_URL}" />
  <s4:UpdateSettings>
    <s4:OnLaunch HoursBetweenUpdateChecks="6" />
    <s4:AutomaticBackgroundTask />
  </s4:UpdateSettings>
</s4:AppInstaller>
XML

echo "Wrote $OUT"
