#!/usr/bin/env bash
set -euo pipefail

# usage: generate_appinstaller_msix.sh PACKAGE_NAME PUBLISHER DISPLAY_NAME VERSION MSIX_URL OUT.appinstaller
PACKAGE_NAME="${1:?}"        # e.g. com.globalmathfabric.gmf
PUBLISHER="${2:?}"           # e.g. CN=GMF
DISPLAY_NAME="${3:?}"        # e.g. Global Math Fabric
VERSION="${4:?}"             # e.g. 0.1.0.0
MSIX_URL="${5:?}"            # https://.../gmf-windows-x64.msix
OUT="${6:-releases/windows/gmf.appinstaller}"

cat > "$OUT" <<XML
<?xml version="1.0" encoding="utf-8"?>
<AppInstaller Uri="$MSIX_URL.appinstaller"
  Version="$VERSION"
  xmlns="http://schemas.microsoft.com/appx/appinstaller/2018">
  <MainPackage
    Name="$PACKAGE_NAME"
    Publisher="$PUBLISHER"
    Version="$VERSION"
    Uri="$MSIX_URL" />
  <UpdateSettings>
    <OnLaunch HoursBetweenUpdateChecks="6" />
    <AutomaticBackgroundTask />
  </UpdateSettings>
</AppInstaller>
XML

echo "Wrote $OUT"
