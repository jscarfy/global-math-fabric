param(
  [string]$Owner = "pujustinyang",
  [string]$Repo = "global-math-fabric",
  [string]$InstallDir = "$env:LOCALAPPDATA\gmf\bin"
)

$BinName = "gmf-client"
$Api = "https://api.github.com/repos/$Owner/$Repo/releases/latest"

$resp = Invoke-RestMethod -Uri $Api -Headers @{ "User-Agent" = "gmf-installer" }
$asset = $resp.assets | Where-Object { $_.name -eq "$BinName-Windows" } | Select-Object -First 1
if (-not $asset) { throw "Could not find asset: $BinName-Windows" }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$dest = Join-Path $InstallDir "$BinName.exe"
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dest
Write-Host "Installed: $dest"
Write-Host "Next:"
Write-Host "  $dest setup --api http://<your-server>:8000 --client-id <your-id> --display-name <name>"
Write-Host "  $dest run --only-on-ac --max-cpu-percent 70"
