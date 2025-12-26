param(
  [Parameter(Mandatory=$true)][string]$Repo,      # owner/repo
  [Parameter(Mandatory=$true)][string]$Relay,     # http(s)://host:8787
  [string]$DeviceName = $env:COMPUTERNAME
)

$OSN = "windows"
$arch = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Architecture)
# Architecture: 9 = x64, 12 = arm64 (common)
if ($arch -eq 12) { $ARCHN = "arm64" } else { $ARCHN = "x86_64" }

$AgentAsset = "gmf_agent-$OSN-$ARCHN.exe"
$WorkerAsset = "gmf_worker-$OSN-$ARCHN.exe"

$Api = "https://api.github.com/repos/$Repo/releases/latest"
Write-Host "[install] fetching $Api"
$Json = Invoke-RestMethod -Uri $Api -Headers @{ "User-Agent" = "gmf-install" }

function Find-AssetUrl($name) {
  foreach ($a in $Json.assets) {
    if ($a.name -eq $name) { return $a.browser_download_url }
  }
  return $null
}

$AgentUrl = Find-AssetUrl $AgentAsset
$WorkerUrl = Find-AssetUrl $WorkerAsset

if (-not $AgentUrl) { throw "Missing asset $AgentAsset in latest release" }
if (-not $WorkerUrl) { throw "Missing asset $WorkerAsset in latest release" }

$BinDir = Join-Path $HOME "gmf-bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

Invoke-WebRequest -Uri $AgentUrl -OutFile (Join-Path $BinDir "gmf_agent.exe")
Invoke-WebRequest -Uri $WorkerUrl -OutFile (Join-Path $BinDir "gmf_worker.exe")

Write-Host "[install] OK. Next:"
Write-Host "  $BinDir\gmf_agent.exe init --relay $Relay --device-name `"$DeviceName`""
Write-Host "  $BinDir\gmf_agent.exe enroll"
Write-Host "  $BinDir\gmf_agent.exe run --loop-seconds 5"
