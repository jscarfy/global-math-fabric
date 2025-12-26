param(
  [Parameter(Mandatory=$true)][string]$Repo,
  [Parameter(Mandatory=$true)][string]$Relay
)

$BinDir = Join-Path $HOME "gmf-bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

Write-Host "Installing to $BinDir"
Write-Host "NOTE: download gmf_agent.exe and gmf_worker.exe from GitHub Releases and put them in:"
Write-Host "  $BinDir\gmf_agent.exe"
Write-Host "  $BinDir\gmf_worker.exe"
Write-Host ""
Write-Host "Then run:"
Write-Host "  $BinDir\gmf_agent.exe init --relay $Relay --device-name $env:COMPUTERNAME"
Write-Host "  $BinDir\gmf_agent.exe enroll"
Write-Host "  $BinDir\gmf_agent.exe run --loop-seconds 5"
