param(
  [string]$Subject = "CN=GMF",
  [string]$OutDir = ".\certs",
  [string]$PfxPassword = "change_me"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Create self-signed code signing cert (CurrentUser\My)
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject $Subject `
  -CertStoreLocation "Cert:\CurrentUser\My"

# Export CER (public) and PFX (private)
$cerPath = Join-Path $OutDir "gmf.cer"
$pfxPath = Join-Path $OutDir "gmf.pfx"

Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
$sec = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $sec | Out-Null

Write-Host "Wrote:"
Write-Host "  CER: $cerPath"
Write-Host "  PFX: $pfxPath"
Write-Host ""
Write-Host "To trust on a test machine:"
Write-Host "  import CER into 'Trusted People' (or enterprise policy store)."
