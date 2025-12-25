Param([Parameter(Mandatory=$true)][string]$AppExe)
$Startup = [Environment]::GetFolderPath("Startup")
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Startup\GMF.lnk")
$Shortcut.TargetPath = $AppExe
$Shortcut.Save()
Write-Host "Created startup shortcut at $Startup\GMF.lnk"
