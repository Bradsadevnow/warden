# Windows laptop: authorize the main PC's key. Run in an ADMIN PowerShell from the repo root:  .\lab\setup-ssh.ps1
$key = (Get-Content "$PSScriptRoot\main-pc.pub").Trim()
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$inAdminGroup = (whoami /groups) -match "S-1-5-32-544"
if ($inAdminGroup) { $file = "C:\ProgramData\ssh\administrators_authorized_keys" }
else { New-Item -ItemType Directory -Force "$env:USERPROFILE\.ssh" | Out-Null; $file = "$env:USERPROFILE\.ssh\authorized_keys" }
if (-not (Test-Path $file) -or -not (Select-String -Path $file -SimpleMatch -Quiet $key)) { Add-Content -Path $file -Value $key -Encoding ascii }
if ($inAdminGroup) { icacls $file /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null }
Write-Host "key authorized in $file for $env:USERNAME on $env:COMPUTERNAME"
