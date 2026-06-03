#requires -Version 7.0
<#
.SYNOPSIS
    H2Shield — standalone manual mitigation for HTTP/2 Bomb (CVE-2026-49975) on IIS.
.DESCRIPTION
    The entire IIS mitigation, with no GUI: disable HTTP/2 at the HTTP.SYS layer
    and clamp header limits. State-aware — restarts HTTP.SYS/W3SVC only if IIS is
    actually running; otherwise writes the values and lets HTTP.SYS pick them up
    on its next start (avoiding the kernel-driver-restart hang on stopped IIS).
.PARAMETER WhatIf
    Show what would change without writing anything.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\Apply-H2Mitigation.ps1
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\Apply-H2Mitigation.ps1 -WhatIf
.NOTES
    Run elevated. Disabling HTTP/2 is a MITIGATION for unpatched IIS, not a fix.
    Apply vendor patches when available.
#>
[CmdletBinding()]
param([switch]$WhatIf)

$ErrorActionPreference = 'Stop'

# --- elevation check ---
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Run this in an elevated PowerShell 7 session.'
    return
}

$reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
$svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue

if (-not $svc) {
    Write-Host 'No IIS/W3SVC on this box — no HTTP/2 server surface to harden. Nothing to do.' -ForegroundColor Yellow
    return
}

$values = [ordered]@{
    EnableHttp2Tls       = 0
    EnableHttp2Cleartext = 0
    MaxFieldLength       = 16384
    MaxRequestBytes      = 32768
}

Write-Host "`nIIS detected. W3SVC: $($svc.Status)/$($svc.StartType)`n" -ForegroundColor Cyan

foreach ($name in $values.Keys) {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would set $name = $($values[$name])"
    } else {
        if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
        New-ItemProperty -Path $reg -Name $name -Value $values[$name] -PropertyType DWord -Force | Out-Null
        Write-Host "Set $name = $($values[$name])" -ForegroundColor Green
    }
}

# --- state-aware restart ---
if ($WhatIf) {
    Write-Host "`n[WhatIf] Would restart HTTP.SYS + W3SVC only if IIS is running and not disabled."
} elseif ($svc.Status -eq 'Running' -and $svc.StartType -ne 'Disabled') {
    try {
        Write-Host "`nIIS is running — restarting HTTP.SYS + W3SVC to apply immediately..." -ForegroundColor Cyan
        Stop-Service W3SVC -Force -ErrorAction Stop
        Restart-Service HTTP -Force -ErrorAction Stop
        Start-Service W3SVC -ErrorAction Stop
        Write-Host 'Restarted. HTTP/2 is now disabled live.' -ForegroundColor Green
    } catch {
        Write-Warning "Restart issue (registry values still applied): $($_.Exception.Message)"
    }
} else {
    Write-Host "`nIIS is $($svc.Status)/$($svc.StartType) — registry values written; NO kernel restart performed." -ForegroundColor Yellow
    Write-Host 'Values apply automatically the next time HTTP.SYS starts.' -ForegroundColor Yellow
}

# --- verify ---
if (-not $WhatIf) {
    Write-Host "`n--- Verification ---" -ForegroundColor Cyan
    Get-ItemProperty $reg | Select-Object EnableHttp2Tls, EnableHttp2Cleartext, MaxFieldLength, MaxRequestBytes
}
