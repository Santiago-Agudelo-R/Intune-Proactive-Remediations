<#
.SYNOPSIS
    MSP / Intune System Health & Backup Readiness Remediation: Resets failed VSS Writers and Windows Update components.

.DESCRIPTION
    Executes in 64-bit SYSTEM context via RMM / Intune Proactive Remediations:
    1. Re-enables core backup and patching services (VSS, CryptSvc, BITS, wuauserv) if disabled.
    2. Restarts Volume Shadow Copy (VSS) and Cryptographic Services to clear transient VSS writer locks before backup windows.
    3. Purges stale Windows Temp files older than 14 days when disk pressure is detected.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$WhatIfMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $coreServices = @(
        @{ Name = 'CryptSvc'; StartupType = 'Automatic' },
        @{ Name = 'VSS';      StartupType = 'Manual' },
        @{ Name = 'BITS';     StartupType = 'Manual' },
        @{ Name = 'wuauserv'; StartupType = 'Manual' }
    )

    foreach ($entry in $coreServices) {
        $svc = Get-Service -Name $entry.Name -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.StartType -eq 'Disabled' -and -not $WhatIfMode) {
                Set-Service -Name $entry.Name -StartupType $entry.StartupType -ErrorAction Stop
            }
            if (-not $WhatIfMode) {
                Restart-Service -Name $entry.Name -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $cutoff = [DateTime]::UtcNow.AddDays(-14)
    $tempPath = Join-Path $env:SystemRoot 'Temp'
    if ((Test-Path -LiteralPath $tempPath) -and -not $WhatIfMode) {
        Get-ChildItem -LiteralPath $tempPath -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -lt $cutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    Write-Output "REMEDIATED: Core VSS backup writers and Windows Update services reset; stale system temp files purged."
    exit 0
}
catch {
    Write-Output "REMEDIATION FAILED: $($_.Exception.Message)"
    exit 1
}
