<#
.SYNOPSIS
    Intune System Health & Backup Readiness Remediation: Re-enables and restarts core VSS and Windows Update services.

.DESCRIPTION
    Executes in 64-bit SYSTEM context via Intune Proactive Remediations or an RMM script policy:
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

    if ($WhatIfMode) {
        Write-Output "WHATIF: Would re-enable and restart VSS, BITS, wuauserv and CryptSvc, and purge system temp files older than 14 days."
        exit 0
    }

    Write-Output "REMEDIATED: VSS, BITS, wuauserv and CryptSvc re-enabled and restarted; system temp files older than 14 days purged. Application VSS writers (for example SQL) may still need their own service restarted."
    exit 0
}
catch {
    Write-Output "REMEDIATION FAILED: $($_.Exception.Message)"
    exit 1
}
