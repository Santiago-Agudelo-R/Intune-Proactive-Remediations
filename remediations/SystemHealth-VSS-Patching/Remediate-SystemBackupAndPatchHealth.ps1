<#
.SYNOPSIS
    Intune System Health & Backup Readiness Remediation: Selectively restores disabled patching services and failed VSS writers.

.DESCRIPTION
    Executes in 64-bit SYSTEM context via Intune Proactive Remediations or an RMM script policy:
    1. Targeted Service Recovery: Re-enables core patching/backup services (CryptSvc, VSS, BITS, wuauserv)
       only if their StartType is Disabled, and restarts VSS only when a VSS writer is in a failed state.
       Does not force-restart VSS when writers are healthy, avoiding interruption of active backup jobs.
    2. Evidence-Safe Storage Handling: Does not delete files from C:\Windows\Temp by default
       ($PurgeTempOnLowDisk = $false) because C:\Windows\Temp is a common attacker staging directory.
       When $PurgeTempOnLowDisk is explicitly enabled, cleanup only runs if free disk space is actually
       below $MinimumFreePercent and no incident-response hold marker (%ProgramData%\SecOps\IR_HOLD.lock)
       is present.

.NOTES
    Author: Santiago Agudelo
    License: MIT
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 50)]
    [int]$MinimumFreePercent = 10,

    [Parameter(Mandatory = $false)]
    [bool]$PurgeTempOnLowDisk = $false,

    [Parameter(Mandatory = $false)]
    [PSCustomObject]$MockTelemetry,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIfMode,

    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FailedVssWriter {
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$VssAdminOutput
    )

    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($block in ($VssAdminOutput -split '\r?\n\s*\r?\n')) {
        if ($block -match "'([^']+)'") {
            $writerName = $Matches[1]
            if ($block -match '\[(\d+)\]' -and $Matches[1] -ne '1') {
                $failed.Add($writerName)
            }
        }
    }
    return $failed.ToArray()
}

try {
    $telemetry = if ($PSBoundParameters.ContainsKey('MockTelemetry') -and $null -ne $MockTelemetry) {
        $MockTelemetry
    }
    else {
        $vssOutput = vssadmin list writers 2>&1 | Out-String
        $failedWriters = @(Get-FailedVssWriter -VssAdminOutput $vssOutput)
        $sysDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop
        $freePct = [Math]::Round(($sysDrive.FreeSpace / $sysDrive.Size) * 100, 1)

        [PSCustomObject]@{
            FailedVssWriters = $failedWriters
            FreeDiskPercent  = $freePct
            IrHoldPresent    = (Test-Path -LiteralPath (Join-Path $env:ProgramData 'SecOps\IR_HOLD.lock'))
        }
    }

    $actions = [System.Collections.Generic.List[string]]::new()
    $coreServices = @(
        @{ Name = 'CryptSvc'; StartupType = 'Automatic' },
        @{ Name = 'VSS';      StartupType = 'Manual' },
        @{ Name = 'BITS';     StartupType = 'Manual' },
        @{ Name = 'wuauserv'; StartupType = 'Manual' }
    )

    if (-not $PSBoundParameters.ContainsKey('MockTelemetry')) {
        foreach ($entry in $coreServices) {
            $svc = Get-Service -Name $entry.Name -ErrorAction SilentlyContinue
            if ($svc -and $svc.StartType -eq 'Disabled') {
                if (-not $WhatIfMode) {
                    Set-Service -Name $entry.Name -StartupType $entry.StartupType -ErrorAction Stop
                }
                $actions.Add("ReEnabledService($($entry.Name))")
            }
        }
    }

    # Only restart VSS / CryptSvc when at least one VSS writer is actually in a failed state
    if (@($telemetry.FailedVssWriters).Count -gt 0) {
        if (-not $WhatIfMode -and (-not $PSBoundParameters.ContainsKey('MockTelemetry'))) {
            Restart-Service -Name 'VSS' -ErrorAction SilentlyContinue
            Restart-Service -Name 'CryptSvc' -ErrorAction SilentlyContinue
        }
        $actions.Add("RestartedVssForFailedWriters($($telemetry.FailedVssWriters -join ','))")
    }

    # Only consider Temp cleanup when disk pressure is actually below threshold AND opt-in is enabled
    $isLowDisk = ($telemetry.FreeDiskPercent -lt $MinimumFreePercent)
    $irHold = if ($telemetry.PSObject.Properties['IrHoldPresent']) { [bool]$telemetry.IrHoldPresent } else { $false }

    if ($isLowDisk) {
        if ($irHold) {
            $actions.Add('SkippedTempPurge(IR_HOLD_Active)')
        }
        elseif (-not $PurgeTempOnLowDisk) {
            $actions.Add("LowDiskDetected($($telemetry.FreeDiskPercent)%_TempPurgeDisabledByDefault)")
        }
        else {
            $removedCount = 0
            if (-not $WhatIfMode -and (-not $PSBoundParameters.ContainsKey('MockTelemetry'))) {
                $cutoff = [DateTime]::UtcNow.AddDays(-14)
                $tempPath = Join-Path $env:SystemRoot 'Temp'
                if (Test-Path -LiteralPath $tempPath) {
                    $staleFiles = @(Get-ChildItem -LiteralPath $tempPath -File -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTimeUtc -lt $cutoff })
                    foreach ($f in $staleFiles) {
                        try {
                            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                            $removedCount++
                        }
                        catch {
                            Write-Verbose "Skipped locked or protected file: $($f.FullName)"
                        }
                    }
                }
            }
            $actions.Add("PurgedStaleTempFiles($removedCount)")
        }
    }

    if ($actions.Count -eq 0) {
        $actions.Add('NoDestructiveActionRequired')
    }

    $prefix = if ($WhatIfMode) { 'WHATIF' } else { 'REMEDIATED' }
    $msg = "${prefix}: $($actions -join '; ')"

    if ($NoExit) {
        return [PSCustomObject]@{
            Remediated = $true
            ExitCode   = 0
            Actions    = $actions.ToArray()
            Message    = $msg
        }
    }

    Write-Output $msg
    exit 0
}
catch {
    $errMsg = "REMEDIATION FAILED: $($_.Exception.Message)"
    if ($NoExit) {
        return [PSCustomObject]@{ Remediated = $false; ExitCode = 1; Actions = @(); Message = $errMsg }
    }
    Write-Output $errMsg
    exit 1
}
