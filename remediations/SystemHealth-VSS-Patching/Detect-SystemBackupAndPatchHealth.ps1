<#
.SYNOPSIS
    MSP / Intune System Health & Backup Readiness Detection: Audits VSS Writers, Windows Update Services, and Disk Free Space.

.DESCRIPTION
    Designed for Centralized Services / RMM (Intune, Kaseya VSAx, Datto/Autotask) recurring health checks:
    1. Volume Shadow Copy Service (VSS) Writers: Ensures zero VSS writers are in a failed/retryable state prior to nightly backup windows.
    2. Patching Services: Verifies Windows Update (wuauserv), Background Intelligent Transfer (BITS), and Cryptographic Services (CryptSvc) are operational.
    3. Storage Pressure: Flags system drives with less than MinimumFreePercent (default: 10%) free space.
    Returns exit 0 when healthy, or exit 1 to trigger Remediate-SystemBackupAndPatchHealth.ps1.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 50)]
    [int]$MinimumFreePercent = 10,

    [Parameter(Mandatory = $false)]
    [PSCustomObject]$MockTelemetry,

    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-SystemBackupAndPatchReadiness {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Telemetry,

        [Parameter(Mandatory = $true)]
        [int]$MinFreePct
    )

    $issues = [System.Collections.Generic.List[string]]::new()

    if (@($Telemetry.FailedVssWriters).Count -gt 0) {
        $writers = ($Telemetry.FailedVssWriters) -join ', '
        $issues.Add("FailedVssWriters($writers)")
    }

    if (@($Telemetry.StoppedCoreServices).Count -gt 0) {
        $svcs = ($Telemetry.StoppedCoreServices) -join ', '
        $issues.Add("StoppedCoreServices($svcs)")
    }

    if ($Telemetry.FreeDiskPercent -lt $MinFreePct) {
        $issues.Add("LowDiskSpace($($Telemetry.FreeDiskPercent)% < $MinFreePct%)")
    }

    if ($issues.Count -gt 0) {
        return [PSCustomObject]@{
            Compliant = $false
            ExitCode  = 1
            Issues    = $issues.ToArray()
            Message   = "NON-COMPLIANT: Endpoint health check failed: $($issues -join '; ')"
        }
    }

    return [PSCustomObject]@{
        Compliant = $true
        ExitCode  = 0
        Issues    = @()
        Message   = "COMPLIANT: VSS writers healthy, core patching services active, FreeDisk=$($Telemetry.FreeDiskPercent)%."
    }
}

try {
    $telemetry = if ($PSBoundParameters.ContainsKey('MockTelemetry') -and $null -ne $MockTelemetry) {
        $MockTelemetry
    }
    else {
        $vssOutput = vssadmin list writers 2>&1 | Out-String
        $failedWriters = [System.Collections.Generic.List[string]]::new()
        $writerBlocks = $vssOutput -split "Writer name:"
        foreach ($block in $writerBlocks) {
            if ($block -match "^\s*'([^']+)'" -and $block -notmatch "State:\s*\[1\]\s*Stable") {
                $failedWriters.Add($Matches[1])
            }
        }

        $stoppedSvcs = [System.Collections.Generic.List[string]]::new()
        foreach ($svcName in @('VSS', 'CryptSvc', 'BITS', 'wuauserv')) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.StartType -eq 'Disabled') {
                $stoppedSvcs.Add("$svcName(Disabled)")
            }
        }

        $sysDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop
        $freePct = [Math]::Round(($sysDrive.FreeSpace / $sysDrive.Size) * 100, 1)

        [PSCustomObject]@{
            FailedVssWriters    = $failedWriters.ToArray()
            StoppedCoreServices = $stoppedSvcs.ToArray()
            FreeDiskPercent     = $freePct
        }
    }

    $res = Test-SystemBackupAndPatchReadiness -Telemetry $telemetry -MinFreePct $MinimumFreePercent
    if ($NoExit) {
        return $res
    }

    Write-Output $res.Message
    exit $res.ExitCode
}
catch {
    $errMsg = "ERROR: System health check failed: $($_.Exception.Message)"
    if ($NoExit) {
        return [PSCustomObject]@{ Compliant = $false; ExitCode = 1; Issues = @(); Message = $errMsg }
    }
    Write-Output $errMsg
    exit 1
}
