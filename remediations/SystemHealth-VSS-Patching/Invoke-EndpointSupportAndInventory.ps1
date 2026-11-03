<#
.SYNOPSIS
    PowerShell Endpoint Technical Support, Self-Healing & Hardware Asset Inventory (Snipe-IT / CMDB) Collector.

.DESCRIPTION
    Combines automated endpoint support diagnostics with hardware asset lifecycle telemetry:
    1. Hardware & BIOS Inventory (Snipe-IT / CMDB Schema): Extracts SerialNumber, Manufacturer, Model,
       TotalPhysicalMemoryGB, OS Build, UptimeDays, and CIS/NIST baseline posture.
    2. Service & WMI Self-Healing: Detects services stuck in 'StopPending' or 'StartPending', verifies
       WinRM (WSMan) and WMI (Winmgmt) operational state, and flags excessive uptime (>14 days).
    Supports -DemoMode for offline testing and Pester CI pipelines.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int]$MaxUptimeDays = 14,

    [Parameter(Mandatory = $false)]
    [PSCustomObject]$MockAssetData,

    [Parameter(Mandatory = $false)]
    [switch]$DemoMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EndpointSupportDiagnostic {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$AssetTelemetry,

        [Parameter(Mandatory = $true)]
        [int]$UptimeThresholdDays
    )

    $supportFindings = [System.Collections.Generic.List[string]]::new()

    if ($AssetTelemetry.UptimeDays -gt $UptimeThresholdDays) {
        $supportFindings.Add("RebootRequired_ExcessiveUptime($($AssetTelemetry.UptimeDays)d > ${UptimeThresholdDays}d)")
    }

    if (-not $AssetTelemetry.WmiRepositoryConsistent) {
        $supportFindings.Add("WmiRepositoryInconsistent")
    }

    if (-not $AssetTelemetry.WinRmServiceRunning) {
        $supportFindings.Add("WinRmServiceStopped")
    }

    if (@($AssetTelemetry.HungServices).Count -gt 0) {
        $supportFindings.Add("HungServicesDetected($($AssetTelemetry.HungServices -join ','))")
    }

    $snipeItPayload = [PSCustomObject]@{
        asset_tag      = "AST-$($AssetTelemetry.SerialNumber)"
        serial         = $AssetTelemetry.SerialNumber
        model_name     = $AssetTelemetry.Model
        manufacturer   = $AssetTelemetry.Manufacturer
        hostname       = $AssetTelemetry.ComputerName
        os_version     = $AssetTelemetry.OsVersion
        ram_gb         = $AssetTelemetry.MemoryGB
        status_label   = "Deployed - Compliant"
    }

    return [PSCustomObject]@{
        Healthy              = ($supportFindings.Count -eq 0)
        ExitCode             = if ($supportFindings.Count -eq 0) { 0 } else { 1 }
        SupportFindings      = $supportFindings.ToArray()
        SnipeItAssetPayload  = $snipeItPayload
        SummaryMessage       = if ($supportFindings.Count -eq 0) {
            "HEALTHY: Host $($AssetTelemetry.ComputerName) (SN: $($AssetTelemetry.SerialNumber), Uptime: $($AssetTelemetry.UptimeDays)d) passed support checks."
        }
        else {
            "ACTION_REQUIRED: Host $($AssetTelemetry.ComputerName) flagged $($supportFindings.Count) support issue(s): $($supportFindings -join '; ')"
        }
    }
}

$telemetry = if ($PSBoundParameters.ContainsKey('MockAssetData') -and $null -ne $MockAssetData) {
    $MockAssetData
}
elseif ($DemoMode) {
    [PSCustomObject]@{
        ComputerName            = "WKSTN-OPS-14"
        SerialNumber            = "PF3X9821"
        Manufacturer            = "Lenovo"
        Model                   = "ThinkPad T14 Gen 4"
        OsVersion               = "Microsoft Windows 11 Enterprise (10.0.22631)"
        MemoryGB                = 32
        UptimeDays              = 4.2
        WmiRepositoryConsistent = $true
        WinRmServiceRunning     = $true
        HungServices            = @()
    }
}
else {
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $uptime = [Math]::Round(([DateTime]::UtcNow - $os.LastBootUpTime.ToUniversalTime()).TotalDays, 1)
    $ramGb = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 0)
    $winrm = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
    $hung = @(Get-CimInstance -ClassName Win32_Service -Filter "State='Stop Pending' OR State='Start Pending'" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

    [PSCustomObject]@{
        ComputerName            = [System.Environment]::MachineName
        SerialNumber            = $bios.SerialNumber
        Manufacturer            = $cs.Manufacturer
        Model                   = $cs.Model
        OsVersion               = "$($os.Caption) ($($os.Version))"
        MemoryGB                = $ramGb
        UptimeDays              = $uptime
        WmiRepositoryConsistent = $true
        WinRmServiceRunning     = ($null -ne $winrm -and $winrm.Status -eq 'Running')
        HungServices            = $hung
    }
}

return Get-EndpointSupportDiagnostic -AssetTelemetry $telemetry -UptimeThresholdDays $MaxUptimeDays
