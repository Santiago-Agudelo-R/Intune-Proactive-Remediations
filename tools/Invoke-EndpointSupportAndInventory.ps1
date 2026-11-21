<#
.SYNOPSIS
    PowerShell endpoint support diagnostics and hardware inventory collector.

.DESCRIPTION
    Combines endpoint support diagnostics with hardware asset inventory telemetry:
    1. Hardware inventory: serial number, manufacturer, model, memory and OS version, in field names that
       map to a CMDB such as Snipe-IT. Asset tags and lifecycle status are left to the CMDB.
    2. Service & Uptime Diagnostics: Detects services stuck in 'Stop Pending' or 'Start Pending', verifies
       that the WinRM and WMI (Winmgmt) services are running, and flags excessive uptime (>14 days).
    Supports -DemoMode for offline testing and Pester CI pipelines.

.NOTES
    Author: Santiago Agudelo
    License: MIT
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

    if (-not $AssetTelemetry.WmiServiceRunning) {
        $supportFindings.Add("WmiServiceStopped")
    }

    if (-not $AssetTelemetry.WinRmServiceRunning) {
        $supportFindings.Add("WinRmServiceStopped")
    }

    if (@($AssetTelemetry.HungServices).Count -gt 0) {
        $supportFindings.Add("HungServicesDetected($($AssetTelemetry.HungServices -join ','))")
    }

    # Only facts collected from the device. Asset tags and lifecycle status belong to the CMDB
    # (for example Snipe-IT) and are not invented here.
    $hardwareInventory = [PSCustomObject]@{
        serial       = $AssetTelemetry.SerialNumber
        manufacturer = $AssetTelemetry.Manufacturer
        model_name   = $AssetTelemetry.Model
        hostname     = $AssetTelemetry.ComputerName
        os_version   = $AssetTelemetry.OsVersion
        ram_gb       = $AssetTelemetry.MemoryGB
    }

    return [PSCustomObject]@{
        Healthy              = ($supportFindings.Count -eq 0)
        ExitCode             = if ($supportFindings.Count -eq 0) { 0 } else { 1 }
        SupportFindings      = $supportFindings.ToArray()
        HardwareInventory    = $hardwareInventory
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
        WmiServiceRunning       = $true
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
    $wmi = Get-Service -Name 'Winmgmt' -ErrorAction SilentlyContinue
    $hung = @(Get-CimInstance -ClassName Win32_Service -Filter "State='Stop Pending' OR State='Start Pending'" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

    [PSCustomObject]@{
        ComputerName            = [System.Environment]::MachineName
        SerialNumber            = $bios.SerialNumber
        Manufacturer            = $cs.Manufacturer
        Model                   = $cs.Model
        OsVersion               = "$($os.Caption) ($($os.Version))"
        MemoryGB                = $ramGb
        UptimeDays              = $uptime
        WmiServiceRunning       = ($null -ne $wmi -and $wmi.Status -eq 'Running')
        WinRmServiceRunning     = ($null -ne $winrm -and $winrm.Status -eq 'Running')
        HungServices            = $hung
    }
}

return Get-EndpointSupportDiagnostic -AssetTelemetry $telemetry -UptimeThresholdDays $MaxUptimeDays
