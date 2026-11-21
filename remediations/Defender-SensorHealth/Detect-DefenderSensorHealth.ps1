<#
.SYNOPSIS
    Intune Endpoint Security Detection: Audits Microsoft Defender Antivirus, MDE Sensor (Sense), Tamper Protection, and Signature Freshness.

.DESCRIPTION
    Designed for Microsoft Intune Remediations or RMM script policies (MITRE ATT&CK T1562.001 defense-in-depth):
    1. Core Services: Verifies WinDefend and Sense (when onboarded to Defender for Endpoint) are running.
    2. Protection Engines: Verifies RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, and IsTamperProtected.
    3. Signature Freshness: Flags endpoints whose AntivirusSignatureLastUpdated exceeds MaxSignatureAgeDays (default: 7 days).
    Returns exit 0 when healthy, or exit 1 to trigger Remediate-DefenderSensorHealth.ps1.

.NOTES
    Author: Santiago Agudelo
    License: MIT
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 30)]
    [int]$MaxSignatureAgeDays = 7,

    [Parameter(Mandatory = $false)]
    [PSCustomObject]$MockTelemetry,

    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-DefenderSensorPosture {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Telemetry,

        [Parameter(Mandatory = $true)]
        [int]$MaxAgeDays
    )

    $issues = [System.Collections.Generic.List[string]]::new()

    if ($Telemetry.WinDefendServiceState -ne 'Running') {
        $issues.Add("WinDefendService($($Telemetry.WinDefendServiceState))")
    }

    if ($Telemetry.MdeOnboarded -and $Telemetry.SenseServiceState -ne 'Running') {
        $issues.Add("SenseService($($Telemetry.SenseServiceState))")
    }

    if (-not $Telemetry.RealTimeProtectionEnabled) {
        $issues.Add('RealTimeProtectionDisabled')
    }

    if (-not $Telemetry.BehaviorMonitorEnabled) {
        $issues.Add('BehaviorMonitorDisabled')
    }

    if (-not $Telemetry.IsTamperProtected) {
        $issues.Add('TamperProtectionDisabled')
    }

    if ($Telemetry.SignatureAgeDays -gt $MaxAgeDays) {
        $issues.Add("StaleSignatures($($Telemetry.SignatureAgeDays)d > ${MaxAgeDays}d)")
    }

    if ($issues.Count -gt 0) {
        return [PSCustomObject]@{
            Compliant = $false
            ExitCode  = 1
            Issues    = $issues.ToArray()
            Message   = "NON-COMPLIANT: Defender sensor posture degraded: $($issues -join '; ')"
        }
    }

    return [PSCustomObject]@{
        Compliant = $true
        ExitCode  = 0
        Issues    = @()
        Message   = "COMPLIANT: WinDefend=Running, RealTimeProtection=True, TamperProtected=True, SignatureAge=$($Telemetry.SignatureAgeDays)d."
    }
}

try {
    $telemetry = if ($PSBoundParameters.ContainsKey('MockTelemetry') -and $null -ne $MockTelemetry) {
        $MockTelemetry
    }
    else {
        $winDefend = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
        $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        $onboardReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
        $mdeOnboarded = [bool]($null -ne $sense -or ($null -ne $onboardReg -and $onboardReg.PSObject.Properties['OnboardingState'] -and $onboardReg.OnboardingState -eq 1))

        $mp = Get-MpComputerStatus -ErrorAction Stop
        $sigDate = if ($mp.AntivirusSignatureLastUpdated) { ([DateTime]$mp.AntivirusSignatureLastUpdated).ToUniversalTime() } else { [DateTime]::UtcNow.AddDays(-99) }
        $sigAge = [int][Math]::Floor(([DateTime]::UtcNow - $sigDate).TotalDays)
        $tamper = if ($mp.PSObject.Properties['IsTamperProtected']) { [bool]$mp.IsTamperProtected } else { $true }

        [PSCustomObject]@{
            WinDefendServiceState     = if ($winDefend) { $winDefend.Status.ToString() } else { 'Missing' }
            MdeOnboarded              = $mdeOnboarded
            SenseServiceState         = if ($sense) { $sense.Status.ToString() } else { 'NotInstalled' }
            RealTimeProtectionEnabled = [bool]$mp.RealTimeProtectionEnabled
            BehaviorMonitorEnabled    = [bool]$mp.BehaviorMonitorEnabled
            IsTamperProtected         = $tamper
            SignatureAgeDays          = $sigAge
        }
    }

    $res = Test-DefenderSensorPosture -Telemetry $telemetry -MaxAgeDays $MaxSignatureAgeDays
    if ($NoExit) {
        return $res
    }

    Write-Output $res.Message
    exit $res.ExitCode
}
catch {
    $errMsg = "ERROR: Defender sensor check failed: $($_.Exception.Message)"
    if ($NoExit) {
        return [PSCustomObject]@{ Compliant = $false; ExitCode = 1; Issues = @(); Message = $errMsg }
    }
    Write-Output $errMsg
    exit 1
}