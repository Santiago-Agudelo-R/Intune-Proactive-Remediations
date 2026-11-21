<#
.SYNOPSIS
    Intune Remediations script: restores Microsoft Defender services, monitoring and signatures, then verifies the result.

.DESCRIPTION
    Triggered when Detect-DefenderSensorHealth.ps1 exits with code 1:
    1. Starts WinDefend if stopped, and Sense only when the device is onboarded to Defender for Endpoint.
    2. Re-enables Real-Time and Behavior Monitoring with Set-MpPreference when Defender is the primary AV.
       If Tamper Protection or a managed policy blocks the change, the block is reported instead of hidden.
    3. Forces a signature update with Update-MpSignature.
    4. Re-reads Get-MpComputerStatus and exits 1 if protection is still off, so Intune reports the
       remediation as failed instead of falsely successful. Tamper Protection itself cannot be turned on
       from a script; it must be enabled from the Defender portal or Intune.

.PARAMETER NoExit
    Returns a result object instead of calling exit, for Pester tests.

.NOTES
    Author: Santiago Agudelo
    License: MIT
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$actions = [System.Collections.Generic.List[string]]::new()
$returnResultObject = $NoExit.IsPresent

function Complete-Run {
    [CmdletBinding()]
    param ([bool]$Remediated, [int]$ExitCode, [string]$Message)

    if ($returnResultObject) {
        return [PSCustomObject]@{ Remediated = $Remediated; ExitCode = $ExitCode; Actions = $actions.ToArray(); Message = $Message }
    }
    Write-Output $Message
    exit $ExitCode
}

try {
    $onboardReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
    $mdeOnboarded = [bool]($null -ne $onboardReg -and $onboardReg.PSObject.Properties['OnboardingState'] -and $onboardReg.OnboardingState -eq 1)

    $services = @('WinDefend')
    if ($mdeOnboarded) { $services += 'Sense' }

    foreach ($svcName in $services) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -ne 'Running' -and $PSCmdlet.ShouldProcess($svcName, 'Start-Service')) {
            Start-Service -Name $svcName -ErrorAction Stop
            $actions.Add("StartedService($svcName)")
        }
    }

    $status = Get-MpComputerStatus -ErrorAction Stop
    $isPrimaryAv = [string]$status.AMRunningMode -notmatch '(?i)passive|edr block'

    if ($isPrimaryAv -and (-not $status.RealTimeProtectionEnabled -or -not $status.BehaviorMonitorEnabled) -and
        $PSCmdlet.ShouldProcess('Microsoft Defender Antivirus', 'Enable real-time and behavior monitoring')) {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -ErrorAction Stop
            $actions.Add('RequestedMonitoringOn')
        }
        catch {
            $actions.Add("SetMpPreferenceBlocked($($_.Exception.Message))")
        }
    }

    if ($PSCmdlet.ShouldProcess('Microsoft Defender Antivirus', 'Update-MpSignature')) {
        Update-MpSignature -ErrorAction Stop
        $actions.Add('UpdatedSignatures')
    }

    if ($WhatIfPreference) {
        return Complete-Run -Remediated $false -ExitCode 0 -Message 'WHATIF: No changes were made.'
    }

    $after = Get-MpComputerStatus -ErrorAction Stop
    $stillOff = [System.Collections.Generic.List[string]]::new()
    if ($isPrimaryAv -and -not $after.RealTimeProtectionEnabled) { $stillOff.Add('RealTimeProtection') }
    if ($isPrimaryAv -and -not $after.BehaviorMonitorEnabled) { $stillOff.Add('BehaviorMonitor') }
    if ((Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue).Status -ne 'Running') { $stillOff.Add('WinDefend') }

    if ($stillOff.Count -gt 0) {
        return Complete-Run -Remediated $false -ExitCode 1 `
            -Message "REMEDIATION INCOMPLETE: still off after remediation: $($stillOff -join ', '). Actions: $($actions -join '; ')"
    }

    return Complete-Run -Remediated $true -ExitCode 0 -Message "REMEDIATED: $($actions -join '; ')"
}
catch {
    return Complete-Run -Remediated $false -ExitCode 1 -Message "REMEDIATION FAILED: $($_.Exception.Message)"
}
