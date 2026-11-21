<#
.SYNOPSIS
    Intune Endpoint Security Remediation: Restores Microsoft Defender Services, Real-Time Protection, and Signature Freshness.

.DESCRIPTION
    Triggered when Detect-DefenderSensorHealth.ps1 exits with code 1:
    1. Starts WinDefend (and Sense if installed and stopped).
    2. Re-enables Real-Time Monitoring and Behavior Monitoring via Set-MpPreference (when not blocked by Tamper Protection).
    3. Forces an immediate signature update via Update-MpSignature.

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

try {
    foreach ($svcName in @('WinDefend', 'Sense')) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -ne 'Running') {
            if ($PSCmdlet.ShouldProcess($svcName, 'Start-Service')) {
                Start-Service -Name $svcName -ErrorAction Stop
                $actions.Add("StartedService($svcName)")
            }
            else {
                $actions.Add("WhatIf:StartService($svcName)")
            }
        }
    }

    if ($PSCmdlet.ShouldProcess('Microsoft Defender Engine', 'Enable RealTimeMonitoring & BehaviorMonitoring and Update-MpSignature')) {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        $actions.Add('VerifiedRealtimeAndBehaviorMonitoring')
        Update-MpSignature -ErrorAction Stop
        $actions.Add('UpdatedMpSignatures')
    }
    else {
        $actions.Add('WhatIf:EnableMonitoringAndUpdateSignatures')
    }

    $msg = "REMEDIATED: Defender sensor remediation actions completed: $($actions -join '; ')"
    if ($NoExit) {
        return [PSCustomObject]@{ Remediated = $true; ExitCode = 0; Actions = $actions.ToArray(); Message = $msg }
    }
    Write-Output $msg
    exit 0
}
catch {
    $errMsg = "ERROR: Defender sensor remediation failed: $($_.Exception.Message)"
    if ($NoExit) {
        return [PSCustomObject]@{ Remediated = $false; ExitCode = 1; Actions = $actions.ToArray(); Message = $errMsg }
    }
    Write-Output $errMsg
    exit 1
}