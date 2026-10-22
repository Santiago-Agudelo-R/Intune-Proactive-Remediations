<#
.SYNOPSIS
    Intune Proactive Remediation Detection: Verifies OS BitLocker protection and RecoveryPassword protector presence.

.DESCRIPTION
    Evaluates the system drive ($env:SystemDrive) for Microsoft Intune compliance:
    - VolumeStatus must be 'FullyEncrypted' or 'EncryptionInProgress'.
    - ProtectionStatus must be 'On'.
    - At least one 'RecoveryPassword' key protector must exist for Entra ID escrow.
    Returns exit code 0 when compliant, or exit code 1 to trigger Remediate-BitLockerEscrow.ps1.

.PARAMETER TestVolumeObject
    Optional mock volume object used by Pester unit tests for offline validation.

.PARAMETER NoExit
    Suppresses process termination (exit 0/1) during Pester test execution and returns a status object.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [PSCustomObject]$TestVolumeObject,

    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-BitLockerEscrowPosture {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Volume
    )

    $protectors = @($Volume.KeyProtector)
    $hasRecoveryPassword = [bool]($protectors | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
    $hasTpmProtector = [bool]($protectors | Where-Object { $_.KeyProtectorType -match '^Tpm' })

    if ($Volume.VolumeStatus -eq 'FullyDecrypted') {
        return [PSCustomObject]@{
            Compliant = $false
            ExitCode  = 1
            Message   = "NON-COMPLIANT: Volume $($Volume.MountPoint) is FullyDecrypted."
        }
    }

    if ($Volume.ProtectionStatus -ne 'On') {
        return [PSCustomObject]@{
            Compliant = $false
            ExitCode  = 1
            Message   = "NON-COMPLIANT: Volume $($Volume.MountPoint) status is $($Volume.VolumeStatus) but ProtectionStatus is Off."
        }
    }

    if (-not $hasRecoveryPassword) {
        return [PSCustomObject]@{
            Compliant = $false
            ExitCode  = 1
            Message   = "NON-COMPLIANT: Volume $($Volume.MountPoint) is missing a RecoveryPassword key protector for Entra ID escrow."
        }
    }

    return [PSCustomObject]@{
        Compliant = $true
        ExitCode  = 0
        Message   = "COMPLIANT: Volume $($Volume.MountPoint) encrypted ($($Volume.EncryptionMethod)), ProtectionStatus=On, RecoveryPassword present (TPM=$hasTpmProtector)."
    }
}

try {
    $vol = if ($PSBoundParameters.ContainsKey('TestVolumeObject') -and $null -ne $TestVolumeObject) {
        $TestVolumeObject
    }
    else {
        Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    }

    $evaluation = Test-BitLockerEscrowPosture -Volume $vol
    if ($NoExit) {
        return $evaluation
    }

    Write-Output $evaluation.Message
    exit $evaluation.ExitCode
}
catch {
    $errMsg = "ERROR: BitLocker detection failed: $($_.Exception.Message)"
    if ($NoExit) {
        return [PSCustomObject]@{ Compliant = $false; ExitCode = 1; Message = $errMsg }
    }
    Write-Output $errMsg
    exit 1
}
