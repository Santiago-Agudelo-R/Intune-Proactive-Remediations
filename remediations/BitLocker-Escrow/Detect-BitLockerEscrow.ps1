<#
.SYNOPSIS
    Intune Proactive Remediation Detection: Verifies OS BitLocker protection and RecoveryPassword protector presence.

.DESCRIPTION
    Evaluates the system drive ($env:SystemDrive) for Microsoft Intune compliance:
    - VolumeStatus must not be 'FullyDecrypted'.
    - ProtectionStatus must be 'On' (an initial encryption still in progress is reported as pending, not as a failure).
    - At least one 'RecoveryPassword' key protector must exist.
    - That protector must have an escrow confirmation: a BitLocker-API Event ID 845 that mentions its
      KeyProtectorId. Event ID 846 means the backup to Entra ID failed.
    Returns exit code 0 when compliant, or exit code 1 to trigger Remediate-BitLockerEscrow.ps1.
    If the event log has rotated, the device is reported non-compliant and the remediation simply
    escrows the key again, which is safe to repeat.

.PARAMETER TestVolumeObject
    Optional mock volume object used by Pester unit tests for offline validation.

.PARAMETER TestEscrowEventMessages
    Optional array of Event ID 845 messages used by Pester unit tests instead of the event log.

.PARAMETER NoExit
    Suppresses process termination (exit 0/1) during Pester test execution and returns a status object.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [PSCustomObject]$TestVolumeObject,

    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$TestEscrowEventMessages,

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
        [PSCustomObject]$Volume,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$EscrowEventMessages
    )

    $protectors = @($Volume.KeyProtector)
    $recoveryProtectors = @($protectors | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
    $hasRecoveryPassword = $recoveryProtectors.Count -gt 0
    $hasTpmProtector = [bool]($protectors | Where-Object { $_.KeyProtectorType -match '^Tpm' })

    if ($Volume.VolumeStatus -eq 'FullyDecrypted') {
        return [PSCustomObject]@{
            Compliant = $false
            ExitCode  = 1
            Message   = "NON-COMPLIANT: Volume $($Volume.MountPoint) is FullyDecrypted."
        }
    }

    if ($Volume.VolumeStatus -eq 'EncryptionInProgress' -and $Volume.ProtectionStatus -ne 'On' -and $hasRecoveryPassword) {
        return [PSCustomObject]@{
            Compliant = $true
            ExitCode  = 0
            Message   = "PENDING: Volume $($Volume.MountPoint) encryption in progress ($($Volume.EncryptionPercentage)%). Protection turns on when encryption completes."
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

    $escrowed = $false
    foreach ($rp in $recoveryProtectors) {
        $id = ([string]$rp.KeyProtectorId).Trim('{', '}')
        if ($EscrowEventMessages | Where-Object { $_ -match [regex]::Escape($id) }) {
            $escrowed = $true
            break
        }
    }

    if (-not $escrowed) {
        return [PSCustomObject]@{
            Compliant = $false
            ExitCode  = 1
            Message   = "NON-COMPLIANT: Volume $($Volume.MountPoint) has a RecoveryPassword protector but no escrow confirmation (Event ID 845) was found."
        }
    }

    return [PSCustomObject]@{
        Compliant = $true
        ExitCode  = 0
        Message   = "COMPLIANT: Volume $($Volume.MountPoint) encrypted ($($Volume.EncryptionMethod)), ProtectionStatus=On, RecoveryPassword escrowed (TPM=$hasTpmProtector)."
    }
}

try {
    $vol = if ($PSBoundParameters.ContainsKey('TestVolumeObject') -and $null -ne $TestVolumeObject) {
        $TestVolumeObject
    }
    else {
        Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    }

    $escrowMessages = @(if ($PSBoundParameters.ContainsKey('TestEscrowEventMessages')) {
        $TestEscrowEventMessages
    }
    else {
        @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'; Id = 845 } -ErrorAction SilentlyContinue |
                ForEach-Object { [string]$_.Message })
    })

    $evaluation = Test-BitLockerEscrowPosture -Volume $vol -EscrowEventMessages $escrowMessages
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
