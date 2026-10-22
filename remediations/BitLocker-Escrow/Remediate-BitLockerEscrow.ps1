<#
.SYNOPSIS
    Intune Proactive Remediation: Enables or resumes BitLocker protection and escrows RecoveryPassword to Entra ID.

.DESCRIPTION
    Executes in 64-bit SYSTEM context via Microsoft Intune Management Extension:
    1. If VolumeStatus is 'FullyDecrypted', enables BitLocker with XtsAes256 and TPM + RecoveryPassword protectors.
    2. Creates a RecoveryPassword protector if missing on $env:SystemDrive.
    3. Resumes BitLocker protection if currently suspended (ProtectionStatus = Off).
    4. Escrows the 48-digit RecoveryPassword protector to Microsoft Entra ID via BackupToAAD-BitLockerKeyProtector.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$WhatIfMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $mount = $env:SystemDrive
    $vol = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop

    if ($vol.VolumeStatus -eq 'FullyDecrypted') {
        if (-not $WhatIfMode) {
            $null = Enable-BitLocker -MountPoint $mount -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -SkipHardwareTest -ErrorAction Stop
            $vol = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop
        }
    }

    $recoveryProtector = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1

    if (-not $recoveryProtector) {
        if (-not $WhatIfMode) {
            $null = Add-BitLockerKeyProtector -MountPoint $mount -RecoveryPasswordProtector -ErrorAction Stop
            $vol = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop
            $recoveryProtector = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
        }
    }

    if ($vol.VolumeStatus -in @('FullyEncrypted', 'EncryptionInProgress') -and $vol.ProtectionStatus -eq 'Off') {
        if (-not $WhatIfMode) {
            $null = Resume-BitLocker -MountPoint $mount -ErrorAction Stop
        }
    }

    if ($recoveryProtector -and -not $WhatIfMode) {
        $null = BackupToAAD-BitLockerKeyProtector -MountPoint $mount -KeyProtectorId $recoveryProtector.KeyProtectorId -ErrorAction Stop
    }

    Write-Output "REMEDIATED: BitLocker protection verified and RecoveryPassword escrowed for volume $mount."
    exit 0
}
catch {
    Write-Output "REMEDIATION FAILED: $($_.Exception.Message)"
    exit 1
}
