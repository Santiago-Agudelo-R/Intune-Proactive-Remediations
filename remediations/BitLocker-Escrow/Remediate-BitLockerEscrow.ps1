<#
.SYNOPSIS
    Intune Proactive Remediation: Resumes BitLocker protection and escrows the RecoveryPassword to Entra ID.

.DESCRIPTION
    Executes in 64-bit SYSTEM context via Microsoft Intune Management Extension:
    1. If VolumeStatus is 'FullyDecrypted', exits without changes: initial encryption is owned by the
       Intune Endpoint Security disk encryption policy, not by this script.
    2. Creates a RecoveryPassword protector if missing on $env:SystemDrive.
    3. Resumes BitLocker protection if currently suspended (ProtectionStatus = Off).
    4. Escrows the 48-digit RecoveryPassword protector to Microsoft Entra ID via BackupToAAD-BitLockerKeyProtector.
       Escrowing again is safe; Entra ID keeps the key linked to the device.
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
        # Out of scope by design: initial encryption belongs to the Intune Endpoint Security
        # disk encryption policy. Enabling BitLocker from a remediation script would conflict with it.
        Write-Output "SKIPPED: Volume $mount is FullyDecrypted. Assign the Intune disk encryption policy to this device; this script only fixes protection and escrow."
        exit 1
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

    if ($WhatIfMode) {
        Write-Output "WHATIF: Would resume protection if suspended, add a RecoveryPassword protector if missing, and escrow it to Entra ID for volume $mount."
        exit 0
    }

    Write-Output "REMEDIATED: Protection verified and RecoveryPassword $($recoveryProtector.KeyProtectorId) escrowed to Entra ID for volume $mount."
    exit 0
}
catch {
    Write-Output "REMEDIATION FAILED: $($_.Exception.Message)"
    exit 1
}
