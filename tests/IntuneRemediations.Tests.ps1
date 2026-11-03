#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:BitLockerDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\BitLocker-Escrow\Detect-BitLockerEscrow.ps1'
    $script:AdminDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\LocalAdmin-Hygiene\Detect-UnauthorizedLocalAdmins.ps1'
    $script:HealthDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\SystemHealth-VSS-Patching\Detect-SystemBackupAndPatchHealth.ps1'
}

Describe 'Detect-BitLockerEscrow' {

    It 'returns Compliant (ExitCode 0) when encrypted, ProtectionStatus is On, and RecoveryPassword exists' {
        $mockVol = [PSCustomObject]@{
            MountPoint       = 'C:'
            VolumeStatus     = 'FullyEncrypted'
            ProtectionStatus = 'On'
            EncryptionMethod = 'XtsAes256'
            KeyProtector     = @(
                [PSCustomObject]@{ KeyProtectorId = '{11111111-2222-3333-4444-555555555555}'; KeyProtectorType = 'Tpm' },
                [PSCustomObject]@{ KeyProtectorId = '{66666666-7777-8888-9999-000000000000}'; KeyProtectorType = 'RecoveryPassword' }
            )
        }

        $res = & $script:BitLockerDetect -TestVolumeObject $mockVol -NoExit
        $res.Compliant | Should -BeTrue
        $res.ExitCode | Should -Be 0
    }

    It 'returns Non-Compliant (ExitCode 1) when RecoveryPassword protector is missing' {
        $mockVol = [PSCustomObject]@{
            MountPoint       = 'C:'
            VolumeStatus     = 'FullyEncrypted'
            ProtectionStatus = 'On'
            EncryptionMethod = 'XtsAes256'
            KeyProtector     = @(
                [PSCustomObject]@{ KeyProtectorId = '{11111111-2222-3333-4444-555555555555}'; KeyProtectorType = 'Tpm' }
            )
        }

        $res = & $script:BitLockerDetect -TestVolumeObject $mockVol -NoExit
        $res.Compliant | Should -BeFalse
        $res.ExitCode | Should -Be 1
        $res.Message | Should -Match 'missing a RecoveryPassword'
    }
}

Describe 'Detect-UnauthorizedLocalAdmins' {

    It 'returns Compliant (ExitCode 0) when only baseline approved principals are present' {
        $members = @('WKSTN-01\Administrator', 'WKSTN-01\LAPS_Admin', 'CORP\Domain Admins')
        $res = & $script:AdminDetect -TestMembers $members -NoExit
        $res.Compliant | Should -BeTrue
        $res.ExitCode | Should -Be 0
        @($res.UnauthorizedMembers).Count | Should -Be 0
    }

    It 'returns Non-Compliant (ExitCode 1) and flags rogue local or domain accounts' {
        $members = @('WKSTN-01\Administrator', 'CORP\jdoe_shadow_admin', 'WKSTN-01\TempVendor')
        $res = & $script:AdminDetect -TestMembers $members -NoExit
        $res.Compliant | Should -BeFalse
        $res.ExitCode | Should -Be 1
        $res.UnauthorizedMembers | Should -Be @('CORP\jdoe_shadow_admin', 'WKSTN-01\TempVendor')
    }
}

Describe 'Detect-SystemBackupAndPatchHealth' {

    It 'returns Compliant (ExitCode 0) when VSS writers are stable, services enabled, and disk space sufficient' {
        $mockHealth = [PSCustomObject]@{
            FailedVssWriters    = @()
            StoppedCoreServices = @()
            FreeDiskPercent     = 34.5
        }
        $res = & $script:HealthDetect -MockTelemetry $mockHealth -MinimumFreePercent 10 -NoExit
        $res.Compliant | Should -BeTrue
        $res.ExitCode | Should -Be 0
    }

    It 'returns Non-Compliant (ExitCode 1) when a VSS writer is in failed state or disk space is low' {
        $mockHealth = [PSCustomObject]@{
            FailedVssWriters    = @('SqlServerWriter')
            StoppedCoreServices = @('wuauserv(Disabled)')
            FreeDiskPercent     = 6.2
        }
        $res = & $script:HealthDetect -MockTelemetry $mockHealth -MinimumFreePercent 10 -NoExit
        $res.Compliant | Should -BeFalse
        $res.ExitCode | Should -Be 1
        @($res.Issues).Count | Should -Be 3
    }
}


Describe 'Invoke-EndpointSupportAndInventory' {
    BeforeAll {
        $script:SupportScript = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\SystemHealth-VSS-Patching\Invoke-EndpointSupportAndInventory.ps1'
    }

    It 'builds a valid Snipe-IT asset payload and passes healthy hosts in DemoMode' {
        $res = & $script:SupportScript -DemoMode
        $res.Healthy | Should -BeTrue
        $res.ExitCode | Should -Be 0
        $res.SnipeItAssetPayload.asset_tag | Should -Be 'AST-PF3X9821'
    }

    It 'flags excessive uptime, stopped WinRM, and hung services for L2/L3 remediation' {
        $mock = [PSCustomObject]@{
            ComputerName            = 'WKSTN-FIN-09'
            SerialNumber            = 'SN99281'
            Manufacturer            = 'Dell Inc.'
            Model                   = 'Latitude 5440'
            OsVersion               = 'Windows 11 Enterprise'
            MemoryGB                = 16
            UptimeDays              = 28.5
            WmiRepositoryConsistent = $false
            WinRmServiceRunning     = $false
            HungServices            = @('Spooler')
        }
        $res = & $script:SupportScript -MockAssetData $mock -MaxUptimeDays 14
        $res.Healthy | Should -BeFalse
        $res.ExitCode | Should -Be 1
        @($res.SupportFindings).Count | Should -Be 4
    }
}
