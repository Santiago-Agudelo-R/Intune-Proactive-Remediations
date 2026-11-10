#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:BitLockerDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\BitLocker-Escrow\Detect-BitLockerEscrow.ps1'
    $script:AdminDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\LocalAdmin-Hygiene\Detect-UnauthorizedLocalAdmins.ps1'
    $script:HealthDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\SystemHealth-VSS-Patching\Detect-SystemBackupAndPatchHealth.ps1'
}

Describe 'Detect-BitLockerEscrow' {

    It 'returns Compliant (ExitCode 0) when encrypted, protected, and the RecoveryPassword escrow is confirmed (Event 845)' {
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

        $events = @('BitLocker Drive Encryption recovery information for volume C: was backed up successfully to your Azure AD. Protector GUID: {66666666-7777-8888-9999-000000000000}')
        $res = & $script:BitLockerDetect -TestVolumeObject $mockVol -TestEscrowEventMessages $events -NoExit
        $res.Compliant | Should -BeTrue
        $res.ExitCode | Should -Be 0
    }

    It 'returns Non-Compliant (ExitCode 1) when the RecoveryPassword exists but was never escrowed' {
        $mockVol = [PSCustomObject]@{
            MountPoint       = 'C:'
            VolumeStatus     = 'FullyEncrypted'
            ProtectionStatus = 'On'
            EncryptionMethod = 'XtsAes256'
            KeyProtector     = @(
                [PSCustomObject]@{ KeyProtectorId = '{66666666-7777-8888-9999-000000000000}'; KeyProtectorType = 'RecoveryPassword' }
            )
        }

        $res = & $script:BitLockerDetect -TestVolumeObject $mockVol -TestEscrowEventMessages @() -NoExit
        $res.Compliant | Should -BeFalse
        $res.Message | Should -Match 'no escrow confirmation'
    }

    It 'reports initial encryption in progress as PENDING instead of failing' {
        $mockVol = [PSCustomObject]@{
            MountPoint           = 'C:'
            VolumeStatus         = 'EncryptionInProgress'
            ProtectionStatus     = 'Off'
            EncryptionPercentage = 42
            EncryptionMethod     = 'XtsAes256'
            KeyProtector         = @(
                [PSCustomObject]@{ KeyProtectorId = '{66666666-7777-8888-9999-000000000000}'; KeyProtectorType = 'RecoveryPassword' }
            )
        }

        $res = & $script:BitLockerDetect -TestVolumeObject $mockVol -TestEscrowEventMessages @() -NoExit
        $res.ExitCode | Should -Be 0
        $res.Message | Should -Match '^PENDING'
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

        $res = & $script:BitLockerDetect -TestVolumeObject $mockVol -TestEscrowEventMessages @() -NoExit
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

    It 'does not approve Entra ID users by default (AzureAD\* is not a wildcard allowlist)' {
        $members = @('WKSTN-01\Administrator', 'AzureAD\JohnDoe')
        $res = & $script:AdminDetect -TestMembers $members -NoExit
        $res.Compliant | Should -BeFalse
        $res.UnauthorizedMembers | Should -Be @('AzureAD\JohnDoe')
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


Describe 'Get-FailedVssWriter (language-independent vssadmin parsing)' {
    BeforeAll {
        # Load only the parser function from the detection script.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:HealthDetect, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-FailedVssWriter' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    It 'finds failed writers in Spanish (es-CO) output' {
        $output = @"
Nombre del escritor: 'System Writer'
   Id. del escritor: {e8132975-6f93-4464-a53e-1050253ae220}
   Estado: [1] Estable
   Ultimo error: Sin error

Nombre del escritor: 'SqlServerWriter'
   Id. del escritor: {a65faa63-5ea8-4ebc-9dbd-a0c4db26912a}
   Estado: [8] Con error
   Ultimo error: Error no reintentable
"@
        Get-FailedVssWriter -VssAdminOutput $output | Should -Be @('SqlServerWriter')
    }

    It 'returns nothing when every English writer is Stable' {
        $output = @"
Writer name: 'System Writer'
   State: [1] Stable
   Last error: No error

Writer name: 'WMI Writer'
   State: [1] Stable
   Last error: No error
"@
        @(Get-FailedVssWriter -VssAdminOutput $output).Count | Should -Be 0
    }
}

Describe 'Invoke-EndpointSupportAndInventory' {
    BeforeAll {
        $script:SupportScript = Join-Path -Path $PSScriptRoot -ChildPath '..\tools\Invoke-EndpointSupportAndInventory.ps1'
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
            WmiServiceRunning       = $false
            WinRmServiceRunning     = $false
            HungServices            = @('Spooler')
        }
        $res = & $script:SupportScript -MockAssetData $mock -MaxUptimeDays 14
        $res.Healthy | Should -BeFalse
        $res.ExitCode | Should -Be 1
        @($res.SupportFindings).Count | Should -Be 4
    }
}
