#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:BitLockerDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\BitLocker-Escrow\Detect-BitLockerEscrow.ps1'
    $script:AdminDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\LocalAdmin-Hygiene\Detect-UnauthorizedLocalAdmins.ps1'
    $script:AdminRemediate = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\LocalAdmin-Hygiene\Remediate-UnauthorizedLocalAdmins.ps1'
    $script:HealthDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\SystemHealth-VSS-Patching\Detect-SystemBackupAndPatchHealth.ps1'
    $script:HealthRemediate = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\SystemHealth-VSS-Patching\Remediate-SystemBackupAndPatchHealth.ps1'
    $script:DefenderDetect = Join-Path -Path $PSScriptRoot -ChildPath '..\remediations\Defender-SensorHealth\Detect-DefenderSensorHealth.ps1'
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

Describe 'LocalAdmin-Hygiene (Detect & Remediate Contract, SID & Localization)' {

    It 'returns Compliant (ExitCode 0) when only baseline approved principals are present' {
        $members = @('WKSTN-01\Administrator', 'WKSTN-01\LAPS_Admin', 'CORP\Domain Admins')
        $res = & $script:AdminDetect -TestMembers $members -LocalHostName 'WKSTN-01' -NoExit
        $res.Compliant | Should -BeTrue
        $res.ExitCode | Should -Be 0
        @($res.UnauthorizedMembers).Count | Should -Be 0
    }

    It 'approves Spanish Windows built-in Administrador (RID -500) and Admins. del dominio (RID -512) by SID' {
        $esMembers = @(
            [PSCustomObject]@{ Name = 'EQUIPO-01\Administrador'; Sid = 'S-1-5-21-1000-2000-3000-500' },
            [PSCustomObject]@{ Name = 'EMPRESA\Admins. del dominio'; Sid = 'S-1-5-21-9000-8000-7000-512' },
            [PSCustomObject]@{ Name = 'EQUIPO-01\LAPS_Admin'; Sid = 'S-1-5-21-1000-2000-3000-1005' }
        )
        $detectRes = & $script:AdminDetect -TestMembers $esMembers -LocalHostName 'EQUIPO-01' -NoExit
        $remRes = & $script:AdminRemediate -TestMembers $esMembers -LocalHostName 'EQUIPO-01' -NoExit

        $detectRes.Compliant | Should -BeTrue
        $remRes.Compliant | Should -BeTrue
    }

    It 'honors Entra ID role SIDs identically in both Detect and Remediate (preventing infinite remediation loops)' {
        $roleSid = '^S-1-12-1-1111111111-2222222222-3333333333-4444444444$'
        $approvedSids = @(
            '^S-1-5-21-\d+-\d+-\d+-500$',
            $roleSid
        )
        $members = @(
            [PSCustomObject]@{ Name = 'WKSTN-01\Administrator'; Sid = 'S-1-5-21-100-200-300-500' },
            [PSCustomObject]@{ Name = 'AzureAD\DeviceLocalAdminRole'; Sid = 'S-1-12-1-1111111111-2222222222-3333333333-4444444444' }
        )

        $detectRes = & $script:AdminDetect -TestMembers $members -ApprovedSids $approvedSids -LocalHostName 'WKSTN-01' -NoExit
        $remRes = & $script:AdminRemediate -TestMembers $members -ApprovedSids $approvedSids -LocalHostName 'WKSTN-01' -NoExit

        $detectRes.Compliant | Should -BeTrue
        $remRes.Compliant | Should -BeTrue
    }

    It 'rejects spoofed LAPS_Admin or Administrator accounts from foreign domains or non-500 RIDs' {
        $members = @(
            [PSCustomObject]@{ Name = 'WKSTN-01\Administrator'; Sid = 'S-1-5-21-100-200-300-500' },
            [PSCustomObject]@{ Name = 'ROGUEDOM\LAPS_Admin'; Sid = 'S-1-5-21-999-888-777-1104' },
            [PSCustomObject]@{ Name = 'ROGUEDOM\Administrator'; Sid = 'S-1-5-21-999-888-777-1105' }
        )

        $res = & $script:AdminDetect -TestMembers $members -LocalHostName 'WKSTN-01' -NoExit
        $res.Compliant | Should -BeFalse
        $res.ExitCode | Should -Be 1
        $res.UnauthorizedMembers | Should -Be @('ROGUEDOM\LAPS_Admin', 'ROGUEDOM\Administrator')
    }

    It 'does not approve regular Entra ID users by default (AzureAD\* is not a wildcard allowlist)' {
        $members = @(
            [PSCustomObject]@{ Name = 'WKSTN-01\Administrator'; Sid = 'S-1-5-21-100-200-300-500' },
            [PSCustomObject]@{ Name = 'AzureAD\JohnDoe'; Sid = 'S-1-12-1-999999999-111111111-222222222-333333333' }
        )
        $res = & $script:AdminDetect -TestMembers $members -LocalHostName 'WKSTN-01' -NoExit
        $res.Compliant | Should -BeFalse
        $res.UnauthorizedMembers | Should -Be @('AzureAD\JohnDoe')
    }
}

Describe 'SystemHealth-VSS-Patching (Detect & Evidence-Safe Remediate)' {

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

    It 'does not restart VSS when VSS writers are healthy, and does not purge Temp by default or under IR hold' {
        $lowDiskOnly = [PSCustomObject]@{
            FailedVssWriters = @()
            FreeDiskPercent  = 6.0
            IrHoldPresent    = $false
        }
        $rem1 = & $script:HealthRemediate -MockTelemetry $lowDiskOnly -MinimumFreePercent 10 -NoExit
        $rem1.Actions | Should -Not -Contain 'RestartedVssForFailedWriters'
        $rem1.Message | Should -Match 'TempPurgeDisabledByDefault'

        $irHoldActive = [PSCustomObject]@{
            FailedVssWriters = @('SqlServerWriter')
            FreeDiskPercent  = 5.0
            IrHoldPresent    = $true
        }
        $rem2 = & $script:HealthRemediate -MockTelemetry $irHoldActive -PurgeTempOnLowDisk $true -MinimumFreePercent 10 -NoExit
        $rem2.Message | Should -Match 'RestartedVssForFailedWriters\(SqlServerWriter\)'
        $rem2.Actions | Should -Contain 'SkippedTempPurge(IR_HOLD_Active)'
    }
}

Describe 'Get-FailedVssWriter (language-independent vssadmin parsing)' {
    BeforeAll {
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

Describe 'Detect-DefenderSensorHealth' {
    It 'returns Compliant (ExitCode 0) when WinDefend and Sense are running, protection enabled, and signatures fresh' {
        $mock = [PSCustomObject]@{
            WinDefendServiceState     = 'Running'
            MdeOnboarded              = $true
            SenseServiceState         = 'Running'
            RealTimeProtectionEnabled = $true
            BehaviorMonitorEnabled    = $true
            IsTamperProtected         = $true
            SignatureAgeDays          = 1
        }
        $res = & $script:DefenderDetect -MockTelemetry $mock -MaxSignatureAgeDays 7 -NoExit
        $res.Compliant | Should -BeTrue
        $res.ExitCode | Should -Be 0
    }

    It 'returns Non-Compliant (ExitCode 1) when Sense is stopped, RealTimeProtection is disabled, or signatures are stale' {
        $mock = [PSCustomObject]@{
            WinDefendServiceState     = 'Running'
            MdeOnboarded              = $true
            SenseServiceState         = 'Stopped'
            RealTimeProtectionEnabled = $false
            BehaviorMonitorEnabled    = $true
            IsTamperProtected         = $false
            SignatureAgeDays          = 12
        }
        $res = & $script:DefenderDetect -MockTelemetry $mock -MaxSignatureAgeDays 7 -NoExit
        $res.Compliant | Should -BeFalse
        $res.ExitCode | Should -Be 1
        @($res.Issues).Count | Should -Be 4
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
