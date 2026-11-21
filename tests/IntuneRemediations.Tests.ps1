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

Describe 'LocalAdmin-Hygiene (shared SID-based approval for Detect and Remediate)' {

    BeforeAll {
        $script:MachineSid = 'S-1-5-21-1000-2000-3000'
        $script:DomainSid = 'S-1-5-21-9000-8000-7000'

        function Invoke-LocalAdminPair {
            param ([object[]]$Members, [hashtable]$Options = @{})
            $common = @{ TestMembers = $Members; LocalMachineSid = $script:MachineSid; NoExit = $true } + $Options
            [PSCustomObject]@{
                Detect    = & $script:AdminDetect @common
                Remediate = & $script:AdminRemediate @common
            }
        }
    }

    It 'approves the Spanish built-in Administrador and your own Admins. del dominio by SID' {
        $members = @(
            [PSCustomObject]@{ Name = 'EQUIPO-01\Administrador'; Sid = "$script:MachineSid-500" },
            [PSCustomObject]@{ Name = 'EMPRESA\Admins. del dominio'; Sid = "$script:DomainSid-512" }
        )
        $r = Invoke-LocalAdminPair -Members $members -Options @{ ApprovedDomainSid = $script:DomainSid }
        $r.Detect.Compliant | Should -BeTrue
        $r.Detect.ExitCode | Should -Be 0
        $r.Remediate.Compliant | Should -BeTrue
    }

    It 'rejects Domain Admins and RID-500 accounts from any other domain' {
        $members = @(
            [PSCustomObject]@{ Name = 'EQUIPO-01\Administrator'; Sid = "$script:MachineSid-500" },
            [PSCustomObject]@{ Name = 'OTHER\Domain Admins'; Sid = 'S-1-5-21-5-6-7-512' },
            [PSCustomObject]@{ Name = 'OTHER\Administrator'; Sid = 'S-1-5-21-5-6-7-500' }
        )
        $r = Invoke-LocalAdminPair -Members $members -Options @{ ApprovedDomainSid = $script:DomainSid }
        $r.Detect.UnauthorizedMembers | Should -Be @('OTHER\Domain Admins', 'OTHER\Administrator')
        @($r.Remediate.Targets).Count | Should -Be 2
    }

    It 'does not approve a local account just because of its name (attacker-created LAPS_Admin)' {
        $members = @([PSCustomObject]@{ Name = 'EQUIPO-01\LAPS_Admin'; Sid = "$script:MachineSid-1005" })
        $r = Invoke-LocalAdminPair -Members $members
        $r.Detect.Compliant | Should -BeFalse
        $r.Remediate.Compliant | Should -BeFalse
    }

    It 'approves an explicitly listed local account only when its SID belongs to this machine' {
        $local = @([PSCustomObject]@{ Name = 'EQUIPO-01\LAPS_Admin'; Sid = "$script:MachineSid-1005" })
        $foreign = @([PSCustomObject]@{ Name = 'OTHER\LAPS_Admin'; Sid = 'S-1-5-21-5-6-7-1005' })
        (Invoke-LocalAdminPair -Members $local -Options @{ ApprovedLocalAccounts = @('LAPS_Admin') }).Detect.Compliant | Should -BeTrue
        (Invoke-LocalAdminPair -Members $foreign -Options @{ ApprovedLocalAccounts = @('LAPS_Admin') }).Detect.Compliant | Should -BeFalse
    }

    It 'honors Entra ID role SIDs identically in Detect and Remediate, including unresolved SIDs' {
        $roleSid = 'S-1-12-1-1111111111-2222222222-3333333333-4444444444'
        $r = Invoke-LocalAdminPair -Members @($roleSid) -Options @{ ApprovedSids = @($roleSid) }
        $r.Detect.Compliant | Should -BeTrue
        $r.Remediate.Compliant | Should -BeTrue
    }

    It 'compares plain SID entries exactly, never as a prefix' {
        $r = Invoke-LocalAdminPair -Members @('S-1-12-1-1111-2222-3333-44445') -Options @{ ApprovedSids = @('S-1-12-1-1111-2222-3333-4444') }
        $r.Detect.Compliant | Should -BeFalse
    }

    It 'requires the domain SID to match for name-approved domain groups' {
        $options = @{ ApprovedDomainSid = $script:DomainSid; ApprovedDomainAccounts = @('CORP\SecOps') }
        $good = @([PSCustomObject]@{ Name = 'CORP\SecOps'; Sid = "$script:DomainSid-1200" })
        $bad = @([PSCustomObject]@{ Name = 'CORP\SecOps'; Sid = 'S-1-5-21-5-6-7-1200' })
        (Invoke-LocalAdminPair -Members $good -Options $options).Detect.Compliant | Should -BeTrue
        (Invoke-LocalAdminPair -Members $bad -Options $options).Detect.Compliant | Should -BeFalse
    }

    It 'does not approve regular Entra ID users' {
        $members = @([PSCustomObject]@{ Name = 'AzureAD\JohnDoe'; Sid = 'S-1-12-1-999999999-111111111-222222222-333333333' })
        (Invoke-LocalAdminPair -Members $members).Detect.UnauthorizedMembers | Should -Be @('AzureAD\JohnDoe')
    }

    It 'fails closed when the machine SID cannot be resolved' {
        $res = & $script:AdminDetect -TestMembers @('X\y') -LocalMachineSid 'not-a-sid' -NoExit
        $res.Compliant | Should -BeFalse
        $res.ExitCode | Should -Be 1
        $res.Message | Should -Match 'refusing to evaluate'
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

Describe 'Detect-DefenderSensorHealth (passive mode and unknown Tamper Protection)' {
    It 'does not flag real-time or behavior monitoring when Defender runs in Passive mode' {
        $mock = [PSCustomObject]@{
            WinDefendServiceState     = 'Running'
            MdeOnboarded              = $true
            SenseServiceState         = 'Running'
            RealTimeProtectionEnabled = $false
            BehaviorMonitorEnabled    = $false
            IsTamperProtected         = $false
            AMRunningMode             = 'Passive Mode'
            SignatureAgeDays          = 1
        }
        $res = & $script:DefenderDetect -MockTelemetry $mock -NoExit
        $res.Compliant | Should -BeTrue
    }

    It 'reports Tamper Protection as unknown instead of assuming it is on' {
        $mock = [PSCustomObject]@{
            WinDefendServiceState     = 'Running'
            MdeOnboarded              = $false
            SenseServiceState         = 'Stopped'
            RealTimeProtectionEnabled = $true
            BehaviorMonitorEnabled    = $true
            IsTamperProtected         = $null
            SignatureAgeDays          = 1
        }
        $res = & $script:DefenderDetect -MockTelemetry $mock -NoExit
        $res.Compliant | Should -BeFalse
        $res.Issues | Should -Be @('TamperProtectionUnknown')
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
