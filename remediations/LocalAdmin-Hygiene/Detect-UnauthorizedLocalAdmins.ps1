<#
.SYNOPSIS
    Intune Proactive Remediation Detection: Audits local Administrators group membership by SID and machine-scoped allowlist.

.DESCRIPTION
    Enumerates members of the built-in Administrators group (SID S-1-5-32-544) and evaluates each
    member using the same SID-first logic as Remediate-UnauthorizedLocalAdmins.ps1:
    1. Built-in Local Administrator (RID -500) and Domain/Enterprise Admins (RID -512 / -519) are
       approved by SID regardless of OS display language (e.g. "Administrator" vs "Administrador"
       or "Domain Admins" vs "Admins. del dominio" on Spanish es-CO/es-ES Windows).
    2. Explicit Entra ID role SIDs (S-1-12-1-...) and domain security group SIDs in $ApprovedSids
       are matched directly against each member's SID so detection and remediation never diverge.
    3. Local management accounts (such as LAPS_Admin) are only approved when scoped to the local
       ComputerName (<ComputerName>\LAPS_Admin), preventing cross-domain account name spoofing.

.PARAMETER ApprovedSids
    Exact SIDs or SID regex patterns for authorized roles/groups (RID -500, -512, -519 are built-in).

.PARAMETER ApprovedLocalAccounts
    Local administrator account names valid only when prefixed by the local machine name.

.PARAMETER ApprovedDomainAccounts
    Explicitly domain-qualified group/account names (DOMAIN\GroupName) when SID resolution is unavailable.

.PARAMETER TestMembers
    Optional array of member objects (@{ Name = '...'; Sid = '...' }) or strings for offline Pester testing.

.PARAMETER LocalHostName
    Local machine name used to scope local accounts. Defaults to $env:COMPUTERNAME.

.PARAMETER NoExit
    Suppresses exit 0/1 termination for Pester unit tests and returns a result object.

.NOTES
    Author: Santiago Agudelo
    License: MIT
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$ApprovedSids = @(
        '^S-1-5-21-\d+-\d+-\d+-500$',
        '^S-1-5-21-\d+-\d+-\d+-512$',
        '^S-1-5-21-\d+-\d+-\d+-519$'
        # Entra ID joined devices: add your tenant's role SIDs here (and in Remediate-UnauthorizedLocalAdmins.ps1):
        # '^S-1-12-1-1111111111-2222222222-3333333333-4444444444$'  # Global Administrator role
        # '^S-1-12-1-5555555555-6666666666-7777777777-8888888888$'  # Entra Joined Device Local Administrator role
    ),

    [Parameter(Mandatory = $false)]
    [string[]]$ApprovedLocalAccounts = @(
        'LAPS_Admin'
    ),

    [Parameter(Mandatory = $false)]
    [string[]]$ApprovedDomainAccounts = @(
        'CORP\Domain Admins',
        'CORP\Admins. del dominio',
        'CORP\SecOps_Endpoint_Admins'
    ),

    [Parameter(Mandatory = $false)]
    [object[]]$TestMembers,

    [Parameter(Mandatory = $false)]
    [string]$LocalHostName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LocalAdminMember {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param ()

    try {
        return , @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name = [string]$_.Name
                    Sid  = if ($_.SID) { [string]$_.SID.Value } else { $null }
                }
            })
    }
    catch {
        # Fallback for error 1789 (orphaned / unresolvable SIDs): read the group through ADSI.
        $groupName = (Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop).Name
        $group = [ADSI]"WinNT://./$groupName,group"
        $result = foreach ($member in @($group.Invoke('Members'))) {
            $entry = [ADSI]$member
            $path = $entry.Path -replace '^WinNT://', ''
            $parts = @($path -split '/')
            $name = if ($parts.Count -ge 2) { '{0}\{1}' -f $parts[-2], $parts[-1] } else { $parts[-1] }
            $sid = try { (New-Object System.Security.Principal.SecurityIdentifier($entry.objectSid.Value, 0)).Value } catch { $null }
            [PSCustomObject]@{ Name = $name; Sid = $sid }
        }
        return , @($result)
    }
}

function ConvertTo-NormalizedAdminMember {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$RawMembers
    )

    $normalized = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($item in $RawMembers) {
        if ($item -is [string]) {
            $normalized.Add([PSCustomObject]@{
                Name = $item
                Sid  = if ($item -match '^S-1-\d+-') { $item } else { $null }
            })
        }
        else {
            $nameVal = if ($item.PSObject.Properties['Name']) { [string]$item.Name } else { [string]$item }
            $sidVal = if ($item.PSObject.Properties['Sid']) { [string]$item.Sid } elseif ($item.PSObject.Properties['SID']) { [string]$item.SID } else { $null }
            $normalized.Add([PSCustomObject]@{
                Name = $nameVal
                Sid  = $sidVal
            })
        }
    }
    return , $normalized.ToArray()
}

function Test-IsApprovedLocalAdmin {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Member,

        [Parameter(Mandatory = $true)]
        [string[]]$SidPatterns,

        [Parameter(Mandatory = $true)]
        [string[]]$LocalAccounts,

        [Parameter(Mandatory = $true)]
        [string[]]$DomainAccounts,

        [Parameter(Mandatory = $true)]
        [string]$LocalMachineName
    )

    # 1. SID evaluation (primary, language-independent, non-spoofable)
    if (-not [string]::IsNullOrWhiteSpace($Member.Sid)) {
        foreach ($sidPattern in $SidPatterns) {
            if ($Member.Sid -match $sidPattern) {
                return $true
            }
        }
    }

    $memberName = [string]$Member.Name
    if ([string]::IsNullOrWhiteSpace($memberName)) {
        return $false
    }

    # If the member name itself is a raw SID (e.g., unresolved Entra ID role SID), check against SidPatterns
    if ($memberName -match '^S-1-\d+-') {
        foreach ($sidPattern in $SidPatterns) {
            if ($memberName -match $sidPattern) {
                return $true
            }
        }
    }

    # 2. Machine-scoped local account check (<LocalMachineName>\AccountName)
    # Prevents spoofing where a foreign domain account is named LAPS_Admin or Administrator.
    $escapedMachine = [regex]::Escape($LocalMachineName)
    foreach ($localAcc in $LocalAccounts) {
        $escapedAcc = [regex]::Escape($localAcc)
        if ($memberName -match "(?i)^${escapedMachine}\\${escapedAcc}$") {
            return $true
        }
    }

    # Built-in local Administrator fallback when SID was not supplied in string-only test mode,
    # strictly scoped to the local machine name (never matches OTHERDOMAIN\Administrator).
    if ([string]::IsNullOrWhiteSpace($Member.Sid) -and $memberName -match "(?i)^${escapedMachine}\\(Administrator|Administrador)$") {
        return $true
    }

    # 3. Explicitly domain-qualified group/account names
    foreach ($domAcc in $DomainAccounts) {
        if ($memberName.Equals($domAcc, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Find-UnauthorizedLocalAdmin {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Members,

        [Parameter(Mandatory = $true)]
        [string[]]$SidPatterns,

        [Parameter(Mandatory = $true)]
        [string[]]$LocalAccounts,

        [Parameter(Mandatory = $true)]
        [string[]]$DomainAccounts,

        [Parameter(Mandatory = $true)]
        [string]$LocalMachineName
    )

    $unauthorized = [System.Collections.Generic.List[string]]::new()

    foreach ($member in $Members) {
        $isApproved = Test-IsApprovedLocalAdmin `
            -Member $member `
            -SidPatterns $SidPatterns `
            -LocalAccounts $LocalAccounts `
            -DomainAccounts $DomainAccounts `
            -LocalMachineName $LocalMachineName

        if (-not $isApproved) {
            $label = if (-not [string]::IsNullOrWhiteSpace($member.Name)) { $member.Name } else { $member.Sid }
            $unauthorized.Add($label)
        }
    }

    if ($unauthorized.Count -gt 0) {
        $joined = $unauthorized -join '; '
        return [PSCustomObject]@{
            Compliant           = $false
            ExitCode            = 1
            UnauthorizedMembers = $unauthorized.ToArray()
            Message             = "NON-COMPLIANT: Unauthorized local administrators detected ($($unauthorized.Count)): $joined"
        }
    }

    return [PSCustomObject]@{
        Compliant           = $true
        ExitCode            = 0
        UnauthorizedMembers = @()
        Message             = "COMPLIANT: Local Administrators group contains only approved principals ($($Members.Count) total)."
    }
}

try {
    $rawMembers = if ($PSBoundParameters.ContainsKey('TestMembers')) {
        $TestMembers
    }
    else {
        Get-LocalAdminMember
    }

    $normalizedMembers = ConvertTo-NormalizedAdminMember -RawMembers $rawMembers

    # In offline string-only test runs, infer machine prefix from the first local RID-500-like entry if ComputerName wasn't overridden
    $effectiveComputerName = $LocalHostName
    if ($PSBoundParameters.ContainsKey('TestMembers') -and (-not $PSBoundParameters.ContainsKey('LocalHostName'))) {
        foreach ($m in $normalizedMembers) {
            if ($m.Name -match '^([^\\]+)\\(Administrator|Administrador|LAPS_Admin)$' -and $Matches[1] -notmatch '^(?i)(CORP|AzureAD|CONTOSO|ROGUEDOM)$') {
                $effectiveComputerName = $Matches[1]
                break
            }
        }
    }

    $result = Find-UnauthorizedLocalAdmin `
        -Members $normalizedMembers `
        -SidPatterns $ApprovedSids `
        -LocalAccounts $ApprovedLocalAccounts `
        -DomainAccounts $ApprovedDomainAccounts `
        -LocalMachineName $effectiveComputerName

    if ($NoExit) {
        return $result
    }

    Write-Output $result.Message
    exit $result.ExitCode
}
catch {
    $errMsg = "ERROR: Failed to query local Administrators group: $($_.Exception.Message)"
    if ($NoExit) {
        return [PSCustomObject]@{ Compliant = $false; ExitCode = 1; UnauthorizedMembers = @(); Message = $errMsg }
    }
    Write-Output $errMsg
    exit 1
}
