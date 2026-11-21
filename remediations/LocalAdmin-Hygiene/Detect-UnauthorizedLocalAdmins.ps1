<#
.SYNOPSIS
    Intune Remediations detection: flags members of the local Administrators group that are not approved.

.DESCRIPTION
    Enumerates the built-in Administrators group (S-1-5-32-544) and evaluates every member with
    Test-IsApprovedLocalAdmin, the same function Remediate-UnauthorizedLocalAdmins.ps1 uses, so the
    pair cannot disagree and loop.

    Approval is SID-based and therefore language-independent ("Administrator" / "Administrador",
    "Domain Admins" / "Admins. del dominio"): the machine's own RID-500 account, your domain's -512/-519
    groups (when ApprovedDomainSid is set) and any SID listed in ApprovedSids.

    Exit 0 = only approved members. Exit 1 = unapproved members found, or the check could not run.

    Limitation: this is a configuration-hygiene control. An attacker who already holds local admin
    rights can tamper with any script running on the device; treat results as drift detection, not
    as tamper-proof evidence.

.PARAMETER ApprovedDomainSid
    SID of your Active Directory domain (S-1-5-21-x-y-z). Approves that domain's Domain Admins (-512)
    and Enterprise Admins (-519). Leave empty on Entra ID-only devices.

.PARAMETER ApprovedSids
    Exact SIDs, or regex patterns starting with '^', for Entra ID role SIDs or other approved groups.

.PARAMETER ApprovedDomainAccounts
    DOMAIN\Name entries approved by name. When ApprovedDomainSid is set, the SID must also match it.

.PARAMETER ApprovedLocalAccounts
    Additional local account names approved only when their SID belongs to this machine. Empty by
    default because a local administrator can create a local account with any name.

.PARAMETER LocalMachineSid
    Machine SID. Resolved automatically when empty; set explicitly only for offline tests.

.PARAMETER TestMembers
    Member objects (@{ Name = '...'; Sid = '...' }) for offline Pester tests.

.PARAMETER NoExit
    Returns a result object instead of calling exit, for Pester tests.

.NOTES
    Author: Santiago Agudelo
    License: MIT
#>

[CmdletBinding()]
param (
    # Your AD domain SID (S-1-5-21-x-y-z). When set, that domain's Domain Admins (-512) and
    # Enterprise Admins (-519) are approved. Other domains' -512/-519 groups are never approved.
    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$ApprovedDomainSid = '',

    # Exact SIDs, or regex patterns that start with '^'. Entra ID joined devices: add your tenant's
    # Global Administrator and "Microsoft Entra Joined Device Local Administrator" role SIDs, e.g.
    # 'S-1-12-1-1111111111-2222222222-3333333333-4444444444'
    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$ApprovedSids = @(),

    # DOMAIN\Name entries, e.g. 'CORP\SecOps_Endpoint_Admins'. If $ApprovedDomainSid is set,
    # the member's SID must also belong to that domain.
    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$ApprovedDomainAccounts = @(),

    # Extra local accounts approved by name (for example a custom LAPS account). Empty by default on
    # purpose: anyone who already has local admin rights can create a local account with any name.
    # Prefer Windows LAPS managing the built-in RID-500 account, which is approved by SID.
    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$ApprovedLocalAccounts = @(),

    # Resolved automatically from the local accounts when empty. Exposed for offline tests.
    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$LocalMachineSid = '',

    [Parameter(Mandatory = $false)]
    [object[]]$TestMembers,

    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Shared approval logic (keep identical to Remediate-UnauthorizedLocalAdmins.ps1) ---
function Get-LocalMachineSid {
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    # Every local account SID is <machine SID>-<RID>; the built-in Administrator always exists (RID 500).
    try {
        $account = Get-LocalUser -ErrorAction Stop | Select-Object -First 1
        return [string]$account.SID.AccountDomainSid.Value
    }
    catch {
        $account = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount = True' -ErrorAction Stop | Select-Object -First 1
        return ([string]$account.SID -replace '-\d+$', '')
    }
}

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

function ConvertTo-AdminMember {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObject
    )

    $members = foreach ($item in $InputObject) {
        $name = if ($item -is [string]) { $item } elseif ($item.PSObject.Properties['Name']) { [string]$item.Name } else { $null }
        $sid = if ($item -isnot [string] -and $item.PSObject.Properties['Sid']) { [string]$item.Sid } else { $null }
        # Unresolvable members (common for Entra ID role SIDs) are reported by their raw SID as the name.
        if ([string]::IsNullOrWhiteSpace($sid) -and $name -match '^S-1-\d+(-\d+)+$') {
            $sid = $name
        }
        [PSCustomObject]@{ Name = $name; Sid = $sid }
    }
    return , @($members)
}

function Test-IsApprovedLocalAdmin {
    <#
        Single source of truth for both Detect and Remediate. Approval is by SID first:
          - <this machine SID>-500  built-in Administrator, in any display language
          - <ApprovedDomainSid>-512/-519  Domain/Enterprise Admins of YOUR domain only
          - $ApprovedSids  exact SIDs (or '^'-anchored regex) such as Entra ID role SIDs
        Name-based approval is limited to DOMAIN\Name entries (optionally SID-checked) and to
        explicitly listed local accounts whose SID belongs to this machine.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Member,

        [Parameter(Mandatory = $true)]
        [string]$MachineSid,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DomainSid = '',

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$Sids = @(),

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$DomainAccounts = @(),

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$LocalAccounts = @()
    )

    $sid = [string]$Member.Sid
    $name = [string]$Member.Name

    if (-not [string]::IsNullOrWhiteSpace($sid)) {
        if ($sid -eq "$MachineSid-500") { return $true }

        if (-not [string]::IsNullOrWhiteSpace($DomainSid) -and ($sid -eq "$DomainSid-512" -or $sid -eq "$DomainSid-519")) {
            return $true
        }

        foreach ($entry in $Sids) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            # Plain entries are compared exactly so 'S-1-12-1-1-2' can never match 'S-1-12-1-1-23'.
            $isMatch = if ($entry.StartsWith('^')) { $sid -match $entry } else { $sid -eq $entry }
            if ($isMatch) { return $true }
        }
    }

    $parts = @($name -split '\\', 2)
    if ($parts.Count -ne 2) { return $false }

    $isLocalAccount = (-not [string]::IsNullOrWhiteSpace($sid)) -and $sid.StartsWith("$MachineSid-")
    if ($isLocalAccount) {
        return ($parts[1] -in $LocalAccounts)
    }

    if ($name -in $DomainAccounts) {
        if ([string]::IsNullOrWhiteSpace($DomainSid)) { return $true }
        return ((-not [string]::IsNullOrWhiteSpace($sid)) -and $sid.StartsWith("$DomainSid-"))
    }

    return $false
}

function Find-UnauthorizedLocalAdmin {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Members,

        [Parameter(Mandatory = $true)]
        [hashtable]$Policy
    )

    $unauthorized = foreach ($m in $Members) {
        if (-not (Test-IsApprovedLocalAdmin -Member $m @Policy)) { $m }
    }
    return , @($unauthorized)
}

function Get-MemberLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory = $true)][PSCustomObject]$Member)

    if (-not [string]::IsNullOrWhiteSpace($Member.Name)) { return $Member.Name }
    return [string]$Member.Sid
}
# --- End of shared approval logic ---

try {
    $members = if ($PSBoundParameters.ContainsKey('TestMembers')) {
        ConvertTo-AdminMember -InputObject $TestMembers
    }
    else {
        ConvertTo-AdminMember -InputObject (Get-LocalAdminMember)
    }

    $machineSid = if ([string]::IsNullOrWhiteSpace($LocalMachineSid)) { Get-LocalMachineSid } else { $LocalMachineSid }
    if ($machineSid -notmatch '^S-1-5-21-\d+-\d+-\d+$') {
        throw "Could not resolve the local machine SID (got '$machineSid'); refusing to evaluate membership."
    }

    $policy = @{
        MachineSid     = $machineSid
        DomainSid      = $ApprovedDomainSid
        Sids           = $ApprovedSids
        DomainAccounts = $ApprovedDomainAccounts
        LocalAccounts  = $ApprovedLocalAccounts
    }
    $unauthorized = Find-UnauthorizedLocalAdmin -Members $members -Policy $policy

    $result = if ($unauthorized.Count -gt 0) {
        $labels = @($unauthorized | ForEach-Object { Get-MemberLabel -Member $_ })
        [PSCustomObject]@{
            Compliant           = $false
            ExitCode            = 1
            UnauthorizedMembers = $labels
            Message             = "NON-COMPLIANT: $($labels.Count) unapproved local administrator(s): $($labels -join '; ')"
        }
    }
    else {
        [PSCustomObject]@{
            Compliant           = $true
            ExitCode            = 0
            UnauthorizedMembers = @()
            Message             = "COMPLIANT: All $($members.Count) local Administrators member(s) are approved."
        }
    }

    if ($NoExit) { return $result }
    Write-Output $result.Message
    exit $result.ExitCode
}
catch {
    $errMsg = "ERROR: Local Administrators check failed: $($_.Exception.Message)"
    if ($NoExit) {
        return [PSCustomObject]@{ Compliant = $false; ExitCode = 1; UnauthorizedMembers = @(); Message = $errMsg }
    }
    Write-Output $errMsg
    exit 1
}
