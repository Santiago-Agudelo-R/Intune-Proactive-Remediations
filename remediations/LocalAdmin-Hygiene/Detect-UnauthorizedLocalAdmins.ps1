<#
.SYNOPSIS
    Intune Proactive Remediation Detection: Audits local Administrators group membership against an approved baseline.

.DESCRIPTION
    Enumerates members of the built-in Administrators group (SID S-1-5-32-544) and compares them
    against an allowlist of approved principals (built-in Administrator, LAPS account, Domain Admins,
    and any Entra ID role SIDs you add). Returns exit 0 if only approved principals are present,
    or exit 1 if unauthorized members are found.

    Entra ID joined devices: the Global Administrator and "Microsoft Entra Joined Device Local
    Administrator" roles are added to the group as SIDs that start with S-1-12-1-. Every Entra ID
    user also has an S-1-12-1- SID, so this script never approves AzureAD\* or S-1-12-1-* as a whole.
    Add your tenant's two role SIDs to $ApprovedPatterns instead (see README).

    Get-LocalGroupMember fails (error 1789) when the group holds orphaned or unresolvable SIDs,
    which is common on Entra ID joined devices. In that case the script falls back to ADSI.

.PARAMETER ApprovedPatterns
    Regex patterns matching authorized administrator account names or SIDs.

.PARAMETER TestMembers
    Optional array of member names for offline Pester unit testing.

.PARAMETER NoExit
    Suppresses exit 0/1 termination for Pester unit tests and returns a result object.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$ApprovedPatterns = @(
        '(?i)\\Administrator$',
        '(?i)\\LAPS_Admin$',
        '(?i)\\Domain Admins$',
        '(?i)\\SecOps_Endpoint_Admins$'
        # Entra ID joined devices: add your tenant's role SIDs here, for example:
        # '^S-1-12-1-1111111111-2222222222-3333333333-4444444444$'  # Global Administrator role
        # '^S-1-12-1-5555555555-6666666666-7777777777-8888888888$'  # Entra Joined Device Local Administrator role
    ),

    [Parameter(Mandatory = $false)]
    [string[]]$TestMembers,

    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LocalAdminMemberName {
    [CmdletBinding()]
    [OutputType([string[]])]
    param ()

    try {
        return , @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name })
    }
    catch {
        # Fallback for error 1789 (orphaned / unresolvable SIDs): read the group through ADSI.
        $groupName = (Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop).Name
        $group = [ADSI]"WinNT://./$groupName,group"
        $names = foreach ($member in @($group.Invoke('Members'))) {
            $path = ([ADSI]$member).Path -replace '^WinNT://', ''
            $parts = @($path -split '/')
            if ($parts.Count -ge 2) { '{0}\{1}' -f $parts[-2], $parts[-1] } else { $parts[-1] }
        }
        return , @($names)
    }
}

function Find-UnauthorizedLocalAdmin {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Members,

        [Parameter(Mandatory = $true)]
        [string[]]$AllowlistRegex
    )

    $unauthorized = [System.Collections.Generic.List[string]]::new()

    foreach ($member in $Members) {
        $isApproved = $false
        foreach ($pattern in $AllowlistRegex) {
            if ($member -match $pattern) {
                $isApproved = $true
                break
            }
        }

        if (-not $isApproved) {
            $unauthorized.Add($member)
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
    $currentMembers = if ($PSBoundParameters.ContainsKey('TestMembers')) {
        $TestMembers
    }
    else {
        Get-LocalAdminMemberName
    }

    $result = Find-UnauthorizedLocalAdmin -Members $currentMembers -AllowlistRegex $ApprovedPatterns
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
