<#
.SYNOPSIS
    Intune Proactive Remediation Detection: Audits local Administrators group membership against an approved baseline.

.DESCRIPTION
    Enumerates members of the built-in Administrators group (SID S-1-5-32-544) and compares them
    against a strict baseline allowlist (built-in Administrator, LAPS admin, Domain Admins, Entra Global/Device Admins).
    Returns exit 0 if only approved principals are present, or exit 1 if unauthorized members are found.

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
        '(?i)\\SecOps_Endpoint_Admins$',
        '^AzureAD\\'
    ),

    [Parameter(Mandatory = $false)]
    [string[]]$TestMembers,

    [Parameter(Mandatory = $false)]
    [switch]$NoExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
        @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Select-Object -ExpandProperty Name)
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
