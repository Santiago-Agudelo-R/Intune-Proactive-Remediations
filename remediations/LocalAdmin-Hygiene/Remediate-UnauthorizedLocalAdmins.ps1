<#
.SYNOPSIS
    Intune Proactive Remediation: Removes unauthorized members from the local Administrators group.

.DESCRIPTION
    Enumerates the built-in Administrators group (SID S-1-5-32-544) and removes any principal
    that does not match the approved enterprise baseline allowlist. Never removes the built-in
    RID-500 Administrator account.
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
    [switch]$WhatIfMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    $members = @(Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop)
    $removed = [System.Collections.Generic.List[string]]::new()

    foreach ($m in $members) {
        if ($m.SID.Value -match '-500$') {
            continue
        }

        $isApproved = $false
        foreach ($pattern in $ApprovedPatterns) {
            if ($m.Name -match $pattern) {
                $isApproved = $true
                break
            }
        }

        if (-not $isApproved) {
            if (-not $WhatIfMode) {
                Remove-LocalGroupMember -Group $adminGroup -Member $m.Name -ErrorAction Stop
            }
            $removed.Add($m.Name)
        }
    }

    Write-Output "REMEDIATED: Removed $($removed.Count) unauthorized principal(s) from local Administrators: $($removed -join '; ')"
    exit 0
}
catch {
    Write-Output "REMEDIATION FAILED: $($_.Exception.Message)"
    exit 1
}
