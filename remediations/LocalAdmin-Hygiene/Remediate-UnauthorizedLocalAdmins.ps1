<#
.SYNOPSIS
    Intune Proactive Remediation: Reports or removes unauthorized members of the local Administrators group.

.DESCRIPTION
    Enumerates the built-in Administrators group (SID S-1-5-32-544) and finds every principal that
    does not match the approved allowlist. Never touches the built-in RID-500 Administrator account.

    SAFE BY DEFAULT: the script runs in report-only mode and removes nothing until you set
    $Enforce to $true. Intune Remediations cannot pass parameters, so to enforce you change the
    default value below after validating the report-only output on a pilot group.

    Keep $ApprovedPatterns identical to Detect-UnauthorizedLocalAdmins.ps1. On Entra ID joined
    devices, add your tenant's Global Administrator and Device Local Administrator role SIDs first,
    or enforcement will remove them.

.PARAMETER ApprovedPatterns
    Regex patterns matching authorized administrator account names or SIDs.

.PARAMETER Enforce
    $false (default) = report only. $true = remove unauthorized members.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$ApprovedPatterns = @(
        '(?i)\\Administrator$',
        '(?i)\\LAPS_Admin$',
        '(?i)\\Domain Admins$',
        '(?i)\\SecOps_Endpoint_Admins$'
        # Entra ID joined devices: add the same role SIDs you added to the detection script.
    ),

    [Parameter(Mandatory = $false)]
    [bool]$Enforce = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LocalAdminMember {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param ()

    try {
        return , @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{ Name = [string]$_.Name; Sid = [string]$_.SID.Value }
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

try {
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    $members = Get-LocalAdminMember
    $targets = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($m in $members) {
        if ($m.Sid -and $m.Sid -match '-500$') {
            continue
        }

        $isApproved = $false
        foreach ($pattern in $ApprovedPatterns) {
            if ($m.Name -match $pattern -or ($m.Sid -and $m.Sid -match $pattern)) {
                $isApproved = $true
                break
            }
        }

        if (-not $isApproved) {
            $targets.Add($m)
        }
    }

    if ($targets.Count -eq 0) {
        Write-Output "COMPLIANT: No unauthorized local administrators found."
        exit 0
    }

    $names = ($targets | ForEach-Object { $_.Name }) -join '; '

    if (-not $Enforce) {
        Write-Output "REPORT-ONLY: $($targets.Count) unauthorized principal(s) found, nothing removed (Enforce = false): $names"
        exit 0
    }

    $removed = [System.Collections.Generic.List[string]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $targets) {
        $member = if ($t.Sid) { $t.Sid } else { $t.Name }
        try {
            Remove-LocalGroupMember -Group $adminGroup -Member $member -ErrorAction Stop
            $removed.Add($t.Name)
        }
        catch {
            $failed.Add("$($t.Name) ($($_.Exception.Message))")
        }
    }

    if ($failed.Count -gt 0) {
        Write-Output "PARTIAL: Removed $($removed.Count), failed $($failed.Count): $($failed -join '; ')"
        exit 1
    }

    Write-Output "REMEDIATED: Removed $($removed.Count) unauthorized principal(s): $($removed -join '; ')"
    exit 0
}
catch {
    Write-Output "REMEDIATION FAILED: $($_.Exception.Message)"
    exit 1
}
