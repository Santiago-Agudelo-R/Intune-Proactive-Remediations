<#
.SYNOPSIS
    Intune Proactive Remediation: Reports or removes unauthorized members of the local Administrators group.

.DESCRIPTION
    Enumerates the built-in Administrators group (SID S-1-5-32-544) and uses the exact same
    SID-first evaluation contract as Detect-UnauthorizedLocalAdmins.ps1:
    1. Built-in Local Administrator (RID -500) and Domain/Enterprise Admins (RID -512 / -519)
       are protected by SID across all Windows display languages (English, Spanish es-CO/es-ES, etc.).
    2. Explicit Entra ID role SIDs in $ApprovedSids are honored identically by both Detection and Remediation.
    3. Local accounts in $ApprovedLocalAccounts are strictly scoped to <ComputerName>\<AccountName>.

    SAFE BY DEFAULT: Runs in report-only mode ($Enforce = $false) until explicitly enabled after pilot review.

.PARAMETER ApprovedSids
    Exact SIDs or SID regex patterns for authorized roles/groups (RID -500, -512, -519 are built-in).

.PARAMETER ApprovedLocalAccounts
    Local administrator account names valid only when prefixed by the local machine name.

.PARAMETER ApprovedDomainAccounts
    Explicitly domain-qualified group/account names (DOMAIN\GroupName).

.PARAMETER Enforce
    $false (default) = report only. $true = remove unauthorized members.

.PARAMETER TestMembers
    Optional array of member objects (@{ Name = '...'; Sid = '...' }) for offline Pester testing.

.PARAMETER ComputerName
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
        # Entra ID joined devices: add the same role SIDs you added to Detect-UnauthorizedLocalAdmins.ps1.
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
    [bool]$Enforce = $false,

    [Parameter(Mandatory = $false)]
    [object[]]$TestMembers,

    [Parameter(Mandatory = $false)]
    [string]$ComputerName = $env:COMPUTERNAME,

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

    if (-not [string]::IsNullOrWhiteSpace($Member.Sid)) {
        if ($Member.Sid -match '-500$') {
            return $true
        }
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

    if ($memberName -match '^S-1-\d+-') {
        foreach ($sidPattern in $SidPatterns) {
            if ($memberName -match $sidPattern) {
                return $true
            }
        }
    }

    $escapedMachine = [regex]::Escape($LocalMachineName)
    foreach ($localAcc in $LocalAccounts) {
        $escapedAcc = [regex]::Escape($localAcc)
        if ($memberName -match "(?i)^${escapedMachine}\\${escapedAcc}$") {
            return $true
        }
    }

    if ([string]::IsNullOrWhiteSpace($Member.Sid) -and $memberName -match "(?i)^${escapedMachine}\\(Administrator|Administrador)$") {
        return $true
    }

    foreach ($domAcc in $DomainAccounts) {
        if ($memberName.Equals($domAcc, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

try {
    $members = if ($PSBoundParameters.ContainsKey('TestMembers')) {
        foreach ($item in $TestMembers) {
            if ($item -is [string]) {
                [PSCustomObject]@{ Name = $item; Sid = if ($item -match '^S-1-\d+-') { $item } else { $null } }
            }
            else {
                [PSCustomObject]@{
                    Name = if ($item.PSObject.Properties['Name']) { [string]$item.Name } else { [string]$item }
                    Sid  = if ($item.PSObject.Properties['Sid']) { [string]$item.Sid } elseif ($item.PSObject.Properties['SID']) { [string]$item.SID } else { $null }
                }
            }
        }
    }
    else {
        Get-LocalAdminMember
    }

    $targets = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($m in @($members)) {
        $approved = Test-IsApprovedLocalAdmin `
            -Member $m `
            -SidPatterns $ApprovedSids `
            -LocalAccounts $ApprovedLocalAccounts `
            -DomainAccounts $ApprovedDomainAccounts `
            -LocalMachineName $ComputerName

        if (-not $approved) {
            $targets.Add($m)
        }
    }

    if ($targets.Count -eq 0) {
        $msg = "COMPLIANT: No unauthorized local administrators found."
        if ($NoExit) {
            return [PSCustomObject]@{ Compliant = $true; ExitCode = 0; Targets = @(); Message = $msg }
        }
        Write-Output $msg
        exit 0
    }

    $names = ($targets | ForEach-Object { if ($_.Name) { $_.Name } else { $_.Sid } }) -join '; '

    if (-not $Enforce) {
        $msg = "REPORT-ONLY: $($targets.Count) unauthorized principal(s) found, nothing removed (Enforce = false): $names"
        if ($NoExit) {
            return [PSCustomObject]@{ Compliant = $false; ExitCode = 0; Targets = $targets.ToArray(); Message = $msg }
        }
        Write-Output $msg
        exit 0
    }

    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    $removed = [System.Collections.Generic.List[string]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $targets) {
        $memberId = if ($t.Sid) { $t.Sid } else { $t.Name }
        try {
            Remove-LocalGroupMember -Group $adminGroup -Member $memberId -ErrorAction Stop
            $removed.Add($t.Name)
        }
        catch {
            $failed.Add("$($t.Name) ($($_.Exception.Message))")
        }
    }

    if ($failed.Count -gt 0) {
        $msg = "PARTIAL: Removed $($removed.Count), failed $($failed.Count): $($failed -join '; ')"
        if ($NoExit) {
            return [PSCustomObject]@{ Compliant = $false; ExitCode = 1; Targets = $targets.ToArray(); Message = $msg }
        }
        Write-Output $msg
        exit 1
    }

    $msg = "REMEDIATED: Removed $($removed.Count) unauthorized principal(s): $($removed -join '; ')"
    if ($NoExit) {
        return [PSCustomObject]@{ Compliant = $true; ExitCode = 0; Targets = $targets.ToArray(); Message = $msg }
    }
    Write-Output $msg
    exit 0
}
catch {
    $errMsg = "REMEDIATION FAILED: $($_.Exception.Message)"
    if ($NoExit) {
        return [PSCustomObject]@{ Compliant = $false; ExitCode = 1; Targets = @(); Message = $errMsg }
    }
    Write-Output $errMsg
    exit 1
}
