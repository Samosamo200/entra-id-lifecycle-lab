<#
.SYNOPSIS
    Detection: finds users added to privileged groups, using the Entra ID audit logs.
.DESCRIPTION
    Reads the directory audit logs through Microsoft Graph (works on the free Entra ID tier)
    and raises an alert for every "Add member to group" event on a privileged group.
    Each alert is enriched with the user's job title and current membership:
      OPEN      still a member, and the role does not need the group  -> investigate and contain
      EXPECTED  still a member, and the role map gives this group     -> benign positive
      CLOSED    no longer a member                                     -> already handled
    This is the same logic as a Microsoft Sentinel analytics rule, without a SIEM.
.EXAMPLE
    ./detect-privileged-group-changes.ps1
.EXAMPLE
    ./detect-privileged-group-changes.ps1 -LookbackHours 24 -PrivilegedGroups SG-IT-Security, SG-Finance
#>
#Requires -Modules Microsoft.Graph.Reports
[CmdletBinding()]
param(
    [string[]]$PrivilegedGroups = @('SG-IT-Security'),
    [ValidateRange(1, 168)][int]$LookbackHours = 168
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IamLab.psm1') -Force

$since = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-Step "Searching audit logs since $since UTC for additions to: $($PrivilegedGroups -join ', ')"

$roleMap = Get-RoleMap
$events = Get-MgAuditLogDirectoryAudit -All `
    -Filter "activityDisplayName eq 'Add member to group' and activityDateTime ge $since"

$alerts = foreach ($e in $events) {
    # The user is the target; the group name is in its modified properties.
    $userTarget = $e.TargetResources | Where-Object Type -eq 'User' | Select-Object -First 1
    $groupName = ($userTarget.ModifiedProperties |
        Where-Object DisplayName -eq 'Group.DisplayName').NewValue -replace '"', ''
    if ($groupName -notin $PrivilegedGroups) { continue }

    $stillMember = $false
    $jobTitle = $null
    try {
        $group = Get-LabGroup -Name $groupName
        $stillMember = (Get-LabUserGroups -UserId $userTarget.Id).Id -contains $group.Id
        $jobTitle = (Get-LabUser -UserPrincipalName $userTarget.Id).JobTitle
    } catch { }

    # Enrichment: is this group what the user's role should have, according to the role map?
    $expected = $jobTitle -and $roleMap.ContainsKey($jobTitle) -and $roleMap[$jobTitle].Group -eq $groupName
    $status = if (-not $stillMember) { 'CLOSED' } elseif ($expected) { 'EXPECTED' } else { 'OPEN' }

    [pscustomobject]@{
        TimeUtc     = $e.ActivityDateTime
        AddedUser   = $userTarget.UserPrincipalName
        Group       = $groupName
        AddedBy     = $e.InitiatedBy.User.UserPrincipalName ?? $e.InitiatedBy.App.DisplayName
        FromIp      = $e.InitiatedBy.User.IpAddress
        JobTitle    = $jobTitle
        StillMember = $stillMember
        Status      = $status
        Correlation = $e.CorrelationId
    }
}

if (-not $alerts) {
    Write-Step 'No additions to privileged groups found.' -Level Ok
    return
}

Write-Step "$(@($alerts).Count) addition(s) to privileged groups found" -Level Warn
$alerts | Sort-Object TimeUtc | Format-Table TimeUtc, AddedUser, Group, JobTitle, Status -AutoSize

foreach ($a in $alerts | Where-Object Status -eq 'OPEN') {
    Write-Step "OPEN: $($a.AddedUser) ($($a.JobTitle)) is in $($a.Group), which the role does not need. Verify, then contain with:" -Level Warn
    Write-Host "    ./incident-contain-user.ps1 -UserPrincipalName $($a.AddedUser) -PrivilegedGroup $($a.Group)"
}
foreach ($a in $alerts | Where-Object Status -eq 'EXPECTED') {
    Write-Step "EXPECTED: $($a.AddedUser) is a $($a.JobTitle), and that role uses $($a.Group). Benign, but confirm it was approved." -Level Ok
}
foreach ($a in $alerts | Where-Object Status -eq 'CLOSED') {
    Write-Step "CLOSED: $($a.AddedUser) is no longer in $($a.Group)." -Level Ok
}
