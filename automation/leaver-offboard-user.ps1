<#
.SYNOPSIS
    Leaver: blocks sign-in, revokes sessions and removes all group memberships.
    The account is kept (not deleted) so its audit history stays available.
.EXAMPLE
    ./leaver-offboard-user.ps1 -UserPrincipalName ingrid.solberg@contoso.onmicrosoft.com
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IamLab.psm1') -Force

$user = Get-LabUser -UserPrincipalName $UserPrincipalName
$groups = @(Get-LabUserGroups -UserId $user.Id)
Write-Step "Offboarding $($user.DisplayName) ($($user.JobTitle))"

if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, 'Disable account, revoke sessions and remove all groups')) {
    # 1. Block new sign-ins.
    Update-MgUser -UserId $user.Id -AccountEnabled:$false
    Write-Step 'Account disabled' -Level Ok

    # 2. Kill existing sessions, so open apps stop working too.
    Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
    Write-Step 'Sign-in sessions revoked' -Level Ok

    # 3. Remove all group memberships.
    foreach ($g in $groups) {
        Remove-MgGroupMemberDirectoryObjectByRef -GroupId $g.Id -DirectoryObjectId $user.Id
        Write-Step "Removed from $($g.DisplayName)" -Level Ok
    }

    $check = Get-LabUser -UserPrincipalName $UserPrincipalName
    $left = @(Get-LabUserGroups -UserId $user.Id)
    Write-Step "Verified: AccountEnabled=$($check.AccountEnabled), groups left=$($left.Count)" -Level Ok
    Write-Step 'Account kept for audit and forensics (not deleted).'
}
