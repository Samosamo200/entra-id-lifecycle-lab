<#
.SYNOPSIS
    Incident: contains an account that was added to a privileged group without approval.
    Removes the group, revokes sessions and disables the account.
.EXAMPLE
    ./incident-contain-user.ps1 -UserPrincipalName test.user@contoso.onmicrosoft.com -PrivilegedGroup SG-IT-Security
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [string]$PrivilegedGroup = 'SG-IT-Security'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IamLab.psm1') -Force

$user = Get-LabUser -UserPrincipalName $UserPrincipalName
$group = Get-LabGroup -Name $PrivilegedGroup
$isMember = (Get-LabUserGroups -UserId $user.Id).Id -contains $group.Id

Write-Step "Containing $($user.DisplayName) - member of $PrivilegedGroup`: $isMember" -Level Warn

if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, 'Remove privileged access, revoke sessions, disable account')) {
    if ($isMember) {
        Remove-MgGroupMemberDirectoryObjectByRef -GroupId $group.Id -DirectoryObjectId $user.Id
        Write-Step "Removed from $PrivilegedGroup" -Level Ok
    }
    Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
    Write-Step 'Sign-in sessions revoked' -Level Ok
    Update-MgUser -UserId $user.Id -AccountEnabled:$false
    Write-Step 'Account disabled' -Level Ok
    Write-Step "Next: check who added the user in the audit logs, and their sign-in logs." -Level Warn
}
