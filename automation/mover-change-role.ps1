<#
.SYNOPSIS
    Mover: moves a user to a new role and removes the access from the old one,
    so a role change never leaves privilege creep behind.
.EXAMPLE
    ./mover-change-role.ps1 -UserPrincipalName sofie.andersen@contoso.onmicrosoft.com -NewRole Driftsleder
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [Parameter(Mandatory)][string]$NewRole
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IamLab.psm1') -Force

$user = Get-LabUser -UserPrincipalName $UserPrincipalName
$newInfo = Get-RoleInfo -Role $NewRole
$newGroup = Get-LabGroup -Name $newInfo.Group
$roleGroupNames = (Get-RoleMap).Values.Group

$before = @(Get-LabUserGroups -UserId $user.Id)
Write-Step "$($user.DisplayName): $($user.JobTitle) -> $NewRole"
Write-Step "Groups before: $(if ($before) { $before.DisplayName -join ', ' } else { 'none' })"

if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, "Move to $NewRole")) {
    # 1. Add the new role group first, so the user is never left without access.
    if ($before.Id -notcontains $newGroup.Id) {
        New-MgGroupMember -GroupId $newGroup.Id -DirectoryObjectId $user.Id
        Write-Step "Added to $($newGroup.DisplayName)" -Level Ok
    }

    # 2. Remove every other role group: this is what prevents privilege creep.
    foreach ($g in $before | Where-Object { $_.DisplayName -in $roleGroupNames -and $_.Id -ne $newGroup.Id }) {
        Remove-MgGroupMemberDirectoryObjectByRef -GroupId $g.Id -DirectoryObjectId $user.Id
        Write-Step "Removed from $($g.DisplayName) (old role)" -Level Ok
    }

    # 3. Update the job information.
    Update-MgUser -UserId $user.Id -JobTitle $NewRole -Department $newInfo.Department
    Write-Step "Job title set to $NewRole" -Level Ok

    $after = Get-LabUserGroups -UserId $user.Id
    Write-Step "Groups after: $($after.DisplayName -join ', ')" -Level Ok
}
