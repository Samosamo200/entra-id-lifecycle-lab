<#
.SYNOPSIS
    Joiner: creates a user and gives them only the group that belongs to their role.
.EXAMPLE
    ./joiner-onboard-user.ps1 -FirstName Nora -LastName Lie -Role Lagertekniker
.EXAMPLE
    ./joiner-onboard-user.ps1 -FirstName Nora -LastName Lie -Role Lagertekniker -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$FirstName,
    [Parameter(Mandatory)][string]$LastName,
    [Parameter(Mandatory)][string]$Role
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IamLab.psm1') -Force

$roleInfo = Get-RoleInfo -Role $Role
$group = Get-LabGroup -Name $roleInfo.Group
$alias = ("$FirstName.$LastName").ToLower() -replace '[^a-z0-9.]', ''
$upn = "$alias@$(Get-DefaultDomain)"

if (Get-MgUser -Filter "userPrincipalName eq '$upn'") {
    throw "User $upn already exists."
}

Write-Step "Onboarding $FirstName $LastName as $Role ($($roleInfo.Department))"
if ($PSCmdlet.ShouldProcess($upn, "Create user and add to $($group.DisplayName)")) {
    $password = New-LabPassword
    $user = New-MgUser -DisplayName "$FirstName $LastName" -GivenName $FirstName -Surname $LastName `
        -UserPrincipalName $upn -MailNickname $alias -JobTitle $Role -Department $roleInfo.Department `
        -UsageLocation 'NO' -AccountEnabled `
        -PasswordProfile @{ Password = $password; ForceChangePasswordNextSignIn = $true }
    Write-Step "Created $upn" -Level Ok

    New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id
    Write-Step "Added to $($group.DisplayName) (least privilege: one role, one group)" -Level Ok

    $groups = Get-LabUserGroups -UserId $user.Id
    Write-Step "Verified groups: $($groups.DisplayName -join ', ')" -Level Ok
    Write-Step "Temporary password (must be changed at first sign-in): $password" -Level Warn
    Write-Step "Give the password to the user through a secure channel, never by e-mail." -Level Warn
}
