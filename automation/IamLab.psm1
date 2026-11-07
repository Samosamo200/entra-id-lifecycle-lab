#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Users.Actions, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement
# Shared helpers for the Joiner-Mover-Leaver scripts.

$script:ConfigPath = Join-Path $PSScriptRoot 'config/role-groups.json'

function Get-RoleMap {
    # Role -> department and security group. One place to change access rules.
    Get-Content -Path $script:ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
}

function Get-RoleInfo {
    param([Parameter(Mandatory)][string]$Role)
    $map = Get-RoleMap
    if (-not $map.ContainsKey($Role)) {
        throw "Unknown role '$Role'. Valid roles: $($map.Keys -join ', ')"
    }
    $map[$Role]
}

function Get-LabGroup {
    param([Parameter(Mandatory)][string]$Name)
    $group = Get-MgGroup -Filter "displayName eq '$Name'" -ErrorAction Stop
    if (-not $group) { throw "Group '$Name' was not found." }
    if (@($group).Count -gt 1) { throw "More than one group is named '$Name'." }
    $group
}

function Get-LabUser {
    param([Parameter(Mandatory)][string]$UserPrincipalName)
    Get-MgUser -UserId $UserPrincipalName -Property Id, DisplayName, UserPrincipalName, JobTitle, Department, AccountEnabled -ErrorAction Stop
}

function Get-LabUserGroups {
    # Security groups the user is a direct member of.
    param([Parameter(Mandatory)][string]$UserId)
    Get-MgUserMemberOf -UserId $UserId -All |
        Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' } |
        ForEach-Object { [pscustomobject]@{ Id = $_.Id; DisplayName = $_.AdditionalProperties['displayName'] } }
}

function Get-DefaultDomain {
    (Get-MgDomain | Where-Object IsDefault).Id
}

function New-LabPassword {
    # 16 random characters from a cryptographic RNG, with every character class present.
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%+?'
    $all = -join $sets
    $chars = foreach ($set in $sets) { $set[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($set.Length)] }
    $chars += 1..12 | ForEach-Object { $all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)] }
    -join ($chars | Sort-Object { [System.Security.Cryptography.RandomNumberGenerator]::GetInt32([int]::MaxValue) })
}

function Write-Step {
    param([string]$Message, [ValidateSet('Info', 'Ok', 'Warn')][string]$Level = 'Info')
    $color = @{ Info = 'Cyan'; Ok = 'Green'; Warn = 'Yellow' }[$Level]
    $prefix = @{ Info = '[*]'; Ok = '[+]'; Warn = '[!]' }[$Level]
    Write-Host "$prefix $Message" -ForegroundColor $color
}

Export-ModuleMember -Function Get-RoleMap, Get-RoleInfo, Get-LabGroup, Get-LabUser, Get-LabUserGroups, Get-DefaultDomain, New-LabPassword, Write-Step
