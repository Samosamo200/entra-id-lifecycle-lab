<#
.SYNOPSIS
    Connects to Microsoft Graph with only the permissions the JML scripts need.
.DESCRIPTION
    Uses interactive sign-in. Device code flow is not used, because it is a common
    phishing technique and is blocked by Security Defaults in this tenant (AADSTS530035).
    Run it from a normal PowerShell 7 window: embedded terminals may hide the sign-in window.
.EXAMPLE
    ./connect-graph.ps1 -TenantId contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    # Tenant domain or ID. Required for personal Microsoft accounts (e.g. @hotmail.com),
    # otherwise the sign-in goes to the consumer tenant instead of your directory.
    [Parameter(Mandatory)][string]$TenantId
)

$scopes = @(
    'User.ReadWrite.All'       # create users, change job title, disable accounts
    'Group.ReadWrite.All'      # add and remove group members
    'User.RevokeSessions.All'  # revoke sign-in sessions when someone leaves
    'Domain.Read.All'          # find the tenant's default domain for new UPNs
    'AuditLog.Read.All'        # read audit logs for the detection script
)

Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome -ErrorAction Stop
$ctx = Get-MgContext
if (-not $ctx -or -not $ctx.TenantId) {
    throw 'Sign-in did not complete. Run the script again from a normal PowerShell 7 window.'
}
$missing = $scopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missing) { Write-Warning "Missing scopes: $($missing -join ', ')" }

Write-Host "[+] Connected to tenant $($ctx.TenantId)" -ForegroundColor Green
Write-Host "[*] Scopes: $($ctx.Scopes -join ', ')" -ForegroundColor Cyan
