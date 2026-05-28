<#
.SYNOPSIS
    Bootstraps the app registration and Service Principal used to run
    Revoke-SpAppRoleAssignment.ps1 unattended.

.DESCRIPTION
    Creates (or reuses) an Entra ID app registration with the four
    Microsoft Graph application permissions required by the revoke
    script, grants tenant-wide admin consent, and optionally creates a
    client secret. Optionally restricts the Mail.Send scope to a single
    sender mailbox via an Exchange Online Application Access Policy.

    Idempotent: re-running detects existing objects and only adds what
    is missing.

.PARAMETER DisplayName
    Display name for the app registration / Service Principal.

.PARAMETER SenderMailbox
    UPN of the mailbox the revoke script will send notifications from.
    When supplied, an Exchange Application Access Policy is created
    restricting this app to that single mailbox (recommended).

.PARAMETER CreateClientSecret
    If set, creates a client secret valid for -SecretLifetimeDays days
    and emits it to the pipeline. Prefer Federated Credentials
    (OIDC / GitHub Actions / Azure DevOps) or a Managed Identity in
    production.

.PARAMETER SecretLifetimeDays
    Lifetime in days for the generated client secret. Default: 180.

.EXAMPLE
    Connect-MgGraph -Scopes `
        'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All'

    ./New-RevokeSpAccessApp.ps1 `
        -DisplayName    'sec-revoke-spaccess' `
        -SenderMailbox  secops@contoso.com `
        -CreateClientSecret

.NOTES
    Required Graph scopes for THIS bootstrap script (delegated, admin):
        Application.ReadWrite.All
        AppRoleAssignment.ReadWrite.All
        Directory.ReadWrite.All

    For the Exchange Application Access Policy you also need the
    ExchangeOnlineManagement module and the Exchange Administrator role.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $DisplayName,
    [string]   $SenderMailbox,
    [switch]   $CreateClientSecret,
    [int]      $SecretLifetimeDays = 180
)

$ErrorActionPreference = 'Stop'

# Microsoft Graph resource AppId (constant across tenants)
$GraphAppId = '00000003-0000-0000-c000-000000000000'

# Required Graph application permissions for Revoke-SpAppRoleAssignment.ps1
$RequiredScopes = @(
    'AppRoleAssignment.ReadWrite.All',
    'Directory.Read.All',
    'User.Read.All',
    'Mail.Send'
)

# --- Sanity check ------------------------------------------------------------
$ctx = Get-MgContext
if (-not $ctx) { throw "Not connected to Microsoft Graph. Run Connect-MgGraph first." }
Write-Host "Tenant: $($ctx.TenantId) | Account: $($ctx.Account)"

# --- Resolve Graph SP and the AppRole GUIDs we need --------------------------
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
if (-not $graphSp) { throw "Microsoft Graph Service Principal not found in this tenant." }

$resourceAccess = foreach ($scope in $RequiredScopes) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $scope -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "AppRole '$scope' not found on Microsoft Graph SP." }
    @{ Id = $role.Id; Type = 'Role' }
}

# --- Create or reuse the app registration ------------------------------------
$app = Get-MgApplication -Filter "displayName eq '$DisplayName'" -Top 1
if (-not $app) {
    if ($PSCmdlet.ShouldProcess($DisplayName, "Create app registration")) {
        $app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' `
            -RequiredResourceAccess @(@{
                ResourceAppId  = $GraphAppId
                ResourceAccess = $resourceAccess
            })
        Write-Host "Created app registration: $($app.DisplayName) (AppId=$($app.AppId))"
    }
} else {
    Write-Host "Found existing app registration: $($app.DisplayName) (AppId=$($app.AppId))"

    # Merge required resource access if missing
    $current = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $GraphAppId }
    $existingIds = @($current.ResourceAccess.Id)
    $missing = $resourceAccess | Where-Object { $_.Id -notin $existingIds }
    if ($missing) {
        $merged = @{
            ResourceAppId  = $GraphAppId
            ResourceAccess = @($current.ResourceAccess + $missing)
        }
        $others = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -ne $GraphAppId }
        Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess (@($merged) + $others)
        Write-Host "Added $($missing.Count) missing Graph permission(s) to the app."
    }
}

# --- Ensure the Service Principal exists -------------------------------------
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -Top 1
if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-Host "Created Service Principal: $($sp.Id)"
} else {
    Write-Host "Service Principal already exists: $($sp.Id)"
}

# --- Grant admin consent (app role assignments on Graph) ---------------------
$alreadyGranted = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All |
    Where-Object { $_.ResourceId -eq $graphSp.Id }

foreach ($ra in $resourceAccess) {
    if ($alreadyGranted | Where-Object { $_.AppRoleId -eq $ra.Id }) {
        continue
    }
    if ($PSCmdlet.ShouldProcess($DisplayName, "Grant Graph AppRole $($ra.Id)")) {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $sp.Id `
            -PrincipalId        $sp.Id `
            -ResourceId         $graphSp.Id `
            -AppRoleId          $ra.Id | Out-Null
    }
}
Write-Host "Admin consent granted for all required Graph application permissions."

# --- Optional: client secret -------------------------------------------------
if ($CreateClientSecret) {
    $params = @{
        PasswordCredential = @{
            DisplayName   = "bootstrap-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
            EndDateTime   = [DateTime]::UtcNow.AddDays($SecretLifetimeDays)
        }
    }
    $pwd = Add-MgApplicationPassword -ApplicationId $app.Id -BodyParameter $params
    Write-Warning "Store this client secret securely; it is shown ONCE."
    [pscustomobject]@{
        TenantId     = $ctx.TenantId
        AppId        = $app.AppId
        SpObjectId   = $sp.Id
        ClientSecret = $pwd.SecretText
        ExpiresOn    = $pwd.EndDateTime
    }
}

# --- Optional: Exchange Application Access Policy ----------------------------
if ($SenderMailbox) {
    if (-not (Get-Module -ListAvailable ExchangeOnlineManagement)) {
        Write-Warning "ExchangeOnlineManagement module not installed; skipping Application Access Policy."
        Write-Warning "Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
    } else {
        try {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
                # Pass -UserPrincipalName to avoid the WAM broker path,
                # which is known to throw NullReferenceException on some
                # Windows builds / older EXO module versions.
                Connect-ExchangeOnline `
                    -UserPrincipalName $ctx.Account `
                    -ShowBanner:$false -ErrorAction Stop
            }
            $existing = Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue |
                Where-Object { $_.AppId -eq $app.AppId }
            if ($existing) {
                Write-Host "Application Access Policy already present for $($app.AppId)."
            } else {
                if ($PSCmdlet.ShouldProcess($SenderMailbox, "Create Exchange Application Access Policy")) {
                    New-ApplicationAccessPolicy `
                        -AppId            $app.AppId `
                        -PolicyScopeGroupId $SenderMailbox `
                        -AccessRight      RestrictAccess `
                        -Description      "Restrict $DisplayName to $SenderMailbox for Mail.Send" | Out-Null
                    Write-Host "Application Access Policy created. Test with:"
                    Write-Host "  Test-ApplicationAccessPolicy -Identity $SenderMailbox -AppId $($app.AppId)"
                }
            }
        } catch {
            Write-Warning "Application Access Policy step failed: $_"
            Write-Warning "App + SP + consent are already in place. You can retry just this step with:"
            Write-Warning "  Connect-ExchangeOnline -UserPrincipalName <admin-upn> -ShowBanner:`$false"
            Write-Warning "  New-ApplicationAccessPolicy -AppId $($app.AppId) -PolicyScopeGroupId $SenderMailbox -AccessRight RestrictAccess -Description 'Restrict $DisplayName to $SenderMailbox'"
        }
    }
}

Write-Host ""
Write-Host "Done. Use these identifiers in the revoke script:"
Write-Host "  TenantId : $($ctx.TenantId)"
Write-Host "  AppId    : $($app.AppId)"
Write-Host "  SP Id    : $($sp.Id)"
