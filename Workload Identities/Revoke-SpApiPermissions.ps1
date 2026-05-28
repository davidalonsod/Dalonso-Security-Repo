<#
.SYNOPSIS
    Revokes API permissions (application and/or delegated) held by an
    Entra ID Service Principal and sends a notification email listing
    exactly which permissions were removed.

.DESCRIPTION
    Two permission surfaces are revoked:

      * Application permissions: appRoleAssignments where the target SP
        is the PrincipalId on a resource SP (Graph, MCAS, etc.).
        These are the "Application" rows on the SP's Permissions blade.

      * Delegated permissions: oauth2PermissionGrants where the target
        SP is the ClientId. These are the "Delegated" rows on the SP's
        Permissions blade.

    The script collects every permission first, optionally filters by
    resource (e.g. 'Microsoft Graph') and/or by claim value (e.g.
    'AuditLog.Read.All'), revokes the matches, and sends a single HTML
    email summarising what was removed.

    Idempotent. -DryRun and -WhatIf supported.

.PARAMETER ServicePrincipalId
    ObjectId of the target Service Principal (the one whose API
    permissions you want to revoke).

.PARAMETER ResourceFilter
    Optional. Display name of the resource API to limit revocation to,
    e.g. 'Microsoft Graph' or 'Microsoft Cloud App Security'. Case
    insensitive, substring match.

.PARAMETER Claims
    Optional. One or more claim values (e.g. 'AuditLog.Read.All',
    'Mail.Send') to limit revocation to. Case insensitive.

.PARAMETER PermissionType
    Optional. 'Application', 'Delegated', or 'Both' (default).

.PARAMETER NotifyFromUserId
    UPN / ObjectId of the sender mailbox.

.PARAMETER NotifyTo
    Optional. Override the recipient list. By default the script
    notifies all owners of the target SP; if there are none, it falls
    back to NotifyFromUserId (self-notification to the operator).

.PARAMETER DryRun
    If set, no revoke or mail send is performed. Logs intended actions.

.EXAMPLE
    Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All','Directory.Read.All','User.Read.All','Mail.Send'

    ./Revoke-SpApiPermissions.ps1 `
        -ServicePrincipalId 11111111-1111-1111-1111-111111111111 `
        -ResourceFilter     'Microsoft Graph' `
        -Claims             'AuditLog.Read.All','ServiceHealth.Read.All' `
        -NotifyFromUserId   secops@contoso.com `
        -DryRun

.NOTES
    Required Microsoft Graph permissions:
        AppRoleAssignment.ReadWrite.All        delete application permissions
        DelegatedPermissionGrant.ReadWrite.All delete delegated permissions
        Directory.Read.All                     read the target SP + resources
        User.Read.All                          resolve owners to UPN / mail
        Mail.Send                              send the notification
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]   $ServicePrincipalId,
    [string]                          $ResourceFilter,
    [string[]]                        $Claims,
    [ValidateSet('Application','Delegated','Both')]
    [string]                          $PermissionType = 'Both',
    [Parameter(Mandatory)] [string]   $NotifyFromUserId,
    [string[]]                        $NotifyTo,
    [switch]                          $DryRun
)

$ErrorActionPreference = 'Stop'

# --- Sanity check ------------------------------------------------------------
$ctx = Get-MgContext
if (-not $ctx) { throw "Not connected to Microsoft Graph. Run Connect-MgGraph first." }
Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account) ($($ctx.AuthType))."

# --- Resolve the target SP ---------------------------------------------------
$sp = Get-MgServicePrincipal -ServicePrincipalId $ServicePrincipalId
Write-Host "Target Service Principal: $($sp.DisplayName) ($($sp.Id))"

# Cache of resource SPs (for resolving role/scope display names)
$resourceCache = @{}
function Get-ResourceSp([string]$id) {
    if (-not $resourceCache.ContainsKey($id)) {
        $resourceCache[$id] = Get-MgServicePrincipal -ServicePrincipalId $id `
            -Property 'id,displayName,appRoles,oauth2PermissionScopes'
    }
    $resourceCache[$id]
}

# --- Collect candidates ------------------------------------------------------
$candidates = New-Object System.Collections.Generic.List[object]

# 1) Application permissions: appRoleAssignments where SP is the principal
if ($PermissionType -in 'Application','Both') {
    Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All | ForEach-Object {
        $resource = Get-ResourceSp $_.ResourceId
        $role     = $resource.AppRoles | Where-Object Id -eq $_.AppRoleId
        $candidates.Add([pscustomobject]@{
            Kind         = 'Application'
            AssignmentId = $_.Id
            ResourceId   = $resource.Id
            Resource     = $resource.DisplayName
            ClaimValue   = if ($role) { $role.Value }       else { '<unknown>' }
            Display      = if ($role) { $role.DisplayName } else { '<unknown>' }
        })
    }
}

# 2) Delegated permissions: oauth2PermissionGrants where SP is the client
if ($PermissionType -in 'Delegated','Both') {
    $grants = Get-MgOauth2PermissionGrant -All -Filter "clientId eq '$($sp.Id)'"
    foreach ($g in $grants) {
        $resource = Get-ResourceSp $g.ResourceId
        # Scope is a space-separated list; explode so we can filter per claim
        foreach ($scope in ($g.Scope -split '\s+' | Where-Object { $_ })) {
            $scopeDef = $resource.Oauth2PermissionScopes | Where-Object Value -eq $scope
            $candidates.Add([pscustomobject]@{
                Kind         = 'Delegated'
                AssignmentId = $g.Id            # whole grant; revoke is at grant level
                ResourceId   = $resource.Id
                Resource     = $resource.DisplayName
                ClaimValue   = $scope
                Display      = if ($scopeDef) { $scopeDef.AdminConsentDisplayName } else { $scope }
                ConsentType  = $g.ConsentType   # 'AllPrincipals' or 'Principal'
                PrincipalId  = $g.PrincipalId
            })
        }
    }
}

# --- Apply filters -----------------------------------------------------------
$targets = $candidates
if ($ResourceFilter) {
    $targets = $targets | Where-Object { $_.Resource -like "*$ResourceFilter*" }
}
if ($Claims) {
    $targets = $targets | Where-Object { $Claims -contains $_.ClaimValue }
}

if (-not $targets) {
    Write-Host "No matching API permissions to revoke."
    return
}

Write-Host "Matched $($targets.Count) permission(s):"
$targets | Format-Table Kind, Resource, ClaimValue, Display -AutoSize | Out-String | Write-Host

# --- Revoke ------------------------------------------------------------------
$revoked = New-Object System.Collections.Generic.List[object]

# Application permissions revoke individually
foreach ($t in $targets | Where-Object Kind -eq 'Application') {
    $label = "$($t.Resource) / $($t.ClaimValue) [Application]"
    if ($DryRun -or -not $PSCmdlet.ShouldProcess($label, "Revoke")) {
        Write-Host "[DryRun] Would revoke $label"
        $revoked.Add($t); continue
    }
    try {
        Remove-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId    $sp.Id `
            -AppRoleAssignmentId   $t.AssignmentId
        Write-Host "Revoked: $label"
        $revoked.Add($t)
    } catch {
        Write-Warning "Failed to revoke ${label}: $_"
    }
}

# Delegated permissions: a grant carries a Scope string. If we are only
# removing some of the scopes inside a grant, patch it; if all scopes in
# the grant are targeted, delete the whole grant.
$delegatedTargets = $targets | Where-Object Kind -eq 'Delegated'
$grantsToProcess  = $delegatedTargets | Group-Object AssignmentId

foreach ($g in $grantsToProcess) {
    $grantId    = $g.Name
    $scopesGone = $g.Group.ClaimValue
    $grantNow   = Get-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grantId
    $currentSc  = ($grantNow.Scope -split '\s+' | Where-Object { $_ })
    $remaining  = $currentSc | Where-Object { $_ -notin $scopesGone }
    $resource   = (Get-ResourceSp $grantNow.ResourceId).DisplayName

    $labels = $g.Group | ForEach-Object { "$($_.Resource) / $($_.ClaimValue) [Delegated]" }
    if ($DryRun -or -not $PSCmdlet.ShouldProcess(($labels -join ', '), "Revoke")) {
        $labels | ForEach-Object { Write-Host "[DryRun] Would revoke $_" }
        $g.Group | ForEach-Object { $revoked.Add($_) }
        continue
    }

    try {
        if ($remaining.Count -eq 0) {
            Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grantId
            Write-Host "Deleted grant $grantId on $resource (all scopes removed)."
        } else {
            Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grantId `
                -BodyParameter @{ scope = ($remaining -join ' ') }
            Write-Host "Updated grant $grantId on ${resource}: remaining scopes -> $($remaining -join ', ')"
        }
        $g.Group | ForEach-Object {
            Write-Host "Revoked: $($_.Resource) / $($_.ClaimValue) [Delegated]"
            $revoked.Add($_)
        }
    } catch {
        Write-Warning "Failed to revoke delegated scopes on grant ${grantId}: $_"
    }
}

if (-not $revoked) {
    Write-Host "Nothing was revoked. Skipping notification."
    return
}

# --- Decide recipients -------------------------------------------------------
if (-not $NotifyTo) {
    $ownerUpns = @()
    try {
        $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All
        $ownerUpns = $owners | ForEach-Object {
            if ($_.AdditionalProperties.userPrincipalName) {
                $_.AdditionalProperties.userPrincipalName
            } elseif ($_.AdditionalProperties.mail) {
                $_.AdditionalProperties.mail
            }
        } | Where-Object { $_ }
    } catch {
        Write-Warning "Could not enumerate SP owners: $_"
    }
    $NotifyTo = if ($ownerUpns) { $ownerUpns } else { @($NotifyFromUserId) }
    Write-Host "Notification recipients: $($NotifyTo -join ', ')"
}

# --- Build the email body ----------------------------------------------------
$rowsHtml = ($revoked | ForEach-Object {
    "<tr><td>$($_.Kind)</td><td>$($_.Resource)</td><td><code>$($_.ClaimValue)</code></td><td>$($_.Display)</td></tr>"
}) -join "`n"

$emailHtml = @"
<p>Hi,</p>
<p>The following API permissions were revoked from Service Principal
<strong>$($sp.DisplayName)</strong> on
$([DateTime]::UtcNow.ToString('u')).</p>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:13px;">
  <thead style="background:#f3f3f3;">
    <tr><th>Type</th><th>API</th><th>Claim</th><th>Description</th></tr>
  </thead>
  <tbody>
    $rowsHtml
  </tbody>
</table>
<p>Tenant: $($ctx.TenantId)<br/>
Service Principal: $($sp.DisplayName) ($($sp.Id))<br/>
Operator: $($ctx.Account)</p>
<p>If this was unexpected, please contact the security team immediately.</p>
<p>Regards,<br/>Security Team</p>
"@

if ($DryRun) {
    Write-Host "[DryRun] Would send notification to: $($NotifyTo -join ', ')"
    return
}

$body = @{
    message = @{
        subject = "API permissions revoked on Service Principal '$($sp.DisplayName)'"
        body    = @{ contentType = 'HTML'; content = $emailHtml }
        toRecipients = @($NotifyTo | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    }
    saveToSentItems = $true
}

try {
    Send-MgUserMail -UserId $NotifyFromUserId -BodyParameter $body
    Write-Host "Notification sent to $($NotifyTo -join ', ')."
} catch {
    Write-Warning "Permissions were revoked but notification failed: $_"
}
