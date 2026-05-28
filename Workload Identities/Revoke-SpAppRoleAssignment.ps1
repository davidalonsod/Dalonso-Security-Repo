<#
.SYNOPSIS
    Revokes app role assignments on an Entra ID Service Principal and
    notifies the affected users via Microsoft Graph (sendMail).

.DESCRIPTION
    Enumerates user app role assignments on a target Service Principal,
    revokes them via Microsoft Graph, and sends an email notification to
    each impacted user from a designated sender mailbox.

    Safe to re-run: revoked assignments are not returned on subsequent
    queries. A revoke failure skips the notification for that user; a
    notification failure does not undo the revoke (logged as a warning).

.PARAMETER ServicePrincipalId
    ObjectId of the Service Principal (not the AppId).

.PARAMETER AppRoleId
    GUID of the appRole to revoke. Use the all-zero GUID
    (00000000-0000-0000-0000-000000000000) for the "default access" role
    that apps without explicit roles assign.

.PARAMETER NotifyFromUserId
    UPN or ObjectId of the sender mailbox. Must be a licensed Exchange
    Online mailbox. When using application permissions, scope this
    mailbox with an Exchange Application Access Policy.

.PARAMETER DryRun
    If set, no revoke or mail send is performed. Logs the intended
    actions only.

.EXAMPLE
    Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','Directory.Read.All','Mail.Send','User.Read.All'

    ./Revoke-SpAppRoleAssignment.ps1 `
        -ServicePrincipalId 11111111-1111-1111-1111-111111111111 `
        -AppRoleId          00000000-0000-0000-0000-000000000000 `
        -NotifyFromUserId   secops@contoso.com `
        -DryRun

.NOTES
    Required Microsoft Graph permissions:
        AppRoleAssignment.ReadWrite.All   delete assignments
        Directory.Read.All                read the Service Principal
        User.Read.All                     resolve principalId to UPN/mail
        Mail.Send                         send the notification

    Tested with Microsoft.Graph PowerShell SDK v2.x on PowerShell 7.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $ServicePrincipalId,
    [Parameter(Mandatory)] [string] $AppRoleId,
    [Parameter(Mandatory)] [string] $NotifyFromUserId,
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'

# --- Sanity check: Graph context ---------------------------------------------
$ctx = Get-MgContext
if (-not $ctx) {
    throw "Not connected to Microsoft Graph. Run Connect-MgGraph first."
}
Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account) ($($ctx.AuthType))."

# --- Resolve the target Service Principal ------------------------------------
$sp = Get-MgServicePrincipal -ServicePrincipalId $ServicePrincipalId
Write-Host "Service Principal: $($sp.DisplayName) ($($sp.Id))"

# --- Enumerate user app role assignments to revoke ---------------------------
$assignments = Get-MgServicePrincipalAppRoleAssignedTo `
        -ServicePrincipalId $ServicePrincipalId -All |
    Where-Object { $_.AppRoleId -eq [Guid]$AppRoleId -and $_.PrincipalType -eq 'User' }

if (-not $assignments) {
    Write-Host "No user assignments found for AppRoleId $AppRoleId."
    return
}

Write-Host "Found $($assignments.Count) user assignment(s) to process."

# --- Process each assignment -------------------------------------------------
foreach ($a in $assignments) {

    $user = $null
    try {
        $user = Get-MgUser -UserId $a.PrincipalId `
                           -Property 'id,displayName,userPrincipalName,mail'
    } catch {
        Write-Warning "Could not resolve user $($a.PrincipalId): $_"
        continue
    }

    $recipient = if ($user.Mail) { $user.Mail } else { $user.UserPrincipalName }
    $target    = "$($user.DisplayName) <$recipient>"

    # Resolve the friendly role name. The all-zero GUID is the
    # implicit "Default Access" role that doesn't appear in $sp.AppRoles.
    $roleName = if ([Guid]$a.AppRoleId -eq [Guid]::Empty) {
        'Default Access'
    } else {
        $match = $sp.AppRoles | Where-Object { $_.Id -eq $a.AppRoleId }
        if ($match) {
            "$($match.DisplayName) ($($match.Value))"
        } else {
            "Unknown role ($($a.AppRoleId))"
        }
    }

    if ($DryRun -or -not $PSCmdlet.ShouldProcess(
            $target, "Revoke '$roleName' on $($sp.DisplayName) and notify")) {
        Write-Host "[DryRun] Would revoke '$roleName' ($($a.Id)) and notify $target"
        continue
    }

    # 1) Revoke ---------------------------------------------------------------
    try {
        Remove-MgServicePrincipalAppRoleAssignedTo `
            -ServicePrincipalId   $ServicePrincipalId `
            -AppRoleAssignmentId  $a.Id
        Write-Host "Revoked '$roleName' for: $target"
    } catch {
        Write-Warning "Failed to revoke ${target} ($($a.Id)): $_"
        continue   # if revoke failed, skip the notification
    }

    # 2) Notify ---------------------------------------------------------------
    $body = @{
        message = @{
            subject = "Your access to $($sp.DisplayName) has been revoked"
            body    = @{
                contentType = 'HTML'
                content     = @"
<p>Hi $($user.DisplayName),</p>
<p>This is to let you know that your access to the application
<strong>$($sp.DisplayName)</strong> in Entra ID was revoked on
$([DateTime]::UtcNow.ToString('u')).</p>
<p>Details of the revoked assignment:</p>
<ul>
  <li><strong>Application:</strong> $($sp.DisplayName)</li>
  <li><strong>Role revoked:</strong> $roleName</li>
  <li><strong>Tenant:</strong> $($ctx.TenantId)</li>
</ul>
<p>If you believe this is a mistake, reply to this email or open a
ticket with the security team.</p>
<p>Regards,<br/>Security Team</p>
"@
            }
            toRecipients = @(@{ emailAddress = @{ address = $recipient } })
        }
        saveToSentItems = $true
    }

    try {
        Send-MgUserMail -UserId $NotifyFromUserId -BodyParameter $body
        Write-Host "Notified: $target"
    } catch {
        Write-Warning "Access revoked but notification failed for ${target}: $_"
    }
}
