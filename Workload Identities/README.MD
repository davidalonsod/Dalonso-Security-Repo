# Revoke-SpAccess

Two Mcrosoft Graph PowerShell scripts for revoking access on Entra ID
Service Principals and notifying the right people by email, end-to-end
(no Logic Apps, no Power Automate).

| Script | Revokes | Notifies |
|---|---|---|
| [`Revoke-SpAppRoleAssignment.ps1`](#users-assigned-to-an-enterprise-app-revoke-spapproleassignmentps1) | **Users** assigned to an enterprise application (Users-and-groups blade) | the affected user |
| [`Revoke-SpApiPermissions.ps1`](#api-permissions-held-by-a-sp-revoke-spapipermissionsps1) | **API permissions held by the SP itself** (Permissions blade: application + delegated) | SP owners (fallback: operator) |
| [`New-RevokeSpAccessApp.ps1`](#1b-unattended-only-bootstrap-the-app-registration) | n/a | n/a (bootstrap for unattended runs) |

Both runtime scripts are useful when:

- You are decommissioning an enterprise application and want users to
  know their access is gone.
- Periodic access reviews surface stale assignments and you want a
  scripted, auditable revoke + notify flow.
- You want a portable replacement for a Logic App that does the same
  thing but lives in source control with the rest of your security
  tooling.

---

## Users assigned to an enterprise app: `Revoke-SpAppRoleAssignment.ps1`

Use this script when you want to remove **users** from an enterprise
application (rows on the **Users and groups** blade) and tell each
user by email that their access is gone.

### How it works

```
                ┌──────────────────────────────┐
                │  Get-MgServicePrincipal      │  resolve target SP
                └──────────────┬───────────────┘
                               │
                ┌──────────────▼───────────────┐
                │  Get-MgServicePrincipal      │  list app role
                │     AppRoleAssignedTo        │  assignments
                └──────────────┬───────────────┘
                               │  filter PrincipalType=User
                               │         AppRoleId=<target>
                               ▼
                       for each assignment
                               │
            ┌──────────────────┼──────────────────┐
            ▼                                     ▼
  Remove-MgServicePrincipal               Send-MgUserMail
   AppRoleAssignedTo                  (HTML notification to user)
```

Two Graph calls per user:

1. `DELETE /servicePrincipals/{sp-id}/appRoleAssignedTo/{assignmentId}`
2. `POST   /users/{senderId}/sendMail`

---

## Prerequisites (both scripts)

| Requirement | Notes |
|---|---|
| PowerShell 7+ | Cross-platform. |
| `Microsoft.Graph` SDK v2.x | `Install-Module Microsoft.Graph -Scope CurrentUser`. Only one version should be installed (see [Troubleshooting](#troubleshooting)). |
| Graph permissions | See per-script tables below. |
| Licensed sender mailbox | Any Exchange Online mailbox you control. Service accounts work fine. |

### Permissions used by `Revoke-SpAppRoleAssignment.ps1`

| Scope | Why |
|---|---|
| `AppRoleAssignment.ReadWrite.All` | Delete the user assignment. |
| `Directory.Read.All` | Read the Service Principal object. |
| `User.Read.All` | Resolve `principalId` to UPN / mail. |
| `Mail.Send` | Send the notification. |

Both **delegated** (interactive admin) and **application** (unattended)
permission types work. For unattended runs, prefer a Managed Identity
or an app registration with admin consent.

> **Lock down `Mail.Send` (application).** With the application scope,
> Graph allows sending as **any** mailbox in the tenant. Always pair it
> with an
> [Exchange Application Access Policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access)
> that restricts the calling app to a single sender mailbox.

---

## Step by step (`Revoke-SpAppRoleAssignment.ps1`)

### 1. Install the Graph SDK

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
# Optional, only if you want the script to scope Mail.Send to one mailbox
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

### 1b. (Unattended only) Bootstrap the app registration

If you plan to run the revoke script as a service (CI/CD, scheduled
task, runbook), use the included bootstrap to create the app
registration + Service Principal with the four Graph application
permissions, grant admin consent, and optionally lock down `Mail.Send`:

```powershell
Connect-MgGraph -Scopes `
    'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All'

./New-RevokeSpAccessApp.ps1 `
    -DisplayName    'sec-revoke-spaccess' `
    -SenderMailbox  secops@<your-tenant> `
    -CreateClientSecret
```

What it does:

1. Creates (or reuses) an app registration `sec-revoke-spaccess`.
2. Adds the four required Graph application permissions:
   `AppRoleAssignment.ReadWrite.All`, `Directory.Read.All`,
   `User.Read.All`, `Mail.Send`.
3. Creates the Service Principal and grants tenant-wide admin consent.
4. (`-CreateClientSecret`) Generates a client secret valid for
   `-SecretLifetimeDays` (default 180) and prints it **once** —
   store it in a secret vault.
5. (`-SenderMailbox`) Creates an Exchange Application Access Policy so
   the app can only send mail from that one mailbox.

The script is idempotent; re-run it any time to converge.

**Prefer Federated Credentials (OIDC) or a Managed Identity** over
client secrets where possible. To skip the secret, omit
`-CreateClientSecret` and configure the federated credential on the
returned `AppId` yourself.

### 2. Identify the Service Principal and AppRole

The script needs two GUIDs and they are easy to confuse. Get them right:

| Parameter | What it is | Where to find it |
|---|---|---|
| `-ServicePrincipalId` | The **Enterprise application Object ID** (the SP) | Entra portal: **Enterprise applications** -> app -> **Overview** -> **Object ID** |
| `-AppRoleId` | The role GUID on that SP. For apps with no published roles, this is the **Default Access** role: `00000000-0000-0000-0000-000000000000`. | See discovery snippet below. |

The **App registration Object ID** and **Application (client) ID** are
**not** valid values for `-ServicePrincipalId`.

Find both with Graph:

```powershell
# Resolve the target SP by display name
$sp = Get-MgServicePrincipal -Filter "displayName eq 'Contoso HR App'"
$sp.Id            # -> use as -ServicePrincipalId

# Roles published by the app (if any)
$sp.AppRoles | Select-Object Id, Value, DisplayName

# Actual current user assignments (this is the source of truth)
Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All |
    Where-Object PrincipalType -eq 'User' |
    Select-Object PrincipalDisplayName, AppRoleId, Id
```

The `AppRoleId` column from the last query is exactly what to pass to
`-AppRoleId`. If the portal shows the role as **Default Access**, the
GUID will be `00000000-0000-0000-0000-000000000000`.

### 3. Connect to Graph

Interactive (admin signs in once):

```powershell
Connect-MgGraph -Scopes `
    'AppRoleAssignment.ReadWrite.All',
    'Directory.Read.All',
    'User.Read.All',
    'Mail.Send'
```

Unattended with a managed identity:

```powershell
Connect-MgGraph -Identity
```

### 4. Dry-run first

The script supports `-DryRun` and `-WhatIf`. Always do a dry run before
the real thing:

```powershell
./Revoke-SpAppRoleAssignment.ps1 `
    -ServicePrincipalId <SP-OBJECT-ID> `
    -AppRoleId          <APPROLE-GUID> `
    -NotifyFromUserId   secops@<your-tenant> `
    -DryRun
```

Expected output (sample):

```
Connected to tenant <tenant-id> as <upn> (Delegated).
Service Principal: Contoso HR App (<sp-id>)
Found 3 user assignment(s) to process.
[DryRun] Would revoke 'Default Access' (<assignment-id-1>) and notify Alice Example <alice@...>
[DryRun] Would revoke 'HR.Reader (HR.Reader)' (<assignment-id-2>) and notify Bob Example <bob@...>
[DryRun] Would revoke 'HR.Reader (HR.Reader)' (<assignment-id-3>) and notify Carol Example <carol@...>
```

The role label is resolved from the SP's `AppRoles` collection; the
all-zero GUID is rendered as **Default Access**.

### 5. Run for real

Drop `-DryRun`. `ShouldProcess` is still active, so `-Confirm` will
prompt per user; pass `-Confirm:$false` to run silently.

```powershell
./Revoke-SpAppRoleAssignment.ps1 `
    -ServicePrincipalId <SP-OBJECT-ID> `
    -AppRoleId          <APPROLE-GUID> `
    -NotifyFromUserId   secops@<your-tenant> `
    -Confirm:$false
```

### 6. Verify

Re-run the dry run; you should see "No user assignments found for
AppRoleId ...". Cross-check in the Entra portal:
**Enterprise applications** → app → **Users and groups**.

---

## Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `ServicePrincipalId` | string (GUID) | yes | ObjectId of the target SP. |
| `AppRoleId` | string (GUID) | yes | App role to revoke. `00000000-...` for default access. |
| `NotifyFromUserId` | string | yes | Sender mailbox UPN / ObjectId. |
| `DryRun` | switch | no | Log intended actions only. |
| `WhatIf` / `Confirm` | switch | no | Standard `ShouldProcess` behaviour. |

---

## Behaviour notes

- **Idempotent.** Subsequent runs are no-ops once assignments are gone.
- **Groups are skipped.** The script filters `PrincipalType -eq 'User'`.
  To handle group-based assignments, expand members up front with
  `Get-MgGroupTransitiveMember` and notify them, or revoke the group
  assignment separately.
- **Revoke before notify.** A notification failure is logged but does
  not roll back the revoke (Graph has no transactional API for this).
- **Audit trail.** Pipe `Write-Host` output to a file or change them to
  `Write-Output` and capture the stream into a CSV / Log Analytics
  custom table.

---

## What the email looks like

Each affected user receives an HTML message that includes:

- The application's display name (`$sp.DisplayName`)
- The role that was revoked (e.g. `Default Access`, or
  `HR.Reader (HR.Reader)` for custom roles)
- The tenant ID
- The UTC timestamp

The body lives inside the script in the `$body.message.body.content`
here-string. Edit the wording, add your branding, or swap to a template
file loaded with `Get-Content -Raw`. Variables available out of the box:

- `$user.DisplayName`
- `$sp.DisplayName`
- `$roleName`
- `$ctx.TenantId`
- `[DateTime]::UtcNow`

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `No user assignments found for AppRoleId ...` | Wrong `-AppRoleId` (often a custom GUID where the assignment is on **Default Access**), or wrong `-ServicePrincipalId`. | Confirm the actual role with `Get-MgServicePrincipalAppRoleAssignedTo` (see [Step 2](#2-identify-the-service-principal-and-approle)). For Default Access pass `00000000-0000-0000-0000-000000000000`. |
| `Resource '...' does not exist or one of its queried reference-property objects are not present` (404) | `-ServicePrincipalId` is not an SP Object ID (likely an AppId or App-registration Object ID). | Use the Object ID from the **Enterprise application** Overview blade. |
| `Could not load file or assembly 'Microsoft.Graph.Authentication, Version=2.xx.x.x'. Assembly with same name is already loaded` | Multiple versions of `Microsoft.Graph.*` side-by-side. | Close all pwsh windows. In a fresh session: `Get-Module Microsoft.Graph* -ListAvailable \| Group-Object Name`. Uninstall stale versions (`Uninstall-Module Microsoft.Graph.Authentication -RequiredVersion <old>` or delete the version folder under `~\Documents\PowerShell\Modules`). Then `Install-Module Microsoft.Graph -Scope CurrentUser -Force`. |
| `Access is denied` / 403 `ErrorAccessDenied` on `Send-MgUserMail` (delegated) | The `Mail.Send` scope is missing from the token, **or** the sender UPN has no Exchange Online mailbox. | `Disconnect-MgGraph; Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','Directory.Read.All','User.Read.All','Mail.Send'`. Verify with `(Get-MgContext).Scopes`. If still 403, the mailbox does not exist (common in MCAP / sandbox tenants without an EXO licence) - assign a licence or use a different sender. |
| `ErrorAccessDenied` on `sendMail` (application auth) | Exchange Application Access Policy blocks this sender. | Add the sender to the policy or remove the restriction. Test with `Test-ApplicationAccessPolicy -Identity <upn> -AppId <appid>`. |
| `Insufficient privileges to complete the operation` on revoke | Missing `AppRoleAssignment.ReadWrite.All` or admin consent. | Re-run `Connect-MgGraph` with the scope; grant admin consent on the app registration. |
| `MailboxNotEnabledForRESTAPI` | `NotifyFromUserId` has no Exchange Online mailbox. | Use a licensed mailbox. |
| `Connect-ExchangeOnline` throws `NullReferenceException` (WAM broker) | Bug in older EXO module / Windows broker. | `Update-Module ExchangeOnlineManagement -Force`, or call `Connect-ExchangeOnline -UserPrincipalName <admin-upn> -ShowBanner:$false` to bypass the broker. |
| Notification sent but no revoke logged | Earlier `Remove-Mg...` threw and `continue` triggered; check warnings above. | Re-run; idempotent. |
| `Authorization_RequestDenied` deleting an `oauth2PermissionGrant` | The session lacks `DelegatedPermissionGrant.ReadWrite.All`. | Reconnect with the scope: `Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All','Directory.Read.All','User.Read.All','Mail.Send'`. |
| `No matching API permissions to revoke.` | `-ResourceFilter` or `-Claims` did not match anything on the SP. | Drop the filters or list current permissions first: `Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <sp>` and `Get-MgOauth2PermissionGrant -Filter "clientId eq '<sp>'"`. |
| Email recipients land on the operator instead of expected owners | The SP has no user owners, or owners are groups / other SPs. | Pass `-NotifyTo` explicitly, or assign user owners on the Enterprise application **Owners** blade. |

---

## API permissions held by a SP: `Revoke-SpApiPermissions.ps1`

Use this script when you want to revoke the **API permissions a Service
Principal itself has been granted** — the rows on the SP's
**Permissions** blade in the Entra portal, both **Application** and
**Delegated**.

### What it revokes

| Tab in portal | Graph object | Endpoint used |
|---|---|---|
| Application | `appRoleAssignment` where the SP is the **principal** | `DELETE /servicePrincipals/{sp}/appRoleAssignments/{id}` |
| Delegated | `oauth2PermissionGrant` where the SP is the **client** | `PATCH` (remove some scopes) or `DELETE` (when no scopes remain) on `/oauth2PermissionGrants/{id}` |

For delegated grants the script is granular: if you ask to remove
`Mail.Send` from a grant that also contains `Mail.Read`, it patches the
grant down to `Mail.Read` instead of deleting the whole grant.

### Required Graph scopes

| Scope | Why |
|---|---|
| `AppRoleAssignment.ReadWrite.All` | Delete application permissions. |
| `DelegatedPermissionGrant.ReadWrite.All` | Patch / delete delegated grants. |
| `Directory.Read.All` | Read the target SP and resource SPs. |
| `User.Read.All` | Resolve SP owners to UPN / mail. |
| `Mail.Send` | Send the notification. |

### Step-by-step

1. **Identify the target SP** — same Object ID as the other script
   (Enterprise application Overview → Object ID).
2. **Decide the scope** of revocation:
   - All permissions on the SP: pass only `-ServicePrincipalId`.
   - One API: add `-ResourceFilter 'Microsoft Graph'`.
   - Specific claims: add `-Claims 'AuditLog.Read.All','ServiceHealth.Read.All'`.
   - Limit to one type: add `-PermissionType Application` (or `Delegated`).
3. **Connect:**

   ```powershell
   Connect-MgGraph -Scopes `
       'AppRoleAssignment.ReadWrite.All',
       'DelegatedPermissionGrant.ReadWrite.All',
       'Directory.Read.All',
       'User.Read.All',
       'Mail.Send'
   ```

4. **Dry run** to see exactly what would be revoked and to whom the
   notification would go:

   ```powershell
   ./Revoke-SpApiPermissions.ps1 `
       -ServicePrincipalId <SP-OBJECT-ID> `
       -ResourceFilter     'Microsoft Graph' `
       -Claims             'AuditLog.Read.All','ServiceHealth.Read.All' `
       -NotifyFromUserId   secops@<your-tenant> `
       -DryRun
   ```

   Sample output:

   ```
   Target Service Principal: Contoso Worker (<sp-id>)
   Matched 2 permission(s):

   Kind        Resource         ClaimValue              Display
   ----        --------         ----------              -------
   Application Microsoft Graph  AuditLog.Read.All       Read all audit log data
   Application Microsoft Graph  ServiceHealth.Read.All  Read service health

   [DryRun] Would revoke Microsoft Graph / AuditLog.Read.All [Application]
   [DryRun] Would revoke Microsoft Graph / ServiceHealth.Read.All [Application]
   [DryRun] Would send notification to: owner1@..., owner2@...
   ```

5. **Run for real** (drop `-DryRun`, add `-Confirm:$false` to skip
   per-permission prompts).

6. **Verify** in the portal: SP → **Permissions** → the rows are gone.

### Notification email

One HTML message per script run, with a table summarising every
permission removed:

| Type | API | Claim | Description |
|---|---|---|---|
| Application | Microsoft Graph | `AuditLog.Read.All` | Read all audit log data |
| Application | Microsoft Graph | `ServiceHealth.Read.All` | Read service health |

Plus the tenant ID, SP display name + ObjectId, and the operator
account. Recipients default to the **SP owners**; if the SP has no
owners, the operator (`-NotifyFromUserId`) is notified instead. Override
with `-NotifyTo`.

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `ServicePrincipalId` | string (GUID) | yes | ObjectId of the target SP. |
| `ResourceFilter`    | string        | no  | API display-name substring filter, e.g. `'Microsoft Graph'`. |
| `Claims`            | string[]      | no  | Specific claim values to remove, e.g. `'Mail.Send','User.Read.All'`. |
| `PermissionType`    | string        | no  | `Application`, `Delegated`, or `Both` (default). |
| `NotifyFromUserId`  | string        | yes | Sender mailbox UPN / ObjectId. |
| `NotifyTo`          | string[]      | no  | Override recipients. Default = SP owners, fallback = operator. |
| `DryRun`            | switch        | no  | Log intended actions only. |
| `WhatIf` / `Confirm` | switch       | no  | Standard `ShouldProcess` behaviour. |

### Behaviour notes

- **Idempotent.** Re-runs are no-ops once permissions are gone.
- **Granular delegated revoke.** Removes only the requested scopes from
  a grant, deleting the grant only when it would otherwise be empty.
- **Owner resolution** uses `Get-MgServicePrincipalOwner`. If owners are
  groups or other SPs, they are skipped; only user owners receive the
  email.
- **No mass-revoke surprises.** Calling the script with **no**
  `-ResourceFilter` and **no** `-Claims` revokes **all** API
  permissions on the SP. Always start with `-DryRun`.

---

## File layout

```
Revoke-SpAccess/
├── README.md                          this file
├── New-RevokeSpAccessApp.ps1          bootstrap (unattended runs)
├── Revoke-SpAppRoleAssignment.ps1     revoke users assigned to an app
└── Revoke-SpApiPermissions.ps1        revoke API permissions held by a SP
```

---

## Licence

Same as the parent repository.
