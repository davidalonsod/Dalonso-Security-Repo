# NetworkAllowlist — IP / CIDR / Range Exclusion

A single Sentinel **watchlist** that every SigninLogs analytic rule and hunting
query consults to suppress false positives from trusted source networks
(corporate egress, VPN concentrators, NAT gateways, test ranges, partner IPs,
etc.).

---

## 1. Watchlist schema

| Column       | Example              | Notes                                                       |
|--------------|----------------------|-------------------------------------------------------------|
| `IPOrRange`  | `166.48.0.0/16`     | **Required.** Single IP, CIDR or `start-end` hyphen range.  |
| `Description`| `Corporate egress`   | Free text — who/what this represents.                       |
| `Owner`      | `SOC`                | Accountable team.                                           |
| `AddedDate`  | `2026-04-20`         | ISO date the entry was added.                               |

Supported `IPOrRange` formats:

- Single IPv4          → `203.0.113.45`
- CIDR subnet          → `10.0.0.0/8`, `163.116.0.0/16`
- Hyphenated range     → `10.20.30.1-10.20.30.50`

IPv6 entries are passed through unchanged (the KQL filter only suppresses IPv4
matches — IPv6 rows are never falsely excluded).

---

## 2. One-time deployment

### Portal
1. Microsoft Sentinel → **Configuration → Watchlists → + New**
2. **Alias:** `NetworkAllowlist`
3. **Search key:** `IPOrRange`
4. Upload `NetworkAllowlist.csv`

### ARM
```powershell
$csv = [Convert]::ToBase64String([IO.File]::ReadAllBytes("NetworkAllowlist.csv"))
New-AzResourceGroupDeployment `
  -ResourceGroupName "sentinel-rg" `
  -TemplateFile      "azuredeploy-watchlist.json" `
  -workspaceName     "CyberSOC" `
  -watchlistItemsBase64 $csv
```

---

## 3. KQL pattern used by rules & hunting queries

Every analytic rule and hunting query embeds this block at the top:

```kql
// ---- Network Allowlist (exclude trusted IPs / CIDR / ranges) ----
let _allow = materialize(
    union isfuzzy=true
        (print R = "" | take 0),
        (_GetWatchlist('NetworkAllowlist') | project R = tostring(IPOrRange))
    | where isnotempty(R));
let _allowCIDR  = toscalar(_allow
    | where R !matches regex @'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$'
    | extend R = iff(R has '/', R, strcat(R, '/32'))
    | summarize make_list(R));
let _allowRange = toscalar(_allow
    | where R matches regex @'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$'
    | summarize make_list(R));
let _ExcludeAllowlistedIPs = (T:(IPAddress:string)) {
    T
    | extend IPAddress = tostring(IPAddress)
    | where array_length(_allowCIDR) == 0
         or isnull(ipv4_is_in_any_range(IPAddress, _allowCIDR))
         or not(ipv4_is_in_any_range(IPAddress, _allowCIDR))
    | mv-apply _r = _allowRange to typeof(string) on (
        extend _lo = tostring(split(_r, '-')[0]),
               _hi = tostring(split(_r, '-')[1])
        | extend _inRange = ipv4_compare(IPAddress, _lo) >= 0
                        and ipv4_compare(IPAddress, _hi) <= 0
        | summarize _anyInRange = max(toint(_inRange)))
    | where isnull(_anyInRange) or _anyInRange == 0
    | project-away _anyInRange
};
```

Applied via:

```kql
SigninLogs
| invoke _ExcludeAllowlistedIPs()
| where TimeGenerated > ago(1h)
| ...
```

- `union isfuzzy=true` → rules don't fail if the watchlist hasn't been created
  yet; behavior gracefully degrades to "no exclusions".
- The UDF works on any table that exposes an `IPAddress` column
  (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `SigninLogs` subsets, etc.).
- Watchlist changes take effect within ~5 min — no rule redeploy needed.

---

## 4. Operational guidance

- **Do not** add threat-intel IOCs here — this list *suppresses* detections.
- Review quarterly. Old egress blocks expire as infra changes.
- For per-rule suppression (e.g. a specific IP only excluded from one rule),
  handle it via Sentinel **Automation rules** instead of this watchlist.

---

## 5. Automated sync from Entra ID **Trusted Named Locations**

`Sync-NamedLocationsToWatchlist.ps1` (in `Analytic-Rules/`) pulls every
`ipNamedLocation` from Microsoft Graph where `isTrusted=true`, flattens each
CIDR into its own row, and replaces the items in the `NetworkAllowlist`
watchlist via the Sentinel REST API. Run it manually or on a schedule
(Task Scheduler / cron / GitHub Actions / Azure Automation Runbook).

> **Why DELETE-then-recreate, item-by-item?**
> Sentinel's `PUT /watchlists/{alias}` with bulk `rawContent` (CSV body) is
> unreliable: on existing watchlists it updates the definition but does not
> replace items, and even on fresh creates the CSV parser silently drops the
> header on some tenants/regions. The script therefore:
> 1. `DELETE`s the existing watchlist (if any), polling until 404.
> 2. `PUT`s a bare definition (no `rawContent`).
> 3. `PUT`s each row individually to `/watchlistItems/{guid}`.
>
> This is slower (one HTTP call per row) but is the only path that reliably
> populates items across tenants.

### 5.1 Recommended auth: **Service Principal** (no MFA prompt, CI-friendly)

User accounts often hit Conditional Access "Require MFA for Azure
management" (app GUID `797f4846-ba00-4fd7-ba43-dac1f8f63013`) which blocks
non-interactive scenarios. A dedicated SP avoids this entirely.

#### Required permissions

| Surface | Permission | Permission ID | Type |
|---|---|---|---|
| Microsoft Graph | `Policy.Read.All` | `246dd0d5-5bd0-4def-940b-0421030a5b68` | Application (admin-consent) |
| Azure RBAC | `Microsoft Sentinel Contributor` | — | Scope: workspace's **resource group** |

If your tenant enforces a **Workload Identities** Conditional Access policy
on service principals, ask your IT admin to exclude this SP from it.

#### Create + grant in one shot

```powershell
$tenantId = '<your-tenant-guid>'
$subId    = '<your-sub-guid>'
$rg       = '<workspace-rg>'
$spName   = 'sentinel-namedlocation-sync-sp'

# 1) Create SP (returns appId + password — store securely; do NOT commit)
$sp = az ad sp create-for-rbac --name $spName --skip-assignment --years 1 | ConvertFrom-Json
$appId  = $sp.appId
$secret = $sp.password

# 2) Graph application permission: Policy.Read.All
az ad app permission add --id $appId --api 00000003-0000-0000-c000-000000000000 `
    --api-permissions 246dd0d5-5bd0-4def-940b-0421030a5b68=Role
az ad app permission admin-consent --id $appId

# 3) Azure RBAC on the workspace's resource group
az role assignment create --assignee $appId `
    --role "Microsoft Sentinel Contributor" `
    --scope "/subscriptions/$subId/resourceGroups/$rg"
```

> ⚠️ **Never commit the client secret.** Store it in Key Vault, GitHub Actions
> Secrets, Azure DevOps variable groups, or a local password manager. Pass it
> to the script via parameter (preferably read from `$env:` at runtime).

#### Verify the SP can mint tokens

```powershell
$body = @{
    client_id     = $appId
    client_secret = $secret
    grant_type    = 'client_credentials'
    scope         = 'https://graph.microsoft.com/.default'
}
$r = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -Body $body
"OK — token len: $($r.access_token.Length)"
```

### 5.2 Run the script with the SP

```powershell
# Read secret from env / Key Vault — never hard-code
$secret = $env:SENTINEL_SYNC_SP_SECRET

.\Analytic-Rules\Sync-NamedLocationsToWatchlist.ps1 `
    -WatchlistAlias  NetworkAllowlist `
    -SubscriptionId  '<sub-guid>' `
    -ResourceGroup   '<workspace-rg>' `
    -WorkspaceName   '<workspace-name>' `
    -TenantId        '<tenant-guid>' `
    -ClientId        '<sp-appId>' `
    -ClientSecret    $secret
```

When all three of `-TenantId / -ClientId / -ClientSecret` are supplied, the
script:

- Skips the interactive `az login` flow entirely.
- Mints tokens via `client_credentials` grant against
  `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` with scope
  `https://graph.microsoft.com/.default` and `https://management.azure.com/.default`.
- Uses those tokens for all Graph reads and the ARM PUT.

### 5.3 Fallback: interactive user auth

Omit `-ClientId/-ClientSecret` and the script falls back to `az login` (interactive
browser). This requires the user to clear the MFA challenge and have
`Microsoft Sentinel Contributor` on the workspace RG and `Policy.Read.All`
delegated.

### 5.4 Scheduling

| Platform | Notes |
|---|---|
| **Windows Task Scheduler** | Run `pwsh.exe -File Sync-NamedLocationsToWatchlist.ps1 ...`. Pull `$secret` from Windows Credential Manager. |
| **GitHub Actions** | Store secret as `SENTINEL_SYNC_SP_SECRET`. Use `azure/login@v2` or pass directly. |
| **Azure Automation Runbook** | Use a Run-As SP or Managed Identity with the same permissions instead of a stored secret. |
| **Azure Function (timer)** | Same as Automation; prefer **System-assigned Managed Identity** + RBAC. |

### 5.5 Observed propagation lag

The PUT returns `provisioningState=Succeeded` immediately, but the materialized
backing table that `_GetWatchlist('NetworkAllowlist')` queries lags:

| Watchlist size | Typical lag |
|---|---|
| < 100 rows | 2–5 min |
| 100–1 000 rows | 5–10 min |
| 10 000+ rows | up to 30 min |

To verify the control-plane state immediately (bypassing the lag):

```powershell
az rest --method get --url ("https://management.azure.com/subscriptions/$subId" +
    "/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws" +
    "/providers/Microsoft.SecurityInsights/watchlists/NetworkAllowlist/watchlistItems" +
    "?api-version=2024-09-01") --query "value | length(@)"
```



---

### 5.3 Scheduled execution: **Azure Automation Runbook + Managed Identity** (recommended)

For unattended daily sync with no secrets to rotate, run the script as a
PowerShell 7.2 runbook in an Azure Automation Account using its
**system-assigned managed identity**.

Bicep template provided: `Watchlists/azuredeploy-automation.bicep`. It creates:

- Automation Account (`Basic` SKU, free for runbook minutes used here)
- System-assigned managed identity on the account
- Empty `Sync-NamedLocationsToWatchlist` runbook (PowerShell 7.2)
- Daily schedule (configurable via `scheduleHours`)
- Job-schedule linkage with the right parameters (uses `-UseManagedIdentity`)
- `Microsoft Sentinel Contributor` role on this resource group for the MI

#### Deploy

```powershell
$rg            = '<workspace-rg>'
$workspaceName = '<sentinel-workspace>'

az deployment group create `
    -g $rg `
    --template-file ./Analytic-Rules/Watchlists/azuredeploy-automation.bicep `
    --parameters workspaceName=$workspaceName watchlistAlias=NetworkAllowlist
```

#### Post-deploy (3 commands)

```powershell
$acct = 'aa-sentinel-sync'
$rb   = 'Sync-NamedLocationsToWatchlist'

# 1. Upload the script body
az automation runbook replace-content `
    -g $rg --automation-account-name $acct -n $rb `
    --content @./Analytic-Rules/Sync-NamedLocationsToWatchlist.ps1

# 2. Publish (draft -> published)
az automation runbook publish -g $rg --automation-account-name $acct -n $rb

# 3. Grant the MI Microsoft Graph Policy.Read.All (admin-consent app role)
$miOid     = (az deployment group show -g $rg -n azuredeploy-automation `
                --query "properties.outputs.managedIdentityPrincipalId.value" -o tsv)
$graphSpId = (az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv)
$permId    = '246dd0d5-5bd0-4def-940b-0421030a5b68'  # Policy.Read.All (Application)
az rest --method POST `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$miOid/appRoleAssignments" `
    --headers "Content-Type=application/json" `
    --body (@{principalId=$miOid; resourceId=$graphSpId; appRoleId=$permId} | ConvertTo-Json)
```

Granting the Graph app role requires you to be a tenant **Privileged Role
Administrator** (or higher) — same prerequisite as SP admin-consent.

#### Trigger immediately (optional)

```powershell
az automation runbook start -g $rg --automation-account-name $acct -n $rb
```

Output appears in the Automation Account → Runbooks → Jobs blade. The
`Microsoft Sentinel Contributor` role takes ~1–2 min to propagate, so the
first run may need to be retried if it fires before that.

#### Why managed identity beats SP for this workload

| Concern | SP | Managed Identity |
|---|---|---|
| Secret rotation | required (~12 months) | none |
| Secret storage | Key Vault / GH Secrets | n/a |
| Tenant boundary | works cross-tenant | same tenant only |
| CA "Workload Identities" exemption | often needed | often pre-exempt |
| Local dev | easy | only works inside Azure compute |

Use SP for local dev / GitHub Actions; use MI for the production scheduled run.

cd C:\Users\dalonso\SigninLogs-ThreatHunting
$rg   = 'RG_sentinel'
$acct = 'aa-sentinel-sync'
$rb   = 'Sync-NamedLocationsToWatchlist'

# Sanity check
az --version | Select-Object -First 1
az account show --query name -o tsv

# Upload
$content = Get-Content -Raw -LiteralPath .\Analytic-Rules\Sync-NamedLocationsToWatchlist.ps1
az automation runbook replace-content -g $rg --automation-account-name $acct -n $rb --content $content
az automation runbook publish        -g $rg --automation-account-name $acct -n $rb

az account set --subscription "<sub-name-or-id>"
az account show --query "{name:name, id:id}" -o table
