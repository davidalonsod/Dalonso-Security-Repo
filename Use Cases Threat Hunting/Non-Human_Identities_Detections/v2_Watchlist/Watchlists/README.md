# NetworkAllowlist — Trusted IP / CIDR / Range exclusion

A single Sentinel **watchlist** consumed by every WorkloadIdentities analytic
rule and hunting query in this repo to suppress false positives from trusted
source networks (corporate egress, VPN concentrators, NAT gateways, partner
IPs, etc.).

The watchlist itself is created by the main ARM template
(`ARM-Template/WorkloadIdentities-Detections.json`). This folder adds the
**automation** that keeps it in sync with **trusted Entra Named Locations**.

---

## 1. Watchlist schema

| Column        | Example              | Notes                                                       |
|---------------|----------------------|-------------------------------------------------------------|
| `IPOrRange`   | `166.48.0.0/16`     | **Required.** Single IP, CIDR or `start-end` hyphen range.  |
| `Name`        | `Corporate egress`   | Source Named Location display name.                         |
| `Description` | `synced from NL`     | Free text.                                                  |

Supported `IPOrRange` formats:

- Single IPv4          → `203.0.113.45`
- CIDR subnet          → `10.0.0.0/8`, `163.116.0.0/16`
- Hyphenated range     → `10.20.30.1-10.20.30.50`

IPv6 entries pass through unchanged; the `ExcludeAllowlistedIPs` function only
suppresses IPv4 matches.

---

## 2. Sync script — `Sync-NamedLocationsToWatchlist.ps1`

Pulls all `ipNamedLocation` entries from Microsoft Graph where `isTrusted=true`,
flattens each CIDR range into its own row, and re-creates the watchlist items
via the Sentinel REST API (`DELETE` watchlist → `PUT` empty definition → loop
`PUT` per item). The per-item POST loop is required because Sentinel rejects
quoted CSV headers in `rawContent` bulk uploads.

### Auth modes

| Mode | When to use |
|---|---|
| **Service Principal** (`-TenantId / -ClientId / -ClientSecret`) | Recommended for unattended runs |
| **Managed Identity** (`-UseManagedIdentity`) | Inside Azure Automation / Function / VM, **only** if your tenant doesn't block workload identities via CA |
| **Interactive `az`** | Local dev only (interactive MFA) |

### Required permissions for the SP

| Surface | Permission | Permission ID | Type |
|---|---|---|---|
| Microsoft Graph | `Policy.Read.All` | `246dd0d5-5bd0-4def-940b-0421030a5b68` | Application (admin-consent) |
| Azure RBAC | `Microsoft Sentinel Contributor` | — | Scope: workspace **resource group** |

### Create + grant in one shot

```powershell
$tenantId = '<your-tenant-guid>'
$subId    = '<your-sub-guid>'
$rg       = '<workspace-rg>'
$spName   = 'sentinel-namedlocation-sync-sp'

$sp = az ad sp create-for-rbac --name $spName --skip-assignment --years 1 | ConvertFrom-Json
$appId  = $sp.appId
$secret = $sp.password

az ad app permission add --id $appId --api 00000003-0000-0000-c000-000000000000 `
    --api-permissions 246dd0d5-5bd0-4def-940b-0421030a5b68=Role
az ad app permission admin-consent --id $appId

az role assignment create --assignee $appId `
    --role "Microsoft Sentinel Contributor" `
    --scope "/subscriptions/$subId/resourceGroups/$rg"
```

> **Never commit the client secret.** Store it in Key Vault, GitHub Actions
> Secrets, or pass via `$env:` at runtime.

### Manual run

```powershell
$secret = $env:SENTINEL_SYNC_SP_SECRET

.\Watchlists\Sync-NamedLocationsToWatchlist.ps1 `
    -WatchlistAlias  NetworkAllowlist `
    -SubscriptionId  '<sub-guid>' `
    -ResourceGroup   '<workspace-rg>' `
    -WorkspaceName   '<workspace-name>' `
    -TenantId        '<tenant-guid>' `
    -ClientId        '<sp-appId>' `
    -ClientSecret    $secret
```

---

## 3. Scheduled execution: **Azure Automation Runbook + Service Principal** (recommended)

For unattended daily sync, run the script as a PowerShell 7.2 runbook in an
Azure Automation Account. **Use a service principal**, not a managed identity:
in tenants whose Conditional Access enforces MFA on workload identities,
managed identities are blocked by `RequestDisallowedByAzure` and cannot be
exempted without **Workload Identities Premium**. Service principals are not
affected by that policy and run with no extra licensing.

Bicep template provided: `Watchlists/azuredeploy-automation.bicep`. It creates:

- Automation Account (`Basic` SKU)
- System-assigned managed identity on the account (unused in SP mode but harmless)
- Empty `Sync-NamedLocationsToWatchlist` runbook (PowerShell 7.2)
- Daily schedule (configurable via `scheduleHours`)
- Encrypted Automation Variable `SpClientSecret` (when `authMode=SP`)
- Job-schedule linkage with the right parameters
- `Microsoft Sentinel Contributor` role on this resource group for the MI

### Deploy (two passes)

The Bicep deploys in two passes because Azure rejects linking a job schedule
to a runbook that has no published content yet.

```powershell
$rg            = '<workspace-rg>'
$workspaceName = '<workspace-name>'
$tenant        = '<tenant-id>'
$clientId      = '<sp-app-id>'
$secret        = Read-Host -AsSecureString 'SP client secret' | ConvertFrom-SecureString -AsPlainText

# Pass 1: Account + runbook (empty) + schedule + encrypted SpClientSecret variable.
az deployment group create -g $rg `
    --template-file ./Watchlists/azuredeploy-automation.bicep `
    --parameters workspaceName=$workspaceName watchlistAlias=NetworkAllowlist `
                 authMode=SP spTenantId=$tenant spClientId=$clientId spClientSecret=$secret
```

### Upload + publish runbook content via `az rest`

The `az automation` CLI extension is flaky on Windows; pure REST is reliable.

```powershell
$sub  = az account show --query id -o tsv
$ps1  = Resolve-Path .\Watchlists\Sync-NamedLocationsToWatchlist.ps1
$base = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Automation/automationAccounts/aa-sentinel-sync/runbooks/Sync-NamedLocationsToWatchlist"

az rest --method put `
    --url "$base/draft/content?api-version=2023-11-01" `
    --headers "Content-Type=text/powershell" `
    --body "@$ps1"

az rest --method post `
    --url "$base/publish?api-version=2023-11-01"
```

### Pass 2: link the schedule

```powershell
az deployment group create -g $rg `
    --template-file ./Watchlists/azuredeploy-automation.bicep `
    --parameters workspaceName=$workspaceName watchlistAlias=NetworkAllowlist `
                 authMode=SP spTenantId=$tenant spClientId=$clientId spClientSecret=$secret `
                 linkJobSchedule=true
```

The job-schedule parameters include `TenantId` and `ClientId` (plain text —
not sensitive), but **not** the secret. The runbook reads the secret at runtime
from the encrypted `SpClientSecret` Automation Variable.

### Trigger immediately (optional)

Portal: Automation Account → Runbooks → `Sync-NamedLocationsToWatchlist` →
**Start**. Override parameters to:

- `WatchlistAlias`   = `NetworkAllowlist`
- `SubscriptionId`   = your subscription ID
- `ResourceGroup`    = workspace RG
- `WorkspaceName`    = workspace name
- `TenantId`         = your tenant ID
- `ClientId`         = SP app ID

Leave `ClientSecret` and `UseManagedIdentity` empty. The script auto-resolves
the secret from the encrypted variable.

### Rotating the SP secret

Re-run pass 1 with the new `spClientSecret` value. The Bicep updates the
encrypted Automation Variable in place; no code changes needed.

### SP vs managed identity for this workload

| Concern | Service Principal | Managed Identity |
|---|---|---|
| Secret rotation | required (~12 months) | none |
| Secret storage | encrypted Automation Variable | n/a |
| Tenant boundary | cross-tenant supported | same tenant only |
| Blocked by CA "MFA for workload identities" | not affected | requires Workload Identities Premium to exempt |
| Local dev / GitHub Actions | works | not available |

**Use SP** when CA targets workload identities and you don't have Workload
Identities Premium. **Use MI** when the tenant has no such CA policy and you
want zero-secret operation — set `authMode=MI` (default) and omit the SP
parameters; the runbook then runs with `-UseManagedIdentity`.

---

## 4. Observed propagation lag

The PUT returns `provisioningState=Succeeded` immediately, but the materialized
backing table that `_GetWatchlist('NetworkAllowlist')` queries lags:

| Watchlist size | Typical lag |
|---|---|
| < 100 rows | 2–5 min |
| 100–1 000 rows | 5–10 min |
| 10 000+ rows | up to 30 min |

To verify the control-plane state immediately:

```powershell
az rest --method get --url ("https://management.azure.com/subscriptions/$subId" +
    "/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws" +
    "/providers/Microsoft.SecurityInsights/watchlists/NetworkAllowlist/watchlistItems" +
    "?api-version=2024-09-01") --query "value | length(@)"
```
