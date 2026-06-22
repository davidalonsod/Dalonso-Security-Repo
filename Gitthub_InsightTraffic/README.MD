# GitHub Traffic to Microsoft Sentinel

Snapshot a GitHub repository's **Traffic** metrics into a Microsoft Sentinel
(Log Analytics) custom table once per day, so you can build **1-year trend
charts** in an Azure Workbook.

GitHub only retains **14 days** of Traffic data and exposes referrers / popular
content only as a **rolling 14-day total**. By taking a daily snapshot and
storing it in Sentinel, you keep history for as long as your table retention
allows (this solution sets 730 days).

---

## What you get

| Metric | Source (GitHub API) | Stored as `MetricType` |
| --- | --- | --- |
| Clones (total + unique, per day) | `/traffic/clones` | `clones` |
| Views (total + unique, per day) | `/traffic/views` | `views` |
| Referring sites | `/traffic/popular/referrers` | `referrer` |
| Popular content | `/traffic/popular/paths` | `path` |
| Stars | `/repos/{owner}/{repo}` | `stars` |
| Forks | `/repos/{owner}/{repo}` | `forks` |
| Watchers | `/repos/{owner}/{repo}` | `watchers` |

The workbook visualises daily/monthly/yearly trends for clones and views,
side-by-side **30-day vs 1-year** panels for referrers and popular content, and
tiles + a trend line for stars / forks / watchers.

---

## Architecture

```text
GitHub Traffic API ──(daily)──> PowerShell script ──> Logs Ingestion API
                                                          │
                                            Data Collection Endpoint (DCE)
                                                          │
                                            Data Collection Rule (DCR)
                                                          │
                                            GitHubTraffic_CL  (Sentinel table)
                                                          │
                                                   Azure Workbook
```

A daily GitHub Actions workflow logs in to Azure with **OIDC** (no stored Azure
secrets), requests a short-lived Azure Monitor token, then runs the PowerShell
script which pulls the Traffic metrics and posts them to the DCE.

---

## Files

| File | Purpose |
| --- | --- |
| `Deploy-GitHubTrafficTable.bicep` | Creates the `GitHubTraffic_CL` table, DCE and DCR. |
| `Send-GitHubTrafficToSentinel.ps1` | Pulls Traffic metrics and posts them to the DCE. |
| `github-traffic-to-sentinel.yml` | Daily GitHub Actions workflow (place at `.github/workflows/`). |
| `Workbook-GitHubTraffic.json` | Azure Workbook for visualising the data. |

---

## Prerequisites

- An existing **Log Analytics / Microsoft Sentinel** workspace.
- Permission to create resources (DCE/DCR) and assign roles in the resource
  group that holds the workspace.
- A **GitHub PAT** (classic, `repo` scope) for an account with **admin** on the
  monitored repository - Traffic data is only readable by repo admins.
- Azure PowerShell **or** Azure CLI for the one-off deployment.

---

## Setup

### 1. Deploy the table, DCE and DCR

```powershell
# Azure PowerShell
New-AzResourceGroupDeployment `
  -ResourceGroupName '<your-resource-group>' `
  -TemplateFile      './Deploy-GitHubTrafficTable.bicep' `
  -workspaceName     '<your-workspace-name>'
```

Note the deployment outputs - you'll need them later:

- `dceLogsIngestionUri` -> used as `DCE_ENDPOINT`
- `dcrImmutableId` -> used as `DCR_IMMUTABLE_ID`
- `dcrResourceId` -> used for the role assignment below

### 2. Create the Entra app + federated credential (OIDC)

Create an app registration and add a **federated credential** for the workflow
so GitHub Actions can log in without a stored secret:

- **Subject** (branch example): `repo:<owner>/<repo>:ref:refs/heads/main`
- **Issuer**: `https://token.actions.githubusercontent.com`
- **Audience**: `api://AzureADTokenExchange`

### 3. Grant the app permission to ingest

Assign **Monitoring Metrics Publisher** to the app on the DCR:

```powershell
New-AzRoleAssignment `
  -ApplicationId '<app-client-id>' `
  -RoleDefinitionName 'Monitoring Metrics Publisher' `
  -Scope '<dcrResourceId-from-step-1>'
```

> Running the script **locally** instead? Grant the same role to your own
> signed-in identity (`-ObjectId <your-object-id>`) on the same DCR scope, or
> you'll get a `403 Forbidden` from the ingestion endpoint.

### 4. Add the workflow + secrets to the monitored repo

Copy `github-traffic-to-sentinel.yml` to `.github/workflows/` in the repository
you want to monitor, then add:

**Secrets**

| Name | Value |
| --- | --- |
| `GH_TRAFFIC_PAT` | Classic PAT, `repo` scope, repo admin. |
| `AZURE_CLIENT_ID` | App registration (client) ID. |
| `AZURE_TENANT_ID` | Entra tenant ID. |
| `AZURE_SUBSCRIPTION_ID` | Subscription ID. |

**Variables**

| Name | Value |
| --- | --- |
| `DCE_ENDPOINT` | Bicep output `dceLogsIngestionUri`. |
| `DCR_IMMUTABLE_ID` | Bicep output `dcrImmutableId`. |
| `TARGET_REPOSITORY` | `owner/repo` to monitor. |

> **Why `GH_TRAFFIC_PAT` and not `GITHUB_TOKEN`?** `GITHUB_TOKEN` is a reserved
> name in GitHub Actions - the runner injects its own token, which cannot read
> Traffic. The workflow and script therefore use `GH_TRAFFIC_PAT` (with
> `GH_PAT` / `GITHUB_TOKEN` accepted as local fallbacks).

### 5. Run it

Trigger the workflow manually (**Actions -> GitHub Traffic to Sentinel -> Run
workflow**) for the first snapshot, then let the daily schedule (06:00 UTC)
take over. Data appears in `GitHubTraffic_CL` within a few minutes.

### 6. Import the workbook

Azure portal -> **Microsoft Sentinel -> Workbooks -> Add workbook -> Edit ->
Advanced Editor (`</>`)** -> paste the contents of `Workbook-GitHubTraffic.json`
-> **Apply -> Save**. Pick your repo in the **Repository** dropdown.

---

## Run the script locally (optional)

```powershell
# Acquire an Azure Monitor token (Azure CLI shown; Az PowerShell also works)
$env:AZURE_MONITOR_TOKEN = (az account get-access-token `
  --resource 'https://monitor.azure.com' --query accessToken -o tsv)
$env:GH_TRAFFIC_PAT = '<your-github-pat>'

./Send-GitHubTrafficToSentinel.ps1 `
  -Repository     '<owner>/<repo>' `
  -DceEndpoint    '<dceLogsIngestionUri>' `
  -DcrImmutableId '<dcrImmutableId>'
```

---

## Table schema (`GitHubTraffic_CL`)

| Column | Type | Notes |
| --- | --- | --- |
| `TimeGenerated` | datetime | Day the metric corresponds to. |
| `RepoFullName` | string | `owner/repo`. |
| `MetricType` | string | `clones`, `views`, `referrer`, `path`, `stars`, `forks`, `watchers`. |
| `Dimension` | string | Referrer site (`referrer`) or content path (`path`); empty otherwise. |
| `Title` | string | Page title for `path` rows; empty otherwise. |
| `Count` | int | Total count. |
| `Uniques` | int | Unique count (visitors / cloners). |

---

## Notes & limitations

- **Duplicate per-day points** are expected because overlapping 14-day windows
  re-report the same days. De-duplicate at query time in KQL (e.g.
  `summarize ... by bin(TimeGenerated, 1d)` taking `max()`), as the workbook does.
- **Referrers / popular content** are only available as a **rolling 14-day
  total** with no per-day breakdown, so a true cumulative 30-day or 1-year total
  can't be reconstructed. The workbook's 30-day and 1-year panels show the
  **peak 14-day total** observed in each window; they read the same until you've
  accumulated more than 14 days of history.
- The PAT must belong to a **repo admin** - non-admins get `403` from the
  Traffic endpoints.

---

## Security

- **No long-lived Azure secrets**: the workflow authenticates with OIDC.
- The Azure Monitor token is masked in workflow logs.
- The only stored secret is the GitHub PAT (`GH_TRAFFIC_PAT`); scope it to
  `repo` only and rotate it periodically.
- The ingestion identity holds just **Monitoring Metrics Publisher** on the
  single DCR - no broader access.
