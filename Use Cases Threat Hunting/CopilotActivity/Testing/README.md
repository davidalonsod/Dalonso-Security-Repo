# Testing the Microsoft 365 Copilot detection bundle

This folder contains a reproducible test harness that stands up the
full detection bundle in a fresh Azure environment so you can exercise
the 11 analytic rules + 3 hunting queries end-to-end.

## What gets created

| Component | Resource |
| --- | --- |
| Resource group | (you choose) |
| Log Analytics workspace | (you choose) |
| Microsoft Sentinel | onboarded on the workspace |
| `CopilotActivity` table plan | set to **Analytics** (90-day retention) |
| `CopilotTrustedRagSources` watchlist | seeded from `Watchlists/CopilotTrustedRagSources.csv` |
| `CopilotApprovedPlugins` watchlist | seeded from `Watchlists/CopilotApprovedPlugins.csv` |
| 11 scheduled analytic rules + 3 hunting queries | from `..\Deploy\azuredeploy.json` |

See [`..\Docs\Coverage-Limits.md`](../Docs/Coverage-Limits.md) for what
this bundle does **not** detect (everything that requires raw prompt /
response text, output classifiers, delegation lineage, or per-call
status codes) and why.

## Prerequisites

**On your workstation**

- PowerShell 7+
- Az modules: `Az.Accounts`, `Az.Resources`, `Az.OperationalInsights`,
  `Az.SecurityInsights`, `Az.Monitor`
  ```powershell
  Install-Module Az.Accounts, Az.Resources, Az.OperationalInsights, Az.SecurityInsights, Az.Monitor -Scope CurrentUser
  ```
- `Connect-AzAccount` already run.

**In the target tenant**

- Subscription where you have **Contributor** (the script creates the RG,
  workspace, Sentinel onboarding, watchlist, rules).
- A Microsoft 365 tenant with **Microsoft 365 Copilot** licensed for at
  least one test user. The Microsoft Copilot data connector requires
  this; the `CopilotActivity` table only materialises once the
  connector is enabled and one Copilot session has happened.

## End-to-end procedure

### 1. Run the bootstrap

```powershell
pwsh .\Deploy-TestEnvironment.ps1 `
    -SubscriptionId    '<sub-guid>' `
    -ResourceGroupName 'rg-copilot-test' `
    -WorkspaceName     'la-copilot-test' `
    -Location          'westeurope'
```

Expected output: each `==> step` followed by `OK:` or, for the table
plan, a `WARN:` if the connector isn't enabled yet.

### 2. Enable the Microsoft Copilot data connector (manual)

This step has to happen in the portal because the connector requires
admin consent on a Microsoft Graph permission.

1. Azure portal -> Microsoft Sentinel -> select your workspace.
2. **Content management > Content hub** -> search for **Microsoft Copilot**
   (sometimes listed as "Microsoft 365 Copilot" or "Copilot for
   Microsoft 365"). Install the solution.
3. **Configuration > Data connectors** -> open the Microsoft Copilot
   connector -> click **Connect** / **Configure** and grant the consent
   prompt.
4. Generate one Copilot session from a test user (Word, Teams, or
   Copilot Chat) so the table is created.
5. Confirm in **Sentinel > Logs**:
   ```kusto
   CopilotActivity | take 5
   ```
   If the table now exists, re-run the bootstrap script to apply the
   Analytics plan:
   ```powershell
   pwsh .\Deploy-TestEnvironment.ps1 -SubscriptionId '<sub>' -ResourceGroupName 'rg-copilot-test' -WorkspaceName 'la-copilot-test' -Location 'westeurope'
   ```
   This time the "Setting CopilotActivity table plan to Analytics" step
   will succeed.

### 3. Validate the deploy

```powershell
# Rules
Get-AzSentinelAlertRule -ResourceGroupName rg-copilot-test -WorkspaceName la-copilot-test |
    Where-Object { $_.DisplayName -like 'Microsoft 365 Copilot -*' } |
    Select-Object DisplayName, Severity, Enabled, Kind

# Hunting queries (savedSearches)
Get-AzOperationalInsightsSavedSearch -ResourceGroupName rg-copilot-test -WorkspaceName la-copilot-test |
    Where-Object { $_.Properties.Category -eq 'Hunting Queries' } |
    Select-Object @{n='Name';e={$_.Properties.DisplayName}}, @{n='Tactics';e={($_.Properties.Tags | Where-Object name -eq 'tactics').value}}
```

You should see 11 alert rules and 3 saved searches.

### 4. Exercise the rules

See [`Test-Scenarios.md`](./Test-Scenarios.md) for per-rule recipes
(what to do in Copilot, what to query in the workspace to confirm the
rule fired).

### 5. Tear down

```powershell
Remove-AzResourceGroup -Name rg-copilot-test -Force
```

This deletes the workspace, Sentinel, watchlist, and rules in one go.

## Re-running

`Deploy-TestEnvironment.ps1` is idempotent:

- RG / workspace / Sentinel onboarding are skipped if they exist.
- Table plan PATCH is a no-op if it's already on Analytics.
- Watchlist is skipped if `CopilotTrustedRagSources` or
  `CopilotApprovedPlugins` already exists (delete via
  `Remove-AzSentinelWatchlist` if you want to re-seed).
- ARM deploy is incremental; rules get updated in place.

## Adapting to your own environment

| You want to ... | Edit |
| --- | --- |
| Seed your real trusted RAG sources | `Watchlists\CopilotTrustedRagSources.csv` (column `SourceUri` is required, others are descriptive) |
| Seed your approved Copilot plugins | `Watchlists\CopilotApprovedPlugins.csv` (column `PluginName` is required, must match `LLMEventData.AISystemPlugin[].Name`) |
| Deploy rules disabled | Pass `-EnableAnalyticRules $false` to `Deploy-TestEnvironment.ps1` |
| Use a different workspace name / region | Pass different `-WorkspaceName` / `-Location` |
| Deploy into an existing workspace | Pass its RG + name; the script reuses them |
