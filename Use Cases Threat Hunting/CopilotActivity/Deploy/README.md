# Microsoft 365 Copilot - ARM deployment

Single-file ARM template that deploys the Microsoft 365 Copilot
detection bundle to an existing Microsoft Sentinel workspace.

## Files

| File | Purpose |
| --- | --- |
| `azuredeploy.json` | Main ARM template - 8 scheduled analytic rules + 7 hunting queries |
| `azuredeploy.parameters.json` | Parameter values (edit `workspaceName` before deploy) |
| `New-CopilotArmTemplate.ps1` | Regenerates `azuredeploy.json` from the YAML sources |

## Parameters

| Name | Type | Default | Notes |
| --- | --- | --- | --- |
| `workspaceName` | string | _required_ | Log Analytics workspace name where Sentinel is enabled |
| `enableAnalyticRules` | bool | `true` | Set to `false` to deploy all scheduled analytic rules in a **disabled** state. Hunting queries are always deployed (they sit in the Hunting blade and produce no alerts until run). |

## What gets deployed

- **8 analytic rules** as `Microsoft.SecurityInsights/alertRules` (kind `Scheduled`) under the workspace - visible in **Sentinel > Analytics**.
- **7 hunting queries** as `Microsoft.OperationalInsights/workspaces/savedSearches` with category `Hunting Queries` - visible in **Sentinel > Hunting**.

## Deploy (Azure CLI)

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file ./azuredeploy.json \
  --parameters workspaceName=<workspace-name> enableAnalyticRules=true
```

To deploy with the analytic rules disabled (hunting queries still go in):

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file ./azuredeploy.json \
  --parameters workspaceName=<workspace-name> enableAnalyticRules=false
```

## Deploy (Azure PowerShell)

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName '<sentinel-rg>' `
  -TemplateFile     './azuredeploy.json' `
  -workspaceName    '<workspace-name>' `
  -enableAnalyticRules $false
```

## Deploy (Azure portal)

1. Portal > **Deploy a custom template** > **Build your own template in the editor**.
2. Paste the content of `azuredeploy.json` and **Save**.
3. Pick the subscription and the resource group containing the Sentinel workspace.
4. Set `workspaceName`, choose **Enable analytic rules** (`true` / `false`), then **Review + create**.

## Pre-requisites

- Microsoft Sentinel enabled on the target Log Analytics workspace.
- The **Microsoft Copilot** data connector enabled so the
  `CopilotActivity` table is populated (otherwise rules will run but
  return no data).
- **`CopilotActivity` table plan must be set to `Analytics`.** The
  Azure Monitor reference page flags the table with "Lake-only
  ingestion: Yes", which is an ingestion-pipeline attribute, **not** a
  tier assignment. Scheduled analytic rules can only query tables on
  the **Analytics** plan; on `Basic` plan KQL is restricted and on
  `Auxiliary` / lake-only plan rules deploy but never fire. Set this
  via **Sentinel > Settings > Table management**, locate
  `CopilotActivity`, plan = `Analytics`.
- For `CopilotRagUntrustedSource` rule: a Sentinel watchlist named
  `CopilotTrustedRagSources` with a `SourceUri` column. The rule will
  treat every retrieval as untrusted if the watchlist is empty - either
  populate it or set `enableAnalyticRules` to `false` first.
- Deployer needs `Microsoft Sentinel Contributor` on the workspace
  resource group.

## Re-generating the template

If you edit any YAML under `..\AnalyticalRules\` or `..\HuntingQueries\`:

```powershell
.\New-CopilotArmTemplate.ps1
```

The script will install `powershell-yaml` for the current user if
missing, then rewrite both `azuredeploy.json` and
`azuredeploy.parameters.json`.
