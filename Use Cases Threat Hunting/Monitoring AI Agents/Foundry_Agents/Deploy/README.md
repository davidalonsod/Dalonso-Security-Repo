# Deploy - Foundry-AppInsights bundle

ARM template for the Foundry / Application Insights guardrail detections:
**36 scheduled analytic rules + 21 hunting queries + 3 watchlists**.

| File | Purpose |
| --- | --- |
| `azuredeploy.json` | Main ARM template - 36 analytic rules + 21 hunting queries (`savedSearches`) + three watchlists |
| `azuredeploy.parameters.json` | Parameter values (edit `workspaceName` before deploy) |
| `New-FoundryArmTemplate.ps1` | Regenerates `azuredeploy.json` from the YAML sources |

## Parameters

| Name | Type | Default | Notes |
| --- | --- | --- | --- |
| `workspaceName` | string | _required_ | Log Analytics workspace where Sentinel is enabled **and** the Foundry Application Insights telemetry is exported (e.g. `LAWSentinel`) |
| `enableAnalyticRules` | bool | `true` | Set to `false` to deploy the analytic rules disabled. Hunting queries always deploy. |
| `enableWatchlist` | bool | `true` | Set to `false` to skip all bundled watchlists. Allowlist-based rules depend on their corresponding watchlists. |

## Deploy (Azure CLI)

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file ./azuredeploy.json \
  --parameters workspaceName=<workspace-name> enableAnalyticRules=true
```

## Deploy (Azure PowerShell)

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName '<sentinel-rg>' `
  -TemplateFile     './azuredeploy.json' `
  -workspaceName    '<workspace-name>' `
  -enableAnalyticRules $true
```

## Pre-requisites

- Microsoft Sentinel enabled on the target workspace.
- Foundry project Application Insights **connected and workspace-based**,
  exporting to the **same** workspace named in `workspaceName`, so the
  `AppDependencies` table is populated.
- Content recording enabled
  (`OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`, or the
  language-specific equivalent) for approved prompt / response matching.
- `AppGenAIContent` configured as a protected table; analysts who inspect
  content need `Privileged Monitoring Data Reader`. New rules return
  metadata only.
- Deployer needs `Microsoft Sentinel Contributor` on the workspace
  resource group.

## Re-generating the template

After editing YAML, watchlist data, or generator logic:

```powershell
.\New-FoundryArmTemplate.ps1
```

It installs `powershell-yaml` for the current user if missing, then
rewrites both `azuredeploy.json` and `azuredeploy.parameters.json`.

The repository does not currently include a Foundry simulation harness.
Validate KQL against an approved nonproduction workspace and use ARM
what-if or validation before deployment.
