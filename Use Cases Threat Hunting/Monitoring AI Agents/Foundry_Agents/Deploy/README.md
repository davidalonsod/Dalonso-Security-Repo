# Deploy - Foundry-AppInsights bundle

ARM template for the Foundry / Application Insights guardrail detections:
**21 scheduled analytic rules + 17 hunting queries + 2 watchlists**.

| File | Purpose |
| --- | --- |
| `azuredeploy.json` | Main ARM template - 21 analytic rules + 17 hunting queries (`savedSearches`) + the `FoundryTrustedToolSources` / `AgentIdentityMap` watchlists |
| `azuredeploy.parameters.json` | Parameter values (edit `workspaceName` before deploy) |
| `New-FoundryArmTemplate.ps1` | Regenerates `azuredeploy.json` from the YAML sources |

## Parameters

| Name | Type | Default | Notes |
| --- | --- | --- | --- |
| `workspaceName` | string | _required_ | Log Analytics workspace where Sentinel is enabled **and** the Foundry Application Insights telemetry is exported (e.g. `LAWSentinel`) |
| `enableAnalyticRules` | bool | `true` | Set to `false` to deploy the analytic rules disabled. Hunting queries always deploy. |
| `enableWatchlist` | bool | `true` | Set to `false` to skip the `FoundryTrustedToolSources` watchlist (e.g. if you manage it separately). The untrusted-tool-source rule depends on it. |

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
  (`AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true`) for prompt /
  response text, with new conversations generated afterwards.
- Deployer needs `Microsoft Sentinel Contributor` on the workspace
  resource group.

## Re-generating the template

After editing any YAML under `../HuntingQueries/`:

```powershell
.\New-FoundryArmTemplate.ps1
```

It installs `powershell-yaml` for the current user if missing, then
rewrites both `azuredeploy.json` and `azuredeploy.parameters.json`.

## Generating test data

Use `../Simulation/` to drive guardrail test prompts at a deployment so
these hunts have rows to find. See `../Simulation/README.md`.
