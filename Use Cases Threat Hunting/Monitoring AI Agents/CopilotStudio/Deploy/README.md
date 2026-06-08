# Deploy - CopilotStudio-AppInsights bundle

ARM template for the Copilot Studio / Application Insights detections:
**16 scheduled analytic rules + 12 hunting queries + 2 watchlists**.

| File | Purpose |
| --- | --- |
| `azuredeploy.json` | Main ARM template - analytic rules + hunting queries (`savedSearches`) + the `CopilotStudioTrustedConnectors` / `CopilotStudioAgentMap` watchlists |
| `azuredeploy.parameters.json` | Parameter values (edit `workspaceName` before deploy) |
| `New-CopilotStudioArmTemplate.ps1` | Regenerates `azuredeploy.json` from the YAML sources |

## Parameters

| Name | Type | Default | Notes |
| --- | --- | --- | --- |
| `workspaceName` | string | _required_ | Log Analytics workspace where Sentinel is enabled **and** the Copilot Studio Application Insights telemetry is exported (e.g. `SentinelPurview`) |
| `enableAnalyticRules` | bool | `true` | Set to `false` to deploy the analytic rules disabled. Hunting queries always deploy. |
| `enableWatchlist` | bool | `true` | Set to `false` to skip the watchlists (e.g. if you manage them separately). The untrusted-connector hunt depends on `CopilotStudioTrustedConnectors`. |

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
- Copilot Studio agent Application Insights **connected and
  workspace-based**, exporting to the **same** workspace named in
  `workspaceName`, so the `AppEvents` / `AppDependencies` tables are
  populated.
- **Log sensitive properties** enabled on the agent for the text-content
  rules (prompt injection, sensitive output / input, system-prompt
  disclosure, jailbreak), with new conversations generated afterwards.
- Deployer needs `Microsoft Sentinel Contributor` on the workspace
  resource group.

## Re-generating the template

After editing any YAML under `../AnalyticalRules/` or `../HuntingQueries/`:

```powershell
.\New-CopilotStudioArmTemplate.ps1
```

It installs `powershell-yaml` for the current user if missing, then
rewrites both `azuredeploy.json` and `azuredeploy.parameters.json`.
