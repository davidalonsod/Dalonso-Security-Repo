# Deploy - CopilotStudio-AppInsights bundle

ARM template for the Copilot Studio / Application Insights detections:
**28 scheduled analytic rules + 16 hunting queries + 2 watchlists**.

| File | Purpose |
| --- | --- |
| `azuredeploy.json` | Main ARM template - analytic rules + hunting queries (`savedSearches`) + the `CopilotStudioTrustedConnectors` / `CopilotStudioAgentMap` watchlists |
| `azuredeploy.parameters.json` | Parameter values (edit `workspaceName` before deploy) |
| `New-CopilotStudioArmTemplate.ps1` | Regenerates `azuredeploy.json` from the YAML sources |

## Parameters

| Name | Type | Default | Notes |
| --- | --- | --- | --- |
| `workspaceName` | string | _required_ | Log Analytics workspace where Sentinel is enabled **and** the Copilot Studio Application Insights telemetry is exported (e.g. `SentinelPurview`) |
| `enableAnalyticRules` | bool | `true` | Enables rules whose YAML `enabled` value is true. A YAML rule set to false remains disabled. Hunting queries always deploy. |
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
- For full MCP trace detections, configure **environment-level Copilot
  Studio telemetry export** in a managed environment. This emits
  `InvokeAgent` / `ExecuteTool` spans and `gen_ai.tool.*`; initial delivery
  can take up to 24 hours.
- **Log sensitive properties** enabled on the agent for the text-content
  rules (prompt injection, sensitive output / input, system-prompt
  disclosure, jailbreak), with new conversations generated afterwards.
- Deployer needs `Microsoft Sentinel Contributor` on the workspace
  resource group.
- Populate `CopilotStudioTrustedConnectors` before enabling
  `CopilotStudioUntrustedMcpTarget`. The rule is disabled by default.

## Re-generating the template

After editing any YAML under `../AnalyticalRules/` or `../HuntingQueries/`:

```powershell
.\New-CopilotStudioArmTemplate.ps1
```

It installs `powershell-yaml` for the current user if missing, then
rewrites both `azuredeploy.json` and `azuredeploy.parameters.json`.
