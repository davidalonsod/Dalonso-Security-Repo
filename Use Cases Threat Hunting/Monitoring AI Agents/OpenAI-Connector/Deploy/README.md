# Deploy - OpenAI-Connector bundle

ARM template for the OpenAI CCF-connector detections. Targets
**Analytics-tier** tables (`OpenAIAuditLogs_CL`, `ASimAgentEventLogs`)
and ships as a conventional ARM template.

The OpenAI-connector detections under `../AnalyticalRules/` and
`../HuntingQueries/` (ported from the sibling Microsoft 365 Copilot
pack) deploy independently of the `../../Foundry-AppInsights/` bundle.

| File | Purpose |
| --- | --- |
| `azuredeploy.json` | Main ARM template - 6 scheduled analytic rules + 3 hunting queries |
| `azuredeploy.parameters.json` | Parameter values (edit `workspaceName` before deploy) |
| `New-OpenAiArmTemplate.ps1` | Regenerates `azuredeploy.json` from the YAML sources |

### Parameters

| Name | Type | Default | Notes |
| --- | --- | --- | --- |
| `workspaceName` | string | _required_ | Log Analytics workspace name where Sentinel is enabled |
| `enableAnalyticRules` | bool | `true` | Set to `false` to deploy the analytic rules disabled. Hunting queries always deploy. |

### Deploy (Azure CLI)

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file ./azuredeploy.json \
  --parameters workspaceName=<workspace-name> enableAnalyticRules=true
```

### Deploy (Azure PowerShell)

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName '<sentinel-rg>' `
  -TemplateFile     './azuredeploy.json' `
  -workspaceName    '<workspace-name>' `
  -enableAnalyticRules $false
```

### Pre-requisites

- Microsoft Sentinel enabled on the target workspace.
- The **OpenAI** connector (`Azure-Sentinel/Solutions/OpenAI`) enabled
  with its parsers installed, so the `OpenAIAuditLogs` /
  `OpenAIChatCompletions` aliases resolve (the queries fail to compile
  otherwise).
- `OpenAIAuditLogs_CL` and `ASimAgentEventLogs` on the **Analytics**
  table plan (scheduled rules cannot read Basic / Auxiliary / lake-only
  tables). Set via **Sentinel > Settings > Table management**.
- For `OpenAISensitiveToolInvocation`: a Sentinel watchlist named
  `AzureAI_SensitiveTools` (column `ToolName`). This is **shared** with
  the `AzureAI-ThreatHunting` pack so the high-risk tool list lives in
  one place; the rule fires nothing until it is populated.
- Deployer needs `Microsoft Sentinel Contributor` on the workspace
  resource group.

### Re-generating the template

After editing any YAML under `../AnalyticalRules/` or
`../HuntingQueries/`:

```powershell
.\New-OpenAiArmTemplate.ps1
```

It installs `powershell-yaml` for the current user if missing, then
rewrites both `azuredeploy.json` and `azuredeploy.parameters.json`.
