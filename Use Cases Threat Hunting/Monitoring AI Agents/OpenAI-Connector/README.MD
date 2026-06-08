# OpenAI-Connector bundle (native CCF connector)

Independent, deployable-today bundle of Microsoft Sentinel detections for
the **OpenAI** Codeless Connector (CCF). Everything here targets the
**Analytics-tier** tables the connector and its parsers expose:

- `OpenAIAuditLogs` (alias over `OpenAIAuditLogs_CL`) - org audit events.
- `OpenAIChatCompletions` / `ASimAgentEventLogs` - runtime request /
  completion events with `ModelName`, `InputTokensUsed`,
  `OutputTokensUsed`, `ToolName`, `AdditionalFields.input_user`.


## Contents

| Folder | Contents |
| --- | --- |
| `AnalyticalRules/` | 6 scheduled analytic rules (YAML) |
| `HuntingQueries/` | 3 hunting queries (YAML) |
| `Deploy/` | ARM template + generator (`New-OpenAiArmTemplate.ps1`) |

### Analytic rules

| File | Severity | OpenAI signal |
| --- | --- | --- |
| `AnalyticalRules/OpenAITokenCostSpike.yaml` | Medium | `InputTokensUsed`/`OutputTokensUsed` spike vs 7-day per-model median |
| `AnalyticalRules/OpenAIOrgConfigOverride.yaml` | High | Org settings / logging / retention / SSO / role changes |
| `AnalyticalRules/OpenAIConfigToAbuseChain.yaml` | High | Privileged config / credential change then a content-filter block within 24h (same actor) |
| `AnalyticalRules/OpenAIToolUsageDrift.yaml` | Medium | New `ToolName` first use per user vs 14-day baseline |
| `AnalyticalRules/OpenAIRedTeamPacingAnomaly.yaml` | Medium | Low-variance request pacing (PyRIT / DeepTeam / fuzzers) |
| `AnalyticalRules/OpenAISensitiveToolInvocation.yaml` | High | `ToolName` matches the shared `AzureAI_SensitiveTools` watchlist |

### Hunting queries

| File | OpenAI signal |
| --- | --- |
| `HuntingQueries/OpenAIOffHoursOrGeoAnomaly.yaml` | Off-hours / new-country org login via `ActorSession.ip_address` + `geo_info_from_ip_address()` |
| `HuntingQueries/OpenAICredentialSprawlAnomaly.yaml` | API-key / service-account / project / invite bursts by previously-quiet actors |
| `HuntingQueries/OpenAITraceLevelAnomalies.yaml` | Tight tool-call loops / >2-min request duration |

---

## Deploy

```powershell
# (re)build the template from the YAML sources
.\Deploy\New-OpenAiArmTemplate.ps1

# deploy (Azure CLI)
az deployment group create `
  --resource-group <sentinel-rg> `
  --template-file ./Deploy/azuredeploy.json `
  --parameters workspaceName=<workspace-name> enableAnalyticRules=true
```

Full parameters, prerequisites and the watchlist requirement are in
[`Deploy/README.md`](./Deploy/README.md).

---

## Pre-requisites

- Microsoft Sentinel enabled on the target workspace.
- The **OpenAI** connector (`Azure-Sentinel/Solutions/OpenAI`) enabled
  with parsers installed, so `OpenAIAuditLogs` / `OpenAIChatCompletions`
  resolve.
- `OpenAIAuditLogs_CL` and `ASimAgentEventLogs` on the **Analytics**
  table plan.
- For `OpenAISensitiveToolInvocation`: a Sentinel watchlist named
  `AzureAI_SensitiveTools` (column `ToolName`), shared with the
  `AzureAI-ThreatHunting` pack.

> **Actor join caveat**: `ASimAgentEventLogs` has no first-class user
> column. Per-user rules key on `AdditionalFields.input_user` (the
> OpenAI `user` request parameter). If callers do not set it, baseline on
> `ModelName` alone or promote the API-key id instead.
