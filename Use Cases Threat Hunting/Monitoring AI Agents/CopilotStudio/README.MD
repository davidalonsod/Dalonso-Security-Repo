# CopilotStudio-AppInsights bundle (Application Insights telemetry)

Independent, deployable-today bundle of Microsoft Sentinel **analytic
rules** and **hunting queries** for **Microsoft Copilot Studio** agent
runtime telemetry. Everything here reads the real trace shape that
Copilot Studio emits to Application Insights and exports to the Sentinel
workspace:

- Tables: **`AppEvents`** (bot turns) and **`AppDependencies`**
  (connector / action calls), exported from the agent's workspace-based
  Application Insights into the Sentinel workspace (e.g.
  `SentinelPurview`).
- Property bag: **`Properties`** (the dynamic column - *not*
  `customDimensions`, because the resource is workspace-based).
- AppEvents keys: `Name` is `BotMessageReceived` (user -> bot) or
  `BotMessageSend` (bot -> user); `Properties` carries `conversationId`,
  `channelId`, `locale`, `DesignMode`, and `text` (the message body, only
  populated when **Log sensitive properties** is enabled on the agent's
  Application Insights settings).
- AppDependencies keys: `DependencyType == "Connector"`,
  `AppRoleName == "Microsoft Copilot Studio"`, with `Name` (connector
  display name), `Target` (operation, e.g. `shared_msnweather/...`),
  `Success`, `ResultCode`, `DurationMs`.

This bundle is structured as a sibling of `../Foundry-AppInsights/`
(which reads the Foundry `AppDependencies` / `gen_ai.*` span shape) but
is fully independent of it.

> **Identity note**: Copilot Studio telemetry has no human-user field in
> the basic event shape; the runtime `UserId` is the bot/agent identifier
> (e.g. `pva-studio<botid>`). The rules pivot on that `UserId`, the
> `conversationId`, the `channelId`, and the client IP. The
> `CopilotStudioAgentMap` watchlist maps those `UserId` values to friendly
> agent names.

---

## Contents

| Folder | Contents |
| --- | --- |
| `AnalyticalRules/` | 19 scheduled analytic rules (YAML) |
| `HuntingQueries/` | 12 hunting queries (YAML) |
| `Watchlists/` | `CopilotStudioTrustedConnectors` (approved connector targets) and `CopilotStudioAgentMap` (bot UserId -> agent name) |
| `Deploy/` | ARM template + generator (`New-CopilotStudioArmTemplate.ps1`) |

### Analytic rules

| File | Severity | Signal | MITRE ATT&CK | Source |
| --- | --- | --- | --- | --- |
| `AnalyticalRules/CopilotStudioPromptInjectionPatterns.yaml` | Medium | Instruction-override / prompt-injection markers in user message | InitialAccess T1566, DefenseEvasion T1562 | `AppEvents` `BotMessageReceived.text` |
| `AnalyticalRules/CopilotStudioSensitiveDataInResponse.yaml` | High | Secrets / bulk-PII (AWS key, private key, JWT, emails) in agent response | Exfiltration T1567, Collection T1213 | `AppEvents` `BotMessageSend.text` |
| `AnalyticalRules/CopilotStudioSecretsInUserMessage.yaml` | High | Secrets / bulk-PII pasted into the user prompt | CredentialAccess T1552, Collection T1213 | `AppEvents` `BotMessageReceived.text` |
| `AnalyticalRules/CopilotStudioSystemPromptDisclosure.yaml` | High | User asks for instructions and the response leaks instruction markers | Discovery T1082, Collection T1213 | `AppEvents` in/out join on `conversationId` |
| `AnalyticalRules/CopilotStudioConnectorErrorStorm.yaml` | Medium | >=10 failed connector calls in one conversation (enumeration / loop) | Discovery T1046, Impact T1499 | `AppDependencies` `Success == false` |
| `AnalyticalRules/CopilotStudioNewConnectorFirstSeen.yaml` | Medium | A connector target never seen in the 14-day baseline is invoked | Execution T1059, Persistence T1554 | `AppDependencies` `Target` |
| `AnalyticalRules/CopilotStudioSensitiveConnectorInvocation.yaml` | Medium | High-impact connector (mail / http / sql / azure / sharepoint) invoked | Execution T1059, LateralMovement T1648 | `AppDependencies` `Name`/`Target` |
| `AnalyticalRules/CopilotStudioConversationFloodingDoW.yaml` | Medium | Abnormal inbound message volume per session / conversation (denial-of-wallet) | Impact T1499 | `AppEvents` `BotMessageReceived` |
| `AnalyticalRules/CopilotStudioOffHoursActivity.yaml` | Low | Published-channel activity outside business hours | InitialAccess T1078 | `AppEvents` + `hourofday()` |
| `AnalyticalRules/CopilotStudioJailbreakOrModelProbing.yaml` | Medium | Jailbreak persona / unrestricted-mode / model-fingerprinting markers | DefenseEvasion T1562, Discovery T1082 | `AppEvents` `BotMessageReceived.text` |
| `AnalyticalRules/CopilotStudioPrivilegeEscalationClaim.yaml` | Medium | Authority / role-impersonation claim ("I'm the CFO", "as an admin") | PrivilegeEscalation T1548, InitialAccess T1078 | `AppEvents` `BotMessageReceived.text` |
| `AnalyticalRules/CopilotStudioBulkDataExfiltrationIntent.yaml` | Medium | Bulk-retrieval intent ("show all", "export all", "dump the table") | Collection T1213, Exfiltration T1530 | `AppEvents` `BotMessageReceived.text` |
| `AnalyticalRules/CopilotStudioMultiStageAttackChain.yaml` | High | >=2 distinct attack stages (inject / escalate / exfil / jailbreak) in one conversation, with connector context | InitialAccess T1566, PrivilegeEscalation T1078, Exfiltration T1567 | `AppEvents` + `AppDependencies` join on `conversationId` |
| `AnalyticalRules/CopilotStudioAsciiSmugglingInjection.yaml` | Medium | Invisible-Unicode smuggling (Tag block / zero-width / bidi override) in user prompt | DefenseEvasion T1027, InitialAccess T1566 | `AppEvents` `BotMessageReceived.text` |
| `AnalyticalRules/CopilotStudioSuspiciousUrlInContent.yaml` | High | Phishing / malicious URL heuristics (raw-IP, punycode, shortener, bait path) in prompt or response | InitialAccess T1566, Execution T1204 | `AppEvents` `BotMessageReceived` / `BotMessageSend` |
| `AnalyticalRules/CopilotStudioThreatIntelUrlMatch.yaml` | High | URL / domain / IP in prompt or response matched against active Sentinel threat-intel indicators | CommandAndControl T1071, InitialAccess T1566 | `AppEvents` + `ThreatIntelIndicators` join |
| `AnalyticalRules/CopilotStudioGoalDriftBetweenTurns.yaml` | Medium | Benign opening message + no sensitive intent vocabulary, yet >=3 sensitive connector calls in same conversation | Execution T1059, DefenseEvasion T1556 | `AppEvents` + `AppDependencies` join on `conversationId` |
| `AnalyticalRules/CopilotStudioCapabilityDisclosureExtended.yaml` | Medium | Connector / action / topic probe AND response reflects >=2 actual connector prefixes from the 7-day inventory | Discovery T1213, Discovery T1518 | `AppEvents` in/out + baseline `AppDependencies` `Target` |
| `AnalyticalRules/CopilotStudioSessionContextContamination.yaml` | Medium | First-quartile external URL or injection marker AND later sensitive connector call in same conversation (>=5 turns) | InitialAccess T1566, Execution T1059 | `AppEvents` quartiles + `AppDependencies` |

> The text-content rules (prompt injection, sensitive output / input,
> system-prompt disclosure, jailbreak) only fire when **Log sensitive
> properties** is enabled on the agent (Settings -> Advanced ->
> Application Insights), which populates `Properties.text`. The
> connector and volume rules work from metadata alone.

### Hunting queries

| File | Signal | Source |
| --- | --- | --- |
| `HuntingQueries/AgentConversationVolumeByUser.yaml` | Busiest users / sessions / channels | `AppEvents` |
| `HuntingQueries/AgentConnectorBaselineDeviation.yaml` | New or spiking connector vs 14-day baseline | `AppDependencies` |
| `HuntingQueries/AgentConnectorErrorStorm.yaml` | High connector-failure rate by conversation | `AppDependencies` |
| `HuntingQueries/AgentSensitiveResponseContent.yaml` | Secret / bulk-PII content in responses (broad) | `AppEvents` `BotMessageSend.text` |
| `HuntingQueries/AgentPromptInjectionSignals.yaml` | Prompt-injection markers ranked by count (broad) | `AppEvents` `BotMessageReceived.text` |
| `HuntingQueries/AgentChannelDistribution.yaml` | Channel mix + new-channel first seen | `AppEvents` `channelId` |
| `HuntingQueries/AgentDormancyBreak.yaml` | Connector silent >=7 days then reactivates | `AppDependencies` |
| `HuntingQueries/AgentResponseLatencyAnomaly.yaml` | Connector latency anomaly (`series_decompose_anomalies`) | `AppDependencies` `DurationMs` |
| `HuntingQueries/AgentUntrustedConnectorTarget.yaml` | Connector target not on the trusted allowlist | `AppDependencies` + watchlist |
| `HuntingQueries/AgentTopicTriggerEnumeration.yaml` | Many distinct non-message events in one conversation | `AppEvents` (topic / generative events) |
| `HuntingQueries/AgentIndirectInjectionInResponse.yaml` | Injection markers in agent output that the user never typed (poisoned-data / indirect injection) | `AppEvents` in/out compare on `conversationId` |
| `HuntingQueries/AgentToolAbuseBreadth.yaml` | Wide connector fan-out or destructive operation verbs in one conversation | `AppDependencies` `Target` |

The analytic rules alert on the highest-fidelity / high-severity subset
(incidents); the hunts surface the full picture including low / medium
severity for proactive review. The rules' `enabled` flag is bound to the
`enableAnalyticRules` deployment parameter.

> **Table-plan note**: scheduled analytic rules can only read tables on
> the **Analytics** plan. Confirm `AppEvents` and `AppDependencies` are on
> the Analytics plan in the target workspace (they are by default). The
> hunting queries work regardless.

### Watchlists

Two watchlists ship with the bundle (under `Watchlists/<alias>/`, each a
`watchlist.json` definition plus a seed `data.csv`). They are deployed by
the ARM template when `enableWatchlist` is `true` (default).

| Alias | Search key | Purpose | Consumed by |
| --- | --- | --- | --- |
| `CopilotStudioTrustedConnectors` | `ConnectorTarget` | Allowlist of approved connector / action **target prefixes** | `HuntingQueries/AgentUntrustedConnectorTarget.yaml` (leftanti join - anything not on the list is flagged untrusted) |
| `CopilotStudioAgentMap` | `BotId` | Maps each agent's runtime `UserId` to a friendly agent name and ownership metadata | Enrichment / friendly-name lookup; hook for future cross-table correlation hunts |

#### `CopilotStudioTrustedConnectors`

Columns and seed rows (`Watchlists/CopilotStudioTrustedConnectors/data.csv`):

| Column | Meaning | Example |
| --- | --- | --- |
| `ConnectorTarget` | Lowercase target prefix exactly as it appears in the `AppDependencies` `Target` column (the part before the first `/`), or the full operation path | `shared_msnweather` |
| `ConnectorName` | Human-friendly connector name | `MSN Weather` |
| `Description` | Why it is approved / who owns it | `Approved mail connector` |

Seed rows: `shared_msnweather`, `shared_office365`, `shared_office365users`.

> **Populate before relying on the hunt.** While the list holds only the
> three seed rows, the `AgentUntrustedConnectorTarget` hunt treats every
> other connector as untrusted and will be noisy. Add a row for each
> connector your agents are approved to call. To find the prefixes in use,
> run:
>
> ```kql
> AppDependencies
> | where AppRoleName == "Microsoft Copilot Studio" or DependencyType == "Connector"
> | extend TargetPrefix = tolower(tostring(split(Target, "/")[0]))
> | summarize Calls = count() by TargetPrefix
> | order by Calls desc
> ```

#### `CopilotStudioAgentMap`

Columns and seed row (`Watchlists/CopilotStudioAgentMap/data.csv`):

| Column | Meaning | Example |
| --- | --- | --- |
| `BotId` | The value seen in the `AppEvents` `UserId` column (e.g. `pva-studio<botid>`) | `pva-studioc09d8629-...` |
| `AgentName` | Friendly agent name | `TestCopilotAgent` |
| `Environment` | Copilot Studio environment / team | `PurviewSpainTeam` |
| `AppId` | Optional Entra app (client) ID the agent acts under | _(blank)_ |
| `ObjectId` | Optional Entra service-principal object ID | _(blank)_ |
| `Owner` | Owning team / person | _(blank)_ |
| `Description` | Free-text note | `Seed example - replace with your agents` |

> Replace the single seed row with one row per agent you operate. `BotId`
> is the join key against `AppEvents.UserId`, so it must match exactly.

### Attack -> detection mapping

How the detections line up with the common Copilot Studio attack classes:

| Attack class | Analytic rule(s) | Hunting query(ies) |
| --- | --- | --- |
| Direct prompt injection | `CopilotStudioPromptInjectionPatterns` | `AgentPromptInjectionSignals` |
| Indirect / poisoned-data injection | - | `AgentIndirectInjectionInResponse` |
| Data exfiltration (bulk intent + bulk content) | `CopilotStudioBulkDataExfiltrationIntent`, `CopilotStudioSensitiveDataInResponse` | `AgentSensitiveResponseContent` |
| Secrets pasted into prompt | `CopilotStudioSecretsInUserMessage` | - |
| Privilege escalation (role impersonation) | `CopilotStudioPrivilegeEscalationClaim` | - |
| Tool abuse / action manipulation | `CopilotStudioSensitiveConnectorInvocation`, `CopilotStudioNewConnectorFirstSeen` | `AgentToolAbuseBreadth`, `AgentUntrustedConnectorTarget`, `AgentConnectorBaselineDeviation`, `AgentDormancyBreak` |
| System-prompt extraction | `CopilotStudioSystemPromptDisclosure` | - |
| Jailbreak / safety bypass | `CopilotStudioJailbreakOrModelProbing` | - |
| Enumeration / denial-of-wallet | `CopilotStudioConnectorErrorStorm`, `CopilotStudioConversationFloodingDoW` | `AgentConnectorErrorStorm`, `AgentConversationVolumeByUser`, `AgentTopicTriggerEnumeration` |
| Combined multi-stage chain | `CopilotStudioMultiStageAttackChain` | - |
| Anomalous / off-hours behaviour | `CopilotStudioOffHoursActivity` | `AgentChannelDistribution`, `AgentResponseLatencyAnomaly` |

### Microsoft AI Red Team v2.0 taxonomy coverage

Three rules port the applicable subset of the Microsoft AI Red Team v2.0
failure-mode taxonomy
(<https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/>)
to the Copilot Studio `AppEvents` / `AppDependencies` shape:

| v2.0 failure mode | Rule |
| --- | --- |
| Goal Hijacking | `CopilotStudioGoalDriftBetweenTurns` |
| Capability / Architecture Disclosure | `CopilotStudioCapabilityDisclosureExtended` (+ `CopilotStudioSystemPromptDisclosure`) |
| Session Context Contamination | `CopilotStudioSessionContextContamination` |

The remaining v2.0 categories do **not** port because the telemetry does
not exist in Copilot Studio's runtime exports: there is no consent /
human-in-the-loop approval field (HitL bypass), no MCP server / tool-
description metadata (MCP abuse, supply-chain description poisoning), no
persistent-memory spans (memory poisoning), and no computer-use
observation surface (CUA visual attack). These are covered in the sibling
`../Foundry-AppInsights/` bundle where the `gen_ai.*` / `mcp.*` span
shape carries the needed keys.

---

## Prerequisites

1. **Microsoft Sentinel** enabled on the target Log Analytics workspace.
2. The agent's **Application Insights** resource is **workspace-based**
   and points at the **same** workspace named in `workspaceName`, so the
   `AppEvents` / `AppDependencies` tables are populated. (In Copilot
   Studio: Settings -> Advanced -> Application Insights -> paste the
   workspace-based resource's **Connection string**.)
3. **Enable logging** turned on for the agent; **Log sensitive
   properties** enabled if you want the text-content rules to fire
   (otherwise `Properties.text` is empty and those rules stay silent).
4. Some conversations generated **after** the above, so there is data to
   read.
5. Deployer needs **Microsoft Sentinel Contributor** on the workspace
   resource group.

## Deploy

```powershell
# (re)build the template from the YAML sources
.\Deploy\New-CopilotStudioArmTemplate.ps1

# deploy (Azure CLI)
az deployment group create `
  --resource-group <sentinel-rg> `
  --template-file ./Deploy/azuredeploy.json `
  --parameters workspaceName=<workspace-name> enableAnalyticRules=true enableWatchlist=true
```

Full details in [`Deploy/README.md`](./Deploy/README.md).

> **Watchlist**: the `AgentUntrustedConnectorTarget` hunt joins against
> the `CopilotStudioTrustedConnectors` watchlist (column
> `ConnectorTarget`). The ARM template deploys it from
> `Watchlists/CopilotStudioTrustedConnectors/` (toggle with the
> `enableWatchlist` parameter, default true). Replace the seed rows with
> your approved connector target prefixes **before** relying on that hunt
> - while the watchlist only has seed rows the join treats every other
> connector as untrusted and the hunt will be noisy.
