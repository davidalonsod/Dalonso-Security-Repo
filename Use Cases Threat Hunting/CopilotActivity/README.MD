# Microsoft 365 Copilot - Microsoft Sentinel detection content

Microsoft Sentinel custom analytical rules and hunting queries that
monitor Microsoft 365 Copilot activity via the `CopilotActivity` table
delivered by the Microsoft Copilot data connector.


## Contents

### Analytical rules - `AnalyticalRules/` (11 rules)

| File | Severity | Coverage | Tactics | Techniques |
| --- | --- | --- | --- | --- |
| `CopilotAccessDriftDetection.yaml` | Medium | 14-day baseline per agent of tools / resources, alerts on new resources in the last hour | PrivilegeEscalation, Discovery | T1098, T1087 |
| `CopilotConfigToAbuseChain.yaml` | High | Admin config change (settings / plugin / prompt-book) followed within 24h by Prompt-Shield jailbreak, XPIA verdict, or DLP hit by the same actor / agent | Persistence, DefenseEvasion, Execution | T1098, T1556, T1059 |
| `CopilotExfiltrationPattern.yaml` | High | Single thread combines sensitive-resource hit (DLP) + many distinct grounding sites + large multi-document synthesis | Collection, Exfiltration | T1213, T1530, T1567 |
| `CopilotIndirectPromptInjection.yaml` | High | Native XPIA classifier flag on `LLMEventData.AccessedResources[].XPIADetected` | InitialAccess, Execution | T1566, T1059 |
| `CopilotJailbreakAttemptDetection.yaml` | High | Known jailbreak personas (DAN / DUDE / STAN / developer mode), safety overrides, system-prompt disclosure | DefenseEvasion, InitialAccess, Execution | T1562, T1059 |
| `CopilotRagUntrustedSource.yaml` | Medium | RAG grounding from a source not in the `CopilotTrustedRagSources` watchlist | InitialAccess, DefenseEvasion | T1195, T1199 |
| `CopilotRedTeamPacingAnomaly.yaml` | Medium | Pacing fingerprint of automated red-team / fuzzing frameworks (PyRIT, DeepTeam, custom adversarial scripts) | Discovery, Impact | T1526, T1499 |
| `CopilotResourceDiversityBurst.yaml` | Medium | Sudden burst in distinct grounding-source breadth per user in a 1h window (cross-department reconnaissance) | Discovery, Collection | T1087, T1213, T1083 |
| `CopilotSensitiveDataExposure.yaml` | High | Sensitivity labels / classifiers match Confidential / Restricted / PII / PCI lists | Collection, Exfiltration | T1530, T1213, T1567 |
| `CopilotSystemPromptOverride.yaml` | High | Admin config changes, model swaps, system-prompt edits, runtime override attempts | DefenseEvasion, Persistence | T1562, T1098 |
| `CopilotTokenCostSpike.yaml` | Medium | Last-hour token usage > 3x agent's 7-day per-hour median (token abuse, runaway loops, wallet drain) | Impact | T1496, T1499 |

### Hunting queries - `HuntingQueries/` (14 queries)

| File | Coverage | Tactics | Techniques |
| --- | --- | --- | --- |
| `CopilotAbnormalToolUsage.yaml` | 14-day vs 1-day tool-mix delta, sensitive-tool first use, 5x spikes | Execution, PrivilegeEscalation | T1059, T1098 |
| `CopilotAdversarialParaphraseLoop.yaml` | Refusal signal followed by >= 3 paraphrased prompts from same actor in 15min (jailbreak refinement loop) | DefenseEvasion, InitialAccess | T1059, T1204 |
| `CopilotBiasOrPiiInOutput.yaml` | Email / phone / IBAN / PAN regex + bias keywords in agent responses | Collection, Exfiltration | T1530, T1213 |
| `CopilotCrossTenantGuestLeak.yaml` | Conversations mixing internal grounding sources with external-tenant guest participants | Exfiltration, Collection | T1567, T1213 |
| `CopilotDelegationChainAnomaly.yaml` | Conversations with >= 3 agents in chain, cross-tenant / cross-user delegations | LateralMovement, Discovery | T1078, T1087 |
| `CopilotGroundingSourceEnumeration.yaml` | Unusually diverse set of grounding sources per user in a short window (RAG port-scan) | Discovery, Collection | T1083, T1213 |
| `CopilotHallucinationAndQualityDrift.yaml` | Low model confidence, contradiction markers, hallucination admission, non-existent citations | Impact | T1496 |
| `CopilotJailbreakMultiTurnHunting.yaml` | 3-step escalation: benign -> roleplay -> policy-bypass per conversation | DefenseEvasion, InitialAccess | T1562, T1059 |
| `CopilotMemoryContextPoisoning.yaml` | Custom-instruction / memory writes by non-owner actors and downstream influence on unrelated chats | Persistence, DefenseEvasion | T1546, T1556 |
| `CopilotOffHoursOrGeoAnomaly.yaml` | Sessions outside actor's normal business hours or from a country not seen in 30 days | InitialAccess, DefenseEvasion | T1078, T1078.004 |
| `CopilotPluginInstallAnomaly.yaml` | New plugin / connector / declarative-agent installs by previously-quiet actors or at burst rate | Persistence, PrivilegeEscalation | T1098, T1505 |
| `CopilotPromptInjectionPatterns.yaml` | Injection markers + base64 data-URI in prompts and tool inputs | InitialAccess, Execution | T1059, T1204 |
| `CopilotSensitivityLabelDowngrade.yaml` | Highly-classified RAG grounding -> output sent to lower-trust surface (external, public site, guest chat) | Exfiltration, Collection | T1530, T1213 |
| `CopilotTraceLevelAnomalies.yaml` | Long traces, tight tool loops (>= 10 calls / 5 min), low tool diversity | Impact, Execution | T1499, T1059 |

Both folders also contain a `Parked/` subdirectory holding earlier
drafts that the deployment pipeline explicitly excludes.

---

## Deploy summary

The current ARM template at [`Deploy/azuredeploy.json`](./Deploy/azuredeploy.json)
ships **25 resources** (11 analytic + 14 hunting). It is rebuilt by:

```pwsh
pwsh -NoProfile -File .\Deploy\New-CopilotArmTemplate.ps1
```

which reads every active YAML in `AnalyticalRules/` and
`HuntingQueries/` (skipping `Parked/`) and emits ARM resources plus a
matching `azuredeploy.parameters.json`.

---

## Data model assumptions

These rules target the `CopilotActivity` table populated by the
Microsoft Copilot data connector for Microsoft Sentinel. The column
references below were inherited from the original Agent 365 draft and
remain **partially speculative** - validate them against your tenant's
actual `CopilotActivity` schema before promoting to production.

- **Table**: `CopilotActivity` (Microsoft Copilot connector; AI workload audit).
- **Connector ID** in `requiredDataConnectors`: `MicrosoftCopilot`.
- **Required table plan: `Analytics`.** The Azure Monitor reference
  page flags `CopilotActivity` with **"Lake-only ingestion: Yes"** -
  that is a *capability* attribute (the connector writes via the
  data-lake ingestion pipeline), **not** a tier assignment. The actual
  query tier is controlled by the table plan you set in
  **Sentinel > Settings > Table management**:
  - `Analytics` (required for this bundle) - scheduled analytic rules
    and Sentinel hunting `savedSearches` can query it.
  - `Basic` - only KQL Basic Logs queries; scheduled rules will not run.
  - `Auxiliary` / lake-only - rules deploy but never fire because the
    rule engine cannot read auxiliary-plan data. Defender-portal
    Advanced Hunting can still query it.

  Before enabling the rules in a new workspace, open Sentinel > Settings
  > Table management, locate `CopilotActivity`, and set the plan to
  `Analytics`.

### Confirmed `CopilotActivity` columns

- `TimeGenerated`, `RecordType` (string), `AgentId`, `AgentName`,
  `ActorName`, `TenantId`, `LLMEventData` (dynamic).
- `LLMEventData` subfields confirmed: `Response`, `Prompt`,
  `AISystemPlugin[]`, `RagSources`, `ResponseConfidence`,
  `ConversationId`, `Messages[].Id`, `Messages[].JailbreakDetected`,
  `AccessedResources[].SiteUrl`, `AccessedResources[].Action`,
  `AccessedResources[].Type`, `AccessedResources[].XPIADetected`,
  `Resource[].Property`.


### Confirmed `RecordType` values

`CopilotInteraction`, `CreateCopilotPlugin`, `UpdateCopilotPlugin`,
`EnableCopilotPlugin`, `DisableCopilotPlugin`, `CreateCopilotPromptBook`,
`UpdateCopilotPromptBook`, `DeleteCopilotPromptBook`, `UpdateCopilotSettings`.

### Cross-table joins

Several hunts join `CopilotActivity` with adjacent tables:

- `SigninLogs` (off-hours / geo baseline, location/country).
- `AuditLogs` (`InitiatedBy.user.userPrincipalName`,
  `TargetResources[]`, `OperationName` - admin actions).
- `OfficeActivity` (`Operation`, `RecordType`, `UserId`, `ItemName` -
  plugin install / config events).
- `CopilotAdminActivity` (may not exist in every tenant - referenced
  via `union isfuzzy=true` + `column_ifexists`).

> **KQL pattern note**: `column_ifexists` does **not** survive a
> `union isfuzzy=true` when none of the branches has the column.
> Several hunts (`PluginInstallAnomaly`, `MemoryContextPoisoning`)
> use per-branch projection: each table arm projects normalized
> synthetic columns (`_OperationName`, `_RecordType`, `_Initiator`,
> `_TargetName`, `_OwnerUpn`, `_Payload`) before the union, and
> downstream operators only reference the synthetic names.

### Still speculative (validate against a live row)

The remaining `LLMEventData` subfields used by these rules are
**not** documented by Microsoft. Confirm with:

```kusto
CopilotActivity
| take 10
| project RecordType, LLMEventData
```

- `ResponseStatus`, `SafetyVerdict`, `SafetyCategories`
- `ToolName`, `ToolInput`, `ToolStatus`, `HttpStatus`, `ApiTarget`
- `SensitivityLabel`, `Classifiers`, `TotalTokens`, `TraceStepId`
- `PreviousModel` / `NewModel`, `PreviousSystemPrompt` /
  `NewSystemPrompt`, `ConfigChange`
- `Participants`, `TenantDefaultDomain`, `ChatId` (used by
  cross-tenant guest leak hunt)

---

## External dependency

- `CopilotRagUntrustedSource.yaml` references a Sentinel watchlist
  `CopilotTrustedRagSources` (column `SourceUri`). Provision it before
  enabling the rule, otherwise the query treats every retrieval source
  as untrusted.

---

## Cost-reduction guidance (ingest-time filtering)

`CopilotActivity` ingest cost is driven almost entirely by the
`LLMEventData` dynamic blob (prompts, responses, message arrays,
accessed-resource arrays). Recommended levers, cheapest first:

### 1. Workspace transformation DCR

Attach a transformation to the `Microsoft-CopilotActivity` stream and
drop / trim before ingest. Combine as needed:

```kusto
// (a) Truncate free-text to 512 chars - keeps regex hunts, drops ~80%
//     of volume on chatty tenants.
source
| extend LLMEventData = bag_merge(LLMEventData, dynamic({
    "Prompt":   substring(tostring(LLMEventData.Prompt),   0, 512),
    "Response": substring(tostring(LLMEventData.Response), 0, 512)
  }))
```

```kusto
// (b) Drop free-text entirely; keep only the safety / verdict signals
//     scheduled rules actually fire on.
source
| extend LLMEventData = bag_remove_keys(LLMEventData,
        dynamic(['Prompt','Response','Messages']))
```

```kusto
// (c) Drop low-signal Interactions, keep anything risky.
source
| where RecordType != "CopilotInteraction"
   or  tobool(LLMEventData.Messages[0].JailbreakDetected)
   or  array_length(LLMEventData.AccessedResources) > 0
   or  isnotempty(LLMEventData.SafetyVerdict)
   or  DlpHits > 0
```

```kusto
// (d) Cap unbounded arrays.
source
| extend LLMEventData = bag_merge(LLMEventData, dynamic({
    "Messages":          array_slice(LLMEventData.Messages,          0, 20),
    "AccessedResources": array_slice(LLMEventData.AccessedResources, 0, 50)
  }))
```

```kusto
// (e) Sample low-risk traffic at 10%, keep all risky.
source
| where DlpHits > 0
   or tobool(LLMEventData.Messages[0].JailbreakDetected)
   or hash(ThreadId, 10) == 0
```

### 2. Hybrid tiering by `RecordType`

Route admin / config events to **Analytics** (rules need them) and bulk
`CopilotInteraction` rows to **Auxiliary** or the data lake (10-100x
cheaper):

- High-value, low-volume -> Analytics tier:
  `UpdateCopilotSettings`, `CreateCopilotPlugin`, `UpdateCopilotPlugin`,
  `EnableCopilotPlugin`, `DisableCopilotPlugin`, `*CopilotPromptBook`.
- Bulk -> Auxiliary / lake: `CopilotInteraction`.

Detections that **lose coverage** when Interactions move off Analytics
(must be re-implemented as summary rules against the auxiliary table):
`JailbreakAttemptDetection`, `SensitiveDataExposure`, `TokenCostSpike`,
`IndirectPromptInjection`, `RagUntrustedSource`,
`ExfiltrationPattern`, `ResourceDiversityBurst`,
`ConfigToAbuseChain` (abuse half), `AccessDriftDetection`,
`RedTeamPacingAnomaly`.

Detections that **stay fine** on Analytics-only admin events:
`SystemPromptOverride`, `ConfigToAbuseChain` (config half),
`PluginInstallAnomaly` (hunt), `MemoryContextPoisoning` (hunt).

### 3. Drop columns no rule references

Safe to project out via DCR when present and unused:
`DistinctTypes`, empty `Policies`, redundant `AgentIds` /
`AgentNames` / `ActorUserIds` arrays when scalar `AgentId` /
`AgentName` / `ActorUserId` is already populated, `Sites` array when
`DistinctSites` count is sufficient.

### 4. Connector-side controls

In the Microsoft Copilot connector blade, disable optional
content-capture toggles (prompt / response text) you don't need
**before** relying on DCR transforms - cheaper than trimming after the
fact.

### Suggested starting point

For a cost-sensitive tenant, apply transforms **(a) + (c) + (d)** as a
single DCR, keep everything on Analytics tier, then measure 7-day
ingest delta. Typical reduction: **60-85%** with no detection coverage
loss except minor PII / hallucination regex precision (since (a) trims
text to first 512 chars).

---

## File / style conventions

- All YAML files carry a fresh GUID `id`, descriptive `name`, and
  explanatory `description` text.
- KQL is bounded by `queryPeriod`, avoids `search *` / `union *`, and
  pushes filters before joins / `mv-expand` for cost.
- `extract_all` regex always wraps the target pattern in a capture
  group `( )` (otherwise KQL raises `SEM0213`).
- Severity, tactics, and techniques follow Microsoft Sentinel
  scheduled-rule schema; hunting-query files use the lighter hunting
  schema.
- Tags: `Sentinel-As-Code`, `Custom`, `Copilot`, `AI`.

---

## How to deploy

1. **ARM template (recommended)** - run `Deploy/azuredeploy.json` via
   Azure CLI, PowerShell, or the Azure portal. See
   [`Deploy/README.md`](./Deploy/README.md). Regenerate after editing
   any YAML with `Deploy/New-CopilotArmTemplate.ps1`.
2. **Sentinel-As-Code pipeline** - drop the YAML files back into a
   Sentinel-As-Code repo under `AnalyticalRules/Copilot/` and
   `HuntingQueries/Copilot/`, then run
   `./Scripts/Build-DependencyManifest.ps1 -Mode Generate` and let the
   pipeline deploy via `Deploy-CustomContent.ps1`.
3. **Manual portal import** - Sentinel > Analytics > Create > Scheduled
   query rule, copying the `query` field; Hunting > Queries > New query
   for the hunting set.

---

## Threat-model references

Built against the categories in:

- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic AI Applications 2026 (draft)
- DeepTeam (https://github.com/confident-ai/deepteam) vulnerability /
  attack taxonomy: Bias, PII, Toxicity, Prompt Injection, Jailbreak,
  Hallucination, RAG poisoning, Cybersecurity
- RedAmon (https://github.com/samugit83/redamon) agent-loop and
  runaway-tool concepts for trace-level anomaly hunting
- MITRE ATLAS for AI/ML tactic and technique mapping
