# Foundry-AppInsights bundle (Application Insights telemetry)

Independent, deployable-today bundle of Microsoft Sentinel **hunting
queries** for **Foundry / Agent Service** runtime telemetry. Everything
here reads the real trace shape that Foundry emits to Application
Insights and exports to the Sentinel workspace:

- Table: **`AppDependencies`** (spans), exported from the project's
  workspace-based Application Insights into the Sentinel workspace
  (e.g. `LAWSentinel`).
- Property bag: **`Properties`** (not `customDimensions`).
- Keys: **`gen_ai.*`** (agent, model, tokens, `input.messages` /
  `output.messages`) and **`microsoft.foundry.content_filter.results`**
  (guardrail verdicts).

This bundle is fully independent of the sibling `../OpenAI-Connector/`
bundle (which reads the OpenAI CCF Analytics-tier tables).

---

## Contents

| Folder | Contents |
| --- | --- |
| `AnalyticalRules/` | 30 scheduled analytic rules (YAML) |
| `HuntingQueries/` | 12 guardrail / content-safety / behaviour / cross-table hunting queries (YAML) |
| `Watchlists/` | `FoundryTrustedToolSources` (approved tool / RAG hosts) and `AgentIdentityMap` (agent name -> Entra identity) used by the untrusted-source and cross-table correlation content |
| `Simulation/` | Test harness that drives prompts so the rules / hunts light up |
| `Deploy/` | ARM template + generator (`New-FoundryArmTemplate.ps1`) and `Enable-FoundryTracing.ps1` (turns on server-side tracing across every Foundry project) |

### Analytic rules

| File | Severity | Signal | Source key |
| --- | --- | --- | --- |
| `AnalyticalRules/FoundryGuardrailJailbreakDetected.yaml` | High | Prompt Shields jailbreak / indirect prompt-injection detected | `content_filter.results.{jailbreak,prompt_shield,indirect_attack}` |
| `AnalyticalRules/FoundrySensitiveDataInOutput.yaml` | High | Secrets / bulk-PII (AWS key, private key, JWT, card, emails) in response | `gen_ai.output.messages` |
| `AnalyticalRules/FoundryContentSafetyHighSeverity.yaml` | Medium | Content-safety **high-severity** hit (hate / sexual / violence / self-harm) | `microsoft.foundry.content_filter.results` |
| `AnalyticalRules/FoundryBlocklistTermMatched.yaml` | Medium | Custom blocklist term matched | `content_filter.results.custom_blocklists` |
| `AnalyticalRules/FoundryPromptInjectionPatterns.yaml` | Medium | Prompt-injection / tool-coercion markers in input | `gen_ai.input.messages`, `gen_ai.tool.call.arguments` |
| `AnalyticalRules/FoundryUntrustedToolSource.yaml` | Medium | Tool / RAG fetch from a host not on the trusted allowlist (poisoning) | `gen_ai.tool.call.{arguments,result}` + watchlist `FoundryTrustedToolSources` |
| `AnalyticalRules/FoundrySensitiveToolInvocation.yaml` | Medium | High-impact tool invoked (code / shell / http / sql / email) | `gen_ai.tool.{name,type}` |
| `AnalyticalRules/FoundryTokenCostSpike.yaml` | Medium | Per-agent hourly token use >=3x its 7-day median (denial-of-wallet) | `gen_ai.usage.{input,output}_tokens` |
| `AnalyticalRules/FoundryRedTeamPacingAnomaly.yaml` | Medium | Automated red-team / fuzzing pacing (fan-out, guardrail hammer, sustained rate) | `gen_ai.conversation.id` + `content_filter.results` |
| `AnalyticalRules/FoundryOffHoursOrGeoAnomaly.yaml` | Low | Agent activity off-hours or from a non-allowed country | `ClientCountryOrRegion`, `hourofday()` |
| `AnalyticalRules/FoundrySystemPromptDisclosure.yaml` | High | User asks for the system prompt and the response leaks instruction markers | `gen_ai.input.messages`, `gen_ai.output.messages` |
| `AnalyticalRules/FoundrySecretsInPrompt.yaml` | High | Secrets / bulk-PII (AWS key, private key, JWT, emails) in the **input** prompt | `gen_ai.input.messages` |
| `AnalyticalRules/FoundryNewToolFirstSeen.yaml` | Medium | A tool never seen in the 14-day baseline is invoked | `gen_ai.tool.name` |
| `AnalyticalRules/FoundryExcessiveToolChaining.yaml` | Medium | >=15 tool calls or >=6 distinct tools in one conversation (autonomous loop) | `gen_ai.tool.name`, `gen_ai.conversation.id` |
| `AnalyticalRules/FoundryPrivilegeEscalationClaim.yaml` | Medium | Authority / role-impersonation claim ("I'm the CFO", "as an admin") in input | `gen_ai.input.messages` |
| `AnalyticalRules/FoundryBulkDataExfiltrationIntent.yaml` | Medium | Bulk-retrieval intent ("show all", "export all", "dump the table", `select *`) in input | `gen_ai.input.messages` |
| `AnalyticalRules/FoundryAsciiSmugglingInjection.yaml` | Medium | Invisible-Unicode smuggling (Tag block / zero-width / bidi override) in input | `gen_ai.input.messages` |
| `AnalyticalRules/FoundrySuspiciousUrlInContent.yaml` | High | Phishing / malicious URL heuristics (raw-IP, punycode, shortener, bait path) in prompt or response | `gen_ai.input.messages`, `gen_ai.output.messages` |
| `AnalyticalRules/FoundryThreatIntelUrlMatch.yaml` | High | URL / domain / IP in prompt or response matched against active Sentinel threat-intel indicators | `gen_ai.input.messages` / `gen_ai.output.messages` + `ThreatIntelIndicators` join |
| `AnalyticalRules/FoundryMultiStageAttackChain.yaml` | High | >=2 distinct attack stages (inject / escalate / exfil / jailbreak) in one conversation, with tool context | `gen_ai.input.messages` + `gen_ai.tool.name` |
| `AnalyticalRules/FoundryHitLConsentBypass.yaml` | High | Consent fatigue (>=5 approvals / 5 min) or compound action (>=3 sensitive tools, >=2 distinct, in 2 min) | `gen_ai.tool.consent.*`, `gen_ai.tool.user_approved`, `gen_ai.tool.{name,type}` |
| `AnalyticalRules/FoundryMcpToolDescriptionChange.yaml` | High | New SHA-256 of `gen_ai.tool.description` for an established (server, tool) pair (>=10 baseline calls, >=3 days old) | `gen_ai.tool.description`, `mcp.tool.description` |
| `AnalyticalRules/FoundryMcpCrossServerOverride.yaml` | High | Override-instruction phrasing in tool desc / args / result AND >=2 distinct tool servers in conversation | `gen_ai.tool.{description,call.arguments,call.result}`, `mcp.server.name` |
| `AnalyticalRules/FoundryAgentMemoryPoisoning.yaml` | High | Memory write or recall content matches injection markers; recall sub-signal also requires sensitive tool fire <= 30 min later | `gen_ai.memory.*`, `gen_ai.thread.message.content`, `gen_ai.tool.name` |
| `AnalyticalRules/FoundryCuaVisualAttack.yaml` | High | Hidden Unicode (Tag block / zero-width / bidi) or prompt-injection markers in computer-use observation / screenshot text | `gen_ai.computer_use.observation`, `gen_ai.computer_use.screenshot.text` |
| `AnalyticalRules/FoundryGoalDriftBetweenSpans.yaml` | Medium | Benign first input AND no sensitive intent vocabulary, yet >=3 sensitive tool calls in same conversation within 2h | `gen_ai.input.messages` + `gen_ai.tool.{name,type}` |
| `AnalyticalRules/FoundryCapabilityDisclosureExtended.yaml` | Medium | Tool / schema / consent / memory probe AND output reflects >=3 actual project tool names from the 7-day inventory | `gen_ai.input.messages`, `gen_ai.output.messages`, baseline `gen_ai.tool.name` |
| `AnalyticalRules/FoundryInterAgentPermissionMismatch.yaml` | Medium | Sub-agent (cross-agent invocation in last 1h) uses tools not in its 14-day baseline; requires >=2 new tools or 1 sensitive | `gen_ai.tool.{type,name,target_agent}`, `gen_ai.agent.name` |
| `AnalyticalRules/FoundrySessionContextContamination.yaml` | Medium | First-quartile untrusted URL or injection marker AND last-quartile sensitive tool call in same conversation (>=5 spans) | `gen_ai.tool.call.{arguments,result}` + `FoundryTrustedToolSources` |

> **Identity note**: Foundry telemetry has no human-user field, so the
> rules pivot on the **agent** (`gen_ai.agent.name`) and **conversation**
> (`gen_ai.conversation.id`). Account entities map to the agent name.
> The text-content rules (prompt injection, sensitive output, untrusted
> tool args) only fire when
> `AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true`.

### Hunting queries

| File | Signal | Source key |
| --- | --- | --- |
| `HuntingQueries/AgentContentSafetyFilterHits.yaml` | Content-safety filter hits (all severities) | `microsoft.foundry.content_filter.results` |
| `HuntingQueries/AgentBlocklistMatches.yaml` | Custom blocklist (blocked-term) matches | `content_filter.results.custom_blocklists` |
| `HuntingQueries/AgentGuardrailJailbreakSignals.yaml` | Prompt Shields jailbreak / indirect prompt-injection | `content_filter.results.{jailbreak,prompt_shield,indirect_attack}` |
| `HuntingQueries/AgentAbnormalToolUsage.yaml` | New / spiking tool vs 14-day baseline | `gen_ai.tool.{name,type}` |
| `HuntingQueries/AgentGroundingSourceEnumeration.yaml` | Diverse retrieval-source fan-out (RAG recon) | `gen_ai.tool.call.{arguments,result}` |
| `HuntingQueries/AgentTraceLevelAnomalies.yaml` | Long traces / tight tool loops / sustained span rate | `gen_ai.conversation.id`, `gen_ai.tool.name` |
| `HuntingQueries/AgentModelFingerprinting.yaml` | Repeated model-identity probing ("which model are you") | `gen_ai.input.messages`, `gen_ai.request.model` |
| `HuntingQueries/AgentCrossAgentInvocation.yaml` | One agent invoking another / agent-typed tool (lateral movement) | `gen_ai.agent.name`, `gen_ai.tool.type` |
| `HuntingQueries/AgentDormancyBreak.yaml` | Agent silent >=7 days then reactivates (dormant-then-active) | `gen_ai.agent.name` |
| `HuntingQueries/AgentCostAnomalyByDimension.yaml` | Token-cost anomaly per model via `series_decompose_anomalies` | `gen_ai.usage.*` |
| `HuntingQueries/AgentMemoryOperations.yaml` | Inventory of agent memory write / recall spans (paired with `FoundryAgentMemoryPoisoning`) | `gen_ai.memory.*`, `gen_ai.thread.message.content` |

#### Cross-table correlation hunts

These join Foundry spans to platform logs through the `AgentIdentityMap`
watchlist (or trusted-source watchlist). They only return rows once the
watchlist is populated **and** the relevant connector is ingesting.

| File | Correlates | Source tables |
| --- | --- | --- |
| `HuntingQueries/AgentAutonomousAzureWrite.yaml` | Agent span -> privileged control-plane write within 15 min | `AppDependencies` + `AzureActivity` |
| `HuntingQueries/AgentIdentityOAuthEscalation.yaml` | Agent identity granted new OAuth scope / role / credential | `AuditLogs` |
| `HuntingQueries/AgentSensitiveRetrievalOffice.yaml` | Agent identity bulk-reads sensitive documents | `OfficeActivity` |
| `HuntingQueries/RagSourcePoisoningWrites.yaml` | Writes to a RAG/knowledge host or injection-named file | `OfficeActivity` + `FoundryTrustedToolSources` |
| `HuntingQueries/AgentExternalExfiltration.yaml` | Sensitive agent output then external share/egress within 30 min | `AppDependencies` + `OfficeActivity` |

The analytic rules alert on the highest-fidelity / high-severity subset
(incidents); the hunts surface the full picture including low / medium
severity for proactive review. The rules' `enabled` flag is bound to the
`enableAnalyticRules` deployment parameter.

> **Table-plan note**: scheduled analytic rules can only read tables on
> the **Analytics** plan. Confirm `AppDependencies` is on the Analytics
> plan in the target workspace (it is by default). The hunting queries
> work regardless.

---

## Deploy

```powershell
# (re)build the template from the YAML sources
.\Deploy\New-FoundryArmTemplate.ps1

# deploy (Azure CLI)
az deployment group create `
  --resource-group <sentinel-rg> `
  --template-file ./Deploy/azuredeploy.json `
  --parameters workspaceName=<workspace-name> enableAnalyticRules=true enableWatchlist=true
```

Full details in [`Deploy/README.md`](./Deploy/README.md).

> **Watchlist**: the `FoundryUntrustedToolSource` rule joins against the
> `FoundryTrustedToolSources` watchlist (column `SourceUri`). The ARM
> template deploys it from `Watchlists/FoundryTrustedToolSources/` (toggle
> with the `enableWatchlist` parameter, default true). Replace the seed
> rows with your approved tool / RAG hostnames **before enabling that
> rule** - while the watchlist only has seed rows the leftanti join treats
> every other fetched host as untrusted and the rule will be noisy.

---

## Coverage map - Microsoft AI Red Team v2.0 taxonomy

The 9 rules + 1 hunt added in 06/2026 close the gaps surfaced by the
Microsoft AI Red Team v2.0 taxonomy update
(<https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/>).

| v2.0 failure mode / operational finding | Rule(s) / hunt |
| --- | --- |
| Agentic Supply Chain Compromise | `FoundryUntrustedToolSource`, `FoundryNewToolFirstSeen`, `FoundryMcpToolDescriptionChange` |
| Goal Hijacking | `FoundryMultiStageAttackChain`, `FoundryPrivilegeEscalationClaim`, `FoundryGoalDriftBetweenSpans` |
| Inter-Agent Trust Escalation | `FoundryInterAgentPermissionMismatch`, hunt `AgentCrossAgentInvocation` |
| Computer Use Agent (CUA) Visual Attack | `FoundryCuaVisualAttack` |
| Session Context Contamination | `FoundrySessionContextContamination`, `FoundryRedTeamPacingAnomaly`, `FoundryAsciiSmugglingInjection` |
| MCP / Plugin Abuse | `FoundryMcpToolDescriptionChange`, `FoundryMcpCrossServerOverride`, `FoundryUntrustedToolSource` |
| Capability / Architecture Disclosure | `FoundrySystemPromptDisclosure`, `FoundryCapabilityDisclosureExtended`, hunt `AgentModelFingerprinting` |
| HitL bypass (op. finding - most exploited) | `FoundryHitLConsentBypass` |
| XPIA (op. finding) | `FoundryPromptInjectionPatterns`, `FoundryUntrustedToolSource`, `FoundrySuspiciousUrlInContent`, `FoundryThreatIntelUrlMatch` |
| Memory poisoning (op. finding) | `FoundryAgentMemoryPoisoning`, hunt `AgentMemoryOperations` |
| Multi-step / incremental escalation (op. finding) | `FoundryMultiStageAttackChain`, `FoundrySessionContextContamination`, `FoundryGoalDriftBetweenSpans` |

Every new rule carries explicit thresholds (call counts, distinct tool
counts, conversation span minimums, baseline-window join filters,
sensitive-tool intersections) so they remain low-noise out of the box.
Telemetry keys for memory, consent and computer-use are probed
defensively across `gen_ai.*` / `microsoft.agent.*` / `mcp.*` namespaces
because the OTel semantic conventions for those areas are still
evolving; rules will start firing as soon as any namespace is populated.

---

## Pre-requisites

- A Foundry project with **Application Insights connected** and
  **workspace-based**, pointing at the Sentinel workspace
  (e.g. `LAWSentinel`), so spans land in `AppDependencies`.
- Content recording on so prompt / response text is captured:
  `AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true` (generate new
  conversations afterwards - tracing is not retroactive).
- A content-filter policy on the deployment with **Prompt Shields** on
  and the four harm categories set to annotate / block; a **custom
  blocklist** for the blocklist hunt.

---

## Enabling tracing (OpenTelemetry) so the content lights up

None of this content sees anything until the Foundry project is sending
spans to the Sentinel-backed Application Insights. Foundry tracing uses
**OpenTelemetry** semantic conventions (`gen_ai.*`) and is **off by
default**.

### How it works

Tracing is **server-side** and is switched on **per project** by
connecting an Application Insights resource. Once a project is connected,
**every agent in that project** emits spans automatically - no per-agent
or in-code change is required.

### One project (portal)

1. Foundry portal -> open the project -> **Agents** -> **Traces** tab.
2. Select **Connect** and pick (or create) an Application Insights
   resource. Use the **workspace-based** App Insights whose Log Analytics
   workspace backs your Sentinel instance, otherwise the spans never
   reach `AppDependencies` and this content stays empty.

### Every project at once (script)

`Deploy/Enable-FoundryTracing.ps1` walks every Foundry (New Foundry)
project across the chosen subscriptions and connects the same App
Insights to each one. It is **dry-run by default** (idempotent; skips
projects already connected) and only writes when you pass `-Apply`.

```powershell
# Dry-run: list which projects would be connected (no changes)
./Deploy/Enable-FoundryTracing.ps1 `
    -ApplicationInsightsResourceId '<app-insights-resource-id>'

# Apply across one or more subscriptions
./Deploy/Enable-FoundryTracing.ps1 `
    -ApplicationInsightsResourceId '<app-insights-resource-id>' `
    -SubscriptionId '<sub-a>','<sub-b>' -Apply
```

> Pick the App Insights whose backing Log Analytics workspace is the one
> Sentinel reads. App Insights connected to any other workspace produces
> traces your rules cannot see.

### Capture prompt / response content

Server-side tracing records inputs, outputs and tool calls by default,
which is what most of this content needs. For your **own** code paths
(custom agents, the `Simulation/` scripts) force content capture with:

```powershell
$env:AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED   = "true"
$env:OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT = "true"
```

Tracing is **not retroactive** - only conversations created after it is
enabled appear in `AppDependencies`.

### Noisy, but it unlocks capability

Turning OpenTelemetry on **increases Log Analytics ingestion** (every
agent turn, every tool call, full prompt and response text). Budget for
it and tune retention. In exchange you get the signals the whole bundle
depends on:

- **Prompt / response content** - jailbreak, prompt-injection, system-
  prompt disclosure, secrets-in-prompt, sensitive-output detections.
- **Per-step tool spans** - `gen_ai.tool.{name,type,call.arguments}`:
  untrusted tool source, sensitive tool invocation, new-tool baseline,
  excessive tool chaining, cross-agent invocation.
- **Token / cost metrics** - `gen_ai.usage.*`: denial-of-wallet and
  per-model cost-anomaly detections.
- **Guardrail verdicts** - `microsoft.foundry.content_filter.results`:
  content-safety severity and custom-blocklist matches.
- **Conversation / span correlation** - `gen_ai.conversation.id` plus
  trace IDs: trace-level anomalies, red-team pacing, and the cross-table
  correlation hunts (agent action -> Azure write / OAuth grant / Office
  read / external egress).

To keep the noise down: enable content recording only where you need
text-content detections, keep `AppDependencies` on a sensible retention,
and rely on the hunting queries (which carry no alert cost) for the
lower-fidelity signals.

### Filtering `AppDependencies` ingestion

The biggest cost driver is that `AppDependencies` carries **all**
dependency telemetry (SQL, HTTP, storage, SDK chatter), not just the
`gen_ai.*` agent spans the bundle reads. A workspace **transformation /
filter rule** on the table drops matching rows **before** they are
ingested, so you pay only for what you keep.

> Filter rules **drop** every row the KQL condition matches. The golden
> rule is therefore: only ever match rows that are **not** agent spans.
> Always anchor the condition on
> `isempty(tostring(Properties['gen_ai.system']))` (or
> `isempty(tostring(Properties['gen_ai.agent.name']))`) so a Foundry span
> can never be discarded by mistake. Validate in Logs first by running the
> condition with `count()` and confirming **zero** `gen_ai.*` rows match.
>
> Note: this is a Log Analytics / Application Insights table
> transformation. At time of writing `AppDependencies` cannot yet be
> configured through the **data lake** tier, so apply the filter on the
> analytics (interactive) tier.

Safe, high-value conditions to filter **out** (drop), each already scoped
so it cannot touch agent spans:

```kql
// 1. Health probes, readiness checks and favicon noise (never agent spans)
isempty(tostring(Properties['gen_ai.system']))
  and Name has_any ('/health','/healthz','/ready','/live','ping','favicon.ico','heartbeat')
```

```kql
// 2. Backing-store chatter the detections never read
isempty(tostring(Properties['gen_ai.system']))
  and DependencyType in ('SQL','Azure blob','Azure table','Azure queue','Azure Service Bus')
```

```kql
// 3. Fast successful infra calls (very high volume, no security value)
isempty(tostring(Properties['gen_ai.system']))
  and Success == 'True'
  and toint(column_ifexists('DurationMs', 0)) < 50
```

```kql
// 4. Synthetic / availability-test traffic
isempty(tostring(Properties['gen_ai.system']))
  and (isnotempty(column_ifexists('SyntheticSource','')) or Name startswith 'GET /robots')
```

```kql
// 5. SDK metadata / token-endpoint polling (IMDS, AAD token, instance metadata)
isempty(tostring(Properties['gen_ai.system']))
  and Target has_any ('169.254.169.254','login.microsoftonline.com','metadata/identity','oauth2/v2.0/token')
```

Keep it conservative: start with rule 1 (probes) and rule 2 (backing
stores), confirm `gen_ai.*` volume is unchanged, then add the others. If
in doubt, drop nothing that lacks the `isempty(...gen_ai.system...)`
anchor. The bundle's detections only ever need rows where
`Properties['gen_ai.agent.name']` (or another `gen_ai.*` key) is present,
so anything without a `gen_ai.*` property is fair game to filter.

### Does anything change in the rules?

No. The rules and hunts already read `AppDependencies` / `Properties` /
`gen_ai.*`, which is exactly the shape OpenTelemetry produces. Enabling
tracing is purely an **environment** action - once spans flow, the
existing content starts matching with no edit required. The only thing to
keep current is the two watchlists (`FoundryTrustedToolSources` hosts and
`AgentIdentityMap` agent->identity rows) so the trusted-source and
cross-table content resolves real values.

---


## Testing

Use `Simulation/` to generate test data. See
[`Simulation/README.md`](./Simulation/README.md).

```powershell
$env:AZURE_OPENAI_API_KEY = '<key>'
.\Simulation\Invoke-AgentGuardrailSimulation.ps1 `
    -Endpoint   'https://foundrytest45.openai.azure.com' `
    -Deployment 'gpt-4.1'
```

Then verify ingestion with `Simulation/Verify-GuardrailTelemetry.kql` in
the Sentinel workspace.

To also exercise the volume-based detections
(`FoundryRedTeamPacingAnomaly`, `FoundryTokenCostSpike`,
`AgentTraceLevelAnomalies`), run several fast passes:

```powershell
.\Simulation\Invoke-AgentGuardrailSimulation.ps1 `
    -Endpoint   'https://foundrytest45.openai.azure.com' `
    -Deployment 'gpt-4.1' `
    -Repeat 10 -DelaySeconds 0
```

> **Key-name caveat**: the exact sub-keys under
> `microsoft.foundry.content_filter.results` vary by API version. The
> three hunts parse the common names defensively
> (`jailbreak` / `prompt_shield` / `indirect_attack` /
> `custom_blocklists`). Run block 2 of the verification KQL to list your
> tenant's real keys and adjust the `extend` lines if they differ.
