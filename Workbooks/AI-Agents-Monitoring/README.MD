# 🤖 AI Agents Monitoring Workbook

Stop Guessing What Your AI Agents Are Doing and Monitor AI Agents at Scale https://youtu.be/GYHOH9GUcDc

Unified Microsoft Sentinel workbook for **threat hunting and telemetry across your
entire agentic-AI estate** — Microsoft 365 Copilot, Copilot Studio agents, Azure AI
Foundry agents, the OpenAI connector, Defender XDR agent inventory, and local AI
agents discovered on endpoints — from a single pane.

- **File:** `AI-Agents-Monitoring-Workbook.workbook`
- **Tabs:** 18 · **Query tiles:** 106 (20 Defender Advanced Hunting) · **Parameters:** 7
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

Every tile reads the **real runtime telemetry** each platform exports to the Sentinel
workspace and surfaces the same signals the companion detection packs alert on. All
queries use `union isfuzzy=true`, so a tab for a source you haven't onboarded renders
**empty instead of erroring**.

---

## Why this workbook

Agentic AI spreads telemetry across many products, each with its own table shape and
enablement switch. This workbook consolidates them into one investigation surface with
**per-source deep-dive tabs** and **persona pages** that aggregate across all sources —
so a SOC analyst, an identity engineer, and an executive can each answer their question
without writing KQL.

---

## Data sources (per-source tabs)

| Tab | Source | Tables & keys |
|---|---|---|
| 🟦 **M365 Copilot** | Microsoft Copilot connector | `CopilotActivity` — `RecordType`, `LLMEventData` (`Messages[].JailbreakDetected`, `AccessedResources[].XPIADetected`, `RagSources`) |
| 🟨 **Copilot Studio** | Agent Application Insights | `AppEvents` (`BotMessageReceived/Send`, `Properties.text/conversationId/channelId`) + `AppDependencies` (`DependencyType=Connector`, `Target`, `Success`, `DurationMs`) |
| 🟪 **Foundry Agents** | Foundry → App Insights | `AppDependencies` spans — `Properties['gen_ai.*']` (`agent.name`, `conversation.id`, `tool.name/type`, `usage.*`, `request.model`) + `microsoft.foundry.content_filter.results` |
| 🟩 **OpenAI Connector** | OpenAI CCF | `ASimAgentEventLogs` / `OpenAIChatCompletions` (`ModelName`, `InputTokensUsed`, `OutputTokensUsed`, `ToolName`, `AdditionalFields.input_user`) + `OpenAIAuditLogs` |
| 🔬 **Advanced Hunting** | Defender XDR | `BehaviorInfo` (Prompt Shield / AI-agent behaviors), `BehaviorEntities`, `AgentsInfo` (cloud **and** local agent inventory, MCP, model, channels), `AADAgentRiskEvents`, `ExposureGraphNodes/Edges` — runnable directly in Advanced hunting |
| 🗄️ **Data Lake** | Agent Observability (lake) | `UnifiedAgentObservability` (`AISpanOutput` spans, Src/Target agents), `EntraAgentIdentities` / `Blueprints` / `BlueprintPrincipals` / `AgentUsers` — usage-based billing |

## Persona pages (aggregate across all sources)

| Tab | Purpose |
|---|---|
| 🧭 **Executive Overview** | 15 unified KPIs + AI Risk Score + requests by platform / business unit + top identities |
| 📈 **Usage Analytics** | Requests by day / model / user / department + averages (tokens, latency, cost) |
| ⏱️ **Activity Timeline** | One chronological cross-source event feed |
| 🚨 **Security Monitoring** | Detection categories + alerts + severity + MITRE ATT&CK |
| 🛡️ **Content Safety** | Harm categories, jailbreak / Prompt Shield, trend, worst agents / models |
| 🧠 **Model Observability** | Per-model tokens / latency / cost / failures |
| ⚙️ **Agent Operations** | Failures, result codes, success %, exceptions |
| 📋 **Governance** | Ownerless / weak-auth / external-data / shadow-AI (`CloudAppEvents`) |
| 🔎 **Investigation** | Entity-pivot timeline + related alerts + sign-ins |
| 🎯 **AI Risk Score** | Weighted composite 0–100 + component sub-scores |
| 📡 **Telemetry Health** | Per-table volume/cost, `AppDependencies` gen_ai-vs-other split, content-recording coverage, `CopilotActivity` RecordType tiering |
| 🛡️ **Detections & Coverage** | Detection-pack reference + firing `SecurityAlert` / `SecurityIncident` |

---

## Key capabilities

- **Cross-source AI visibility** — one workbook over M365 Copilot, Copilot Studio,
  Foundry, OpenAI, Defender XDR, and the Agent Observability lake.
- **Prompt-injection & jailbreak hunting** — M365 Copilot XPIA/jailbreak flags,
  Foundry Prompt Shield verdicts, Copilot Studio injection markers, and Defender
  `BehaviorInfo` Prompt Shield detections.
- **Agent inventory & governance** — every agent's type, auth, knowledge, tools, MCP
  servers, and owners; ownerless / inactive / growth; shadow-AI usage.
- **Local AI agent discovery (Defender for Endpoint, Preview)** — inventory and
  deployment footprint, remote/local MCP and declared tools, risky auto-approval or
  untrusted host processes, risky agents on **critical devices**, and the user
  **blast radius** to critical/sensitive assets via the exposure graph.
- **Supply-chain & MCP surface** — agents exposing MCP servers / connected agents,
  tool usage, and access drift (tools newly used by an agent).
- **Content safety & model observability** — harm categories, per-model tokens /
  latency / cost / failures, denial-of-wallet token spikes.
- **Cost estimation** — token-cost tiles driven by the `PriceInput` / `PriceOutput`
  parameters.
- **AI Risk Score** — a weighted 0–100 composite with component sub-scores for
  executive reporting.
- **Investigation workflow** — entity pivot into cross-source timeline, related
  alerts, and related sign-ins.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `Workspace` | Resource picker | — | Target Log Analytics / Sentinel workspace (portable across tenants). |
| `TimeRange` | Time picker | 7 days | Applies to every tile. |
| `AgentSearch` | Text | *(empty)* | Free-text filter (agent / bot / model / actor) across the per-source grids. |
| `DepartmentSearch` | Text | *(empty)* | Filters usage / business-unit tiles by resolved department (`IdentityInfo` join). |
| `PriceInput` | Text | `0.005` | USD per 1K input tokens — token-cost tiles. |
| `PriceOutput` | Text | `0.015` | USD per 1K output tokens — token-cost tiles. |
| `selectedTab` | Text (hidden) | `exec` | Drives tab navigation. |

---

## Prerequisites (per source — tiles stay empty until met)

| Source | Requirement |
|---|---|
| **M365 Copilot** | Microsoft Copilot data connector populating `CopilotActivity`; set the table plan to **Analytics** for rule use. |
| **Copilot Studio** | Agent's **workspace-based** Application Insights pointed at this workspace (Settings → Advanced → Application Insights). Enable **Log sensitive properties** for the `Properties.text` (content) tiles. |
| **Foundry** | Project connected to workspace-based App Insights so spans land in `AppDependencies`. Set `AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true` for text-content tiles (not retroactive). |
| **OpenAI** | OpenAI codeless connector + parsers so `ASimAgentEventLogs` / `OpenAIAuditLogs` resolve. Callers should set the `user` request param for per-user tiles. |
| **Advanced Hunting** | Defender XDR connector streaming `BehaviorInfo` / `AgentsInfo` / `AADAgentRiskEvents`. Local agent discovery requires **Defender for Endpoint Plan 2**; local risk indicators require **Microsoft 365 E7** or **Microsoft Agent 365**. Local discovery is **Preview**. |
| **Data Lake** | Agent Observability onboarded; `UnifiedAgentObservability` + Entra Agent Identity tables in the lake tier (usage-based billing — widen the time range carefully). |

---

## Deploy / import

**Portal (fastest)**

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `AI-Agents-Monitoring-Workbook.workbook` and **Apply**.
3. **Done Editing** → **Save**, name it *AI Agents Monitoring*, and pick your resource
   group / workspace.
4. Select your **Workspace** and **Time range**, then work the tabs. Use **Agent /
   bot / model / actor contains** to focus the per-source grids on one agent.

**Run Advanced Hunting tiles directly**

The 🔬 Advanced Hunting tab uses `queryType: advancedHunting`. The same queries can be
pasted into the Defender portal → **Advanced hunting** (`security.microsoft.com`) — the
tab header includes ready-to-run snippets for `BehaviorInfo`, `AgentsInfo`,
`AADAgentRiskEvents`, and the local-agent (`AgentsInfo` `Platform == "LocalAgents"`)
scenarios.

---

## Notes

- **Read-only.** The workbook never modifies agents, identities, or configuration.
- **Cost lever.** The 📡 Telemetry Health tab shows the `AppDependencies` gen_ai-vs-other
  split and content-recording coverage so you can size ingestion before enabling text
  detections tenant-wide.
- **Graceful degradation.** `union isfuzzy=true` and `column_ifexists()` keep tiles
  rendering on tenants missing a given source or optional column.
- **Data-lake tiles** query the lake tier and incur usage-based charges — widen their
  time range deliberately.
