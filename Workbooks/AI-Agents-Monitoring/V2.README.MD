# 🤖 AI Agents Monitoring Workbook

Stop Guessing What Your AI Agents Are Doing and Monitor AI Agents at Scale https://youtu.be/GYHOH9GUcDc

Unified Microsoft Sentinel workbook for **threat hunting and telemetry across your
entire agentic-AI estate** — Microsoft 365 Copilot, Copilot Studio agents, Azure AI
Foundry agents, the OpenAI connector, Defender XDR agent inventory, and local AI
agents discovered on endpoints — plus custom and containerized agent traffic crossing
APIM AI Gateway — from a single pane.

- **V2 file (recommended):** `AI-Agents-Monitoring-Workbook-V2.workbook`
- **V1 file:** `AI-Agents-Monitoring-Workbook.workbook`
- **V2:** 20 tabs · **254 query tiles** (55 paired APIM query tiles per source, 28 Defender Advanced Hunting) · **12 shared parameters**
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

Every tile reads the **real runtime telemetry** each platform exports to the Sentinel
workspace and surfaces the same signals the companion detection packs alert on.
Cross-source queries use `union isfuzzy=true`; source-specific tabs document their
prerequisites so missing telemetry is easy to distinguish from a clean result.

Every V2 tab includes an analyst reading guide covering purpose, investigation flow,
prerequisites, event grain, and interpretation limits. Bare subsection headings have
also been expanded so inventory posture, heuristic content matches, control verdicts,
and fired alerts are not presented as equivalent evidence. The M365 Copilot tab adds
panel-level guidance for all seven views, including interaction-count semantics, direct
user-prompt attacks, XPIA in grounding content, configuration activity, and resource
access. Detection flags identify risk for investigation; they do not by themselves
prove that the model followed an instruction or that a downstream action succeeded.

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
| 🟨 **Copilot Studio** | Agent or environment Application Insights | Agent-level `AppEvents` + connector `AppDependencies`; environment-level `InvokeAgent` / `ExecuteTool` spans with `gen_ai.agent.*`, `gen_ai.tool.*`, and `OperationId` |
| 🟪 **Foundry Agents** | Foundry → App Insights | `AppDependencies` spans — `Properties['gen_ai.*']` (`agent.name`, `conversation.id`, `tool.name/type`, `usage.*`, `request.model`) + `microsoft.foundry.content_filter.results` |
| 🟩 **OpenAI Connector** | OpenAI CCF | `ASimAgentEventLogs` / `OpenAIChatCompletions` (`ModelName`, `InputTokensUsed`, `OutputTokensUsed`, `ToolName`, `AdditionalFields.input_user`) + `OpenAIAuditLogs` |
| 🌐 **APIM AI Gateway (V2)** | APIM + agent OTel → Application Insights | APIM emits `AppRequests`, `AppDependencies`, `AppExceptions`, configured `AppTraces`, and optional token `AppMetrics`; agent OTel emits `AppDependencies` spans and protected `AppGenAIContent` |
| 🔬 **Advanced Hunting** | Defender XDR | `AgentsInfo`, `AADAgentRiskEvents`, `ExposureGraphNodes/Edges`, `DeviceProcessEvents`, and `CloudAppEvents`; Defender-native Purview DLP queries are embedded in Security & Attack Coverage |
| 🗄️ **Data Lake** | Agent Observability (lake) | `UnifiedAgentObservability` (`AISpanOutput` spans, Src/Target agents), `EntraAgentIdentities` / `Blueprints` / `BlueprintPrincipals` / `AgentUsers` — usage-based billing |

## Persona pages (aggregate across all sources)

| Tab | Purpose |
|---|---|
| 🧭 **Executive Overview** | 15 unified KPIs + AI Risk Score + requests by platform / business unit + top identities |
| 📈 **Usage Analytics** | Requests by day / model / user / department + averages (tokens, latency, cost) |
| ⏱️ **Timeline & Investigation** | Global cross-source chronology plus entity-focused timeline, related alerts, and sign-ins |
| 🚨 **Security & Attack Coverage** | Severity/evidence/verdict semantics, live monitoring, fired alerts/incidents, Purview DLP correlation, detection-pack status, and the 30-risk attack matrix |
| 🛡️ **Content Safety** | Cross-platform jailbreak and content-safety evidence for M365 Copilot, Foundry, Copilot Studio, and APIM AI Gateway |
| 🧠 **Model Observability** | Per-model tokens / latency / cost / failures |
| ⚙️ **Agent Operations** | Failures, result codes, success %, exceptions |
| 📋 **Governance** | Ownerless / weak-auth / external-data / shadow-AI (`CloudAppEvents`) |
| 🎯 **AI Risk Score** | Weighted composite 0–100 + component sub-scores |
| 📡 **Telemetry Health** | Collection KPIs; `AppRequests`, `AppDependencies`, `AppExceptions`, `AppTraces`, and `AppMetrics` health; hourly trend; telemetry mix; cost and content coverage |

The consolidated **Content Safety** tab labels evidence by platform and strength:
M365 Copilot uses native `JailbreakDetected` and `XPIADetected` flags; Foundry uses
content-filter and Prompt Shield metadata plus recorded-input heuristics; Copilot Studio
uses heuristic inbound-message matching because its current `AppEvents` schema has no
universal native verdict; and APIM combines request-body patterns, sanitized policy
events, and explicit blocked requests. APIM panels honor the independent APIM telemetry
source selector and retain workspace/Application Insights parity. A detection flag or
text match does not by itself prove that content was blocked, influenced a response, or
caused tool execution.

The APIM subsection uses an English **AI Safety Control Center** layout: summary KPIs,
a unified control-event feed, per-layer calls/latency/failures, category frequency,
category-by-severity, jailbreak-technique counts, allowed-through injection review,
output-masking evidence, explicit PII-policy outcomes, policy events, and blocked
payload evidence. Output masking is measured from successful `AppRequests` rows whose
recorded `Response-Body` contains mask runs; this proves that output was transformed but
does not identify the PII type or prove complete protection. Category, severity,
threshold, and stage are parsed from `AppExceptions` where `ExceptionType` is
`ContentSafetyPolicyViolated`, then correlated to blocked `AppRequests` by
`OperationId`. Explicit PII-policy views still require sanitized policy metadata.
Empty optional panels therefore mean missing telemetry or no events in the selected
range, not proof that the control is healthy.

---

## 🚨 Security & Attack Coverage (V2)

The unified tab begins with severity, evidence-classification, and verdict semantics;
then presents live security monitoring, fired detections, Purview DLP correlation, and
incidents. Its **AI Attack Matrix** section maps 30 risks across input/prompt, model
exploitation, data/knowledge, confidentiality, agent decision, tools/APIs, runtime,
memory/state, and supply chain. Each row includes examples, dominant consequence,
OWASP LLM and MITRE ATLAS references, workbook evidence, detection-pack evidence,
and limitations.

Coverage statuses are intentionally evidence-based:

| Status | Meaning |
|---|---|
| **COVERED** | Direct observable signal with workbook visibility and detection content |
| **OBSERVABLE** | Useful evidence exists, but does not establish the complete attack or outcome |
| **PARTIAL** | Heuristic or scope-limited evidence only |
| **CONDITIONAL** | A supported evidence path exists, but its evaluator, diagnostic, endpoint, or provenance source must be enabled |
| **GAP** | Current telemetry cannot directly support the claim |

The color map keeps three axes separate: **attack severity** (potential impact),
**evidence classification** (confirmed, correlated, heuristic, or context only), and
**control verdict** (PASS, FAIL, ERROR, or INCONCLUSIVE). A high-severity attempt can
be blocked, and a confirmed signal does not by itself prove successful compromise.

The former six gaps now have explicit evidence contracts. Training-data extraction and
model inversion are **PARTIAL** and retain live heuristic attempt hunts over captured
APIM request content. Vector-database poisoning, hallucination, adversarial
hallucination, and AI package hallucination are **CONDITIONAL** contracts only: no live
tiles run until Azure AI Search diagnostics, Foundry evaluation exports, or package
provenance correlation are onboarded into stable queryable sources. The workbook does
not claim successful extraction, inversion, poisoning, false output, or package
hallucination without the required proof.

The platform-parity panel lists all 30 risks separately for Foundry, Copilot Studio,
and Microsoft 365 Copilot. Each cell names the scheduled rule or hunt, labels an
incomplete signal as observable, or states that the platform telemetry is unsupported.

Runtime outcomes use a separate verdict model:

| Verdict | Meaning |
|---|---|
| **PASS** | A security control demonstrably blocked or normalized the tested behavior |
| **FAIL** | A suspicious/prohibited action was allowed or sensitive output was emitted |
| **ERROR** | Network, timeout, `5xx`, or API-contract failure prevented a security conclusion |
| **INCONCLUSIVE** | Suspicious evidence exists, but enforcement or downstream impact is not provable |

No matching event is never treated as an automatic PASS. APIM has a dedicated verdict
panel in both Application Insights and workspace modes, including full request and
response body evidence.

The APIM section provides one-to-one workbook views for all 13 APIM scheduled
analytics. In addition to body-aware AI threats, it covers request-volume baselines,
repeated unauthorized activity, successful or failed API enumeration, first-seen
operations, new countries, high failure rates, latency drift, unusual operation
combinations, and request-to-dependency/exception correlation. Every query is paired
for workspace and direct Application Insights scope.

---

## 🛡️ Purview DLP correlation (V2)

The **Security & Attack Coverage** tab contains two adjacent surfaces: Sentinel
`SecurityAlert` copies and a Defender-native Advanced Hunting feed. The native feed
starts from `AlertEvidence.ServiceSource == "Microsoft Data Loss Prevention"`, enriches
with `AlertInfo`, and also reads `BehaviorInfo`/`BehaviorEntities`. It keeps every native
Purview signal visible and labels it as direct AI/Copilot context, same-user agent
correlation, or no agent link found. User correlation is useful context but does not
prove the agent caused the DLP event; no link found is not a clean verdict.

Alert details include account and display name, critical-asset tags, workload, location,
policy and rule matches, sensitive information types, action taken, user override, path,
event ID, and correlation ID when Purview emits them in `AdditionalFields`.

Microsoft plans to tune many DLP signals from alerts into behaviors in early October
2026. V2 queries both paths. If a signal appears in Defender and Sentinel, deduplicate
using its alert or behavior ID. Native DLP access requires the appropriate Purview
license and least-privilege alert roles; behavior tables are preview and unavailable
in GCC.

---

## 💻 Local AI agents on endpoints (Preview)

V2 preserves the dedicated **Local AI agents on endpoints (Preview)** section from V1
and expands it with a nested **Visual Studio Code and coding-agent MCP discovery &
runtime (Preview)** subsection. Together, the 12 panels cover agents **Microsoft
Defender for Endpoint discovers on devices** — coding agents and IDE extensions,
desktop AI assistants, local AI runtimes, and agent platforms. They read `AgentsInfo`
filtered to `Platform == "LocalAgents"`
(local posture nested in `RawAgentInfo.localAgentMetadata` — vendor, host process,
trust & `autoApprove`, device, account, **local MCP servers**) joined with the
`ExposureGraphNodes` / `ExposureGraphEdges` attack-surface graph (what each agent
*runs on*, is *used by*, and can *reach*).

<!-- Screenshot placeholder — replace with a capture of the "Local AI agents on endpoints (Preview)"
     subsection of the Advanced Hunting tab. Save it as media/local-ai-agents-on-endpoints.png,
     then uncomment the image line below. -->
<!-- ![Local AI agents on endpoints (Preview)](media/local-ai-agents-on-endpoints.png) -->
> _Screenshot: add `media/local-ai-agents-on-endpoints.png` — the Local AI agents subsection of the 🔬 Advanced Hunting tab._

| Tile | Answers |
|---|---|
| **Inventory & deployment footprint** | Each local agent's vendor, host process, versions, devices, and how widely it's deployed |
| **Remote MCP, local MCP & declared tools** | The MCP servers (remote and **local**) and declared tools each agent uses — and where they run |
| **Risky: auto-approval / untrusted process** | Agents that act without approval, or run in an untrusted host process |
| **Risky agents on critical devices** | Risky agents running on business-critical devices (exposure-graph criticality) |
| **User blast radius** | Users whose local agents can reach **critical / sensitive assets** |
| **Lifecycle: new & removed (7d)** | Local agent profiles added or removed in the last 7 days |

The panels query Defender Advanced Hunting directly. A hidden Azure Resource Graph
parameter derives `properties.customerId` from the visible Sentinel `Workspace` picker
and passes it to every panel's Advanced Hunting workspace selector. The same underlying
queries can be pasted into Defender → **Advanced hunting**. Requires **Defender for
Endpoint Plan 2**; risk levels and recommendations need **Microsoft 365 E7** or
**Microsoft Agent 365**. Docs:
[Discover local AI agents with Microsoft Defender for Endpoint](https://learn.microsoft.com/defender-endpoint/discover-local-ai-agents).

### Visual Studio Code and coding-agent MCP discovery & runtime

The Advanced Hunting tab adds six VS Code-focused panels:

| Panel | Answers |
|---|---|
| **Coverage health** | Whether local profile, endpoint process, and governed gateway telemetry is available |
| **MCP configuration inventory** | Which local/remote MCP servers and declared tools are attached to supported VS Code agent extensions |
| **Exposure by account and device** | Which discovered account/device/extension profiles have MCP access |
| **MCP-like processes** | Which binaries and command lines VS Code spawned, including hashes and elevation |
| **Governed MCP calls** | Which server/tool operations VS Code or GitHub Copilot invoked through `ExecuteToolByGateway` |
| **Prioritized risk** | Auto-approval, untrusted host processes, external/command-capable configuration, and elevated or shell-like MCP child processes |

Defender currently discovers supported VS Code extensions including GitHub Copilot,
Claude Code, Cline, Codex, Gemini Code Assist, and Roo Code. Configuration inventory is
not execution evidence; endpoint process events are not tool-level audit events; and
gateway telemetry covers only governed calls. The companion custom-detection candidates
are in `Use Cases Threat Hunting/Monitoring AI Agents/Local_Agents/`.

---

## 🟨 Copilot Studio MCP exploitation protection (V2)

The Copilot Studio tab includes a local **Approved MCP targets** parameter and six MCP
security panels:

| Panel | Purpose |
|---|---|
| **MCP inventory** | Server/tool targets, call volume, failures, agents, conversations, and latency |
| **Approved-target drift** | Exact connector targets not present in the environment's reviewed allowlist |
| **Command-capable tools** | Shell, command, code execution, SSH, offensive tooling, and RCE-like names |
| **External URL targets** | Explicit HTTP/S destinations outside Microsoft-hosted domains |
| **Agent → MCP chains** | `InvokeAgent` roots joined to `ExecuteTool` spans through `OperationId` |
| **Exploit intent** | RCE, reverse-shell, offensive-tool, and remote-command intent without displaying content |

Use [COPILOT-STUDIO-MCP-SECURITY.md](COPILOT-STUDIO-MCP-SECURITY.md) for the
preventive-control checklist. The core design rule is to remove general-purpose command
execution from production agents, not merely detect prompts that ask the agent to use it.

---

## 🟪 Foundry MCP exploitation protection (V2)

The Foundry Agents tab includes a local **Approved Foundry MCP servers** parameter and
six metadata-first security panels:

| Panel | Purpose |
|---|---|
| **MCP inventory** | Observed servers, tools, agents, models, conversations, failures, and latency |
| **Approved-server drift** | Exact server URLs, labels, or dependency targets outside the reviewed allowlist |
| **Command-capable tools** | Shell, command, code execution, SSH, offensive tooling, and RCE-like names or descriptions |
| **External server targets** | Explicit HTTP/S MCP destinations outside Microsoft/Azure-hosted domains |
| **Agent → MCP chains** | Foundry agent and MCP tool spans correlated through W3C `OperationId` |
| **Intent + execution chain** | Remote-command or exploitation intent joined to an observed command-capable MCP call in the same trace |

Foundry tracing is preview telemetry, and SDKs do not currently emit one universal MCP
server field. V2 checks `gen_ai.tool.name/type`, operation, server label/URL variants,
tool description, and dependency target. Missing server metadata is reported separately
instead of being labeled unapproved. The exploit-chain panel reads legacy trace content
and protected `AppGenAIContent`, deduplicates dual-routed records, and returns metadata
only; prompts, tool arguments, and results are never displayed.

Use `allowed_tools`, require approval for consequential operations, and enforce that
approval in the agent runtime. A system-prompt instruction is not an approval control,
and a toolbox MCP endpoint does not block `tools/call` by itself. Treat remote tool
descriptions and results as untrusted input, use least-privilege agent identities and
project connections, and route MCP traffic through APIM AI Gateway when centralized
policy enforcement is required.

---

## 🌐 APIM AI Gateway observability (V2)

The APIM tab keeps gateway and agent telemetry separate, then correlates them when both
share a W3C `OperationId`:

| Layer | What the tab shows |
|---|---|
| **Gateway** | Request volume, success rate, HTTP result codes, p50/p95/p99 latency, API operations, consumers, and recent failures |
| **Backend** | Dependency targets, call volume, failures, average and p95 latency |
| **Request + exception diagnostics** | Correlated exception trends and hot spots, caller/route blast radius, timeout and cancellation concentration, version/instance regressions, and failed requests without exception evidence |
| **LLM metrics** | Token custom metrics emitted by `llm-emit-token-metric`, when enabled |
| **Agent OTel spans** | Agent, model, conversation, tool calls, tokens, and failures from `gen_ai.*` data in `AppDependencies` |
| **Agent OTel content** | Prompts, responses, instructions, and tool payloads in protected `AppGenAIContent`; V2 reports health counts but does not render content |
| **Correlation** | Gateway requests joined to spans through `OperationId`; `AppGenAIContent.TraceId` maps to the same W3C trace ID |

The threat-protection area includes analyst guidance before each panel. Reconnaissance
results are event-level and include attempted method/URL, request and operation IDs,
caller, burst context, service/region, and latency. Prompt Shield/content-safety results
show sanitized policy markers enriched with the correlated request result and route;
prompt or response content is never displayed.

Every APIM operational panel also includes guidance explaining what the visualization
means, how to investigate it, expected prerequisites, and important limitations such as
sampling, missing identity fields, streaming token undercount, and partial trace coverage.
`AppRequests` and `AppExceptions` diagnostics correlate on `OperationId` and use
`ItemCount` for sampled event totals. Exception messages are displayed in root-cause
views and can contain sensitive application data.

The APIM payload-security subsection intentionally displays parsed `Input`,
`Instructions`, `Model`, and `Tools`, plus full `RequestBody` and `ResponseBody` fields.
It includes payload coverage, raw investigation, content-safety 403 confirmation,
prompt-injection outcome, and sensitive-data panels. In an Application Insights resource
the equivalent schema is `requests.customDimensions`; in Log Analytics it is
`AppRequests.Properties`.

APIM telemetry is an API/network transaction view; OpenTelemetry GenAI instrumentation
supplies the semantic agent execution and content views. For high-volume APIs, tune
diagnostic sampling and always log errors rather than treating Application Insights as
an audit store. Because bodies are displayed, apply strict workspace/workbook RBAC,
retention, export, screenshot, and incident controls.

V2 identifies APIM-emitted rows with `SDKVersion startswith "apim:"`. This is the
gateway's current sender signature, not a documented permanent schema contract. After
onboarding, verify it with `AppRequests | summarize count() by SDKVersion`.

### Generate test traffic with two agents

The [APIM simulator](apim-simulator/README.md) includes two instrumented synthetic
agents, a temporary APIM mock API, intentional success/failure traffic, and a KQL
verification query. It is preconfigured for `APIMAgentAI` in `RG_Sentinel` and its
linked `appi-apjizpjl4algs` / `logs-apjizpjl4algs` resources in `rg-foundrykit`;
secrets are retrieved only at runtime and are not stored.

---

## Key capabilities

- **Cross-source AI visibility** — one workbook over M365 Copilot, Copilot Studio,
  Foundry, OpenAI, APIM AI Gateway, Defender XDR, and the Agent Observability lake.
- **Framework-independent gateway visibility (V2)** — monitor custom/containerized
  agents, A2A calls, MCP/tool endpoints, models, and REST/knowledge services exposed
  through APIM, then enrich transactions with agent OTel when available.
- **AI Gateway threat detections (V2)** — authentication/policy-block bursts,
  throttling and denial-of-wallet pressure, route reconnaissance, 5xx failures, and
  sanitized Prompt Shield/content-safety events. See `APIM-SECURITY.md` for controls.
- **AppRequests body detections (V2)** — full input/request/response investigation,
  confirmed content-safety blocks, allowed prompt-injection patterns, sensitive-data
  indicators, model/tool inventory, and payload-logging coverage. Scheduled rules and
  saved hunts are in `Use Cases Threat Hunting/Monitoring AI Agents/APIM_Gateway/`.
- **Copilot Studio MCP exploitation detections (V2)** — approved-target drift,
  command-capable tools, external destinations, full agent-to-tool traces, and optional
  exploit/RCE intent signals. See `COPILOT-STUDIO-MCP-SECURITY.md` for controls.
- **Foundry MCP exploitation detections (V2)** — observed MCP inventory,
  approved-server drift, command-capable tools, external destinations, trace chains,
  and exploit intent correlated with command-capable tool execution.
- **Prompt-injection & jailbreak hunting** — one Content Safety tab for M365 Copilot
  native XPIA/jailbreak flags, Foundry filter/Prompt Shield metadata, Copilot Studio
  heuristic injection markers, and APIM gateway policy/block outcomes; Defender
  `BehaviorInfo` Prompt Shield detections remain in Advanced Hunting.
- **Agent inventory & governance** — every agent's type, auth, knowledge, tools, MCP
  servers, and owners; ownerless / inactive / growth; shadow-AI usage.
- **Local AI agent discovery (Defender for Endpoint, Preview)** — inventory and
  deployment footprint, remote/local MCP and declared tools, risky auto-approval or
  untrusted host processes, risky agents on **critical devices**, and the user
  **blast radius** to critical/sensitive assets via the exposure graph.
- **VS Code MCP monitoring (Preview)** — configured MCP servers and tools by extension,
  account and device; MCP-like child processes; governed tool calls; and prioritized
  auto-approval, untrusted-process, external-server, command-capability, and elevation risk.
- **Supply-chain & MCP surface** — agents exposing MCP servers / connected agents,
  tool usage, and access drift (tools newly used by an agent).
- **Content safety & model observability** — harm categories, per-model tokens /
  latency / cost / failures, denial-of-wallet token spikes.
- **Cost estimation** — token-cost tiles driven by the `PriceInput` / `PriceOutput`
  parameters.
- **AI Risk Score** — a weighted 0–100 composite with component sub-scores for
  executive reporting.
- **AI Attack Matrix** — 30-risk English catalog, OWASP/MITRE ATLAS references,
  defense-zone/control-family mapping, evidence traceability, explicit telemetry gaps,
  and PASS/FAIL/ERROR/INCONCLUSIVE runtime verdicts.
- **Investigation workflow** — entity pivot into cross-source timeline, related
  alerts, and related sign-ins.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `Workspace` | Resource picker | — | Target Log Analytics / Sentinel workspace (portable across tenants). |
| `AdvancedHuntingWorkspaceId` | Hidden ARG-derived value | From `Workspace` | Customer ID passed directly to Defender Advanced Hunting panels. |
| `APIMSubscription` | Subscription picker | *(select)* | Subscription containing the APIM Application Insights workspace. |
| `APIMTelemetrySource` | Dropdown | `Application Insights` | Switches every APIM panel between direct component scope and backing workspace scope. |
| `APIMWorkspace` | Resource picker | *(optional)* | APIM Log Analytics workspace for `AppRequests` / `Properties` mode. |
| `APIMApplicationInsights` | Resource picker | *(optional)* | APIM Application Insights component for `requests` / `customDimensions` mode; use this when a managed workspace cannot be selected. |
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
| **Copilot Studio** | For legacy views, point the agent's workspace-based Application Insights at `Workspace`. For full `InvokeAgent` → `ExecuteTool` chains, configure **environment-level Copilot Studio export** to Application Insights in a managed environment; initial delivery can take up to 24 hours. Content-based panels additionally require approved content recording and protected-table access. |
| **Foundry** | Project connected to workspace-based App Insights so spans land in `AppDependencies`. Set `AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true` for text-content tiles (not retroactive). |
| **OpenAI** | OpenAI codeless connector + parsers so `ASimAgentEventLogs` / `OpenAIAuditLogs` resolve. Callers should set the `user` request param for per-user tiles. |
| **APIM AI Gateway (V2)** | Select the APIM subscription and telemetry source. **Application Insights** mode queries the component directly (`requests`, `customDimensions`) and works when its managed workspace is unavailable in the picker. **Log Analytics workspace** mode uses `AppRequests` and `Properties`. Connect APIM using a connection string and managed identity; grant **Monitoring Metrics Publisher**, enable API diagnostics with W3C correlation, and preserve `traceparent`. |
| **Defender XDR & Agents** | Defender-native Advanced Hunting access. Local discovery uses `AgentsInfo`; VS Code runtime evidence uses `DeviceProcessEvents` and governed `CloudAppEvents`; blast-radius panels use `ExposureGraphNodes/Edges`. The visible `Workspace` must be connected in the Defender portal so its customer ID is accepted by the Advanced Hunting selector. Local discovery requires **Defender for Endpoint Plan 2**; risk features can require **Microsoft 365 E7** or **Microsoft Agent 365**. |
| **Data Lake** | Agent Observability onboarded; `UnifiedAgentObservability` + Entra Agent Identity tables in the lake tier (usage-based billing — widen the time range carefully). |

---

## Deploy / import

**Portal (manual import)**

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `AI-Agents-Monitoring-Workbook-V2.workbook` and **Apply**.
3. **Done Editing** → **Save**, name it *AI Agents Monitoring V2*, and pick your resource
   group / workspace.
4. Select your **Workspace** and **Time range**, then work the tabs. Use **Agent /
   bot / model / actor contains** to focus the per-source grids on one agent.

**Deploy or update the separate V2 resource**

```powershell
.\deploy-workbook-v2.ps1 `
  -SourceWorkspaceResourceId '/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<sentinel-workspace>'
```

The script derives the subscription, target resource group, location, and stable workbook
resource ID from the selected source workspace. The APIM subscription and workspace are
then selected at run time and can belong to another environment.

**Run Advanced Hunting tiles directly**

The 🔬 Advanced Hunting tab uses `queryType: advancedHunting`. The same queries can be
pasted into the Defender portal → **Advanced hunting** (`security.microsoft.com`) — the
tab header includes ready-to-run snippets for `BehaviorInfo`, `AgentsInfo`,
`AADAgentRiskEvents`, and the local-agent (`AgentsInfo` `Platform == "LocalAgents"`)
scenarios.

---

## Notes

- **Read-only.** The workbook never modifies agents, identities, or configuration.
- **APIM privacy.** V2 does not render payloads. Keep APIM body logging at `0` bytes by
  default; if content logging is approved, mask sensitive headers and query parameters.
- **GenAI content.** `AppGenAIContent` comes from OTel instrumentation, not APIM. Mark
  it as a protected table. From September 30, 2026, new values for prompts, responses,
  system instructions, and tool arguments/results are stored there instead of inline
  in `AppDependencies`, `AppTraces`, or `AppEvents`.
- **APIM metric cardinality.** `llm-emit-token-metric` allows at most five custom
  dimensions. Do not use prompt, conversation, request, or other high-cardinality IDs.
- **Cost lever.** The 📡 Telemetry Health tab shows the `AppDependencies` gen_ai-vs-other
  split and content-recording coverage so you can size ingestion before enabling text
  detections tenant-wide.
- **Graceful degradation.** `union isfuzzy=true` and `column_ifexists()` keep tiles
  rendering on tenants missing a given source or optional column.
- **Data-lake tiles** query the lake tier and incur usage-based charges — widen their
  time range deliberately.
