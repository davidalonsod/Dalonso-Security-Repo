Hunting AI Agents: A Sentinel Data Lake Investigation Notebook

# Agent 365 - Sentinel data-lake observability

This bundle is the **data-lake-tier** approach to monitoring Microsoft
Agent 365 telemetry. It is the companion to the Log-Analytics-tier
`Copilot/` bundle (which targets `CopilotActivity` for Microsoft 365
Copilot).

> **Status**: scaffolding only. Microsoft has not yet published the
> Agent 365 ASIM-aligned table name or schema. Once it does, populate
> the folders below with the actual content (KQL jobs, hunting queries,
> tier-up summary rules).

---

## Notebook capabilities - `Hunting_AIAgents_Investigation_Notebook.ipynb`

A PySpark / Livy notebook that runs **inside the Sentinel data lake** and
correlates the lake `UnifiedAgentObservability` and Entra System tables
with the Foundry, Copilot Studio, and Microsoft 365 Copilot telemetry
already ingested into the workspace Analytics tier (`AppEvents`,
`AppDependencies`, `CopilotActivity`). It is the working, runnable
front end of this bundle: role-based reporting, threat hunting,
behavioral anomaly detection, and SOC investigation boards over data
that returns rows in the tenant today.

**Design guarantees**

- Aggregation happens in Spark; only compact summaries reach
  pandas / matplotlib, so panels stay fast.
- Every source is optional - absent tables make a panel skip cleanly
  rather than error.
- Prompt and response bodies are **never** plotted or written to
  findings; text-dependent hunts expose counts and identifiers only.
- Heuristic results are labelled **candidates** and kept distinct from
  native service verdicts (Prompt Shield / content-safety).
- No Defender Advanced Hunting dependency (`AgentsInfo` / `BehaviorInfo`
  are not in this lake or workspace).

| Section | Capability | Audience |
| --- | --- | --- |
| 1-7 | Estate & governance reporting, identity reconciliation, SRE health, transparent SOC heuristics, composite risk score, focused agent timeline, optional compact findings output | CISO, Entra admin, SRE, SOC, investigator |
| 8 | Closes lake gaps with ingested **Copilot Studio + Foundry** Application Insights (tools/MCP, model + tokens + cost, content-safety, channel, connector reliability) | Detection engineering |
| 9 | Advanced executive visuals - KPI ribbon, weekday x hour activity heatmap, top-agents-by-risk | CISO, SOC |
| 10 | Cross-source estate board + **unified conversation-volume anomaly** (rolling mean + 2σ spike candidates) | SOC |
| 11 | **Foundry** hunting scenarios - guardrail/prompt-shield, injection & secrets markers, model fingerprinting, tool chaining, cross-agent lateral movement, token-cost spike, trace anomalies, dormancy break | SOC |
| 12 | **Copilot Studio** hunting scenarios - conversation flooding, injection/bulk-exfil/secret markers, indirect injection, connector error storm, new/sensitive connectors, latency, fan-out | SOC |
| 13 | **SOC investigation boards** - 13a Foundry, 13b Copilot Studio, 13c cross-platform triage queue; each goes signal → ranked entity → scoped evidence → next pivot | SOC |
| 14 | **Behavioral anomaly gap analysis** - dormant reactivation, operating-hours shift, new A2A / A2T / user-to-agent edges, tool-call rate spikes, repetition loops, operation expansion | SOC |
| 15 | **Microsoft 365 Copilot** board over `CopilotActivity` - native verdicts, DLP/sensitivity, resources & plugins, pacing | SOC |

**Investigation flow:** `System-table health → schema normalization →
inventory / governance → activity & SRE → cross-source hunts →
SOC boards → behavioral anomalies → focused timeline / findings`

**Prerequisites:** Sentinel data lake onboarding with **System tables**
read access; VS Code Sentinel extension signed in to the tenant; a
**Microsoft Sentinel** runtime pool (Medium is a practical start - no
package installs, only runtime PySpark + matplotlib). Set
`WORKSPACE_NAME` in the controls cell to enable the Analytics-tier
sections. Foundry text-content tiles additionally require
`AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true`.

**Interpretation boundary:** agent telemetry describes behavior, not
intent. Every detection output is a triage lead requiring analyst
validation.

---

## Why data-lake-tier

Per the Microsoft Sentinel blog post **"Agent 365 connector: monitor,
hunt and investigate AI agent activity in Microsoft Sentinel"**
(May 2026):

> "Agent 365 agent observability data is normalized into an ASIM-aligned
> schema so it is consistent, queryable, and ready for analytics and
> detections."

The telemetry lands in the **Sentinel data lake**, not in Log Analytics.
Consequences:

- **Scheduled analytic rules** (`Microsoft.SecurityInsights/alertRules`)
  cannot query data-lake-only tables directly.
- **`savedSearches` hunting queries** (the analytics-tier "Hunting"
  blade) cannot query them either.
- Investigation surfaces:
  - **Defender portal -> Hunting** (advanced hunting against the lake).
  - **KQL jobs** scheduled against the lake.
  - **Summary rules** that aggregate lake data into a smaller
    Log-Analytics-tier table (and *then* analytic rules can run on that
    summary table).

---

## Discovery checklist (do this first in your tenant)

1. Enable the **Agent 365 (`A365Observability`)** data connector on the
   target Sentinel workspace.
2. Defender portal -> **Hunting** -> Advanced hunting -> run:
   ```kusto
   search "Agent365"
   | summarize by $table
   ```
   Note the actual table name(s) and their tier (lake vs analytics).
3. Pull the schema of each discovered table:
   ```kusto
   <TableName>
   | take 1
   | getschema
   ```
4. Compare against the ASIM column conventions (`EventVendor`,
   `EventProduct`, `EventType`, `ActorUsername`, `TargetAppName`, etc.)
   to confirm which ASIM schema the table aligns with (ASIM
   AuditEvent, ASIM Authentication, or a new AI-specific schema).
5. Record findings in `Discovery/findings.md`.

---

## Folder layout

| Folder | Contents |
| --- | --- |
| `Discovery/` | Notes / KQL snippets used to identify the real Agent 365 table(s) and schema in your tenant |
| `KqlJobs/` | Scheduled KQL jobs that run against the data-lake table(s) |
| `Hunting/` | Defender-portal hunting queries (data-lake-aware) |
| `SummaryRules/` | Tier-up summary rules that aggregate lake data into a Log-Analytics summary table so analytic rules can fire on it |
| `Workbooks/` | Sentinel workbooks - `AI-Governance.workbook` (full tabbed AI Governance & Exposure dashboard: estate, agents, models, MCP, shadow AI, risk, exfiltration, lifecycle) and `AI-Agent-Sprawl.workbook` (lighter shadow-AI/sprawl view). Both query Log-Analytics-tier signals and work today. Companion detections in `Hunting/AI-Governance-Detections.kql` |
| `OpenAI-Connector/` | **Deployable bundle 1** - native OpenAI CCF connector detections (`OpenAIAuditLogs` / `ASimAgentEventLogs`). 6 analytic rules + 3 hunting queries + ARM. See [`OpenAI-Connector/README.md`](../OpenAI-Connector/README.md) |
| `Foundry-AppInsights/` | **Deployable bundle 2** - Foundry guardrail / content-safety detections that read Application Insights `AppDependencies` (`Properties` / `gen_ai.*`). 10 analytic rules + 6 hunting queries + watchlist + ARM + Simulation harness. See [`Foundry-AppInsights/README.md`](../Foundry-AppInsights/README.md) |

---

## Two deployable detection bundles

The deployable detections are split into two **independent** bundles,
each with its own ARM template, generator and README. They share no
resources and can be deployed separately.

### Bundle 1 - `OpenAI-Connector/` (native CCF connector)

Targets the **Analytics-tier** tables the Microsoft Sentinel **OpenAI**
connector and its parsers expose (`OpenAIAuditLogs`,
`OpenAIChatCompletions` / `ASimAgentEventLogs`). The OpenAI solution
ships parsers and a codeless connector but **no analytic rules**; this
bundle fills that gap by porting the reusable subset of the sibling
`Copilot/` detections.

- 6 scheduled analytic rules + 3 hunting queries.
- Deploy: `OpenAI-Connector/Deploy/azuredeploy.json`.
- Full table and prerequisites: [`OpenAI-Connector/README.md`](../OpenAI-Connector/README.md).

> **Actor join caveat**: `ASimAgentEventLogs` has no first-class user
> column. Per-user rules key on `AdditionalFields.input_user` (the
> OpenAI `user` request parameter). If callers do not set it, baseline
> on `ModelName` alone or promote the API-key id instead.

### Bundle 2 - `Foundry-AppInsights/` (Application Insights telemetry)

Targets the real **Foundry / Agent Service** trace shape confirmed in
this tenant: spans land in **`AppDependencies`**, the property bag is
**`Properties`** (not `customDimensions`), and the keys are
**`gen_ai.*`** plus **`microsoft.foundry.content_filter.results`**.
Prompt / response text is in `gen_ai.input.messages` /
`gen_ai.output.messages` and requires
`AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true`.

- 10 scheduled analytic rules + 6 guardrail / content-safety / behaviour hunting queries.
- A `FoundryTrustedToolSources` watchlist used by the untrusted-tool-source rule.
- A `Simulation/` harness that drives test prompts so the rules / hunts light up.
- Deploy: `Foundry-AppInsights/Deploy/azuredeploy.json` (`enableAnalyticRules` toggles the rules).
- Full table, prerequisites and testing: [`Foundry-AppInsights/README.md`](../Foundry-AppInsights/README.md).

Copilot-specific OpenAI detections that depend on prompt / response
text, grounding sources, or sensitivity labels were **not** ported to
bundle 1 - the OpenAI connector does not expose that data; the
equivalent prompt-level visibility now comes from bundle 2 instead.

---

## Three rebuild strategies

When you populate this bundle, pick one of the following per detection:

1. **Park and wait** - leave a detection in the `Copilot/` bundle
   pointing at `CopilotActivity` while you wait for Microsoft to
   document the Agent 365 schema.
2. **Tier-up summary rule** - write a summary rule (in
   `SummaryRules/`) that aggregates lake data into a custom
   Log-Analytics table, then write a thin scheduled analytic rule
   against that summary table.
3. **Native data-lake job** - port the detection to a scheduled KQL job
   (in `KqlJobs/`) that runs against the data-lake table directly,
   raising findings via a notification channel rather than a Sentinel
   incident.

---

