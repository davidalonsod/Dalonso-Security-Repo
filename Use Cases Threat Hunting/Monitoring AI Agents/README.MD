
Monitoring AI Agents: Observability in Foundry & Copilot Studio" https://youtu.be/5Axu9dJ2lfw
# AI Agent Threat Detection for Microsoft Sentinel

Detection engineering content for monitoring AI agents, copilots, model APIs,
tools, and MCP activity across Microsoft Sentinel, Application Insights, Azure
API Management, and Microsoft Defender XDR.

The repository separates each telemetry plane into an independent pack. This is
intentional: a prompt match, a gateway response, a tool span, and an endpoint
process are different kinds of evidence and must not be presented as equivalent
proof of compromise.

## Detection packs

| Pack | Primary telemetry | Content |
| --- | --- | --- |
| [APIM Gateway](./APIM_Gateway/README.MD) | `AppRequests` / Application Insights `requests`, captured request and response bodies | **7 analytics + 4 hunts**, with one-to-one workbook panels in both query modes |
| [Microsoft Foundry agents](./Foundry_Agents/README.MD) | `AppDependencies` `gen_ai.*` spans and protected `AppGenAIContent` | **36 analytics + 21 hunts + 3 watchlists** |
| [Microsoft Copilot Studio](./CopilotStudio/README.MD) | `AppEvents`, connector `AppDependencies`, and environment-level agent/tool spans | **28 analytics + 16 hunts + 2 watchlists** |
| [Microsoft 365 Copilot](../CopilotActivity/README.MD) | Microsoft Copilot connector `CopilotActivity` | **16 analytics + 14 hunts** |
| [OpenAI connector](./OpenAI-Connector/README.MD) | `OpenAIAuditLogs`, `OpenAIChatCompletions`, and `ASimAgentEventLogs` | **6 analytics + 3 hunts** |
| [Local agents and VS Code MCP](./Local_Agents/README.MD) | Defender `AgentsInfo`, `DeviceProcessEvents`, `CloudAppEvents`, and exposure graph | **4 Defender custom-detection candidates** |

The Sentinel packs contain **93 scheduled analytics and 58 hunting queries**.
Generated ARM templates are checked into each pack under `Deploy/`, but rules are
not automatically enabled or deployed by browsing this repository.

## What the detections cover

- Direct and indirect prompt injection, jailbreaks, and system-prompt disclosure.
- Sensitive information in prompts and responses, bulk retrieval, and exfiltration
  indicators.
- New, sensitive, command-capable, unapproved, or poisoned tools, connectors, and
  MCP servers.
- SSRF-like internal targets where tool destination telemetry is available.
- Excessive agency, tool chaining, retry storms, loops, throttling, and cost
  amplification.
- Goal drift, session contamination, memory poisoning, inter-agent trust
  escalation, and computer-use attacks where the runtime emits the required spans.
- Model, plugin, configuration, resource-access, and supply-chain drift.
- Threat-intelligence URL matches, off-hours activity, and multi-stage attack
  chains.

Coverage follows telemetry, not aspiration. Training-data extraction, model
inversion, vector-database poisoning, factual hallucination, adversarial
hallucination, and AI package hallucination remain explicit gaps unless model
evaluation, vector-store audit, provenance, or package-install evidence is added.
Microsoft 365 Copilot also does not expose the tool arguments and target details
needed to substantiate SSRF or function-call manipulation.

## Workbook

The V2 AI Agents Monitoring workbook provides 20 tabs and 183 query tiles. Its
**AI Attack Matrix** maps 30 risks to Foundry, Copilot Studio, Microsoft 365
Copilot, APIM, Defender, and OpenAI evidence using four coverage states:

| State | Meaning |
| --- | --- |
| `COVERED` | Direct workbook visibility and deployable detection content exist |
| `OBSERVABLE` | Relevant evidence exists but does not establish the complete attack |
| `PARTIAL` | Evidence is heuristic, schema-dependent, or limited to one telemetry plane |
| `GAP` | Current telemetry cannot substantiate the claim |

Runtime verdicts are separate: `PASS` means an explicit control block, `FAIL`
means suspicious behavior was allowed or emitted, `ERROR` means an operational
failure prevented a conclusion, and `INCONCLUSIVE` means impact cannot be proven.
No event is never treated as an automatic pass.

## Choose a pack

- Deploy [Foundry agents](./Foundry_Agents/README.MD) for Foundry projects that
  export OpenTelemetry traces to workspace-based Application Insights.
- Deploy [Copilot Studio](./CopilotStudio/README.MD) for agent-level events,
  connector calls, and environment-level `InvokeAgent` / `ExecuteTool` spans.
- Deploy [Microsoft 365 Copilot](../CopilotActivity/README.MD) when the Microsoft
  Copilot connector populates `CopilotActivity` on the Analytics plan.
- Deploy [APIM Gateway](./APIM_Gateway/README.MD) when agent traffic crosses APIM
  and request/response body capture is approved.
- Deploy [OpenAI connector](./OpenAI-Connector/README.MD) for the Sentinel OpenAI
  codeless connector tables.
- Use [Local agents](./Local_Agents/README.MD) in Defender Advanced Hunting for
  endpoint-discovered agents and VS Code MCP activity.

Packs can be combined. Deploy analytics disabled first, populate required
watchlists, execute the KQL against representative telemetry, tune thresholds,
and only then enable incident creation.

## Controlled APIM simulation

The [APIM attack-simulation playbook](./APIM_Gateway/Testing/APIM-Attack-Simulation-Playbook.md)
contains inert prompts and request payloads for all seven APIM analytics, expected
workbook evidence, deterministic mock-response guidance, stop conditions, and
cleanup. Run it only against an owned nonproduction API.

---

## Configure Application Insights

Use a **workspace-based** Application Insights resource whose backing
Log Analytics workspace is the Microsoft Sentinel workspace where you
deploy these detections. A connection to another workspace can show
traces in Application Insights but does not populate the tables queried
by this repository in the target Sentinel workspace.

### Microsoft Foundry - one configuration per project

Application Insights is connected at the **Foundry project** scope. The
connection automatically enables server-side tracing for every prompt
and hosted agent in that project; you do not configure each agent
separately. Repeat these steps for each project that you want to monitor.

1. In the Azure portal, create or select a workspace-based Application
  Insights resource connected to the target Sentinel workspace.
2. Give operators who need to query traces **Log Analytics Reader** on
  the Application Insights resource or its backing workspace. If the
  tables are protected, also assign **Privileged Monitoring Data
  Reader**.
3. Open [Microsoft Foundry](https://ai.azure.com/) and ensure the **New
  Foundry** experience is selected.
4. Open the project, select **Agents**, and then select **Traces**.
5. Select **Connect**, choose the Application Insights resource from
  step 1, and select **Connect** again. You can create a resource from
  this dialog, but verify that it uses the target Sentinel workspace.
6. If **Connect** is not shown, select **Manage** -> **Project details**
  -> **Connected resources** -> **Add connection** -> **Application
  Insights**.
7. Run an agent once. After a few minutes, confirm the run appears under
  the project's **Traces** view.
8. In the Sentinel workspace, run the following query and confirm that
  the project is producing `gen_ai.*` spans:

  ```kusto
  AppDependencies
  | where TimeGenerated > ago(30m)
  | where isnotempty(tostring(Properties["gen_ai.agent.name"]))
  | project TimeGenerated,
     AgentName = tostring(Properties["gen_ai.agent.name"]),
     Operation = tostring(Properties["gen_ai.operation.name"]),
     Success
  | take 20
  ```

For custom client-side code paths that need prompt and response content,
set `AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true` and
`OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true` in the agent
host. Treat prompt, response, and tool-argument tracing as sensitive
production data and review access, retention, and ingestion cost first.

To connect multiple Foundry projects, use the repository helper in
[`Foundry_Agents/Deploy/Enable-FoundryTracing.ps1`](./Foundry_Agents/Deploy/Enable-FoundryTracing.ps1).
It inventories projects in dry-run mode by default and changes them only
with `-Apply`. This is still a **per-project connection** performed in
bulk; one project connection covers all agents inside that project.

Full Foundry prerequisites and helper-script examples are in
[`Foundry_Agents/README.MD`](./Foundry_Agents/README.MD).

### Copilot Studio - one configuration per agent

Use this mode for the existing `CopilotStudio` rules. It is
available to agents that use the **standard harness** and emits the
event-based `AppEvents` and connector `AppDependencies` shape expected
by the bundle.

1. In the Azure portal, open the workspace-based Application Insights
  resource connected to the target Sentinel workspace and copy its
  **Connection string** from **Overview**.
2. Open [Copilot Studio](https://copilotstudio.microsoft.com/), select
  the correct Power Platform environment, and open the agent.
3. Select **Settings** -> **Advanced** -> **Application Insights**.
4. Paste the connection string.
5. Turn on **Enable logging**.
6. Turn on **Log conversation details** when user identity, message text,
  and tool input/output are required. In some UI versions, message text
  is controlled by **Log sensitive Activity properties** or **Log
  sensitive properties**; enable it only after privacy and compliance
  approval. The repository's text-content detections remain silent
  when message text is not collected.
7. Optionally turn on **Node execution events** when topic/node
  diagnostics are needed.
8. Save the settings and run a new test conversation. Telemetry is not
  retroactive.
9. In the Sentinel workspace, verify both event and connector telemetry:

  ```kusto
  union isfuzzy=true
     (AppEvents
      | where TimeGenerated > ago(30m)
      | where Name in ("BotMessageReceived", "BotMessageSend")
      | project TimeGenerated, Table="AppEvents", Name,
        ConversationId=tostring(Properties["conversationId"])),
     (AppDependencies
      | where TimeGenerated > ago(30m)
      | where AppRoleName == "Microsoft Copilot Studio"
        or DependencyType == "Connector"
      | project TimeGenerated, Table="AppDependencies", Name,
        ConversationId=tostring(Properties["conversationId"]))
  | take 20
  ```

Repeat steps 2-8 for every standard-harness agent that needs the current
Sentinel detection bundle.

### Copilot Studio - all agents in an environment (preview)

Copilot Studio also supports a centralized **environment-level** export.
This configures all eligible Copilot Studio agents in one Power Platform
environment, including standard- and GitHub Copilot-harness agents. It
does not include declarative agents. There is currently no single
tenant-wide switch; repeat the export for each environment.

Requirements and limitations:

- The Power Platform environment must be a **Managed Environment**.
- The feature is preview, is rolling out by region, and might require
  the environment's **Early release cycle** in a non-production test.
- The configuring identity needs the tenant-level **Power Platform
  administrator** or **Dynamics 365 administrator** role and the
  Dataverse **Environment administrator** or **System administrator**
  role.
- The identity also needs **Contributor** or **Owner** on the target
  Application Insights resource, and Application Insights **local
  authentication must be enabled**.

Configure the export:

1. Sign in to the [Power Platform admin
  center](https://admin.powerplatform.microsoft.com/).
2. Select **Manage** -> **Data export** -> **App Insights**.
3. Select **New data export** and enter a descriptive package name.
4. Select **Copilot Studio** as the data type and configure any required
  filters.
5. Select the source Managed Environment, and then select **Next**.
6. Select the Azure subscription, resource group, and workspace-based
  Application Insights destination, and then select **Next**.
7. Review the configuration and select **Create**.
8. Run a test conversation. Initial delivery can take up to 24 hours.
9. In Application Insights **Logs**, verify that `InvokeAgent`,
  `ExecuteTool`, and `OutputMessages` spans appear in `dependencies`
  and share an `operation_Id` for each turn. In the Sentinel workspace,
  the corresponding table is `AppDependencies`.

Environment-level export uses an OpenTelemetry-aligned span schema in
`dependencies` / `AppDependencies`, with agent fields under
`customDimensions` / `Properties` as `gen_ai.*`. It is **not the same
schema** as the agent-level `AppEvents` + connector `AppDependencies`
telemetry consumed by the current `CopilotStudio` rules.
Microsoft also recommends not sending both scopes to the same
Application Insights instance. Therefore:

- Use **agent-level telemetry** for the existing Copilot Studio bundle.
- Use **environment-level telemetry** for centralized all-agent
  observability, preferably in a separate Application Insights resource.
- Do not enable the existing Copilot Studio analytic rules against only
  environment-level telemetry until the rules are adapted and tested
  for its OpenTelemetry schema.

Official setup references:

- [Set up tracing in Microsoft Foundry](https://learn.microsoft.com/azure/foundry/observability/how-to/trace-agent-setup)
- [Copilot Studio agent-level telemetry](https://learn.microsoft.com/microsoft-copilot-studio/advanced-bot-framework-composer-capture-telemetry)
- [Copilot Studio environment-level telemetry](https://learn.microsoft.com/microsoft-copilot-studio/advanced-environment-level-agent-telemetry)
- [Export Power Platform data to Application Insights](https://learn.microsoft.com/power-platform/admin/set-up-export-application-insights)

---

## Deploy

Each bundle regenerates and ships its own ARM template. The general flow
is the same everywhere:

```powershell
# 1. (re)build the template from the YAML sources
.\<Bundle>\Deploy\New-*ArmTemplate.ps1

# 2. deploy with Azure CLI
az deployment group create `
  --resource-group <sentinel-rg> `
  --template-file .\<Bundle>\Deploy\azuredeploy.json `
  --parameters workspaceName=<workspace-name> enableAnalyticRules=true
```

See each bundle's `README.md` and `Deploy/README.md` for the exact
parameters, watchlist requirements and prerequisites.

---

## Repository layout

| Path | Contents |
| --- | --- |
| [`APIM_Gateway/`](./APIM_Gateway/README.MD) | APIM body-aware analytics, hunts, ARM deployment, and controlled simulation playbook |
| [`Foundry_Agents/`](./Foundry_Agents/README.MD) | Foundry analytics, hunts, watchlists, tracing helper, and ARM deployment |
| [`CopilotStudio/`](./CopilotStudio/README.MD) | Copilot Studio analytics, hunts, watchlists, and ARM deployment |
| [`Local_Agents/`](./Local_Agents/README.MD) | Defender custom-detection candidates for endpoint agents and VS Code MCP |
| [`OpenAI-Connector/`](./OpenAI-Connector/README.MD) | OpenAI CCF connector analytics, hunts, and ARM deployment |
| [`../CopilotActivity/`](../CopilotActivity/README.MD) | Microsoft 365 Copilot analytics, hunts, testing, and ARM deployment |
| [`Watchlists/`](./Watchlists/) | Shared watchlist definitions used by detection content |

---

## Pre-requisites

- Microsoft Sentinel enabled on the target Log Analytics workspace.
- The relevant telemetry source connected for whichever bundle you
  deploy (Foundry / Copilot Studio Application Insights export, or the
  OpenAI connector, or the Agent 365 data-lake connector).
- Permissions to create analytic rules, hunting queries and watchlists
  on the workspace.

Per-bundle prerequisites (tracing flags, sensitive-property logging,
parser installation, watchlist seeding) are documented inside each
bundle's `README.md`.

