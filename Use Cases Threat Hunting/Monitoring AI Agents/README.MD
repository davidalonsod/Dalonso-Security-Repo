# AI Agent Threat Detection for Microsoft Sentinel

Microsoft Sentinel detection content for monitoring **AI agents** across
the three runtimes most organisations are putting into production today:

- **Microsoft Foundry / Agent Service** agents
- **Microsoft Copilot Studio** agents
- **OpenAI** (platform / API)

Each runtime emits a different telemetry shape, so the repo is organised
as **independent, deployable-today bundles**. Every bundle ships its own
analytic rules, hunting queries, watchlists, an ARM template and a
generator script, and can be deployed on its own. They share no resources.

---

## What we monitor

| Bundle | Runtime | Telemetry it reads | Detections |
| --- | --- | --- | --- |
| [`Foundry-AppInsights/`](./Foundry-AppInsights/README.md) | Microsoft Foundry / Agent Service | Application Insights `AppDependencies` spans - `Properties` / `gen_ai.*` / `mcp.*` / `microsoft.foundry.content_filter.results` | 30 analytic rules + 12 hunting queries |
| [`CopilotStudio-AppInsights/`](./CopilotStudio-AppInsights/README.md) | Microsoft Copilot Studio | Application Insights `AppEvents` (bot turns) + `AppDependencies` (connector calls) | 19 analytic rules + 12 hunting queries |
| [`OpenAI-Connector/`](./OpenAI-Connector/README.md) | OpenAI (platform / API) | Sentinel OpenAI codeless connector - `OpenAIAuditLogs` / `OpenAIChatCompletions` / `ASimAgentEventLogs` | 6 analytic rules + 3 hunting queries |
| [`Agent365-DataLake/`](./Agent365-DataLake/README.md) | Microsoft Agent 365 (data-lake tier) | ASIM-aligned Agent 365 tables in the Sentinel data lake | KQL jobs + summary rules + workbooks (scaffolding) |

---

## Coverage at a glance

All three runtime bundles align to the **Microsoft AI Red Team v2.0
failure-mode taxonomy**
([blog, June 2026](https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/))
and to MITRE ATT&CK. The depth of coverage tracks what each telemetry
source actually exposes.

| Threat area | Foundry | Copilot Studio | OpenAI |
| --- | :---: | :---: | :---: |
| Prompt injection / jailbreak (direct + indirect) | yes | yes | partial |
| Sensitive data in prompt / response (secrets, PII) | yes | yes | n/a |
| System-prompt / capability disclosure | yes | yes | - |
| Sensitive / new tool or connector invocation | yes | yes | yes |
| Goal hijacking / goal drift across a session | yes | yes | - |
| Session context contamination | yes | yes | - |
| Token / cost spike (denial-of-wallet) | yes | yes | yes |
| Red-team / automated-pacing anomaly | yes | yes | yes |
| Threat-intel URL match | yes | yes | - |
| Off-hours / geo anomaly | yes | yes | yes |
| Multi-stage attack chain | yes | yes | - |
| Human-in-the-loop (HitL) consent bypass | yes | n/a | n/a |
| MCP tool-description / cross-server abuse | yes | n/a | n/a |
| Agent memory poisoning | yes | n/a | n/a |
| Computer-use (CUA) visual attack | yes | n/a | n/a |
| Inter-agent permission mismatch | yes | n/a | n/a |
| Org-config override / abuse chain | - | - | yes |

`n/a` means the runtime does not emit the telemetry that detection needs
(for example Copilot Studio exposes no consent, MCP, memory or
computer-use surface). The deepest agentic coverage therefore lives in
the Foundry bundle, where the `gen_ai.*` / `mcp.*` span shape carries the
required keys.

---

## Which bundle should I deploy?

- Running **Foundry / Agent Service** agents with Application Insights
  tracing enabled -> [`Foundry-AppInsights/`](./Foundry-AppInsights/README.md).
- Running **Copilot Studio** agents with Application Insights wired up
  (and "Log sensitive properties" on for text-content rules) ->
  [`CopilotStudio-AppInsights/`](./CopilotStudio-AppInsights/README.md).
- Calling the **OpenAI** platform / API and ingesting it through the
  Sentinel OpenAI connector -> [`OpenAI-Connector/`](./OpenAI-Connector/README.md).
- Onboarding **Agent 365** observability into the Sentinel **data lake**
  -> [`Agent365-DataLake/`](./Agent365-DataLake/README.md).

You can deploy any combination; the bundles are independent.

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
[`Foundry-AppInsights/Deploy/Enable-FoundryTracing.ps1`](./Foundry-AppInsights/Deploy/Enable-FoundryTracing.ps1).
It inventories projects in dry-run mode by default and changes them only
with `-Apply`. This is still a **per-project connection** performed in
bulk; one project connection covers all agents inside that project.

Full Foundry prerequisites and helper-script examples are in
[`Foundry-AppInsights/README.md`](./Foundry-AppInsights/README.md).

### Copilot Studio - one configuration per agent

Use this mode for the existing `CopilotStudio-AppInsights` rules. It is
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
telemetry consumed by the current `CopilotStudio-AppInsights` rules.
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
| `Foundry-AppInsights/` | Foundry / Agent Service detection bundle (rules, hunts, watchlists, Simulation harness, ARM) |
| `CopilotStudio-AppInsights/` | Copilot Studio detection bundle (rules, hunts, watchlists, ARM) |
| `OpenAI-Connector/` | OpenAI CCF connector detection bundle (rules, hunts, ARM) |
| `Agent365-DataLake/` | Agent 365 data-lake-tier observability bundle (discovery notes, KQL jobs, summary rules, workbooks) |
| `Discovery/`, `Hunting/`, `KqlJobs/`, `SummaryRules/`, `Workbooks/` | Data-lake-tier working folders referenced by `Agent365-DataLake/README.md` |

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
