# AI Agent Threat Detection for Microsoft Sentinel

Monitoring AI Agents https://youtu.be/5Axu9dJ2lfw

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
