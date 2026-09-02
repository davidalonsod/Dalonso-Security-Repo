# Hunting AI Agents Investigation Notebook

This folder contains a Microsoft Sentinel data lake notebook for Agent 365 inventory, governance, reliability, threat hunting, and investigation. The notebook combines Agent 365 and Entra System tables in the lake with selected Analytics-tier tables from a Sentinel workspace.

> **Status:** Working analytical prototype. The notebook contains executable PySpark analysis and visualizations; it is not a finished multi-page Sentinel workbook. Its findings are investigation candidates, not malicious-activity verdicts.

Are Your AI Agents Compromised? Hunt Threats Like a Pro with Sentinel Notebookhttps://youtu.be/ASPE6dviQFY

## Primary notebook

[`Agent365-Role-Based-Monitoring.ipynb`](Agent365-Role-Based-Monitoring.ipynb) is organized around four audiences:

| Audience | Capabilities |
| --- | --- |
| CISO / AI governance | Estate, adoption, posture, risk, and activity summaries |
| AI Agent / Entra administrator | Identity inventory, blueprint reconciliation, lifecycle, and governance exceptions |
| Observability / SRE | Volume, latency, reliability, error, token, cost, and telemetry-quality views |
| SOC / investigation | Explainable heuristics, platform hunts, anomaly analysis, ranked investigation boards, and focused timelines |

## Data sources

### Sentinel data lake System tables

System tables are read without a workspace argument:

- `UnifiedAgentObservability`
- `EntraAgentIdentities`
- `EntraAgentIdentityBlueprints`
- `EntraAgentIdentityBlueprintPrincipals`
- `EntraAgentUsers`

### Sentinel workspace Analytics-tier tables

Set `WORKSPACE_NAME` in section 1 to enable workspace-backed analysis. Each source is optional; a missing or empty table causes the relevant panel to skip cleanly.

| Area | Tables |
| --- | --- |
| Copilot Studio and Foundry | `AppEvents`, `AppDependencies` |
| Microsoft 365 Copilot | `CopilotActivity` |
| Identity and sign-ins | `SigninLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AADRiskyUsers`, `IdentityInfo` |
| Directory changes | `AuditLogs` |
| Security operations | `SecurityAlert`, `SecurityIncident` |
| Data access | `CloudAppEvents` |

## Notebook sections

| Section | Capability |
| --- | --- |
| 1 | Lookback, focus-agent, privacy, output, pricing, and detection-threshold controls |
| 2 | Table availability, schema inspection, preview-schema normalization, and event spine |
| 3 | Agent inventory, identity and blueprint reconciliation, stale assets, and governance exceptions |
| 4 | Activity, operation mix, errors, correlation quality, latency, and SRE health |
| 5 | Transparent SOC heuristics for bursts, off-hours use, fan-out/fan-in, suspicious markers, and disabled identities |
| 6 | Volume anomalies, explainable composite triage score, and focused agent timeline |
| 7 | Optional compact findings output and operationalization guidance |
| 8 | Copilot Studio and Foundry dimensions from Application Insights: tools, MCP, models, tokens, cost, guardrails, channels, and connectors |
| 9 | Executive KPI ribbon, activity heatmap, and agent-risk visuals |
| 10 | Cross-source estate board and rolling conversation-volume anomaly candidates |
| 11 | Foundry hunts for guardrails, prompt injection, secrets, model probing, tool chaining, lateral movement, cost spikes, trace anomalies, and dormancy breaks |
| 12 | Copilot Studio hunts for flooding, injection/exfiltration markers, secrets, channels, connector failures, latency, novelty, and fan-out |
| 13 | Foundry, Copilot Studio, and cross-platform SOC investigation boards |
| 14 | Behavioral anomalies: dormant reactivation, operating-hours shifts, new user/agent/tool edges, rate spikes, loops, and operation expansion |
| 15 | Microsoft 365 Copilot hunts over `CopilotActivity`, including native jailbreak/XPIA signals, DLP metadata, resource drift, plugin novelty, and pacing anomalies |
| 16 | Cross-source identity, audit, alert, incident, MITRE ATT&CK, and data-access correlation |

Section 16 uses workspace data already available to Sentinel to connect agent actors and service principals with risky or failed sign-ins, privilege and consent changes, agent-targeted alerts and incidents, and cloud data-access activity. Joins use normalized UPNs, object IDs, agent names, application IDs, and blueprint IDs; results remain correlation candidates for analyst review.

## Prerequisites

- Microsoft Sentinel data lake onboarding and permission to read System tables.
- VS Code with the Microsoft Sentinel extension signed in to the correct tenant.
- A Microsoft Sentinel runtime pool. Medium is a practical starting point.
- Read access to the configured Sentinel / Log Analytics workspace for the workspace-backed panels in sections 8-16.
- Agent instrumentation that emits a root `invoke_agent` span and propagates `gen_ai.conversation.id` for complete correlation.
- Workspace-based Application Insights for Copilot Studio and Foundry analysis.

The notebook uses runtime-provided PySpark and matplotlib; no package installation is required. Foundry text-content hunts additionally require `AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED=true`. Copilot Studio text-content hunts require **Log sensitive properties**. Metadata-only hunts continue to work without those settings.

## Run the notebook

1. Open [`Agent365-Role-Based-Monitoring.ipynb`](Agent365-Role-Based-Monitoring.ipynb) and select a Microsoft Sentinel runtime pool.
2. Run section 1 and set `LOOKBACK_DAYS`, `RECENT_HOURS`, `FOCUS_AGENT`, and `WORKSPACE_NAME` for the target tenant.
3. Leave `SHOW_SENSITIVE_CONTENT=False` and `WRITE_RESULTS=False` during exploration.
4. Run section 2 to validate System-table availability and normalize the event spine.
5. Run sections 3-7 in order for lake-native governance, SRE, detections, risk, and timeline analysis.
6. Run section 8 before sections 10-14; it loads the Foundry and Copilot Studio DataFrames used by those sections.
7. Run sections 15 and 16 when the corresponding Analytics-tier tables are available.

Reduce `LOOKBACK_DAYS` while developing to limit Spark scans. All charts aggregate in Spark before collecting compact summaries to pandas/matplotlib, and displayed row sets are bounded by `DISPLAY_LIMIT`.

## Output and privacy

The default execution is read-only. When `WRITE_RESULTS=True`, section 7 writes compact, high-score findings to the lake-tier table `Agent365RiskFindings_SPRK`. Review the findings and retention requirements before enabling writes.

Raw prompt, response, tool content, and `AdditionalFields` are not persisted to findings. Investigation boards display counts and identifiers rather than prompt or response bodies. Apply appropriate Sentinel access controls, retention, and privacy policies before sharing notebook results.

## Current boundaries

The notebook intentionally does not infer signals that the available telemetry cannot establish. Remaining enrichment and modeling gaps include:

- Authoritative owner, sponsor, business-unit, and lifecycle data.
- Purview DLP and sensitivity-label correlation outside the metadata present in `CopilotActivity`.
- Blueprint-principal OAuth scope and application-role decoding.
- A canonical run/span tree with complete parent-child lineage.
- Governed allowlists for approved tools, MCP servers, connectors, and plugins.

## Files

| File | Purpose |
| --- | --- |
| [`Agent365-Role-Based-Monitoring.ipynb`](Agent365-Role-Based-Monitoring.ipynb) | Current 16-section role-based monitoring and investigation notebook |
| [`Hunting_AIAgents_Investigation_Notebook.ipynb`](Hunting_AIAgents_Investigation_Notebook.ipynb) | Companion AI-agent investigation notebook |
| [`guion-demo-youtube.md`](guion-demo-youtube.md) | Demo narration and walkthrough notes |
