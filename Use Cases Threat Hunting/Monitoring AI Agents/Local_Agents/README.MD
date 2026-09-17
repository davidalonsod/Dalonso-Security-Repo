# Local AI Agents and Visual Studio Code MCP Detection Pack

This pack contains Microsoft Defender Advanced Hunting queries for local AI
agents and Model Context Protocol (MCP) use from Visual Studio Code. It is
separate from the Foundry and Copilot Studio packs because its authoritative
sources are Defender XDR tables, not Application Insights.

## Evidence planes

| Question | Table | Evidence |
| --- | --- | --- |
| Which VS Code extensions and MCPs are configured? | `AgentsInfo` | Discovery inventory and posture, not execution |
| Which MCP-like server processes did VS Code start? | `DeviceProcessEvents` | Endpoint process execution, not a tool-level MCP audit |
| Which governed tools were invoked? | `CloudAppEvents` / `ExecuteToolByGateway` | Runtime calls routed through the Agent 365 MCP gateway |

An empty query does not prove that no MCP is used. It can mean local-agent
discovery is not enabled, the extension is unsupported, the process command
does not contain an MCP marker, or calls bypass the governed gateway.

## Detection queries

| File | Severity | Signal |
| --- | --- | --- |
| `DetectionQueries/VSCodeMcpRiskyConfiguration.yaml` | High | New or changed VS Code profile with auto-approval, untrusted host process, external MCP, or command-capable metadata |
| `DetectionQueries/VSCodeMcpCommandCapableProcess.yaml` | High | VS Code launches an elevated or command-capable MCP-like process |
| `DetectionQueries/VSCodeMcpFirstSeenProcess.yaml` | Medium | New MCP-like process name/hash appears beneath VS Code after a 14-day baseline |
| `DetectionQueries/VSCodeMcpFirstSeenGatewayTool.yaml` | Medium | VS Code/GitHub Copilot invokes a governed server/tool tuple not seen for that account in the prior 30 days |

These YAML files are source templates for Defender custom detections; they are
not Sentinel ARM analytics rules. Paste the KQL into **Microsoft Defender >
Advanced Hunting**, verify results and schema in your tenant, then create the
custom detection. Keep automated response actions disabled until entity and
false-positive behavior are validated.

## Prerequisites

- Microsoft Defender for Endpoint Plan 2 and supported Windows/macOS devices.
- Local AI agent discovery enabled for supported VS Code extensions.
- `AgentsInfo` local profiles available with `Platform == "LocalAgents"`.
- `DeviceProcessEvents` available for endpoint process detections.
- Agent 365 observability for `ExecuteToolByGateway` runtime events.
- Appropriate Defender Advanced Hunting and custom-detection permissions.

Supported VS Code extensions currently include GitHub Copilot, Claude Code,
Cline, Codex, Gemini Code Assist, and Roo Code. Discovery and runtime protection
are preview capabilities and can change.

## Tuning

- Replace generic command/MCP markers with approved binaries, hashes, package
  paths, and server identifiers observed in your environment.
- Exclude signed, centrally deployed MCP servers only after validating owner,
  endpoint, authentication, tools, data handling, and update process.
- Treat `autoApprove` and `trustedProcess` as strings in local-agent metadata.
- A profile represents agent type + user + device, not each repository folder.
- Correlate process alerts with profile inventory, signer reputation, network
  activity, file changes, and the governed invocation record when available.

## Workbook

The V2 AI Agents Monitoring workbook contains a six-panel **Visual Studio Code
and coding-agent MCP exposure** subsection in the Advanced Hunting tab. Its
panels query Defender Advanced Hunting directly. A hidden Azure Resource Graph
parameter derives the selected Sentinel workspace customer ID and supplies it to each
panel's workspace selector. Connect the Sentinel workspace in the Defender portal if
the selector does not accept it.