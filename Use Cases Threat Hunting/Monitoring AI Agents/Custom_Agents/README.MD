# Custom SDK and external-platform agents

Independent Microsoft Sentinel pack for **custom applications**, including SDK
agents hosted on AWS, Azure, another cloud, containers or local compute. Calling
an Azure OpenAI/Foundry model does not make the calling application a Foundry
agent. This is not a Copilot Studio, Foundry, APIM-only, or endpoint-process pack.

**19 analytics + 14 hunts + 3 reusable functions + 2 watchlists (catalog v1.2.0).** All source YAML
analytics are disabled. The ARM deployment also defaults to disabled analytics,
SDK-only attribution, and no content detections. No rules are deployed by building.

The current pack uses **inline captured content only**, from custom-attributed
AppRequests/AppDependencies. It does **not** query AppGenAIContent or require its
protected-data permissions. All analytics return unmasked recorded prompt/output
evidence; the eleven content-pattern/chain analytics remain separately opt-in.
This intentionally replaces the earlier protected-only, metadata-only contract.

**Exposure warning:** alert query results and investigation hunts include captured
messages, output and tool arguments/results. Raw envelopes can include recorded
system/developer instructions. Real credentials, personal information or confidential
content can consequently be exposed to SOC readers and downstream automation.
Approve recording, access, retention and exports before enabling these rules.

**Deploying alongside Foundry?** Read the
[Foundry / Custom overlap matrix](../CUSTOM-FOUNDRY-DETECTION-OVERLAP.md) before
enabling both packs. It maps the original 16 Custom analytics to close or conditional
Foundry counterparts and explains why shared tables and broad source scope can
produce more than one alert without making the rules interchangeable.

## Complete change summary

| Version | Analytics / hunts | Content and SOC behavior |
| --- | --- | --- |
| Original protected-only catalog (1.0) | 16 / 10 | AppGenAIContent required for content detection; analytic results were metadata-only. |
| Inline SOC evidence (1.1) | 16 / 11 | Removed the protected-table dependency; all alert queries expose unmasked recorded prompt/output, raw message envelopes and tool bodies, with bounded custom-detail previews. Added the content-security evidence hunt. |
| Current coverage expansion (1.2) | 19 / 14 | Added tool-argument secrets, tool-result secrets and a completed-tool-result/risky-model-output correlator. Added tool-body evidence, capture/parsing-gap and indirect-chain hunts. Updated existing coverage/security/timeline hunts and all analytic evidence projections. |

The current changes preserve all original 16 analytic IDs, all 11 prior hunt IDs,
the existing eight metadata-trigger predicates, and existing numeric thresholds.
New analytics are disabled in source and ARM defaults, like the existing ones.
Building/testing has not deployed, enabled, disabled or rewritten any live rule,
watchlist, recording setting, permission or workbook.

Key implementation changes:

- [CustomAgentInlineContent](./Functions/CustomAgentInlineContent.kql) is the active
  content helper; it reads only AppRequests/AppDependencies and exact resource +
  trace + span + agent keys. Finding-span evidence wins over labeled trace context.
- The helper returns measured `DurationMs` and four same-span capture/parser states:
  `InputParseState`, `OutputParseState`, `ToolArgumentsState`, `ToolResultState`.
  Not recorded, recorded empty, unverified user role and unsupported/no-text output
  remain distinct. These states do not claim that recording is disabled or a check passed.
- All 19 analytics return prompt/output evidence and parser states. The new indirect
  correlator also returns `TriggerSpanId`, `TriggerTime`, `TriggerTool`,
  `TriggerToolResult`, `TriggerServerDisplay`, `TriggerTargetHost`,
  `RiskyOutputKind` and `RelatedToolResults`; unrelated rules leave these empty.
- The aggregate coverage hunt now reports missing, empty, unstructured and unparsed
  counts plus nonempty tool arguments/results. The existing security-evidence hunt
  expands from six to eight pattern flags, adding both secret-shaped tool-body planes.
- ARM conditional counts/descriptions are derived from the catalog to prevent drift:
  default **8 disabled metadata-trigger analytics + 10 hunts**; full content mode
  **19 analytics + 14 hunts**. Both modes deploy the same 3 helpers and 2 watchlists.

## What the review changed for custom agents

The parent packs' YAML metadata was parsed and their counts checked; representative
Foundry/APIM/MCP rules and deployment generators were reviewed for adaptation.
This was a detection-content review, not an exhaustive audit of every predicate.
Existing dirty Foundry/Studio/APIM files were not rewritten.

| Existing reference | Adaptation in this pack |
| --- | --- |
| [Foundry MCP inventory](../Foundry_Agents/HuntingQueries/FoundryMcpInventory.yaml) scopes on generic agent/tool fields and includes name-based MCP heuristics | Explicit custom attribution is required. Model/provider names are never platform attribution. Name-only MCP candidates appear in hunting, not MCP analytics. Existing Foundry/custom pack results can still overlap unless the older pack is separately scoped. |
| [Foundry exploit chain](../Foundry_Agents/AnalyticalRules/FoundryMcpExploitIntentExecutionChain.yaml) joins intent and tools on trace ID without enforcing resource, agent or order | The two user-intent chains require identical resource, agent and trace, input before tool, and at most ten minutes. The additional indirect-result chain requires recorded tool end before model start. |
| The same reference scans serialized input content, including non-user roles | User-input detections parse supported message roles and text parts; system/developer instructions cannot satisfy user intent. |
| Legacy content unions accept inline and protected messages | This pack reads inline content only, correlated to custom structural spans on resource + trace + span + agent key. Content alone cannot attribute an agent. |
| Existing ARM generators provide reusable deployment patterns | This pack adds explicit function dependencies, unmasked SOC evidence, budgeted alert previews, per-result grouping, exact agent/resource incident grouping and disabled defaults. Node generation avoids a new YAML dependency. |

These are adaptation boundaries, not claims that all reference detections are
invalid. A workbook hunt is not an enabled rule. Scheduled Sentinel alerts from
this pack are **Sentinel** detections, not native Defender **AI Security** alerts.

## Analytics

| File in AnalyticalRules | Evidence / threshold |
| --- | --- |
| `CustomPromptInjectionAttempt.yaml` | Instruction-override candidate in inline **user-role** input |
| `CustomSecretsInUserInput.yaml` | Selected private-key/credential shapes in inline user input |
| `CustomSecretShapedOutput.yaml` | Credential-shaped inline assistant/text output; validity/exfiltration unproven |
| `CustomSystemPromptDisclosure.yaml` | At least 80 recorded system/developer characters and their prefix in output |
| `CustomUnsafeActiveContentOutput.yaml` | Script/active-content syntax in output; not browser execution |
| `CustomToolResultInstructionInjection.yaml` | Instruction-override candidate in an inline tool result on a tool span |
| `CustomUnapprovedMcpServerExecution.yaml` | Explicit MCP execution + known server + configured nonempty exact allowlist |
| `CustomCommandCapableMcpToolInvocation.yaml` | Explicit MCP span with command-capable name/description; not proof of shell execution |
| `CustomInternalNetworkToolTarget.yaml` | Emitted private, loopback, link-local or selected local-name URL target; not proof of SSRF |
| `CustomToolFailureStorm.yaml` | At least 10 unique observed tool spans, failure rate at least 80%, per resource/agent/trace/hour |
| `CustomExcessiveToolCalls.yaml` | At least 50 unique observed tool spans per resource/agent/trace/hour |
| `CustomTokenUsageSpike.yaml` | At least 100,000 recorded tokens on **chat spans only**, excluding root aggregates |
| `CustomExplicitGuardrailBlock.yaml` | Explicit normalized block attribute; low-severity control evidence, not compromise |
| `CustomGuardrailEvaluationUnavailable.yaml` | Explicit unavailable evaluation; a coverage gap, not a passed control |
| `CustomExploitIntentMcpCommandChain.yaml` | Inline user exploit/command intent before command-capable explicit MCP span |
| `CustomPromptInjectionToolChain.yaml` | Inline user injection candidate before observed tool span |
| [CustomSecretsInToolArguments.yaml](./AnalyticalRules/CustomSecretsInToolArguments.yaml) | **New:** selected credential shapes in arguments on an observed execution span; not a tool declaration |
| [CustomSecretsInToolResult.yaml](./AnalyticalRules/CustomSecretsInToolResult.yaml) | **New:** selected credential shapes in an observed tool result; model consumption/disclosure unproven |
| [CustomToolResultRiskyOutputChain.yaml](./AnalyticalRules/CustomToolResultRiskyOutputChain.yaml) | **New:** tool-result instruction override, then a chat span with secret-shaped or active-content output, at/after recorded tool end and within 10 minutes |

The eleven content-dependent rules are omitted unless `deployContentDetections=true`.
No Enterprise ATT&CK technique is asserted solely from a text/capability heuristic;
the generated technique arrays are intentionally empty. Tactic labels provide
investigation context, not proof of technique execution.

### New-rule interpretation and duplicate alerts

Tool-body credential patterns can be legitimate authentication, retained secrets,
test canaries or quoted examples. They establish recorded credential-shaped content,
not validity, unauthorized tool delivery or exfiltration. Both tool-body rules require
an observed execution operation; a tool name, declaration or discovery event alone
cannot trigger them. Review agent/tool ownership and approved parameter paths before
enabling; no secret-value allowlist or automatic redaction is added.

The indirect-result/output rule requires both spans inside the last-hour lookback,
an instruction-override candidate in a nonempty tool result, a recorded nonnegative
tool duration, and a risky **chat-span** output. It calculates tool end as
`EventTime + DurationMs * 1ms` and requires model start in the following inclusive
ten-minute interval. Missing/negative duration, reverse order, a different resource
or agent, root-only output, and later calls do not satisfy it. This relies on recorded
timestamps/durations and does not prove that the model consumed or obeyed that result.
Only the selected triggering tool's full result is returned; the finding span remains
the model span. `EventCount` counts distinct risky model spans, not joined pairs;
`RelatedToolResults` counts distinct matching tool spans.

The composite rule intentionally overlaps base **tool-result instruction injection**,
**secret-shaped output** and/or **active-content output** findings. It adds ordered
context; it is not automatic duplicate suppression. Exact agent/resource incident
grouping can put the alerts together but does not collapse them. Prefer hunts while
tuning and review the [Foundry overlap appendix](../CUSTOM-FOUNDRY-DETECTION-OVERLAP.md#new-inline-tool-body-and-output-chain-coverage-v12)
before enabling overlapping rule families.

## Attribution and centralized scope

[CustomAgentSpans](./Functions/CustomAgentSpans.kql) normalizes `AppRequests` and
`AppDependencies`, then classifies each observed span:

1. Explicit Foundry/Copilot/Power Platform platform markers, known managed inventory
   identities (when enabled), and centrally excluded IDs take precedence.
2. With `useAgentInventory=true`, recognized custom/external inventory can attribute
   registered agents by record, Entra, source and observability identifiers.
3. Otherwise emit `contoso.agent.kind=custom`, `sdk`, `third-party` or `thirdparty`
   on relevant spans, or populate **CustomAgentScope**.
4. Generic `gen_ai.*`, model/provider names, and a shared role name do not establish
   custom attribution. Unattributed records cannot trigger the analytics.

**CustomAgentScope** columns:

| Column | Meaning |
| --- | --- |
| `ScopeType` | `AppRoleName`, `AgentId`, or `ExcludeAgentId` |
| `ResourceId` | Exact Application Insights resource ID, not workspace ID; normalized case |
| `ScopeValue` | Exact, case-sensitive AppRoleName, or agent ID (normalized case) |
| `Enabled` | `true` only after review |
| `Description` | Operator context |

This is deliberately stricter than the workbook's case-normalized role selector.
Select a custom-only role; never allow a role shared by managed and custom workloads.
Prefer stable emitted agent IDs for multi-agent applications. Marker/scope attribution
is a trusted configuration contract, not cryptographic proof. In SDK-only mode the
pack cannot exclude inventory it does not have: emit accurate platform markers and/or
configure `ExcludeAgentId` for known managed identities.

**CustomAgentApprovedMcpTargets** uses exact, case-sensitive `ServerIdentifier`
values and an `Enabled` flag. Match the emitted URL, label or target, including URL
path case. This is a global approved list for this custom pack, not a per-agent
authorization policy. Zero enabled rows means **CONFIGURE ALLOWLIST**; absent server
metadata means **NO SERVER METADATA**. Neither generates an unapproved-server alert.
The checked-in CSV rows are disabled examples, not permissive defaults.

Inventory attribution and declared MCP configuration require an **ingested/queryable
workspace copy of AgentsInfo**, not merely the XDR table's existence. SDK-only mode
does not query AgentsInfo at all. Inventory uses a 14-day snapshot window; missing
or stale inventory is a coverage limitation.

## Telemetry contract

Use the customer's own Sentinel workspace and workspace-based Application Insights.
There are no fixed workspace names, subscription IDs, tenant IDs or lab roles.
An OTel collector can centralize export, but each SDK must emit the necessary semantic
attributes; gateway-only logs cannot reconstruct internal prompts or tool execution.

Structural spans require:

- `_ResourceId`, `OperationId` (trace) and `Id` (span), plus `AppRoleName`.
- `Properties['gen_ai.agent.id']` and/or an agent name with a dedicated role.
- `gen_ai.operation.name`: `invoke_agent`, `chat`, `execute_tool`, or emitted MCP operation.
- `gen_ai.tool.name`, `gen_ai.tool.type`, and `mcp.server.*` / `gen_ai.tool.server_*`
  for supported MCP/tool views. A name containing "mcp" alone is not MCP proof.
- Tool analytics require `execute_tool`, `call_tool`, `tools/call`, `mcp.call_tool`,
  `mcp.tools.call`, or `mcp.method=tools/call`. MCP discovery/listing and tool
  declarations are not execution; hunting keeps their metadata labeled separately.
- Optional `gen_ai.conversation.id`, `gen_ai.request.model`,
  `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `Success`, `DurationMs`.
- Guardrail events must explicitly emit `contoso.guardrail.blocked` (or
  `gen_ai.guardrail.blocked`) and/or `contoso.guardrail.unevaluated_controls`.
  The pack does not infer a provider verdict from HTTP errors or generic text.
- The new indirect-result/output correlator additionally needs a trustworthy,
  nonnegative `DurationMs` on the observed tool span. Unknown duration is a timing
  coverage gap, not an instantaneous completion.

Inline content requires:

- `Properties['gen_ai.input.messages']` and `Properties['gen_ai.output.messages']`
  on AppRequests/AppDependencies, with matching resource, operation, span and agent keys.
- `gen_ai.tool.call.arguments` / `gen_ai.tool.call.result` for recorded tool bodies.
- Input messages as an array or single object with a role; supported text is string
  `content`, `parts[].content`, `parts[].text`, or text-content arrays.
- Recorded system/developer messages or `gen_ai.system_instructions` for the
  system-prefix disclosure check. Plain unstructured input is displayed with an
  unverified-role label, but cannot satisfy user-intent detections. Output parsing
  accepts assistant-role envelopes or plain text; unknown structured output remains
  visible as a raw envelope but cannot satisfy assistant-text detections.
  Hidden model reasoning is neither required nor collected by this pack.

Enabling content detections does **not** configure SDK recording, backfill content,
enable an irreversible telemetry upgrade, or grant RBAC. Approve and configure inline
recording first. Operators and the scheduled-rule query identity need workspace/table
permissions. Incident readers may see evidence previews without the same underlying
table access. Functions do not bypass table permissions, but copying content into an
alert creates a separate exposure surface.

Missing required telemetry tables are query errors. New/empty watchlists can expose
only the base WatchlistItem schema, without expanded CSV columns. The classifier
binds typed scope/approval columns before using them and accepts either expanded
fields or a WatchlistItem bag. Empty lists provide no implicit custom scope,
exclusions or MCP approval. Source health reports watchlist row/enablement counts
and explicit EMPTY / NOT READY or NO ENABLED ENTRIES states.

The source-health, attribution and inline-coverage hunts identify gaps; empty
findings or unsupported message shapes must never be treated as safe. Normalized
spans without resource/trace/span/agent lineage cannot generate analytic findings.

## Hunting and evidence limits

The complete 14-hunt inventory is below. Four content hunts require
`deployContentDetections=true`; the metadata-only capture/parsing-gap diagnostic is
included in the default deployment. Source health and attribution diagnostics can
inspect workspace-wide GenAI metadata; they are not custom activity totals.

| Hunting query | Purpose / output | Content opt-in |
| --- | --- | --- |
| [CustomSourceHealth](./HuntingQueries/CustomSourceHealth.yaml) | Runtime classification, inventory and watchlist readiness; metadata | No |
| [CustomAttributionGaps](./HuntingQueries/CustomAttributionGaps.yaml) | Missing custom attribution/lineage; metadata | No |
| [CustomObservedAgentInventory](./HuntingQueries/CustomObservedAgentInventory.yaml) | Runtime-observed custom applications; metadata | No |
| [CustomModelUsage](./HuntingQueries/CustomModelUsage.yaml) | Chat-span token totals and latency, no root double-count | No |
| [CustomToolInventory](./HuntingQueries/CustomToolInventory.yaml) | Execution versus metadata-only tool inventory | No |
| [CustomMcpRuntimeInventory](./HuntingQueries/CustomMcpRuntimeInventory.yaml) | Explicit MCP execution versus candidates and approval gaps | No |
| [CustomMcpDeclaredConfiguration](./HuntingQueries/CustomMcpDeclaredConfiguration.yaml) | Declared servers, not execution; requires inventory mode | No |
| [CustomTraceTimeline](./HuntingQueries/CustomTraceTimeline.yaml) | Full prompt/output, tool bodies, duration, parser states and source span IDs | No |
| [CustomProtectedContentCoverage](./HuntingQueries/CustomProtectedContentCoverage.yaml) | **Updated:** inline same-span coverage/parse-state counters; legacy filename retained for ID stability | Yes |
| [CustomInlineContentSecurityEvidence](./HuntingQueries/CustomInlineContentSecurityEvidence.yaml) | **Updated:** eight user/output/tool-body pattern flags with full recorded evidence | Yes |
| [CustomGuardrailOutcomes](./HuntingQueries/CustomGuardrailOutcomes.yaml) | Recorded blocks, unavailable evaluations and no-verdict counts | No |
| [CustomToolContentSecurityEvidence](./HuntingQueries/CustomToolContentSecurityEvidence.yaml) | **New:** secret-shaped and instruction-override candidates in tool arguments/results | Yes |
| [CustomInlineContentGaps](./HuntingQueries/CustomInlineContentGaps.yaml) | **New:** not recorded vs empty vs unstructured/unparsed; per-span states/timing only, no body projection | No |
| [CustomIndirectInjectionOutputEvidence](./HuntingQueries/CustomIndirectInjectionOutputEvidence.yaml) | **New:** exact scheduled indirect-result/output predicate and projection over 24 hours | Yes |

Full-evidence per-event hunts return at most 500 rows. Most use 24 hours; aggregate
runtime/inventory/coverage queries retain their existing one-hour contracts, and
attribution/declared inventory use their documented 24-hour/14-day scope. Filter exact
resource, agent and trace before sorting/limiting when investigating a larger trace;
sampling, retention and KQL/UI size limits can prevent complete reconstruction.

- Use the full **resource + agent + trace** key, not trace ID or display name alone.
- Both tables can describe the same logical operation. Records are deduplicated by
  resource/trace/span; sampled or missing spans still undercount activity.
- All analytics return `Prompt`, `Output`, raw same-span `InputMessages` /
  `OutputMessages`, and recorded `ToolArguments` / `ToolResult`. No application
  substring limit is added to these result fields; ingestion, KQL and UI limits still
  apply. The parser no longer stops at 100 parts. Raw envelopes preserve recorded order.
- Exact-span content wins. Missing prompt/output may use the same resource + agent +
  trace, explicitly labeled by `PromptEvidenceOrigin`, `OutputEvidenceOrigin` and
  their source span IDs. Context is not proof of causation or tool success.
  User-intent chain alerts instead prefer the actual matched intent span, not the first benign
  prompt in a multi-prompt trace. Missing content is labeled, never called safe.
- Alert custom details `Prompt` / `Output` are previews of at most 160 characters
  each, shortened further by a conservative UTF-8/escaping budget. `EvidenceStatus`
  reports shortening, missing text or exhausted preview budget. Full fields remain in
  query results. Sentinel has a [2 KB combined custom-details limit](https://learn.microsoft.com/azure/sentinel/surface-custom-details-in-alerts#how-to-surface-custom-event-details); unusually large
  pre-existing identity metadata can itself exceed it. Do not use previews as the
  complete evidence record.
- Tool URL displays remove userinfo, queries and fragments. The original exact
  identifier is used internally for approval matching; investigate full metadata
  only under appropriate access.
- Prompt matches can be quotations, test fixtures or legitimate requests. Tool
  capability names can be misleading. A successful span is not proof of downstream
  execution, exfiltration or exploit success.
- Internal-target checks do not resolve DNS or prove reachability; DNS rebinding,
  redirects, alternate address encodings and tool argument destinations require
  additional evidence. No-tools chat cannot produce genuine MCP/tool telemetry.
- This pack does not query native CloudAppEvents, endpoint processes, DLP, risk,
  vulnerability or incident evidence. Use the other packs/workbook surfaces for
  those evidence planes rather than inventing them from SDK messages.

## Build, validate and deploy

The source of truth is [build-custom-agents.mjs](./build-custom-agents.mjs) plus
[Functions](./Functions) and [Watchlists](./Watchlists). YAML and ARM are generated.
Edit those sources and rebuild; manual edits to generated files will be overwritten.
Node.js 18+ is sufficient; there are no npm or YAML-module build dependencies.

```powershell
node .\build-custom-agents.mjs
node .\Testing\test-custom-agents.mjs
```

See [deployment steps](./Deploy/README.md). Deploy disabled first, configure and review
the watchlists, run the hunts, tune thresholds to representative workloads, and only
then deliberately enable selected rules.

Rules run hourly over explicitly filtered last-hour runtime/content spans. Their
`queryPeriod=P14D` permits the inventory function's older snapshots to be resolved;
it does not broaden runtime detections to fourteen days. Late-arriving spans older
than the explicit last-hour filter are not backfilled automatically. Alerts use
per-result grouping and incident grouping by exact agent/resource custom details.
Sentinel alert-per-result limits still apply during very large bursts.

## SOC investigation and upgrading existing alerts

After deploying the new helper and updated queries, use **Custom-attributed trace
timeline** or **Inline content security evidence** in Hunting. Filter the exact
resource ID, agent key and trace ID from the alert. For example:

```kusto
CustomAgentInlineContent(7d)
| where _ResourceId =~ '<application-insights-resource-id-from-alert>'
| where AgentKey == '<agent-key-from-alert>' and OperationId =~ '<trace-id-from-alert>'
| project EventTime, OperationId, SpanId, Agent, Operation, Prompt, Output,
    PromptEvidenceOrigin, OutputEvidenceOrigin, PromptEvidenceSpanId, OutputEvidenceSpanId,
    InputMessages, OutputMessages, ToolArguments, ToolResult,
    InputParseState, OutputParseState, ToolArgumentsState, ToolResultState, DurationMs
| order by EventTime asc
| take 500
```

In new alerts, expand Query results to see `Prompt` and `Output`; custom details show
the previews. Existing alerts retain their original metadata-only fields and their
old "Protected output..." signal. Rule updates do not retroactively rewrite them.
Use the new hunt over retained inline telemetry to investigate an older alert.
Protected-only historical records cannot be recovered by this inline-only query.

All original 16 analytic IDs and the prior 11 hunt IDs are retained. Three analytic
and three hunt IDs are added in v1.2. The protected-coverage
hunt's legacy file/key remains for ID continuity, but its name/query now describe
inline coverage. The v1.1 eleventh hunt exposes content-security evidence. The active
content helper is [CustomAgentInlineContent](./Functions/CustomAgentInlineContent.kql).
The older protected helper source is retained for reference, but is not deployed or
called by the current pack. Incremental updates do not delete an old deployed alias.
Read [update precautions](./Deploy/README.md#update-and-rollback) before redeploying:
do not overwrite reviewed watchlists or inadvertently disable currently enabled rules.

## Validation performed

- Deterministic generation and structural contracts for 19 rules / 14 hunts, plus
  baseline checks retaining every prior ARM resource ID.
- Disabled defaults, conditional content-pattern resources, dependencies, entity/custom
  detail mappings, unmasked SOC evidence and environment-neutral inputs.
- Actual KQL execution of synthetic positive/negative fixtures for all 19 analytics
  and all 14 hunts, including 49/50 tool-count, 99,999/100,000 token and 70%/80%
  failure-rate boundaries, duplicate spans and root-token exclusion.
- Inline-only content with no AppGenAIContent table in the fixtures, user-vs-system roles, exact scope/resource/case matching,
  managed inventory precedence, explicit exclusions, empty approval, path case,
  cross-agent/resource/content isolation, reversed/late chains and ten-minute limit.
- IPv4/IPv6 loopback/link-local targets, zone identifiers, hostname/userinfo decoys,
  URL credential/query/fragment removal, and MCP discovery/declarations that must
  not satisfy tool-execution analytics.
- Eleven SOC evidence assertions cover full alert prompt/output, exact agent/resource
  context, latest duplicates, missing capture, single envelopes, unstructured role
  boundaries, more than 100 parts, Unicode/escaped previews within 2 KB, and matched
  intent selection in chains.
- Thirteen additional assertions cover actual tool-body evidence, exact triggering
  tool/model provenance, completion-time boundaries, distinct model-span counting,
  empty vs missing vs unsupported capture, complete-content/missing-timing gaps,
  and coverage/hunt projections. Negative
  fixtures include tool metadata without execution, managed/unattributed agents,
  missing/negative duration, before-completion/reversed/late output, other
  agents/resources and root-only/ordinary output.
- Live App* schema resolution with `take 0` and candidate helpers against deployed
  inventory/watchlists; no recorded content returned and no fixtures ingested.
- The new inline version has not been deployed/enabled by building or testing.
  Historical ARM/deployment validation described below applied to the older
  protected version; it is not proof that the new version is installed.
- The 2026-10-28 deployment failure exposed an empty-watchlist semantic gap that
  Template-level validation and typed fixtures did not catch. Empty base-schema
  and WatchlistItem-bag regressions now pass, and synthetic helper names are isolated
  from production aliases. Candidate and deployed helpers were verified against
  the real inventory/watchlists after the repair; see the
  [deployment troubleshooting and recovery notes](./Deploy/README.md#managed--empty-watchlist-semantic-error).

Reproduce the read-only fixtures in an authorized workspace:

```powershell
.\Testing\Test-CustomAgentsLive.ps1 `
  -WorkspaceId '<workspace-customer-id>' -TenantId '<tenant-id>' -CheckLiveSchema
```

After deploying the helper functions/watchlists, additionally check the real
watchlists and saved aliases:

```powershell
.\Testing\Test-CustomAgentsLive.ps1 `
  -WorkspaceId '<workspace-customer-id>' -TenantId '<tenant-id>' `
  -CheckLiveSchema -CheckLiveWatchlists -CheckDeployedFunctions
```

These optional checks use the new inline helper, never the protected table.
`-CheckDeployedFunctions` requires deploying the inline helper first; it does not
silently test the older protected alias instead.

Azure CLI must be signed in. Synthetic tests need log-query permissions; the optional
live schema check also needs the actual tables and query access. No protected table
is used. The tests do not
deploy functions, watchlists, rules or data, and do not call any MCP server or model.
