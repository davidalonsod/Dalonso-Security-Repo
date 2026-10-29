# AI Agents Monitoring Workbook V3

V3 adds the Microsoft Entra Agent ID identity control plane to the runtime, content,
tool, MCP, APIM, Defender, and incident monitoring already present in V2.

V2 remains unchanged. V3 is generated as a separate workbook:

- Source artifact: `AI-Agents-MonitoringV2.workbook`
- Generated workbook: `AI-Agents-Monitoring-Workbook-V3.workbook`

## Summary

V3 adds 17 query panels and supporting guidance across six existing workbook tabs:

| Existing tab | V3 addition |
|---|---|
| Executive Overview | Agent ID posture and risk KPIs |
| Governance | Agent ID-related Sentinel alerts, administrative changes, and blueprint-principal permission posture |
| Timeline & Investigation | Workload sign-ins, risk-to-authentication correlation, and Agent ID audit changes |
| Security & Attack Coverage | Unified Agent ID security signals and eight scheduled-detection contracts |
| AI Risk Score | Separate Agent ID alert-based risk score and control findings |
| Data Lake | Identity topology, lifecycle hygiene, grant posture, and creation bursts |

The V3 workbook now contains **336 query items across 18 tabs**. Seventeen query items
use the `v3-` prefix; fifty-two use the `custom-` prefix. Both sets are validated by the
generator. The existing V2/V3 tab groups are unchanged by the Custom Agents addition.

## Cross-environment filter startup repair (2026-10-28)

The supplied Defender console trace failed in CanvasConfig.getDefaultSubscriptions:
the host dereferenced a null Sentinel context's subscriptionId while evaluating
parameter options. Public source-map inspection confirmed that subscription
parameters with includeAll=false choose that default-context callback.

Both WorkspaceSubscriptions and APIMSubscription now set includeAll=true, selecting
accessible-subscription enumeration instead. This changes options, not selection:
the saved values and Workspace default remain empty/null. No LAWSentinel, tenant
or subscription default is introduced.

The generated workbook differs from the pre-repair artifact only in these two
settings. All 336 queries, 19 parameter names and other settings are preserved.
The startup regression reproduces the old null-context error and checks null,
alternate-subscription and empty-accessible-list cases. Other structural suites
pass. The affected other-environment renderer still requires confirmation after
the user imports the updated artifact; no live workbook or detection was modified.

## Non-Microsoft publisher sources (2026-10-28)

- Added 8 native Defender and 3 Sentinel lake adapter panels under Custom Agents.
  The section now has 52 queries, and the workbook has 19 shared parameters.
- Publisher/ownership is separate from SDK, model or hosting cloud. Recorded
  Microsoft/GitHub publishers override manual review in native queries; Platform=Other
  no longer automatically includes Microsoft-built apps in the original Custom scope.
- New publisher-first inventory, identity keys, cloud audit actions/timeline,
  endpoint-binding readiness, exact process/direct-child evidence and MCP declaration
  views preserve configuration/execution distinctions.
- Added reviewed full agent IDs and reviewed device/process-unique-ID JSON controls.
  Shared-process mappings, invalid JSON and missing bindings stay explicit gaps.
  Generic executable names, PIDs and time proximity do not establish attribution.
- Lake source/target scope is an explicit reviewed-ID contract, not an automatic
  cross-engine inventory/publisher lookup. Unreviewed peers stay unclassified.
  Raw audit/commands/lake payloads remain behind the existing Show captured content.
- Native schemas/reference queries, eight workspace-copy contracts and fourteen
  isolated KQL assertions passed. Native local inventory profiles were absent in
  the checked data. **Live lake validation remains pending due to authentication**;
  no lake rows/schema are claimed and Analytics does not have a UAO copy.
- Non-Custom groups, including the 20 M365 queries, remain unchanged. No collection,
  permissions, scheduled analytics or Azure workbook deployment is performed.

See [NON-MICROSOFT-AGENT-SOURCES.md](NON-MICROSOFT-AGENT-SOURCES.md) for all panel names,
proof boundaries, test commands and the lake validation blocker.

## M365 channel, published agents and measured usage (2026-10-28)

- Added `m365-copilot-v3.mjs`; the M365 section now contains **20 queries**, replacing
  the original seven query bodies and adding thirteen focused views.
- Operator-approved **M365-first** scope excludes known Fabric, Security Copilot,
  connected-AI and unknown host identities from headline totals while retaining
  all of them in host discovery/source-health diagnostics.
- Populated organization/RecordId pairs are deduplicated; missing IDs remain
  separate records. Stable agent/actor keys, not display names, drive rankings.
  Non-interaction records are no longer labeled automatically as plugin/config events.
- Added top-user/agent risk rollups, interaction timeline, resource action/status/
  sensitivity/policy metadata, DLP deferral and model/provider transparency.
- Published catalog entries require recorded publication and Copilot-advertised
  metadata. Declared custom-engine/declarative types are not inferred from Other.
  Exact unique ID bindings are used; conflicting bindings are rejected.
- Cowork/Code identification coverage reports literal marker candidates separately
  from verified product usage. Shared Office/BizChat shell records cannot prove
  the mode; dedicated product reports/action sources remain necessary where the
  connector lacks a discriminator.
- Recorded Copilot-channel SDK token rankings use exact caller/owner/resource/trace
  attribution and resource/trace/span deduplication. Model counters take precedence;
  root aggregates are fallback-only, consistent and never added over model counters.
  Conflicts, explicit non-Copilot channels, negative counters and missing identities
  are not guessed into user rankings. Partial counters remain labeled.
- First-party M365 internal tokens, Copilot Credits and invoices are different
  measurements. No interaction-to-token conversion or new Graph permission/collector
  is introduced.
- All 17 parameters and 305 non-M365 query objects, including the 41 Custom queries,
  are preserved. The workbook is rebuilt locally, not deployed automatically.

See [M365-COPILOT-OBSERVABILITY.md](M365-COPILOT-OBSERVABILITY.md) for all panel names,
source contracts, official references, testing commands and current product limits.

Validation: all 20 real query contracts and 13 KQL assertions passed. Actual published
pilot bindings and positive SDK token totals were confirmed using metadata/counts
without returning user identities or message content. Deterministic generation and
the 305-query non-M365 preservation contract passed. Cowork/Code identification gaps
remain explicit rather than inferred from the UI or agent names.

## Custom Agents correlated evidence (2026-10-28)

- Added the shared `custom-agents-evidence-v3.mjs` source/parser, reused by content
  findings, timeline, control/provider evidence and recorded-content views.
- Injection, secret-pattern, disclosure, indirect/tool-result and unsafe-output
  findings now include opt-in prompt/output evidence. Disclosure adds recorded
  instructions; indirect injection adds the actual recorded tool result.
- Timeline, block/provider evidence and recorded content now have inline/protected
  variants. New `custom-explicit-blocks` and `-protected` views show only explicit
  normalized block flags. Total Custom queries: **41**, with **11 protected variants**.
- The existing Show captured content switch gates every raw payload field in KQL.
  Defaults remain hidden. Text rendering is used, not active HTML rendering. This
  does not alter ingestion, retention, role assignment or scheduled analytics.
- Same-span evidence is preferred. Same-resource/trace/observed-agent context is
  clearly labeled with source span IDs; protected records are joined on exact
  nonempty resource/trace/span keys and deduplicated by latest content timestamp.
- Raw input/output envelopes remain available when parsed message text is incomplete
  or exceeds its 100-part limit. The parsing limit is exposed as metadata.
- Policy, mode, provider code and request ID remain metadata; recorded reason,
  decision JSON and service response payloads are opt-in. Missing payloads are not
  fabricated. Unavailable checks remain distinct from blocks; empty arrays/objects
  and false values do not create unavailable-provider findings.
- All 17 parameters, portable workspace selection, Custom-only attribution and
  other tabs remain. The source selector's label is now **evidence content source**
  while its stable parameter name remains CustomSecurityContentSource.

The workbook is rebuilt locally. Import/deploy the updated definition to see these
fields; no Azure workbook update is performed by generation. See the README for
the two evidence-control selections.

Validation passed: all 41 actual query contracts, 18 opt-in projections with
metadata-only result counts, hidden/shown fixtures, same-agent/resource context
isolation, missing trace keys, latest protected payload selection, instruction and
provider-reason evidence, and 100/101-part boundaries with complete raw envelopes.
The 271 non-Custom query objects, navigation and unrelated parameters were preserved.
No captured customer text was returned by the validation commands.

## Workspace portability and Custom Agents labels (2026-10-27)

- Added **Workspace subscriptions**, an initially empty multi-select subscription
  picker. **Workspace** now discovers accessible Log Analytics workspaces through
  Azure Resource Graph in that scope, instead of listing only workbook-context
  resources. No workspace is preselected and no tenant-specific resource IDs are
  embedded. Select subscriptions and then a workspace after importing the workbook.
- Advanced Hunting still derives its customer ID from the selected Workspace;
  APIM keeps its independent subscription and resource selectors.
- Added **🧩 Custom Agents** consistently in the landing-page coverage/operations
  tables, section heading, navigation tab and tab reading guide.
- V3 has **17 shared parameters**; all 307 query panels and 18 tabs remain.
  The generated workbook and generator are both updated. No cloud deployment is
  performed by rebuilding the local artifact.

Validation: the build and structural/query-contract tests passed, including all
36 Custom Agents panels. Two builds produced identical SHA-256 hashes. A full
pre-change comparison confirmed all 307 query objects, APIM/Advanced Hunting
parameters, and unrelated tabs/settings are unchanged. The exact new picker query
was executed read-only against Azure Resource Graph and returned 15 accessible
workspace rows with `id`, `name`, `selected`, and `group`; every `selected` value
was `false`. This validates discovery, not ingestion or log-table permissions.
No Azure workbook deployment or portal rendering was performed for this update.

## Custom Agents addition (2026-10-27)

`custom-agents-v3.mjs` adds one dedicated tab immediately after Foundry, plus two
parameters: **CustomAgentRoles** and **CustomShowContent**. It is called by the existing
`build-v3.mjs`; do not hand-edit the generated workbook and expect changes to survive
a build. `custom-agents-security-v3.mjs` adds MCP/security parity through the same
custom classification, with **CustomApprovedMcpTargets** and
**CustomSecurityContentSource**. Together with WorkspaceSubscriptions, V3 now has
17 shared parameters.

| Panel | Purpose |
| --- | --- |
| custom-health | Explicit required-source health and collection gaps |
| custom-inventory | Latest custom/external inventory, without managed-platform rows |
| custom-kpi | Attributed runtime spans/traces, stable agent IDs, tools and model-only tokens |
| custom-runs | Invocation-trace trend |
| custom-applications | Runtime identity/role/platform/SDK and missing context |
| custom-models | Chat-span usage, latency, failures and missing token data |
| custom-tools | Tool spans, trace counts, failures and missing conversation context |
| custom-outcomes | Per-trace invocation outcomes, explicit blocks and unavailable checks |
| custom-evidence | Recorded block/unavailable-provider metadata, not content heuristics |
| custom-timeline | Runtime trace/span/parent, model/tool and channel investigation |
| custom-audit-summary | Inventory-attributed custom Agent 365 action counts |
| custom-audit-timeline | Invocation/tool/inference audit timeline |
| custom-classification | Custom attribution and unresolved SDK coverage, not managed details |
| custom-content | Opt-in display of already-recorded span payloads and protected-content IDs |

### Custom MCP and security parity extension

The 22 additional query items below extend the original 14:

| Panel | Purpose |
| --- | --- |
| custom-mcp-config | Declared custom MCP server configuration, not execution |
| custom-mcp-runtime | Observed MCP server/tool/type/transport, latency, failures and context gaps |
| custom-mcp-allowlist | Exact approval comparison with separate unconfigured/missing statuses |
| custom-mcp-capabilities | Command/exploitation-capable tool-name/description heuristic |
| custom-mcp-targets | Explicit URL host classification; no assumed trusted-provider allowlist |
| custom-mcp-chains | Invocation-to-MCP trace correlation using resource, trace and agent |
| custom-mcp-audit | Governed custom MCP audit calls from CloudAppEvents |
| custom-alerts | Fired alerts with exact custom identity in AlertEvidence |
| custom-security-content-health and -protected | Readable user input, output, tool result and reference coverage |
| custom-input-injection and -protected | User-role instruction-override/jailbreak markers |
| custom-output-secrets and -protected | Secret-shaped output without returning the value |
| custom-prompt-disclosure and -protected | Same-span disclosure request and output markers |
| custom-unsafe-output and -protected | Active-content syntax in output, not proof of execution |
| custom-tool-output-injection and -protected | Instruction markers in untrusted tool results |
| custom-mcp-exploit-chain and -protected | Ordered user intent then command-capable MCP span within ten minutes |

Protected-content variants are conditionally visible only when the protected source
is selected. They join `_ResourceId`, trace and span identifiers to scoped custom
metadata, do not classify by content agent names, and prefer matching protected
payloads with inline fallback. The inline variants never reference AppGenAIContent.
This keeps absent protected sources isolated unless explicitly requested.

MCP source normalization follows the Foundry patterns (`gen_ai.tool.type`, operation,
server URL/label/name variants, description, dependency Target). Stronger explicit
MCP attributes and heuristic name-only candidates have different evidence labels.
Unknown declaration objects do not dump configuration/credential dictionaries.
Configured server inventory is never presented as runtime calls.

The new source tables for the exact fired-alert view are `AlertInfo` and
`AlertEvidence` in the selected workspace. It preserves product source labels and
never creates an alert from a heuristic. SDK-only workloads without inventory keys
can have runtime hunts, but cannot be attributed through registry-only alert/audit
joins until that mapping exists.

As initially delivered on 2026-10-27, hunts returned metadata, flags and IDs rather
than matched snippets. The 2026-10-28 update adds explicit opt-in recorded evidence
while preserving hidden defaults and protected access. Empty findings can be missing content.
No new scheduled analytics, Defender custom detections, source connectors, or workbook
deployment were performed.

### Landing-page coverage

The generated main page now lists Custom Agents in both source coverage and
operational/persona tables, summarizes its MCP/security hunts, documents the four
custom-specific controls and source prerequisites, and displays build-derived counts
of tabs, queries and parameters. The obsolete Overview/Agent Inventory rows were
removed because they are not standalone V3 tabs. Inventory remains described in
the actual Custom Agents, Defender and governance experiences. The landing guidance
separates heuristic findings, configured controls and fired alerts, and does not
promise that an empty or failed query is a clean result. Runtime queries are unchanged
by this landing-page update.

Classification rules:

1. Normalize the latest inventory platform; known Foundry, Copilot and Power Platform
   platforms are managed and excluded.
2. Recognize explicit custom/external platforms (`Other`, custom/SDK/external/third-party,
   AWS/Bedrock/AgentCore, OpenAI/Anthropic/LangChain/LangGraph).
3. Match runtime/audit identities to record, source, Entra and observability keys.
   A key also mapped to a managed identity remains excluded.
4. Include unregistered runtime SDK spans only with `contoso.agent.kind` explicitly
   marked custom/SDK/third-party or a deliberately selected exact application role.
5. Managed platform attributes / Foundry or Studio identity markers override that
   inclusion. Generic `gen_ai.*`, framework names, provider/model, or unknown platform
   alone are not custom attribution.
6. Preserve unknown/unmapped coverage without adding it to custom totals.

The custom front end may invoke a Foundry model/backend; only its own application
identity belongs here, not the backend's separate managed inventory record.

The new queries use the selected Log Analytics workspace and its available
`AgentsInfo`, `AppRequests`, `AppDependencies`, and `CloudAppEvents` copies, not a
hard-coded tenant, agent name, or remote workspace. Inventory/raw tables are
prerequisites. Source errors remain visible, and empty health results are not a clean
security state. AgentSearch is passed using workbook-supported base64 formatting and
decoded inside KQL; it is not interpolated into a quoted KQL string. Shared APIM and
department controls are intentionally not interpreted as custom-agent selectors.

Usage and evidence semantics:

- Rows are deduplicated by resource, trace and span identifiers.
- Invocation traces are distinct traces with an invocation span, not audit-row counts.
- Stable registered IDs prevent different SDK display names from inflating agent counts.
- Token totals use only `chat` spans; root aggregates are not added a second time.
- Tool span records may include native and explicit instrumentation for one action.
- Explicit blocks, unavailable provider checks, application failures and alerts differ.
- Agent 365 timelines choose the invoked target on InvokeAgent and the acting agent
  on tool/inference events, including human callers with zero caller AgentId.
- Captured content is hidden by default. Display toggles are not authorization or
  collection controls; AppGenAIContent payloads retain their separate access path.

Validation includes all 36 live panel-query contracts, synthetic KQL fixtures
(managed exclusion, marker/role inclusion, unknown/conflicting identity, duplicate
spans, token aggregation, stable ID counting), MCP/security fixtures, and
structural/non-regression tests. Security fixtures verify managed-platform exclusion,
exact case-sensitive approval and empty-list semantics, config/runtime separation,
user-role extraction, protected-resource isolation, heuristic markers, exact alerts
and prevention of cross-agent/reversed/over-ten-minute exploit correlations.
No workbook deployment or browser rendering was performed for this change.

## New Executive Overview panels

### `v3-exec-agent-id-posture`

Data source: Microsoft Sentinel data lake.

Displays:

- Agent identity count
- Disabled identity count
- Agent identities without a matching blueprint snapshot
- Enabled identities whose blueprint is disabled
- Multi-tenant blueprint count
- Blueprints without verified-publisher metadata

### `v3-exec-agent-id-risk`

Data source: Sentinel `SecurityAlert`.

Displays:

- High-severity Agent ID-related alerts
- Medium-severity Agent ID-related alerts
- Low-severity Agent ID-related alerts
- Distinct alerted Agent ID entities

The panel selects alerts whose searchable fields contain Agent ID or agent-risk
indicators and uses the latest record for each `SystemAlertId`.

V3 does not automatically reference `AADAgentRiskEvents`. Defender Advanced Hunting
rejects an unresolved table name before query execution in scopes where this preview
table is unavailable, including when the query uses a fuzzy union. Agent ID risk
detections must be connected to Sentinel `SecurityAlert` for these panels. Empty or
zero results can reflect missing connectors, permissions, alert ingestion, or telemetry
rather than a clean security state.

## New Governance panels

### `v3-gov-agent-id-risk-detail`

Shows Agent ID-related Sentinel alerts with:

- Severity and status
- Compromised entity
- Provider and product
- Description
- Entities and extended properties
- MITRE tactics and techniques
- Stable Sentinel alert ID

Alert text and entity mapping determine whether an alert is included. This is an alert
correlation surface, not a replacement for native Defender risk-event investigation.

### `v3-gov-agent-id-admin-changes`

Hunts `AuditLogs` for candidate changes involving:

- Agent identities
- Agent identity blueprints
- Blueprint principals
- Credentials
- Owners and sponsors
- Consent and application-role assignments
- Creation, deletion, enablement, and disablement

This is a candidate hunt. Preview audit operation names and target-resource type values
can evolve and must be validated against tenant events before the query becomes a
scheduled analytic.

### `v3-gov-blueprint-principal-permissions`

Uses `EntraAgentIdentityBlueprintPrincipals` to show:

- Enabled state
- Publisher tenant
- Tenant relationship
- Multi-tenant status
- Verified-publisher metadata
- App-role-assignment requirement
- Delegated OAuth grant count
- Application-role assignment count
- Microsoft disablement status

An enabled, unverified, multi-tenant principal with grants receives the highest review
priority.

### Governance evidence boundary

The native lake tables do not provide complete:

- Owners and sponsors
- Password, certificate, and federated-credential inventory
- PIM activation history
- Child Agent ID permission grants
- Group-derived permissions
- Directory roles
- Azure RBAC
- Conditional Access targeting
- Resource-specific consent
- Target-resource ACLs

Those controls require Microsoft Graph, Azure, and resource-specific collectors.

## New Timeline & Investigation panels

### `v3-invest-agent-id-signins`

Uses `AADServicePrincipalSignInLogs` to show:

- Service principal and application identifiers
- Resource
- Result
- Result description
- IP address
- Location
- Conditional Access status
- Sign-in risk
- Credential key ID
- Agent details
- Correlation ID

The global agent search can match agent name, service-principal object ID, application
ID, or serialized agent details.

### `v3-invest-risky-agent-auth`

Joins `AADServicePrincipalRiskEvents` with successful
`AADServicePrincipalSignInLogs` records for the same service principal during the seven
days after risk detection.

This panel prioritizes:

- Confirmed-compromised identities that authenticate successfully
- High-risk identities that authenticate successfully
- Medium- and low-risk identities with subsequent activity

The result proves temporal and identity correlation. It does not prove that the risk
event caused the later sign-in.

### `v3-invest-agent-id-audit`

Shows Agent ID administrative changes around the selected entity or actor, including
modified properties, initiator, target, result, and correlation ID.

## New Security & Attack Coverage panels

### `v3-soc-agent-id-signals`

Combines three identity-plane signal classes:

1. Successful authentication after an at-risk or confirmed-compromised workload event
2. Conditional Access blocks affecting service-principal authentication
3. Candidate Agent ID administrative changes

Every row includes severity, signal, agent, agent ID, actor, detail, and correlation ID.

Conditional Access blocks are investigation signals. A block can show that a control
worked and is not automatically evidence of compromise.

### `v3-soc-agent-id-detection-contracts`

Documents eight scheduled-detection candidates:

1. At-risk Agent ID successfully authenticates
2. Confirmed-compromised Agent ID remains active
3. Agent blueprint credential changed
4. Agent owner or sponsor changed
5. Agent consent or application role expanded
6. Multi-tenant unverified blueprint has grants
7. Burst creation of child agent identities
8. Disabled Agent ID still produces activity

The contract table names severity, evidence, required source, and interpretation
limitation. It does not claim that a scheduled analytic is deployed.

## New AI Risk Score panels

### `v3-risk-agent-id-score`

Adds a separate 0-100 contribution from the latest active Agent ID-related Sentinel
alerts:

| Condition | Points per event |
|---|---:|
| High-severity alert | 20 |
| Medium-severity alert | 12 |
| Low-severity alert | 6 |

The score is capped at 100.

This score remains separate from the V2 behavioral score so users can compare versions
and so missing Agent ID telemetry does not silently reduce the existing score.

### `v3-risk-agent-id-controls`

Shows:

- Agent identities without a matching blueprint snapshot
- Enabled agent identities whose blueprint is disabled
- Unverified multi-tenant blueprint principals with delegated or application grants

## New Data Lake panels

### `v3-dl-agent-id-health`

Provides the same six posture KPIs used in Executive Overview, directly in the Agent ID
data-lake investigation context.

### `v3-dl-blueprint-topology`

Relates:

```text
Blueprint
  -> Blueprint principal
  -> Agent identities
  -> Agent users
```

The panel includes:

- Blueprint enabled state
- Sign-in audience
- Publisher domain
- Verified-publisher metadata
- Principal counts
- Enabled-principal counts
- Agent identity counts
- Enabled-agent counts
- Agent-user counts
- Delegated grant counts
- Application-role assignment counts

### `v3-dl-agent-id-hygiene`

Produces lifecycle findings for:

- Missing blueprint mappings
- Enabled identity under a disabled blueprint
- Disabled identity with runtime activity in the selected range
- Agent user without a matching agent identity
- Enabled agent user under a disabled agent identity

Runtime activity is correlated by agent application ID.

A disabled object can still have telemetry because of an access token issued before
disablement, cached sessions, or ingestion delay.

### `v3-dl-blueprint-principal-grants`

Lists blueprint principals with delegated OAuth grants or application-role assignments.
It also shows published role and scope counts, but does not treat published capabilities
as effective grants.

### `v3-dl-agent-creation-bursts`

Groups newly created child agent identities into one-hour windows by blueprint.

- Five or more identities: review
- Ten or more identities: medium
- Twenty or more identities: high

Provisioning, migration, testing, and scale-out events can create legitimate bursts.

## Workbook title and guidance changes

The title is updated to:

```text
Monitoring AI Agents V3 - Threat Hunting, Identity Security & Telemetry
```

The main introduction now identifies identity security as a first-class workbook
purpose and summarizes the V3 Agent ID additions.

The Governance and AI Risk Score headings now explicitly identify the identity control
plane.

Every new section includes evidence and interpretation guidance. Empty panels are never
described as proof of health.

## Data sources

V3 adds or expands use of:

| Source | Purpose |
|---|---|
| `SecurityAlert` | Resilient Agent ID-related risk and detection surface used by V3 |
| `AADAgentRiskEvents` | Optional Defender-native Agent ID risk source; documented but not queried automatically |
| `AADServicePrincipalRiskEvents` | Workload risk correlation in Log Analytics |
| `AADServicePrincipalSignInLogs` | Agent/workload authentication and Conditional Access |
| `AuditLogs` | Agent ID and blueprint administrative-change hunting |
| `AgentsInfo` | Discovered platform, owner, tool, MCP, and authentication context |
| `EntraAgentIdentities` | Agent identity inventory and lifecycle |
| `EntraAgentIdentityBlueprints` | Blueprint inventory, audience, publisher, and enabled state |
| `EntraAgentIdentityBlueprintPrincipals` | Principal trust and permission grants |
| `EntraAgentUsers` | Agent-user relationships and lifecycle |
| `UnifiedAgentObservability` | Runtime activity for lifecycle correlation |

## Schema and product limitations

The Entra Agent ID data-lake tables are preview system tables. V3 uses schema fields
captured in October 2026. Run `getschema` for all five Agent ID/observability tables
after connector or platform updates.

The following distinctions are intentional:

- Published roles/scopes are not grants.
- A permission grant is not proof that the permission was used.
- A sign-in is not proof of a downstream action.
- A risk event is not proof of compromise unless its state says confirmed compromised.
- A detection signal is not proof that an attack succeeded.
- A Conditional Access block can represent successful prevention.
- A disabled identity can have delayed or pre-disable activity.
- Missing telemetry is not a clean result.

## Build

Run:

```powershell
Set-Location .\Workbooks\AI-Agents-Monitoring
node .\build-v3.mjs
```

The generator:

1. Finds the existing V2 artifact.
2. Adds V3 items without changing V2.
3. Validates all required groups.
4. Validates unique workbook item names.
5. Validates all 17 required V3 query items.
6. Validates the workbook schema version.
7. Writes `AI-Agents-Monitoring-Workbook-V3.workbook`.

The generator also adds and validates the 41 Custom Agents queries. To run structural
checks after generation:

## Deploy

Manual portal import:

1. Open Microsoft Sentinel.
2. Open **Threat management > Workbooks**.
3. Select **Add workbook** or edit an existing workbook.
4. Open the advanced editor.
5. Paste the contents of `AI-Agents-Monitoring-Workbook-V3.workbook`.


V3 uses a distinct default display name and deterministic resource ID, so it deploys
beside V2 unless `WorkbookId` or `DisplayName` is explicitly reused.

## Validation performed by the repository

The V3 implementation is expected to pass:

- Node.js generator execution
- JSON parsing
- `Notebook/1.0` version check
- Unique item-name check
- Required group and anchor checks
- Required V3 panel check
- Query-type payload parsing
- PowerShell deployment-script syntax parsing

Live KQL execution still requires a tenant with the corresponding connectors, tables,
licenses, permissions, and populated telemetry.

The inherited `ah-risk` and `ah-riskstate` panels are replaced in the generated V3
artifact with Log Analytics `SecurityAlert` queries. This prevents an unavailable
`AADAgentRiskEvents` table from breaking those panels.

The inherited `ah-kpi` panel is also converted to a Log Analytics query over
`SecurityAlert`. It reports AI/agent alerts, high-severity AI alerts, prompt-attack
alerts, MCP/tool alerts, Agent ID alerts, and distinct alerted entities. This avoids
optional-table fuzzy unions and prevents an unresolved hidden Advanced Hunting
workspace parameter from breaking the summary KPI. Detailed Defender panels continue
to use Advanced Hunting.
