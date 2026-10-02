 Agent 365 Permission Intelligence

An evidence-backed identity and access graph for answering four questions about AI agents:

1. What permissions were configured?
2. What access was actually observed?
3. What resources are deterministically, boundedly, or inferentially reachable?
4. What changes—and what might break—if access is removed?

The project combines a canonical JSON model, a deterministic evaluator, Microsoft Sentinel/Agent 365 data adapters, and an importable Azure Workbook designed for CISO, IAM, SOC, audit, and application-owner workflows.

 Introduction

An AI-agent inventory can tell you that an identity exists. A permissions export can tell you that a scope or role was granted. An activity log can tell you that an operation occurred.

None of those sources, by itself, answers:

 Which Agent 365 identities exceed their intended blueprint, what sensitive resources can they reach, how was that conclusion derived, and what is the impact of changing the access?

Agent 365 Permission Intelligence treats identity, configured authorization, observed behavior, resource reachability, controls, and evidence quality as separate graph planes. They can be correlated, but they are never silently converted into one another.

 Why this is useful

The workbook turns raw identity and telemetry records into defensible IAM decisions:

- Identify direct permissions outside a blueprint baseline.
- Distinguish inherited, direct, delegated, RSC, Azure RBAC, and workload-ACL paths.
- Measure permission utilization without treating request volume as permission count.
- Separate configured-but-unobserved access from observed-but-unexplained activity.
- Show deterministic, bounded, inferred, blocked, and unknown resource reach separately.
- Explain why an agent has access through ordered provenance edges.
- Identify stale, dormant, orphaned, or incompletely governed identities.
- Simulate permission, identity, RSC, Azure role, and blueprint changes.
- Preserve source authority, confidence, freshness, and collector coverage.

A representative executive metric is:

 Only X% of configured permissions were observed during the last 90 days.

`X` is calculated from distinct configured agent-permission paths matched to at least one observation—not from request volume. It is a least-privilege review signal, not proof that every unobserved permission is unnecessary.

 Non-negotiable evidence rules

1. An observed event never becomes a configured grant.
2. A broad grant never becomes an exact resource list without enforceable resource state.
3. An inferred path is never presented as fact.
4. Missing evidence is `unknown`, not `allowed`, `denied`, or `unused`.
5. Simulation is dry-run graph recomputation, never destructive automation.

 Project status

- [`examples/procurement-agent.access.json`](./examples/procurement-agent.access.json) is fully synthetic. It represents no real tenant, incident, identity, or user.
- The workbook defaults to Live Tenant mode. Synthetic results are hidden unless Content = Synthetic demo is selected.
- Live Agent 365 panels query Sentinel Data lake System tables directly.
- The production collector populates `AgentPermissionEdges_CL` with Microsoft Graph, Azure Resource Graph, Conditional Access, audit, identity, permission, control, and derived reachability evidence. Live results require deploying and running that collector in the selected workspace.
- KQL files are implementation starting points. Their comments identify confirmed schemas, assumptions, and tenant-specific validation steps.

 Quick start

 Validate and evaluate the synthetic model

From the repository root:

powershell
node access-graph\scripts\validate-access-model.mjs
node access-graph\scripts\evaluate-access.mjs


The evaluator writes:


access-graph/examples/procurement-agent.access.evaluation.json


 Import the workbook

1. Open a Workbooks experience that supports the Data lake data source.
2. Create a workbook.
3. Open Advanced editor.
4. Paste [`workbook/agent-effective-access-workbook.json`](./workbook/agent-effective-access-workbook.json).
5. Apply the JSON.
6. Select a Subscription and Analytics workspace.
7. Confirm the visible Agent 365 Data lake scope is System tables (Agent 365).

Reimport the JSON after repository changes; the portal does not automatically update an already-imported copy.

 Dual-source architecture

The workbook intentionally uses two evidence locations.

 Agent 365 Data lake / System tables

Used for native Agent 365 identity and runtime evidence:


EntraAgentIdentityBlueprints
EntraAgentIdentities
EntraAgentUsers
UnifiedAgentObservability


Data lake query items serialize KQL inside a JSON envelope:

json
{
  "queryType": "sentinelDataLake",
  "query": "{\"workspaces\":[{\"id\":\"default\",\"name\":\"default\",\"apiName\":\"default\"}],\"query\":\"EntraAgentIdentities | take 5\"}"
}


Putting raw KQL directly in a Data lake `content.query` property causes a client-side `... is not valid JSON` error.

 Selected Analytics workspace

Used for:


AgentsInfo
MicrosoftGraphActivityLogs
AADServicePrincipalSignInLogs
CloudAppEvents
AgentPermissionEdges_CL
synthetic datatable demonstrations


Synthetic `datatable()` visualizations run against the selected Analytics workspace rather than the Data lake endpoint. This avoids Data lake request failures for workbook-only sample queries.

 Optional KQL jobs

Queries 08 and 09 can optionally materialize narrow Agent 365 projections for scheduled analytics, cross-tier joins, or longer analytics-tier retention:

text
AgentIdentityInventory_KQL_CL
AgentExecutionActivity_KQL_CL


They are not required by the workbook.

 Filters

 Global filters

| Filter | Purpose |
| --- | --- |
| Subscription | Scopes Analytics workspace discovery |
| Analytics workspace | Selects Log Analytics/Defender/Graph activity and canonical-edge data |
| Agent 365 Data lake | Displays the fixed `System tables (Agent 365)` scope |
| Content | Defaults to Live tenant; optionally reveals the explicitly labeled synthetic demonstration |
| Activity window | Controls runtime and source-health lookback |
| Agent identity / sample agent | Live Agent ID object IDs plus explicitly labeled `[SAMPLE]` agents |
| Blueprint | Live blueprint app IDs plus labeled sample blueprints |
| Identity state | Active/enabled or disabled/blocked |
| Permission | Live values from `AgentPermissionEdges_CL` and resiliently extracted `AgentsInfo.Permissions`; labeled sample values in Demo mode |

 Investigation filters

Visible only in Observed Access:

| Filter | Purpose |
| --- | --- |
| Execution context | Human delegated/OBO, autonomous application, agent-to-agent, unknown |
| Activity type | Stable Agent 365 operation choices, so the filter remains usable even when the current time window has no events |
| Tool | Dynamic Agent 365 `ToolName` values |

High-cardinality filters are single-select. `All` uses a literal `*` sentinel instead of expanding every Agent ID, activity type, or tool into the request. This prevents `413 Request Entity Too Large` failures.

Agent and Blueprint values are mode-aware: Live Tenant lists only live Agent ID values; Synthetic Demo lists only `[SAMPLE]` identities and blueprints.

Every analytical page has live detail and a live visual summary. Configured, reachable, drift, sensitive-exposure, explain-path, change-impact, evidence-confidence, and Permission 360 panels read `AgentPermissionEdges_CL` with a safe empty fallback.

Reachability and exposure panels also perform the same conservative permission-to-resource-category mapping as the collector when an older snapshot has configured grants but no derived reachability edges yet. This fallback can produce `SharePoint sites`, `Exchange Online mailboxes`, or `Microsoft Entra directory`; it cannot produce an exact site, mailbox, file, or sensitivity label. Missing classification remains `Unknown`.

Synthetic tables, charts, matrices, recommendations, timelines, and simulations are conditionally hidden until Content is switched to Synthetic demo.

The Permission filter is also mode-aware:

- Live Tenant combines configured `PermissionValue` entries from `AgentPermissionEdges_CL` with best-effort values from `AgentsInfo.Permissions`.
- Synthetic Demo shows labeled sample scopes/roles.
- If neither live source is populated, the menu displays `No live permission data — connect AgentPermissionEdges_CL or populate AgentsInfo.Permissions` instead of presenting an unexplained empty list.

 Selected-agent context

A persistent context area appears above the tabs.

It contains two source-specific outputs:

1. Live Agent ID Portfolio / Selection Context  
   Directly queries `EntraAgentIdentities`.
2. Sample Permission Portfolio / Selection Context  
   Uses synthetic posture data from the selected Analytics workspace.

When Agent identity is `All`, both show compact portfolio summaries. Selecting a live or sample identity reduces the corresponding output to that identity. Live and synthetic evidence are never unioned into one request.

 The eleven workbook views

 01 Executive — What requires attention?

The decision landing page contains:

- Multi-metric live Permission Intelligence tiles
- Per-agent permission lists, provenance, write capability, utilization, controls, and evidence freshness
- Live configured-versus-observed utilization chart
- Live permission concentration chart
- Executive attention KPI cards
- Privilege Exposure Matrix
- Agents requiring attention
- Evidence-coverage graphic
- Agent Permission Posture
- Permission-utilization headline
- Live Agent ID, blueprint, user, and event counts
- Permission concentration

The page leads with problems and actions. Methodology is located under Evidence & Methodology.

 02 Identity & Lifecycle — Who or what is this agent?

Shows:

- Live identity population chart by blueprint and enabled state
- Blueprint → agent identity → optional agent-user lineage
- Application IDs and directory object IDs
- Enabled/disabled state
- Blueprint mapping health
- Agent ID vs classic service-principal coverage
- Live Agent 365 identity context
- Dormant, stale, orphaned, ownerless, and blueprint-mismatch examples

Owner, sponsor, manager, and classic-service-principal findings require Microsoft Graph data beyond the four native Agent 365 lake tables.

 03 Configured Access — What was actually granted?

Separates:

- Application permissions
- Delegated permissions
- Direct assignments
- Blueprint inheritance
- Resource-specific consent
- Group-derived authorization
- Directory roles
- Azure RBAC
- Workload ACLs
- Declaration, grant, and token state

The view also shows permission utilization and configured path details. Runtime activity never creates configured rows.

Live mode adds permission concentration and grant-provenance charts beside the authoritative edge grid.

 04 Observed Access — What did it actually do?

Shows:

- Live `UnifiedAgentObservability` activity
- Live operation distribution and activity timeline
- Agent caller and human subject
- Acting application
- Agent-to-agent calls
- Tools and MCP servers
- Models and token usage
- Result/error state
- Observed operations explained by configured paths
- Observed activity without explained configuration

Execution context, activity type, and tool filters are scoped to this investigation page.

 05 Effective & Reachable Access — What can it effectively reach?

Every result is classified as:

text
Deterministic
Bounded
Inferred
Blocked
Unknown


Examples:

- Exact RSC + site permission → deterministic
- Broad grant + complete resource inventory → bounded
- Permission-to-resource-type mapping → inferred
- Consent without resource ACL → blocked/incomplete
- Missing ACL/control collector → unknown

Live mode shows a reachability-class pie chart, a resource-category chart, and the detailed supporting rows. Broad Graph scopes are mapped only to inferred categories. Explicit Azure RBAC scopes can be deterministic; tenant directory roles are bounded.

 06 Blueprint Drift — Does reality match intent?

Compares:

- Blueprint declaration
- Inheritable eligibility
- Blueprint-principal consent
- Child materialization
- Child direct exceptions

It also includes direct-vs-blueprint comparisons and a permission-change timeline. A direct child exception is not mislabeled as an inheritance failure.

In live mode, the comparison is computed from Agent ID `belongsTo` edges, blueprint `declares` edges, and child configured grants. It reports baseline matches, direct exceptions, and missing blueprint mappings.

 07 Sensitive Exposure & Hygiene — What valuable data is exposed?

Shows:

- Live classified and potential exposure candidates
- Resource-category and access-level graphics
- Sensitive-resource classification
- Access level
- Reachability class
- Permission and evidence
- Transparent Permission Exposure Index
- Evidence-qualified recommendations
- Stale, unused, dormant, direct-exception, and incomplete-evidence findings
- Hygiene priority distribution

No finding triggers automatic revocation.

If no governed classification source is connected, the workbook still shows potential resource-category exposure with classification `Unknown` and names the missing evidence. It does not hide the rows or invent a sensitivity.

 08 Explain Access Paths — Why can it reach it?

Provides:

- Friendly live Agent names and ordered canonical edge stages
- Live edge-plane composition chart
- Permission provenance
- Ordered identity/inheritance/consent/materialization paths
- Direct/RSC/RBAC/ACL relationships
- Permission escalation paths
- Dependency edge data
- Confidence and source authority per hop

This is the primary IAM investigation experience.

 09 Change Impact — What happens if I change it?

Performs dry-run analysis for:

- Removing a direct app role
- Removing blueprint eligibility
- Disabling an agent identity
- Removing Azure RBAC
- Revoking delegated consent
- Changing RSC
- Changing a blueprint principal

Outputs remain separate:

text
Configured edges removed
Deterministic paths lost
Observed dependencies affected
Potential dependencies affected
Alternative paths
Token/session uncertainty
Business-process impact


Live mode adds per-agent/per-permission impact rows, permission blast-radius graphics, and blueprint declaration fan-out.

 10 Evidence & Methodology — Can I verify the conclusion?

Contains:

- Source and evidence-plane map
- Capability register
- Reading guide
- Visual legend
- Collector authority
- Schema status
- Data lake source health
- Analytics workspace source health
- Confidence composition
- Live confidence and evidence-authority distribution
- Query behavior and limitations
- Missing configured-permission collector warnings

 11 Permission 360 — Give me everything about this agent

Combines:

- Live Agent ID identity context
- Live configured/observed/reachable/control posture
- Live permission list, provenance, target service principal, resource categories, and evidence timestamps
- Live utilization and evidence-plane graphics
- Direct vs inherited counts
- Permission utilization
- Deterministic and inferred reach
- Drift
- Evidence completeness
- Recommendations
- Utilization graphic

 The sixteen Permission Intelligence capabilities

1. Permission Coverage
2. Permission Utilization
3. Permission Provenance
4. Direct vs Blueprint Drift
5. Permission Escalation Paths
6. Permission → Resource Reach
7. Observed vs Potential Blast Radius
8. Transparent Permission Exposure Index
9. Permission Hygiene
10. Agent ID vs Classic Service Principal coverage
11. Permission Change Timeline
12. Blueprint Blast Radius
13. Permission Concentration
14. Permission Dependency Graph
15. Permission Confidence
16. Agent Permission 360

“Implemented” means the workbook surface and evidence semantics exist. Live results appear only when their authoritative source is connected. Otherwise a live panel reports no rows or `unknown`; it never silently substitutes sample findings. Synthetic outputs remain available only when Content = Synthetic demo is selected.

 Canonical permission-edge model

Normalize Microsoft Graph, Azure Resource Graph/ARM, Agent 365 Data lake, resource ACL, and control-policy results before visualization.

Files:

- [`schema/permission-edge-schema.json`](./schema/permission-edge-schema.json)
- [`kql/10-canonical-permission-edge-contract.kql`](./kql/10-canonical-permission-edge-contract.kql)

Recommended table:


AgentPermissionEdges_CL


Edge classes:


identityLifecycle
configured
observed
reachableDeterministic
reachableBounded
reachableInferred
control


Observed/reachable/control edges may reference a configured edge through `ConfiguredEdgeId`, but never replace it. Every edge preserves source system, source object, authority, confidence, observed/retrieved/valid times, and collector version.

 Three implementation phases

 Phase 1 — Canonical model

| File | Purpose |
| --- | --- |
| [`schema/access-model-schema.json`](./schema/access-model-schema.json) | Input facts: identities, grants, constraints, resources, executions, dependencies, change proposals |
| [`schema/access-model-evaluation-schema.json`](./schema/access-model-evaluation-schema.json) | Evaluated output contract |
| [`schema/permission-edge-schema.json`](./schema/permission-edge-schema.json) | Normalized multi-source edge contract |
| [`examples/procurement-agent.access.json`](./examples/procurement-agent.access.json) | Synthetic worked example |

 Phase 2 — Deterministic evaluator

| File | Purpose |
| --- | --- |
| [`scripts/validate-access-model.mjs`](./scripts/validate-access-model.mjs) | Structural and cross-reference validation |
| [`scripts/evaluate-access.mjs`](./scripts/evaluate-access.mjs) | Permission resolution, drift, exposure, utilization, and change-impact evaluation |

Run:

powershell
node access-graph\scripts\validate-access-model.mjs
node access-graph\scripts\evaluate-access.mjs


 Phase 3 — Source adapters

| Query | Purpose |
| --- | --- |
| [`01-agent-entitlement-materialization.kql`](./kql/01-agent-entitlement-materialization.kql) | Graph token-claim cross-check |
| [`02-observed-permission-usage.kql`](./kql/02-observed-permission-usage.kql) | Graph operation-to-permission mapping |
| [`03-service-principal-context-and-risk.kql`](./kql/03-service-principal-context-and-risk.kql) | Sign-in, CA, and identity-risk context |
| [`04-blast-radius-dependency-rollup.kql`](./kql/04-blast-radius-dependency-rollup.kql) | Telemetry-side blast-radius cross-check |
| [`05-agentsinfo-blueprint-and-identity-snapshot.kql`](./kql/05-agentsinfo-blueprint-and-identity-snapshot.kql) | `AgentsInfo` identity/configuration snapshot |
| [`06-cloudappevents-agent-execution-spans.kql`](./kql/06-cloudappevents-agent-execution-spans.kql) | Agent 365 OTel fields in `CloudAppEvents` |
| [`07-sentinel-datalake-agent-tables-preflight.kql`](./kql/07-sentinel-datalake-agent-tables-preflight.kql) | Confirmed Agent 365 lake schemas/freshness |
| [`08-datalake-agent-identity-inventory-job.kql`](./kql/08-datalake-agent-identity-inventory-job.kql) | Optional identity projection job |
| [`09-datalake-unified-agent-executions-job.kql`](./kql/09-datalake-unified-agent-executions-job.kql) | Optional privacy-minimized execution projection |
| [`10-canonical-permission-edge-contract.kql`](./kql/10-canonical-permission-edge-contract.kql) | Canonical table shape |

 Live configured-permission collector

The production collector populates `AgentPermissionEdges_CL` in `WORKSPACE`.

 Infrastructure

[`infra/`](./infra) contains subscription-scope Bicep that reuses:

- `RG_xxxx`
- `LAW`
- `aa-sentinel-sync`
- the Automation Account's system-assigned managed identity

It creates:

- `AgentPermissionEdges_CL`
- `dce-agent-permission-edges`
- `dcr-agent-permission-edges`
- a DCR-scoped `Monitoring Metrics Publisher` assignment
- a current-subscription `Reader` assignment

 Collector

[`collector/`](./collector) contains:

- the managed-identity PowerShell 7.2 runbook;
- an idempotent post-infrastructure deployment script;
- synthetic no-Azure-write tests;
- a non-secret example configuration;
- operations and rollback guidance.

The collector retrieves:

- Agent ID blueprints, blueprint principals, identities, agent users, owners, and sponsors;
- app-role assignments and delegated OAuth grants;
- blueprint inheritance eligibility and materialized inheritance;
- transitive group-derived app-role assignments;
- directory-role assignments/eligibility;
- current-subscription Azure RBAC;
- permission/role changes from AuditLogs;
- Conditional Access workload-identity targeting;
- disabled identities and credential-expiry controls.

It writes only authorization metadata/resource identifiers. It does not collect prompts, responses, reasoning, tool arguments/results, or documents.

 Deployment workflow

The approved deployment plan is [`.azure/deployment-plan.md`](../.azure/deployment-plan.md).


azure-prepare → azure-validate → azure-deploy


Do not deploy the Bicep or run the post-infrastructure script until Azure validation succeeds. The first collector execution must be manual and the daily schedule remains disabled until table/workbook results are verified.

 Visual language

| Color | Meaning |
| --- | --- |
| 🔵 Blue | Configured grants, declarations, roles, consent, ACLs |
| 🟢 Green | Observed runtime activity |
| 🟡 Amber | Deterministic/bounded reach and change caution |
| 🟣 Purple | Inferred reach and potential dependencies |
| 🔴 Red | Controls, drift, exposure, and review priority |
| ⚪ Gray | Unknown or missing evidence |

The workbook uses KPI tiles, bar charts, pie charts, a permission-change timeline, numeric heat bars, filters, and exportable evidence grids. Visual summaries never replace the supporting evidence.

 Troubleshooting

 Data lake query says the KQL is not valid JSON

Data lake query items require a nested JSON payload. Do not put raw KQL directly in `content.query`.

 `413 Request Entity Too Large`

Use the current single-select filters. `All` is the literal `*`; it must not expand every identity/tool/activity value into the request.

 Synthetic output fails through Data lake

Synthetic `datatable()` items should use the selected Analytics workspace. Native Agent 365 tables should use Data lake System tables.

 Live multi-table query returns HTTP 500

Prefer source-specific Agent 365 queries over one large cross-table union. The Executive page intentionally uses separate identity, blueprint, agent-user, and event queries.

 Live `UnifiedAgentObservability` panels return HTTP 400

Two independent issues can cause this on the same panels, so fix both:

1. Bare `{TimeRange}` macro. `TimeGenerated {TimeRange}` only auto-expands into a comparison operator (for example `= ago(24h)`) for query types the Workbooks runtime recognizes natively, such as Log Analytics (`queryType: 0`) and Azure Resource Graph. For `queryType: "sentinelDataLake"` items it is not expanded the same way, so the literal placeholder text reaches the Data lake engine as invalid KQL. Use the explicit form instead:

   kusto
   | where TimeGenerated between (datetime({TimeRange:startISO}) .. datetime({TimeRange:endISO}))
   

2. Stale/incorrect schema columns. An earlier `getschema` capture (recorded in [`07-sentinel-datalake-agent-tables-preflight.kql`](./kql/07-sentinel-datalake-agent-tables-preflight.kql)) listed four columns that do not actually exist against the live tenant: `PlatformAgentId`, `EventTypeName`, `ToolServerName`, and `ClientIp`. Each one makes the Data lake engine return `SemanticError: 'extend'/'project' operator: Failed to resolve scalar expression named '<column'` — and because KQL compilation stops at the first unresolved name, fixing one can simply reveal the next, so a single `400` can take several rounds to fully resolve. The portal only ever surfaces a generic `400`; the real message is only visible in browser DevTools → Network → the failed request's Response tab (not Console). Use the verified replacements instead: `PlatformTargetAgentId`/`PlatformTargetAgentName` (not `PlatformAgentId`), `coalesce(EventOriginalType, EventType)` (not `EventTypeName`), and drop `ToolServerName`/`ClientIp` entirely (no equivalent column exists). The preflight file now carries the re-verified 69-column list — treat any `getschema` capture as a point-in-time snapshot and re-run it before relying on a column that matters, since these are preview/system tables.

This affects every view that queries `UnifiedAgentObservability` directly (Executive, Observed Access). `enrich-live-workbook.mjs` generates new Data lake items with both fixes already applied; if you hand-author a Data lake query item, follow the same pattern.

 Selected context is empty

The current workbook shows portfolio summaries when `All` is selected and selection summaries for one agent. Ensure you imported the latest workbook JSON.

 `No resources selected`

Choose a Subscription and Analytics workspace. Workspace-scoped synthetic and source-health queries need that selection.

 Known limitations

- The four Agent 365 lake tables do not expose complete resource-permission assignments.
- `appRoles` and `oauth2PermissionScopes` on a blueprint describe permissions exposed by the application, not grants assigned to it.
- Complete live configured access requires Microsoft Graph (`appRoleAssignments`, `oauth2PermissionGrants`, blueprint `inheritablePermissions`, owners/sponsors, directory roles, groups, RSC) and Azure Resource Graph/ARM/resource-ACL collectors.
- Broad permissions cannot produce deterministic resource lists without complete resource inventory and authorization state.
- Conditional Access and token revocation effects are scenario/resource dependent.
- Preview schemas and workbook Data lake behavior can change.

 
