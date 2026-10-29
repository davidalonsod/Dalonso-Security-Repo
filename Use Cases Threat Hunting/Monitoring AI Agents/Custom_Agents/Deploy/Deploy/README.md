# Deploy Custom Agents detections

The template is generated from the pack's catalog and KQL functions. Rebuild from
the parent directory with `node .\build-custom-agents.mjs`, or run
`.\New-CustomAgentsArmTemplate.ps1` here. Neither command contacts Azure.

## Prerequisites

1. A Sentinel-enabled workspace in the target resource group.
2. AppRequests and/or AppDependencies with correctly attributed custom SDK spans.
   The pack's fuzzy union tolerates one absent table, not both missing.
3. Approved **inline** recording in `gen_ai.input.messages` / `gen_ai.output.messages`
   and tool-body properties, with matching resource/trace/span/agent IDs and supported
   message roles/parts. No AppGenAIContent dependency or protected-table access is needed.
4. If inventory is enabled, an ingested/queryable workspace **AgentsInfo** copy.
5. Permission to deploy Sentinel analytic rules/watchlists and Log Analytics saved
   searches/functions. Deployment permission does not automatically grant the
   rule-query identity or analysts table access.

All analytics now expose unmasked recorded prompt/output in query results and shorter
previews in custom details. This is a deliberate change from the older metadata-only
pack. Review sensitive-data exposure, SOC/automation access and retention before enabling.

## Parameters

| Parameter | Default | Effect |
| --- | --- | --- |
| `workspaceName` | Required | Target workspace in the deployment resource group |
| `enableAnalyticRules` | `false` | Explicitly enable deployed analytics; keep false during onboarding |
| `deployContentDetections` | `false` | Include 11 inline content-pattern analytics and 4 content hunts; does not control capture or evidence enrichment |
| `useAgentInventory` | `false` | Use AgentsInfo classification/declared MCP; otherwise an explicit SDK-only empty inventory function |

The default deployment creates **8 disabled metadata-trigger analytics + 10 hunts + 3
functions + 2 watchlists**. Set `deployContentDetections=true` for **19 disabled
analytics + 14 hunts + 3 functions + 2 watchlists**. All deployed analytics include
inline evidence enrichment, even when content-pattern detections are omitted.
The inline helper is therefore always included. Watchlists contain disabled placeholder rows.

Catalog v1.2 adds three analytics (credential-shaped tool arguments, credential-shaped
tool results, and tool-result instruction override before risky model output) and three
hunts (tool-body security evidence, capture/parsing gaps, and indirect/output chain
evidence). Existing coverage/security/timeline hunts and alert evidence projections
also expose capture states. The [complete change summary and inventory](../README.MD#complete-change-summary)
describes all original and new resources. Conditional counts in ARM are generated
from the catalog instead of maintained separately.

`useAgentInventory=true` replaces the SDK-only inventory function with the real
14-day AgentsInfo query. Managed inventory evidence then overrides an SDK marker
or central custom scope. Do not enable this option without the table and access.

## Validate and deploy disabled

Use your own tenant, subscription, resource group and workspace. No lab names or
resource IDs are embedded in the template/parameter file. The examples below are
commands for an operator, **not actions performed by building the pack**.

```powershell
az login --tenant '<tenant-id>'
az account set --subscription '<subscription-id>'

# Full inline-content pack. This validates without deploying resources.
az deployment group validate `
  --resource-group '<resource-group>' `
  --template-file .\azuredeploy.json `
  --parameters workspaceName='<sentinel-workspace>' `
    enableAnalyticRules=false deployContentDetections=true useAgentInventory=false

# Explicit deployment, still disabled.
az deployment group create `
  --resource-group '<resource-group>' `
  --template-file .\azuredeploy.json `
  --parameters workspaceName='<sentinel-workspace>' `
    enableAnalyticRules=false deployContentDetections=true useAgentInventory=false
```

Do not pass the unchanged placeholder workspace in `azuredeploy.parameters.json`.
ARM provider validation can require the target workspace/Sentinel configuration;
local structural checks and fixture success do not replace target-specific validation.

## Configure, test, then enable selectively

1. Wait for the deployed watchlists to become queryable through `_GetWatchlist`.
2. Edit **CustomAgentScope** if using central attribution. Its resource ID is the
   **Application Insights component resource ID**, not a workspace ID. Review exact
   role/agent scope and managed exclusions. Do not allow mixed managed/custom roles.
3. Populate **CustomAgentApprovedMcpTargets** with reviewed exact server identifiers.
   Enable only approved rows. The list applies globally to this custom pack.
4. Run source health and attribution hunts. Review both watchlists' Rows,
   EnabledRows and State. Empty/new watchlists may not expose CSV columns yet;
   the fixed functions compile safely but report configuration unavailable.
   Resolve missing tables, permissions, missing lineage and unavailable inventory
   before interpreting empty findings.
5. Run inline-content coverage and the unmasked evidence hunts. Confirm same-span
   capture, supported roles, source span IDs and explicit missing-evidence labels.
   Review the capture/parsing-gap diagnostic: recorded empty is not missing capture,
   and recorded-but-unparsed output cannot satisfy assistant-text detections.
   The indirect-result/output chain requires a nonnegative measured tool duration;
   verify recorded tool end precedes model start rather than assuming instantaneous completion.
6. Exercise an owned, nonproduction custom agent with harmless test markers, ordinary
   questions and an authorized synthetic tool. Never run exploitation or real
   credential-exposure tests to force a finding. Pure chat cannot exercise tool rules.
7. Run the synthetic test suite from the pack README. It performs no ingestion.
8. Tune the catalog thresholds and rebuild; defaults are operational heuristics, not
   universal attack thresholds. Enable selected analytics manually after review.
   Setting `enableAnalyticRules=true` explicitly enables **all deployed rules**,
   including the three additions. Do not use it as an unattended migration setting
   if only the previously enabled rules should remain active.
9. Inspect AzureResource and CloudApplication entities, exact agent/resource incident
   grouping, prompt/output custom-detail previews and expected false positives before wider rollout.

Alerts can contain real credential matches and confidential messages. Query results
return full recorded content; custom details have budgeted previews because Sentinel
limits all custom details combined to 2 KB. Aggregate inventory/usage hunts remain
metadata summaries; use the trace and content-security hunts for full evidence.
This pack's Sentinel alerts do not become native Defender AI Security alerts merely
because the SDK uses Agent 365.

## Update and rollback

IDs and function aliases are deterministic across builds. Rebuilding does not deploy.
Redeploying the full template updates those IDs and watchlist content; preserve/export
reviewed watchlist entries before replacing their generated placeholder CSVs.

For an existing installation, omit the two already-existing watchlist resources and
their dependency edges from an explicitly reviewed incremental update template, or
deploy reviewed current watchlist contents instead of seeds. Install helpers before
updating rules/hunts: inventory and spans first, then CustomAgentInlineContent, then
dependent query resources. Preserve the existing useAgentInventory choice and each
rule's enabled state; the checked-in false default must not accidentally disable
your currently enabled rules. If rules have mixed states, preserve them individually
instead of bulk-enabling the whole template.

When upgrading an installation with the original 16 rules, include
`deployContentDetections=true` so the eight formerly protected content queries are
actually updated. Passing false does not migrate or remove those existing queries.
This parameter remains opt-in for a new installation.

All original analytic IDs and prior 11 hunt IDs are stable. Compared with v1.1,
v1.2 adds three analytics and three hunts; compared with v1.0, there are three
additional analytics and four additional hunts. Preserve the current enabled states
of existing IDs and leave new rules disabled until their false positives/overlap are
reviewed. Bulk enabling the generated template is not a state-preserving update.

Update the inline helper before the new/updated queries: v1.2 additionally uses
DurationMs and InputParseState/OutputParseState/ToolArgumentsState/ToolResultState.
An older v1.1 helper alias is not schema-compatible with the new evidence projection.
The new
inline helper has its own deterministic ID. The old protected alias is not called
or removed automatically. No deployed resource has been changed by this source update.
Existing alerts are not rewritten; inspect retained inline data with the new hunt.
See the pack [SOC investigation guide](../README.MD#soc-investigation-and-upgrading-existing-alerts).

Turning a deployment `condition` false is **not removal** in incremental ARM mode.
If content resources were previously deployed and you later set
`deployContentDetections=false`, old content rules/functions/hunts remain. Disable
the old content rules and deliberately remove only this pack's reviewed IDs if
retiring them. Do not use complete-mode deployment to delete unrelated resources.

Disable the pack's rules first during rollback. Retain recorded evidence per your
organization's retention policy; disabling rules does not delete already collected data.

## Managed / empty-watchlist semantic error

The initial deployment could fail with:

```text
SEM0015: Failed to analyze expression for extended column ["Managed"]
```

In the investigated case the inventory function resolved, but both new watchlists
had zero rows. `_GetWatchlist` exposed only `_DTItemId`, LastUpdatedTimeUTC,
SearchKey and WatchlistItem, not the CSV fields. The direct lookup failed with
`SEM0100: Failed to resolve scalar expression named 'Enabled'`; within the nested
classifier it appeared as the Managed error. Changing the Managed classification
or disabling inventory would not fix that missing watchlist schema.

The corrected CustomAgentSpans query uses `column_ifexists` and typed projections
for Enabled, ScopeType, ResourceId, ScopeValue and ServerIdentifier, with explicit
WatchlistItem-bag support. It retains exact role/approval semantics and managed
precedence. An empty approval list remains CONFIGURE ALLOWLIST, never approval or
an unapproved-server finding. Central scope/exclusions cannot operate until their
reviewed entries are queryable; marker/inventory attribution remains available.

Template-level ARM validation is not Sentinel query-semantic validation. The older
fixture tests also substituted pretyped tables and therefore missed cold-start
watchlist schemas. The updated tests cover zero-row base schemas, populated dynamic
bags, real watchlist lookups, and actual saved-function aliases. Synthetic helpers
use separate names so deployed aliases cannot replace the fixture definitions.

For an existing partial deployment:

1. Rebuild the corrected template from the pack source.
2. Preserve/export existing watchlists; do not overwrite reviewed entries with seed
   CSVs. A recovery deployment may omit the two already-existing watchlist resources
   and their dependency edges. Do not omit them on a new installation.
3. Apply the corrected helper functions first and verify
   `CustomAgentProtectedContent(1h) | take 0 | count` resolves. Use
   `CustomAgentSpans(1h) | take 0 | count` in metadata-only mode.
4. Retry the pack's same rule IDs in incremental mode with deliberately selected
   enablement/content/inventory settings. Do not use complete mode or duplicate IDs.
5. Run the tests with `-CheckLiveWatchlists -CheckDeployedFunctions`, inspect watchlist
   readiness, and verify actual rule enablement separately from template defaults.

On 2026-10-28 the approved staged recovery succeeded: helper deployment
`custom-agent-watchlist-schema-helpers`, then
`custom-agent-watchlist-schema-repair`. All 16 analytics were verified enabled with
their original IDs and expected queries; protected-content and inventory mode were
retained at the operator's request. Recovery operations did not write either
watchlist. Both lists were still empty at verification and require configuration
where central scoping/exclusions or MCP approval is needed.

The original failed deployment records remain failed historical records. Review
the new recovery deployment and current analytic resources to confirm the repair.
