 Agent Permission Edge Collector

This directory contains the PowerShell 7.2 collector and the idempotent post-infrastructure configuration script for the canonical `AgentPermissionEdges_CL` table.

The collector follows the evidence contract in [`../schema/permission-edge-schema.json`](../schema/permission-edge-schema.json) and the ingestion shape in [`../kql/10-canonical-permission-edge-contract.kql`](../kql/10-canonical-permission-edge-contract.kql). It writes authorization metadata and resource identifiers only. It does not collect prompts, responses, reasoning, tool arguments/results, or document content.

 Files

| File | Purpose |
| --- | --- |
| [`AgentPermissionEdgeCollector.ps1`](./AgentPermissionEdgeCollector.ps1) | PowerShell 7.2 Azure Automation runbook. |
| [`Deploy-AgentPermissionEdgeCollector.ps1`](./Deploy-AgentPermissionEdgeCollector.ps1) | Idempotent post-infrastructure configuration for Graph app roles, Automation variables/modules, runbook publication, and the daily schedule. |
| [`Test-AgentPermissionEdgeCollector.ps1`](./Test-AgentPermissionEdgeCollector.ps1) | Local synthetic tests. All HTTP/Azure behavior in the tests is in-memory; no Azure write is possible. |
| [`collector.config.example.json`](./collector.config.example.json) | Non-secret deployment and dry-run configuration template. |

 Collected evidence

The runbook collects and normalizes:

- Agent Identity Blueprints, blueprint principals, Agent Identities, and Agent Users.
- Owner, sponsor, parent blueprint, agent-user, and transitive group relationships.
- Direct app-role assignments and delegated OAuth permission grants.
- Blueprint inheritable permissions and materialized inherited grants.
- Transitive group-derived app-role assignments.
- Active and eligible Microsoft Entra directory-role assignments.
- Current-subscription Azure RBAC assignments and role definitions through Azure Resource Graph.
- Permission and role changes from Microsoft Entra directory audit logs.
- Conditional Access application inclusions/exclusions.
- Disabled identity and expired/expiring credential controls.
- Conservative resource reachability derived from configured permissions:
  - explicit Azure RBAC scopes → `reachableDeterministic`;
  - tenant directory roles → `reachableBounded`;
  - broad Microsoft Graph permissions → `reachableInferred` resource categories.

Agent ID APIs and inherited-permission APIs use Microsoft Graph beta where that is the documented surface. All pageable Graph and Azure Resource Graph calls follow continuation links/tokens. Per-object permission calls use Microsoft Graph JSON batching, and Logs Ingestion requests are bounded by both record count and UTF-8 payload size.

The collector fails if an enabled source fails. It does not silently omit a source and report success.

 Runtime identity and permissions

The runbook authenticates only with:

powershell
Connect-AzAccount -Identity


It acquires managed-identity tokens for Microsoft Graph, Azure Resource Manager/Azure Resource Graph, and Azure Monitor Logs Ingestion. It has no client secret, certificate credential, storage key, or shared key.

The deployment script resolves and idempotently assigns these read-only Microsoft Graph application roles from the Microsoft Graph service principal:

- `Application.Read.All`
- `Directory.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`
- `Policy.Read.All`

The infrastructure deployment is responsible for the current-subscription `Reader` role and the DCR-scoped `Monitoring Metrics Publisher` role described in [`.azure/deployment-plan.md`](../../.azure/deployment-plan.md).

Tenant administrator consent is required for Graph application-role assignments. The operator running the deployment script must already be authenticated to the intended tenant and authorized to assign application roles and configure the Automation Account. The deployment script uses the operator's current Az context and never asks for or stores a credential.

 Configuration

Copy [`collector.config.example.json`](./collector.config.example.json) to a local ignored path and replace the placeholder IDs/endpoints with the infrastructure deployment outputs.

The post-infrastructure script creates these unencrypted Automation variables:

text
AgentPermissionEdge.TenantId
AgentPermissionEdge.SubscriptionId
AgentPermissionEdge.DceEndpoint
AgentPermissionEdge.DcrImmutableId
AgentPermissionEdge.StreamName
AgentPermissionEdge.AuditLookbackHours
AgentPermissionEdge.BatchMaxRecords
AgentPermissionEdge.BatchMaxBytes
AgentPermissionEdge.GraphMaxPages
AgentPermissionEdge.CredentialExpiryWarningDays
AgentPermissionEdge.EnableAuditLogs
AgentPermissionEdge.EnableConditionalAccess


The example creates or updates a named PowerShell 7.2 Runtime Environment and pins its `Az.Accounts` package. Review and deliberately update the package version in the copied configuration rather than resolving an unpinned latest version during deployment.

 Local validation and dry run

Run the synthetic tests:

powershell
pwsh -NoProfile -File .\access-graph\collector\Test-AgentPermissionEdgeCollector.ps1


The tests cover:

- stable SHA256 edge IDs;
- exact canonical table columns;
- Graph `@odata.nextLink` paging;
- Azure Resource Graph skip-token paging;
- app-role, delegated-scope, and blueprint-inheritance normalization;
- deterministic, bounded, and inferred resource-category reachability derivation;
- record-count ingestion batching;
- dry-run write suppression;
- secret-free example configuration.

To execute a real read-only collection without Logs Ingestion writes, use an authenticated environment that supports managed identity and run:

powershell
pwsh -NoProfile -File .\access-graph\collector\AgentPermissionEdgeCollector.ps1 `
  -ConfigPath .\path\to\collector.config.json `
  -DryRun


`-DryRun` suppresses Logs Ingestion only. It still authenticates with managed identity and reads the configured Graph and Azure sources so source failures remain visible.

 Post-infrastructure configuration

Do not run this step until the DCE, DCR, custom table, and Azure RBAC deployment has been validated.

Preview all changes:

powershell
pwsh -NoProfile -File .\access-graph\collector\Deploy-AgentPermissionEdgeCollector.ps1 `
  -ConfigPath .\path\to\collector.config.json `
  -WhatIf


Apply the configuration while keeping the schedule disabled:

powershell
pwsh -NoProfile -File .\access-graph\collector\Deploy-AgentPermissionEdgeCollector.ps1 `
  -ConfigPath .\path\to\collector.config.json


The script is idempotent:

- existing Graph assignments are retained;
- matching Automation variables/runtime packages are skipped;
- the PowerShell 7.2 Runtime Environment and runbook association are updated idempotently;
- the runbook is force-imported and published;
- the named schedule is created or updated;
- duplicate runbook/schedule associations are not created.

The schedule is disabled by default, matching the approved manual-first-run gate. After a successful manual collection and table/workbook verification, rerun with:

powershell
pwsh -NoProfile -File .\access-graph\collector\Deploy-AgentPermissionEdgeCollector.ps1 `
  -ConfigPath .\path\to\collector.config.json `
  -EnableSchedule


The default schedule is daily at 02:00 UTC.

 Operational behavior

- A stable edge ID is SHA256 over normalized source system, source object, relation, subject, target, permission ID, and permission value.
- Logs Ingestion is append-only. Workbook queries select the latest snapshot per stable `EdgeId` with `summarize arg_max(TimeGenerated, *) by EdgeId`, preventing daily collections from inflating permission/path counts.
- `EdgeClass` is preserved. Audit events are `observed`; configured grants remain `configured`; controls remain `control`.
- Group-derived and blueprint-inherited paths remain distinguishable through `GrantOrigin`.
- Broad application and delegated permissions are mapped only to `reachableInferred` resource categories. They are never expanded into exact sites, files, mailboxes, directory objects, or sensitivity labels.
- Exact Azure RBAC assignment scopes can produce `reachableDeterministic` edges. Directory roles produce tenant-bounded `reachableBounded` edges.
- Derived reachability keeps `ResourceClassification = Unknown` until a governed resource inventory or classification collector supplies authoritative evidence.
- `Sites.Selected` or another broad/resource-specific consent is recorded as configured permission only; this collector does not enumerate SharePoint/OneDrive ACLs.
- Partial source failures terminate the run. Automation job output includes final record, batch, edge-class, and source counts only after a complete collection.
