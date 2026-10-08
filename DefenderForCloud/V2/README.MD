 CIEM Gap Coverage and Workbook Changes

Workbook: `Defender-CIEM-RiskLeastPrivilege-Workbook.json`  
Source of truth: `Build-CIEMWorkbook.ps1`  
Review date: 2026-10-08  
Language: English

 Executive decision

The workbook can provide strong native coverage for Azure RBAC inventory, custom roles,
identity risk, excessive permissions, logged role changes, and Key Vault investigation while
reusing the native Microsoft Sentinel Key Vault detections.
Several controls are necessarily partial because Azure Resource Graph does not expose the
complete Microsoft Entra directory, credential metadata, provider access keys, group-expanded
net-effective permissions, or authoritative PIM schedule state.

The implementation deliberately distinguishes observed evidence from inference. It does
not label a principal as orphaned, a credential as unused, or a built-in role as deprecated
without the authoritative directory, credential, or versioned-role data required to prove it.

 Coverage matrix

|  | Requested capability | Coverage after this change | Evidence in the workbook | Remaining dependency |
|---:|---|---|---|---|
| 1 | Non-human identity discovery | Partial | Defender CIEM findings, Azure RBAC service principals, user-assigned identities, and system-assigned identities attached to Azure resources | Microsoft Graph plus AWS/GCP identity APIs for identities with no Azure evidence |
| 2 | Complete inventory by roles, permissions, and assignments | Covered for Azure RBAC | Assignment export and role-definition permission blocks, including actions, data actions, exclusions, scopes, conditions, and published timestamps | AWS/GCP provider exports |
| 3 | Visibility of secrets, certificates, and access keys | Partial | Key Vault secret/key/certificate access events and source readiness | Microsoft Graph credential inventory, Key Vault object metadata collection, AWS access-key and GCP service-account-key inventories |
| 4 | Complete custom-role inventory | Covered for Azure RBAC | Dedicated custom-role inventory with permission blocks and assignable scopes | AWS/GCP custom roles |
| 5 | Current permissions for every resource | Partial | Direct/inherited role-derived permission lineage for selected Azure resources | Management-group inheritance, group expansion, deny assignments, ABAC evaluation, and service-specific data-plane authorization |
| 6 | Unusual access to secrets and keys | Covered through existing Sentinel detections | Displays native Key Vault solution alerts/incidents and adds failure, dependency, rotation-impact, client/API, and posture context | Enable and tune the native Sentinel analytic templates |
| 7 | Inherited role and permission changes | Covered for logged Azure changes | Role assignment, PIM schedule/policy, and role-definition write/delete events | Diagnostic routing and sufficient retention |
| 8 | Deprecated and new roles | Partial | New/modified/deleted role-definition events and current metadata | Versioned Microsoft built-in-role baseline for authoritative deprecation state |
| 9 | Disabled identity control | Partial | Disabled identities known to Sentinel `IdentityInfo` | Authoritative Microsoft Graph export joined to all assignments |
| 10 | Automatic identity risk calculation | Covered | Existing transparent CIEM Risk Score (0-100) | Organization-specific calibration if desired |
| 11 | Excessive permissions | Covered where evidence exists | Defender overprovisioned findings, unused counts/actions, and rightsizing queue | AWS/GCP provider-native action detail where Defender does not publish it |
| 12 | Elevated or persistent privileges | Partial | Current active privileged RBAC plus direct-grant/PIM change history | ARM PIM schedule-instance collection for authoritative active-versus-eligible state |
| 13 | Excessive and orphaned permissions | Partial | Excessive permissions covered | Graph/provider directory resolution before declaring an assignment orphaned |
| 14 | Unused static credentials | Partial; closable with inventory ingestion | `AADServicePrincipalSignInLogs` exposes credential key ID, thumbprint, client credential type, federated credential ID, and observed use | Ingest credential inventory from Microsoft Graph and provider key inventories/last-used timestamps |
| 15 | Privileged identities linked to exposed resources | Partial | Azure principal IDs holding known privileged built-in roles are correlated with internet-exposure attack paths when Defender graph IDs resolve | Custom privileged-role classification and Cloud Security Explorer/provider graph validation for unresolved entity types |

 Implemented workbook changes

 New tabs

1. Credentials & Directory
   - Telemetry-readiness status for Key Vault, service-principal sign-ins, and Sentinel identity data.
   - Normalized Key Vault activity from `AZKVAuditLogs` and legacy `AzureDiagnostics`.
   - Existing Sentinel Key Vault alerts and incidents from `SecurityAlert` and
     `SecurityIncident`; native analytic logic is not copied.
   - Identity-to-object dependency mapping for secrets, keys, and certificates.
   - Rotation-impact analysis showing last-observed consumers.
   - Access failure, policy/network denial, correlation-ID, client, API-version, and latency context.
   - Azure Policy evaluation outcomes and detailed checks from
     `AZKVPolicyEvaluationDetailsLogs`.
   - Exportable Key Vault availability, API-hit, API-result, and API-latency metrics from
     `AzureMetrics`.
   - Azure Key Vault network, RBAC, soft-delete, purge-protection, and private-endpoint posture.
   - Service-principal sign-in activity from `AADServicePrincipalSignInLogs`.
   - Disabled identities known to Sentinel from `IdentityInfo`.

The gap matrix remains in this document only. It is intentionally not included as a workbook
tab so the operational workbook stays reusable and focused on live evidence.

 Enhanced tabs

- Privilege
  - Added a complete Azure RBAC assignment inventory.
  - Added a complete role-definition permission inventory.
  - Added a dedicated custom-role inventory.
  - Preserved actions, data actions, exclusions, assignable scopes, conditions, and timestamps
    when Azure publishes them.

- PIM Changes
  - Extended Azure Activity monitoring to role-definition writes and deletes.
  - Added role-definition change counts.
  - Added a detailed new/modified/deleted role-definition view with actor, IP, target, permission
    payload, assignable-scope payload, and correlation ID when present.

- Non-Human
  - Added service-principal discovery through Azure RBAC assignments.
  - Added managed-identity discovery from user-assigned identity resources and attached
    system-assigned identities.
  - Added explicit language explaining why this is not a complete Entra/AWS/GCP directory.

- Resource Access
  - Added role-derived permission lineage for selected Azure resources.
  - Labels each assignment as direct or inherited.
  - Shows role actions, data actions, exclusions, conditions, and assignment scope.
  - Explicitly labels the result as non-authoritative for net-effective access.

- Attack Paths
  - Added correlation of internet-exposure attack paths with Azure principal IDs holding known
    privileged built-in roles and present in Defender graph entities.
  - Preserves path, role, scope, entry point, target, and attack-path identifiers.

 Shared model changes

- Azure RBAC normalization now carries assignment ID, condition, condition version, and
  created/updated timestamps when available.
- The navigation, header, and README now describe 12 operational tabs and the additional data sources.
- The Gap Coverage tab was removed; this document remains the authoritative gap matrix and
  implementation history.
- The workspace picker no longer preselects or references a tenant-specific workspace. Every
  Log Analytics query is bound to the user-selected `{Workspace}` parameter.
- The generated workbook now contains 99 query tiles: 69 Azure Resource Graph and 30 Log
  Analytics.

 Closing partial gaps with custom ingestion

 Recommended architecture

Use two complementary collection modes:

1. Native event streams for access and changes:
   - Azure Activity, Microsoft Entra audit/sign-in logs, Key Vault audit logs, Sentinel alerts,
     AWS CloudTrail, and GCP Audit Logs.
2. Periodic authoritative snapshots for current state:
   - Microsoft Graph directory/application inventory.
   - Azure RBAC/PIM schedule APIs.
   - Key Vault secret/key/certificate metadata APIs.
   - AWS IAM and GCP IAM/Cloud Asset inventories.

A managed-identity Azure Function or Automation runbook should normalize records and send them
through a Data Collection Rule and the Azure Monitor Logs Ingestion API. The DCR determines the
destination workspace; the workbook continues to read only from the workspace selected in its
Workspace (logs / history) filter.

Never ingest secret values, private keys, access-key secrets, certificate private material, or
password credential values.

 Recommended custom tables

| Table | Purpose | Minimum keys |
|---|---|---|
| `CIEM_IdentityInventory_CL` | Users, groups, applications, service principals, managed identities, AWS/GCP identities, enabled/deleted state, and ownership | `SnapshotTime`, `Provider`, `TenantOrAccountId`, `IdentityId`, `IdentityType`, `AccountEnabled`, `DeletedDateTime`, `OwnerIds` |
| `CIEM_CredentialInventory_CL` | Password, certificate, federated, AWS access-key, GCP service-account-key, and Key Vault object metadata without values | `SnapshotTime`, `Provider`, `IdentityId`, `CredentialId`, `CredentialType`, `CreatedTime`, `StartTime`, `ExpiryTime`, `Enabled`, `LastUsedTime` |
| `CIEM_EntitlementSnapshot_CL` | Provider-normalized assignments, role definitions, actions, data actions, conditions, exclusions, and scope | `SnapshotTime`, `Provider`, `IdentityId`, `RoleId`, `RoleName`, `ScopeId`, `AssignmentState`, `Actions`, `DataActions`, `Condition` |
| `CIEM_PrivilegeSchedule_CL` | Azure resource and Entra active/eligible PIM schedules and permanence | `SnapshotTime`, `IdentityId`, `RoleId`, `ScopeId`, `ScheduleType`, `StartTime`, `EndTime`, `MemberType`, `AssignmentType` |
| `CIEM_RoleCatalog_CL` | Versioned built-in/custom role catalog for new, changed, removed, and deprecated-role comparison | `SnapshotTime`, `Provider`, `RoleId`, `RoleName`, `RoleType`, `PermissionsHash`, `AssignableScopes`, `LifecycleState` |
| `CIEM_ExposureEdge_CL` | Normalized identity-to-resource and exposed-entry-to-critical-target relationships | `SnapshotTime`, `Provider`, `SourceEntityId`, `TargetEntityId`, `EdgeType`, `ExposureType`, `Criticality`, `AttackPathId` |
| `CIEM_CollectorHealth_CL` | Collector heartbeat and completeness evidence | `CollectionTime`, `Collector`, `Provider`, `RunId`, `Status`, `IsFullSnapshot`, `RecordCount`, `ErrorCode` |

 Capability closure assessment

| Gap | Ingested source | Collection mode | Expected result |
|---|---|---|---|
| Non-human identity discovery | Microsoft Graph applications/service principals, Azure managed identities, AWS IAM, GCP IAM | Daily snapshot plus directory change events | Near-complete provider inventory, including identities with no findings or assignments |
| Multi-cloud roles, permissions, assignments, and custom roles | AWS IAM/Access Analyzer and GCP Cloud Asset/IAM policies and role definitions | Daily snapshot plus audit events | Provider-normalized inventory comparable to Azure RBAC |
| Secrets, certificates, and access keys | Key Vault metadata-only list APIs, Graph `passwordCredentials`/`keyCredentials`, AWS access-key inventory, GCP service-account keys | Daily snapshot | Metadata, age, expiry, enabled state, owner, and rotation posture without sensitive values |
| Current permissions per resource | Entitlements, group membership, deny assignments, PIM schedules, conditions, provider policies | Snapshot plus change events | Strong calculated access view; still not an absolute runtime authorization decision for every service/ABAC context |
| New, changed, removed, and deprecated roles | Versioned provider role snapshots plus Microsoft/provider lifecycle baseline | Daily snapshot plus change events | Reliable drift and lifecycle detection when the baseline is maintained |
| Disabled identities | Graph `accountEnabled`/`deletedDateTime` and AWS/GCP identity status | Daily snapshot plus directory events | Authoritative disabled/deleted state joined to permissions |
| Elevated or persistent privilege | ARM `roleAssignmentScheduleInstances`, `roleEligibilityScheduleInstances`, Entra PIM, AWS/GCP privileged bindings | Frequent snapshot plus events | Active, eligible, permanent, expiring, and standing-privilege classification |
| Orphaned permissions | Entitlement snapshot left-joined to complete identity inventory | Daily snapshot with deletion grace period | High-confidence orphan candidates; retain a grace period for replication and soft deletion |
| Unused static credentials | Graph credential inventory joined by `ServicePrincipalCredentialKeyId`; AWS `GetAccessKeyLastUsed`; GCP key inventory plus audit evidence | Daily inventory plus continuous events | Credential-level last-observed use where providers expose a stable credential ID |
| Privileged identities linked to exposed resources | Exposure graph/attack paths plus complete identity, custom-role, and entitlement snapshots | Frequent snapshot | Strong identity-to-exposure correlation, including custom privileged roles and unresolved graph nodes |

 Why this is not always mathematically 100%

Custom ingestion can make most gaps operationally complete, but the workbook should continue to
label evidence honestly:

- Provider APIs are eventually consistent and can be throttled.
- A failed or partial snapshot must not be interpreted as an empty inventory.
- Some authorization decisions depend on runtime resource state, ABAC conditions, network
  location, workload token claims, or service-specific data-plane logic.
- "Unused" means not observed during the retained evidence window, not proof that a
  credential is unnecessary.
- Some providers do not expose stable per-credential IDs or last-used timestamps for every
  credential type.

 Required configuration

 Always available with Azure read access

- Azure Resource Graph:
  - `authorizationresources`
  - `resources`
  - `resourcecontainers`
  - Defender `securityresources` when Defender CIEM/CSPM data is enabled

 Optional Log Analytics configuration

1. Route Azure Activity Log Administrative events for RBAC/PIM/role-definition changes.
2. Route Microsoft Entra `AuditLogs` for PIM workflows.
3. Route Key Vault AuditEvent diagnostics:
   - Prefer resource-specific `AZKVAuditLogs`.
   - Legacy `AzureDiagnostics` remains supported by the workbook.
4. Route Key Vault AzurePolicyEvaluationDetails and AllMetrics for policy and
   reliability views. Saturation is not exportable through diagnostic settings.
5. Route Microsoft Entra service-principal sign-in logs to
   `AADServicePrincipalSignInLogs`.
6. Enable Microsoft Sentinel UEBA to populate `IdentityInfo` if disabled-identity visibility
   is required.

 Important interpretation rules

- The workbook never retrieves secret values.
- The workbook does not recreate the native Sentinel Key Vault analytics for sensitive
  operations, mass retrieval, or time-series anomalies. It displays their resulting alerts and
  incidents and adds investigation context.
- A service principal with no observed sign-in is not automatically an unused credential.
- A principal missing from `IdentityInfo` is not automatically orphaned.
- A role-definition change event does not by itself identify a deprecated Microsoft built-in role.
- Resource Access is role-derived evidence, not a complete authorization-engine result.
- Attack-path correlation depends on Defender graph entities publishing a principal ID that can
  be matched to Azure RBAC.

 Validation performed

- Regenerated the workbook from `Build-CIEMWorkbook.ps1` without PowerShell errors.
- Parsed the generated JSON successfully as `Notebook/1.0`.
- Confirmed 12 navigation tabs and 12 conditional groups.
- Confirmed 99 query tiles: 69 ARG and 30 Log Analytics.
- Confirmed no duplicate workbook item names.
- Confirmed no empty tab groups.
- Confirmed every ARG tile retains cross-subscription scoping.
- Confirmed all 15 requested capabilities remain documented in this file.
- Executed the Key Vault posture query successfully through the Azure Resource Graph REST API.
- Compiled all seven new Key Vault Log Analytics queries successfully against a selected test
  workspace; the workbook contains no workspace-specific query binding.
- Corrected the privileged/exposure correlation query so `authorizationresources` is referenced
  only once on the join's right side, complying with the Azure Resource Graph table-reference
  limit. Known privileged built-in role names are now resolved directly from their stable role
  definition GUIDs.
- Inlined the selected-resource pipeline in the Resource Access lineage query because Azure
  Resource Graph does not accept the tabular `let SelectedResources` binding used in the first
  implementation.
- Restructured the Resource Access lineage query to use role definitions as its left-side source,
  join `authorizationresources` once for assignments, and join `resources` once for selected
  resources. This complies with Azure Resource Graph's one-right-side-reference-per-table limit.

 Microsoft references

- Azure Resource Graph supported tables and resource types:  
  https://learn.microsoft.com/azure/governance/resource-graph/reference/supported-tables-resources
- Azure Resource Graph query language:  
  https://learn.microsoft.com/azure/governance/resource-graph/concepts/query-language
- Azure Key Vault monitoring data reference:  
  https://learn.microsoft.com/azure/key-vault/general/monitor-key-vault-reference
- Microsoft Sentinel Azure Key Vault solution content:  
  https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Azure%20Key%20Vault
- Microsoft Entra service-principal sign-in activity:  
  https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins
- Microsoft Graph application resource (`passwordCredentials` and `keyCredentials`):  
  https://learn.microsoft.com/graph/api/resources/application
- Azure RBAC custom roles:  
  https://learn.microsoft.com/azure/role-based-access-control/custom-roles
