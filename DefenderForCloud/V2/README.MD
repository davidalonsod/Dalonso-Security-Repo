 CIEM Gap Coverage and Change Record


 Executive summary

The workbook provides strong native coverage for:

- Azure RBAC assignments, role definitions, and custom roles
- Identity risk and excessive-permission prioritization
- Logged RBAC, PIM, and role-definition changes
- Key Vault security investigation using native Microsoft Sentinel detections
- Multi-cloud Defender CIEM findings and attack-path context

Some controls remain partial because Azure Resource Graph does not expose the complete
Microsoft Entra directory, credential metadata, provider access keys, group-expanded
net-effective permissions, or authoritative PIM schedule state.

The implementation deliberately separates observed evidence from inference. It does
not label a principal as orphaned, a credential as unused, or a built-in role as deprecated
unless the authoritative directory, credential, or versioned-role data required to prove that
condition is available.

 Coverage at a glance

| Status | Capabilities | Meaning |
|---|---:|---|
| 🟢 Covered | 6 | Implemented with the evidence currently available to the workbook |
| 🟡 Partial | 9 | Useful coverage exists, but an authoritative source or provider-specific API is still required |
| Total | 15 | Requested capabilities assessed |

 Contents

- [Coverage matrix](coverage-matrix)
- [Implemented workbook changes](implemented-workbook-changes)
- [Closing partial gaps](closing-partial-gaps)
- [Required configuration](required-configuration)
- [Interpretation guardrails](interpretation-guardrails)
- [Validation evidence](validation-evidence)
- [Microsoft references](microsoft-references)

---

 Coverage matrix

|  | Capability | Status | Evidence in the workbook | Remaining dependency |
|---:|---|---|---|---|
| 1 | Non-human identity discovery | 🟡 Partial | Defender CIEM findings, Azure RBAC service principals, user-assigned identities, and system-assigned identities attached to Azure resources | Microsoft Graph plus AWS/GCP identity APIs for identities with no Azure evidence |
| 2 | Complete inventory by roles, permissions, and assignments | 🟢 Azure RBAC | Assignment export and role-definition permission blocks, including actions, data actions, exclusions, scopes, conditions, and published timestamps | AWS/GCP provider exports |
| 3 | Visibility of secrets, certificates, and access keys | 🟡 Partial | Key Vault secret, key, and certificate access events plus source readiness | Microsoft Graph credential inventory, Key Vault object metadata collection, AWS access-key inventory, and GCP service-account-key inventory |
| 4 | Complete custom-role inventory | 🟢 Azure RBAC | Dedicated custom-role inventory with permission blocks and assignable scopes | AWS/GCP custom roles |
| 5 | Current permissions for every resource | 🟡 Partial | Direct and inherited role-derived permission lineage for selected Azure resources | Management-group inheritance, group expansion, deny assignments, ABAC evaluation, and service-specific data-plane authorization |
| 6 | Unusual access to secrets and keys | 🟢 Covered | Native Key Vault solution alerts/incidents plus failure, dependency, rotation-impact, client/API, and posture context | Enable and tune the native Sentinel analytic templates |
| 7 | Inherited role and permission changes | 🟢 Logged Azure changes | Role assignment, PIM schedule/policy, and role-definition write/delete events | Diagnostic routing and sufficient retention |
| 8 | Deprecated and new roles | 🟡 Partial | New, modified, and deleted role-definition events plus current metadata | Versioned Microsoft built-in-role baseline for authoritative deprecation state |
| 9 | Disabled identity control | 🟡 Partial | Disabled identities known to Sentinel through `IdentityInfo` | Authoritative Microsoft Graph export joined to all assignments |
| 10 | Automatic identity risk calculation | 🟢 Covered | Transparent CIEM Risk Score from 0–100 | Organization-specific calibration, if required |
| 11 | Excessive permissions | 🟢 Evidence-based | Defender overprovisioned findings, unused counts/actions, and rightsizing queue | AWS/GCP provider-native action detail where Defender does not publish it |
| 12 | Elevated or persistent privileges | 🟡 Partial | Current active privileged RBAC plus direct-grant and PIM change history | ARM PIM schedule-instance collection for authoritative active-versus-eligible state |
| 13 | Excessive and orphaned permissions | 🟡 Partial | Excessive permissions are covered | Graph/provider directory resolution before declaring an assignment orphaned |
| 14 | Unused static credentials | 🟡 Partial; closable | `AADServicePrincipalSignInLogs` exposes credential key ID, thumbprint, client credential type, federated credential ID, and observed use | Microsoft Graph credential inventory plus provider key inventories and last-used timestamps |
| 15 | Privileged identities linked to exposed resources | 🟡 Partial | Azure principal IDs holding known privileged built-in roles are correlated with internet-exposure attack paths when Defender graph IDs resolve | Custom privileged-role classification and Cloud Security Explorer/provider graph validation for unresolved entity types |

 Scope note: A capability marked as covered can still have a provider boundary. The
 evidence and dependency columns define that boundary explicitly.

---

 Implemented workbook changes

 New tab

 Credentials & Directory

The new tab adds:

- Telemetry readiness for Key Vault, service-principal sign-ins, and Sentinel identity data
- Normalized Key Vault activity from `AZKVAuditLogs` and legacy `AzureDiagnostics`
- Existing Sentinel Key Vault alerts and incidents from `SecurityAlert` and
  `SecurityIncident`; native analytic logic is not copied
- Identity-to-object dependency mapping for secrets, keys, and certificates
- Rotation-impact analysis showing last-observed consumers
- Access failure, policy/network denial, correlation ID, client, API version, and latency context
- Azure Policy outcomes and detailed checks from `AZKVPolicyEvaluationDetailsLogs`
- Exportable Key Vault availability, API-hit, API-result, and API-latency metrics from
  `AzureMetrics`
- Key Vault network, RBAC, soft-delete, purge-protection, and private-endpoint posture
- Service-principal activity from `AADServicePrincipalSignInLogs`
- Disabled identities known to Sentinel through `IdentityInfo`

The coverage matrix remains in this document rather than in the workbook so the operational
experience stays focused on live evidence.

 Enhanced tabs

| Tab | Changes |
|---|---|
| Privilege | Added complete Azure RBAC assignment, role-definition permission, and custom-role inventories. Preserves actions, data actions, exclusions, assignable scopes, conditions, and timestamps when Azure publishes them. |
| PIM Changes | Extended Azure Activity monitoring to role-definition writes/deletes. Added change counts and a detailed new/modified/deleted view with actor, IP, target, permission payload, assignable-scope payload, and correlation ID when available. |
| Non-Human | Added service-principal discovery through Azure RBAC and managed-identity discovery from user-assigned identity resources and attached system-assigned identities. Clearly identifies why this is not a complete Entra/AWS/GCP directory. |
| Resource Access | Added direct/inherited role-derived permission lineage for selected Azure resources, including actions, data actions, exclusions, conditions, and assignment scope. Results are explicitly labeled as non-authoritative for net-effective access. |
| Attack Paths | Correlates internet-exposure attack paths with Azure principal IDs holding known privileged built-in roles and present in Defender graph entities. Preserves path, role, scope, entry point, target, and attack-path identifiers. |

 Shared model changes

- Azure RBAC normalization now carries assignment ID, condition, condition version, and
  created/updated timestamps when available.
- Navigation, header, and README describe 12 operational tabs and the additional data sources.
- The former Gap Coverage tab was removed. This document is the authoritative gap matrix and
  implementation record.
- The workspace picker no longer preselects or references a tenant-specific workspace. Every
  Log Analytics query uses the user-selected `{Workspace}` parameter.
- The generated workbook contains 99 query tiles:
  - 69 Azure Resource Graph
  - 30 Log Analytics

---

 Closing partial gaps

 Recommended architecture

Use two complementary collection modes:

| Collection mode | Purpose | Examples |
|---|---|---|
| Native event streams | Record access and changes continuously | Azure Activity, Microsoft Entra audit/sign-in logs, Key Vault audit logs, Sentinel alerts, AWS CloudTrail, and GCP Audit Logs |
| Authoritative snapshots | Capture current identity, credential, entitlement, and lifecycle state | Microsoft Graph, Azure RBAC/PIM schedule APIs, Key Vault metadata APIs, AWS IAM, and GCP IAM/Cloud Asset inventories |

A managed-identity Azure Function or Automation runbook should normalize the records and send
them through a Data Collection Rule and the Azure Monitor Logs Ingestion API. The DCR controls
the destination workspace; the workbook continues to read only from the workspace selected in
the Workspace (logs / history) filter.

 [!CAUTION]
 Never ingest secret values, private keys, access-key secrets, certificate private material,
 or password credential values.

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

 Capability closure roadmap

| Gap | Authoritative source | Collection mode | Expected result |
|---|---|---|---|
| Non-human identity discovery | Microsoft Graph applications/service principals, Azure managed identities, AWS IAM, and GCP IAM | Daily snapshot plus directory change events | Near-complete provider inventory, including identities with no findings or assignments |
| Multi-cloud roles, permissions, assignments, and custom roles | AWS IAM/Access Analyzer and GCP Cloud Asset/IAM policies and role definitions | Daily snapshot plus audit events | Provider-normalized inventory comparable to Azure RBAC |
| Secrets, certificates, and access keys | Key Vault metadata-only APIs, Graph `passwordCredentials`/`keyCredentials`, AWS access-key inventory, and GCP service-account keys | Daily snapshot | Metadata, age, expiry, enabled state, owner, and rotation posture without sensitive values |
| Current permissions per resource | Entitlements, group membership, deny assignments, PIM schedules, conditions, and provider policies | Snapshot plus change events | Strong calculated-access view; not an absolute runtime authorization decision for every service or ABAC context |
| New, changed, removed, and deprecated roles | Versioned provider role snapshots plus Microsoft/provider lifecycle baseline | Daily snapshot plus change events | Reliable drift and lifecycle detection when the baseline is maintained |
| Disabled identities | Graph `accountEnabled`/`deletedDateTime` plus AWS/GCP identity status | Daily snapshot plus directory events | Authoritative disabled/deleted state joined to permissions |
| Elevated or persistent privilege | ARM `roleAssignmentScheduleInstances`, `roleEligibilityScheduleInstances`, Entra PIM, and AWS/GCP privileged bindings | Frequent snapshot plus events | Active, eligible, permanent, expiring, and standing-privilege classification |
| Orphaned permissions | Entitlement snapshot left-joined to complete identity inventory | Daily snapshot with deletion grace period | High-confidence orphan candidates while allowing for replication and soft deletion |
| Unused static credentials | Graph credential inventory joined by `ServicePrincipalCredentialKeyId`, AWS `GetAccessKeyLastUsed`, and GCP key inventory plus audit evidence | Daily inventory plus continuous events | Credential-level last-observed use where providers expose a stable credential ID |
| Privileged identities linked to exposed resources | Exposure graph/attack paths plus complete identity, custom-role, and entitlement snapshots | Frequent snapshot | Strong identity-to-exposure correlation, including custom privileged roles and unresolved graph nodes |

 Why coverage is not mathematically 100%

Even with custom ingestion, the workbook must continue to describe evidence accurately:

- Provider APIs are eventually consistent and can be throttled.
- A failed or partial snapshot must not be interpreted as an empty inventory.
- Some authorization decisions depend on runtime resource state, ABAC conditions, network
  location, workload token claims, or service-specific data-plane logic.
- Unused means not observed during the retained evidence window; it does not prove that a
  credential is unnecessary.
- Some providers do not expose stable per-credential IDs or last-used timestamps for every
  credential type.

---

 Required configuration

 Baseline Azure access

The following Azure Resource Graph sources are available with appropriate Azure read access:

- `authorizationresources`
- `resources`
- `resourcecontainers`
- Defender `securityresources` when Defender CIEM/CSPM is enabled

 Optional Log Analytics checklist

- [ ] Route Azure Activity Log Administrative events for RBAC, PIM, and role-definition changes.
- [ ] Route Microsoft Entra `AuditLogs` for PIM workflows.
- [ ] Route Key Vault AuditEvent diagnostics.
  - Prefer resource-specific `AZKVAuditLogs`.
  - Legacy `AzureDiagnostics` remains supported.
- [ ] Route Key Vault AzurePolicyEvaluationDetails and AllMetrics for policy and
      reliability views. Saturation is not exportable through diagnostic settings.
- [ ] Route Microsoft Entra service-principal sign-in logs to
      `AADServicePrincipalSignInLogs`.
- [ ] Enable Microsoft Sentinel UEBA to populate `IdentityInfo` when disabled-identity
      visibility is required.
- [ ] Select the correct Log Analytics workspace in the workbook's
      Workspace (logs / history) filter.

---

 Interpretation guardrails

| Rule | Reason |
|---|---|
| The workbook never retrieves secret values. | Security analysis requires metadata and events, not credential material. |
| Native Sentinel Key Vault detections are reused rather than copied. | The workbook displays their alerts/incidents and adds investigation context without duplicating analytic logic. |
| A service principal with no observed sign-in is not automatically an unused credential. | Identity activity is not credential-level inventory or proof of necessity. |
| A principal missing from `IdentityInfo` is not automatically orphaned. | `IdentityInfo` is not an authoritative directory export. |
| A role-definition change does not prove that a Microsoft built-in role is deprecated. | Authoritative deprecation requires a versioned lifecycle baseline. |
| Resource Access is role-derived evidence, not a complete authorization-engine result. | Group expansion, deny assignments, ABAC, management-group inheritance, and service data planes can change effective access. |
| Attack-path correlation depends on resolvable Defender graph principal IDs. | Unresolved graph entities cannot be safely attributed to Azure RBAC principals. |

---

  Microsoft references

- [Azure Resource Graph supported tables and resource types](https://learn.microsoft.com/azure/governance/resource-graph/reference/supported-tables-resources)
- [Azure Resource Graph query language](https://learn.microsoft.com/azure/governance/resource-graph/concepts/query-language)
- [Azure Key Vault monitoring data reference](https://learn.microsoft.com/azure/key-vault/general/monitor-key-vault-reference)
- [Microsoft Sentinel Azure Key Vault solution content](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Azure%20Key%20Vault)
- [Microsoft Entra service-principal sign-in activity](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins)
- [Microsoft Graph application resource](https://learn.microsoft.com/graph/api/resources/application)
- [Azure RBAC custom roles](https://learn.microsoft.com/azure/role-based-access-control/custom-roles)
