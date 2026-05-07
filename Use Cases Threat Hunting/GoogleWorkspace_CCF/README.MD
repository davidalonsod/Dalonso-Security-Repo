# GWSAlerts_CL — Detections Pack

Detection content for the `GWSAlerts_CL` table populated by the
**Google Workspace Alert Center** CCF connector in this folder.

Sources used:
- [Google Workspace Alert types](https://developers.google.com/workspace/admin/alertcenter/reference/alert-types)
-  — OAuth/IAM persistence, programmatic login abuse, admin-pivot patterns
- MITRE ATT&CK Cloud (SaaS) matrix

## Analytic rules (`AnalyticRules/`)

| Rule | Severity | Trigger | Tactics |
|---|---|---|---|
| `GWSAlerts_StateSponsoredAttack.yaml` | High | Government attack warning | Initial Access, Credential Access |
| `GWSAlerts_DomainWideTakeout.yaml` | High | Customer takeout initiated | Exfiltration |
| `GWSAlerts_DriveRansomware.yaml` | High | Drive Counter-Abuse ransomware signal | Impact |
| `GWSAlerts_SensitiveAdminSSOChange.yaml` | High | SSO profile / super-admin / primary-admin change | Persistence, Priv Esc, Defense Evasion |
| `GWSAlerts_AdminPrivilegeGrant.yaml` | Medium | User granted admin / suspended user reactivated | Persistence, Priv Esc |
| `GWSAlerts_DLPHighSeverity.yaml` | High | DLP rule violation at HIGH severity | Exfiltration, Collection |
| `GWSAlerts_LeakedPasswordChain.yaml` | High | Leaked password → suspicious login (24h chain) | Initial Access, Credential Access |
| `GWSAlerts_BadWhitelist.yaml` | Medium | Misconfigured Gmail allowlist | Defense Evasion, Initial Access |
| `GWSAlerts_DeviceCompromised.yaml` | High | MDM device compromised | Initial Access, Persistence |
| `GWSAlerts_PhishingSpike.yaml` | Medium | ≥5 distinct users with phishing alerts in 1h | Initial Access |

## Hunting queries (`HuntingQueries/`)

| Query | Purpose |
|---|---|
| `GWSAlerts_Overview.yaml` | Volume / type baseline over 30d |
| `GWSAlerts_SuspiciousProgrammaticLogin.yaml` | OAuth / token abuse hunt (GCP-Pentest-Checklist) |
| `GWSAlerts_StaleAlerts.yaml` | Triage hygiene — unresolved alerts > 7d |
| `GWSAlerts_AdminPersistenceCluster.yaml` | Multiple admin-persistence alert types per actor in 24h |
| `GWSAlerts_DLPTopOffenders.yaml` | DLP top offenders & sensitive file hotspots |
| `GWSAlerts_PhishingDetectionGap.yaml` | User-reported phishing vs Google reclassification gap |
| `GWSAlerts_FirstSeenPerUser.yaml` | New (User, AlertType) pairs vs 60d baseline |
| `GWSAlerts_AccountWarningToExfilChain.yaml` | AccountWarning → DLP/Drive/Takeout chain |
| `GWSAlerts_AppSettingsChanged.yaml` | Risky setting flips (sharing, forwarding, MDM) |
| `GWSAlerts_CrossIdentityEntraCorrelation.yaml` | GWS alert + Entra anomalous sign-in for same UPN |

## Field assumptions

All queries assume the columns produced by `GoogleWorkspace_DCR.json`:

```
TimeGenerated, AlertId, CustomerId, AlertType, Source,
CreateTime, StartTime, EndTime, Deleted,
SecurityInvestigationToolLink, Etag, UpdateTime,
MetadataAlertId, MetadataCustomerId, MetadataStatus, MetadataAssignee,
MetadataUpdateTime, MetadataSeverity, MetadataEtag,
AlertDataType, AlertData (dynamic)
```

If you change the DCR transform, update the dynamic `AlertData.*` paths in
each query accordingly.

## Deployment

Each YAML follows the [Microsoft Sentinel detection schema](https://learn.microsoft.com/azure/sentinel/detect-threats-custom)
and can be deployed via:

- **Sentinel UI** → Analytics → Import (paste KQL from `query:`)
- **API / azd / Bicep** → wrap in an `analyticRules` ARM resource of kind
  `Scheduled` (analytic rules) or `huntingQueries` (saved searches)
- **Solution package** → drop into a Sentinel Solution alongside the connector
  and submit to the Content Hub

## Tuning notes

- The `AlertData` schema differs per `AlertDataType`. Queries use
  `coalesce(...)` and `tostring(AlertData.x)` defensively. Validate with the
  `GWSAlerts_Overview` hunt before turning on incident creation everywhere.
- Some alert types only exist on tenants with the relevant licence
  (e.g., DLP requires Workspace Enterprise, State-Sponsored requires Enterprise+).
- For `GWSAlerts_LeakedPasswordChain` and `GWSAlerts_PhishingSpike`, expect
  noise during password-rotation campaigns or red-team exercises — consider
  excluding test accounts.
