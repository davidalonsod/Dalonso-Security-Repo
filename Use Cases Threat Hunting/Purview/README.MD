# Purview / IRM / eDiscovery gap-filler pack for Microsoft Sentinel (v2.2)

ARM template that deploys **14 scheduled analytic rules** targeting detection gaps **not** covered by native Microsoft Purview DLP, IRM Adaptive Protection, MDA built-in policies, Activity Explorer, Compliance dashboards, or Sentinel UEBA / Fusion.

## What is new in v2.2

- **Per-rule enable parameters.** Every rule has a boolean `enableXxx` parameter (default `true`). Set to `false` to deploy the rule resource in a disabled state - the rule is created idempotently but does NOT execute, so it produces zero query cost while remaining ready to flip back on.
- **Ingestion-cost guidance** (see "Cost optimisation" below). Cuts noisy data volume *before* it hits the workspace, which is where the bill comes from.
- Output `enabledRuleCount` reports how many rules are active after deployment.

## Per-rule enable / disable

| Parameter | Rule | Default |
| --- | --- | --- |
| `enableLabelDowngrade` | `AR-PURVIEW-LABEL-DOWNGRADE` | `true` |
| `enableDlpBulkMatches` | `AR-PURVIEW-DLP-BULK-MATCHES` | `true` |
| `enableOverrideUsed` | `AR-PURVIEW-OVERRIDE-USED` | `true` |
| `enableLabelRemoved` | `AR-PURVIEW-LABEL-REMOVED` | `true` |
| `enableAuditTampering` | `AR-AUDIT-EDISCOVERY-TAMPERING` | `true` |
| `enableAdminConfigDrift` | `AR-PURVIEW-ADMIN-CONFIG-DRIFT` | `true` |
| `enableIngestionStall` | `AR-PURVIEW-INGESTION-STALL` | `true` |
| `enableLabelMassMod` | `AR-PURVIEW-LABEL-MASS-MODIFICATION` | `true` |
| `enableRmsFailures` | `AR-RMS-DECRYPTION-FAILURES` | `true` |
| `enableEdiscoveryExport` | `AR-EDISCOVERY-EXPORT-ABUSE` | `true` |
| `enableEdiscoveryRoleEsc` | `AR-EDISCOVERY-ROLE-ESCALATION` | `true` |
| `enableDlpUnfamiliarLoc` | `AR-PURVIEW-DLP-UNFAMILIAR-LOCATION` | `true` |
| `enableDiagDisabled` | `AR-DIAGNOSTICS-DISABLED` | `true` |
| `enableSpoAnonLink` | `AR-SPO-ANONLINK-BURST` | `true` |

Toggle in `azuredeploy.parameters.json` or pass on the command line:

```powershell
az deployment group create `
    --resource-group <rg> `
    --template-file .\azuredeploy.json `
    --parameters .\azuredeploy.parameters.json `
    --parameters enableDlpUnfamiliarLoc=false enableSpoAnonLink=false
```

Re-deploys are idempotent - flipping a rule from `true` to `false` updates the existing rule's `enabled` flag and stops it executing without recreating it.

## Cost optimisation - reduce data ingestion

Sentinel cost is driven mostly by **what you ingest**, not what you query. Reduce the volume per source first, then tune query behaviour second.

### 1. Drop noise at the workspace boundary (Data Collection Rule transformations)

For every connector below, attach a workspace-level DCR transformation that drops or trims rows you do not need. Transformations apply *before* billing.

| Table | Typical noise to drop | Reference KQL filter (in transform) |
| --- | --- | --- |
| `MicrosoftPurviewInformationProtection` | Read-only label-evaluation events without state change | `source \| where LabelEventType != "LabelEvaluated" or isnotempty(OldSensitivityLabelId)` |
| `SigninLogs` | Successful logins from compliant + managed devices (keep failures + risky) | Use `Risk` filters, keep `ResultType != 0 or RiskLevelDuringSignIn != "none" or DeviceDetail.isCompliant == false` |
| `AuditLogs` | Routine self-service password resets, low-risk service principal sign-ins | Filter `Category` to `RoleManagement`, `UserManagement`, `ApplicationManagement`, `Policy`. |
|| `EmailEvents` (XDR) | Already routed via XDR connector - filter on `DeliveryAction != "Delivered"` if cost is the concern (loses benign-mail context). |

Apply via Azure portal → Log Analytics workspace → Tables → `<table>` → Edit transformation, or via DCR ARM in code.

### 2. Use the right log tier per table

| Tier | Use for | Caveats |
| --- | --- | --- |
| **Analytics** (default) | All 14 rules in this pack - they need real-time alerting | Standard ingestion price. |
| **Basic** | Tables you only need for ad-hoc hunt + investigation, not for analytic rules (e.g. some forwarded firewall / proxy logs) | No analytic rules, no UEBA, 8-day retention then archive, KQL subset only. |
| **Auxiliary** (preview) | Very high-volume telemetry where you only ever search by IP / time | Cheaper than Basic. Same KQL caveats. |

The 14 rules in this template all need **Analytics** tier on `MicrosoftPurviewInformationProtection`, `OfficeActivity`, `SigninLogs`, `AuditLogs`, `AzureActivity`. Do not move those tables to Basic or you will lose the rules.

### 3. Drop rules you do not need

Use the `enableXxx` parameters above. Common reduction patterns:

| Scenario | Recommended toggles | Rationale |
| --- | --- | --- |
| You already have full Purview + IRM E5 with Adaptive Protection rolled out tenant-wide | `enableLabelDowngrade=false`, `enableLabelRemoved=false` | IRM indicators cover the same ground when policy scope = everyone. |
| You do not use eDiscovery Premium | `enableEdiscoveryExport=false`, `enableEdiscoveryRoleEsc=false` | Removes two `OfficeActivity` rules that add no value for you. |
| `SigninLogs` retention < 30d | `enableDlpUnfamiliarLoc=false` | The rule's `queryPeriod` is `P30D`; without 30d data it underperforms. |
| Tenant has < 1 Purview event / hour baseline | `enableIngestionStall=false` | Health check needs baseline activity to be meaningful. |
| You have a third-party CSPM that already alerts on diagnostic-setting deletes | `enableDiagDisabled=false` | Avoid duplicate alerts. |

### 4. Tune thresholds upwards

Higher thresholds = fewer alerts = fewer Logic-App / Defender-XDR sync calls = lower automation cost. The template exposes:

- `bulkDlpUniqueFilesThreshold`, `bulkDlpHitsThreshold`
- `labelMassModUniqueItems`
- `rmsDenialThreshold`
- `eDiscoveryExportSizeMB`
- `anonLinkBurstThreshold`
- `ingestionStallHours`

Raise them after a 7-day observation period.

### 5. Most expensive rule in the pack

`AR-PURVIEW-DLP-UNFAMILIAR-LOCATION` queries 30 days of `SigninLogs` per execution (`queryPeriod=P30D`). On large tenants this is the dominant query cost. Options:

- Reduce `queryPeriod` to `P7D` (edit the rule post-deploy) - lower fidelity but ~4x cheaper.
- Replace the per-user country lookup with a **Sentinel Watchlist** of "approved countries per BU" maintained out-of-band.
- Disable the rule via `enableDlpUnfamiliarLoc=false` if `BehaviorAnalytics` already covers anomalous-country logins for you.

### 6. Compress hot tables with Summary Rules

`MicrosoftPurviewInformationProtection` is a good candidate for **Summary Rules** (Sentinel feature) if you keep them at full retention only for compliance: roll up hourly aggregates into a smaller summary table, then move the source table to Basic / Archive. None of the rules in this pack need that, but it is the pattern for shaving 70-90 % off long-retention cost.

### 7. Quick cost telemetry

```kql
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| where DataType in ("MicrosoftPurviewInformationProtection","OfficeActivity","SigninLogs","AuditLogs","AzureActivity")
| summarize GBPerDay = sum(Quantity)/1024 by bin(TimeGenerated, 1d), DataType
| render timechart
```

Run this before tuning, then again 7 days after. Pick the top-3 tables and optimise those first.

## Resources deployed (14 scheduled analytic rules, 0 hunting queries)

### Purview / DLP / Label
| Rule | Severity | Tactics | Source |
| --- | --- | --- | --- |
| `AR-PURVIEW-LABEL-DOWNGRADE` | Medium | Exfiltration / DefenseEvasion | `MicrosoftPurviewInformationProtection` |
| `AR-PURVIEW-LABEL-REMOVED` | Medium | DefenseEvasion | `MicrosoftPurviewInformationProtection` |
| `AR-PURVIEW-LABEL-MASS-MODIFICATION` | High | DefenseEvasion / Exfiltration | `MicrosoftPurviewInformationProtection` |
| `AR-PURVIEW-DLP-BULK-MATCHES` | High | Exfiltration | `MicrosoftPurviewInformationProtection` |
| `AR-PURVIEW-OVERRIDE-USED` | Medium | DefenseEvasion | `MicrosoftPurviewInformationProtection` |
| `AR-PURVIEW-DLP-UNFAMILIAR-LOCATION` | High | Exfiltration / InitialAccess | `MicrosoftPurviewInformationProtection` + `SigninLogs` |
| `AR-RMS-DECRYPTION-FAILURES` | High | CredentialAccess / Discovery | `MicrosoftPurviewInformationProtection` |

### eDiscovery / Audit / Admin abuse
| Rule | Severity | Tactics | Source |
| --- | --- | --- | --- |
| `AR-AUDIT-EDISCOVERY-TAMPERING` | High | DefenseEvasion / Impact | `OfficeActivity` |
| `AR-PURVIEW-ADMIN-CONFIG-DRIFT` | High | DefenseEvasion / PrivilegeEscalation | `OfficeActivity` |
| `AR-EDISCOVERY-EXPORT-ABUSE` | High | Exfiltration / Collection | `OfficeActivity` |
| `AR-EDISCOVERY-ROLE-ESCALATION` | High | PrivilegeEscalation / Persistence | `OfficeActivity` + `AuditLogs` |

### Platform integrity / scanner pattern
| Rule | Severity | Tactics | Source |
| --- | --- | --- | --- |
| `AR-DIAGNOSTICS-DISABLED` | High | DefenseEvasion / ImpairProcessControl | `AzureActivity` |
| `AR-PURVIEW-INGESTION-STALL` | Medium | ImpairProcessControl / DefenseEvasion | `MicrosoftPurviewInformationProtection` |
| `AR-SPO-ANONLINK-BURST` | High | Exfiltration / Collection | `OfficeActivity` |

## Threshold parameters

| Name | Default | Notes |
| --- | --- | --- |
| `bulkDlpUniqueFilesThreshold` | `10` | Min distinct files / hour for `AR-PURVIEW-DLP-BULK-MATCHES`. |
| `bulkDlpHitsThreshold` | `25` | Min DLP hits / hour for `AR-PURVIEW-DLP-BULK-MATCHES`. |
| `ingestionStallHours` | `6` | Stall window for `AR-PURVIEW-INGESTION-STALL`. |
| `labelMassModUniqueItems` | `25` | Min distinct items / hour for `AR-PURVIEW-LABEL-MASS-MODIFICATION`. |
| `rmsDenialThreshold` | `10` | Min RMS denials / hour for `AR-RMS-DECRYPTION-FAILURES`. |
| `eDiscoveryExportSizeMB` | `500` | Min export size (MB) for `AR-EDISCOVERY-EXPORT-ABUSE`. |
| `anonLinkBurstThreshold` | `20` | Min share-link creations / hour for `AR-SPO-ANONLINK-BURST`. |

## Prerequisites

- Sentinel enabled on the target Log Analytics workspace.
- **Microsoft Purview Information Protection** Sentinel connector connected.
- **Office 365** Sentinel connector enabled (`OfficeActivity`).
- **Microsoft Entra ID** Sentinel connector enabled (`SigninLogs`, `AuditLogs`).
- **Azure Activity** Sentinel connector enabled (`AzureActivity`).
- **Unified Audit Logging** enabled in Microsoft 365.
- Deploying identity needs **Microsoft Sentinel Contributor** on the workspace.

## Deploy

```powershell
cd C:\Users\USER\Purview
.\deploy.ps1 -SubscriptionId <sub> -ResourceGroup <rg>           # apply
.\deploy.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WhatIf   # preview
```

```powershell
az deployment group create `
    --resource-group <rg> `
    --template-file .\azuredeploy.json `
    --parameters .\azuredeploy.parameters.json
```

## Validate after deploy

```kql
SecurityAlert
| where TimeGenerated > ago(1d)
| where AlertName has_any (
    "Purview - ", "Audit / eDiscovery tampering", "Purview admin abuse",
    "eDiscovery - ", "Azure diagnostic settings", "SharePoint / OneDrive"
)
| project TimeGenerated, AlertName, AlertSeverity, Tactics
| order by TimeGenerated desc
```

```kql
// Confirm enable flags applied
SecurityInsightsAnalytics // or via Az.SecurityInsights cmdlet
| project DisplayName, Enabled, Severity, LastModifiedTime
| order by Enabled asc, DisplayName asc
```

## Notes

- Resource names are deterministic GUIDs from `workspaceName + rule key`; re-running updates rules in place.
- `xdr/` folder hosts cross-portal queries that must run in the unified Defender + Sentinel portal (not deployed by this template).
