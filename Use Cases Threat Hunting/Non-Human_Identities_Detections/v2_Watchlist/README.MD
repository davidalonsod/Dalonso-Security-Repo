# Workload Identities — Custom Detections Package

Secure and monitor Compromised Service Principals Non-Human Identities (NHI) with Microsoft Sentinel https://youtu.be/LW-rTQUovHo

> **Workspace:** `xxxx`  
> **Created:** March 12, 2026  
> **Updated:** March 13, 2026  
> **Status:** Production-ready (ARM template validated — 17 analytic rules)

Custom analytic rules and hunting queries for Microsoft Sentinel focused exclusively on **Workload Identities** (Service Principals and Managed Identities). All rules are grounded in live table schemas, cross-correlated across multiple Log Analytics tables, and designed not to duplicate confirmed built-in detections.

---

## Folder Structure

```
WorkloadIdentitiesDetections/
├── README.md                              ← This file
├── ARM-Template/
│   └── WorkloadIdentities-Detections.json   ← Deploy all rules + hunting queries at once
├── AnalyticRules/
│   ├── RULE-01_SP-SignIn-Suspicious-Country.kql
│   ├── RULE-02_SP-BruteForce-Authentication.kql
│   ├── RULE-03_SP-Token-Replay-MultiIP.kql
│   ├── RULE-04_SP-CABypass-CloudAppEvents.kql
│   ├── RULE-05_MI-OutOfHours-Anomaly.kql
│   ├── RULE-06_MI-Lateral-Movement-Resource-Spread.kql
│   ├── RULE-07_SP-FirstTime-Critical-Resource.kql
│   ├── RULE-08_SP-Created-Used-HighRisk-Country.kql
│   ├── RULE-09_SP-Credentials-Added-No-Signin.kql
│   ├── RULE-10_SP-Mass-Privilege-Escalation.kql
│   ├── RULE-11_MI-KV-Storage-MgmtPlane-Correlation.kql
│   ├── RULE-12_SP-Signin-Volume-Anomaly.kql
│   ├── RULE-13_SP-Stale-Credential-Activation.kql
│   ├── RULE-14_SP-Risky-Auth-Flow.kql               ← KQL only (not in ARM — requires AuditLogs connector)
│   ├── RULE-15_SP-GraphAPI-Enumeration.kql
│   ├── RULE-16_SP-Self-Privilege-Escalation.kql
│   ├── RULE-17_SP-Sensitive-Permission-Grant.kql
│   ├── RULE-18_SP-Bulk-Creation-Burst.kql
│   ├── RULE-19_SP-IdentityProtection-Risk-Escalation.kql   ← KQL only (not in ARM — requires Entra ID P2 + Identity Protection for Workload Identities)
│   └── RULE-20_SP-RiskEvent-Stacking.kql                   ← KQL only (not in ARM — requires Entra ID P2 + Identity Protection for Workload Identities)
└── HuntingQueries/
    ├── HUNT-01_SP-Suspicious-IP-Country-Timeline.kql
    ├── HUNT-02_SP-BruteForce-History-30d.kql
    ├── HUNT-03_SP-CA-Bypass-History-30d.kql
    ├── HUNT-04_SP-CloudAppEvents-Correlation.kql
    ├── HUNT-05_MI-OutOfHours-Timeline-90d.kql
    ├── HUNT-06_SP-Critical-Resource-Access-90d.kql
    ├── HUNT-07_SP-Token-Abuse-7d.kql
    ├── HUNT-08_SP-FirstTime-Resource-30d.kql
    ├── HUNT-09_SP-Created-Never-Used-30d.kql
    ├── HUNT-10_SP-NotUsed-90d-Stale.kql
    ├── HUNT-11_SP-Dormant-Reactivation-History.kql
│   ├── HUNT-12_SP-RiskState-Trends-30d.kql
│   └── HUNT-13_SP-RiskEvents-Attribution-30d.kql
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Connected to `LAWSentinel` workspace |
| Data connectors | Azure Active Directory (Sign-in Logs, Audit Logs, Service Principal Sign-in Logs, Managed Identity Sign-in Logs), Microsoft Defender for Cloud Apps (CloudAppEvents), Azure Activity |
| Tables required (ARM rules) | `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs`, `AzureActivity`, `CloudAppEvents` |
| Tables required (HUNT-12/13 only) | `RiskyServicePrincipals`, `ServicePrincipalRiskEvents` — populated only when **Entra ID P2 + Identity Protection for Workload Identities** is licensed |
| ARM API version | `2023-02-01-preview` (alertRules), `2020-08-01` (savedSearches) |
| Permissions (deploy) | Microsoft Sentinel Contributor + Log Analytics Contributor |

---

## Deploying the ARM Template

### Azure Portal
1. Navigate to **Deploy a custom template** → `portal.azure.com/#create/Microsoft.Template`
2. Click **Build your own template in the editor**
3. Load `ARM-Template/WorkloadIdentities-Detections.json`
4. Set `workspaceName` = `LAWSentinel`
5. Deploy to the resource group hosting your Sentinel workspace

### Azure CLI
```bash
az deployment group create \
  --resource-group <YOUR-RESOURCE-GROUP> \
  --template-file "ARM-Template/WorkloadIdentities-Detections.json" \
  --parameters workspaceName=LAWSentinel
```

### PowerShell
```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<YOUR-RESOURCE-GROUP>" `
  -TemplateFile "ARM-Template\WorkloadIdentities-Detections.json" `
  -workspaceName "LAWSentinel"
```

### Deploy with all rules disabled (staged rollout)

Set `enableAnalyticRules=false` to deploy the watchlist, function, and all 22
analytic rules **in disabled state**. Re-enable individually in the portal as
you validate each rule against your environment.

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<YOUR-RESOURCE-GROUP>" `
  -TemplateFile "ARM-Template\WorkloadIdentities-Detections.json" `
  -workspaceName "LAWSentinel" `
  -enableAnalyticRules $false
```

| Parameter | Default | Notes |
|---|---|---|
| `workspaceName` | `LAWSentinel` | Sentinel/Log Analytics workspace |
| `enableAnalyticRules` | `true` | Set `false` to deploy rules disabled |
| `watchlistAlias` | `NetworkAllowlist` | Trusted-IP exclusion watchlist |
| `functionAlias` | `ExcludeAllowlistedIPs` | KQL function used by every rule |
| `watchlistRawContent` | (empty) | Optional CSV override for the seed watchlist content |

### Keeping `NetworkAllowlist` in sync with Entra Named Locations

See [`Watchlists/README.md`](Watchlists/README.md) for the automated sync stack
(PowerShell script + Azure Automation runbook + Bicep template). Pulls
`isTrusted=true` IP Named Locations from Microsoft Graph daily and rewrites
the `NetworkAllowlist` watchlist used by every rule and hunt in this repo.

---

## Analytic Rules (17 rules in ARM template + 3 KQL-only)

### RULE-01 — SP Sign-in from Suspicious Country
| Field | Value |
|---|---|
| **File** | `RULE-01_SP-SignIn-Suspicious-Country.kql` |
| **Severity** | High |
| **Tactics** | InitialAccess, CredentialAccess |
| **MITRE** | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Tables** | `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects Service Principal successful sign-ins from a curated list of high-risk countries. Builds a 30-day per-SP historical country baseline — new country triggers "Critical" vs. known country triggers "High". Includes geo enrichment via `geo_info_from_ip_address`. |
| **Key FP mitigations** | 30-day per-SP country baseline; Private IP range exclusions; Success-only events |

---

### RULE-02 — SP Brute Force Authentication
| Field | Value |
|---|---|
| **File** | `RULE-02_SP-BruteForce-Authentication.kql` |
| **Severity** | High |
| **Tactics** | CredentialAccess |
| **MITRE** | T1110.003, T1078.004 |
| **Tables** | `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects brute force or password spray against Service Principals: 20+ failures OR 5+ unique source IPs in 1 hour. Corroborates with successful sign-ins in the same window to flag when spray succeeded. |
| **Key FP mitigations** | MFA prompts and session expiry error codes excluded (50076, 50079, 50058, 70044); Threshold of 20+ failures minimum |

---

### RULE-03 — SP Token Replay (Multiple IPs/Countries)
| Field | Value |
|---|---|
| **File** | `RULE-03_SP-Token-Replay-MultiIP.kql` |
| **Severity** | High |
| **Tactics** | CredentialAccess, LateralMovement |
| **MITRE** | T1528 (Steal Application Access Token), T1550.001 |
| **Tables** | `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects the same token (`UniqueTokenIdentifier`) used from 3+ IPs or 2+ countries within 60 minutes — a strong indicator of token theft and replay. Legitimate SPs use a single token from one source location. |
| **Key FP mitigations** | Private IP range exclusions; 60-minute time boundary; Minimum 3 IPs or 2 countries threshold |

---

### RULE-04 — SP CA Bypass → Cloud App Events Correlation
| Field | Value |
|---|---|
| **File** | `RULE-04_SP-CABypass-CloudAppEvents.kql` |
| **Severity** | High |
| **Tactics** | InitialAccess, Exfiltration |
| **MITRE** | T1078.004, T1567, T1530 |
| **Tables** | `AADServicePrincipalSignInLogs`, `CloudAppEvents` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Multi-table correlation: SP bypasses Conditional Access (status = notApplied/failure), then within 60 minutes performs high-risk CloudApp actions (FileDownloaded, MailItemsAccessed, MassDelete, etc.). Joins on `ServicePrincipalId` / `AccountObjectId`. |
| **Key FP mitigations** | Requires both CA bypass AND downstream high-risk action; 2+ actions threshold; 1-hour time window |

---

### RULE-05 — Managed Identity Out-of-Hours Anomaly
| Field | Value |
|---|---|
| **File** | `RULE-05_MI-OutOfHours-Anomaly.kql` |
| **Severity** | Medium |
| **Tactics** | Persistence, LateralMovement |
| **MITRE** | T1078.004, T1550 |
| **Tables** | `AADManagedIdentitySignInLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects Managed Identities with 50+ authentications or 10+ unique resource accesses outside business hours (Mon–Fri 06:00–22:00 local). Corroborates against 14-day business-hours baseline. |
| **Key FP mitigations** | 14-day business hours baseline; Volume threshold (50+ auths or 10+ resources) |

---

### RULE-06 — MI Lateral Movement (High Resource Spread)
| Field | Value |
|---|---|
| **File** | `RULE-06_MI-Lateral-Movement-Resource-Spread.kql` |
| **Severity** | High |
| **Tactics** | LateralMovement, CredentialAccess, Discovery |
| **MITRE** | T1550, T1552.001, T1087 |
| **Tables** | `AADManagedIdentitySignInLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects Managed Identities accessing 5+ distinct sensitive resource types (Key Vault, Storage, SQL, Cognitive, Synapse, etc.) in a single hour. Baseline comparison flags spikes beyond 1.5× historical max. |
| **Key FP mitigations** | 14-day per-MI hourly resource spread baseline; Sensitive resource keyword filter; Threshold of 5+ unique resources |

---

### RULE-07 — SP First-Time Access to Critical Resource
| Field | Value |
|---|---|
| **File** | `RULE-07_SP-FirstTime-Critical-Resource.kql` |
| **Severity** | High |
| **Tactics** | CredentialAccess, Discovery |
| **MITRE** | T1552.001, T1087.004 |
| **Tables** | `AADServicePrincipalSignInLogs`, `AuditLogs` |
| **Frequency** | Every 6 hours / 14-day lookback |
| **Description** | Surfaces SP–resource pairs with no historical access baseline that first access Microsoft Graph, Key Vault, ARM, Exchange, or SharePoint. Cross-correlates with `AuditLogs` to flag whether the SP was recently created or had credentials added (heightening risk). |
| **Key FP mitigations** | 14-day per-SP per-resource baseline; Restricted to critical resource list only |

---

### RULE-08 — SP Created and Used from High-Risk Country Same Day
| Field | Value |
|---|---|
| **File** | `RULE-08_SP-Created-Used-HighRisk-Country.kql` |
| **Severity** | High |
| **Tactics** | Persistence, InitialAccess |
| **MITRE** | T1136.003, T1078.004 |
| **Tables** | `AuditLogs`, `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 6 hours / 1-day lookback |
| **Description** | Detects SPs created within the last 24 hours that are immediately used from a high-risk country. This pattern is characteristic of attacker-created SPs for establishing access from controlled infrastructure. Joins `AuditLogs` creation events with `AADServicePrincipalSignInLogs` on `ServicePrincipalId`. |
| **Key FP mitigations** | Creation must be within 24h; Sign-in must originate from high-risk country list; Records minutes-after-creation metric |

---

### RULE-09 — SP Credentials Added with No Subsequent Sign-in (Dormant Backdoor)
| Field | Value |
|---|---|
| **File** | `RULE-09_SP-Credentials-Added-No-Signin.kql` |
| **Severity** | Medium |
| **Tactics** | Persistence |
| **MITRE** | T1098.001 |
| **Tables** | `AuditLogs`, `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 6 hours / 2-day lookback |
| **Description** | Detects credentials added to SPs between 48–24 hours ago where no successful sign-in occurred after the addition. Attackers add credentials to existing SPs as dormant backdoors held in reserve, making them invisible to activity-based alerting. |
| **Key FP mitigations** | 24-hour grace period after credential addition; Requires at least 24h of observation; Leftanti join confirms absence of sign-in |

---

### RULE-10 — SP Mass Privilege Escalation
| Field | Value |
|---|---|
| **File** | `RULE-10_SP-Mass-Privilege-Escalation.kql` |
| **Severity** | High |
| **Tactics** | PrivilegeEscalation, Persistence |
| **MITRE** | T1098.003, T1078.004 |
| **Tables** | `AuditLogs` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects when a single initiator (SP or user) assigns 3+ high-privilege roles (Owner, Contributor, Global Administrator, etc.) within 2 hours. Escalates to "Critical" when roles include Global Administrator or Owner. |
| **Key FP mitigations** | Threshold of 3+ assignments; Restricted to known high-privilege role names; SP-or-user agnostic — catches both actor types |

---

### RULE-11 — MI Key Vault / Storage Access Correlated with Management Plane Write
| Field | Value |
|---|---|
| **File** | `RULE-11_MI-KV-Storage-MgmtPlane-Correlation.kql` |
| **Severity** | Medium |
| **Tactics** | CredentialAccess, Exfiltration |
| **MITRE** | T1552.001, T1530 |
| **Tables** | `AADManagedIdentitySignInLogs`, `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Multi-table correlation: Managed Identity accesses Key Vault or Storage (data plane) AND within 60 minutes triggers write/delete operations via the Azure management plane. Links data-plane auth to management-plane impact — a compromised workload pattern. |
| **Key FP mitigations** | Requires both data-plane auth AND management-plane write in 1-hour window; Read/List/Get ops excluded from management plane check |

---

### RULE-12 — SP Sign-in Volume Anomaly (Statistical Deviation)
| Field | Value |
|---|---|
| **File** | `RULE-12_SP-Signin-Volume-Anomaly.kql` |
| **Severity** | Medium |
| **Tactics** | Discovery, CredentialAccess |
| **MITRE** | T1078.004, T1087.004 |
| **Tables** | `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 1 hour / 14-day lookback |
| **Description** | Statistical baseline detection: flags SPs whose current-hour sign-in count is 3+ standard deviations above their 14-day personal mean. Catches sudden automation bursts, token stuffing, or credential abuse that doesn't match country-based detection. |
| **Key FP mitigations** | 3-sigma threshold; 14-day baseline with minimum 3-day history requirement; Minimum 50 sign-ins in current hour |

---

### RULE-13 — SP Stale Credential Activation
| Field | Value |
|---|---|
| **File** | `RULE-13_SP-Stale-Credential-Activation.kql` |
| **Severity** | High |
| **Tactics** | CredentialAccess, Persistence |
| **MITRE** | T1078.004, T1098.001 |
| **Tables** | `AADServicePrincipalSignInLogs`, `AuditLogs` |
| **Frequency** | Every 1 hour / 90-day lookback |
| **Description** | Detects SPs dormant for 30+ days that suddenly reactivate with a successful sign-in. Cross-correlates `AuditLogs` to identify whether credentials were added during the dormancy window (backdoor pre-staging). Escalates to Critical when dormancy >60 days and credential-during-dormancy confirmed. |
| **Key FP mitigations** | 30-day minimum dormancy before triggering; Three-way join ensures genuine gap (not missing log data); 90-day baseline window for dormancy confirmation |

---

### RULE-14 — SP Risky Authentication Flow

> **KQL only — not in ARM template.** This rule joins `AADServicePrincipalSignInLogs` with `AuditLogs`. The `AuditLogs` table requires the **Azure Active Directory** data connector to be enabled. The ARM validator rejects the query at deploy-time if `AuditLogs` is absent in the workspace. Deploy manually via `push_alert_rules.py` or the Sentinel portal once the connector is confirmed.

| Field | Value |
|---|---|
| **File** | `RULE-14_SP-Risky-Auth-Flow.kql` |
| **Severity** | High |
| **Tactics** | CredentialAccess, InitialAccess |
| **MITRE** | T1078.004, T1528 |
| **Tables** | `AADServicePrincipalSignInLogs`, `AuditLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects SPs authenticating via non-standard flows: `ClientCredentialType == "none"` (no real credential), ROPC/device-code/username-password protocols, or Conditional Access not applied. Multi-signal scoring combines risky credential type, CA-blind status, and delegated flow anomalies. |
| **Key FP mitigations** | Built-in "Legacy Authentication" targets user sign-ins only — this rule is exclusively `AADServicePrincipalSignInLogs`; Multi-signal scoring reduces single-field FPs |

---

### RULE-15 — SP Graph API Service Principal Enumeration
| Field | Value |
|---|---|
| **File** | `RULE-15_SP-GraphAPI-Enumeration.kql` |
| **Severity** | Medium |
| **Tactics** | Discovery |
| **MITRE** | T1087.004, T1069.003 |
| **Tables** | `AuditLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects Graph API calls that list or read service principals (10+ operations per caller per hour) — the pattern produced by AzureHound, ROADtools, and AADInternals during tenant reconnaissance. Distinguishes SP callers from user callers and correlates with recent privilege changes. |
| **Key FP mitigations** | Threshold of 10+ operations per hour; Distinguishes SP-initiator vs user-initiator; No Sentinel built-in covers Graph API SP listing patterns from non-interactive callers |

---

### RULE-16 — SP Self-Privilege Escalation via App Role Assignment
| Field | Value |
|---|---|
| **File** | `RULE-16_SP-Self-Privilege-Escalation.kql` |
| **Severity** | High |
| **Tactics** | PrivilegeEscalation, Persistence |
| **MITRE** | T1098.003 |
| **Tables** | `AuditLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Fires when a **service principal is the initiator** of an app role assignment or permission grant — either granting itself permissions (self-elevation) or granting dangerous scopes to other SPs it controls. Catches the cloud-native equivalent of token privilege escalation. |
| **Key FP mitigations** | Requires SP as initiator (filters `InitiatedBy.app.servicePrincipalId`); Targets dangerous permission scope list or explicit self-grant; Different from RULE-10 (user → SP) and the Sentinel built-in (RBAC role assignment) |

---

### RULE-17 — SP Sensitive API Permission Grant
| Field | Value |
|---|---|
| **File** | `RULE-17_SP-Sensitive-Permission-Grant.kql` |
| **Severity** | High |
| **Tactics** | PrivilegeEscalation, Persistence |
| **MITRE** | T1098.003, T1078.004 |
| **Tables** | `AuditLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects OAuth2/Microsoft Graph API permission consent grants for dangerous scopes: `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `Mail.ReadWrite`, `full_access_as_app`, `Exchange.ManageAsApp`, and others. Escalates to Critical when a newly created SP receives tenant-wide admin Graph scopes. |
| **Key FP mitigations** | Sentinel built-in "SP assigned privileged role" targets Azure RBAC — this rule targets OAuth2 consent grants, a separate escalation vector; New SP + dangerous scope = Critical; Existing SP = High |

---

### RULE-18 — Multiple SPs Created by Single Principal (Bulk Burst)
| Field | Value |
|---|---|
| **File** | `RULE-18_SP-Bulk-Creation-Burst.kql` |
| **Severity** | Medium |
| **Tactics** | Persistence, PrivilegeEscalation |
| **MITRE** | T1136.003, T1078.004 |
| **Tables** | `AuditLogs` |
| **Frequency** | Every 30 minutes / 30-minute lookback |
| **Description** | Flags when a single principal creates more than 3 service principals within a 10-minute sliding window. Detects attacker bulk-creation of SP backdoors and correlates with immediate credential/role arming of the new SPs. Escalates to Critical when an SP (not a user) is creating other SPs. |
| **Key FP mitigations** | Sliding 10-minute window via inner join; No Sentinel built-in detects creation velocity; `queryFrequency = PT30M` to catch bursts near hour boundaries |

---

### RULE-19 — SP Identity Protection Risk State Escalation *(KQL only — not in ARM template)*

> **Not included in `WorkloadIdentities-Detections.json`.** This rule references `RiskyServicePrincipals` and `ServicePrincipalRiskEvents`, which are only available when **Microsoft Entra ID P2 + Identity Protection for Workload Identities** is licensed. The ARM validator rejects the query if these tables are absent. Deploy manually via `push_alert_rules.py` or through the Sentinel portal once the license is confirmed.

| Field | Value |
|---|---|
| **File** | `RULE-19_SP-IdentityProtection-Risk-Escalation.kql` |
| **Severity** | High |
| **Tactics** | InitialAccess, CredentialAccess |
| **MITRE** | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Tables** | `RiskyServicePrincipals`, `ServicePrincipalRiskEvents` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Fires when Entra ID Identity Protection elevates a Service Principal to `atRisk` or `confirmedCompromised` at medium/high risk level. Correlates with `ServicePrincipalRiskEvents` to surface which detection types drove the escalation (anomalousToken, investigationsThreatIntelligence, maliciousIPAddress, suspiciousAPITraffic). Escalates to Critical when `confirmedCompromised` or when a high-severity ML detection type fires. |
| **Key FP mitigations** | Requires explicit state escalation from Identity Protection (not self-assessed); Built-in RiskyUsers rules cover only user accounts — this fills the workload identity gap |

---

### RULE-20 — SP Risk Event Stacking (Multiple Concurrent Detections) *(KQL only — not in ARM template)*

> **Not included in `WorkloadIdentities-Detections.json`.** Same licensing requirement as RULE-19. Deploy via `push_alert_rules.py` or the Sentinel portal once `ServicePrincipalRiskEvents` is confirmed to exist in the workspace.

| Field | Value |
|---|---|
| **File** | `RULE-20_SP-RiskEvent-Stacking.kql` |
| **Severity** | High |
| **Tactics** | CredentialAccess, Persistence |
| **MITRE** | T1078.004, T1550.001 |
| **Tables** | `ServicePrincipalRiskEvents`, `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 1 hour / 1-hour lookback |
| **Description** | Detects when 2+ distinct Identity Protection risk event types fire for the same SP within 1 hour (risk stacking), or when any single high-severity event type triggers. Risk stacking is statistically unlikely for benign identities and indicates active exploitation. Corroborated by concurrent sign-in activity in `AADServicePrincipalSignInLogs`. Distinct from RULE-19 (which tracks state transitions) — this rule fires on the raw detection stream before state changes propagate. |
| **Key FP mitigations** | Threshold of 2+ distinct event types; Single-type trigger only for known high-severity types; Concurrent sign-in join adds exploitation confirmation signal |

---

## Hunting Queries (13 Queries)

| File | Purpose | Key Tables | Lookback |
|---|---|---|---|
| `HUNT-01_SP-Suspicious-IP-Country-Timeline.kql` | Full geo-analysis of SP sign-in IP origins, high-risk country breakdown | `AADServicePrincipalSignInLogs` | 7d |
| `HUNT-02_SP-BruteForce-History-30d.kql` | 30-day brute force history per SP, error code distribution, spray success correlation | `AADServicePrincipalSignInLogs` | 30d |
| `HUNT-03_SP-CA-Bypass-History-30d.kql` | 30-day CA bypass (notApplied/failure) history, persistent policy evaders | `AADServicePrincipalSignInLogs` | 30d |
| `HUNT-04_SP-CloudAppEvents-Correlation.kql` | SPs with suspicious sign-ins correlated with high-risk M365 cloud app actions | `AADServicePrincipalSignInLogs`, `CloudAppEvents` | 7d |
| `HUNT-05_MI-OutOfHours-Timeline-90d.kql` | 90-day MI out-of-hours activity timeline, OOH ratio, sensitive resource access | `AADManagedIdentitySignInLogs` | 90d |
| `HUNT-06_SP-Critical-Resource-Access-90d.kql` | 90-day critical resource access history (Graph, KV, ARM, Exchange, SharePoint) with AuditLogs correlation | `AADServicePrincipalSignInLogs`, `AuditLogs` | 90d |
| `HUNT-07_SP-Token-Abuse-7d.kql` | Token replay candidates: same token used from 3+ IPs or 2+ countries within 60 min | `AADServicePrincipalSignInLogs` | 7d |
| `HUNT-08_SP-FirstTime-Resource-30d.kql` | SP–resource pairs with first access in last 7d but no history in prior 23d | `AADServicePrincipalSignInLogs`, `AuditLogs` | 30d |
| `HUNT-09_SP-Created-Never-Used-30d.kql` | **SPs created in last 30 days with ZERO sign-in activity** — ghost/backdoor SPs | `AuditLogs`, `AADServicePrincipalSignInLogs` | 30d |
| `HUNT-10_SP-NotUsed-90d-Stale.kql` | **SPs not used in 90+ days** — stale identity attack surface, reactivation detection | `AADServicePrincipalSignInLogs`, `AuditLogs`, `AzureActivity` | 180d |
| `HUNT-11_SP-Dormant-Reactivation-History.kql` | **90-day retroactive view of SP dormancy gaps** — credential changes and privilege escalations during dormancy | `AADServicePrincipalSignInLogs`, `AuditLogs` | 90d |
| `HUNT-12_SP-RiskState-Trends-30d.kql` | **SP risk state history and dismissed-without-remediation pattern** — surfaces incomplete triage and alert suppression | `RiskyServicePrincipals`, `ServicePrincipalRiskEvents`, `AuditLogs` | 30d |
| `HUNT-13_SP-RiskEvents-Attribution-30d.kql` | **Full Identity Protection risk event attribution** — composite risk scoring, attack-breadth classification, DFIR correlation | `ServicePrincipalRiskEvents`, `AADServicePrincipalSignInLogs`, `AuditLogs` | 30d |

---

## MITRE ATT&CK Coverage

| Technique | ID | Rules | Hunts |
|---|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | RULE-01, 02, 04, 05, 06, 07, 08, 10, 12, 13, 14, 16, 17, 18 *(+ RULE-19, 20 KQL-only)* | HUNT-01, 02, 03, 06, 08, 11 |
| Steal Application Access Token | T1528 | RULE-03, 04, 14 | HUNT-07 |
| Use Alternate Authentication Material | T1550.001 | RULE-03, 05, 06 *(+ RULE-20 KQL-only)* | HUNT-07, 13 |
| Account Manipulation: Additional Cloud Credentials | T1098.001 | RULE-09, 13 | HUNT-09, 10, 11 |
| Additional Cloud Roles | T1098.003 | RULE-10, 16, 17 | — |
| Create Cloud Account | T1136.003 | RULE-08, 18 | HUNT-09 |
| Brute Force: Password Spray | T1110.003 | RULE-02 | HUNT-02 |
| Credentials in Files / Secrets | T1552.001 | RULE-07, 11 | HUNT-06 |
| Account Discovery: Cloud | T1087.004 | RULE-07, 12, 15 | HUNT-06, 08 |
| Permission Groups: Cloud Groups | T1069.003 | RULE-15 | — |
| Exfiltration to Cloud Storage | T1567 / T1530 | RULE-04, 11 | HUNT-04 |

---

## Table Cross-Correlation Map

| Detection Pattern | Primary Table | Correlated Tables |
|---|---|---|
| SP suspicious geo + baseline | `AADServicePrincipalSignInLogs` | — |
| SP brute force + spray success | `AADServicePrincipalSignInLogs` | `AADServicePrincipalSignInLogs` (success join) |
| SP token replay | `AADServicePrincipalSignInLogs` | — |
| SP CA bypass → data exfil | `AADServicePrincipalSignInLogs` | `CloudAppEvents` |
| MI out-of-hours | `AADManagedIdentitySignInLogs` | — |
| MI lateral movement | `AADManagedIdentitySignInLogs` | `AzureActivity` |
| SP first critical resource | `AADServicePrincipalSignInLogs` | `AuditLogs` |
| SP created → used from risk geo | `AuditLogs` | `AADServicePrincipalSignInLogs` |
| SP dormant backdoor cred | `AuditLogs` | `AADServicePrincipalSignInLogs` |
| SP mass role escalation | `AuditLogs` | — |
| MI KV/Storage + mgmt plane | `AADManagedIdentitySignInLogs` | `AzureActivity` |
| SP volume statistical spike | `AADServicePrincipalSignInLogs` | — |
| SP stale credential reactivation | `AADServicePrincipalSignInLogs` | `AuditLogs` |
| SP risky auth flow | `AADServicePrincipalSignInLogs` | `AuditLogs` |
| SP Graph API reconnaissance | `AuditLogs` (Graph audit) | `AuditLogs` (priv correlation) |
| SP self-privilege escalation | `AuditLogs` | — |
| SP sensitive API permission consent | `AuditLogs` | `AuditLogs` (recent SP creation) |
| SP bulk creation burst | `AuditLogs` | `AuditLogs` (post-creation arming) |
| SP Identity Protection risk escalation *(RULE-19 — KQL only)* | `RiskyServicePrincipals` | `ServicePrincipalRiskEvents` |
| SP risk event stacking *(RULE-20 — KQL only)* | `ServicePrincipalRiskEvents` | `AADServicePrincipalSignInLogs` |

---

## Notes

- **HUNT-09** surfaces SPs created but never signed in within 30 days. Risk is stratified: credentialed-but-dormant SPs are flagged "High"; uncredentialed abandoned SPs are "Medium". Cross-referenced with credential additions in `AuditLogs`.
- **HUNT-10** performs a 180-day lookback to find SPs whose last sign-in was over 90 days ago. Stale SPs with recent credential changes or management plane activity in `AzureActivity` are escalated to "Critical" — this is the reactivation pattern used by attackers targeting abandoned identities.
- **RULE-03** and **HUNT-07** focus on token replay via `UniqueTokenIdentifier`. This field is available in `AADServicePrincipalSignInLogs` only when the connector sends full non-interactive sign-in data. Verify your AAD connector sends this field before relying on these detections.
- **RULE-04** and **HUNT-04** require the **Microsoft Defender for Cloud Apps** connector to populate `CloudAppEvents`. Verify `CloudAppEvents` has data before deploying.
- **Managed Identity sign-ins** (`AADManagedIdentitySignInLogs`) require the **Azure Active Directory** data connector with the **Managed Identity Sign-In Logs** option enabled.
- All rules use `ResultType == "0"` for successful sign-ins — this is the integer value `0`, not the string `"0"`. In `AADServicePrincipalSignInLogs` the column type is string, so quotes are intentional.
- **RULE-13** and **HUNT-11** detect SP dormancy gaps of 30+ days followed by reactivation. These cross-correlate `AuditLogs` for credential changes made *during* the dormancy window — a critical signal for backdoor discovery.
- **RULE-14** targets risky SP authentication flows by inspecting `ClientCredentialType` and `AuthenticationProtocol` fields in `AADServicePrincipalSignInLogs`. Fields are null for some token types; the rule handles this with `isempty()` checks. **RULE-14 is excluded from the ARM template** because it joins `AuditLogs`, which requires the Azure Active Directory connector — the ARM validator rejects the deployment when this table is absent. Deploy via `push_alert_rules.py` once the connector is confirmed.
- **RULE-15** detects Graph API enumeration (10+ SP list/read operations per caller per hour). This requires the **Microsoft Entra ID / Azure AD** audit logs connector. Graph API calls appear in `AuditLogs` with `OperationName = "List servicePrincipals"`, not in sign-in logs.
- **RULE-16** fires when a **service principal acts as the initiator** of its own app role grant — SP-initiated self-elevation. This is fundamentally different from RULE-10 (user assigning roles to SPs) and from the built-in "Service Principal assigned privileged role" detection.
- **RULE-17** catches **OAuth2/Graph API permission consent grants** for dangerous scopes (RoleManagement.ReadWrite.Directory, Application.ReadWrite.All, Mail.ReadWrite, etc.). This is a different escalation vector from Azure RBAC role assignment and is not covered by any known Sentinel built-in.
- **RULE-18** uses a sliding time-window join to detect burst creation (>3 SPs in 10 minutes). The `queryFrequency` and `queryPeriod` are both PT30M to catch bursts that begin near the edge of an hour boundary.
- **RULE-19 and RULE-20 are excluded from the ARM template** because `RiskyServicePrincipals` and `ServicePrincipalRiskEvents` only exist in tenants with **Microsoft Entra ID P2 + Identity Protection for Workload Identities** licensed. The ARM validator rejects the query at deploy-time if those tables are absent in the workspace, causing the entire deployment to fail. The `.kql` source files are retained in `AnalyticRules/` — deploy them individually via `push_alert_rules.py` (which bypasses the ARM validator) or create them manually in the Sentinel portal once the license is confirmed.
- **RULE-19** fires on SP risk *state transitions* (`atRisk` or `confirmedCompromised` in `RiskyServicePrincipals`), which are aggregated ML/TI determinations. It correlates with `ServicePrincipalRiskEvents` to enumerate the specific detection types that drove the escalation.
- **RULE-20** fires on the raw *detection event stream* in `ServicePrincipalRiskEvents`, independently of whether the SP's risk state has been updated yet. Risk stacking (2+ distinct event types within 1 hour) is a compound indicator that distinguishes active exploitation from isolated model noise. RULE-19 and RULE-20 are complementary: RULE-20 can pre-fire before RULE-19 if a burst of events triggers multiple models simultaneously.
- **HUNT-12** surfaces SPs that were dismissed or remediated in `RiskyServicePrincipals` without a preceding `confirmedCompromised` investigation — a pattern consistent with alert suppression or analyst fatigue. Correlates with concurrent `AuditLogs` changes to detect backdoor staging during the risk window. Requires `RiskyServicePrincipals` / `ServicePrincipalRiskEvents` (Entra ID P2); the query uses `union isfuzzy=true` with an empty datatable fallback so it runs without error even when the tables are absent — it will simply return no results.
- **HUNT-13** provides full 30-day DFIR attribution from `ServicePrincipalRiskEvents`. The composite `TotalRiskScore` (sum of per-event severity scores) and `AttackBreadth` classification are designed to support incident triage prioritization when multiple SPs are flagged simultaneously. Same `isfuzzy=true` fallback as HUNT-12.

---



