# Azure Sentinel — Custom Detections Package

> **Workspace:** `LAWSentinel`  
> **Created:** March 9, 2026  
> **Status:** Production-ready (ARM template validated)

Custom analytic rules and hunting queries for Microsoft Sentinel that **do not duplicate any confirmed live built-in detections** in the workspace. All rules are grounded in live table schema discovery, real AzureActivity operation names observed in the environment, and comprehensive false-positive mitigations.

---

## NetworkAllowlist (trusted IPs)

The ARM template now provisions a `NetworkAllowlist` watchlist (seeded with RFC1918 ranges by default) and a scalar function `ExcludeAllowlistedIPs_AzureCustom(ip:string) -> bool`. Every analytic rule and hunt that references `CallerIpAddress` or `IPAddress` is filtered through this function — keeping known-good infrastructure (corporate egress, VPN, Azure platform IPs) out of alerts without code changes.

To customize, pass a CSV via `watchlistRawContent` at deploy time, or edit the watchlist in the portal after deploy. Schema: `IPOrRange,Description,Owner,AddedDate`. CIDR is supported.

The function is **isfuzzy-safe** against a missing watchlist (returns `false` when the watchlist hasn't yet seeded), so first-deploy doesn't break queries.

---

## Folder Structure

```
AzureSentinelCustomDetections/
├── README.md                          ← This file
├── ARM-Template/
│   └── Azure-Sentinel-CustomDetections.json   ← Deploy all rules at once
├── Watchlists/                        ← Optional named-location sync helpers
├── AnalyticRules/
│   ├── RULE-01_GPU-Cryptojacking-VM-New-Identity.kql
│   ├── RULE-02_DiagnosticSettings-Deleted-Without-Recreation.kql
│   ├── RULE-03_Mass-Privileged-Role-Assignments.kql
│   ├── RULE-04_Storage-SAS-Token-Bulk-Generation.kql
│   ├── RULE-05_Automation-Runbook-New-Caller.kql
│   ├── RULE-06_TI-Match-STIX-Management-Plane.kql
│   ├── RULE-07_Resource-Lock-Policy-Deleted.kql
│   ├── RULE-08_SP-Credential-Added-Privileged-Role.kql
│   ├── RULE-09_Privileged-Ops-New-IP.kql
│   ├── RULE-10_SP-CA-Bypass-Management-Ops.kql
│   ├── RULE-11_Mass-Resource-Deletion.kql
│   ├── RULE-12_Mass-Resource-Creation.kql
│   ├── RULE-13_Storage-Anonymous-Public-Access.kql
│   ├── RULE-14_NSG-Deleted.kql
│   ├── RULE-15_VM-Custom-Script-Extension.kql
│   ├── RULE-16_Sentinel-Analytics-Rule-Deleted.kql
│   ├── RULE-17_Anomalous-Management-Operations.kql
│   ├── RULE-18_AAD-Illicit-Consent-Grant.kql
│   ├── RULE-19_Anonymizer-Signin-Priv-Ops.kql
│   └── RULE-20_Storage-Immutability-Removed.kql
└── HuntingQueries/
    ├── HUNT-01_GPU-VM-Deployment-History.kql
    ├── HUNT-02_DiagSettings-Change-Timeline.kql
    ├── HUNT-03_Storage-Blob-Exfiltration.kql
    ├── HUNT-04_Automation-Runbook-History.kql
    ├── HUNT-05_TI-Management-Plane-Extended.kql
    ├── HUNT-06_Orphaned-Privileged-Roles.kql
    ├── HUNT-07_Lighthouse-Delegation-Changes.kql
    ├── HUNT-08_Privileged-Ops-Outside-Hours.kql
    ├── HUNT-09_New-SP-KeyVault-Access.kql
    ├── HUNT-10_SP-Credential-Rotation-Anomaly.kql
    ├── HUNT-11_Storage-Anonymous-SAS-Access-Timeline.kql
    ├── HUNT-12_NSG-Firewall-Change-History.kql
    ├── HUNT-13_VM-Script-Extension-History.kql
    ├── HUNT-14_Sentinel-Config-Changes.kql
    ├── HUNT-15_Identity-Ops-Anomaly-DeepDive.kql
    ├── HUNT-16_FirstSeen-ResourceProvider-Per-Identity.kql
    ├── HUNT-17_KeyVault-Bulk-Read.kql
    ├── HUNT-18_SP-Signin-New-Country.kql
    ├── HUNT-19_Consent-Grant-Burst.kql
    ├── HUNT-20_Signin-Anomalous-ASN.kql
    ├── HUNT-21_Caller-IP-Concentration.kql
    ├── HUNT-22_Federation-Domain-Trust-Changes.kql
    ├── HUNT-23_MFA-Auth-Method-Changes.kql
    ├── HUNT-24_Guest-Invite-Privileged-Role.kql
    ├── HUNT-25_Storage-DataProtection-Changes.kql
    └── HUNT-26_Risky-Anonymizer-Signin-Timeline.kql
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Connected to `LAWSentinel` workspace |
| Data connectors | Azure Activity, Azure Active Directory (Sign-in Logs, Audit Logs, Service Principal Sign-in Logs), Storage Blob Logs, Microsoft Threat Intelligence |
| Tables required | `AzureActivity`, `AuditLogs`, `StorageBlobLogs`, `SigninLogs`, `AADServicePrincipalSignInLogs`, `ThreatIntelIndicators` (STIX 2.1) |
| ARM API version | `2023-02-01-preview` (alertRules), `2020-08-01` (savedSearches) |
| Permissions (deploy) | Microsoft Sentinel Contributor + Log Analytics Contributor |

---

## Deploying the ARM Template

### Azure Portal
1. Navigate to **Deploy a custom template** → `portal.azure.com/#create/Microsoft.Template`
2. Click **Build your own template in the editor**
3. Load `ARM-Template/Azure-Sentinel-CustomDetections.json`
4. Set `workspaceName` = `LAWSentinel`
5. Deploy to the resource group hosting your Sentinel workspace

### Azure CLI
```bash
az deployment group create \
  --resource-group <YOUR-RESOURCE-GROUP> \
  --template-file "ARM-Template/Azure-Sentinel-CustomDetections.json" \
  --parameters workspaceName=LAWSentinel
```

#### Staged deploy (rules disabled, then enable after baseline)
```bash
# 1) Deploy watchlist + function + hunts; alertRules created disabled
az deployment group create \
  --resource-group <RG> \
  --template-file "ARM-Template/Azure-Sentinel-CustomDetections.json" \
  --parameters workspaceName=LAWSentinel enableAnalyticRules=false

# 2) Optionally seed the NetworkAllowlist watchlist (CSV body) in the portal,
#    then enable rules
az deployment group create \
  --resource-group <RG> \
  --template-file "ARM-Template/Azure-Sentinel-CustomDetections.json" \
  --parameters workspaceName=LAWSentinel enableAnalyticRules=true
```

### Template Parameters
| Parameter | Default | Description |
|---|---|---|
| `workspaceName` | `LAWSentinel` | Log Analytics workspace name |
| `location` | resource group location | Azure region |
| `enableAnalyticRules` | `true` | Set `false` for staged deploy (rules created disabled) |
| `watchlistAlias` | `NetworkAllowlist` | Watchlist alias (rarely changed) |
| `functionAlias` | `ExcludeAllowlistedIPs_AzureCustom` | Scalar function name (avoid collisions across solutions) |
| `watchlistRawContent` | *(empty)* | Optional CSV body to seed the watchlist; defaults to RFC1918 |

### PowerShell
```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<YOUR-RESOURCE-GROUP>" `
  -TemplateFile "ARM-Template\Azure-Sentinel-CustomDetections.json" `
  -workspaceName "LAWSentinel"
```

---

## Analytic Rules (20 Rules)

### RULE-01 — GPU/High-Compute VM Deployed by New Identity
| Field | Value |
|---|---|
| **File** | `RULE-01_GPU-Cryptojacking-VM-New-Identity.kql` |
| **Severity** | High |
| **Tactics** | Impact |
| **MITRE** | T1496 (Resource Hijacking) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 6 hours / 14-day lookback |
| **Description** | Detects deployment of GPU or high-compute VMs (NC/NV/ND/NP/HB/HC series) by identities with no prior GPU deployment history in 14 days. Targets cryptojacking operators who compromise Azure credentials and immediately provision mining infrastructure. |
| **Key FP mitigations** | 14-day per-identity baseline; IaC/CI-CD caller name exclusions; Azure platform IP exclusions; Success-only events |

---

### RULE-02 — Diagnostic Settings Deleted Without Recreation
| Field | Value |
|---|---|
| **File** | `RULE-02_DiagnosticSettings-Deleted-Without-Recreation.kql` |
| **Severity** | High |
| **Tactics** | DefenseEvasion |
| **MITRE** | T1562.008 (Disable Cloud Logs) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects deletion of Azure Diagnostic Settings not followed by re-creation within 30 minutes. Attackers disable monitoring ingestion before destructive operations to blind the SIEM. |
| **Key FP mitigations** | IaC patterns excluded; 30-min re-creation window handles Terraform destroy+apply cycles; Success-only |

---

### RULE-03 — Mass Privileged Role Assignments by Single Identity
| Field | Value |
|---|---|
| **File** | `RULE-03_Mass-Privileged-Role-Assignments.kql` |
| **Severity** | High |
| **Tactics** | PrivilegeEscalation, Persistence |
| **MITRE** | T1098.003 (Add Office 365 Global Administrator Role) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 30 minutes / 1-hour lookback |
| **Description** | Triggers when a single identity assigns 8+ non-read-only roles within a 30-minute window, and either spans ≥2 distinct roles or targets ≥3 distinct principals. Used by LAPSUS$ and Storm-0501 for rapid bulk privilege escalation post-compromise. |
| **Key FP mitigations** | PIM/IdentityGovernance/Azure AD Sync SP excluded; read-only role GUIDs (Reader, Billing Reader, Directory Reader, Global Reader, Security Reader) excluded; **threshold raised 5+ → 8+ in 30 min** and role/principal diversity required; Azure platform IPs excluded |

---

### RULE-04 — Storage SAS Token Bulk Generation
| Field | Value |
|---|---|
| **File** | `RULE-04_Storage-SAS-Token-Bulk-Generation.kql` |
| **Severity** | Medium |
| **Tactics** | DefenseEvasion, LateralMovement |
| **MITRE** | T1550 (Use Alternate Authentication Material) |
| **Tables** | `AzureActivity`, `StorageBlobLogs` |
| **Frequency** | Every 1 hour / 14-day lookback |
| **Description** | Detects bulk generation of SAS tokens (ListAccountSAS / ListServiceSAS) — 8+ in 30 minutes by a single identity, or 5+ generations spanning ≥3 storage accounts (cross-account enumeration) — by a caller that is **not** an established SAS generator. Attackers use SAS tokens as alternative credentials to exfiltrate data without standard AAD sign-in traces. |
| **Key FP mitigations** | Backup/monitor/AzCopy/CDN/DataFactory/Synapse SP patterns excluded; **14-day recurring-generator baseline** — callers seen minting SAS on ≥3 distinct days (routine automation/backup/pipeline SPs) are suppressed, removing the dominant `N tokens by <GUID>` noise; **burst floors raised (8, or 5 across ≥3 accounts)**; correlated with StorageBlobLogs for blob-read egress enrichment |

---

### RULE-05 — Automation Runbook Created by First-Time Caller
| Field | Value |
|---|---|
| **File** | `RULE-05_Automation-Runbook-New-Caller.kql` |
| **Severity** | High |
| **Tactics** | Execution, Persistence |
| **MITRE** | T1059.009 (Cloud Administration Command) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 6 hours / 14-day lookback |
| **Description** | Detects creation or publishing of Azure Automation runbooks by identities with no runbook history in 14 days. Runbooks execute code with Automation Account managed identity privileges — a cloud-native persistence vector used by APT29 and LAPSUS$. |
| **Key FP mitigations** | 14-day behavioral baseline; DevOps pipeline name exclusions; Azure platform IPs excluded; Success-only |

---

### RULE-06 — TI Match on Azure Management Plane Caller IP (STIX)
| Field | Value |
|---|---|
| **File** | `RULE-06_TI-Match-STIX-Management-Plane.kql` |
| **Severity** | High |
| **Tactics** | InitialAccess, Persistence, Impact |
| **MITRE** | T1078, T1098, T1496 |
| **Tables** | `ThreatIntelIndicators` (STIX 2.1), `AzureActivity`, `SigninLogs`, `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 1 hour / 1-day lookback |
| **Description** | Correlates `CallerIpAddress` in AzureActivity against active STIX 2.1 IPv4 indicators from `ThreatIntelIndicators`. A match indicates adversary-controlled infrastructure calling Azure management APIs. Corroborated with sign-in sessions from the same IP to confirm live access vs. scan noise. Uses the new STIX 2.1 table with `ObservableKey =~ "ipv4-addr:value"` / `ObservableValue` for IP extraction. |
| **Key FP mitigations** | `Confidence >= 75`; `IsActive == true`, `Revoked == false`, `IsDeleted == false`, `ValidUntil > now()`; Private/platform IPs excluded; SigninLogs + AADServicePrincipalSignInLogs corroboration; `CorroboratedBySignin` flag in alert |

---

### RULE-07 — Resource Lock or Policy Deleted
| Field | Value |
|---|---|
| **File** | `RULE-07_Resource-Lock-Policy-Deleted.kql` |
| **Severity** | Medium |
| **Tactics** | DefenseEvasion |
| **MITRE** | T1562 (Impair Defenses) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects deletion of Azure Resource Locks, Policy Assignments, Policy Definitions, or Policy Exemption WRITE operations. Attackers remove guardrails before destructive operations (ransomware staging, data wipe). |
| **Key FP mitigations** | IaC/policy-compliance tool patterns excluded; Azure platform IPs excluded; Success-only |

---

### RULE-08 — Service Principal Credential Added Then Privileged Role Assigned
| Field | Value |
|---|---|
| **File** | `RULE-08_SP-Credential-Added-Privileged-Role.kql` |
| **Severity** | High |
| **Tactics** | Persistence, PrivilegeEscalation |
| **MITRE** | T1098.001 (Additional Cloud Credentials) |
| **Tables** | `AuditLogs` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects the "backdoor SP" attack chain — same initiator adds a credential to a service principal AND assigns it a privileged role (Owner, Contributor, Global Admin, User Access Admin, Privileged Role Admin, Security Admin, Application Admin, Cloud App Admin, Hybrid Identity Admin, Privileged Authentication Admin) within 60 minutes and from the same source IP (when both audit events carry an IP). Used by Storm-0501 and Midnight Blizzard for persistent privileged access. |
| **Key FP mitigations** | **Role name matching tightened** to exact `in~` on ~11 vetted role names (previously bare `has_any` over-matched, e.g. `Storage Blob Data Contributor`); 60-min correlation window; **same-IP correlation** across cred-add and role-assign events (falls back to Initiator-only when IP is absent) |

---

### RULE-09 — Privileged Management Ops from New Source IP
| Field | Value |
|---|---|
| **File** | `RULE-09_Privileged-Ops-New-IP.kql` |
| **Severity** | Medium |
| **Tactics** | InitialAccess, Persistence |
| **MITRE** | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 6 hours / 14-day lookback |
| **Description** | Azure management-plane equivalent of Impossible Travel. Detects established identities (active in last 14 days) performing privileged operations (IAM, KV, VM, diagnostics, runbooks) from an IP not seen in their 14-day history — requires ≥3 operations from the new IP (or 2+ distinct operation types) to fire. |
| **Key FP mitigations** | Per-identity 14-day IP whitelist with `set_has_element`; Azure platform IPs excluded; only privileged operation types; new identities (no baseline) handled by Rule-01/05 instead; **operation-count floor raised from 1 → 3** (or 2+ distinct op types) to drop single-op reconnect FPs |

---

### RULE-10 — Service Principal CA Bypass Sign-in Then Management Ops
| Field | Value |
|---|---|
| **File** | `RULE-10_SP-CA-Bypass-Management-Ops.kql` |
| **Severity** | High |
| **Tactics** | InitialAccess, CredentialAccess |
| **MITRE** | T1528, T1078 |
| **Tables** | `AADServicePrincipalSignInLogs`, `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects SP sign-in with Conditional Access status `failure` or `notApplied` (CA bypass) but `ResultType=0` (succeeded), followed by 3+ Azure management operations from the same IP within 1 hour. Indicates stolen SP tokens or credential abuse bypassing CA policies. |
| **Key FP mitigations** | `ResultType=0` required; **minimum management-op count raised 2 → 3**; platform IPs excluded; 1-hour tight temporal window reduces NAT coincidences |

---

### RULE-11 — Mass Deletion of Critical Resources
| Field | Value |
|---|---|
| **File** | `RULE-11_Mass-Resource-Deletion.kql` |
| **Severity** | High |
| **Tactics** | Impact, DefenseEvasion |
| **MITRE** | T1485 (Data Destruction), T1562 |
| **Tables** | `AzureActivity`, `SigninLogs`, `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 1 hour / 3-hour lookback |
| **Description** | Detects bulk deletion of critical Azure infrastructure (NSGs, VMs, Storage Accounts, VNETs, Subnets, Disks, Key Vaults, App Gateways, Load Balancers) — 15+ deletions across 2+ resource types within 1 hour. Characteristic of ransomware pre-staging and insider destruction attacks. Correlated with sign-in risk levels from SigninLogs and AADServicePrincipalSignInLogs. |
| **Key FP mitigations** | **Deletion floor raised 10 → 15**, plus 2+ resource types; 14-day baseline excludes established bulk-deleters (avg ≥10/day for ≥5 days); IaC/pipeline patterns excluded; SigninLogs risk enrichment (`SigninRiskLevel`, `HasSigninCorroboration`) |

---

### RULE-12 — Mass Resource Creation Burst by New Identity
| Field | Value |
|---|---|
| **File** | `RULE-12_Mass-Resource-Creation.kql` |
| **Severity** | High |
| **Tactics** | Impact, Persistence |
| **MITRE** | T1496, T1136 |
| **Tables** | `AzureActivity`, `SigninLogs`, `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 2 hours / 4-hour lookback |
| **Description** | Detects 15+ resource creation events across 3+ distinct resource types in 2 hours, by an identity with **zero creation history** in the past 14 days. Targets cryptojacking operators and attackers deploying C2 infrastructure. Differentiated from the built-in "Unusual number of resources created" by using identity-baseline logic (zero-history qualifier) + type diversity scoring instead of simple count thresholds. |
| **Key FP mitigations** | 14-day zero-history baseline (established creators never trigger); 3+ resource type diversity; IaC/pipeline patterns excluded; correlated with preceding sign-in risk and CA bypass events |

---

### RULE-13 — Storage Account Accessed Anonymously or via SAS from Public Internet
| Field | Value |
|---|---|
| **File** | `RULE-13_Storage-Anonymous-Public-Access.kql` |
| **Severity** | Medium |
| **Tactics** | Collection, Exfiltration |
| **MITRE** | T1530 (Data from Cloud Storage Object) |
| **Tables** | `StorageBlobLogs` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects blob reads from public IPs using Anonymous or SAS-Token authentication. Anonymous blob access is disabled by default in new accounts but may exist in legacy deployments; SAS tokens are frequently abused post-compromise to exfiltrate data without AAD traces. Triggers at 10+ anonymous requests from a single IP, or >500 MB / ≥50 distinct blobs via SAS. |
| **Key FP mitigations** | RFC 1918 and Azure platform IPs excluded; **Anonymous threshold raised 5 → 10** requests; **SAS threshold raised 50 MB → 500 MB**, with an alternate `DistinctBlobs ≥ 50` gate for enumeration campaigns that stay under the byte cap; HTTP 200 only |

---

### RULE-14 — Network Security Group Deleted
| Field | Value |
|---|---|
| **File** | `RULE-14_NSG-Deleted.kql` |
| **Severity** | High |
| **Tactics** | DefenseEvasion |
| **MITRE** | T1562.007 (Disable or Modify Cloud Firewall) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects successful deletion of any Network Security Group by a non-IaC caller. NSG deletion removes perimeter firewall rules, exposing VMs and subnets to unrestricted traffic — a deliberate attacker tactic before lateral movement or data exfiltration. Fires on any single NSG deletion (unlike Rule-11 which requires 10+ resources across multiple types). |
| **Key FP mitigations** | IaC/CI-CD caller patterns excluded; Azure platform IPs excluded; Success-only events |

---

### RULE-15 — Custom Script Extension or Run Command Executed on Virtual Machine
| Field | Value |
|---|---|
| **File** | `RULE-15_VM-Custom-Script-Extension.kql` |
| **Severity** | High |
| **Tactics** | Execution, Persistence |
| **MITRE** | T1059, T1059.009 (Cloud Administration Command) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects deployment of CustomScriptExtension (Windows/Linux) or RunCommand execution on an Azure VM by a non-IaC identity. Both mechanisms execute arbitrary code inside the VM with SYSTEM/root permissions — used by attackers to drop reverse shells, install crypto miners, or stage ransomware without touching OS logins. Detects `CustomScriptExtension`, `CustomScriptForLinux`, `RunCommandHandler`, and `RunCommand` types. |
| **Key FP mitigations** | Known config-management tools excluded (Terraform, Ansible, Chef, Puppet, DSC, pipelines); Azure platform IPs excluded; Success-only; **Azure-managed extension markers filtered** (Monitor/Log Analytics/AMA/OMS/Security/Antimalware/GuestConfiguration/NetworkWatcher/DependencyAgent) | 

---

### RULE-16 — Sentinel Analytics Rule Deleted or Disabled
| Field | Value |
|---|---|
| **File** | `RULE-16_Sentinel-Analytics-Rule-Deleted.kql` |
| **Severity** | High |
| **Tactics** | DefenseEvasion |
| **MITRE** | T1562 (Impair Defenses) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects deletion or bulk modification (disabling) of Microsoft Sentinel Analytics Rules by a non-IaC caller. Attackers with sufficient RBAC privileges delete or disable detection rules to blind the SIEM before further activity. Fires on: (1) any single DELETE of an alert rule; (2) 5+ WRITE operations (bulk rule toggles/edits). Records `DeleteCount` and `ModifyCount` separately. |
| **Key FP mitigations** | IaC/pipeline patterns excluded (DevSecOps pipelines deploying rules via ARM/API are known-good); Azure platform IPs excluded; **WRITE threshold raised 3 → 5** to filter legitimate multi-rule tuning sessions |

---

### RULE-17 — Anomalous Spike in Management Operations (Statistical Baseline Deviation)
| Field | Value |
|---|---|
| **File** | `RULE-17_Anomalous-Management-Operations.kql` |
| **Severity** | Medium |
| **Tactics** | Discovery, Impact, DefenseEvasion |
| **MITRE** | T1078 (Valid Accounts), T1580 (Cloud Infrastructure Discovery) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 14-day lookback |
| **Description** | Detects identities whose current-hour write/delete/action count exceeds their personal 13-day hourly average by ≥3 standard deviations (minimum 30 ops, baseline avg ≥0.5 ops/hr). Uses statistical per-identity baseline rather than hard-coded thresholds — catches compromised credentials performing bulk changes (ransomware staging, data wipe prep, infrastructure abuse) for accounts of any activity level. Requires ≥3 days of baseline history per identity. |
| **Key FP mitigations** | Per-identity 3-sigma threshold (<0.3% FP rate on normal distributions); IaC/pipeline callers excluded; Azure platform IPs excluded; minimum **30 ops/hour** floor (raised from 20 in tuning pass); baseline avg ≥0.5 ops/hr to suppress low-volume identities; read/list/get operations excluded; 3-day minimum history requirement |

---

### RULE-18 — AAD Illicit OAuth Consent Grant with High-Privilege Scope
| Field | Value |
|---|---|
| **File** | `RULE-18_AAD-Illicit-Consent-Grant.kql` |
| **Severity** | High |
| **Tactics** | Persistence, InitialAccess, CredentialAccess |
| **MITRE** | T1528 (Steal Application Access Token) |
| **Tables** | `AuditLogs` |
| **Frequency** | Every 30 minutes / 2-hour lookback |
| **Description** | Detects consent grants (delegated permissions, app role assignments, OAuth2 permission grants) to applications for high-impact scopes: `Mail.Read`/`Mail.Send`, `Files.ReadWrite.All`, `Sites.FullControl.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `full_access_as_app`, `Policy.ReadWrite.ConditionalAccess`, `AuditLog.Read.All`, and ~15 similar scopes. Classic illicit consent grant attack chain used by Midnight Blizzard, Storm-0558, and phishing kits to gain persistent mailbox/file access without stealing passwords. |
| **Key FP mitigations** | Success-only Consent events; IaC/pipeline initiator patterns excluded; Microsoft first-party publisher patterns excluded; only ~20 pre-vetted high-impact scopes trigger (read-only or narrow-scope grants ignored); grants deduplicated per (Initiator, 30-min bin) |

---

### RULE-19 — Sign-in from Anonymizer / Tor IP Followed by Management Operations
| Field | Value |
|---|---|
| **File** | `RULE-19_Anonymizer-Signin-Priv-Ops.kql` |
| **Severity** | High |
| **Tactics** | InitialAccess, DefenseEvasion |
| **MITRE** | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Tables** | `SigninLogs`, `AADServicePrincipalSignInLogs`, `AzureActivity` |
| **Frequency** | Every 30 minutes / 2-hour lookback |
| **Description** | Correlates a successful user or SP sign-in whose `RiskEventTypes` contains `anonymizedIPAddress`/`anonymousIPAddress` (or `RiskLevelAggregated` ∈ {medium, high}) with an Azure management-plane WRITE/DELETE/ACTION from the same IP within 1 hour. Strong indicator of session takeover via Tor/VPN, password-spray success from anonymizer, or stolen refresh-token replay. |
| **Key FP mitigations** | `ResultType == 0` only (failed anonymizer attempts — which are very noisy — excluded); RFC1918 + Azure platform IPs excluded (anonymizer IPs are always public); IaC caller patterns excluded; requires ≥1 mgmt-plane WRITE/DELETE/ACTION within 1h — orphan anonymizer sign-ins do not fire |

---

### RULE-20 — Storage Immutability Policy or Legal Hold Removed
| Field | Value |
|---|---|
| **File** | `RULE-20_Storage-Immutability-Removed.kql` |
| **Severity** | High |
| **Tactics** | Impact, DefenseEvasion |
| **MITRE** | T1490 (Inhibit System Recovery) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects deletion / extension-shortening of blob immutability policies, clearing of legal holds, or bulk BlobServices default-settings deletion. Immutability and legal holds are the primary anti-ransomware / anti-tamper guardrails in Azure Storage — removing them is a pre-cursor to ransomware encryption / mass-delete campaigns (T1490). Complements RULE-11 (mass delete) and RULE-14 (NSG delete) by covering the specific tamper-with-recovery-controls TTP. |
| **Key FP mitigations** | IaC/pipeline/lifecycle-tool caller patterns excluded; Azure platform IPs excluded; success-only |

---

## Hunting Queries (26 Queries)

> **2026-07 hunt pass:** fixed three latent bugs and tuned four thresholds (see **Hunting Tuning & Fixes** below), promoted the 6 former ARM-only hunts to source `.kql` files (HUNT-16–21), and added 5 new hunts (HUNT-22–26). All hunts are kept in sync with the ARM template by [`scripts/Sync-HuntsToArm.ps1`](scripts/Sync-HuntsToArm.ps1).

| File | Display Name | Tactics | MITRE |
|---|---|---|---|
| `HUNT-01_GPU-VM-Deployment-History.kql` | GPU and High-Compute VM Deployment History (90d) | Impact | T1496 |
| `HUNT-02_DiagSettings-Change-Timeline.kql` | Diagnostic Settings Change Timeline per Resource (90d) | DefenseEvasion | T1562.008 |
| `HUNT-03_Storage-Blob-Exfiltration.kql` | Storage Blob High-Volume Read by Single IP (Potential Exfiltration) | Exfiltration | T1530 |
| `HUNT-04_Automation-Runbook-History.kql` | Azure Automation Runbook Create, Modify, Publish History (90d) | Execution, Persistence | T1059.009 |
| `HUNT-05_TI-Management-Plane-Extended.kql` | TI Indicator Match in Azure Management Plane — Extended 90 Days | InitialAccess, Persistence, Impact | T1078, T1098, T1496 |
| `HUNT-06_Orphaned-Privileged-Roles.kql` | Privileged Role Assignments to Disabled/Deleted AAD Identities | Persistence, PrivilegeEscalation | T1098.003 |
| `HUNT-07_Lighthouse-Delegation-Changes.kql` | Azure Lighthouse Delegation Changes (90d) | Persistence | T1098 |
| `HUNT-08_Privileged-Ops-Outside-Hours.kql` | Privileged Operations Outside Business Hours (UTC 07–19) | DefenseEvasion, Persistence | T1078.004 |
| `HUNT-09_New-SP-KeyVault-Access.kql` | Service Principals Accessing Key Vault for the First Time (7d) | CredentialAccess | T1552.001 |
| `HUNT-10_SP-Credential-Rotation-Anomaly.kql` | Service Principal Credential Rotation Anomaly (3+ per hour, 30d) | Persistence, CredentialAccess | T1098.001 |
| `HUNT-11_Storage-Anonymous-SAS-Access-Timeline.kql` | Storage Anonymous and SAS-Token Access Timeline (90d) | Collection, Exfiltration | T1530 |
| `HUNT-12_NSG-Firewall-Change-History.kql` | NSG Deletion and Firewall Rule Modification History (30d) | DefenseEvasion | T1562.007 |
| `HUNT-13_VM-Script-Extension-History.kql` | VM Custom Script Extension and Run Command History (30d) | Execution, Persistence | T1059, T1059.009 |
| `HUNT-14_Sentinel-Config-Changes.kql` | Sentinel Configuration Changes — Rules, Connectors, Automation (30d) | DefenseEvasion | T1562 |
| `HUNT-15_Identity-Ops-Anomaly-DeepDive.kql` | Identity Operation Volume Anomaly Deep-Dive (30d) | Discovery, Impact, DefenseEvasion | T1078, T1580 |
| `HUNT-16_FirstSeen-ResourceProvider-Per-Identity.kql` | First-Seen Azure Resource Provider per Identity (30d) | Discovery, Persistence | T1078, T1580 |
| `HUNT-17_KeyVault-Bulk-Read.kql` | KeyVault Secret or Key Bulk Read (potential dump) | CredentialAccess, Collection | T1552.001, T1555 |
| `HUNT-18_SP-Signin-New-Country.kql` | Service Principal Sign-in from New Country (30d baseline) | InitialAccess | T1078.004 |
| `HUNT-19_Consent-Grant-Burst.kql` | AAD App Consent Grant Burst | Persistence, InitialAccess | T1528 |
| `HUNT-20_Signin-Anomalous-ASN.kql` | Sign-in from Anomalous Network Location (ASN) per Identity (30d) | InitialAccess | T1078.004 |
| `HUNT-21_Caller-IP-Concentration.kql` | Caller IP Concentration Across Many Identities (7d) | LateralMovement, CredentialAccess | T1550 |
| `HUNT-22_Federation-Domain-Trust-Changes.kql` | Federation & Domain Trust Changes (Golden SAML / Persistence) (30d) | Persistence, PrivilegeEscalation, DefenseEvasion | T1484.002, T1556 |
| `HUNT-23_MFA-Auth-Method-Changes.kql` | MFA / Authentication Method Registration Changes (30d) | Persistence, CredentialAccess | T1098.005, T1556.006 |
| `HUNT-24_Guest-Invite-Privileged-Role.kql` | Guest (B2B) Invitation Followed by Privileged Role (30d) | Persistence, PrivilegeEscalation | T1078.004, T1098.003 |
| `HUNT-25_Storage-DataProtection-Changes.kql` | Storage Data-Protection Config Changes: Immutability / Legal Hold / Soft-Delete (30d) | Impact, DefenseEvasion | T1490, T1562 |
| `HUNT-26_Risky-Anonymizer-Signin-Timeline.kql` | Risky & Anonymizer Sign-in Timeline (30d) | InitialAccess, DefenseEvasion | T1078.004, T1090.003 |

### Hunting Tuning & Fixes (2026-07 pass)

| Hunt | Change | Rationale |
|---|---|---|
| HUNT-03 | Read-count floor `500 → 1000/hr`; added `DistinctBlobs ≥ 200` gate; surfaced `RequesterObjectId` + `AuthTypes` | 500 reads/hr is normal for busy app/CDN tiers; the distinct-blob gate catches broad low-byte enumeration; requester/auth breakdown separates anonymous/SAS egress from AAD app reads. |
| HUNT-06 | **Bug fix:** removed `"Update user"` from the disable-detection set | `has_any("…","Update user")` treated *every* profile edit as a disable event, correlating benign updates as "role assigned to disabled identity". Now uses only the authoritative `Disable account` / `Delete user`. |
| HUNT-08 | Made business-hours window configurable; added `OffHoursOpCount ≥ 5` floor | Previously returned *every* off-hours action (huge for global orgs); now surfaces meaningful off-hours bursts. |
| HUNT-09 | **Bug fix:** join on `Caller` **and** `VaultPath` | Previous join on `Caller` only surfaced a caller's long-standing vault B access whenever they newly touched vault A — wrong attribution. |
| HUNT-12 | Parse security-rule body; flag `IsDangerousAllowAny` (inbound Allow, source `*`/Internet, port `*`) | Turns a raw change log into an actionable feed that highlights the actual attacker objective (exposing RDP/SSH/mgmt ports). |
| HUNT-14 | **Bug fix:** `SAVEDEARCHES` → `SAVEDSEARCHES` | The misspelled operation name never matched, so hunting-query deletions were silently invisible in the Sentinel-config timeline. |
| HUNT-15 | Added daily-volume floor (`≥ 15`); low-baseline fallback `10 → 20` | A modest spike from a tiny baseline was surfacing as a large-sigma "anomaly". |
| HUNT-20 | **Bug fix:** ASN now read from `AutonomousSystemNumber` (was `NetworkLocationDetails`) | The former field is not the ASN, so the baseline never matched correctly. |

### New Hunts (HUNT-22–26)

- **HUNT-22 — Federation & Domain Trust Changes** (T1484.002): Golden SAML persistence — added/modified federated domains or token-signing config let an attacker forge SAML tokens for any user (Midnight Blizzard). Rare, review-every-hit.
- **HUNT-23 — MFA / Auth Method Registration Changes** (T1098.005): attacker registering their own MFA method (or removing the victim's) after a session compromise; flags `ActorIsNotTarget` admin-on-behalf-of changes.
- **HUNT-24 — Guest (B2B) Invitation → Privileged Role** (T1078.004/T1098.003): external identity invited then granted a privileged role within 7 days — standing external persistence that survives password resets.
- **HUNT-25 — Storage Data-Protection Config Changes** (T1490): broad companion to RULE-20 — immutability / legal hold / soft-delete / versioning weakening across 30 days, with a `WeakensRecovery` flag.
- **HUNT-26 — Risky & Anonymizer Sign-in Timeline** (T1078.004/T1090.003): broad companion to RULE-19 — successful risky/anonymizer sign-ins across users and workload identities for baselining and low-and-slow hunting.

---

## False Positive Mitigation Strategy

All rules use layered FP mitigations designed for the observed environment:

| Mitigation | Applied in Rules |
|---|---|
| **14-day behavioral baseline** per identity | 01, 05, 09, 11, 12, 17 |
| **IaC/CI-CD caller pattern exclusions** (terraform, bicep, pipeline, github, pulumi, devops, arm-) | 01, 02, 03, 04, 05, 07, 11, 12, 14, 15, 16, 17, 18, 19, 20 |
| **Azure platform IP exclusions** (168.63.x, 169.254.x) | All rules |
| **RFC 1918 private IP exclusions** | 06, 11, 12, 13, 19 |
| **30-minute re-creation window** (handles Terraform destroy+apply) | 02 |
| **PIM / IdentityGovernance / AAD Sync SP exclusions** | 03, 18 |
| **Read-only role GUID exclusions** (Reader, Billing Reader, Directory Reader, Global Reader, Security Reader) | 03 |
| **Minimum threshold + time window** (burst detection) | 03, 04, 09, 10, 11, 12, 13, 16, 17 |
| **TI quality filters** (IsActive, Revoked, IsDeleted, ValidUntil, Confidence ≥75) | 06 |
| **Sign-in corroboration** (SigninLogs + AADServicePrincipalSignInLogs) | 06, 11, 12, 19 |
| **Statistical σ-deviation** (3-sigma per-identity hourly baseline, avg ≥0.5 ops/hr) | 17 |
| **HTTP 200 response filter** (confirmed successful data access only) | 13 |
| **Same-IP correlation across audit events** | 08 |
| **Exact-match role names** (avoids `Contributor` substring matching e.g. `Storage Blob Data Contributor`) | 08 |
| **Azure-managed extension marker exclusion** (AMA/OMS/Antimalware/GuestConfig/NetworkWatcher) | 15 |
| **Only pre-vetted high-impact OAuth scopes trigger** | 18 |
| **Requires post-signin management-plane action** (orphan sign-ins ignored) | 19 |
| **Success-only activity status** | All rules |

---

## Tuning History (2026-07 pass — noise reduction + new detections)

Thresholds were revised based on 90 days of alert triage across the LAWSentinel workspace.
All changes are applied to both the standalone `.kql` files and the ARM template `query`
fields — kept in sync by [`scripts/Sync-KqlToArm.ps1`](scripts/Sync-KqlToArm.ps1).

| Rule | Change | Rationale |
|---|---|---|
| RULE-03 | `AssignmentCount >= 5` → `>= 8`; added role/principal-diversity gate (≥2 roles or ≥3 principals); added `Directory Reader` / `Global Reader` GUIDs to exclusion; added `azure ad sync` / `aad connect` initiator excludes | Scripted single-role grants to many SPs (e.g. Contributor to a batch of automation identities) were the largest FP source. |
| RULE-04 | **Noise pass 1:** `SASGenerationCount >= 3` → `>= 5` (or 3+ across ≥2 accounts); added `azurewebsites`, `azurecdn`, `datafactory`, `synapse`, `azcopy` exclusions. **Noise pass 2:** added a 14-day recurring-generator baseline (callers minting SAS on ≥3 distinct days suppressed); raised burst floors to 8 (or 5 across ≥3 accounts); `queryPeriod` PT2H → P14D | Backup/PaaS-integration SPs re-issue SAS constantly. A live alert (`3 tokens by <GUID>`) fired from a recurring automation SP via the loose cross-account branch — the baseline now suppresses these while keeping new/anomalous callers in scope. |
| RULE-08 | Role match tightened from `has_any` (loose substring) to `in~` on 11 exact role names; added same-source-IP correlation between cred-add and role-assign | `has_any("Contributor")` incorrectly matched roles like `Storage Blob Data Contributor`. NAT-based initiator coincidence produced additional FPs. |
| RULE-09 | Added `OperationCount >= 3 or DistinctOps >= 2` filter | Previously fired on any single privileged op from a new IP; legitimate admins reconnecting from home often produced single-op alerts. |
| RULE-10 | `MGMTOpCount >= 2` → `>= 3` | 2-op threshold hit on opportunistic single-token replays that returned harmless outcomes. |
| RULE-11 | `DeleteThreshold = 10` → `15`; **`queryPeriod` PT3H → P14D** so the `KnownBulkDeleters` baseline (needs `DaysActive >= 5` over 14 days) actually receives data | Environment teardowns of dev subscriptions crossed 10; 15+ deletions across ≥2 resource types remains a strong ransomware/insider signal. The short period previously starved the 14-day baseline, so the "exclude established bulk-deleters" mitigation was silently inert — established deleters were not being suppressed. |
| RULE-12 | **`queryPeriod` PT4H → P14D** so the `KnownCreators` 14-day baseline receives data | Same latent bug as RULE-11: the zero-history qualifier could not function with a 4-hour period, so established creators were not excluded. |
| RULE-13 | Anon `>= 5` → `>= 10`; SAS `>= 50 MB` → `>= 500 MB` with `or DistinctBlobs >= 50` | Legacy public containers hosting static assets produced constant low-volume anon reads; backup jobs regularly crossed 50 MB. |
| RULE-15 | Added `BenignExtensionMarkers` exclusion (AMA/OMS/Antimalware/GuestConfig/NetworkWatcher/DependencyAgent) | Azure managed extension re-writes on VM update produced hundreds of FPs. |
| RULE-16 | `ModifyCount >= 3` → `>= 5` | SOC tuning sessions commonly touch 3-4 rules; DELETE trigger unchanged. |
| RULE-17 | `MinOpsThreshold = 20` → `30`; new `MinAvgOpsPerHour = 0.5`; dropped fallback that fired on tiny baselines | Low-volume identities with sub-1-op/hr baselines produced misleading sigma scores. |
| **NEW RULE-18** | AAD Illicit OAuth Consent Grant | Fills the T1528 gap — illicit consent phishing (Storm-0558 / Midnight Blizzard) previously not covered by any custom or built-in rule in this workspace. |
| **NEW RULE-19** | Anonymizer / Tor sign-in + follow-on mgmt ops | Chains AAD anonymizer risk with actual management-plane impact — dramatically lower FP rate than firing on the sign-in alone. |
| **NEW RULE-20** | Storage immutability policy / legal hold removed | Fills the T1490 (Inhibit System Recovery) gap — direct anti-ransomware guardrail tampering, not caught by RULE-11 (mass delete) or RULE-14 (NSG delete). |

### Sync workflow

Edit the `.kql` files under `AnalyticRules/` and then run:

```powershell
pwsh -File scripts/Sync-KqlToArm.ps1
```

The script strips comment headers, injects the standard `_AllowIP =
coalesce(...)` + `ExcludeAllowlistedIPs_AzureCustom(_AllowIP)` filter after every
`| where TimeGenerated ...` clause, JSON-encodes the result, and rewrites the
`query` field for every matching `"comments": "RULE-XX | ..."` block in the ARM
template. The root duplicate `Azure-Sentinel-CustomDetections.json` is
mirrored automatically.

To add a new rule, drop a `RULE-NN_*.kql` file in `AnalyticRules/`, add an ARM
resource block for it (see `scripts/Add-NewArmRules.ps1` for the pattern), then
re-run the sync script.

---


---

## Data Tables Required

| Table | Used by |
|---|---|
| `AzureActivity` | RULE-01 through 05, 07, 09, 11–17, 19–20; HUNT-01,02,04,06,07,08,12,13,14,15 |
| `AuditLogs` | RULE-08, 18; HUNT-06, 10 |
| `StorageBlobLogs` | RULE-04, 13; HUNT-03, 11 |
| `SigninLogs` | RULE-06, 11, 12, 19 |
| `AADServicePrincipalSignInLogs` | RULE-06, 10, 11, 12, 19 |
| `ThreatIntelIndicators` (STIX 2.1) | RULE-06, HUNT-05 |

---

## Notes

- **HUNT-05** uses the `ThreatIntelIndicators` (STIX 2.1) table with a lower confidence threshold (≥50) and no `IsActive`/`Revoked` filter, providing a wider 90-day retroactive hunting net. `IsActive` and `Revoked` are surfaced as output columns so analysts can assess indicator state without pre-filtering it out.
- **RULE-06** exclusively uses `ThreatIntelIndicators` (STIX 2.1) with `ObservableKey =~ "ipv4-addr:value"` for IP extraction.
- All GUIDs in the ARM template are fixed (not generated at deploy time) to ensure idempotent re-deployments.
