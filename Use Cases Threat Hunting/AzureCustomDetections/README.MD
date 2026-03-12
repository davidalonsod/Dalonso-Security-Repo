# Azure — Custom Detections Package

> **Workspace:** `xxxxx`  
> **Created:** March 9, 2026  
> **Status:** Testing-ready (ARM template validated)

Custom analytic rules and hunting queries for Microsoft Sentinel that **do not duplicate any confirmed live built-in detections** in the workspace. All rules are grounded in live table schema discovery, real AzureActivity operation names observed in the environment, and comprehensive false-positive mitigations.


## Folder Structure

```
AzureSentinelCustomDetections/
├── README.md                          ← This file
├── ARM-Template/
│   └── Azure-Sentinel-CustomDetections.json   ← Deploy all rules at once
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
│   └── RULE-17_Anomalous-Management-Operations.kql
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
    └── HUNT-15_Identity-Ops-Anomaly-DeepDive.kql
```

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Connected to `xxxxxx` workspace |
| Data connectors | Azure Activity, Azure Active Directory (Sign-in Logs, Audit Logs, Service Principal Sign-in Logs), Storage Blob Logs, Microsoft Threat Intelligence |
| Tables required | `AzureActivity`, `AuditLogs`, `StorageBlobLogs`, `SigninLogs`, `AADServicePrincipalSignInLogs`, `ThreatIntelIndicators` (STIX 2.1) |
| ARM API version | `2023-02-01-preview` (alertRules), `2020-08-01` (savedSearches) |
| Permissions (deploy) | Microsoft Sentinel Contributor + Log Analytics Contributor |


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

### PowerShell
```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<YOUR-RESOURCE-GROUP>" `
  -TemplateFile "ARM-Template\Azure-Sentinel-CustomDetections.json" `
  -workspaceName "LAWSentinel"
```


## Analytic Rules (17 Rules)

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


### RULE-03 — Mass Privileged Role Assignments by Single Identity
| Field | Value |
|---|---|
| **File** | `RULE-03_Mass-Privileged-Role-Assignments.kql` |
| **Severity** | High |
| **Tactics** | PrivilegeEscalation, Persistence |
| **MITRE** | T1098.003 (Add Office 365 Global Administrator Role) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 30 minutes / 1-hour lookback |
| **Description** | Triggers when a single identity assigns 5+ non-read-only roles within a 30-minute window. Used by LAPSUS$ and Storm-0501 for rapid bulk privilege escalation post-compromise. |
| **Key FP mitigations** | PIM service principal excluded; read-only role GUIDs excluded; threshold of 5+ in 30 min; Azure platform IPs excluded |


### RULE-04 — Storage SAS Token Bulk Generation
| Field | Value |
|---|---|
| **File** | `RULE-04_Storage-SAS-Token-Bulk-Generation.kql` |
| **Severity** | Medium |
| **Tactics** | DefenseEvasion, LateralMovement |
| **MITRE** | T1550 (Use Alternate Authentication Material) |
| **Tables** | `AzureActivity`, `StorageBlobLogs` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects bulk generation of SAS tokens (ListAccountSAS / ListServiceSAS) — 3+ in 30 minutes by a single identity. Attackers use SAS tokens as alternative credentials to exfiltrate data without standard AAD sign-in traces. |
| **Key FP mitigations** | Backup/monitor SP patterns excluded; threshold of 3+ in 30 min; correlated with StorageBlobLogs for blob read confirmation |


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


### RULE-08 — Service Principal Credential Added Then Privileged Role Assigned
| Field | Value |
|---|---|
| **File** | `RULE-08_SP-Credential-Added-Privileged-Role.kql` |
| **Severity** | High |
| **Tactics** | Persistence, PrivilegeEscalation |
| **MITRE** | T1098.001 (Additional Cloud Credentials) |
| **Tables** | `AuditLogs` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects the "backdoor SP" attack chain — same initiator adds a credential to a service principal AND assigns it a privileged role (Owner, Contributor, Global Admin, etc.) within 60 minutes. Used by Storm-0501 and Midnight Blizzard for persistent privileged access. Distinct from the built-in "First access credential added to App" which does not require the role-escalation correlation. |
| **Key FP mitigations** | Only high-privilege role names trigger; 60-min correlation window; requires same Initiator for both events |


### RULE-09 — Privileged Management Ops from New Source IP
| Field | Value |
|---|---|
| **File** | `RULE-09_Privileged-Ops-New-IP.kql` |
| **Severity** | Medium |
| **Tactics** | InitialAccess, Persistence |
| **MITRE** | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 6 hours / 14-day lookback |
| **Description** | Azure management-plane equivalent of Impossible Travel. Detects established identities (active in last 14 days) performing privileged operations (IAM, KV, VM, diagnostics, runbooks) from an IP not seen in their 14-day history. |
| **Key FP mitigations** | Per-identity 14-day IP whitelist with `set_has_element`; Azure platform IPs excluded; only privileged operation types; new identities (no baseline) handled by Rule-01/05 instead |


### RULE-10 — Service Principal CA Bypass Sign-in Then Management Ops
| Field | Value |
|---|---|
| **File** | `RULE-10_SP-CA-Bypass-Management-Ops.kql` |
| **Severity** | High |
| **Tactics** | InitialAccess, CredentialAccess |
| **MITRE** | T1528, T1078 |
| **Tables** | `AADServicePrincipalSignInLogs`, `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects SP sign-in with Conditional Access status `failure` or `notApplied` (CA bypass) but `ResultType=0` (succeeded), followed by 2+ Azure management operations from the same IP within 1 hour. Indicates stolen SP tokens or credential abuse bypassing CA policies. |
| **Key FP mitigations** | `ResultType=0` required; minimum 2 management ops; platform IPs excluded; 1-hour tight temporal window reduces NAT coincidences |


### RULE-11 — Mass Deletion of Critical Resources
| Field | Value |
|---|---|
| **File** | `RULE-11_Mass-Resource-Deletion.kql` |
| **Severity** | High |
| **Tactics** | Impact, DefenseEvasion |
| **MITRE** | T1485 (Data Destruction), T1562 |
| **Tables** | `AzureActivity`, `SigninLogs`, `AADServicePrincipalSignInLogs` |
| **Frequency** | Every 1 hour / 3-hour lookback |
| **Description** | Detects bulk deletion of critical Azure infrastructure (NSGs, VMs, Storage Accounts, VNETs, Subnets, Disks, Key Vaults, App Gateways, Load Balancers) — 10+ deletions across 2+ resource types within 1 hour. Characteristic of ransomware pre-staging and insider destruction attacks. Correlated with sign-in risk levels from SigninLogs and AADServicePrincipalSignInLogs. |
| **Key FP mitigations** | Threshold of 10+ deletions + 2+ resource types; 14-day baseline excludes established bulk-deleters (avg ≥10/day for ≥5 days); IaC/pipeline patterns excluded; SigninLogs risk enrichment (`SigninRiskLevel`, `HasSigninCorroboration`) |


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


### RULE-13 — Storage Account Accessed Anonymously or via SAS from Public Internet
| Field | Value |
|---|---|
| **File** | `RULE-13_Storage-Anonymous-Public-Access.kql` |
| **Severity** | Medium |
| **Tactics** | Collection, Exfiltration |
| **MITRE** | T1530 (Data from Cloud Storage Object) |
| **Tables** | `StorageBlobLogs` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects blob reads from public IPs using Anonymous or SAS-Token authentication. Anonymous blob access is disabled by default in new accounts but may exist in legacy deployments; SAS tokens are frequently abused post-compromise to exfiltrate data without AAD traces. Triggers at 5+ anonymous requests or >50 MB via SAS from a single public IP. |
| **Key FP mitigations** | RFC 1918 and Azure platform IPs excluded; Anonymous threshold of 5+ requests; SAS threshold of 50 MB; HTTP 200 only; private IP ranges (10.x, 172.16-31.x, 192.168.x) fully excluded |


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
| **Key FP mitigations** | Known config-management tools excluded (Terraform, Ansible, Chef, Puppet, DSC, pipelines); Azure platform IPs excluded; Success-only | 


### RULE-16 — Sentinel Analytics Rule Deleted or Disabled
| Field | Value |
|---|---|
| **File** | `RULE-16_Sentinel-Analytics-Rule-Deleted.kql` |
| **Severity** | High |
| **Tactics** | DefenseEvasion |
| **MITRE** | T1562 (Impair Defenses) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 2-hour lookback |
| **Description** | Detects deletion or bulk modification (disabling) of Microsoft Sentinel Analytics Rules by a non-IaC caller. Attackers with sufficient RBAC privileges delete or disable detection rules to blind the SIEM before further activity. Fires on: (1) any single DELETE of an alert rule; (2) 3+ WRITE operations (bulk rule toggles/edits). Records `DeleteCount` and `ModifyCount` separately. |
| **Key FP mitigations** | IaC/pipeline patterns excluded (DevSecOps pipelines deploying rules via ARM/API are known-good); Azure platform IPs excluded; WRITE threshold of 3 to filter individual rule tuning |


### RULE-17 — Anomalous Spike in Management Operations (Statistical Baseline Deviation)
| Field | Value |
|---|---|
| **File** | `RULE-17_Anomalous-Management-Operations.kql` |
| **Severity** | Medium |
| **Tactics** | Discovery, Impact, DefenseEvasion |
| **MITRE** | T1078 (Valid Accounts), T1580 (Cloud Infrastructure Discovery) |
| **Tables** | `AzureActivity` |
| **Frequency** | Every 1 hour / 14-day lookback |
| **Description** | Detects identities whose current-hour write/delete/action count exceeds their personal 13-day hourly average by ≥3 standard deviations (minimum 20 ops). Uses statistical per-identity baseline rather than hard-coded thresholds — catches compromised credentials performing bulk changes (ransomware staging, data wipe prep, infrastructure abuse) for accounts of any activity level. Requires ≥3 days of baseline history per identity. |
| **Key FP mitigations** | Per-identity 3-sigma threshold (<0.3% FP rate on normal distributions); IaC/pipeline callers excluded; Azure platform IPs excluded; minimum 20 ops/hour floor; read/list/get operations excluded; 3-day minimum history requirement |


## Hunting Queries (15 Queries)

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


## False Positive Mitigation Strategy

All rules use layered FP mitigations designed for the observed environment:

| Mitigation | Applied in Rules |
|---|---|
| **14-day behavioral baseline** per identity | 01, 05, 09, 11, 12, 17 |
| **IaC/CI-CD caller pattern exclusions** (terraform, bicep, pipeline, github, pulumi, devops, arm-) | 01, 02, 03, 04, 05, 07, 11, 12, 14, 15, 16, 17 |
| **Azure platform IP exclusions** (168.63.x, 169.254.x) | All rules |
| **RFC 1918 private IP exclusions** | 06, 11, 12, 13 |
| **30-minute re-creation window** (handles Terraform destroy+apply) | 02 |
| **PIM service principal exclusions** (ms-pim, privilegedidentity) | 03 |
| **Read-only role GUID exclusions** | 03 |
| **Minimum threshold + time window** (burst detection) | 03, 04, 11, 12, 13, 17 |
| **TI quality filters** (IsActive, Revoked, IsDeleted, ValidUntil, Confidence ≥75) | 06 |
| **Sign-in corroboration** (SigninLogs + AADServicePrincipalSignInLogs) | 06, 11, 12 |
| **Statistical σ-deviation** (3-sigma per-identity hourly baseline) | 17 |
| **HTTP 200 response filter** (confirmed successful data access only) | 13 |
| **Success-only activity status** | All rules |


## Data Tables Required

| Table | Used by |
|---|---|
| `AzureActivity` | RULE-01 through 05, 07, 09, 11–17; HUNT-01,02,04,06,07,08,12,13,14,15 |
| `AuditLogs` | RULE-08; HUNT-06, 10 |
| `StorageBlobLogs` | RULE-04, 13; HUNT-03, 11 |
| `SigninLogs` | RULE-06, 11, 12 |
| `AADServicePrincipalSignInLogs` | RULE-06, 10, 11, 12 |
| `ThreatIntelIndicators` (STIX 2.1) | RULE-06, HUNT-05 |


