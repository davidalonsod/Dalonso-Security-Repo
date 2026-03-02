# 🛡️ Microsoft Sentinel Security Analysis — 12-Month Threat Detection

A comprehensive Jupyter Notebook that queries the **Microsoft Sentinel Data Lake** across a fixed 12-month window, delivering threat detection, threat hunting, forensic investigation, and executive reporting — all from a single interactive notebook.

**Designed for:** SOC analysts · Threat hunters · CISO-level reporting

---

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Authentication](#authentication)
- [Analysis Sections](#analysis-sections)
- [Data Sources](#data-sources)
- [MITRE ATT\&CK Coverage](#mitre-attck-coverage)
- [SOC KPI Targets](#soc-kpi-targets)
- [Dashboards & Reporting](#dashboards--reporting)
- [Known Issues & Bug Fixes](#known-issues--bug-fixes)
- [Data Tables Reference](#data-tables-reference)

---

## Overview

| Property | Value |
|---|---|
| **Notebook file** | `Sentinel-Security-Analysis-6Month.ipynb` |
| **Analysis window** | 2025-02-20 → 2026-02-20 (rolling 12 months) |
| **Query engine** | Azure Monitor REST API via `azure-monitor-query` |
| **Visualizations** | Interactive Plotly charts + HTML tables (renders in VS Code & JupyterLab) |
| **Total sections** | 20 analysis modules + forensic hub + 4 executive dashboards |

| Capability | Description |
|---|---|
| 🔍 **Threat Detection** | Brute force, password spray, IOC matching, lateral movement, statistical anomaly detection |
| 🎯 **Threat Hunting** | On-prem identity (AD/DC), Azure environment, Defender for Office 365 full suite |
| 🔬 **Forensics** | Deep-dive IP, device, and identity pivot investigations |
| 📊 **SOC Dashboard** | MTTD, alert fidelity, severity trends, provider breakdown |
| 🏢 **CISO Dashboard** | Risk gauge (RAG), business risk areas, compliance gaps, top-5 recommendations |
| 🧩 **MITRE Heatmap** | Detection coverage mapped across 22 techniques / 8 tactics |
| 📝 **Executive Summary** | Auto-generated plain-text briefing narrative |

---

## Prerequisites

- **Python 3.9+** (tested on 3.14)
- **VS Code** with the [Jupyter extension](https://marketplace.visualstudio.com/items?itemName=ms-toolsai.jupyter), or JupyterLab
- **Azure access** with read permissions to a Microsoft Sentinel Log Analytics workspace
- One of the following authentication setups:
  - Azure CLI (`az login`) — recommended
  - Interactive browser login
  - Device code flow *(default — works when browser popups are blocked)*
  - Service Principal (client ID + secret)

---

## Installation & Setup

1. **Open the notebook in VS Code**

   ```bash
   code Sentinel-Security-Analysis-6Month.ipynb
   ```

2. **Select a Python kernel** — use the kernel picker in the top-right corner of VS Code.

3. **Run Cell 1 (Setup)** — it auto-installs all required packages into the selected kernel:

   | Package | Purpose |
   |---|---|
   | `azure-monitor-query` | Execute KQL queries against Log Analytics |
   | `azure-identity` | Azure authentication credential providers |
   | `pandas` | Data manipulation and tabular output |
   | `numpy` | Numerical operations, z-score calculations |
   | `plotly` | Interactive charts and heatmaps |
   | `matplotlib` | Static chart fallback |
   | `scipy` | Statistical spike detection |

   Or install manually:

   ```bash
   pip install azure-monitor-query azure-identity pandas numpy plotly matplotlib scipy
   ```

---

## Authentication

Edit the configuration block in the **Setup & Authentication** cell:

```python
WORKSPACE_ID = "your-log-analytics-workspace-guid"
TENANT_ID    = "your-azure-tenant-guid"
AUTH_METHOD  = "device_code"   # change to preferred method
```

| `AUTH_METHOD` | Description |
|---|---|
| `"default"` | Tries `az login` → VS Code credential → environment variables |
| `"browser"` | Opens an interactive browser popup |
| `"device_code"` | Prints a code + URL — no browser popup required *(default)* |
| `"service_principal"` | Non-interactive; requires `CLIENT_ID` + `CLIENT_SECRET` |

**Recommended quick start:**

```bash
az login --tenant <your-tenant-id>
```

Then set `AUTH_METHOD = "default"` and run the Setup cell.

---

## Analysis Sections

### 🔐 Identity & Credential Attacks

| # | Section | Key Detections | Primary Tables |
|---|---|---|---|
| **1** | Setup & Authentication | Workspace config, auth helper, `run_kql()` utility | — |
| **2** | Data Source Availability | Table presence check across 19 sources | All |
| **3** | Brute Force Detection | High-frequency failed sign-ins per user/IP | SigninLogs, AADNonInteractiveUserSignInLogs |
| **3.1** | Success After Failure | Successful login following a brute force pattern | SigninLogs |
| **4** | Password Spray | Single IP → many accounts; distributed botnet spray | SigninLogs, AADNonInteractiveUserSignInLogs |
| **5** | Risky Users & Sign-ins | AAD Identity Protection risk correlation | AADRiskyUsers, AADUserRiskEvents, RiskySignIns |
| **5.1** | Geolocation Analysis | Sign-in map, country breakdown, multi-country sessions | SigninLogs |
| **6** | Baseline Anomaly Detection | Z-score time-series, 3σ spike detection | SigninLogs |

### 🧨 Threat Intelligence Correlation (11 Tables)

| # | Section | Entity Type | Tables |
|---|---|---|---|
| **7** | IOC Matching — Full Spectrum | All entity types | ThreatIntelligenceIndicator + all |
| **7.1** | → IP Address IOC | IPv4/IPv6 addresses | DeviceNetworkEvents, DeviceLogonEvents, SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AuditLogs, AzureActivity, IdentityLogonEvents, IdentityDirectoryEvents, CloudAppEvents, SecurityAlert |
| **7.2** | → File Hash IOC | SHA256 / SHA1 / MD5 | DeviceFileEvents, DeviceProcessEvents, EmailAttachmentInfo |
| **7.3** | → Domain / Hostname IOC | DNS, LDAP, email sender, UPN | DeviceNetworkEvents, IdentityQueryEvents, EmailEvents, SigninLogs, AuditLogs |
| **7.4** | → URL IOC | Web requests, Safe Links, email URLs | DeviceNetworkEvents, UrlClickEvents, EmailUrlInfo, CloudAppEvents |
| **7.5** | → Process / Command-line IOC | Image hash + LOLBin patterns | DeviceProcessEvents, SecurityAlert |
| **7.6** | → Email / Collaboration IOC | Sender IP/address, attachment hashes, Teams | EmailEvents, EmailAttachmentInfo, CloudAppEvents |
| **7.7** | → IOC Summary | Hit-count pivot, source heatmap, stacked bar | All TI |
| **7.8** | → Threat Actor & Analytics | TI actor grouping, UEBA BehaviorAnalytics | ThreatIntelligenceIndicator, SecurityAlert, BehaviorAnalytics |

### 🔄 Lateral Movement & Endpoint

| # | Section | Key Detections | Primary Tables |
|---|---|---|---|
| **8** | Lateral Movement Detection | Accounts on many devices, pass-the-hash / ticket | DeviceLogonEvents |
| **8.1** | Lateral Device Propagation | Device-to-device connection analysis | DeviceNetworkEvents |
| **8.2** | Recon Tool Detection | LOLBin discovery (nltest, dsquery, nmap…) | DeviceProcessEvents |

### 🚨 Alerts & Cloud Apps

| # | Section | Key Detections | Primary Tables |
|---|---|---|---|
| **9** | Defender Alerts | High/medium fidelity alert enrichment by provider | SecurityAlert |
| **9.1** | Alert Enrichment | Cross-correlate alerts with IOC hits, risky users, geo | SecurityAlert + multiple |
| **9.2** | Cloud App Correlation | CloudAppEvents anomaly and OAuth abuse detection | CloudAppEvents |
| **10** | Spike Detection | Statistical spike vs 180-day baseline | SigninLogs |
| **10.1** | Identity Alerts | IdentityInfo + IdentityLogonEvents fusion | IdentityLogonEvents, IdentityInfo |
| **10.2** | Malicious OAuth Apps & Service Principals | Consent grant abuse, SP geo anomalies, credential abuse | AuditLogs, AADServicePrincipalSignInLogs |

### 📧 Defender for Office 365

| # | Section | Key Detections | Primary Tables |
|---|---|---|---|
| **11** | MDO Threat Hunting Suite | Full coverage | EmailEvents, EmailAttachmentInfo, CloudAppEvents |
| **11.1** | → Spam & Phishing | Blocked/quarantined email, sender geo, category breakdown | EmailEvents |
| **11.2** | → Email Malware | Attachment detonation, delivered malware, malware families | EmailAttachmentInfo, EmailEvents |
| **11.3** | → Teams / SharePoint / OneDrive Malware | FileMalwareDetected, AntiVirus events | CloudAppEvents |
| **11.4** | → Business Email Compromise (BEC) | Suspicious inbox rules, external forwarding | AuditLogs, EmailEvents |
| **11.5** | → Adversary-in-the-Middle (AiTM) | MFA-bypass sign-ins, phishing link correlation | SigninLogs, UrlClickEvents |

### 🔬 Forensic Investigation Hub

| # | Section | Description | Tables |
|---|---|---|---|
| **12** | Forensic Hub | Set a target entity and pivot across all data | All |
| **12.1** | → IP Forensics | Full activity timeline for a single IP | SigninLogs, DeviceNetworkEvents, EmailEvents, TI |
| **12.2** | → Device Forensics | Logons, processes, file changes, network, alerts | DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, SecurityAlert |
| **12.3** | → Identity Forensics | Sign-ins, audit, risk events, device logons, email | SigninLogs, AuditLogs, AADRiskyUsers, EmailEvents |

### 🏛️ On-Prem Identity & Domain Controllers

| # | Section | Technique | Tables |
|---|---|---|---|
| **16** | On-Prem Threat Hunting | Full on-prem AD/DC coverage | SecurityEvent, IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents |
| **16.1** | → Kerberoasting / AS-REP Roasting | RC4 TGS/TGT requests — T1558.003/004 | SecurityEvent (4768/4769) |
| **16.2** | → DCSync / Directory Replication | Replication GUID monitoring — T1003.006 | IdentityDirectoryEvents, SecurityEvent (4662) |
| **16.3** | → LDAP Recon / BloodHound-style | Mass LDAP/SAMR queries — T1087.002 | IdentityQueryEvents |
| **16.4** | → NTLM Relay & Pass-the-Hash | Multi-device NTLM from single identity — T1550.002 | IdentityLogonEvents, SecurityEvent (4776) |
| **16.5** | → Privileged Group Changes | Domain Admins / Enterprise Admins additions — T1098 | SecurityEvent (4728/4732/4756) |
| **16.6** | → Suspicious Processes on DCs | MDI attack category alerts (DCSync, Golden Ticket, Skeleton Key) | IdentityDirectoryEvents |

### ☁️ Azure Environment Threat Hunting

| # | Section | Technique | Tables |
|---|---|---|---|
| **17** | Azure Threat Hunting | Full Azure control-plane coverage | AzureActivity, AzureDiagnostics |
| **17.1** | → Cryptojacking | GPU/HPC VM deployments — T1496 | AzureActivity |
| **17.2** | → Privilege Escalation | Owner/UAA role assignment — T1098.003 | AzureActivity, AuditLogs |
| **17.3** | → Mass Resource Deletion | Bulk DELETE pattern (ransomware/sabotage) — T1485 | AzureActivity |
| **17.4** | → Key Vault Enumeration | High-volume SecretGet/List — T1552.001 | AzureDiagnostics |
| **17.5** | → Storage Exfiltration | Anonymous / SAS blob reads — T1530 | AzureDiagnostics |
| **17.6** | → Impossible Travel (Azure Mgmt) | CallerIpAddress geo velocity — T1078.004 | AzureActivity |
| **17.7** | → Suspicious Automation Deployments | Automation Accounts, Runbooks, Logic Apps — T1059.009 | AzureActivity |

### 📊 Dashboards & Reporting

| # | Section | Audience |
|---|---|---|
| **13** | SOC KPI Dashboard | SOC Manager — MTTD, alert volume, TP rate, provider breakdown |
| **14** | CISO Dashboard | CISO / Executive — Risk gauge (RAG), compliance gaps, top-5 recommendations |
| **15** | MITRE ATT&CK Heatmap | Red/Blue Team — 22 techniques across 8 tactics |
| **18** | Summary Dashboard | All — interactive chart grid across every section |
| **19** | Data Volume | Engineering — ingestion volume per table |
| **20** | Executive Summary | C-Suite — auto-generated plain-text briefing |

---

## Data Sources

| Category | Tables |
|---|---|
| **Azure AD** | SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AuditLogs |
| **Identity Protection** | AADRiskyUsers, AADUserRiskEvents, RiskySignIns |
| **Behavior Analytics** | BehaviorAnalytics |
| **Threat Intelligence** | ThreatIntelligenceIndicator |
| **Defender for Cloud Apps** | CloudAppEvents |
| **Defender for Identity (MDI)** | IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents, IdentityInfo |
| **Defender for Endpoint (MDE)** | DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceFileEvents |
| **Defender for Office 365 (MDO)** | EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents |
| **On-Prem / Windows Security** | SecurityEvent (4624, 4648, 4662, 4768, 4769, 4771, 4776, 4728, 4732, 4756) |
| **Azure Control Plane** | AzureActivity, AzureDiagnostics |
| **Sentinel Core** | SecurityAlert, SecurityIncident |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|---|---|
| **TA0001 Initial Access** | T1566, T1566.001, T1566.002, T1078, T1078.004 |
| **TA0003 Persistence** | T1098, T1098.003, T1059.009 |
| **TA0004 Privilege Escalation** | T1098.003, T1548 |
| **TA0005 Defense Evasion** | T1078.004, T1550.002 |
| **TA0006 Credential Access** | T1110, T1110.003, T1539, T1557, T1558.003, T1558.004, T1003.006, T1552.001 |
| **TA0007 Discovery** | T1087, T1087.002, T1083, T1046 |
| **TA0008 Lateral Movement** | T1021, T1550, T1550.002 |
| **TA0009 Collection** | T1114, T1213, T1530 |
| **TA0010 Exfiltration** | T1048, T1567, T1530 |
| **TA0011 C2** | T1071, T1102 |
| **TA0040 Impact** | T1486, T1485, T1496, T1565 |

---

## SOC KPI Targets

| KPI | Target | Description |
|---|---|---|
| **MTTD** | < 4 h | Mean Time to Detect |
| **High + Medium Signal Rate** | > 30% | Alert quality ratio |
| **Credential Attack Trend** | ↓ 0 | Brute force + spray volume |
| **IOC Hit Rate** | 0 | Confirmed TI matches |
| **Risky Users** | ↓ | Active high-risk identities |

---

## Known Issues & Bug Fixes

| Section | Fix Applied |
|---|---|
| **Process IOC (§7.5)** | `SEM0100: MaxConfidence` — `ConfidenceScore` is dynamic in TI; added schema-anchor `datatable` + `column_ifexists()` |
| **Spam/Phishing (§11.1)** | `SEM0100: PhishFilterVerdict` / `SpamFilterVerdict` — optional columns; wrapped with `column_ifexists()` |
| **Email Malware (§11.2)** | `SEM0100: MalwareFamily`, `DetectionMethods`, `FileType` — optional columns; wrapped with `column_ifexists()` |
| **Threat Actor (§7.8)** | `SEM0100: IndicatorType` dynamic + `DeviceName` missing from UEBA; used `tostring(column_ifexists())`, removed `dcount(DeviceName)`, fixed `array_length(ActivityInsights) > 0` |
| **MITRE ATT&CK (§15)** | Missing `import plotly.graph_objects as go`; rebuilt via cell delete + insert |
| **OAuth / SP (§10.2)** | `SEM0100: IsHighRisk` out-of-scope after `project` — moved `order by` before `project` |
| **IOC Matching (§7.1–7.6)** | Expanded from 6 to 11+ tables per entity type; all use `union isfuzzy=true` to handle unavailable tables gracefully |

---

## Data Tables Reference

| Table | Description | Key Fields |
|---|---|---|
| **SigninLogs** | Interactive user sign-ins | UserPrincipalName, ResultType, IPAddress, Location |
| **AADNonInteractiveUserSignInLogs** | Non-interactive sign-ins | UserPrincipalName, ResultType, AppDisplayName |
| **AADServicePrincipalSignInLogs** | Service principal sign-ins | ServicePrincipalId, ResultType |
| **AuditLogs** | Azure AD audit events | OperationName, InitiatedBy, TargetResources |
| **AADRiskyUsers** | Users flagged as risky | UserPrincipalName, RiskLevel, RiskState |
| **AADUserRiskEvents** | Individual risk events | UserPrincipalName, RiskEventType |
| **RiskySignIns** | Sign-ins with risk | UserPrincipalName, RiskLevel, IpAddress |
| **CloudAppEvents** | Cloud app activity | AccountDisplayName, ActionType, Application |
| **DeviceLogonEvents** | Device logon events | DeviceName, AccountName, LogonType |
| **DeviceNetworkEvents** | Network connections | DeviceName, RemoteIP, RemotePort |
| **DeviceProcessEvents** | Process execution | DeviceName, FileName, ProcessCommandLine |
| **DeviceFileEvents** | File system events | DeviceName, FileName, SHA256 |
| **IdentityLogonEvents** | MDI logon events | AccountName, DeviceName, Protocol |
| **IdentityQueryEvents** | MDI query events | AccountName, QueryType |
| **IdentityDirectoryEvents** | MDI directory events | ActionType, TargetAccountName, DeviceName |
| **IdentityInfo** | User identity attributes | AccountName, Department, JobTitle, IsAccountEnabled |
| **SecurityAlert** | Security alerts | AlertName, AlertSeverity, ProviderName |
| **SecurityEvent** | Windows Security Event Log | EventID, Account, Computer, LogonType |
| **AzureActivity** | Azure control-plane operations | OperationNameValue, Caller, CallerIpAddress, ResourceGroup |
| **AzureDiagnostics** | Azure resource diagnostic logs | ResourceType, OperationName, ResultType |
| **EmailEvents** | Email delivery & filtering | SenderFromAddress, RecipientEmailAddress, ThreatTypes, EmailDirection |
| **EmailAttachmentInfo** | Email attachment metadata | FileName, SHA256, ThreatTypes, MalwareFamily |
| **EmailUrlInfo** | URLs embedded in emails | Url, UrlLocation, ThreatTypes |
| **UrlClickEvents** | Safe Links click telemetry | Url, AccountUpn, ActionType, IPAddress, IsClickedThrough |
| **ThreatIntelligenceIndicator** | Threat intel feed | IndicatorId, NetworkIP, DomainName, Url, FileHashValue, ThreatType |
| **BehaviorAnalytics** | UEBA behavioral insights | UserName, ActivityInsights, InvestigationPriority |
