# Netskope Internet Access – Threat Hunting & Analytic Rules for Microsoft Sentinel

A curated collection of **19 KQL threat-hunting queries** and **21 Scheduled Analytic Rules** targeting the `NetskopeEvents_CL` (built-in) table in Microsoft Sentinel. This folder covers the **Netskope Internet Access** data connector available from Content Hub.

- Rules **52–65** (NK-BI-*) are NetskopeEvents_CL mirrors of the original NetskopeWebTx_CL rules 38–51.
- Rules **66–72** (NK-IA-*) are **new detections** that leverage columns exclusive to NetskopeEvents_CL.

---

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Data Sources & Prerequisites](#data-sources--prerequisites)
- [Analytic Rules](#analytic-rules)
- [Hunting Queries](#hunting-queries)
- [Deployment](#deployment)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Cost Optimization](#cost-optimization)

---

## Overview

| Item | Detail |
|------|--------|
| Sentinel Table | `NetskopeEvents_CL` (built-in via Netskope Internet Access data connector) |
| Vendor | Netskope |
| Analytic Rules | 21 YAML files (52–72) · ARM template deployable |
| Hunting Queries | 19 (HQ50–HQ68) · deployed as savedSearches to Hunting blade |
| Cross-Table Joins | `ThreatIntelIndicators` (Rule 54), `SecurityAlert` (Rule 62) |
| Author | CyberSOC Engineering |
| Last Updated | 2026-04-16 |

---

## Repository Structure

```
Internet-Access/
├── README.md                                ← This file
├── Analytic-Rules/
│   ├── rules/                               ← 21 YAML analytic rule files (52–72)
│   │   ├── 52-NK-BI-MaliciousCategoryBlocks.yaml
│   │   ├── 53-NK-BI-DLP-BlockedUpload.yaml
│   │   ├── 54-NK-BI-ThreatIntelligence-DomainIPMatch.yaml
│   │   ├── 55-NK-BI-OffHours-HighVolumeActivity.yaml
│   │   ├── 56-NK-BI-MultiUser-PhishingCampaign.yaml
│   │   ├── 57-NK-BI-HighConfidenceThreat-Allowed.yaml
│   │   ├── 58-NK-BI-ATP-SandboxMaliciousFile.yaml
│   │   ├── 59-NK-BI-TunnelProxyBypass.yaml
│   │   ├── 60-NK-BI-VisibilityLoss-NoTraffic.yaml
│   │   ├── 61-NK-BI-LOTL-C2-LegitimateServices.yaml
│   │   ├── 62-NK-BI-SecurityAlert-Correlation.yaml
│   │   ├── 63-NK-BI-LowSlow-Exfiltration.yaml
│   │   ├── 64-NK-BI-CategoryShift-Anomaly.yaml
│   │   ├── 65-NK-BI-DNSTunneling-LongHostnames.yaml
│   │   ├── 66-NK-IA-UnauthorizedCloudAppAccess.yaml
│   │   ├── 67-NK-IA-ImpossibleTravel.yaml
│   │   ├── 68-NK-IA-CredentialPhishingSubmission.yaml
│   │   ├── 69-NK-IA-SuspiciousFileDownloadUncategorized.yaml
│   │   ├── 70-NK-IA-RiskyCloudAppDataTransfer.yaml
│   │   ├── 71-NK-IA-GeoAnomalyHighRiskCountry.yaml
│   │   └── 72-NK-IA-MultiProtocolC2Beaconing.yaml
│   ├── azuredeploy.json                     ← ARM template — 21 rules + 19 hunting queries
│   └── deploy-rules.ps1                     ← PowerShell deployer (ARM + YAML modes)
└── Hunting-Queries/
    └── NK-Netskope-IA-HuntingQueries.kql    ← 19 KQL hunting queries (HQ50–HQ68)
```

---

## Data Sources & Prerequisites

| Requirement | Details |
|-------------|---------|
| **Netskope Internet Access** | Install from Content Hub; enables `NetskopeEvents_CL` via the built-in Netskope data connector |
| **ThreatIntelIndicators** | Required for Rule 54 (TI Correlation); enable the **Microsoft Defender Threat Intelligence** or **Threat Intelligence Platforms** connector |
| **SecurityAlert** | Required for Rule 62 (cross-source correlation); any alert-generating product (MDE, MDO, etc.) |

### Key Columns Used (NetskopeEvents_CL)

| Column | Type | Description |
|--------|------|-------------|
| `user_s` | string | User email / UPN |
| `srcip_s` | string | Source IP address |
| `dstip_s` | string | Destination IP address |
| `domain_s` | string | Destination domain |
| `url_s` | string | Full request URL |
| `app_s` | string | Application name |
| `category_s` | string | URL category |
| `action_s` | string | Action taken (allow / block / alert) |
| `activity_s` | string | Activity type (Upload / Download / Browse) |
| `severity_s` | string | Threat severity (low / medium / high / critical) |
| `malware_name_s` | string | Detected malware name |
| `malware_type_s` | string | Malware classification |
| `threat_name_s` | string | Threat name |
| `dlp_rule_s` | string | DLP rule that triggered |
| `dlp_profile_s` | string | DLP profile name |
| `bytes_uploaded_d` | double | Bytes sent |
| `bytes_downloaded_d` | double | Bytes received |
| `object_s` | string | File / object name |
| `file_type_s` | string | File type |
| `ccl_s` | string | Cloud confidence level (poor / low / medium / high / excellent) |
| `dst_country_s` | string | Destination country |
| `src_country_s` | string | Source country |
| `access_method_s` | string | Access method (Client / API Connector / Reverse Proxy) |
| `traffic_type_s` | string | Traffic type (CloudApp / Web) |

> **Note:** Columns `ccl_s`, `dst_country_s`, `src_country_s`, `access_method_s`, and `traffic_type_s` are additional columns available in `NetskopeEvents_CL` beyond the `NetskopeWebTx_CL` schema. The new IA-specific rules (66–72) leverage these columns.

### Required PowerShell Modules (for deployment)

```powershell
Install-Module Az.Accounts, Az.Resources, Az.SecurityInsights -Force -Scope CurrentUser
```

---

## Analytic Rules

21 Scheduled Analytic Rules in [`Analytic-Rules/rules/`](Analytic-Rules/rules/). Each YAML file defines a fully configured Sentinel rule with query, frequency, severity, MITRE tactics, entity mappings, custom details, and incident-grouping settings.

### Built-In Mirrors (52–65) — NetskopeEvents_CL equivalents of rules 38–51

| # | File | Rule Name | Severity | MITRE |
|---|------|-----------|----------|-------|
| 52 | 52-NK-BI-MaliciousCategoryBlocks.yaml | Netskope BI – Blocked Request to Malicious / C2 Category | High | T1071 |
| 53 | 53-NK-BI-DLP-BlockedUpload.yaml | Netskope BI – DLP Policy Violation – Blocked Sensitive Upload | High | T1048, T1567 |
| 54 | 54-NK-BI-ThreatIntelligence-DomainIPMatch.yaml | Netskope BI – Threat Intelligence Domain/IP Correlation | High | T1071, T1568 |
| 55 | 55-NK-BI-OffHours-HighVolumeActivity.yaml | Netskope BI – Off-Hours High-Volume Web Activity | Medium | T1029, T1567 |
| 56 | 56-NK-BI-MultiUser-PhishingCampaign.yaml | Netskope BI – Multi-User Phishing Campaign Detection | High | T1566, T1566.002 |
| 57 | 57-NK-BI-HighConfidenceThreat-Allowed.yaml | Netskope BI – High-Confidence Threat Allowed Through | High | T1071, T1204 |
| 58 | 58-NK-BI-ATP-SandboxMaliciousFile.yaml | Netskope BI – ATP/Sandbox Malicious File Detection | High | T1105, T1204.002 |
| 59 | 59-NK-BI-TunnelProxyBypass.yaml | Netskope BI – Tunnel/Proxy/VPN Bypass Attempt | Medium | T1090, T1572 |
| 60 | 60-NK-BI-VisibilityLoss-NoTraffic.yaml | Netskope BI – User Visibility Loss – No Traffic | Medium | T1562, T1562.001 |
| 61 | 61-NK-BI-LOTL-C2-LegitimateServices.yaml | Netskope BI – LOTL C2 via Legitimate Services | Medium | T1102, T1105 |
| 62 | 62-NK-BI-SecurityAlert-Correlation.yaml | Netskope BI – Netskope + SecurityAlert Correlation | High | T1071, T1078 |
| 63 | 63-NK-BI-LowSlow-Exfiltration.yaml | Netskope BI – Low & Slow Multi-Channel Exfiltration (Z-Score) | High | T1041, T1567.002 |
| 64 | 64-NK-BI-CategoryShift-Anomaly.yaml | Netskope BI – Category Shift Anomaly – Domain Recategorization | Medium | T1584, T1583 |
| 65 | 65-NK-BI-DNSTunneling-LongHostnames.yaml | Netskope BI – DNS Tunneling via Long Hostnames | High | T1071.004 |

### New Internet Access Detections (66–72)

| # | File | Rule Name | Severity | MITRE |
|---|------|-----------|----------|-------|
| 66 | 66-NK-IA-UnauthorizedCloudAppAccess.yaml | Netskope IA – Unauthorized Cloud App Access (Shadow IT) | Medium | T1567, T1537 |
| 67 | 67-NK-IA-ImpossibleTravel.yaml | Netskope IA – Impossible Travel Detection | High | T1078 |
| 68 | 68-NK-IA-CredentialPhishingSubmission.yaml | Netskope IA – Credential Phishing Submission | High | T1566, T1056 |
| 69 | 69-NK-IA-SuspiciousFileDownloadUncategorized.yaml | Netskope IA – Suspicious File Download from Uncategorized Sites | Medium | T1105, T1204 |
| 70 | 70-NK-IA-RiskyCloudAppDataTransfer.yaml | Netskope IA – High-Volume Data Transfer to Risky Cloud Apps | High | T1567, T1537 |
| 71 | 71-NK-IA-GeoAnomalyHighRiskCountry.yaml | Netskope IA – Geo Anomaly – Traffic to High-Risk Countries | Medium | T1071, T1048 |
| 72 | 72-NK-IA-MultiProtocolC2Beaconing.yaml | Netskope IA – Multi-Protocol C2 Beaconing Pattern | High | T1071, T1573 |

---

## Hunting Queries

19 hunting queries in [`Hunting-Queries/NK-Netskope-IA-HuntingQueries.kql`](Hunting-Queries/NK-Netskope-IA-HuntingQueries.kql). Each query includes a header comment with MITRE tactics, techniques, and description.

The ARM template also deploys these as `savedSearches` resources, so after deployment they appear in the **Microsoft Sentinel → Hunting** blade under **My Queries** with full MITRE ATT&CK tagging.

### Built-In Mirrors (HQ50–HQ61) — NetskopeEvents_CL equivalents of HQ38–HQ49

| # | Name | MITRE Techniques |
|---|------|-----------------|
| HQ50 | Blocked Requests by Malicious Category | T1071 |
| HQ51 | DLP Violations Deep Dive | T1048, T1567 |
| HQ52 | Allowed Traffic to TI-Listed Domains/IPs | T1071, T1568 |
| HQ53 | Off-Hours Activity Profiling | T1029, T1567 |
| HQ54 | Phishing Campaign Detection – Multi-User Domain Access | T1566, T1566.002 |
| HQ55 | Threat Severity Allowed Traffic Analysis | T1071, T1204 |
| HQ56 | ATP/Sandbox Detections Summary | T1105, T1204.002 |
| HQ57 | Tunnel/Proxy/VPN Bypass Hunting | T1090, T1572 |
| HQ58 | Visibility Loss – Users Gone Silent | T1562, T1562.001 |
| HQ59 | LOTL C2 via Legitimate Platforms | T1102, T1105 |
| HQ60 | Netskope + SecurityAlert Cross-Source Corroboration | T1071, T1078 |
| HQ61 | Low & Slow Exfiltration (Z-Score) | T1041, T1567.002 |

### New Internet Access Queries (HQ62–HQ68)

| # | Name | MITRE Techniques |
|---|------|-----------------|
| HQ62 | Unauthorized Cloud App Access (Shadow IT) | T1567, T1537 |
| HQ63 | Impossible Travel Detection | T1078 |
| HQ64 | Credential Phishing Submission Hunting | T1566, T1056 |
| HQ65 | Suspicious File Download from Uncategorized Domains | T1105, T1204.002 |
| HQ66 | High-Volume Data Transfer to Risky Cloud Apps | T1567.002, T1537 |
| HQ67 | Geo Anomaly – Traffic to High-Risk Countries | T1071, T1048 |
| HQ68 | Multi-Protocol C2 Beaconing Pattern | T1071, T1573 |

---

## Deployment

### Option A – ARM Template (recommended)

Deploys all 21 analytic rules **and** 19 hunting queries in a single operation. Hunting queries appear in the Sentinel **Hunting** blade as saved searches with MITRE tagging.

```powershell
cd Netskope\Internet-Access\Analytic-Rules
.\deploy-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod"
```

### Option B – Per-File YAML Deployment

Deploys each YAML rule individually via the Sentinel REST API — retains `customDetails`, `incidentGrouping`, and entity mappings.

```powershell
cd Netskope\Internet-Access\Analytic-Rules
.\deploy-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DeploymentMode    YAML
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `SubscriptionId` | Yes | Azure Subscription ID |
| `ResourceGroupName` | Yes | Resource group containing the Log Analytics workspace |
| `WorkspaceName` | Yes | Log Analytics workspace name (not the workspace ID) |
| `DeploymentMode` | No | `ARM` (default) or `YAML` |
| `RulesPath` | No | Path to YAML rules folder (defaults to `.\rules\`) |

### What Gets Deployed

| Resource Type | Count | Where It Appears |
|---------------|-------|-----------------|
| `Microsoft.SecurityInsights/alertRules` (Scheduled) | 21 | Sentinel → Analytics → Active rules |
| `Microsoft.OperationalInsights/workspaces/savedSearches` | 19 | Sentinel → Hunting → My Queries |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| Initial Access | T1566, T1566.002 |
| Execution | T1204, T1204.002 |
| Credential Access | T1056, T1078 |
| Command & Control | T1071, T1071.004, T1090, T1102, T1105, T1568, T1572, T1573 |
| Exfiltration | T1029, T1041, T1048, T1537, T1567, T1567.002 |
| Defense Evasion | T1562, T1562.001 |
| Resource Development | T1583, T1584 |

---

## Cost Optimization

The `NetskopeEvents_CL` table can generate high ingestion volume. Consider:

1. **DCR ingestion-time filtering** — drop routine allowed traffic before it reaches the workspace (60–80% volume reduction)
2. **Analytics vs Basic/Auxiliary log plans** — assign the right plan per use case
3. **Table splitting by event type** — route security events to Analytics and bulk traffic to Basic

**Quick volume check:**

```kql
Usage
| where DataType == "NetskopeEvents_CL"
| summarize GB = round(sum(Quantity) / 1024, 2)
  by bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

> **Recommendation:** If daily volume exceeds 100 GB, apply DCR filtering + table splitting.

---

## Relationship to Parent Folder

The parent `Netskope/Analytic-Rules/` folder contains rules targeting `NetskopeWebTx_CL` (custom log via Blob Storage). Rules 73–79 in that folder are `NetskopeWebTx_CL` duplicates of the new IA-specific detections (66–72) in this folder. See the [parent README](../README.md) for details.

---

## License

This project is provided as-is for educational and operational use within your own Microsoft Sentinel environment.
