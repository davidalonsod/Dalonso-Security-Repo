# Netskope Web Transactions – Threat Hunting & Analytic Rules for Microsoft Sentinel

A curated collection of **12 KQL threat-hunting queries** and **14 Scheduled Analytic Rules** targeting the `NetskopeWebTx_CL` (custom log) table in Microsoft Sentinel. These rules complement — and do not duplicate — the **10 built-in analytic rules** shipped with the [Netskope Web Transaction Events](https://azuremarketplace.microsoft.com/marketplace/apps/netaborplatforminc1588aboraborplatform.netskope_web_transaction_events_mss?tab=Overview) Content Hub solution.

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
| Sentinel Table | `NetskopeWebTx_CL` (custom log via Blob Storage ingestion) |
| Vendor | Netskope |
| Analytic Rules | 14 YAML files (38–51) · ARM template deployable |
| Hunting Queries | 12 (HQ38–HQ49) · deployed as savedSearches to Hunting blade |
| Cross-Table Joins | `ThreatIntelIndicators` (Rule 40), `SecurityAlert` (Rule 48) |
| Author | CyberSOC Engineering |
| Last Updated | 2026-04-15 |

---

## Repository Structure

```
Netskope/
├── README.md                                ← This file
├── Analytic-Rules/
│   ├── rules/                               ← 14 YAML analytic rule files (38–51)
│   │   ├── 38-NK-MaliciousCategoryBlocks.yaml
│   │   ├── 39-NK-DLP-BlockedUpload.yaml
│   │   ├── 40-NK-ThreatIntelligence-DomainIPMatch.yaml
│   │   ├── 41-NK-OffHours-HighVolumeActivity.yaml
│   │   ├── 42-NK-MultiUser-PhishingCampaign.yaml
│   │   ├── 43-NK-HighConfidenceThreat-Allowed.yaml
│   │   ├── 44-NK-ATP-SandboxMaliciousFile.yaml
│   │   ├── 45-NK-TunnelProxyBypass.yaml
│   │   ├── 46-NK-VisibilityLoss-NoTraffic.yaml
│   │   ├── 47-NK-LOTL-C2-LegitimateServices.yaml
│   │   ├── 48-NK-SecurityAlert-Correlation.yaml
│   │   ├── 49-NK-LowSlow-Exfiltration.yaml
│   │   ├── 50-NK-CategoryShift-Anomaly.yaml
│   │   └── 51-NK-DNSTunneling-LongHostnames.yaml
│   ├── azuredeploy.json                     ← ARM template — 14 rules + 12 hunting queries
│   └── deploy-rules.ps1                     ← PowerShell deployer (ARM + YAML modes)
└── Hunting-Queries/
    └── NK-Netskope-HuntingQueries.kql       ← 12 KQL hunting queries (HQ38–HQ49)
```

---

## Data Sources & Prerequisites

| Requirement | Details |
|-------------|---------|
| **Netskope Web Transaction Events** | Install from Content Hub; enables `NetskopeWebTx_CL` via the Netskope Data Connector (Blob Storage) |
| **ThreatIntelIndicators** | Required for Rule 40 (TI Correlation); enable the **Microsoft Defender Threat Intelligence** or **Threat Intelligence Platforms** connector |
| **SecurityAlert** | Required for Rule 48 (cross-source correlation); any alert-generating product (MDE, MDO, etc.) |

### Key Columns Used (NetskopeWebTx_CL)

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
| `ccl_s` | string | Cloud confidence level |
| `dst_country_s` | string | Destination country |

### Required PowerShell Modules (for deployment)

```powershell
Install-Module Az.Accounts, Az.Resources, Az.SecurityInsights -Force -Scope CurrentUser
```

---

## Analytic Rules

14 Scheduled Analytic Rules in [`Analytic-Rules/rules/`](Analytic-Rules/rules/). Each YAML file defines a fully configured Sentinel rule with query, frequency, severity, MITRE tactics, entity mappings, custom details, and incident-grouping settings.

| # | File | Rule Name | Severity | MITRE |
|---|------|-----------|----------|-------|
| 38 | 38-NK-MaliciousCategoryBlocks.yaml | Blocked Request to Malicious / C2 Category | High | T1071 |
| 39 | 39-NK-DLP-BlockedUpload.yaml | DLP Policy Violation – Blocked Sensitive Upload | High | T1048, T1567 |
| 40 | 40-NK-ThreatIntelligence-DomainIPMatch.yaml | Threat Intelligence Domain/IP Correlation | High | T1071, T1568 |
| 41 | 41-NK-OffHours-HighVolumeActivity.yaml | Off-Hours High-Volume Web Activity | Medium | T1029, T1567 |
| 42 | 42-NK-MultiUser-PhishingCampaign.yaml | Multi-User Phishing Campaign Detection | High | T1566, T1566.002 |
| 43 | 43-NK-HighConfidenceThreat-Allowed.yaml | High-Confidence Threat Allowed Through | High | T1071, T1204 |
| 44 | 44-NK-ATP-SandboxMaliciousFile.yaml | ATP/Sandbox Malicious File Detection | High | T1105, T1204.002 |
| 45 | 45-NK-TunnelProxyBypass.yaml | Tunnel/Proxy/VPN Bypass Attempt | Medium | T1090, T1572 |
| 46 | 46-NK-VisibilityLoss-NoTraffic.yaml | User Visibility Loss – No Traffic | Medium | T1562, T1562.001 |
| 47 | 47-NK-LOTL-C2-LegitimateServices.yaml | LOTL C2 via Legitimate Services (GitHub/Pastebin) | Medium | T1102, T1105 |
| 48 | 48-NK-SecurityAlert-Correlation.yaml | Netskope + SecurityAlert Cross-Source Correlation | High | T1071, T1078 |
| 49 | 49-NK-LowSlow-Exfiltration.yaml | Low & Slow Multi-Channel Exfiltration (Z-Score) | High | T1041, T1567.002 |
| 50 | 50-NK-CategoryShift-Anomaly.yaml | Category Shift Anomaly – Domain Recategorization | Medium | T1584, T1583 |
| 51 | 51-NK-DNSTunneling-LongHostnames.yaml | DNS Tunneling via Long Hostnames | High | T1071.004 |

### Built-in Rules NOT Duplicated

The following 10 rules already ship with the Netskope Web Transaction Events Content Hub solution and are **not** recreated in this folder:

1. Data Movement Tracking (Upload/Download Monitoring)
2. Large Outbound Data Transfer / Sensitive Upload
3. Heavy Personal Cloud Storage Usage (Shadow IT)
4. Repeated or Critical Policy Violations
5. Suspicious Network Context (Unusual IPs/Geo/Port)
6. Excessive Downloads Detection (Spike vs Baseline)
7. Unsanctioned/Risky Cloud App Access (Shadow IT)
8. Impossible Travel Detection
9. New Risky App Access vs 7-Day Baseline
10. Anomalous User Behavior (High Volume from Unusual)

---

## Hunting Queries

12 hunting queries in [`Hunting-Queries/NK-Netskope-HuntingQueries.kql`](Hunting-Queries/NK-Netskope-HuntingQueries.kql). Each query includes a header comment with MITRE tactics, techniques, and description.

The ARM template also deploys these as `savedSearches` resources, so after deployment they appear in the **Microsoft Sentinel → Hunting** blade under **My Queries** with full MITRE ATT&CK tagging.

| # | Name | MITRE Techniques |
|---|------|-----------------|
| HQ38 | Blocked Requests by Malicious Category | T1071 |
| HQ39 | DLP Violations Deep Dive | T1048, T1567 |
| HQ40 | Allowed Traffic to TI-Listed Domains/IPs | T1071, T1568 |
| HQ41 | Off-Hours Activity Profiling | T1029, T1567 |
| HQ42 | Phishing Campaign Detection | T1566, T1566.002 |
| HQ43 | Threat Severity Allowed Traffic Analysis | T1071, T1204 |
| HQ44 | ATP/Sandbox Detections Summary | T1105, T1204.002 |
| HQ45 | Tunnel/Proxy/VPN Bypass Hunting | T1090, T1572 |
| HQ46 | Visibility Loss – Users Gone Silent | T1562, T1562.001 |
| HQ47 | LOTL C2 via Legitimate Platforms | T1102, T1105 |
| HQ48 | Netskope + SecurityAlert Cross-Source Corroboration | T1071, T1078 |
| HQ49 | Low & Slow Exfiltration (Z-Score) | T1041, T1567.002 |

---

## Deployment

### Option A – ARM Template (recommended)

Deploys all 14 analytic rules **and** 12 hunting queries in a single operation. Hunting queries appear in the Sentinel **Hunting** blade as saved searches with MITRE tagging.

```powershell
cd Netskope\Analytic-Rules
.\deploy-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod"
```

### Option B – Per-File YAML Deployment

Deploys each YAML rule individually via the Sentinel REST API — retains `customDetails`, `incidentGrouping`, and entity mappings.

```powershell
cd Netskope\Analytic-Rules
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
| `Microsoft.SecurityInsights/alertRules` (Scheduled) | 14 | Sentinel → Analytics → Active rules |
| `Microsoft.OperationalInsights/workspaces/savedSearches` | 12 | Sentinel → Hunting → My Queries |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| Initial Access | T1566, T1566.002 |
| Execution | T1204, T1204.002 |
| Command & Control | T1071, T1071.004, T1090, T1102, T1105, T1568, T1572 |
| Exfiltration | T1029, T1041, T1048, T1567, T1567.002 |
| Defense Evasion | T1562, T1562.001 |
| Resource Development | T1583, T1584 |
| Credential Access | T1078 |

---

## Cost Optimization

The `NetskopeWebTx_CL` table can generate high ingestion volume. See the **Cost Optimization — Ingestion Filtering & Data Split** section in the [repository CHANGES.md](../CHANGES.md) for detailed guidance on:

1. **DCR ingestion-time filtering** — drop routine allowed traffic before it reaches the workspace (60–80% volume reduction)
2. **Analytics vs Basic/Auxiliary log plans** — assign the right plan per use case
3. **Table splitting by event type** — route security events to `NetskopeWebTx_CL` (Analytics) and bulk traffic to `NetskopeWebTx_Bulk_CL` (Basic)
4. **Workspace-level filtering** — vendor-scoped DCR filters and daily volume estimation queries

**Quick volume check:**

```kql
Usage
| where DataType == "NetskopeWebTx_CL"
| summarize GB = round(sum(Quantity) / 1024, 2)
  by bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

> **Recommendation:** If daily volume exceeds 100 GB, apply DCR filtering + table splitting. Combined strategies can reduce Sentinel costs by **70–90%** while keeping all 14 analytic rules fully operational.

---

## License

This project is provided as-is for educational and operational use within your own Microsoft Sentinel environment.
