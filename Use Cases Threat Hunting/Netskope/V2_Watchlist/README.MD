# Netskope – Threat Hunting & Analytic Rules for Microsoft Sentinel

A curated collection of threat-hunting queries and Scheduled Analytic Rules for **two Netskope tables** in Microsoft Sentinel:

| Folder | Sentinel Table | Rules | Hunting Queries |
|--------|---------------|-------|-----------------|
| `Analytic-Rules/` | `NetskopeWebTx_CL` (custom log via Blob Storage) | 21 YAML (38–51, 73–79) | 18 KQL (HQ38–HQ49, HQ50–HQ55) |
| `Internet-Access/` | `NetskopeEvents_CL` (built-in Content Hub connector) | 21 YAML (52–72) | 19 KQL (HQ50–HQ68) |

These rules complement — and do not duplicate — the **10 built-in analytic rules** shipped with the [Netskope Web Transaction Events](https://azuremarketplace.microsoft.com/marketplace/apps/netaborplatforminc1588aboraborplatform.netskope_web_transaction_events_mss?tab=Overview) Content Hub solution.

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
| Analytic Rules (this folder) | 21 YAML files (38–51, 73–79) · ARM template deployable |
| Hunting Queries (this folder) | 18 (HQ38–HQ49 + HQ50–HQ55) · deployed as savedSearches to Hunting blade |
| Internet Access folder | 21 rules (52–72) + 19 hunting queries (HQ50–HQ68) for `NetskopeEvents_CL` |
| Cross-Table Joins | `ThreatIntelIndicators` (Rule 40), `SecurityAlert` (Rule 48) |
| Author | CyberSOC Engineering |
| Last Updated | 2026-04-16 |

---

## Repository Structure

```
Netskope/
├── README.md                                ← This file
├── Analytic-Rules/
│   ├── rules/                               ← 21 YAML analytic rule files (38–51, 73–79)
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
│   │   ├── 51-NK-DNSTunneling-LongHostnames.yaml
│   │   ├── 73-NK-UnauthorizedCloudAppAccess.yaml
│   │   ├── 74-NK-ImpossibleTravel.yaml
│   │   ├── 75-NK-CredentialPhishingSubmission.yaml
│   │   ├── 76-NK-SuspiciousFileDownloadUncategorized.yaml
│   │   ├── 77-NK-RiskyCloudAppDataTransfer.yaml
│   │   ├── 78-NK-GeoAnomalyHighRiskCountry.yaml
│   │   └── 79-NK-MultiProtocolC2Beaconing.yaml
│   ├── azuredeploy.json                     ← ARM template — 21 rules + 12 hunting queries
│   └── deploy-rules.ps1                     ← PowerShell deployer (ARM + YAML modes)
├── Hunting-Queries/
│   └── NK-Netskope-HuntingQueries.kql       ← 12 KQL hunting queries (HQ38–HQ49)
└── Internet-Access/                         ← NetskopeEvents_CL (built-in connector)
    ├── README.md
    ├── Analytic-Rules/
    │   ├── rules/                           ← 21 YAML rules (52–72)
    │   ├── azuredeploy.json                 ← ARM template — 21 rules + 19 hunting queries
    │   └── deploy-rules.ps1
    └── Hunting-Queries/
        └── NK-Netskope-IA-HuntingQueries.kql ← 19 KQL queries (HQ50–HQ68)
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

### Original Rules (38–51)

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

### New IA-Equivalent Rules (73–79) — NetskopeWebTx_CL versions of Internet Access rules 66–72

| # | File | Rule Name | Severity | MITRE |
|---|------|-----------|----------|-------|
| 73 | 73-NK-UnauthorizedCloudAppAccess.yaml | Unauthorized Cloud App Access (Shadow IT) | Medium | T1567, T1537 |
| 74 | 74-NK-ImpossibleTravel.yaml | Impossible Travel Detection | High | T1078 |
| 75 | 75-NK-CredentialPhishingSubmission.yaml | Credential Phishing Submission | High | T1566, T1056 |
| 76 | 76-NK-SuspiciousFileDownloadUncategorized.yaml | Suspicious File Download from Uncategorized Sites | Medium | T1105, T1204 |
| 77 | 77-NK-RiskyCloudAppDataTransfer.yaml | High-Volume Data Transfer to Risky Cloud Apps | High | T1567, T1537 |
| 78 | 78-NK-GeoAnomalyHighRiskCountry.yaml | Geo Anomaly – Traffic to High-Risk Countries | Medium | T1071, T1048 |
| 79 | 79-NK-MultiProtocolC2Beaconing.yaml | Multi-Protocol C2 Beaconing Pattern | High | T1071, T1573 |

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

18 hunting queries deployed as `savedSearches`. The original 12 (HQ38–HQ49) live in [`Hunting-Queries/NK-Netskope-HuntingQueries.kql`](Hunting-Queries/NK-Netskope-HuntingQueries.kql); the additional 6 (HQ50–HQ55) are defined inline in `Analytic-Rules/azuredeploy.json`.

After deployment they appear in the **Microsoft Sentinel → Hunting** blade under **My Queries** with full MITRE ATT&CK tagging.

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
| HQ50 | SaaS Data Exfiltration Spike (per user, per app) | T1567, T1530 |
| HQ51 | App Category Drift per User (7d vs 30d) | T1078, T1213 |
| HQ52 | DLP Near-Miss Pattern (allowed sensitive uploads) | T1567 |
| HQ53 | Browser Isolation / Steering Bypass Candidates | T1090, T1562 |
| HQ54 | Sanctioned App Credential Reuse from Multiple IPs | T1078, T1110 |
| HQ55 | Suspicious External Share / Public Link Activity | T1530, T1213 |

---

## Deployment

### Network Allowlist (false-positive suppression)

This repo ships a `NetworkAllowlist` watchlist and a per-repo scalar function
`ExcludeAllowlistedIPs_Netskope(ip:string) -> bool` that every IP-bearing rule
and hunt calls against both `srcip_s` and `dstip_s`. Trusted CIDR ranges
(corporate egress, VPN concentrators, partner NATs) are suppressed without
editing individual queries.

| Item | Value |
|---|---|
| Watchlist alias | `NetworkAllowlist` (parameter `watchlistAlias`) |
| Function alias | `ExcludeAllowlistedIPs_Netskope` (parameter `functionAlias`) |
| Function signature | `(ip:string)` → `bool` |
| Seed override | `watchlistRawContent` (CSV body, no header) — leave empty for RFC1918 defaults |
| Rules wired | 12 of 21 (IP-bearing only) |
| Hunts wired | 5 of 18 (IP-bearing only) |
| Sync to Entra Named Locations | See [`Watchlists/`](Watchlists/) |

### Deployment Parameters (new in this patch)

| Parameter | Default | Purpose |
|---|---|---|
| `enableAnalyticRules` | `true` | Deploy all 21 alert rules disabled when `false` (staged rollout). |
| `watchlistAlias` | `NetworkAllowlist` | Watchlist name created by the template. |
| `functionAlias` | `ExcludeAllowlistedIPs_Netskope` | Scalar function created in `savedSearches`. |
| `watchlistRawContent` | `""` | Optional CSV override (CIDR rows). |

### Threshold Uplift (May 2026)

To reduce alert noise in high-volume tenants, baseline thresholds were raised
on 7 detections:

| Rule | Field | Old → New |
|---|---|---|
| Off-Hours High-Volume Web Activity | `TotalMBUploaded` / `TotalMBDownload` / `RequestCount` | 100→250 / 500→1000 / 5000→10000 |
| Multi-User Phishing Campaign | `UniqueUsers` | 3→5 |
| LOTL C2 via Legitimate Services | `RequestCount` | 100→250 |
| Low & Slow Multi-Channel Exfiltration | `ActiveDays` / `TotalMBSent` | 5→7 / 100→250 |
| DNS Tunneling via Long Hostnames | `QueryCount` | 10→25 |
| Unauthorized Cloud App Access (Shadow IT) | `UniqueApps` / `TotalMBUploaded` | 3→5 / 50→150 |
| High-Volume Data Transfer to Risky Cloud App | `TotalMBUploaded` / `UploadCount` | 100→250 / 50→100 |
| Geo Anomaly - High-Risk Countries | `RequestCount` | 5→15 |
| Multi-Protocol C2 Beaconing | `RequestCount` | 20→50 |

### Staged Deploy (recommended)

```powershell
# 1) Watchlist + function + rules DISABLED
az deployment group create -g rg-sentinel `
    --template-file Analytic-Rules/azuredeploy.json `
    --parameters workspace=law-sentinel-prod enableAnalyticRules=false

# 2) (Optional) seed real corporate CIDRs from Entra Named Locations
.\Watchlists\Sync-NamedLocationsToWatchlist.ps1 -SubscriptionId ... -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel-prod -TenantId ... -ClientId ... -ClientSecret ...

# 3) Enable rules
az deployment group create -g rg-sentinel `
    --template-file Analytic-Rules/azuredeploy.json `
    --parameters workspace=law-sentinel-prod enableAnalyticRules=true
```

### Option A – ARM Template (recommended)

Deploys all 21 analytic rules **and** 18 hunting queries (plus the `NetworkAllowlist` watchlist and `ExcludeAllowlistedIPs_Netskope` function) in a single operation. Hunting queries appear in the Sentinel **Hunting** blade as saved searches with MITRE tagging.

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
| `Microsoft.SecurityInsights/alertRules` (Scheduled) | 21 | Sentinel → Analytics → Active rules |
| `Microsoft.OperationalInsights/workspaces/savedSearches` | 19 (18 hunts + 1 function) | Sentinel → Hunting → My Queries |
| `Microsoft.OperationalInsights/workspaces/providers/watchlists` | 1 (`NetworkAllowlist`) | Sentinel → Watchlists |

> For the **NetskopeEvents_CL** Internet Access rules and hunting queries, see the [Internet-Access deployment instructions](Internet-Access/README.md#deployment).

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
