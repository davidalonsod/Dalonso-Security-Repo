# CommonSecurityLog – Threat Hunting & Analytic Rules for Microsoft Sentinel

A curated collection of **31 KQL threat-hunting queries** and **37 Scheduled Analytic Rules** targeting the `CommonSecurityLog` (CEF) table in Microsoft Sentinel. Coverage spans three data sources: **Fortinet FortiGate**, **Palo Alto Networks**, and **Zscaler ZIA/ZPA**.

---

## Table of Contents

- [Overview](#overview)
- [Data Sources & Prerequisites](#data-sources--prerequisites)
- [Threat-Hunting Queries](#threat-hunting-queries)
- [Analytic Rules](#analytic-rules)
- [Deployment](#deployment)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Validation Status](#validation-status)

---

## Overview

| Item | Detail |
|------|--------|
| Sentinel Table | `CommonSecurityLog` (CEF / Syslog) |
| Vendors Covered | Fortinet FortiGate · Palo Alto Networks · Zscaler ZIA · Zscaler ZPA |
| Hunting Queries | 31 (Q01 – Q31) |
| Analytic Rules | 37 YAML files · ARM template (all 37 deployable) |
| KQL Validated | Yes — syntax confirmed against a live Sentinel workspace |
| Last Updated | 2026-02-27 |

---

## Data Sources & Prerequisites

All queries and rules rely on the `CommonSecurityLog` table. This table is **not ingested by default** — you must enable the CEF/Syslog data connectors for each vendor in Microsoft Sentinel:

| Connector | DeviceVendor Filter | Documentation |
|-----------|-------------------|---------------|
| Fortinet FortiGate | `"Fortinet"` | [Fortinet connector](https://learn.microsoft.com/azure/sentinel/data-connectors/fortinet) |
| Palo Alto Networks | `"Palo Alto Networks"` | [Palo Alto connector](https://learn.microsoft.com/azure/sentinel/data-connectors/palo-alto-networks) |
| Zscaler ZIA | `"Zscaler"` | [Zscaler ZIA connector](https://learn.microsoft.com/azure/sentinel/data-connectors/zscaler) |
| Zscaler ZPA | `"Zscaler"` + `DeviceProduct has "ZPA"` | [Zscaler ZPA connector](https://learn.microsoft.com/azure/sentinel/data-connectors/zscaler-private-access) |

### Required PowerShell Modules (for deployment)

```powershell
Install-Module Az.Accounts, Az.Resources, Az.SecurityInsights -Force -Scope CurrentUser
```

---

## Threat-Hunting Queries

All queries are in [`CSL-ThreatHunting-Queries.txt`](CSL-ThreatHunting-Queries.txt).

### Core Hunts (Q01 – Q20)

| # | Name | Vendors | MITRE Techniques |
|---|------|---------|-----------------|
| 01 | Beaconing Detection | All | T1071, T1571 |
| 02 | Data Exfiltration – Anomalous Outbound Volume | All | T1048 |
| 03 | Threat Intelligence IP Correlation | All | T1071 |
| 04 | Port Scanning – Single Source to Many Destinations | All | T1046 |
| 05 | High-Risk Country Inbound & Outbound Traffic | All | T1071 |
| 06 | Lateral Movement – Internal-to-Internal Port Sweep | All | T1021 |
| 07 | Fortinet – IPS / Application Control Blocks | Fortinet | T1190, T1059 |
| 08 | Palo Alto – Threat Logs (Threat Type Breakdown) | Palo Alto | T1203 |
| 09 | Zscaler ZIA – Blocked Requests by Malicious Category | Zscaler ZIA | T1566 |
| 10 | Zscaler ZIA – User Accessing File-Sharing / Shadow IT | Zscaler ZIA | T1567 |
| 11 | DNS Tunneling Indicators (Long DNS Queries) | Zscaler ZIA | T1071.004 |
| 12 | New / First-Seen External IPs Allowed Through Firewall | All | T1071 |
| 13 | Correlation: Firewall Allow + Azure AD Sign-In (Same External IP) | All | T1078 |
| 14 | Correlation: CommonSecurityLog + SecurityAlert (Shared IOC IPs) | All | — |
| 15 | Correlation: CommonSecurityLog + ThreatIntelligenceIndicator | All | — |
| 16 | Palo Alto – Zone Transfer Violations & Policy Denies | Palo Alto | T1190 |
| 17 | Fortinet – Repeated Auth Failures (SSL-VPN / Admin) | Fortinet | T1110 |
| 18 | Zscaler – Impossible Travel (Same User, Multiple Countries) | Zscaler ZIA | T1078 |
| 19 | Protocol Anomaly – HTTP/HTTPS on Non-Standard Ports | All | T1571 |
| 20 | Correlation: Firewall + IdentityInfo (Risky User Generating Traffic) | All | T1078 |

### Advanced / Hypothesis-Based Hunts (Q21 – Q28)

| # | Name | Vendors | MITRE Techniques |
|---|------|---------|-----------------|
| 21 | Slow & Low Exfiltration – Aggregated Small Transfers Over Multiple Days | All | T1048 |
| 22 | LOTL Web C2 – GitHub Raw / Pastebin / Google Docs as C2 Staging | Zscaler ZIA | T1102 |
| 23 | Stealthy SaaS Attack – ZIA Proxy + M365 OfficeActivity Correlation | Zscaler ZIA | T1078 |
| 24 | ZIA Allowed Traffic to TI-Listed Domains/IPs Categorized as Unknown | Zscaler ZIA | T1071 |
| 25 | ZIA C2 Block + EDR SecurityAlert Escalation (Multi-Control Correlation) | Zscaler ZIA | T1071 |
| 26 | HTTP Tunneling – Long or Base64-Encoded URL Parameters | Zscaler ZIA | T1071.001 |
| 27 | Domain Fronting – CDN SNI / Suspicious Path Pattern Detection | Zscaler ZIA | T1090.004 |
| 28 | ZPA + ZIA Combined Insider Threat / Stolen Credential Hunt | Zscaler ZIA/ZPA | T1078.004 |

### APT / Nation-State Hypothesis Hunts (Q29 – Q31)

These three hunts require a long observation window (7–30 days) and correlate across multiple data sources (ZIA, ZPA, M365 OfficeActivity, MDE DeviceEvents). They are designed for periodic proactive hunting rather than real-time alerting.

| # | Name | Data Sources | MITRE Techniques |
|---|------|-------------|------------------|
| 29 | Patient APT: Multi-Channel "Low & Slow" Exfiltration | ZIA + M365 OfficeActivity | TA0009, T1041, T1567, T1567.002 |
| 30 | "Perfect Impostor": Account Takeover Hiding Within Normal Traffic | ZPA + ZIA + M365 OfficeActivity | T1078, T1098, T1114, T1556 |
| 31 | APT Control Evasion: Degrading / Bypassing Zscaler & EDR Visibility | ZIA + MDE DeviceEvents + SecurityEvent | T1562, T1562.001, T1070 |

---

## Analytic Rules

Scheduled rules are in [`Analytic-Rules/rules/`](Analytic-Rules/rules/). Each YAML file defines a fully configured Sentinel Scheduled Analytic Rule, including query, frequency, severity, tactics, and incident-grouping settings.

| File | Rule Name | Severity |
|------|-----------|----------|
| 01-CSL-Beaconing-Detection.yaml | Firewall Beaconing Detection - Regular Outbound Connections | High |
| 02-CSL-DataExfiltration-OutboundVolume.yaml | Anomalous Outbound Data Volume | High |
| 03-CSL-ThreatIntelligence-IPMatch.yaml | Threat Intelligence IP Match | High |
| 04-CSL-PortScan-Detection.yaml | Port Scan Detection | Medium |
| 05-CSL-HighRiskCountry-Traffic.yaml | High-Risk Country Traffic | Medium |
| 06-CSL-LateralMovement-InternalPortSweep.yaml | Lateral Movement - Internal Port Sweep | High |
| 07-CSL-Fortinet-IPSAlerts.yaml | Fortinet - IPS / Application Control Blocks | High |
| 08-CSL-PaloAlto-ThreatLogs.yaml | Palo Alto - Threat Logs | High |
| 09-CSL-Zscaler-MaliciousCategoryBlocks.yaml | Zscaler ZIA - Blocked Requests by Malicious Category | Medium |
| 10-CSL-Zscaler-ShadowIT-FileSharing.yaml | Zscaler ZIA - Shadow IT / File Sharing Access | Low |
| 11-CSL-DNSTunneling-LongHostnames.yaml | DNS Tunneling Indicators via Zscaler | High |
| 12-CSL-NewFirstSeen-ExternalIP.yaml | New / First-Seen External IP Allowed | Medium |
| 13-CSL-Firewall-AADSignIn-Correlation.yaml | Firewall Allow + Azure AD Sign-In Correlation | High |
| 14-CSL-Firewall-SecurityAlert-IOCCorrelation.yaml | Firewall + SecurityAlert IOC Correlation | High |
| 15-CSL-ThreatIntelligence-DomainMatch.yaml | Threat Intelligence Domain Match | High |
| 16-CSL-PaloAlto-ZonePolicyDenies.yaml | Palo Alto - Zone Transfer Violations & Policy Denies | Medium |
| 17-CSL-Fortinet-VPN-BruteForce.yaml | Fortinet - VPN / Admin Brute Force | High |
| 18-CSL-Zscaler-ImpossibleTravel.yaml | Zscaler - Impossible Travel Detection | High |
| 19-CSL-ProtocolAnomaly-NonStandardPorts.yaml | Protocol Anomaly - Non-Standard Ports | Medium |
| 20-CSL-RiskyIdentity-FirewallTraffic.yaml | Risky Identity Generating Firewall Traffic | High |
| 21-CSL-Zscaler-DLP-DataUploadViolation.yaml | Zscaler ZIA - DLP Policy Violation | High |
| 22-CSL-Zscaler-ATP-SandboxMaliciousFile.yaml | Zscaler ZIA - ATP Sandbox Malicious File | High |
| 23-CSL-Zscaler-MassCloudStorageDownload.yaml | Zscaler ZIA - Mass Cloud Storage Download | Medium |
| 24-CSL-Zscaler-UncategorizedDomainSpike.yaml | Zscaler ZIA - Uncategorized Domain Spike | Medium |
| 25-CSL-Zscaler-TunnelProxyBypass.yaml | Zscaler ZIA - Tunnel / Proxy Bypass Attempt | High |
| 26-CSL-Zscaler-OffHours-HighVolumeActivity.yaml | Zscaler ZIA - Off-Hours High-Volume Activity | Medium |
| 27-CSL-Zscaler-MultiUser-PhishingCampaign.yaml | Zscaler ZIA - Multi-User Phishing Campaign | High |
| 28-CSL-Zscaler-HighThreatRiskLevel-Allowed.yaml | Zscaler ZIA - High Threat Risk Level Allowed | High |
| 29-CSL-Zscaler-CategoryShift-Anomaly.yaml | Zscaler ZIA - Category Shift Anomaly | Medium |
| 30-CSL-Zscaler-VisibilityLoss-NoTraffic.yaml | Zscaler ZIA - Visibility Loss / No Traffic | Medium |
| 31-CSL-ZPA-AnomalousGeolocation-Access.yaml | Zscaler ZPA - Access from Anomalous Geolocation | High |
| 32-CSL-ZPA-RepeatedConnectionFailures.yaml | Zscaler ZPA - Repeated Connection Failures | Medium |
| 33-CSL-ZPA-FirstTimeAppAccess.yaml | Zscaler ZPA - First-Time Application Access | Low |
| 34-CSL-ZPA-AppVolumeSpike.yaml | Zscaler ZPA - Application Volume Spike | Medium |
| 35-CSL-ZIA-LowSlowMultiChannel-Exfiltration.yaml | Zscaler ZIA - Patient APT: Multi-Channel Low & Slow Exfiltration | High |
| 36-CSL-ZPA-PerfectImpostor-AccountTakeover.yaml | Zscaler ZPA/ZIA - Perfect Impostor: Account Takeover Hiding Within Normal Traffic | High |
| 37-CSL-ZIA-ControlEvasion-VisibilityDegradation.yaml | Zscaler ZIA - APT Control Evasion: Agent Tampering and Visibility Degradation | High |

---

## Deployment

An ARM template and a PowerShell deployment script are included in [`Analytic-Rules/`](Analytic-Rules/).

### Option 1 – ARM Template (recommended for first-time deployment)

```powershell
.\deploy-csl-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod"
```

Deploys all rules at once via [`azuredeploy.json`](Analytic-Rules/azuredeploy.json).

### Option 2 – Per-File YAML Deployment (preserves all rule metadata)

```powershell
.\deploy-csl-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DeploymentMode    YAML
```

Deploys each YAML file individually via the Sentinel REST API — retains `customDetails`, `incidentGrouping`, and other advanced metadata.

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `SubscriptionId` | Yes | Azure Subscription ID |
| `ResourceGroupName` | Yes | Resource group containing the Log Analytics workspace |
| `WorkspaceName` | Yes | Log Analytics workspace name (not the workspace ID) |
| `DeploymentMode` | No | `ARM` (default) or `YAML` |
| `RulesPath` | No | Path to YAML rules folder (defaults to `.\rules\`) |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| Initial Access | T1078, T1133, T1190, T1566 |
| Execution | T1059 |
| Persistence | T1078, T1098 |
| Command & Control | T1071, T1071.001, T1071.004, T1090.004, T1102, T1571 |
| Exfiltration | T1041, T1048, T1567, T1567.002 |
| Discovery | T1046 |
| Lateral Movement | T1021 |
| Credential Access | T1110, T1556 |
| Defense Evasion | T1070, T1562, T1562.001 |
| Collection | T1114 |

---

## Validation Status

- **Q01 – Q20**: Validated against the CyberSOC Microsoft Sentinel environment.
- **Q21 – Q28**: Added 2026-02-27; KQL syntax validated. Data availability depends on active connectors.
- **Q29 – Q31**: Added 2026-02-27; APT / nation-state hypothesis hunts. Require ZIA, ZPA, M365 OfficeActivity, and MDE connectors. Long-window queries intended for periodic proactive hunts or scheduled daily/4-hour rules.
- **Rules 35 – 37**: Added to ARM template 2026-02-27; Scheduled Analytic Rule versions of Q29–Q31 (APT/nation-state). Rule 35 `queryPeriod` capped at P14D (YAML specifies P30D). Rule 37 `customDetails` key `BaselineRPDay` maps to query column `BaselineRequestsPerDay` (key name shortened to meet 20-char limit).
- All KQL functions verified: `ipv4_is_private()`, `round()`, `toreal()`, `strlen()`, `countof()`, `make_set()`, `dcount()`, `bin()`, `case()`, `mv-expand`, `join` kinds (inner / leftanti / leftouter), `let` blocks, cross-table correlations, `geo_info_from_ip_address()`, `set_difference()`, `avg()`, `stdev()`, `toscalar()`, `coalesce()`, `array_length()`.

> **Note:** A `SemanticError: "Failed to resolve table CommonSecurityLog"` from the Sentinel API is a **data availability** error — not a syntax error. It means the CEF connector is not yet configured. See [Data Sources & Prerequisites](#data-sources--prerequisites) above.

---

## License

This project is provided as-is for educational and operational use within your own Microsoft Sentinel environment.
