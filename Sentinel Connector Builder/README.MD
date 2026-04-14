# AbuseIPDB Threat Intelligence — Microsoft Sentinel Solution

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/)

A Microsoft Sentinel solution that ingests the [AbuseIPDB](https://www.abuseipdb.com/) blacklist into a custom Log Analytics table, correlates blacklisted IPs with your environment's sign-in and network telemetry, and provides hunting queries, analytics rules, and an interactive workbook for threat investigation.

Built using the **Codeless Connector Framework (CCF)** and the Sentinel Connector Builder Agent.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Solution Contents](#solution-contents)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Data Schema](#data-schema)
- [Analytics Rules](#analytics-rules)
- [Hunting Queries](#hunting-queries)
- [Workbook](#workbook)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

AbuseIPDB is a community-driven threat intelligence platform that tracks IP addresses involved in malicious activity (brute force, DDoS, spam, port scanning, etc.). This solution:

1. **Ingests** the AbuseIPDB blacklist (up to 500K IPs) every 24 hours into `AbuseIPDB_Blacklist_CL`
2. **Correlates** blacklisted IPs against 8 Sentinel tables: `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `ADFSSignInLogs`, `SecurityEvent`, `CommonSecurityLog`, `SecurityAlert`, and `DeviceNetworkEvents`
3. **Alerts** on successful sign-ins, service principal auth, Windows logons, and network traffic from abusive IPs
4. **Visualizes** ingestion health, IOC geolocation, affected users/devices, and geo-environment overlap in an interactive workbook

---

## Architecture

```
┌─────────────────────┐       ┌──────────────────────┐       ┌──────────────────────┐
│   AbuseIPDB API     │       │   Data Collection     │       │  Microsoft Sentinel  │
│                     │       │   Rule (DCR)          │       │                      │
│  GET /api/v2/       │──────▶│                       │──────▶│  AbuseIPDB_          │
│    blacklist        │       │  KQL Transform:       │       │  Blacklist_CL        │
│                     │       │  - Map field names    │       │                      │
│  Auth: API Key      │       │  - Parse timestamps   │       │  ┌────────────────┐  │
│  Header: "Key"      │       │  - Set TimeGenerated  │       │  │ Analytics Rules │  │
│                     │       │                       │       │  │ Hunting Queries │  │
│  Rate: 1 QPS        │       └──────────────────────┘       │  │ Workbook        │  │
│  Polling: 24h       │                                      │  └────────────────┘  │
└─────────────────────┘                                      └──────────────────────┘
```

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Microsoft Sentinel** | Active workspace with Contributor role |
| **AbuseIPDB API Key** | Free tier: 5 requests/day. [Get your key](https://www.abuseipdb.com/account/api) |
| **Azure AD Sign-in Logs** | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs` |
| **ADFS Sign-in Logs** | `ADFSSignInLogs` for federated authentication correlation (optional) |
| **Windows Security Events** | `SecurityEvent` table for on-premises logon correlation (optional) |
| **CommonSecurityLog** | Firewall/Proxy/IDS logs via CEF connector (optional) |
| **Defender for Endpoint** | `DeviceNetworkEvents` table for device correlation (optional) |
| **VS Code** | With GitHub Copilot + [Microsoft Sentinel extension](https://marketplace.visualstudio.com/items?itemName=ms-security.ms-sentinel) (for Connector Builder deployment) |

---

## Solution Contents

```
AbuseIPDB_CCF/
├── AbuseIPDB_ArmTemplate.json              # Full ARM template (connector + table + DCR)
├── AbuseIPDB_ConnectorDefinition.json       # CCF connector definition
├── AbuseIPDB_DCR.json                       # Data Collection Rule
├── AbuseIPDB_PollingConfig.json             # API polling configuration
├── AbuseIPDB_Table.json                     # Custom table schema
├── analytics-rules/
│   ├── AR1_Successful_SignIn_High_Abuse_IP.json           # High — successful user auth from abusive IP
│   ├── AR2_BruteForce_From_Blacklisted_IP.json            # Medium — brute force across sign-in types
│   ├── AR3_ServicePrincipal_Auth_Blacklisted_IP.json      # High — SPN/MI auth from abusive IP
│   ├── AR4_Windows_Logon_Blacklisted_IP.json              # High — Windows logon from abusive IP
│   └── AR5_CommonSecurityLog_Inbound_Blacklisted_IP.json  # Medium — inbound traffic from abusive IP
├── hunting-queries/
│   ├── HQ1_SignIns_From_Blacklisted_IPs.json              # All sign-in types correlation
│   ├── HQ2_Network_Connections_Blacklisted_IPs.json       # Device network correlation
│   ├── HQ3_Blacklist_Geographic_Distribution.json         # Geographic analysis
│   ├── HQ4_Windows_Logon_From_Blacklisted_IPs.json        # SecurityEvent logon correlation
│   ├── HQ5_CommonSecurityLog_Blacklisted_IPs.json         # Firewall/IDS/proxy correlation
│   ├── HQ6_SecurityAlerts_Blacklisted_IPs.json            # Alert entity correlation
│   └── HQ7_ServicePrincipal_ManagedIdentity_Blacklisted_IPs.json  # SPN/MI correlation
├── workbook/
│   └── AbuseIPDB_Workbook_Content.json      # Interactive workbook (8 sections)
└── README.md                                # This file
```

---

## Deployment

### Option A: Sentinel Connector Builder Agent (recommended)

1. Open the `AbuseIPDB_CCF/` folder in VS Code
2. Right-click the folder → **Microsoft Sentinel → Deploy Connector**
3. Select your Sentinel workspace
4. After deployment, go to **Data connectors** in Sentinel, find **AbuseIPDB Blacklist**, enter your API key, and connect

### Option B: Azure CLI

```bash
# Deploy the ARM template
az deployment group create \
  --resource-group <YOUR_RG> \
  --template-file AbuseIPDB_ArmTemplate.json \
  --parameters workspace=<YOUR_WORKSPACE> apiKey=<YOUR_API_KEY>
```

### Deploy Analytics Rules

```bash
# Analytics Rule 1: Successful Sign-in from High Confidence Abusive IP
az rest --method PUT \
  --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WS>/providers/Microsoft.SecurityInsights/alertRules/abuseipdb-ar1-signin-high-abuse-ip?api-version=2024-09-01" \
  --body @analytics-rules/AR1_Successful_SignIn_High_Abuse_IP.json

# Analytics Rule 2: Brute Force from Blacklisted IP
az rest --method PUT \
  --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WS>/providers/Microsoft.SecurityInsights/alertRules/abuseipdb-ar2-bruteforce-blacklisted-ip?api-version=2024-09-01" \
  --body @analytics-rules/AR2_BruteForce_From_Blacklisted_IP.json
```

### Deploy Hunting Queries

```bash
# Deploy each hunting query as a saved search
for file in hunting-queries/HQ*.json; do
  name=$(basename "$file" .json)
  az rest --method PUT \
    --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WS>/savedSearches/AbuseIPDB-${name}?api-version=2020-08-01" \
    --body @"$file"
done
```

### Deploy Workbook

```powershell
$wbGuid = [guid]::NewGuid().ToString()
# Prepare the body with serializedData from workbook/AbuseIPDB_Workbook_Content.json
az rest --method PUT `
  --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.Insights/workbooks/${wbGuid}?api-version=2022-04-01" `
  --body @workbook_body.json
```

---

## Configuration

After deploying the connector:

1. Navigate to **Microsoft Sentinel → Data connectors**
2. Find **AbuseIPDB Blacklist (using Sentinel Connector Builder Agent)**
3. Click **Open connector page**
4. Enter your **AbuseIPDB API Key** and click **Connect**

### Polling Settings

| Parameter | Value | Description |
|-----------|-------|-------------|
| Endpoint | `GET /api/v2/blacklist` | AbuseIPDB blacklist endpoint |
| Frequency | Every 24 hours | Snapshot-based (not incremental) |
| `confidenceMinimum` | 25 | Minimum abuse score (25-100) |
| `limit` | 500,000 | Maximum IPs per poll (capped by subscription tier) |
| Rate Limit | 1 QPS | API rate limiting |

---

## Data Schema

### Table: `AbuseIPDB_Blacklist_CL`

| Column | Type | Description |
|--------|------|-------------|
| `TimeGenerated` | datetime | Event timestamp (mapped from `lastReportedAt`) |
| `IpAddress` | string | The reported abusive IP address (IPv4 or IPv6) |
| `AbuseConfidenceScore` | real | Calculated abuse confidence score (25-100) |
| `CountryCode` | string | ISO 3166 alpha-2 country code |
| `LastReportedAt` | datetime | Timestamp of the most recent abuse report |

### Sample Query

```kql
AbuseIPDB_Blacklist_CL
| where TimeGenerated > ago(1d)
| where AbuseConfidenceScore >= 80
| summarize Count = count() by CountryCode
| top 10 by Count
```

---

## Analytics Rules

### AR1: Successful Sign-in from High Confidence Abusive IP

| Property | Value |
|----------|-------|
| **Severity** | 🔴 High |
| **Frequency** | Every 1 hour |
| **MITRE ATT&CK** | T1078 (Valid Accounts) |
| **Data Sources** | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `ADFSSignInLogs` |
| **Trigger** | Any successful user sign-in (`ResultType == 0`) from an IP with AbuseIPDB score ≥ 80 |
| **Entity Mapping** | Account (UPN) + IP Address |

**Why this matters:** A successful authentication (interactive or non-interactive) from a known high-confidence abusive IP strongly suggests compromised credentials, token replay, or credential stuffing success.

### AR2: Brute Force Attempt from Blacklisted IP

| Property | Value |
|----------|-------|
| **Severity** | 🟠 Medium |
| **Frequency** | Every 1 hour |
| **MITRE ATT&CK** | T1110 (Brute Force) |
| **Data Sources** | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `ADFSSignInLogs` |
| **Trigger** | ≥ 10 failed sign-in attempts from a blacklisted IP (score ≥ 50) within 1 hour |
| **Entity Mapping** | IP Address |

**Why this matters:** Active brute force attacks from known malicious infrastructure across any sign-in type indicate targeted credential attacks.

### AR3: Service Principal or Managed Identity Auth from Blacklisted IP

| Property | Value |
|----------|-------|
| **Severity** | 🔴 High |
| **Frequency** | Every 1 hour |
| **MITRE ATT&CK** | T1078.004 (Cloud Accounts) |
| **Data Sources** | `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs` |
| **Trigger** | Successful SPN/MI authentication from an IP with AbuseIPDB score ≥ 80 |
| **Entity Mapping** | IP Address |

**Why this matters:** Non-human identity authentication from known malicious infrastructure indicates compromised application credentials, leaked secrets, or API key theft.

### AR4: Windows Logon from Blacklisted IP

| Property | Value |
|----------|-------|
| **Severity** | 🔴 High |
| **Frequency** | Every 1 hour |
| **MITRE ATT&CK** | T1078 (Valid Accounts), T1021.001 (RDP) |
| **Data Sources** | `SecurityEvent` |
| **Trigger** | Successful Windows network logon (Type 3) or RDP logon (Type 10) from an IP with score ≥ 75 |
| **Entity Mapping** | Host + Account + IP Address |

**Why this matters:** Direct on-premises authentication from a known abusive IP indicates perimeter breach, exposed RDP, or lateral movement from compromised infrastructure.

### AR5: Inbound Network Traffic from Blacklisted IP

| Property | Value |
|----------|-------|
| **Severity** | 🟠 Medium |
| **Frequency** | Every 1 hour |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application), T1595 (Active Scanning) |
| **Data Sources** | `CommonSecurityLog` |
| **Trigger** | ≥ 5 inbound connections from a blacklisted IP (score ≥ 75) within 1 hour |
| **Entity Mapping** | IP Address |

**Why this matters:** Persistent inbound connections from known malicious IPs across firewalls/proxies indicate active scanning, exploitation attempts, or reconnaissance.

---

## Hunting Queries

| ID | Name | Data Sources | Tactics | Description |
|----|------|-------------|---------|-------------|
| **HQ1** | All Sign-Ins from Blacklisted IPs | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `ADFSSignInLogs` | Initial Access, Credential Access | Union of all 5 sign-in tables — normalizes identity/app fields, shows sign-in type per result |
| **HQ2** | Device Network Connections to Blacklisted IPs | `DeviceNetworkEvents` | C2, Exfiltration | Correlates high-confidence blacklisted IPs (score ≥ 75) with device network events |
| **HQ3** | Blacklist Geographic Distribution | `AbuseIPDB_Blacklist_CL` | Reconnaissance | Top 30 countries by IP count, avg/max scores, critical concentration |
| **HQ4** | Windows Logon from Blacklisted IPs | `SecurityEvent` | Initial Access, Lateral Movement | Windows logon events (4624, 4625, 4648) from blacklisted IPs |
| **HQ5** | Network Device Logs with Blacklisted IPs | `CommonSecurityLog` | C2, Exfiltration, Initial Access | Inbound and outbound traffic via firewalls/proxies/IDS with direction tagging |
| **HQ6** | Security Alerts Involving Blacklisted IPs | `SecurityAlert` | Initial Access, C2, Impact | Parses alert IP entities and enriches with abuse scores for triage prioritization |
| **HQ7** | Service Principal & Managed Identity Auth | `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs` | Initial Access, Persistence | Dedicated non-human identity view with AppId for credential rotation tracking |

---

## Workbook

The **AbuseIPDB Threat Intelligence** workbook provides 8 interactive sections:

| Section | Description | Key Visualizations |
|---------|-------------|-------------------|
| **1. Data Ingestion Health** | Monitor connector health and data freshness | Summary tiles, daily volume chart, score distribution pie |
| **2. IOC Geolocation** | Geographic distribution of blacklisted IPs | Top 25 countries table, country bar chart |
| **3. Sign-in Correlation** | Sign-ins from blacklisted IPs | Summary tiles, IP-level detail table, timeline chart |
| **4. Affected Users** | Users authenticating from blacklisted IPs | Risk-scored user table (Critical/High/Medium/Low), top 15 users chart |
| **5. Affected Devices** | Devices connecting to blacklisted IPs | Device detail table, top processes pie, destination ports bar |
| **6. Threat Intel Details** | Blacklist deep dive | Top 50 highest-risk IPs, recently reported IPs |
| **7. Geo Environment Match** | Blacklist countries vs. your sign-in countries | Cross-reference table with Overlap/Blacklist-only/Environment-only categories |
| **8. Security Alerts** | Alerts involving blacklisted IPs | Alert table with severity coloring |

### Parameters

- **Time Range** — 1 hour to 30 days (default: 7 days)
- **Min Abuse Confidence Score** — Threshold filter (default: 50)

### Screenshots

> _Add screenshots of your workbook here after deployment._

---

## MITRE ATT&CK Coverage

| Technique | ID | Coverage |
|-----------|----|----------|
| Valid Accounts | T1078 | AR1: Successful user sign-in from abusive IP (Interactive + Non-Interactive + ADFS) |
| Valid Accounts: Cloud Accounts | T1078.004 | AR3: Service Principal / Managed Identity auth from abusive IP |
| Brute Force | T1110 | AR2: Failed sign-in attempts across all user sign-in types |
| Remote Desktop Protocol | T1021.001 | AR4: Windows RDP logon from blacklisted IP |
| Exploit Public-Facing Application | T1190 | AR5: Inbound connections via CommonSecurityLog |
| Active Scanning | T1595 | AR5 + HQ3: Scanning detection + geographic distribution |
| Application Layer Protocol | T1071 | HQ2 + HQ5: Device network + firewall/proxy traffic |
| Exfiltration Over C2 Channel | T1041 | HQ2 + HQ5: Outbound connections to blacklisted IPs |
| Application Credential Abuse | T1098.001 | HQ7: Non-human identity auth tracking |

---

## Contributing

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Add your hunting query or analytics rule to the appropriate folder
4. Submit a pull request

### Adding a New Hunting Query

Place your JSON file in `hunting-queries/` following the naming convention `HQ<N>_<Description>.json`. Include `tactics`, `techniques`, and `description` in the tags.

### Adding a New Analytics Rule

Place your JSON file in `analytics-rules/` following the naming convention `AR<N>_<Description>.json`. Include entity mappings, incident grouping, and alert detail overrides.

---

## License

This project is provided as-is under the [MIT License](../../LICENSE).

---

## Acknowledgments

- [AbuseIPDB](https://www.abuseipdb.com/) for the threat intelligence API
- [Microsoft Sentinel Connector Builder Agent](https://learn.microsoft.com/en-us/azure/sentinel/create-custom-connector-builder-agent) for the CCF scaffolding
- Built with the [Codeless Connector Framework (CCF)](https://learn.microsoft.com/en-us/azure/sentinel/create-codeless-connector)
