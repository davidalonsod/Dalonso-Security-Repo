# Zscaler Threat Hunting Pack (ZIA + ZPA via CommonSecurityLog)

> Microsoft Sentinel detections and hunts for **Zscaler Internet Access (ZIA)** and **Zscaler Private Access (ZPA)** ingested through the CEF/Syslog `CommonSecurityLog` pipeline.

[![Status: Production](https://img.shields.io/badge/status-production-brightgreen)]()
[![Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?logo=microsoft-azure)]()
[![Table](https://img.shields.io/badge/table-CommonSecurityLog-blue)]()
[![Rules](https://img.shields.io/badge/analytic_rules-21-orange)]()
[![Hunts](https://img.shields.io/badge/hunts-21-orange)]()

---

## Table of Contents

- [What's in this folder](#whats-in-this-folder)
- [Capabilities](#capabilities)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Staged deployment (recommended)](#staged-deployment-recommended)
- [Template parameters](#template-parameters)
- [NetworkAllowlist (trusted IPs)](#networkallowlist-trusted-ips)
- [Analytic rules (21)](#analytic-rules-21)
- [Hunting queries (21)](#hunting-queries-21)
- [MITRE ATT&CK coverage](#mitre-attck-coverage)
- [Tuning tips](#tuning-tips)
- [Optional: automated watchlist sync](#optional-automated-watchlist-sync)
- [Uninstall](#uninstall)
- [License](#license)

---

## What's in this folder

```
Zscaler/
├── README.md                          ← This file
├── Analytic-Rules/
│   ├── azuredeploy.json               ← Single ARM template, deploys everything
│   ├── deploy-rules.ps1               ← Helper script
│   └── rules/                         ← Standalone .yaml / .kql per rule
├── Hunting-Queries/                   ← Standalone .yaml / .kql per hunt
└── Watchlists/                        ← Optional Named-Locations → watchlist sync
    ├── azuredeploy-automation.bicep
    ├── README.md
    └── Sync-NamedLocationsToWatchlist.ps1
```

## Capabilities

- **21 analytic rules** across ZIA (C2/malware block visibility, DLP, ATP/Sandbox, Shadow-IT, mass cloud-storage download, phishing, NRD/Uncategorized, off-hours volume, visibility loss, low-and-slow APT chains, agent tampering) and ZPA (anomalous geo, repeated auth failures, first-time app access, volume spike, account-takeover correlation).
- **21 hunting queries (Q09–Q37)** broadening rule coverage to 7/30-day windows and adding DoH egress, push-notification phishing, ZPA discovery sweeps, HTTP-method anomalies, off-hours storage bursts, and ZPA+EDR auth-failure correlation.
- **NetworkAllowlist watchlist** + scalar function `ExcludeAllowlistedIPs_Zscaler(ip:string)` silences corporate egress, ZIA service nodes, VPN concentrators, and partner ranges without editing KQL.
- **Staged-deploy switch** (`enableAnalyticRules`) lets you deploy disabled, baseline the allowlist, then enable.
- **Single nested deployment** wraps all alertRules — atomic, idempotent, parameterized.

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Onboarded on a Log Analytics workspace |
| Data connector | Zscaler NSS (or equivalent CEF forwarder) producing `DeviceVendor == "Zscaler"` in `CommonSecurityLog` |
| ZPA logs | NSS for ZPA configured (the rules detect ZPA via `AdditionalExtensions has "ZPA"` and `DeviceCustomString1` app metadata) |
| Optional tables | `SecurityAlert` (Q25, Q37 EDR correlation), `OfficeActivity` (Q23 SaaS), `IdentityInfo` (risky-user join) |
| Permissions | `Microsoft Sentinel Contributor` + `Log Analytics Contributor` |

## Quick start

```bash
az deployment group create \
  --resource-group <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WORKSPACE_NAME>
```

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName <RG> `
  -TemplateFile .\Analytic-Rules\azuredeploy.json `
  -workspace <WORKSPACE_NAME>
```

## Staged deployment (recommended)

```bash
# 1) Deploy watchlist + function + hunts. Rules created DISABLED.
az deployment group create -g <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=false

# 2) Seed NetworkAllowlist (CSV: IPOrRange,Description,Owner,AddedDate) in the portal.
#    Wait 5–15 min for the watchlist to materialize before enabling.

# 3) Enable rules.
az deployment group create -g <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=true
```

## Template parameters

| Parameter | Default | Description |
|---|---|---|
| `workspace` | *required* | Log Analytics workspace name |
| `location` | `[resourceGroup().location]` | Deploy region |
| `enableAnalyticRules` | `true` | Set `false` for staged deploy |
| `watchlistAlias` | `NetworkAllowlist` | Watchlist alias (rarely changed) |
| `functionAlias` | `ExcludeAllowlistedIPs_Zscaler` | Scalar-function name (per-solution to avoid collisions) |
| `watchlistRawContent` | *(empty)* | Optional CSV body to seed the watchlist; defaults to RFC1918 |

## NetworkAllowlist (trusted IPs)

The template provisions:

- **Watchlist** `NetworkAllowlist` — schema `IPOrRange,Description,Owner,AddedDate`, CIDR-aware, seeded with RFC1918 ranges by default.
- **Function** `ExcludeAllowlistedIPs_Zscaler(ip:string) -> bool` — scalar, **isfuzzy-safe** when the watchlist hasn't yet seeded (returns `false` so first-deploy doesn't error).

Every analytic rule and hunt that references `SourceIP` / `DestinationIP` is filtered through this function (via `column_ifexists` — Zscaler doesn't populate every column on every event). To customize:

```csv
IPOrRange,Description,Owner,AddedDate
203.0.113.0/24,Office egress NAT,NetOps,2026-05-01
185.46.212.0/24,ZIA service nodes,NetOps,2026-05-01
```

Then edit the watchlist in Sentinel → Configuration → Watchlists. Cache propagation is typically <15 minutes.

## Analytic rules (21)

| # | Rule | Severity | Tactics |
|---|---|---|---|
| 1 | Zscaler ZIA — Blocked Request to Malicious / C2 Category | High | CommandAndControl |
| 2 | Zscaler ZIA — Shadow IT and Unauthorized File Sharing — High Volume | Medium | Exfiltration, Collection |
| 3 | DNS Tunneling Indicators — Anomalously Long Hostnames | High | CommandAndControl, Exfiltration |
| 4 | Zscaler ZIA — Impossible Travel (Same User, Multiple Locations) | High | InitialAccess |
| 5 | Zscaler ZIA — DLP Policy Violation — Blocked Sensitive Data | High | Exfiltration |
| 6 | Zscaler ZIA — ATP / Sandbox Malicious File Detection | High | InitialAccess, Execution |
| 7 | Zscaler ZIA — Mass Cloud Storage Download — Data Staging Risk | High | Collection, Exfiltration |
| 8 | Zscaler ZIA — Uncategorized or Newly Registered Domain Requests | Medium | CommandAndControl |
| 9 | Zscaler ZIA — Tunnel, SOCKS Proxy, or SSL Bypass Category Detected | High | DefenseEvasion, CommandAndControl |
| 10 | Zscaler ZIA — Off-Hours High-Volume Proxy Activity (Behavioral) | Medium | Exfiltration |
| 11 | Zscaler ZIA — Multi-User Phishing Campaign — Same Domain Hits | High | InitialAccess |
| 12 | Zscaler ZIA — High ThreatRiskLevel Browsing in Allowed Traffic | High | InitialAccess, CommandAndControl |
| 13 | Zscaler ZIA — Sudden Category Shift — User Accessing New High-Risk Categories | Medium | InitialAccess |
| 14 | Zscaler ZIA / ZPA — Visibility Loss — No Events Received | High | DefenseEvasion |
| 15 | Zscaler ZPA — Access to Internal Application from Anomalous Geo | High | LateralMovement, InitialAccess |
| 16 | Zscaler ZPA — Repeated Connection Failures — Possible Credential Stuffing | High | CredentialAccess |
| 17 | Zscaler ZPA — First-Time Access to Internal Application | Medium | Discovery, LateralMovement |
| 18 | Zscaler ZPA — App Access Volume Spike — User Accessing Significantly More Apps | Medium | Discovery, Collection |
| 19 | Zscaler ZIA — Patient APT: Multi-Channel Low & Slow Exfiltration | High | Exfiltration |
| 20 | Zscaler ZPA/ZIA — Perfect Impostor: Account Takeover Hiding in Normal Traffic | High | InitialAccess, DefenseEvasion |
| 21 | Zscaler ZIA — APT Control Evasion: Agent Tampering and Visibility Decay | High | DefenseEvasion |

## Hunting queries (21)

| ID | Name |
|---|---|
| Q09 | Zscaler ZIA — Blocked Requests by Malicious Category |
| Q10 | Zscaler ZIA — Shadow IT and File-Sharing Access |
| Q11 | DNS Tunneling Indicators via Zscaler |
| Q18 | Zscaler — Impossible Travel (Same User, Multiple Locations) |
| Q21 | Slow & Low Exfiltration — Aggregated Small Uploads |
| Q22 | LOTL Web C2 — GitHub / Pastebin / Google Docs as Channel |
| Q23 | Stealthy SaaS Attack — ZIA Proxy + M365 Correlation |
| Q24 | ZIA Allowed Traffic to TI-Listed Domains/Categories |
| Q25 | ZIA C2 Block + EDR SecurityAlert Escalation |
| Q26 | HTTP Tunneling — Long or Base64-Encoded URL Path |
| Q27 | Domain Fronting — CDN SNI + Suspicious Path |
| Q28 | ZPA + ZIA Combined Insider Threat Hunt |
| Q29 | Patient APT — Multi-Channel Low & Slow Exfiltration |
| Q30 | Perfect Impostor — Account Takeover in Normal Traffic |
| Q31 | APT Control Evasion — Degrading Zscaler + EDR |
| **Q32** | **Zscaler DoH Egress to Non-Sanctioned Resolvers** |
| **Q33** | **Zscaler Browser-Push Notification Phishing** |
| **Q34** | **ZPA Application Discovery Sweep (first-time access)** |
| **Q35** | **Zscaler HTTP Method Anomaly: Bulk PUT/DELETE** |
| **Q36** | **Off-Hours Cloud Storage Upload Burst** |
| **Q37** | **ZPA + EDR Auth-Failure Correlation** |

> Bold entries are new additions in this release.

## MITRE ATT&CK coverage

| Tactic | Rules | Hunts |
|---|---|---|
| Initial Access | 1, 4, 6, 11, 12, 13, 15, 20 | Q33 |
| Execution | 6 | — |
| Persistence | — | — |
| Defense Evasion | 9, 14, 20, 21 | Q22, Q26, Q27 |
| Credential Access | 16 | Q37 |
| Discovery | 17, 18 | Q34 |
| Lateral Movement | 15, 17 | Q28 |
| Collection | 2, 7, 18 | Q23, Q35 |
| Command and Control | 1, 3, 8, 9, 12, 19 | Q11, Q24, Q25, Q27, Q32 |
| Exfiltration | 2, 3, 5, 7, 10, 19 | Q21, Q29, Q35, Q36 |
| Impact | — | Q35 |

## Tuning tips

1. **Visibility Loss (Rule 14)** — Triggers when no events arrive in a window. Whitelist scheduled outage windows or backup-feed identities by adjusting the threshold inline.
2. **Off-Hours Volume (Rule 10 / Q36)** — Adjust the off-hours window if your org runs follow-the-sun ops. Default is 20:00–06:00 local + weekends.
3. **Patient APT / Account Takeover (19, 20)** — These rules use multi-signal correlation across 7-day windows. Run as low-frequency (every 1h+) to avoid load.
4. **Mass Cloud Storage (Rule 7)** — Backup clients (Acronis, Veeam Cloud Connect) are frequent FPs. Allowlist by `SourceIP` or filter `RequestClientApplication`.
5. **ZPA Sweep (Q34)** — A penetration test will trigger it; pair with `IdentityInfo` to focus on accounts without recent privileged escalation history.
6. **Vendor-string columns** — Zscaler maps category to `DeviceCustomString2` and threat risk to `DeviceCustomString3` by default. Verify your NSS dictionary if rules look quiet.

## Optional: automated watchlist sync

`Watchlists/` ships a Bicep + PowerShell pair that provisions an Azure Automation Account + Runbook to pull Entra Named Locations on a schedule and update `NetworkAllowlist`. See [Watchlists/README.md](./Watchlists/README.md).

## Uninstall

```bash
az deployment group create -g <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=false
# then delete the rules in Sentinel → Analytics, and remove the watchlist / function in the portal
```

## License

MIT — see top-level `LICENSE`. Detection content provided as-is. Test in a non-production workspace before enabling broadly.
