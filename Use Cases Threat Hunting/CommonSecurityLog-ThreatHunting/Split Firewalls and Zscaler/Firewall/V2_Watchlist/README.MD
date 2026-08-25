# Firewall Threat Hunting Pack (CommonSecurityLog)

> **Vendor-agnostic** Microsoft Sentinel detections and hunts for `CommonSecurityLog` (Fortinet, Palo Alto Networks, Zscaler, Check Point, Cisco). Drop in, enable, tune.

[![Status: Production](https://img.shields.io/badge/status-production-brightgreen)]()
[![Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?logo=microsoft-azure)]()
[![Tables](https://img.shields.io/badge/table-CommonSecurityLog-blue)]()
[![Rules](https://img.shields.io/badge/analytic_rules-16-orange)]()
[![Hunts](https://img.shields.io/badge/hunts-22-orange)]()

Are Your Firewall Logs Too Noisy? Stop Attacks with Sentinel https://youtu.be/_q_tG7GscZA

## Table of Contents

- [What's in this folder](#whats-in-this-folder)
- [Capabilities](#capabilities)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Staged deployment (recommended)](#staged-deployment-recommended)
- [Template parameters](#template-parameters)
- [NetworkAllowlist (trusted IPs)](#networkallowlist-trusted-ips)
- [Analytic rules (16)](#analytic-rules-16)
- [Hunting queries (22)](#hunting-queries-22)
- [MITRE ATT&CK coverage](#mitre-attck-coverage)
- [Tuning tips](#tuning-tips)
- [Optional: automated watchlist sync](#optional-automated-watchlist-sync)
- [Uninstall](#uninstall)
- [License](#license)

---

## What's in this folder

```
Firewall/
├── README.md                          ← This file
├── Analytic-Rules/
│   ├── azuredeploy.json               ← Single ARM template, deploys everything
│   ├── deploy-rules.ps1               ← Helper script
│   └── rules/                         ← Standalone .yaml / .kql per rule
├── Hunting-Queries/                   ← Standalone .yaml / .kql per hunt
└── Watchlists/                        ← Optional named-location → watchlist sync
    ├── azuredeploy-automation.bicep
    ├── README.md
    └── Sync-NamedLocationsToWatchlist.ps1
```

## Capabilities

- **16 analytic rules** spanning Beaconing, Exfiltration, TI matching, Port-scan, Geo-anomaly, Lateral Movement, Vendor-specific (Fortinet IPS, Palo Alto Threat / Zone, SSL-VPN brute force), Protocol Anomaly, Sign-in / Security Alert correlation.
- **22 hunting queries** for SOC analysts (Q01–Q26): same coverage broadened to 7/30/90-day windows plus DoH egress, crypto-miner ports, Tor/I2P, large-transfer detection, first-seen inbound external IPs.
- **NetworkAllowlist watchlist** (`IPOrRange`, CIDR-aware) wired through every query via the scalar function `ExcludeAllowlistedIPs_Firewall(ip:string) -> bool` — silence corporate egress, VPN, NAT, partner ranges without editing KQL.
- **Staged-deploy switch** (`enableAnalyticRules`) — deploy disabled, baseline the allowlist, then flip the switch.
- **Single nested deployment** (`scope=inner`) wraps all alertRules so deploys are atomic and idempotent.

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Onboarded onto a Log Analytics workspace |
| Data connector | A CEF/Syslog forwarder producing `CommonSecurityLog` (Fortinet, Palo Alto, Zscaler, Check Point, Cisco supported out of the box) |
| Optional tables | `SigninLogs` (rule "Correlation: Firewall + Sign-In"), `SecurityAlert` (Q14), `IdentityInfo` (Q20) |
| Permissions | `Microsoft Sentinel Contributor` + `Log Analytics Contributor` on the target resource group |

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
# 1) Deploy the watchlist, function, hunts. Rules created DISABLED.
az deployment group create -g <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=false

# 2) Seed NetworkAllowlist in the portal (or pass watchlistRawContent CSV).
#    Wait 5–15 min for the watchlist to materialize.

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
| `enableAnalyticRules` | `true` | Set `false` for staged deploy (rules created disabled) |
| `watchlistAlias` | `NetworkAllowlist` | Watchlist alias (rarely changed) |
| `functionAlias` | `ExcludeAllowlistedIPs_Firewall` | Scalar-function name (avoid collisions across solutions) |
| `watchlistRawContent` | *(empty)* | Optional CSV body to seed the watchlist; defaults to RFC1918 ranges |

## NetworkAllowlist (trusted IPs)

The template provisions:

- **Watchlist** `NetworkAllowlist` — schema `IPOrRange,Description,Owner,AddedDate`; CIDR supported. Seeded with `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` by default.
- **Function** `ExcludeAllowlistedIPs_Firewall(ip:string) -> bool` — scalar; **isfuzzy-safe** when the watchlist hasn't yet materialized (returns `false` so queries don't error on first deploy).

Every analytic rule and hunt that references `SourceIP` or `DestinationIP` is filtered via this function (using `column_ifexists` so it works across vendors that may not populate every column). To customize:

```kql
// CSV row:
IPOrRange,Description,Owner,AddedDate
203.0.113.0/24,Office egress NAT,NetOps,2026-05-01
198.51.100.42,Partner SFTP,Vendor,2026-05-01
```

…and update the watchlist in Sentinel → Configuration → Watchlists. Function-side cache propagation is typically <15 minutes.

## Analytic rules (16)

| # | Rule | Severity | Tactics |
|---|---|---|---|
| 1 | Firewall Beaconing Detection — Regular Outbound Connections | High | CommandAndControl |
| 2 | Firewall Anomalous Outbound Data Volume — Exfiltration Risk | High | Exfiltration |
| 3 | Firewall Traffic to Threat Intelligence Flagged IP | High | CommandAndControl, InitialAccess |
| 4 | Firewall Port Scan Detection — Vertical and Horizontal Sweeps | Medium | Discovery |
| 5 | Firewall Allowed Traffic to High-Risk Country | Medium | InitialAccess, Exfiltration |
| 6 | Lateral Movement — Internal Host Port Sweep on Admin/Pivot Ports | High | LateralMovement |
| 7 | Fortinet IPS — High-Frequency Intrusion Prevention Alerts | High | InitialAccess, Execution |
| 8 | Palo Alto — Threat Log Events (Spyware, Wildfire, Vulnerability) | High | InitialAccess, CommandAndControl |
| 9 | Firewall New First-Seen External IP Contacted | Medium | CommandAndControl |
| 10 | Correlation: Firewall Allowed Traffic + Azure AD Sign-In from Same IP | High | InitialAccess, DefenseEvasion |
| 11 | Correlation: Firewall Traffic + Active Security Alert — Shared IOC IP | High | InitialAccess, CommandAndControl |
| 12 | Correlation: Firewall Traffic Matching TI Domain / URL | High | CommandAndControl |
| 13 | Palo Alto — High-Volume Inter-Zone Policy Denies | Medium | DefenseEvasion, Discovery |
| 14 | Fortinet SSL-VPN and Admin Authentication Brute Force | High | CredentialAccess |
| 15 | Protocol Anomaly — HTTP or HTTPS on Non-Standard Ports | High | CommandAndControl |
| 16 | Anomalous User Firewall Activity — High Request Count or Data Volume | High | InitialAccess, DefenseEvasion |

## Hunting queries (22)

| ID | Name |
|---|---|
| Q01 | Beaconing Detection — All Vendors |
| Q02 | Data Exfiltration — Anomalous Outbound Volume |
| Q03 | Threat Intelligence IP Correlation |
| Q04 | Port Scanning — Single Source to Many Destinations |
| Q05 | High-Risk Country Inbound and Outbound Traffic |
| Q06 | Lateral Movement — Internal Port Sweep |
| Q07 | Fortinet — IPS and Application Control Blocks |
| Q08 | Palo Alto — Threat Logs Breakdown |
| Q12 | New and First-Seen External IP Allowed Through Firewall |
| Q13 | Firewall Allow + Azure AD Sign-In Correlation |
| Q14 | CommonSecurityLog + SecurityAlert IOC Correlation |
| Q15 | CommonSecurityLog + ThreatIntelligence Domain Match |
| Q16 | Palo Alto — Zone Transfer Violations and Policy Denies |
| Q17 | Fortinet — Repeated Auth Failures SSL-VPN and Admin |
| Q19 | Protocol Anomaly — HTTP/HTTPS on Non-Standard Ports |
| Q20 | Firewall + IdentityInfo Risky User Correlation |
| **Q21** | **DNS-over-HTTPS Egress to Non-Standard Resolvers** |
| **Q22** | **Egress on Crypto-Miner / Stratum Ports** |
| **Q23** | **Inbound SSH/RDP Brute Force — Dispersed Targets** |
| **Q24** | **Large Single-Session Outbound Transfer (>500MB)** |
| **Q25** | **Tor/I2P/Anonymizer Egress** |
| **Q26** | **First-Seen Inbound Allowed from External IP (30d)** |

> Bold entries are new additions in this release.

## MITRE ATT&CK coverage

| Tactic | Rules | Hunts |
|---|---|---|
| Initial Access | 3, 5, 7, 8, 10, 11, 16 | Q05, Q12, Q26 |
| Execution | 7 | Q07 |
| Persistence | — | — |
| Defense Evasion | 10, 13, 16 | Q16 |
| Credential Access | 14 | Q17, Q23 |
| Discovery | 4, 13 | Q04 |
| Lateral Movement | 6 | Q06 |
| Command and Control | 1, 3, 8, 9, 11, 12, 15 | Q01, Q03, Q14, Q15, Q19, Q21, Q25 |
| Exfiltration | 2, 5 | Q02, Q24 |
| Impact | — | Q22 |

## Tuning tips

1. **Beaconing (Rule 1 / Q01)** — Baseline is interval-regularity. If your DNS recursors or NTP servers light it up, add their IPs to `NetworkAllowlist`.
2. **Data Volume (Rule 2 / Q02 / Q24)** — Backup egress and cloud-sync clients are recurring false positives. Allowlist the SaaS egress edge or backup target, not the corporate egress NAT.
3. **High-Risk Country (Rule 5 / Q05)** — Country list lives inline in the KQL; edit and re-deploy to match your travel-risk policy.
4. **Fortinet IPS / Palo Alto Threat (7, 8)** — Severity thresholds are vendor-string–based; verify your firewall is sending `EventSeverity` or `DeviceCustomString*` fields.
5. **DoH / Tor / Miner (Q21, Q22, Q25)** — These are *hunts*, not alerts. Promote to a rule once you've baselined.

## Optional: automated watchlist sync

`Watchlists/` contains a Bicep + PowerShell pair that creates an Azure Automation Account + Runbook that pulls Entra Named Locations on a schedule and pushes them to `NetworkAllowlist`. See [Watchlists/README.md](./Watchlists/README.md) for SP-auth deploy.

## Uninstall

```bash
az deployment group create -g <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=false
# then delete the rules in Sentinel → Analytics, and remove the watchlist / function via portal
```

## License

MIT — see top-level `LICENSE`. Detection content is provided as-is. Test in a non-production workspace before enabling broadly.
