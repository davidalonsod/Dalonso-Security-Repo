# Google Workspace Threat Hunting Pack (GWSAlerts_CL)

> Microsoft Sentinel analytic rules and hunts for the **Google Workspace Alert Center** stream (`GWSAlerts_CL`) ingested via the Function App connector in this repo.

[![Status: Production](https://img.shields.io/badge/status-production-brightgreen)]()
[![Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?logo=microsoft-azure)]()
[![Table](https://img.shields.io/badge/table-GWSAlerts__CL-blue)]()
[![Rules](https://img.shields.io/badge/analytic_rules-10-orange)]()
[![Hunts](https://img.shields.io/badge/hunts-16-orange)]()

This folder contains a **direct-deployment ARM template** that mirrors the standardization pattern used by sibling Sentinel content packs in this organization. It is **complementary** to (not a replacement for) the Marketplace Solution package under [`../Solution/Package/`](../Solution/Package).

---

## Table of Contents

- [What's in this folder](#whats-in-this-folder)
- [Capabilities](#capabilities)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Staged deployment (recommended)](#staged-deployment-recommended)
- [Template parameters](#template-parameters)
- [NetworkAllowlist (trusted IPs)](#networkallowlist-trusted-ips)
- [Analytic rules (10)](#analytic-rules-10)
- [Hunting queries (16)](#hunting-queries-16)
- [MITRE ATT&CK coverage](#mitre-attck-coverage)
- [Tuning tips](#tuning-tips)
- [Optional: automated watchlist sync](#optional-automated-watchlist-sync)
- [Uninstall](#uninstall)

---

## What's in this folder

```
Analytic-Rules/
├── README.md                    ← This file
├── azuredeploy.json             ← Direct-deploy ARM (watchlist + function + 16 hunts + nested rules)
└── Watchlists/                  ← Optional Named-Locations → watchlist sync automation
    ├── azuredeploy-automation.bicep
    ├── README.md
    └── Sync-NamedLocationsToWatchlist.ps1
```

## Capabilities

- **10 analytic rules** covering: admin-privilege grants, email allowlist abuse, DLP, mobile-device compromise, domain-wide takeout, Drive ransomware, leaked-password chains, phishing spikes, SSO/super-admin changes, and state-sponsored attack warnings.
- **16 hunting queries**:
  - 10 existing (account-warning → exfil chain, admin persistence cluster, app-settings changed, cross-cloud correlation, DLP top offenders, first-seen alert types, inventory overview, phishing user-reported vs system-detected, stale-alert triage, suspicious programmatic login).
  - **6 new (G11–G16)** — Drive external sharing spike, OAuth token grant burst, login from new country, account recovery anomaly, calendar external invite burst, GWS+Entra cross-cloud correlation.
- **`NetworkAllowlist` watchlist** + scalar function **`ExcludeAllowlistedIPs_GWS(ip:string)`** that operates on the **nested JSON IP fields** GWS provides (`AlertData.loginDetails.ipAddress`, `AlertData.sourceIp`) — silences corporate egress and trusted partners without editing queries.
- **Staged-deploy switch** (`enableAnalyticRules`) lets you provision everything disabled, baseline the allowlist, then enable.
- **Single nested deployment** for atomic rule provisioning.

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Onboarded on a Log Analytics workspace |
| Data connector | This repo's `FunctionApp/` polling the Google Alert Center API; table `GWSAlerts_CL` must exist |
| Optional tables | `SigninLogs` (G16 cross-cloud correlation hunt) |
| Permissions | `Microsoft Sentinel Contributor` + `Log Analytics Contributor` |

## Quick start

```bash
az deployment group create \
  --resource-group <RG> \
  --template-file ./azuredeploy.json \
  --parameters workspace=<WORKSPACE_NAME>
```

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName <RG> `
  -TemplateFile .\azuredeploy.json `
  -workspace <WORKSPACE_NAME>
```

## Staged deployment (recommended)

```bash
# 1) Deploy watchlist + function + hunts. Rules created DISABLED.
az deployment group create -g <RG> \
  --template-file ./azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=false

# 2) Seed NetworkAllowlist (CSV: IPOrRange,Description,Owner,AddedDate) in the portal.
#    Wait 5–15 min for the watchlist to materialize before enabling rules.

# 3) Enable rules.
az deployment group create -g <RG> \
  --template-file ./azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=true
```

## Template parameters

| Parameter | Default | Description |
|---|---|---|
| `workspace` | *required* | Log Analytics workspace name |
| `location` | `[resourceGroup().location]` | Deploy region |
| `enableAnalyticRules` | `true` | Set `false` for staged deploy |
| `watchlistAlias` | `NetworkAllowlist` | Watchlist alias |
| `functionAlias` | `ExcludeAllowlistedIPs_GWS` | Scalar-function name (suffix avoids collisions with sibling packs) |
| `watchlistRawContent` | RFC1918 seed | Optional CSV body for the watchlist |

## NetworkAllowlist (trusted IPs)

The template provisions:

- **Watchlist** `NetworkAllowlist` — schema `IPOrRange,Description,Owner,AddedDate`, CIDR-aware.
- **Function** `ExcludeAllowlistedIPs_GWS(ip:string) -> bool` — scalar, **isfuzzy-safe** when the watchlist hasn't yet seeded.

Because GWS Alert Center events nest IPs inside dynamic JSON, every rule and hunt extracts the IP via:

```kql
| extend _GwsIp = coalesce(tostring(AlertData.loginDetails.ipAddress), tostring(AlertData.sourceIp), "")
| where not(ExcludeAllowlistedIPs_GWS(_GwsIp))
| project-away _GwsIp
```

Rules with no IP field still benefit by being deployable through the same template. Customize the allowlist:

```csv
IPOrRange,Description,Owner,AddedDate
203.0.113.0/24,Office egress NAT,NetOps,2026-05-01
198.51.100.10,Mailgateway,IT,2026-05-01
```

## Analytic rules (10)

| # | Rule | Severity | Tactics |
|---|---|---|---|
| 1 | GWS — User Granted Admin Privilege | Medium | Persistence, PrivilegeEscalation |
| 2 | GWS — Misconfigured Email Allowlist Causing Phishing Delivery | Medium | DefenseEvasion, InitialAccess |
| 3 | GWS — High-Severity DLP Rule Violation | High | Exfiltration, Collection |
| 4 | GWS — Mobile Device Compromised | High | InitialAccess, Persistence |
| 5 | GWS — Domain-Wide Takeout Initiated | High | Exfiltration |
| 6 | GWS — Potential Ransomware Detected on Drive | High | Impact |
| 7 | GWS — Leaked Password Followed by Suspicious Login (Chained) | High | InitialAccess, CredentialAccess |
| 8 | GWS — Phishing Alert Spike Across Multiple Users | Medium | InitialAccess |
| 9 | GWS — Sensitive Admin Action — SSO / Super Admin Changes | High | Persistence, PrivilegeEscalation, DefenseEvasion |
| 10 | GWS — Government-backed (State-Sponsored) Attack Warning | High | InitialAccess, CredentialAccess |

## Hunting queries (16)

| ID | Name |
|---|---|
| H01 | GWS Alerts — Account Warnings + Drive/Takeout Activity (Exfil Chain) |
| H02 | GWS Alerts — SSO / Admin Persistence Cluster |
| H03 | GWS Alerts — App Settings Changed (Calendar / Drive / Email / Mobile) |
| H04 | GWS Alerts — Cross-Tenant Correlation with Sentinel UEBA / Sign-in Logs |
| H05 | GWS Alerts — DLP Top Offenders & Sensitive File Hotspots |
| H06 | GWS Alerts — First-Seen Alert Types Per User (Anomaly Hunt) |
| H07 | GWS Alerts — Inventory Overview by Source / Type / Severity |
| H08 | GWS Alerts — Phishing User-Reported vs System-Detected Correlation |
| H09 | GWS Alerts — Stale / Unassigned Alerts (Triage Hygiene) |
| H10 | GWS Alerts — Suspicious Programmatic Login (OAuth Abuse) |
| **G11** | **Drive External Sharing Spike** |
| **G12** | **OAuth Token Grant Burst (Consent Phishing)** |
| **G13** | **Login from New Country per User** |
| **G14** | **Account Recovery Anomaly (Potential ATO)** |
| **G15** | **Calendar External Invite Burst** |
| **G16** | **GWS + Entra Cross-Cloud Identity Risk** |

> Bold entries are new additions in this release.

## MITRE ATT&CK coverage

| Tactic | Rules | Hunts |
|---|---|---|
| Initial Access | 2, 4, 7, 8, 10 | G12, G13, G15, G16 |
| Credential Access | 7, 10 | G12, G14, G16 |
| Persistence | 1, 4, 9 | G14, H02 |
| Privilege Escalation | 1, 9 | H02 |
| Defense Evasion | 2, 9 | — |
| Collection | 3 | G11, H05 |
| Exfiltration | 3, 5 | G11, H01, H05 |
| Impact | 6 | — |

## Tuning tips

1. **DLP rule volume (Rule 3)** — High-Severity threshold can be noisy in regulated environments. Pair with `Source` or `AlertData.ruleName` filter to scope to specific policies.
2. **Phishing spike (Rule 8)** — Sensitivity is keyed off recipient count, not message count. Adjust if your environment runs heavy security training simulations.
3. **State-sponsored (Rule 10)** — These are first-class Google indicators; treat any alert as a P1 incident, even one event.
4. **OAuth grant burst (G12)** — Tune `Users >= 5` threshold based on tenant size. A help-desk app rollout will trigger this.
5. **Geo-anomaly (G13)** — Frequent travelers/contractors generate FPs. Pair with `IdentityInfo` or recent travel attestation.
6. **JSON column shape** — Google occasionally changes `AlertData` schemas. If a rule goes silent, run the hunt equivalent to inspect the raw JSON via `| extend Raw = tostring(AlertData)`.

## Optional: automated watchlist sync

`Watchlists/` ships a Bicep + PowerShell pair that provisions an Azure Automation Account + Runbook to pull Entra Named Locations on a schedule and update `NetworkAllowlist`. See [Watchlists/README.md](./Watchlists/README.md).

## Uninstall

```bash
az deployment group create -g <RG> \
  --template-file ./azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=false
# then delete the rules in Sentinel → Analytics, and remove the watchlist / function in the portal
```

## Relationship to the Solution package

This direct-deploy ARM template is for organizations that want to install just the rules + hunts (and the standard allowlist plumbing) without going through the Marketplace. The Solution package under [`../Solution/Package/mainTemplate.json`](../Solution/Package/mainTemplate.json) remains the canonical artifact for AppSource distribution. Both reference the same `GWSAlerts_CL` table.
