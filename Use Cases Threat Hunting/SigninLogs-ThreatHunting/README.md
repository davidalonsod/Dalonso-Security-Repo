# SigninLogs Threat Hunting Pack

Production-ready Microsoft Sentinel hunting queries and analytic rules for
Azure Active Directory / Entra ID sign-in telemetry.

---

## Contents

| File | Description |
|---|---|
| `SigninLogs-ThreatHunting.kql` | 28 hunting queries (KQL) |
| `Analytic-Rules/azuredeploy.json` | ARM template — 22 scheduled analytic rules |
| `Analytic-Rules/rules/*.yaml` | Individual rule definitions (YAML) |
| `Analytic-Rules/deploy-signin-rules.ps1` | PowerShell deployment script |

---

## Required Data Connectors

| Connector | Data Type | Required By |
|---|---|---|
| Azure Active Directory | SigninLogs | All rules + Q01-Q22 |
| Azure Active Directory | AADNonInteractiveUserSignInLogs | Q06, Q18 |
| Azure Active Directory | AADUserRiskEvents | Q08, Q17, Q18 |
| Azure Active Directory | AADRiskyUsers | Q27 |
| Azure Active Directory | AuditLogs | Q21, Q23, Rule 14 |
| Threat Intelligence | ThreatIntelIndicators | Q10, Q12, Q24 |
| Office 365 | OfficeActivity | Q22 |
| Microsoft Defender XDR / Sentinel | SecurityAlert | Q16, Q24 |
| Azure Active Directory | AADServicePrincipalSignInLogs | Q26 |

> **Minimum viable deployment**: Azure Active Directory connector only.
> Rules 01–22 use `SigninLogs` as the primary source. Rule 08 (AiTM) additionally
> joins `SecurityAlert` + `AADUserRiskEvents`. Rule 14 joins `AuditLogs` for
> password-reset events (SSPR). All other rules are `SigninLogs`-only.

---

## Hunting Queries — 28 Queries

### Brute Force & Password Spray (Q01–Q08)

| Query | Threat | Key Threshold |
|---|---|---|
| Q01 Password Spray | 1 IP → 10+ accounts, 60 min | uniqueAccounts >= 10 |
| Q02 Brute Force | 1 user, 10+ failures, 60 min | failures >= 10 |
| Q03 Distributed Coordinated Attack | 1 user, 10+ IPs, 30 days | uniqueIPs >= 10 |
| Q04 Impossible Travel | 3+ countries, 1 hour | dcount(Location) >= 3 |
| Q05 Credential Stuffing | 1 IP, 50+ error-50126, 20 days | attempts >= 50 |
| Q06 Brute Force then Success | failures then success in 30 min | failures >= 5 |
| Q07 Legacy Auth Brute Force | IMAP/POP/SMTP failures | failures >= 10 |
| Q08 Privileged Account Attack | admin-named account, low threshold | failures >= 3 |

### Breach Indicators (Q09–Q12)

| Query | Threat |
|---|---|
| Q09 Brute Force → Success Chain | Post-breach pivot detection |
| Q10 TI-Enriched Sign-Ins | IP matches threat intelligence feed |
| Q11 Smart Lockout / Blocked Users | ResultType 50053 cluster analysis |
| Q12 Nation State IP | estsNationStateIP risk event tag |

### Geolocation & Travel (Q13–Q15)

| Query | Threat |
|---|---|
| Q13 Impossible Travel (Detailed) | Sign-in velocity across continents |
| Q14 Location Summary | Per-user geographic baseline |
| Q15 Daily Country Trending | Anomalous country spike detection |

### Token & Session Abuse (Q16–Q18)

| Query | Threat | Extra Tables |
|---|---|---|
| Q16 AiTM Detection | Evilginx/Modlishka proxy token theft | SecurityAlert, AADUserRiskEvents |
| Q17 MFA Fatigue | Push bombardment (ResultType 50074/76/79/158) | SigninLogs |
| Q18 Token Replay after Password Reset | Session reuse after forced reset | AuditLogs, AADNonInteractiveUserSignInLogs |

### Legacy Auth & CA Policy (Q19–Q20)

| Query | Threat |
|---|---|
| Q19 Legacy Auth Usage | IMAP/POP/SMTP via ASIM _ASim_Authentication() |
| Q20 CA Failure Spike | ResultType 53003/53000/53001 surge detection |

### Cross-Table Correlations (Q21–Q24)

| Query | Correlates With | Threat |
|---|---|---|
| Q21 Sign-In → Privileged AuditLogs | AuditLogs | Risky sign-in followed by admin action |
| Q22 Risky Sign-In → M365 Activity | OfficeActivity | Compromised access pivoting to M365 |
| Q23 New Device + Privileged Action | AuditLogs | Rogue device registration + elevation |
| Q24 TI-IP + Active Alert Dual Confirm | ThreatIntelIndicators, SecurityAlert | High-confidence actor confirmation |

### UEBA & Behavioral (Q25–Q28)

| Query | Threat |
|---|---|
| Q25 Country/App Baseline Deviation | User authenticating from anomalous country or app |
| Q26 Service Principal Geo Anomaly | SP signing in from unusual geography |
| Q27 Multi-Signal Risk Score Dashboard | Composite risk: failures + risky events + blocked IPs |
| Q28 Distributed Attack (Botnet) | Single target, 10+ IPs, 30-day window |

---

## Analytic Rules — 22 Rules

### Original 10 Rules

| # | Rule Name | Severity | Frequency | Period | Tactics | Techniques |
|---|---|---|---|---|---|---|
| 01 | Password Spray Attack | High | 1h | 1h | CredentialAccess | T1110, T1110.003 |
| 02 | Brute Force Success Chain | High | 1h | 1h | CredentialAccess, InitialAccess | T1110, T1078 |
| 03 | Credential Stuffing | High | 6h | 7d | CredentialAccess | T1110, T1110.004 |
| 04 | Impossible Travel | Medium | 6h | 7d | InitialAccess | T1078 |
| 05 | Legacy Auth Brute Force | High | 1h | 1h | CredentialAccess, DefenseEvasion | T1110, T1550 |
| 06 | Privileged Account Attack | High | 1h | 1h | CredentialAccess, PrivilegeEscalation | T1110, T1078 |
| 07 | Nation State IP Sign-In | High | 6h | 7d | InitialAccess | T1078 |
| 08 | AiTM Token Theft | High | 1h | 7d | CredentialAccess, Collection | T1557, T1539 |
| 09 | Distributed Coordinated Attack | Medium | 12h | 30d | CredentialAccess | T1110 |
| 10 | MFA Fatigue Attack | Medium | 1h | 1h | CredentialAccess | T1621 |

### 12 New Rules (11–22)

> **None of the new rules duplicate Sentinel built-in analytics.** The built-in rules use ML-based Unfamiliar Sign-in Properties, Anomalous Token, and basic brute force heuristics. All rules below are deterministic, threshold-based detections targeting attack paths that built-in rules do not cover.

| # | Rule Name | Severity | Frequency | Period | Key Signal | Techniques |
|---|---|---|---|---|---|---|
| 11 | Slow & Low Password Spray (Multi-Day) | High | 1d | 7d | Same IP, 3+ accounts/day, 3+ days — evades 1h windows | T1110, T1110.003 |
| 12 | Account Enumeration via Error Codes | High | 6h | 6h | ≥40% of errors are 50034 (UserNotFound) — valid-user recon | T1087, T1087.002, T1110 |
| 13 | Service Account Interactive Browser Login | High | 4h | 4h | svc/api/bot accounts using browser auth — should never happen | T1078, T1078.004 |
| 14 | Password Reset → New-Country Sign-In | High | 2h | 1d | SSPR + new-country login within 2h — account takeover chain | T1078, T1098 |
| 15 | Off-Hours Privileged Account Sign-In | Medium | 1h | 1h | Admin accounts signing in 22:00–05:00 UTC | T1078, T1098 |
| 16 | Concurrent Sessions from Multiple Countries | High | 1h | 1h | Same user, 2+ countries within 30 min — parallel attacker session | T1078 |
| 17 | Device Code Flow Phishing | High | 4h | 4h | `deviceCode` protocol, 1 IP → 2+ accounts — Storm-0539/Midnight Blizzard TTP | T1566, T1566.002, T1528 |
| 18 | Legacy Auth First Appearance | High | 6h | 15d | Account used only modern auth for 14d now uses IMAP/POP/SMTP | T1550, T1078 |
| 19 | High-Frequency Automated Sign-Ins | Medium | 1h | 1h | 10+ successful logins/hr from same user+IP — C2 token refresh | T1078, T1539, T1528 |
| 20 | New Country Sign-In for Privileged Admin | High | 6h | 31d | Admin account — country not in 30d baseline (deterministic, no P2 needed) | T1078, T1078.004 |
| 21 | Conditional Access Policy Bypass | High | 4h | 4h | CA block (53003) → successful sign-in within 4h — policy gap exploit | T1078, T1562, T1562.001 |
| 22 | Fresh IP Authenticating Multiple Accounts | High | 2h | 15d | IP not seen in 14d successfully authenticates 5+ accounts in 2h | T1110, T1110.003, T1078 |

#### Design Decisions — No Duplicates with Built-In Sentinel Rules

| What built-in Sentinel covers | What these new rules add |
|---|---|
| Unfamiliar sign-in properties (ML-based, needs P2) | Rule 20 — deterministic new-country detection for privileged accounts only |
| Impossible travel (ML velocity model) | Rule 16 — deterministic concurrent-session detection (attacker + victim running in parallel) |
| Anomalous token / AiTM (SecurityAlert-based) | Rule 17 — device code phishing (different attack vector, pure SigninLogs) |
| Brute force against Azure Portal | Rules 11, 12 — slow/multi-day spray and user enumeration (different patterns) |
| Sign-in from TOR / anonymous IP | Rule 22 — fresh/never-before-seen IP with multi-account success |
| Legacy auth failures (built-in) | Rule 18 — first *appearance* of legacy auth for previously modern-only account |
| Password reset notifications | Rule 14 — reset + new-country login *chain* correlation |

---

## Deployment

### Option 1 — Azure Portal (ARM)

1. Go to **Deploy a custom template** in the Azure Portal
2. Click **Build your own template in the editor** → paste `Analytic-Rules/azuredeploy.json`
3. Set `workspace` = your Sentinel workspace name
4. Click **Review + Create**

### Option 2 — PowerShell (ARM)

```powershell
.\Analytic-Rules\deploy-signin-rules.ps1 `
    -SubscriptionId   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "sentinel-rg" `
    -WorkspaceName     "sentinel-workspace"
```

Preview without deploying:

```powershell
.\Analytic-Rules\deploy-signin-rules.ps1 `
    -SubscriptionId   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "sentinel-rg" `
    -WorkspaceName     "sentinel-workspace" `
    -DryRun
```

### Option 3 — Azure CLI (ARM)

```bash
az deployment group create \
  --resource-group sentinel-rg \
  --template-file Analytic-Rules/azuredeploy.json \
  --parameters workspace=sentinel-workspace
```

### Option 4 — Import Hunting Queries

In Sentinel > **Hunting** > **Queries** > **Import**,
upload `SigninLogs-ThreatHunting.kql` (paste each query using the **+ New query** button).

---

## Customization Guide

### Thresholds

All thresholds are defined as `let` variables at the top of each query/rule.

| Setting | Default | Adjust When |
|---|---|---|
| `userThreshold` (spray) | 10 | Large orgs may need 20+ |
| `failureThreshold` (brute) | 5–10 | High-failure environments |
| `velocityThreshold` (stuffing) | 50 | Low: fewer FPs; High: fewer misses |
| `ipThreshold` (distributed) | 10 | Persistent targeted attacks |
| `mfaBombardThreshold` | 5 | Reduce for VIP accounts |

### High-Risk Countries (Q04 / Q13)

Add exclusions for expected travel countries in the Impossible Travel queries:

```kql
let trustedCountries = dynamic(["United States","Canada","United Kingdom"]);
| where Locations !has_any (trustedCountries)
```

### Privileged Account Keywords (Rule 06 / Q08)

Edit the `privilegedKeywords` dynamic array to match your naming convention:

```kql
let privilegedKeywords = dynamic([
    "admin", "svc", "tier0", "da-", "ea-", "ga-",
    "your-custom-prefix"]);
```

### Entra ID P2 Rules

Rules 07 (Nation State IP) and 08 (AiTM) require **Entra ID P2** licensing for
`RiskEventTypes_V2` and `AADUserRiskEvents` data to be populated.

---

## MITRE ATT&CK Coverage

| Technique | Sub | Name | Rules |
|---|---|---|---|
| T1087 | .002 | Domain Account Discovery | 12 |
| T1110 | | Brute Force | 01, 02, 03, 05, 06, 09, 11, 12 |
| T1110 | .003 | Password Spraying | 01, 11, 22 |
| T1110 | .004 | Credential Stuffing | 03 |
| T1078 | | Valid Accounts | 02, 04, 06, 07, 13, 14, 15, 16, 18, 19, 20, 21, 22 |
| T1078 | .004 | Cloud Accounts | 13, 20 |
| T1098 | | Account Manipulation | 14, 15 |
| T1528 | | Steal Application Access Token | 17, 19 |
| T1539 | | Steal Web Session Cookie | 08, 19 |
| T1550 | | Use Alternate Auth Material | 05, 18 |
| T1557 | | Adversary-in-the-Middle | 08 |
| T1562 | .001 | Disable or Modify Tools | 21 |
| T1566 | | Phishing | 17 |
| T1566 | .002 | Spearphishing Link | 17 |
| T1621 | | MFA Request Generation | 10 |
