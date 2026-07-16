# AADNonInteractiveUserSignInLogs — Sentinel Analytic Rules

Analytic/Scheduled Rules for Microsoft Sentinel derived from the
[AADNonInteractiveUserSignInLogs-ThreatHunting.kql](../AADNonInteractiveUserSignInLogs-ThreatHunting.kql)
threat hunting queries.

---

## Rule Inventory (28 rules + 14 hunting queries)

### HIGH Severity

| # | Rule File | Detection | MITRE |
|---|-----------|-----------|-------|
| 01 | `01-TokenTheft-RefreshTokenReplayNewLocation.yaml` | Same user, same app, different IP+country within 30 min | T1528, T1539 |
| 02 | `02-NIAuth-PrivilegedAuditActions.yaml` | Silent token → privileged audit operation within 60 min | T1078, T1098 |
| 03 | `03-NIAuth-ThreatIntelligenceFeed.yaml` | Non-interactive sign-in from TI-flagged malicious IP | T1528, T1078 |
| 04 | `04-Interactive-ToNIPivotTokenTheft.yaml` | Interactive (no MFA) → NI token from different country within 2h | T1528, T1539 |
| 05 | `05-DeviceCodeFlow-Abuse.yaml` | device_code protocol in non-interactive sign-ins | T1528, T1566 |
| 06 | `06-ROPC-AuthenticationDetected.yaml` | Successful ROPC (password-grant) sign-in across SigninLogs + NI - allowlist + min-count tuned | T1110, T1078, T1550 |
| 07 | `07-TOR-ProxyDetection.yaml` | Non-interactive sign-in via TOR exit node or anonymous proxy | T1090, T1090.003 |
| 08 | `08-BruteForce-SuccessChain.yaml` | >5 credential failures then a successful sign-in | T1110, T1110.004 |
| 09 | `09-MFAFatigue-SilentTokenAbuse.yaml` | MFA push bombing → approval → heavy NI token use | T1621 |
| 10 | `10-StaleToken-AfterPasswordChange.yaml` | NI tokens continue after password/auth method reset | T1528, T1550 |
| 11 | `11-AccountTakeover-EmailForwarding.yaml` | Inbox forwarding rule created within 2h of silent auth (BEC) | T1114.003 |
| 12 | `12-PIMAbuse-NonInteractiveAdminAction.yaml` | PIM role activated → NI token used within 30 min | T1078, T1098 |
| 13 | `13-OAuthConsent-ImmediateAbuse.yaml` | App consent granted → same app generates NI sign-ins within 24h | T1528, T1566 |
| 14 | `14-NIAuth-BulkDataDownload.yaml` | Silent auth correlated with >50 SharePoint/OneDrive operations | T1048, T1213 |
| 15 | `15-NIAuth-RiskyUsers.yaml` | Identity Protection risky users still generating NI sign-ins | T1078, T1528 |
| 16 | `16-PasswordSpray-NonInteractive.yaml` | Single IP targeting >10 accounts with spray error codes | T1110.003 |
| 24 | `24-ROPC-CredentialStuffing.yaml` | >=20 ROPC failures + >=8 distinct users from one IP / 1h (SigninLogs + NI) | T1110.003, T1078 |
| 25 | `25-ROPC-PrivilegedUser.yaml` | Successful ROPC for any account holding a privileged Entra role | T1078.004, T1098 |
| 27 | `27-ROPC-DormantAccount.yaml` | Successful ROPC on account with no sign-in in prior 30 d | T1078, T1110 |
| 28 | `28-ROPC-ImpossibleTravel.yaml` | Same user, >=2 countries AND >=2 IPs via ROPC inside 1 h (SigninLogs + NI) | T1078, T1550 |

### MEDIUM Severity

| # | Rule File | Detection | MITRE |
|---|-----------|-----------|-------|
| 17 | `17-ImpossibleTravel-MultipleCountries.yaml` | 3+ countries in 1 hour via NI sign-ins | T1078 |
| 18 | `18-LegacyAuth-MFABypass.yaml` | EAS/IMAP/POP3/SMTP non-interactive sign-ins (bypasses MFA+CA) | T1078, T1550 |
| 19 | `19-HighFrequency-TokenRefresh.yaml` | >50 token refreshes/hour from same user+IP | T1528 |
| 20 | `20-NewRogue-OAuthApplication.yaml` | OAuth app with no prior 30d history starts NI sign-ins | T1528, T1199 |
| 21 | `21-ServicePrincipal-AnomalousIPSpread.yaml` | Service principal authenticating from 4+ distinct IPs | T1078.004 |
| 22 | `22-HighRiskCountry-SignIn.yaml` | NI sign-ins from sanctioned/high-risk countries | T1078 |
| 23 | `23-BruteForce-SingleUserTargeted.yaml` | >20 failures from multiple IPs targeting one account | T1110.001 |
| 26 | `26-ROPC-NewCountryOrASN.yaml` | Successful ROPC from (Country, ASN) unseen for user in 30 d (SigninLogs + NI) | T1078, T1550 |

### ROPC tuning (shared)

Rules 06 and 24-28 correlate ROPC across **both** `SigninLogs` (interactive) and
`AADNonInteractiveUserSignInLogs`. ROPC password-grant sign-ins are logged in `SigninLogs`
far more often than in the non-interactive table, so querying only the NI table missed the
majority of real ROPC activity. Because unioning both tables increases event volume,
thresholds were tuned to keep false positives down (see the threshold table below).

All six rules share two inline allowlists you can edit per rule to suppress
legitimate ROPC traffic without losing the detection:

- `LegitRopcApps` - app display names that are known to use ROPC by design
  (Microsoft Authentication Broker, Microsoft Intune Company Portal, Azure AD Connect,
  Microsoft Office, Microsoft Office Authentication Broker). Extend as you identify
  others in your tenant.
- `LegitRopcUsers` - lower-cased UPNs of sanctioned sync / service accounts that
  intentionally use ROPC. Empty by default.

All six rules also strip allowlist IPs via `ExcludeAllowlistedIPs_AADNI()`
(NetworkAllowlist watchlist).

---

## Deployment

### Network Allowlist Watchlist (false-positive suppression)

All 23 rules call a KQL function `ExcludeAllowlistedIPs_AADNI()` that filters out `IPAddress` values matching the `NetworkAllowlist` Sentinel watchlist (sanctioned corporate egress IPs, trusted SaaS gateways, named locations). The 14 hunting queries (`AAD-Hunt-NI-01` through `AAD-Hunt-NI-14`) deploy under the **Hunting** blade.

The watchlist + function are deployed automatically by `azuredeploy.json`. For scheduled sync from Entra Named Locations, see [`Watchlists/README.md`](Watchlists/README.md).

### New ARM template parameters

| Parameter | Default | Purpose |
|---|---|---|
| `workspaceName` | (required) | Sentinel workspace name. |
| `location` | `[resourceGroup().location]` | Azure region. |
| `enableAnalyticRules` | `true` | If `false`, all 23 rules deploy **disabled** for staged rollout. |
| `watchlistAlias` | `NetworkAllowlist` | Trusted-IP exclusion watchlist alias. |
| `functionAlias` | `ExcludeAllowlistedIPs_AADNI` | savedSearches function used by rules (unique alias avoids collision with sibling repos). |
| `watchlistRawContent` | empty (seeds RFC1918) | Override CSV (CRLF-separated; header `IPOrRange,Description,Owner,AddedDate`). Sync runbook replaces with Entra Named Locations. |

### Threshold tuning (May 2026)

Inline thresholds raised ~2-3x to reduce production noise:

| Rule | Threshold variable | Old → New |
|---|---|---|
| 08 BruteForce-SuccessChain | `FailCount` | 5 → **15** |
| 09 MFAFatigue-SilentTokenAbuse | `MFAAttempts` / `NI_Count` | 3 / 10 → **8 / 25** |
| 14 NIAuth-BulkDataDownload | `OpCount` | 50 → **150** |
| 15 NIAuth-RiskyUsers | `SilentCount` | (none) → **5** |
| 16 PasswordSpray-NonInteractive | `TargetCount` | 10 → **25** |
| 17 ImpossibleTravel-MultipleCountries | `CountryCount` | 3 → **4** |
| 18 LegacyAuth-MFABypass | `SignInCount` | 3 → **8** |
| 19 HighFrequency-TokenRefresh | `RefreshCount` | 50 → **150** |
| 21 ServicePrincipal-AnomalousIPSpread | `UniqueIPs` | 3 → **8** |
| 23 BruteForce-SingleUserTargeted | `FailCount` | 20 → **50** |

> **Consistency note (Jul 2026):** the `rules/*.yaml` files were re-synced to these values.
> Previously the ARM template (`azuredeploy.json`) carried the tuned thresholds while the
> YAML rules still had the original lower values, so the two deployment paths behaved
> differently. Both now match. Rule 15 previously had **no** threshold (it alerted on any
> risky user with a single silent sign-in) and now requires `SilentCount >= 5`.

### ROPC + SigninLogs correlation (Jul 2026)

ROPC rules 06 and 24-28 now union `SigninLogs` with `AADNonInteractiveUserSignInLogs`
(ROPC surfaces mostly in `SigninLogs`). Thresholds were adjusted to offset the added volume:

| Rule | Threshold | Old → New |
|---|---|---|
| 06 ROPC-AuthenticationDetected | `MinSuccessfulSignIns` (per user / 1h) | 1 (any) → **3** |
| 24 ROPC-CredentialStuffing | `FailCount` / `Users` | 15 / 5 → **20 / 8** |
| 28 ROPC-ImpossibleTravel | added `IPCount` requirement | (none) → **>= 2 distinct IPs** |

Rules 25 (privileged), 26 (new country/ASN) and 27 (dormant) keep their any-match trigger
(all high-signal); 26 additionally drops blank-location rows.

### Hunting Queries (14)

Deployed as `savedSearches` in category `Hunting Queries`. Visible under the Sentinel **Hunting** blade.

- `AAD-Hunt-NI-01` — NI Sign-Ins from New/Unseen Countries (30d baseline)
- `AAD-Hunt-NI-02` — Dormant Accounts with Sudden NI Token Activity
- `AAD-Hunt-NI-03` — NI Token Refresh Frequency Spike (5× baseline)
- `AAD-Hunt-NI-04` — NI Auth to Sensitive/Admin Apps Outside Business Hours
- `AAD-Hunt-NI-05` — Interactive-to-NI Token Pivot
- `AAD-Hunt-NI-06` — NI Token Used Across Many Apps or IPs Simultaneously
- `AAD-Hunt-NI-07` — Service Principal First-Seen NI IP
- `AAD-Hunt-NI-08` — Long-Lived Token Still Refreshing After Password Change
- `AAD-Hunt-NI-09` — OAuth Consent Grant → Immediate NI Token Issuance
- `AAD-Hunt-NI-10` — Cross-Tenant NI Token Issuance (B2B Anomaly)
- `AAD-Hunt-NI-11` — Tokens Persisting Past CA Block (CAE Disabled)
- `AAD-Hunt-NI-12` — NI Tokens for Anomalous Resource APIs
- `AAD-Hunt-NI-13` — Impossible Token Velocity Across Countries
- `AAD-Hunt-NI-14` — NI Token Spike from Unmanaged Devices

### Staged deployment

```powershell
# Stage 1 - deploy disabled for review
New-AzResourceGroupDeployment `
  -ResourceGroupName "your-rg" `
  -TemplateFile .\azuredeploy.json `
  -workspaceName "your-workspace" `
  -enableAnalyticRules $false

# Stage 2 - enable after review
New-AzResourceGroupDeployment `
  -ResourceGroupName "your-rg" `
  -TemplateFile .\azuredeploy.json `
  -workspaceName "your-workspace" `
  -enableAnalyticRules $true
```

### Prerequisites

```powershell
Install-Module Az.Accounts, Az.Resources, Az.SecurityInsights -Force
```

### Option A — ARM Template (Recommended — all 23 rules in one operation)

```powershell
.\deploy-analytic-rules.ps1 `
    -SubscriptionId   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod"
```

### Option B — YAML per-rule via REST API (richer metadata: customDetails, alertDetailsOverride, grouping)

```powershell
.\deploy-analytic-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DeploymentMode    YAML
```

### Dry Run (validate without deploying)

```powershell
.\deploy-analytic-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DryRun
```

---

## File Structure

```
Sentinel-AnalyticRules-AADNonInteractive\
├── azuredeploy.json              ← ARM template (23 rules + 14 hunts + watchlist + function)
├── deploy-analytic-rules.ps1     ← Deployment script (ARM + YAML modes)
├── README.md                     ← This file
├── Watchlists\                   ← NetworkAllowlist sync (Entra Named Locations)
│   ├── azuredeploy-automation.bicep
│   ├── Sync-NamedLocationsToWatchlist.ps1
│   └── README.md
└── rules\
    ├── 01-TokenTheft-RefreshTokenReplayNewLocation.yaml
    ├── 02-NIAuth-PrivilegedAuditActions.yaml
    ├── 03-NIAuth-ThreatIntelligenceFeed.yaml
    ├── 04-Interactive-ToNIPivotTokenTheft.yaml
    ├── 05-DeviceCodeFlow-Abuse.yaml
    ├── 06-ROPC-AuthenticationDetected.yaml
    ├── 07-TOR-ProxyDetection.yaml
    ├── 08-BruteForce-SuccessChain.yaml
    ├── 09-MFAFatigue-SilentTokenAbuse.yaml
    ├── 10-StaleToken-AfterPasswordChange.yaml
    ├── 11-AccountTakeover-EmailForwarding.yaml
    ├── 12-PIMAbuse-NonInteractiveAdminAction.yaml
    ├── 13-OAuthConsent-ImmediateAbuse.yaml
    ├── 14-NIAuth-BulkDataDownload.yaml
    ├── 15-NIAuth-RiskyUsers.yaml
    ├── 16-PasswordSpray-NonInteractive.yaml
    ├── 17-ImpossibleTravel-MultipleCountries.yaml
    ├── 18-LegacyAuth-MFABypass.yaml
    ├── 19-HighFrequency-TokenRefresh.yaml
    ├── 20-NewRogue-OAuthApplication.yaml
    ├── 21-ServicePrincipal-AnomalousIPSpread.yaml
    ├── 22-HighRiskCountry-SignIn.yaml
    ├── 23-BruteForce-SingleUserTargeted.yaml
    ├── 24-ROPC-CredentialStuffing.yaml
    ├── 25-ROPC-PrivilegedUser.yaml
    ├── 26-ROPC-NewCountryOrASN.yaml
    ├── 27-ROPC-DormantAccount.yaml
    └── 28-ROPC-ImpossibleTravel.yaml
```

---

## Required Data Connectors

| Connector | Tables Used |
|-----------|-------------|
| Azure Active Directory | `AADNonInteractiveUserSignInLogs`, `SigninLogs`, `AuditLogs`, `AADRiskyUsers`, `AADRiskySignIns` |
| Threat Intelligence | `ThreatIntelIndicators` (unified TI table — `ThreatIntelligenceIndicator` is deprecated) |
| Office 365 | `OfficeActivity` |
| Microsoft 365 Defender / UEBA | `BehaviorAnalytics` |

---

## Post-Deployment Tuning

| Rule | Tuning Recommendation |
|------|-----------------------|
| `22-HighRiskCountry-SignIn` | Edit the `HighRiskCountries` dynamic list per your org policy |
| `19-HighFrequency-TokenRefresh` | Adjust the `> 50` threshold per your app baseline |
| `23-BruteForce-SingleUserTargeted` | Adjust `> 20` failure threshold per your lockout policy |
| `16-PasswordSpray-NonInteractive` | Adjust the `> 10` target account threshold |
| `03-NIAuth-ThreatIntelligenceFeed` | Requires an active TI data connector with NetworkIP indicators |
| `07-TOR-ProxyDetection` | Requires TI indicators tagged with `tor`/`proxy`/`anonymizer` |

---

## Required Azure RBAC

- **Microsoft Sentinel Contributor** — to create analytic rules
- **Contributor** on the resource group — for ARM template deployment

---

*Source: AADNonInteractiveUserSignInLogs-ThreatHunting.kql — Updated 2026-02-24*
