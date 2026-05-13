# AADNonInteractiveUserSignInLogs — Sentinel Analytic Rules

Analytic/Scheduled Rules for Microsoft Sentinel derived from the
[AADNonInteractiveUserSignInLogs-ThreatHunting.kql](../AADNonInteractiveUserSignInLogs-ThreatHunting.kql)
threat hunting queries.

---

## Rule Inventory (23 rules + 14 hunting queries)

### HIGH Severity

| # | Rule File | Detection | MITRE |
|---|-----------|-----------|-------|
| 01 | `01-TokenTheft-RefreshTokenReplayNewLocation.yaml` | Same user, same app, different IP+country within 30 min | T1528, T1539 |
| 02 | `02-NIAuth-PrivilegedAuditActions.yaml` | Silent token → privileged audit operation within 60 min | T1078, T1098 |
| 03 | `03-NIAuth-ThreatIntelligenceFeed.yaml` | Non-interactive sign-in from TI-flagged malicious IP | T1528, T1078 |
| 04 | `04-Interactive-ToNIPivotTokenTheft.yaml` | Interactive (no MFA) → NI token from different country within 2h | T1528, T1539 |
| 05 | `05-DeviceCodeFlow-Abuse.yaml` | device_code protocol in non-interactive sign-ins | T1528, T1566 |
| 06 | `06-ROPC-AuthenticationDetected.yaml` | Resource Owner Password Credential (ROPC) flow detected | T1110, T1078 |
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

| Rule | Threshold | Old → New |
|---|---|---|
| 08 BruteForce-SuccessChain | `FailCount` | 5 → **15** |
| 09 MFAFatigue-SilentTokenAbuse | `MFAAttempts` / `NI_Count` | 3/10 → **8/25** |
| 14 NIAuth-BulkDataDownload | `CountryCount` | 3 → **4** |
| 15 NIAuth-RiskyUsers | `SignInCount` | 3 → **8** |
| 16 PasswordSpray-NonInteractive | `TargetCount` | 10 → **25** |
| 18 LegacyAuth-MFABypass | `UniqueIPs` | 3 → **8** |
| 20 NewRogue-OAuthApplication | `FailCount` | 20 → **50** |
| 21 ServicePrincipal-AnomalousIPSpread | `OpCount` | 50 → **150** |
| 23 BruteForce-SingleUserTargeted | `RefreshCount` | 50 → **150** |

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
    └── 23-BruteForce-SingleUserTargeted.yaml
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
