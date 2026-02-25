# AADNonInteractiveUserSignInLogs — Sentinel Analytic Rules

Analytic/Scheduled Rules for Microsoft Sentinel derived from the
[AADNonInteractiveUserSignInLogs-ThreatHunting.kql](../AADNonInteractiveUserSignInLogs-ThreatHunting.kql)
threat hunting queries.

---

## Rule Inventory (23 rules)

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
├── azuredeploy.json              ← ARM template (all 23 rules)
├── deploy-analytic-rules.ps1     ← Deployment script (ARM + YAML modes)
├── README.md                     ← This file
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
| Threat Intelligence | `ThreatIntelligenceIndicator` |
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
