# 🔐 ADFSSignInLogs — Threat Hunting Queries

KQL threat hunting queries for Microsoft Sentinel targeting **Active Directory Federation Services (ADFS)** federated authentication events captured in the `ADFSSignInLogs` table.

> This is a **hunting-only** pack. Queries are designed to be run interactively in  
> **Microsoft Sentinel → Logs** or the **Hunting** blade.

---

## Table: ADFSSignInLogs

`ADFSSignInLogs` captures authentication events processed by on-premises ADFS federated to Azure AD, including WS-Federation, SAML 2.0, OAuth 2.0, and OpenID Connect flows.

**Key columns used in these queries:**

| Column | Description |
|---|---|
| `UserPrincipalName` | Authenticating user UPN |
| `IPAddress` | Source IP of the authentication request |
| `Location` | Country/region of the source IP |
| `ResultType` | `0` = success; non-zero = error code |
| `ResultDescription` | Human-readable error description |
| `TokenIssuerName` | ADFS server that issued the token |
| `TokenIssuerType` | `ADFederationServices` or `AzureAD` |
| `AuthenticationRequirement` | `singleFactorAuthentication` or `multiFactorAuthentication` |
| `AuthenticationProcessingDetails` | Raw protocol/flow details (ROPC, device code, etc.) |
| `ConditionalAccessStatus` | CA policy evaluation result |
| `UserAgent` | Client user agent string |
| `AppDisplayName` | Application the user authenticated to |
| `AppId` | OAuth client app ID |
| `CorrelationId` | End-to-end request correlation |
| `UniqueTokenIdentifier` | Unique token ID (useful for token replay detection) |

**ADFS-specific error codes:**

| Code | Meaning |
|---|---|
| `396083` | Extranet lockout triggered |
| `50053` | Account locked out |
| `50126` | Invalid credentials |
| `50034` | User not found |

---

## 📋 Query Inventory (36 queries)

### Section 1 — Data Overview & Coverage

| # | Query | Purpose |
|---|---|---|
| 1 | Volume & failure rates | Breakdown by `AuthenticationRequirement` |
| 2 | Top error codes | ADFS-specific + Azure AD codes |
| 3 | ADFS server coverage | Identify all token issuers in the farm |
| 4 | Daily authentication trend | Volume baseline & spike detection |

### Section 2 — Brute Force & Password Spray

| # | Query | Purpose |
|---|---|---|
| 5 | Extranet lockout (error 396083) | ADFS extranet lockout events per user |
| 6 | Password spray — single IP, many accounts | >10 target accounts from one IP |
| 7 | Low-and-slow spray | 2–15 attempts/hour below lockout threshold |
| 8 | Brute force — single user targeted | >20 failures from multiple IPs against one account |
| 9 | Brute force → success chain | Failures followed by successful sign-in |

### Section 3 — Geolocation & IP Intelligence

| # | Query | Purpose |
|---|---|---|
| 10 | High-risk country sign-ins | Sanctioned / high APT-activity countries |
| 11 | Impossible travel | 3+ countries in 1 hour |
| 12 | New country baseline | First-time access from unseen location |
| 13 | TOR / anonymous proxy (TI correlation) | Anonymizer infrastructure via TI feed |
| 14 | Threat intelligence — malicious IPs | ADFS auth from TI-flagged IPs |

### Section 4 — Golden SAML & Token Abuse

| # | Query | Purpose |
|---|---|---|
| 15 | Unexpected token issuer | Golden SAML indicator — unknown `TokenIssuerName` |
| 16 | Single-factor MFA gap | `singleFactorAuthentication` + ADFS issuer |
| 17 | High SAML token volume | >50 tokens/hour per user+IP = automated replay |
| 18 | Stale token after password change | ADFS tokens continue after password reset (AuditLogs join) |

### Section 5 — Legacy Authentication & Protocol Abuse

| # | Query | Purpose |
|---|---|---|
| 19 | Legacy auth via ADFS | EAS/IMAP/POP3 detected via UserAgent — bypasses MFA+CA |
| 20 | ROPC / device code flow | High-risk flows via `AuthenticationProcessingDetails` |

### Section 6 — Cross-Table Correlations

| # | Query | Correlates with | Purpose |
|---|---|---|---|
| 21 | ADFS auth → privileged audit action | `AuditLogs` | Token used for admin operation within 60 min |
| 22 | ADFS auth → email forwarding rule | `OfficeActivity` | BEC indicator within 2h |
| 23 | ADFS auth → bulk data download | `OfficeActivity` | Exfiltration via federated session |
| 24 | ADFS auth + risky users | `AADRiskyUsers` | Identity Protection risky users still using ADFS |
| 25 | ADFS auth + risky sign-ins | `SigninLogs` | Entra risk events correlated with ADFS activity |
| 26 | MFA fatigue → ADFS pivot | `SigninLogs` | MFA bombing approval → ADFS federated resource access |
| 27 | PIM activation → ADFS sign-in | `AuditLogs` | Privileged role activated, then ADFS token used |
| 28 | Interactive ↔ ADFS country mismatch | `SigninLogs` | Cloud sign-in from country A, ADFS from country B same day |
| 29 | OAuth consent → ADFS federation abuse | `AuditLogs` | Illicit consent + ADFS sign-ins within 24h |

### Section 7 — Botnet & Automated Attack Detection

| # | Query | Purpose |
|---|---|---|
| 30 | Botnet user agent | Same UA across >50 accounts |
| 31 | C2 heartbeat — regular interval | Low stddev token refresh cadence |
| 32 | IP reuse across many accounts | One IP authenticating as many different users |
| 33 | Botnet TI correlation | ADFS sign-ins from TI-tagged C2/malware IPs |

### Section 8 — Forensic Timeline & Hunting Dashboard

| # | Query | Purpose |
|---|---|---|
| 34 | Forensic timeline per user | 5-table union: ADFS + Interactive + NI + Audit + SecurityAlert |
| 35 | Sign-in spike detection | 3× daily average = statistical anomaly alert |
| 36 | Multi-signal risk dashboard | Score users across: impossible travel, spray, lockout, country, risk |

---

## 🔌 Required Data Connectors

| Connector | Table | Used in |
|---|---|---|
| **Azure Active Directory** | `ADFSSignInLogs` | All queries |
| **Azure Active Directory** | `AuditLogs` | Q18, Q21, Q27, Q29 |
| **Azure Active Directory** | `SigninLogs` | Q26, Q28, Q34 |
| **Azure Active Directory** | `AADRiskyUsers` | Q24, Q36 |
| **Azure Active Directory** | `SigninLogs` (risk fields) | Q25 |
| **Azure Active Directory** | `AADNonInteractiveUserSignInLogs` | Q34 (forensic timeline) |
| **Threat Intelligence** | `ThreatIntelIndicators` | Q13, Q14, Q33 |
| **Office 365** | `OfficeActivity` | Q22, Q23 |
| **Microsoft Defender XDR** | `SecurityAlert` | Q34 (forensic timeline) |

---

## ✅ KQL Syntax Validation

All 36 queries have been validated against a live Sentinel workspace using the included Python script:

```powershell
# From C:\Users\dalonso\
python validate-adfs-queries.py
```

Authenticates via device code — no Azure CLI required.

---

## ⚠️ Customization Required

| Query | What to update |
|---|---|
| Q15 — Unexpected Token Issuer | Replace `"YOUR_ADFS_FEDERATION_SERVICE_NAME"` with your ADFS service name |
| Q10, Q36 — High-Risk Countries | Adjust the `HighRiskCountries` list to match your org's policy |
| Q34 — Forensic Timeline | Replace `"testuser@example.com"` with the target UPN |

---

## 🚨 Sentinel Analytic Rules

Scheduled Analytic Rules for Microsoft Sentinel derived from `ADFSSignInLogs-ThreatHunting.kql`.  
Rules are located in `Sentinel-AnalyticRules-ADFS\`.

### Rule Inventory (23 rules)

#### HIGH Severity

| # | Rule File | Detection | MITRE |
|---|-----------|-----------|-------|
| 01 | `01-ADFS-ExtravnetLockout-Spray.yaml` | Extranet lockout (396083) across >3 accounts from same IP | T1110.003 |
| 02 | `02-ADFS-PasswordSpray-SingleIP.yaml` | Single IP targeting >10 accounts with ADFS error codes | T1110.003 |
| 03 | `03-ADFS-BruteForce-SuccessChain.yaml` | >5 ADFS failures then a successful sign-in (same user) | T1110, T1078 |
| 04 | `04-ADFS-GoldenSAML-UnknownIssuer.yaml` | Token issued by unknown/unexpected `TokenIssuerName` | T1606.002, T1558 |
| 05 | `05-ADFS-ThreatIntelligence-MaliciousIP.yaml` | ADFS authentication from TI-flagged malicious IP | T1078, T1199 |
| 06 | `06-ADFS-TOR-AnonymousProxy.yaml` | ADFS sign-in via TOR exit node or anonymous proxy | T1090, T1090.003 |
| 07 | `07-ADFS-ImpossibleTravel.yaml` | ADFS auth from 3+ countries within 1 hour | T1078 |
| 08 | `08-ADFS-StaleToken-AfterPasswordChange.yaml` | ADFS tokens continue after password/auth method reset | T1528, T1550 |
| 09 | `09-ADFS-PrivilegedAuditAction.yaml` | ADFS token used for privileged audit operation within 60 min | T1078, T1098 |
| 10 | `10-ADFS-EmailForwardingRule.yaml` | Inbox forwarding rule created within 2h of ADFS auth (BEC) | T1114.003 |
| 11 | `11-ADFS-BulkDataDownload.yaml` | ADFS auth correlated with >50 SharePoint/OneDrive ops | T1048, T1213 |
| 12 | `12-ADFS-PIMAbuse-FederatedToken.yaml` | PIM role activated → ADFS token used within 30 min | T1078, T1098 |
| 13 | `13-ADFS-OAuthConsent-FederationAbuse.yaml` | Illicit app consent + ADFS sign-ins within 24h | T1528, T1566 |

#### MEDIUM Severity

| # | Rule File | Detection | MITRE |
|---|-----------|-----------|-------|
| 14 | `14-ADFS-LegacyAuth-MFABypass.yaml` | EAS/IMAP/POP3 detected via UserAgent — bypasses MFA+CA | T1078, T1550 |
| 15 | `15-ADFS-ROPC-DeviceCode.yaml` | ROPC or device_code flow via `AuthenticationProcessingDetails` | T1110, T1528 |
| 16 | `16-ADFS-HighFrequency-SAMLToken.yaml` | >50 SAML tokens/hour from same user+IP (automated replay) | T1528 |
| 17 | `17-ADFS-HighRiskCountry.yaml` | ADFS sign-in from sanctioned/high-risk countries | T1078 |
| 18 | `18-ADFS-SingleFactor-MFAGap.yaml` | `singleFactorAuthentication` + ADFS issuer (MFA policy gap) | T1078, T1606.002 |
| 19 | `19-ADFS-BruteForce-SingleUser.yaml` | >20 failures from multiple IPs targeting one account | T1110.001 |
| 20 | `20-ADFS-BotnetUserAgent.yaml` | Same UserAgent string across >50 distinct accounts | T1078, T1110 |
| 21 | `21-ADFS-LowAndSlow-Spray.yaml` | 2–15 attempts/hour below lockout threshold per IP | T1110.003 |
| 22 | `22-ADFS-RiskyUsers-FederatedAuth.yaml` | Identity Protection risky users still using ADFS | T1078, T1528 |
| 23 | `23-ADFS-CloudAdfs-CountryMismatch.yaml` | Cloud sign-in from country A, ADFS sign-in from country B same day | T1078 |

---

### Deployment

#### Prerequisites

```powershell
Install-Module Az.Accounts, Az.Resources, Az.SecurityInsights -Force
```

#### Option A — ARM Template (Recommended — all 23 rules in one operation)

```powershell
cd ADFSSignInLogs-ThreatHunting\Sentinel-AnalyticRules-ADFS

.\deploy-analytic-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod"
```

#### Option B — YAML per-rule via REST API (richer metadata: customDetails, alertDetailsOverride, grouping)

```powershell
.\deploy-analytic-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DeploymentMode    YAML
```

#### Dry Run (validate without deploying)

```powershell
.\deploy-analytic-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DryRun
```

---

### File Structure

```
ADFSSignInLogs-ThreatHunting\
├── ADFSSignInLogs-ThreatHunting.kql      ← 36 hunting queries
├── README.md                              ← This file
└── Sentinel-AnalyticRules-ADFS\
    ├── azuredeploy.json                   ← ARM template (all 23 rules)
    ├── deploy-analytic-rules.ps1          ← Deployment script (ARM + YAML modes)
    ├── README.md                          ← Rules deployment guide
    └── rules\
        ├── 01-ADFS-ExtravnetLockout-Spray.yaml
        ├── 02-ADFS-PasswordSpray-SingleIP.yaml
        ├── 03-ADFS-BruteForce-SuccessChain.yaml
        ├── 04-ADFS-GoldenSAML-UnknownIssuer.yaml
        ├── 05-ADFS-ThreatIntelligence-MaliciousIP.yaml
        ├── 06-ADFS-TOR-AnonymousProxy.yaml
        ├── 07-ADFS-ImpossibleTravel.yaml
        ├── 08-ADFS-StaleToken-AfterPasswordChange.yaml
        ├── 09-ADFS-PrivilegedAuditAction.yaml
        ├── 10-ADFS-EmailForwardingRule.yaml
        ├── 11-ADFS-BulkDataDownload.yaml
        ├── 12-ADFS-PIMAbuse-FederatedToken.yaml
        ├── 13-ADFS-OAuthConsent-FederationAbuse.yaml
        ├── 14-ADFS-LegacyAuth-MFABypass.yaml
        ├── 15-ADFS-ROPC-DeviceCode.yaml
        ├── 16-ADFS-HighFrequency-SAMLToken.yaml
        ├── 17-ADFS-HighRiskCountry.yaml
        ├── 18-ADFS-SingleFactor-MFAGap.yaml
        ├── 19-ADFS-BruteForce-SingleUser.yaml
        ├── 20-ADFS-BotnetUserAgent.yaml
        ├── 21-ADFS-LowAndSlow-Spray.yaml
        ├── 22-ADFS-RiskyUsers-FederatedAuth.yaml
        └── 23-ADFS-CloudAdfs-CountryMismatch.yaml
```

---

### Post-Deployment Tuning

| Rule | Tuning Recommendation |
|------|-----------------------|
| `17-ADFS-HighRiskCountry` | Edit the `HighRiskCountries` dynamic list per your org policy |
| `16-ADFS-HighFrequency-SAMLToken` | Adjust the `> 50` threshold per your app baseline |
| `19-ADFS-BruteForce-SingleUser` | Adjust `> 20` failure threshold per your lockout policy |
| `02-ADFS-PasswordSpray-SingleIP` | Adjust the `> 10` target account threshold |
| `04-ADFS-GoldenSAML-UnknownIssuer` | Set your expected `TokenIssuerName` values for your ADFS farm |
| `05-ADFS-ThreatIntelligence-MaliciousIP` | Requires an active TI data connector with NetworkIP indicators |
| `06-ADFS-TOR-AnonymousProxy` | Requires TI indicators tagged with `tor`/`proxy`/`anonymizer` |

---

### Required Azure RBAC

- **Microsoft Sentinel Contributor** — to create analytic rules
- **Contributor** on the resource group — for ARM template deployment

---

*Table: `ADFSSignInLogs` — Validated 2026-02-25*
