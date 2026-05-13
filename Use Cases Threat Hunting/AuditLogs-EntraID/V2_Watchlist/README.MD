# Sentinel Content – AuditLogs Entra ID
## Threat Coverage: Entra ID Recon, OAuth Abuse, Persistence & Federation Attacks

All queries validated against workspace 
> **Duplication review last run: 2026-04-06** against the Microsoft Entra ID Content Hub solution (73 analytic rules).
> AR-001 and AR-002 were specifically examined — see findings below.

---

## Coverage Matrix

| ID | Type | Technique | Tools Covered | Severity | MITRE |
|----|------|-----------|---------------|----------|-------|
| HQ-001 | Hunting | Directory Enumeration | AzureHound, BloodHound, ROADtools | Medium | T1069.003, T1087.004 |
| HQ-002 | Hunting | App + Immediate Credential | ROADtools, MicroBurst, AADInternals | Medium-High | T1098.001 |
| HQ-003 | Hunting | OAuth Consent – Multi App | TokenTactics, ROADtools, AADInternals | Medium | T1528 |
| HQ-004 | Hunting | Bulk SP Creation | ROADtools, MicroBurst, CloudKatana | Medium | T1136.003 |
| HQ-005 | Hunting | Role Assignment Non-PIM | AADInternals, MicroBurst | High | T1098.003 |
| HQ-006 | Hunting | Guest User Priv Escalation | Manual, AADInternals | High | T1078.004 |
| HQ-007 | Hunting | Bulk Token Revocation | AADInternals, IR scripts | Medium | T1070, T1531 |
| HQ-008 | Hunting | Sensitive Scope Consent | TokenTactics, ROADtools | High | T1528 |
| HQ-009 | Hunting | App Credential Persistence | MicroBurst, AADInternals | High | T1098.001 |
| HQ-010 | Hunting | Federation Config Changed | AADInternals | Critical | T1484.002, T1606.002 |
| AR-001 | Analytic Rule | New App + Immediate Consent | TokenTactics, ROADtools | High | T1098.001, T1528 |
| AR-002 | Analytic Rule | SP-Initiated Role Assignment Non-PIM | AADInternals, CloudKatana | High | T1098.003, T1078.004 |
| AR-003 | Analytic Rule | App Credential – After Hours | MicroBurst, AADInternals | Medium | T1098.001 |
| AR-004 | Analytic Rule | Burst OAuth Consent Grants | TokenTactics, ROADtools | High | T1528, T1098.001 |
| AR-005 | Analytic Rule | Federation Domain Config Changed | AADInternals | High | T1484.002, T1606.002 |
| AR-006 | Analytic Rule | Bulk Password Profile Updates | AADInternals, sync abuse | High | T1098, T1531, T1070 |
| HQ-011 | Hunting | Privileged Role Changes Monitoring | Any — covers all assignment sources | High | T1078.004, T1098.003 |
| HQ-012 | Hunting | Risky Sign-In → MFA Registration | TokenTactics, AiTM frameworks | High | T1098.005, T1556.006 |
| HQ-013 | Hunting | Admin Actions from Risky Users | Any — post-compromise admin ops | High | T1078.004, T1098 |
| HQ-014 | Hunting | Password Reset on Privileged User | AADInternals, manual | High | T1110, T1098 |
| HQ-015 | Hunting | SSPR → Risky Sign-In | Phishing/credential theft with SSPR bypass | High | T1110.004, T1078 |
| HQ-016 | Hunting | Privileged Role Change + Risk Event | AADInternals, CloudKatana | Critical | T1078.004, T1098.003 |

---

## Non-Duplication with Built-in Rules

The following built-in Sentinel rules already cover common AuditLogs scenarios and are
**intentionally excluded** to avoid duplication:

| Built-in Rule | Reason Excluded |
|---|---|
| Mail.Read Permissions Granted to Application | Covered by MS built-in |
| Rare application consent | Covered by MS built-in (ML-based) |
| User added to Azure AD Privileged Groups | Covered by MS built-in |
| New access credential added to App or Service Principal | Covered by MS built-in |
| Suspicious application consent similar to O365 Attack Toolkit | Covered by MS built-in |
| Suspicious application consent for offline access | Covered by MS built-in |
| **Privileged Role Assigned Outside PIM** (scheduled) | **DUPLICATE** → AR-002 replaced (see below) |
| **NRT Privileged Role Assigned Outside PIM** (NRT) | **DUPLICATE** → AR-002 replaced (see below) |

### AR-001 (New App + Immediate Consent) – CONFIRMED UNIQUE

The closest built-in is **"Credential added after admin consented to Application"** which:
- Joins `Consent to application` (admin-consent only) + `Add service principal credentials`
- Uses a 1–2 day lookback window between the two events
- Detects **credential add persistence AFTER an existing app was admin-consented**

AR-001 is different: it joins `Add application` (new app creation) + any consent within **10 minutes**,
targeting the OAuth phishing infrastructure setup pattern. **Not a duplicate — keep as-is.**


The original AR-002 was deleted. It has been replaced with:
**AR-002-SP-RoleAssignment-NonPIM.yaml**: Detects **Service Principal-initiated** non-PIM role assignments only
(no human actor involved). This is not covered by the built-ins and is the specific signal for
outomated attacks (AADInternals, CloudKatana, MicroBurst) where an SP assigns roles programmatically.

Our rules add **context not covered by built-ins**: time-correlation of creation+consent,
after-hours timing analysis, federation config changes, bulk token revocation, and
SP-automated non-PIM role assignments.

---

## File Structure

```
AuditLogs-EntraID/
├── ARMTemplates/
│   ├── azuredeploy.json                  ← Single ARM template: all 6 rules + 16 queries
│   ├── azuredeploy.parameters.json       ← Parameters (set workspace name here)
│   ├── deploy-analytic-rules.json        ← Analytic rules only (reference copy)
│   ├── deploy-hunting-queries.json       ← Hunting queries only (reference copy)
│   └── Deploy-SentinelContent.ps1        ← PowerShell deployment script
├── HuntingQueries/
│   ├── HQ-001-AzureHound-DirectoryEnumeration.kql
│   ├── HQ-002-NewApp-ImmediateCredentialAdd.kql
│   ├── HQ-003-OAuth-ConsentGrants-MultiApp.kql
│   ├── HQ-004-BulkServicePrincipalCreation.kql
│   ├── HQ-005-PrivilegedRoleAssignment-NonPIM.kql
│   ├── HQ-006-GuestUser-PrivilegeEscalation.kql
│   ├── HQ-007-BulkRefreshToken-Revocation.kql
│   ├── HQ-008-OAuth-SensitiveScope-PermissionGrant.kql
│   ├── HQ-009-AppCredential-PersistenceAdd.kql
│   ├── HQ-010-FederationConfig-Changes.kql
│   ├── HQ-011-PrivilegedRole-Changes-Monitoring.kql
│   ├── HQ-012-RiskySignIn-MFARegistration.kql
│   ├── HQ-013-AdminActions-from-RiskyUsers.kql
│   ├── HQ-014-PasswordReset-HighPrivilegedUser.kql
│   ├── HQ-015-SSPR-Followed-by-RiskySignIn.kql
│   └── HQ-016-PrivilegedRoleChange-RiskEventCorrelation.kql
└── AnalyticRules/
    ├── AR-001-NewApp-ImmediateHighPrivilegeConsent.yaml
│   ├── AR-002-SP-RoleAssignment-NonPIM.yaml         ← replaced duplicate
    ├── AR-003-AppCredential-AddedOutsideBusinessHours.yaml
    ├── AR-004-BurstOAuthConsentGrants.yaml
    ├── AR-005-FederationDomainConfigChanged.yaml
    └── AR-006-BulkPasswordProfileUpdates.yaml
```

## Deployment

### Network Allowlist Watchlist (false-positive suppression)

All 6 analytic rules call a KQL function `ExcludeAllowlistedIPs_AuditLogs(ip:string)` that returns `true` when `ip` matches an entry in the `NetworkAllowlist` Sentinel watchlist (sanctioned corporate egress IPs, trusted SaaS gateways, Entra named locations). The 22 hunting queries (`HQ-001` through `HQ-022`) deploy under the **Hunting** blade; the 2 hunts that pivot on `SigninLogs.IPAddress` (HQ-012 RiskySignIn-MFARegistration, HQ-015 SSPR-Followed-by-RiskySignIn) also call the function.

The watchlist + function are deployed automatically by `azuredeploy.json`. For scheduled sync from Entra Named Locations, see [`Watchlists/README.md`](Watchlists/README.md).

### New ARM template parameters

| Parameter | Default | Purpose |
|---|---|---|
| `workspace` | (required) | Sentinel workspace name. |
| `enableAnalyticRules` | `true` | If `false`, all 6 rules deploy **disabled** for staged rollout. |
| `watchlistAlias` | `NetworkAllowlist` | Trusted-IP exclusion watchlist alias. |
| `functionAlias` | `ExcludeAllowlistedIPs_AuditLogs` | savedSearches scalar function (unique alias avoids collision with sibling repos). |
| `watchlistRawContent` | empty (seeds RFC1918) | Override CSV (CRLF-separated; header `IPOrRange,Description,Owner,AddedDate`). Sync runbook replaces with Entra Named Locations. |

### Threshold tuning (May 2026)

Inline thresholds raised to reduce production noise:

| Rule | Threshold | Old → New |
|---|---|---|
| AR-004 Burst OAuth Consent | `ConsentThreshold` | 5 → **10** |
| AR-006 Bulk Password Profile | `UpdateThreshold` | 5 → **10** |
| AR-006 Bulk Password Profile | `DistinctTargets` | 3 → **5** |

### New Hunting Queries (HQ-017 — HQ-022)

Deployed as `savedSearches` in category `Hunting Queries`:

- `HQ-017` — Admin Consent for Anomalous OAuth Scopes (30d baseline)
- `HQ-018` — Service Principal Sign-In from First-Seen IP with Burst (>20 events)
- `HQ-019` — Application Certificate Added Without Expiry or with >2y Lifetime
- `HQ-020` — Federation Certificate Rotation Outside Maintenance Window
- `HQ-021` — Dormant Admin Suddenly Performs Sensitive Audit Action
- `HQ-022` — OAuth Consent Followed by Mail.Read Token Use Within 1h

### Staged deployment

```powershell
# Stage 1 - deploy disabled for review
New-AzResourceGroupDeployment `
  -ResourceGroupName "rg-sentinel" `
  -TemplateFile .\ARMTemplates\azuredeploy.json `
  -workspace "law-sentinel-prod" `
  -enableAnalyticRules $false

# Stage 2 - enable after review
New-AzResourceGroupDeployment `
  -ResourceGroupName "rg-sentinel" `
  -TemplateFile .\ARMTemplates\azuredeploy.json `
  -workspace "law-sentinel-prod" `
  -enableAnalyticRules $true
```

### Option A — PowerShell (recommended)

```powershell
# Install Az module if needed
Install-Module Az -Scope CurrentUser

# Log in
Connect-AzAccount

# Deploy everything (6 analytic rules + 16 hunting queries) in one shot
.\ARMTemplates\Deploy-SentinelContent.ps1 -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel-prod"
```

### Option B — Azure CLI

```bash
# Edit azuredeploy.parameters.json first — set "workspace" to your workspace name

az deployment group create \
  --resource-group rg-sentinel \
  --template-file ARMTemplates/azuredeploy.json \
  --parameters ARMTemplates/azuredeploy.parameters.json
```

### Option C — Azure Portal (manual import)
**Analytic Rules:** Sentinel → Analytics → Create → Import from file (paste YAML from `AnalyticRules/`)  
**Hunting Queries:** Sentinel → Hunting → New Query → Paste `.kql` content from `HuntingQueries/`

---

## Tuning Notes

| Rule | Tuning Recommendation |
|---|---|
| HQ-001 | Raise threshold from 5 if tenant has automated group lifecycle management |
| HQ-002 | Add exclusion list for known CI/CD service principals |
| AR-003 | Adjust `BusinessHoursStart`/`BusinessHoursEnd` variables to your timezone offset |
| AR-004 | Raise threshold from 5 if tenant uses automated provisioning that triggers consent events |
| AR-005 | No tuning – any federation change is critical; always alert |
| AR-006 | Narrow `DistinctTargets >= 3` down if your tenant has automated password expiry workflows |
| HQ-011 | Exclude known break-glass accounts or automation service principals that perform scheduled role cleanup |
| HQ-012 | Adjust `MFAChangeWindow` (default 4h) — tighten to 2h to reduce noise in tenants with frequent MFA self-enrollment |
| HQ-013 | The query matches users currently at-risk; if AADRiskyUsers is sparse, combine with `AADUserRiskEvents` as an additional signal source |
| HQ-014 | Extend `RoleLookback` beyond 90d if you want to catch resets of accounts that were deprivileged long ago |
| HQ-015 | Add exclusion for `AppDisplayName == "Microsoft Password Reset Portal"` if users commonly reset + immediately sign in normally |
| HQ-016 | Adjust `CorrelationWindow` (default 2h) to 4h in high-turnover environments where legitimate role changes may precede delayed risk detections |
