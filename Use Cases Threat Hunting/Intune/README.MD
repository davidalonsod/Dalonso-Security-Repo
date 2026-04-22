# Microsoft Sentinel Content Hub Solution — Intune Logs

This solution provides detections, hunting queries, a data connector, and an
executive workbook focused on **Microsoft Intune / MDM** attack paths:

- Device trust abuse (rogue device registration, compliance bypass, jailbreak/root)
- MDM enrollment attacks (AADInternals, ROADtools, PRT abuse, enrollment fuzzing)
- Azure AD device identity abuse (join type anomalies, refresh token replay)
- Privilege escalation via Intune roles
- Policy / configuration / app-protection tampering & persistence
- Destructive admin actions (mass wipe / retire)
- Stale-device / ghost-compliance token replay

## Solution contents

```
IntuneLogs/
├── Analytic Rules/         # 15 scheduled detections (YAML)
├── Hunting Queries/        # 15 hunting queries (YAML)
├── Data Connectors/        # Native (diagnostic settings) + CCF Graph API + DCR
├── Workbooks/              # CIO/CISO KPI workbook (JSON + metadata)
├── Package/                # ARM solution package + build script
│   ├── mainTemplate.json           # full deployable ARM (37 resources)
│   ├── deploy-workbook.json        # workbook-only ARM (fallback)
│   ├── createUiDefinition.json     # Content Hub wizard
│   ├── build-maintemplate.ps1      # regenerate mainTemplate.json from YAMLs
│   └── input.json                  # Content Hub build manifest
├── SolutionMetadata.json
└── README.md
```

## Data connectors

| Connector | Type | Tables produced | Required |
|---|---|---|---|
| **Microsoft Intune (Diagnostic Settings)** | GenericUI tile (push-based) | `IntuneAuditLogs`, `IntuneOperationalLogs`, `IntuneDeviceComplianceOrg`, `IntuneDevices` | **Yes** — primary data path for every rule / hunt / workbook tile |
| **Microsoft Intune - Graph API (CCF)** | RestApiPoller (CCF) | `IntuneGraph_AuditEvents_CL`, `IntuneGraph_ManagedDevices_CL` | Optional — covers Graph-only events and `managedDevices` snapshots |

### Enable the native connector (required)

1. Sign in to the [Microsoft Intune admin center](https://intune.microsoft.com).
2. **Reports → Diagnostic settings → + Add diagnostic setting**.
3. Under **Logs to send** select:
   - `AuditLogs`
   - `OperationalLogs`
   - `DeviceComplianceOrg`
   - `Devices`
   - *(optional)* `Windows365AuditLogs`
4. Under **Destination details** check **Send to Log Analytics workspace** and
   select your Sentinel-enabled workspace (e.g. `lawsentinel`).
5. Save. Data appears in ~15 minutes.

### Enable the Graph API CCF connector (optional)

The `mainTemplate.json` deploys the DCE, DCR, custom tables, and connector
definition. After deployment:

1. Register an Entra ID application.
2. Grant these Microsoft Graph **Application** permissions (admin consent):
   - `DeviceManagementApps.Read.All`
   - `DeviceManagementConfiguration.Read.All`
   - `DeviceManagementManagedDevices.Read.All`
   - `DeviceManagementRBAC.Read.All`
3. Generate a client secret.
4. In Sentinel → **Data connectors → Microsoft Intune - Graph API (CCF)**,
   click **Connect** and enter tenant ID, client ID, and secret.

Reference: [Microsoft Graph Intune overview](https://learn.microsoft.com/graph/api/resources/intune-graph-overview).

## Required data sources

| Source | Sentinel Table | Used by |
|---|---|---|
| Intune Diagnostic — AuditLogs | `IntuneAuditLogs` | 9 rules / 5 hunts |
| Intune Diagnostic — OperationalLogs | `IntuneOperationalLogs` | 2 rules / 2 hunts |
| Intune Diagnostic — DeviceComplianceOrg | `IntuneDeviceComplianceOrg` | 4 rules / 2 hunts |
| Intune Diagnostic — Devices | `IntuneDevices` | 3 rules / 4 hunts |
| Entra ID AuditLogs | `AuditLogs` | Rogue registration, role assignment, offboarded accounts |
| Entra ID SigninLogs | `SigninLogs`, `AADNonInteractiveUserSignInLogs` | Impossible travel, token replay, non-compliant access |
| UEBA *(optional)* | `IdentityInfo`, `BehaviorAnalytics` | Enrichment |
| Graph CCF *(optional)* | `IntuneGraph_AuditEvents_CL`, `IntuneGraph_ManagedDevices_CL` | Supplementary coverage |

## Analytic rules (15)

| # | Rule | Severity | Primary table(s) |
|---|---|---|---|
| 1 | Intune compliance bypass (flip without remediation) | High | `IntuneDeviceComplianceOrg`, `IntuneAuditLogs` |
| 2 | Mass device enrollment by user | Medium | `IntuneAuditLogs` |
| 3 | Impossible travel device registration | High | `AuditLogs`, `SigninLogs` |
| 4 | Rogue device registration tooling (AADInternals / ROADtools) | High | `AuditLogs` |
| 5 | Intune policy tampering | Medium | `IntuneAuditLogs` |
| 6 | Privileged Intune role assignment | High | `AuditLogs` |
| 7 | Device join-type anomaly | Medium | `AuditLogs` |
| 8 | Refresh-token reuse on Intune device | High | `SigninLogs` |
| 9 | Bulk destructive MDM actions | High | `IntuneAuditLogs` |
| 10 | BYOD accessing privileged app | Medium | `SigninLogs`, `IntuneDevices` |
| 11 | Wipe / retire action on managed device | High | `IntuneAuditLogs` |
| 12 | App Protection / Configuration policy tampered | Medium | `IntuneAuditLogs` |
| 13 | Jailbroken / rooted device accessing corporate resources | High | `IntuneDevices`, `IntuneDeviceComplianceOrg` |
| 14 | MDM enrollment / check-in failure spike per user | Medium | `IntuneOperationalLogs` |
| 15 | Stale managed device still reporting as Compliant | Medium | `IntuneDevices`, `IntuneDeviceComplianceOrg` |

## Hunting queries (15)

| # | Query | Purpose |
|---|---|---|
| 1 | First-time enrollment by user | Baseline new enrollments |
| 2 | Enrollment spikes | Surge detection |
| 3 | Non-compliant devices accessing corporate apps | CA gap finder |
| 4 | Device registration from hosting ASN | Cloud-based rogue registration |
| 5 | Sensitive Intune role membership | Role exposure |
| 6 | Enroll → immediate privileged action | Post-enrollment escalation |
| 7 | Dormant device reactivation | Staged attack indicator |
| 8 | Conditional Access gaps | CA coverage |
| 9 | Operational errors by category | Config / policy issues |
| 10 | Token / session hijack indicators | Token replay |
| 11 | Top Intune audit operators (volume baseline) | Actor anomaly vs 7d avg |
| 12 | Intune operational failures grouped by reason | Root-cause grouping |
| 13 | Intune devices by outdated OS version | Vulnerability exposure |
| 14 | Disabled / offboarded accounts with active devices | Residual access |
| 15 | Recent Intune policy assignment / unassignment changes | Scoping changes |

## Workbook

`Workbooks/IntuneSecurity-CIO-CISO.json` — executive KPI workbook:

- Compliance posture tiles & trend
- Enrollment volume and source distribution
- Geographic map of device registrations
- Privileged-role exposure
- Policy-tampering audit timeline
- Destructive admin actions
- Incidents raised by this solution (last 30d)

## Watchlists

IP-aware rules and hunts reference the existing `NetworkAllowlist` watchlist in
the `lawsentinel` workspace to exclude corporate / trusted egress ranges.

| Alias | Watchlist | Key column | Purpose |
|---|---|---|---|
| `NetworkAllowlist` | `NetworkAllowlist` | `SearchKey` (built-in) | Trusted IPs / CIDR ranges |

Usage pattern:

```kql
let NetworkAllowlist = _GetWatchlist('NetworkAllowlist')
    | project IPRange = tostring(SearchKey);
let AllowedRanges = toscalar(NetworkAllowlist | summarize make_list(IPRange));
SigninLogs
| where not(ipv4_is_in_any_range(tostring(IPAddress), AllowedRanges))
```

## Deployment

### Option A — Full ARM template (recommended)

```powershell
cd C:\Users\dalonso\SentinelSolutions\IntuneLogs
az deployment group create `
  --resource-group RG_Sentinel `
  --template-file .\Package\mainTemplate.json `
  --parameters workspace=lawsentinel
```

Deploys **37 resources**: 15 analytic rules, 15 hunting queries, 1 workbook,
2 data connectors, 2 custom tables, 1 DCE, 1 DCR.

### Option B — Portal

Azure portal → **Deploy a custom template** → upload `Package/mainTemplate.json`
→ provide workspace name.

### Option C — Regenerate from source

After editing any rule or hunt YAML, rebuild the ARM template:

```powershell
pwsh -File .\Package\build-maintemplate.ps1
```

The script parses every YAML under `Analytic Rules/` and `Hunting Queries/`,
inlines the workbook, and emits `Package/mainTemplate.json`.

## Post-deploy checklist

- [ ] Intune Diagnostic Settings sending all 4 categories to `lawsentinel`
- [ ] Tables show rows: run `IntuneAuditLogs | take 1`, etc.
- [ ] 15 analytic rules enabled and running
- [ ] 15 hunting queries visible in *Hunting → Queries*
- [ ] `Intune Security - CIO / CISO KPIs` workbook renders
- [ ] `NetworkAllowlist` watchlist exists (or update rules to remove the filter)
- [ ] *(Optional)* Graph CCF connector configured with Entra app credentials

## Threat coverage (MITRE ATT&CK)

| Tactic | Techniques |
|---|---|
| Initial Access | T1078.004 (Valid Accounts: Cloud), T1566 |
| Reconnaissance | T1595 (Active Scanning — enrollment fuzzing) |
| Persistence | T1098.005 (Device Registration), T1556 (Modify Auth Process), T1078 |
| Privilege Escalation | T1078.004, T1484.002 (Domain Trust Modification) |
| Defense Evasion | T1562 (Impair Defenses — policy tampering), T1550 (Token Replay) |
| Credential Access | T1528 (Steal App Access Token — PRT/refresh), T1552 |
| Lateral Movement | T1550.001 (Application Access Token) |
| Impact | T1485 (Data Destruction), T1531 (Account Access Removal — wipe/retire) |

## Version

- **Version:** 1.1.0
- **Last updated:** 2026-04-21
- **Changes in 1.1.0:**
  - +5 analytic rules and +5 hunting queries targeting native Intune diagnostic tables
  - +2 data connectors (Diagnostic Settings GenericUI + Graph API CCF)
  - +DCE / DCR / custom tables for the CCF connector
  - Rebuilt `mainTemplate.json` from source via `build-maintemplate.ps1`
