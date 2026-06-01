# AADProvisioningLogs — Threat Hunting & Detection Pack

KQL detection / hunting pack for **Microsoft Sentinel** targeting the
Microsoft Entra **provisioning service** (`AADProvisioningLogs`) plus
hybrid coverage of the **Entra Connect Sync** service account
(`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`).

Built to protect:

- The Entra **provisioning channel** (SCIM apps, HR-driven, Cloud Sync
  agent, on-prem ECMA connector hosts) — anything that writes objects
  into Entra ID via the provisioning service.
- The **Entra Connect Sync** service account
  (`On-Premises Directory Synchronization Service Account`,
  `Sync_<server>_<guid>@<tenant>.onmicrosoft.com`) — credential
  protection, TAP backdoors, sign-ins outside the Entra Connect
  server's public IP.
- The **DirSync feature surface** — `BlockSoftMatch`,
  `BlockCloudObjectTakeoverThroughHardMatch`, Password Hash Sync,
  Seamless SSO toggles.

## Tables used

### Primary: `AADProvisioningLogs`

| Column | Use |
|---|---|
| `TimeGenerated` | Event time |
| `OperationName` / `ProvisioningAction` | `Create` / `Update` / `Delete` / `Disable` / `StagedDelete` / `Other` |
| `ResultType` | `Success` / `Failure` / `Skipped` |
| `ResultDescription` / `ResultSignature` | Error detail |
| `InitiatedBy` | JSON: who/what triggered (user UPN, app, service principal) |
| `ServicePrincipal` | Provisioning agent / SCIM app SP |
| `SourceIdentity` / `TargetIdentity` | Object being moved across systems (JSON) |
| `SourceSystem` / `TargetSystem` | `Azure Active Directory` / `Workday` / `SuccessFactors` / `Active Directory` / SCIM endpoint |
| `ModifiedProperties` | Per-attribute before/after (JSON array) |
| `JobId` / `CycleId` / `ChangeId` | Job/iteration/event correlation |
| `ProvisioningSteps` | Step-by-step trail (JSON) |
| `Category` | `ProvisioningEvent` and similar |

### Hybrid tables (for Entra Connect Sync coverage)

- `SigninLogs` — sync account sign-ins (`On-Premises Directory Synchronization Service Account`).
- `AADNonInteractiveUserSignInLogs` — token refreshes; where most sync traffic lives.
- `AuditLogs` — DirSync feature changes, TAP issuance, password resets, role assignments.
- `IdentityInfo` (UEBA) — to identify accounts with `Directory Synchronization Accounts` and `Hybrid Identity Administrator` roles.

### Watchlists (recommended)

- `EntraConnect_HighValueAssets` - Entra Connect server **public IP addresses**.
- `EntraConnect_ServiceAccounts` - Entra Connector account **ObjectIds / UPNs**.

Both tagged `EntraIDConnect`. Aliases are namespaced with the
`EntraConnect_` prefix to avoid collision with any pre-existing
`HighValueAssets` / `ServiceAccounts` watchlists that have a different
schema in your workspace (Sentinel watchlists are immutable on
`itemsSearchKey`). Several rules use these - if you don't have them
yet, the rules degrade to "always alert", which you'll want to tune by
hand.

---

## Detection inventory

### Analytic rules (`Analytic-Rules/rules/`)

| # | Rule | Severity | Channel |
|---|---|---|---|
| 01 | Provisioning failure burst — single job | Medium | `AADProvisioningLogs` |
| 02 | Mass user disable via provisioning (≥10 in 1h) | High | `AADProvisioningLogs` |
| 03 | Mass user deletion via provisioning (≥5 in 1h) | High | `AADProvisioningLogs` |
| 04 | Privileged group membership change via provisioning | High | `AADProvisioningLogs` |
| 05 | Bulk attribute churn on privileged target | High | `AADProvisioningLogs` |
| 06 | Provisioning service silence (no events for 2h on busy job) | Medium | `AADProvisioningLogs` |
| 07 | DirSync feature toggled (BlockSoftMatch / HardMatch / PHS) | **High** | `AuditLogs` |
| 08 | TAP added to Entra Connector account (backdoor) | **High** | `AuditLogs` + `IdentityInfo` |
| 09 | Password reset on Entra Connector account | High | `AuditLogs` |
| 10 | Entra Connector sign-in outside allowlisted public IP | High | `SigninLogs` + Watchlist |
| 11 | New service principal performing provisioning | Medium | `AADProvisioningLogs` |
| 12 | Sync account outside the ServiceAccounts watchlist | Medium | `IdentityInfo` + Watchlist |
| 13 | Match-anchor modification on privileged cloud user (soft/hard-match takeover) | **High** | `AADProvisioningLogs` + `AuditLogs` + `IdentityInfo` |
| 14 | Interactive / browser sign-in by sync service account | **High** | `SigninLogs` |
| 15 | New high-risk TargetSystem (SCIM / Workday / Salesforce / AWS / ServiceNow) | Medium | `AADProvisioningLogs` |
| 16 | Credentials added or rotated on a provisioning ServicePrincipal | **High** | `AuditLogs` + `AADProvisioningLogs` |
| 17 | Rogue outbound provisioning - mass `Create` to new TargetSystem | **High** | `AADProvisioningLogs` |

### Hunting queries (`HuntingQueries/`)

| # | Hunt | Window |
|---|---|---|
| 01 | Provisioning failure top-N by job/error | 30d |
| 02 | First-seen `SourceIdentity → TargetIdentity` mappings | 30d vs 90d |
| 03 | Sync account sign-ins outside Entra Connect IP | 14d |
| 04 | Activities from Entra Connector account enriched with `IdentityInfo` | 30d |
| 05 | Bulk attribute changes by single `CycleId` | 30d |
| 06 | New `ServicePrincipal` performing provisioning | 30d vs 90d |
| 07 | DirSync feature change history | 180d |
| 08 | Provisioning of role-assignable groups | 30d |
| 09 | Cycle duration outliers vs 7d baseline | 7d |
| 10 | Rare `ProvisioningAction` / `TargetSystem` / `ResultSignature` | 30d |
| 11 | Dormant account re-enabled via provisioning (>= 90d disabled) | 30d / 180d |
| 12 | Provisioning operation followed by consent grant on same SP | 7d |
| 13 | Sync account token-replay geography (new IP/Location, non-interactive) | 14d vs 90d |
| 14 | Self-provisioning loop - actor modifies its own object | 30d |

---

## Out of scope / covered by built-ins

The following adjacent threats are intentionally **not** duplicated by this
pack because Microsoft already ships solid first-party coverage:

| Threat | Built-in source |
|---|---|
| Password spray / brute force against Entra ID | Entra ID Protection (risky sign-in), Sentinel `BruteForceAttempts*` analytics |
| Risky user / risky sign-in scoring | Entra ID Protection |
| Anomalous interactive logon to Entra Connect host | MDI (Defender for Identity) - `Suspicious interactive logon to Microsoft Entra Connect server` |
| Password reset performed by the Entra Connect service | MDI - `User Password Reset by Microsoft Entra Connect` |
| `AADInternals` / `DCSync` from Entra Connect host | MDE (Defender for Endpoint) behavioural detections |
| Suspicious writeback from cloud to AD | MDI writeback alerts |
| On-prem AD `ADSyncAdmins` / Tier-0 group tampering | MDI / `IdentityDirectoryEvents` (Defender XDR) |

If any of these built-ins are disabled in your tenant, re-enable them before
relying on this pack alone. This pack focuses on what built-ins **miss**:
the provisioning channel itself and the cloud-side sync-account abuse paths.

---

## Threshold philosophy

All thresholds are deliberately **conservative**. Each rule documents
the rationale next to the `triggerThreshold` so the SOC can tune from
"high signal / low noise" downward.

Common knobs:

- `triggerThreshold` - events per evaluation window.
- `queryFrequency` / `queryPeriod` - usually 1h/4h for bursts, 4h/1d
  for slower patterns.
- Watchlist references - degrade gracefully (the rule still fires, but
  noisier) if the watchlist isn't populated.

---

## Tuning the thresholds in your tenant

Run these baseline queries **before** going live with the pack. Set
each rule's `triggerThreshold` to the **p99** of your last 14 days of
benign activity, plus 20% headroom.

### Step 1 - Measure your baseline

```kusto
// Per-hour failure baseline for RULE-01
AADProvisioningLogs
| where TimeGenerated > ago(14d)
| where ResultType =~ "Failure"
| summarize Failures = count() by JobId, bin(TimeGenerated, 1h)
| summarize p50 = percentile(Failures, 50),
            p95 = percentile(Failures, 95),
            p99 = percentile(Failures, 99),
            max_h = max(Failures) by JobId
| order by p99 desc
```

```kusto
// Per-hour Disable / Delete baseline for RULE-02, RULE-03
AADProvisioningLogs
| where TimeGenerated > ago(14d)
| where ProvisioningAction in~ ("Disable","Delete")
| summarize Events = count() by ProvisioningAction, bin(TimeGenerated, 1h)
| summarize p95 = percentile(Events, 95),
            p99 = percentile(Events, 99) by ProvisioningAction
```

```kusto
// Bulk-attribute baseline for RULE-05
AADProvisioningLogs
| where TimeGenerated > ago(14d)
| extend Target = tostring(parse_json(TargetIdentity).userPrincipalName)
| mv-expand Mod = todynamic(ModifiedProperties)
| summarize Attrs = dcount(tostring(Mod.displayName))
        by Target, bin(TimeGenerated, 1h)
| summarize p95 = percentile(Attrs, 95),
            p99 = percentile(Attrs, 99)
```

### Step 2 - Apply the rule of thumb

| Rule | Default `triggerThreshold` | Tune to |
|---|---|---|
| 01 Failure burst | 30 / hr | `p99 * 1.2` of historical failures per job |
| 02 Mass disable | 10 / hr | max of (10, `p99 * 1.2`) - never below 10 |
| 03 Mass deletion | 5 / hr | max of (5, `p99 * 1.2`) - never below 5 |
| 05 Attr churn | 5 attrs / hr | `p99 * 1.2` per target |
| 06 Service silence | baseline >= 100 / hr -> 0 | set the **baseline floor** to your p10 hourly volume |
| 11 New SP | >= 50 ops, unseen 30d | raise to 100 ops in noisy tenants |

### Step 3 - Filter known-good actors

For RULE-04 (privileged group), RULE-05 (attr churn), RULE-13
(match-anchor), add a `not in` exclusion for service accounts that
**legitimately** rewrite admin attributes (HR-driven joiner/mover/leaver
runs, M&A migration runbooks). Capture them in a Watchlist
`ProvisioningAllowlist` tagged `EntraIDConnect-Allowlist` and append
`| where Actor !in (_GetWatchlist('ProvisioningAllowlist'))` to each
rule.

### Step 4 - Narrow the privileged scope (Rule 13)

If `IdentityInfo` still produces too many "privileged" users for your
tenant, restrict the join to Tier-0 only:

```kusto
let PrivilegedUsers =
    IdentityInfo
    | where TimeGenerated > ago(14d)
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | where AssignedRoles has_any (
        "Global Administrator","Privileged Role Administrator",
        "Hybrid Identity Administrator","Application Administrator",
        "Cloud Application Administrator","User Administrator",
        "Authentication Administrator","Privileged Authentication Administrator"
    )
    | project AccountUPN, AccountObjectId, AssignedRoles;
```

This drops false positives from non-admin roles (e.g. Reports Reader,
Message Center Reader) that still populate `AssignedRoles`.

### Step 5 - Re-evaluate quarterly

Re-run Step 1 each quarter. Provisioning volume scales with tenant
growth - a threshold that was conservative at 5k users is too tight at
50k users.

---

## Cost optimisation - DCR transformation + `project-away`

`AADProvisioningLogs` can be the noisiest table in a hybrid tenant
(hundreds of MB / day on a 20k-user estate). Ingestion cost lives on
columns that no detection in this pack uses. Apply a **DCR workspace
transformation** to drop them at ingest.

### Columns this pack actually reads

Required (do **not** drop):

```
TimeGenerated, ResultType, ResultDescription, ResultSignature,
OperationName, ProvisioningAction, Category,
ServicePrincipal, InitiatedBy,
SourceIdentity, TargetIdentity, SourceSystem, TargetSystem,
ModifiedProperties, JobId, CycleId, ChangeId, DurationMs
```

Safe to drop (not referenced by any rule or hunt):

```
ProvisioningSteps          // huge JSON blob - per-step trail
ProvisioningStatusInfo     // duplicate of ResultDescription
TenantId                   // implicit in workspace
Type, _ResourceId, _SubscriptionId, SourceSystem_
AdditionalDetails          // free-text, rarely used
Identity, Level, Location  // empty / control-plane fields
```

`ProvisioningSteps` alone is typically **40 to 60% of row size**.

### DCR transformation example

Workspace transformation DCR (`Microsoft.Insights/dataCollectionRules`):

```jsonc
{
  "properties": {
    "dataFlows": [
      {
        "streams": [ "Microsoft-AADProvisioningLogs" ],
        "destinations": [ "<lawName>" ],
        "transformKql": "source | project-away ProvisioningSteps, ProvisioningStatusInfo, AdditionalDetails | where ResultType !in~ ('Skipped') or ProvisioningAction !in~ ('Other')",
        "outputStream": "Microsoft-AADProvisioningLogs"
      }
    ]
  }
}
```

That single transformation typically cuts `AADProvisioningLogs`
ingestion by **50 to 70%** with no detection impact.

### Optional - drop `Skipped` reconciliation noise

Routine reconciliation cycles emit floods of
`ResultType = "Skipped" / OperationName = "Other"` events. None of the
17 rules or 12 hunts depend on them.

```kusto
source
| where not(ResultType =~ "Skipped" and ProvisioningAction =~ "Other")
| project-away ProvisioningSteps, ProvisioningStatusInfo, AdditionalDetails
```

Caveat: if you later want to baseline cycle health on `Skipped` events,
keep them and rely only on `project-away`.

### Split high-value vs low-value to Basic Logs

For tenants on the **Basic / Auxiliary Logs** tier, route the verbose
provisioning columns to a separate custom table at Basic-tier pricing:

1. Create `AADProvisioningLogs_Verbose_CL` (Basic tier).
2. In the DCR, fan out one stream to Analytics tier (the columns
   this pack reads) and one to Basic tier (`ProvisioningSteps`,
   `AdditionalDetails`).
3. Hunting queries that **do** need full step detail can `union` the
   two tables on `ChangeId`.

Saves another 30 to 40% on the columns you do want to retain for forensics.

### Validation

After applying the DCR, confirm no detection breaks:

```kusto
// Schema diff - what is the new column set?
AADProvisioningLogs
| getschema
| project ColumnName

// Volume delta - run before and after DCR
Usage
| where DataType == "AADProvisioningLogs"
| where TimeGenerated > ago(7d)
| summarize GB = sum(Quantity) / 1024 by bin(TimeGenerated, 1d)
| render timechart
```

If `getschema` no longer returns a column referenced by a rule, the
rule will fail validation in the PR gate - run
`./Scripts/Invoke-PRValidation.ps1` from Sentinel-As-Code against the
pack before deploying.

---

## Deploy

This pack ships an **ARM template** (`Analytic-Rules/azuredeploy.json`)
and a dual-mode deployer (`Analytic-Rules/deploy-aadprov-rules.ps1`)
that mirror the ADFSSignInLogs pack.

The ARM template provisions in one operation:

- `NetworkAllowlist` watchlist - trusted SOC / jump-host IPs and CIDRs.
- `EntraConnect_HighValueAssets` watchlist - Entra Connect server public IPs (tagged `EntraIDConnect`, consumed by RULE-10 and HUNT-03).
- `EntraConnect_ServiceAccounts` watchlist - Entra Connector sync UPNs / ObjectIds (tagged `EntraIDConnect`, consumed by RULE-12).
- `ExcludeAllowlistedIPs` saved KQL function - shared FP suppression for any rule with an `IPAddress` column (RULE-14, RULE-16 invoke it).
- All 17 analytic rules.

> The `EntraConnect_*` prefix prevents ARM-level collision with any
> existing `HighValueAssets` / `ServiceAccounts` watchlist already in
> the workspace (Sentinel watchlists cannot have their `itemsSearchKey`
> changed). Set `-SkipNetworkAllowlist` / `-SkipHighValueAssets` /
> `-SkipServiceAccounts` on the deployer if you want to skip any of
> these and point the rules at an existing watchlist by editing the
> alias in the YAML.

### ARM (recommended)

```powershell
.\Analytic-Rules\deploy-aadprov-rules.ps1 `
    -SubscriptionId   "<sub-guid>" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod"
```

### YAML (per-rule via REST)

```powershell
.\Analytic-Rules\deploy-aadprov-rules.ps1 `
    -SubscriptionId   "<sub-guid>" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DeploymentMode YAML `
    -DryRun
```

YAML mode does **not** create the watchlists or function - run ARM mode
once first (or deploy `azuredeploy.json` directly) to provision the
shared infrastructure.

### Regenerate `azuredeploy.json` after editing rules

`azuredeploy.json` is generated from the YAML rule sources by
`Analytic-Rules/Build-AzureDeployTemplate.ps1`. Re-run it whenever you
edit a rule:

```powershell
.\Analytic-Rules\Build-AzureDeployTemplate.ps1
```

### Manual / UI fallback

Or import each YAML by hand through Sentinel UI ->
**Analytics -> Create -> Scheduled query rule -> Import from file**.
