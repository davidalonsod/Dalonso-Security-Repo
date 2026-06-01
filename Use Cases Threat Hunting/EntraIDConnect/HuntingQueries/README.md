# HuntingQueries

Hunting-only KQL queries for the **AADProvisioningLogs** + Entra Connect Sync threat pack.

These queries are designed for interactive use in **Microsoft Sentinel → Logs** or the **Hunting** blade. They are *not* scheduled detections - they are exploration tools that complement the rules under `../Analytic-Rules/rules/`.

## Inventory

| # | File | Purpose | Window |
|---|---|---|---|
| 01 | `HUNT-01_AADProv-FailuresByJobError-30d.yaml` | Top failures by Job × ServicePrincipal × ErrorSignature | 30d |
| 02 | `HUNT-02_AADProv-FirstSeenMappings-30v90d.yaml` | New SourceIdentity → TargetIdentity pairs | 30d vs 90d |
| 03 | `HUNT-03_AADProv-SyncSignin-OutsideIP-14d.yaml` | Sync account sign-ins outside allowlisted IP | 14d |
| 04 | `HUNT-04_AADProv-SyncAccount-Activities-30d.yaml` | Sync account audit activities enriched with IdentityInfo | 30d |
| 05 | `HUNT-05_AADProv-BulkAttributeChange-30d.yaml` | High attribute churn per CycleId | 30d |
| 06 | `HUNT-06_AADProv-NewServicePrincipals-30v90d.yaml` | New provisioning SPs | 30d vs 90d |
| 07 | `HUNT-07_AADProv-DirSyncFeatureHistory-180d.yaml` | DirSync feature change audit history | 180d |
| 08 | `HUNT-08_AADProv-RoleAssignableGroupChanges-30d.yaml` | Provisioning of role-assignable groups | 30d |
| 09 | `HUNT-09_AADProv-CycleDuration-Outliers.yaml` | Cycle duration outliers vs 7d baseline | 7d |
| 10 | `HUNT-10_AADProv-RareOperations-30d.yaml` | Rare ProvisioningAction / TargetSystem / ResultSignature | 30d |
| 11 | `HUNT-11_AADProv-DormantReEnable-30d.yaml` | Dormant account re-enabled via provisioning | 30d / 180d |
| 12 | `HUNT-12_AADProv-ConsentGrantAfterProvisioning.yaml` | Provisioning op followed by consent grant on same SP | 7d |
| 13 | `HUNT-13_AADProv-SyncToken-ReplayGeography-14v90d.yaml` | Sync account token-replay geography (new IP/Location, non-interactive) | 14d vs 90d |
| 14 | `HUNT-14_AADProv-SelfProvisioningLoop-30d.yaml` | Actor provisions / modifies its own object (self-service loop) | 30d |

## Watchlist dependencies

- `HighValueAssets` (tag `EntraIDConnect`) — public IPs of Entra Connect servers (HUNT-03)
- `ServiceAccounts` (tag `EntraIDConnect`) — approved sync account ObjectIds (referenced by RULE-12)
- `IdentityInfo` (UEBA) — required by HUNT-04 (degrades to naming-pattern heuristic if missing)
