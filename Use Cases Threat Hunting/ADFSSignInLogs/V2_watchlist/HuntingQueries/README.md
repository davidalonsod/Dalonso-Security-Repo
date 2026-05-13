# ADFS Hunting Queries

Ten hunting queries (`.yaml`, Sentinel Hunting format) that complement the 20
analytic rules in `Analytic-Rules/`. They cover long-range history, lateral
correlations, and protocol/identity governance gaps that the real-time rules
either suppress (via grouping) or do not cover.

All IP-bearing queries call the `ExcludeAllowlistedIPs()` KQL function deployed
from the watchlist Bicep, so corporate / VPN / SaaS egress ranges are filtered.

| # | File | Window | Focus | Key Tactic |
|---|------|--------|-------|------------|
| 01 | `HUNT-01_ADFS-ExtranetLockout-History-30d.yaml`         | 30d  | Sustained extranet lockout campaigns per user/IP                          | Credential Access |
| 02 | `HUNT-02_ADFS-PasswordSpray-Suspects-14d.yaml`          | 14d  | Single-IP password spray candidates below rule thresholds                 | Credential Access |
| 03 | `HUNT-03_ADFS-HighRiskCountry-Timeline-90d.yaml`        | 90d  | Successful sign-ins from sanctioned / high-risk countries                 | Initial Access |
| 04 | `HUNT-04_ADFS-ImpossibleTravel-Pairs-30d.yaml`          | 30d  | Same user, two countries, < 4h apart                                      | Initial Access / Lateral Movement |
| 05 | `HUNT-05_ADFS-ThreatIntelIP-History-90d.yaml`           | 90d  | Joins ADFS auth with `ThreatIntelligenceIndicator` active IP IoCs         | Initial Access / C2 |
| 06 | `HUNT-06_ADFS-LegacyAuth-Protocols-30d.yaml`            | 30d  | POP/IMAP/SMTP/MAPI/Other-clients legacy auth                              | Defense Evasion |
| 07 | `HUNT-07_ADFS-NewCountry-PerUser-30v90d.yaml`           | 30d vs 90d | First-seen country shifts per user                                  | Initial Access |
| 08 | `HUNT-08_ADFS-AuthToPrivilegedAction-30d.yaml`          | 30d  | ADFS auth -> AuditLogs privileged op within 1h                            | Privilege Escalation |
| 09 | `HUNT-09_ADFS-AuthToMailboxRule-BEC-14d.yaml`           | 14d  | ADFS auth -> Exchange inbox / transport rule creation within 6h           | Collection / Exfil |
| 10 | `HUNT-10_ADFS-RiskyOrDisabledUser-ActiveAuth-7d.yaml`   | 7d   | Active ADFS auth for currently-disabled / risky-flagged users             | Persistence |

## Deploying as Sentinel hunting queries

These YAML files are compatible with the Sentinel content / hunting query
schema. You can:

1. Import via Sentinel UI: **Hunting** -> **Queries** -> **+ New query** and
   paste the KQL block, or
2. Package them into a Solution under `HuntingQueries/` and deploy via
   `mainTemplate.json`, or
3. Use the `Sentinel-AnalyticRules-ManagedIdentity` runbook pattern to PUT each
   query against `Microsoft.OperationalInsights/savedSearches` with
   `category = "Hunting Queries"`.

## Dependencies

- `ADFSSignInLogs` table populated (Sentinel ADFS connector or custom ingest).
- `NetworkAllowlist` watchlist deployed (see [`../Watchlists/README.md`](../Watchlists/README.md)).
- `ExcludeAllowlistedIPs` KQL function deployed (created by the rules ARM template).
- Some hunts also require:
  - HUNT-05: `ThreatIntelligenceIndicator`
  - HUNT-08: `AuditLogs`
  - HUNT-09: `OfficeActivity`
  - HUNT-10: `IdentityInfo`
