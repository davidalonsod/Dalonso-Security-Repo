Video Demo 

Avoid Azure Billing Surprises: Sentinel Anomaly Alerts and Detect Data Ingestion Spike https://youtu.be/U3Fx_U56igg

# Sentinel Data Ingestion Control

ARM-deployable monitoring pack for **any** Microsoft Sentinel workspace: **5 analytic rules** + **16 ingestion & cost monitoring queries** + **15 cost optimization queries** for data ingestion anomaly detection, noise identification, cost management, M365 E5 benefit tracking, Auxiliary table monitoring, and retention compliance.


## Folder Structure

```
sentinel-ingestion-control/
├── deploy.ps1                          # PowerShell deployment script (any environment)
├── cleanup-old-hunts.ps1               # Standalone cleanup (optional)
├── README.md
├── analytic-rules/                     # 5 Scheduled analytic rules (.kql)
│   ├── ingestion-anomaly-zscore.kql
│   ├── ingestion-spike-3x.kql
│   ├── ingestion-drop-silent-table.kql
│   ├── new-table-detected.kql
│   └── daily-budget-breach.kql
├── hunting-queries/                    # 24 Hunting queries (.kql)
│   ├── full-ingestion-dashboard.kql
│   ├── hourly-ingestion-heatmap.kql
│   ├── table-growth-week-over-week.kql
│   ├── top10-noisiest-tables-trend.kql
│   ├── custom-table-cost-analysis.kql
│   ├── per-solution-breakdown.kql
│   ├── securityevent-top-eventids.kql
│   ├── column-size-analysis.kql
│   ├── m365-e5-benefit-usage.kql       # M365 E5/A5/F5/G5 benefit tracking
│   ├── defender-xdr-table-sizes.kql    # M365 E5 table sizes by product
│   ├── all-tables-sentinel-price.kql   # All tables with cost estimation
│   ├── ingestion-per-server.kql        # Per-server ingestion volume
│   ├── computers-not-reporting.kql     # Silent server detection
│   ├── noise-process-creation.kql      # Cost Optimization
│   ├── noise-logon-events.kql
│   ├── noise-syslog-facility.kql
│   ├── noise-noninteractive-signin.kql
│   ├── noise-commonsecuritylog.kql
│   ├── noise-heartbeat-frequency.kql
│   ├── noise-repeated-values.kql
│   ├── noise-auditlogs-operations.kql
│   ├── noise-master-summary.kql
│   ├── duplicate-cross-table-overlap.kql
│   └── duplicate-signin-overlap.kql
├── auxiliary-monitoring/               # 4 Auxiliary table queries (.kql)
│   ├── auxiliary-vs-analytics-inventory.kql
│   ├── auxiliary-volume-monitor.kql
│   ├── auxiliary-daily-trend.kql
│   └── migration-candidates.kql
├── retention-monitoring/               # 4 Retention compliance queries (.kql)
│   ├── effective-retention-per-table.kql
│   ├── retention-gap-detection.kql
│   ├── approaching-retention-boundary.kql
│   └── cost-projection.kql
└── arm-templates/
    ├── azuredeploy.json                # Master template (rules + ingestion queries)
    ├── azuredeploy.parameters.json     # Parameter file (edit with your values)
    ├── analytic-rules.json             # Standalone analytic rules template
    ├── hunting-queries.json            # Standalone hunting queries (16 queries)
    └── cost-optimization-queries.json  # Standalone cost optimization queries (15)
```

## Deployment

### Prerequisites

- Azure PowerShell (`Az` module) installed
- Contributor or Microsoft Sentinel Contributor role on the workspace resource group
- Microsoft Sentinel enabled on the target Log Analytics workspace

### Quick Deploy (All Resources)

```powershell
.\deploy.ps1 -ResourceGroupName "<RG_NAME>" -WorkspaceName "<WORKSPACE>"
```

The script will automatically:
1. Clean up stale savedSearches from prior deployments (prevents Hunts blade duplicates)
2. Deploy analytic rules
3. Deploy ingestion monitoring queries
4. Deploy cost optimization queries

### Selective Deployment

```powershell
# Analytic rules only
.\deploy.ps1 -ResourceGroupName "<RG_NAME>" -WorkspaceName "<WORKSPACE>" -DeploymentMode AnalyticRulesOnly

# Ingestion monitoring queries only
.\deploy.ps1 -ResourceGroupName "<RG_NAME>" -WorkspaceName "<WORKSPACE>" -DeploymentMode HuntingQueriesOnly

# Cost optimization queries only
.\deploy.ps1 -ResourceGroupName "<RG_NAME>" -WorkspaceName "<WORKSPACE>" -DeploymentMode CostOptimizationOnly

# All except cost optimization
.\deploy.ps1 -ResourceGroupName "<RG_NAME>" -WorkspaceName "<WORKSPACE>" -SkipCostOptimization

# Skip cleanup of old savedSearches
.\deploy.ps1 -ResourceGroupName "<RG_NAME>" -WorkspaceName "<WORKSPACE>" -SkipCleanup
```

### Custom Parameters

```powershell
.\deploy.ps1 `
    -ResourceGroupName "<RG_NAME>" `
    -WorkspaceName "<WORKSPACE>" `
    -DailyBudgetGB 20 `
    -CostPerGB "3.10"
```

### Direct ARM Deployment

```powershell
# Master template (edit parameters file first)
New-AzResourceGroupDeployment `
    -ResourceGroupName "<RG_NAME>" `
    -TemplateFile "arm-templates/azuredeploy.json" `
    -TemplateParameterFile "arm-templates/azuredeploy.parameters.json"

# Standalone - analytic rules only
New-AzResourceGroupDeployment `
    -ResourceGroupName "<RG_NAME>" `
    -TemplateFile "arm-templates/analytic-rules.json" `
    -workspaceName "<WORKSPACE>"

# Standalone - ingestion monitoring queries only
New-AzResourceGroupDeployment `
    -ResourceGroupName "<RG_NAME>" `
    -TemplateFile "arm-templates/hunting-queries.json" `
    -workspaceName "<WORKSPACE>"

# Standalone - cost optimization queries only
New-AzResourceGroupDeployment `
    -ResourceGroupName "<RG_NAME>" `
    -TemplateFile "arm-templates/cost-optimization-queries.json" `
    -workspaceName "<WORKSPACE>"
```

> **Note:** When deploying via ARM directly (not `deploy.ps1`), run `cleanup-old-hunts.ps1` first
> to remove stale savedSearches that may appear in the Hunts blade.

## Analytic Rules (5)

| Rule | Severity | Frequency | Description |
|------|----------|-----------|-------------|
| Z-Score Anomaly | Medium | Daily | Detects tables with ingestion >3σ from 14-day baseline |
| 3x Spike | High | Daily | Single table exceeds 3x average (min 10 MB threshold) |
| Silent Table | Medium | Daily | Active table drops to zero ingestion in 24h |
| New Table | Medium | Daily | Unknown DataType appears (not seen in 30 days) |
| Budget Breach | High | Daily | Total daily ingestion exceeds configured GB budget |

## Hunting Queries (16 in ARM template)

### Ingestion Analysis (6)
- **Ingestion Dashboard** — 30-day overview with cost estimates and % of total
- **Hourly Heatmap** — 7-day hour-by-day pattern detection
- **Week-over-Week Growth** — Growth classification (RAPID/GROWING/STABLE/DECLINING)
- **Top 10 Noisiest** — 30-day daily trend for highest-volume tables
- **Custom Table Cost** — `_CL` tables with staleness detection
- **Solution Breakdown** — Per-connector cost aggregation

### M365 E5 Benefit & Table Analysis (5)
- **M365 E5 Benefit Usage** — Daily benefit consumption from Operation/Billing records vs grant capacity (5 MB/user/day). Supports E5/A5/F5/G5 and Security SKUs
- **M365 E5 Table Sizes by Product** — Size of all benefit-eligible tables (Entra ID + Defender XDR) with `estimate_data_size` and cost if billable
- **All Tables with Sentinel Price** — Every table with actual size via `estimate_data_size` and cost projection
- **Data Ingestion per Server** — Top 50 noisiest servers by volume with monthly cost estimate
- **Computers Not Reporting** — Servers that stopped sending SecurityEvent for >1h

### Security & Operational (2)
- **SecurityEvent Top EventIDs** — Volume by EventID with DCR recommendations
- **Column Size Analysis** — Per-column size analysis using `evaluate narrow()`

### Auxiliary Monitoring (1 in ARM)
- **Migration Candidates** — Cost optimization via query-frequency analysis (identifies tables for Data Lake migration with ~67% savings)

### Retention Compliance (2)
- **Effective Retention** — Observed retention per table with tier classification
- **Gap Detection** — Tables below 90-day expected retention

### Cost Optimization - Noise Detection (15 in separate template)
- **Process Creation Noise** — Top 50 noisy processes in EventID 4688 with DCR filter thresholds
- **Logon Event Noise** — LogonType breakdown + top 20 noisiest accounts (machine/service)
- **Syslog Facility Noise** — By severity (info/notice/debug = FILTER) and facility (cron/ntp = FILTER)
- **NonInteractive SignIn Noise** — App analysis for token refresh noise (Outlook, Teams, OneDrive)
- **CommonSecurityLog Noise** — Device vendor/product, DeviceAction (allow = FILTER), health events
- **Heartbeat Over-Reporting** — Duplicate agent detection (MMA+AMA), excess heartbeat quantification
- **Repeated Value Dominance** — Generic any-table query for columns with >30% single-value dominance
- **AuditLogs Operation Noise** — High-volume operations (Update policy, group churn, consent)
- **Cross-Table Entity Overlap** — Accounts/IPs/Hosts in 3+ tables simultaneously
- **SignIn Tables Overlap** — SignInLogs vs AADNonInteractiveUserSignInLogs volume ratio and user overlap
- **Master Noise Summary** — All-table noise aggregation with estimated GB savings and monthly cost reduction
- *Plus 4 additional noise/duplicate queries*

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `workspaceName` | — | Log Analytics workspace name (required) |
| `workspaceResourceGroup` | Current RG | Resource group of the workspace |
| `dailyBudgetGB` | 15 | Daily ingestion budget threshold (GB) |
| `costPerGB` | 2.76 | Cost per GB for ingestion estimates (EUR/USD) |
| `m365LicensedUsers` | 100 | M365 E5/A5/F5/G5 licensed user count for benefit grant (5 MB/user/day) |
| `deployAnalyticRules` | true | Deploy the 5 analytic rules |
| `deployHuntingQueries` | true | Deploy the 16 hunting queries |

## Auxiliary Tables (Excluded from Billing)

These tables are classified as Auxiliary/Free and excluded from billable ingestion calculations:

- `OfficeActivity`, `AzureActivity`, `Heartbeat`, `SentinelHealth`
- `SecurityAlert`, `SecurityIncident`, `Operation`
