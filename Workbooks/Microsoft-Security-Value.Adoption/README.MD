# Microsoft Security E5 Value Workbook

An Azure Workbook that presents evidence of Microsoft security adoption, threat prevention, response, and improvement opportunities across Microsoft Sentinel and Microsoft Defender.

The workbook deliberately keeps different event units separate. Alerts, blocked messages, risky sign-ins, endpoint actions, and incidents must not be added together as a single "threats stopped" value. A zero can also mean that telemetry is missing, stale, or not connected.

## Evidence sources

| Source | Purpose | Window |
| --- | --- | --- |
| Microsoft Sentinel Analytics | Incidents, alerts, sign-ins, email, cloud, and SOC operations | Workbook time selector |
| Defender Advanced Hunting | Endpoint, identity, email, cloud, disruption, and vulnerability evidence | Native 30 days |
| Sentinel Data Lake | Retained evidence across the workbook tables | Selectable 30, 60, 90, 180, or 365 days |
| Microsoft Graph | Licensing, Secure Score, Conditional Access, MFA registration, device compliance, guests, risky users, and XDR alerts | Live control-plane state |

## Workbook pages

1. `00 KPI cards` - security posture, threat protection, and response summary.
2. `01 Executive` - observed outcomes, incident trend, and evidence quality.
3. `02 Adoption` - telemetry-driven maturity and observed inventory coverage.
4. `03 Prevented` - prevention and containment actions by security domain.
5. `04 XDR` - cross-workload alert and incident correlation.
6. `05 Identity` - risky identities, risky sign-ins, and interrupted authentication.
7. `06 Endpoint` - device onboarding, sensor health, exposure, and protection actions.
8. `07 Email` - email threats, remediation, and cloud application activity.
9. `08 SOC` - incident operations, throughput, resolution time, and automation.
10. `09 Roadmap` - evidence-backed gaps and prioritized improvements.
11. `10 Hunting` - on-demand Defender Advanced Hunting views.
12. `11 Data Lake` - selectable 30-365 day trends across eight security evidence areas.
13. `12 Microsoft Graph` - licensing, posture, identity, and device governance.

## Prerequisites

- An Azure subscription and resource group.
- A Log Analytics workspace with Microsoft Sentinel enabled.
- Permission to deploy `Microsoft.Insights/workbooks` resources.
- Access to Microsoft Defender XDR Advanced Hunting for pages `00`, `03`, `06`, and `10`.
- A Sentinel Data Lake workspace with the relevant tables retained for page `11`.
- Microsoft Graph read permissions appropriate to each page `12` tile, including Organization/Directory, SecurityEvents, Policy, Identity Risky User, Reports/Audit Log, Device Management, and User read permissions.

Available results depend on licensing, data connectors, retention, role assignments, and activity in the selected tenant.

## Build and validate

Run from the repository root in PowerShell:

```powershell
.\build-workbook.ps1
.\Test-Workbook.ps1
```

The build script generates [workbook/Microsoft-Security-E5-Value.workbook.json](workbook/Microsoft-Security-E5-Value.workbook.json). The test script rebuilds it and validates page navigation, query providers, on-demand Advanced Hunting controls, portable resource bindings, and basic content safety.

## Deploy

Deploy the workbook with Bicep. The template replaces the portable workspace placeholder with the supplied resource ID.

```powershell
$workspaceResourceId = '/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>'

az deployment group create `
  --resource-group '<resource-group>' `
  --template-file '.\infra\main.bicep' `
  --parameters workspaceResourceId=$workspaceResourceId
```

The default workbook display name is **Microsoft Security Value and Adoption**. Optional Bicep parameters can change its location, display name, and tags.

## Post-deployment setup

1. Open **Microsoft Sentinel > Workbooks** and select **Microsoft Security Value and Adoption**.
2. Set **Evidence period** and confirm the **Sentinel workspace**.
3. On page `11 Data Lake`, select the Data Lake workspace in each tile and save the workbook. The selector is intentionally unset for portability.
4. On page `12 Microsoft Graph`, sign in with an identity that has the required read permissions. If a tile fails, edit it and confirm its Microsoft Graph data source and workspace.
5. Leave Advanced Hunting selectors at **Off** until needed. Run one view at a time to reduce Defender tenant CPU usage.

## Repository layout

```text
build-workbook.ps1       Workbook generator
Test-Workbook.ps1        Structural and safety validation
infra/main.bicep         Azure Workbook deployment
queries/                 Standalone hunting and Data Lake examples
workbook/                Generated workbook JSON
YOUTUBE-DEMO-GUIDE.md    English presenter walkthrough and script
YOUTUBE-DEMO-GUIDE-ES.md Spanish presenter walkthrough and script
```

## Interpretation guardrails

- Validate page `01` **Evidence quality** before making an executive claim.
- "Not observed" does not prove that a capability is unlicensed or disabled.
- Coverage is based on observed inventories, not license assignments.
- Advanced Hunting uses a native 30-day window, independent of the workbook time selector.
- Data Lake tiles default to 30 days and use lightweight counts. Increase the page-specific period only when needed; use native Data Lake exploration for exact distinct counts or heavier analysis.
- Analyst-hours-saved estimates require an organization-approved effort model and should remain separate from observed metrics.
