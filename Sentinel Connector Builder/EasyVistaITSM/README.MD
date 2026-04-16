# EasyVista ITSM Integration for Microsoft Sentinel

Complete **bidirectional integration** between Microsoft Sentinel (SecOps) and EasyVista ITSM (IT Service Management). This Content Hub solution automates the full incident-to-ticket lifecycle with full attack story enrichment.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_ORG%2FYOUR_REPO%2Fmain%2FEasyVista%2FSolution%2FmainTemplate.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_ORG%2FYOUR_REPO%2Fmain%2FEasyVista%2FSolution%2FcreateUiDefinition.json)

> **Note**: Replace `YOUR_ORG/YOUR_REPO` in the button URL above with your actual GitHub organization and repository name.

---

## Architecture

```
┌──────────────────────┐                          ┌──────────────────────┐
│  Microsoft Sentinel  │  ◄─── Bidirectional ───► │   EasyVista ITSM     │
│                      │                          │                      │
│  ┌────────────────┐  │    Create Ticket ──►     │  ┌────────────────┐  │
│  │ Incidents      │──┼──────────────────────────┼─►│ Tickets        │  │
│  │ (High/Medium)  │  │                          │  │ (RFC_NUMBER)   │  │
│  └────────────────┘  │    ◄── Sync Status       │  └────────────────┘  │
│                      │                          │                      │
│  ┌────────────────┐  │    Get Enrichment ──►    │  ┌────────────────┐  │
│  │ Alerts         │──┼──────────────────────────┼─►│ Assets (CMDB)  │  │
│  │ (Full Story)   │  │                          │  │ Employees      │  │
│  └────────────────┘  │    ◄── Response Actions  │  │ Config Items   │  │
│                      │                          │  └────────────────┘  │
│  ┌────────────────┐  │    Close Ticket ──►      │                      │
│  │ Analytics      │  │                          │  ┌────────────────┐  │
│  │ Workbook       │  │                          │  │ ##SECURITY##   │  │
│  │ Hunting        │  │    ◄── Trigger Actions   │  │ Action Tags    │  │
│  └────────────────┘  │                          │  └────────────────┘  │
└──────────────────────┘                          └──────────────────────┘
         │                                                   │
         └───── EV:{RFC_NUMBER} tag ◄────────────────────────┘
                EXTERNAL_REFERENCE (ARM ID) ─────────────────►
```

### Status Lifecycle Mapping

| Sentinel Status | Direction | EasyVista Status |
|---|:---:|---|
| New | ↔ | Open |
| Active | ↔ | Investigating |
| Active | ← | Contained |
| Closed | ↔ | Resolved |

---

## Solution Contents

This solution deploys **18 resources** via a single ARM template:

| Category | Count | Description |
|---|---|---|
| **Playbooks** | 6 | Logic App workflows for bidirectional automation |
| **Analytic Rules** | 5 | Scheduled KQL detection rules |
| **Hunting Queries** | 5 | Proactive threat hunting saved searches |
| **Workbook** | 1 | CISO Dashboard with 6 operational tabs |
| **Solution Metadata** | 1 | Content Hub package registration |

---

## Playbooks

### 1. EasyVista-CreateIncident
**Direction**: Sentinel → EasyVista

Creates an EasyVista ITSM ticket when a Sentinel incident is generated. Includes a **confidence gate** that only escalates High/Medium severity incidents.

**Ticket content includes**:
- **Full Attack Story** — All correlated alerts with descriptions, providers, and severity
- **Chronological Timeline** — Events sorted oldest-to-newest as an HTML table
- **Root Cause Analysis** — First-alert attribution, kill chain progression, attack narrative
- **Endpoint Telemetry** — Hostname, FQDN, IP address, OS family & version, Azure AD Device ID
- **User Context** — Account name, UPN, AAD User ID, SID, account type
- **MITRE ATT&CK Mapping** — Tactics + techniques per alert, overall kill chain
- **IOCs** — IP addresses, file hashes (SHA1/SHA256), URLs, domain names
- **Recommended Actions** — Immediate response steps for the IT team

Low/Informational severity incidents are tagged `EV:Skipped-LowConfidence` and remain in Sentinel only.

### 2. EasyVista-UpdateTicketStatus
**Direction**: Sentinel → EasyVista

Syncs incident status changes from Sentinel to EasyVista. When an analyst changes the Sentinel incident status, the linked EasyVista ticket is automatically updated with the mapped status and an action log entry.

### 3. EasyVista-CloseTicket
**Direction**: Sentinel → EasyVista

When a Sentinel incident is closed, this playbook closes the linked EasyVista ticket with the full resolution details including classification, determination, and closing comments.

### 4. EasyVista-SyncStatusToSentinel
**Direction**: EasyVista → Sentinel

Polls EasyVista every 5 minutes for recently updated tickets with Sentinel linkage (`EXTERNAL_REFERENCE`). Maps EasyVista status changes back to Sentinel incident status via the ARM API.

### 5. EasyVista-GetTicketInfo
**Direction**: Bidirectional (Enrichment)

Retrieves ticket details from EasyVista (status, owner, SLA deadline, actions) and adds them as an enrichment comment to the Sentinel incident. Automatically escalates incident severity if the SLA has been breached.

### 6. EasyVista-TriggerResponseActions
**Direction**: EasyVista → Sentinel → MDE

Polls EasyVista for tickets tagged with `##SECURITY_ACTION##`. Supports:
- `##ISOLATE_HOST##` — Isolate device via MDE API
- `##KILL_PROCESS##` — Terminate malicious processes
- `##QUARANTINE_FILE##` — Quarantine files by SHA1 hash

Requires an Azure AD App Registration with MDE `Machine.Isolate` and `Machine.StopAndQuarantineFile` permissions.

---

## Analytic Rules

| Rule | Severity | Frequency | Detection |
|---|---|---|---|
| **High Severity SLA Breach** | High | 1h | Open tickets past SLA deadline |
| **Sync Drift Detection** | Medium | 30m | Sentinel ↔ EasyVista status mismatch >30 min |
| **Unusual Ticket Volume** | Medium | 1h | Volume >3σ above 14-day baseline |
| **Repeated Incidents Same Asset** | High | 6h | 3+ incidents on same asset in 7 days |
| **Missing ITSM Ticket** | Informational | 1h | High/Medium incidents without EV: tag after 1h |

### MITRE ATT&CK Coverage

| Tactic | Techniques |
|---|---|
| Impact | T1499, T1489 |
| Initial Access | T1566 |
| Persistence | T1078 |
| Lateral Movement | T1021 |

---

## Hunting Queries

| Query | Tactics | What it finds |
|---|---|---|
| **Expired Warranty Assets** | Persistence (T1190) | Assets with expired warranty involved in incidents |
| **Dormant Account Tickets** | Initial Access, Persistence (T1078) | Ex-employees still creating ITSM tickets |
| **Orphaned Tickets** | Impact | API-created tickets missing Sentinel linkage |
| **High Churn Tickets** | Defense Evasion | Tickets with >5 updates in <60 minutes |
| **Cross-Dept Correlation** | Lateral Movement (T1021) | High-severity incidents hitting 3+ departments in 2h |

---

## Workbook — CISO Dashboard

A 6-tab operational dashboard with a capabilities overview page:

| Tab | Key Visualizations |
|---|---|
| **Executive Summary** | KPI tiles, volume trend, severity distribution, top departments, linkage rate |
| **Ticket Operations** | Open tickets table, type/origin/status breakdowns, resolved tickets |
| **SLA & Performance** | SLA compliance (Met/Breached/On Track/At Risk), MTTR by severity, trend |
| **Sync Health** | Linkage tiles, status comparison table, sync rate trend, unlinked incidents |
| **Response Actions** | Action type distribution, action log table, actions over time |
| **Asset & Employee Intel** | Asset overview, top 20 assets/users by incidents, CI status |

---

## Data Connector (CCF)

The Codeless Connector Framework (CCF) data connector ingests 4 data types from EasyVista REST API v1:

| Table | Description | Key Fields |
|---|---|---|
| `EasyVista_Tickets_CL` | Service requests & incidents | RFC_NUMBER, STATUS_EN, SEVERITY_ID, ASSET_TAG |
| `EasyVista_Assets_CL` | CMDB assets | ASSET_TAG, SERIAL_NUMBER, END_OF_WARANTY |
| `EasyVista_Employees_CL` | Employee directory | EMPLOYEE_ID, E_MAIL, END_OF_CONTRACT |
| `EasyVista_CIs_CL` | Configuration items | CI_ID, CI_NAME, STATUS, CRITICALITY |

> The CCF data connector files are located in the `DataConnector/` folder and should be deployed separately before deploying this solution.

---

## Prerequisites

1. **Microsoft Sentinel** workspace with Log Analytics
2. **EasyVista ITSM** with REST API v1 access enabled
3. **EasyVista Bearer Token** with permissions to read/write tickets, assets, employees, CIs
4. **Azure AD App Registration** (optional) — Only required for the `TriggerResponseActions` playbook:
   - API permissions: `Machine.Isolate`, `Machine.StopAndQuarantineFile` on Microsoft Defender for Endpoint
5. **CCF Data Connector** deployed (from `DataConnector/` folder) to ingest EasyVista data

---

## Deployment

### Option 1: Deploy to Azure Button

Click the **Deploy to Azure** button at the top of this README. The portal wizard will guide you through:
1. **Basics** — Select subscription, resource group, and Sentinel workspace
2. **EasyVista Connection** — Enter server host, account ID, and Bearer token
3. **Solution Components** — Choose which components to deploy (playbooks, workbook)
4. **Response Actions** — Optionally configure MDE API credentials

### Option 2: PowerShell Deployment

```powershell
# Generate the mainTemplate.json from source files
cd EasyVista\Solution
pwsh -File .\build-mainTemplate.ps1

# Deploy to Azure
Connect-AzAccount
New-AzResourceGroupDeployment `
    -ResourceGroupName "RG_Sentinel" `
    -TemplateFile ".\mainTemplate.json" `
    -workspace "lawsentinel" `
    -EasyVistaHost "your-company.easyvista.com" `
    -EasyVistaAccount "50004" `
    -EasyVistaBearerToken (Read-Host -AsSecureString "Bearer Token")
```

### Option 3: Azure CLI

```bash
az deployment group create \
    --resource-group RG_Sentinel \
    --template-file EasyVista/Solution/mainTemplate.json \
    --parameters workspace=lawsentinel \
                 EasyVistaHost=your-company.easyvista.com \
                 EasyVistaAccount=50004 \
                 EasyVistaBearerToken=<YOUR_TOKEN>
```

### Deploy Data Connector (Separate Step)

The CCF data connector must be deployed before the solution to ensure the custom tables exist:

```powershell
# Deploy the custom tables
az monitor log-analytics workspace table create `
    --resource-group RG_Sentinel `
    --workspace-name lawsentinel `
    --name EasyVista_Tickets_CL `
    --plan Analytics `
    --columns @DataConnector/table-tickets.json

# Deploy the DCR (Data Collection Rule)
az monitor data-collection rule create `
    --resource-group RG_Sentinel `
    --name "EasyVista-DCR" `
    --rule-file DataConnector/dcr.json

# Deploy the connector definition
# (Follow the CCF deployment guide for your environment)
```

---

## Post-Deployment Configuration

1. **Enable Managed Identity** on each playbook and grant:
   - `Microsoft Sentinel Responder` role on the Sentinel workspace
   - `Logic App Contributor` (for the SyncStatusToSentinel playbook)

2. **Authorize API Connections** in each playbook:
   - Open each Logic App in the Azure Portal
   - Go to **API connections** and authorize the Sentinel connection

3. **Configure Automation Rules** in Sentinel:
   - **Incident creation** → Trigger `EasyVista-CreateIncident`
   - **Incident updated** → Trigger `EasyVista-UpdateTicketStatus`
   - **Incident closed** → Trigger `EasyVista-CloseTicket`

4. **Enable Analytic Rules** — All 5 rules are deployed enabled by default

5. **Test the Integration**:
   - Create a test incident in Sentinel (High severity)
   - Verify a ticket is created in EasyVista with the full attack story
   - Change the Sentinel incident status and verify EasyVista updates
   - Close the incident and verify bidirectional closure

---

## File Structure

```
EasyVista/
├── README.md                                          # This file
├── DataConnector/                                     # CCF REST API Connector
│   ├── connector-definition.json                      # Connector metadata & UI
│   ├── dcr.json                                       # Data Collection Rule
│   ├── polling-tickets.json                           # Ticket polling config
│   ├── polling-assets.json                            # Asset polling config
│   ├── polling-employees.json                         # Employee polling config
│   ├── polling-cis.json                               # CI polling config
│   ├── table-tickets.json                             # EasyVista_Tickets_CL schema
│   ├── table-assets.json                              # EasyVista_Assets_CL schema
│   ├── table-employees.json                           # EasyVista_Employees_CL schema
│   └── table-cis.json                                 # EasyVista_CIs_CL schema
└── Solution/                                          # Content Hub Solution
    ├── mainTemplate.json                              # ARM template (all 18 resources)
    ├── createUiDefinition.json                        # Portal deployment wizard
    ├── build-mainTemplate.ps1                         # Script to regenerate mainTemplate
    ├── Playbooks/
    │   ├── EasyVista-CreateIncident/azuredeploy.json  # Sentinel → EV (full attack story)
    │   ├── EasyVista-UpdateTicketStatus/azuredeploy.json
    │   ├── EasyVista-GetTicketInfo/azuredeploy.json   # Bidirectional enrichment
    │   ├── EasyVista-TriggerResponseActions/azuredeploy.json  # EV → MDE actions
    │   ├── EasyVista-SyncStatusToSentinel/azuredeploy.json    # EV → Sentinel sync
    │   └── EasyVista-CloseTicket/azuredeploy.json
    ├── Workbooks/
    │   └── EasyVista-CISO-Dashboard.json              # 6-tab CISO workbook
    ├── AnalyticRules/
    │   ├── EV-HighSeverity-SLABreach.yaml
    │   ├── EV-SyncDrift-Detection.yaml
    │   ├── EV-UnusualTicketVolume.yaml
    │   ├── EV-RepeatedIncidents-SameAsset.yaml
    │   └── EV-MissingITSMTicket.yaml
    └── HuntingQueries/
        ├── EV-Hunt-ExpiredWarrantyAssets.yaml
        ├── EV-Hunt-DormantAccountTickets.yaml
        ├── EV-Hunt-OrphanedTickets.yaml
        ├── EV-Hunt-HighChurnTickets.yaml
        └── EV-Hunt-CrossDeptCorrelation.yaml
```

---

## Tracking & Cross-Referencing

All bidirectional communication uses two identifiers:

| Identifier | Where | Format | Example |
|---|---|---|---|
| **EV: tag** | Sentinel incident labels | `EV:{RFC_NUMBER}` | `EV:I240416-001` |
| **EXTERNAL_REFERENCE** | EasyVista ticket field | Full ARM resource ID | `/subscriptions/.../incidents/...` |

This ensures every Sentinel incident can find its EasyVista ticket and vice versa.

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---|---|---|
| No tickets created | Confidence gate filtering | Check if incidents are High/Medium severity. Low severity gets `EV:Skipped-LowConfidence` tag |
| Sync drift alerts firing | Playbook execution failure | Check Logic App run history for errors. Verify API connections are authorized |
| Missing ITSM Ticket alerts | Automation rule not configured | Ensure the `EasyVista-CreateIncident` playbook is triggered by an incident creation automation rule |
| Response actions not executing | MDE permissions missing | Verify the Azure AD App Registration has `Machine.Isolate` and `Machine.StopAndQuarantineFile` permissions |
| Workbook shows no data | Data connector not deployed | Deploy the CCF data connector from the `DataConnector/` folder first |

---

## License

This solution is provided as-is for the security community. No warranty expressed or implied.
