<#
.SYNOPSIS
    Generates the mainTemplate.json for the EasyVista ITSM Content Hub Solution.
.DESCRIPTION
    Reads all solution components (playbooks, workbook, analytic rules, hunting queries)
    and assembles them into a single self-contained ARM template for Content Hub deployment.
.NOTES
    Run from the Solution directory: .\build-mainTemplate.ps1
#>

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Building EasyVista ITSM Content Hub Solution mainTemplate.json..." -ForegroundColor Cyan

# ============================================================
# READ SOURCE FILES
# ============================================================

# --- Workbook ---
$workbookPath = Join-Path $scriptDir "Workbooks\EasyVista-CISO-Dashboard.json"
if (-not (Test-Path $workbookPath)) { throw "Workbook not found: $workbookPath" }
$workbookContent = Get-Content $workbookPath -Raw
Write-Host "  Read workbook: $workbookPath" -ForegroundColor Gray

# --- Playbooks ---
$playbookNames = @(
    'EasyVista-CreateIncident',
    'EasyVista-UpdateTicketStatus',
    'EasyVista-GetTicketInfo',
    'EasyVista-TriggerResponseActions',
    'EasyVista-SyncStatusToSentinel',
    'EasyVista-CloseTicket'
)
$playbookTemplates = @{}
foreach ($name in $playbookNames) {
    $pbPath = Join-Path $scriptDir "Playbooks\$name\azuredeploy.json"
    if (-not (Test-Path $pbPath)) { throw "Playbook not found: $pbPath" }
    $playbookTemplates[$name] = Get-Content $pbPath -Raw | ConvertFrom-Json
    Write-Host "  Read playbook: $name" -ForegroundColor Gray
}

# ============================================================
# DEFINE ANALYTIC RULE QUERIES (using here-strings to avoid escaping issues)
# ============================================================

$rule1_query = @'
union isfuzzy=true
    EasyVista_Tickets_CL,
    (datatable(TimeGenerated:datetime,RFC_NUMBER:string,TITLE:string,SEVERITY_ID:int,STATUS_EN:string,REQUESTOR_NAME:string,REQUESTOR_EMAIL:string,RECIPIENT_NAME:string,DEPARTMENT_PATH:string,LOCATION_PATH:string,ASSET_TAG:string,MAX_RESOLUTION_DATE_UT:datetime,REQUEST_TYPE:string,SUBMIT_DATE_UT:datetime)[] | where 1==0)
| where TimeGenerated > ago(1d)
| where REQUEST_TYPE has_any ("Incident", "I")
| where SEVERITY_ID <= 2
| where STATUS_EN !in ("Closed", "Resolved")
| where isnotempty(MAX_RESOLUTION_DATE_UT)
| where MAX_RESOLUTION_DATE_UT < now()
| extend OverdueHours = datetime_diff('hour', now(), MAX_RESOLUTION_DATE_UT)
| project
    TimeGenerated,
    RFC_NUMBER,
    ['TITLE'],
    SEVERITY_ID,
    STATUS_EN,
    REQUESTOR_NAME,
    REQUESTOR_EMAIL,
    RECIPIENT_NAME,
    DEPARTMENT_PATH,
    LOCATION_PATH,
    ASSET_TAG,
    MAX_RESOLUTION_DATE_UT,
    OverdueHours
'@

$rule2_query = @'
SecurityIncident
| where TimeGenerated > ago(1h)
| where Labels has "EV:"
| extend EVTicket = extract(@"EV:([^,\]]+)", 1, tostring(Labels))
| where isnotempty(EVTicket)
| join kind=inner (
    union isfuzzy=true
        EasyVista_Tickets_CL,
        (datatable(TimeGenerated:datetime,RFC_NUMBER:string,STATUS_EN:string,LAST_UPDATE:datetime)[] | where 1==0)
    | where TimeGenerated > ago(1d)
    | summarize arg_max(TimeGenerated, *) by RFC_NUMBER
    | project RFC_NUMBER, EV_Status = STATUS_EN, EV_LastUpdate = LAST_UPDATE
) on $left.EVTicket == $right.RFC_NUMBER
| extend ExpectedEVStatus = case(
    Status == "New", "Open",
    Status == "Active", "Investigating",
    Status == "Closed", "Resolved",
    "Unknown")
| where EV_Status != ExpectedEVStatus
| where EV_Status != "Contained" or Status != "Active"
| where datetime_diff('minute', now(), LastModifiedTime) > 30
| project
    TimeGenerated,
    IncidentNumber,
    IncidentTitle = Title,
    SentinelStatus = Status,
    EVTicket,
    EV_Status,
    ExpectedEVStatus,
    DriftMinutes = datetime_diff('minute', now(), LastModifiedTime)
'@

$rule3_query = @'
let baseline = (union isfuzzy=true
    EasyVista_Tickets_CL,
    (datatable(TimeGenerated:datetime,REQUEST_TYPE:string)[] | where 1==0))
| where TimeGenerated between (ago(14d) .. ago(1h))
| where REQUEST_TYPE has_any ("Incident", "I")
| summarize HourlyCount = count() by bin(TimeGenerated, 1h)
| summarize AvgCount = avg(HourlyCount), StdDev = stdev(HourlyCount);
let current = (union isfuzzy=true
    EasyVista_Tickets_CL,
    (datatable(TimeGenerated:datetime,REQUEST_TYPE:string)[] | where 1==0))
| where TimeGenerated > ago(1h)
| where REQUEST_TYPE has_any ("Incident", "I")
| summarize CurrentCount = count();
baseline
| join kind=cross current
| where CurrentCount > AvgCount + (3 * StdDev)
| extend Threshold = round(AvgCount + (3 * StdDev), 0)
| project
    TimeGenerated = now(),
    CurrentCount,
    BaselineAvg = round(AvgCount, 1),
    BaselineStdDev = round(StdDev, 1),
    Threshold,
    Deviation = round((CurrentCount - AvgCount) / StdDev, 1)
'@

$rule4_query = @'
union isfuzzy=true
    EasyVista_Tickets_CL,
    (datatable(TimeGenerated:datetime,RFC_NUMBER:string,REQUEST_TYPE:string,ASSET_TAG:string,SEVERITY_ID:int,SUBMIT_DATE_UT:datetime)[] | where 1==0)
| where TimeGenerated > ago(7d)
| where REQUEST_TYPE has_any ("Incident", "I")
| where isnotempty(ASSET_TAG)
| summarize
    IncidentCount = count(),
    Tickets = make_set(RFC_NUMBER, 10),
    Severities = make_set(SEVERITY_ID, 10),
    FirstSeen = min(SUBMIT_DATE_UT),
    LastSeen = max(SUBMIT_DATE_UT)
    by ASSET_TAG
| where IncidentCount >= 3
| join kind=leftouter (
    union isfuzzy=true
        EasyVista_Assets_CL,
        (datatable(TimeGenerated:datetime,ASSET_TAG:string,ASSET_LABEL:string,SERIAL_NUMBER:string,EMPLOYEE_NAME:string,EMPLOYEE_EMAIL:string,DEPARTMENT_PATH:string,LOCATION_PATH:string)[] | where 1==0)
    | summarize arg_max(TimeGenerated, *) by ASSET_TAG
    | project ASSET_TAG, ASSET_LABEL, SERIAL_NUMBER, EMPLOYEE_NAME, EMPLOYEE_EMAIL, DEPARTMENT_PATH, LOCATION_PATH
) on ASSET_TAG
| project
    TimeGenerated = now(),
    ASSET_TAG,
    ASSET_LABEL,
    SERIAL_NUMBER,
    IncidentCount,
    Tickets,
    Severities,
    FirstSeen,
    LastSeen,
    AssignedUser = EMPLOYEE_NAME,
    AssignedEmail = EMPLOYEE_EMAIL,
    Department = DEPARTMENT_PATH,
    Location = LOCATION_PATH
'@

$rule5_query = @'
SecurityIncident
| where TimeGenerated > ago(4h)
| where CreatedTime < ago(1h)
| where Status != "Closed"
| where not(Labels has "EV:")
| where Severity in ("High", "Medium")
| project
    TimeGenerated,
    IncidentNumber,
    IncidentTitle = Title,
    Severity,
    Status,
    CreatedTime,
    AlertCount = AdditionalData.alertsCount,
    Owner = tostring(Owner.assignedTo)
'@

# ============================================================
# DEFINE HUNTING QUERY QUERIES
# ============================================================

$hunt1_query = @'
EasyVista_Assets_CL
| where TimeGenerated > ago(30d)
| where isnotempty(END_OF_WARANTY) and END_OF_WARANTY < now()
| join kind=inner (
    EasyVista_Tickets_CL
    | where TimeGenerated > ago(30d)
    | where REQUEST_TYPE has_any ("Incident", "I")
    | summarize IncidentCount = count(), LastIncident = max(SUBMIT_DATE_UT), Tickets = make_set(RFC_NUMBER, 5) by ASSET_TAG
) on ASSET_TAG
| project ASSET_TAG, ASSET_LABEL, SERIAL_NUMBER, END_OF_WARANTY, EMPLOYEE_NAME, DEPARTMENT_PATH, LOCATION_PATH, IncidentCount, LastIncident, Tickets
| sort by IncidentCount desc
'@

$hunt2_query = @'
EasyVista_Employees_CL
| where TimeGenerated > ago(30d)
| where isnotempty(END_OF_CONTRACT) and END_OF_CONTRACT < now()
| join kind=inner (
    EasyVista_Tickets_CL
    | where TimeGenerated > ago(30d)
    | summarize TicketCount = count(), LastTicket = max(SUBMIT_DATE_UT), Tickets = make_set(RFC_NUMBER, 5) by REQUESTOR_EMAIL
) on $left.E_MAIL == $right.REQUESTOR_EMAIL
| project EMPLOYEE_ID, LAST_NAME, E_MAIL, END_OF_CONTRACT, DEPARTMENT_PATH, LOCATION_PATH, TicketCount, LastTicket, Tickets
| sort by TicketCount desc
'@

$hunt3_query = @'
EasyVista_Tickets_CL
| where TimeGenerated > ago(7d)
| where REQUEST_TYPE has_any ("Incident", "I")
| where ORIGIN == "API"
| where isempty(EXTERNAL_REFERENCE) or not(EXTERNAL_REFERENCE has "/subscriptions/")
| project TimeGenerated, RFC_NUMBER, ['TITLE'], STATUS_EN, SEVERITY_ID, REQUESTOR_NAME, ORIGIN, EXTERNAL_REFERENCE
| sort by TimeGenerated desc
'@

$hunt4_query = @'
EasyVista_Tickets_CL
| where TimeGenerated > ago(7d)
| where REQUEST_TYPE has_any ("Incident", "I")
| summarize
    UpdateCount = count(),
    StatusChanges = dcount(STATUS_EN),
    Statuses = make_set(STATUS_EN),
    TimeSpanMinutes = datetime_diff('minute', max(LAST_UPDATE), min(SUBMIT_DATE_UT))
    by RFC_NUMBER, ['TITLE']
| where UpdateCount > 5 and TimeSpanMinutes < 60
| extend ChurnRate = round(toreal(UpdateCount) / iif(TimeSpanMinutes > 0, toreal(TimeSpanMinutes), 1.0), 2)
| sort by ChurnRate desc
'@

$hunt5_query = @'
EasyVista_Tickets_CL
| where TimeGenerated > ago(24h)
| where REQUEST_TYPE has_any ("Incident", "I")
| where SEVERITY_ID <= 2
| summarize
    TicketCount = count(),
    Departments = make_set(DEPARTMENT_PATH, 20),
    DeptCount = dcount(DEPARTMENT_PATH),
    Locations = make_set(LOCATION_PATH, 20),
    Assets = make_set(ASSET_TAG, 20),
    Users = make_set(REQUESTOR_NAME, 20),
    Tickets = make_set(RFC_NUMBER, 20)
    by bin(TimeGenerated, 2h)
| where DeptCount >= 3
| project TimeGenerated, TicketCount, DeptCount, Departments, Locations, Assets, Users, Tickets
| sort by DeptCount desc
'@

# ============================================================
# BUILD ANALYTIC RULES RESOURCES
# ============================================================

$analyticRules = @(
    # Rule 1: SLA Breach
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
        name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d')]"
        apiVersion = "2023-02-01"
        kind = "Scheduled"
        location = "[parameters('location')]"
        properties = [ordered]@{
            displayName = "EasyVista - High Severity Ticket SLA Breach"
            description = "Detects when a high-severity EasyVista security ticket has breached its SLA deadline while still open. This indicates the SOC or IT team has not resolved a critical security issue within the agreed timeframe."
            severity = "High"
            enabled = $true
            query = $rule1_query
            queryFrequency = "PT1H"
            queryPeriod = "P1D"
            triggerOperator = "GreaterThan"
            triggerThreshold = 0
            suppressionDuration = "PT5H"
            suppressionEnabled = $false
            tactics = @("Impact")
            techniques = @("T1499")
            entityMappings = @(
                @{ entityType = "Account"; fieldMappings = @(@{ identifier = "FullName"; columnName = "REQUESTOR_NAME" }) }
                @{ entityType = "Mailbox"; fieldMappings = @(@{ identifier = "MailboxPrimaryAddress"; columnName = "REQUESTOR_EMAIL" }) }
            )
            customDetails = [ordered]@{
                TicketNumber = "RFC_NUMBER"
                TicketStatus = "STATUS_EN"
                SeverityLevel = "SEVERITY_ID"
                OverdueHours = "OverdueHours"
                AssignedTo = "RECIPIENT_NAME"
                Department = "DEPARTMENT_PATH"
            }
            alertDetailsOverride = [ordered]@{
                alertDisplayNameFormat = "SLA Breach: {{RFC_NUMBER}} - {{TITLE}} ({{OverdueHours}}h overdue)"
                alertDescriptionFormat = "EasyVista ticket {{RFC_NUMBER}} (severity {{SEVERITY_ID}}) has breached SLA by {{OverdueHours}} hours."
            }
            incidentConfiguration = [ordered]@{
                createIncident = $true
                groupingConfiguration = [ordered]@{
                    enabled = $true
                    reopenClosedIncident = $false
                    lookbackDuration = "PT4H"
                    matchingMethod = "Selected"
                    groupByCustomDetails = @("TicketNumber")
                }
            }
        }
    },
    # Rule 2: Sync Drift
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
        name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e')]"
        apiVersion = "2023-02-01"
        kind = "Scheduled"
        location = "[parameters('location')]"
        properties = [ordered]@{
            displayName = "EasyVista - Ticket Status Sync Drift Detected"
            description = "Detects when a Sentinel incident status and its linked EasyVista ticket status are out of sync for more than 30 minutes. Ensures SOC and IT teams stay aligned."
            severity = "Medium"
            enabled = $true
            query = $rule2_query
            queryFrequency = "PT30M"
            queryPeriod = "PT1H"
            triggerOperator = "GreaterThan"
            triggerThreshold = 0
            suppressionDuration = "PT5H"
            suppressionEnabled = $false
            tactics = @("Impact")
            techniques = @("T1489")
            entityMappings = @(
                @{ entityType = "CloudApplication"; fieldMappings = @(@{ identifier = "Name"; columnName = "EVTicket" }) }
            )
            customDetails = [ordered]@{
                SentinelIncident = "IncidentNumber"
                SentinelStatus = "SentinelStatus"
                EasyVistaTicket = "EVTicket"
                EasyVistaStatus = "EV_Status"
                ExpectedStatus = "ExpectedEVStatus"
                DriftMinutes = "DriftMinutes"
            }
            alertDetailsOverride = [ordered]@{
                alertDisplayNameFormat = "Sync Drift: Sentinel #{{IncidentNumber}} vs EV {{EVTicket}} ({{EV_Status}})"
                alertDescriptionFormat = "Status sync drift detected. Sentinel #{{IncidentNumber}} and EasyVista {{EVTicket}} are out of sync for {{DriftMinutes}} minutes."
            }
            incidentConfiguration = [ordered]@{
                createIncident = $true
                groupingConfiguration = [ordered]@{
                    enabled = $true
                    reopenClosedIncident = $false
                    lookbackDuration = "PT2H"
                    matchingMethod = "Selected"
                    groupByCustomDetails = @("EasyVistaTicket")
                }
            }
        }
    },
    # Rule 3: Unusual Volume
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
        name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f')]"
        apiVersion = "2023-02-01"
        kind = "Scheduled"
        location = "[parameters('location')]"
        properties = [ordered]@{
            displayName = "EasyVista - Unusual Volume of Security Tickets"
            description = "Detects when the number of security-related EasyVista tickets created in the last hour exceeds the historical baseline by 3 standard deviations. May indicate a mass incident or phishing campaign."
            severity = "Medium"
            enabled = $true
            query = $rule3_query
            queryFrequency = "PT1H"
            queryPeriod = "P14D"
            triggerOperator = "GreaterThan"
            triggerThreshold = 0
            suppressionDuration = "PT5H"
            suppressionEnabled = $false
            tactics = @("Impact", "InitialAccess")
            techniques = @("T1566")
            customDetails = [ordered]@{
                CurrentVolume = "CurrentCount"
                BaselineAverage = "BaselineAvg"
                Threshold = "Threshold"
                StandardDeviations = "Deviation"
            }
            alertDetailsOverride = [ordered]@{
                alertDisplayNameFormat = "Unusual EasyVista Ticket Volume: {{CurrentCount}} tickets in 1h (baseline: {{BaselineAvg}})"
                alertDescriptionFormat = "{{CurrentCount}} security tickets created in the last hour, exceeding the baseline of {{BaselineAvg}} (threshold: {{Threshold}})."
            }
            incidentConfiguration = [ordered]@{
                createIncident = $true
            }
        }
    },
    # Rule 4: Repeated Incidents Same Asset
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
        name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80')]"
        apiVersion = "2023-02-01"
        kind = "Scheduled"
        location = "[parameters('location')]"
        properties = [ordered]@{
            displayName = "EasyVista - Repeated Security Incidents on Same Asset"
            description = "Detects assets that have been involved in 3+ security incidents within 7 days. Indicates persistent compromise, incomplete remediation, or a high-value target under sustained attack. Enriched with CMDB data."
            severity = "High"
            enabled = $true
            query = $rule4_query
            queryFrequency = "PT6H"
            queryPeriod = "P7D"
            triggerOperator = "GreaterThan"
            triggerThreshold = 0
            suppressionDuration = "PT5H"
            suppressionEnabled = $false
            tactics = @("Persistence", "LateralMovement")
            techniques = @("T1078", "T1021")
            entityMappings = @(
                @{ entityType = "Host"; fieldMappings = @(@{ identifier = "HostName"; columnName = "ASSET_TAG" }) }
                @{ entityType = "Account"; fieldMappings = @(@{ identifier = "FullName"; columnName = "AssignedUser" }) }
                @{ entityType = "Mailbox"; fieldMappings = @(@{ identifier = "MailboxPrimaryAddress"; columnName = "AssignedEmail" }) }
            )
            customDetails = [ordered]@{
                AssetTag = "ASSET_TAG"
                AssetLabel = "ASSET_LABEL"
                IncidentCount = "IncidentCount"
                AssignedUser = "AssignedUser"
                Department = "Department"
                Location = "Location"
            }
            alertDetailsOverride = [ordered]@{
                alertDisplayNameFormat = "Repeated Incidents on Asset {{ASSET_TAG}}: {{IncidentCount}} in 7d"
                alertDescriptionFormat = "Asset {{ASSET_TAG}} has had {{IncidentCount}} security incidents in 7 days. Assigned to: {{AssignedUser}}."
            }
            incidentConfiguration = [ordered]@{
                createIncident = $true
                groupingConfiguration = [ordered]@{
                    enabled = $true
                    reopenClosedIncident = $true
                    lookbackDuration = "P7D"
                    matchingMethod = "Selected"
                    groupByCustomDetails = @("AssetTag")
                }
            }
        }
    },
    # Rule 5: Missing ITSM Ticket
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
        name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091')]"
        apiVersion = "2023-02-01"
        kind = "Scheduled"
        location = "[parameters('location')]"
        properties = [ordered]@{
            displayName = "EasyVista - Sentinel Incident Without ITSM Ticket"
            description = "Detects Sentinel incidents older than 1 hour that have no linked EasyVista ticket (no EV: tag). Ensures all security incidents are tracked in the ITSM workflow."
            severity = "Informational"
            enabled = $true
            query = $rule5_query
            queryFrequency = "PT1H"
            queryPeriod = "PT4H"
            triggerOperator = "GreaterThan"
            triggerThreshold = 0
            suppressionDuration = "PT5H"
            suppressionEnabled = $false
            tactics = @("Impact")
            customDetails = [ordered]@{
                IncidentId = "IncidentNumber"
                IncidentSeverity = "Severity"
                IncidentOwner = "Owner"
            }
            alertDetailsOverride = [ordered]@{
                alertDisplayNameFormat = "Missing ITSM Ticket: Sentinel Incident #{{IncidentNumber}} - {{IncidentTitle}}"
                alertDescriptionFormat = "Sentinel incident #{{IncidentNumber}} ({{Severity}}) has been open for over 1 hour without an EasyVista ticket. Owner: {{Owner}}"
            }
            incidentConfiguration = [ordered]@{
                createIncident = $true
                groupingConfiguration = [ordered]@{
                    enabled = $true
                    reopenClosedIncident = $false
                    lookbackDuration = "PT4H"
                    matchingMethod = "AnyAlert"
                }
            }
        }
    }
)

# ============================================================
# BUILD HUNTING QUERIES RESOURCES (as savedSearches)
# ============================================================

$huntingQueries = @(
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/savedSearches"
        name = "[concat(parameters('workspace'), '/EV-Hunt-ExpiredWarrantyAssets')]"
        apiVersion = "2020-08-01"
        properties = [ordered]@{
            category = "Hunting Queries"
            displayName = "EasyVista - Assets with Expired Warranty Linked to Incidents"
            query = $hunt1_query
            tags = @(
                @{ name = "description"; value = "Hunts for assets that have expired warranties and have been involved in security incidents. These assets may lack vendor support for patching." }
                @{ name = "tactics"; value = "Persistence" }
                @{ name = "techniques"; value = "T1190" }
            )
        }
    },
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/savedSearches"
        name = "[concat(parameters('workspace'), '/EV-Hunt-DormantAccountTickets')]"
        apiVersion = "2020-08-01"
        properties = [ordered]@{
            category = "Hunting Queries"
            displayName = "EasyVista - Dormant Accounts Creating Tickets"
            query = $hunt2_query
            tags = @(
                @{ name = "description"; value = "Hunts for employees whose contracts have ended but who still appear as requestors on recent tickets. May indicate compromised credentials." }
                @{ name = "tactics"; value = "InitialAccess,Persistence" }
                @{ name = "techniques"; value = "T1078" }
            )
        }
    },
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/savedSearches"
        name = "[concat(parameters('workspace'), '/EV-Hunt-OrphanedTickets')]"
        apiVersion = "2020-08-01"
        properties = [ordered]@{
            category = "Hunting Queries"
            displayName = "EasyVista - Orphaned Tickets Missing Sentinel Linkage"
            query = $hunt3_query
            tags = @(
                @{ name = "description"; value = "Hunts for EasyVista security tickets created via API that lack a valid EXTERNAL_REFERENCE. May indicate playbook failures." }
                @{ name = "tactics"; value = "Impact" }
            )
        }
    },
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/savedSearches"
        name = "[concat(parameters('workspace'), '/EV-Hunt-HighChurnTickets')]"
        apiVersion = "2020-08-01"
        properties = [ordered]@{
            category = "Hunting Queries"
            displayName = "EasyVista - High Churn Tickets (Rapid Status Changes)"
            query = $hunt4_query
            tags = @(
                @{ name = "description"; value = "Hunts for tickets with suspiciously rapid status changes, which may indicate automated loops, sync issues, or ticket manipulation." }
                @{ name = "tactics"; value = "DefenseEvasion" }
            )
        }
    },
    [ordered]@{
        type = "Microsoft.OperationalInsights/workspaces/savedSearches"
        name = "[concat(parameters('workspace'), '/EV-Hunt-CrossDeptCorrelation')]"
        apiVersion = "2020-08-01"
        properties = [ordered]@{
            category = "Hunting Queries"
            displayName = "EasyVista - Cross-Department Incident Correlation"
            query = $hunt5_query
            tags = @(
                @{ name = "description"; value = "Hunts for security incidents affecting multiple departments simultaneously. May indicate lateral movement or organization-wide campaigns." }
                @{ name = "tactics"; value = "LateralMovement,Impact" }
                @{ name = "techniques"; value = "T1021" }
            )
        }
    }
)

# ============================================================
# BUILD WORKBOOK RESOURCE
# ============================================================

$workbookResource = [ordered]@{
    condition = "[parameters('deployWorkbook')]"
    type = "microsoft.insights/workbooks"
    name = "[variables('workbookId')]"
    location = "[parameters('location')]"
    apiVersion = "2022-04-01"
    kind = "shared"
    properties = [ordered]@{
        displayName = "EasyVista ITSM - CISO Dashboard"
        serializedData = $workbookContent
        version = "1.0"
        sourceId = "[variables('workspaceResourceId')]"
        category = "sentinel"
    }
}

# ============================================================
# BUILD PLAYBOOK NESTED DEPLOYMENTS
# ============================================================

$playbookDeployments = @()

# Standard 4-param playbooks
$standardPlaybooks = @('EasyVista-CreateIncident', 'EasyVista-UpdateTicketStatus', 'EasyVista-GetTicketInfo', 'EasyVista-CloseTicket')
foreach ($name in $standardPlaybooks) {
    $playbookDeployments += [ordered]@{
        condition = "[parameters('deployPlaybooks')]"
        type = "Microsoft.Resources/deployments"
        name = "deploy-$name"
        apiVersion = "2022-09-01"
        properties = [ordered]@{
            mode = "Incremental"
            expressionEvaluationOptions = @{ scope = "Inner" }
            template = $playbookTemplates[$name]
            parameters = [ordered]@{
                PlaybookName = @{ value = $name }
                EasyVistaHost = @{ value = "[parameters('EasyVistaHost')]" }
                EasyVistaAccount = @{ value = "[parameters('EasyVistaAccount')]" }
                EasyVistaBearerToken = @{ value = "[parameters('EasyVistaBearerToken')]" }
            }
        }
    }
}

# TriggerResponseActions (extra MDE params)
$playbookDeployments += [ordered]@{
    condition = "[parameters('deployPlaybooks')]"
    type = "Microsoft.Resources/deployments"
    name = "deploy-EasyVista-TriggerResponseActions"
    apiVersion = "2022-09-01"
    properties = [ordered]@{
        mode = "Incremental"
        expressionEvaluationOptions = @{ scope = "Inner" }
        template = $playbookTemplates['EasyVista-TriggerResponseActions']
        parameters = [ordered]@{
            PlaybookName = @{ value = "EasyVista-TriggerResponseActions" }
            EasyVistaHost = @{ value = "[parameters('EasyVistaHost')]" }
            EasyVistaAccount = @{ value = "[parameters('EasyVistaAccount')]" }
            EasyVistaBearerToken = @{ value = "[parameters('EasyVistaBearerToken')]" }
            TenantId = @{ value = "[parameters('TenantId')]" }
            MDEClientId = @{ value = "[parameters('MDEClientId')]" }
            MDEClientSecret = @{ value = "[parameters('MDEClientSecret')]" }
        }
    }
}

# SyncStatusToSentinel (extra workspace params)
$playbookDeployments += [ordered]@{
    condition = "[parameters('deployPlaybooks')]"
    type = "Microsoft.Resources/deployments"
    name = "deploy-EasyVista-SyncStatusToSentinel"
    apiVersion = "2022-09-01"
    properties = [ordered]@{
        mode = "Incremental"
        expressionEvaluationOptions = @{ scope = "Inner" }
        template = $playbookTemplates['EasyVista-SyncStatusToSentinel']
        parameters = [ordered]@{
            PlaybookName = @{ value = "EasyVista-SyncStatusToSentinel" }
            EasyVistaHost = @{ value = "[parameters('EasyVistaHost')]" }
            EasyVistaAccount = @{ value = "[parameters('EasyVistaAccount')]" }
            EasyVistaBearerToken = @{ value = "[parameters('EasyVistaBearerToken')]" }
            SubscriptionId = @{ value = "[subscription().subscriptionId]" }
            ResourceGroupName = @{ value = "[resourceGroup().name]" }
            WorkspaceName = @{ value = "[parameters('workspace')]" }
        }
    }
}

# ============================================================
# BUILD CONTENT PACKAGE (Solution Metadata for Content Hub)
# ============================================================

$contentPackage = [ordered]@{
    type = "Microsoft.OperationalInsights/workspaces/providers/contentPackages"
    apiVersion = "2023-04-01-preview"
    name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/', variables('solutionId'))]"
    location = "[parameters('location')]"
    properties = [ordered]@{
        version = "1.0.0"
        kind = "Solution"
        contentSchemaVersion = "3.0.0"
        displayName = "EasyVista ITSM Integration"
        publisherDisplayName = "Security Engineering"
        descriptionHtml = "<p>Complete bidirectional integration between <b>Microsoft Sentinel</b> and <b>EasyVista ITSM</b>. Includes 6 automation playbooks, 5 analytic rules, 5 hunting queries, and a CISO dashboard workbook.</p>"
        contentKind = "Solution"
        contentProductId = "[concat(variables('solutionId'),'-sl-',uniqueString(variables('solutionId')))]"
        id = "[concat(variables('solutionId'),'-sl-',uniqueString(variables('solutionId')))]"
        contentId = "[variables('solutionId')]"
        parentId = "[variables('solutionId')]"
        source = [ordered]@{
            kind = "Solution"
            name = "EasyVista ITSM Integration"
            sourceId = "[variables('solutionId')]"
        }
        author = @{ name = "Security Engineering" }
        support = [ordered]@{
            tier = "Community"
            name = "Security Engineering"
        }
        dependencies = [ordered]@{
            operator = "AND"
            criteria = @(
                @{ kind = "DataConnector"; contentId = "EasyVistaITSM"; version = "1.0.0" }
                @{ kind = "AnalyticsRule"; contentId = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"; version = "1.0.0" }
                @{ kind = "AnalyticsRule"; contentId = "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"; version = "1.0.0" }
                @{ kind = "AnalyticsRule"; contentId = "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f"; version = "1.0.0" }
                @{ kind = "AnalyticsRule"; contentId = "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80"; version = "1.0.0" }
                @{ kind = "AnalyticsRule"; contentId = "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091"; version = "1.0.0" }
            )
        }
        firstPublishDate = "2026-04-16"
        providers = @("EasyVista")
        categories = [ordered]@{
            domains = @("Security - Automation (SOAR)", "IT Operations")
            verticals = @()
        }
    }
}

# ============================================================
# ASSEMBLE THE MAIN TEMPLATE
# ============================================================

$template = [ordered]@{
    '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    contentVersion = "1.0.0.0"
    metadata = [ordered]@{
        title = "EasyVista ITSM Integration for Microsoft Sentinel"
        description = "Complete bidirectional integration between Microsoft Sentinel and EasyVista ITSM. Deploys 6 playbooks, 5 analytic rules, 5 hunting queries, a CISO dashboard workbook, and Content Hub solution metadata."
        prerequisites = "1) Microsoft Sentinel workspace; 2) EasyVista ITSM API credentials (Bearer token); 3) Optional: Azure AD App Registration for MDE response actions"
        version = "1.0.0"
        author = @{ name = "Security Engineering" }
    }
    parameters = [ordered]@{
        workspace = [ordered]@{
            type = "string"
            metadata = @{ description = "Log Analytics workspace name where Microsoft Sentinel is deployed" }
        }
        location = [ordered]@{
            type = "string"
            defaultValue = "[resourceGroup().location]"
            metadata = @{ description = "Azure region for all deployed resources" }
        }
        EasyVistaHost = [ordered]@{
            type = "string"
            defaultValue = "CONFIGURE-AFTER-DEPLOYMENT"
            metadata = @{ description = "EasyVista server hostname (e.g. your-company.easyvista.com). Can be configured later in each Logic App." }
        }
        EasyVistaAccount = [ordered]@{
            type = "string"
            defaultValue = "CONFIGURE-AFTER-DEPLOYMENT"
            metadata = @{ description = "EasyVista account identifier used in API paths. Can be configured later in each Logic App." }
        }
        EasyVistaBearerToken = [ordered]@{
            type = "securestring"
            defaultValue = "CONFIGURE-AFTER-DEPLOYMENT"
            metadata = @{ description = "EasyVista REST API Bearer token for authentication. Can be configured later in each Logic App." }
        }
        deployPlaybooks = [ordered]@{
            type = "bool"
            defaultValue = $true
            metadata = @{ description = "Set to true to deploy all 6 Logic App playbooks for bidirectional integration" }
        }
        deployWorkbook = [ordered]@{
            type = "bool"
            defaultValue = $true
            metadata = @{ description = "Set to true to deploy the CISO Dashboard workbook" }
        }
        TenantId = [ordered]@{
            type = "string"
            defaultValue = "[subscription().tenantId]"
            metadata = @{ description = "Azure AD Tenant ID (required for TriggerResponseActions playbook - MDE API calls)" }
        }
        MDEClientId = [ordered]@{
            type = "string"
            defaultValue = ""
            metadata = @{ description = "Azure AD App Registration Client ID for MDE API access (optional - for TriggerResponseActions)" }
        }
        MDEClientSecret = [ordered]@{
            type = "securestring"
            defaultValue = ""
            metadata = @{ description = "Azure AD App Registration Client Secret for MDE API (optional - for TriggerResponseActions)" }
        }
    }
    variables = [ordered]@{
        solutionId = "easyvista-itsm-sentinel"
        solutionVersion = "1.0.0"
        workspaceResourceId = "[resourceId('microsoft.OperationalInsights/Workspaces', parameters('workspace'))]"
        workbookId = "[guid('EasyVista-CISO-Dashboard', parameters('workspace'), resourceGroup().id)]"
    }
    resources = @()
}

# Assemble all resources
$allResources = @()
$allResources += $analyticRules
$allResources += $huntingQueries
$allResources += $workbookResource
$allResources += $playbookDeployments
$allResources += $contentPackage

$template.resources = $allResources

# ============================================================
# OUTPUT
# ============================================================

$outputPath = Join-Path $scriptDir "mainTemplate.json"
$json = $template | ConvertTo-Json -Depth 100
$json | Out-File $outputPath -Encoding UTF8 -Force

Write-Host ""
Write-Host "SUCCESS: Generated $outputPath" -ForegroundColor Green
Write-Host "  - 5 Analytic Rules" -ForegroundColor White
Write-Host "  - 5 Hunting Queries" -ForegroundColor White
Write-Host "  - 1 CISO Dashboard Workbook" -ForegroundColor White
Write-Host "  - 6 Playbook Nested Deployments" -ForegroundColor White
Write-Host "  - 1 Content Hub Solution Package" -ForegroundColor White
Write-Host ""
Write-Host "Total resources: $($allResources.Count)" -ForegroundColor Cyan
