# Build mainTemplate.json for the IntuneLogs Sentinel solution.
# Parses every YAML under Analytic Rules/ and Hunting Queries/, inlines the
# workbook JSON, and appends the data connectors + DCE/DCR/custom tables.
#
# Run from the solution root:  pwsh -File .\Package\build-maintemplate.ps1

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
if (-not $OutFile) { $OutFile = Join-Path $Root 'Package\mainTemplate.json' }

if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
    Write-Host "Installing powershell-yaml module..."
    Install-Module powershell-yaml -Scope CurrentUser -Force -AllowClobber
}
Import-Module powershell-yaml -ErrorAction Stop

function Read-Yaml($path) {
    return (Get-Content -Raw -LiteralPath $path | ConvertFrom-Yaml)
}

# ----- collect rule + hunt YAMLs --------------------------------------------------
$rulesDir = Join-Path $Root 'Analytic Rules'
$huntsDir = Join-Path $Root 'Hunting Queries'
$workbookFile = Join-Path $Root 'Workbooks\IntuneSecurity-CIO-CISO.json'

$ruleFiles = Get-ChildItem -LiteralPath $rulesDir -Filter *.yaml | Sort-Object Name
$huntFiles = Get-ChildItem -LiteralPath $huntsDir -Filter *.yaml | Sort-Object Name

Write-Host "Found $($ruleFiles.Count) analytic rules and $($huntFiles.Count) hunting queries."

# ----- helpers --------------------------------------------------------------------
function ConvertTo-IsoDuration([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return 'PT1H' }
    $v = $v.Trim()
    if ($v -match '^P') { return $v.ToUpper() }               # already ISO (P1D, PT1H)
    $u = $v.ToUpper()
    if ($u -match '^(\d+)([DMHS])$') {
        $n = $Matches[1]; $unit = $Matches[2]
        if ($unit -eq 'D') { return "P${n}D" }                # days: no T
        return "PT${n}${unit}"                                # hours / minutes / seconds
    }
    return $u  # fall back
}

$triggerMap = @{ 'gt' = 'GreaterThan'; 'lt' = 'LessThan'; 'eq' = 'Equal'; 'ne' = 'NotEqual' }

function New-AlertRule($y) {
    $freq   = ConvertTo-IsoDuration ([string]$y.queryFrequency)
    $period = ConvertTo-IsoDuration ([string]$y.queryPeriod)

    $op = [string]$y.triggerOperator
    if ($triggerMap.ContainsKey($op)) { $op = $triggerMap[$op] }

    $tactics  = @(); if ($y.tactics)           { $tactics  = @($y.tactics) }
    $techs    = @()
    if ($y.relevantTechniques) {
        # Sentinel alertRules.techniques accepts T#### only; strip sub-technique suffix (.NNN).
        $techs = @($y.relevantTechniques | ForEach-Object {
            ([string]$_ -replace '\.\d+$','')
        } | Sort-Object -Unique)
    }
    $entities = @(); if ($y.entityMappings)    { $entities = @($y.entityMappings) }

    return [ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
        apiVersion = '2022-11-01'
        name       = "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', '$($y.id)')]"
        kind       = 'Scheduled'
        properties = [ordered]@{
            displayName         = [string]$y.name
            description         = [string]$y.description
            severity            = [string]$y.severity
            enabled             = $true
            query               = [string]$y.query
            queryFrequency      = $freq
            queryPeriod         = $period
            triggerOperator     = $op
            triggerThreshold    = [int]$y.triggerThreshold
            suppressionDuration = 'PT1H'
            suppressionEnabled  = $false
            tactics             = $tactics
            techniques          = $techs
            entityMappings      = $entities
        }
    }
}

function New-SavedSearch($y) {
    $tactics = @(); if ($y.tactics) { $tactics = @($y.tactics) }
    # savedSearch tag value max-length 255; description is stored in first line of query instead.
    $tags = @(
        [ordered]@{ name = 'tactics';   value = ($tactics -join ',') }
        [ordered]@{ name = 'createdBy'; value = 'IntuneLogs Solution' }
    )
    return [ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/savedSearches'
        apiVersion = '2020-08-01'
        name       = "[concat(parameters('workspace'), '/$($y.id)')]"
        properties = [ordered]@{
            category     = 'Hunting Queries - IntuneLogs'
            displayName  = [string]$y.name
            query        = [string]$y.query
            version      = 2
            tags         = $tags
        }
    }
}

# ----- build resource list --------------------------------------------------------
$resources = [System.Collections.Generic.List[object]]::new()

foreach ($f in $ruleFiles) {
    $y = Read-Yaml $f.FullName
    $resources.Add((New-AlertRule $y))
}
foreach ($f in $huntFiles) {
    $y = Read-Yaml $f.FullName
    $resources.Add((New-SavedSearch $y))
}

# ----- workbook (inline serializedData) -------------------------------------------
$wbJson = Get-Content -Raw -LiteralPath $workbookFile | ConvertFrom-Json -Depth 100
$wbSerialized = $wbJson | ConvertTo-Json -Depth 100 -Compress

$resources.Add([ordered]@{
    type       = 'Microsoft.Insights/workbooks'
    apiVersion = '2022-04-01'
    name       = "[guid(resourceGroup().id, 'IntuneSecurity-CIO-CISO')]"
    location   = "[parameters('location')]"
    kind       = 'shared'
    properties = [ordered]@{
        displayName    = 'Intune Security - CIO / CISO KPIs'
        serializedData = $wbSerialized
        version        = '1.0'
        sourceId       = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"
        category       = 'sentinel'
    }
})

# ----- native diagnostic-settings connector (GenericUI tile) ----------------------
$diagConnector = Get-Content -Raw -LiteralPath (Join-Path $Root 'Data Connectors\IntuneLogsDiagnosticSettings_connector.json') |
    ConvertFrom-Json -Depth 50
$resources.Add([ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/dataConnectors'
    apiVersion = '2024-01-01-preview'
    name       = "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/IntuneLogsDiagnosticSettings')]"
    kind       = 'GenericUI'
    properties = [ordered]@{
        connectorUiConfig = $diagConnector
    }
})

# ----- DCE + custom tables + DCR (for Graph CCF) ----------------------------------
# $dceName/$dcrName used inside resource "name" must be ARM expressions.
# $dceExpr/$dcrExpr are the bare concat() body we reuse inside resourceId().
$dceName = "[concat('dce-intune-graph-', uniqueString(resourceGroup().id))]"
$dcrName = "[concat('dcr-intune-graph-', uniqueString(resourceGroup().id))]"
$dceExpr = "concat('dce-intune-graph-', uniqueString(resourceGroup().id))"
$dcrExpr = "concat('dcr-intune-graph-', uniqueString(resourceGroup().id))"

$tableAudit = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/tables'
    apiVersion = '2022-10-01'
    name       = "[concat(parameters('workspace'), '/IntuneGraph_AuditEvents_CL')]"
    properties = [ordered]@{
        schema = [ordered]@{
            name    = 'IntuneGraph_AuditEvents_CL'
            columns = @(
                @{ name='TimeGenerated';           type='datetime' },
                @{ name='id_s';                    type='string'   },
                @{ name='displayName_s';           type='string'   },
                @{ name='componentName_s';         type='string'   },
                @{ name='actor_s';                 type='dynamic'  },
                @{ name='activity_s';              type='string'   },
                @{ name='activityDateTime_t';      type='datetime' },
                @{ name='activityType_s';          type='string'   },
                @{ name='activityOperationType_s'; type='string'   },
                @{ name='activityResult_s';        type='string'   },
                @{ name='correlationId_g';         type='string'   },
                @{ name='category_s';              type='string'   },
                @{ name='userPrincipalName_s';     type='string'   },
                @{ name='resources_s';             type='dynamic'  }
            )
        }
        retentionInDays = 90
    }
}
$tableDevices = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/tables'
    apiVersion = '2022-10-01'
    name       = "[concat(parameters('workspace'), '/IntuneGraph_ManagedDevices_CL')]"
    properties = [ordered]@{
        schema = [ordered]@{
            name    = 'IntuneGraph_ManagedDevices_CL'
            columns = @(
                @{ name='TimeGenerated';            type='datetime' },
                @{ name='id_s';                     type='string'   },
                @{ name='deviceName_s';             type='string'   },
                @{ name='userPrincipalName_s';      type='string'   },
                @{ name='operatingSystem_s';        type='string'   },
                @{ name='osVersion_s';              type='string'   },
                @{ name='complianceState_s';        type='string'   },
                @{ name='ownerType_s';              type='string'   },
                @{ name='deviceRegistrationState_s';type='string'   },
                @{ name='managementState_s';        type='string'   },
                @{ name='joinType_s';               type='string'   },
                @{ name='lastSyncDateTime_s';       type='string'   },
                @{ name='enrolledDateTime_s';       type='string'   },
                @{ name='serialNumber_s';           type='string'   },
                @{ name='model_s';                  type='string'   },
                @{ name='manufacturer_s';           type='string'   }
            )
        }
        retentionInDays = 90
    }
}
$dce = [ordered]@{
    type       = 'Microsoft.Insights/dataCollectionEndpoints'
    apiVersion = '2022-06-01'
    name       = $dceName
    location   = "[parameters('location')]"
    properties = [ordered]@{
        networkAcls = [ordered]@{ publicNetworkAccess = 'Enabled' }
    }
}

$auditTransform = 'source | extend TimeGenerated = iff(isnull(todatetime(activityDateTime)), now(), todatetime(activityDateTime)) | project TimeGenerated, id_s=id, displayName_s=displayName, componentName_s=componentName, actor_s=actor, activity_s=activity, activityDateTime_t=todatetime(activityDateTime), activityType_s=activityType, activityOperationType_s=activityOperationType, activityResult_s=activityResult, correlationId_g=correlationId, category_s=category, userPrincipalName_s=userPrincipalName, resources_s=resources'
$devTransform   = 'source | extend TimeGenerated = now() | project TimeGenerated, id_s=id, deviceName_s=deviceName, userPrincipalName_s=userPrincipalName, operatingSystem_s=operatingSystem, osVersion_s=osVersion, complianceState_s=complianceState, ownerType_s=ownerType, deviceRegistrationState_s=deviceRegistrationState, managementState_s=managementState, joinType_s=joinType, lastSyncDateTime_s=lastSyncDateTime, enrolledDateTime_s=enrolledDateTime, serialNumber_s=serialNumber, model_s=model, manufacturer_s=manufacturer'

$dcr = [ordered]@{
    type       = 'Microsoft.Insights/dataCollectionRules'
    apiVersion = '2022-06-01'
    name       = $dcrName
    location   = "[parameters('location')]"
    dependsOn  = @(
        "[resourceId('Microsoft.Insights/dataCollectionEndpoints', $dceExpr)]",
        "[resourceId('Microsoft.OperationalInsights/workspaces/tables', parameters('workspace'), 'IntuneGraph_AuditEvents_CL')]",
        "[resourceId('Microsoft.OperationalInsights/workspaces/tables', parameters('workspace'), 'IntuneGraph_ManagedDevices_CL')]"
    )
    properties = [ordered]@{
        dataCollectionEndpointId = "[resourceId('Microsoft.Insights/dataCollectionEndpoints', $dceExpr)]"
        streamDeclarations = [ordered]@{
            'Custom-IntuneGraph_AuditEvents_CL' = [ordered]@{
                columns = @(
                    @{ name='TimeGenerated';         type='datetime' },
                    @{ name='id';                    type='string'   },
                    @{ name='displayName';           type='string'   },
                    @{ name='componentName';         type='string'   },
                    @{ name='actor';                 type='dynamic'  },
                    @{ name='activity';              type='string'   },
                    @{ name='activityDateTime';      type='datetime' },
                    @{ name='activityType';          type='string'   },
                    @{ name='activityOperationType'; type='string'   },
                    @{ name='activityResult';        type='string'   },
                    @{ name='correlationId';         type='string'   },
                    @{ name='category';              type='string'   },
                    @{ name='userPrincipalName';     type='string'   },
                    @{ name='resources';             type='dynamic'  }
                )
            }
            'Custom-IntuneGraph_ManagedDevices_CL' = [ordered]@{
                columns = @(
                    @{ name='TimeGenerated';          type='datetime' },
                    @{ name='id';                     type='string'   },
                    @{ name='deviceName';             type='string'   },
                    @{ name='userPrincipalName';      type='string'   },
                    @{ name='operatingSystem';        type='string'   },
                    @{ name='osVersion';              type='string'   },
                    @{ name='complianceState';        type='string'   },
                    @{ name='ownerType';              type='string'   },
                    @{ name='deviceRegistrationState';type='string'   },
                    @{ name='managementState';        type='string'   },
                    @{ name='joinType';               type='string'   },
                    @{ name='lastSyncDateTime';       type='string'   },
                    @{ name='enrolledDateTime';       type='string'   },
                    @{ name='serialNumber';           type='string'   },
                    @{ name='model';                  type='string'   },
                    @{ name='manufacturer';           type='string'   }
                )
            }
        }
        destinations = [ordered]@{
            logAnalytics = @(
                [ordered]@{
                    workspaceResourceId = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"
                    name = 'sentinelWorkspace'
                }
            )
        }
        dataFlows = @(
            [ordered]@{
                streams        = @('Custom-IntuneGraph_AuditEvents_CL')
                destinations   = @('sentinelWorkspace')
                transformKql   = $auditTransform
                outputStream   = 'Custom-IntuneGraph_AuditEvents_CL'
            },
            [ordered]@{
                streams        = @('Custom-IntuneGraph_ManagedDevices_CL')
                destinations   = @('sentinelWorkspace')
                transformKql   = $devTransform
                outputStream   = 'Custom-IntuneGraph_ManagedDevices_CL'
            }
        )
    }
}

$resources.Add($tableAudit)
$resources.Add($tableDevices)
$resources.Add($dce)
$resources.Add($dcr)

# ----- CCF Graph connector (dataConnectorDefinitions only) ------------------------
# 2024-01-01-preview CCF model splits CCF into two resources:
#   1. Microsoft.SecurityInsights/dataConnectorDefinitions — the tile + UI shown
#      in the Content Hub / Data Connectors gallery. Contains connectorUiConfig.
#   2. Microsoft.SecurityInsights/dataConnectors kind RestApiPoller — the
#      connected instance holding auth + dcrConfig. Sentinel creates this
#      automatically when a user clicks Connect in the portal and enters
#      tenantId / clientId / clientSecret. Deploying it via ARM with literal
#      credential placeholders fails the synchronous connectivity check, so we
#      ship only the definition. DCE / DCR / custom tables are already deployed
#      (above); the portal Connect button will wire them together.
$ccfRaw = Get-Content -Raw -LiteralPath (Join-Path $Root 'Data Connectors\IntuneGraphAPI_connector.json') |
    ConvertFrom-Json -Depth 50

$connectorDefinitionName = 'IntuneGraphAPIDefinition'

$resources.Add([ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/dataConnectorDefinitions'
    apiVersion = '2024-01-01-preview'
    name       = "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', '$connectorDefinitionName')]"
    kind       = 'Customizable'
    properties = [ordered]@{
        connectorUiConfig = $ccfRaw.properties.connectorUiConfig
    }
})

# ----- assemble ARM template ------------------------------------------------------
$template = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    parameters     = [ordered]@{
        workspace = [ordered]@{ type='string'; metadata=@{ description='Sentinel-enabled Log Analytics workspace name.' } }
        location  = [ordered]@{ type='string'; defaultValue="[resourceGroup().location]" }
    }
    resources      = $resources
    outputs        = [ordered]@{
        analyticRulesDeployed    = [ordered]@{ type='int'; value=$ruleFiles.Count }
        huntingQueriesDeployed   = [ordered]@{ type='int'; value=$huntFiles.Count }
    }
}

$json = $template | ConvertTo-Json -Depth 100
$json | Set-Content -LiteralPath $OutFile -Encoding UTF8

Write-Host ""
Write-Host "Wrote $OutFile"
Write-Host "  Analytic rules : $($ruleFiles.Count)"
Write-Host "  Hunting queries: $($huntFiles.Count)"
Write-Host "  Total resources: $($resources.Count)"
