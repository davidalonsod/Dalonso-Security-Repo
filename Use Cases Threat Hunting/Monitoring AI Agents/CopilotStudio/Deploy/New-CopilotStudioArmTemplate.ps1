<#
.SYNOPSIS
    Generate the Copilot Studio / Application Insights Sentinel ARM
    template from the YAML analytic-rule and hunting-query source files.

.DESCRIPTION
    Reads all analytic rules under ..\AnalyticalRules\ and hunting queries
    under ..\HuntingQueries\, then writes a single ARM template
    (azuredeploy.json) plus a parameters file (azuredeploy.parameters.json)
    next to this script.

    Both content types read the real Copilot Studio runtime trace shape
    that lands in Application Insights and is exported to the Sentinel
    workspace:
      - Bot turns in the AppEvents table (Name == "BotMessageReceived" /
        "BotMessageSend") with the property bag in the dynamic Properties
        column (conversationId, channelId, text, locale, DesignMode).
      - Connector / action calls in the AppDependencies table
        (DependencyType == "Connector", AppRoleName == "Microsoft Copilot
        Studio") with Name / Target / Success / DurationMs.

    Analytic rules are deployed as Microsoft.SecurityInsights/alertRules of
    kind Scheduled. Their "enabled" flag is bound to the deployment
    parameter "enableAnalyticRules". Hunting queries are deployed as
    Microsoft.OperationalInsights/workspaces/savedSearches with category
    "Hunting Queries" so they appear in the Sentinel Hunting blade.

    Any watchlist under ..\Watchlists\<alias>\ (watchlist.json + data.csv)
    is deployed as a Microsoft.SecurityInsights/watchlists resource with
    the CSV embedded in rawContent. Each watchlist resource carries an ARM
    "condition" bound to the deployment parameter "enableWatchlist", so the
    operator can choose whether to deploy the watchlists alongside the
    rules (default true).

    Requires the powershell-yaml module. Install with:
        Install-Module powershell-yaml -Scope CurrentUser

.NOTES
    Agent365/CopilotStudio-AppInsights/Deploy/New-CopilotStudioArmTemplate.ps1
    Created on 04/06/2026.
#>

[CmdletBinding()]
param(
    [string] $SourceRoot = (Join-Path $PSScriptRoot '..'),
    [string] $OutputPath = (Join-Path $PSScriptRoot 'azuredeploy.json'),
    [string] $ParamsPath = (Join-Path $PSScriptRoot 'azuredeploy.parameters.json')
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable powershell-yaml)) {
    Write-Host 'Installing powershell-yaml ...' -ForegroundColor Yellow
    Install-Module powershell-yaml -Scope CurrentUser -Force -AllowClobber | Out-Null
}
Import-Module powershell-yaml -ErrorAction Stop

function ConvertTo-TriggerOperator {
    param([string] $op)
    switch ($op) {
        'gt' { 'GreaterThan' }
        'lt' { 'LessThan' }
        'eq' { 'Equal' }
        'ne' { 'NotEqual' }
        default { 'GreaterThan' }
    }
}

$analyticDir  = Join-Path $SourceRoot 'AnalyticalRules'
$huntingDir   = Join-Path $SourceRoot 'HuntingQueries'
$watchlistDir = Join-Path $SourceRoot 'Watchlists'

$resources = New-Object System.Collections.Generic.List[object]

# ----- Build analytic-rule resources -----
if (Test-Path $analyticDir) {
    Get-ChildItem -Path $analyticDir -Filter *.yaml | ForEach-Object {
        $y = ConvertFrom-Yaml ((Get-Content $_.FullName -Raw))

        $entityMappings = @()
        foreach ($em in @($y.entityMappings)) {
            if (-not $em) { continue }
            $entityMappings += @{
                entityType    = [string]$em.entityType
                fieldMappings = @(
                    foreach ($fm in $em.fieldMappings) {
                        @{ identifier = [string]$fm.identifier; columnName = [string]$fm.columnName }
                    }
                )
            }
        }

        $grouping = $null
        if ($y.incidentConfiguration -and $y.incidentConfiguration.groupingConfiguration) {
            $g = $y.incidentConfiguration.groupingConfiguration
            $grouping = @{
                enabled              = [bool]$g.enabled
                reopenClosedIncident = [bool]$g.reopenClosedIncident
                lookbackDuration     = [string]$g.lookbackDuration
                matchingMethod       = [string]$g.matchingMethod
                groupByEntities      = @($g.groupByEntities)
                groupByAlertDetails  = @($g.groupByAlertDetails)
                groupByCustomDetails = @($g.groupByCustomDetails)
            }
        }

        $props = [ordered]@{
            displayName           = [string]$y.name
            description           = [string]$y.description
            severity              = [string]$y.severity
            enabled               = "[parameters('enableAnalyticRules')]"
            query                 = [string]$y.query
            queryFrequency        = [string]$y.queryFrequency
            queryPeriod           = [string]$y.queryPeriod
            triggerOperator       = (ConvertTo-TriggerOperator $y.triggerOperator)
            triggerThreshold      = [int]$y.triggerThreshold
            suppressionDuration   = 'PT1H'
            suppressionEnabled    = $false
            tactics               = @($y.tactics)
            techniques            = @($y.relevantTechniques)
            alertRuleTemplateName = $null
            eventGroupingSettings = @{ aggregationKind = [string]$y.eventGroupingSettings.aggregationKind }
            incidentConfiguration = @{
                createIncident        = [bool]$y.incidentConfiguration.createIncident
                groupingConfiguration = $grouping
            }
            entityMappings        = $entityMappings
        }

        $resources.Add([ordered]@{
                type       = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
                apiVersion = '2023-12-01-preview'
                name       = "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', '$($y.id)')]"
                kind       = 'Scheduled'
                properties = $props
            })
    }
}

# ----- Build hunting-query resources -----
Get-ChildItem -Path $huntingDir -Filter *.yaml | ForEach-Object {
    $y = ConvertFrom-Yaml ((Get-Content $_.FullName -Raw))

    $tactics    = (@($y.tactics)    -join ',')
    $techniques = (@($y.techniques) -join ',')

    # Azure tag values are capped at 256 chars. Collapse whitespace and
    # truncate the description used as a tag so the deployment validates.
    $descTag = ([string]$y.description) -replace '\s+', ' '
    $descTag = $descTag.Trim()
    if ($descTag.Length -gt 255) {
        $descTag = $descTag.Substring(0, 252) + '...'
    }

    $resources.Add([ordered]@{
            type       = 'Microsoft.OperationalInsights/workspaces/savedSearches'
            apiVersion = '2022-10-01'
            name       = "[concat(parameters('workspaceName'), '/$($y.id)')]"
            properties = [ordered]@{
                category    = 'Hunting Queries'
                displayName = [string]$y.name
                query       = [string]$y.query
                version     = 2
                tags        = @(
                    @{ name = 'description'; value = $descTag }
                    @{ name = 'tactics';     value = $tactics }
                    @{ name = 'techniques';  value = $techniques }
                )
            }
        })
}

# ----- Build watchlist resources (optional via enableWatchlist) -----
if (Test-Path $watchlistDir) {
    Get-ChildItem -Path $watchlistDir -Directory | ForEach-Object {
        $defPath = Join-Path $_.FullName 'watchlist.json'
        $csvPath = Join-Path $_.FullName 'data.csv'
        if (-not (Test-Path $defPath) -or -not (Test-Path $csvPath)) { return }

        $def = Get-Content $defPath -Raw | ConvertFrom-Json
        $csv = (Get-Content $csvPath -Raw) -replace "`r`n", "`n"
        $alias = [string]$def.watchlistAlias

        $resources.Add([ordered]@{
                type       = 'Microsoft.OperationalInsights/workspaces/providers/watchlists'
                apiVersion = '2023-12-01-preview'
                name       = "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', '$alias')]"
                condition  = "[parameters('enableWatchlist')]"
                properties = [ordered]@{
                    displayName         = [string]$def.displayName
                    description         = [string]$def.description
                    provider            = [string]$def.provider
                    source              = 'Local file'
                    itemsSearchKey      = [string]$def.itemsSearchKey
                    contentType         = 'text/csv'
                    numberOfLinesToSkip = 0
                    rawContent          = $csv
                }
            })
    }
}

# ----- Assemble the ARM template -----
$template = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    metadata       = @{
        description = 'Copilot Studio / Application Insights - Microsoft Sentinel analytic rules and hunting queries (read AppEvents / AppDependencies / Properties for BotMessageReceived/Send and connector calls).'
        author      = 'Sentinel-As-Code / Agent365 CopilotStudio-AppInsights bundle'
    }
    parameters     = [ordered]@{
        workspaceName       = @{
            type     = 'string'
            metadata = @{ description = 'Name of the Log Analytics workspace where Microsoft Sentinel is enabled and the Copilot Studio Application Insights telemetry is exported (e.g. SentinelPurview).' }
        }
        enableAnalyticRules = @{
            type         = 'bool'
            defaultValue = $true
            metadata     = @{ description = 'Set to false to deploy the scheduled analytic rules in a disabled state. Hunting queries are always deployed.' }
        }
        enableWatchlist     = @{
            type         = 'bool'
            defaultValue = $true
            metadata     = @{ description = 'Set to false to skip deploying the CopilotStudioTrustedConnectors / CopilotStudioAgentMap watchlists (e.g. if you manage them separately). The untrusted-connector hunt depends on the trusted-connectors watchlist.' }
        }
    }
    variables      = @{}
    resources      = $resources.ToArray()
    outputs        = [ordered]@{
        analyticRuleCount    = @{
            type  = 'int'
            value = ($resources | Where-Object { $_.type -like '*alertRules' }).Count
        }
        huntingQueryCount    = @{
            type  = 'int'
            value = ($resources | Where-Object { $_.type -like '*savedSearches' }).Count
        }
        watchlistCount       = @{
            type  = 'int'
            value = ($resources | Where-Object { $_.type -like '*watchlists' }).Count
        }
        analyticRulesEnabled = @{
            type  = 'bool'
            value = "[parameters('enableAnalyticRules')]"
        }
    }
}

$json = $template | ConvertTo-Json -Depth 32
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $OutputPath ($($resources.Count) resources)" -ForegroundColor Green

# ----- Parameters file -----
$params = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters     = [ordered]@{
        workspaceName       = @{ value = '<your-sentinel-workspace-name>' }
        enableAnalyticRules = @{ value = $true }
        enableWatchlist     = @{ value = $true }
    }
}
$paramsJson = $params | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($ParamsPath, $paramsJson, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $ParamsPath" -ForegroundColor Green
