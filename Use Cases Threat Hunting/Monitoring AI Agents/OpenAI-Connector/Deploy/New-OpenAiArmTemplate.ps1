<#
.SYNOPSIS
    Generate the OpenAI-connector Sentinel ARM template from the YAML source files.

.DESCRIPTION
    Reads all analytic rules under ..\AnalyticalRules\ and hunting queries
    under ..\HuntingQueries\, then writes a single ARM template
    (azuredeploy.json) plus a parameters file (azuredeploy.parameters.json)
    next to this script.

    Hunting queries are deployed as Microsoft.OperationalInsights/workspaces/
    savedSearches with category "Hunting Queries" so they appear in the
    Sentinel Hunting blade.

    Analytic rules are deployed as Microsoft.SecurityInsights/alertRules of
    kind Scheduled. Their "enabled" flag is bound to the deployment
    parameter "enableAnalyticRules" so the operator can deploy them in a
    disabled state from the portal "Deploy a custom template" wizard.

    These detections were ported from the sibling Microsoft 365 Copilot
    bundle and retargeted at the Sentinel OpenAI solution tables
    (OpenAIAuditLogs / ASimAgentEventLogs).

    Requires the powershell-yaml module. Install with:
        Install-Module powershell-yaml -Scope CurrentUser

.NOTES
    Agent365/OpenAI-Connector/Deploy/New-OpenAiArmTemplate.ps1
    Created on 02/06/2026.
#>

[CmdletBinding()]
param(
    [string] $SourceRoot   = (Join-Path $PSScriptRoot '..'),
    [string] $OutputPath   = (Join-Path $PSScriptRoot 'azuredeploy.json'),
    [string] $ParamsPath   = (Join-Path $PSScriptRoot 'azuredeploy.parameters.json')
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

# ----- Build analytic-rule resources -----
$analyticDir   = Join-Path $SourceRoot 'AnalyticalRules'
$huntingDir    = Join-Path $SourceRoot 'HuntingQueries'

$resources = New-Object System.Collections.Generic.List[object]

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
        displayName            = [string]$y.name
        description            = [string]$y.description
        severity               = [string]$y.severity
        enabled                = "[parameters('enableAnalyticRules')]"
        query                  = [string]$y.query
        queryFrequency         = [string]$y.queryFrequency
        queryPeriod            = [string]$y.queryPeriod
        triggerOperator        = (ConvertTo-TriggerOperator $y.triggerOperator)
        triggerThreshold       = [int]$y.triggerThreshold
        suppressionDuration    = 'PT1H'
        suppressionEnabled     = $false
        tactics                = @($y.tactics)
        techniques             = @($y.relevantTechniques)
        alertRuleTemplateName  = $null
        eventGroupingSettings  = @{ aggregationKind = [string]$y.eventGroupingSettings.aggregationKind }
        incidentConfiguration  = @{
            createIncident         = [bool]$y.incidentConfiguration.createIncident
            groupingConfiguration  = $grouping
        }
        entityMappings         = $entityMappings
    }

    $resources.Add([ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
        apiVersion = '2023-12-01-preview'
        name       = "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', '$($y.id)')]"
        kind       = 'Scheduled'
        properties = $props
    })
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

# ----- Assemble the ARM template -----
$template = [ordered]@{
    '$schema'        = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion   = '1.0.0.0'
    metadata         = @{
        description = 'OpenAI connector - Microsoft Sentinel analytic rules and hunting queries (ported from the Microsoft 365 Copilot bundle).'
        author      = 'Sentinel-As-Code / Agent365 OpenAI bundle'
    }
    parameters       = [ordered]@{
        workspaceName        = @{
            type     = 'string'
            metadata = @{ description = 'Name of the Log Analytics workspace where Microsoft Sentinel is enabled.' }
        }
        enableAnalyticRules  = @{
            type         = 'bool'
            defaultValue = $true
            metadata     = @{ description = 'Set to false to deploy the scheduled analytic rules in a disabled state. Hunting queries are always deployed.' }
        }
    }
    variables        = @{}
    resources        = $resources.ToArray()
    outputs          = [ordered]@{
        analyticRuleCount = @{
            type  = 'int'
            value = ($resources | Where-Object { $_.type -like '*alertRules' }).Count
        }
        huntingQueryCount = @{
            type  = 'int'
            value = ($resources | Where-Object { $_.type -like '*savedSearches' }).Count
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
    }
}
$paramsJson = $params | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($ParamsPath, $paramsJson, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $ParamsPath" -ForegroundColor Green
