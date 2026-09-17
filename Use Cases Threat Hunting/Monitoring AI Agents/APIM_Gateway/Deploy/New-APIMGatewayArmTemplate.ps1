[CmdletBinding()]
param(
    [string] $SourceRoot = (Join-Path $PSScriptRoot '..'),
    [string] $OutputPath = (Join-Path $PSScriptRoot 'azuredeploy.json'),
    [string] $ParamsPath = (Join-Path $PSScriptRoot 'azuredeploy.parameters.json')
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable powershell-yaml)) {
    Install-Module powershell-yaml -Scope CurrentUser -Force -AllowClobber | Out-Null
}
Import-Module powershell-yaml -ErrorAction Stop

function ConvertTo-TriggerOperator([string] $Operator) {
    switch ($Operator) {
        'gt' { 'GreaterThan' }
        'lt' { 'LessThan' }
        'eq' { 'Equal' }
        'ne' { 'NotEqual' }
        default { 'GreaterThan' }
    }
}

$resources = [Collections.Generic.List[object]]::new()

Get-ChildItem (Join-Path $SourceRoot 'AnalyticalRules') -Filter *.yaml | ForEach-Object {
    $rule = ConvertFrom-Yaml (Get-Content $_.FullName -Raw)
    try {
        $queryPeriod = [Xml.XmlConvert]::ToTimeSpan([string]$rule.queryPeriod)
        $queryFrequency = [Xml.XmlConvert]::ToTimeSpan([string]$rule.queryFrequency)
    }
    catch {
        throw "Invalid ISO 8601 query period or frequency in $($_.Name): $($_.Exception.Message)"
    }
    $minimumSchedule = [TimeSpan]::FromMinutes(5)
    $maximumSchedule = [TimeSpan]::FromDays(14)
    if ($queryPeriod -lt $minimumSchedule -or $queryPeriod -gt $maximumSchedule) {
        throw "Invalid queryPeriod '$($rule.queryPeriod)' in $($_.Name). Microsoft Sentinel requires PT5M through P14D."
    }
    if ($queryFrequency -lt $minimumSchedule -or $queryFrequency -gt $maximumSchedule) {
        throw "Invalid queryFrequency '$($rule.queryFrequency)' in $($_.Name). Microsoft Sentinel requires PT5M through P14D."
    }
    if ($queryFrequency -gt $queryPeriod) {
        throw "queryFrequency '$($rule.queryFrequency)' exceeds queryPeriod '$($rule.queryPeriod)' in $($_.Name)."
    }
    $entityMappings = @(
        foreach ($mapping in @($rule.entityMappings)) {
            if (-not $mapping) { continue }
            @{
                entityType = [string]$mapping.entityType
                fieldMappings = @(
                    foreach ($field in @($mapping.fieldMappings)) {
                        @{ identifier = [string]$field.identifier; columnName = [string]$field.columnName }
                    }
                )
            }
        }
    )
    $group = $rule.incidentConfiguration.groupingConfiguration
    $enabled = if ($null -ne $rule.enabled -and -not [bool]$rule.enabled) {
        $false
    }
    else {
        "[parameters('enableAnalyticRules')]"
    }
    $resources.Add([ordered]@{
        type = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
        apiVersion = '2023-12-01-preview'
        name = "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', '$($rule.id)')]"
        kind = 'Scheduled'
        properties = [ordered]@{
            displayName = [string]$rule.name
            description = [string]$rule.description
            severity = [string]$rule.severity
            enabled = $enabled
            query = [string]$rule.query
            queryFrequency = [string]$rule.queryFrequency
            queryPeriod = [string]$rule.queryPeriod
            triggerOperator = ConvertTo-TriggerOperator $rule.triggerOperator
            triggerThreshold = [int]$rule.triggerThreshold
            suppressionDuration = 'PT1H'
            suppressionEnabled = $false
            tactics = @($rule.tactics)
            techniques = @($rule.relevantTechniques)
            alertRuleTemplateName = $null
            eventGroupingSettings = @{ aggregationKind = [string]$rule.eventGroupingSettings.aggregationKind }
            incidentConfiguration = @{
                createIncident = [bool]$rule.incidentConfiguration.createIncident
                groupingConfiguration = @{
                    enabled = [bool]$group.enabled
                    reopenClosedIncident = [bool]$group.reopenClosedIncident
                    lookbackDuration = [string]$group.lookbackDuration
                    matchingMethod = [string]$group.matchingMethod
                    groupByEntities = @($group.groupByEntities)
                    groupByAlertDetails = @($group.groupByAlertDetails)
                    groupByCustomDetails = @($group.groupByCustomDetails)
                }
            }
            entityMappings = $entityMappings
        }
    })
}

Get-ChildItem (Join-Path $SourceRoot 'HuntingQueries') -Filter *.yaml | ForEach-Object {
    $hunt = ConvertFrom-Yaml (Get-Content $_.FullName -Raw)
    $description = (([string]$hunt.description) -replace '\s+', ' ').Trim()
    if ($description.Length -gt 255) { $description = $description.Substring(0, 252) + '...' }
    $resources.Add([ordered]@{
        type = 'Microsoft.OperationalInsights/workspaces/savedSearches'
        apiVersion = '2022-10-01'
        name = "[concat(parameters('workspaceName'), '/$($hunt.id)')]"
        properties = [ordered]@{
            category = 'Hunting Queries'
            displayName = [string]$hunt.name
            query = [string]$hunt.query
            version = 2
            tags = @(
                @{ name = 'description'; value = $description }
                @{ name = 'tactics'; value = (@($hunt.tactics) -join ',') }
                @{ name = 'techniques'; value = (@($hunt.techniques) -join ',') }
            )
        }
    })
}

$template = [ordered]@{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    metadata = @{
        description = 'APIM AI Gateway AppRequests body-aware Microsoft Sentinel analytics and hunts.'
        author = 'Sentinel-As-Code APIM AI Gateway bundle'
    }
    parameters = [ordered]@{
        workspaceName = @{ type = 'string'; metadata = @{ description = 'Sentinel workspace containing APIM AppRequests telemetry.' } }
        enableAnalyticRules = @{ type = 'bool'; defaultValue = $true; metadata = @{ description = 'Enable scheduled analytics unless an individual YAML rule is disabled.' } }
    }
    variables = @{}
    resources = $resources.ToArray()
    outputs = [ordered]@{
        analyticRuleCount = @{ type = 'int'; value = ($resources | Where-Object { $_.type -like '*alertRules' }).Count }
        huntingQueryCount = @{ type = 'int'; value = ($resources | Where-Object { $_.type -like '*savedSearches' }).Count }
        analyticRulesEnabled = @{ type = 'bool'; value = "[parameters('enableAnalyticRules')]" }
    }
}

$json = ($template | ConvertTo-Json -Depth 32) -replace "`r`n", "`n"
[IO.File]::WriteAllText($OutputPath, $json, [Text.UTF8Encoding]::new($false))

$parameters = [ordered]@{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters = [ordered]@{
        workspaceName = @{ value = '<workspace-containing-apim-apprequests>' }
        enableAnalyticRules = @{ value = $true }
    }
}
$paramsJson = ($parameters | ConvertTo-Json -Depth 8) -replace "`r`n", "`n"
[IO.File]::WriteAllText($ParamsPath, $paramsJson, [Text.UTF8Encoding]::new($false))
Write-Host "Wrote $OutputPath ($($resources.Count) resources)"