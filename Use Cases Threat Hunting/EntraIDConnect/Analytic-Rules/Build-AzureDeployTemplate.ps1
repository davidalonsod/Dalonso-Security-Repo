#Requires -Modules powershell-yaml
<#
.SYNOPSIS
    Builds azuredeploy.json for the AADProvisioningLogs-ThreatHunting pack
    from the YAML rule sources in .\rules\.

.DESCRIPTION
    Reads every *.yaml file under .\rules\, converts each to a Sentinel
    alertRules ARM resource, and emits a single azuredeploy.json that also
    provisions:
      - NetworkAllowlist watchlist (trusted IPs / CIDR / ranges)
      - HighValueAssets watchlist (Entra Connect server public IPs - tagged
        EntraIDConnect, consumed by RULE-10)
      - ServiceAccounts watchlist (Entra Connector sync UPNs / ObjectIds -
        tagged EntraIDConnect, consumed by RULE-12)
      - ExcludeAllowlistedIPs saved KQL function (FP suppression for any
        rule with an IPAddress column)

    Mirrors the pattern used by ADFSSignInLogs-ThreatHunting.

.PARAMETER OutputPath
    Path to write azuredeploy.json. Defaults to .\azuredeploy.json.

.EXAMPLE
    .\Build-AzureDeployTemplate.ps1
#>
[CmdletBinding()]
param(
    [string] $RulesPath    = "$PSScriptRoot\rules",
    [string] $HuntingPath  = "$PSScriptRoot\..\HuntingQueries",
    [string] $OutputPath   = "$PSScriptRoot\azuredeploy.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
    Install-Module powershell-yaml -Force -Scope CurrentUser
}
Import-Module powershell-yaml

function ConvertTo-Iso8601 {
    param([string]$Value)
    if (-not $Value) { return 'PT1H' }
    if ($Value -match '^(\d+)m$') { return "PT$($Matches[1])M" }
    if ($Value -match '^(\d+)h$') { return "PT$($Matches[1])H" }
    if ($Value -match '^(\d+)d$') { return "P$($Matches[1])D" }
    if ($Value -match '^P')        { return $Value }
    return 'PT1H'
}

function ConvertTo-TriggerOperator {
    param([string]$Value)
    switch ($Value) {
        'gt' { 'GreaterThan' }
        'lt' { 'LessThan' }
        'eq' { 'Equal' }
        'ne' { 'NotEqual' }
        default { if ($Value) { $Value } else { 'GreaterThan' } }
    }
}

$yamlFiles = Get-ChildItem -Path $RulesPath -Filter '*.yaml' | Sort-Object Name
Write-Host "Found $($yamlFiles.Count) rule file(s)."

$alertRuleResources = @()

foreach ($file in $yamlFiles) {
    $rule = Get-Content $file.FullName -Raw | ConvertFrom-Yaml

    $entityMappings = [System.Collections.ArrayList]@()
    if ($rule.entityMappings) {
        foreach ($em in $rule.entityMappings) {
            $fm = [System.Collections.ArrayList]@()
            foreach ($f in $em.fieldMappings) {
                [void]$fm.Add([ordered]@{ identifier = $f.identifier; columnName = $f.columnName })
            }
            [void]$entityMappings.Add([ordered]@{ entityType = $em.entityType; fieldMappings = $fm })
        }
    }

    $customDetails = $null
    if ($rule.customDetails) {
        $customDetails = [ordered]@{}
        foreach ($k in $rule.customDetails.Keys) { $customDetails[$k] = $rule.customDetails[$k] }
    }

    $alertOverride = $null
    if ($rule.alertDetailsOverride) {
        $alertOverride = [ordered]@{}
        if ($rule.alertDetailsOverride.alertDisplayNameFormat) {
            $alertOverride.alertDisplayNameFormat = $rule.alertDetailsOverride.alertDisplayNameFormat
        }
        if ($rule.alertDetailsOverride.alertDescriptionFormat) {
            $alertOverride.alertDescriptionFormat = $rule.alertDetailsOverride.alertDescriptionFormat
        }
    }

    $incident = [ordered]@{
        createIncident        = $true
        groupingConfiguration = [ordered]@{
            enabled              = $false
            reopenClosedIncident = $false
            lookbackDuration     = 'PT5H'
            matchingMethod       = 'AnyAlert'
            groupByEntities      = [string[]]@()
            groupByAlertDetails  = [string[]]@()
            groupByCustomDetails = [string[]]@()
        }
    }
    if ($rule.incidentConfiguration) {
        $incident.createIncident = [bool]$rule.incidentConfiguration.createIncident
        $gc = $rule.incidentConfiguration.groupingConfiguration
        if ($gc) {
            $incident.groupingConfiguration = [ordered]@{
                enabled              = [bool]$gc.enabled
                reopenClosedIncident = [bool]$gc.reopenClosedIncident
                lookbackDuration     = if ($gc.lookbackDuration) { $gc.lookbackDuration } else { 'PT5H' }
                matchingMethod       = if ($gc.matchingMethod)   { $gc.matchingMethod }   else { 'AnyAlert' }
                groupByEntities      = [string[]]@($gc.groupByEntities      | Where-Object { $_ })
                groupByAlertDetails  = [string[]]@($gc.groupByAlertDetails  | Where-Object { $_ })
                groupByCustomDetails = [string[]]@($gc.groupByCustomDetails | Where-Object { $_ })
            }
        }
    }

    $properties = [ordered]@{
        displayName           = $rule.name
        description           = ($rule.description -replace "`r`n|`n", ' ').Trim()
        severity              = $rule.severity
        enabled               = "[parameters('enableAnalyticRules')]"
        query                 = $rule.query
        queryFrequency        = ConvertTo-Iso8601 $rule.queryFrequency
        queryPeriod           = ConvertTo-Iso8601 $rule.queryPeriod
        triggerOperator       = ConvertTo-TriggerOperator $rule.triggerOperator
        triggerThreshold      = [int]$rule.triggerThreshold
        suppressionEnabled    = $false
        suppressionDuration   = 'PT5H'
        tactics               = [string[]]@($rule.tactics            | Where-Object { $_ })
        techniques            = [string[]]@($rule.relevantTechniques | Where-Object { $_ })
        entityMappings        = $entityMappings
        incidentConfiguration = $incident
    }
    if ($customDetails) { $properties.customDetails        = $customDetails }
    if ($alertOverride) { $properties.alertDetailsOverride = $alertOverride }

    $resource = [ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
        apiVersion = '2022-11-01'
        name       = "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', '$($rule.id)')]"
        kind       = 'Scheduled'
        location   = "[parameters('location')]"
        dependsOn  = @(
            "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspaceName'), parameters('functionAlias'))]"
        )
        properties = $properties
    }
    $alertRuleResources += $resource
    Write-Host "  + $($rule.name)" -ForegroundColor Green
}

# ── Static resources: watchlists + function ─────────────────────────────────

$networkAllowlist = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/watchlists'
    apiVersion = '2023-02-01'
    name       = "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', parameters('networkAllowlistAlias'))]"
    condition  = "[parameters('deployNetworkAllowlist')]"
    properties = [ordered]@{
        displayName         = 'Network Allowlist (Trusted IP / CIDR / Ranges)'
        source              = 'NetworkAllowlist.csv'
        sourceType          = 'Local file'
        provider            = 'SOC'
        description         = 'Trusted IPs/CIDR/ranges excluded from AADProvisioningLogs rules and hunts to suppress false positives. Shared model with the ADFSSignInLogs pack.'
        itemsSearchKey      = 'IPOrRange'
        contentType         = 'text/csv'
        numberOfLinesToSkip = 0
        rawContent          = "[variables('effectiveNetworkAllowlistContent')]"
    }
}

$highValueAssets = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/watchlists'
    apiVersion = '2023-02-01'
    name       = "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', 'EntraConnect_HighValueAssets')]"
    condition  = "[parameters('deployHighValueAssets')]"
    properties = [ordered]@{
        displayName         = 'Entra Connect High Value Assets (server public IPs)'
        source              = 'EntraConnect_HighValueAssets.csv'
        sourceType          = 'Local file'
        provider            = 'SOC'
        description         = 'Entra Connect server public IP addresses. Tagged EntraIDConnect. Consumed by RULE-10 and HUNT-03. Namespaced alias to avoid collision with any pre-existing HighValueAssets watchlist in the workspace.'
        itemsSearchKey      = 'IPAddress'
        contentType         = 'text/csv'
        numberOfLinesToSkip = 0
        rawContent          = "[parameters('highValueAssetsContent')]"
    }
}

$serviceAccounts = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/watchlists'
    apiVersion = '2023-02-01'
    name       = "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/', 'EntraConnect_ServiceAccounts')]"
    condition  = "[parameters('deployServiceAccounts')]"
    properties = [ordered]@{
        displayName         = 'Entra Connect Service Accounts (sync identities)'
        source              = 'EntraConnect_ServiceAccounts.csv'
        sourceType          = 'Local file'
        provider            = 'SOC'
        description         = 'Entra Connector sync UPNs / ObjectIds. Tagged EntraIDConnect. Consumed by RULE-12. Namespaced alias to avoid collision with any pre-existing ServiceAccounts watchlist.'
        itemsSearchKey      = 'AccountObjectId'
        contentType         = 'text/csv'
        numberOfLinesToSkip = 0
        rawContent          = "[parameters('serviceAccountsContent')]"
    }
}

$functionQuery = @"
let _allow = materialize(
    union isfuzzy=true (print R='' | take 0),
    (_GetWatchlist('NetworkAllowlist') | project R = tostring(IPOrRange))
    | where isnotempty(R)
);
let _allowCIDR = toscalar(
    _allow
    | where not(R matches regex @'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+`$')
    | extend R = iff(R has '/', R, strcat(R, '/32'))
    | summarize make_list(R)
);
let _allowRange = toscalar(
    _allow
    | where R matches regex @'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+`$'
    | summarize make_list(R)
);
T
| extend IPAddress = tostring(IPAddress)
| where array_length(_allowCIDR) == 0 or isnull(ipv4_is_in_any_range(IPAddress, _allowCIDR)) or not(ipv4_is_in_any_range(IPAddress, _allowCIDR))
| mv-apply _r = _allowRange to typeof(string) on (
    extend _lo = tostring(split(_r,'-')[0]), _hi = tostring(split(_r,'-')[1])
    | extend _inRange = ipv4_compare(IPAddress, _lo) >= 0 and ipv4_compare(IPAddress, _hi) <= 0
    | summarize _anyInRange = max(toint(_inRange))
)
| where isnull(_anyInRange) or _anyInRange == 0
| project-away _anyInRange
"@

$function = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/savedSearches'
    apiVersion = '2020-08-01'
    name       = "[concat(parameters('workspaceName'), '/', parameters('functionAlias'))]"
    properties = [ordered]@{
        etag               = '*'
        displayName        = "[parameters('functionAlias')]"
        category           = 'Security - Functions'
        functionAlias      = "[parameters('functionAlias')]"
        functionParameters = 'T:(IPAddress:string)'
        query              = $functionQuery
        version            = 2
        tags               = @(
            [ordered]@{ name = 'Description'; value = 'Filters any table with an IPAddress column, excluding rows whose IPv4 matches the NetworkAllowlist watchlist.' }
        )
    }
}

# Make alert rules depend on watchlists too
foreach ($r in $alertRuleResources) {
    $r.dependsOn += "[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspaceName'), 'Microsoft.SecurityInsights', parameters('networkAllowlistAlias'))]"
    $r.dependsOn += "[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspaceName'), 'Microsoft.SecurityInsights', 'EntraConnect_HighValueAssets')]"
    $r.dependsOn += "[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspaceName'), 'Microsoft.SecurityInsights', 'EntraConnect_ServiceAccounts')]"
}

# ── Hunting queries (savedSearches with category 'Hunting Queries') ─────────

$huntResources = @()
if (Test-Path $HuntingPath) {
    $huntFiles = Get-ChildItem -Path $HuntingPath -Filter '*.yaml' | Sort-Object Name
    Write-Host "Found $($huntFiles.Count) hunting query file(s)."
    foreach ($file in $huntFiles) {
        $h = Get-Content $file.FullName -Raw | ConvertFrom-Yaml

        $tagList = [System.Collections.ArrayList]@()
        $descFlat = ($h.description -replace "`r`n|`n", ' ').Trim()
        if ($descFlat.Length -gt 255) { $descFlat = $descFlat.Substring(0, 252) + '...' }
        [void]$tagList.Add([ordered]@{ name = 'description'; value = $descFlat })
        if ($h.tactics)            { [void]$tagList.Add([ordered]@{ name = 'tactics';    value = (($h.tactics            | Where-Object { $_ }) -join ',') }) }
        if ($h.relevantTechniques) { [void]$tagList.Add([ordered]@{ name = 'techniques'; value = (($h.relevantTechniques | Where-Object { $_ }) -join ',') }) }
        if ($h.severity)           { [void]$tagList.Add([ordered]@{ name = 'severity';   value = $h.severity }) }

        $huntResource = [ordered]@{
            type       = 'Microsoft.OperationalInsights/workspaces/savedSearches'
            apiVersion = '2020-08-01'
            name       = "[concat(parameters('workspaceName'), '/', '$($h.id)')]"
            condition  = "[parameters('deployHuntingQueries')]"
            properties = [ordered]@{
                etag        = '*'
                displayName = $h.name
                category    = 'Hunting Queries'
                query       = $h.query
                version     = 2
                tags        = $tagList
            }
            dependsOn  = @(
                "[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspaceName'), 'Microsoft.SecurityInsights', 'EntraConnect_HighValueAssets')]",
                "[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspaceName'), 'Microsoft.SecurityInsights', 'EntraConnect_ServiceAccounts')]"
            )
        }
        $huntResources += $huntResource
        Write-Host "  + [HUNT] $($h.name)" -ForegroundColor Yellow
    }
} else {
    Write-Host "HuntingPath '$HuntingPath' not found - skipping hunts." -ForegroundColor DarkYellow
}

# ── Top-level template ──────────────────────────────────────────────────────

$template = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    metadata       = [ordered]@{
        description = 'AADProvisioningLogs Threat Hunting pack - 17 analytic rules + 14 hunting queries + watchlists + ExcludeAllowlistedIPs function.'
        author      = 'AADProvisioningLogs Threat Hunting Rule Pack'
    }
    parameters     = [ordered]@{
        workspaceName = [ordered]@{
            type = 'string'
            metadata = [ordered]@{ description = 'Name of the Log Analytics workspace that Sentinel is deployed on.' }
        }
        location = [ordered]@{
            type = 'string'
            defaultValue = "[resourceGroup().location]"
            metadata = [ordered]@{ description = 'Azure region.' }
        }
        enableAnalyticRules = [ordered]@{
            type = 'bool'
            defaultValue = $true
            metadata = [ordered]@{ description = 'Deploy rules enabled (true) or disabled (false) for staged rollout.' }
        }
        networkAllowlistAlias = [ordered]@{
            type = 'string'
            defaultValue = 'NetworkAllowlist'
            metadata = [ordered]@{ description = 'Alias of the shared trusted-IP allowlist watchlist.' }
        }
        functionAlias = [ordered]@{
            type = 'string'
            defaultValue = 'ExcludeAllowlistedIPs'
            metadata = [ordered]@{ description = 'Alias of the saved KQL function for IP allowlist filtering.' }
        }
        deployNetworkAllowlist = [ordered]@{
            type = 'bool'
            defaultValue = $true
            metadata = [ordered]@{ description = 'Set to false if a NetworkAllowlist watchlist already exists in this workspace (avoids ARM searchKey collision). Rules still resolve it by alias at query time.' }
        }
        deployHighValueAssets = [ordered]@{
            type = 'bool'
            defaultValue = $true
            metadata = [ordered]@{ description = 'Set to false if a HighValueAssets watchlist already exists with a different schema (e.g. DeviceName search key). RULE-10 will still work as long as the existing watchlist has an IPAddress column populated with Entra Connect server IPs tagged EntraIDConnect.' }
        }
        deployServiceAccounts = [ordered]@{
            type = 'bool'
            defaultValue = $true
            metadata = [ordered]@{ description = 'Set to false if a ServiceAccounts watchlist already exists. RULE-12 needs an AccountObjectId column with sync identities tagged EntraIDConnect.' }
        }
        deployHuntingQueries = [ordered]@{
            type = 'bool'
            defaultValue = $true
            metadata = [ordered]@{ description = 'Deploy the 14 companion hunting queries as savedSearches in the Hunting Queries category.' }
        }
        networkAllowlistContent = [ordered]@{
            type = 'string'
            defaultValue = ''
            metadata = [ordered]@{ description = 'Initial CSV content for NetworkAllowlist. Header IPOrRange,Description,Owner,AddedDate.' }
        }
        highValueAssetsContent = [ordered]@{
            type = 'string'
            defaultValue = "IPAddress,Tags,Description,Owner,AddedDate`r`n203.0.113.10,EntraIDConnect,Replace with your Entra Connect server public IP,SOC,2026-05-26`r`n"
            metadata = [ordered]@{ description = 'CSV content for HighValueAssets watchlist. Replace stub with real Entra Connect public IPs.' }
        }
        serviceAccountsContent = [ordered]@{
            type = 'string'
            defaultValue = "AccountObjectId,AccountUPN,Tags,Description,Owner,AddedDate`r`n00000000-0000-0000-0000-000000000000,Sync_REPLACE_ME@tenant.onmicrosoft.com,EntraIDConnect,Replace with your Entra Connector account,SOC,2026-05-26`r`n"
            metadata = [ordered]@{ description = 'CSV content for ServiceAccounts watchlist. Replace stub with real sync identities.' }
        }
    }
    variables      = [ordered]@{
        defaultNetworkAllowlistEntries = @(
            '10.0.0.0/8,RFC1918 private space,SOC,2026-05-26',
            '172.16.0.0/12,RFC1918 private space,SOC,2026-05-26',
            '192.168.0.0/16,RFC1918 private space,SOC,2026-05-26'
        )
        csvHeader = 'IPOrRange,Description,Owner,AddedDate'
        crlf      = "[json('`"\r\n`"')]"
        builtCsv  = "[concat(variables('csvHeader'), variables('crlf'), join(variables('defaultNetworkAllowlistEntries'), variables('crlf')), variables('crlf'))]"
        effectiveNetworkAllowlistContent = "[if(empty(parameters('networkAllowlistContent')), variables('builtCsv'), parameters('networkAllowlistContent'))]"
    }
    resources      = @($networkAllowlist, $highValueAssets, $serviceAccounts, $function) + $alertRuleResources + $huntResources
}

$json = $template | ConvertTo-Json -Depth 50
Set-Content -Path $OutputPath -Value $json -Encoding UTF8
Write-Host ""
Write-Host "Wrote: $OutputPath" -ForegroundColor Cyan
Write-Host "Resources: $($template.resources.Count) (3 watchlists + 1 function + $($alertRuleResources.Count) alert rules + $($huntResources.Count) hunts)" -ForegroundColor Cyan
