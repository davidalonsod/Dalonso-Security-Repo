# Build mainTemplate.json as a Microsoft Sentinel Content Hub SOLUTION.
# Emits:
#   - 1 x Microsoft.OperationalInsights/workspaces/providers/contentPackages (the tile)
#   - 1 x Microsoft.OperationalInsights/workspaces/providers/metadata (Solution kind)
#   - N x Microsoft.OperationalInsights/workspaces/providers/contentTemplates
#       each with a nested mainTemplate that creates the actual resource + its Metadata
#
# Run:  pwsh -File .\Package\build-contenthub.ps1

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
if (-not $OutFile) { $OutFile = Join-Path $Root 'Package\mainTemplate.json' }

if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
    Install-Module powershell-yaml -Scope CurrentUser -Force -AllowClobber
}
Import-Module powershell-yaml -ErrorAction Stop

function Read-Yaml($p) { Get-Content -Raw -LiteralPath $p | ConvertFrom-Yaml }

# ------------------------------------------------------------------ Solution identity
$solutionName        = 'IntuneLogs'
$solutionDisplayName = 'Intune Logs (Community)'
$solutionVersion     = '1.1.0'
$solutionId          = 'e6d4f7a1-9c2b-4c8e-bd0a-1f2b3c4d5e6f'   # stable GUID for this solution
$author              = [ordered]@{ name = 'Community'; email = 'community@example.com' }
$support             = [ordered]@{ name = 'Community'; tier = 'Community'; link = 'https://github.com/Azure/Azure-Sentinel' }

# ------------------------------------------------------------------ Helpers
function To-Iso([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return 'PT1H' }
    $v = $v.Trim()
    if ($v -match '^P') { return $v.ToUpper() }
    $u = $v.ToUpper()
    if ($u -match '^(\d+)([DMHS])$') {
        $n = $Matches[1]; $unit = $Matches[2]
        if ($unit -eq 'D') { return "P${n}D" }
        return "PT${n}${unit}"
    }
    return $u
}
$triggerMap = @{ 'gt'='GreaterThan'; 'lt'='LessThan'; 'eq'='Equal'; 'ne'='NotEqual' }

function Strip-SubTechniques($arr) {
    if (-not $arr) { return @() }
    @($arr | ForEach-Object { ([string]$_ -replace '\.\d+$','') } | Sort-Object -Unique)
}

function Common-MetadataBase($contentId, $kind, $parentIdExpr) {
    return [ordered]@{
        parentId = $parentIdExpr
        contentId = $contentId
        kind = $kind
        version = '1.0.0'
        source = [ordered]@{
            kind     = 'Solution'
            name     = $solutionDisplayName
            sourceId = $solutionId
        }
        author  = $author
        support = $support
    }
}

function Common-TemplateProps($contentId, $kind, $displayName) {
    $v = $solutionVersion.Replace('.','')
    return [ordered]@{
        contentSchemaVersion = '3.0.0'
        contentId        = $contentId
        contentKind      = $kind
        displayName      = $displayName
        version          = '1.0.0'
        contentProductId = "$contentId-$($kind.ToLower())-$v"
        packageKind      = 'Solution'
        packageVersion   = $solutionVersion
        packageName      = $solutionDisplayName
        packageId        = $solutionId
        source           = [ordered]@{ kind='Solution'; name=$solutionDisplayName; sourceId=$solutionId }
        author           = $author
        support          = $support
    }
}

# ------------------------------------------------------------------ Content items
$rulesDir     = Join-Path $Root 'Analytic Rules'
$huntsDir     = Join-Path $Root 'Hunting Queries'
$workbookFile = Join-Path $Root 'Workbooks\IntuneSecurity-CIO-CISO.json'
$ruleFiles    = Get-ChildItem -LiteralPath $rulesDir -Filter *.yaml | Sort-Object Name
$huntFiles    = Get-ChildItem -LiteralPath $huntsDir -Filter *.yaml | Sort-Object Name

$resources    = [System.Collections.Generic.List[object]]::new()
$dependencies = [System.Collections.Generic.List[object]]::new()

$parentIdAlertRule = {
    param($contentId)
    "[resourceId('Microsoft.OperationalInsights/workspaces/providers/alertRules', parameters('workspace'), 'Microsoft.SecurityInsights', '$contentId')]"
}
$parentIdSavedSearch = {
    param($contentId)
    "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), '$contentId')]"
}
$parentIdWorkbook = {
    param($contentId)
    "[resourceId('Microsoft.Insights/workbooks', '$contentId')]"
}

# ---------------- Analytic rules ----------------
foreach ($f in $ruleFiles) {
    $y = Read-Yaml $f.FullName
    $cid = [string]$y.id
    $templateName = "$solutionName-ar-$cid"

    $freq   = To-Iso ([string]$y.queryFrequency)
    $period = To-Iso ([string]$y.queryPeriod)
    $op     = [string]$y.triggerOperator
    if ($triggerMap.ContainsKey($op)) { $op = $triggerMap[$op] }
    $tactics  = if ($y.tactics) { @($y.tactics) } else { @() }
    $techs    = Strip-SubTechniques $y.relevantTechniques
    $entities = if ($y.entityMappings) { @($y.entityMappings) } else { @() }

    $alertRuleResource = [ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
        apiVersion = '2022-11-01'
        name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','$cid')]"
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
    $metaInner = Common-MetadataBase $cid 'AnalyticsRule' (& $parentIdAlertRule $cid)
    $alertRuleMeta = [ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/providers/metadata'
        apiVersion = '2022-01-01-preview'
        name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','analyticsrule-$cid')]"
        properties = $metaInner
    }

    $tProps = Common-TemplateProps $cid 'AnalyticsRule' ([string]$y.name)
    $tProps['mainTemplate'] = [ordered]@{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        resources      = @($alertRuleResource, $alertRuleMeta)
    }

    $resources.Add([ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/providers/contentTemplates'
        apiVersion = '2023-04-01-preview'
        name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','$templateName')]"
        location   = "[parameters('location')]"
        dependsOn  = @("[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', '$solutionId')]")
        properties = $tProps
    })

    $dependencies.Add([ordered]@{ kind='AnalyticsRule'; contentId=$cid; version='1.0.0' })
}

# ---------------- Hunting queries ----------------
foreach ($f in $huntFiles) {
    $y = Read-Yaml $f.FullName
    $cid = [string]$y.id
    $templateName = "$solutionName-hq-$cid"
    $tactics = if ($y.tactics) { @($y.tactics) } else { @() }

    $savedSearchResource = [ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/savedSearches'
        apiVersion = '2020-08-01'
        name       = "[concat(parameters('workspace'),'/','$cid')]"
        properties = [ordered]@{
            category    = 'Hunting Queries - IntuneLogs'
            displayName = [string]$y.name
            query       = [string]$y.query
            version     = 2
            tags        = @(
                [ordered]@{ name='tactics';   value=($tactics -join ',') }
                [ordered]@{ name='createdBy'; value=$solutionDisplayName }
            )
        }
    }
    $metaInner = Common-MetadataBase $cid 'HuntingQuery' (& $parentIdSavedSearch $cid)
    $savedSearchMeta = [ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/providers/metadata'
        apiVersion = '2022-01-01-preview'
        name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','huntingquery-$cid')]"
        properties = $metaInner
    }

    $tProps = Common-TemplateProps $cid 'HuntingQuery' ([string]$y.name)
    $tProps['mainTemplate'] = [ordered]@{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        resources      = @($savedSearchResource, $savedSearchMeta)
    }

    $resources.Add([ordered]@{
        type       = 'Microsoft.OperationalInsights/workspaces/providers/contentTemplates'
        apiVersion = '2023-04-01-preview'
        name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','$templateName')]"
        location   = "[parameters('location')]"
        dependsOn  = @("[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', '$solutionId')]")
        properties = $tProps
    })

    $dependencies.Add([ordered]@{ kind='HuntingQuery'; contentId=$cid; version='1.0.0' })
}

# ---------------- Workbook ----------------
$wbJson = Get-Content -Raw -LiteralPath $workbookFile | ConvertFrom-Json -Depth 100
$wbSerialized = $wbJson | ConvertTo-Json -Depth 100 -Compress
$wbContentId = '4a1f9c30-88b7-4e6d-9c9c-7d2f3a5c1f21'

$workbookResource = [ordered]@{
    type       = 'Microsoft.Insights/workbooks'
    apiVersion = '2022-04-01'
    name       = $wbContentId
    location   = "[parameters('location')]"
    kind       = 'shared'
    properties = [ordered]@{
        displayName    = 'Intune Security - CIO / CISO KPIs'
        serializedData = $wbSerialized
        version        = '1.0'
        sourceId       = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"
        category       = 'sentinel'
    }
}
$wbMetaInner = Common-MetadataBase $wbContentId 'Workbook' (& $parentIdWorkbook $wbContentId)
$workbookMeta = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/metadata'
    apiVersion = '2022-01-01-preview'
    name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','workbook-$wbContentId')]"
    properties = $wbMetaInner
}
$tWbProps = Common-TemplateProps $wbContentId 'Workbook' 'Intune Security - CIO / CISO KPIs'
$tWbProps['mainTemplate'] = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    resources      = @($workbookResource, $workbookMeta)
}
$resources.Add([ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/contentTemplates'
    apiVersion = '2023-04-01-preview'
    name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','$solutionName-wb-$wbContentId')]"
    location   = "[parameters('location')]"
    dependsOn  = @("[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', '$solutionId')]")
    properties = $tWbProps
})
$dependencies.Add([ordered]@{ kind='Workbook'; contentId=$wbContentId; version='1.0.0' })

# ---------------- Data connector (native diagnostic settings, GenericUI) ----------------
$diagConnectorContentId = 'd4c1b2e3-5a6f-4c8d-9f01-aabbccdd0001'
$diagConnector = Get-Content -Raw -LiteralPath (Join-Path $Root 'Data Connectors\IntuneLogsDiagnosticSettings_connector.json') |
    ConvertFrom-Json -Depth 50

$connectorResource = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/dataConnectors'
    apiVersion = '2024-01-01-preview'
    name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','IntuneLogsDiagnosticSettings')]"
    kind       = 'GenericUI'
    properties = [ordered]@{
        connectorUiConfig = $diagConnector
    }
}
$connectorMetaInner = Common-MetadataBase $diagConnectorContentId 'DataConnector' `
    "[resourceId('Microsoft.OperationalInsights/workspaces/providers/dataConnectors', parameters('workspace'), 'Microsoft.SecurityInsights', 'IntuneLogsDiagnosticSettings')]"
$connectorMeta = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/metadata'
    apiVersion = '2022-01-01-preview'
    name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','dataconnector-$diagConnectorContentId')]"
    properties = $connectorMetaInner
}
$tConnProps = Common-TemplateProps $diagConnectorContentId 'DataConnector' 'Microsoft Intune (Diagnostic Settings)'
$tConnProps['mainTemplate'] = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    resources      = @($connectorResource, $connectorMeta)
}
$resources.Add([ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/contentTemplates'
    apiVersion = '2023-04-01-preview'
    name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','$solutionName-dc-$diagConnectorContentId')]"
    location   = "[parameters('location')]"
    dependsOn  = @("[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', '$solutionId')]")
    properties = $tConnProps
})
$dependencies.Add([ordered]@{ kind='DataConnector'; contentId=$diagConnectorContentId; version='1.0.0' })

# ------------------------------------------------------------------ Solution tile + Metadata
$solutionPackage = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/contentPackages'
    apiVersion = '2023-04-01-preview'
    name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','$solutionId')]"
    location   = "[parameters('location')]"
    properties = [ordered]@{
        version         = $solutionVersion
        kind            = 'Solution'
        contentSchemaVersion = '3.0.0'
        displayName     = $solutionDisplayName
        contentKind     = 'Solution'
        contentProductId= "$solutionId-sl-$($solutionVersion.Replace('.',''))"
        id              = "$solutionId-sl-$($solutionVersion.Replace('.',''))"
        contentId       = $solutionId
        packageId       = $solutionId
        source          = [ordered]@{ kind='Solution'; name=$solutionDisplayName; sourceId=$solutionId }
        author          = $author
        support         = $support
        descriptionHtml = '<p>Microsoft Intune / MDM security solution: 15 analytic rules, 15 hunting queries, CIO/CISO workbook, and native Intune Diagnostic Settings data connector. Covers device trust abuse, compliance bypass, MDM enrollment attacks, PRT/refresh token replay, privileged role changes, policy tampering, and destructive admin actions.</p>'
        dependencies    = [ordered]@{
            operator = 'AND'
            criteria = $dependencies
        }
        firstPublishDate = '2026-04-21'
        providers = @('Community')
        categories = [ordered]@{
            domains   = @('Security - Cloud Security','Identity','Security - Threat Protection')
            verticals = @()
        }
    }
}

$solutionMeta = [ordered]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/metadata'
    apiVersion = '2022-01-01-preview'
    name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','$solutionId')]"
    location   = "[parameters('location')]"
    properties = [ordered]@{
        kind        = 'Solution'
        contentId   = $solutionId
        parentId    = $solutionId
        source      = [ordered]@{ kind='Solution'; name=$solutionDisplayName; sourceId=$solutionId }
        author      = $author
        support     = $support
        version     = $solutionVersion
        dependencies= [ordered]@{
            operator = 'AND'
            criteria = $dependencies
        }
    }
}

# insert solution first so every template can depend on it
$ordered = [System.Collections.Generic.List[object]]::new()
$ordered.Add($solutionPackage)
$ordered.Add($solutionMeta)
foreach ($r in $resources) { $ordered.Add($r) }

# ------------------------------------------------------------------ Emit
$template = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    parameters     = [ordered]@{
        workspace = [ordered]@{ type='string'; metadata=@{ description='Sentinel-enabled workspace name.' } }
        location  = [ordered]@{ type='string'; defaultValue="[resourceGroup().location]" }
    }
    resources      = $ordered
    outputs        = [ordered]@{
        solutionId   = [ordered]@{ type='string'; value=$solutionId }
        contentItems = [ordered]@{ type='int';    value=$dependencies.Count }
    }
}

$json = $template | ConvertTo-Json -Depth 100
$json | Set-Content -LiteralPath $OutFile -Encoding UTF8

Write-Host ""
Write-Host "Wrote $OutFile"
Write-Host "  Solution         : $solutionDisplayName ($solutionVersion)"
Write-Host "  Analytic rules   : $($ruleFiles.Count)"
Write-Host "  Hunting queries  : $($huntFiles.Count)"
Write-Host "  Workbook         : 1"
Write-Host "  Data connectors  : 1"
Write-Host "  Total resources  : $($ordered.Count)"
