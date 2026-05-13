<#
.SYNOPSIS
    Integrates the NetworkAllowlist watchlist and the ExcludeAllowlistedIPs
    saved function into Analytic-Rules/azuredeploy.json so a single
    New-AzResourceGroupDeployment call provisions everything in order:
        1. Watchlist  (Microsoft.SecurityInsights/watchlists)
        2. Function   (Microsoft.OperationalInsights/.../savedSearches)
        3. 22 alert rules (each dependsOn the watchlist)

    Idempotent.
#>
[CmdletBinding()]
param(
    [string]$ArmPath         = (Join-Path $PSScriptRoot 'azuredeploy.json'),
    [string]$CsvPath         = (Join-Path $PSScriptRoot 'Watchlists\NetworkAllowlist.csv'),
    [string]$FunctionArmPath = (Join-Path $PSScriptRoot 'Watchlists\azuredeploy-function.json')
)

$ErrorActionPreference = 'Stop'

$arm = Get-Content -LiteralPath $ArmPath -Raw | ConvertFrom-Json -Depth 100

# ---- Parameters ----------------------------------------------------------
if (-not $arm.parameters.PSObject.Properties['watchlistAlias']) {
    $arm.parameters | Add-Member -NotePropertyName 'watchlistAlias' -NotePropertyValue ([pscustomobject]@{
        type         = 'string'
        defaultValue = 'NetworkAllowlist'
        metadata     = [pscustomobject]@{ description = 'Watchlist alias referenced by every rule and hunting query.' }
    })
}
if (-not $arm.parameters.PSObject.Properties['functionAlias']) {
    $arm.parameters | Add-Member -NotePropertyName 'functionAlias' -NotePropertyValue ([pscustomobject]@{
        type         = 'string'
        defaultValue = 'ExcludeAllowlistedIPs'
        metadata     = [pscustomobject]@{ description = 'Saved-function alias: SigninLogs | invoke ExcludeAllowlistedIPs().' }
    })
}
if (-not $arm.parameters.PSObject.Properties['watchlistRawContent']) {
    $csv = if (Test-Path $CsvPath) { (Get-Content -LiteralPath $CsvPath -Raw) -replace "`r`n","`n" -replace "`n","`r`n" } else {
        "IPOrRange,Description,Owner,AddedDate`r`n10.0.0.0/8,RFC1918 private space,SOC,2026-04-20`r`n172.16.0.0/12,RFC1918 private space,SOC,2026-04-20`r`n192.168.0.0/16,RFC1918 private space,SOC,2026-04-20`r`n"
    }
    $arm.parameters | Add-Member -NotePropertyName 'watchlistRawContent' -NotePropertyValue ([pscustomobject]@{
        type         = 'string'
        defaultValue = $csv
        metadata     = [pscustomobject]@{ description = 'CSV contents of the NetworkAllowlist watchlist (header: IPOrRange,Description,Owner,AddedDate). Supports single IPs, CIDR subnets and IPv4 start-end ranges.' }
    })
}

# ---- Function query string (reuse authoritative ARM) ---------------------
$fnArm = Get-Content -LiteralPath $FunctionArmPath -Raw | ConvertFrom-Json -Depth 100
$functionQuery = $fnArm.variables.functionQuery

# ---- Resources: watchlist + function -------------------------------------
$watchlistResource = [pscustomobject]@{
    type       = 'Microsoft.OperationalInsights/workspaces/providers/watchlists'
    apiVersion = '2023-02-01'
    name       = "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', parameters('watchlistAlias'))]"
    properties = [pscustomobject]@{
        displayName         = 'Network Allowlist (Trusted IP / CIDR / Ranges)'
        source              = 'NetworkAllowlist.csv'
        sourceType          = 'Local file'
        provider            = 'SOC'
        description         = 'Trusted IPs, CIDR subnets and IPv4 ranges excluded from SigninLogs analytic rules and hunting queries to suppress false positives.'
        itemsSearchKey      = 'IPOrRange'
        contentType         = 'text/csv'
        numberOfLinesToSkip = 0
        rawContent          = "[parameters('watchlistRawContent')]"
    }
}

$functionResource = [pscustomobject]@{
    type       = 'Microsoft.OperationalInsights/workspaces/savedSearches'
    apiVersion = '2020-08-01'
    name       = "[concat(parameters('workspace'), '/', parameters('functionAlias'))]"
    properties = [pscustomobject]@{
        etag               = '*'
        displayName        = "[parameters('functionAlias')]"
        category           = 'Security - Functions'
        functionAlias      = "[parameters('functionAlias')]"
        functionParameters = 'T:(IPAddress:string)'
        query              = $functionQuery
        version            = 2
        tags               = @(
            [pscustomobject]@{
                name  = 'Description'
                value = 'Filters any table with an IPAddress column, excluding rows whose IPv4 matches the NetworkAllowlist watchlist (single IPs, CIDR subnets, IPv4 start-end ranges).'
            }
        )
    }
}

# Resource IDs used in dependsOn.
$watchlistDep = "[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspace'), 'Microsoft.SecurityInsights', parameters('watchlistAlias'))]"
$functionDep  = "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), parameters('functionAlias'))]"

# ---- Inject ruleDependsOn into every alertRules resource -----------------
$existingTypes = $arm.resources | ForEach-Object { $_.type }
$hasWatchlist  = $existingTypes -contains $watchlistResource.type
$hasFunction   = $existingTypes -contains $functionResource.type

$newResources = New-Object System.Collections.Generic.List[object]
if (-not $hasWatchlist) { $newResources.Add($watchlistResource) }
if (-not $hasFunction)  { $newResources.Add($functionResource)  }

foreach ($r in $arm.resources) {
    if ($r.type -eq 'Microsoft.OperationalInsights/workspaces/providers/alertRules') {
        $deps = @()
        if ($r.PSObject.Properties['dependsOn'] -and $r.dependsOn) {
            $deps = @($r.dependsOn | Where-Object { $_ -ne $watchlistDep -and $_ -ne $functionDep })
        }
        $deps += $watchlistDep
        $deps += $functionDep
        if ($r.PSObject.Properties['dependsOn']) {
            $r.dependsOn = $deps
        } else {
            $r | Add-Member -NotePropertyName dependsOn -NotePropertyValue $deps
        }
    }
    $newResources.Add($r)
}
$arm.resources = $newResources.ToArray()

# ---- Persist -------------------------------------------------------------
$json = $arm | ConvertTo-Json -Depth 100
[System.IO.File]::WriteAllText($ArmPath, $json)

# Validate.
$null = Get-Content -LiteralPath $ArmPath -Raw | ConvertFrom-Json -Depth 100
$counts = @{}
foreach ($r in (Get-Content -LiteralPath $ArmPath -Raw | ConvertFrom-Json -Depth 100).resources) {
    $counts[$r.type] = ($counts[$r.type] + 1)
}
Write-Host "Resources:" -ForegroundColor Cyan
foreach ($k in $counts.Keys) { Write-Host ("  {0,3} × {1}" -f $counts[$k], $k) }
Write-Host "OK -> $ArmPath" -ForegroundColor Green
