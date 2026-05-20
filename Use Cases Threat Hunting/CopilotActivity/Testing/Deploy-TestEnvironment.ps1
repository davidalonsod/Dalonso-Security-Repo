# Microsoft 365 Copilot detections - test environment bootstrap
#
# Stands up a complete, isolated environment to test the Copilot
# analytic rules + hunting queries in another tenant / subscription:
#
#   1. Create (or reuse) resource group
#   2. Create (or reuse) Log Analytics workspace
#   3. Onboard Microsoft Sentinel on the workspace
#   4. Set the CopilotActivity table plan to Analytics
#   5. Provision the CopilotTrustedRagSources + CopilotApprovedPlugins watchlists
#   6. Deploy the ARM template (7 analytic rules + 3 hunting queries)
#
# Prereqs on the operator's machine:
#   - PowerShell 7+
#   - Az PowerShell modules: Az.Accounts, Az.Resources, Az.OperationalInsights
#       Install-Module Az.Accounts, Az.Resources, Az.OperationalInsights -Scope CurrentUser
#     (Watchlist + table-plan calls go via the management REST API directly,
#      so Az.SecurityInsights / Az.Monitor are not required.)
#   - Connect-AzAccount run, with rights:
#       - Contributor on the subscription (or RG-scoped)
#       - Microsoft Sentinel Contributor on the workspace RG
#
# Prereqs in the target tenant (manual, see Testing\README.md):
#   - A Microsoft 365 tenant with Microsoft 365 Copilot licensed for at
#     least one test user
#   - The Microsoft Copilot data connector enabled on the target
#     workspace (must be done in the Sentinel portal; the connector is
#     surfaced under "Microsoft Copilot for M365" / similar - exact
#     name depends on portal locale).
#
# Usage:
#   pwsh ./Deploy-TestEnvironment.ps1 `
#       -SubscriptionId '<sub-guid>' `
#       -ResourceGroupName 'rg-copilot-test' `
#       -WorkspaceName    'la-copilot-test' `
#       -Location         'westeurope'

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [Parameter(Mandatory)] [string] $ResourceGroupName,
    [Parameter(Mandatory)] [string] $WorkspaceName,
    [Parameter(Mandatory)] [string] $Location,

    [string] $WatchlistCsvPath = (Join-Path $PSScriptRoot 'Watchlists\CopilotTrustedRagSources.csv'),
    [string] $ArmTemplatePath  = (Join-Path $PSScriptRoot '..\Deploy\azuredeploy.json'),
    [bool]   $EnableAnalyticRules = $true
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string] $Msg) Write-Host "==> $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string] $Msg) Write-Host "    OK: $Msg" -ForegroundColor Green }
function Write-Warn { param([string] $Msg) Write-Host "    WARN: $Msg" -ForegroundColor Yellow }

function Get-MgmtBearerToken {
    # Az.Accounts >= 5.x defaults Get-AzAccessToken to SecureString;
    # older versions return plain text. Handle both.
    $raw = Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -ErrorAction Stop
    if ($raw.Token -is [System.Security.SecureString]) {
        return [System.Net.NetworkCredential]::new('', $raw.Token).Password
    }
    if ($raw.PSObject.Properties.Name -contains 'Token') { return [string]$raw.Token }
    return [string]$raw
}

# ----- 0. Context -----
Write-Step "Setting subscription context"
$ctx = Get-AzContext -ErrorAction Stop
if (-not $ctx) { throw 'Run Connect-AzAccount before invoking this script.' }
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
Write-Ok "Subscription: $SubscriptionId"

# ----- 1. Resource group -----
Write-Step "Ensuring resource group $ResourceGroupName ($Location)"
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    Write-Ok "Created resource group"
} else {
    Write-Ok "Resource group already exists"
}

# ----- 2. Log Analytics workspace -----
Write-Step "Ensuring Log Analytics workspace $WorkspaceName"
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction SilentlyContinue
if (-not $ws) {
    $ws = New-AzOperationalInsightsWorkspace `
        -ResourceGroupName $ResourceGroupName `
        -Name              $WorkspaceName `
        -Location          $Location `
        -Sku               'PerGB2018' `
        -RetentionInDays   30
    Write-Ok "Created workspace"
} else {
    Write-Ok "Workspace already exists"
}
$workspaceResourceId = $ws.ResourceId

# ----- 3. Microsoft Sentinel onboarding -----
Write-Step "Ensuring Microsoft Sentinel is onboarded on $WorkspaceName"
$solutionName = "SecurityInsights($WorkspaceName)"
$solution = Get-AzResource `
    -ResourceGroupName $ResourceGroupName `
    -ResourceType      'Microsoft.OperationsManagement/solutions' `
    -ResourceName      $solutionName `
    -ErrorAction       SilentlyContinue
if (-not $solution) {
    New-AzResource `
        -ResourceGroupName $ResourceGroupName `
        -Location          $Location `
        -ResourceType      'Microsoft.OperationsManagement/solutions' `
        -ResourceName      $solutionName `
        -Properties        @{ workspaceResourceId = $workspaceResourceId } `
        -Plan              @{ Name = $solutionName; Publisher = 'Microsoft'; Product = 'OMSGallery/SecurityInsights'; PromotionCode = '' } `
        -Force | Out-Null
    Write-Ok "Onboarded Sentinel"
} else {
    Write-Ok "Sentinel already onboarded"
}

# ----- 4. CopilotActivity table plan = Analytics -----
Write-Step "Setting CopilotActivity table plan to Analytics"
# The Microsoft Copilot connector must be enabled in the portal first
# for the CopilotActivity table to exist in the workspace. Until then
# this PATCH fails with 404 - that's expected; the operator should
# re-run this script after enabling the connector.
$tableUri = ("https://management.azure.com$workspaceResourceId/tables/CopilotActivity?api-version=2022-10-01")
$tableBody = @{ properties = @{ plan = 'Analytics'; retentionInDays = 90 } } | ConvertTo-Json -Depth 5
try {
    $token = Get-MgmtBearerToken
    $hdrs  = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
    Invoke-RestMethod -Method Patch -Uri $tableUri -Headers $hdrs -Body $tableBody | Out-Null
    Write-Ok "Table plan set to Analytics (90-day retention)"
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        Write-Warn "CopilotActivity table not found - enable the Microsoft Copilot data connector first, then re-run this script. Skipping for now."
    } else {
        Write-Warn ("Could not set table plan: {0}" -f $_.Exception.Message)
    }
}

# ----- 5. Watchlists -----
# Uses the Microsoft.SecurityInsights REST API directly so we don't
# depend on the Az.SecurityInsights PowerShell module being installed.
$watchlistsToProvision = @(
    [pscustomobject]@{
        Alias          = 'CopilotTrustedRagSources'
        DisplayName    = 'Copilot trusted RAG sources'
        Description    = 'Approved retrieval sources (URLs / hostnames) for Microsoft 365 Copilot RAG grounding. Rows here are TRUSTED; anything else hit by Copilot ground-on is flagged by CopilotRagUntrustedSource.'
        CsvPath        = $WatchlistCsvPath
        Source         = 'CopilotTrustedRagSources.csv'
        ItemsSearchKey = 'SourceUri'
    },
    [pscustomobject]@{
        Alias          = 'CopilotApprovedPlugins'
        DisplayName    = 'Copilot approved plugins'
        Description    = 'Approved AISystemPlugin names for Microsoft 365 Copilot agents. Plugins NOT in this list and either newly seen or spiking are surfaced by the CopilotAbnormalToolUsage hunting query.'
        CsvPath        = (Join-Path $PSScriptRoot 'Watchlists\CopilotApprovedPlugins.csv')
        Source         = 'CopilotApprovedPlugins.csv'
        ItemsSearchKey = 'PluginName'
    }
)

foreach ($wl in $watchlistsToProvision) {
    Write-Step ("Provisioning watchlist {0}" -f $wl.Alias)
    if (-not (Test-Path $wl.CsvPath)) {
        throw ("Watchlist CSV not found: {0}" -f $wl.CsvPath)
    }
    $watchlistUri = ("https://management.azure.com{0}/providers/Microsoft.SecurityInsights/watchlists/{1}?api-version=2024-03-01" -f $workspaceResourceId, $wl.Alias)
    $token = Get-MgmtBearerToken
    $hdrs  = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
    $existingWatchlist = $null
    try {
        $existingWatchlist = Invoke-RestMethod -Method Get -Uri $watchlistUri -Headers $hdrs
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
    }
    if ($existingWatchlist) {
        Write-Ok "Watchlist already exists (skipping; delete it to re-seed)"
        continue
    }

    # Read CSV as plain text; strip a UTF-8 BOM if PowerShell left one in.
    $csv = [System.IO.File]::ReadAllText($wl.CsvPath, [System.Text.Encoding]::UTF8)
    if ($csv.Length -gt 0 -and [int][char]$csv[0] -eq 0xFEFF) { $csv = $csv.Substring(1) }

    $watchlistProps = [ordered]@{
        displayName          = $wl.DisplayName
        description          = $wl.Description
        source               = $wl.Source
        provider             = 'Sentinel-As-Code'
        itemsSearchKey       = $wl.ItemsSearchKey
        contentType          = 'text/csv'
        numberOfLinesToSkip  = 0
        rawContent           = [string]$csv
    }
    $watchlistBody = ([ordered]@{ properties = $watchlistProps } | ConvertTo-Json -Depth 20 -Compress)
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($watchlistBody)
    try {
        Invoke-RestMethod -Method Put -Uri $watchlistUri -Headers $hdrs -Body $bodyBytes -ContentType 'application/json' | Out-Null
        Write-Ok "Watchlist provisioned"
    } catch {
        $resp = $_.Exception.Response
        if ($resp) {
            try {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $errBody = $reader.ReadToEnd()
                Write-Warn ("Watchlist PUT failed: {0}" -f $errBody)
            } catch { }
        }
        throw
    }
}

# ----- 6. Deploy ARM template (rules + hunting queries) -----
Write-Step "Deploying analytic rules and hunting queries"
if (-not (Test-Path $ArmTemplatePath)) {
    throw "ARM template not found: $ArmTemplatePath"
}
$deployName = "copilot-detections-{0:yyyyMMdd-HHmmss}" -f (Get-Date)
$deploy = New-AzResourceGroupDeployment `
    -ResourceGroupName $ResourceGroupName `
    -Name              $deployName `
    -TemplateFile      $ArmTemplatePath `
    -workspaceName     $WorkspaceName `
    -enableAnalyticRules $EnableAnalyticRules
Write-Ok ("Deployment {0} - {1}" -f $deploy.DeploymentName, $deploy.ProvisioningState)
Write-Ok ("Analytic rules deployed: {0}" -f $deploy.Outputs.analyticRuleCount.Value)
Write-Ok ("Hunting queries deployed: {0}" -f $deploy.Outputs.huntingQueryCount.Value)
Write-Ok ("Rules enabled: {0}" -f $deploy.Outputs.analyticRulesEnabled.Value)

Write-Host ""
Write-Host "Done. Next steps:" -ForegroundColor Cyan
Write-Host "  - If the table-plan step warned, enable the Microsoft Copilot data connector in the portal and re-run this script."
Write-Host "  - See Testing\Test-Scenarios.md for the per-rule organic-traffic test recipes."
