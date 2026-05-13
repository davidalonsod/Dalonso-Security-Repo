<#
.SYNOPSIS
    Deploy SigninLogs Threat Hunting ARM template with optional analytic rules
    state and auto-populated NetworkAllowlist watchlist from Entra Named Locations.

.DESCRIPTION
    Workflow:
      1. (Optional) Pulls Trusted=Yes Entra ID Named Locations via Microsoft Graph
         and flattens cidrAddress entries into the watchlist CSV.
      2. Deploys azuredeploy.json with:
           - deployAnalyticRulesEnabled  → user-selectable
           - watchlistRawContent         → built CSV (or template default if -SkipNamedLocations)

    Requires:
      - Azure CLI (az login) with Microsoft Sentinel Contributor on the workspace.
      - Graph Policy.Read.ConditionalAccess (default Az CLI scope covers this for admins).
      - MFA-authenticated session if tenant enforces "MFA for Azure" policy.

.PARAMETER EnableAnalyticRules
    Deploy analytic rules in Enabled state. Default: $true. Use -EnableAnalyticRules:$false
    or answer 'N' at the prompt to deploy them disabled.

.PARAMETER SkipNamedLocations
    Skip Graph fetch and use the template's built-in default watchlist CSV.

.EXAMPLE
    .\Deploy-SigninThreatHunting.ps1
    .\Deploy-SigninThreatHunting.ps1 -EnableAnalyticRules:$false
    .\Deploy-SigninThreatHunting.ps1 -SkipNamedLocations -EnableAnalyticRules:$false
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $WorkspaceName,
    [string] $TenantId,
    [string] $TemplateFile      = (Join-Path $PSScriptRoot 'azuredeploy.json'),
    [Nullable[bool]] $EnableAnalyticRules = $null,
    [switch] $SkipNamedLocations
)

$ErrorActionPreference = 'Stop'

# --- 1. Resolve analytic rules toggle (prompt if not provided) ---------
if ($null -eq $EnableAnalyticRules) {
    $ans = Read-Host "Deploy analytic rules in ENABLED state? (Y/n)"
    $EnableAnalyticRules = -not ($ans -match '^[nN]')
}
Write-Host "Analytic rules enabled : $EnableAnalyticRules" -ForegroundColor Cyan

# --- 2. Build watchlist CSV ---------------------------------------------
function Get-Token($resource) {
    if ($TenantId) {
        az account get-access-token --tenant $TenantId --resource $resource --query accessToken -o tsv
    } else {
        az account get-access-token --resource $resource --query accessToken -o tsv
    }
}

$csvHeader = 'IPOrRange,Description,Owner,AddedDate'
$today     = (Get-Date).ToString('yyyy-MM-dd')
$csvRows   = @()

if (-not $SkipNamedLocations) {
    Write-Host "Fetching trusted Entra Named Locations..." -ForegroundColor Cyan
    $graphToken = Get-Token 'https://graph.microsoft.com'
    if (-not $graphToken) { throw "Graph token acquisition failed. Run 'az login'." }
    $uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'
    $nls = (Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $graphToken"}).value |
        Where-Object { $_.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' -and $_.isTrusted }
    Write-Host "  Trusted IP named locations: $($nls.Count)" -ForegroundColor Green

    foreach ($nl in $nls) {
        foreach ($rng in $nl.ipRanges) {
            $cidr = $rng.cidrAddress
            if (-not $cidr) { continue }
            # CSV-escape displayName (commas, quotes)
            $desc = "Trusted Entra named location: $($nl.displayName)"
            if ($desc -match '[,"]') { $desc = '"' + ($desc -replace '"','""') + '"' }
            $csvRows += "$cidr,$desc,SOC,$today"
        }
    }
    Write-Host "  CIDR rows collected       : $($csvRows.Count)" -ForegroundColor Green
}

# Always seed RFC1918 (safe default; analytic rules ignore internal IPs anyway)
$rfc1918 = @(
    "10.0.0.0/8,RFC1918 private space,SOC,$today",
    "172.16.0.0/12,RFC1918 private space,SOC,$today",
    "192.168.0.0/16,RFC1918 private space,SOC,$today"
)
$csvRows = ($csvRows + $rfc1918) | Select-Object -Unique

$watchlistRawContent = ''
if ($csvRows.Count -gt 0) {
    $watchlistRawContent = ($csvHeader, ($csvRows -join "`r`n"), '') -join "`r`n"
    Write-Host "`nWatchlist CSV preview:" -ForegroundColor Cyan
    Write-Host $watchlistRawContent -ForegroundColor DarkGray
}

# --- 3. Deploy ARM ------------------------------------------------------
az account set --subscription $SubscriptionId | Out-Null

$paramsFile = New-TemporaryFile
$paramsObj = @{
    '$schema'        = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters     = @{
        workspace                  = @{ value = $WorkspaceName }
        deployAnalyticRulesEnabled = @{ value = [bool]$EnableAnalyticRules }
    }
}
if ($watchlistRawContent) {
    $paramsObj.parameters['watchlistRawContent'] = @{ value = $watchlistRawContent }
}
$paramsObj | ConvertTo-Json -Depth 8 | Set-Content -Path $paramsFile -Encoding utf8

$deployName = "signin-threathunting-$((Get-Date).ToString('yyyyMMddHHmmss'))"
Write-Host "`nDeploying '$deployName'..." -ForegroundColor Cyan
az deployment group create `
    --resource-group $ResourceGroup `
    --name $deployName `
    --template-file $TemplateFile `
    --parameters "@$paramsFile" `
    --output table

Remove-Item $paramsFile -ErrorAction SilentlyContinue
Write-Host "`n✅ Deployment complete." -ForegroundColor Green
