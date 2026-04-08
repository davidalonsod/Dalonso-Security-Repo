<#
.SYNOPSIS
    Deploys Sentinel Data Ingestion Control pack to any Microsoft Sentinel workspace.

.DESCRIPTION
    Deploys ARM templates containing 5 analytic rules, 16 ingestion monitoring queries,
    and 11 cost optimization queries for Microsoft Sentinel. Includes automatic cleanup
    of stale savedSearches from prior deployments to prevent duplicates in Hunts blade.

.PARAMETER ResourceGroupName
    Resource group containing the Log Analytics workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace with Sentinel enabled.

.PARAMETER DailyBudgetGB
    Daily ingestion budget in GB (default: 15).

.PARAMETER CostPerGB
    Cost per GB for ingestion estimation (default: 2.76).

.PARAMETER DeploymentMode
    What to deploy: All, AnalyticRulesOnly, HuntingQueriesOnly, or CostOptimizationOnly.

.PARAMETER SkipCostOptimization
    Skip deploying cost optimization queries.

.PARAMETER SkipCleanup
    Skip cleanup of old savedSearches before deployment.

.EXAMPLE
    .\deploy.ps1 -ResourceGroupName "rg-sentinel" -WorkspaceName "MyWorkspace"

.EXAMPLE
    .\deploy.ps1 -ResourceGroupName "rg-sentinel" -WorkspaceName "MyWorkspace" -DeploymentMode CostOptimizationOnly

.EXAMPLE
    .\deploy.ps1 -ResourceGroupName "rg-sentinel" -WorkspaceName "MyWorkspace" -DailyBudgetGB 20 -CostPerGB "3.10"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,

    [Parameter()]
    [int]$DailyBudgetGB = 15,

    [Parameter()]
    [string]$CostPerGB = "2.76",

    [Parameter()]
    [ValidateSet("All", "AnalyticRulesOnly", "HuntingQueriesOnly", "CostOptimizationOnly")]
    [string]$DeploymentMode = "All",

    [Parameter()]
    [switch]$SkipCostOptimization,

    [Parameter()]
    [switch]$SkipCleanup
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- Pre-flight checks ---
Write-Host "`n[*] Sentinel Data Ingestion Control - Deployment" -ForegroundColor Cyan
Write-Host "=" * 60

# Check Az module
if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
    Write-Error "Az.Resources module not found. Install with: Install-Module -Name Az -Scope CurrentUser"
    return
}

# Check authentication
$context = Get-AzContext
if (-not $context) {
    Write-Host "[!] Not authenticated. Running Connect-AzAccount..." -ForegroundColor Yellow
    Connect-AzAccount
    $context = Get-AzContext
}
Write-Host "[+] Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))" -ForegroundColor Green

# Validate resource group
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    Write-Error "Resource group '$ResourceGroupName' not found in subscription '$($context.Subscription.Name)'."
    return
}
Write-Host "[+] Resource Group: $ResourceGroupName" -ForegroundColor Green

# Validate workspace
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction SilentlyContinue
if (-not $workspace) {
    Write-Error "Log Analytics workspace '$WorkspaceName' not found in resource group '$ResourceGroupName'."
    return
}
Write-Host "[+] Workspace: $WorkspaceName" -ForegroundColor Green

# --- Cleanup stale savedSearches ---
# Removes old savedSearches from prior deployments that may have ended up in Hunts blade
# Categories to clean: "Hunting Queries" (legacy), plus our current categories to avoid duplicates
$categoriesToClean = @("Hunting Queries", "Sentinel - Ingestion Control", "Sentinel - Cost Optimization")

if (-not $SkipCleanup) {
    Write-Host "`n[*] Cleaning up old savedSearches..." -ForegroundColor Cyan
    try {
        $savedSearches = Get-AzOperationalInsightsSavedSearch -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
        $removed = 0
        foreach ($ss in $savedSearches.Value) {
            $cat = $ss.Properties.Category
            if ($cat -in $categoriesToClean) {
                $displayName = $ss.Properties.DisplayName
                $ssId = ($ss.Id -split '/')[-1]
                Write-Host "    [-] Removing: [$cat] $displayName" -ForegroundColor DarkYellow
                Remove-AzOperationalInsightsSavedSearch `
                    -ResourceGroupName $ResourceGroupName `
                    -WorkspaceName $WorkspaceName `
                    -SavedSearchId $ssId
                $removed++
            }
        }
        if ($removed -gt 0) {
            Write-Host "    [+] Removed $removed stale savedSearches" -ForegroundColor Green
        } else {
            Write-Host "    [+] No stale savedSearches found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [!] Cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Continuing with deployment..." -ForegroundColor Yellow
    }
} else {
    Write-Host "`n[*] Skipping cleanup (-SkipCleanup)" -ForegroundColor DarkGray
}

# --- Deployment ---
$templateFile = Join-Path $scriptDir "arm-templates\azuredeploy.json"
$costOptTemplate = Join-Path $scriptDir "arm-templates\cost-optimization-queries.json"

if (-not (Test-Path $templateFile)) {
    Write-Error "Template not found: $templateFile"
    return
}

$deployAnalytic = ($DeploymentMode -eq "All" -or $DeploymentMode -eq "AnalyticRulesOnly")
$deployHunting = ($DeploymentMode -eq "All" -or $DeploymentMode -eq "HuntingQueriesOnly")
$deployCostOpt = ($DeploymentMode -eq "All" -or $DeploymentMode -eq "CostOptimizationOnly") -and (-not $SkipCostOptimization)

$deploymentParams = @{
    workspaceName        = $WorkspaceName
    workspaceResourceGroup = $ResourceGroupName
    dailyBudgetGB        = $DailyBudgetGB
    costPerGB            = $CostPerGB
    deployAnalyticRules  = $deployAnalytic
    deployHuntingQueries = $deployHunting
}

$deploymentName = "sentinel-ingestion-control-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Write-Host "`n[*] Deployment: $deploymentName" -ForegroundColor Cyan
Write-Host "    Mode: $DeploymentMode"
Write-Host "    Analytic Rules: $deployAnalytic"
Write-Host "    Hunting Queries: $deployHunting"
Write-Host "    Cost Optimization: $deployCostOpt"
Write-Host "    Daily Budget: $DailyBudgetGB GB"
Write-Host "    Cost/GB: $CostPerGB"

# --- Deploy main template (if not CostOptimizationOnly) ---
if ($DeploymentMode -ne "CostOptimizationOnly") {
    Write-Host "`n[*] Deploying main template..." -ForegroundColor Cyan
    try {
        $result = New-AzResourceGroupDeployment `
            -Name $deploymentName `
            -ResourceGroupName $ResourceGroupName `
            -TemplateFile $templateFile `
            -TemplateParameterObject $deploymentParams `
            -Verbose

        if ($result.ProvisioningState -eq "Succeeded") {
            Write-Host "[+] Main template deployed!" -ForegroundColor Green
            Write-Host "    Duration: $($result.Duration)"
            if ($deployAnalytic) {
                Write-Host "    - 5 Analytic Rules (Scheduled)" -ForegroundColor White
            }
            if ($deployHunting) {
                Write-Host "    - 16 Hunting Queries (Ingestion, Auxiliary, Retention)" -ForegroundColor White
            }
        }
        else {
            Write-Host "[!] Main template: $($result.ProvisioningState)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[X] Main template failed: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# --- Deploy cost optimization template ---
if ($deployCostOpt) {
    if (-not (Test-Path $costOptTemplate)) {
        Write-Host "[!] Cost optimization template not found: $costOptTemplate" -ForegroundColor Yellow
    }
    else {
        $costOptDeployName = "sentinel-cost-optimization-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Write-Host "`n[*] Deploying cost optimization queries..." -ForegroundColor Cyan
        
        $costOptParams = @{
            workspaceName = $WorkspaceName
            costPerGB     = $CostPerGB
        }
        
        try {
            $costResult = New-AzResourceGroupDeployment `
                -Name $costOptDeployName `
                -ResourceGroupName $ResourceGroupName `
                -TemplateFile $costOptTemplate `
                -TemplateParameterObject $costOptParams `
                -Verbose

            if ($costResult.ProvisioningState -eq "Succeeded") {
                Write-Host "[+] Cost optimization queries deployed!" -ForegroundColor Green
                Write-Host "    Duration: $($costResult.Duration)"
                Write-Host "    - 11 Cost Optimization Hunting Queries" -ForegroundColor White
                Write-Host "      Noise Detection: Process Creation, Logon Events, Syslog, NonInteractive SignIn,"
                Write-Host "                       CommonSecurityLog, Heartbeat, Repeated Values, AuditLogs"
                Write-Host "      Duplicate Data:  Cross-Table Overlap, SignIn Tables Overlap"
                Write-Host "      Summary:         Master Noise Summary with Savings Estimate"
            }
            else {
                Write-Host "[!] Cost optimization: $($costResult.ProvisioningState)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[X] Cost optimization deployment failed: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
}

Write-Host "`n[+] All deployments complete!" -ForegroundColor Green
