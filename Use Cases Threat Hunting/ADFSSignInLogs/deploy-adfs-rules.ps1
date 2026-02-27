#Requires -Modules Az.Accounts, Az.Resources, Az.SecurityInsights
<#
.SYNOPSIS
    Deploys ADFSSignInLogs Analytic Rules to Microsoft Sentinel.

.DESCRIPTION
    Provides two deployment modes:
      1. ARM Template  — deploys all 20 rules via azuredeploy.json (recommended for bulk deployment).
      2. YAML Rules    — deploys individual YAML rule files from the .\rules\ folder using the
                        Sentinel REST API, with full support for all rule properties including
                        customDetails, alertDetailsOverride, and incidentGrouping.

.PARAMETER SubscriptionId
    Azure Subscription ID where Sentinel is deployed.

.PARAMETER ResourceGroupName
    Resource Group containing the Log Analytics workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace that Sentinel is attached to.

.PARAMETER DeploymentMode
    "ARM"  – uses azuredeploy.json (default, fastest)
    "YAML" – deploys each .\rules\*.yaml file via REST API (richer metadata)

.PARAMETER DryRun
    Print what would be deployed without making changes.

.PARAMETER RulesPath
    Path to the directory containing YAML rule files.
    Defaults to .\rules\ relative to the script location.

.EXAMPLE
    # ARM deployment (20 rules in one operation)
    .\deploy-adfs-rules.ps1 `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName "law-sentinel-prod"

.EXAMPLE
    # YAML deployment with dry run
    .\deploy-adfs-rules.ps1 `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName "law-sentinel-prod" `
        -DeploymentMode YAML `
        -DryRun

.NOTES
    Author  : ADFS Threat Hunting Rule Pack
    Version : 1.0.0
    Updated : 2026-02-25

    Required Azure RBAC:
      - Microsoft Sentinel Contributor (on the workspace resource group)
      - Contributor (for ARM template deployment)

    Required PowerShell Modules:
      Install-Module Az.Accounts, Az.Resources, Az.SecurityInsights -Force

    Optional (required for YAML mode only):
      Install-Module powershell-yaml -Force
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string] $SubscriptionId,

    [Parameter(Mandatory)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory)]
    [string] $WorkspaceName,

    [Parameter()]
    [ValidateSet("ARM", "YAML")]
    [string] $DeploymentMode = "ARM",

    [Parameter()]
    [string] $RulesPath = "$PSScriptRoot\rules",

    [Parameter()]
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─── Banner ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "     ADFSSignInLogs — Sentinel Analytic Rules Deployer (20 Rules)     " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Workspace   : $WorkspaceName"
Write-Host "  RG          : $ResourceGroupName"
Write-Host "  Subscription: $SubscriptionId"
Write-Host "  Mode        : $DeploymentMode"
if ($DryRun) {
    Write-Host "  *** DRY RUN — no changes will be made ***" -ForegroundColor Yellow
}
Write-Host ""

# ─── Authentication ───────────────────────────────────────────────────────────
Write-Host "[1/4] Authenticating to Azure..." -ForegroundColor Green

$context = Get-AzContext
if (-not $context) {
    Connect-AzAccount
    $context = Get-AzContext
}

if ($context.Subscription.Id -ne $SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    Write-Host "      Switched to subscription: $SubscriptionId"
} else {
    Write-Host "      Already in subscription: $($context.Subscription.Name)"
}

# ─── Workspace validation ─────────────────────────────────────────────────────
Write-Host "[2/4] Validating Sentinel workspace..." -ForegroundColor Green

try {
    $workspace = Get-AzOperationalInsightsWorkspace `
        -ResourceGroupName $ResourceGroupName `
        -Name $WorkspaceName
    Write-Host "      Workspace found: $($workspace.ResourceId)"
} catch {
    Write-Error "Workspace '$WorkspaceName' not found in resource group '$ResourceGroupName'. Error: $_"
    exit 1
}

# Verify Sentinel is enabled on this workspace
$sentinelUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/" +
               "$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/" +
               "$WorkspaceName/providers/Microsoft.SecurityInsights/settings?api-version=2022-11-01"
try {
    $token         = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
    $headers       = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
    $sentinelCheck = Invoke-RestMethod -Uri $sentinelUri -Headers $headers -Method Get
    Write-Host "      Sentinel is enabled on this workspace."
} catch {
    Write-Warning "Could not verify Sentinel on workspace (may still be enabled). Continuing..."
}

# ─── Deployment ───────────────────────────────────────────────────────────────
Write-Host "[3/4] Starting deployment (Mode: $DeploymentMode)..." -ForegroundColor Green

if ($DeploymentMode -eq "ARM") {
    # ── ARM Template Deployment ────────────────────────────────────────────────
    $templatePath = "$PSScriptRoot\azuredeploy.json"
    if (-not (Test-Path $templatePath)) {
        Write-Error "ARM template not found at: $templatePath"
        exit 1
    }

    $deploymentName = "SentinelADFSRules-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $parameters     = @{ workspaceName = $WorkspaceName }

    Write-Host "      Template        : $templatePath"
    Write-Host "      Deployment name : $deploymentName"
    Write-Host "      Rules to deploy : 20 ADFS analytic rules"

    if (-not $DryRun) {
        $result = New-AzResourceGroupDeployment `
            -Name                    $deploymentName `
            -ResourceGroupName       $ResourceGroupName `
            -TemplateFile            $templatePath `
            -TemplateParameterObject $parameters `
            -Verbose

        if ($result.ProvisioningState -eq "Succeeded") {
            Write-Host "      ARM deployment succeeded." -ForegroundColor Green
        } else {
            Write-Warning "ARM deployment state: $($result.ProvisioningState)"
        }
    } else {
        Write-Host "      [DRY RUN] Would deploy ARM template: $templatePath" -ForegroundColor Yellow
        Write-Host "      [DRY RUN] Deployment name would be : $deploymentName" -ForegroundColor Yellow

        # Validate the ARM template in dry-run mode
        Write-Host "      [DRY RUN] Running template validation..." -ForegroundColor Yellow
        try {
            $validation = Test-AzResourceGroupDeployment `
                -ResourceGroupName       $ResourceGroupName `
                -TemplateFile            $templatePath `
                -TemplateParameterObject $parameters
            if ($validation) {
                Write-Warning "Template validation issues found:"
                $validation | ForEach-Object { Write-Warning "  - $($_.Message)" }
            } else {
                Write-Host "      [DRY RUN] Template validation passed." -ForegroundColor Green
            }
        } catch {
            Write-Warning "Template validation error: $_"
        }
    }

} else {
    # ── YAML Rule Deployment via REST API ──────────────────────────────────────
    if (-not (Test-Path $RulesPath)) {
        Write-Error "Rules path not found: $RulesPath"
        exit 1
    }

    $yamlFiles = Get-ChildItem -Path $RulesPath -Filter "*.yaml" | Sort-Object Name
    Write-Host "      Found $($yamlFiles.Count) rule file(s) in: $RulesPath"

    # Check for powershell-yaml module
    if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
        Write-Host "      Installing powershell-yaml module..." -ForegroundColor Yellow
        Install-Module powershell-yaml -Force -Scope CurrentUser
    }
    Import-Module powershell-yaml -ErrorAction Stop

    $token      = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
    $baseUri    = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
                  "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
                  "/providers/Microsoft.SecurityInsights/alertRules"
    $apiVersion = "2022-11-01"

    $successCount = 0
    $failCount    = 0

    foreach ($file in $yamlFiles) {
        $ruleName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        Write-Host "      Deploying: $ruleName" -NoNewline

        try {
            $yaml = Get-Content $file.FullName -Raw | ConvertFrom-Yaml

            # Map YAML query frequency/period strings to ISO 8601 durations
            function ConvertTo-ISO8601Duration ([string]$s) {
                if ($s -match "^(\d+)m$")  { return "PT$($Matches[1])M" }
                if ($s -match "^(\d+)h$")  { return "PT$($Matches[1])H" }
                if ($s -match "^(\d+)d$")  { return "P$($Matches[1])D" }
                if ($s -match "^P(T)?")    { return $s }   # already ISO 8601
                return "PT1H"
            }

            $ruleId = if ($yaml.id) { $yaml.id } else { [System.Guid]::NewGuid().ToString() }

            # Build entity mappings
            $entityMappings = @()
            if ($yaml.entityMappings) {
                foreach ($em in $yaml.entityMappings) {
                    $fieldMappings = @()
                    foreach ($fm in $em.fieldMappings) {
                        $fieldMappings += @{ identifier = $fm.identifier; columnName = $fm.columnName }
                    }
                    $entityMappings += @{ entityType = $em.entityType; fieldMappings = $fieldMappings }
                }
            }

            # Build custom details
            $customDetails = $null
            if ($yaml.customDetails) {
                $customDetails = @{}
                foreach ($key in $yaml.customDetails.Keys) {
                    $customDetails[$key] = $yaml.customDetails[$key]
                }
            }

            # Build alertDetailsOverride
            $alertDetailsOverride = $null
            if ($yaml.alertDetailsOverride) {
                $alertDetailsOverride = @{}
                if ($yaml.alertDetailsOverride.alertDisplayNameFormat) {
                    $alertDetailsOverride.alertDisplayNameFormat = $yaml.alertDetailsOverride.alertDisplayNameFormat
                }
                if ($yaml.alertDetailsOverride.alertDescriptionFormat) {
                    $alertDetailsOverride.alertDescriptionFormat = $yaml.alertDetailsOverride.alertDescriptionFormat
                }
            }

            # Build incident configuration
            $incidentConfig = @{
                createIncident        = $true
                groupingConfiguration = @{
                    enabled              = $false
                    reopenClosedIncident = $false
                    lookbackDuration     = "PT5H"
                    matchingMethod       = "AnyAlert"
                    groupByEntities      = @()
                    groupByAlertDetails  = @()
                    groupByCustomDetails = @()
                }
            }
            if ($yaml.incidentConfiguration) {
                $incidentConfig.createIncident = $yaml.incidentConfiguration.createIncident
                if ($yaml.incidentConfiguration.groupingConfiguration) {
                    $gc  = $yaml.incidentConfiguration.groupingConfiguration
                    $incidentConfig.groupingConfiguration = @{
                        enabled              = [bool]$gc.enabled
                        reopenClosedIncident = [bool]$gc.reopenClosedIncident
                        lookbackDuration     = if ($gc.lookbackDuration) { $gc.lookbackDuration } else { "PT5H" }
                        matchingMethod       = if ($gc.matchingMethod)   { $gc.matchingMethod }   else { "AnyAlert" }
                        groupByEntities      = if ($gc.groupByEntities)  { @($gc.groupByEntities) } else { @() }
                        groupByAlertDetails  = if ($gc.groupByAlertDetails)  { @($gc.groupByAlertDetails) }  else { @() }
                        groupByCustomDetails = if ($gc.groupByCustomDetails) { @($gc.groupByCustomDetails) } else { @() }
                    }
                }
            }

            # Assemble rule body
            $ruleBody = @{
                kind       = "Scheduled"
                properties = @{
                    displayName              = $yaml.name
                    description              = ($yaml.description -replace "`r`n|`n", " ").Trim()
                    severity                 = $yaml.severity
                    enabled                  = $true
                    query                    = $yaml.query
                    queryFrequency           = ConvertTo-ISO8601Duration($yaml.queryFrequency)
                    queryPeriod              = ConvertTo-ISO8601Duration($yaml.queryPeriod)
                    triggerOperator          = if ($yaml.triggerOperator -eq "gt") { "GreaterThan" } else { $yaml.triggerOperator }
                    triggerThreshold         = [int]$yaml.triggerThreshold
                    suppressionEnabled       = $false
                    suppressionDuration      = "PT5H"
                    tactics                  = if ($yaml.tactics) { @($yaml.tactics) } else { @() }
                    techniques               = if ($yaml.relevantTechniques) { @($yaml.relevantTechniques) } else { @() }
                    entityMappings           = $entityMappings
                    incidentConfiguration    = $incidentConfig
                }
            }

            if ($null -ne $customDetails)       { $ruleBody.properties.customDetails       = $customDetails }
            if ($null -ne $alertDetailsOverride) { $ruleBody.properties.alertDetailsOverride = $alertDetailsOverride }

            $ruleUri = "$baseUri/$($ruleId)?api-version=$apiVersion"
            $body    = $ruleBody | ConvertTo-Json -Depth 20 -Compress

            if (-not $DryRun) {
                $freshToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
                $headers    = @{ Authorization = "Bearer $freshToken"; "Content-Type" = "application/json" }
                $response   = Invoke-RestMethod -Uri $ruleUri -Method Put -Headers $headers -Body $body
                Write-Host "  OK ($($response.properties.severity))" -ForegroundColor Green
                $successCount++
            } else {
                Write-Host "  [DRY RUN] $($yaml.severity)" -ForegroundColor Yellow
                $successCount++
            }
        } catch {
            Write-Host "  FAILED" -ForegroundColor Red
            Write-Warning "  Error deploying '$ruleName': $_"
            $failCount++
        }
    }

    Write-Host ""
    Write-Host "      YAML deployment complete — Success: $successCount  |  Failed: $failCount"
}

# ─── Summary ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/4] Deployment complete." -ForegroundColor Green
Write-Host ""
Write-Host "  To view deployed rules in Sentinel:" -ForegroundColor Cyan
Write-Host "    Azure Portal > Microsoft Sentinel > $WorkspaceName > Analytics > Active Rules"
Write-Host ""
Write-Host "  Detection coverage (20 rules):" -ForegroundColor Cyan
Write-Host "    Severity HIGH   (12): Extranet lockout, brute→success, impossible travel," -ForegroundColor White
Write-Host "                         TOR/proxy, malicious IP, Golden SAML, stale token,"  -ForegroundColor White
Write-Host "                         ROPC/DeviceCode, ADFS→privileged, ADFS→BEC,"         -ForegroundColor White
Write-Host "                         risky user, MFA fatigue→ADFS, PIM→ADFS"              -ForegroundColor White
Write-Host "    Severity MEDIUM  (5): Password spray, low-and-slow spray, brute force,"   -ForegroundColor White
Write-Host "                         high-risk country, MFA gap, high SAML volume,"        -ForegroundColor White
Write-Host "                         legacy auth"                                           -ForegroundColor White
Write-Host ""
Write-Host "  IMPORTANT — Rule requiring customization before use:" -ForegroundColor Yellow
Write-Host "    Rule 10: ADFS Golden SAML - Unexpected Token Issuer Detected"              -ForegroundColor Yellow
Write-Host "    Edit the KnownADFSIssuers list in the rule query with your ADFS server"   -ForegroundColor Yellow
Write-Host "    federation service names (e.g., adfs.yourdomain.com)"                     -ForegroundColor Yellow
Write-Host ""
