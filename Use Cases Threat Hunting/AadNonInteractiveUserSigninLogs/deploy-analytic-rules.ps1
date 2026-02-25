#Requires -Modules Az.Accounts, Az.Resources, Az.SecurityInsights
<#
.SYNOPSIS
    Deploys AADNonInteractiveUserSignInLogs Analytic Rules to Microsoft Sentinel.

.DESCRIPTION
    Provides two deployment modes:
      1. ARM Template  — deploys all 23 rules via azuredeploy.json (recommended for bulk deployment).
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
    # ARM deployment (23 rules in one operation)
    .\deploy-analytic-rules.ps1 `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName "law-sentinel-prod"

.EXAMPLE
    # YAML deployment with dry run
    .\deploy-analytic-rules.ps1 `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName "law-sentinel-prod" `
        -DeploymentMode YAML `
        -DryRun

.NOTES
    Author  : AAD Threat Hunting Rule Pack
    Version : 1.0.0
    Updated : 2026-02-24

    Required Azure RBAC:
      - Microsoft Sentinel Contributor (on the workspace resource group)
      - Contributor (for ARM template deployment)

    Required PowerShell Modules:
      Install-Module Az.Accounts, Az.Resources, Az.SecurityInsights -Force
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
Write-Host "  AADNonInteractiveUserSignInLogs — Sentinel Analytic Rules Deployer  " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Workspace  : $WorkspaceName"
Write-Host "  RG         : $ResourceGroupName"
Write-Host "  Subscription: $SubscriptionId"
Write-Host "  Mode       : $DeploymentMode"
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

# Set subscription context
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

# ─── Deployment ───────────────────────────────────────────────────────────────
Write-Host "[3/4] Starting deployment (Mode: $DeploymentMode)..." -ForegroundColor Green

if ($DeploymentMode -eq "ARM") {
    # ── ARM Template Deployment ────────────────────────────────────────────────
    $templatePath = "$PSScriptRoot\azuredeploy.json"
    if (-not (Test-Path $templatePath)) {
        Write-Error "ARM template not found at: $templatePath"
        exit 1
    }

    $deploymentName = "SentinelNIRules-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $parameters     = @{ workspaceName = $WorkspaceName }

    Write-Host "      Template : $templatePath"
    Write-Host "      Deployment name: $deploymentName"

    if (-not $DryRun) {
        $result = New-AzResourceGroupDeployment `
            -Name              $deploymentName `
            -ResourceGroupName $ResourceGroupName `
            -TemplateFile      $templatePath `
            -TemplateParameterObject $parameters `
            -Verbose

        if ($result.ProvisioningState -eq "Succeeded") {
            Write-Host "      ARM deployment succeeded." -ForegroundColor Green
        } else {
            Write-Warning "ARM deployment state: $($result.ProvisioningState)"
        }
    } else {
        Write-Host "      [DRY RUN] Would deploy ARM template: $templatePath" -ForegroundColor Yellow
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

    $token    = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
    $baseUri  = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
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

            # Map query frequency/period to ISO 8601
            function ConvertTo-ISO8601Duration ([string]$s) {
                if ($s -match "^\d+m$") { return "PT$($s -replace 'm','')M" }
                if ($s -match "^\d+h$") { return "PT$($s -replace 'h','')H" }
                if ($s -match "^\d+d$") { return "P$($s -replace 'd','')D" }
                if ($s -match "^PT")    { return $s }   # already ISO 8601
                if ($s -match "^P")     { return $s }
                return "PT1H"  # default
            }

            $ruleId = if ($yaml.id) { $yaml.id } else { [System.Guid]::NewGuid().ToString() }

            # Build entity mappings array
            $entityMappings = @()
            if ($yaml.entityMappings) {
                foreach ($em in $yaml.entityMappings) {
                    $mappings = @()
                    foreach ($fm in $em.fieldMappings) {
                        $mappings += @{ identifier = $fm.identifier; columnName = $fm.columnName }
                    }
                    $entityMappings += @{ entityType = $em.entityType; fieldMappings = $mappings }
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
                    enabled               = $false
                    reopenClosedIncident  = $false
                    lookbackDuration      = "PT5H"
                    matchingMethod        = "AnyAlert"
                    groupByEntities       = @()
                    groupByAlertDetails   = @()
                    groupByCustomDetails  = @()
                }
            }
            if ($yaml.incidentConfiguration) {
                $ic = $yaml.incidentConfiguration
                $incidentConfig.createIncident = $ic.createIncident
                if ($ic.groupingConfiguration) {
                    $gc = $ic.groupingConfiguration
                    $incidentConfig.groupingConfiguration = @{
                        enabled              = $gc.enabled
                        reopenClosedIncident = $gc.reopenClosedIncident
                        lookbackDuration     = $gc.lookbackDuration
                        matchingMethod       = $gc.matchingMethod
                        groupByEntities      = if ($gc.groupByEntities) { @($gc.groupByEntities) } else { @() }
                        groupByAlertDetails  = if ($gc.groupByAlertDetails) { @($gc.groupByAlertDetails) } else { @() }
                        groupByCustomDetails = if ($gc.groupByCustomDetails) { @($gc.groupByCustomDetails) } else { @() }
                    }
                }
            }

            $body = @{
                kind       = "Scheduled"
                properties = @{
                    displayName           = $yaml.name
                    description           = ($yaml.description -replace "`n", " ").Trim()
                    severity              = $yaml.severity
                    enabled               = $true
                    query                 = $yaml.query
                    queryFrequency        = (ConvertTo-ISO8601Duration $yaml.queryFrequency.ToString())
                    queryPeriod           = (ConvertTo-ISO8601Duration $yaml.queryPeriod.ToString())
                    triggerOperator       = "GreaterThan"
                    triggerThreshold      = 0
                    suppressionEnabled    = $false
                    suppressionDuration   = "PT5H"
                    tactics               = if ($yaml.tactics) { @($yaml.tactics) } else { @() }
                    techniques            = if ($yaml.relevantTechniques) { @($yaml.relevantTechniques) } else { @() }
                    entityMappings        = $entityMappings
                    incidentConfiguration = $incidentConfig
                }
            }

            if ($customDetails) {
                $body.properties.customDetails = $customDetails
            }
            if ($alertDetailsOverride) {
                $body.properties.alertDetailsOverride = $alertDetailsOverride
            }

            $uri       = "$baseUri/$ruleId`?api-version=$apiVersion"
            $bodyJson  = $body | ConvertTo-Json -Depth 20

            if (-not $DryRun) {
                $response = Invoke-RestMethod `
                    -Method  PUT `
                    -Uri     $uri `
                    -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
                    -Body    $bodyJson

                Write-Host " ✓" -ForegroundColor Green
                $successCount++
            } else {
                Write-Host " [DRY RUN - would deploy]" -ForegroundColor Yellow
                $successCount++
            }
        } catch {
            Write-Host " ✗ FAILED" -ForegroundColor Red
            Write-Warning "    Error deploying $ruleName`: $_"
            $failCount++
        }
    }

    Write-Host ""
    Write-Host "      Deployment complete. Success: $successCount | Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
}

# ─── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/4] Deployment summary" -ForegroundColor Green
Write-Host "      Navigate to: https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade/Analytics"
Write-Host "      Workspace  : $WorkspaceName ($ResourceGroupName)"
Write-Host ""
Write-Host "  Rules deployed cover the following attack techniques:" -ForegroundColor Cyan
Write-Host "    HIGH  severity (16 rules):"
Write-Host "      • Token Theft / Refresh Token Replay from New Location"
Write-Host "      • Non-Interactive Auth → Privileged Audit Actions"
Write-Host "      • Non-Interactive Auth → Threat Intelligence Feed (TI match)"
Write-Host "      • Interactive → Non-Interactive Token Pivot"
Write-Host "      • Device Code Flow Abuse (phishing vector)"
Write-Host "      • ROPC Authentication (MFA/CA bypass)"
Write-Host "      • TOR / Anonymous Proxy Sign-Ins"
Write-Host "      • Brute Force Success (Credential Stuffing)"
Write-Host "      • MFA Fatigue Attack (push bombing)"
Write-Host "      • Stale Token After Password/Auth Change"
Write-Host "      • Account Takeover - Email Forwarding Rule (BEC)"
Write-Host "      • PIM Role Activation → Non-Interactive Admin Action"
Write-Host "      • OAuth Consent → Immediate Silent Auth (Illicit Consent)"
Write-Host "      • Non-Interactive Auth → Bulk Data Download"
Write-Host "      • Non-Interactive Auth by Identity Protection Risky Users"
Write-Host "      • Password Spray via Non-Interactive Sign-Ins"
Write-Host ""
Write-Host "    MEDIUM severity (7 rules):"
Write-Host "      • Impossible Travel (3+ countries in 1 hour)"
Write-Host "      • Legacy Authentication (MFA/CA bypass)"
Write-Host "      • High-Frequency Token Refresh (>50/hr)"
Write-Host "      • New / Rogue OAuth Application First Seen"
Write-Host "      • Service Principal from Anomalous IP Spread"
Write-Host "      • High-Risk Country Sign-Ins"
Write-Host "      • Non-Interactive Brute Force (single user)"
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Post-deployment recommendations:" -ForegroundColor Cyan
Write-Host "   1. Review HIGH-risk country list in rule 22 and adjust to your policy"
Write-Host "   2. Tune thresholds (e.g., refresh count, failure counts) per your baseline"
Write-Host "   3. Create Automation Rules to assign severity/owners to these incidents"
Write-Host "   4. Link a Playbook for ROPC and Device Code Flow rules (auto-revoke tokens)"
Write-Host "   5. Verify ThreatIntelligenceIndicator table is populated for TI-based rules"
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
