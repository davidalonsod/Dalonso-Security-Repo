<#
.SYNOPSIS
    Deploys 20 CommonSecurityLog Sentinel Analytic Rules (Fortinet / Palo Alto / Zscaler ZIA)
    to a Microsoft Sentinel workspace via ARM template or individual YAML files.

.DESCRIPTION
    Supports two deployment modes:
      ARM  — One-shot deployment via azuredeploy.json (default, fastest)
      YAML — Per-file deployment via the Sentinel REST API (preserves all metadata)

    Prerequisites:
      Install-Module Az.Accounts, Az.Resources, Az.SecurityInsights -Force -Scope CurrentUser

.PARAMETER SubscriptionId
    Azure Subscription ID containing the target Sentinel workspace.

.PARAMETER ResourceGroupName
    Resource group name where the Log Analytics workspace resides.

.PARAMETER WorkspaceName
    Log Analytics workspace name (NOT the workspace ID).

.PARAMETER DeploymentMode
    ARM  — Deploy all rules via azuredeploy.json (default)
    YAML — Deploy each YAML file individually via REST API

.PARAMETER RulesPath
    Path to the folder containing the YAML rule files.
    Defaults to .\rules\ relative to this script's location.

.EXAMPLE
    # ARM deployment (recommended for first-time deployment)
    .\deploy-csl-rules.ps1 `
        -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod"

.EXAMPLE
    # YAML deployment (retains customDetails, incidentGrouping, etc.)
    .\deploy-csl-rules.ps1 `
        -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -DeploymentMode    YAML

.NOTES
    Author : CyberSOC Engineering
    Version: 1.0.0
    Rules  : 20 Scheduled Analytic Rules — CommonSecurityLog (CEF)
    Vendors: Fortinet FortiGate, Palo Alto Networks, Zscaler ZIA
    Required connectors: CEF/Syslog for all three vendors
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string] $SubscriptionId,

    [Parameter(Mandatory)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory)]
    [string] $WorkspaceName,

    [ValidateSet('ARM', 'YAML')]
    [string] $DeploymentMode = 'ARM',

    [string] $RulesPath = (Join-Path $PSScriptRoot 'rules')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helpers ──────────────────────────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    $border = '─' * ($Text.Length + 4)
    Write-Host "`n┌$border┐" -ForegroundColor Cyan
    Write-Host "│  $Text  │"  -ForegroundColor Cyan
    Write-Host "└$border┘`n" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "  ▶ $Text" -ForegroundColor White
}

function Write-Success {
    param([string]$Text)
    Write-Host "  ✔ $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "  ⚠ $Text" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Text)
    Write-Host "  ✖ $Text" -ForegroundColor Red
}

function Convert-IsoToTimespan {
    <# Converts ISO 8601 duration strings (PT15M, PT1H, P1D, P7D) to TimeSpan #>
    param([string]$Iso)
    switch -Regex ($Iso) {
        '^PT(\d+)M$'  { return [TimeSpan]::FromMinutes($Matches[1]) }
        '^PT(\d+)H$'  { return [TimeSpan]::FromHours($Matches[1]) }
        '^P(\d+)D$'   { return [TimeSpan]::FromDays($Matches[1]) }
        '^P(\d+)W$'   { return [TimeSpan]::FromDays($Matches[1] * 7) }
        default        { throw "Unsupported ISO 8601 duration: $Iso" }
    }
}

#endregion

#region ── Dependency check ─────────────────────────────────────────────────────

function Assert-Modules {
    $required = @('Az.Accounts', 'Az.Resources', 'Az.SecurityInsights')
    foreach ($mod in $required) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Fail "Module '$mod' not found."
            Write-Host "  Run: Install-Module $mod -Force -Scope CurrentUser" -ForegroundColor Yellow
            throw "Missing module: $mod"
        }
    }
    Write-Success 'All required Az modules present.'
}

#endregion

#region ── Authentication ────────────────────────────────────────────────────────

function Connect-ToAzure {
    param([string]$SubscriptionId)

    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if ($ctx -and $ctx.Subscription.Id -eq $SubscriptionId) {
        Write-Success "Already authenticated as '$($ctx.Account.Id)' on subscription '$SubscriptionId'."
        return
    }

    Write-Step 'Connecting to Azure (browser / device-code)…'
    Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    Write-Success "Connected to subscription '$SubscriptionId'."
}

#endregion

#region ── ARM deployment ────────────────────────────────────────────────────────

function Deploy-ViaArm {
    param(
        [string] $ResourceGroupName,
        [string] $WorkspaceName,
        [string] $ScriptRoot
    )

    $templatePath = Join-Path $ScriptRoot 'azuredeploy.json'
    if (-not (Test-Path $templatePath)) {
        throw "ARM template not found: $templatePath"
    }

    Write-Step "Deploying ARM template: $templatePath"

    $deploymentName = "CSL-Rules-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $params = @{ workspace = $WorkspaceName }

    $result = New-AzResourceGroupDeployment `
        -Name              $deploymentName `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile      $templatePath `
        -TemplateParameterObject $params `
        -Verbose:$false `
        -ErrorAction Stop

    if ($result.ProvisioningState -eq 'Succeeded') {
        Write-Success "ARM deployment '$deploymentName' succeeded."
        Write-Host "`n  Rules are now visible in:" -ForegroundColor Gray
        Write-Host "  Microsoft Sentinel → Analytics → Active rules" -ForegroundColor Gray
    }
    else {
        throw "ARM deployment '$deploymentName' ended in state: $($result.ProvisioningState)"
    }
}

#endregion

#region ── YAML per-rule deployment ─────────────────────────────────────────────

function Deploy-ViaYaml {
    param(
        [string] $SubscriptionId,
        [string] $ResourceGroupName,
        [string] $WorkspaceName,
        [string] $RulesPath
    )

    # Collect YAML rule files
    $yamlFiles = Get-ChildItem -Path $RulesPath -Filter '*.yaml' | Sort-Object Name
    if ($yamlFiles.Count -eq 0) {
        throw "No YAML rule files found in: $RulesPath"
    }
    Write-Step "Found $($yamlFiles.Count) YAML rule files in '$RulesPath'."

    # Obtain OAuth2 token for Sentinel REST API
    $token = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com/').Token
    $apiBase = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/" +
               "$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/" +
               "$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules"
    $apiVersion = '2022-11-01-preview'

    $results = [ordered]@{ Deployed = 0; Skipped = 0; Failed = 0 }
    $failedRules = [System.Collections.Generic.List[string]]::new()

    foreach ($file in $yamlFiles) {
        $ruleName = $file.BaseName
        try {
            # Parse YAML (requires pyyaml installed, or use ConvertFrom-Yaml if PS module available)
            # Fallback: use python to parse and return JSON
            $pythonExe = 'python'
            $parseScript = @"
import sys, yaml, json
with open(r'$($file.FullName)', encoding='utf-8') as f:
    d = yaml.safe_load(f)
print(json.dumps(d))
"@
            $jsonStr = & $pythonExe -c $parseScript 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Python YAML parse failed: $jsonStr"
            }
            $rule = $jsonStr | ConvertFrom-Json

            # Build REST body
            $body = @{
                kind       = 'Scheduled'
                properties = @{
                    displayName       = $rule.name
                    description       = $rule.description
                    severity          = $rule.severity
                    enabled           = $true
                    query             = $rule.query
                    queryFrequency    = $rule.queryFrequency
                    queryPeriod       = $rule.queryPeriod
                    triggerOperator   = $rule.triggerOperator
                    triggerThreshold  = $rule.triggerThreshold
                    suppressionEnabled   = $false
                    suppressionDuration  = 'PT5H'
                    tactics           = @($rule.tactics)
                    techniques        = @($rule.relevantTechniques)
                }
            }

            # Optional properties
            if ($rule.entityMappings)      { $body.properties.entityMappings      = $rule.entityMappings }
            if ($rule.customDetails)       { $body.properties.customDetails        = $rule.customDetails }
            if ($rule.alertDetailsOverride){ $body.properties.alertDetailsOverride = $rule.alertDetailsOverride }
            if ($rule.incidentConfiguration) {
                $body.properties.incidentConfiguration = $rule.incidentConfiguration
            }

            $ruleId   = $rule.id
            $uri      = "$apiBase/$ruleId`?api-version=$apiVersion"
            $headers  = @{
                'Authorization' = "Bearer $token"
                'Content-Type'  = 'application/json'
            }

            $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers `
                            -Body ($body | ConvertTo-Json -Depth 20) -ErrorAction Stop

            Write-Success "[$ruleName] deployed → '$($response.properties.displayName)'"
            $results.Deployed++
        }
        catch {
            Write-Fail "[$ruleName] FAILED: $($_.Exception.Message)"
            $failedRules.Add($ruleName)
            $results.Failed++
        }
    }

    return [PSCustomObject]$results, $failedRules
}

#endregion

#region ── Main ──────────────────────────────────────────────────────────────────

Write-Header 'CommonSecurityLog Sentinel Analytic Rules Deployer'
Write-Host "  Deployment mode : $DeploymentMode" -ForegroundColor Gray
Write-Host "  Subscription    : $SubscriptionId" -ForegroundColor Gray
Write-Host "  Resource Group  : $ResourceGroupName" -ForegroundColor Gray
Write-Host "  Workspace       : $WorkspaceName`n" -ForegroundColor Gray

Assert-Modules
Connect-ToAzure -SubscriptionId $SubscriptionId

switch ($DeploymentMode) {
    'ARM' {
        Write-Header 'ARM Template Deployment'
        Deploy-ViaArm -ResourceGroupName $ResourceGroupName `
                      -WorkspaceName $WorkspaceName `
                      -ScriptRoot $PSScriptRoot
    }

    'YAML' {
        Write-Header 'YAML Per-Rule REST API Deployment'

        if (-not (Test-Path $RulesPath)) {
            throw "Rules folder not found: $RulesPath"
        }

        $results, $failedRules = Deploy-ViaYaml `
            -SubscriptionId    $SubscriptionId `
            -ResourceGroupName $ResourceGroupName `
            -WorkspaceName     $WorkspaceName `
            -RulesPath         $RulesPath

        Write-Header 'Deployment Summary'
        Write-Host "  Deployed : $($results.Deployed)" -ForegroundColor Green
        Write-Host "  Failed   : $($results.Failed)"   -ForegroundColor $(if ($results.Failed -gt 0) { 'Red' } else { 'Green' })

        if ($failedRules.Count -gt 0) {
            Write-Host "`n  Failed rules:" -ForegroundColor Red
            $failedRules | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
        }
    }
}

Write-Host ''
Write-Success 'Deployment complete. Verify rules in Microsoft Sentinel → Analytics → Active rules.'
Write-Host ''

#endregion
