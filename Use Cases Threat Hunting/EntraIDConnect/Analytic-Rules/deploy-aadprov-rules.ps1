#Requires -Modules Az.Accounts, Az.Resources, Az.SecurityInsights
<#
.SYNOPSIS
    Deploys the AADProvisioningLogs-ThreatHunting Sentinel pack
    (17 analytic rules + 3 watchlists + ExcludeAllowlistedIPs function).

.DESCRIPTION
    Two deployment modes (mirrors the ADFSSignInLogs pack):
      1. ARM  - deploys everything via azuredeploy.json (recommended).
      2. YAML - deploys each .\rules\*.yaml via the Sentinel REST API
                (richer for staged tuning, e.g. per-rule severity overrides).

.PARAMETER SubscriptionId
    Azure Subscription ID where Sentinel is deployed.

.PARAMETER ResourceGroupName
    Resource Group containing the Log Analytics workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace that Sentinel is attached to.

.PARAMETER DeploymentMode
    "ARM"  - uses azuredeploy.json (default).
    "YAML" - deploys each .\rules\*.yaml individually via REST API.

.PARAMETER DryRun
    Print what would be deployed without making changes.

.PARAMETER RulesPath
    Path to the directory containing YAML rule files.
    Defaults to .\rules\ relative to the script location.

.EXAMPLE
    # ARM deployment (17 rules + watchlists + function in one operation)
    .\deploy-aadprov-rules.ps1 `
        -SubscriptionId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName    "law-sentinel-prod"

.EXAMPLE
    # YAML deployment with dry run
    .\deploy-aadprov-rules.ps1 `
        -SubscriptionId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName    "law-sentinel-prod" `
        -DeploymentMode YAML `
        -DryRun

.NOTES
    Required Azure RBAC:
      - Microsoft Sentinel Contributor (on the workspace resource group)
      - Contributor (for ARM template deployment of watchlists/function)

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
    [ValidateSet('ARM','YAML')]
    [string] $DeploymentMode = 'ARM',

    [Parameter()]
    [string] $RulesPath = "$PSScriptRoot\rules",

    [Parameter()]
    [hashtable] $ArmParameters = @{},

    [Parameter()]
    [switch] $SkipHighValueAssets,

    [Parameter()]
    [switch] $SkipServiceAccounts,

    [Parameter()]
    [switch] $SkipNetworkAllowlist,

    [Parameter()]
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host ''
Write-Host '=======================================================================' -ForegroundColor Cyan
Write-Host '  AADProvisioningLogs - Sentinel Threat Hunting Pack Deployer (17)    ' -ForegroundColor Cyan
Write-Host '=======================================================================' -ForegroundColor Cyan
Write-Host "  Workspace   : $WorkspaceName"
Write-Host "  RG          : $ResourceGroupName"
Write-Host "  Subscription: $SubscriptionId"
Write-Host "  Mode        : $DeploymentMode"
if ($DryRun) { Write-Host '  *** DRY RUN - no changes will be made ***' -ForegroundColor Yellow }
Write-Host ''

# Auth
Write-Host '[1/4] Authenticating to Azure...' -ForegroundColor Green
$context = Get-AzContext
if (-not $context) { Connect-AzAccount; $context = Get-AzContext }
if ($context.Subscription.Id -ne $SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    Write-Host "      Switched to subscription: $SubscriptionId"
}

# Workspace check
Write-Host '[2/4] Validating Sentinel workspace...' -ForegroundColor Green
try {
    $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
    Write-Host "      Workspace found: $($ws.ResourceId)"
} catch {
    Write-Error "Workspace '$WorkspaceName' not found in '$ResourceGroupName'. $_"
    exit 1
}

Write-Host "[3/4] Starting deployment (Mode: $DeploymentMode)..." -ForegroundColor Green

if ($DeploymentMode -eq 'ARM') {
    $templatePath = "$PSScriptRoot\azuredeploy.json"
    if (-not (Test-Path $templatePath)) {
        Write-Error "ARM template not found at: $templatePath. Run Build-AzureDeployTemplate.ps1 first."
        exit 1
    }

    $deploymentName = "SentinelAADProv-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $parameters     = @{ workspaceName = $WorkspaceName }
    if ($SkipHighValueAssets)  { $parameters.deployHighValueAssets  = $false }
    if ($SkipServiceAccounts)  { $parameters.deployServiceAccounts  = $false }
    if ($SkipNetworkAllowlist) { $parameters.deployNetworkAllowlist = $false }
    foreach ($k in $ArmParameters.Keys) { $parameters[$k] = $ArmParameters[$k] }

    Write-Host "      Template        : $templatePath"
    Write-Host "      Deployment name : $deploymentName"
    Write-Host "      Resources       : 3 watchlists + 1 function + 17 analytic rules"
    if ($parameters.Count -gt 1) {
        Write-Host '      Parameters      :'
        $parameters.GetEnumerator() | Where-Object { $_.Key -ne 'workspaceName' } | ForEach-Object {
            Write-Host ("        {0,-26} = {1}" -f $_.Key, $_.Value)
        }
    }

    if (-not $DryRun) {
        $result = New-AzResourceGroupDeployment `
            -Name                    $deploymentName `
            -ResourceGroupName       $ResourceGroupName `
            -TemplateFile            $templatePath `
            -TemplateParameterObject $parameters `
            -Verbose
        if ($result.ProvisioningState -eq 'Succeeded') {
            Write-Host '      ARM deployment succeeded.' -ForegroundColor Green
        } else {
            Write-Warning "ARM deployment state: $($result.ProvisioningState)"
        }
    } else {
        Write-Host "      [DRY RUN] Would deploy: $templatePath" -ForegroundColor Yellow
        try {
            $validation = Test-AzResourceGroupDeployment `
                -ResourceGroupName       $ResourceGroupName `
                -TemplateFile            $templatePath `
                -TemplateParameterObject $parameters
            if ($validation) {
                Write-Warning 'Template validation issues:'
                $validation | ForEach-Object { Write-Warning "  - $($_.Message)" }
            } else {
                Write-Host '      [DRY RUN] Template validation passed.' -ForegroundColor Green
            }
        } catch {
            Write-Warning "Template validation error: $_"
        }
    }
}
else {
    # YAML mode
    if (-not (Test-Path $RulesPath)) { Write-Error "Rules path not found: $RulesPath"; exit 1 }
    if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
        Install-Module powershell-yaml -Force -Scope CurrentUser
    }
    Import-Module powershell-yaml

    $yamlFiles = Get-ChildItem -Path $RulesPath -Filter '*.yaml' | Sort-Object Name
    Write-Host "      Found $($yamlFiles.Count) rule file(s) in: $RulesPath"

    $token   = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com/').Token
    $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
               "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
               "/providers/Microsoft.SecurityInsights/alertRules"
    $apiVersion = '2022-11-01'

    function ConvertTo-Iso8601 ([string]$s) {
        if ($s -match '^(\d+)m$') { return "PT$($Matches[1])M" }
        if ($s -match '^(\d+)h$') { return "PT$($Matches[1])H" }
        if ($s -match '^(\d+)d$') { return "P$($Matches[1])D" }
        if ($s -match '^P')        { return $s }
        return 'PT1H'
    }

    $success = 0; $fail = 0
    foreach ($file in $yamlFiles) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        Write-Host "      Deploying: $name" -NoNewline
        try {
            $yaml = Get-Content $file.FullName -Raw | ConvertFrom-Yaml

            $entityMappings = @()
            if ($yaml.entityMappings) {
                foreach ($em in $yaml.entityMappings) {
                    $fm = @()
                    foreach ($f in $em.fieldMappings) {
                        $fm += @{ identifier = $f.identifier; columnName = $f.columnName }
                    }
                    $entityMappings += @{ entityType = $em.entityType; fieldMappings = $fm }
                }
            }

            $customDetails = $null
            if ($yaml.customDetails) {
                $customDetails = @{}
                foreach ($k in $yaml.customDetails.Keys) { $customDetails[$k] = $yaml.customDetails[$k] }
            }

            $alertOverride = $null
            if ($yaml.alertDetailsOverride) {
                $alertOverride = @{}
                if ($yaml.alertDetailsOverride.alertDisplayNameFormat) {
                    $alertOverride.alertDisplayNameFormat = $yaml.alertDetailsOverride.alertDisplayNameFormat
                }
                if ($yaml.alertDetailsOverride.alertDescriptionFormat) {
                    $alertOverride.alertDescriptionFormat = $yaml.alertDetailsOverride.alertDescriptionFormat
                }
            }

            $incident = @{
                createIncident = $true
                groupingConfiguration = @{
                    enabled = $false; reopenClosedIncident = $false
                    lookbackDuration = 'PT5H'; matchingMethod = 'AnyAlert'
                    groupByEntities = @(); groupByAlertDetails = @(); groupByCustomDetails = @()
                }
            }
            if ($yaml.incidentConfiguration) {
                $incident.createIncident = [bool]$yaml.incidentConfiguration.createIncident
                $gc = $yaml.incidentConfiguration.groupingConfiguration
                if ($gc) {
                    $incident.groupingConfiguration = @{
                        enabled              = [bool]$gc.enabled
                        reopenClosedIncident = [bool]$gc.reopenClosedIncident
                        lookbackDuration     = if ($gc.lookbackDuration) { $gc.lookbackDuration } else { 'PT5H' }
                        matchingMethod       = if ($gc.matchingMethod)   { $gc.matchingMethod }   else { 'AnyAlert' }
                        groupByEntities      = if ($gc.groupByEntities)      { @($gc.groupByEntities) }      else { @() }
                        groupByAlertDetails  = if ($gc.groupByAlertDetails)  { @($gc.groupByAlertDetails) }  else { @() }
                        groupByCustomDetails = if ($gc.groupByCustomDetails) { @($gc.groupByCustomDetails) } else { @() }
                    }
                }
            }

            $ruleBody = @{
                kind = 'Scheduled'
                properties = @{
                    displayName           = $yaml.name
                    description           = ($yaml.description -replace "`r`n|`n", ' ').Trim()
                    severity              = $yaml.severity
                    enabled               = $true
                    query                 = $yaml.query
                    queryFrequency        = ConvertTo-Iso8601 $yaml.queryFrequency
                    queryPeriod           = ConvertTo-Iso8601 $yaml.queryPeriod
                    triggerOperator       = if ($yaml.triggerOperator -eq 'gt') { 'GreaterThan' } else { $yaml.triggerOperator }
                    triggerThreshold      = [int]$yaml.triggerThreshold
                    suppressionEnabled    = $false
                    suppressionDuration   = 'PT5H'
                    tactics               = if ($yaml.tactics)            { @($yaml.tactics) }            else { @() }
                    techniques            = if ($yaml.relevantTechniques) { @($yaml.relevantTechniques) } else { @() }
                    entityMappings        = $entityMappings
                    incidentConfiguration = $incident
                }
            }
            if ($customDetails) { $ruleBody.properties.customDetails        = $customDetails }
            if ($alertOverride) { $ruleBody.properties.alertDetailsOverride = $alertOverride }

            $ruleId = if ($yaml.id) { $yaml.id } else { [System.Guid]::NewGuid().ToString() }
            $uri    = "$baseUri/$($ruleId)?api-version=$apiVersion"
            $body   = $ruleBody | ConvertTo-Json -Depth 20 -Compress

            if (-not $DryRun) {
                $freshToken = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com/').Token
                $headers    = @{ Authorization = "Bearer $freshToken"; 'Content-Type' = 'application/json' }
                $resp       = Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -Body $body
                Write-Host "  OK ($($resp.properties.severity))" -ForegroundColor Green
                $success++
            } else {
                Write-Host "  [DRY RUN] $($yaml.severity)" -ForegroundColor Yellow
                $success++
            }
        } catch {
            Write-Host '  FAILED' -ForegroundColor Red
            Write-Warning "  Error deploying '$name': $_"
            $fail++
        }
    }

    Write-Host ''
    Write-Host "      YAML deployment complete - Success: $success | Failed: $fail"
}

Write-Host ''
Write-Host '[4/4] Deployment complete.' -ForegroundColor Green
Write-Host ''
Write-Host '  Post-deploy actions:' -ForegroundColor Cyan
Write-Host '    1. Populate the HighValueAssets watchlist with your Entra Connect server public IPs.'
Write-Host '    2. Populate the ServiceAccounts watchlist with your Sync_* / DirSync UPNs + ObjectIds.'
Write-Host '    3. Populate the NetworkAllowlist watchlist with trusted SOC / jump-host IPs and CIDRs.'
Write-Host '    4. Run the baseline KQL queries in README.md (Tuning section) and adjust triggerThreshold per tenant.'
Write-Host ''
