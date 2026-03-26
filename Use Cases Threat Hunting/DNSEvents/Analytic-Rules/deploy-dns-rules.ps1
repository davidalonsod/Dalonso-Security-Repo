<#
.SYNOPSIS
    Deploys Windows DNS Threat Hunting analytic rules and hunting queries to Microsoft Sentinel.

.DESCRIPTION
    Deploys 15 analytic rules and 30 hunting queries for Windows DNS threat detection
    via the Windows DNS Events via AMA data connector (ASimDnsActivityLogs table).

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace running Microsoft Sentinel.

.PARAMETER ResourceGroupName
    Resource group containing the workspace.

.PARAMETER SubscriptionId
    Azure subscription ID. Defaults to current Az context subscription.

.EXAMPLE
    .\deploy-dns-rules.ps1 -WorkspaceName "sentinel-ws" -ResourceGroupName "RG_Sentinel"

.EXAMPLE
    .\deploy-dns-rules.ps1 -WorkspaceName "sentinel-ws" -ResourceGroupName "RG_Sentinel" -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId
)

$ErrorActionPreference = 'Stop'
$TemplateFile = Join-Path $PSScriptRoot "azuredeploy.json"

# ---------------------------------------------------------------------------
# Verify Az module
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
    Write-Error "Az.Resources module not found. Install with: Install-Module Az -Scope CurrentUser"
    exit 1
}

# ---------------------------------------------------------------------------
# Set subscription context
# ---------------------------------------------------------------------------
if ($SubscriptionId) {
    Write-Host "[*] Setting subscription context: $SubscriptionId" -ForegroundColor Cyan
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
} else {
    $ctx = Get-AzContext
    if (-not $ctx) {
        Write-Error "Not logged in. Run Connect-AzAccount first."
        exit 1
    }
    $SubscriptionId = $ctx.Subscription.Id
    Write-Host "[*] Using current subscription: $SubscriptionId ($($ctx.Subscription.Name))" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Validate template file
# ---------------------------------------------------------------------------
if (-not (Test-Path $TemplateFile)) {
    Write-Error "Template file not found: $TemplateFile"
    exit 1
}

Write-Host "[*] Validating ARM template..." -ForegroundColor Cyan
try {
    $json = Get-Content $TemplateFile -Raw | ConvertFrom-Json
    $resourceCount = ($json.resources | Measure-Object).Count
    Write-Host "[+] Template valid — $resourceCount resources (15 analytic rules + 30 hunting queries)" -ForegroundColor Green
} catch {
    Write-Error "Invalid JSON in template: $_"
    exit 1
}

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
$DeploymentName = "DNS-ThreatHunting-$(Get-Date -Format 'yyyyMMddHHmmss')"

Write-Host ""
Write-Host "[*] Starting deployment: $DeploymentName" -ForegroundColor Cyan
Write-Host "    Workspace     : $WorkspaceName"
Write-Host "    ResourceGroup : $ResourceGroupName"
Write-Host "    Subscription  : $SubscriptionId"
Write-Host "    Template      : $TemplateFile"
Write-Host ""

try {
    $result = New-AzResourceGroupDeployment `
        -Name $DeploymentName `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile $TemplateFile `
        -workspaceName $WorkspaceName `
        -Verbose

    if ($result.ProvisioningState -eq 'Succeeded') {
        Write-Host ""
        Write-Host "[+] Deployment succeeded!" -ForegroundColor Green
        Write-Host ""
        Write-Host "    Deployed resources:" -ForegroundColor White
        Write-Host "      • 15 Analytic Rules  → Sentinel → Analytics → Active Rules" -ForegroundColor White
        Write-Host "      • 30 Hunting Queries → Sentinel → Hunting blade" -ForegroundColor White
        Write-Host ""
        Write-Host "    IMPORTANT — Post-deployment steps:" -ForegroundColor Yellow
        Write-Host "      1. Enable 'Windows DNS Events via AMA' data connector in Sentinel" -ForegroundColor Yellow
        Write-Host "      2. Create/assign Data Collection Rule (DCR) with DNS event XPath filters" -ForegroundColor Yellow
        Write-Host "      3. Populate 'CorporateDNS' variable in Q07, Q23 with your DNS server IPs" -ForegroundColor Yellow
        Write-Host "      4. Update 'KnownMailServers' in Q19 with your mail server hostnames" -ForegroundColor Yellow
        Write-Host "      5. Enable Windows DNS analytical log on target DNS servers" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    DCR XPath filter (recommended as minimum for Tier 1+2):" -ForegroundColor Cyan
        Write-Host "      Microsoft-Windows-DNSServer/Audit!*" -ForegroundColor Gray
        Write-Host "      Microsoft-Windows-DNSServer/Analytical!*[System[(EventID=256 or EventID=257 or EventID=260 or EventID=541)]]" -ForegroundColor Gray
    } else {
        Write-Warning "Deployment completed with state: $($result.ProvisioningState)"
    }
} catch {
    Write-Host ""
    Write-Error "Deployment failed: $_"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  - Verify workspace '$WorkspaceName' exists in resource group '$ResourceGroupName'" -ForegroundColor Yellow
    Write-Host "  - Ensure Microsoft Sentinel is enabled on the workspace" -ForegroundColor Yellow
    Write-Host "  - Check you have Sentinel Contributor role on the workspace" -ForegroundColor Yellow
    exit 1
}
