<#
.SYNOPSIS
    Deploys AuditLogs Entra ID Sentinel content (analytic rules + hunting queries)
    to a target Log Analytics workspace.

.DESCRIPTION
    This script deploys:
      - 6 custom Analytic Rules (Scheduled) via ARM template
      - 16 Hunting Queries (savedSearches) via ARM template

    Prerequisites:
      - Az PowerShell module:  Install-Module Az -Scope CurrentUser
      - Logged in:             Connect-AzAccount
      - Appropriate RBAC:      Microsoft Sentinel Contributor on the workspace RG

.EXAMPLE
    .\Deploy-SentinelContent.ps1 -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel-prod"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory)]
    [string] $WorkspaceName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Verify Az module ───────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
    throw "Az.Resources module not found. Run: Install-Module Az -Scope CurrentUser"
}

# ── Verify login ───────────────────────────────────────────────────────────
$ctx = Get-AzContext
if (-not $ctx) {
    Write-Host "Not logged in. Running Connect-AzAccount..."
    Connect-AzAccount
}
Write-Host "Deploying as: $($ctx.Account.Id)"
Write-Host "Subscription: $($ctx.Subscription.Name) ($($ctx.Subscription.Id))"

# ── Deploy everything (6 analytic rules + 16 hunting queries) ─────────────
$template = Join-Path $scriptDir "azuredeploy.json"
if (-not (Test-Path $template)) {
    throw "Template not found: $template"
}

Write-Host "`n[ Deploying 6 Analytic Rules + 16 Hunting Queries ]"
$deploy = New-AzResourceGroupDeployment `
    -ResourceGroupName $ResourceGroupName `
    -Name "SentinelEntraID-$(Get-Date -Format 'yyyyMMddHHmm')" `
    -TemplateFile $template `
    -TemplateParameterObject @{ workspace = $WorkspaceName } `
    -Verbose

if ($deploy.ProvisioningState -eq 'Succeeded') {
    Write-Host "`nDeployment succeeded."
} else {
    Write-Warning "Deployment state: $($deploy.ProvisioningState)"
}

Write-Host "`nVerify in Sentinel:"
Write-Host "  Analytic Rules : Sentinel > Analytics > Active Rules"
Write-Host "  Hunting Queries: Sentinel > Hunting > Queries (filter: Entra ID AuditLogs)"
