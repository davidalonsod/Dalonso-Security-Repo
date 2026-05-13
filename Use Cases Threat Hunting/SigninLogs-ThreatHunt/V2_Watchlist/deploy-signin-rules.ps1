<#
.SYNOPSIS
    Deploy SigninLogs Analytic Rules to Microsoft Sentinel.

.DESCRIPTION
    Deploys the 10 SigninLogs analytic rules to a Sentinel workspace via:
      - ARM template deployment (default, recommended)
      - Individual YAML upload via the Sentinel REST API

.PARAMETER SubscriptionId
    Azure subscription containing the Sentinel workspace.

.PARAMETER ResourceGroupName
    Resource group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    Log Analytics workspace name where Sentinel is enabled.

.PARAMETER DeploymentMode
    "ARM"  — deploys azuredeploy.json via New-AzResourceGroupDeployment (default)
    "YAML" — pushes each YAML rule individually via Sentinel REST API

.PARAMETER DryRun
    Validates parameters and shows what would be deployed — no changes made.

.EXAMPLE
    # ARM deployment (recommended)
    .\deploy-signin-rules.ps1 `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "sentinel-rg" `
        -WorkspaceName "sentinel-workspace"

.EXAMPLE
    # Dry run preview
    .\deploy-signin-rules.ps1 `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "sentinel-rg" `
        -WorkspaceName "sentinel-workspace" `
        -DryRun

.NOTES
    Requirements:
      - Az PowerShell module (Install-Module Az)
      - At minimum: Contributor role on the Sentinel workspace
      - For YAML mode: Microsoft Sentinel Contributor role
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string] $SubscriptionId,
    [Parameter(Mandatory)][string] $ResourceGroupName,
    [Parameter(Mandatory)][string] $WorkspaceName,
    [ValidateSet("ARM","YAML")]
    [string] $DeploymentMode = "ARM",
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir   = $PSScriptRoot
$ARMTemplate = Join-Path $ScriptDir "azuredeploy.json"
$RulesDir    = Join-Path $ScriptDir "rules"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
Write-Host "`n=== SigninLogs Analytic Rules Deployment ===" -ForegroundColor Cyan
Write-Host "  Subscription : $SubscriptionId"
Write-Host "  ResourceGroup: $ResourceGroupName"
Write-Host "  Workspace    : $WorkspaceName"
Write-Host "  Mode         : $DeploymentMode"
Write-Host "  DryRun       : $($DryRun.IsPresent)"

if (-not (Test-Path $ARMTemplate)) {
    throw "ARM template not found: $ARMTemplate — run _build_signin_rules.py first."
}
$YamlFiles = Get-ChildItem -Path $RulesDir -Filter "*.yaml" | Sort-Object Name
if ($YamlFiles.Count -eq 0) {
    throw "No YAML files found in: $RulesDir"
}
Write-Host "`nFound $($YamlFiles.Count) YAML rules in $RulesDir"
$YamlFiles | ForEach-Object { Write-Host "  - $($_.Name)" }

if ($DryRun) {
    Write-Host "`n[DRY RUN] No changes will be made." -ForegroundColor Yellow
    switch ($DeploymentMode) {
        "ARM" {
            Write-Host "[DRY RUN] Would run: New-AzResourceGroupDeployment"
            Write-Host "  Template  : $ARMTemplate"
            Write-Host "  Parameters: workspace=$WorkspaceName"
        }
        "YAML" {
            Write-Host "[DRY RUN] Would upload $($YamlFiles.Count) rules via REST API"
        }
    }
    Write-Host "`n[DRY RUN] Exiting — no resources created." -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
Write-Host "`nConnecting to Azure (subscription: $SubscriptionId)..." -ForegroundColor Cyan
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx -or $ctx.Subscription.Id -ne $SubscriptionId) {
    Connect-AzAccount -SubscriptionId $SubscriptionId | Out-Null
}
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
Write-Host "  Connected as: $((Get-AzContext).Account.Id)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
switch ($DeploymentMode) {

    "ARM" {
        Write-Host "`nDeploying ARM template..." -ForegroundColor Cyan
        $DeploymentName = "signin-rules-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $result = New-AzResourceGroupDeployment `
            -Name              $DeploymentName `
            -ResourceGroupName $ResourceGroupName `
            -TemplateFile      $ARMTemplate `
            -workspace         $WorkspaceName `
            -Verbose

        if ($result.ProvisioningState -eq "Succeeded") {
            Write-Host "  ARM deployment SUCCEEDED: $DeploymentName" -ForegroundColor Green
        } else {
            throw "ARM deployment failed: $($result.ProvisioningState)"
        }
    }

    "YAML" {
        Write-Host "`nUploading rules via REST API..." -ForegroundColor Cyan
        $Token    = (Get-AzAccessToken).Token
        $Headers  = @{
            Authorization  = "Bearer $Token"
            "Content-Type" = "application/json"
        }
        $BaseUri  = "https://management.azure.com/subscriptions/$SubscriptionId" +
                    "/resourceGroups/$ResourceGroupName" +
                    "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
                    "/providers/Microsoft.SecurityInsights/alertRules"
        $ApiVer   = "2022-11-01-preview"

        $Success  = 0
        $Failed   = 0

        foreach ($YamlFile in $YamlFiles) {
            try {
                # Minimal parse: extract id and name from YAML (no external module needed)
                $raw    = Get-Content $YamlFile.FullName -Raw
                $ruleId = ($raw | Select-String -Pattern '^id:\s*(.+)' | Select-Object -First 1).Matches.Groups[1].Value.Trim()
                $name   = ($raw | Select-String -Pattern '^name:\s*"?(.+?)"?\s*$' | Select-Object -First 1).Matches.Groups[1].Value.Trim()

                # Convert YAML to a minimal ARM-like body via the REST API content
                # Best approach: use ARM properties from the azuredeploy.json we already built
                $armContent = Get-Content $ARMTemplate | ConvertFrom-Json
                $resource   = $armContent.resources | Where-Object {
                    $_.properties.displayName -like "*$($name.Replace('"',''))*" -or
                    $_.name -like "*$ruleId*"
                } | Select-Object -First 1

                if (-not $resource) {
                    throw "Could not match YAML to ARM resource for: $($YamlFile.Name)"
                }

                $body = @{
                    kind       = "Scheduled"
                    properties = $resource.properties
                } | ConvertTo-Json -Depth 20

                $Uri = "$BaseUri/$($ruleId)?api-version=$ApiVer"
                $resp = Invoke-RestMethod -Method PUT -Uri $Uri -Headers $Headers -Body $body
                Write-Host "  OK  $($YamlFile.Name)" -ForegroundColor Green
                $Success++
            }
            catch {
                Write-Host "  FAIL $($YamlFile.Name): $_" -ForegroundColor Red
                $Failed++
            }
        }

        Write-Host "`nREST API upload: $Success succeeded / $Failed failed" `
            -ForegroundColor $(if ($Failed -eq 0) {"Green"} else {"Yellow"})
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Cyan
Write-Host "  Rules deployed : $($YamlFiles.Count)"
Write-Host "  Mode           : $DeploymentMode"
Write-Host "  Workspace      : $WorkspaceName"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Verify rules in Sentinel > Analytics > Active rules"
Write-Host "  2. Review query thresholds for your environment"
Write-Host "  3. Import SigninLogs-ThreatHunting.kql into Sentinel > Hunting > Queries"
