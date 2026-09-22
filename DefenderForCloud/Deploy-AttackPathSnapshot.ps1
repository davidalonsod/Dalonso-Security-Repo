<#
    Deploy-AttackPathSnapshot.ps1
    One-command stand-up of the attack-path history pipeline for the CIEM workbook.

    It:
      1. Deploys infra\attackpath-snapshot.bicep (DCE, CIEM_AttackPaths_CL table,
         DCR, Automation account + managed identity, DCR publisher role).
      2. Imports & publishes the runbook (infra\runbook\Snapshot-AttackPaths.Runbook.ps1).
      3. Creates a daily schedule and links it to the runbook.
      4. Grants the Automation identity Reader on the target subscriptions (so ARG
         returns their attack paths).
      5. Optionally runs the runbook once.

    Prereqs: Az.Accounts, Az.Resources, Az.Automation  (Install-Module Az).
             Connect-AzAccount first; you need Owner/UAA on the resource group and
             the ability to grant Reader on the target subscriptions.

    Example:
      Connect-AzAccount
      .\Deploy-AttackPathSnapshot.ps1 -ResourceGroup rg-sentinel `
          -WorkspaceName law-sentinel-prod -Location eastus `
          -ReaderScopeSubscriptionIds '<subA>','<subB>' -RunNow
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]   $ResourceGroup,
    [Parameter(Mandatory)] [string]   $WorkspaceName,
    [string]   $Location = 'eastus',
    [string]   $AutomationAccountName = 'aa-ciem-attackpaths',
    [string]   $RunbookName = 'Snapshot-AttackPaths',
    [string[]] $ReaderScopeSubscriptionIds,
    [int]      $DailyRunHourUtc = 2,
    [switch]   $RunNow
)

$ErrorActionPreference = 'Stop'
foreach ($m in 'Az.Accounts','Az.Resources','Az.Automation') {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module '$m' is required. Run: Install-Module Az -Scope CurrentUser" }
    Import-Module $m -ErrorAction Stop
}
if (-not (Get-AzContext)) { throw 'Run Connect-AzAccount first.' }

$here        = $PSScriptRoot
$bicepFile   = Join-Path $here 'infra\attackpath-snapshot.bicep'
$runbookFile = Join-Path $here 'infra\runbook\Snapshot-AttackPaths.Runbook.ps1'
foreach ($f in $bicepFile, $runbookFile) { if (-not (Test-Path $f)) { throw "Missing file: $f" } }

Write-Host '==> 1/5 Deploying infrastructure (DCE, table, DCR, Automation identity)...' -ForegroundColor Cyan
$dep = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroup -TemplateFile $bicepFile `
    -logAnalyticsWorkspaceName $WorkspaceName -location $Location -automationAccountName $AutomationAccountName `
    -Name ("ciem-attackpath-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss')) -Verbose:$false
$mi = $dep.Outputs.automationPrincipalId.Value
Write-Host ("    Automation identity: {0}" -f $mi)

Write-Host '==> 2/5 Importing & publishing the runbook...' -ForegroundColor Cyan
Import-AzAutomationRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName `
    -Name $RunbookName -Type PowerShell72 -Path $runbookFile -Published -Force | Out-Null

Write-Host '==> 3/5 Creating daily schedule and linking it...' -ForegroundColor Cyan
$start = (Get-Date).ToUniversalTime().Date.AddDays(1).AddHours($DailyRunHourUtc)
$schedName = 'Daily-AttackPathSnapshot'
$existing = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -Name $schedName -ErrorAction SilentlyContinue
if (-not $existing) {
    New-AzAutomationSchedule -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName `
        -Name $schedName -StartTime $start -DayInterval 1 -TimeZone 'UTC' | Out-Null
}
Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName `
    -RunbookName $RunbookName -ScheduleName $schedName -ErrorAction SilentlyContinue | Out-Null

Write-Host '==> 4/5 Granting the identity Reader on target subscriptions...' -ForegroundColor Cyan
if (-not $ReaderScopeSubscriptionIds) {
    $ReaderScopeSubscriptionIds = @((Get-AzContext).Subscription.Id)
    Write-Host ("    No subscriptions passed; defaulting to current: {0}" -f $ReaderScopeSubscriptionIds[0])
}
foreach ($sub in $ReaderScopeSubscriptionIds) {
    $scope = "/subscriptions/$sub"
    if (-not (Get-AzRoleAssignment -ObjectId $mi -RoleDefinitionName 'Reader' -Scope $scope -ErrorAction SilentlyContinue)) {
        New-AzRoleAssignment -ObjectId $mi -RoleDefinitionName 'Reader' -Scope $scope -ErrorAction Stop | Out-Null
        Write-Host ("    Reader granted on {0}" -f $scope)
    } else {
        Write-Host ("    Reader already present on {0}" -f $scope)
    }
}

if ($RunNow) {
    Write-Host '==> 5/5 Starting the runbook once...' -ForegroundColor Cyan
    Start-AzAutomationRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -Name $RunbookName | Out-Null
} else {
    Write-Host '==> 5/5 Skipped first run (use -RunNow to trigger one now).' -ForegroundColor Cyan
}

Write-Host ''
Write-Host 'Done. In the workbook, pick this workspace under "Workspace (history)" and set "Show history = On".' -ForegroundColor Green
Write-Host 'First-seen / resolved / history populate as daily snapshots accumulate (>=2 runs to detect a resolution).' -ForegroundColor Green
