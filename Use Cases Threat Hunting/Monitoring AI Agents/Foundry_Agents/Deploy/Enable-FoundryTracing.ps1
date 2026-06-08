#
# Foundry-AppInsights/Deploy/Enable-FoundryTracing.ps1
#
# Created on 03/06/2026.
#
# Connects a single Application Insights resource to every Microsoft Foundry
# (New Foundry) project across the selected subscriptions, which enables
# server-side agent tracing for ALL agents in each project at once. No agent
# code changes are required - once a project has an AppInsights connection,
# Foundry logs gen_ai.* spans into AppDependencies automatically.
#
# Safety:
#   - Runs in DRY-RUN mode by default. It only reports what it would change.
#   - Pass -Apply to actually create the connections.
#   - Idempotent: projects that already have an AppInsights connection are
#     skipped.
#
# Requirements:
#   - Az PowerShell modules: Az.Accounts (Connect-AzAccount done beforehand).
#   - The caller needs Contributor (or Cognitive Services Contributor) on the
#     Foundry accounts and Reader on the Application Insights resource.
#
# Example (preview, no changes):
#   ./Enable-FoundryTracing.ps1 `
#       -ApplicationInsightsResourceId '/subscriptions/<sub>/resourceGroups/<rg>/providers/microsoft.insights/components/<ai>'
#
# Example (apply across two subscriptions):
#   ./Enable-FoundryTracing.ps1 `
#       -ApplicationInsightsResourceId '/subscriptions/<sub>/resourceGroups/<rg>/providers/microsoft.insights/components/<ai>' `
#       -SubscriptionId 'sub-a','sub-b' -Apply
#

[CmdletBinding()]
param(
    # Full ARM resource ID of the Application Insights component to connect.
    # This MUST be the same workspace-backed App Insights that feeds your
    # Sentinel AppDependencies table, or the hunts will not see the data.
    [Parameter(Mandatory)]
    [string] $ApplicationInsightsResourceId,

    # One or more subscription IDs to scan. Defaults to the current context
    # subscription when omitted.
    [string[]] $SubscriptionId,

    # Name given to the connection created on each project.
    [string] $ConnectionName = 'appinsights-tracing',

    # Share the connection with every project member (recommended).
    [bool] $IsSharedToAll = $true,

    # API version for the CognitiveServices accounts/projects/connections path.
    [string] $ApiVersion = '2025-04-01-preview',

    # Actually create connections. Without this switch the script only reports.
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Section { param([string] $Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }

# --- Pre-flight ----------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    throw 'Az.Accounts is not installed. Run: Install-Module Az.Accounts -Scope CurrentUser'
}
$context = Get-AzContext
if (-not $context) {
    throw 'No Azure context. Run Connect-AzAccount first.'
}

if (-not $SubscriptionId) {
    $SubscriptionId = @($context.Subscription.Id)
}

Write-Section 'Resolving Application Insights connection string'
$aiResponse = Invoke-AzRestMethod -Method GET -Path "$ApplicationInsightsResourceId`?api-version=2020-02-02"
if ($aiResponse.StatusCode -ge 400) {
    throw "Could not read Application Insights resource ($($aiResponse.StatusCode)): $($aiResponse.Content)"
}
$aiProps = ($aiResponse.Content | ConvertFrom-Json).properties
$aiConnectionString = $aiProps.ConnectionString
if ([string]::IsNullOrWhiteSpace($aiConnectionString)) {
    throw 'Application Insights resource returned no ConnectionString.'
}
Write-Host "App Insights: $($ApplicationInsightsResourceId.Split('/')[-1]) (connection string resolved)" -ForegroundColor Green

# Connection body shared by every project.
$connectionBody = @{
    properties = @{
        category      = 'AppInsights'
        authType      = 'ApiKey'
        target        = $aiConnectionString
        isSharedToAll = $IsSharedToAll
        credentials   = @{ key = $aiConnectionString }
        metadata      = @{
            ApiType    = 'Azure'
            ResourceId = $ApplicationInsightsResourceId
        }
    }
} | ConvertTo-Json -Depth 8

$summary = [System.Collections.Generic.List[object]]::new()

foreach ($sub in $SubscriptionId) {
    Write-Section "Subscription $sub"
    try { Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null }
    catch { Write-Warning "Cannot switch to subscription $sub - skipping. $($_.Exception.Message)"; continue }

    # Foundry (new) accounts are CognitiveServices accounts of kind AIServices.
    $accounts = Get-AzResource -ResourceType 'Microsoft.CognitiveServices/accounts' -ExpandProperties -ErrorAction SilentlyContinue |
        Where-Object { $_.Kind -in @('AIServices', 'AIServices,OpenAI') -or $_.Kind -like 'AIServices*' }

    if (-not $accounts) {
        Write-Host 'No Foundry (AIServices) accounts found.' -ForegroundColor DarkGray
        continue
    }

    foreach ($account in $accounts) {
        # List projects under the account.
        $projPath = "$($account.ResourceId)/projects?api-version=$ApiVersion"
        $projResp = Invoke-AzRestMethod -Method GET -Path $projPath
        if ($projResp.StatusCode -ge 400) {
            Write-Warning "  $($account.Name): cannot list projects ($($projResp.StatusCode)) - account may be classic/hub. Skipping."
            continue
        }
        $projects = ($projResp.Content | ConvertFrom-Json).value
        if (-not $projects) {
            Write-Host "  $($account.Name): no projects." -ForegroundColor DarkGray
            continue
        }

        foreach ($project in $projects) {
            $projName = $project.name
            $connBase = "$($account.ResourceId)/projects/$projName/connections"

            # Does an AppInsights connection already exist?
            $listResp = Invoke-AzRestMethod -Method GET -Path "$connBase`?api-version=$ApiVersion"
            $existing = $null
            if ($listResp.StatusCode -lt 400) {
                $existing = (($listResp.Content | ConvertFrom-Json).value) |
                    Where-Object { $_.properties.category -eq 'AppInsights' } | Select-Object -First 1
            }

            if ($existing) {
                Write-Host "  [skip]  $($account.Name)/$projName already has AppInsights connection '$($existing.name)'." -ForegroundColor DarkGray
                $summary.Add([pscustomobject]@{ Account = $account.Name; Project = $projName; Action = 'AlreadyConnected'; Connection = $existing.name })
                continue
            }

            if (-not $Apply) {
                Write-Host "  [dry-run] would connect $($account.Name)/$projName -> '$ConnectionName'" -ForegroundColor Yellow
                $summary.Add([pscustomobject]@{ Account = $account.Name; Project = $projName; Action = 'WouldConnect'; Connection = $ConnectionName })
                continue
            }

            $putResp = Invoke-AzRestMethod -Method PUT `
                -Path "$connBase/$ConnectionName`?api-version=$ApiVersion" `
                -Payload $connectionBody
            if ($putResp.StatusCode -ge 400) {
                Write-Warning "  [fail]  $($account.Name)/$projName ($($putResp.StatusCode)): $($putResp.Content)"
                $summary.Add([pscustomobject]@{ Account = $account.Name; Project = $projName; Action = "Failed:$($putResp.StatusCode)"; Connection = $ConnectionName })
            }
            else {
                Write-Host "  [ok]    connected $($account.Name)/$projName -> '$ConnectionName'" -ForegroundColor Green
                $summary.Add([pscustomobject]@{ Account = $account.Name; Project = $projName; Action = 'Connected'; Connection = $ConnectionName })
            }
        }
    }
}

Write-Section 'Summary'
$summary | Format-Table -AutoSize

if (-not $Apply) {
    Write-Host "`nDRY-RUN only. Re-run with -Apply to create the connections above." -ForegroundColor Yellow
}
else {
    Write-Host "`nDone. Allow a few minutes, then run an agent and check AppDependencies for gen_ai.* spans." -ForegroundColor Green
}

# --- Optional: client-side content recording reminder --------------------
Write-Host @'

Note on prompt/response content:
  Server-side tracing captures inputs, outputs and tool calls by default,
  which is what most of the Foundry-AppInsights detections need.
  For your OWN code paths (Simulation scripts, custom agents) set these
  environment variables where the agent process runs to force content
  capture:

    $env:AZURE_TRACING_GEN_AI_CONTENT_RECORDING_ENABLED = "true"
    $env:OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT = "true"
'@ -ForegroundColor DarkCyan
