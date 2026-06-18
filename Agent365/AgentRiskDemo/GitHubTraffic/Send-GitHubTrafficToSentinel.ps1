#
# Agent365/AgentRiskDemo/GitHubTraffic/Send-GitHubTrafficToSentinel.ps1
#
# Takes a daily snapshot of a GitHub repository's Traffic metrics
# (clones + views, including the per-day breakdown for the last 14 days)
# and sends it to a Microsoft Sentinel custom table (GitHubTraffic_CL)
# via the Logs Ingestion API + Data Collection Rule.
#
# Run this once per day (GitHub Actions schedule, Azure Automation, or a
# scheduled task). GitHub only keeps 14 days of Traffic data, so the
# accumulated snapshots in Sentinel are what give you a 1-year history.
#
# Duplicate per-day points (from overlapping 14-day windows) are harmless:
# de-duplicate at query time in KQL (see Workbook-GitHubTraffic.json).
#
# Auth:
#   - GitHub: a PAT with 'repo' scope (admin of the repo). Passed via
#     -GitHubToken or env var GITHUB_TOKEN.
#   - Azure:  a bearer token for https://monitor.azure.com scope. In
#     GitHub Actions this comes from azure/login (OIDC). Pass via
#     -AzureMonitorToken or env var AZURE_MONITOR_TOKEN.
#
# Created on 17/06/2026.
#

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Repository,                # owner/repo, e.g. davidalonsod/Dalonso-Security-Repo

    [Parameter(Mandatory)]
    [string] $DceEndpoint,               # DCE logs ingestion URI (bicep output dceLogsIngestionUri)

    [Parameter(Mandatory)]
    [string] $DcrImmutableId,            # bicep output dcrImmutableId

    [string] $StreamName = 'Custom-GitHubTraffic_CL',

    [string] $GitHubToken = $env:GITHUB_TOKEN,

    [string] $AzureMonitorToken = $env:AZURE_MONITOR_TOKEN,

    [string] $ApiVersion = '2023-01-01'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repository = $Repository.Trim()

if ([string]::IsNullOrWhiteSpace($GitHubToken)) {
    throw 'No GitHub token provided. Set -GitHubToken or the GITHUB_TOKEN environment variable.'
}
if ([string]::IsNullOrWhiteSpace($AzureMonitorToken)) {
    throw 'No Azure Monitor token provided. Set -AzureMonitorToken or the AZURE_MONITOR_TOKEN environment variable.'
}

$ghHeaders = @{
    Authorization          = "Bearer $GitHubToken"
    Accept                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent'           = 'Sentinel-GitHubTraffic-Snapshot'
}

function Get-TrafficRows {
    param(
        [string] $MetricType,   # 'clones' or 'views'
        [string] $Url,
        [string] $BreakdownProperty   # 'clones' or 'views' (array property in the response)
    )

    $resp = Invoke-RestMethod -Method Get -Uri $Url -Headers $ghHeaders
    $rows = @()

    foreach ($point in $resp.$BreakdownProperty) {
        $rows += [pscustomobject]@{
            TimeGenerated = ([datetime]$point.timestamp).ToString('o')
            RepoFullName  = $Repository
            MetricType    = $MetricType
            Count         = [int]$point.count
            Uniques       = [int]$point.uniques
        }
    }
    return $rows
}

Write-Host "Fetching Traffic data for $Repository ..."

$rows = @()
$rows += Get-TrafficRows -MetricType 'clones' `
    -Url "https://api.github.com/repos/$Repository/traffic/clones" `
    -BreakdownProperty 'clones'
$rows += Get-TrafficRows -MetricType 'views' `
    -Url "https://api.github.com/repos/$Repository/traffic/views" `
    -BreakdownProperty 'views'

if ($rows.Count -eq 0) {
    Write-Host 'No Traffic data points returned by GitHub. Nothing to send.'
    return
}

Write-Host "Collected $($rows.Count) data point(s). Sending to Sentinel ..."

$body = $rows | ConvertTo-Json -Depth 5 -AsArray
$uri = "$($DceEndpoint.TrimEnd('/'))/dataCollectionRules/$DcrImmutableId/streams/$StreamName`?api-version=$ApiVersion"

$ingestHeaders = @{
    Authorization  = "Bearer $AzureMonitorToken"
    'Content-Type' = 'application/json'
}

Invoke-RestMethod -Method Post -Uri $uri -Headers $ingestHeaders -Body $body | Out-Null

Write-Host "Sent $($rows.Count) row(s) to $StreamName via DCR $DcrImmutableId."
