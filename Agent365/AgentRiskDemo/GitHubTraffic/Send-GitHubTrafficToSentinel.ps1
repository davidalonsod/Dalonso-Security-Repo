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
#     -GitHubToken or env var GH_TRAFFIC_PAT (GITHUB_TOKEN is reserved in
#     GitHub Actions, so the workflow uses GH_TRAFFIC_PAT; GH_PAT and
#     GITHUB_TOKEN are also accepted as fallbacks).
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

    [string] $GitHubToken,

    [string] $AzureMonitorToken = $env:AZURE_MONITOR_TOKEN,

    [string] $ApiVersion = '2023-01-01'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Resolve the GitHub PAT. GITHUB_TOKEN is a reserved name in GitHub Actions
# (the runner injects its own token, which has no Traffic-admin rights), so
# the workflow passes the PAT under a non-reserved name. Accept the common
# names here so the script works whichever one the caller used.
if ([string]::IsNullOrWhiteSpace($GitHubToken)) {
    foreach ($name in 'GH_TRAFFIC_PAT', 'GH_PAT', 'GITHUB_TOKEN') {
        $candidate = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($candidate)) { $GitHubToken = $candidate; break }
    }
}

# Null-safe trimming: a missing env var leaves the value $null, and calling
# .Trim() on $null throws under Set-StrictMode. Only trim when present.
if ($Repository)        { $Repository        = $Repository.Trim() }
if ($GitHubToken)       { $GitHubToken       = $GitHubToken.Trim() }
if ($AzureMonitorToken) { $AzureMonitorToken = $AzureMonitorToken.Trim() }
if ($DceEndpoint)       { $DceEndpoint       = $DceEndpoint.Trim() }
if ($DcrImmutableId)    { $DcrImmutableId    = $DcrImmutableId.Trim() }

if ([string]::IsNullOrWhiteSpace($GitHubToken)) {
    throw 'No GitHub token provided. Pass -GitHubToken, or set GH_TRAFFIC_PAT (recommended in GitHub Actions) / GITHUB_TOKEN.'
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

    try {
        $resp = Invoke-RestMethod -Method Get -Uri $Url -Headers $ghHeaders
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 404) {
            throw "GitHub Traffic API returned 404 for '$Repository'. Check that -GitHubToken (or GITHUB_TOKEN) is a PAT with 'repo' scope and access to this repository's traffic metrics, and that Repository is a valid owner/repo name."
        }
        throw
    }
    $rows = @()

    foreach ($point in $resp.$BreakdownProperty) {
        $rows += [pscustomobject]@{
            TimeGenerated = ([datetime]$point.timestamp).ToString('o')
            RepoFullName  = $Repository
            MetricType    = $MetricType
            Dimension     = ''
            Title         = ''
            Count         = [int]$point.count
            Uniques       = [int]$point.uniques
        }
    }
    return $rows
}

function Get-ReferrerRows {
    # Top referral sources over the last 14 days (no per-day breakdown).
    $url = "https://api.github.com/repos/$Repository/traffic/popular/referrers"
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $rows = @()
    try {
        $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $ghHeaders
    } catch {
        Write-Warning "Could not fetch referrers for '$Repository': $($_.Exception.Message)"
        return $rows
    }
    foreach ($r in $resp) {
        $rows += [pscustomobject]@{
            TimeGenerated = $now
            RepoFullName  = $Repository
            MetricType    = 'referrer'
            Dimension     = [string]$r.referrer
            Title         = ''
            Count         = [int]$r.count
            Uniques       = [int]$r.uniques
        }
    }
    return $rows
}

function Get-PathRows {
    # Most popular content paths over the last 14 days (no per-day breakdown).
    $url = "https://api.github.com/repos/$Repository/traffic/popular/paths"
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $rows = @()
    try {
        $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $ghHeaders
    } catch {
        Write-Warning "Could not fetch popular paths for '$Repository': $($_.Exception.Message)"
        return $rows
    }
    foreach ($p in $resp) {
        $rows += [pscustomobject]@{
            TimeGenerated = $now
            RepoFullName  = $Repository
            MetricType    = 'path'
            Dimension     = [string]$p.path
            Title         = [string]$p.title
            Count         = [int]$p.count
            Uniques       = [int]$p.uniques
        }
    }
    return $rows
}

function Get-RepoStatRows {
    # Point-in-time social counts: stars, forks, watchers.
    $url = "https://api.github.com/repos/$Repository"
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $rows = @()
    try {
        $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $ghHeaders
    } catch {
        Write-Warning "Could not fetch repository stats for '$Repository': $($_.Exception.Message)"
        return $rows
    }
    $stats = @(
        @{ Type = 'stars';    Value = [int]$resp.stargazers_count }
        @{ Type = 'forks';    Value = [int]$resp.forks_count }
        @{ Type = 'watchers'; Value = [int]$resp.subscribers_count }
    )
    foreach ($s in $stats) {
        $rows += [pscustomobject]@{
            TimeGenerated = $now
            RepoFullName  = $Repository
            MetricType    = $s.Type
            Dimension     = ''
            Title         = ''
            Count         = $s.Value
            Uniques       = 0
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
$rows += Get-ReferrerRows
$rows += Get-PathRows
$rows += Get-RepoStatRows

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
