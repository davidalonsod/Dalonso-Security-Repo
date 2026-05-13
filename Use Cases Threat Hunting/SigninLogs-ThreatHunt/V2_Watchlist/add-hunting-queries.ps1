<#
.SYNOPSIS
    Parses SigninLogs-ThreatHunting.kql into discrete hunting queries and
    injects them into Analytic-Rules/azuredeploy.json as Sentinel hunting
    queries (Microsoft.OperationalInsights/workspaces/savedSearches with
    category='Hunting Queries').

    After deployment they appear in Microsoft Sentinel -> Hunting blade.
#>
[CmdletBinding()]
param(
    [string]$KqlPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'SigninLogs-ThreatHunting.kql'),
    [string]$ArmPath = (Join-Path $PSScriptRoot 'azuredeploy.json')
)

$ErrorActionPreference = 'Stop'

$kql = [System.IO.File]::ReadAllText($KqlPath)

# Split on the "// NN – TITLE" banner (================= line immediately above
# is included in the header). We parse by locating each numbered section
# header that precedes a real query.
$lines = $kql -split "`r?`n"

# A query block starts at a comment line matching: // NN – <title>
# and ends at the next such header, or the next standalone "// ======" block
# that introduces a non-query section (table of contents, banners).
$sections = New-Object System.Collections.Generic.List[object]
$current = $null
$headerRx  = '^//\s*(?<num>\d{2})\s*[–-]\s*(?<title>.+?)\s*$'
$bannerRx  = '^//\s*={5,}\s*$'

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]

    if ($line -match $headerRx) {
        $num   = $Matches['num']
        $title = $Matches['title']
        # Only accept if the preceding line is a banner (====) — avoids the
        # Table-of-Contents block at the top of the file.
        $prev = if ($i -gt 0) { $lines[$i - 1] } else { '' }
        if ($prev -match $bannerRx) {
            if ($current) { $sections.Add($current) | Out-Null }
            $current = [pscustomobject]@{
                Num    = $num
                Title  = $title
                Desc   = ''
                Mitre  = ''
                Body   = New-Object System.Collections.Generic.List[string]
                InHeader = $true
            }
            continue
        }
    }

    if (-not $current) { continue }

    if ($current.InHeader) {
        # Collect description comments until we hit the closing banner.
        if ($line -match $bannerRx) { $current.InHeader = $false; continue }
        if ($line -match '^//\s*(?<rest>.*)$') {
            $rest = $Matches['rest']
            if ($rest -match '^Logic:\s*(?<v>.+)') { $current.Desc = $Matches['v']; continue }
            if ($rest -match '^MITRE:\s*(?<v>.+)') { $current.Mitre = $Matches['v']; continue }
            if ($current.Desc -and -not ($rest -match '^(MITRE|=+)')) {
                $current.Desc += ' ' + ("$rest".Trim())
            }
            continue
        }
        # Non-comment encountered while still "in header" (shouldn't happen
        # in well-formed file): fall through to body capture.
        $current.InHeader = $false
    }

    # Body: everything between the closing banner of one section and the
    # opening banner of the next.
    $current.Body.Add($line) | Out-Null
}
if ($current) { $sections.Add($current) | Out-Null }

Write-Host "Parsed $($sections.Count) hunting queries from $KqlPath" -ForegroundColor Cyan

# Clean each body: trim leading / trailing blank lines.
$huntingResources = New-Object System.Collections.Generic.List[object]
foreach ($s in $sections) {
    $body = ($s.Body -join "`n").Trim()
    if (-not $body) { continue }
    if ($body.Length -lt 20) { continue }

    # Sentinel hunting queries live under savedSearches. Per the DataConnector
    # schema they must be placed in category "Hunting Queries". Tactics/MITRE
    # go into 'tags'. Id is a deterministic GUID from "SigninHunt-NN".
    $num   = [string]$s.Num
    $title = [string]$s.Title
    if ([string]::IsNullOrWhiteSpace($num) -or [string]::IsNullOrWhiteSpace($title)) { continue }
    # Pad title for deterministic length.
    $displayName = "SigninLogs Hunt {0:D2} - {1}" -f [int]$num, $title
    # Strip non-ASCII from title for savedSearch 'name' key.
    $safeTitle = ($title -replace '[^A-Za-z0-9]+','-') -replace '-+','-'
    $safeName  = ($num + '-' + $safeTitle).Trim('-').ToLower()
    if ($safeName.Length -gt 60) { $safeName = $safeName.Substring(0, 60) }

    $tags = @()
    if ($s.Desc) {
        # Sentinel TagValue max length is 255. Truncate with ellipsis.
        $desc = [string]$s.Desc
        if ($desc.Length -gt 255) { $desc = $desc.Substring(0, 252) + '...' }
        $tags += [pscustomobject]@{ name = 'description'; value = $desc }
    }
    if ($s.Mitre) {
        $mitre = [string]$s.Mitre
        if ($mitre.Length -gt 255) { $mitre = $mitre.Substring(0, 252) + '...' }
        $tags += [pscustomobject]@{ name = 'tactics'; value = $mitre }
    }
    # Generic markers used by the Sentinel Hunting blade.
    $tags += [pscustomobject]@{ name = 'createdBy'; value = 'SigninLogs-ThreatHunting' }
    $tags += [pscustomobject]@{ name = 'createdTimeUtc'; value = '2026-04-20T00:00:00Z' }

    $resource = [pscustomobject]@{
        type       = 'Microsoft.OperationalInsights/workspaces/savedSearches'
        apiVersion = '2020-08-01'
        name       = "[concat(parameters('workspace'), '/$safeName')]"
        dependsOn  = @(
            "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), parameters('functionAlias'))]"
        )
        properties = [pscustomobject]@{
            etag        = '*'
            displayName = $displayName
            category    = 'Hunting Queries'
            query       = $body
            version     = 2
            tags        = $tags
        }
    }
    $huntingResources.Add($resource) | Out-Null
}

Write-Host "Built $($huntingResources.Count) hunting savedSearches resources" -ForegroundColor Cyan

# Load ARM, strip any existing hunting resources (idempotent), append new ones.
$arm = Get-Content -LiteralPath $ArmPath -Raw | ConvertFrom-Json -Depth 100

$kept = @()
foreach ($r in $arm.resources) {
    if ($r.type -eq 'Microsoft.OperationalInsights/workspaces/savedSearches' -and
        $r.properties.category -eq 'Hunting Queries') { continue }
    $kept += $r
}
$kept += $huntingResources.ToArray()
$arm.resources = $kept

$json = $arm | ConvertTo-Json -Depth 100
[System.IO.File]::WriteAllText($ArmPath, $json)

# Validate.
$null = Get-Content -LiteralPath $ArmPath -Raw | ConvertFrom-Json -Depth 100
Write-Host "OK -> $ArmPath" -ForegroundColor Green

$counts = @{}
foreach ($r in (Get-Content -LiteralPath $ArmPath -Raw | ConvertFrom-Json -Depth 100).resources) {
    $key = $r.type
    if ($r.type -eq 'Microsoft.OperationalInsights/workspaces/savedSearches' -and
        $r.properties.category) {
        $key = $r.type + ' [' + $r.properties.category + ']'
    }
    $counts[$key] = ($counts[$key] + 1)
}
Write-Host "Resources:" -ForegroundColor Cyan
foreach ($k in $counts.Keys) { Write-Host ("  {0,3} x {1}" -f $counts[$k], $k) }
