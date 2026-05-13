<#
.SYNOPSIS
    Patches SigninLogs-ThreatHunting.kql to use the ExcludeAllowlistedIPs
    saved function on every SigninLogs table scan, and prepends a setup
    banner documenting the dependency.
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'SigninLogs-ThreatHunting.kql')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Path)) {
    Write-Error "Not found: $Path"
    return
}

$bannerMarker = '// EXCLUSION LOGIC — NetworkAllowlist Watchlist'
$banner = @'
// =============================================================================
// EXCLUSION LOGIC — NetworkAllowlist Watchlist
// -----------------------------------------------------------------------------
// Every query below pipes its SigninLogs scan through ExcludeAllowlistedIPs(),
// a workspace-saved function that suppresses sign-ins from trusted IPs, CIDR
// subnets and IPv4 ranges defined in the "NetworkAllowlist" Sentinel watchlist.
//
// Prerequisites (deployed once):
//   1. Watchlist "NetworkAllowlist" with column `IPOrRange`
//      -> Analytic-Rules/Watchlists/NetworkAllowlist.csv
//      -> Analytic-Rules/Watchlists/azuredeploy-watchlist.json
//   2. Saved function "ExcludeAllowlistedIPs"
//      -> Analytic-Rules/Watchlists/azuredeploy-function.json
//
// NetworkAllowlist entries may be any of:
//   * single IPv4          (203.0.113.45)
//   * CIDR subnet          (10.0.0.0/8, 163.116.0.0/16)
//   * hyphenated IP range  (10.20.30.1-10.20.30.50)
//
// Usage inside any query:
//   SigninLogs
//   | invoke ExcludeAllowlistedIPs()
//   | where TimeGenerated > ago(1h)
//   | ...
//
// Fallback (no saved function deployed): replace `| invoke Exclude...` with
// the inline UDF in Analytic-Rules/Watchlists/README.md.
// =============================================================================

'@

$text = Get-Content -LiteralPath $Path -Raw

if ($text.Contains($bannerMarker)) {
    Write-Host "Banner already present — skipping banner insertion." -ForegroundColor DarkGray
} else {
    # Insert banner after the existing header block (first '// ====' block).
    # Find the first blank line after the opening comment block.
    $lines = $text -split "`r?`n"
    $insertAt = 0
    $inHeader = $true
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($inHeader -and $lines[$i] -match '^\s*//') { continue }
        $insertAt = $i; break
    }
    $pre = ($lines[0..($insertAt - 1)] -join "`r`n")
    $post = ($lines[$insertAt..($lines.Count - 1)] -join "`r`n")
    $text = $pre + "`r`n`r`n" + $banner + "`r`n" + $post
    Write-Host "Inserted banner at line $insertAt." -ForegroundColor Green
}

# Patch every standalone SigninLogs line. Detect both top-level and indented
# occurrences. Insert '| invoke ExcludeAllowlistedIPs()' on the next line if
# not already present.
$lines = $text -split "`r?`n"
$out   = New-Object System.Collections.Generic.List[string]
$patches = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $out.Add($line) | Out-Null
    if ($line -match '^(\s*)SigninLogs\s*$') {
        $indent = $Matches[1]
        $nextIdx = $i + 1
        while ($nextIdx -lt $lines.Count -and $lines[$nextIdx].Trim() -eq '') { $nextIdx++ }
        $nextLine = if ($nextIdx -lt $lines.Count) { $lines[$nextIdx] } else { '' }
        if ($nextLine -notmatch 'ExcludeAllowlistedIPs') {
            $out.Add("$indent| invoke ExcludeAllowlistedIPs()") | Out-Null
            $patches++
        }
    }
}
$newText = [string]::Join("`r`n", $out)
Set-Content -LiteralPath $Path -Value $newText -NoNewline:$false -Encoding utf8
Write-Host "Added `| invoke ExcludeAllowlistedIPs() after $patches SigninLogs scans." -ForegroundColor Green
