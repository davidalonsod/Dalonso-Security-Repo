<#
.SYNOPSIS
    Patches every embedded 'query' string inside azuredeploy.json so each
    analytic rule applies the NetworkAllowlist exclusion UDF to every
    SigninLogs table scan.
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot 'azuredeploy.json')
)

$ErrorActionPreference = 'Stop'

# Header prepended to each query (flattened to \n-delimited single-string form
# matching the ARM-embedded style).
$headerLines = @(
    '// ---- Network Allowlist (exclude trusted IPs / CIDR / ranges) ----',
    'let _allow = materialize(union isfuzzy=true (print R="" | take 0), (_GetWatchlist(''NetworkAllowlist'') | project R = tostring(IPOrRange)) | where isnotempty(R));',
    'let _allowCIDR  = toscalar(_allow | where R !matches regex @''^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$'' | extend R = iff(R has ''/'', R, strcat(R, ''/32'')) | summarize make_list(R));',
    'let _allowRange = toscalar(_allow | where R matches regex @''^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$'' | summarize make_list(R));',
    'let _ExcludeAllowlistedIPs = (T:(IPAddress:string)) {',
    '    T',
    '    | extend IPAddress = tostring(IPAddress)',
    '    | where array_length(_allowCIDR) == 0 or isnull(ipv4_is_in_any_range(IPAddress, _allowCIDR)) or not(ipv4_is_in_any_range(IPAddress, _allowCIDR))',
    '    | mv-apply _r = _allowRange to typeof(string) on (',
    '        extend _lo = tostring(split(_r,''-'')[0]), _hi = tostring(split(_r,''-'')[1])',
    '        | extend _inRange = ipv4_compare(IPAddress, _lo) >= 0 and ipv4_compare(IPAddress, _hi) <= 0',
    '        | summarize _anyInRange = max(toint(_inRange)))',
    '    | where isnull(_anyInRange) or _anyInRange == 0',
    '    | project-away _anyInRange',
    '};'
)
$header = ($headerLines -join "`n") + "`n"

$marker = '_ExcludeAllowlistedIPs'

# Using raw text edits so we preserve the exact JSON formatting of azuredeploy.json.
$text = [System.IO.File]::ReadAllText($Path)

# Find each "query": "..." string (JSON-escaped) and rewrite it.
# Pattern: "query"  :  "<body>"  — body may span with escaped chars but no raw
# control chars / unescaped quotes inside JSON strings. Use a non-greedy match
# that respects escape sequences.
$pattern = '(?s)"query"\s*:\s*"((?:\\.|[^"\\])*)"'

$rx = [regex]$pattern
$queryMatches = $rx.Matches($text)
Write-Host "Found $($queryMatches.Count) embedded query strings." -ForegroundColor Cyan

# Build result from right-to-left to keep offsets stable.
for ($i = $queryMatches.Count - 1; $i -ge 0; $i--) {
    $m = $queryMatches[$i]
    $escapedBody = $m.Groups[1].Value

    # Unescape JSON string to raw KQL.
    $body = $escapedBody `
        -replace '\\"','"' `
        -replace '\\\\','\' `
        -replace '\\n',"`n" `
        -replace '\\r',"`r" `
        -replace '\\t',"`t"

    if ($body.Contains($marker)) { continue }  # already patched

    # Prepend header.
    $body = $header + $body

    # After every standalone 'SigninLogs' token, insert invoke pipe on next line.
    $bodyLines = $body -split "`n"
    $newLines = New-Object System.Collections.Generic.List[string]
    for ($j = 0; $j -lt $bodyLines.Count; $j++) {
        $bl = $bodyLines[$j]
        $newLines.Add($bl) | Out-Null
        if ($bl -match '^(\s*)SigninLogs\s*$') {
            $indent = $Matches[1]
            # Skip insertion if next non-empty line already invokes UDF.
            $nextIdx = $j + 1
            while ($nextIdx -lt $bodyLines.Count -and $bodyLines[$nextIdx].Trim() -eq '') { $nextIdx++ }
            $nextLine = if ($nextIdx -lt $bodyLines.Count) { $bodyLines[$nextIdx] } else { '' }
            if ($nextLine -notmatch $marker) {
                $newLines.Add("$indent| invoke _ExcludeAllowlistedIPs()") | Out-Null
            }
        }
    }
    $body = [string]::Join("`n", $newLines)

    # Re-escape for JSON.
    $newEscaped = $body `
        -replace '\\','\\' `
        -replace '"','\"' `
        -replace "`r",'\r' `
        -replace "`n",'\n' `
        -replace "`t",'\t'

    $replacement = '"query": "' + $newEscaped + '"'
    $text = $text.Substring(0, $m.Index) + $replacement + $text.Substring($m.Index + $m.Length)
}

[System.IO.File]::WriteAllText($Path, $text)
Write-Host "Patched: $Path" -ForegroundColor Green

# Validate JSON structure.
try {
    $null = Get-Content $Path -Raw | ConvertFrom-Json -Depth 100
    Write-Host "JSON parse: OK" -ForegroundColor Green
} catch {
    Write-Host "JSON parse FAILED: $_" -ForegroundColor Red
    throw
}
