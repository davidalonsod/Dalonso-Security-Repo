<#
.SYNOPSIS
    Recovers YAML files corrupted by the first apply-exclusion attempt, then
    re-applies the exclusion logic correctly using literal string concat
    (so '$' characters in the replacement are treated literally).
#>
[CmdletBinding()]
param(
    [string]$RulesPath = (Join-Path $PSScriptRoot 'rules')
)

$ErrorActionPreference = 'Stop'

$headerBlock = @'
    // ---- Network Allowlist (exclude trusted IPs / CIDR / ranges) --------------
    let _allow = materialize(union isfuzzy=true (print R="" | take 0), (_GetWatchlist('NetworkAllowlist') | project R = tostring(IPOrRange)) | where isnotempty(R));
    let _allowCIDR  = toscalar(_allow | where R !matches regex @'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$' | extend R = iff(R has '/', R, strcat(R, '/32')) | summarize make_list(R));
    let _allowRange = toscalar(_allow | where R matches regex @'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$' | summarize make_list(R));
    let _ExcludeAllowlistedIPs = (T:(IPAddress:string)) {
        T
        | extend IPAddress = tostring(IPAddress)
        | where array_length(_allowCIDR) == 0 or isnull(ipv4_is_in_any_range(IPAddress, _allowCIDR)) or not(ipv4_is_in_any_range(IPAddress, _allowCIDR))
        | mv-apply _r = _allowRange to typeof(string) on (
            extend _lo = tostring(split(_r,'-')[0]), _hi = tostring(split(_r,'-')[1])
            | extend _inRange = ipv4_compare(IPAddress, _lo) >= 0 and ipv4_compare(IPAddress, _hi) <= 0
            | summarize _anyInRange = max(toint(_inRange)))
        | where isnull(_anyInRange) or _anyInRange == 0
        | project-away _anyInRange
    };
    // ---------------------------------------------------------------------------
'@

$headerEndMarker = '// ---------------------------------------------------------------------------'

$files = Get-ChildItem -Path $RulesPath -Filter *.yaml -File
Write-Host "Processing $($files.Count) rule files..." -ForegroundColor Cyan

foreach ($file in $files) {
    $text = Get-Content -LiteralPath $file.FullName -Raw

    # ----- Corruption detection via 'entityMappings' duplication --------------
    $entityCount = ([regex]::Matches($text, 'entityMappings')).Count
    $isCorrupt   = $entityCount -gt 1
    $hasMarker   = $text.Contains($headerEndMarker)

    if ($isCorrupt) {
        # Rebuild clean file: prefix (up to & incl 'query: |\n') + clean body.
        # The clean body is whatever follows the LAST header-end marker line;
        # that slice is the untouched 3rd copy of original post-query content.
        $m = [regex]::Match($text, '(?m)^query:\s*\|\s*\r?\n')
        if (-not $m.Success) { Write-Warning "  $($file.Name): cannot locate 'query: |' during recovery"; continue }
        $prefix = $text.Substring(0, $m.Index + $m.Length)

        $lastIdx = $text.LastIndexOf($headerEndMarker)
        $afterMarker = $text.Substring($lastIdx + $headerEndMarker.Length) -replace '^\r?\n', ''

        $text = $prefix + $afterMarker
        Write-Host "  recovered: $($file.Name)" -ForegroundColor Yellow
    }
    elseif ($hasMarker -and $text.Contains('_ExcludeAllowlistedIPs')) {
        Write-Host "  keep (already patched): $($file.Name)" -ForegroundColor DarkGray
        continue
    }

    # ----- Inject header (literal, no backref expansion) ----------------------
    $m = [regex]::Match($text, '(?m)^query:\s*\|\s*\r?\n')
    if (-not $m.Success) {
        Set-Content -LiteralPath $file.FullName -Value $text -NoNewline:$false -Encoding utf8
        Write-Warning "  $($file.Name): no 'query: |' block — skipped injection"
        continue
    }
    $before = $text.Substring(0, $m.Index + $m.Length)
    $after  = $text.Substring($m.Index + $m.Length)
    $text   = $before + $headerBlock + "`r`n" + $after

    # ----- Add '| invoke _ExcludeAllowlistedIPs()' after each SigninLogs ref --
    $lines = $text -split "`r?`n"
    $out = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $out.Add($line) | Out-Null
        if ($line -match '^(\s{4,})SigninLogs\s*$') {
            $indent = $Matches[1]
            $nextIdx = $i + 1
            while ($nextIdx -lt $lines.Count -and $lines[$nextIdx].Trim() -eq '') { $nextIdx++ }
            $nextLine = if ($nextIdx -lt $lines.Count) { $lines[$nextIdx] } else { '' }
            if ($nextLine -notmatch '_ExcludeAllowlistedIPs') {
                $out.Add("$indent| invoke _ExcludeAllowlistedIPs()") | Out-Null
            }
        }
    }
    $newText = [string]::Join("`r`n", $out)
    if (-not $newText.EndsWith("`n")) { $newText += "`r`n" }

    Set-Content -LiteralPath $file.FullName -Value $newText -NoNewline:$false -Encoding utf8
    Write-Host "  patched: $($file.Name)" -ForegroundColor Green
}

Write-Host "Done." -ForegroundColor Cyan
