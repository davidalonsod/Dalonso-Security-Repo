<#
.SYNOPSIS
    Replaces every occurrence of the invalid KQL operator
        R !matches regex @'...'
    with the valid form
        not(R matches regex @'...')
    across:
      - Analytic-Rules/rules/*.yaml
      - Analytic-Rules/azuredeploy.json
      - Analytic-Rules/Watchlists/azuredeploy-function.json
      - SigninLogs-ThreatHunting.kql
      - SigninLogs Threat Hunting & Identity Security_v2.json  (workbook)

    Two forms are replaced:
      - raw YAML/KQL form:   !matches regex
      - JSON-escaped form:   \!matches regex  (shouldn't exist, but safe)
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$targets = @(
    @{ Path = (Get-ChildItem (Join-Path $PSScriptRoot 'rules') -Filter *.yaml).FullName; Encoding = 'utf8' }
    @{ Path = @((Join-Path $PSScriptRoot 'azuredeploy.json')); Encoding = 'utf8' }
    @{ Path = @((Join-Path $PSScriptRoot 'Watchlists\azuredeploy-function.json')); Encoding = 'utf8' }
    @{ Path = @((Join-Path $repo 'SigninLogs-ThreatHunting.kql')); Encoding = 'utf8' }
)

# Patterns (regex) -> replacements. We intentionally match the whole
# "<expr> !matches regex <literal>" head-chunk so we can wrap it in not(...).
# Three variants cover:
#   A) raw:       R !matches regex @'...$'
#   B) JSON-esc:  R !matches regex @'...\\$'    (backslash-escaped inner regex)
#   C) with ':   R !matches regex @\"...\"     (unlikely, safety)

function Convert-NotMatches {
    param([string]$Text)

    # Walk character by character to handle arbitrary regex content safely.
    # Matches the shape:  <WORD> <WS>! matches regex <WS>@ <quote> ... <quote>
    # Quote can be ' or \" (JSON-escaped).
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    $len = $Text.Length
    $count = 0
    while ($i -lt $len) {
        # Look for literal "!matches regex" preceded by whitespace and a word.
        $idx = $Text.IndexOf('!matches regex', $i)
        if ($idx -lt 0) {
            [void]$sb.Append($Text.Substring($i))
            break
        }

        # Find identifier (word) before the '!', skipping whitespace.
        $j = $idx - 1
        while ($j -ge 0 -and ($Text[$j] -eq ' ' -or $Text[$j] -eq "`t")) { $j-- }
        # j now points to last char of identifier.
        $identEnd = $j
        while ($j -ge 0 -and ($Text[$j] -match '[A-Za-z0-9_]')) { $j-- }
        $identStart = $j + 1
        if ($identStart -gt $identEnd) {
            # No identifier — skip.
            [void]$sb.Append($Text.Substring($i, $idx - $i + 1))
            $i = $idx + 1
            continue
        }
        $ident = $Text.Substring($identStart, $identEnd - $identStart + 1)

        # Now find the regex literal that follows.
        $after = $idx + '!matches regex'.Length
        $k = $after
        while ($k -lt $len -and ($Text[$k] -eq ' ' -or $Text[$k] -eq "`t")) { $k++ }
        if ($k -ge $len -or $Text[$k] -ne '@') {
            [void]$sb.Append($Text.Substring($i, $idx - $i + 1))
            $i = $idx + 1
            continue
        }
        $k++  # skip '@'

        # Detect quote: ' or \"
        $quote = $null
        $quoteLen = 0
        if ($k -lt $len -and $Text[$k] -eq "'") { $quote = "'"; $quoteLen = 1 }
        elseif ($k + 1 -lt $len -and $Text[$k] -eq '\' -and $Text[$k + 1] -eq '"') { $quote = '\"'; $quoteLen = 2 }
        elseif ($k -lt $len -and $Text[$k] -eq '"') { $quote = '"'; $quoteLen = 1 }
        else {
            [void]$sb.Append($Text.Substring($i, $idx - $i + 1))
            $i = $idx + 1
            continue
        }
        $regexStart = $k
        $k += $quoteLen
        # Scan to matching close quote. For single-quote: just find next '.
        # For \" form: find next \".  For ": find next " not preceded by backslash.
        $close = -1
        while ($k -lt $len) {
            if ($quote -eq "'" -and $Text[$k] -eq "'") { $close = $k; break }
            elseif ($quote -eq '\"' -and $k + 1 -lt $len -and $Text[$k] -eq '\' -and $Text[$k + 1] -eq '"') { $close = $k; break }
            elseif ($quote -eq '"' -and $Text[$k] -eq '"' -and ($k -eq 0 -or $Text[$k - 1] -ne '\')) { $close = $k; break }
            $k++
        }
        if ($close -lt 0) {
            [void]$sb.Append($Text.Substring($i, $idx - $i + 1))
            $i = $idx + 1
            continue
        }
        $regexEnd = $close + $quoteLen

        # Build not(<ident> matches regex @<literal>)
        $regexLiteral = $Text.Substring($regexStart, $regexEnd - $regexStart)
        $replacement  = "not($ident matches regex $regexLiteral)"

        # Emit text up to identStart
        [void]$sb.Append($Text.Substring($i, $identStart - $i))
        [void]$sb.Append($replacement)

        $i = $regexEnd
        $count++
    }
    return ,@($sb.ToString(), $count)
}

$grandTotal = 0
foreach ($t in $targets) {
    foreach ($p in $t.Path) {
        if (-not (Test-Path $p)) { continue }
        $orig = [System.IO.File]::ReadAllText($p)
        $res = Convert-NotMatches -Text $orig
        $new = $res[0]; $cnt = $res[1]
        if ($cnt -gt 0) {
            [System.IO.File]::WriteAllText($p, $new)
            Write-Host ("  fixed {0,3} occurrences  : {1}" -f $cnt, $p) -ForegroundColor Green
            $grandTotal += $cnt
        }
    }
}

# Workbook is UTF-16 LE with BOM; handle separately.
$wb = Join-Path $repo 'SigninLogs Threat Hunting & Identity Security_v2.json'
if (Test-Path $wb) {
    $orig = [System.IO.File]::ReadAllText($wb, [System.Text.Encoding]::Unicode)
    $res = Convert-NotMatches -Text $orig
    $new = $res[0]; $cnt = $res[1]
    if ($cnt -gt 0) {
        [System.IO.File]::WriteAllText($wb, $new, [System.Text.UnicodeEncoding]::new($false, $true))
        Write-Host ("  fixed {0,3} occurrences  : {1}" -f $cnt, $wb) -ForegroundColor Green
        $grandTotal += $cnt
    }
}

Write-Host ""
Write-Host "Total replacements: $grandTotal" -ForegroundColor Cyan
