[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 5173,
    [switch]$Production,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$graphExample = Join-Path $root 'examples\imports\mcp-data-exfiltration-provenance.json'
$healthExample = Join-Path $root 'examples\imports\table-health-snapshot.json'
$url = "http://localhost:$Port/"

foreach ($path in @($graphExample, $healthExample, (Join-Path $root 'package.json'))) {
    if (-not (Test-Path $path)) {
        throw "Required demo file not found: $path"
    }
}

$node = Get-Command node -ErrorAction Stop
$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npm) {
    $npm = Get-Command npm -ErrorAction Stop
}

Write-Host 'Validating the provenance import example...'
& $node.Source (Join-Path $root 'scripts\validate.mjs') $graphExample
if ($LASTEXITCODE -ne 0) {
    throw 'The provenance import example failed validation.'
}

$snapshot = Get-Content -Raw $healthExample | ConvertFrom-Json
if ($snapshot -isnot [array] -or $snapshot.Count -eq 0) {
    throw 'The table health snapshot must be a non-empty JSON array.'
}
if (@($snapshot | Where-Object { -not $_.table }).Count -gt 0) {
    throw 'Every table health snapshot row requires a table property.'
}
Write-Host "Validated $($snapshot.Count) table-health snapshot rows."

if (-not (Test-Path (Join-Path $root 'node_modules'))) {
    Write-Host 'Installing locked dependencies...'
    & $npm.Source ci --prefix $root
    if ($LASTEXITCODE -ne 0) {
        throw 'npm ci failed.'
    }
}

$alreadyRunning = $false
try {
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
    $alreadyRunning = $response.StatusCode -eq 200
}
catch {
    $alreadyRunning = $false
}

$process = $null
if ($alreadyRunning) {
    Write-Host "Reusing the running PWA at $url"
}
else {
    $scriptName = if ($Production) { 'preview' } else { 'dev' }
    if ($Production) {
        Write-Host 'Building the production PWA...'
        & $npm.Source run build --prefix $root
        if ($LASTEXITCODE -ne 0) {
            throw 'The production build failed.'
        }
    }

    $arguments = @(
        'run',
        $scriptName,
        '--prefix',
        $root,
        '--',
        '--host',
        '127.0.0.1',
        '--port',
        $Port
    )
    $process = Start-Process `
        -FilePath $npm.Source `
        -ArgumentList $arguments `
        -WorkingDirectory $root `
        -PassThru

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Milliseconds 500
        if ($process.HasExited) {
            throw "The PWA process exited with code $($process.ExitCode)."
        }
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                $ready = $true
                break
            }
        }
        catch {
            continue
        }
    }

    if (-not $ready) {
        Stop-Process -Id $process.Id
        throw "The PWA did not become ready at $url."
    }

    Write-Host "Started the PWA. Process ID: $($process.Id)"
    Write-Host "Stop it later with: Stop-Process -Id $($process.Id)"
}

Write-Host ''
Write-Host 'YouTube demo URLs'
Write-Host "  PWA:             $url"
Write-Host "  Graph example:   ${url}examples/imports/mcp-data-exfiltration-provenance.json"
Write-Host "  Health snapshot: ${url}examples/imports/table-health-snapshot.json"
Write-Host ''
Write-Host 'Demo sequence'
Write-Host '  1. Import the MCP exfiltration graph from Graph explorer.'
Write-Host '  2. Search for export_records and inspect the evidence path.'
Write-Host '  3. Import the health snapshot from Telemetry tables.'
Write-Host '  4. Show active, delayed, stale, and no-snapshot sources.'

if (-not $NoBrowser) {
    Start-Process $url
}
