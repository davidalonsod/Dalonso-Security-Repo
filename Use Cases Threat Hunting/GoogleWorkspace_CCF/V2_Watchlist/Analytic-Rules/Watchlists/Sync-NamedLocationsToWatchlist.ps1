<#
.SYNOPSIS
    Sync trusted Entra ID Named Locations into a Sentinel watchlist.

.DESCRIPTION
    Pulls all ipNamedLocation entries from Microsoft Graph where isTrusted=true,
    flattens each CIDR range into its own row, and bulk-replaces the watchlist
    items via the Sentinel REST API.

    Watchlist columns produced: IPOrRange, Name, Description

.PARAMETER WatchlistAlias
    The alias (not display name) of the target watchlist. Find it in
    Sentinel > Watchlists > select watchlist > "Watchlist alias" field.

.EXAMPLE
    .\Sync-NamedLocationsToWatchlist.ps1 -WatchlistAlias NetworkAllowlist -WhatIf
    .\Sync-NamedLocationsToWatchlist.ps1 -WatchlistAlias NetworkAllowlist
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $WatchlistAlias,
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $WorkspaceName,
    [string] $TenantId,
    # Service-principal auth (bypasses interactive MFA / CA on user accounts)
    [string] $ClientId,
    [string] $ClientSecret,
    # Managed-identity auth (use when running inside Azure Automation / Function /
    # VM with a system- or user-assigned identity). For user-assigned, also pass -ClientId.
    [switch] $UseManagedIdentity
)

$ErrorActionPreference = 'Stop'

# When running inside Azure Automation with -ClientId/-TenantId but no
# -ClientSecret, pull the secret from an encrypted Automation Variable
# named 'SpClientSecret'. Lets you store the secret once and avoid passing
# it in job-schedule parameters (which are visible in the portal).
if ($ClientId -and $TenantId -and -not $ClientSecret) {
    try {
        $ClientSecret = Get-AutomationVariable -Name 'SpClientSecret' -ErrorAction Stop
    } catch {
        # Not running in Automation, or variable missing — leave empty.
    }
}

$Script:UseSp = [bool]($ClientId -and $ClientSecret -and $TenantId) -and -not $UseManagedIdentity
$Script:UseMi = [bool]$UseManagedIdentity

# --- Auth ---------------------------------------------------------------
function Get-SpToken {
    param([Parameter(Mandatory)][string]$Resource)
    # Resource-style ('https://graph.microsoft.com') -> v2 scope ('.../.default')
    $scope = if ($Resource -match '/$') { "$Resource.default" } else { "$Resource/.default" }
    $body  = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        grant_type    = 'client_credentials'
        scope         = $scope
    }
    $resp = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -ContentType 'application/x-www-form-urlencoded' -Body $body
    return $resp.access_token
}

function Get-MiToken {
    param([Parameter(Mandatory)][string]$Resource)
    # IMDS endpoint inside any Azure compute (Automation sandbox, Function, VM, AKS).
    # User-assigned identity: pass -ClientId at script invocation.
    $r = $Resource.TrimEnd('/')
    $uri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$r"
    if ($ClientId) { $uri += "&client_id=$ClientId" }
    $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Metadata = 'true' }
    return $resp.access_token
}

function Get-Token($resource) {
    if ($Script:UseMi) {
        try { return Get-MiToken -Resource $resource } catch { return $null }
    }
    if ($Script:UseSp) {
        try { return Get-SpToken -Resource $resource } catch { return $null }
    }
    $tok = $null
    try {
        if ($TenantId) {
            $tok = az account get-access-token --tenant $TenantId --resource $resource --query accessToken -o tsv 2>$null
        } else {
            $tok = az account get-access-token --resource $resource --query accessToken -o tsv 2>$null
        }
    } catch { $tok = $null }
    if (-not $tok -or $LASTEXITCODE -ne 0) { $global:LASTEXITCODE = 0; return $null }
    return $tok
}

function Invoke-AzLoginWithMfa {
    if ($Script:UseMi) {
        Write-Host "Managed-identity auth in use; cannot interactively re-login." -ForegroundColor DarkGray
        return
    }
    if ($Script:UseSp) {
        # SP auth path: nothing to do (tokens fetched per-call). Just no-op.
        Write-Host "Service-principal auth in use; skipping interactive login." -ForegroundColor DarkGray
        return
    }
    Write-Host "Re-authenticating with MFA..." -ForegroundColor Yellow
    # Suppress "no active accounts" errors when nothing is logged in.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { az logout        2>&1 | Out-Null } catch {}
    try { az account clear 2>&1 | Out-Null } catch {}
    $global:LASTEXITCODE = 0
    $ErrorActionPreference = $prevEAP

    $loginArgs = @('login', '--allow-no-subscriptions', '--scope', 'https://management.azure.com/.default')
    if ($TenantId) { $loginArgs += @('--tenant', $TenantId) }

    Write-Host "Attempting interactive browser login..." -ForegroundColor Cyan
    & az @loginArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Browser login failed or unavailable. Falling back to device code flow." -ForegroundColor Yellow
        Write-Host "Open the URL below and enter the code shown:" -ForegroundColor Yellow
        & az @loginArgs --use-device-code
        if ($LASTEXITCODE -ne 0) { throw "az login failed (both browser and device code flows)." }
    }

    if ($SubscriptionId) {
        az account set --subscription $SubscriptionId
        if ($LASTEXITCODE -ne 0) { throw "az account set --subscription $SubscriptionId failed." }
    }
}

function Invoke-GraphWithReauth {
    param([string] $Uri, [string] $Method = 'GET', $Body)
    for ($i = 0; $i -lt 2; $i++) {
        try {
            $tok = Get-Token 'https://graph.microsoft.com'
            if (-not $tok) {
                if ($i -eq 0) { Write-Host "No Graph token available. Forcing re-login..." -ForegroundColor Yellow; Invoke-AzLoginWithMfa; continue }
                throw "Unable to acquire Graph token after re-login."
            }
            $hdr = @{ Authorization = "Bearer $tok"; 'Content-Type' = 'application/json' }
            if ($Body) { return Invoke-RestMethod -Uri $Uri -Headers $hdr -Method $Method -Body $Body }
            else       { return Invoke-RestMethod -Uri $Uri -Headers $hdr -Method $Method }
        } catch {
            $code = $null
            try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            $msg = "$($_.ErrorDetails.Message) $($_.Exception.Message)"
            $mfa = $msg -match 'RequestDisallowedByAzure' -or $msg -match 'MFA'
            if ($i -eq 0 -and ($code -eq 401 -or $code -eq 403 -or $mfa)) {
                Write-Host "Graph call rejected (code=$code, mfa=$mfa). Forcing re-login..." -ForegroundColor Yellow
                Invoke-AzLoginWithMfa
                continue
            }
            throw
        }
    }
}

function Invoke-ArmWithReauth {
    param([string] $Uri, [string] $Method = 'GET', $Body)
    for ($i = 0; $i -lt 2; $i++) {
        try {
            $tok = Get-Token 'https://management.azure.com'
            if (-not $tok) {
                if ($i -eq 0) { Write-Host "No ARM token available. Forcing re-login..." -ForegroundColor Yellow; Invoke-AzLoginWithMfa; continue }
                throw "Unable to acquire ARM token after re-login."
            }
            $hdr = @{ Authorization = "Bearer $tok"; 'Content-Type' = 'application/json' }
            if ($Body) { return Invoke-RestMethod -Uri $Uri -Headers $hdr -Method $Method -Body $Body }
            else       { return Invoke-RestMethod -Uri $Uri -Headers $hdr -Method $Method }
        } catch {
            $code = $null
            try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            $msg = "$($_.ErrorDetails.Message) $($_.Exception.Message)"
            $mfa = $msg -match 'RequestDisallowedByAzure' -or $msg -match 'MFA'
            if ($i -eq 0 -and ($code -eq 401 -or $code -eq 403 -or $mfa)) {
                Write-Host "ARM call rejected (code=$code, mfa=$mfa). Forcing re-login..." -ForegroundColor Yellow
                Invoke-AzLoginWithMfa
                continue
            }
            throw
        }
    }
}

# Pre-flight: ensure az has an active account before any Graph/ARM call
if ($Script:UseMi) {
    $miKind = if ($ClientId) { "user-assigned ($ClientId)" } else { "system-assigned" }
    Write-Host "Auth mode: managed identity $miKind" -ForegroundColor Cyan
} elseif ($Script:UseSp) {
    Write-Host "Auth mode: service principal ($ClientId @ tenant $TenantId)" -ForegroundColor Cyan
} else {
    $acct = $null
    try { $acct = az account show 2>$null } catch { $acct = $null }
    if (-not $acct -or $LASTEXITCODE -ne 0) {
        $global:LASTEXITCODE = 0
        Write-Host "No active az account detected." -ForegroundColor Yellow
        Invoke-AzLoginWithMfa
    }
}

# --- 1. Fetch trusted IP Named Locations from Graph ---------------------
Write-Host "Fetching trusted Named Locations..." -ForegroundColor Cyan
$nlUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
$nls   = (Invoke-GraphWithReauth -Uri $nlUri).value |
    Where-Object { $_.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' -and $_.isTrusted }

Write-Host "  Trusted IP named locations: $($nls.Count)" -ForegroundColor Green

# --- 2. Flatten to (IPRange, Name, Description) rows --------------------
$rows = foreach ($nl in $nls) {
    foreach ($rng in $nl.ipRanges) {
        $cidr = $rng.cidrAddress
        if ($cidr) {
            [pscustomobject]@{
                IPOrRange   = $cidr
                Name        = $nl.displayName
                Description = "Trusted Entra named location"
            }
        }
    }
}
Write-Host "  Total CIDR rows: $($rows.Count)" -ForegroundColor Green
$rows | Format-Table -AutoSize | Out-String | Write-Host

# --- 3. (Items posted individually below; CSV bulk ingest not used) -----

# --- 4. PUT watchlist (replaces all items) ------------------------------
$apiVer = '2024-09-01'
$base   = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
          "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
          "/providers/Microsoft.SecurityInsights/watchlists/$WatchlistAlias"

# Read existing watchlist to preserve displayName/description/itemsSearchKey
$existing = $null
try {
    $existing = Invoke-ArmWithReauth -Uri "$base`?api-version=$apiVer" -Method GET
} catch {
    $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    if ($code -ne 404) { throw }
    Write-Host "Watchlist '$WatchlistAlias' does not yet exist - will create fresh." -ForegroundColor Yellow
}

$displayName = if ($existing) { $existing.properties.displayName } else { $WatchlistAlias }
$description = if ($existing) { $existing.properties.description } else { 'Synced from trusted Entra Named Locations' }
Write-Host "Target watchlist: '$displayName' (alias=$WatchlistAlias)" -ForegroundColor Cyan

# --- 4a. DELETE existing watchlist (PUT does not reliably replace items) ---
if ($existing) {
    Write-Host "Deleting existing watchlist (definition + items) for clean re-create..." -ForegroundColor Yellow
    Invoke-ArmWithReauth -Uri "$base`?api-version=$apiVer" -Method DELETE | Out-Null
    # Sentinel returns immediately but the alias stays reserved for a few seconds.
    # Poll until GET returns 404 (or 30s max).
    for ($w = 0; $w -lt 30; $w++) {
        Start-Sleep -Seconds 1
        try {
            Invoke-ArmWithReauth -Uri "$base`?api-version=$apiVer" -Method GET | Out-Null
        } catch {
            $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            if ($code -eq 404) { Write-Host "  ...delete confirmed after ${w}s" -ForegroundColor DarkGray; break }
        }
    }
}

# PUT only creates the watchlist *definition* (columns inferred from first item).
# Items are then posted individually below - Sentinel's rawContent bulk ingest
# is unreliable across tenants/regions so we don't use it.
$body = @{
    properties = @{
        displayName    = $displayName
        source         = 'Local file'
        provider       = 'Sync-NamedLocationsToWatchlist.ps1'
        description    = $description
        itemsSearchKey = 'IPOrRange'
    }
} | ConvertTo-Json -Depth 6

if ($PSCmdlet.ShouldProcess($WatchlistAlias, "Replace watchlist with $($rows.Count) rows")) {
    $tmp = (New-TemporaryFile).FullName
    Set-Content -LiteralPath $tmp -Value $body -Encoding utf8
    $resp = $null
    for ($i = 0; $i -lt 2; $i++) {
        try {
            $armHdr = @{ Authorization = "Bearer $(Get-Token 'https://management.azure.com')"; 'Content-Type' = 'application/json' }
            $resp = Invoke-RestMethod -Uri "$base`?api-version=$apiVer" -Headers $armHdr -Method PUT -InFile $tmp
            break
        } catch {
            $code = $null
            try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            if ($i -eq 0 -and ($code -eq 401 -or $code -eq 403)) {
                Write-Host "ARM PUT returned $code (likely missing MFA claim). Forcing re-login..." -ForegroundColor Yellow
                Invoke-AzLoginWithMfa
                continue
            }
            Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
            throw
        }
    }
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    Write-Host "[OK] Watchlist definition created. provisioningState=$($resp.properties.provisioningState)" -ForegroundColor Green

    # --- 4b. Wait for the watchlist to be queryable, then POST each item ---
    # rawContent ingestion is unreliable; per-item PUT is the only path that
    # reliably populates rows on every tenant/region.
    Write-Host "Posting $($rows.Count) items individually..." -ForegroundColor Cyan
    $ok = 0; $fail = 0
    foreach ($r in $rows) {
        $itemId  = [guid]::NewGuid().ToString()
        $itemUri = "$base/watchlistItems/${itemId}?api-version=$apiVer"
        $itemBody = @{
            properties = @{
                itemsKeyValue = @{
                    IPOrRange   = $r.IPOrRange
                    Name        = $r.Name
                    Description = $r.Description
                }
            }
        } | ConvertTo-Json -Depth 6 -Compress
        try {
            $itemTmp = (New-TemporaryFile).FullName
            Set-Content -LiteralPath $itemTmp -Value $itemBody -Encoding utf8
            $itemHdr = @{ Authorization = "Bearer $(Get-Token 'https://management.azure.com')"; 'Content-Type' = 'application/json' }
            Invoke-RestMethod -Uri $itemUri -Headers $itemHdr -Method PUT -InFile $itemTmp | Out-Null
            Remove-Item -LiteralPath $itemTmp -ErrorAction SilentlyContinue
            $ok++
        } catch {
            $fail++
            Write-Host "  ! failed: $($r.IPOrRange) - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "[OK] Items posted: $ok succeeded, $fail failed" -ForegroundColor Green
}
