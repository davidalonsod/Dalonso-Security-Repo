<#
    Snapshot-AttackPaths.ps1
    ---------------------------------------------------------------------------
    Point-in-time snapshot of Microsoft Defender for Cloud ATTACK PATHS into a
    Log Analytics custom table so the CIEM workbook can show FIRST SEEN,
    RESOLVED and HISTORY (Azure Resource Graph itself keeps only the current,
    active set with no timestamps).

    Run it on a schedule (Azure Automation runbook or a timer-triggered
    Function, e.g. daily). Each run appends one heartbeat plus one row per
    currently-active attack path, stamped with TimeGenerated = run time. The workbook derives:
        FirstSeen  = min(TimeGenerated) per AttackPathId
        Resolved   = max(TimeGenerated) for paths absent from the latest run
        History    = active / new / resolved per day

    ---------------------------------------------------------------------------
    ONE-TIME SETUP (durable Logs Ingestion API path)
    ---------------------------------------------------------------------------
    1. Create the custom table `CIEM_AttackPaths_CL` in your Log Analytics
       workspace with the schema declared in `infra/attackpath-snapshot.bicep`.
       It includes TimeGenerated, SnapshotId/RecordType, path metadata,
       Cloud/ProviderSet/AccountOrProject, entry and target IDs, graph counts,
       and bounded entity/connection JSON. Prefer deploying the Bicep rather
       than creating the schema manually so the DCR stays aligned.
       (Portal: Workspace > Tables > Create > New custom log (DCR-based), or
        `az monitor log-analytics workspace table create`.)
    2. Create a Data Collection Endpoint (DCE) and a Data Collection Rule (DCR)
       with a stream named `Custom-CIEM_AttackPaths_CL` that maps to the table.
    3. Grant the identity that runs this script the **Monitoring Metrics
       Publisher** role on the DCR.
    4. Pass the DCE logs-ingestion URI, the DCR immutable id and the stream
       name below.

    Requires: Az.Accounts, Az.ResourceGraph  (Install-Module Az).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]   $DceEndpoint,                    # e.g. https://<dce>.<region>.ingest.monitor.azure.com
    [Parameter(Mandatory)] [string]   $DcrImmutableId,                 # e.g. dcr-xxxxxxxxxxxxxxxx
    [string]   $StreamName = 'Custom-CIEM_AttackPaths_CL',
    [string[]] $SubscriptionIds,                                       # optional; default = all accessible
    [switch]   $WhatIfNoIngest                                         # build rows but don't POST (dry run)
)

$ErrorActionPreference = 'Stop'

foreach ($m in 'Az.Accounts','Az.ResourceGraph') {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module '$m' is required. Run: Install-Module Az -Scope CurrentUser" }
    Import-Module $m -ErrorAction Stop
}

if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }

# ---- 1. Pull current attack paths from Azure Resource Graph (paged) ----------
$argQuery = @'
securityresources
| where type == 'microsoft.security/attackpaths'
| extend Graph = properties.graphComponent,
         GraphEntities = properties.graphComponent.entities,
         GraphConnections = properties.graphComponent.connections
| extend GraphText = tostring(Graph), ProviderText = tolower(strcat(tostring(properties.displayName), ' ', tostring(properties.cloudProvider), ' ', tostring(properties.resourceDetails.Source), ' ', tostring(Graph)))
| extend HasAWS = ProviderText contains 'arn:aws:' or ProviderText contains 'amazon web services' or ProviderText contains 'aws.' or ProviderText contains '"source":"aws"' or ProviderText contains '"source": "aws"' or ProviderText contains 'awsaccount',
         HasGCP = ProviderText contains 'googleapis.com' or ProviderText contains 'google cloud' or ProviderText contains 'gcp.' or ProviderText contains '"source":"gcp"' or ProviderText contains '"source": "gcp"' or ProviderText contains 'gcpproject'
| extend Cloud = case(HasAWS and HasGCP, 'Cross-cloud', HasAWS, 'AWS', HasGCP, 'GCP', 'Azure'),
         ProviderSet = trim_end(', ', strcat(iff(HasAWS, 'AWS, ', ''), iff(HasGCP, 'GCP, ', ''), iff(not(HasAWS) and not(HasGCP), 'Azure, ', '')))
| extend AWSAccountId = coalesce(extract(@'arn:aws[^:]*:[^:]*:[^:]*:([0-9]{12}):', 1, GraphText), extract(@'(?i)"accountId"\s*:\s*"([0-9]{12})"', 1, GraphText)),
         GCPProjectId = coalesce(extract(@'(?i)"projectId"\s*:\s*"([^"\\]+)"', 1, GraphText), extract(@'(?i)/projects/([^/"\\]+)', 1, GraphText))
| project AttackPathId    = tostring(coalesce(properties.AttackPathID, name)),
          DisplayName      = tostring(properties.displayName),
          Risk             = tostring(properties.riskLevel),
          AttackPathType   = tostring(properties.attackPathType),
          PotentialImpact  = tostring(properties.potentialImpact),
          RiskCategories   = tostring(properties.riskCategories),
          SubscriptionId   = subscriptionId,
          Cloud,
          ProviderSet,
          AccountOrProject = case(HasAWS, AWSAccountId, HasGCP, GCPProjectId, subscriptionId),
          EntryPointEntityId = tostring(properties.entryPointEntityInternalID),
          TargetEntityId   = tostring(properties.targetEntityInternalID),
          EntityCount      = coalesce(array_length(GraphEntities), 0),
          ConnectionCount  = coalesce(array_length(GraphConnections), 0),
          GraphEntitiesJson = substring(tostring(GraphEntities), 0, 30000),
          GraphConnectionsJson = substring(tostring(GraphConnections), 0, 30000)
'@

$rows = New-Object System.Collections.Generic.List[object]
$skipToken = $null
do {
    $params = @{ Query = $argQuery; First = 1000 }
    if ($SubscriptionIds) { $params.Subscription = $SubscriptionIds }
    if ($skipToken)       { $params.SkipToken   = $skipToken }
    $page = Search-AzGraph @params
    foreach ($r in $page) { $rows.Add($r) }
    $skipToken = $page.SkipToken
} while ($skipToken)

$stamp = (Get-Date).ToUniversalTime().ToString('o')
$snapshotId = [guid]::NewGuid().ToString()
$payload = @(
    [ordered]@{
        TimeGenerated = $stamp
        SnapshotId = $snapshotId
        RecordType = 'Snapshot'
        AttackPathId = ''
        DisplayName = ''
        Risk = ''
        AttackPathType = ''
        PotentialImpact = ''
        RiskCategories = ''
        SubscriptionId = ''
        Cloud = ''
        ProviderSet = ''
        AccountOrProject = ''
        EntryPointEntityId = ''
        TargetEntityId = ''
        EntityCount = 0
        ConnectionCount = 0
        GraphEntitiesJson = ''
        GraphConnectionsJson = ''
    }
    $rows | ForEach-Object {
    [ordered]@{
        TimeGenerated   = $stamp
        SnapshotId      = $snapshotId
        RecordType      = 'Path'
        AttackPathId    = [string]$_.AttackPathId
        DisplayName     = [string]$_.DisplayName
        Risk            = [string]$_.Risk
        AttackPathType  = [string]$_.AttackPathType
        PotentialImpact = [string]$_.PotentialImpact
        RiskCategories  = [string]$_.RiskCategories
        SubscriptionId  = [string]$_.SubscriptionId
        Cloud           = [string]$_.Cloud
        ProviderSet     = [string]$_.ProviderSet
        AccountOrProject = [string]$_.AccountOrProject
        EntryPointEntityId = [string]$_.EntryPointEntityId
        TargetEntityId  = [string]$_.TargetEntityId
        EntityCount     = [int]$_.EntityCount
        ConnectionCount = [int]$_.ConnectionCount
        GraphEntitiesJson = [string]$_.GraphEntitiesJson
        GraphConnectionsJson = [string]$_.GraphConnectionsJson
    }
    }
)

Write-Host ("Collected {0} active attack path(s) at {1}." -f $rows.Count, $stamp)
if ($WhatIfNoIngest) { $payload | ConvertTo-Json -Depth 5; return }

# ---- 2. Ingest into Log Analytics via the Logs Ingestion API (DCR) -----------
$token = (Get-AzAccessToken -ResourceUrl 'https://monitor.azure.com').Token
$uri   = "$DceEndpoint/dataCollectionRules/$DcrImmutableId/streams/$StreamName`?api-version=2023-01-01"

# batch to stay well under the 1 MB request limit
$batchSize = 100
for ($i = 0; $i -lt $payload.Count; $i += $batchSize) {
    $batch = $payload[$i..([Math]::Min($i + $batchSize - 1, $payload.Count - 1))]
    $body  = ConvertTo-Json -InputObject @($batch) -Depth 5 -Compress
    Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' `
        -Headers @{ Authorization = "Bearer $token" }
    Write-Host ("Ingested rows {0}-{1}." -f ($i + 1), ($i + $batch.Count))
}
Write-Host 'Done. First-seen / resolved / history will populate as snapshots accumulate.'
