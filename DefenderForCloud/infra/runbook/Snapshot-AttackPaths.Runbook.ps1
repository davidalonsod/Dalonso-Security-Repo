<#
    Snapshot-AttackPaths.Runbook.ps1
    Azure Automation (PowerShell 7.2) runbook — system-assigned managed identity.

    ZERO module dependencies: it authenticates with the Automation managed
    identity via the sandbox IDENTITY endpoint and calls REST directly, so you do
    NOT need to import Az.Accounts / Az.ResourceGraph into the Automation account.

    It appends one row per currently-active Defender for Cloud attack path to the
    CIEM_AttackPaths_CL table (via the Logs Ingestion API / DCR). Reads its config
    from Automation variables DceEndpoint / DcrImmutableId / StreamName, which the
    Bicep template creates.

    Managed-identity RBAC required:
      - Reader (or Security Reader) on the subscriptions to snapshot  → ARG read
      - Monitoring Metrics Publisher on the DCR                        → ingest
    (Deploy-AttackPathSnapshot.ps1 assigns both.)
#>

$ErrorActionPreference = 'Stop'

$dce    = Get-AutomationVariable -Name 'DceEndpoint'
$dcrId  = Get-AutomationVariable -Name 'DcrImmutableId'
$stream = Get-AutomationVariable -Name 'StreamName'

if ([string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT)) {
    throw 'IDENTITY_ENDPOINT not present. Enable the system-assigned managed identity on the Automation account.'
}

function Get-MiToken([string]$Resource) {
    $uri = "$($env:IDENTITY_ENDPOINT)?resource=$Resource&api-version=2019-08-01"
    (Invoke-RestMethod -Method GET -Uri $uri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER }).access_token
}

# ---- 1. Read current attack paths from Azure Resource Graph (REST, paged) -----
$armToken = Get-MiToken 'https://management.azure.com'
$argUri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01'
$query = @'
securityresources
| where type == "microsoft.security/attackpaths"
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
    $options = @{ resultFormat = 'objectArray'; '$top' = 1000 }
    if ($skipToken) { $options['$skipToken'] = $skipToken }
    $body = @{ query = $query; options = $options } | ConvertTo-Json -Depth 6
    $resp = Invoke-RestMethod -Method POST -Uri $argUri -ContentType 'application/json' `
        -Headers @{ Authorization = "Bearer $armToken" } -Body $body
    foreach ($r in $resp.data) { $rows.Add($r) }
    $skipToken = $resp.'$skipToken'
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

Write-Output ("Collected {0} active attack path(s) at {1}." -f $rows.Count, $stamp)

# ---- 2. Ingest into Log Analytics via the Logs Ingestion API (DCR) ------------
$monToken  = Get-MiToken 'https://monitor.azure.com'
$ingestUri = "$dce/dataCollectionRules/$dcrId/streams/$stream`?api-version=2023-01-01"

$batchSize = 100
for ($i = 0; $i -lt $payload.Count; $i += $batchSize) {
    $slice = $payload[$i..([Math]::Min($i + $batchSize - 1, $payload.Count - 1))]
    $body  = ConvertTo-Json -InputObject @($slice) -Depth 6 -Compress
    Invoke-RestMethod -Method POST -Uri $ingestUri -ContentType 'application/json' `
        -Headers @{ Authorization = "Bearer $monToken" } -Body $body
    Write-Output ("Ingested rows {0}-{1}." -f ($i + 1), ($i + $slice.Count))
}
Write-Output 'Ingestion complete.'
