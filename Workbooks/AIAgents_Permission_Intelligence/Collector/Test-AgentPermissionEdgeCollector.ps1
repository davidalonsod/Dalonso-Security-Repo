[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AgentPermissionEdgeCollector.ps1') -NoRun

$script:Passed = 0
$script:Failed = 0

function Assert-Equal {
    param(
        [Parameter(Mandatory)]
        [object]$Actual,
        [Parameter(Mandatory)]
        [object]$Expected,
        [Parameter(Mandatory)]
        [string]$Message
    )

    if ([string]$Actual -ne [string]$Expected) {
        throw "$Message Expected='$Expected' Actual='$Actual'."
    }
}

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,
        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-TestCase {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [scriptblock]$Test
    )

    try {
        & $Test
        $script:Passed++
        Write-Output "PASS: $Name"
    }
    catch {
        $script:Failed++
        Write-Output "FAIL: $Name - $($_.Exception.Message)"
    }
}

$fixtureJson = @'
{
  "tenantId": "11111111-1111-1111-1111-111111111111",
  "retrievedAt": "2026-10-01T12:00:00Z",
  "subject": {
    "id": "agent-001",
    "type": "AgentIdentity"
  },
  "resourceServicePrincipal": {
    "id": "resource-sp-001",
    "appId": "resource-app-001",
    "displayName": "Synthetic Resource API",
    "appRoles": [
      {
        "id": "app-role-001",
        "value": "Synthetic.Read.All"
      }
    ],
    "oauth2PermissionScopes": [
      {
        "id": "scope-001",
        "value": "Synthetic.Read"
      },
      {
        "id": "scope-002",
        "value": "Synthetic.Write"
      }
    ]
  },
  "appRoleAssignment": {
    "id": "assignment-001",
    "appRoleId": "app-role-001",
    "resourceId": "resource-sp-001",
    "resourceDisplayName": "Synthetic Resource API",
    "createdDateTime": "2026-09-01T00:00:00Z"
  },
  "oauthGrant": {
    "id": "oauth-grant-001",
    "resourceId": "resource-sp-001",
    "scope": "Synthetic.Read Synthetic.Write",
    "consentType": "AllPrincipals",
    "principalId": null,
    "startTime": "2026-09-01T00:00:00Z",
    "expiryTime": "2027-09-01T00:00:00Z"
  },
  "blueprint": {
    "id": "blueprint-001",
    "appId": "blueprint-app-001"
  },
  "inheritablePermissions": [
    {
      "resourceAppId": "resource-app-001",
      "inheritableScopes": {
        "kind": "enumerated",
        "scopes": [
          "Synthetic.Read",
          "Synthetic.Write"
        ]
      }
    }
  ]
}
'@
$fixture = $fixtureJson | ConvertFrom-Json -Depth 20
$retrievedAt = [datetime]$fixture.retrievedAt

Invoke-TestCase -Name 'Stable SHA256 EdgeId is deterministic and input-sensitive' -Test {
    $parameters = @{
        SourceSystem = 'MicrosoftGraph'
        SourceObjectId = 'assignment-001'
        Relation = 'assigned'
        SubjectId = 'agent-001'
        TargetId = 'resource-sp-001'
        PermissionId = 'app-role-001'
        PermissionValue = 'Synthetic.Read.All'
    }
    $first = Get-StableEdgeId @parameters
    $second = Get-StableEdgeId @parameters
    $changed = Get-StableEdgeId @parameters -PermissionValue 'Synthetic.Write.All'

    Assert-Equal -Actual $first.Length -Expected 64 -Message 'SHA256 EdgeId must contain 64 lowercase hex characters.'
    Assert-Equal -Actual $first -Expected $second -Message 'Equivalent edge inputs must hash identically.'
    Assert-True -Condition ($first -ne $changed) -Message 'Changing permission input must change EdgeId.'
    Assert-True -Condition ($first -cmatch '^[0-9a-f]{64}$') -Message 'EdgeId must be lowercase hexadecimal.'
}

Invoke-TestCase -Name 'Canonical edge exactly matches the ingestion contract columns' -Test {
    $edge = New-PermissionEdge `
        -EdgeClass configured `
        -Relation assigned `
        -TenantId $fixture.tenantId `
        -SubjectId $fixture.subject.id `
        -SubjectType $fixture.subject.type `
        -TargetId $fixture.resourceServicePrincipal.id `
        -TargetType ServicePrincipal `
        -PermissionId app-role-001 `
        -PermissionValue Synthetic.Read.All `
        -PermissionMode application `
        -AuthorizationMechanism appRoleAssignment `
        -GrantOrigin direct `
        -SourceSystem MicrosoftGraph `
        -SourceTable appRoleAssignments `
        -SourceObjectId assignment-001 `
        -RetrievedAt $retrievedAt

    $expectedColumns = @(
        'TimeGenerated',
        'EdgeId',
        'EdgeClass',
        'Relation',
        'TenantId',
        'SubjectId',
        'SubjectType',
        'TargetId',
        'TargetType',
        'PermissionId',
        'PermissionValue',
        'PermissionMode',
        'AuthorizationMechanism',
        'GrantOrigin',
        'ConsentType',
        'DeclarationState',
        'GrantState',
        'TokenState',
        'ConfiguredEdgeId',
        'ResourceScope',
        'Operation',
        'EventId',
        'SourceSystem',
        'SourceTable',
        'SourceObjectId',
        'EvidenceAuthority',
        'Confidence',
        'ObservedAt',
        'RetrievedAt',
        'ValidFrom',
        'ValidTo',
        'CollectorName',
        'CollectorVersion',
        'Details'
    )
    Assert-Equal -Actual (($edge.Keys) -join ',') -Expected ($expectedColumns -join ',') -Message 'Canonical edge columns differ from the KQL contract.'
    Assert-True -Condition (-not ($edge.Keys -match '(?i)prompt|content|response|argument|result')) -Message 'Canonical contract must not add prompt or content columns.'
}

Invoke-TestCase -Name 'Graph paging follows synthetic next links without network access' -Test {
    $requests = [System.Collections.Generic.List[string]]::new()
    $invoker = {
        param($request)
        $requests.Add([string]$request.Uri)
        if ($request.Uri -eq 'https://fixture.test/page/1') {
            return [pscustomobject]@{
                value = @([pscustomobject]@{ id = 'one' })
                '@odata.nextLink' = 'https://fixture.test/page/2'
            }
        }
        if ($request.Uri -eq 'https://fixture.test/page/2') {
            return [pscustomobject]@{
                value = @([pscustomobject]@{ id = 'two' })
            }
        }
        throw "Unexpected fixture URI '$($request.Uri)'."
    }

    $results = @(Invoke-GraphPagedRequest -Uri 'https://fixture.test/page/1' -Headers @{} -RequestInvoker $invoker)
    Assert-Equal -Actual $requests.Count -Expected 2 -Message 'Pager must request both fixture pages.'
    Assert-Equal -Actual $results.Count -Expected 2 -Message 'Pager must merge both fixture pages.'
    Assert-Equal -Actual $results[1].id -Expected 'two' -Message 'Pager returned unexpected second item.'
}

Invoke-TestCase -Name 'ARG paging follows synthetic skip tokens without Azure access' -Test {
    $requests = [System.Collections.Generic.List[object]]::new()
    $invoker = {
        param($request)
        $requests.Add($request.Body)
        if ($requests.Count -eq 1) {
            return [pscustomobject]@{
                data = @([pscustomobject]@{ id = 'role-assignment-one' })
                '$skipToken' = 'next-page'
            }
        }
        return [pscustomobject]@{
            data = @([pscustomobject]@{ id = 'role-assignment-two' })
        }
    }

    $results = @(Invoke-ArgPagedQuery -SubscriptionId 'subscription-001' -Query 'fixture' -Headers @{} -RequestInvoker $invoker)
    Assert-Equal -Actual $requests.Count -Expected 2 -Message 'ARG pager must request both fixture pages.'
    Assert-Equal -Actual $requests[1].options['$skipToken'] -Expected 'next-page' -Message 'ARG pager must submit the returned skip token.'
    Assert-Equal -Actual $results.Count -Expected 2 -Message 'ARG pager must merge both fixture pages.'
}

Invoke-TestCase -Name 'Synthetic permissions normalize to configured canonical edges' -Test {
    $servicePrincipalsById = @{
        $fixture.resourceServicePrincipal.id = $fixture.resourceServicePrincipal
    }
    $servicePrincipalsByAppId = @{
        $fixture.resourceServicePrincipal.appId = $fixture.resourceServicePrincipal
    }
    $edges = @{}

    Add-AppRoleAssignmentEdges `
        -EdgesById $edges `
        -Assignments @($fixture.appRoleAssignment) `
        -TenantId $fixture.tenantId `
        -SubjectId $fixture.subject.id `
        -SubjectType $fixture.subject.type `
        -GrantOrigin direct `
        -ServicePrincipalsById $servicePrincipalsById `
        -RetrievedAt $retrievedAt
    Add-OAuthGrantEdges `
        -EdgesById $edges `
        -Grants @($fixture.oauthGrant) `
        -TenantId $fixture.tenantId `
        -SubjectId $fixture.subject.id `
        -SubjectType $fixture.subject.type `
        -GrantOrigin direct `
        -ServicePrincipalsById $servicePrincipalsById `
        -RetrievedAt $retrievedAt
    Add-InheritablePermissionEdges `
        -EdgesById $edges `
        -Permissions @($fixture.inheritablePermissions) `
        -Blueprint $fixture.blueprint `
        -TenantId $fixture.tenantId `
        -ServicePrincipalsByAppId $servicePrincipalsByAppId `
        -RetrievedAt $retrievedAt

    Assert-Equal -Actual $edges.Count -Expected 5 -Message 'Fixture should produce one app role, two OAuth, and two inheritable edges.'
    Assert-Equal -Actual @($edges.Values | Where-Object PermissionMode -eq 'application').Count -Expected 1 -Message 'Fixture app-role edge was not normalized.'
    Assert-Equal -Actual @($edges.Values | Where-Object PermissionMode -eq 'delegated').Count -Expected 4 -Message 'Fixture delegated edges were not normalized.'
    Assert-Equal -Actual @($edges.Values | Where-Object Relation -eq 'eligibleToInherit').Count -Expected 2 -Message 'Fixture inheritable edges were not normalized.'
}

Invoke-TestCase -Name 'Configured permissions derive honest resource-category reachability' -Test {
    $edges = @{}
    $graphEdge = New-PermissionEdge `
        -EdgeClass configured `
        -Relation consented `
        -TenantId $fixture.tenantId `
        -SubjectId $fixture.subject.id `
        -SubjectType AgentIdentity `
        -TargetId $fixture.resourceServicePrincipal.id `
        -TargetType ServicePrincipal `
        -PermissionId scope-sites-rw `
        -PermissionValue Sites.ReadWrite.All `
        -PermissionMode delegated `
        -AuthorizationMechanism oauth2PermissionGrant `
        -GrantOrigin direct `
        -SourceSystem MicrosoftGraph `
        -SourceTable oauth2PermissionGrants `
        -SourceObjectId grant-sites-rw `
        -RetrievedAt $retrievedAt
    $rbacEdge = New-PermissionEdge `
        -EdgeClass configured `
        -Relation assigned `
        -TenantId $fixture.tenantId `
        -SubjectId $fixture.subject.id `
        -SubjectType AgentIdentity `
        -TargetId /subscriptions/sub-001/resourceGroups/rg-001 `
        -TargetType Resource `
        -PermissionId role-reader `
        -PermissionValue Reader `
        -PermissionMode application `
        -AuthorizationMechanism azureRbac `
        -GrantOrigin direct `
        -ResourceScope /subscriptions/sub-001/resourceGroups/rg-001 `
        -SourceSystem AzureResourceGraph `
        -SourceTable authorizationresources `
        -SourceObjectId assignment-reader `
        -RetrievedAt $retrievedAt
    Add-UniqueEdge -EdgesById $edges -Edge $graphEdge
    Add-UniqueEdge -EdgesById $edges -Edge $rbacEdge

    Add-DerivedReachabilityEdges -EdgesById $edges -TenantId $fixture.tenantId -RetrievedAt $retrievedAt

    $derived = @($edges.Values | Where-Object AuthorizationMechanism -eq 'derivedReachability')
    $graphReach = @($derived | Where-Object ConfiguredEdgeId -eq $graphEdge.EdgeId)[0]
    $rbacReach = @($derived | Where-Object ConfiguredEdgeId -eq $rbacEdge.EdgeId)[0]
    Assert-Equal -Actual $derived.Count -Expected 2 -Message 'Each configured Agent Identity permission should produce one derived reachability edge.'
    Assert-Equal -Actual $graphReach.EdgeClass -Expected reachableInferred -Message 'Broad Microsoft Graph permissions must remain inferred.'
    Assert-Equal -Actual $graphReach.TargetId -Expected 'resource-category:sharepoint-sites' -Message 'Sites permissions should map to the SharePoint resource category.'
    Assert-Equal -Actual $graphReach.Details.AccessLevel -Expected readWrite -Message 'Write scopes should retain their access level.'
    Assert-Equal -Actual $graphReach.Details.ResourceClassification -Expected Unknown -Message 'Missing resource-classification evidence must remain unknown.'
    Assert-Equal -Actual $rbacReach.EdgeClass -Expected reachableDeterministic -Message 'Explicit Azure RBAC scopes should be deterministic.'
    Assert-Equal -Actual $rbacReach.TargetId -Expected '/subscriptions/sub-001/resourceGroups/rg-001' -Message 'Azure RBAC reach should preserve the exact assignment scope.'
}

Invoke-TestCase -Name 'Logs ingestion dry run batches records and performs no write' -Test {
    $records = @(
        1..5 | ForEach-Object {
            New-PermissionEdge `
                -EdgeClass configured `
                -Relation assigned `
                -TenantId $fixture.tenantId `
                -SubjectId "agent-$_" `
                -SubjectType AgentIdentity `
                -TargetId 'resource-sp-001' `
                -TargetType ServicePrincipal `
                -PermissionId 'app-role-001' `
                -PermissionValue 'Synthetic.Read.All' `
                -PermissionMode application `
                -AuthorizationMechanism appRoleAssignment `
                -GrantOrigin direct `
                -SourceSystem Fixture `
                -SourceTable fixture `
                -SourceObjectId "fixture-$_" `
                -RetrievedAt $retrievedAt
        }
    )
    $senderCalled = $false
    $sender = {
        $senderCalled = $true
        throw 'Dry run must not call the sender.'
    }
    $result = Send-LogIngestionBatches `
        -Records $records `
        -DceEndpoint 'https://fixture.invalid' `
        -DcrImmutableId 'dcr-fixture' `
        -StreamName 'Custom-AgentPermissionEdges_CL' `
        -MaxRecords 2 `
        -MaxBytes 900000 `
        -DryRun `
        -Sender $sender

    Assert-Equal -Actual $result.BatchCount -Expected 3 -Message 'Five records with a two-record limit must produce three batches.'
    Assert-Equal -Actual $result.RecordCount -Expected 5 -Message 'Dry-run record count is incorrect.'
    Assert-True -Condition (-not $result.Sent) -Message 'Dry run must report Sent=false.'
    Assert-True -Condition (-not $senderCalled) -Message 'Dry run invoked the synthetic sender.'
}

Invoke-TestCase -Name 'Example configuration parses and contains no secret material' -Test {
    $path = Join-Path $PSScriptRoot 'collector.config.example.json'
    $configuration = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 20
    Assert-Equal -Actual $configuration.automationAccountName -Expected 'aa-sentinel-sync' -Message 'Example targets the wrong Automation Account.'
    Assert-Equal -Actual $configuration.runtimeVersion -Expected '7.2' -Message 'Example must configure the required PowerShell 7.2 runtime.'
    Assert-True -Condition (-not ((Get-Content -LiteralPath $path -Raw) -match '(?i)clientSecret|password|certificateData|accessToken')) -Message 'Example configuration must not contain secret fields.'
}

Write-Output "Tests completed. Passed=$script:Passed Failed=$script:Failed."
if ($script:Failed -gt 0) {
    exit 1
}
