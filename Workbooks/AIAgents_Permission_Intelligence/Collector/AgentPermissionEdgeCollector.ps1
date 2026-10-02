[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$DryRun,
    [switch]$NoRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CollectorName = 'AgentPermissionEdgeCollector'
$script:CollectorVersion = '1.0.0'
$script:GraphBaseUri = 'https://graph.microsoft.com'
$script:ManagementBaseUri = 'https://management.azure.com'
$script:MonitorResourceUri = 'https://monitor.azure.com'

function Get-ObjectProperty {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,
        [Parameter(Mandatory)]
        [string]$Name,
        [object]$DefaultValue = $null
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $DefaultValue
    }

    return $property.Value
}

function ConvertFrom-SecureToken {
    param(
        [Parameter(Mandatory)]
        [object]$Token
    )

    if ($Token -is [string]) {
        return $Token
    }

    if ($Token -isnot [securestring]) {
        throw "Unsupported access-token type '$($Token.GetType().FullName)'."
    }

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Get-ManagedIdentityToken {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceUrl
    )

    $tokenResult = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop
    return ConvertFrom-SecureToken -Token $tokenResult.Token
}

function Get-HttpStatusCode {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $response = Get-ObjectProperty -InputObject $ErrorRecord.Exception -Name 'Response'
    if ($null -eq $response) {
        return $null
    }

    $statusCode = Get-ObjectProperty -InputObject $response -Name 'StatusCode'
    if ($null -eq $statusCode) {
        return $null
    }

    return [int]$statusCode
}

function Get-RetryAfterSeconds {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [int]$DefaultSeconds
    )

    $response = Get-ObjectProperty -InputObject $ErrorRecord.Exception -Name 'Response'
    if ($null -eq $response) {
        return $DefaultSeconds
    }

    $headers = Get-ObjectProperty -InputObject $response -Name 'Headers'
    if ($null -eq $headers) {
        return $DefaultSeconds
    }

    $retryAfter = Get-ObjectProperty -InputObject $headers -Name 'RetryAfter'
    $delta = if ($null -ne $retryAfter) {
        Get-ObjectProperty -InputObject $retryAfter -Name 'Delta'
    }
    else {
        $null
    }

    if ($null -ne $delta) {
        return [Math]::Max(1, [int][Math]::Ceiling($delta.TotalSeconds))
    }

    return $DefaultSeconds
}

function Invoke-CollectorRestMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [hashtable]$Headers,
        [object]$Body,
        [string]$ContentType = 'application/json',
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 5,
        [scriptblock]$RequestInvoker
    )

    if ($null -ne $RequestInvoker) {
        return & $RequestInvoker @{
            Method = $Method
            Uri = $Uri
            Headers = $Headers
            Body = $Body
            ContentType = $ContentType
        }
    }

    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        try {
            $parameters = @{
                Method = $Method
                Uri = $Uri
                Headers = $Headers
                ContentType = $ContentType
                ErrorAction = 'Stop'
            }
            if ($null -ne $Body) {
                $parameters.Body = if ($Body -is [string]) {
                    $Body
                }
                else {
                    $Body | ConvertTo-Json -Depth 30 -Compress
                }
            }

            return Invoke-RestMethod @parameters
        }
        catch {
            $statusCode = Get-HttpStatusCode -ErrorRecord $_
            $retryable = $statusCode -in @(429, 500, 502, 503, 504)
            if (-not $retryable -or $attempt -eq $MaxRetries) {
                $statusText = if ($null -eq $statusCode) { 'unknown' } else { [string]$statusCode }
                throw "HTTP $Method failed for '$Uri' with status $statusText after $($attempt + 1) attempt(s): $($_.Exception.Message)"
            }

            $defaultDelay = [Math]::Min(60, [Math]::Pow(2, $attempt + 1))
            $delay = Get-RetryAfterSeconds -ErrorRecord $_ -DefaultSeconds $defaultDelay
            Write-Warning "HTTP $statusCode from '$Uri'. Retrying in $delay second(s)."
            Start-Sleep -Seconds $delay
        }
    }
}

function Invoke-GraphPagedRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [hashtable]$Headers,
        [ValidateRange(1, 100000)]
        [int]$MaxPages = 10000,
        [scriptblock]$RequestInvoker
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri
    $page = 0

    while (-not [string]::IsNullOrWhiteSpace($nextLink)) {
        $page++
        if ($page -gt $MaxPages) {
            throw "Graph paging exceeded MaxPages=$MaxPages for '$Uri'."
        }

        $response = Invoke-CollectorRestMethod -Method GET -Uri $nextLink -Headers $Headers -RequestInvoker $RequestInvoker
        $value = Get-ObjectProperty -InputObject $response -Name 'value'
        if ($null -eq $value) {
            $results.Add($response)
            $nextLink = $null
            continue
        }

        foreach ($item in @($value)) {
            $results.Add($item)
        }

        $nextLink = Get-ObjectProperty -InputObject $response -Name '@odata.nextLink'
    }

    return @($results.ToArray())
}

function Invoke-GraphBatchCollections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('v1.0', 'beta')]
        [string]$ApiVersion,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Requests,
        [Parameter(Mandatory)]
        [hashtable]$Headers,
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 5
    )

    $output = @{}
    if ($Requests.Count -eq 0) {
        return $output
    }

    for ($offset = 0; $offset -lt $Requests.Count; $offset += 20) {
        $lastIndex = [Math]::Min($offset + 19, $Requests.Count - 1)
        $pending = [System.Collections.Generic.List[object]]::new()
        foreach ($request in @($Requests[$offset..$lastIndex])) {
            $pending.Add([pscustomobject]@{
                Key = [string]$request.Key
                Url = [string]$request.Url
                Headers = Get-ObjectProperty -InputObject $request -Name 'Headers' -DefaultValue @{}
                Attempt = 0
            })
            if (-not $output.ContainsKey([string]$request.Key)) {
                $output[[string]$request.Key] = [System.Collections.Generic.List[object]]::new()
            }
        }

        while ($pending.Count -gt 0) {
            $batchRequests = @(
                foreach ($request in $pending) {
                    $batchRequest = @{
                        id = $request.Key
                        method = 'GET'
                        url = $request.Url
                    }
                    if ($request.Headers.Count -gt 0) {
                        $batchRequest.headers = $request.Headers
                    }
                    $batchRequest
                }
            )

            $response = Invoke-CollectorRestMethod `
                -Method POST `
                -Uri "$script:GraphBaseUri/$ApiVersion/`$batch" `
                -Headers $Headers `
                -Body @{ requests = $batchRequests }

            $responseById = @{}
            foreach ($subResponse in @((Get-ObjectProperty -InputObject $response -Name 'responses' -DefaultValue @()))) {
                $responseById[[string]$subResponse.id] = $subResponse
            }

            $retry = [System.Collections.Generic.List[object]]::new()
            $retryDelay = 0
            foreach ($request in $pending) {
                if (-not $responseById.ContainsKey($request.Key)) {
                    throw "Graph batch response omitted request '$($request.Key)'."
                }

                $subResponse = $responseById[$request.Key]
                $status = [int]$subResponse.status
                if ($status -in @(429, 500, 502, 503, 504)) {
                    if ($request.Attempt -ge $MaxRetries) {
                        throw "Graph batch request '$($request.Key)' failed with status $status after $($request.Attempt + 1) attempt(s)."
                    }

                    $headerRetryAfter = Get-ObjectProperty -InputObject $subResponse.headers -Name 'Retry-After'
                    $retryDelay = [Math]::Max($retryDelay, $(if ($null -ne $headerRetryAfter) { [int]$headerRetryAfter } else { [Math]::Pow(2, $request.Attempt + 1) }))
                    $retry.Add([pscustomobject]@{
                        Key = $request.Key
                        Url = $request.Url
                        Headers = $request.Headers
                        Attempt = $request.Attempt + 1
                    })
                    continue
                }

                if ($status -lt 200 -or $status -ge 300) {
                    $errorMessage = Get-ObjectProperty -InputObject (Get-ObjectProperty -InputObject $subResponse.body -Name 'error' -DefaultValue @{}) -Name 'message' -DefaultValue 'No error message returned.'
                    throw "Graph batch request '$($request.Key)' failed with status ${status}: $errorMessage"
                }

                $body = $subResponse.body
                $value = Get-ObjectProperty -InputObject $body -Name 'value'
                if ($null -eq $value) {
                    $output[$request.Key].Add($body)
                }
                else {
                    foreach ($item in @($value)) {
                        $output[$request.Key].Add($item)
                    }
                }

                $nextLink = Get-ObjectProperty -InputObject $body -Name '@odata.nextLink'
                if (-not [string]::IsNullOrWhiteSpace($nextLink)) {
                    foreach ($item in @(Invoke-GraphPagedRequest -Uri $nextLink -Headers $Headers)) {
                        $output[$request.Key].Add($item)
                    }
                }
            }

            if ($retry.Count -gt 0) {
                $retryDelay = [Math]::Min(60, [Math]::Max(1, $retryDelay))
                Write-Warning "Retrying $($retry.Count) Graph batch request(s) in $retryDelay second(s)."
                Start-Sleep -Seconds $retryDelay
            }
            $pending = $retry
        }
    }

    $result = @{}
    foreach ($key in $output.Keys) {
        $result[$key] = @($output[$key].ToArray())
    }
    return $result
}

function Get-StableEdgeId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourceSystem,
        [Parameter(Mandatory)]
        [string]$SourceObjectId,
        [Parameter(Mandatory)]
        [string]$Relation,
        [Parameter(Mandatory)]
        [string]$SubjectId,
        [Parameter(Mandatory)]
        [string]$TargetId,
        [string]$PermissionId,
        [string]$PermissionValue
    )

    $parts = @(
        $SourceSystem,
        $SourceObjectId,
        $Relation,
        $SubjectId,
        $TargetId,
        $PermissionId,
        $PermissionValue
    ) | ForEach-Object {
        if ($null -eq $_) { '' } else { ([string]$_).Trim().ToLowerInvariant() }
    }
    $canonical = $parts -join [char]0x1f
    $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($bytes)
    }
    finally {
        $sha256.Dispose()
    }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-PermissionEdge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('identityLifecycle', 'configured', 'observed', 'reachableDeterministic', 'reachableBounded', 'reachableInferred', 'control')]
        [string]$EdgeClass,
        [Parameter(Mandatory)]
        [ValidateSet('belongsTo', 'representedBy', 'owns', 'sponsors', 'manages', 'declares', 'eligibleToInherit', 'assigned', 'consented', 'materialized', 'memberOf', 'observedUsing', 'reaches', 'blockedBy', 'constrainedBy', 'dependsOn')]
        [string]$Relation,
        [string]$TenantId,
        [Parameter(Mandatory)]
        [string]$SubjectId,
        [string]$SubjectType = 'Unknown',
        [Parameter(Mandatory)]
        [string]$TargetId,
        [string]$TargetType = 'Unknown',
        [string]$PermissionId = '',
        [string]$PermissionValue = '',
        [ValidateSet('application', 'delegated', 'notApplicable', 'unknown')]
        [string]$PermissionMode = 'notApplicable',
        [ValidateSet('appRoleAssignment', 'oauth2PermissionGrant', 'resourceSpecificConsent', 'directoryRole', 'azureRbac', 'workloadAcl', 'apiKey', 'identityRelationship', 'runtimeObservation', 'derivedReachability', 'policyEvaluation', 'unknown')]
        [string]$AuthorizationMechanism = 'identityRelationship',
        [ValidateSet('direct', 'blueprintInherited', 'groupDerived', 'roleDerived', 'accessPackage', 'resourceSpecific', 'notApplicable', 'unknown')]
        [string]$GrantOrigin = 'notApplicable',
        [ValidateSet('AllPrincipals', 'Principal', 'notApplicable', 'unknown')]
        [string]$ConsentType = 'notApplicable',
        [string]$DeclarationState = '',
        [string]$GrantState = '',
        [string]$TokenState = '',
        [string]$ConfiguredEdgeId = '',
        [string]$ResourceScope = '',
        [string]$Operation = '',
        [string]$EventId = '',
        [Parameter(Mandatory)]
        [string]$SourceSystem,
        [string]$SourceTable = '',
        [Parameter(Mandatory)]
        [string]$SourceObjectId,
        [ValidateSet('authoritative', 'nativeTelemetry', 'deterministicDerived', 'boundedDerived', 'inferred', 'manual')]
        [string]$EvidenceAuthority = 'authoritative',
        [ValidateSet('confirmed', 'high', 'medium', 'low', 'unknown')]
        [string]$Confidence = 'confirmed',
        [AllowNull()]
        [object]$ObservedAt,
        [Parameter(Mandatory)]
        [datetime]$RetrievedAt,
        [AllowNull()]
        [object]$ValidFrom,
        [AllowNull()]
        [object]$ValidTo,
        [hashtable]$Details = @{}
    )

    if ([string]::IsNullOrWhiteSpace($SubjectId) -or [string]::IsNullOrWhiteSpace($TargetId)) {
        throw 'Canonical edges require non-empty SubjectId and TargetId.'
    }

    $edgeId = Get-StableEdgeId `
        -SourceSystem $SourceSystem `
        -SourceObjectId $SourceObjectId `
        -Relation $Relation `
        -SubjectId $SubjectId `
        -TargetId $TargetId `
        -PermissionId $PermissionId `
        -PermissionValue $PermissionValue

    return [ordered]@{
        TimeGenerated = $RetrievedAt.ToUniversalTime().ToString('o')
        EdgeId = $edgeId
        EdgeClass = $EdgeClass
        Relation = $Relation
        TenantId = $TenantId
        SubjectId = $SubjectId
        SubjectType = $SubjectType
        TargetId = $TargetId
        TargetType = $TargetType
        PermissionId = $PermissionId
        PermissionValue = $PermissionValue
        PermissionMode = $PermissionMode
        AuthorizationMechanism = $AuthorizationMechanism
        GrantOrigin = $GrantOrigin
        ConsentType = $ConsentType
        DeclarationState = $DeclarationState
        GrantState = $GrantState
        TokenState = $TokenState
        ConfiguredEdgeId = $ConfiguredEdgeId
        ResourceScope = $ResourceScope
        Operation = $Operation
        EventId = $EventId
        SourceSystem = $SourceSystem
        SourceTable = $SourceTable
        SourceObjectId = $SourceObjectId
        EvidenceAuthority = $EvidenceAuthority
        Confidence = $Confidence
        ObservedAt = if ($null -eq $ObservedAt -or [string]::IsNullOrWhiteSpace([string]$ObservedAt)) { $null } else { ([datetime]$ObservedAt).ToUniversalTime().ToString('o') }
        RetrievedAt = $RetrievedAt.ToUniversalTime().ToString('o')
        ValidFrom = if ($null -eq $ValidFrom -or [string]::IsNullOrWhiteSpace([string]$ValidFrom)) { $null } else { ([datetime]$ValidFrom).ToUniversalTime().ToString('o') }
        ValidTo = if ($null -eq $ValidTo -or [string]::IsNullOrWhiteSpace([string]$ValidTo)) { $null } else { ([datetime]$ValidTo).ToUniversalTime().ToString('o') }
        CollectorName = $script:CollectorName
        CollectorVersion = $script:CollectorVersion
        Details = $Details
    }
}

function Add-UniqueEdge {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EdgesById,
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Edge
    )

    if (-not $EdgesById.ContainsKey($Edge.EdgeId)) {
        $EdgesById[$Edge.EdgeId] = $Edge
    }
}

function Get-DirectoryObjectType {
    param(
        [Parameter(Mandatory)]
        [object]$DirectoryObject
    )

    $odataType = [string](Get-ObjectProperty -InputObject $DirectoryObject -Name '@odata.type' -DefaultValue '')
    switch -Regex ($odataType) {
        'agentIdentityBlueprint' { return 'AgentIdentityBlueprint' }
        'agentIdentity' { return 'AgentIdentity' }
        'agentUser' { return 'AgentUser' }
        'servicePrincipal' { return 'ServicePrincipal' }
        'application' { return 'EntraApplication' }
        'group' { return 'Group' }
        'user' { return 'HumanUser' }
        default { return 'Unknown' }
    }
}

function Get-AppRoleDefinition {
    param(
        [Parameter(Mandatory)]
        [hashtable]$ServicePrincipalsById,
        [Parameter(Mandatory)]
        [string]$ResourceId,
        [Parameter(Mandatory)]
        [string]$AppRoleId
    )

    if (-not $ServicePrincipalsById.ContainsKey($ResourceId)) {
        return $null
    }

    foreach ($appRole in @((Get-ObjectProperty -InputObject $ServicePrincipalsById[$ResourceId] -Name 'appRoles' -DefaultValue @()))) {
        if ([string]$appRole.id -eq $AppRoleId) {
            return $appRole
        }
    }

    return $null
}

function Get-OAuthScopeDefinition {
    param(
        [Parameter(Mandatory)]
        [object]$ServicePrincipal,
        [Parameter(Mandatory)]
        [string]$ScopeValue
    )

    foreach ($scope in @((Get-ObjectProperty -InputObject $ServicePrincipal -Name 'oauth2PermissionScopes' -DefaultValue @()))) {
        if ([string]$scope.value -eq $ScopeValue) {
            return $scope
        }
    }

    return $null
}

function Add-RequiredResourceAccessEdges {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EdgesById,
        [Parameter(Mandatory)]
        [object]$Blueprint,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [hashtable]$ServicePrincipalsByAppId,
        [Parameter(Mandatory)]
        [datetime]$RetrievedAt
    )

    foreach ($resourceDeclaration in @((Get-ObjectProperty -InputObject $Blueprint -Name 'requiredResourceAccess' -DefaultValue @()))) {
        $resourceAppId = [string](Get-ObjectProperty -InputObject $resourceDeclaration -Name 'resourceAppId' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($resourceAppId)) {
            Write-Warning "Skipping requiredResourceAccess entry on blueprint '$($Blueprint.id)' because resourceAppId is missing."
            continue
        }
        $resourcePrincipal = if ($ServicePrincipalsByAppId.ContainsKey($resourceAppId)) {
            $ServicePrincipalsByAppId[$resourceAppId]
        }
        else {
            $null
        }
        $targetId = if ($null -eq $resourcePrincipal) { $resourceAppId } else { [string]$resourcePrincipal.id }
        foreach ($permissionDeclaration in @((Get-ObjectProperty -InputObject $resourceDeclaration -Name 'resourceAccess' -DefaultValue @()))) {
            $permissionId = [string](Get-ObjectProperty -InputObject $permissionDeclaration -Name 'id' -DefaultValue '')
            $permissionType = [string](Get-ObjectProperty -InputObject $permissionDeclaration -Name 'type' -DefaultValue '')
            if ([string]::IsNullOrWhiteSpace($permissionId) -or $permissionType -notin @('Role', 'Scope')) {
                Write-Warning "Skipping malformed requiredResourceAccess permission on blueprint '$($Blueprint.id)'."
                continue
            }

            $definition = $null
            if ($permissionType -eq 'Role' -and $null -ne $resourcePrincipal) {
                $definition = Get-AppRoleDefinition -ServicePrincipalsById @{ $targetId = $resourcePrincipal } -ResourceId $targetId -AppRoleId $permissionId
            }
            elseif ($permissionType -eq 'Scope' -and $null -ne $resourcePrincipal) {
                $definition = @((Get-ObjectProperty -InputObject $resourcePrincipal -Name 'oauth2PermissionScopes' -DefaultValue @()) | Where-Object {
                    [string]$_.id -eq $permissionId
                }) | Select-Object -First 1
            }
            $permissionValue = if ($null -eq $definition) { $permissionId } else { [string]$definition.value }

            $edge = New-PermissionEdge `
                -EdgeClass configured `
                -Relation declares `
                -TenantId $TenantId `
                -SubjectId ([string]$Blueprint.id) `
                -SubjectType AgentIdentityBlueprint `
                -TargetId $targetId `
                -TargetType ServicePrincipal `
                -PermissionId $permissionId `
                -PermissionValue $permissionValue `
                -PermissionMode $(if ($permissionType -eq 'Role') { 'application' } else { 'delegated' }) `
                -AuthorizationMechanism $(if ($permissionType -eq 'Role') { 'appRoleAssignment' } else { 'oauth2PermissionGrant' }) `
                -GrantOrigin blueprintInherited `
                -DeclarationState declared `
                -GrantState declaredOnly `
                -SourceSystem MicrosoftGraph `
                -SourceTable requiredResourceAccess `
                -SourceObjectId "$($Blueprint.id):${resourceAppId}:$permissionId" `
                -RetrievedAt $RetrievedAt `
                -Details @{
                    baselineApproved = $true
                    declarationOnly = $true
                    resourceAppId = $resourceAppId
                }
            Add-UniqueEdge -EdgesById $EdgesById -Edge $edge
        }
    }
}

function Add-AppRoleAssignmentEdges {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EdgesById,
        [Parameter(Mandatory)]
        [object[]]$Assignments,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [string]$SubjectId,
        [Parameter(Mandatory)]
        [string]$SubjectType,
        [Parameter(Mandatory)]
        [ValidateSet('direct', 'blueprintInherited', 'groupDerived')]
        [string]$GrantOrigin,
        [Parameter(Mandatory)]
        [hashtable]$ServicePrincipalsById,
        [Parameter(Mandatory)]
        [datetime]$RetrievedAt,
        [string]$GroupId = ''
    )

    foreach ($assignment in $Assignments) {
        if ($null -eq $assignment) {
            Write-Warning "Skipping a null app-role assignment returned for subject '$SubjectId'."
            continue
        }
        $assignmentId = [string](Get-ObjectProperty -InputObject $assignment -Name 'id' -DefaultValue '')
        $resourceId = [string](Get-ObjectProperty -InputObject $assignment -Name 'resourceId' -DefaultValue '')
        $appRoleId = [string](Get-ObjectProperty -InputObject $assignment -Name 'appRoleId' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($resourceId) -or [string]::IsNullOrWhiteSpace($appRoleId)) {
            $properties = @($assignment.PSObject.Properties.Name) -join ','
            Write-Warning "Skipping app-role assignment '$assignmentId' for subject '$SubjectId' because resourceId or appRoleId is missing. Properties=[$properties]."
            continue
        }

        $definition = Get-AppRoleDefinition -ServicePrincipalsById $ServicePrincipalsById -ResourceId $resourceId -AppRoleId $appRoleId
        $permissionValue = if ($null -eq $definition) { $appRoleId } else { [string]$definition.value }
        $sourceObjectId = if ([string]::IsNullOrWhiteSpace($GroupId)) {
            $assignmentId
        }
        else {
            "${assignmentId}:$SubjectId"
        }
        $relation = if ($GrantOrigin -eq 'blueprintInherited') { 'materialized' } else { 'assigned' }
        $details = @{
            resourceDisplayName = [string](Get-ObjectProperty -InputObject $assignment -Name 'resourceDisplayName' -DefaultValue '')
        }
        if (-not [string]::IsNullOrWhiteSpace($GroupId)) {
            $details.groupId = $GroupId
        }

        $edge = New-PermissionEdge `
            -EdgeClass configured `
            -Relation $relation `
            -TenantId $TenantId `
            -SubjectId $SubjectId `
            -SubjectType $SubjectType `
            -TargetId $resourceId `
            -TargetType ServicePrincipal `
            -PermissionId $appRoleId `
            -PermissionValue $permissionValue `
            -PermissionMode application `
            -AuthorizationMechanism appRoleAssignment `
            -GrantOrigin $GrantOrigin `
            -GrantState active `
            -SourceSystem MicrosoftGraph `
            -SourceTable appRoleAssignments `
            -SourceObjectId $sourceObjectId `
            -RetrievedAt $RetrievedAt `
            -ValidFrom (Get-ObjectProperty -InputObject $assignment -Name 'createdDateTime') `
            -Details $details
        Add-UniqueEdge -EdgesById $EdgesById -Edge $edge
    }
}

function Add-OAuthGrantEdges {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EdgesById,
        [Parameter(Mandatory)]
        [object[]]$Grants,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [string]$SubjectId,
        [Parameter(Mandatory)]
        [string]$SubjectType,
        [Parameter(Mandatory)]
        [ValidateSet('direct', 'blueprintInherited')]
        [string]$GrantOrigin,
        [Parameter(Mandatory)]
        [hashtable]$ServicePrincipalsById,
        [Parameter(Mandatory)]
        [datetime]$RetrievedAt
    )

    foreach ($grant in $Grants) {
        if ($null -eq $grant) {
            Write-Warning "Skipping a null delegated permission grant returned for subject '$SubjectId'."
            continue
        }
        $grantId = [string](Get-ObjectProperty -InputObject $grant -Name 'id' -DefaultValue '')
        $resourceId = [string](Get-ObjectProperty -InputObject $grant -Name 'resourceId' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($resourceId)) {
            $properties = @($grant.PSObject.Properties.Name) -join ','
            Write-Warning "Skipping OAuth2 permission grant '$grantId' for subject '$SubjectId' because resourceId is missing. Properties=[$properties]."
            continue
        }

        $resourcePrincipal = if ($ServicePrincipalsById.ContainsKey($resourceId)) {
            $ServicePrincipalsById[$resourceId]
        }
        else {
            $null
        }
        $scopes = @(([string](Get-ObjectProperty -InputObject $grant -Name 'scope' -DefaultValue '')).Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
        foreach ($scopeValue in $scopes) {
            $definition = if ($null -eq $resourcePrincipal) {
                $null
            }
            else {
                Get-OAuthScopeDefinition -ServicePrincipal $resourcePrincipal -ScopeValue $scopeValue
            }
            $permissionId = if ($null -eq $definition) { $scopeValue } else { [string]$definition.id }
            $consentType = [string](Get-ObjectProperty -InputObject $grant -Name 'consentType' -DefaultValue 'unknown')
            if ($consentType -notin @('AllPrincipals', 'Principal')) {
                $consentType = 'unknown'
            }
            $relation = if ($GrantOrigin -eq 'blueprintInherited') { 'materialized' } else { 'consented' }

            $edge = New-PermissionEdge `
                -EdgeClass configured `
                -Relation $relation `
                -TenantId $TenantId `
                -SubjectId $SubjectId `
                -SubjectType $SubjectType `
                -TargetId $resourceId `
                -TargetType ServicePrincipal `
                -PermissionId $permissionId `
                -PermissionValue $scopeValue `
                -PermissionMode delegated `
                -AuthorizationMechanism oauth2PermissionGrant `
                -GrantOrigin $GrantOrigin `
                -ConsentType $consentType `
                -GrantState active `
                -SourceSystem MicrosoftGraph `
                -SourceTable oauth2PermissionGrants `
                -SourceObjectId "${grantId}:$scopeValue" `
                -RetrievedAt $RetrievedAt `
                -ValidFrom (Get-ObjectProperty -InputObject $grant -Name 'startTime') `
                -ValidTo (Get-ObjectProperty -InputObject $grant -Name 'expiryTime') `
                -Details @{
                    principalId = [string](Get-ObjectProperty -InputObject $grant -Name 'principalId' -DefaultValue '')
                }
            Add-UniqueEdge -EdgesById $EdgesById -Edge $edge
        }
    }
}

function Add-DerivedReachabilityEdges {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EdgesById,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [datetime]$RetrievedAt
    )

    $configuredEdges = @($EdgesById.Values | Where-Object {
        $_.EdgeClass -eq 'configured' -and
        $_.SubjectType -eq 'AgentIdentity' -and
        -not [string]::IsNullOrWhiteSpace([string]$_.PermissionValue)
    })

    foreach ($configuredEdge in $configuredEdges) {
        $permissionValue = [string]$configuredEdge.PermissionValue
        $resourceScope = [string]$configuredEdge.ResourceScope
        $authorizationMechanism = [string]$configuredEdge.AuthorizationMechanism
        $permissionMode = [string]$configuredEdge.PermissionMode
        $grantOrigin = [string]$configuredEdge.GrantOrigin
        $accessLevel = if ($permissionValue -match '(?i)(write|manage|fullcontrol|send|contributor|owner)') {
            'readWrite'
        }
        else {
            'read'
        }

        $reachability = [ordered]@{
            EdgeClass = 'reachableInferred'
            TargetId = 'resource-category:microsoft-graph'
            TargetType = 'ResourceCategory'
            ResourceScope = 'Microsoft Graph resources'
            EvidenceAuthority = 'inferred'
            Confidence = 'low'
            Reason = 'Permission mapped to a resource category; exact resource authorization was not collected.'
        }

        if ($authorizationMechanism -eq 'azureRbac' -and -not [string]::IsNullOrWhiteSpace($resourceScope)) {
            $reachability.EdgeClass = 'reachableDeterministic'
            $reachability.TargetId = $resourceScope
            $reachability.TargetType = 'AzureResourceScope'
            $reachability.ResourceScope = $resourceScope
            $reachability.EvidenceAuthority = 'deterministicDerived'
            $reachability.Confidence = 'confirmed'
            $reachability.Reason = 'Azure role assignment contains an explicit resource scope.'
        }
        elseif ($authorizationMechanism -eq 'directoryRole') {
            $reachability.EdgeClass = 'reachableBounded'
            $reachability.TargetId = 'resource-category:entra-directory'
            $reachability.TargetType = 'ResourceCategory'
            $reachability.ResourceScope = 'Microsoft Entra directory'
            $reachability.EvidenceAuthority = 'boundedDerived'
            $reachability.Confidence = 'medium'
            $reachability.Reason = 'Directory role bounds access to the tenant directory, but exact objects are not enumerated.'
        }
        else {
            switch -Regex ($permissionValue) {
                '(?i)^Sites\.' {
                    $reachability.TargetId = 'resource-category:sharepoint-sites'
                    $reachability.ResourceScope = 'SharePoint sites'
                    break
                }
                '(?i)^Files\.' {
                    $reachability.TargetId = 'resource-category:microsoft-365-files'
                    $reachability.ResourceScope = 'SharePoint and OneDrive files'
                    break
                }
                '(?i)^(Mail|MailboxSettings)\.' {
                    $reachability.TargetId = 'resource-category:exchange-mailboxes'
                    $reachability.ResourceScope = 'Exchange Online mailboxes'
                    break
                }
                '(?i)^AuditLog\.' {
                    $reachability.TargetId = 'resource-category:entra-audit-logs'
                    $reachability.ResourceScope = 'Microsoft Entra audit logs'
                    break
                }
                '(?i)^Reports\.' {
                    $reachability.TargetId = 'resource-category:microsoft-365-reports'
                    $reachability.ResourceScope = 'Microsoft 365 reports'
                    break
                }
                '(?i)^Application\.' {
                    $reachability.TargetId = 'resource-category:entra-applications'
                    $reachability.ResourceScope = 'Microsoft Entra applications and service principals'
                    break
                }
                '(?i)^(User|Group|Directory)\.' {
                    $reachability.TargetId = 'resource-category:entra-directory'
                    $reachability.ResourceScope = 'Microsoft Entra directory'
                    break
                }
                '(?i)^RoleManagement\.' {
                    $reachability.TargetId = 'resource-category:entra-role-management'
                    $reachability.ResourceScope = 'Microsoft Entra role management'
                    break
                }
            }
        }

        $edge = New-PermissionEdge `
            -EdgeClass $reachability.EdgeClass `
            -Relation reaches `
            -TenantId $TenantId `
            -SubjectId ([string]$configuredEdge.SubjectId) `
            -SubjectType AgentIdentity `
            -TargetId $reachability.TargetId `
            -TargetType $reachability.TargetType `
            -PermissionId ([string]$configuredEdge.PermissionId) `
            -PermissionValue $permissionValue `
            -PermissionMode $permissionMode `
            -AuthorizationMechanism derivedReachability `
            -GrantOrigin $grantOrigin `
            -ConfiguredEdgeId ([string]$configuredEdge.EdgeId) `
            -ResourceScope $reachability.ResourceScope `
            -SourceSystem AgentPermissionEdgeCollector `
            -SourceTable derivedReachability `
            -SourceObjectId "reach:$($configuredEdge.EdgeId):$($reachability.TargetId)" `
            -EvidenceAuthority $reachability.EvidenceAuthority `
            -Confidence $reachability.Confidence `
            -RetrievedAt $RetrievedAt `
            -Details @{
                AccessLevel = $accessLevel
                ResourceClassification = 'Unknown'
                ResourceCategory = $reachability.ResourceScope
                DerivationReason = $reachability.Reason
                ExactResourceEvidence = $reachability.EdgeClass -eq 'reachableDeterministic'
            }
        Add-UniqueEdge -EdgesById $EdgesById -Edge $edge
    }
}

function Add-InheritablePermissionEdges {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EdgesById,
        [Parameter(Mandatory)]
        [object[]]$Permissions,
        [Parameter(Mandatory)]
        [object]$Blueprint,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [hashtable]$ServicePrincipalsByAppId,
        [Parameter(Mandatory)]
        [datetime]$RetrievedAt
    )

    foreach ($permission in $Permissions) {
        if ($null -eq $permission) {
            Write-Warning "Skipping a null inheritable-permission record returned for blueprint '$($Blueprint.id)'."
            continue
        }
        $resourceAppId = [string](Get-ObjectProperty -InputObject $permission -Name 'resourceAppId' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($resourceAppId)) {
            $properties = @($permission.PSObject.Properties.Name) -join ','
            Write-Warning "Skipping inheritable-permission metadata for blueprint '$($Blueprint.id)' because resourceAppId is missing. Properties=[$properties]."
            continue
        }
        $targetId = if ($ServicePrincipalsByAppId.ContainsKey($resourceAppId)) {
            [string]$ServicePrincipalsByAppId[$resourceAppId].id
        }
        else {
            $resourceAppId
        }
        $inheritableScopes = Get-ObjectProperty -InputObject $permission -Name 'inheritableScopes' -DefaultValue @{}
        $kind = [string](Get-ObjectProperty -InputObject $inheritableScopes -Name 'kind' -DefaultValue 'unknown')
        $scopeValues = if ($kind -eq 'allAllowed') {
            @('*')
        }
        elseif ($kind -eq 'enumerated') {
            @((Get-ObjectProperty -InputObject $inheritableScopes -Name 'scopes' -DefaultValue @()))
        }
        elseif ($kind -eq 'none') {
            @()
        }
        else {
            throw "Inheritable permission on blueprint '$($Blueprint.id)' has unsupported kind '$kind'."
        }

        foreach ($scopeValue in $scopeValues) {
            $edge = New-PermissionEdge `
                -EdgeClass configured `
                -Relation eligibleToInherit `
                -TenantId $TenantId `
                -SubjectId ([string]$Blueprint.id) `
                -SubjectType AgentIdentityBlueprint `
                -TargetId $targetId `
                -TargetType ServicePrincipal `
                -PermissionId ([string]$scopeValue) `
                -PermissionValue ([string]$scopeValue) `
                -PermissionMode delegated `
                -AuthorizationMechanism oauth2PermissionGrant `
                -GrantOrigin blueprintInherited `
                -DeclarationState $kind `
                -GrantState declared `
                -SourceSystem MicrosoftGraph `
                -SourceTable inheritablePermissions `
                -SourceObjectId "$($Blueprint.id):${resourceAppId}:$scopeValue" `
                -RetrievedAt $RetrievedAt `
                -Details @{
                    resourceAppId = $resourceAppId
                    inheritancePattern = $kind
                }
            Add-UniqueEdge -EdgesById $EdgesById -Edge $edge
        }
    }
}

function Add-RelationshipEdges {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EdgesById,
        [Parameter(Mandatory)]
        [object]$Entity,
        [Parameter(Mandatory)]
        [string]$EntityType,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [datetime]$RetrievedAt
    )

    foreach ($relationship in @(
        @{ Property = 'owners'; Relation = 'owns' },
        @{ Property = 'sponsors'; Relation = 'sponsors' }
    )) {
        foreach ($relatedObject in @((Get-ObjectProperty -InputObject $Entity -Name $relationship.Property -DefaultValue @()))) {
            $relatedId = [string](Get-ObjectProperty -InputObject $relatedObject -Name 'id' -DefaultValue '')
            if ([string]::IsNullOrWhiteSpace($relatedId)) {
                continue
            }

            $edge = New-PermissionEdge `
                -EdgeClass identityLifecycle `
                -Relation $relationship.Relation `
                -TenantId $TenantId `
                -SubjectId $relatedId `
                -SubjectType (Get-DirectoryObjectType -DirectoryObject $relatedObject) `
                -TargetId ([string]$Entity.id) `
                -TargetType $EntityType `
                -SourceSystem MicrosoftGraph `
                -SourceTable $relationship.Property `
                -SourceObjectId "$($Entity.id):$($relationship.Property):$relatedId" `
                -RetrievedAt $RetrievedAt `
                -Details @{
                    displayName = [string](Get-ObjectProperty -InputObject $relatedObject -Name 'displayName' -DefaultValue '')
                }
            Add-UniqueEdge -EdgesById $EdgesById -Edge $edge
        }
    }
}

function Add-CredentialControlEdges {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EdgesById,
        [Parameter(Mandatory)]
        [object]$Entity,
        [Parameter(Mandatory)]
        [string]$EntityType,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [datetime]$RetrievedAt,
        [ValidateRange(0, 3650)]
        [int]$WarningDays = 30
    )

    foreach ($credentialProperty in @('keyCredentials', 'passwordCredentials')) {
        foreach ($credential in @((Get-ObjectProperty -InputObject $Entity -Name $credentialProperty -DefaultValue @()))) {
            $endDateTime = Get-ObjectProperty -InputObject $credential -Name 'endDateTime'
            if ($null -eq $endDateTime) {
                continue
            }

            $expiry = [datetime]$endDateTime
            $daysRemaining = [Math]::Floor(($expiry.ToUniversalTime() - $RetrievedAt.ToUniversalTime()).TotalDays)
            if ($daysRemaining -gt $WarningDays) {
                continue
            }

            $keyId = [string](Get-ObjectProperty -InputObject $credential -Name 'keyId' -DefaultValue '')
            if ([string]::IsNullOrWhiteSpace($keyId)) {
                $keyId = Get-StableEdgeId -SourceSystem MicrosoftGraph -SourceObjectId ([string]$Entity.id) -Relation constrainedBy -SubjectId ([string]$Entity.id) -TargetId ([string]$expiry.Ticks)
            }
            $state = if ($daysRemaining -lt 0) { 'expired' } else { 'expiring' }
            $edge = New-PermissionEdge `
                -EdgeClass control `
                -Relation constrainedBy `
                -TenantId $TenantId `
                -SubjectId ([string]$Entity.id) `
                -SubjectType $EntityType `
                -TargetId "credential:$keyId" `
                -TargetType Control `
                -GrantState $state `
                -AuthorizationMechanism policyEvaluation `
                -SourceSystem MicrosoftGraph `
                -SourceTable $credentialProperty `
                -SourceObjectId "$($Entity.id):${credentialProperty}:$keyId" `
                -RetrievedAt $RetrievedAt `
                -ValidTo $expiry `
                -Details @{
                    credentialType = $credentialProperty
                    daysRemaining = $daysRemaining
                }
            Add-UniqueEdge -EdgesById $EdgesById -Edge $edge
        }
    }
}

function Invoke-ArgPagedQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [Parameter(Mandatory)]
        [string]$Query,
        [Parameter(Mandatory)]
        [hashtable]$Headers,
        [ValidateRange(1, 100000)]
        [int]$MaxPages = 10000,
        [scriptblock]$RequestInvoker
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null
    $page = 0

    do {
        $page++
        if ($page -gt $MaxPages) {
            throw "Azure Resource Graph paging exceeded MaxPages=$MaxPages."
        }

        $options = @{
            '$top' = 1000
            resultFormat = 'objectArray'
        }
        if (-not [string]::IsNullOrWhiteSpace($skipToken)) {
            $options['$skipToken'] = $skipToken
        }
        $body = @{
            subscriptions = @($SubscriptionId)
            query = $Query
            options = $options
        }
        $response = Invoke-CollectorRestMethod `
            -Method POST `
            -Uri "$script:ManagementBaseUri/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" `
            -Headers $Headers `
            -Body $body `
            -RequestInvoker $RequestInvoker
        foreach ($item in @((Get-ObjectProperty -InputObject $response -Name 'data' -DefaultValue @()))) {
            $results.Add($item)
        }
        $skipToken = [string](Get-ObjectProperty -InputObject $response -Name '$skipToken' -DefaultValue '')
    } while (-not [string]::IsNullOrWhiteSpace($skipToken))

    return @($results.ToArray())
}

function Split-LogBatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Records,
        [ValidateRange(1, 10000)]
        [int]$MaxRecords = 500,
        [ValidateRange(1024, 10485760)]
        [int]$MaxBytes = 900000
    )

    $batches = [System.Collections.Generic.List[object]]::new()
    $current = [System.Collections.Generic.List[object]]::new()
    $currentBytes = 2

    foreach ($record in $Records) {
        $recordJson = $record | ConvertTo-Json -Depth 30 -Compress
        $recordBytes = [Text.Encoding]::UTF8.GetByteCount($recordJson)
        if ($recordBytes + 2 -gt $MaxBytes) {
            throw "Edge '$($record.EdgeId)' is $recordBytes bytes and exceeds the configured batch limit of $MaxBytes bytes."
        }

        $separatorBytes = if ($current.Count -eq 0) { 0 } else { 1 }
        $wouldOverflow = $current.Count -ge $MaxRecords -or ($currentBytes + $separatorBytes + $recordBytes) -gt $MaxBytes
        if ($wouldOverflow) {
            $batches.Add([pscustomobject]@{
                Records = @($current.ToArray())
                ByteCount = $currentBytes
            })
            $current = [System.Collections.Generic.List[object]]::new()
            $currentBytes = 2
            $separatorBytes = 0
        }

        $current.Add($record)
        $currentBytes += $separatorBytes + $recordBytes
    }

    if ($current.Count -gt 0) {
        $batches.Add([pscustomobject]@{
            Records = @($current.ToArray())
            ByteCount = $currentBytes
        })
    }

    return @($batches.ToArray())
}

function Send-LogIngestionBatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Records,
        [Parameter(Mandatory)]
        [string]$DceEndpoint,
        [Parameter(Mandatory)]
        [string]$DcrImmutableId,
        [Parameter(Mandatory)]
        [string]$StreamName,
        [hashtable]$Headers = @{},
        [ValidateRange(1, 10000)]
        [int]$MaxRecords = 500,
        [ValidateRange(1024, 10485760)]
        [int]$MaxBytes = 900000,
        [switch]$DryRun,
        [scriptblock]$Sender
    )

    $batches = @(Split-LogBatches -Records $Records -MaxRecords $MaxRecords -MaxBytes $MaxBytes)
    if ($DryRun) {
        return [pscustomobject]@{
            BatchCount = $batches.Count
            RecordCount = $Records.Count
            Sent = $false
        }
    }

    $endpoint = $DceEndpoint.TrimEnd('/')
    $uri = "$endpoint/dataCollectionRules/$DcrImmutableId/streams/${StreamName}?api-version=2023-01-01"
    foreach ($batch in $batches) {
        if ($null -ne $Sender) {
            & $Sender $uri $Headers $batch.Records
        }
        else {
            Invoke-CollectorRestMethod -Method POST -Uri $uri -Headers $Headers -Body $batch.Records | Out-Null
        }
    }

    return [pscustomobject]@{
        BatchCount = $batches.Count
        RecordCount = $Records.Count
        Sent = $true
    }
}

function Get-AutomationConfiguration {
    param(
        [string]$Path
    )

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Collector configuration file '$Path' does not exist."
        }
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 30
    }

    $getVariable = Get-Command -Name Get-AutomationVariable -ErrorAction SilentlyContinue
    if ($null -eq $getVariable) {
        throw 'Get-AutomationVariable is unavailable. Supply -ConfigPath when running outside Azure Automation.'
    }

    $names = @(
        'TenantId',
        'SubscriptionId',
        'DceEndpoint',
        'DcrImmutableId',
        'StreamName',
        'AuditLookbackHours',
        'BatchMaxRecords',
        'BatchMaxBytes',
        'GraphMaxPages',
        'CredentialExpiryWarningDays',
        'EnableAuditLogs',
        'EnableConditionalAccess'
    )
    $values = @{}
    foreach ($name in $names) {
        $values[$name] = Get-AutomationVariable -Name "AgentPermissionEdge.$name"
    }

    return [pscustomobject]@{
        tenantId = [string]$values.TenantId
        subscriptionId = [string]$values.SubscriptionId
        dceEndpoint = [string]$values.DceEndpoint
        dcrImmutableId = [string]$values.DcrImmutableId
        streamName = [string]$values.StreamName
        auditLookbackHours = [int]$values.AuditLookbackHours
        batchMaxRecords = [int]$values.BatchMaxRecords
        batchMaxBytes = [int]$values.BatchMaxBytes
        graphMaxPages = [int]$values.GraphMaxPages
        credentialExpiryWarningDays = [int]$values.CredentialExpiryWarningDays
        enableAuditLogs = [Convert]::ToBoolean($values.EnableAuditLogs)
        enableConditionalAccess = [Convert]::ToBoolean($values.EnableConditionalAccess)
    }
}

function Assert-CollectorConfiguration {
    param(
        [Parameter(Mandatory)]
        [object]$Configuration,
        [switch]$AllowMissingIngestion
    )

    foreach ($name in @('tenantId', 'subscriptionId')) {
        if ([string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -InputObject $Configuration -Name $name))) {
            throw "Collector configuration property '$name' is required."
        }
    }

    if (-not $AllowMissingIngestion) {
        foreach ($name in @('dceEndpoint', 'dcrImmutableId', 'streamName')) {
            if ([string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -InputObject $Configuration -Name $name))) {
                throw "Collector configuration property '$name' is required unless -DryRun is used."
            }
        }
    }
}

function Invoke-AgentPermissionEdgeCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Configuration,
        [switch]$DryRun
    )

    Assert-CollectorConfiguration -Configuration $Configuration -AllowMissingIngestion:$DryRun
    $tenantId = [string]$Configuration.tenantId
    $subscriptionId = [string]$Configuration.subscriptionId
    $retrievedAt = [datetime]::UtcNow
    $maxPages = [int](Get-ObjectProperty -InputObject $Configuration -Name 'graphMaxPages' -DefaultValue 10000)
    $warningDays = [int](Get-ObjectProperty -InputObject $Configuration -Name 'credentialExpiryWarningDays' -DefaultValue 30)
    $auditLookbackHours = [int](Get-ObjectProperty -InputObject $Configuration -Name 'auditLookbackHours' -DefaultValue 26)
    $enableAuditLogs = [bool](Get-ObjectProperty -InputObject $Configuration -Name 'enableAuditLogs' -DefaultValue $true)
    $enableConditionalAccess = [bool](Get-ObjectProperty -InputObject $Configuration -Name 'enableConditionalAccess' -DefaultValue $true)

    Write-Output "[$script:CollectorName] Authenticating with the Automation Account managed identity."
    Connect-AzAccount -Identity -Tenant $tenantId -Subscription $subscriptionId -ErrorAction Stop | Out-Null
    $graphHeaders = @{
        Authorization = "Bearer $(Get-ManagedIdentityToken -ResourceUrl $script:GraphBaseUri)"
        Accept = 'application/json'
    }
    $managementHeaders = @{
        Authorization = "Bearer $(Get-ManagedIdentityToken -ResourceUrl $script:ManagementBaseUri)"
        Accept = 'application/json'
    }

    $edgesById = @{}
    $subjectTypes = @{}

    $blueprintUri = "$script:GraphBaseUri/beta/applications/microsoft.graph.agentIdentityBlueprint?" +
        '$select=id,appId,displayName,createdDateTime,disabledByMicrosoftStatus,keyCredentials,passwordCredentials,requiredResourceAccess&$expand=owners($select=id,displayName)&$top=100'
    $agentUri = "$script:GraphBaseUri/beta/servicePrincipals/microsoft.graph.agentIdentity?" +
        '$select=id,appId,displayName,agentIdentityBlueprintId,accountEnabled,createdDateTime,disabledByMicrosoftStatus,keyCredentials,passwordCredentials&$expand=owners($select=id,displayName)&$top=100'
    $agentUserUri = "$script:GraphBaseUri/beta/users/microsoft.graph.agentUser?" +
        '$select=id,displayName,identityParentId,accountEnabled,createdDateTime&$top=999'
    $servicePrincipalUri = "$script:GraphBaseUri/v1.0/servicePrincipals?" +
        '$select=id,appId,displayName,servicePrincipalType,appRoles,oauth2PermissionScopes&$top=999'

    $blueprints = @(Invoke-GraphPagedRequest -Uri $blueprintUri -Headers $graphHeaders -MaxPages $maxPages)
    $agents = @(Invoke-GraphPagedRequest -Uri $agentUri -Headers $graphHeaders -MaxPages $maxPages)
    $agentUsers = @(Invoke-GraphPagedRequest -Uri $agentUserUri -Headers $graphHeaders -MaxPages $maxPages)
    $servicePrincipals = @(Invoke-GraphPagedRequest -Uri $servicePrincipalUri -Headers $graphHeaders -MaxPages $maxPages)

    $sponsorRequests = [System.Collections.Generic.List[object]]::new()
    foreach ($blueprint in $blueprints) {
        $sponsorRequests.Add([pscustomobject]@{
            Key = "blueprint|$($blueprint.id)"
            Url = "/applications/$($blueprint.id)/microsoft.graph.agentIdentityBlueprint/sponsors?`$select=id,displayName&`$top=999"
        })
    }
    foreach ($agent in $agents) {
        $sponsorRequests.Add([pscustomobject]@{
            Key = "agent|$($agent.id)"
            Url = "/servicePrincipals/$($agent.id)/microsoft.graph.agentIdentity/sponsors?`$select=id,displayName&`$top=999"
        })
    }
    $sponsorCollections = Invoke-GraphBatchCollections -ApiVersion beta -Requests @($sponsorRequests.ToArray()) -Headers $graphHeaders

    $servicePrincipalsById = @{}
    $servicePrincipalsByAppId = @{}
    foreach ($servicePrincipal in $servicePrincipals) {
        if ($null -eq $servicePrincipal) {
            Write-Warning 'Skipping a null service-principal record.'
            continue
        }
        $servicePrincipalId = [string](Get-ObjectProperty -InputObject $servicePrincipal -Name 'id' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($servicePrincipalId)) {
            $properties = @($servicePrincipal.PSObject.Properties.Name) -join ','
            Write-Warning "Skipping service-principal metadata because id is missing. Properties=[$properties]."
            continue
        }
        $servicePrincipalsById[$servicePrincipalId] = $servicePrincipal
        $servicePrincipalAppId = [string](Get-ObjectProperty -InputObject $servicePrincipal -Name 'appId' -DefaultValue '')
        if (-not [string]::IsNullOrWhiteSpace($servicePrincipalAppId)) {
            $servicePrincipalsByAppId[$servicePrincipalAppId] = $servicePrincipal
        }
    }

    $blueprintsByAppId = @{}
    $blueprintPrincipals = [System.Collections.Generic.List[object]]::new()
    foreach ($blueprint in $blueprints) {
        $blueprintsByAppId[[string]$blueprint.appId] = $blueprint
        $subjectTypes[[string]$blueprint.id] = 'AgentIdentityBlueprint'
        Add-RelationshipEdges -EdgesById $edgesById -Entity $blueprint -EntityType AgentIdentityBlueprint -TenantId $tenantId -RetrievedAt $retrievedAt
        Add-RelationshipEdges `
            -EdgesById $edgesById `
            -Entity ([pscustomobject]@{
                id = $blueprint.id
                sponsors = @($sponsorCollections["blueprint|$($blueprint.id)"])
            }) `
            -EntityType AgentIdentityBlueprint `
            -TenantId $tenantId `
            -RetrievedAt $retrievedAt
        Add-CredentialControlEdges -EdgesById $edgesById -Entity $blueprint -EntityType AgentIdentityBlueprint -TenantId $tenantId -RetrievedAt $retrievedAt -WarningDays $warningDays
        Add-RequiredResourceAccessEdges `
            -EdgesById $edgesById `
            -Blueprint $blueprint `
            -TenantId $tenantId `
            -ServicePrincipalsByAppId $servicePrincipalsByAppId `
            -RetrievedAt $retrievedAt

        if ($servicePrincipalsByAppId.ContainsKey([string]$blueprint.appId)) {
            $principal = $servicePrincipalsByAppId[[string]$blueprint.appId]
            $blueprintPrincipals.Add($principal)
            $subjectTypes[[string]$principal.id] = 'AgentIdentityBlueprintPrincipal'
            $edge = New-PermissionEdge `
                -EdgeClass identityLifecycle `
                -Relation representedBy `
                -TenantId $tenantId `
                -SubjectId ([string]$blueprint.id) `
                -SubjectType AgentIdentityBlueprint `
                -TargetId ([string]$principal.id) `
                -TargetType AgentIdentityBlueprintPrincipal `
                -SourceSystem MicrosoftGraph `
                -SourceTable servicePrincipals `
                -SourceObjectId "$($blueprint.id):$($principal.id)" `
                -RetrievedAt $retrievedAt `
                -Details @{
                    appId = [string]$blueprint.appId
                    displayName = [string]$blueprint.displayName
                }
            Add-UniqueEdge -EdgesById $edgesById -Edge $edge
        }
    }

    $agentsById = @{}
    foreach ($agent in $agents) {
        $agentId = [string]$agent.id
        $agentsById[$agentId] = $agent
        $subjectTypes[$agentId] = 'AgentIdentity'
        Add-RelationshipEdges -EdgesById $edgesById -Entity $agent -EntityType AgentIdentity -TenantId $tenantId -RetrievedAt $retrievedAt
        Add-RelationshipEdges `
            -EdgesById $edgesById `
            -Entity ([pscustomobject]@{
                id = $agent.id
                sponsors = @($sponsorCollections["agent|$agentId"])
            }) `
            -EntityType AgentIdentity `
            -TenantId $tenantId `
            -RetrievedAt $retrievedAt
        Add-CredentialControlEdges -EdgesById $edgesById -Entity $agent -EntityType AgentIdentity -TenantId $tenantId -RetrievedAt $retrievedAt -WarningDays $warningDays

        $blueprintAppId = [string](Get-ObjectProperty -InputObject $agent -Name 'agentIdentityBlueprintId' -DefaultValue '')
        if (-not [string]::IsNullOrWhiteSpace($blueprintAppId) -and $blueprintsByAppId.ContainsKey($blueprintAppId)) {
            $blueprint = $blueprintsByAppId[$blueprintAppId]
            $edge = New-PermissionEdge `
                -EdgeClass identityLifecycle `
                -Relation belongsTo `
                -TenantId $tenantId `
                -SubjectId $agentId `
                -SubjectType AgentIdentity `
                -TargetId ([string]$blueprint.id) `
                -TargetType AgentIdentityBlueprint `
                -SourceSystem MicrosoftGraph `
                -SourceTable agentIdentities `
                -SourceObjectId $agentId `
                -RetrievedAt $retrievedAt `
                -ValidFrom (Get-ObjectProperty -InputObject $agent -Name 'createdDateTime') `
                -Details @{
                    blueprintAppId = $blueprintAppId
                    displayName = [string]$agent.displayName
                }
            Add-UniqueEdge -EdgesById $edgesById -Edge $edge
        }

        if ((Get-ObjectProperty -InputObject $agent -Name 'accountEnabled' -DefaultValue $true) -eq $false) {
            $edge = New-PermissionEdge `
                -EdgeClass control `
                -Relation blockedBy `
                -TenantId $tenantId `
                -SubjectId $agentId `
                -SubjectType AgentIdentity `
                -TargetId 'control:identity-disabled' `
                -TargetType Control `
                -GrantState disabled `
                -AuthorizationMechanism policyEvaluation `
                -SourceSystem MicrosoftGraph `
                -SourceTable agentIdentities `
                -SourceObjectId "${agentId}:disabled" `
                -RetrievedAt $retrievedAt
            Add-UniqueEdge -EdgesById $edgesById -Edge $edge
        }
    }

    foreach ($agentUser in $agentUsers) {
        $agentUserId = [string](Get-ObjectProperty -InputObject $agentUser -Name 'id' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($agentUserId)) {
            $displayName = [string](Get-ObjectProperty -InputObject $agentUser -Name 'displayName' -DefaultValue '<unknown>')
            Write-Warning "Skipping Agent User '$displayName' because Microsoft Graph returned no object id."
            continue
        }
        $parentId = [string](Get-ObjectProperty -InputObject $agentUser -Name 'identityParentId' -DefaultValue '')
        $subjectTypes[$agentUserId] = 'AgentUser'
        if (-not [string]::IsNullOrWhiteSpace($parentId)) {
            $edge = New-PermissionEdge `
                -EdgeClass identityLifecycle `
                -Relation representedBy `
                -TenantId $tenantId `
                -SubjectId $parentId `
                -SubjectType AgentIdentity `
                -TargetId $agentUserId `
                -TargetType AgentUser `
                -SourceSystem MicrosoftGraph `
                -SourceTable agentUsers `
                -SourceObjectId $agentUserId `
                -RetrievedAt $retrievedAt `
                -ValidFrom (Get-ObjectProperty -InputObject $agentUser -Name 'createdDateTime') `
                -Details @{
                    displayName = [string]$agentUser.displayName
                    accountEnabled = [bool](Get-ObjectProperty -InputObject $agentUser -Name 'accountEnabled' -DefaultValue $true)
                }
            Add-UniqueEdge -EdgesById $edgesById -Edge $edge
        }
    }

    $v1Requests = [System.Collections.Generic.List[object]]::new()
    foreach ($principal in @($agents) + @($blueprintPrincipals.ToArray())) {
        $id = [string]$principal.id
        $v1Requests.Add([pscustomobject]@{ Key = "$id|appRoles"; Url = "/servicePrincipals/$id/appRoleAssignments?`$top=999" })
        $v1Requests.Add([pscustomobject]@{ Key = "$id|oauth"; Url = "/servicePrincipals/$id/oauth2PermissionGrants?`$top=999" })
    }
    foreach ($agent in $agents) {
        $id = [string]$agent.id
        $v1Requests.Add([pscustomobject]@{
            Key = "$id|groups"
            Url = "/servicePrincipals/$id/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName&`$top=999&`$count=true"
            Headers = @{ ConsistencyLevel = 'eventual' }
        })
    }
    $v1Collections = Invoke-GraphBatchCollections -ApiVersion v1.0 -Requests @($v1Requests.ToArray()) -Headers $graphHeaders

    $betaRequests = [System.Collections.Generic.List[object]]::new()
    foreach ($agent in $agents) {
        $id = [string]$agent.id
        $betaRequests.Add([pscustomobject]@{ Key = "$id|inheritedAppRoles"; Url = "/servicePrincipals/microsoft.graph.agentIdentity/$id/inheritedAppRoleAssignments" })
        $betaRequests.Add([pscustomobject]@{ Key = "$id|inheritedOauth"; Url = "/servicePrincipals/microsoft.graph.agentIdentity/$id/inheritedOauth2PermissionGrants" })
    }
    $betaCollections = Invoke-GraphBatchCollections -ApiVersion beta -Requests @($betaRequests.ToArray()) -Headers $graphHeaders

    foreach ($principal in @($agents) + @($blueprintPrincipals.ToArray())) {
        $id = [string]$principal.id
        $type = if ($agentsById.ContainsKey($id)) { 'AgentIdentity' } else { 'AgentIdentityBlueprintPrincipal' }
        Add-AppRoleAssignmentEdges -EdgesById $edgesById -Assignments @($v1Collections["$id|appRoles"]) -TenantId $tenantId -SubjectId $id -SubjectType $type -GrantOrigin direct -ServicePrincipalsById $servicePrincipalsById -RetrievedAt $retrievedAt
        Add-OAuthGrantEdges -EdgesById $edgesById -Grants @($v1Collections["$id|oauth"]) -TenantId $tenantId -SubjectId $id -SubjectType $type -GrantOrigin direct -ServicePrincipalsById $servicePrincipalsById -RetrievedAt $retrievedAt
    }

    $groupMembers = @{}
    $groupsById = @{}
    foreach ($agent in $agents) {
        $agentId = [string]$agent.id
        Add-AppRoleAssignmentEdges -EdgesById $edgesById -Assignments @($betaCollections["$agentId|inheritedAppRoles"]) -TenantId $tenantId -SubjectId $agentId -SubjectType AgentIdentity -GrantOrigin blueprintInherited -ServicePrincipalsById $servicePrincipalsById -RetrievedAt $retrievedAt
        Add-OAuthGrantEdges -EdgesById $edgesById -Grants @($betaCollections["$agentId|inheritedOauth"]) -TenantId $tenantId -SubjectId $agentId -SubjectType AgentIdentity -GrantOrigin blueprintInherited -ServicePrincipalsById $servicePrincipalsById -RetrievedAt $retrievedAt

        foreach ($group in @($v1Collections["$agentId|groups"])) {
            if ($null -eq $group) {
                Write-Warning "Skipping a null transitive group membership returned for agent '$agentId'."
                continue
            }
            $groupId = [string](Get-ObjectProperty -InputObject $group -Name 'id' -DefaultValue '')
            if ([string]::IsNullOrWhiteSpace($groupId)) {
                $properties = @($group.PSObject.Properties.Name) -join ','
                Write-Warning "Skipping transitive group membership for agent '$agentId' because group id is missing. Properties=[$properties]."
                continue
            }
            $groupsById[$groupId] = $group
            $subjectTypes[$groupId] = 'Group'
            if (-not $groupMembers.ContainsKey($groupId)) {
                $groupMembers[$groupId] = [System.Collections.Generic.List[string]]::new()
            }
            $groupMembers[$groupId].Add($agentId)
            $edge = New-PermissionEdge `
                -EdgeClass identityLifecycle `
                -Relation memberOf `
                -TenantId $tenantId `
                -SubjectId $agentId `
                -SubjectType AgentIdentity `
                -TargetId $groupId `
                -TargetType Group `
                -SourceSystem MicrosoftGraph `
                -SourceTable transitiveMemberOf `
                -SourceObjectId "${agentId}:$groupId" `
                -RetrievedAt $retrievedAt `
                -Details @{
                    transitive = $true
                    displayName = [string](Get-ObjectProperty -InputObject $group -Name 'displayName' -DefaultValue '')
                }
            Add-UniqueEdge -EdgesById $edgesById -Edge $edge
        }
    }

    $groupRequests = [System.Collections.Generic.List[object]]::new()
    foreach ($groupId in $groupsById.Keys) {
        $groupRequests.Add([pscustomobject]@{ Key = $groupId; Url = "/groups/$groupId/appRoleAssignments?`$top=999" })
    }
    $groupCollections = Invoke-GraphBatchCollections -ApiVersion v1.0 -Requests @($groupRequests.ToArray()) -Headers $graphHeaders
    foreach ($groupId in $groupMembers.Keys) {
        foreach ($agentId in $groupMembers[$groupId]) {
            Add-AppRoleAssignmentEdges -EdgesById $edgesById -Assignments @($groupCollections[$groupId]) -TenantId $tenantId -SubjectId $agentId -SubjectType AgentIdentity -GrantOrigin groupDerived -ServicePrincipalsById $servicePrincipalsById -RetrievedAt $retrievedAt -GroupId $groupId
        }
    }

    foreach ($blueprint in $blueprints) {
        $permissionsUri = "$script:GraphBaseUri/beta/applications/$($blueprint.id)/microsoft.graph.agentIdentityBlueprint/inheritablePermissions"
        $permissions = @(Invoke-GraphPagedRequest -Uri $permissionsUri -Headers $graphHeaders -MaxPages $maxPages)
        Add-InheritablePermissionEdges `
            -EdgesById $edgesById `
            -Permissions $permissions `
            -Blueprint $blueprint `
            -TenantId $tenantId `
            -ServicePrincipalsByAppId $servicePrincipalsByAppId `
            -RetrievedAt $retrievedAt
    }

    $roleAssignmentsUri = "$script:GraphBaseUri/v1.0/roleManagement/directory/roleAssignments?" +
        '$expand=roleDefinition&$top=999'
    $eligibleAssignmentsUri = "$script:GraphBaseUri/beta/roleManagement/directory/roleEligibilityScheduleInstances?" +
        '$expand=roleDefinition&$top=999'
    $directoryRoleAssignments = @(Invoke-GraphPagedRequest -Uri $roleAssignmentsUri -Headers $graphHeaders -MaxPages $maxPages)
    $directoryRoleEligibility = @(Invoke-GraphPagedRequest -Uri $eligibleAssignmentsUri -Headers $graphHeaders -MaxPages $maxPages)
    foreach ($roleRecord in @($directoryRoleAssignments) + @($directoryRoleEligibility)) {
        if ($null -eq $roleRecord) {
            Write-Warning 'Skipping a null directory-role assignment record.'
            continue
        }
        $principalId = [string](Get-ObjectProperty -InputObject $roleRecord -Name 'principalId' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($principalId)) {
            $properties = @($roleRecord.PSObject.Properties.Name) -join ','
            Write-Warning "Skipping directory-role metadata because principalId is missing. Properties=[$properties]."
            continue
        }
        if (-not $subjectTypes.ContainsKey($principalId)) {
            continue
        }
        $eligible = $roleRecord.PSObject.Properties['memberType'] -ne $null -or $roleRecord.PSObject.Properties['startDateTime'] -ne $null
        $roleDefinition = Get-ObjectProperty -InputObject $roleRecord -Name 'roleDefinition' -DefaultValue @{}
        $roleDefinitionId = [string](Get-ObjectProperty -InputObject $roleRecord -Name 'roleDefinitionId' -DefaultValue '')
        $edge = New-PermissionEdge `
            -EdgeClass configured `
            -Relation $(if ($eligible) { 'eligibleToInherit' } else { 'assigned' }) `
            -TenantId $tenantId `
            -SubjectId $principalId `
            -SubjectType $subjectTypes[$principalId] `
            -TargetId $roleDefinitionId `
            -TargetType RoleDefinition `
            -PermissionId $roleDefinitionId `
            -PermissionValue ([string](Get-ObjectProperty -InputObject $roleDefinition -Name 'displayName' -DefaultValue $roleDefinitionId)) `
            -PermissionMode application `
            -AuthorizationMechanism directoryRole `
            -GrantOrigin $(if ($subjectTypes[$principalId] -eq 'Group') { 'groupDerived' } else { 'direct' }) `
            -GrantState $(if ($eligible) { 'eligible' } else { 'active' }) `
            -ResourceScope ([string](Get-ObjectProperty -InputObject $roleRecord -Name 'directoryScopeId' -DefaultValue '/')) `
            -SourceSystem MicrosoftGraph `
            -SourceTable $(if ($eligible) { 'roleEligibilityScheduleInstances' } else { 'roleAssignments' }) `
            -SourceObjectId ([string]$roleRecord.id) `
            -RetrievedAt $retrievedAt `
            -ValidFrom (Get-ObjectProperty -InputObject $roleRecord -Name 'startDateTime') `
            -ValidTo (Get-ObjectProperty -InputObject $roleRecord -Name 'endDateTime')
        Add-UniqueEdge -EdgesById $edgesById -Edge $edge
    }

    $argQuery = @'
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId = tostring(properties.principalId),
         principalType = tostring(properties.principalType),
         roleDefinitionId = tolower(tostring(properties.roleDefinitionId)),
         roleScope = tostring(properties.scope),
         condition = tostring(properties.condition),
         conditionVersion = tostring(properties.conditionVersion)
| join kind=leftouter (
    authorizationresources
    | where type =~ 'microsoft.authorization/roledefinitions'
    | project roleDefinitionId = tolower(id),
              roleName = tostring(properties.roleName),
              roleType = tostring(properties.type)
) on roleDefinitionId
| project id, principalId, principalType, roleDefinitionId, roleName, roleType, roleScope, condition, conditionVersion
'@
    $azureRoleAssignments = @(Invoke-ArgPagedQuery -SubscriptionId $subscriptionId -Query $argQuery -Headers $managementHeaders)
    foreach ($assignment in $azureRoleAssignments) {
        $principalId = [string]$assignment.principalId
        if (-not $subjectTypes.ContainsKey($principalId)) {
            continue
        }

        $roleDefinitionId = [string]$assignment.roleDefinitionId
        $edge = New-PermissionEdge `
            -EdgeClass configured `
            -Relation assigned `
            -TenantId $tenantId `
            -SubjectId $principalId `
            -SubjectType $subjectTypes[$principalId] `
            -TargetId ([string]$assignment.roleScope) `
            -TargetType Resource `
            -PermissionId $roleDefinitionId `
            -PermissionValue ([string]$assignment.roleName) `
            -PermissionMode application `
            -AuthorizationMechanism azureRbac `
            -GrantOrigin $(if ($subjectTypes[$principalId] -eq 'Group') { 'groupDerived' } else { 'direct' }) `
            -GrantState active `
            -ResourceScope ([string]$assignment.roleScope) `
            -SourceSystem AzureResourceGraph `
            -SourceTable authorizationresources `
            -SourceObjectId ([string]$assignment.id) `
            -RetrievedAt $retrievedAt `
            -Details @{
                principalType = [string]$assignment.principalType
                roleType = [string]$assignment.roleType
                hasCondition = -not [string]::IsNullOrWhiteSpace([string]$assignment.condition)
                conditionVersion = [string]$assignment.conditionVersion
            }
        Add-UniqueEdge -EdgesById $edgesById -Edge $edge
    }

    if ($enableAuditLogs) {
        $auditStart = $retrievedAt.AddHours(-1 * $auditLookbackHours).ToString('o')
        $auditUri = "$script:GraphBaseUri/v1.0/auditLogs/directoryAudits?" +
            "`$filter=activityDateTime ge $auditStart&`$orderby=activityDateTime asc&`$top=999"
        $auditEvents = @(Invoke-GraphPagedRequest -Uri $auditUri -Headers $graphHeaders -MaxPages $maxPages)
        foreach ($auditEvent in $auditEvents) {
            $operation = [string](Get-ObjectProperty -InputObject $auditEvent -Name 'activityDisplayName' -DefaultValue '')
            if ($operation -notmatch '(?i)(permission|consent|app role|directory role|role assignment|conditional access|service principal|agent identity)') {
                continue
            }

            foreach ($target in @((Get-ObjectProperty -InputObject $auditEvent -Name 'targetResources' -DefaultValue @()))) {
                $targetId = [string](Get-ObjectProperty -InputObject $target -Name 'id' -DefaultValue '')
                if (-not $subjectTypes.ContainsKey($targetId)) {
                    continue
                }

                $edge = New-PermissionEdge `
                    -EdgeClass observed `
                    -Relation observedUsing `
                    -TenantId $tenantId `
                    -SubjectId $targetId `
                    -SubjectType $subjectTypes[$targetId] `
                    -TargetId "audit-operation:$operation" `
                    -TargetType Resource `
                    -AuthorizationMechanism runtimeObservation `
                    -GrantOrigin notApplicable `
                    -Operation $operation `
                    -EventId ([string]$auditEvent.id) `
                    -SourceSystem MicrosoftGraph `
                    -SourceTable directoryAudits `
                    -SourceObjectId ([string]$auditEvent.id) `
                    -EvidenceAuthority nativeTelemetry `
                    -ObservedAt (Get-ObjectProperty -InputObject $auditEvent -Name 'activityDateTime') `
                    -RetrievedAt $retrievedAt `
                    -Details @{
                        category = [string](Get-ObjectProperty -InputObject $auditEvent -Name 'category' -DefaultValue '')
                        result = [string](Get-ObjectProperty -InputObject $auditEvent -Name 'result' -DefaultValue '')
                        correlationId = [string](Get-ObjectProperty -InputObject $auditEvent -Name 'correlationId' -DefaultValue '')
                    }
                Add-UniqueEdge -EdgesById $edgesById -Edge $edge
            }
        }
    }

    if ($enableConditionalAccess) {
        $policiesUri = "$script:GraphBaseUri/v1.0/identity/conditionalAccess/policies?`$top=999"
        $policies = @(Invoke-GraphPagedRequest -Uri $policiesUri -Headers $graphHeaders -MaxPages $maxPages)
        foreach ($policy in $policies) {
            $conditions = Get-ObjectProperty -InputObject $policy -Name 'conditions' -DefaultValue @{}
            $clientApplications = Get-ObjectProperty -InputObject $conditions -Name 'clientApplications' -DefaultValue @{}
            $includedServicePrincipals = @((Get-ObjectProperty -InputObject $clientApplications -Name 'includeServicePrincipals' -DefaultValue @()))
            $excludedServicePrincipals = @((Get-ObjectProperty -InputObject $clientApplications -Name 'excludeServicePrincipals' -DefaultValue @()))
            $applications = Get-ObjectProperty -InputObject $conditions -Name 'applications' -DefaultValue @{}
            $includedApplications = @((Get-ObjectProperty -InputObject $applications -Name 'includeApplications' -DefaultValue @()))
            $excludedApplications = @((Get-ObjectProperty -InputObject $applications -Name 'excludeApplications' -DefaultValue @()))
            $grantControls = Get-ObjectProperty -InputObject $policy -Name 'grantControls' -DefaultValue @{}
            $builtInControls = @((Get-ObjectProperty -InputObject $grantControls -Name 'builtInControls' -DefaultValue @()))
            $isBlock = $builtInControls -contains 'block'

            foreach ($agent in $agents) {
                $agentId = [string]$agent.id
                $appId = [string](Get-ObjectProperty -InputObject $agent -Name 'appId' -DefaultValue '')
                $targeting = if (
                    $excludedServicePrincipals -contains $agentId -or
                    $excludedApplications -contains $appId
                ) {
                    'excluded'
                }
                elseif (
                    $includedServicePrincipals -contains 'All' -or
                    $includedServicePrincipals -contains $agentId -or
                    $includedApplications -contains 'All' -or
                    $includedApplications -contains $appId
                ) {
                    'included'
                }
                else {
                    continue
                }
                $state = [string](Get-ObjectProperty -InputObject $policy -Name 'state' -DefaultValue 'unknown')
                $relation = if ($targeting -eq 'included' -and $state -eq 'enabled' -and $isBlock) { 'blockedBy' } else { 'constrainedBy' }
                $edge = New-PermissionEdge `
                    -EdgeClass control `
                    -Relation $relation `
                    -TenantId $tenantId `
                    -SubjectId ([string]$agent.id) `
                    -SubjectType AgentIdentity `
                    -TargetId ([string]$policy.id) `
                    -TargetType Control `
                    -AuthorizationMechanism policyEvaluation `
                    -GrantOrigin notApplicable `
                    -GrantState "${state}:$targeting" `
                    -SourceSystem MicrosoftGraph `
                    -SourceTable conditionalAccessPolicies `
                    -SourceObjectId "$($policy.id):$($agent.id):$targeting" `
                    -RetrievedAt $retrievedAt `
                    -Details @{
                        displayName = [string](Get-ObjectProperty -InputObject $policy -Name 'displayName' -DefaultValue '')
                        targeting = $targeting
                        targetPlane = $(if ($includedServicePrincipals.Count -gt 0 -or $excludedServicePrincipals.Count -gt 0) { 'workloadIdentity' } else { 'application' })
                        builtInControls = $builtInControls
                    }
                Add-UniqueEdge -EdgesById $edgesById -Edge $edge
            }
        }
    }

    Add-DerivedReachabilityEdges `
        -EdgesById $edgesById `
        -TenantId $tenantId `
        -RetrievedAt $retrievedAt

    $records = @($edgesById.Values | Sort-Object EdgeId)
    $batchMaxRecords = [int](Get-ObjectProperty -InputObject $Configuration -Name 'batchMaxRecords' -DefaultValue 500)
    $batchMaxBytes = [int](Get-ObjectProperty -InputObject $Configuration -Name 'batchMaxBytes' -DefaultValue 900000)
    $ingestionHeaders = @{}
    if (-not $DryRun) {
        $ingestionHeaders.Authorization = "Bearer $(Get-ManagedIdentityToken -ResourceUrl $script:MonitorResourceUri)"
    }
    $ingestion = Send-LogIngestionBatches `
        -Records $records `
        -DceEndpoint ([string](Get-ObjectProperty -InputObject $Configuration -Name 'dceEndpoint' -DefaultValue 'https://dry-run.invalid')) `
        -DcrImmutableId ([string](Get-ObjectProperty -InputObject $Configuration -Name 'dcrImmutableId' -DefaultValue 'dry-run')) `
        -StreamName ([string](Get-ObjectProperty -InputObject $Configuration -Name 'streamName' -DefaultValue 'Custom-AgentPermissionEdges_CL')) `
        -Headers $ingestionHeaders `
        -MaxRecords $batchMaxRecords `
        -MaxBytes $batchMaxBytes `
        -DryRun:$DryRun

    $classCounts = @($records | Group-Object EdgeClass | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })
    $sourceCounts = @($records | Group-Object SourceSystem | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })
    Write-Output "[$script:CollectorName] Completed. Records=$($records.Count); Batches=$($ingestion.BatchCount); Sent=$($ingestion.Sent)."
    Write-Output "[$script:CollectorName] Edge classes: $($classCounts -join ', ')."
    Write-Output "[$script:CollectorName] Sources: $($sourceCounts -join ', ')."

    return [pscustomobject]@{
        Records = $records
        Ingestion = $ingestion
        RetrievedAt = $retrievedAt
    }
}

if (-not $NoRun) {
    try {
        $configuration = Get-AutomationConfiguration -Path $ConfigPath
        Invoke-AgentPermissionEdgeCollection -Configuration $configuration -DryRun:$DryRun | Out-Null
    }
    catch {
        Write-Error "[$script:CollectorName] Collection failed: $($_.Exception.Message)`nScript stack:`n$($_.ScriptStackTrace)"
        throw
    }
}
