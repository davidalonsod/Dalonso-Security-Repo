[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [string]$ConfigPath,
    [string]$RunbookPath = (Join-Path $PSScriptRoot 'AgentPermissionEdgeCollector.ps1'),
    [switch]$EnableSchedule
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GraphAppId = '00000003-0000-0000-c000-000000000000'
$script:GraphBaseUri = 'https://graph.microsoft.com'
$script:RequiredGraphAppRoles = @(
    'Application.Read.All',
    'Directory.Read.All',
    'RoleManagement.Read.Directory',
    'AuditLog.Read.All',
    'Policy.Read.All'
)

function Get-ObjectProperty {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,
        [Parameter(Mandatory)]
        [string]$Name,
        [object]$DefaultValue = $null
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
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

function Assert-RequiredCommand {
    param(
        [Parameter(Mandatory)]
        [string[]]$Name
    )

    foreach ($commandName in $Name) {
        if ($null -eq (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
            throw "Required command '$commandName' is unavailable. Install/import the corresponding Az module before running this script."
        }
    }
}

function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [hashtable]$Headers,
        [object]$Body
    )

    $parameters = @{
        Method = $Method
        Uri = $Uri
        Headers = $Headers
        ContentType = 'application/json'
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $parameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress
    }

    try {
        return Invoke-RestMethod @parameters
    }
    catch {
        $response = Get-ObjectProperty -InputObject $_.Exception -Name 'Response'
        $status = if ($null -eq $response) { 'unknown' } else { [string](Get-ObjectProperty -InputObject $response -Name 'StatusCode' -DefaultValue 'unknown') }
        throw "Microsoft Graph $Method '$Uri' failed with status ${status}: $($_.Exception.Message)"
    }
}

function Get-PagedGraphResults {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri
    while (-not [string]::IsNullOrWhiteSpace($nextLink)) {
        $response = Invoke-GraphRequest -Method GET -Uri $nextLink -Headers $Headers
        foreach ($item in @((Get-ObjectProperty -InputObject $response -Name 'value' -DefaultValue @()))) {
            $results.Add($item)
        }
        $nextLink = [string](Get-ObjectProperty -InputObject $response -Name '@odata.nextLink' -DefaultValue '')
    }

    return @($results.ToArray())
}

function Assert-DeploymentConfiguration {
    param(
        [Parameter(Mandatory)]
        [object]$Configuration
    )

    foreach ($name in @(
        'tenantId',
        'subscriptionId',
        'resourceGroupName',
        'automationAccountName',
        'managedIdentityPrincipalId',
        'dceEndpoint',
        'dcrImmutableId',
        'streamName',
        'runbookName',
        'runtimeEnvironmentName',
        'runtimeVersion',
        'scheduleName',
        'scheduleStartTimeUtc'
    )) {
        if ([string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -InputObject $Configuration -Name $name))) {
            throw "Deployment configuration property '$name' is required."
        }
    }

    $moduleDefinitions = @((Get-ObjectProperty -InputObject $Configuration -Name 'automationModules' -DefaultValue @()))
    if ($moduleDefinitions.Count -eq 0) {
        throw "Deployment configuration property 'automationModules' must contain at least Az.Accounts."
    }
    if (-not ($moduleDefinitions | Where-Object { $_.name -eq 'Az.Accounts' })) {
        throw "Deployment configuration must include the 'Az.Accounts' Automation module."
    }
    if ([string]$Configuration.runtimeVersion -ne '7.2') {
        throw "This collector runbook requires runtimeVersion '7.2'."
    }
}

function Set-GraphAppRoleAssignments {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PrincipalId,
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $filter = [Uri]::EscapeDataString("appId eq '$script:GraphAppId'")
    $graphServicePrincipals = @(Get-PagedGraphResults -Uri "$script:GraphBaseUri/v1.0/servicePrincipals?`$filter=$filter&`$select=id,appId,appRoles" -Headers $Headers)
    if ($graphServicePrincipals.Count -ne 1) {
        throw "Expected one Microsoft Graph service principal, found $($graphServicePrincipals.Count)."
    }

    $graphServicePrincipal = $graphServicePrincipals[0]
    $existingAssignments = @(Get-PagedGraphResults -Uri "$script:GraphBaseUri/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments?`$top=999" -Headers $Headers)
    foreach ($roleValue in $script:RequiredGraphAppRoles) {
        $matches = @($graphServicePrincipal.appRoles | Where-Object {
            $_.value -eq $roleValue -and
            $_.isEnabled -eq $true -and
            @($_.allowedMemberTypes) -contains 'Application'
        })
        if ($matches.Count -ne 1) {
            throw "Could not resolve one enabled Microsoft Graph application role for '$roleValue'."
        }

        $appRoleId = [string]$matches[0].id
        $alreadyAssigned = @($existingAssignments | Where-Object {
            [string]$_.resourceId -eq [string]$graphServicePrincipal.id -and
            [string]$_.appRoleId -eq $appRoleId
        }).Count -gt 0
        if ($alreadyAssigned) {
            Write-Output "Graph application role '$roleValue' is already assigned."
            continue
        }

        if ($PSCmdlet.ShouldProcess($PrincipalId, "Assign Microsoft Graph application role '$roleValue'")) {
            $body = @{
                principalId = $PrincipalId
                resourceId = [string]$graphServicePrincipal.id
                appRoleId = $appRoleId
            }
            Invoke-GraphRequest `
                -Method POST `
                -Uri "$script:GraphBaseUri/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" `
                -Headers $Headers `
                -Body $body | Out-Null
            Write-Output "Assigned Microsoft Graph application role '$roleValue'."
        }
    }
}

function Set-AutomationVariableValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory)]
        [string]$AutomationAccountName,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [object]$Value
    )

    $existing = Get-AzAutomationVariable `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName `
        -Name $Name `
        -ErrorAction SilentlyContinue

    if ($null -eq $existing) {
        if ($PSCmdlet.ShouldProcess($Name, 'Create unencrypted Automation variable')) {
            New-AzAutomationVariable `
                -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName `
                -Name $Name `
                -Value $Value `
                -Encrypted $false | Out-Null
        }
        return
    }

    $existingValue = [string](Get-ObjectProperty -InputObject $existing -Name 'Value' -DefaultValue '')
    if ($existingValue -eq [string]$Value) {
        return
    }

    if ($PSCmdlet.ShouldProcess($Name, 'Update unencrypted Automation variable')) {
        Set-AzAutomationVariable `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName `
            -Name $Name `
            -Value $Value `
            -Encrypted $false | Out-Null
    }
}

function Set-AutomationRuntimeEnvironment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory)]
        [string]$AutomationAccountName,
        [Parameter(Mandatory)]
        [object[]]$Modules,
        [Parameter(Mandatory)]
        [string]$RuntimeEnvironmentName,
        [Parameter(Mandatory)]
        [string]$RuntimeVersion,
        [ValidateRange(1, 120)]
        [int]$ImportTimeoutMinutes = 30
    )

    $runtimeEnvironmentResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runtimeEnvironments/$RuntimeEnvironmentName"
    $runtimePayload = @{
        name = $RuntimeEnvironmentName
        properties = @{
            runtime = @{
                language = 'PowerShell'
                version = $RuntimeVersion
            }
            defaultPackages = @{}
        }
    } | ConvertTo-Json -Depth 10 -Compress

    if ($PSCmdlet.ShouldProcess($runtimeEnvironmentResourceId, "Configure PowerShell $RuntimeVersion Automation runtime environment")) {
        Invoke-AzRestMethod `
            -Method PUT `
            -Path "${runtimeEnvironmentResourceId}?api-version=2024-10-23" `
            -Payload $runtimePayload | Out-Null
    }

    foreach ($module in $Modules) {
        $name = [string]$module.name
        $version = [string]$module.version
        if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($version)) {
            throw "Each automationModules entry requires non-empty 'name' and 'version' values."
        }

        $packageResourceId = "$runtimeEnvironmentResourceId/packages/$name"
        $existing = try {
            $existingResponse = Invoke-AzRestMethod -Method GET -Path "${packageResourceId}?api-version=2024-10-23" -ErrorAction Stop
            if ([int]$existingResponse.StatusCode -eq 200) {
                $existingResponse.Content | ConvertFrom-Json -Depth 20
            }
            elseif ([int]$existingResponse.StatusCode -eq 404) {
                $null
            }
            else {
                throw "Runtime package '$name' lookup returned HTTP $($existingResponse.StatusCode)."
            }
        }
        catch {
            $response = Get-ObjectProperty -InputObject $_.Exception -Name 'Response'
            $statusCode = if ($null -eq $response) {
                $null
            }
            else {
                Get-ObjectProperty -InputObject $response -Name 'StatusCode'
            }
            if ($null -ne $statusCode -and [int]$statusCode -eq 404) {
                $null
            }
            else {
                throw "Failed to inspect runtime package '$name': $($_.Exception.Message)"
            }
        }
        $existingVersion = if ($null -eq $existing) {
            ''
        }
        else {
            [string](Get-ObjectProperty -InputObject $existing.properties -Name 'version' -DefaultValue '')
        }
        $existingState = if ($null -eq $existing) {
            ''
        }
        else {
            [string](Get-ObjectProperty -InputObject $existing.properties -Name 'provisioningState' -DefaultValue '')
        }
        if ($existingVersion -eq $version -and $existingState -eq 'Succeeded') {
            Write-Output "Runtime package '$name' version '$version' is already available."
            continue
        }

        $packageUri = "https://www.powershellgallery.com/api/v2/package/$name/$version"
        $payload = @{
            properties = @{
                contentLink = @{
                    uri = $packageUri
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress

        if (-not $PSCmdlet.ShouldProcess($packageResourceId, "Import runtime package '$name' version '$version'")) {
            continue
        }

        Invoke-AzRestMethod `
            -Method PUT `
            -Path "${packageResourceId}?api-version=2024-10-23" `
            -Payload $payload | Out-Null

        $deadline = [datetime]::UtcNow.AddMinutes($ImportTimeoutMinutes)
        do {
            Start-Sleep -Seconds 10
            $currentResponse = Invoke-AzRestMethod -Method GET -Path "${packageResourceId}?api-version=2024-10-23"
            if ([int]$currentResponse.StatusCode -ne 200) {
                throw "Runtime package '$name' status returned HTTP $($currentResponse.StatusCode)."
            }
            $current = $currentResponse.Content | ConvertFrom-Json -Depth 20
            $currentState = [string](Get-ObjectProperty -InputObject $current.properties -Name 'provisioningState' -DefaultValue '')
            $currentVersion = [string](Get-ObjectProperty -InputObject $current.properties -Name 'version' -DefaultValue '')
            if ($currentState -eq 'Failed') {
                throw "Runtime package '$name' version '$version' failed to import."
            }
        } while (
            ($currentState -ne 'Succeeded' -or $currentVersion -ne $version) -and
            [datetime]::UtcNow -lt $deadline
        )

        if ($currentState -ne 'Succeeded' -or $currentVersion -ne $version) {
            throw "Runtime package '$name' version '$version' did not finish importing within $ImportTimeoutMinutes minute(s)."
        }
        Write-Output "Imported runtime package '$name' version '$version'."
    }
}

function Get-NextScheduleStart {
    param(
        [Parameter(Mandatory)]
        [string]$TimeUtc
    )

    $time = [TimeSpan]::Parse($TimeUtc, [Globalization.CultureInfo]::InvariantCulture)
    $start = [datetime]::UtcNow.Date.Add($time)
    if ($start -lt [datetime]::UtcNow.AddMinutes(5)) {
        $start = $start.AddDays(1)
    }
    return [datetime]::SpecifyKind($start, [DateTimeKind]::Utc)
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Deployment configuration file '$ConfigPath' does not exist."
}
if (-not (Test-Path -LiteralPath $RunbookPath -PathType Leaf)) {
    throw "Runbook file '$RunbookPath' does not exist."
}

Assert-RequiredCommand -Name @(
    'Get-AzContext',
    'Set-AzContext',
    'Get-AzAccessToken',
    'Invoke-AzRestMethod',
    'Get-AzAutomationVariable',
    'New-AzAutomationVariable',
    'Set-AzAutomationVariable',
    'Import-AzAutomationRunbook',
    'Publish-AzAutomationRunbook',
    'Get-AzAutomationSchedule',
    'New-AzAutomationSchedule',
    'Set-AzAutomationSchedule',
    'Get-AzAutomationScheduledRunbook',
    'Register-AzAutomationScheduledRunbook'
)

$configuration = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -Depth 30
Assert-DeploymentConfiguration -Configuration $configuration

$context = Get-AzContext
if ($null -eq $context -or [string]$context.Tenant.Id -ne [string]$configuration.tenantId) {
    throw "Authenticate to tenant '$($configuration.tenantId)' with an authorized deployment identity before running this script."
}
Set-AzContext -SubscriptionId ([string]$configuration.subscriptionId) -TenantId ([string]$configuration.tenantId) | Out-Null

$token = Get-AzAccessToken -ResourceUrl $script:GraphBaseUri -ErrorAction Stop
$graphHeaders = @{
    Authorization = "Bearer $(ConvertFrom-SecureToken -Token $token.Token)"
    Accept = 'application/json'
}

Set-GraphAppRoleAssignments `
    -PrincipalId ([string]$configuration.managedIdentityPrincipalId) `
    -Headers $graphHeaders `
    -WhatIf:$WhatIfPreference

$resourceGroupName = [string]$configuration.resourceGroupName
$automationAccountName = [string]$configuration.automationAccountName
$automationVariables = [ordered]@{
    TenantId = [string]$configuration.tenantId
    SubscriptionId = [string]$configuration.subscriptionId
    DceEndpoint = [string]$configuration.dceEndpoint
    DcrImmutableId = [string]$configuration.dcrImmutableId
    StreamName = [string]$configuration.streamName
    AuditLookbackHours = [int](Get-ObjectProperty -InputObject $configuration -Name 'auditLookbackHours' -DefaultValue 26)
    BatchMaxRecords = [int](Get-ObjectProperty -InputObject $configuration -Name 'batchMaxRecords' -DefaultValue 500)
    BatchMaxBytes = [int](Get-ObjectProperty -InputObject $configuration -Name 'batchMaxBytes' -DefaultValue 900000)
    GraphMaxPages = [int](Get-ObjectProperty -InputObject $configuration -Name 'graphMaxPages' -DefaultValue 10000)
    CredentialExpiryWarningDays = [int](Get-ObjectProperty -InputObject $configuration -Name 'credentialExpiryWarningDays' -DefaultValue 30)
    EnableAuditLogs = [bool](Get-ObjectProperty -InputObject $configuration -Name 'enableAuditLogs' -DefaultValue $true)
    EnableConditionalAccess = [bool](Get-ObjectProperty -InputObject $configuration -Name 'enableConditionalAccess' -DefaultValue $true)
}
foreach ($entry in $automationVariables.GetEnumerator()) {
    Set-AutomationVariableValue `
        -ResourceGroupName $resourceGroupName `
        -AutomationAccountName $automationAccountName `
        -Name "AgentPermissionEdge.$($entry.Key)" `
        -Value $entry.Value `
        -WhatIf:$WhatIfPreference
}

Set-AutomationRuntimeEnvironment `
    -SubscriptionId ([string]$configuration.subscriptionId) `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Modules @($configuration.automationModules) `
    -RuntimeEnvironmentName ([string]$configuration.runtimeEnvironmentName) `
    -RuntimeVersion ([string]$configuration.runtimeVersion) `
    -ImportTimeoutMinutes ([int](Get-ObjectProperty -InputObject $configuration -Name 'moduleImportTimeoutMinutes' -DefaultValue 30)) `
    -WhatIf:$WhatIfPreference

$runbookName = [string]$configuration.runbookName
if ($PSCmdlet.ShouldProcess($runbookName, 'Import and publish PowerShell 7.2 Automation runbook')) {
    Import-AzAutomationRunbook `
        -ResourceGroupName $resourceGroupName `
        -AutomationAccountName $automationAccountName `
        -Name $runbookName `
        -Path (Resolve-Path -LiteralPath $RunbookPath).Path `
        -Type PowerShell `
        -Force | Out-Null

    Publish-AzAutomationRunbook `
        -ResourceGroupName $resourceGroupName `
        -AutomationAccountName $automationAccountName `
        -Name $runbookName | Out-Null

    # Publish-AzAutomationRunbook rewrites the runbook resource. Associate the
    # runtime after publication so the PowerShell 7.2 runtime isn't cleared.
    $runbookResourceId = "/subscriptions/$($configuration.subscriptionId)/resourceGroups/$resourceGroupName/providers/Microsoft.Automation/automationAccounts/$automationAccountName/runbooks/$runbookName"
    $runbookPayload = @{
        properties = @{
            type = 'PowerShell'
            runtimeEnvironment = [string]$configuration.runtimeEnvironmentName
        }
    } | ConvertTo-Json -Depth 10 -Compress
    Invoke-AzRestMethod `
        -Method PATCH `
        -Path "${runbookResourceId}?api-version=2024-10-23" `
        -Payload $runbookPayload | Out-Null
}

$scheduleName = [string]$configuration.scheduleName
$schedule = Get-AzAutomationSchedule `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Name $scheduleName `
    -ErrorAction SilentlyContinue
$scheduleEnabled = [bool]$EnableSchedule
if ($null -eq $schedule) {
    if ($PSCmdlet.ShouldProcess($scheduleName, "Create daily Automation schedule (enabled=$scheduleEnabled)")) {
        $schedule = New-AzAutomationSchedule `
            -ResourceGroupName $resourceGroupName `
            -AutomationAccountName $automationAccountName `
            -Name $scheduleName `
            -StartTime (Get-NextScheduleStart -TimeUtc ([string]$configuration.scheduleStartTimeUtc)) `
            -DayInterval 1 `
            -TimeZone 'UTC'
        if (-not $scheduleEnabled) {
            Set-AzAutomationSchedule `
                -ResourceGroupName $resourceGroupName `
                -AutomationAccountName $automationAccountName `
                -Name $scheduleName `
                -IsEnabled $false | Out-Null
        }
    }
}
elseif ([bool]$schedule.IsEnabled -ne $scheduleEnabled) {
    if ($PSCmdlet.ShouldProcess($scheduleName, "Set Automation schedule enabled=$scheduleEnabled")) {
        Set-AzAutomationSchedule `
            -ResourceGroupName $resourceGroupName `
            -AutomationAccountName $automationAccountName `
            -Name $scheduleName `
            -IsEnabled $scheduleEnabled | Out-Null
    }
}

$associations = @(Get-AzAutomationScheduledRunbook `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -RunbookName $runbookName `
    -ErrorAction SilentlyContinue)
$associated = @($associations | Where-Object { [string]$_.ScheduleName -eq $scheduleName }).Count -gt 0
if (-not $associated -and $PSCmdlet.ShouldProcess($runbookName, "Associate schedule '$scheduleName'")) {
    Register-AzAutomationScheduledRunbook `
        -ResourceGroupName $resourceGroupName `
        -AutomationAccountName $automationAccountName `
        -RunbookName $runbookName `
        -ScheduleName $scheduleName | Out-Null
}

Write-Output "Collector post-infrastructure configuration is complete. ScheduleEnabled=$scheduleEnabled."
