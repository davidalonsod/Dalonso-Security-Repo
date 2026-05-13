// =====================================================================
// Automation Account + Runbook + Schedule for Sync-NamedLocationsToWatchlist
//
// Supports two auth modes (parameter `authMode`):
//   SP  (recommended) - Service principal, secret stored as encrypted
//                       Automation Variable `SpClientSecret`. Works in
//                       tenants whose CA blocks managed identities.
//   MI                - System-assigned managed identity. Requires the
//                       tenant to not block workload-identity MFA (or to
//                       have Workload Identities Premium to exempt the MI).
//
// Deploy in two passes (see Watchlists/README.md section 5.3):
//   1. Deploy with linkJobSchedule=false (default) to create the account,
//      empty runbook, schedule, and encrypted SpClientSecret variable.
//   2. Upload + publish the runbook content via `az rest`.
//   3. Re-deploy with linkJobSchedule=true to attach the daily schedule.
// =====================================================================

@description('Name of the Automation Account to create.')
param automationAccountName string = 'aa-sentinel-sync'

@description('Location for the Automation Account.')
param location string = resourceGroup().location

@description('Sentinel Log Analytics workspace name (in this resource group).')
param workspaceName string

@description('Target watchlist alias.')
param watchlistAlias string = 'NetworkAllowlist'

@description('Schedule frequency in hours (default: every 24h).')
param scheduleHours int = 24

@description('First run time (ISO 8601 UTC). Default = 1 hour after deployment.')
param scheduleStartTime string = dateTimeAdd(utcNow('u'), 'PT1H')

@description('Link the job schedule to the runbook? Set true ONLY on a second deploy AFTER the runbook content has been uploaded and published, because Azure rejects linking a job schedule to an empty (unpublished) runbook.')
param linkJobSchedule bool = false

@description('Auth mode for the runbook. "MI" uses the Automation Account managed identity (requires CA Workload Identities Premium if your tenant blocks MIs from MFA). "SP" uses a service principal whose secret is stored as an encrypted Automation Variable.')
@allowed([ 'MI', 'SP' ])
param authMode string = 'MI'

@description('Required when authMode=SP. Tenant ID of the SP.')
param spTenantId string = ''

@description('Required when authMode=SP. Application (client) ID of the SP.')
param spClientId string = ''

@description('Required when authMode=SP. Client secret of the SP. Stored as an encrypted Automation Variable.')
@secure()
param spClientSecret string = ''

var runbookName = 'Sync-NamedLocationsToWatchlist'
var scheduleName = 'Daily'

resource automationAccount 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationAccountName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: { sku: { name: 'Basic' } }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2023-11-01' = {
  parent: automationAccount
  name: runbookName
  location: location
  properties: {
    runbookType: 'PowerShell72'
    logVerbose: false
    logProgress: false
    description: 'Syncs trusted Entra Named Locations to a Sentinel watchlist.'
  }
}

resource schedule 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {
  parent: automationAccount
  name: scheduleName
  properties: {
    description: 'Runs Sync-NamedLocationsToWatchlist on a fixed cadence.'
    startTime: scheduleStartTime
    frequency: 'Hour'
    interval: scheduleHours
    timeZone: 'UTC'
  }
}

// Encrypted Automation Variable holding the SP client secret (only when authMode=SP).
resource spSecretVar 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = if (authMode == 'SP') {
  parent: automationAccount
  name: 'SpClientSecret'
  properties: {
    isEncrypted: true
    value: '"${spClientSecret}"'
    description: 'Client secret for the SP used by Sync-NamedLocationsToWatchlist.'
  }
}

var jobScheduleParamsMi = {
  WatchlistAlias:     watchlistAlias
  SubscriptionId:     subscription().subscriptionId
  ResourceGroup:      resourceGroup().name
  WorkspaceName:      workspaceName
  UseManagedIdentity: 'true'
}
var jobScheduleParamsSp = {
  WatchlistAlias: watchlistAlias
  SubscriptionId: subscription().subscriptionId
  ResourceGroup:  resourceGroup().name
  WorkspaceName:  workspaceName
  TenantId:       spTenantId
  ClientId:       spClientId
}

resource jobSchedule 'Microsoft.Automation/automationAccounts/jobSchedules@2023-11-01' = if (linkJobSchedule) {
  parent: automationAccount
  name: guid(automationAccount.id, runbookName, scheduleName)
  properties: {
    runbook: { name: runbookName }
    schedule: { name: scheduleName }
    parameters: authMode == 'SP' ? jobScheduleParamsSp : jobScheduleParamsMi
  }
  dependsOn: [ runbook, schedule ]
}

// Grant the Automation Account's system-assigned MI 'Microsoft Sentinel
// Contributor' on this resource group so it can manage watchlists.
var sentinelContributorRoleId = 'ab8e14d6-4a74-4a29-9ba8-549422addade'
resource roleAssign 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, automationAccount.id, sentinelContributorRoleId)
  scope: resourceGroup()
  properties: {
    principalId:      automationAccount.identity.principalId
    principalType:    'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sentinelContributorRoleId)
  }
}

output automationAccountName string = automationAccount.name
output managedIdentityPrincipalId string = automationAccount.identity.principalId
output runbookName string = runbook.name
output postDeployNote string = 'See template header for the 3 post-deploy steps (upload content, publish, grant Graph Policy.Read.All).'
