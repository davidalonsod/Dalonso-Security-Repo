targetScope = 'subscription'

@description('Existing resource group containing LAWSentinel and aa-sentinel-sync.')
param resourceGroupName string = 'RG_Sentinel'

@description('Azure region for collector resources.')
param location string = 'northeurope'

@description('Existing Log Analytics workspace name.')
param workspaceName string = 'LAWSentinel'

@description('Existing Automation Account name.')
param automationAccountName string = 'aa-sentinel-sync'

@description('System-assigned managed identity principal ID for the existing Automation Account.')
param automationPrincipalId string = '4e4b610b-2595-4bdd-82a2-437af67d6570'

@description('Custom table name. Must end in _CL.')
param tableName string = 'AgentPermissionEdges_CL'

@description('Dedicated Data Collection Endpoint name.')
param dataCollectionEndpointName string = 'dce-agent-permission-edges'

@description('Dedicated Data Collection Rule name.')
param dataCollectionRuleName string = 'dcr-agent-permission-edges'

@description('Analytics retention for the custom table.')
@minValue(30)
param retentionInDays int = 90

@description('Total retention for the custom table.')
@minValue(30)
param totalRetentionInDays int = 365

@description('Collector version written to Automation variables and table rows.')
param collectorVersion string = '1.0.0'

@description('Tags applied to new Azure resources.')
param tags object = {
  workload: 'agent-permission-intelligence'
  dataClassification: 'security-metadata'
  managedBy: 'bicep'
}

resource targetResourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  name: resourceGroupName
}

module collectorInfrastructure './modules/permission-edge-ingestion.bicep' = {
  name: 'agent-permission-edge-ingestion'
  scope: targetResourceGroup
  params: {
    location: location
    workspaceName: workspaceName
    automationAccountName: automationAccountName
    automationPrincipalId: automationPrincipalId
    tableName: tableName
    dataCollectionEndpointName: dataCollectionEndpointName
    dataCollectionRuleName: dataCollectionRuleName
    retentionInDays: retentionInDays
    totalRetentionInDays: totalRetentionInDays
    tags: tags
  }
}

var readerRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'acdd72a7-3385-48ef-bd42-f606fba81ae7'
)

resource subscriptionReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, automationPrincipalId, readerRoleDefinitionId)
  properties: {
    roleDefinitionId: readerRoleDefinitionId
    principalId: automationPrincipalId
    principalType: 'ServicePrincipal'
    description: 'Read Azure resource and RBAC metadata for Agent Permission Intelligence.'
  }
}

output workspaceResourceId string = collectorInfrastructure.outputs.workspaceResourceId
output automationAccountResourceId string = collectorInfrastructure.outputs.automationAccountResourceId
output automationPrincipalId string = automationPrincipalId
output tableName string = tableName
output streamName string = collectorInfrastructure.outputs.streamName
output dataCollectionEndpointId string = collectorInfrastructure.outputs.dataCollectionEndpointId
output logsIngestionEndpoint string = collectorInfrastructure.outputs.logsIngestionEndpoint
output dataCollectionRuleId string = collectorInfrastructure.outputs.dataCollectionRuleId
output dataCollectionRuleImmutableId string = collectorInfrastructure.outputs.dataCollectionRuleImmutableId
output collectorVersion string = collectorVersion
output subscriptionId string = subscription().subscriptionId
output tenantId string = tenant().tenantId
