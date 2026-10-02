targetScope = 'resourceGroup'

param location string
param workspaceName string
param automationAccountName string
param automationPrincipalId string
param tableName string
param dataCollectionEndpointName string
param dataCollectionRuleName string
param retentionInDays int
param totalRetentionInDays int
param tags object

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource automationAccount 'Microsoft.Automation/automationAccounts@2023-11-01' existing = {
  name: automationAccountName
}

var columns = [
  {
    name: 'TimeGenerated'
    type: 'datetime'
  }
  {
    name: 'EdgeId'
    type: 'string'
  }
  {
    name: 'EdgeClass'
    type: 'string'
  }
  {
    name: 'Relation'
    type: 'string'
  }
  {
    name: 'TenantId'
    type: 'guid'
  }
  {
    name: 'SubjectId'
    type: 'string'
  }
  {
    name: 'SubjectType'
    type: 'string'
  }
  {
    name: 'TargetId'
    type: 'string'
  }
  {
    name: 'TargetType'
    type: 'string'
  }
  {
    name: 'PermissionId'
    type: 'string'
  }
  {
    name: 'PermissionValue'
    type: 'string'
  }
  {
    name: 'PermissionMode'
    type: 'string'
  }
  {
    name: 'AuthorizationMechanism'
    type: 'string'
  }
  {
    name: 'GrantOrigin'
    type: 'string'
  }
  {
    name: 'ConsentType'
    type: 'string'
  }
  {
    name: 'DeclarationState'
    type: 'string'
  }
  {
    name: 'GrantState'
    type: 'string'
  }
  {
    name: 'TokenState'
    type: 'string'
  }
  {
    name: 'ConfiguredEdgeId'
    type: 'string'
  }
  {
    name: 'ResourceScope'
    type: 'string'
  }
  {
    name: 'Operation'
    type: 'string'
  }
  {
    name: 'EventId'
    type: 'string'
  }
  {
    name: 'SourceSystem'
    type: 'string'
  }
  {
    name: 'SourceTable'
    type: 'string'
  }
  {
    name: 'SourceObjectId'
    type: 'string'
  }
  {
    name: 'EvidenceAuthority'
    type: 'string'
  }
  {
    name: 'Confidence'
    type: 'string'
  }
  {
    name: 'ObservedAt'
    type: 'datetime'
  }
  {
    name: 'RetrievedAt'
    type: 'datetime'
  }
  {
    name: 'ValidFrom'
    type: 'datetime'
  }
  {
    name: 'ValidTo'
    type: 'datetime'
  }
  {
    name: 'CollectorName'
    type: 'string'
  }
  {
    name: 'CollectorVersion'
    type: 'string'
  }
  {
    name: 'Details'
    type: 'dynamic'
  }
]

var streamColumns = map(columns, column => column.name == 'TenantId'
  ? {
      name: column.name
      type: 'string'
    }
  : column)

resource permissionEdgeTable 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: tableName
  properties: {
    retentionInDays: retentionInDays
    totalRetentionInDays: totalRetentionInDays
    schema: {
      name: tableName
      columns: columns
    }
  }
}

resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dataCollectionEndpointName
  location: location
  tags: tags
  properties: {
    description: 'Logs Ingestion endpoint for Agent Permission Intelligence edges.'
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

var streamName = 'Custom-${tableName}'

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dataCollectionRuleName
  location: location
  kind: 'Direct'
  tags: tags
  properties: {
    description: 'Normalizes Agent Permission Intelligence edge records into LAWSentinel.'
    dataCollectionEndpointId: dataCollectionEndpoint.id
    streamDeclarations: {
      '${streamName}': {
        columns: streamColumns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'lawDestination'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          streamName
        ]
        destinations: [
          'lawDestination'
        ]
        transformKql: 'source | extend TenantId=toguid(TenantId)'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [
    permissionEdgeTable
  ]
}

var monitoringMetricsPublisherRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '3913510d-42f4-4e42-8a64-420c390055eb'
)

resource dcrPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: dataCollectionRule
  name: guid(dataCollectionRule.id, automationPrincipalId, monitoringMetricsPublisherRoleDefinitionId)
  properties: {
    roleDefinitionId: monitoringMetricsPublisherRoleDefinitionId
    principalId: automationPrincipalId
    principalType: 'ServicePrincipal'
    description: 'Send normalized Agent Permission Intelligence edges through the Logs Ingestion API.'
  }
}

output workspaceResourceId string = workspace.id
output automationAccountResourceId string = automationAccount.id
output automationPrincipalId string = automationPrincipalId
output streamName string = streamName
output dataCollectionEndpointId string = dataCollectionEndpoint.id
output logsIngestionEndpoint string = dataCollectionEndpoint.properties.logsIngestion.endpoint
output dataCollectionRuleId string = dataCollectionRule.id
output dataCollectionRuleImmutableId string = dataCollectionRule.properties.immutableId
