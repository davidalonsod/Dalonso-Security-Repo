// attackpath-snapshot.bicep
// One-command infrastructure for the CIEM workbook's attack-path history:
//   - Custom Log Analytics table  CIEM_AttackPaths_CL
//   - Data Collection Endpoint (DCE) + Data Collection Rule (DCR)
//   - Azure Automation account with a system-assigned managed identity
//   - Automation variables (DCE endpoint / DCR immutable id / stream name)
//   - Monitoring Metrics Publisher on the DCR granted to the Automation identity
//
// Deploy to the resource group that CONTAINS the Log Analytics workspace.
// The runbook content + daily schedule + subscription Reader role are applied by
// Deploy-AttackPathSnapshot.ps1 (Azure Automation runbook content can't be inlined in ARM).

targetScope = 'resourceGroup'

@description('Name of the EXISTING Log Analytics workspace (must be in this resource group).')
param logAnalyticsWorkspaceName string

@description('Location for the new resources.')
param location string = resourceGroup().location

param automationAccountName string = 'aa-ciem-attackpaths'
param dceName string = 'dce-ciem-attackpaths'
param dcrName string = 'dcr-ciem-attackpaths'

var tableName  = 'CIEM_AttackPaths_CL'
var streamName = 'Custom-CIEM_AttackPaths_CL'

// Shared column set used by BOTH the custom table and the DCR stream declaration.
var columns = [
  { name: 'TimeGenerated',   type: 'datetime' }
  { name: 'SnapshotId',      type: 'string' }
  { name: 'RecordType',      type: 'string' }
  { name: 'AttackPathId',    type: 'string' }
  { name: 'DisplayName',     type: 'string' }
  { name: 'Risk',            type: 'string' }
  { name: 'AttackPathType',  type: 'string' }
  { name: 'PotentialImpact', type: 'string' }
  { name: 'RiskCategories',  type: 'string' }
  { name: 'SubscriptionId',  type: 'string' }
  { name: 'Cloud',           type: 'string' }
  { name: 'ProviderSet',     type: 'string' }
  { name: 'AccountOrProject', type: 'string' }
  { name: 'EntryPointEntityId', type: 'string' }
  { name: 'TargetEntityId',  type: 'string' }
  { name: 'EntityCount',     type: 'int' }
  { name: 'ConnectionCount', type: 'int' }
  { name: 'GraphEntitiesJson', type: 'string' }
  { name: 'GraphConnectionsJson', type: 'string' }
]

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ws
  name: tableName
  properties: {
    schema: {
      name: tableName
      columns: columns
    }
    totalRetentionInDays: 90
    plan: 'Analytics'
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      '${streamName}': {
        columns: columns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'la'
          workspaceResourceId: ws.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [ streamName ]
        destinations: [ 'la' ]
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [ table ]
}

resource aa 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationAccountName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    sku: {
      name: 'Basic'
    }
  }
}

resource vDce 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: aa
  name: 'DceEndpoint'
  properties: {
    isEncrypted: false
    value: '"${dce.properties.logsIngestion.endpoint}"'
  }
}

resource vDcr 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: aa
  name: 'DcrImmutableId'
  properties: {
    isEncrypted: false
    value: '"${dcr.properties.immutableId}"'
  }
}

resource vStream 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: aa
  name: 'StreamName'
  properties: {
    isEncrypted: false
    value: '"${streamName}"'
  }
}

// Monitoring Metrics Publisher lets the Automation identity ingest into the DCR.
resource dcrPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, aa.id, 'MonitoringMetricsPublisher')
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')
    principalId: aa.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output dceEndpoint string = dce.properties.logsIngestion.endpoint
output dcrImmutableId string = dcr.properties.immutableId
output automationAccountName string = aa.name
output automationPrincipalId string = aa.identity.principalId
output streamName string = streamName
output tableName string = tableName
