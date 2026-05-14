// Google Workspace Alert Center -> Sentinel via Function App + DCR.
//
// Deploys: Storage, App Service plan (Flex/Linux consumption), Function App,
// Application Insights, Key Vault (for the SA JSON secret), Data Collection
// Endpoint, Data Collection Rule (Direct kind, custom stream), and the
// custom Log Analytics table. Wires managed identity for:
//   * Key Vault Secrets User      (Function MI -> KV)
//   * Monitoring Metrics Publisher (Function MI -> DCR)
//
// The service-account JSON is supplied at deploy time as a secure parameter
// and stored in Key Vault. The Function reads it via Key Vault reference.
//
// NOTE: arm-ttk's `Location-Should-Not-Be-Hardcoded` is satisfied by using
// resourceGroup().location as the default for `location`.
targetScope = 'resourceGroup'

@description('Region for all resources.')
param location string = resourceGroup().location

@description('Short name prefix (3-12 chars, lowercase). Used to derive resource names.')
@minLength(3)
@maxLength(12)
param namePrefix string = 'gwsalert'

@description('Existing Log Analytics workspace name (Sentinel-enabled) in this RG.')
param workspaceName string

@description('Google Workspace admin email to impersonate (DWD subject).')
param impersonateSubject string

@description('Service account JSON (full key file contents). Stored in Key Vault.')
@secure()
param serviceAccountJson string

@description('Object ID of the principal that should administer the Key Vault secret (you).')
param kvAdminObjectId string

var storageName     = toLower('${namePrefix}st${uniqueString(resourceGroup().id)}')
var planName        = '${namePrefix}-plan'
var funcName        = '${namePrefix}-func-${uniqueString(resourceGroup().id)}'
var aiName          = '${namePrefix}-ai'
var kvName          = toLower('${namePrefix}kv${uniqueString(resourceGroup().id)}')
var dceName         = '${namePrefix}-dce'
var dcrName         = '${namePrefix}-dcr'
var saSecretName    = 'gws-sa-json'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// -----------------------------------------------------------------------------
// Custom table
// -----------------------------------------------------------------------------
resource gwsTable 'Microsoft.OperationalInsights/workspaces/tables@2025-02-01' = {
  parent: workspace
  name: 'GWSAlerts_CL'
  properties: {
    schema: {
      name: 'GWSAlerts_CL'
      columns: [
        { name: 'TimeGenerated',                type: 'datetime' }
        { name: 'CustomerId',                   type: 'string'   }
        { name: 'AlertId',                      type: 'string'   }
        { name: 'CreateTime',                   type: 'datetime' }
        { name: 'StartTime',                    type: 'datetime' }
        { name: 'EndTime',                      type: 'datetime' }
        { name: 'AlertType',                    type: 'string'   }
        { name: 'Source',                       type: 'string'   }
        { name: 'AlertData',                    type: 'dynamic'  }
        { name: 'AlertDataType',                type: 'string'   }
        { name: 'SecurityInvestigationToolLink',type: 'string'   }
        { name: 'Deleted',                      type: 'boolean'  }
        { name: 'UpdateTime',                   type: 'datetime' }
        { name: 'Etag',                         type: 'string'   }
        { name: 'MetadataCustomerId',           type: 'string'   }
        { name: 'MetadataAlertId',              type: 'string'   }
        { name: 'MetadataStatus',               type: 'string'   }
        { name: 'MetadataAssignee',             type: 'string'   }
        { name: 'MetadataUpdateTime',           type: 'datetime' }
        { name: 'MetadataSeverity',             type: 'string'   }
        { name: 'MetadataEtag',                 type: 'string'   }
      ]
    }
  }
}

// -----------------------------------------------------------------------------
// DCE + DCR (Direct ingestion)
// -----------------------------------------------------------------------------
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dceName
  location: location
  properties: {
    networkAcls: { publicNetworkAccess: 'Enabled' }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Direct'
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-GWSAlerts_CL': {
        columns: [
          { name: 'customerId',                   type: 'string'  }
          { name: 'alertId',                      type: 'string'  }
          { name: 'createTime',                   type: 'string'  }
          { name: 'startTime',                    type: 'string'  }
          { name: 'endTime',                      type: 'string'  }
          { name: 'alertType',                    type: 'string'  }
          { name: 'source',                       type: 'string'  }
          { name: 'data',                         type: 'dynamic' }
          { name: 'securityInvestigationToolLink',type: 'string'  }
          { name: 'deleted',                      type: 'boolean' }
          { name: 'metadata',                     type: 'dynamic' }
          { name: 'updateTime',                   type: 'string'  }
          { name: 'etag',                         type: 'string'  }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'clv2ws1'
        }
      ]
    }
    dataFlows: [
      {
        streams: [ 'Custom-GWSAlerts_CL' ]
        destinations: [ 'clv2ws1' ]
        outputStream: 'Custom-GWSAlerts_CL'
        transformKql: 'source | extend TimeGenerated = todatetime(createTime) | extend CustomerId = tostring(customerId), AlertId = tostring(alertId), CreateTime = todatetime(createTime), StartTime = todatetime(startTime), EndTime = todatetime(endTime), AlertType = tostring(alertType), Source = tostring([\'source\']), AlertData = todynamic(data), AlertDataType = tostring(todynamic(data)[\'@type\']), SecurityInvestigationToolLink = tostring(securityInvestigationToolLink), Deleted = tobool(deleted), UpdateTime = todatetime(updateTime), Etag = tostring(etag), MetadataCustomerId = tostring(todynamic(metadata)[\'customerId\']), MetadataAlertId = tostring(todynamic(metadata)[\'alertId\']), MetadataStatus = tostring(todynamic(metadata)[\'status\']), MetadataAssignee = tostring(todynamic(metadata)[\'assignee\']), MetadataUpdateTime = todatetime(todynamic(metadata)[\'updateTime\']), MetadataSeverity = tostring(todynamic(metadata)[\'severity\']), MetadataEtag = tostring(todynamic(metadata)[\'etag\']) | project TimeGenerated, CustomerId, AlertId, CreateTime, StartTime, EndTime, AlertType, Source, AlertData, AlertDataType, SecurityInvestigationToolLink, Deleted, UpdateTime, Etag, MetadataCustomerId, MetadataAlertId, MetadataStatus, MetadataAssignee, MetadataUpdateTime, MetadataSeverity, MetadataEtag'
      }
    ]
  }
  dependsOn: [ gwsTable ]
}

// -----------------------------------------------------------------------------
// Storage (function backing + cursor table)
// -----------------------------------------------------------------------------
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

// -----------------------------------------------------------------------------
// Key Vault (RBAC) + SA secret
// -----------------------------------------------------------------------------
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

resource saSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: saSecretName
  properties: {
    value: serviceAccountJson
    contentType: 'application/json'
  }
}

// Built-in role definitions
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'
var keyVaultSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

// Admin RBAC for the deployer (so they can rotate the SA secret afterwards).
resource kvAdminRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, kvAdminObjectId, keyVaultSecretsOfficerRoleId)
  properties: {
    principalId: kvAdminObjectId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsOfficerRoleId)
    principalType: 'User'
  }
}

// -----------------------------------------------------------------------------
// App Insights + Plan + Function App
// -----------------------------------------------------------------------------
resource ai 'Microsoft.Insights/components@2020-02-02' = {
  name: aiName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  sku: { name: 'Y1', tier: 'Dynamic' }
  properties: { reserved: true }
}

resource func 'Microsoft.Web/sites@2023-12-01' = {
  name: funcName
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appSettings: [
        { name: 'AzureWebJobsStorage',                    value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}' }
        { name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING',value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}' }
        { name: 'WEBSITE_CONTENTSHARE',                   value: toLower(funcName) }
        { name: 'FUNCTIONS_EXTENSION_VERSION',            value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME',               value: 'python' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING',  value: ai.properties.ConnectionString }

        { name: 'GOOGLE_SA_JSON',                         value: '@Microsoft.KeyVault(SecretUri=${saSecret.properties.secretUri})' }
        { name: 'GWS_IMPERSONATE_SUBJECT',                value: impersonateSubject }
        { name: 'GWS_PAGE_SIZE',                          value: '1000' }
        { name: 'GWS_ALERT_FILTER_LOOKBACK_MINUTES',      value: '60' }

        { name: 'DCE_LOGS_INGESTION_ENDPOINT',            value: dce.properties.logsIngestion.endpoint }
        { name: 'DCR_IMMUTABLE_ID',                       value: dcr.properties.immutableId }
        { name: 'DCR_STREAM_NAME',                        value: 'Custom-GWSAlerts_CL' }

        { name: 'STATE_TABLE_NAME',                       value: 'gwsalertstate' }
        { name: 'STATE_PARTITION_KEY',                    value: 'alertcenter' }
        { name: 'STATE_ROW_KEY',                          value: 'cursor' }
      ]
    }
  }
}

// MI -> Key Vault Secrets User on the SA secret
resource funcKvRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, func.id, keyVaultSecretsUserRoleId)
  properties: {
    principalId: func.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalType: 'ServicePrincipal'
  }
}

// MI -> Monitoring Metrics Publisher on the DCR
resource funcDcrRa 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: dcr
  name: guid(dcr.id, func.id, monitoringMetricsPublisherRoleId)
  properties: {
    principalId: func.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalType: 'ServicePrincipal'
  }
}

output functionAppName string = func.name
output dceEndpoint     string = dce.properties.logsIngestion.endpoint
output dcrImmutableId  string = dcr.properties.immutableId
output keyVaultName    string = kv.name
