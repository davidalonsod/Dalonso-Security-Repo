//
// Agent365/AgentRiskDemo/GitHubTraffic/Deploy-GitHubTrafficTable.bicep
//
// Creates the plumbing to store GitHub repository Traffic (clones / views)
// snapshots in a Log Analytics / Microsoft Sentinel workspace so you can
// build 1-year trend charts (GitHub only retains 14 days natively).
//
// Resources:
//   - Custom table  GitHubTraffic_CL  (in the existing workspace)
//   - Data Collection Endpoint (DCE)
//   - Data Collection Rule (DCR) with a transform that lands data in the table
//
// Scope: resource group (the one that holds your Sentinel workspace).
//
// Created on 17/06/2026.
//

@description('Name of the existing Log Analytics / Sentinel workspace.')
param workspaceName string

@description('Azure region for the DCE/DCR. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Base name used for the DCE and DCR resources.')
param baseName string = 'github-traffic'

// --- Existing workspace -------------------------------------------------
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// --- Custom table -------------------------------------------------------
resource trafficTable 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: 'GitHubTraffic_CL'
  properties: {
    schema: {
      name: 'GitHubTraffic_CL'
      columns: [
        {
          name: 'TimeGenerated'
          type: 'datetime'
          description: 'Day the metric corresponds to (from the GitHub Traffic API breakdown).'
        }
        {
          name: 'RepoFullName'
          type: 'string'
          description: 'owner/repo, e.g. davidalonsod/Dalonso-Security-Repo.'
        }
        {
          name: 'MetricType'
          type: 'string'
          description: 'clones, views, referrer, path, stars, forks or watchers.'
        }
        {
          name: 'Dimension'
          type: 'string'
          description: 'Referrer site (referrer) or content path (path); empty for other metrics.'
        }
        {
          name: 'Title'
          type: 'string'
          description: 'Page title for content-path (path) metrics; empty otherwise.'
        }
        {
          name: 'Count'
          type: 'int'
          description: 'Total clones/views/referral-views/path-views, or current stars/forks/watchers.'
        }
        {
          name: 'Uniques'
          type: 'int'
          description: 'Unique cloners/visitors; 0 for stars/forks/watchers.'
        }
      ]
    }
    retentionInDays: 730
    totalRetentionInDays: 730
  }
}

// --- Data Collection Endpoint ------------------------------------------
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: '${baseName}-dce'
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// --- Data Collection Rule ----------------------------------------------
resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${baseName}-dcr'
  location: location
  dependsOn: [
    trafficTable
  ]
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-GitHubTraffic_CL': {
        columns: [
          {
            name: 'TimeGenerated'
            type: 'datetime'
          }
          {
            name: 'RepoFullName'
            type: 'string'
          }
          {
            name: 'MetricType'
            type: 'string'
          }
          {
            name: 'Dimension'
            type: 'string'
          }
          {
            name: 'Title'
            type: 'string'
          }
          {
            name: 'Count'
            type: 'int'
          }
          {
            name: 'Uniques'
            type: 'int'
          }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'sentinelWorkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-GitHubTraffic_CL'
        ]
        destinations: [
          'sentinelWorkspace'
        ]
        transformKql: 'source | extend TimeGenerated = todatetime(TimeGenerated)'
        outputStream: 'Custom-GitHubTraffic_CL'
      }
    ]
  }
}

// --- Outputs (needed by the snapshot script / workflow) -----------------
@description('Logs ingestion URI of the DCE. Use as DCE_ENDPOINT.')
output dceLogsIngestionUri string = dce.properties.logsIngestion.endpoint

@description('Immutable ID of the DCR. Use as DCR_IMMUTABLE_ID.')
output dcrImmutableId string = dcr.properties.immutableId

@description('Stream name to post to. Use as DCR_STREAM_NAME.')
output streamName string = 'Custom-GitHubTraffic_CL'

@description('Resource ID of the DCR. Grant the GitHub Actions identity Monitoring Metrics Publisher on this.')
output dcrResourceId string = dcr.id
