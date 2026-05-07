// Custom Log Analytics table for GWS Alert Center events.
// Deployed in the workspace's resource group (which may differ from the
// Function App's RG).
targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace name.')
param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

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
