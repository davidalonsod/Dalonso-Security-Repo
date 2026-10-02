 Agent Permission Edge Collector Infrastructure

This Bicep deployment prepares `LAWSentinel` to receive canonical permission edges from the existing `aa-sentinel-sync` Automation Account.

 Resources

- `AgentPermissionEdges_CL` custom table
- Dedicated Data Collection Endpoint
- Dedicated direct Data Collection Rule
- `Monitoring Metrics Publisher` assignment on the DCR
- Subscription `Reader` assignment for the Automation managed identity

 Build

powershell
az bicep build --file access-graph/infra/main.bicep


 What-if

Use the approved subscription context:

powershell
az deployment sub what-if `
  --location northeurope `
  --template-file access-graph/infra/main.bicep `
  --parameters access-graph/infra/main.parameters.json


 Deployment

Do not deploy directly from this guide. Follow:

text
azure-prepare → azure-validate → azure-deploy


Microsoft Graph app-role assignments, Automation variables, runbook publication, module checks, and schedule association are completed by the collector deployment script after the ARM deployment.

 Security

- Existing system-assigned managed identity
- No secrets
- Reader at current subscription only
- Monitoring Metrics Publisher at the dedicated DCR only
- No Graph write permissions
- No prompt or document content collected
