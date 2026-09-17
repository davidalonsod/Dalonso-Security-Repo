# Deploy APIM AI Gateway detections

This ARM template deploys 13 scheduled analytics and nine saved hunting
queries to a Microsoft Sentinel workspace containing APIM `AppRequests` rows.

The generator validates every scheduled rule locally: `queryPeriod` and
`queryFrequency` must be between `PT5M` and `P14D`, and frequency cannot exceed
period. Longer historical baselines belong in hunting queries or summary data.

```powershell
.\New-APIMGatewayArmTemplate.ps1

az deployment group validate `
  --resource-group <sentinel-rg> `
  --template-file .\azuredeploy.json `
  --parameters workspaceName=<workspace-name> enableAnalyticRules=false

az deployment group create `
  --resource-group <sentinel-rg> `
  --template-file .\azuredeploy.json `
  --parameters workspaceName=<workspace-name> enableAnalyticRules=true
```

Validate that this workspace contains body telemetry first:

```kusto
AppRequests
| where SDKVersion startswith "apim:"
    or tostring(Properties["Service Type"]) =~ "API Management"
| summarize
    Requests = count(),
    WithRequestBody = countif(isnotempty(tostring(Properties["Request-Body"]))),
    WithResponseBody = countif(isnotempty(tostring(Properties["Response-Body"])))
```

The content fields are intentionally returned by these detections and can be copied
into alerts/incidents. Apply strict access and retention controls.