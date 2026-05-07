# Google Workspace Alert Center → Sentinel (Function App connector)

Codeful Azure Function that ingests Google Workspace **Alert Center** alerts
into the `GWSAlerts_CL` custom table in Microsoft Sentinel.

## Why a Function App and not the CCF connector?

`alertcenter.googleapis.com` only accepts **service-account credentials with
domain-wide delegation (DWD)** — it is not consentable through user OAuth.
Requesting the `https://www.googleapis.com/auth/apps.alerts` scope through a
3-legged OAuth flow returns `400 invalid_scope`. Google's docs state this
explicitly:

> To use the Alert Center API, you must use a service account and set up
> domain-wide delegation.

The Sentinel **Codeless Connector Framework (CCF)** only orchestrates user
OAuth (`authorization_code` / `client_credentials`); it cannot mint JWT
assertions and exchange them for an access token, so a CCF connector for this
API cannot work today. This Function performs the JWT-bearer flow via
`google-auth` and pushes alerts to a DCR using the Logs Ingestion API.

## Components

| Resource | Purpose |
|---|---|
| Function App (Python 3.11, Consumption) | Timer trigger every 5 minutes, polls Alert Center |
| Storage Account | Function backing storage + cursor table `gwsalertstate` |
| Key Vault | Stores the service-account JSON; Function reads it via Key Vault reference |
| Application Insights | Function logs/metrics |
| Data Collection Endpoint + DCR (`Direct` kind) | Logs Ingestion target |
| Custom table `GWSAlerts_CL` | Same schema as the CCF version — analytic rules and hunts work unchanged |

## Google Workspace prerequisites

1. **Create a service account** in Google Cloud Console (any project; the
   Alert Center API itself does not need to be enabled in that project).
2. **Generate a JSON key** and download it (you will paste it into the deploy
   parameters; Bicep stores it in Key Vault).
3. **Enable Domain-Wide Delegation** on the service account and copy its
   *Client ID* (numeric).
4. In **Google Workspace Admin Console** → *Security → Access and data
   control → API controls → Manage Domain Wide Delegation*, add a new
   client with that numeric Client ID and the scope:
   ```
   https://www.googleapis.com/auth/apps.alerts
   ```
5. Pick a Workspace **admin user email** that the SA will impersonate
   (`GWS_IMPERSONATE_SUBJECT`). It must have *View Alert Center* privilege.

## Deploy

```powershell
$rg = '<resource-group>'   # RG for the Function App + DCE/DCR/KV/Storage
$loc = 'westeurope'
az group create -n $rg -l $loc

# Edit deploy/parameters.sample.json with your values, then:
az deployment group create `
  -g $rg `
  --template-file FunctionApp/deploy/main.bicep `
  --parameters '@FunctionApp/deploy/parameters.sample.json'
```

### Cross-resource-group workspaces

If your Sentinel/Log Analytics workspace lives in a **different RG** than
where you want to deploy the Function App, set `workspaceResourceGroup` in
the parameters file to the workspace's RG. The custom table `GWSAlerts_CL`
is deployed via a nested module scoped to that RG (`deploy/table.bicep`),
so the deploying identity needs `Contributor` (or table-write) on the
workspace RG as well as on the Function App RG.

If omitted, the workspace is assumed to be in the same RG as the Function
App.

Outputs include `functionAppName`, `dceEndpoint`, `dcrImmutableId`,
`keyVaultName` — useful for verification.

## Publish the function code

```powershell
cd FunctionApp
func azure functionapp publish <functionAppName> --python
```

Or via VS Code Azure Functions extension → *Deploy to Function App*.

## Verify

1. In the Function App → **Monitor** → look for `AlertCenterPoller` runs.
2. In Sentinel → **Logs**:
   ```kql
   GWSAlerts_CL | take 50
   ```
3. The cursor advances after each successful run — check the
   `gwsalertstate` table in the deployed Storage Account.

## Operational notes

- **Window**: The first run pulls the last `GWS_ALERT_FILTER_LOOKBACK_MINUTES`
  (default 60). Subsequent runs use the persisted cursor.
- **Strict-greater filter**: Filter is `createTime > "<cursor>"` so the same
  alert is never re-ingested across runs.
- **Backfill**: To replay, clear the row in the `gwsalertstate` table and
  raise `GWS_ALERT_FILTER_LOOKBACK_MINUTES` temporarily. Alert Center retains
  alerts for **30 days** — older data cannot be recovered via this API.
- **Rotation**: Replace the `gws-sa-json` secret in Key Vault. The Function
  picks up new versions on the next cold start (or restart it).
- **Quotas**: Default Alert Center quota is 60 QPS per project. The poller
  uses page size 1000 and runs every 5 minutes — ample headroom.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401 Unauthorized` from Alert Center | DWD scope not added in Workspace Admin, or impersonated user lacks Alert Center privilege |
| `403 PERMISSION_DENIED` | Subject email is not a Workspace admin / wrong domain |
| `400 invalid_grant: Invalid JWT Signature` | SA key rotated/disabled in GCP |
| `Forbidden` from Logs Ingestion | Function MI missing **Monitoring Metrics Publisher** on the DCR — Bicep assigns this; re-run if you skipped it |
| Empty table | No new alerts in window; check `AlertCenterPoller` traces in App Insights |
| `409` on `POST /Tables` in App Insights | Harmless. The state-store calls `create_table()` and catches `ResourceExistsError`; the SDK logs the HTTP exchange at INFO before the exception is caught. The poller still succeeds. |
| **"No job functions found"** at startup, empty `wwwroot` in Kudu, `function list` returns `[]` | Storage account has restrictive defaults (often pushed by Azure Policy): `publicNetworkAccess: Disabled` and/or `allowSharedKeyAccess: false`. The Functions host can't mount AzureFiles → `wwwroot` stays empty → no triggers discovered. Fix: `az storage account update -n <stg> -g <rg> --public-network-access Enabled --allow-shared-key-access true`, then redeploy the zip and restart the Function App. (For long-term hardening switch to a Flex Consumption plan or a private-endpoint-aware Premium plan.) |
